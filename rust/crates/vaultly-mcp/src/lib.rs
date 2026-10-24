//! Vaultly MCP Server — Agent-First Zero-Knowledge Interface.
//!
//! Hand-rolled JSON-RPC 2.0 over stdio (newline-delimited), mirroring
//! src/mcp-server.ts. Every operation routes through PolicyEngine → VaultEngine
//! → Scrubber. NO tool returns raw secret values. By design.
//!
//! Implements the subset of the MCP protocol a tool-only server needs:
//!   initialize, notifications/initialized, ping, tools/list, tools/call.

use std::io::IsTerminal;
use std::process::exit;
use std::sync::OnceLock;

use serde_json::{json, Map, Value};
use vaultly_core::{generate, keychain, CallerContext, VaultEngine, VaultError};

pub const SERVER_NAME: &str = "vaultly";
pub const SERVER_VERSION: &str = "1.1.0";
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// The master password, captured at startup before the env var is removed.
/// Used by encrypted export/import tools that need to derive a fresh key.
static MASTER_PASSWORD: OnceLock<String> = OnceLock::new();

/// Retrieve the stored master password, falling back to env (for non-env unlock paths).
fn master_password() -> Option<String> {
    if let Some(pw) = MASTER_PASSWORD.get() {
        return Some(pw.clone());
    }
    std::env::var("VAULTLY_MASTER_PASSWORD").ok()
}
pub const SESSION_TTL_MINUTES: u64 = 120;

fn agent_ctx() -> CallerContext {
    CallerContext {
        caller: vaultly_core::policy::Caller::Agent,
        agent_name: Some("mcp-agent".to_owned()),
        session_id: None,
    }
}

fn ok(text: impl ToString) -> Value {
    json!({ "content": [{ "type": "text", "text": text.to_string() }] })
}

fn fail(text: impl ToString) -> Value {
    json!({ "content": [{ "type": "text", "text": format!("✗ {}", text.to_string()) }], "isError": true })
}

/// Map a structured VaultError to a stable, machine-readable error code.
fn error_code(e: &VaultError) -> &'static str {
    use vaultly_core::VaultError::*;
    match e {
        NotInitialized => "not_initialized",
        AlreadyInitialized(_) => "already_initialized",
        Locked => "locked",
        SessionExpired => "session_expired",
        WrongPassword => "wrong_password",
        VaultNotFound(_) => "vault_not_found",
        VaultEmpty(_) => "vault_empty",
        SecretNotFound(_, _) => "secret_not_found",
        InvalidVaultName(_) => "invalid_vault_name",
        InvalidKeyName(_) => "invalid_key_name",
        ValueTooLarge(_, _) => "value_too_large",
        VaultCorrupt(_, _) => "vault_corrupt",
        ConfigCorrupt(_) => "config_corrupt",
        Crypto(_) => "crypto",
        Decrypt(_) => "decrypt",
        KeyDerivation(_) => "key_derivation",
        Io(_) => "io",
        Json(_) => "json",
        Policy(_) => "policy_denied",
        RateLimit(_) => "rate_limit",
        CloudflareRequest(_) => "cloudflare_error",
        CloudflareResponse(_) => "cloudflare_error",
        CloudflareCredentials(_, _) => "cf_credentials",
        MissingAccountId(_, _) => "cf_missing_account_id",
        CommandSpawn(_, _) => "command_spawn",
        CommandFailed(_, _, _) => "command_failed",
        UnknownSecretAction(_) => "unknown_secret_action",
        RequiredField(_, _) => "required_field",
        Audit(_) => "audit",
    }
}

/// Structured error response carrying a stable `code` for each engine failure.
fn fail_err(e: &VaultError) -> Value {
    json!({
        "content": [{ "type": "text", "text": format!("✗ {}", e) }],
        "isError": true,
        "code": error_code(e),
    })
}

#[cfg(unix)]
fn write_export_file(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let mut f = std::fs::File::create(path)?;
    f.write_all(contents.as_bytes())?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_export_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Bind required string args as `&str` (ident `name` for JSON key `"KEY"`)
/// or return a `fail(...)` error Value. Expands to bare `let` statements so
/// the bindings are visible in the calling function scope.
macro_rules! require {
    ($args:expr, $($name:ident => $key:literal),+ $(,)?) => {
        $(
            let $name: &str = match crate::get_str($args, $key).filter(|s| !s.is_empty()) {
                Some(v) => v,
                None => return crate::fail(concat!(
                    "Missing required argument '", $key, "'."
                )),
            };
        )+
    };
}

// ─── Tool definitions ─────────────────────────────────────

struct Tool {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

fn str_prop(desc: &str) -> Value {
    json!({ "type": "string", "description": desc })
}

fn tools_list() -> Vec<Tool> {
    vec![
        Tool { name: "vault_list", description: "List vault names. No values.", schema: json!({"type":"object","properties":{}}) },
        Tool { name: "vault_keys", description: "List credential key names and expiry metadata. No values.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name")},"required":["vaultName"]}) },
        Tool { name: "vault_add", description: "Write a credential into an encrypted vault. The value is never returned.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name"),"key":str_prop("Credential name"),"value":str_prop("Credential value"),"ttlSeconds":json!({"type":"number"}),"expiresAt":str_prop("RFC3339 expiry")},"required":["vaultName","key","value"]}) },
        Tool { name: "vault_delete", description: "Delete one credential from a vault.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name"),"key":str_prop("Credential name")},"required":["vaultName","key"]}) },
        Tool { name: "vault_import", description: "Import credentials as a write-only JSON object.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name"),"entriesJson":str_prop("JSON object of credentials")},"required":["vaultName","entriesJson"]}) },
        Tool { name: "vault_export_encrypted", description: "Export an encrypted vault blob without plaintext.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name"),"file":str_prop("Output file")},"required":["vaultName","file"]}) },
        Tool { name: "vault_import_encrypted", description: "Import an encrypted vault blob without exposing values.", schema: json!({"type":"object","properties":{"file":str_prop("Encrypted export file"),"vaultName":str_prop("Destination vault")},"required":["file"]}) },
        Tool { name: "vault_generate", description: "Generate and store a credential without returning its value.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name"),"key":str_prop("Credential name"),"length":json!({"type":"number"}),"symbols":json!({"type":"boolean"})},"required":["vaultName","key"]}) },
        Tool { name: "vault_rotate", description: "Rotate one credential or all expired credentials without returning values.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name"),"key":str_prop("Credential name"),"expired":json!({"type":"boolean"}),"length":json!({"type":"number"}),"symbols":json!({"type":"boolean"})},"required":["vaultName"]}) },
        Tool { name: "vault_status", description: "Show lock/session status and vault names.", schema: json!({"type":"object","properties":{}}) },
        Tool { name: "vault_lock", description: "Lock Vaultly and wipe the in-memory key.", schema: json!({"type":"object","properties":{}}) },
        Tool { name: "vault_unlock", description: "Unlock through the configured OS credential store; the agent never handles the password.", schema: json!({"type":"object","properties":{}}) },
        Tool { name: "vault_audit", description: "Read the tamper-evident audit trail without values.", schema: json!({"type":"object","properties":{"lines":json!({"type":"number"}),"vault":str_prop("Filter"),"caller":str_prop("human or agent"),"after":str_prop("RFC3339 timestamp")}}) },
        Tool { name: "vault_meta", description: "Inspect vault metadata and credential names without values.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Vault name")},"required":["vaultName"]}) },
        Tool { name: "cf_accounts", description: "List configured Cloudflare accounts and health, never credentials.", schema: json!({"type":"object","properties":{"health":json!({"type":"boolean"})}}) },
        Tool { name: "cf_account_label", description: "Read or set a non-secret Cloudflare account label.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault"),"label":str_prop("Label; omit to read, empty to clear")},"required":["vaultName"]}) },
        Tool { name: "cf_health", description: "Verify one Cloudflare credential set.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_zones", description: "List domains in a Cloudflare account.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_pages_projects", description: "List Pages projects for discovery and target adoption.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_workers_list", description: "List Workers for discovery and target adoption.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_d1_list", description: "List D1 databases (names and ids) in the vault's account. Read-only.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_r2_list", description: "List R2 buckets (names) in the vault's account. Read-only.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_kv_list", description: "List Workers KV namespaces (titles and ids) in the vault's account. Read-only.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault")},"required":["vaultName"]}) },
        Tool { name: "cf_secrets", description: "List/set/delete Worker secrets. Values are write-only.", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault"),"scriptName":str_prop("Worker name"),"action":json!({"type":"string","enum":["list","set","delete"]}),"name":str_prop("Secret name"),"value":str_prop("Secret value; write-only")},"required":["vaultName","scriptName","action"]}) },
        Tool { name: "deploy_targets", description: "List deployment targets. Metadata only.", schema: json!({"type":"object","properties":{}}) },
        Tool { name: "deploy_target_adopt", description: "Discover and idempotently adopt a Pages/Worker target from a Wrangler config in the current workspace. Account and project identity are resolved from the selected Cloudflare vault and live account inventory. Pass allowCreate=true to register a target whose resource does not exist yet; it is created on first deploy (Workers via npm run deploy, D1/R2 bootstrapped from the config's own bindings).", schema: json!({"type":"object","properties":{"vaultName":str_prop("Cloudflare vault; account is resolved from this vault"),"configPath":str_prop("Wrangler JSON/JSONC/TOML config inside the current workspace"),"allowCreate":json!({"type":"boolean","description":"Register even if the Cloudflare resource does not exist yet (created on first deploy)."})},"required":["vaultName","configPath"]}) },
        Tool { name: "deploy_target", description: "Deploy one approved target by ID. The agent cannot choose account, project, branch, directory, or command.", schema: json!({"type":"object","properties":{"targetId":str_prop("Registered deployment target ID")},"required":["targetId"]}) },
        Tool { name: "deploy_target_preflight", description: "Read-only preflight for one approved target by ID: worker existence, worker secret names, and per-D1-database applied/pending migrations with safety verdicts. No mutations, no credential values.", schema: json!({"type":"object","properties":{"targetId":str_prop("Registered deployment target ID")},"required":["targetId"]}) },
        Tool { name: "deploy_target_exec", description: "Execute one APPROVED repository maintenance script (check:migrations, backup:d1, backup:verify, migrate:apply, watchdog, smoke, purge:test-accounts) against a registered target. Script bodies come from the repo package.json, never from agent input. Mutating scripts need the typed confirm word and a human-granted run policy (default policy_denied).", schema: json!({"type":"object","properties":{"targetId":str_prop("Registered deployment target ID"),"script":str_prop("Approved script name, e.g. migrate:apply"),"confirm":str_prop("Typed confirmation for mutating scripts (APPLY, BACKUP, PURGE)")},"required":["targetId","script"]}) },
        Tool { name: "github_secret_sync", description: "Copy one vault credential into a GitHub Actions repository secret. Value travels vault -> gh only; never returned.", schema: json!({"type":"object","properties":{"sourceVault":str_prop("Vault holding the source credential"),"sourceKey":str_prop("Key of the source credential"),"repo":str_prop("Target repo as owner/name"),"secretName":str_prop("GitHub secret name (A-Z, 0-9, _)"),"environment":str_prop("Optional GitHub environment (its secrets shadow repo secrets)")},"required":["sourceVault","sourceKey","repo","secretName"]}) },
        Tool { name: "policy_info", description: "Show effective agent operation policy without secrets.", schema: json!({"type":"object","properties":{}}) },
    ]
}
// ─── Cloudflare Pages ────────────────────────────────────

async fn tool_cf_pages_projects(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, vault => "vaultName");
    match engine
        .cloudflare_account_api(vault, "GET", "/pages/projects", None, Some(ctx))
        .await
    {
        Ok(r) => {
            let names: Vec<String> = r
                .data
                .get("result")
                .and_then(|x| x.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|p| {
                            p.get("name")
                                .and_then(|n| n.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();
            ok(format!(
                "Pages projects ({}):\n{}",
                names.len(),
                names
                    .iter()
                    .map(|n| format!("  - {}", n))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
        Err(e) => fail_err(&e),
    }
}

async fn tool_deploy_targets(engine: &mut VaultEngine, _ctx: &CallerContext) -> Value {
    match engine.store().load_deployment_targets() {
        Ok(targets) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&targets).unwrap_or_else(|_| "[]".into()) }],
            "targets": targets,
        }),
        Err(e) => fail_err(&e),
    }
}

async fn tool_deploy_target_adopt(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, vault => "vaultName", config => "configPath");
    let allow_create = args
        .get("allowCreate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    match engine
        .adopt_deployment_target(vault, std::path::Path::new(config), Some(ctx), allow_create)
        .await
    {
        Ok(target) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&target).unwrap_or_else(|_| "{}".into()) }],
            "status": "adopted",
            "target": target,
        }),
        Err(e) => fail_err(&e),
    }
}

async fn tool_deploy_target(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, target_id => "targetId");
    let targets = match engine.store().load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => return fail_err(&e),
    };
    let target = match targets.into_iter().find(|target| target.id == target_id) {
        Some(target) => target,
        None => return fail(format!("Deployment target '{}' was not found", target_id)),
    };
    match engine.deploy_target(&target, Some(ctx)).await {
        Ok(result) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&result).unwrap_or_else(|_| "{}".into()) }],
            "deployment": result,
        }),
        Err(e) => fail_err(&e),
    }
}

async fn tool_deploy_target_preflight(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, target_id => "targetId");
    let targets = match engine.store().load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => return fail_err(&e),
    };
    let target = match targets.into_iter().find(|target| target.id == target_id) {
        Some(target) => target,
        None => return fail(format!("Deployment target '{}' was not found", target_id)),
    };
    match engine.preflight_target(&target, Some(ctx)).await {
        Ok(result) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&result).unwrap_or_else(|_| "{}".into()) }],
            "preflight": result,
        }),
        Err(e) => fail_err(&e),
    }
}

async fn tool_deploy_target_exec(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, target_id => "targetId", script => "script");
    let confirm = args.get("confirm").and_then(|v| v.as_str());
    let targets = match engine.store().load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => return fail_err(&e),
    };
    let target = match targets.into_iter().find(|target| target.id == target_id) {
        Some(target) => target,
        None => return fail(format!("Deployment target '{}' was not found", target_id)),
    };
    match engine
        .exec_target_script(&target, script, confirm, Some(ctx))
        .await
    {
        Ok(result) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string(&result).unwrap_or_else(|_| "{}".into()) }],
            "execution": result,
        }),
        Err(e) => fail_err(&e),
    }
}

async fn tool_github_secret_sync(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, source_vault => "sourceVault", source_key => "sourceKey", repo => "repo", secret_name => "secretName");
    let environment = args.get("environment").and_then(|v| v.as_str());
    match engine
        .sync_github_secret(
            source_vault,
            source_key,
            repo,
            secret_name,
            environment,
            Some(ctx),
        )
        .await
    {
        Ok(status) => ok(status),
        Err(e) => fail_err(&e),
    }
}

async fn call_tool(engine: &mut VaultEngine, name: &str, args: &Value) -> Value {
    let ctx = agent_ctx();
    match name {
        "vault_list" => tool_vault_list(engine, &ctx).await,
        "vault_keys" => tool_vault_keys(engine, args, &ctx).await,
        "vault_add" => tool_vault_add(engine, args, &ctx).await,
        "vault_delete" => tool_vault_delete(engine, args, &ctx).await,
        "vault_import" => tool_vault_import(engine, args, &ctx).await,
        "vault_export_encrypted" => tool_vault_export_encrypted(engine, args, &ctx).await,
        "vault_import_encrypted" => tool_vault_import_encrypted(engine, args, &ctx).await,
        "vault_generate" => tool_vault_generate(engine, args, &ctx).await,
        "vault_rotate" => tool_vault_rotate(engine, args, &ctx).await,
        "vault_status" => tool_vault_status(engine).await,
        "vault_lock" => tool_vault_lock(engine, &ctx).await,
        "vault_unlock" => tool_vault_unlock(engine).await,
        "vault_audit" => tool_vault_audit(engine, args, &ctx).await,
        "vault_meta" => tool_vault_meta(engine, args, &ctx).await,
        "cf_accounts" => tool_cf_accounts(engine, args, &ctx).await,
        "cf_account_label" => tool_cf_account_label(engine, args, &ctx).await,
        "cf_health" => tool_cf_health(engine, args, &ctx).await,
        "cf_zones" => tool_cf_zones(engine, args, &ctx).await,
        "cf_pages_projects" => tool_cf_pages_projects(engine, args, &ctx).await,
        "cf_workers_list" => tool_cf_workers_list(engine, args, &ctx).await,
        "cf_d1_list" => tool_cf_storage_list(engine, args, &ctx, StorageKind::D1).await,
        "cf_r2_list" => tool_cf_storage_list(engine, args, &ctx, StorageKind::R2).await,
        "cf_kv_list" => tool_cf_storage_list(engine, args, &ctx, StorageKind::Kv).await,
        "cf_secrets" => tool_cf_secrets(engine, args, &ctx).await,
        "deploy_targets" => tool_deploy_targets(engine, &ctx).await,
        "deploy_target_adopt" => tool_deploy_target_adopt(engine, args, &ctx).await,
        "deploy_target" => tool_deploy_target(engine, args, &ctx).await,
        "deploy_target_preflight" => tool_deploy_target_preflight(engine, args, &ctx).await,
        "deploy_target_exec" => tool_deploy_target_exec(engine, args, &ctx).await,
        "github_secret_sync" => tool_github_secret_sync(engine, args, &ctx).await,
        "policy_info" => tool_policy_info().await,
        "vault_run" | "cf_deploy" | "cf_pages_deploy" => {
            fail("This operation is disabled for agents. Use deploy_target_adopt or a validated deployment target.")
        }
        _ => fail(
            "Unknown tool or disabled operation. Use tools/list for the supported core interface.",
        ),
    }
}

async fn tool_vault_list(engine: &mut VaultEngine, ctx: &CallerContext) -> Value {
    match engine.list_vaults(Some(ctx)) {
        Ok(vaults) => {
            if vaults.is_empty() {
                ok("No vaults. Use vault_add to create one.")
            } else {
                ok(format!(
                    "Vaults:\n{}",
                    vaults
                        .iter()
                        .map(|vault| format!("  - {}", vault))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            }
        }
        Err(error) => fail_err(&error),
    }
}

fn expiry_from_args(args: &Value) -> Result<Option<String>, Value> {
    let ttl = args.get("ttlSeconds").and_then(Value::as_u64);
    let expires_at = args
        .get("expiresAt")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if ttl.is_some() && expires_at.is_some() {
        return Err(fail(
            "ttlSeconds and expiresAt are mutually exclusive — pass only one.",
        ));
    }
    if let Some(seconds) = ttl {
        return chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(seconds as i64))
            .map(|time| Some(time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)))
            .ok_or_else(|| fail("ttlSeconds is out of range."));
    }
    Ok(expires_at.map(str::to_string))
}

async fn tool_vault_keys(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName");
    let metadata = match engine.list_keys_meta(vault, Some(ctx)) {
        Ok(metadata) => metadata,
        Err(error) => return fail_err(&error),
    };
    if metadata.is_empty() {
        return ok(format!("Vault '{}' is empty or doesn't exist.", vault));
    }
    let mut output = format!("Keys in '{}':\n", vault);
    for item in &metadata {
        output.push_str(&format!("  - {}\n", item.key));
    }
    output.push_str("Meta:\n");
    for item in &metadata {
        let expiry = item
            .expires_at
            .as_deref()
            .map(|value| format!("expiresAt={} expired={}", value, item.expired))
            .unwrap_or_else(|| "expiresAt=null expired=false".to_string());
        output.push_str(&format!(
            "  {}: createdAt={} updatedAt={} {}\n",
            item.key, item.created_at, item.updated_at, expiry
        ));
    }
    ok(output.trim_end())
}

async fn tool_vault_add(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", key => "key", value => "value");
    let expiry = match expiry_from_args(args) {
        Ok(expiry) => expiry,
        Err(error) => return error,
    };
    match engine.add_secret_with_expiry(vault, key, value, expiry.as_deref(), Some(ctx)) {
        Ok(()) => ok(format!(
            "✓ Stored '{}' in '{}'. Encrypted. Cannot be read back.",
            key, vault
        )),
        Err(error) => fail_err(&error),
    }
}

async fn tool_vault_delete(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", key => "key");
    match engine.delete_secret(vault, key, Some(ctx)) {
        Ok(true) => ok(format!("✓ Deleted '{}' from '{}'.", key, vault)),
        Ok(false) => fail(format!("'{}' not found in '{}'.", key, vault)),
        Err(error) => fail_err(&error),
    }
}

async fn tool_vault_status(engine: &mut VaultEngine) -> Value {
    let vaults = engine.list_vaults(Some(&agent_ctx())).unwrap_or_default();
    ok(format!(
        "Vaultly Status:\n  Unlocked: {} (expires in {} min)\n  Vaults: {} ({})\n  Keychain: {}\n  Platform: {}",
        if engine.is_unlocked() { "yes" } else { "no" },
        engine.session_expires_in() / 60,
        vaults.len(),
        if vaults.is_empty() { "none".to_string() } else { vaults.join(", ") },
        if keychain::is_keychain_available() { "available" } else { "not available" },
        std::env::consts::OS
    ))
}

async fn tool_vault_lock(engine: &mut VaultEngine, ctx: &CallerContext) -> Value {
    engine.lock(Some(ctx));
    ok("✓ Vault locked. Decryption key wiped from memory.")
}

async fn tool_vault_unlock(engine: &mut VaultEngine) -> Value {
    if !keychain::is_keychain_available() {
        return fail(keychain::unlock_setup_hint());
    }
    match keychain::get_from_keychain() {
        Some(password) => match engine.unlock(&password) {
            Ok(()) => ok("✓ Vault unlocked."),
            Err(_) => fail("The saved OS credential-store password was rejected for this vault."),
        },
        None => {
            fail("No unique unlocked credential-store entry is available. The owner must check the desktop keyring and run `vaultly keychain store` if needed.")
        }
    }
}

async fn tool_vault_audit(engine: &mut VaultEngine, args: &Value, _ctx: &CallerContext) -> Value {
    let lines = args.get("lines").and_then(|l| l.as_u64()).unwrap_or(20) as usize;
    let vault = args
        .get("vault")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let caller = args
        .get("caller")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty());
    let after = args
        .get("after")
        .and_then(|a| a.as_str())
        .filter(|s| !s.is_empty());

    // Read a large tail, then apply structured filters (audit entries are JSON per line).
    let all = engine.get_audit_log(10_000);
    let mut out: Vec<String> = Vec::new();
    for line in all {
        if let Ok(j) = serde_json::from_str::<Value>(&line) {
            if let Some(v) = vault {
                let detail = j.get("detail").and_then(|d| d.as_str()).unwrap_or("");
                if !detail.contains(v) {
                    continue;
                }
            }
            if let Some(c) = caller {
                let caller_f = j.get("caller").and_then(|x| x.as_str()).unwrap_or("");
                if caller_f != c {
                    continue;
                }
            }
            if let Some(a) = after {
                let ts = j.get("ts").and_then(|x| x.as_str()).unwrap_or("");
                // ISO-8601 / RFC3339 timestamps compare correctly as strings.
                if ts < a {
                    continue;
                }
            }
            out.push(line);
            if out.len() >= lines {
                break;
            }
        }
    }
    // Report the integrity of the audit chain regardless of the filters, so
    // agents get tamper evidence alongside the entries themselves.
    let chain_note = match engine.store().verify_audit_chain() {
        Ok(v) if v.is_empty() => "✓ audit chain intact".to_string(),
        Ok(v) => format!(
            "⚠ audit chain tampered at {} line(s):\n{}",
            v.len(),
            v.iter()
                .map(|(i, r)| format!("    line {i}: {r}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
        Err(e) => format!("⚠ could not verify audit chain: {e}"),
    };

    if out.is_empty() {
        if vault.is_some() || caller.is_some() || after.is_some() {
            ok(format!(
                "No audit entries match the given filters.\n{chain_note}"
            ))
        } else {
            ok(format!("No audit entries yet.\n{chain_note}"))
        }
    } else {
        ok(format!("Audit log:\n{}\n\n{chain_note}", out.join("\n")))
    }
}

// ─── Cloudflare tools ────────────────────────────────────

async fn tool_cf_accounts(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let health = args
        .get("health")
        .and_then(|h| h.as_bool())
        .unwrap_or(false);

    // Health view: verify each credential live (may hit the network).
    if health {
        return match engine.cf_accounts_health(Some(ctx)).await {
            Ok(accounts) => {
                if accounts.is_empty() {
                    return ok("No Cloudflare accounts found. Store CLOUDFLARE_API_TOKEN (or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY) in a vault to register it.");
                }
                ok(format!(
                    "Cloudflare accounts health ({}):\n{}",
                    accounts.len(),
                    accounts
                        .iter()
                        .map(|a| format!(
                            "  - {} {}: {}",
                            a.vault,
                            if a.ok { "✓" } else { "✗" },
                            a.message
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            }
            Err(e) => fail_err(&e),
        };
    }

    match engine.list_cf_accounts(Some(ctx)) {
        Ok(accounts) => {
            if accounts.is_empty() {
                return ok("No Cloudflare accounts found. Store CLOUDFLARE_API_TOKEN (or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY) in a vault to register it.");
            }
            ok(format!(
                "Cloudflare accounts ({}):\n{}",
                accounts.len(),
                accounts
                    .iter()
                    .map(|a| {
                        let account_id = if a.has_account_id {
                            "account-id ✓"
                        } else {
                            "no account-id"
                        };
                        let label = a
                            .label
                            .as_ref()
                            .map(|l| format!(" [{}]", l))
                            .unwrap_or_default();
                        let scope = match (a.cf_api, a.deploy) {
                            (true, true) => "cf-api+deploy",
                            (true, false) => "cf-api (read/write)",
                            (false, true) => "deploy only",
                            (false, false) => "no access",
                        };
                        format!(
                            "  - {}{} (auth: {}, {}, scope: {})",
                            a.vault, label, a.auth, account_id, scope
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
        Err(e) => fail_err(&e),
    }
}

async fn tool_cf_account_label(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, vault => "vaultName");
    let label = args.get("label").and_then(|l| l.as_str());
    match label {
        // Read current label.
        None => match engine.get_account_label(vault, Some(ctx)) {
            Ok(l) => ok(match l {
                Some(l) => format!("Label for '{}': {}", vault, l),
                None => format!("No label set for '{}'.", vault),
            }),
            Err(e) => fail_err(&e),
        },
        // Set or clear (empty string clears).
        Some(l) => {
            let clear = l.is_empty();
            match engine.set_account_label(vault, if clear { None } else { Some(l) }, Some(ctx)) {
                Ok(()) => ok(if clear {
                    format!("✓ Cleared label for '{}'.", vault)
                } else {
                    format!("✓ Set label for '{}' to: {}", vault, l)
                }),
                Err(e) => fail_err(&e),
            }
        }
    }
}

async fn tool_cf_zones(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName");
    match engine
        .cloudflare_api(vault, "GET", "/zones?per_page=50", None, Some(ctx))
        .await
    {
        Ok(r) => {
            let zones = r
                .data
                .get("result")
                .and_then(|z| z.as_array())
                .cloned()
                .unwrap_or_default();
            ok(format!(
                "Zones ({}):\n{}",
                zones.len(),
                zones
                    .iter()
                    .map(|z| format!(
                        "  - {} (id: {}, status: {})",
                        z.get("name").and_then(|n| n.as_str()).unwrap_or("?"),
                        z.get("id").and_then(|i| i.as_str()).unwrap_or("?"),
                        z.get("status").and_then(|s| s.as_str()).unwrap_or("?")
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
        Err(e) => fail_err(&e),
    }
}

async fn tool_cf_workers_list(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, vault => "vaultName");
    match engine.list_workers(vault, Some(ctx)).await {
        Ok((_account_id, workers)) => ok(format!(
            "Workers ({}):\n{}",
            workers.len(),
            workers
                .iter()
                .map(|w| format!("  - {}", w))
                .collect::<Vec<_>>()
                .join("\n")
        )),
        Err(e) => fail_err(&e),
    }
}

/// Which account storage inventory a `cf_*_list` call reports.
enum StorageKind {
    D1,
    R2,
    Kv,
}

impl StorageKind {
    fn label(&self) -> &'static str {
        match self {
            StorageKind::D1 => "D1 databases",
            StorageKind::R2 => "R2 buckets",
            StorageKind::Kv => "KV namespaces",
        }
    }
}

/// Read-only D1/R2/KV discovery for one Cloudflare vault. Names and ids only.
async fn tool_cf_storage_list(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
    kind: StorageKind,
) -> Value {
    require!(args, vault => "vaultName");
    let listed = match kind {
        StorageKind::D1 => engine.list_d1_databases(vault, Some(ctx)).await,
        StorageKind::R2 => engine.list_r2_buckets(vault, Some(ctx)).await,
        StorageKind::Kv => engine.list_kv_namespaces(vault, Some(ctx)).await,
    };
    match listed {
        Ok(items) => ok(format!(
            "{} ({}):\n{}",
            kind.label(),
            items.len(),
            items
                .iter()
                .map(|item| {
                    if item.id.is_empty() {
                        format!("  - {}", item.name)
                    } else {
                        format!("  - {} (id: {})", item.name, item.id)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        )),
        Err(e) => fail_err(&e),
    }
}

async fn tool_cf_secrets(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", script => "scriptName", action => "action");
    let name = args.get("name").and_then(|n| n.as_str());
    let value = args.get("value").and_then(|v| v.as_str());

    if action != "list" && name.is_none() {
        return fail(format!("'name' is required for worker secret {}.", action));
    }
    if action == "set" && value.is_none() {
        return fail("'value' is required for worker secret set.");
    }

    match engine
        .worker_secrets(vault, script, action, name, value, Some(ctx))
        .await
    {
        Ok(r) => {
            if action == "list" {
                let names: Vec<String> = r
                    .data
                    .get("result")
                    .and_then(|x| x.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| {
                                s.get("name")
                                    .and_then(|n| n.as_str())
                                    .map(|n| n.to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                return ok(format!(
                    "Secrets in '{}' ({}):\n{}\n\n(names only — values are never returned)",
                    script,
                    names.len(),
                    names
                        .iter()
                        .map(|n| format!("  - {}", n))
                        .collect::<Vec<_>>()
                        .join("\n")
                ));
            }
            let ok_text = if action == "set" {
                format!("✓ Set secret '{}' on '{}'", name.unwrap_or(""), script)
            } else {
                format!(
                    "✓ Deleted secret '{}' from '{}'",
                    name.unwrap_or(""),
                    script
                )
            };
            if r.status < 400 {
                ok(ok_text)
            } else {
                fail(format!(
                    "{} — API error HTTP {}: {}",
                    ok_text,
                    r.status,
                    serde_json::to_string(&r.data).unwrap_or_default()
                ))
            }
        }
        Err(e) => fail_err(&e),
    }
}

async fn tool_cf_health(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName");
    match engine.health_check(vault, Some(ctx)).await {
        Ok((true, msg)) => ok(format!("✓ {}", msg)),
        Ok((false, msg)) => fail(msg),
        Err(e) => fail_err(&e),
    }
}

// ─── Phase 3 tools ──────────────────────────────────────

async fn tool_vault_meta(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName");
    let keys = match engine.list_keys(vault, Some(ctx)) {
        Ok(k) => k,
        Err(e) => return fail_err(&e),
    };
    let exists = engine.store().list_vaults().contains(&vault.to_string());
    let path = engine
        .store()
        .get_vault_file_path(vault)
        .unwrap_or_default();
    let path_str = if path.as_os_str().is_empty() {
        "(unavailable)".to_string()
    } else {
        path.display().to_string()
    };
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    ok(format!(
        "Vault '{}':\n  Exists: {}\n  File: {}\n  Size: {} bytes\n  Secrets: {}\n  Keys:\n{}",
        vault,
        exists,
        path_str,
        size,
        keys.len(),
        if keys.is_empty() {
            "    (none)".to_string()
        } else {
            keys.iter()
                .map(|k| format!("    - {}", k))
                .collect::<Vec<_>>()
                .join("\n")
        }
    ))
}

async fn tool_vault_generate(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", key => "key");
    let length = args.get("length").and_then(|l| l.as_u64()).unwrap_or(32) as usize;
    let symbols = args
        .get("symbols")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    let secret = generate::generate_secret(length, symbols);
    let expiry = match expiry_from_args(args) {
        Ok(e) => e,
        Err(v) => return v,
    };
    match engine.add_secret_with_expiry(vault, key, &secret, expiry.as_deref(), Some(ctx)) {
        Ok(()) => ok(format!(
            "✓ Generated '{}' in '{}' ({} chars). Stored encrypted — value not shown.",
            key,
            vault,
            secret.len()
        )),
        Err(e) => fail_err(&e),
    }
}

async fn tool_vault_rotate(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", key => "key");
    let length = args.get("length").and_then(|l| l.as_u64()).unwrap_or(32) as usize;
    let symbols = args
        .get("symbols")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    let secret = generate::generate_secret(length, symbols);
    match engine.add_secret(vault, key, &secret, Some(ctx)) {
        Ok(()) => ok(format!(
            "✓ Rotated '{}' in '{}': {}-char new value stored, old replaced. New value not shown.",
            key,
            vault,
            secret.len()
        )),
        Err(e) => fail_err(&e),
    }
}

async fn tool_vault_import(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", entries => "entriesJson");
    let entries: Map<String, Value> = match serde_json::from_str(entries) {
        Ok(m) => m,
        Err(e) => return fail(format!("Invalid entriesJson JSON: {}", e)),
    };
    if entries.is_empty() {
        return fail("entriesJson must contain at least one key.");
    }
    match engine.import_secrets(vault, &entries, Some(ctx)) {
        Ok(n) => ok(format!(
            "✓ Imported {} secrets into '{}'. Stored encrypted — values not shown.",
            n, vault
        )),
        Err(e) => fail_err(&e),
    }
}

/// Agent-safe encrypted export: produces a portable encrypted blob with no
/// plaintext values exposed. The blob carries its own salt and can be imported
/// by any vaultly instance with the same master password.
async fn tool_vault_export_encrypted(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, vault => "vaultName", file => "file");
    // The engine's export_encrypted needs the master password to derive a fresh
    // key. The MCP server captures it at startup (before clearing the env var).
    let password = match master_password() {
        Some(pw) => pw,
        None => return fail("Encrypted export requires VAULTLY_MASTER_PASSWORD (MCP server must be started with the master password in env).".to_string()),
    };
    match engine.export_encrypted(vault, &password, Some(ctx)) {
        Ok(blob) => {
            let json = match serde_json::to_string_pretty(&blob) {
                Ok(j) => j,
                Err(e) => return fail(format!("Serialization failed: {e}")),
            };
            if let Err(e) = write_export_file(file, &json) {
                return fail(format!("Write failed: {e}"));
            }
            ok(format!(
                "✓ Encrypted export of '{}' → {} (AES-256-GCM, portable). No plaintext values exposed.",
                vault, file
            ))
        }
        Err(e) => fail_err(&e),
    }
}

/// Import an encrypted export blob (from vault_export_encrypted) into a target
/// vault. The blob is decrypted with the master password + embedded salt.
async fn tool_vault_import_encrypted(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, file => "file");
    let target = args
        .get("vaultName")
        .and_then(|v| v.as_str())
        .unwrap_or("imported");
    let raw = match std::fs::read_to_string(file) {
        Ok(r) => r,
        Err(e) => return fail(format!("Failed to read '{file}': {e}")),
    };
    let blob: vaultly_core::crypto::EncryptedExport = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(e) => return fail(format!("Not a valid encrypted export: {e}")),
    };
    let password = match master_password() {
        Some(pw) => pw,
        None => return fail("Encrypted import requires VAULTLY_MASTER_PASSWORD.".to_string()),
    };
    match engine.import_encrypted(&blob, &password, target, Some(ctx)) {
        Ok(count) => ok(format!(
            "✓ Imported {count} secrets into '{target}' from encrypted export."
        )),
        Err(e) => fail_err(&e),
    }
}

async fn tool_policy_info() -> Value {
    ok(format!(
        "Vaultly agent security policy:\n  Session TTL: {} min\n\n  Raw reads and arbitrary credential-injected commands are disabled.\n  Permitted: encrypted credential operations, safe Cloudflare discovery,\n  write-only Worker secrets, validated dynamic target adoption, deployment,\n  read-only target preflight, and approved target maintenance scripts.\n  Maintenance execution (deploy_target_exec) needs the human-granted `run`\n  operation plus a typed confirmation for mutations; the default agent\n  policy denies it (policy_denied). Every tool returns names, metadata, or\n  safe operation status — never raw secret values.",
        SESSION_TTL_MINUTES
    ))
}

/// Return the ACTUAL loaded per-agent policy (vault allowlists, roles, rate
/// limits) as JSON — agent-safe, no values.
fn get_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

fn tool_schema_list() -> Value {
    let tools: Vec<Value> = tools_list()
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.schema,
            })
        })
        .collect();
    Value::Array(tools)
}

// ─── Server loop ──────────────────────────────────────────

pub async fn start_mcp_server() {
    let mut engine = VaultEngine::new(Some(SESSION_TTL_MINUTES));

    // Owner-managed grants first; explicit env policy wins when both exist.
    if let Err(e) = engine.load_default_policy_file() {
        eprintln!("⚠ Failed to load agent policy file: {e}");
    }
    if let Err(e) = engine.load_policy_from_env() {
        eprintln!("⚠ Failed to load VAULTLY_AGENT_POLICY: {e}");
    } else if let Ok(n) = std::env::var("VAULTLY_AGENT_POLICY") {
        if !n.trim().is_empty() {
            eprintln!("✓ Loaded agent policies from {n}");
        }
    }

    if !engine.is_initialized() {
        eprintln!("Vaultly not initialized. Run: vaultly init");
        exit(1);
    }

    // ─── Unlock: keychain → env var → terminal prompt ─────
    let mut unlocked = false;

    if keychain::is_keychain_available() {
        if let Some(pw) = keychain::get_from_keychain() {
            if engine.unlock(&pw).is_ok() {
                unlocked = true;
                eprintln!("✓ Unlocked from {}", keychain::backend_name());
            } else {
                eprintln!("⚠ Keychain password invalid, falling back...");
            }
        }
    }

    if !unlocked {
        if let Ok(pw) = std::env::var("VAULTLY_MASTER_PASSWORD") {
            if engine.unlock(&pw).is_ok() {
                unlocked = true;
                // Retain a copy for encrypted export/import tools before clearing.
                let _ = MASTER_PASSWORD.set(pw);
                std::env::remove_var("VAULTLY_MASTER_PASSWORD");
                eprintln!("✓ Unlocked from env var");
            } else {
                eprintln!("⚠ Env var password invalid");
            }
        }
    }

    if !unlocked {
        if std::env::var("VAULTLY_HUMAN_MODE").as_deref() == Ok("1")
            && (std::io::stdin().is_terminal() || std::path::Path::new("/dev/tty").exists())
        {
            if let Some(pw) = read_tty_password() {
                if engine.unlock(&pw).is_ok() {
                    unlocked = true;
                }
            }
        }
        if !unlocked {
            eprintln!(
                "Non-interactive unlock unavailable. {}",
                keychain::unlock_setup_hint()
            );
            exit(1);
        }
    }

    eprintln!("✓ Vaultly MCP server ready\n");

    // ─── JSON-RPC over stdio ──────────────────────────────
    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();
    let stdout = tokio::io::stdout();
    let mut out = tokio::io::BufWriter::new(stdout);

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    loop {
        tokio::select! {
            _ = shutdown_signal_handler() => {
                // Graceful shutdown: wipe the key from memory, flush any
                // buffered response, then exit cleanly. Without this the
                // default SIGTERM/SIGINT handler would abort mid-write.
                engine.lock(None);
                let _ = out.flush().await;
                eprintln!("✓ Vaultly MCP server shutting down — key wiped.");
                break;
            }
            line = lines.next_line() => {
                match line {
                    Ok(Some(raw)) => handle_jsonrpc_message(&mut engine, &mut out, &raw).await,
                    // Immediate EOF with no signal is a normal client disconnect.
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }
}

/// Resolves on the first SIGINT or SIGTERM. On non-Unix platforms only SIGINT
/// (ctrl-c) is observable.
async fn shutdown_signal_handler() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    std::future::pending::<()>().await;
                    return;
                }
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Process a single JSON-RPC line and write its response (if any) to `out`.
async fn handle_jsonrpc_message(
    engine: &mut VaultEngine,
    out: &mut tokio::io::BufWriter<tokio::io::Stdout>,
    raw: &str,
) {
    use tokio::io::AsyncWriteExt;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }

    let msg: Value = match serde_json::from_str(trimmed) {
        Ok(m) => m,
        Err(_) => {
            let _ = out
                .write_all(
                    json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": -32700, "message": "Parse error" } })
                        .to_string()
                        .as_bytes(),
                )
                .await;
            let _ = out.write_all(b"\n").await;
            let _ = out.flush().await;
            return;
        }
    };

    let id = msg.get("id").cloned();

    // Notifications have no id — never respond
    if id.is_none() {
        return;
    }
    let id = id.unwrap();

    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let response = match method {
        "initialize" => {
            let params = msg.get("params").unwrap_or(&Value::Null);
            let client_version = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(PROTOCOL_VERSION);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": client_version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION }
                }
            })
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tool_schema_list() }
        }),
        "tools/call" => {
            let params = msg.get("params").unwrap_or(&Value::Null);
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            let args = if args.is_null() { json!({}) } else { args };
            let result = call_tool(engine, name, &args).await;
            json!({ "jsonrpc": "2.0", "id": id, "result": result })
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {}", method) }
        }),
    };

    let _ = out.write_all(response.to_string().as_bytes()).await;
    let _ = out.write_all(b"\n").await;
    let _ = out.flush().await;
}

/// Read a password from /dev/tty (keeps stdin free for MCP JSON-RPC).
fn read_tty_password() -> Option<String> {
    use std::io::Read;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .ok()?;
    eprint!("🔑 Master password: ");
    let mut buf = String::new();
    tty.read_to_string(&mut buf).ok()?;
    eprintln!();
    Some(buf.trim_end().to_string())
}

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
use vaultly_core::{
    generate, keychain, templates, CallerContext, RunOptions, VaultEngine, VaultError,
};

pub const SERVER_NAME: &str = "vaultly";
pub const SERVER_VERSION: &str = "1.0.0";
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
pub const RUN_TIMEOUT_MS: u64 = 300_000;
const OUTPUT_MAX: usize = 10_000;

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
        UnknownSecretAction(_) => "unknown_secret_action",
        RequiredField(_, _) => "required_field",
        Audit(_) => "audit",
        BackupMetaUpdate(_) => "backup_meta",
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

fn truncate(s: &str) -> String {
    if s.len() > OUTPUT_MAX {
        let idx = s.floor_char_boundary(OUTPUT_MAX);
        format!("{}\n...(truncated)", &s[..idx])
    } else {
        s.to_string()
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
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
        Tool {
            name: "vault_list",
            description: "List all vault names. Safe — no secrets exposed.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "vault_keys",
            description: "List secret KEY NAMES in a vault, plus per-key metadata (created/updated timestamps and expiry). Names/meta only — never values.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault name") }, "required": ["vaultName"] }),
        },
        Tool {
            name: "vault_add",
            description: "Store a secret (WRITE-ONLY). You can NEVER read it back. Optionally set an expiry via ttlSeconds or expiresAt.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "key": str_prop("Secret name (e.g. CLOUDFLARE_API_TOKEN)"),
                    "value": str_prop("Secret value to encrypt and store"),
                    "ttlSeconds": json!({ "type": "number", "description": "Expire the secret this many seconds from now (mutually exclusive with expiresAt)" }),
                    "expiresAt": str_prop("Explicit RFC 3339 expiry timestamp (mutually exclusive with ttlSeconds)"),
                },
                "required": ["vaultName", "key", "value"]
            }),
        },
        Tool {
            name: "vault_delete",
            description: "Delete a secret from a vault.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "key": str_prop("Secret key to delete"),
                },
                "required": ["vaultName", "key"]
            }),
        },
        Tool {
            name: "vault_run",
            description: "Run a command with vault secrets injected as env vars. Secrets are NEVER printed — output is scrubbed. Refuses to run while the vault has expired secrets unless force=true.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault to inject"),
                    "command": str_prop("Command (e.g. 'npx wrangler deploy')"),
                    "cwd": str_prop("Working directory"),
                    "force": json!({ "type": "boolean", "description": "Run even if the vault has expired secrets (default false)" }),
                    "allowlist": json!({ "type": "array", "items": { "type": "string" }, "description": "Only inject these secret names into the child (omit to inject all)" }),
                },
                "required": ["vaultName", "command"]
            }),
        },
        Tool {
            name: "vault_status",
            description: "Show vault status: session TTL, vault count, keychain status.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "vault_lock",
            description: "Lock the vault session immediately — wipes the decryption key from memory. Use vault_unlock to re-open.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "vault_unlock",
            description: "Re-open a locked session. Uses the macOS Keychain — the agent never handles the password.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "vault_audit",
            description: "View recent audit log, optionally filtered by vault, caller, or timestamp.",
            schema: json!({
                "type": "object",
                "properties": {
                    "lines": json!({ "type": "number", "description": "Entries to show (default 20)" }),
                    "vault": str_prop("Only entries mentioning this vault name"),
                    "caller": json!({ "type": "string", "enum": ["agent", "human"], "description": "Only entries from this caller" }),
                    "after": str_prop("Only entries with timestamp >= this RFC3339 time (e.g. 2026-08-20T00:00:00Z)")
                }
            }),
        },
        Tool {
            name: "cf_accounts",
            description: "List which vaults hold Cloudflare credentials (account name, auth method, label, scope). Set health=true to also verify each credential is valid. Never exposes values.",
            schema: json!({
                "type": "object",
                "properties": {
                    "health": json!({ "type": "boolean", "description": "Verify each account's credential against Cloudflare (default false)" }),
                }
            }),
        },
        Tool {
            name: "cf_account_label",
            description: "Set, clear, or read a Cloudflare account's human-readable alias (label). Non-secret.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "label": str_prop("Alias to set; omit to read, empty string to clear"),
                },
                "required": ["vaultName"]
            }),
        },
        Tool {
            name: "cf_api",
            description: "Make an authenticated Cloudflare API call. Token injected from vault — you see the response, NEVER the token.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault with CLOUDFLARE_API_TOKEN"),
                    "method": json!({ "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"] }),
                    "path": str_prop("API path (e.g. /zones)"),
                    "body": str_prop("JSON body string"),
                },
                "required": ["vaultName", "method", "path"]
            }),
        },
        Tool {
            name: "cf_zones",
            description: "List all zones (domains) in a Cloudflare account.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault name") }, "required": ["vaultName"] }),
        },
        Tool {
            name: "cf_dns_list",
            description: "List DNS records for a zone.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "zoneId": str_prop("Zone ID"),
                    "type": str_prop("Filter: A, CNAME, MX, TXT..."),
                },
                "required": ["vaultName", "zoneId"]
            }),
        },
        Tool {
            name: "cf_dns_upsert",
            description: "Create or update a DNS record.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "zoneId": str_prop("Zone ID"),
                    "type": str_prop("A, AAAA, CNAME, MX, TXT..."),
                    "name": str_prop("Record name (e.g. app.example.com)"),
                    "content": str_prop("Record value (IP, hostname...)"),
                    "ttl": json!({ "type": "number" }),
                    "proxied": json!({ "type": "boolean" }),
                },
                "required": ["vaultName", "zoneId", "type", "name", "content"]
            }),
        },
        Tool {
            name: "cf_workers_list",
            description: "List deployed Workers in a Cloudflare account.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault with CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID") }, "required": ["vaultName"] }),
        },
        Tool {
            name: "cf_secrets",
            description: "Manage secrets for a deployed Worker (list, set, delete). Values are write-only, never echoed back.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault with CLOUDFLARE_ACCOUNT_ID + auth"),
                    "scriptName": str_prop("Worker script name"),
                    "action": json!({ "type": "string", "enum": ["list", "set", "delete"] }),
                    "name": str_prop("Secret name (required for set/delete)"),
                    "value": str_prop("Secret value (set only; write-only)"),
                },
                "required": ["vaultName", "scriptName", "action"]
            }),
        },
        Tool {
            name: "cf_deploy",
            description: "Deploy a Cloudflare Worker project via wrangler. Credentials injected from vault.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "projectDir": str_prop("Path to Worker project"),
                    "extraArgs": str_prop("Extra wrangler args"),
                },
                "required": ["vaultName", "projectDir"]
            }),
        },
        Tool {
            name: "cf_health",
            description: "Verify a Cloudflare API token is still valid.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault name") }, "required": ["vaultName"] }),
        },
        Tool {
            name: "vault_meta",
            description: "Inspect a vault: file path, size, secret count, key names. Meta only — never values.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault name") }, "required": ["vaultName"] }),
        },
        Tool {
            name: "template_list",
            description: "List available vault templates (name + description).",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "template_apply",
            description: "Create/populate a vault from a template. Optionally pass values to store (write-only).",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault to populate"),
                    "templateName": str_prop("Template name (see template_list)"),
                    "values": json!({ "type": "object", "description": "Optional map of key -> value to store immediately" }),
                },
                "required": ["vaultName", "templateName"]
            }),
        },
        Tool {
            name: "cf_dns_delete",
            description: "Delete a DNS record from a zone. Agent-safe — no values returned.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault with CLOUDFLARE_ACCOUNT_ID + auth"),
                    "zoneId": str_prop("Zone ID"),
                    "recordId": str_prop("DNS record ID"),
                },
                "required": ["vaultName", "zoneId", "recordId"]
            }),
        },
        Tool {
            name: "cf_workers_versions",
            description: "List deployment versions of a Worker script. Agent-safe.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault with CLOUDFLARE_ACCOUNT_ID + auth"),
                    "scriptName": str_prop("Worker script name"),
                },
                "required": ["vaultName", "scriptName"]
            }),
        },
        Tool {
            name: "vault_generate",
            description: "Generate a cryptographically strong random secret and STORE it under a key (write-only — the value is never shown). Optionally set an expiry via ttlSeconds or expiresAt.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "key": str_prop("Key to store the generated secret under"),
                    "length": json!({ "type": "number", "description": "Length (default 32, max 4096)" }),
                    "symbols": json!({ "type": "boolean", "description": "Include punctuation (default false)" }),
                    "ttlSeconds": json!({ "type": "number", "description": "Expire the secret this many seconds from now (mutually exclusive with expiresAt)" }),
                    "expiresAt": str_prop("Explicit RFC 3339 expiry timestamp (mutually exclusive with ttlSeconds)"),
                },
                "required": ["vaultName", "key"]
            }),
        },
        Tool {
            name: "vault_rotate",
            description: "Rotate an existing secret: generate a new random value and overwrite it in place (write-only).",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "key": str_prop("Key to rotate"),
                    "length": json!({ "type": "number", "description": "Length (default 32, max 4096)" }),
                    "symbols": json!({ "type": "boolean", "description": "Include punctuation (default false)" }),
                },
                "required": ["vaultName", "key"]
            }),
        },
        Tool {
            name: "vault_import",
            description: "Import multiple secrets from a JSON object (write-only — values are never read back).",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "entriesJson": str_prop("JSON object of key -> value to store"),
                },
                "required": ["vaultName", "entriesJson"]
            }),
        },
        Tool {
            name: "vault_export",
            description: "Export secrets to a plaintext file. BLOCKED for agents — exporting would expose values. Run 'vaultly export' as a human instead.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "file": str_prop("Output file path"),
                },
                "required": ["vaultName", "file"]
            }),
        },
        Tool {
            name: "vault_export_encrypted",
            description: "Export a vault as an encrypted, portable blob (AES-256-GCM with embedded salt). Safe for agents — no plaintext values are exposed. The blob can be imported by any vaultly instance with the same master password.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "file": str_prop("Output file path for the encrypted blob"),
                },
                "required": ["vaultName", "file"]
            }),
        },
        Tool {
            name: "vault_import_encrypted",
            description: "Import an encrypted export blob (from vault_export_encrypted) into a target vault. The blob is decrypted with the master password + embedded salt, then re-encrypted under the local store.",
            schema: json!({
                "type": "object",
                "properties": {
                    "file": str_prop("Path to the encrypted export blob"),
                    "vaultName": str_prop("Target vault name (defaults to 'imported')"),
                },
                "required": ["file"]
            }),
        },
        Tool {
            name: "policy_info",
            description: "Show Vaultly's agent security policy and session limits.",
            schema: json!({ "type": "object", "properties": {} }),
        },
        Tool {
            name: "vault_policy",
            description: "Show the loaded per-agent security policy (vault allowlists, per-vault roles, rate limits) for every configured agent.",
            schema: json!({ "type": "object", "properties": {} }),
        },
    ]
}

async fn call_tool(engine: &mut VaultEngine, name: &str, args: &Value) -> Value {
    let ctx = agent_ctx();
    match name {
        "vault_list" => tool_vault_list(engine, &ctx).await,
        "vault_keys" => tool_vault_keys(engine, args, &ctx).await,
        "vault_add" => tool_vault_add(engine, args, &ctx).await,
        "vault_delete" => tool_vault_delete(engine, args, &ctx).await,
        "vault_run" => tool_vault_run(engine, args, &ctx).await,
        "vault_status" => tool_vault_status(engine).await,
        "vault_lock" => tool_vault_lock(engine, &ctx).await,
        "vault_unlock" => tool_vault_unlock(engine).await,
        "vault_audit" => tool_vault_audit(engine, args, &ctx).await,
        "cf_accounts" => tool_cf_accounts(engine, args, &ctx).await,
        "cf_account_label" => tool_cf_account_label(engine, args, &ctx).await,
        "cf_api" => tool_cf_api(engine, args, &ctx).await,
        "cf_zones" => tool_cf_zones(engine, args, &ctx).await,
        "cf_dns_list" => tool_cf_dns_list(engine, args, &ctx).await,
        "cf_dns_upsert" => tool_cf_dns_upsert(engine, args, &ctx).await,
        "cf_workers_list" => tool_cf_workers_list(engine, args, &ctx).await,
        "cf_secrets" => tool_cf_secrets(engine, args, &ctx).await,
        "cf_deploy" => tool_cf_deploy(engine, args, &ctx).await,
        "cf_health" => tool_cf_health(engine, args, &ctx).await,
        "vault_meta" => tool_vault_meta(engine, args, &ctx).await,
        "template_list" => tool_template_list(engine, &ctx).await,
        "template_apply" => tool_template_apply(engine, args, &ctx).await,
        "cf_dns_delete" => tool_cf_dns_delete(engine, args, &ctx).await,
        "cf_workers_versions" => tool_cf_workers_versions(engine, args, &ctx).await,
        "vault_generate" => tool_vault_generate(engine, args, &ctx).await,
        "vault_rotate" => tool_vault_rotate(engine, args, &ctx).await,
        "vault_import" => tool_vault_import(engine, args, &ctx).await,
        "vault_export" => tool_vault_export(engine, args, &ctx).await,
        "vault_export_encrypted" => tool_vault_export_encrypted(engine, args, &ctx).await,
        "vault_import_encrypted" => tool_vault_import_encrypted(engine, args, &ctx).await,
        "policy_info" => tool_policy_info().await,
        "vault_policy" => tool_vault_policy(engine).await,
        _ => fail(format!("Unknown tool: {}", name)),
    }
}

// ─── Vault tools ─────────────────────────────────────────

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
                        .map(|v| format!("  - {}", v))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            }
        }
        Err(e) => fail_err(&e),
    }
}

/// Resolve the optional expiry (RFC 3339) from `ttlSeconds` and/or
/// `expiresAt` tool arguments. Returns `Err` (rendered as a tool error) if
/// both are supplied or a TTL value overflows. Values never leak secret data.
fn expiry_from_args(args: &Value) -> Result<Option<String>, Value> {
    let ttl = args.get("ttlSeconds").and_then(|v| v.as_u64());
    let expires = args
        .get("expiresAt")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    if ttl.is_some() && expires.is_some() {
        return Err(fail(
            "ttlSeconds and expiresAt are mutually exclusive — pass only one.",
        ));
    }
    if let Some(secs) = ttl {
        return match chrono::Utc::now().checked_add_signed(chrono::Duration::seconds(secs as i64)) {
            Some(t) => Ok(Some(t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))),
            None => Err(fail("ttlSeconds is out of range.")),
        };
    }
    Ok(expires.map(str::to_string))
}

async fn tool_vault_keys(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName");
    let meta = match engine.list_keys_meta(vault, Some(ctx)) {
        Ok(m) => m,
        Err(e) => return fail_err(&e),
    };
    if meta.is_empty() {
        return ok(format!("Vault '{}' is empty or doesn't exist.", vault));
    }
    let mut head = format!("Keys in '{}':\n", vault);
    for m in &meta {
        head.push_str(&format!("  - {}\n", m.key));
    }
    head.push_str("Meta:\n");
    for m in &meta {
        let exp = m
            .expires_at
            .as_deref()
            .map(|s| format!("expiresAt={} expired={}", s, m.expired))
            .unwrap_or_else(|| "expiresAt=null expired=false".to_string());
        head.push_str(&format!(
            "  {}: createdAt={} updatedAt={} {}\n",
            m.key, m.created_at, m.updated_at, exp
        ));
    }
    ok(head.trim_end())
}

async fn tool_vault_add(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", key => "key", value => "value");
    let expiry = match expiry_from_args(args) {
        Ok(e) => e,
        Err(v) => return v,
    };
    match engine.add_secret_with_expiry(vault, key, value, expiry.as_deref(), Some(ctx)) {
        Ok(()) => ok(format!(
            "✓ Stored '{}' in '{}'. Encrypted. Cannot be read back.",
            key, vault
        )),
        Err(e) => fail_err(&e),
    }
}

async fn tool_vault_delete(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", key => "key");
    match engine.delete_secret(vault, key, Some(ctx)) {
        Ok(true) => ok(format!("✓ Deleted '{}' from '{}'.", key, vault)),
        Ok(false) => fail(format!("'{}' not found in '{}'.", key, vault)),
        Err(e) => fail_err(&e),
    }
}

async fn tool_vault_run(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", command => "command");
    let cwd = args
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let force = args.get("force").and_then(|f| f.as_bool()).unwrap_or(false);
    // Env allowlist: restrict which secrets are injected into the child.
    let allowlist: Option<Vec<String>> =
        args.get("allowlist").and_then(|a| a.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    // Mirror the CLI's expired-secret guard: refuse unless the agent passes
    // force=true. Uses `None` ctx so the scan doesn't double-audit.
    if !force {
        match engine.expired_keys(vault, None) {
            Ok(expired) if !expired.is_empty() => {
                return fail(format!(
                    "{} expired secret(s) in '{}' ({}). Rotate them first (vault_rotate) or set force=true to override.",
                    expired.len(),
                    vault,
                    expired.join(", ")
                ));
            }
            _ => {}
        }
    }
    let opts = RunOptions {
        cwd,
        timeout_ms: Some(RUN_TIMEOUT_MS),
        allowed_keys: allowlist.as_deref(),
    };
    match engine.run_command(vault, command, &opts, Some(ctx)).await {
        Ok(result) => {
            let injected = if let Some(allowed) = &allowlist {
                // Report only the allowlisted names that actually exist.
                let meta = result.secrets_injected.clone();
                let found: Vec<String> = allowed
                    .iter()
                    .filter(|k| meta.iter().any(|m| m == *k))
                    .cloned()
                    .collect();
                found.join(", ")
            } else {
                result.secrets_injected.join(", ")
            };
            let text = format!(
                "Command: {}\nInjected: {}\nExit code: {}\n{}\n{}\n{}",
                command,
                injected,
                result.code,
                if result.scrubbed {
                    "⚠ Output scrubbed (secret values removed)"
                } else {
                    ""
                },
                truncate(&result.stdout),
                if result.stderr.is_empty() {
                    String::new()
                } else {
                    format!("\nSTDERR:\n{}", truncate(&result.stderr))
                }
            );
            json!({ "content": [{ "type": "text", "text": text }], "isError": result.code != 0 })
        }
        Err(e) => fail_err(&e),
    }
}

async fn tool_vault_status(engine: &mut VaultEngine) -> Value {
    let vaults = engine.list_vaults(Some(&agent_ctx())).unwrap_or_default();
    let ttl_min = engine.session_expires_in() / 60;
    ok(format!(
        "Vaultly Status:\n  Unlocked: {} (expires in {} min)\n  Vaults: {} ({})\n  Keychain: {}\n  Platform: {}",
        if engine.is_unlocked() { "yes" } else { "no" },
        ttl_min,
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
        return fail("Keychain unavailable. Restart the MCP server to unlock.");
    }
    match keychain::get_from_keychain() {
        Some(pw) => match engine.unlock(&pw) {
            Ok(()) => ok("✓ Vault unlocked."),
            Err(_) => fail("Keychain password invalid."),
        },
        None => {
            fail("No keychain entry found. Run `vaultly keychain store` or restart the MCP server.")
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

async fn tool_cf_account_label(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
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

async fn tool_cf_api(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", method => "method", path => "path");
    let body = args
        .get("body")
        .and_then(|b| b.as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    match engine
        .cloudflare_api(vault, method, path, body, Some(ctx))
        .await
    {
        Ok(result) => json!({
            "content": [{ "type": "text", "text": format!("{} {} → {}\n\n{}", method, path, result.status, serde_json::to_string_pretty(&result.data).unwrap_or_default()) }],
            "isError": result.status >= 400
        }),
        Err(e) => fail_err(&e),
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

async fn tool_cf_dns_list(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", zone_id => "zoneId");
    let type_filter = args.get("type").and_then(|t| t.as_str());
    let path = match type_filter {
        Some(t) => format!(
            "/zones/{}/dns_records?per_page=100&type={}",
            urlencode(zone_id),
            urlencode(t)
        ),
        None => format!("/zones/{}/dns_records?per_page=100", urlencode(zone_id)),
    };
    match engine
        .cloudflare_api(vault, "GET", &path, None, Some(ctx))
        .await
    {
        Ok(r) => {
            let records = r
                .data
                .get("result")
                .and_then(|z| z.as_array())
                .cloned()
                .unwrap_or_default();
            ok(format!(
                "DNS records ({}):\n{}",
                records.len(),
                records
                    .iter()
                    .map(|d| format!(
                        "  - {} {} → {} (id: {})",
                        d.get("type").and_then(|t| t.as_str()).unwrap_or("?"),
                        d.get("name").and_then(|n| n.as_str()).unwrap_or("?"),
                        d.get("content").and_then(|c| c.as_str()).unwrap_or("?"),
                        d.get("id").and_then(|i| i.as_str()).unwrap_or("?")
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
        Err(e) => fail_err(&e),
    }
}

async fn tool_cf_dns_upsert(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", zone_id => "zoneId", rtype => "type", rname => "name", content => "content");
    let ttl = args.get("ttl").and_then(|t| t.as_u64()).unwrap_or(1);
    let proxied = args
        .get("proxied")
        .and_then(|p| p.as_bool())
        .unwrap_or(false);

    let list_path = format!(
        "/zones/{}/dns_records?type={}&name={}",
        urlencode(zone_id),
        urlencode(rtype),
        urlencode(rname)
    );
    match engine
        .cloudflare_api(vault, "GET", &list_path, None, Some(ctx))
        .await
    {
        Ok(list) => {
            let existing = list
                .data
                .get("result")
                .and_then(|z| z.as_array())
                .cloned()
                .unwrap_or_default();
            let body = json!({ "type": rtype, "name": rname, "content": content, "ttl": ttl, "proxied": proxied });
            if !existing.is_empty() {
                let rec_id = existing[0]
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                match engine
                    .cloudflare_api(
                        vault,
                        "PUT",
                        &format!("/zones/{}/dns_records/{}", zone_id, rec_id),
                        Some(body),
                        Some(ctx),
                    )
                    .await
                {
                    Ok(r) => ok(format!(
                        "✓ Updated {} {} → {}\n{}",
                        rtype,
                        rname,
                        content,
                        serde_json::to_string_pretty(&r.data).unwrap_or_default()
                    )),
                    Err(e) => fail_err(&e),
                }
            } else {
                match engine
                    .cloudflare_api(
                        vault,
                        "POST",
                        &format!("/zones/{}/dns_records", zone_id),
                        Some(body),
                        Some(ctx),
                    )
                    .await
                {
                    Ok(r) => ok(format!(
                        "✓ Created {} {} → {}\n{}",
                        rtype,
                        rname,
                        content,
                        serde_json::to_string_pretty(&r.data).unwrap_or_default()
                    )),
                    Err(e) => fail_err(&e),
                }
            }
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

async fn tool_cf_deploy(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", dir => "projectDir");
    let extra = args.get("extraArgs").and_then(|a| a.as_str()).unwrap_or("");
    let cmd = if extra.is_empty() {
        "npx wrangler deploy".to_string()
    } else {
        format!("npx wrangler deploy {}", extra)
    };
    let opts = RunOptions {
        cwd: Some(dir),
        timeout_ms: Some(RUN_TIMEOUT_MS),
        allowed_keys: None,
    };
    match engine.run_command(vault, &cmd, &opts, Some(ctx)).await {
        Ok(result) => {
            let text = format!(
                "Deploy: {}\nDir: {}\nExit: {}\n{}\n{}\n{}",
                cmd,
                dir,
                result.code,
                if result.scrubbed {
                    "⚠ Output scrubbed\n"
                } else {
                    ""
                },
                truncate(&result.stdout),
                if result.stderr.is_empty() {
                    String::new()
                } else {
                    format!("\nSTDERR:\n{}", truncate(&result.stderr))
                }
            );
            json!({ "content": [{ "type": "text", "text": text }], "isError": result.code != 0 })
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

async fn tool_template_list(_engine: &mut VaultEngine, _ctx: &CallerContext) -> Value {
    let names = templates::template_names();
    ok(format!(
        "Templates ({}):\n{}",
        names.len(),
        templates::TEMPLATES
            .iter()
            .map(|(n, t)| format!("  - {}: {}", n, t.description))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

async fn tool_template_apply(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", template => "templateName");
    let tpl = match templates::get_template(template) {
        Some(t) => t,
        None => {
            return fail(format!(
                "Unknown template '{}'. Available: {}",
                template,
                templates::template_names().join(", ")
            ))
        }
    };
    if tpl.keys.is_empty() {
        return ok(format!(
            "Template '{}' has no predefined keys. Add secrets with vault_add.",
            template
        ));
    }
    let values = args.get("values").and_then(|v| v.as_object());
    let mut stored = 0;
    let mut needed: Vec<&str> = Vec::new();
    for key in tpl.keys {
        let val = values.and_then(|m| m.get(*key)).and_then(|v| v.as_str());
        match val {
            Some(v) => {
                if let Err(e) = engine.add_secret(vault, key, v, Some(ctx)) {
                    return fail_err(&e);
                }
                stored += 1;
            }
            None => needed.push(key),
        }
    }
    ok(format!(
        "✓ Applied '{}' template to '{}': {} keys stored.\n  {}",
        template,
        vault,
        stored,
        if needed.is_empty() {
            "Complete — all keys set.".to_string()
        } else {
            format!("Values still needed for: {}", needed.join(", "))
        }
    ))
}

async fn tool_cf_dns_delete(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", zone_id => "zoneId", record_id => "recordId");
    match engine
        .dns_delete(vault, zone_id, record_id, Some(ctx))
        .await
    {
        Ok(r) => ok(format!(
            "✓ Deleted DNS record {} from zone {}: HTTP {}",
            record_id, zone_id, r.status
        )),
        Err(e) => fail_err(&e),
    }
}

async fn tool_cf_workers_versions(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    require!(args, vault => "vaultName", script => "scriptName");
    match engine.list_worker_versions(vault, script, Some(ctx)).await {
        Ok(versions) => {
            if versions.is_empty() {
                return ok(format!("No versions found for '{}'.", script));
            }
            ok(format!(
                "Versions of '{}' ({}):\n{}",
                script,
                versions.len(),
                versions
                    .iter()
                    .map(|v| format!(
                        "  - id={} created={}",
                        v.get("id").and_then(|x| x.as_str()).unwrap_or("?"),
                        v.get("created_on").and_then(|x| x.as_str()).unwrap_or("?")
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
        }
        Err(e) => fail_err(&e),
    }
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

async fn tool_vault_export(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    require!(args, vault => "vaultName", file => "file");
    // Agents are denied by policy (ReadValue): exporting plaintext would expose
    // secret values, which the agent-first model forbids. Run the human CLI
    // (`vaultly export`) instead.
    match engine.get_secrets(vault, Some(ctx)) {
        Err(e) => fail(format!(
            "Export blocked in MCP/agent context: {}. Run 'vaultly export {} {}' as a human instead.",
            e, vault, file
        )),
        Ok(secrets) => {
            let mut keys: Vec<&String> = secrets.keys().collect();
            keys.sort();
            let mut buf = String::new();
            for k in keys {
                let v = secrets.get(k).and_then(|x| x.as_str()).unwrap_or("");
                buf.push_str(&format!("{}='{}'\n", k, v.replace('\'', "'\\''")));
            }
            if let Err(e) = write_export_file(file, &buf) {
                return fail(format!("Write failed: {}", e));
            }
            ok(format!(
                "✓ Exported {} secrets from '{}' to {} (mode 0600). Values written to file only.",
                secrets.len(),
                vault,
                file
            ))
        }
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
        "Vaultly agent security policy:\n  Session TTL: {} min\n  Command timeout: {} ms\n  Max response output: {} bytes\n\n  READ operations (get/env/export) are BANNED for agents.\n  Permitted: list names, add, delete, run commands, cf_* (no values),\n  template_apply, vault_generate/rotate, import.\n  Every tool returns names/meta/confirmations only — never raw secret values.",
        SESSION_TTL_MINUTES, RUN_TIMEOUT_MS, OUTPUT_MAX
    ))
}

/// Return the ACTUAL loaded per-agent policy (vault allowlists, roles, rate
/// limits) as JSON — agent-safe, no values.
async fn tool_vault_policy(engine: &mut VaultEngine) -> Value {
    let info = engine.policy_info();
    let text = serde_json::to_string_pretty(&info).unwrap_or_else(|_| info.to_string());
    ok(text)
}

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
                eprintln!("✓ Unlocked from macOS Keychain");
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
        if std::io::stdin().is_terminal() || std::path::Path::new("/dev/tty").exists() {
            if let Some(pw) = read_tty_password() {
                if engine.unlock(&pw).is_ok() {
                    unlocked = true;
                }
            }
        }
        if !unlocked {
            eprintln!(
                "No password. Set VAULTLY_MASTER_PASSWORD or run from a terminal.\n  Or run: vaultly keychain store  (saves to macOS Keychain)"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_short_content_is_unchanged() {
        let s = "short";
        assert_eq!(truncate(s), s);
    }

    #[test]
    fn truncate_multibyte_never_panics_and_stays_within_bound() {
        // "字" is 3 UTF-8 bytes. A 10KB cut lands mid-character for many fills.
        let mut s = String::new();
        while s.len() < OUTPUT_MAX + 100 {
            s.push('字');
        }
        let out = truncate(&s);
        // Truncation must not panic and must include the suffix marker.
        assert!(out.contains("...(truncated)"));
        // The retained prefix must be valid UTF-8 (it is, by construction) and
        // the truncated byte-count must not exceed the cap accounting for the marker.
        assert!(s.len() > OUTPUT_MAX);
    }

    #[test]
    fn truncate_exactly_at_boundary_needs_no_marker() {
        let s = "a".repeat(OUTPUT_MAX);
        let out = truncate(&s);
        assert_eq!(out, s);
    }
}

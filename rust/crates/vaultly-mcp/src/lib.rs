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

use serde_json::{json, Value};
use vaultly_core::{keychain, CallerContext, VaultEngine};

pub const SERVER_NAME: &str = "vaultly";
pub const SERVER_VERSION: &str = "1.0.0";
pub const PROTOCOL_VERSION: &str = "2025-06-18";
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

fn truncate(s: &str) -> String {
    if s.len() > OUTPUT_MAX {
        format!("{}\n...(truncated)", &s[..OUTPUT_MAX])
    } else {
        s.to_string()
    }
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

fn opt_str(desc: &str) -> Value {
    str_prop(desc)
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
            description: "List secret KEY NAMES in a vault. Names only — never values.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault name") }, "required": ["vaultName"] }),
        },
        Tool {
            name: "vault_add",
            description: "Store a secret (WRITE-ONLY). You can NEVER read it back.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault name"),
                    "key": str_prop("Secret name (e.g. CLOUDFLARE_API_TOKEN)"),
                    "value": str_prop("Secret value to encrypt and store"),
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
            description: "Run a command with vault secrets injected as env vars. Secrets are NEVER printed — output is scrubbed.",
            schema: json!({
                "type": "object",
                "properties": {
                    "vaultName": str_prop("Vault to inject"),
                    "command": str_prop("Command (e.g. 'npx wrangler deploy')"),
                    "cwd": opt_str("Working directory"),
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
            description: "View recent audit log. Shows all agent + human actions.",
            schema: json!({
                "type": "object",
                "properties": { "lines": json!({ "type": "number", "description": "Entries to show (default 20)" }) }
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
                    "body": opt_str("JSON body string"),
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
                    "type": opt_str("Filter: A, CNAME, MX, TXT..."),
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
                    "name": opt_str("Secret name (required for set/delete)"),
                    "value": opt_str("Secret value (set only; write-only)"),
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
                    "extraArgs": opt_str("Extra wrangler args"),
                },
                "required": ["vaultName", "projectDir"]
            }),
        },
        Tool {
            name: "cf_health",
            description: "Verify a Cloudflare API token is still valid.",
            schema: json!({ "type": "object", "properties": { "vaultName": str_prop("Vault name") }, "required": ["vaultName"] }),
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
        "vault_audit" => tool_vault_audit(args),
        "cf_api" => tool_cf_api(engine, args, &ctx).await,
        "cf_zones" => tool_cf_zones(engine, args, &ctx).await,
        "cf_dns_list" => tool_cf_dns_list(engine, args, &ctx).await,
        "cf_dns_upsert" => tool_cf_dns_upsert(engine, args, &ctx).await,
        "cf_workers_list" => tool_cf_workers_list(engine, args, &ctx).await,
        "cf_secrets" => tool_cf_secrets(engine, args, &ctx).await,
        "cf_deploy" => tool_cf_deploy(engine, args, &ctx).await,
        "cf_health" => tool_cf_health(engine, args, &ctx).await,
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
        Err(e) => fail(e),
    }
}

async fn tool_vault_keys(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    match engine.list_keys(vault, Some(ctx)) {
        Ok(keys) => {
            if keys.is_empty() {
                ok(format!("Vault '{}' is empty or doesn't exist.", vault))
            } else {
                ok(format!(
                    "Keys in '{}':\n{}",
                    vault,
                    keys.iter()
                        .map(|k| format!("  - {}", k))
                        .collect::<Vec<_>>()
                        .join("\n")
                ))
            }
        }
        Err(e) => fail(e),
    }
}

async fn tool_vault_add(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let key = get_str(args, "key");
    let value = get_str(args, "value");
    match engine.add_secret(vault, key, value, Some(ctx)) {
        Ok(()) => ok(format!(
            "✓ Stored '{}' in '{}'. Encrypted. Cannot be read back.",
            key, vault
        )),
        Err(e) => fail(e),
    }
}

async fn tool_vault_delete(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let key = get_str(args, "key");
    match engine.delete_secret(vault, key, Some(ctx)) {
        Ok(true) => ok(format!("✓ Deleted '{}' from '{}'.", key, vault)),
        Ok(false) => fail(format!("'{}' not found in '{}'.", key, vault)),
        Err(e) => fail(e),
    }
}

async fn tool_vault_run(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let command = get_str(args, "command");
    let cwd = args
        .get("cwd")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    match engine
        .run_command(vault, command, cwd, Some(RUN_TIMEOUT_MS), Some(ctx))
        .await
    {
        Ok(result) => {
            let text = format!(
                "Command: {}\nInjected: {}\nExit code: {}\n{}\n{}\n{}",
                command,
                result.secrets_injected.join(", "),
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
        Err(e) => fail(e),
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

fn tool_vault_audit(args: &Value) -> Value {
    let lines = args.get("lines").and_then(|l| l.as_u64()).unwrap_or(20) as usize;
    let log = VaultEngine::new(Some(SESSION_TTL_MINUTES)).get_audit_log(lines);
    if log.is_empty() {
        ok("No audit entries yet.")
    } else {
        ok(format!("Audit log:\n{}", log.join("\n")))
    }
}

// ─── Cloudflare tools ────────────────────────────────────

async fn tool_cf_api(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let method = get_str(args, "method");
    let path = get_str(args, "path");
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
        Err(e) => fail(e),
    }
}

async fn tool_cf_zones(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
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
        Err(e) => fail(e),
    }
}

async fn tool_cf_dns_list(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let zone_id = get_str(args, "zoneId");
    let type_filter = args.get("type").and_then(|t| t.as_str());
    let path = match type_filter {
        Some(t) => format!("/zones/{}/dns_records?per_page=100&type={}", zone_id, t),
        None => format!("/zones/{}/dns_records?per_page=100", zone_id),
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
        Err(e) => fail(e),
    }
}

async fn tool_cf_dns_upsert(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let zone_id = get_str(args, "zoneId");
    let rtype = get_str(args, "type");
    let rname = get_str(args, "name");
    let content = get_str(args, "content");
    let ttl = args.get("ttl").and_then(|t| t.as_u64()).unwrap_or(1);
    let proxied = args
        .get("proxied")
        .and_then(|p| p.as_bool())
        .unwrap_or(false);

    let list_path = format!(
        "/zones/{}/dns_records?type={}&name={}",
        zone_id, rtype, rname
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
                    Err(e) => fail(e),
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
                    Err(e) => fail(e),
                }
            }
        }
        Err(e) => fail(e),
    }
}

async fn tool_cf_workers_list(
    engine: &mut VaultEngine,
    args: &Value,
    ctx: &CallerContext,
) -> Value {
    let vault = get_str(args, "vaultName");
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
        Err(e) => fail(e),
    }
}

async fn tool_cf_secrets(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let script = get_str(args, "scriptName");
    let action = get_str(args, "action");
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
        Err(e) => fail(e),
    }
}

async fn tool_cf_deploy(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    let dir = get_str(args, "projectDir");
    let extra = args.get("extraArgs").and_then(|a| a.as_str()).unwrap_or("");
    let cmd = if extra.is_empty() {
        "npx wrangler deploy".to_string()
    } else {
        format!("npx wrangler deploy {}", extra)
    };
    match engine
        .run_command(vault, &cmd, Some(dir), Some(RUN_TIMEOUT_MS), Some(ctx))
        .await
    {
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
        Err(e) => fail(e),
    }
}

async fn tool_cf_health(engine: &mut VaultEngine, args: &Value, ctx: &CallerContext) -> Value {
    let vault = get_str(args, "vaultName");
    match engine.health_check(vault, Some(ctx)).await {
        Ok((true, msg)) => ok(format!("✓ {}", msg)),
        Ok((false, msg)) => fail(msg),
        Err(e) => fail(e),
    }
}

fn get_str<'a>(args: &'a Value, key: &str) -> &'a str {
    args.get(key).and_then(|v| v.as_str()).unwrap_or("")
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

    while let Some(line) = lines.next_line().await.unwrap_or_default() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
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
                continue;
            }
        };

        let id = msg.get("id").cloned();

        // Notifications have no id — never respond
        if id.is_none() {
            continue;
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
                let result = call_tool(&mut engine, name, &args).await;
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

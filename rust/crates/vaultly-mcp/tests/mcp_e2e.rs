//! End-to-end MCP server tests — the security-critical surface.
//! Spawns the real `vaultly-mcp` binary over stdio and drives it with JSON-RPC.
//! Verifies the core guarantee: NO tool returns a raw secret value.
//! Ported from test/mcp.test.ts.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

const PASSWORD: &str = "mcp-test-password";
const SECRET_VALUE: &str = "sk-e2e-super-secret-token-1234567890";
const SECRET_KEY: &str = "E2E_SECRET_KEY";
const EXPECTED_TOOLS: [&str; 31] = [
    "cf_account_label",
    "cf_accounts",
    "cf_d1_list",
    "cf_health",
    "cf_kv_list",
    "cf_pages_projects",
    "cf_r2_list",
    "cf_secrets",
    "cf_workers_list",
    "cf_zones",
    "deploy_target",
    "deploy_target_adopt",
    "deploy_target_exec",
    "deploy_target_preflight",
    "deploy_targets",
    "github_secret_sync",
    "policy_info",
    "vault_add",
    "vault_audit",
    "vault_delete",
    "vault_export_encrypted",
    "vault_generate",
    "vault_import",
    "vault_import_encrypted",
    "vault_keys",
    "vault_list",
    "vault_lock",
    "vault_meta",
    "vault_rotate",
    "vault_status",
    "vault_unlock",
];

struct McpClient {
    _child: tokio::process::Child,
    stdin: BufWriter<tokio::process::ChildStdin>,
    stdout: BufReader<tokio::process::ChildStdout>,
}

impl McpClient {
    async fn start(dir: &std::path::Path) -> Self {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_vaultly-mcp"))
            .env("VAULTLY_DIR", dir)
            .env("VAULTLY_MASTER_PASSWORD", PASSWORD)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        tokio::spawn(async move {
            let mut err = BufReader::new(stderr).lines();
            while let Ok(Some(_line)) = err.next_line().await {}
        });
        let stdin = BufWriter::new(child.stdin.take().unwrap());
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut client = McpClient {
            _child: child,
            stdin,
            stdout,
        };
        client.call(1, "initialize", json!({})).await;
        client
    }

    async fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.stdin
            .write_all(serde_json::to_string(&msg).unwrap().as_bytes())
            .await
            .unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }

    async fn call_tool(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.call(id, "tools/call", json!({ "name": name, "arguments": args }))
            .await
    }

    fn result_text(&self, res: &Value) -> String {
        res["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

#[tokio::test]
async fn mcp_e2e_security_surface() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let store = vaultly_core::vault::VaultStore::with_dir(dir.path().to_path_buf());
        store.init_vault(PASSWORD).unwrap();

        let mut mcp = McpClient::start(dir.path()).await;

        // 1. Exposes exactly the documented tools
        let res = mcp.call(2, "tools/list", json!({})).await;
        let mut names: Vec<String> = res["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        let mut expected: Vec<String> = EXPECTED_TOOLS.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(names, expected);

        // 2. No tool returns a raw secret value
        for t in res["result"]["tools"].as_array().unwrap() {
            let desc = t["description"].as_str().unwrap_or("").to_lowercase();
            assert!(!desc.contains("raw value"), "tool {}: {}", t["name"], desc);
            assert!(!desc.contains("raw secret"), "tool {}: {}", t["name"], desc);
        }

        // 3. cf_secrets requires name/value for set
        let res = mcp
            .call_tool(
                3,
                "cf_secrets",
                json!({ "vaultName": "e2e", "scriptName": "w", "action": "set" }),
            )
            .await;
        let text = serde_json::to_string(&res).unwrap();
        assert!(text.contains("'name' is required"), "{}", text);

        // 4. Stores a secret (write-only) and lists only its name
        let res = mcp
            .call_tool(
                4,
                "vault_add",
                json!({ "vaultName": "e2e", "key": SECRET_KEY, "value": SECRET_VALUE }),
            )
            .await;
        let text = serde_json::to_string(&res).unwrap();
        assert!(!text.contains(SECRET_VALUE), "{}", text);
        assert!(text.contains("Stored"), "{}", text);

        let res = mcp
            .call_tool(5, "vault_keys", json!({ "vaultName": "e2e" }))
            .await;
        let text = serde_json::to_string(&res).unwrap();
        assert!(text.contains(SECRET_KEY), "{}", text);
        assert!(!text.contains(SECRET_VALUE), "{}", text);

        // 5. Arbitrary command execution is disabled for agents. Scrubbing
        // alone is not a sufficient boundary because a child process could
        // inspect the injected environment before output reaches Vaultly.
        let res = mcp
            .call_tool(
                6,
                "vault_run",
                json!({ "vaultName": "e2e", "command": format!("sh -c \"echo ${}\"", SECRET_KEY) }),
            )
            .await;
        let text = serde_json::to_string(&res).unwrap();
        assert!(!text.contains(SECRET_VALUE), "{}", text);
        assert!(text.contains("disabled for agents"), "{}", text);

        // 6. Lets agents lock and reports locked status
        let res = mcp.call_tool(7, "vault_lock", json!({})).await;
        assert!(
            mcp.result_text(&res).to_lowercase().contains("lock"),
            "{}",
            res
        );
        let res = mcp.call_tool(8, "vault_status", json!({})).await;
        assert!(mcp.result_text(&res).contains("Unlocked: no"), "{}", res);

        // 7. Rejects raw-value reads that don't exist (no vault_get tool)
        let res = mcp.call(9, "tools/list", json!({})).await;
        let names: Vec<String> = res["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        assert!(!names.contains(&"vault_get".to_string()));
        assert!(!names.contains(&"get".to_string()));
        assert!(!names.contains(&"env".to_string()));

        // 8. Audits agent actions with agent attribution
        let res = mcp
            .call_tool(10, "vault_audit", json!({ "lines": 20 }))
            .await;
        let text = mcp.result_text(&res);
        assert!(text.contains("\"action\":\"ADD\""), "{}", text);
        assert!(text.contains("\"agent\":\"mcp-agent\""), "{}", text);
        assert!(text.contains("\"caller\":\"agent\""), "{}", text);
    })
    .await
    .expect("MCP e2e test timed out");
}

const MARKER_VALUE: &str = "sk-mcp-write-read-marker-9f8e7d6c5b4a";

async fn new_client(dir: &std::path::Path) -> McpClient {
    // Initialize a vault so the server unlocks with VAULTLY_MASTER_PASSWORD.
    let store = vaultly_core::vault::VaultStore::with_dir(dir.to_path_buf());
    store.init_vault(PASSWORD).unwrap();
    McpClient::start(dir).await
}

#[tokio::test]
async fn mcp_vault_write_read_cycle_no_leak() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // vault_list is empty before anything is stored.
        let res = mcp.call_tool(2, "vault_list", json!({})).await;
        let text = mcp.result_text(&res);
        assert!(text.contains("No vaults"), "{}", text);

        // vault_add stores a secret bearing a distinctive marker value.
        let res = mcp
            .call_tool(
                3,
                "vault_add",
                json!({ "vaultName": "e2e", "key": SECRET_KEY, "value": MARKER_VALUE }),
            )
            .await;
        let add_text = serde_json::to_string(&res).unwrap();
        assert!(!add_text.contains(MARKER_VALUE), "{}", add_text);
        assert!(add_text.contains("Stored"), "{}", add_text);

        // vault_keys returns only the key NAME.
        let res = mcp
            .call_tool(4, "vault_keys", json!({ "vaultName": "e2e" }))
            .await;
        let keys_text = serde_json::to_string(&res).unwrap();
        assert!(keys_text.contains(SECRET_KEY), "{}", keys_text);
        // The marker VALUE must never appear in any response.
        assert!(!keys_text.contains(MARKER_VALUE), "{}", keys_text);

        // Clean up: vault_delete removes the secret.
        let res = mcp
            .call_tool(
                5,
                "vault_delete",
                json!({ "vaultName": "e2e", "key": SECRET_KEY }),
            )
            .await;
        let del_text = serde_json::to_string(&res).unwrap();
        assert!(del_text.contains("Deleted"), "{}", del_text);
        assert!(!del_text.contains(MARKER_VALUE), "{}", del_text);

        // Final sweep: every response captured above is free of the marker.
        for t in [add_text, keys_text, del_text] {
            assert!(!t.contains(MARKER_VALUE), "secret leaked: {}", t);
        }
    })
    .await
    .expect("mcp_vault_write_read_cycle_no_leak timed out");
}

#[tokio::test]
async fn mcp_cf_accounts_lists_without_values() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // No CF credentials yet → cf_accounts reports none.
        let res = mcp.call_tool(2, "cf_accounts", json!({})).await;
        let text = mcp.result_text(&res);
        assert!(text.contains("No Cloudflare accounts"), "{}", text);

        // Store CF credentials (token + account id) for a personal account.
        mcp.call_tool(
            3,
            "vault_add",
            json!({ "vaultName": "cf-personal", "key": "CLOUDFLARE_API_TOKEN", "value": MARKER_VALUE }),
        )
        .await;
        mcp.call_tool(
            4,
            "vault_add",
            json!({ "vaultName": "cf-personal", "key": "CLOUDFLARE_ACCOUNT_ID", "value": "acc-123" }),
        )
        .await;

        // cf_accounts now discovers the account: name + auth method + account-id,
        // but NEVER the token value.
        let res = mcp.call_tool(5, "cf_accounts", json!({})).await;
        let full = serde_json::to_string(&res).unwrap();
        let text = mcp.result_text(&res);
        assert!(text.contains("cf-personal"), "{}", text);
        assert!(text.contains("token"), "{}", text);
        assert!(text.contains("account-id"), "{}", text);
        // The credential VALUE must never appear in any response.
        assert!(!full.contains(MARKER_VALUE), "secret leaked: {}", full);
    })
    .await
    .expect("mcp_cf_accounts_lists_without_values timed out");
}

#[tokio::test]
async fn mcp_cf_account_label_and_scope() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // Store CF credentials for a personal account.
        mcp.call_tool(
            2,
            "vault_add",
            json!({ "vaultName": "cf-personal", "key": "CLOUDFLARE_API_TOKEN", "value": MARKER_VALUE }),
        )
        .await;
        mcp.call_tool(
            3,
            "vault_add",
            json!({ "vaultName": "cf-personal", "key": "CLOUDFLARE_ACCOUNT_ID", "value": "acc-123" }),
        )
        .await;

        // Scope is surfaced: default agent policy grants cf-api + deploy.
        let res = mcp.call_tool(4, "cf_accounts", json!({})).await;
        let text = mcp.result_text(&res);
        assert!(text.contains("cf-api+deploy"), "{}", text);
        assert!(text.contains("account-id"), "{}", text);

        // Set a label, then read it back.
        let res = mcp
            .call_tool(
                5,
                "cf_account_label",
                json!({ "vaultName": "cf-personal", "label": "Personal" }),
            )
            .await;
        let text = mcp.result_text(&res);
        assert!(text.contains("Personal"), "{}", text);

        let res = mcp
            .call_tool(6, "cf_account_label", json!({ "vaultName": "cf-personal" }))
            .await;
        let text = mcp.result_text(&res);
        assert!(text.contains("Personal"), "{}", text);

        // The label now appears in cf_accounts, and no secret value leaks.
        let res = mcp.call_tool(7, "cf_accounts", json!({})).await;
        let full = serde_json::to_string(&res).unwrap();
        let text = mcp.result_text(&res);
        assert!(text.contains("[Personal]"), "{}", text);
        assert!(!full.contains(MARKER_VALUE), "secret leaked: {}", full);

        // Empty label clears it.
        let res = mcp
            .call_tool(
                8,
                "cf_account_label",
                json!({ "vaultName": "cf-personal", "label": "" }),
            )
            .await;
        let text = mcp.result_text(&res);
        assert!(text.contains("Cleared"), "{}", text);
        let res = mcp.call_tool(9, "cf_accounts", json!({})).await;
        let text = mcp.result_text(&res);
        assert!(!text.contains("Personal"), "{}", text);
    })
    .await
    .expect("mcp_cf_account_label_and_scope timed out");
}

#[tokio::test]
async fn mcp_policy_limits_info() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // policy_info reports the security-policy limits without erroring.
        let res = mcp.call_tool(2, "policy_info", json!({})).await;
        assert!(
            res.get("result").and_then(|r| r.get("isError")).is_none(),
            "policy_info unexpectedly errored: {}",
            res
        );
        let text = mcp.result_text(&res);
        // Policy summary exposes the session boundary and safe operation model.
        assert!(text.contains("Session TTL"), "{}", text);
        assert!(
            text.contains("arbitrary credential-injected commands"),
            "{}",
            text
        );
        // No secret value can appear in a policy summary.
        assert!(!text.contains(SECRET_VALUE), "{}", text);
        assert!(!text.contains(MARKER_VALUE), "{}", text);
    })
    .await
    .expect("mcp_policy_limits_info timed out");
}

#[tokio::test]
async fn mcp_audit_records_and_chain() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // Perform a handful of actions so the audit log has recorded entries.
        mcp.call_tool(
            2,
            "vault_add",
            json!({ "vaultName": "e2e", "key": SECRET_KEY, "value": MARKER_VALUE }),
        )
        .await;
        mcp.call_tool(
            3,
            "vault_generate",
            json!({ "vaultName": "e2e", "key": "E2E_ROTATED", "length": 40 }),
        )
        .await;
        mcp.call_tool(
            4,
            "vault_delete",
            json!({ "vaultName": "e2e", "key": "E2E_ROTATED" }),
        )
        .await;

        let res = mcp
            .call_tool(5, "vault_audit", json!({ "lines": 50 }))
            .await;
        let text = mcp.result_text(&res);
        // The audit log records the action names we just performed.
        assert!(text.contains("\"action\":\"ADD\""), "{}", text);
        // The tamper-evidence hash chain is verified intact.
        assert!(text.contains("audit chain intact"), "{}", text);
        // Audit (and every response) never exposes the secret value.
        assert!(!text.contains(MARKER_VALUE), "{}", text);
        assert!(!text.contains(SECRET_VALUE), "{}", text);
    })
    .await
    .expect("mcp_audit_records_and_chain timed out");
}

#[tokio::test]
async fn mcp_generate_rotates_and_shape() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // vault_generate is local (no Cloudflare account needed): it creates a
        // random secret client-side and stores it encrypted.
        let res = mcp
            .call_tool(
                2,
                "vault_generate",
                json!({ "vaultName": "e2e", "key": SECRET_KEY, "length": 40 }),
            )
            .await;
        let gen_text = serde_json::to_string(&res).unwrap();
        assert!(gen_text.contains("Generated"), "{}", gen_text);
        assert!(gen_text.contains("value not shown"), "{}", gen_text);

        // vault_rotate replaces the existing value; still no value leaked.
        let res = mcp
            .call_tool(
                3,
                "vault_rotate",
                json!({ "vaultName": "e2e", "key": SECRET_KEY, "length": 48 }),
            )
            .await;
        let rot_text = serde_json::to_string(&res).unwrap();
        assert!(rot_text.contains("Rotated"), "{}", rot_text);
        assert!(rot_text.contains("New value not shown"), "{}", rot_text);

        for t in [gen_text, rot_text] {
            assert!(!t.contains(MARKER_VALUE), "{}", t);
            assert!(!t.contains(SECRET_VALUE), "{}", t);
        }
    })
    .await
    .expect("mcp_generate_rotates_and_shape timed out");
}

#[tokio::test]
async fn mcp_encrypted_export_import_roundtrip() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let export_dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // 1. Add secrets
        mcp.call_tool(
            1,
            "vault_add",
            json!({ "vaultName": "xport", "key": "API_KEY", "value": SECRET_VALUE }),
        )
        .await;
        mcp.call_tool(
            2,
            "vault_add",
            json!({ "vaultName": "xport", "key": "TOKEN", "value": "another-secret-12345" }),
        )
        .await;

        // 2. Encrypted export — must NOT contain plaintext
        let export_file = export_dir.path().join("blob.vaultly");
        let res = mcp
            .call_tool(
                3,
                "vault_export_encrypted",
                json!({ "vaultName": "xport", "file": export_file.to_str().unwrap() }),
            )
            .await;
        assert!(
            mcp.result_text(&res).contains("Encrypted export"),
            "export failed: {}",
            res
        );

        let raw = std::fs::read_to_string(&export_file).unwrap();
        assert!(
            !raw.contains(SECRET_VALUE),
            "encrypted export leaked plaintext: {}",
            raw
        );

        // 3. Encrypted import into a new vault
        let res = mcp
            .call_tool(
                4,
                "vault_import_encrypted",
                json!({ "file": export_file.to_str().unwrap(), "vaultName": "imported" }),
            )
            .await;
        assert!(
            mcp.result_text(&res).contains("Imported"),
            "import failed: {}",
            res
        );

        // 4. Verify the imported keys are listed (names only, no values)
        let res = mcp
            .call_tool(5, "vault_keys", json!({ "vaultName": "imported" }))
            .await;
        let text = mcp.result_text(&res);
        assert!(
            text.contains("API_KEY"),
            "API_KEY missing after import: {}",
            text
        );
        assert!(
            text.contains("TOKEN"),
            "TOKEN missing after import: {}",
            text
        );
        assert!(
            !text.contains(SECRET_VALUE),
            "value leaked via vault_keys: {}",
            text
        );
    })
    .await
    .expect("mcp_encrypted_export_import_roundtrip timed out");
}

#[tokio::test]
async fn mcp_unknown_tool_returns_error() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // A bogus tool name must yield a structured error, not a crash.
        let res = mcp
            .call_tool(2, "vault_get_raw_value", json!({ "vaultName": "e2e" }))
            .await;
        assert_eq!(res["result"]["isError"], true, "{}", res);
        assert!(mcp.result_text(&res).contains("Unknown tool"), "{}", res);

        // The server survives the error and keeps serving subsequent calls.
        let ping = mcp.call(3, "ping", json!({})).await;
        assert!(ping.get("result").is_some(), "{}", ping);
        let res = mcp.call_tool(4, "vault_status", json!({})).await;
        assert!(mcp.result_text(&res).contains("Unlocked"), "{}", res);
    })
    .await
    .expect("mcp_unknown_tool_returns_error timed out");
}

#[tokio::test]
async fn mcp_target_exec_and_preflight_reject_unknown_targets() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let mut mcp = new_client(dir.path()).await;

        // Unknown target IDs fail cleanly without touching the network.
        let res = mcp
            .call_tool(
                2,
                "deploy_target_exec",
                json!({ "targetId": "no-such-target", "script": "watchdog" }),
            )
            .await;
        assert!(mcp.result_text(&res).contains("was not found"), "{}", res);

        let res = mcp
            .call_tool(
                3,
                "deploy_target_preflight",
                json!({ "targetId": "no-such-target" }),
            )
            .await;
        assert!(mcp.result_text(&res).contains("was not found"), "{}", res);

        // Missing required args are reported, not panics.
        let res = mcp
            .call_tool(4, "deploy_target_exec", json!({ "targetId": "x" }))
            .await;
        assert!(
            mcp.result_text(&res)
                .contains("Missing required argument 'script'"),
            "{}",
            res
        );
    })
    .await
    .expect("mcp_target_exec_and_preflight_reject_unknown_targets timed out");
}

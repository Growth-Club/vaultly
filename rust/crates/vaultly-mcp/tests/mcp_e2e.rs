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

const EXPECTED_TOOLS: [&str; 17] = [
    "cf_api",
    "cf_deploy",
    "cf_dns_list",
    "cf_dns_upsert",
    "cf_health",
    "cf_secrets",
    "cf_workers_list",
    "cf_zones",
    "vault_add",
    "vault_audit",
    "vault_delete",
    "vault_keys",
    "vault_list",
    "vault_lock",
    "vault_run",
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

        // 1. Exposes exactly the 17 documented tools
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

        // 5. Scrubs secret values from command output
        let res = mcp
            .call_tool(
                6,
                "vault_run",
                json!({ "vaultName": "e2e", "command": format!("sh -c \"echo ${}\"", SECRET_KEY) }),
            )
            .await;
        let text = serde_json::to_string(&res).unwrap();
        assert!(!text.contains(SECRET_VALUE), "{}", text);
        assert!(text.contains("[REDACTED]"), "{}", text);

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

//! HTTP/REST integration tests for `vaultly serve` (Phase C).
//!
//! Drives the compiled `vaultly serve` binary against an isolated temp
//! `VAULTLY_DIR`, then exercises every endpoint with `reqwest`. Mirrors the
//! `cli.rs` env-lock + temp-dir pattern and asserts the agent-first invariant
//! end to end: no endpoint ever returns the stored secret value.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Output};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::time::sleep;

/// Master password (>= the 8-char minimum enforced by `init`).
const PASSWORD: &str = "test-master-password-1234";
/// A secret stored in the vault. It must never appear in ANY HTTP response.
const SECRET: &str = "http-s3cr3t-should-not-leak";
/// Bearer token the server is launched with.
const TOKEN: &str = "test-bearer-token";

/// Global lock guarding the process-level `VAULTLY_DIR` / password env vars.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct VaultlyEnv {
    _guard: std::sync::MutexGuard<'static, ()>,
    dir: TempDir,
}

impl VaultlyEnv {
    fn new() -> Self {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()); // a prior failed test may have poisoned it
        let dir = tempfile::tempdir().expect("make tempdir");
        std::env::set_var("VAULTLY_DIR", dir.path());
        std::env::set_var("VAULTLY_MASTER_PASSWORD", PASSWORD);
        std::env::set_var("NO_COLOR", "1");
        VaultlyEnv { _guard, dir }
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for VaultlyEnv {
    fn drop(&mut self) {
        std::env::remove_var("VAULTLY_DIR");
        std::env::remove_var("VAULTLY_MASTER_PASSWORD");
        std::env::remove_var("NO_COLOR");
    }
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vaultly"))
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("spawn vaultly binary")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
}

fn init(_env: &VaultlyEnv) {
    assert_ok(&run(&["init"]));
}

/// Grab an ephemeral free port for the test server.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    l.local_addr().expect("local addr").port()
}

/// Owns the spawned `vaultly serve` child and guarantees it is killed+reaped
/// (also during test unwind), so no orphaned server holds the port or the
/// cargo output pipe open.
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `vaultly serve` on a fresh port; returns the guard + base URL.
fn spawn_server() -> (ServerGuard, String) {
    let port = free_port();
    let base = format!("http://127.0.0.1:{port}");
    let child = bin()
        .arg("serve")
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--token")
        .arg(TOKEN)
        .spawn()
        .expect("spawn vaultly serve");
    (ServerGuard(child), base)
}

/// Poll `/health` until the server accepts requests.
async fn wait_ready(client: &reqwest::Client, base: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(r) = client.get(format!("{base}/health")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "vaultly serve did not become ready in time"
        );
        sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn endpoints_are_authed_and_agent_safe() {
    let env = VaultlyEnv::new();
    init(&env);

    const VAULT: &str = "httpvault";
    const KEY: &str = "API_KEY";
    assert_ok(&run(&["add", VAULT, "-k", KEY, "-v", SECRET]));

    let (_server, base) = spawn_server();
    let client = reqwest::Client::new();
    wait_ready(&client, &base).await;

    // ── Auth: no token → 401 on every endpoint ──
    let unauth = client
        .get(format!("{base}/vaults"))
        .send()
        .await
        .expect("reqwest");
    assert_eq!(
        unauth.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "missing token must be rejected"
    );

    // ── /health: ok, unlocked ──
    let health = client
        .get(format!("{base}/health"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("reqwest");
    assert!(health.status().is_success());
    let health_body = health.json::<serde_json::Value>().await.unwrap();
    assert_eq!(health_body["status"], "ok");

    // ── /vaults: names only, no values ──
    let vaults = client
        .get(format!("{base}/vaults"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("reqwest");
    assert!(vaults.status().is_success());
    let vaults_text = vaults.text().await.unwrap();
    assert!(vaults_text.contains(VAULT), "vault name missing");
    assert!(!vaults_text.contains(SECRET), "/vaults leaked a value");

    // ── /keys: names + metadata only, no values ──
    let keys = client
        .get(format!("{base}/keys"))
        .query(&[("vault", VAULT)])
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("reqwest");
    assert!(keys.status().is_success());
    let keys_text = keys.text().await.unwrap();
    assert!(keys_text.contains(KEY), "key name missing");
    assert!(keys_text.contains("expired"), "metadata missing");
    assert!(!keys_text.contains(SECRET), "/keys leaked a value");

    // ── /add: write-only, never echoes the value ──
    let add = client
        .post(format!("{base}/add"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({
            "vault": VAULT,
            "key": "NEW_K",
            "value": "brand-new-value",
        }))
        .send()
        .await
        .expect("reqwest");
    assert!(add.status().is_success());
    let add_body = add.json::<serde_json::Value>().await.unwrap();
    assert_eq!(add_body["stored"], true);
    assert_eq!(add_body["key"], "NEW_K");
    assert!(
        !add_body.to_string().contains("brand-new-value"),
        "/add echoed value"
    );

    // ── /run: scrubbed output, no values ──
    let run = client
        .post(format!("{base}/run"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({
            "vault": VAULT,
            "command": "/usr/bin/printenv API_KEY",
        }))
        .send()
        .await
        .expect("reqwest");
    assert!(run.status().is_success());
    let run_text = run.text().await.unwrap();
    assert!(!run_text.contains(SECRET), "/run leaked a value");

    // ServerGuard::drop kills the child; `env` cleans up env vars afterwards.
    let _dir = env.dir();
}

#[tokio::test]
async fn rotate_expired_via_http() {
    let env = VaultlyEnv::new();
    init(&env);

    const VAULT: &str = "rotatehttp";
    const OLD: &str = "OLD_KEY";
    const LIVE: &str = "LIVE_KEY";
    assert_ok(&run(&[
        "add",
        VAULT,
        "-k",
        OLD,
        "-v",
        SECRET,
        "--expires",
        "2000-01-01T00:00:00Z",
    ]));
    assert_ok(&run(&["add", VAULT, "-k", LIVE, "-v", SECRET]));

    let (_server, base) = spawn_server();
    let client = reqwest::Client::new();
    wait_ready(&client, &base).await;

    // /rotate-expired only touches the expired key.
    let rot = client
        .post(format!("{base}/rotate-expired"))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({ "vault": VAULT }))
        .send()
        .await
        .expect("reqwest");
    assert!(rot.status().is_success());
    let rot_body = rot.json::<serde_json::Value>().await.unwrap();
    assert_eq!(rot_body["count"], 1, "only the expired key should rotate");
    let rotated = rot_body["rotated"].as_array().expect("rotated array");
    assert_eq!(rotated[0], OLD, "OLD_KEY should be rotated");
    assert_eq!(rotated.len(), 1);
    assert!(
        !rot_body.to_string().contains(SECRET),
        "/rotate-expired leaked a value"
    );

    // The live key is untouched; OLD_KEY now has a fresh value and no expiry.
    let keys = client
        .get(format!("{base}/keys"))
        .query(&[("vault", VAULT)])
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("reqwest")
        .text()
        .await
        .unwrap();
    assert!(keys.contains(LIVE), "live key disappeared");
    assert!(keys.contains(OLD), "rotated key name still listed");
    assert!(!keys.contains(SECRET));

    let _dir = env.dir();
}

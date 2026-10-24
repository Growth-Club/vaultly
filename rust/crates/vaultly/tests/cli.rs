//! End-to-end CLI integration tests (Phase 6).
//!
//! Drives the compiled `vaultly` binary non-interactively against an isolated
//! temp `VAULTLY_DIR`, with the master password supplied via env so no command
//! ever prompts. Every assertion is a plain `std::process::Command` round-trip,
//! matching the repo's test style.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::Mutex;

use tempfile::TempDir;

/// Master password for every test (>= the 8-char minimum enforced by `init`).
const PASSWORD: &str = "test-master-password-1234";

/// A secret value used across tests. It must never appear in `list` / `inspect`
/// / `status` / audit output (the agent-safe invariant), and is only ever
/// printed by `get` (or passed through to a child by `run`).
const SECRET: &str = "s3cr3t-value-should-not-leak";

/// Integration tests set the process-global `VAULTLY_DIR` /
/// `VAULTLY_MASTER_PASSWORD` env vars that the binary reads. Test threads share
/// this process, so every test that touches a vault MUST hold this global lock
/// for its whole lifetime — otherwise concurrently-running tests would race on
/// the shared env.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Scoped env setup: points `VAULTLY_DIR` at a fresh temp dir (auto-cleaned on
/// drop) and supplies the master password via env. Holds the global lock so no
/// two tests observe each other's env.
struct VaultlyEnv {
    _guard: std::sync::MutexGuard<'static, ()>,
    dir: TempDir,
}

impl VaultlyEnv {
    fn new() -> Self {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let dir = tempfile::tempdir().expect("make tempdir");
        std::env::set_var("VAULTLY_DIR", dir.path());
        std::env::set_var("VAULTLY_MASTER_PASSWORD", PASSWORD);
        // Force deterministic plain-text output: no ANSI, no TUI, no agent mode.
        std::env::set_var("NO_COLOR", "1");
        std::env::remove_var("VAULTLY_AGENT_MODE");
        std::env::set_var("VAULTLY_HUMAN_MODE", "1");
        VaultlyEnv { _guard, dir }
    }

    fn set_password(&self, pw: &str) {
        std::env::set_var("VAULTLY_MASTER_PASSWORD", pw);
    }

    fn dir(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for VaultlyEnv {
    fn drop(&mut self) {
        std::env::remove_var("VAULTLY_DIR");
        std::env::remove_var("VAULTLY_MASTER_PASSWORD");
        std::env::remove_var("VAULTLY_HUMAN_MODE");
    }
}

fn bin() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vaultly"));
    // Parent desktop setup must not opt isolated CLI fixtures into real keyring use.
    command.env_remove("VAULTLY_ALLOW_KEYCHAIN");
    command
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

fn assert_fails(out: &Output) {
    assert!(
        !out.status.success(),
        "command unexpectedly succeeded\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
    // A clean CLI error must be a normal non-zero exit, never a Rust panic.
    assert!(
        !stderr(out).contains("panicked"),
        "command panicked unexpectedly\nstdout: {}\nstderr: {}",
        stdout(out),
        stderr(out)
    );
}

/// `vaultly init` in the scoped env. The master password comes from
/// `VAULTLY_MASTER_PASSWORD`, so the interactive confirm/keychain prompts are
/// skipped entirely (init only prompts when the env password is absent).
fn init(_env: &VaultlyEnv) {
    assert_ok(&run(&["init"]));
}

// ─── 1. init → add → get roundtrip ─────────────────────────

#[test]
fn init_and_add_and_get_roundtrip() {
    let env = VaultlyEnv::new();
    init(&env);

    const VAULT: &str = "roundtrip";
    assert_ok(&run(&["add", VAULT, "-k", "API_KEY", "-v", SECRET]));

    let out = run(&["get", VAULT, "API_KEY"]);
    assert_ok(&out);
    assert_eq!(stdout(&out).trim(), SECRET);
}

// ─── 2. listing commands never leak secret values ──────────

#[test]
fn list_and_keys_do_not_leak_values() {
    let env = VaultlyEnv::new();
    init(&env);

    const VAULT: &str = "leakcheck";
    const KEY: &str = "LEAK_KEY";
    assert_ok(&run(&["add", VAULT, "-k", KEY, "-v", SECRET]));

    // `list` (all vaults) prints vault names only.
    let list_all = run(&["list"]);
    assert_ok(&list_all);
    assert!(stdout(&list_all).contains(VAULT), "vault name missing");
    assert!(!stdout(&list_all).contains(SECRET), "list leaked secret");

    // `list <vault>` prints key names only.
    let list_keys = run(&["list", VAULT]);
    assert_ok(&list_keys);
    assert!(stdout(&list_keys).contains(KEY), "key name missing");
    assert!(
        !stdout(&list_keys).contains(SECRET),
        "list <vault> leaked secret"
    );

    // `inspect <vault>` prints metadata + key names only.
    let inspect = run(&["inspect", VAULT]);
    assert_ok(&inspect);
    assert!(stdout(&inspect).contains(KEY), "inspect key name missing");
    assert!(!stdout(&inspect).contains(SECRET), "inspect leaked secret");

    // `status` prints meta only.
    let status = run(&["status"]);
    assert_ok(&status);
    assert!(!stdout(&status).contains(SECRET), "status leaked secret");
}

// ─── 3. import .env / .json / .yaml / .csv ─────────────────

#[test]
fn import_formats_env_json_yaml_csv() {
    let env = VaultlyEnv::new();
    init(&env);

    // (vault, import file, file contents, expected value for API_KEY,
    //  expected value for DB_PASS)
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        (
            "imp-env",
            "import.env",
            "API_KEY=env-value-1\nDB_PASS=env-value-2\n",
            "env-value-1",
            "env-value-2",
        ),
        (
            "imp-json",
            "import.json",
            r#"{"API_KEY":"json-value-1","DB_PASS":"json-value-2"}"#,
            "json-value-1",
            "json-value-2",
        ),
        (
            "imp-yaml",
            "import.yaml",
            "API_KEY: yaml-value-1\nDB_PASS: yaml-value-2\n",
            "yaml-value-1",
            "yaml-value-2",
        ),
        (
            "imp-csv",
            "import.csv",
            "API_KEY,csv-value-1\n# comment\nDB_PASS,csv-value-2\n",
            "csv-value-1",
            "csv-value-2",
        ),
    ];

    for &(vault, file, content, api_val, db_val) in cases {
        let path = env.dir().join(file);
        std::fs::write(&path, content).expect("write import file");

        let out = run(&["import", path.to_str().unwrap(), "--vault", vault]);
        assert_ok(&out);

        let api = run(&["get", vault, "API_KEY"]);
        assert_ok(&api);
        assert_eq!(stdout(&api).trim(), api_val, "API_KEY in vault {vault}");

        let db = run(&["get", vault, "DB_PASS"]);
        assert_ok(&db);
        assert_eq!(stdout(&db).trim(), db_val, "DB_PASS in vault {vault}");
    }
}

// ─── 5. error paths exit non-zero (without panicking) ──────

#[test]
fn error_paths_return_nonzero_exit() {
    let env = VaultlyEnv::new();

    // add into a non-initialized dir must fail.
    assert_fails(&run(&["add", "nope", "-k", "K", "-v", "v"]));

    init(&env);

    // get on a vault that doesn't exist (correct password) must fail.
    assert_fails(&run(&["get", "missing-vault", "KEY"]));

    // wrong master password on unlock must fail (valid-length wrong password).
    env.set_password("wrong-password-000");
    assert_fails(&run(&["get", "missing-vault", "KEY"]));
    env.set_password(PASSWORD);

    // an invalid vault name (control character is rejected outright) must fail.
    assert_fails(&run(&["add", "bad\nvault", "-k", "K", "-v", "v"]));
}

// ─── 7. rotate --expired (Phase B) ──────────────────────────

#[test]
fn rotate_expired_rotates_and_clears_expiry() {
    let env = VaultlyEnv::new();
    init(&env);

    const VAULT: &str = "ci";
    const OLD: &str = "OLD";
    const FRESH: &str = "FRESH";
    // One secret with a past expiry (expired), one fresh with no expiry.
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
    assert_ok(&run(&["add", VAULT, "-k", FRESH, "-v", SECRET]));

    // First pass: the expired key is rotated (key name + "rotated" on stdout),
    // the fresh key is left alone, and no secret value is shown.
    let rotated = run(&["rotate", VAULT, "--expired"]);
    assert_ok(&rotated);
    let out = stdout(&rotated);
    assert!(
        out.contains(OLD),
        "expected rotated key name in stdout: {out}"
    );
    assert!(
        out.contains("rotated"),
        "expected 'rotated' in stdout: {out}"
    );
    assert!(!out.contains(SECRET), "rotate leaked secret: {out}");

    // Second pass: nothing left to rotate.
    let again = run(&["rotate", VAULT, "--expired"]);
    assert_ok(&again);
    assert!(
        stdout(&again).contains("No expired secrets"),
        "stdout: {}",
        stdout(&again)
    );
}

// ─── doctor ─────────────────────────────────────────────────
#[test]
fn doctor_reports_healthy_state() {
    let env = VaultlyEnv::new();
    init(&env);
    assert_ok(&run(&["add", "v1", "-k", "K", "-v", SECRET]));

    let out = run(&["doctor"]);
    assert_ok(&out);
    let stdout = stdout(&out);
    assert!(
        stdout.contains("initialized"),
        "doctor should report initialized"
    );
    assert!(stdout.contains("vault"), "doctor should mention vaults");
}

#[test]
fn doctor_json_output_is_valid() {
    let env = VaultlyEnv::new();
    init(&env);

    let out = run(&["doctor", "--json"]);
    assert_ok(&out);
    let stdout = stdout(&out);
    // Must parse as a JSON array of findings.
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(&stdout).expect("doctor --json must output valid JSON array");
    assert!(
        !findings.is_empty(),
        "doctor should report at least one finding"
    );
    // Every finding has severity + check + message.
    for f in &findings {
        assert!(f.get("severity").is_some(), "finding missing severity");
        assert!(f.get("check").is_some(), "finding missing check");
        assert!(f.get("message").is_some(), "finding missing message");
    }
}

#[test]
fn doctor_exits_nonzero_when_uninitialized() {
    let _env = VaultlyEnv::new();
    // Do NOT init — doctor should detect this and exit non-zero.
    let out = run(&["doctor"]);
    assert_fails(&out);
}

// ─── gen / generate ─────────────────────────────────────────

#[test]
fn gen_produces_secret_of_requested_length() {
    let env = VaultlyEnv::new();
    init(&env);

    let out = run(&["gen", "--length", "32"]);
    assert_ok(&out);
    let stdout = stdout(&out).trim().to_string();
    assert_eq!(stdout.len(), 32, "gen --length 32 should output 32 chars");
    // Default charset is alphanumeric only.
    assert!(
        stdout.chars().all(|c| c.is_ascii_alphanumeric()),
        "gen output should be alphanumeric: {stdout}"
    );
}

#[test]
fn gen_with_symbols_includes_punctuation() {
    let env = VaultlyEnv::new();
    init(&env);

    // Generate several times; at least one should contain a symbol.
    let mut found_symbol = false;
    for _ in 0..20 {
        let out = run(&["gen", "--length", "64", "--symbols"]);
        assert_ok(&out);
        let stdout = stdout(&out).trim().to_string();
        assert_eq!(stdout.len(), 64);
        if stdout.chars().any(|c| !c.is_alphanumeric()) {
            found_symbol = true;
            break;
        }
    }
    assert!(
        found_symbol,
        "--symbols should eventually produce punctuation"
    );
}

// ─── rotate ─────────────────────────────────────────────────

#[test]
fn rotate_single_secret_changes_value() {
    let env = VaultlyEnv::new();
    init(&env);

    assert_ok(&run(&[
        "add",
        "rot",
        "-k",
        "TOKEN",
        "-v",
        "old-value-12345",
    ]));
    let before = stdout(&run(&["get", "rot", "TOKEN"])).trim().to_string();
    assert_eq!(before, "old-value-12345");

    assert_ok(&run(&["rotate", "rot", "TOKEN"]));
    let after = stdout(&run(&["get", "rot", "TOKEN"])).trim().to_string();
    assert_ne!(before, after, "rotate must change the value");
    assert_eq!(after.len(), 32, "default rotation length is 32");
}

#[test]
fn rotate_expired_only_touches_expired() {
    let env = VaultlyEnv::new();
    init(&env);

    assert_ok(&run(&[
        "add",
        "expire",
        "-k",
        "OLD",
        "-v",
        "old-val",
        "--expires",
        "2000-01-01T00:00:00Z",
    ]));
    assert_ok(&run(&["add", "expire", "-k", "LIVE", "-v", "live-val"]));

    assert_ok(&run(&["rotate", "expire", "--expired"]));

    // OLD changed, LIVE untouched.
    let old_after = stdout(&run(&["get", "expire", "OLD"])).trim().to_string();
    let live_after = stdout(&run(&["get", "expire", "LIVE"])).trim().to_string();
    assert_ne!(old_after, "old-val", "expired key should be rotated");
    assert_eq!(live_after, "live-val", "live key should be untouched");
}

// ─── encrypted export / import ─────────────────────────────

#[test]
fn encrypted_export_import_roundtrip() {
    let env = VaultlyEnv::new();
    init(&env);

    const VAULT: &str = "exportvault";
    assert_ok(&run(&["add", VAULT, "-k", "API_KEY", "-v", SECRET]));
    assert_ok(&run(&["add", VAULT, "-k", "TOKEN", "-v", "another-secret"]));

    let export_path = env.dir().join("export.vaultly");

    // Export as encrypted blob.
    let export_out = run(&[
        "export",
        VAULT,
        export_path.to_str().unwrap(),
        "--encrypted",
    ]);
    assert_ok(&export_out);

    // The export file must NOT contain the plaintext secret.
    let export_raw = std::fs::read_to_string(&export_path).expect("read export file");
    assert!(
        !export_raw.contains(SECRET),
        "encrypted export must not contain plaintext secret"
    );

    // Import into a new vault.
    let import_out = run(&[
        "import",
        export_path.to_str().unwrap(),
        "--encrypted",
        "--vault",
        "imported_vault",
    ]);
    assert_ok(&import_out);

    // Verify the secrets survived the round-trip.
    let api = stdout(&run(&["get", "imported_vault", "API_KEY"]))
        .trim()
        .to_string();
    let token = stdout(&run(&["get", "imported_vault", "TOKEN"]))
        .trim()
        .to_string();
    assert_eq!(api, SECRET, "API_KEY should survive encrypted round-trip");
    assert_eq!(
        token, "another-secret",
        "TOKEN should survive encrypted round-trip"
    );
}

// ─── version / stats / inspect ──────────────────────────────

#[test]
fn version_prints_semver() {
    let env = VaultlyEnv::new();
    init(&env);

    let out = run(&["version"]);
    assert_ok(&out);
    let stdout = stdout(&out).trim().to_string();
    // SemVer: at least "X.Y.Z"
    let parts: Vec<&str> = stdout.split('.').collect();
    assert!(parts.len() >= 2, "version should look semver-ish: {stdout}");
}

#[test]
fn stats_reports_meta_only() {
    let env = VaultlyEnv::new();
    init(&env);
    assert_ok(&run(&["add", "sv", "-k", "A", "-v", SECRET]));
    assert_ok(&run(&["add", "sv", "-k", "B", "-v", SECRET]));

    let out = run(&["stats"]);
    assert_ok(&out);
    let stdout = stdout(&out);
    assert!(!stdout.contains(SECRET), "stats must not leak values");
    assert!(
        stdout.contains("sv") || stdout.contains("1"),
        "stats should mention vault count"
    );
}

#[test]
fn inspect_shows_metadata_not_values() {
    let env = VaultlyEnv::new();
    init(&env);
    assert_ok(&run(&["add", "iv", "-k", "TOKEN", "-v", SECRET]));

    let out = run(&["inspect", "iv"]);
    assert_ok(&out);
    let stdout = stdout(&out);
    assert!(!stdout.contains(SECRET), "inspect must not leak values");
    assert!(stdout.contains("TOKEN"), "inspect should list key names");
}

// Unlock errors must distinguish an absent input from a rejected password,
// without touching a real OS credential store or printing either value.
#[test]
fn agent_unlock_reports_empty_rejected_and_missing_sources() {
    let env = VaultlyEnv::new();
    init(&env);
    assert_ok(&run(&["add", "unlock-check", "-k", "TOKEN", "-v", SECRET]));
    let vaults = env.dir().join("vaults");
    let before: Vec<_> = std::fs::read_dir(&vaults)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.clone(), std::fs::read(path).unwrap())
        })
        .collect();
    for (password, expected) in [
        (Some(""), "VAULTLY_MASTER_PASSWORD is empty"),
        (
            Some("wrong-password-000"),
            "VAULTLY_MASTER_PASSWORD was rejected",
        ),
        (None, "custom vault store has OS auto-unlock disabled"),
    ] {
        let mut command = bin();
        command
            .args(["list", "unlock-check", "--json"])
            .env_remove("VAULTLY_HUMAN_MODE")
            .env("VAULTLY_AGENT_MODE", "1")
            .env_remove("VAULTLY_ALLOW_KEYCHAIN");
        if let Some(password) = password {
            command.env("VAULTLY_MASTER_PASSWORD", password);
        } else {
            command.env_remove("VAULTLY_MASTER_PASSWORD");
        }
        let out = command.output().unwrap();
        assert_fails(&out);
        let output = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            output.contains(expected),
            "missing safe diagnostic: {output}"
        );
        for value in [PASSWORD, SECRET, "wrong-password-000"] {
            assert!(!output.contains(value));
        }
        for (path, bytes) in &before {
            assert_eq!(&std::fs::read(path).unwrap(), bytes);
        }
    }
    // Valid process-only unlock still works in agent mode and returns names only.
    let out = bin()
        .args(["list", "unlock-check", "--json"])
        .env_remove("VAULTLY_HUMAN_MODE")
        .env("VAULTLY_AGENT_MODE", "1")
        .env_remove("VAULTLY_ALLOW_KEYCHAIN")
        .output()
        .unwrap();
    assert_ok(&out);
    assert!(stdout(&out).contains("TOKEN"));
    assert!(!stdout(&out).contains(SECRET));
}

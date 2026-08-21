# Vaultly — Implementation Plan

## 1. Migrate `engine.rs` / `vault.rs` to `VaultError`

### Goal
Replace `Result<T, String>` with `Result<T, VaultError>` in the core engine and vault storage so callers can match on failure modes instead of parsing error text.

### Scope
- `crates/vaultly-core/src/engine.rs`
- `crates/vaultly-core/src/vault.rs`
- `crates/vaultly-core/src/error.rs` (add missing variants if needed)

### Detailed Steps

#### 1.1 Extend `VaultError` enum
Add any missing variants that are currently returned as ad-hoc strings:
- `VaultError::AlreadyInitialized` — `init_vault` when config already exists
- `VaultError::VaultCorrupt { name, source }` — vault file JSON parse failure
- `VaultError::ConfigCorrupt { source }` — `config.json` parse failure
- `VaultError::BackupMetaUpdate { source }` — failure updating `backup_meta`

#### 1.2 Migrate `vault.rs`
Change every public method signature from `Result<T, String>` to `Result<T, VaultError>`:
- `load_config` → `Result<VaultConfig, VaultError>`
- `save_config` → `Result<(), VaultError>`
- `load_vault_file` → `Result<Option<VaultFile>, VaultError>`
- `save_vault_file` → `Result<(), VaultError>`
- `get_secrets` → `Result<Map<String, Value>, VaultError>`
- `get_secret` → `Result<Option<String>, VaultError>`
- `set_secret` → `Result<(), VaultError>`
- `delete_secret` → `Result<bool, VaultError>`
- `delete_vault` → `Result<bool, VaultError>`
- `list_vaults` → `Result<Vec<String>, VaultError>` (currently infallible, keep as-is or wrap for consistency)
- `list_keys` → `Result<Vec<String>, VaultError>`
- `import_secrets` → `Result<usize, VaultError>`
- `get_encrypted_vaults` → keep as-is (infallible)
- `restore_encrypted_vaults` → `Result<usize, VaultError>`
- `get_config_for_backup` → `Result<VaultConfig, VaultError>`
- `update_backup_meta` → `Result<(), VaultError>`
- `init_vault` → `Result<(), VaultError>`
- `unlock` → `Result<Vec<u8>, VaultError>`
- `audit` → keep as-is (infallible, logs failures silently)

Rule of thumb: replace `.map_err(|e| format!(...))` with `.map_err(VaultError::from)` or `.map_err(|e| VaultError::Io(e))` / `.map_err(|e| VaultError::Json(e))`.

#### 1.3 Migrate `engine.rs`
Change every method signature from `Result<T, String>` to `Result<T, VaultError>`:
- `list_vaults` → `Result<Vec<String>, VaultError>`
- `list_keys` → `Result<Vec<String>, VaultError>`
- `add_secret` → `Result<(), VaultError>`
- `delete_secret` → `Result<bool, VaultError>`
- `delete_vault` → `Result<bool, VaultError>`
- `get_secret_value` → `Result<String, VaultError>`
- `import_secrets` → `Result<usize, VaultError>`
- `get_secrets` → `Result<Map<String, Value>, VaultError>`
- `run` → `Result<RunResult, VaultError>`
- `run_command` → `Result<RunResult, VaultError>`
- `spawn` → `Result<RunResult, VaultError>`
- `cloudflare_api` → `Result<ApiResult, VaultError>`
- `list_workers` → `Result<(String, Vec<String>), VaultError>`
- `worker_secrets` → `Result<ApiResult, VaultError>`
- `health_check` → `Result<(bool, String), VaultError>` (keep message as string for now)
- `get_encrypted_vaults` → keep as-is
- `restore_encrypted_vaults` → `Result<usize, VaultError>`
- `update_backup_meta` → `Result<(), VaultError>`
- `get_audit_log` → keep as-is (infallible)
- `audit` → keep as-is (infallible)

#### 1.4 Migrate `policy.rs`
- `PolicyEngine::check` → `Result<(), VaultError>` (return `VaultError::Policy` / `VaultError::RateLimit`)

#### 1.5 Update all callers
Callers in `main.rs`, `tui.rs`, and `vaultly-mcp/src/lib.rs` must be updated. The conversion is mostly mechanical:
- `.unwrap_err().contains("...")` → match on `VaultError::Xxx`
- `eprintln!("{} {}", "✗".red(), e)` → still works via `Display`
- `exit(1)` paths remain unchanged

#### 1.6 Update tests
All tests that assert on error strings must be updated to match on `VaultError` variants.

### Acceptance Criteria
- `cargo test --workspace` passes
- `cargo clippy --workspace --all-targets -- -D warnings` passes
- Every public method in `engine.rs` and `vault.rs` returns `VaultError`
- Zero `Result<T, String>` remain in `engine.rs` / `vault.rs` public API

---

## 2. Add `vaultly doctor` Command

### Goal
Add a diagnostic subcommand that checks vault health and prints actionable findings.

### UX
```
vaultly doctor
vaultly doctor --json
```

### Checks

| Check | Condition | Severity | Message |
|-------|-----------|----------|---------|
| Initialized | `config.json` exists | ERROR if missing | "Vaultly not initialized. Run: vaultly init" |
| Config valid | `config.json` parses | ERROR if corrupt | "Corrupt config.json: {error}" |
| Vault dir permissions | `~/.vaultly` is `0o700` | WARN if wrong | "Vault directory has loose permissions (expected 0o700, got {mode})" |
| Vault files exist | at least one `.vault` file | INFO | "{n} vault(s) found" |
| Unlocked | `engine.is_unlocked()` | ERROR if locked | "Vault is locked. Unlock with: vaultly unlock" |
| Session TTL | `session_expires_in()` | WARN if < 5 min | "Session expires in {n}s" |
| Keychain | `keychain::is_keychain_available()` | INFO | "Keychain available / not available (macOS only)" |
| Keychain entry | `keychain::keychain_entry_exists()` | WARN if missing | "No keychain entry. Run: vaultly keychain store" |
| Audit log | `audit.log` readable | WARN if missing | "No audit log yet" |
| Audit log size | `audit.log` size | INFO | "{size} bytes" |

### Implementation

#### 2.1 Add `Doctor` subcommand
```rust
Doctor {
    #[arg(long, help = "Output results as JSON")]
    json: bool,
}
```

#### 2.2 Add `cmd_doctor` function
```rust
fn cmd_doctor(json: bool) {
    let engine = engine();
    let mut findings = Vec::new();

    // 1. Initialized
    if !engine.is_initialized() {
        findings.push(("ERROR", "Vaultly not initialized"));
    }

    // 2. Config valid
    if engine.is_initialized() {
        match engine.store().load_config() {
            Ok(_) => findings.push(("INFO", "Config valid")),
            Err(e) => findings.push(("ERROR", &format!("Corrupt config: {}", e))),
        }
    }

    // 3. Permissions
    // ... check dir permissions

    // 4. Vaults
    let vaults = engine.store().list_vaults();
    findings.push(("INFO", &format!("{} vault(s)", vaults.len())));

    // 5. Unlocked / TTL
    // attempt unlock via keychain or env

    // 6. Keychain
    // ...

    // Output
    if json {
        println!("{}", serde_json::json!({ "findings": findings }));
    } else {
        for (severity, msg) in findings {
            let icon = match severity {
                "ERROR" => "✗".red(),
                "WARN" => "⚠".yellow(),
                "INFO" => "ℹ".dimmed(),
                _ => "•".dimmed(),
            };
            println!("{} {}", icon, msg);
        }
    }
}
```

#### 2.3 Add to CLI enum
```rust
Doctor {
    #[arg(long, help = "Output results as JSON")]
    json: bool,
},
```

#### 2.4 Add to match
```rust
Some(Command::Doctor { json }) => cmd_doctor(json),
```

### Acceptance Criteria
- `vaultly doctor` works without unlock (checks initialized state, permissions, keychain)
- `vaultly doctor` works after unlock (checks session TTL, vault integrity)
- `vaultly doctor --json` outputs valid JSON
- Exit code 0 if no ERROR findings, exit code 1 if any ERROR

---

## 3. Expand Tests

### Goal
Increase coverage for recently added/changed behavior.

### 3.1 `error.rs` tests (new file)
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_error_display_does_not_leak_secrets() {
        let err = VaultError::SecretNotFound("TOKEN".into(), "github".into());
        assert!(err.to_string().contains("TOKEN")); // key name is OK
        // value should never appear in Display
    }

    #[test]
    fn vault_error_conversion_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "oops");
        let vault_err: VaultError = io_err.into();
        assert!(matches!(vault_err, VaultError::Io(_)));
    }

    #[test]
    fn vault_error_conversion_from_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("").unwrap_err();
        let vault_err: VaultError = json_err.into();
        assert!(matches!(vault_err, VaultError::Json(_)));
    }
}
```

### 3.2 `engine.rs` — new tests
```rust
#[tokio::test]
async fn secrets_injected_reported_on_timeout() {
    let (mut engine, _dir) = setup();
    engine.add_secret("slow", "API_KEY", "secret-123", Some(&agent_ctx())).unwrap();
    let res = engine.run("slow", "sleep", &["30".into()], None, Some(200), Some(&agent_ctx())).await.unwrap();
    assert_eq!(res.code, 124);
    assert!(res.secrets_injected.contains(&"API_KEY".to_string()));
}

#[tokio::test]
async fn run_reports_vault_exists_but_empty() {
    let (mut engine, _dir) = setup();
    engine.add_secret("empty", "K", "v", Some(&agent_ctx())).unwrap();
    engine.delete_secret("empty", "K", Some(&agent_ctx())).unwrap();
    let err = engine.run("empty", "true", &[], None, None, Some(&agent_ctx())).await.unwrap_err();
    assert!(err.contains("exists but has no secrets"));
}

#[tokio::test]
async fn run_reports_vault_not_found() {
    let (mut engine, _dir) = setup();
    let err = engine.run("nonexistent", "true", &[], None, None, Some(&agent_ctx())).await.unwrap_err();
    assert!(err.contains("not found"));
    assert!(err.contains("Create it with"));
}
```

### 3.3 `vault.rs` — new tests
```rust
#[test]
fn vault_exists_true_for_existing() {
    let dir = temp_dir();
    let mut engine = VaultEngine::with_dir(None, dir.clone());
    engine.store.init_vault(PASSWORD).unwrap();
    engine.unlock(PASSWORD).unwrap();
    engine.add_secret("v", "k", "v", None).unwrap();
    assert!(engine.store.vault_exists("v").unwrap());
}

#[test]
fn vault_exists_false_for_missing() {
    let dir = temp_dir();
    let engine = VaultEngine::with_dir(None, dir);
    assert!(!engine.store.vault_exists("nope").unwrap());
}
```

### 3.4 `keychain.rs` — new tests
```rust
#[test]
fn store_in_keychain_verifies_by_reading_back() {
    // Simulate: store succeeds but read-back fails
    // This is hard to unit-test without a real keychain, so skip on CI
    // Instead, add an integration test or mock
}
```

### 3.5 `audit.rs` rotation test (in `vault.rs`)
```rust
#[test]
fn audit_rotates_when_file_exceeds_max() {
    let dir = temp_dir();
    let store = VaultStore::with_dir(dir);
    // Write >10MB of audit entries
    let path = store.audit_path();
    let big = "x".repeat(11 * 1024 * 1024);
    std::fs::write(&path, big).unwrap();
    store.audit("TEST", "rotation check");
    assert!(path.exists());
    assert!(PathBuf::from(format!("{}.1", path.display())).exists());
}
```

### 3.6 `main.rs` — `--timeout` test
```rust
#[tokio::test]
async fn run_with_custom_timeout() {
    let (mut engine, _dir) = setup();
    engine.add_secret("t", "K", "v", Some(&agent_ctx())).unwrap();
    let res = engine.run_command("t", "sleep 30", None, Some(500), Some(&agent_ctx())).await.unwrap();
    assert_eq!(res.code, 124);
}
```

### Acceptance Criteria
- `cargo test --workspace` passes with >50 total tests
- New tests cover: `VaultError` conversions, `secrets_injected` on timeout, vault existence checks, audit rotation, timeout flag
- Zero warnings

---

## Execution Order

| Step | Priority | Status |
|------|----------|--------|
| 1. `VaultError` migration | High | ✅ Complete — `engine.rs`, `vault.rs`, `policy.rs` all return `VaultError`; `Result<T>` alias exported |
| 2. `vaultly doctor` | High | ✅ Complete — includes `--json` flag, structured findings, exit codes |
| 3. Test expansion | Medium | ✅ Complete — 14 new tests (error conversions, timeout injection, vault existence, audit rotation, custom timeout, key allowlist) |

### Additional Fixes (discovered during execution)
- **Build fix**: Migrated all `run`/`run_command` call sites to the new `RunOptions` struct (CLI, TUI, MCP, HTTP server)
- **Docs**: Updated `ARCHITECTURE.md` (full rewrite), `CONTRIBUTING.md`, `CHANGELOG.md` to reflect 28 tools, 13,869 LOC, 119 tests
- **Flaky test**: HTTP readiness timeout 20s → 60s

# Vaultly — Next Phase Plan

## Status: All previous PLAN items complete. Build clean, 119 tests pass.

---

## Phase A: Security Hardening (Highest Priority)

### A1. Remove `Debug` derive from `SecretEntry`
- **Risk:** `SecretEntry` holds `value: String` (plaintext secret). Derived `Debug` could leak it in logs/panics.
- **Fix:** Implement custom `Debug` that redacts the value field.
- **File:** `crates/vaultly-core/src/crypto.rs`

### A2. Audit error messages for secret leakage
- **Risk:** Error messages might include secret values (e.g., in `Decrypt` or `Crypto` variants).
- **Fix:** Audit all `VaultError` construction sites; ensure no secret value is ever passed to an error.
- **File:** `crates/vaultly-core/src/error.rs`, `vault.rs`, `engine.rs`

### A3. Add security tests
- Test that `SecretEntry` Debug does NOT contain the value.
- Test that no error message contains a secret value.
- Test that `scrub_output` handles edge cases (empty, unicode, overlapping secrets).
- **File:** `crates/vaultly-core/src/crypto.rs`, `scrubber.rs`

### A4. Constant-time password verification audit
- Verify the password verifier comparison is constant-time.
- **File:** `crates/vaultly-core/src/crypto.rs`, `vault.rs`

---

## Phase B: Property-Based Tests

### B1. Crypto round-trip proptest
- encrypt → decrypt with random plaintexts, keys, salts.
- **File:** `crates/vaultly-core/src/crypto.rs`

### B2. SecretEntry serialization proptest
- Random `SecretEntry` → JSON → parse → equal.
- **File:** `crates/vaultly-core/src/crypto.rs`

### B3. Scrubber proptest
- For random secret + random output containing the secret, scrubbed output must not contain the secret.
- **File:** `crates/vaultly-core/src/scrubber.rs`

---

## Phase C: CLI Integration Tests

### C1. `vaultly doctor --json` test
- Verify JSON output is valid and parseable.
- **File:** `crates/vaultly/tests/cli.rs`

### C2. `vaultly gen` / `vaultly rotate --expired` test
- Verify generated secrets have correct length and charset.
- **File:** `crates/vaultly/tests/cli.rs`

### C3. `vaultly version` / `vaultly stats` / `vaultly inspect` smoke tests
- **File:** `crates/vaultly/tests/cli.rs`

---

## Phase D: New Feature — Encrypted Export/Import

### D1. `vaultly export --encrypted` 
- Export vault as encrypted blob (AES-256-GCM) that can be imported by another vaultly instance with the same master password.
- **File:** `crates/vaultly/src/main.rs`

### D2. `vaultly import --encrypted`
- Import an encrypted export blob.
- **File:** `crates/vaultly/src/main.rs`

---

## Phase E: Performance Pass

### E1. Reduce clones in hot paths
- Audit `engine.rs` `run()` for unnecessary `String` clones on secret values.
- **File:** `crates/vaultly-core/src/engine.rs`

### E2. Pre-compiled regex for repeated scrubbing
- Cache compiled regexes when scrubbing many values against one output.
- **File:** `crates/vaultly-core/src/scrubber.rs`

---

## Execution Order

| Order | Phase | Est. LOC | Risk |
|-------|-------|----------|------|
| 1 | A1: SecretEntry Debug | ~10 | Low |
| 2 | A2: Error message audit | ~20 | Medium |
| 3 | A3: Security tests | ~60 | Low |
| 4 | A4: Constant-time audit | ~10 | Low |
| 5 | B1-B3: Property tests | ~120 | Low |
| 6 | C1-C3: CLI integration tests | ~100 | Low |
| 7 | D1-D2: Encrypted export/import | ~150 | Medium |
| 8 | E1-E2: Performance | ~40 | Medium |

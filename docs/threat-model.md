# Vaultly Threat Model

Vaultly is an **agent-first** encrypted credential manager. An AI agent drives
it through the MCP server (or restricted shell commands) and never observes a
raw secret value. This document enumerates the assets at stake, the trust
boundaries between components, the threats the design defends against, and the
concrete mitigations implemented in the Rust codebase (`rust/crates/`).

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Master password | User's memory; macOS Keychain (`keychain.rs`) | Never written to any vault file or log |
| Vault encryption key (KEK) | Derived at unlock time; held in memory for the session | Not persisted; wiped on lock/expiry |
| Secret values (plaintext) | In memory only during an operation (`engine.rs`, `crypto.rs`) | AES-256-GCM at rest; scrubbed from child output & CF responses |
| Encrypted vault files | `~/.vaultly/vaults/*.vault` (dir overridable via `VAULTLY_DIR`) | Mode `0600`, dir `0700`, atomic temp+rename writes |
| Store config | `~/.vaultly/config.json` (salt, policy, backup metadata) | Same atomic `0600` write path |
| Audit log | `~/.vaultly/audit.log` | Hash-chained, tamper-evident, rotated at 1 MiB |
| Cloudflare credentials | Encrypted vault (e.g. `cf-personal`) | Same AES-GCM; write-only to agents |

## Trust boundaries

```
  AI AGENT  (untrusted, read-only observer)
     │  JSON-RPC over MCP  |  restricted shell (agent mode)
     ▼
 VAULTLY MCP SERVER / CLI  (trusted; holds derived key in memory)
     │  injects secrets into a child's env or HTTP headers
     ▼
 CHILD PROCESS / CLOUDFLARE API  (distrusted sink)
```

- The agent sits **outside** the boundary that holds plaintext. It only ever
  observes *names, metadata, command output, and API responses* — never values.
- The MCP server unlocks from macOS Keychain → `VAULTLY_MASTER_PASSWORD` →
  terminal prompt, and keeps the key only for the session TTL (120 min for
  MCP). `vault_lock` wipes it immediately.
- Child processes launched by `vaultly run` / `cf deploy` run an **environment
  cleared with `env_clear()`**, so they receive *only* the injected vault
  secrets and cannot read the parent's other secrets.

## Threats and mitigations

### 1. Secret exfiltration by a compromised agent
- **No value-returning tool.** `vault_list`, `vault_keys`, `vault_meta`,
  `vault_status`, `list`, `inspect`, and `stats` return names/metadata only
  (`engine.rs`, `vault.rs list_keys`).
- **Agent mode** (the default; `VAULTLY_AGENT_MODE=1` is retained for
  compatibility) hard-blocks every command that reads
  or writes raw values: `get`, `get --export`, `env`, `export`, `add`, `delete`,
  `import`, `copy`, `rename`, `mv`, `cp`, `backup`, `restore`, `template`,
  `keychain`, `init`, `tui`, `kill`, `status`, and `cf add/use/remove`
  (`main.rs block_in_agent_mode`). Agent-safe commands (`list`, `run`,
  `cf list/zones/secrets/deploy/dns-delete`, `generate`, `rotate`, `inspect`,
  `stats`, `doctor`, `mcp`) remain available.
- The MCP **`vault_export`** tool is always refused in the agent context via the
  policy layer (`ReadValue` is a banned operation), returning
  *"Export blocked in MCP/agent context"* with instructions to run
  `vaultly export` as a human.

### 2. Credential disclosure through logs / process output
- The audit log records *actions, names, and metadata* — never values.
- Child stdout/stderr and Cloudflare responses are passed through the scrubber,
  which replaces any echoed secret value with `[REDACTED]`
  (`scrubber.rs scrub_output`; verified by `run_injects_secrets_and_scrubs_output`
  and `cf_scrubs_credentials_from_api_responses`).

### 3. Vault file tampering / corruption
- Encrypted payloads are **AES-256-GCM** with an authentication tag — any
  tampering invalidates decryption (`crypto.rs`).
- Writes are **atomic**: write a temp file (`*.tmp`) in the same directory,
  `fsync`, `rename` over the target, then `fsync` the directory. A crash mid-write
  can never leave a truncated/corrupt file at the real path (`vault.rs
  write_secure`).
- Concurrent readers/writers are serialized through an exclusive `.write.lock`
  (created with `create_new`, stale-lock recovery after 30 s, give up after
  ~3 s rather than blocking forever), preventing lost updates
  (`concurrent_writes_are_serialized_without_loss`).

### 4. Audit-log forgery (covering tracks)
- Every entry is stamped with `prevHash` = SHA-256 of the previous non-empty
  line, forming a **hash chain**; the first entry chains to a 64-zero sentinel
  (`vault.rs append_audit_line`).
- `verify_audit_chain` walks the chain and returns every line whose declared
  `prevHash` doesn't match the previous line's hash (including unparseable
  lines). Modifying any past line breaks the chain.
- The MCP `vault_audit` tool surfaces chain integrity: `✓ audit chain intact`
  or `⚠ audit chain tampered at N line(s)` with the offending line indices.
- Rotation (`audit.log` → `audit.log.1` at the 1 MiB cap) is chain-aware and
  never drops the linking hashes.

### 5. Brute-force / offline attacks on stolen vault files
- Keys are derived with **PBKDF2-SHA256 at 600,000 iterations** (OWASP 2023 for
  PBKDF2-SHA256) from the master password and a store-wide random hex salt
  (`crypto.rs PBKDF2_ITERATIONS`). A stolen `.vault` file cannot be cheaply
  brute-forced. (Note: the salt is a single value shared across the whole store,
  not per-vault.)

### 6. API-credential misuse
- The Cloudflare path builds authenticated requests from
  `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`, or the legacy
  `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` fallback, and injects them directly
  into HTTP headers — the agent never sees them (`engine.rs build_cf_headers`).
- Responses are passed through the scrubber so a credential echoed in an error
  body is redacted before reaching the agent.
- Transient network failures and HTTP 5xx retry with bounded **exponential
  backoff** (`CF_MAX_ATTEMPTS = 3`, delays 200 ms then 400 ms, capped at 2 s)
  via `send_with_retry` — non-escalating and bounded.

### 7. Resource abuse / runaway agents
- A **rate limit** caps operations per minute per agent (default 60; override
  `VAULTLY_MAX_OPS_PER_MINUTE`) and is enforced by `policy.rs check_rate_limit`
  before each operation (`policy.rs default_max_ops`).
- MCP responses are capped (`OUTPUT_MAX = 10 000` bytes) and child output is
  read through a hard 5 MiB buffer ceiling with a truncation marker.
- `policy_info` reports the session TTL, command timeout, and max response
  output, and enumerates the permitted operation set.

### 8. CLI / name injection
- Vault names are sanitized at the boundary: `sanitize_vault_name` **rejects
  control characters outright** and maps every other non-alphanumeric character
  to `-` (rejecting names that would collapse to empty or just `-`). Secret
  keys pass `validate_key_name`, which rejects control characters so nothing can
  inject into output or JSON (`vault.rs`). Values are length-capped
  (`MAX_SECRET_VALUE_LENGTH = 256 KiB`).
- `vaultly get --export` shell-escapes values, and `env` emits them only in
  single-quoted, escaped `export` statements — and all of these are blocked in
  agent mode anyway.

## Residual risks (accepted)

- An agent that can run arbitrary host code through `vaultly run` still sees
  *only* the env values injected for that specific command — never the parent's
  full store or the in-memory key.
- OS-level compromise of the host that holds the MCP server is out of scope;
  the derived key lives in that host's memory by necessity.
- The remote backup endpoint trusts the Worker's shared bearer token and the
  SHA-256 integrity checksum. Treat the checksum as **tamper-evident**, not a
  proof of origin — a malicious/compromised Worker could serve a coherent but
  attacker-supplied bundle.
- A weak master password limits the strength of PBKDF2 regardless of the
  iteration count.

### 9. Cross-instance secret portability (encrypted export/import)

- `vaultly export --encrypted <vault> <file>` re-encrypts the vault's secrets
  under a fresh random salt derived from the master password, producing a
  portable JSON blob (`EncryptedExport`) that carries its own salt. The blob
  contains no plaintext and can only be decrypted by an instance that knows the
  same master password (`crypto.rs encrypt_export` /
  `decrypt_export`).
- `vaultly import --encrypted <file> [--vault name]` decrypts the blob with the
  embedded salt + master password, then re-encrypts each secret under the local
  store's salt before writing. Import rejects unknown format versions.
- The round-trip is verified by `encrypted_export_import_roundtrip` in
  `cli.rs`: the export file must not contain any plaintext secret, and the
  imported secrets must match the originals.

## Verification

These claims are enforced end-to-end by tests across the workspace: core unit
tests in `vaultly-core`, `crates/vaultly/tests/cli.rs`, and
`crates/vaultly-mcp/tests/mcp_e2e.rs`. Re-run with `cargo test --workspace`
from `rust/`.

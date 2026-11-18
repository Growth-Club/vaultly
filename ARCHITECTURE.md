# Vaultly Architecture

This document describes the **actual Rust implementation** at v1.2.2. Earlier
versions of this file described an aspirational TypeScript-era design (TUI,
HTTP/REST server, template library, remote Worker backup); those components do
not exist in this repository and have been removed from the documentation.

## Ground truth (measured from `rust/crates/**/*.rs`)

| Metric | Actual |
|---|---|
| Rust LOC | 19,513 (vaultly-core 11,833 / vaultly 5,398 / vaultly-mcp 2,282) |
| Crates | 3 (`vaultly-core`, `vaultly`, `vaultly-mcp`) |
| Public core modules | 9 (`engine`, `vault`, `deploy`, `policy`, `crypto`, `scrubber`, `keychain`, `keychain_linux`, `generate`, `error`) |
| MCP tools | 38 (`vaultly-mcp/src/lib.rs` `tools/list` + dispatch) |
| CLI subcommands | 36 (`vaultly/src/main.rs`) |
| Tests | 203 (`#[test]` / `#[tokio::test]`, including proptests) |
| Interfaces | MCP over stdio (JSON-RPC 2.0) and the `vaultly` CLI |
| TUI / HTTP server / templates | **not implemented** |

## Interfaces

### MCP server (`vaultly-mcp`)

A hand-rolled JSON-RPC 2.0 server speaking over stdio. It advertises 38 tools,
including vault CRUD, `run` with approved keys, secret references (`${KEY}`),
diff/history/rollback/trash, Cloudflare discovery and DNS/Worker operations,
GitHub/Vercel secret sync, and deployment operations. No tool returns raw
secret values; values are scrubbed from all output.

### CLI (`vaultly`)

36 clap subcommands: vault lifecycle (`init`, `add`, `get`, `list`, `inspect`,
`stats`, `delete`, `env`, `export`, `import`, `gen`, `rotate`, `passwd`, `trash`,
`history`, `rollback`, `diff`), Cloudflare (`cf add/list/remove`, zones, DNS,
Workers, D1/R2/KV, secrets), deployment targets (`add/adopt`, `preflight`,
`deploy`, `exec`), integrations (`platform`, `mcp install`), and maintenance
(`status`, `doctor`, `schedule`, `completions`, `kill`, `backup`, `restore`).

`vaultly run` spawns a child with `env_clear()`, injects only approved secrets,
and scrubs its output. `read_value` is blocked for agents by default policy.

## Security layer (`vaultly-core`)

- **Crypto** (`crypto.rs`, 543 LOC): AES-256-GCM envelopes with a 16-byte nonce
  (TypeScript-format parity), PBKDF2-SHA256 at 600k iterations with per-store
  salt, `Zeroizing` keys, SHA-256-verified password verifier.
- **Storage** (`vault.rs`, 1,660 LOC): atomic 0600 writes, `create_new` lock
  files, soft delete with trash/history, encrypted local `backup`/`restore`.
  The backup payload includes `config.json` (salt/verifier) so it can be
  restored into a fresh `VAULTLY_DIR`.
- **Policy engine** (`policy.rs`, 861 LOC): default-deny operations, per-vault
  and per-key allowlists, owner-managed `agent-policy.json`, rate limits.
- **Scrubber** (`scrubber.rs`, 284 LOC): exact, URL/base64/quoted, prefix/suffix,
  and interior-fragment redaction; char-boundary-safe for multibyte secrets.
- **Session**: 120-minute auto-lock, key wiped on lock/TTL/drop, persistent
  killswitch, SHA-256 hash-chained JSON audit log (`audit.log`).
- **OS unlock**: macOS Keychain (`keychain.rs`, 205 LOC) and Linux Secret
  Service over encrypted D-Bus (`keychain_linux.rs`, 168 LOC).

## Deployment (`deploy.rs`, 1,799 LOC)

`DeploymentTarget` records bind to one Cloudflare account. `deploy_target`
runs the repository's credential-free build, then publishes either a Worker
script or a Pages deployment. For Pages, the static asset manifest is built
with Wrangler's BLAKE3 asset-key algorithm; advanced-mode Nitro workers are
bundled to a single ESM file by the target repo and attached as `_worker.bundle`
alongside `_routes.json`/`_headers`/`_redirects`. Internal maintenance scripts
call `assertBrokered` and refuse credentials from any other account.

## Release

`.github/workflows/release.yml` builds three `.tar.gz` artifacts:
`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`.
There is no Windows target, Docker image, Homebrew tap update, SBOM, cosign
signature, or GitHub attestation. The website previously claimed some of
these; those claims were removed to match the pipeline.

## Crate layout

```
rust/
├── crates/vaultly-core/   11,833 LOC — engine, vault, deploy, policy, crypto,
│                          scrubber, keychain, keychain_linux, generate, error
├── crates/vaultly/         5,398 LOC — CLI (main.rs 4,549), prompt, tests/cli.rs
└── crates/vaultly-mcp/     2,282 LOC — lib.rs 1,564, main.rs 6, tests/mcp_e2e.rs 712
```

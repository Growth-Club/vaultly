# Contributing to Vaultly

Thanks for helping out. This guide covers the developer workflow for the Rust
workspace: building, testing, linting, code style, and what a PR should look
like.

---

## Repository layout

```
vaultly/
├── rust/
│   ├── Cargo.toml              # workspace: version, shared deps, release profile
│   └── crates/
│       ├── vaultly-core/       # storage, crypto, policy, scrubber, Cloudflare API
│       ├── vaultly/            # CLI + interactive TUI + HTTP server
│       └── vaultly-mcp/        # MCP server (28 agent-safe tools)
├── docs/                       # user-facing reference docs & examples
├── AGENTS.md                   # guidance for AI coding agents
├── ARCHITECTURE.md             # system design & diagrams
└── PLAN.md                     # roadmap
```

Version number lives in `rust/Cargo.toml` under `[workspace.package].version` and
is shared by all three crates via `version.workspace = true`.

---

## Prerequisites

- Rust toolchain (stable). The workspace targets `edition = "2021"`.
  Minimal bootstrap:

  ```bash
  rustup toolchain install stable
  ```

---

## Build

From the `rust/` directory:

```bash
cd rust
cargo build            # debug
cargo build --release  # optimized (LTO + strip, see workspace profile)
```

## Test

```bash
cd rust
cargo test             # whole workspace
```

Unit tests are colocated in each module under `#[cfg(test)]` and cover crypto
round-trips, sanitization, audit-chain integrity, restore validation, fuzzing of
malformed vaults, and cross-crate behavior.

## Lint

```bash
cd rust
cargo clippy --all-targets --all-features -- -D warnings
```

Treat clippy warnings as errors — the CI job fails on warnings.

## Format

```bash
cd rust
cargo fmt --all -- --check      # CI check
cargo fmt --all                 # apply formatting
```

---

## Code style

- **Rust idiom**: `Result` / custom `VaultError` from `vaultly-core`, not panics
  or `unwrap` in production paths (tests may opt out).
- **Security first**: never log, print, or return raw secret values. Secret
  material is wrapped in `zeroize::Zeroizing` and scrubbed from all command
  output. The `ReadValue`/admin operations are intentionally excluded from
  default agent policies.
- **Serde shape**: wire formats use `#[serde(rename_all = "camelCase")]`
  (e.g. `authTag`, `updatedAt`) — keep the JSON contract stable across crates.
- **Follow existing patterns**: reuse the established modules/helpers instead of
  adding a second convention alongside them.
- **Keep secrets out of docs**: docs (this directory, README, examples) never
  include real credentials and never imply an agent can read a raw secret value.

---

## Pull request checklist

- [ ] `cd rust && cargo test` passes.
- [ ] `cd rust && cargo clippy --all-targets --all-features -- -D warnings` is clean.
- [ ] `cd rust && cargo fmt --all -- --check` is clean.
- [ ] No raw-secret logging/printing added; agent-safe invariants preserved.
- [ ] Behavior/API changes covered by a test that fails on a plausible bug.
- [ ] User-facing changes reflected in the relevant docs (README, docs/) if applicable.
- [ ] `CHANGELOG.md` updated under `[Unreleased]`.

---

## Running the gate

The maintainer (`Main`) owns running the full workspace gate. After making
changes, do **not** run `cargo test`/`clippy`/`fmt` if instructed otherwise —
follow the task instructions for who runs verification.

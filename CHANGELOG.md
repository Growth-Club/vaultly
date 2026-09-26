# Changelog

All notable changes to Vaultly are documented here, grouped by release.
Format follows [Keep a Changelog](https://keepachangelog.com/) and
[Conventional Commits](https://www.conventionalcommits.org/). The current
source version, per `rust/Cargo.toml` (`[workspace.package].version`), is
**1.1.0**.

## [Unreleased]

The Rust port is now the only codebase (the TypeScript implementation was
removed). Highlights of the current unreleased feature set:

### Added

- **End-to-end provisioning** — `vaultly target adopt --create` (MCP:
  `deploy_target_adopt` with `allowCreate`) registers a target whose
  Worker/Pages resource does not exist yet (audited as provisioning), and
  the first deploy creates it: Workers via the repository's own `npm run
  deploy`, with missing D1 databases / R2 buckets from the config's own
  `d1_databases` / `r2_buckets` bindings provisioned in the vault-bound
  account first (new D1 ids patched back into the config, `remote: true`
  R2 references skipped). Only config-declared names in that account can
  ever be created; no values reach the agent.
- **Owner-managed agent policy grants** — the CLI and MCP server now load
  `agent-policy.json` from the vault directory on startup (explicit
  `VAULTLY_AGENT_POLICY` still wins on conflict). This makes the documented
  human grant effective: e.g. granting `run` to an agent scoped to one
  vault enables approval-gated maintenance (`vaultly exec <ID>
  migrate:apply --confirm APPLY`, typed word still required per run).
  Group/other-writable grant files are refused fail-closed so an agent
  cannot widen its own permissions.
- **Target preflight** — `vaultly preflight <ID>` and the MCP
  `deploy_target_preflight` tool report worker existence, worker secret
  names, and per-D1-database applied/pending migrations with safety verdicts
  (destructive statements refused unless guarded by `_migration_guard_abort`).
  Read-only, allowed by default, no credential values.
- **Approved maintenance execution** — `vaultly exec <ID> <script>` and the
  MCP `deploy_target_exec` tool run one allowlisted repository script
  (`check:migrations`, `backup:d1`, `backup:verify`, `migrate:apply`,
  `watchdog`, `smoke`) resolved from the repo's own `package.json` with the
  target's Cloudflare scope (plus `D1_BACKUP_*` keys when the vault holds
  them). Mutating scripts require the typed confirmation word and pass
  Vaultly's own pending-migration safety verdicts fail-closed. Gated on the
  `run` policy operation, which stays default-deny for agents
  (`policy_denied` until a human grants it).
- **Agent-safe failure output** — Worker deploy and build failures now include
  scrubbed stdout/stderr tails (already secret-scrubbed), so agents can
  diagnose guard refusals without a human re-run.
- **GitHub secret sync** — `vaultly cf sync-github-secret` and the MCP
  `github_secret_sync` tool copy one vault credential into a GitHub Actions
  repository secret via the human's existing `gh` login. The value is never
  returned, logged, or placed on a command line; repo/secret names are
  strictly validated; gated by the new default-allowed `github_sync` policy
  op. Lets agents keep CI credentials fresh without handling secret values.
- **CLI exports** — `vaultly env <vault>` emits shell export statements and
  `vaultly run <vault> -- <cmd>` runs a command with injected (then cleared)
  environment, with output scrubbed of any secret values.
- **MCP server** (`vaultly mcp`) — 61 agent-safe tools covering vault
  operations and Cloudflare management (cache purge, R2, KV, D1, Pages,
  Workers bindings/triggers, SSL/certs, WAF, load balancers, email routing).
  No tool returns a raw secret value.
- **`cf_accounts` MCP tool** — discover which vaults hold Cloudflare
  credentials (account name + auth method + per-account scope), so agents can
  pick an account without guessing vault names. Inspects key names only —
  never values. `health=true` verifies each credential live.
- **`cf_account_label` MCP tool** — set/clear/read a human-readable alias on a
  Cloudflare account vault (non-secret, stored in plaintext).
- **Interactive TUI** (`vaultly` / `vaultly tui`) — human-only menu UI built on
  ratatui, routing all actions through the same audited, encrypted engine.
- **Cloudflare management** — dynamically add/manage unlimited accounts with
  API tokens or global keys, list zones/DNS, deploy Workers, and manage Worker
  secrets (write-only values).
- **Template vaults** — 14 templates to scaffold a vault for common services.
- **HTTP/REST server** (`vaultly serve`) — local axum edge for agents and CI,
  bearer-token authenticated, reusing the same `VaultEngine`, policy, and audit
  pipeline as the CLI and MCP server. No endpoint returns a raw secret value.
- **Secret generation & rotation** — `vaultly gen` and `vaultly rotate`
  produce CSPRNG secrets (URL/shell-safe alphabet); `rotate --expired` renews
  every expired key in a batch. Both are agent-safe (never print values).
- **Secret expiry** — secrets support TTL / RFC3339 expiry; expired keys are
  flagged in metadata and refused by `run` unless `force=true`.
- **Shell completions** — `vaultly completions <shell>` generates or installs
  bash/zsh/fish completion scripts.
- **Diagnostics** — `vaultly doctor` checks initialization, config validity,
  permissions, keychain, and audit health; `--json` for machine-readable output;
  exits non-zero on errors.

### Changed

- Migrated the entire codebase to Rust: `vaultly-core`, `vaultly` (CLI/TUI/HTTP),
  and `vaultly-mcp` crates in a single Cargo workspace.
- `VaultEngine::run` and `run_command` now take a `RunOptions` struct
  (`cwd`, `timeout_ms`, `allowed_keys`) instead of separate parameters.

### Fixed

- Updated all `run`/`run_command` call sites (CLI, TUI, MCP, HTTP server) to
  match the new `RunOptions` signature — the workspace now builds cleanly.
- `vaultly doctor` now returns a non-zero exit code when any ERROR finding is
  present.
- **Encrypted export/import** — `vaultly export --encrypted <vault> <file>` and
  `vaultly import --encrypted <file> [--vault name]` produce and consume a
  self-contained AES-256-GCM blob that carries its own salt, making it portable
  across any vaultly instance that knows the master password.
- **MCP encrypted tools** — `vault_export_encrypted` and `vault_import_encrypted`
  (2 new MCP tools, 32 total) let agents safely transfer vaults between instances
  without ever exposing plaintext values.

### Security & reliability

- **Reliability / audit chain** — `audit.log` is a hash-chained, structured
  JSON trail (1 MiB rotation) whose integrity can be verified; a deterministic
  backup checksum detects corruption on restore.
- **Hardened parsing** — fuzzing of malformed vault files never panics; restore
  rejects unsupported versions and invalid hex before touching disk.
- **Policy engine** — per-agent allowed operations and rate limiting
  (`VAULTLY_MAX_OPS_PER_MINUTE`, default 60); raw-secret reads excluded from
  default agent policies.

### Testing

- Workspace-wide tests covering crypto round-trips, sanitization, audit-chain
  integrity, restore validation, fuzz cases, `VaultError` conversions,
  secret-injection on timeout, vault-existence checks, audit rotation,
  custom timeouts, key allowlists, encrypted export/import round-trips, and
  scrubber edge cases; CI runs `cargo test`, `cargo clippy`, and `cargo fmt`.

### Documentation

- Rewrote `ARCHITECTURE.md` with accurate LOC, test counts, data-flow
  diagrams, and file map.
- Updated `README.md` command cheat-sheet, `docs/cli-reference.md`, and
  `docs/threat-model.md` to reflect all current commands and features.

## [0.1.0] - Initial

First tagged release of Vaultly. Provides the core feature set that the Rust
port preserves:

- Encrypted credential storage with AES-256-GCM + PBKDF2-SHA256
  (600,000 iterations) and a hash-chained audit log.
- CLI for init / add / get / list / delete / env / run / import / template /
  cf / keychain / backup / restore / protect / mcp / kill / status.
- macOS Keychain auto-unlock, session TTL auto-lock, and emergency killswitch.
- Agent-first model: agents can use secrets (via scrubbed `run`) but cannot
  read raw values.

[Unreleased]: https://github.com/Growth-Club/vaultly/compare/0.1.0...HEAD
[0.1.0]: https://github.com/Growth-Club/vaultly/releases/tag/0.1.0

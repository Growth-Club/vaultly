# Vaultly agent contract

Vaultly is the credential boundary for human and AI work. Agents may request
approved operations, but they must never receive a stored credential, master
password, or arbitrary credential-injected child process.

## Agent-visible MCP surface

The server advertises 31 tools:

- Vault metadata and lifecycle: `vault_list`, `vault_keys`, `vault_meta`,
  `vault_status`, `vault_audit`, `vault_lock`, `vault_unlock`.
- Write-only credentials: `vault_add`, `vault_delete`, `vault_generate`,
  `vault_rotate`, `vault_import`, `vault_export_encrypted`,
  `vault_import_encrypted`.
- Cloudflare discovery and write-only secret management: `cf_accounts`,
  `cf_account_label`, `cf_health`, `cf_zones`, `cf_pages_projects`,
  `cf_workers_list`, `cf_d1_list`, `cf_r2_list`, `cf_kv_list`, `cf_secrets`.
- Approved deployment: `deploy_targets`, `deploy_target_adopt`, `deploy_target`.
- Read-only target preflight: `deploy_target_preflight` (worker existence,
  secret names, per-D1-database applied/pending migrations with safety
  verdicts — no mutations).
- Approved maintenance execution: `deploy_target_exec` runs one allowlisted
  repository script (`check:migrations`, `backup:d1`, `backup:verify`,
  `migrate:apply`, `watchdog`, `smoke`, `purge:test-accounts`) resolved from the repo's own
  `package.json`. Mutating scripts need the typed confirm word (`APPLY`,
  `BACKUP`, `PURGE`) and the
  human-granted `run` operation; the default agent policy denies it
  (`policy_denied`). There is deliberately no generic run: the agent supplies
  only target ID + script name, never a command.
- Value-blind GitHub sync: `github_secret_sync` copies one vault credential
  into a GitHub Actions repository secret via the human's `gh` login. The
  value is never returned, logged, or placed on a command line.
- Policy: `policy_info` (includes the `github_sync` operation).

`vault_run`, generic Cloudflare API calls, arbitrary Pages deployment, and all
unrelated Cloudflare product APIs are not exposed. Compatibility calls for
retired deploy/run names are rejected.

## Deployment protocol

Legacy fallback: a human may register a fully explicit target once:

```bash
VAULTLY_HUMAN_MODE=1 vaultly target add <ID> \
  --provider pages --vault cf-example \
  --account-id <ACCOUNT_ID> --project <PROJECT> \
  --project-dir <DIR> --build-command 'npm run build' \
  --output-dir <DIST> --branch main
```

Agents may also adopt a target dynamically from a Wrangler config in the
current workspace. The selected Cloudflare vault is the only account source;
the project name is read from the config and verified against that account:

```bash
vaultly target adopt --vault cf-example --config apps/api/wrangler.jsonc --json
# First-time provisioning (resource does not exist yet):
vaultly target adopt --vault cf-example --config apps/api/wrangler.jsonc --create --json
```

With `--create` (MCP: `allowCreate`), adoption registers a provisioning
target and the first deploy creates it end to end: the Worker via the
repository's own `npm run deploy`, plus any missing D1 databases / R2
buckets declared in the config's own bindings (new D1 ids patched back into
the config). Only config-declared names in the vault-bound account can ever
be created.

For Workers, adoption requires an `npm run deploy` script so repository
predeploy guards run with Vaultly's scoped Cloudflare environment. Pages and
Workers are both supported, and adoption is idempotent. Agents then use:

```bash
vaultly target list --json
vaultly preflight <ID> --json
vaultly deploy <ID> --json
# Maintenance (needs human-granted `run` op + typed confirm):
vaultly exec <ID> migrate:apply --confirm APPLY --json
```

Recommended agent order for a production release: preflight first (shows
exactly which migrations are pending and their safety verdicts), then exec
the guarded maintenance script when migrations are pending, then deploy.
`preflight` is read-only and allowed by default; `exec` returns
`policy_denied` until a human grants the `run` operation to that agent via
policy file, scoped to the Cloudflare vault.

The target record remains the authorization. Dynamic adoption cannot accept an
account ID, project name, arbitrary command, or path outside the current
workspace. It verifies the live Pages project or Worker exists in the selected
vault's account before saving metadata. Pages builds receive an empty
environment; Vaultly performs the authenticated Cloudflare upload internally.
Worker adoption runs the repository's fixed `npm run deploy` script with only
the scoped Cloudflare credentials.

Run CLI/MCP from the repository root. Agent deployments require exact registered
metadata and a canonical target directory inside that root; Worker targets need
dynamic adoption and exactly one default Wrangler config. `Deploy` permits the
fixed deployment subprocess without enabling generic `Run`; `Exec` permits only
the closed maintenance-script allowlist (still gated on the separately granted
`run` operation plus typed confirmations for mutations). Vaultly rechecks
permissions, registration, config and account after building. Expired selected
credentials are rejected. Keep repository scripts and deployment dependencies
reviewed: scoped subprocess credentials are available to that trusted code.

## Secret rules

- Never call `vaultly get`, `vaultly env`, plaintext export, or arbitrary shell
  execution to inspect credentials.
- Credential writes are write-only and must never be repeated in output.
- Use `vault_keys` for names and expiry metadata only.
- Use `cf_health` to validate credentials without exposing them.
- Report operation, target ID, status, and safe error details clearly to the
  next agent. Do not copy secrets into messages, logs, or issue comments.
- If dynamic adoption is rejected, stop and report the validation or live
  discovery error; do not invent account IDs, project names, or credentials.

## Unlock and communication

The human configures the OS credential store once (macOS Keychain or Linux Secret Service) with:

```bash
VAULTLY_HUMAN_MODE=1 vaultly keychain store
```

MCP and agent-mode CLI processes then unlock through the OS credential store without asking
the agent for the password. In CI, `VAULTLY_MASTER_PASSWORD` may be supplied
to the Vaultly process only. Vaultly never forwards the master password to a
build or returns it over MCP.

Every operation is audited locally. Agents should communicate in structured
terms: `targetId`, `provider`, `status`, `deploymentId`, `url`, and safe error
code. Raw token values are never valid communication data.


Linux 1.2.2 uses encrypted Secret Service sessions and a canonical-store identity. Custom stores still require explicit `VAULTLY_ALLOW_KEYCHAIN=1`. Agent reads never unlock a locked desktop keyring. Default tests must not touch real credential stores; the separately opted-in ignored Linux round-trip test uses only a synthetic key scoped to a temporary directory. Use `cargo +stable` (Linux dependencies require Rust 1.89+) and leave the user's global toolchain unchanged.

# Vaultly agent contract

Vaultly is the credential boundary for human and AI work. Agents may request
approved operations, but they must never receive a stored credential, master
password, or arbitrary credential-injected child process.

## Agent-visible MCP surface

The server advertises 24 tools:

- Vault metadata and lifecycle: `vault_list`, `vault_keys`, `vault_meta`,
  `vault_status`, `vault_audit`, `vault_lock`, `vault_unlock`.
- Write-only credentials: `vault_add`, `vault_delete`, `vault_generate`,
  `vault_rotate`, `vault_import`, `vault_export_encrypted`,
  `vault_import_encrypted`.
- Cloudflare discovery and write-only secret management: `cf_accounts`,
  `cf_account_label`, `cf_health`, `cf_zones`, `cf_pages_projects`,
  `cf_workers_list`, `cf_secrets`.
- Approved deployment: `deploy_targets`, `deploy_target`.
- Policy: `policy_info`.

`vault_run`, generic Cloudflare API calls, arbitrary Pages deployment, and all
unrelated Cloudflare product APIs are not exposed. Compatibility calls for
retired deploy/run names are rejected.

## Deployment protocol

Humans register a target once:

```bash
VAULTLY_HUMAN_MODE=1 vaultly target add <ID> \
  --provider pages --vault cf-example \
  --account-id <ACCOUNT_ID> --project <PROJECT> \
  --project-dir <DIR> --build-command 'npm run build' \
  --output-dir <DIST> --branch main
```

Agents then use only:

```bash
vaultly target list --json
vaultly deploy <ID> --json
```

The target record is the authorization. Agents cannot override the Cloudflare
account, project, branch, local directory, output directory, or build command.
Pages builds receive an empty environment; Vaultly performs the authenticated
Cloudflare upload internally. Worker deployments use the fixed target command
and target account only.

## Secret rules

- Never call `vaultly get`, `vaultly env`, plaintext export, or arbitrary shell
  execution to inspect credentials.
- Credential writes are write-only and must never be repeated in output.
- Use `vault_keys` for names and expiry metadata only.
- Use `cf_health` to validate credentials without exposing them.
- Report operation, target ID, status, and safe error details clearly to the
  next agent. Do not copy secrets into messages, logs, or issue comments.
- If a target is missing or rejected, stop and ask a human to register or
  update it; do not invent account IDs or project names.

## Unlock and communication

The human configures macOS Keychain once with:

```bash
VAULTLY_HUMAN_MODE=1 vaultly keychain store
```

MCP and agent-mode CLI processes then unlock through Keychain without asking
the agent for the password. In CI, `VAULTLY_MASTER_PASSWORD` may be supplied
to the Vaultly process only. Vaultly never forwards the master password to a
build or returns it over MCP.

Every operation is audited locally. Agents should communicate in structured
terms: `targetId`, `provider`, `status`, `deploymentId`, `url`, and safe error
code. Raw token values are never valid communication data.

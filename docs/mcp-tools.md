# Vaultly MCP tools

`vaultly mcp` exposes a deliberately small, agent-safe interface over stdio.
It supports 25 tools: encrypted personal credentials, Cloudflare discovery,
write-only Worker secrets, and validated deployment targets.

No tool returns a raw credential. Agents never receive the master password,
Cloudflare token, or any other stored secret. A human unlocks Vaultly once via
macOS Keychain; the MCP process performs the approved operation locally.

## Credential tools

| Tool | Purpose |
|---|---|
| `vault_list` | List vault names |
| `vault_keys` | List key names and expiry metadata; never values |
| `vault_meta` | Inspect vault metadata and key names |
| `vault_status` | Show lock/session status |
| `vault_add` | Write a credential; write-only confirmation |
| `vault_delete` | Delete one credential |
| `vault_generate` | Generate and store a credential without returning it |
| `vault_rotate` | Rotate one credential or expired credentials |
| `vault_import` | Import a JSON object of credentials; values are never echoed |
| `vault_export_encrypted` | Export an encrypted portable blob |
| `vault_import_encrypted` | Import an encrypted portable blob |
| `vault_lock` | Wipe the in-memory encryption key |
| `vault_unlock` | Unlock through macOS Keychain |
| `vault_audit` | Read the hash-chained audit trail without values |

All credential names and values are validated before storage. Expiry may be
provided as either `ttlSeconds` or `expiresAt`, never both. Plaintext export,
raw secret reads, and arbitrary credential-injected commands are not part of
the agent interface.

## Cloudflare tools

| Tool | Purpose |
|---|---|
| `cf_accounts` | List configured Cloudflare credential vaults; optional health check |
| `cf_account_label` | Read or set non-secret account metadata |
| `cf_health` | Verify one Cloudflare credential set |
| `cf_zones` | List zones/domains |
| `cf_pages_projects` | Discover Pages projects |
| `cf_workers_list` | Discover Workers |
| `cf_secrets` | List, set, or delete Worker secrets; values are write-only |

Cloudflare credentials remain inside Vaultly's authenticated request path. API
responses are scrubbed before they are returned to the agent.

## Approved deployment tools

| Tool | Purpose |
|---|---|
| `deploy_targets` | List registered target metadata |
| `deploy_target_adopt` | Discover, verify, and idempotently register a target from a local Wrangler config |
| `deploy_target` | Deploy one target by ID |

Explicit targets may be registered by a human with `vaultly target add`.
Agents may also call `deploy_target_adopt` with a selected Cloudflare vault and
a Wrangler config inside the current workspace. The account ID comes only from
that vault, the project/provider come only from the config, and the live
Cloudflare account must contain the resource. The agent cannot supply an
account ID, project name, arbitrary command, or outside-workspace path.

For Pages, Vaultly builds without Cloudflare credentials and performs the
Cloudflare upload internally. For Workers, Vaultly invokes the fixed target
deployment path with only the target's approved Cloudflare scope.

## Policy and lifecycle

| Tool | Purpose |
|---|---|
| `policy_info` | Show effective agent limits and allowed operations |

Unknown and retired tool names return a structured error and do not terminate
the server. `vault_run`, `cf_deploy`, and `cf_pages_deploy` are intentionally
not advertised; calls using those compatibility names are rejected.

Add the server to an MCP client:

```json
{
  "mcpServers": {
    "vaultly": {
      "command": "vaultly",
      "args": ["mcp"]
    }
  }
}
```

The integration suite in `rust/crates/vaultly-mcp/tests/mcp_e2e.rs` verifies
the tool list, write-only behavior, locking, audit integrity, and unknown-tool
handling.

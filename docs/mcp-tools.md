# Vaultly MCP Tool Reference

Vaultly exposes a Model Context Protocol (MCP) server via `vaultly mcp` that
agents use to manage credentials and drive Cloudflare. It implements the
tool-only subset of MCP: `initialize`, `notifications/initialized`, `ping`,
`tools/list`, and `tools/call`.

> **No tool returns a raw secret value — by design.** Value-bearing operations
> are write-only (`vault_add`, `vault_generate`, `vault_rotate`,
> `vault_import`) or happen inside a child process / authenticated API request
> (`vault_run`, `cf_*`). `vault_export` is refused outright in the agent context.

There are **30 tools**, grouped below. Start the server with your master
password available:

```json
{
  "mcpServers": {
    "vaultly": {
      "command": "vaultly",
      "args": ["mcp"],
      "env": { "VAULTLY_MASTER_PASSWORD": "your-master-password" }
    }
  }
}
```

> The password is only visible to the MCP server process. The agent
> communicates via JSON-RPC and never sees it. Unlock order at startup:
> macOS Keychain → `VAULTLY_MASTER_PASSWORD` → terminal prompt. Session TTL is
> **120 minutes**; `vault_lock` wipes the key from memory immediately.

## Vault tools

| Tool | Args | Returns | Agent-safety |
|---|---|---|---|
| `vault_list` | — | Vault names | ✓ no values |
| `vault_keys` | `vaultName` | Key names plus per-key metadata (names headline + `Meta` map of `createdAt`/`updatedAt`/`expiresAt`/`expired`) | ✓ meta only, no values |
| `vault_meta` | `vaultName` | Exists, file path, size, secret count, key names | ✓ meta only |
| `vault_status` | — | Unlocked status + TTL, vault list, keychain, platform | ✓ no values |
| `vault_add` | `vaultName`, `key`, `value`, `ttlSeconds`?, `expiresAt`? | Write-only confirmation | ✓ can't read back |
| `vault_delete` | `vaultName`, `key` | Confirmation | ✓ |
| `vault_generate` | `vaultName`, `key`, `length` (def 32, max 4096), `symbols`, `ttlSeconds`?, `expiresAt`? | Confirmation; value never shown | ✓ write-only |
| `vault_rotate` | `vaultName`, `key`, `length`, `symbols` | Confirmation; value never shown | ✓ write-only |
| `vault_import` | `vaultName`, `entriesJson` (JSON object) | Confirmation of count | ✓ write-only |
| `vault_import_encrypted` | `file`, `vaultName?` (def `imported`) | Confirmation of count | ✓ encrypted blob, no values exposed |
| `vault_export` | `vaultName`, `file` | **Blocked for agents** | ⛔ handled by humans |
| `vault_export_encrypted` | `vaultName`, `file` | Confirmation | ✓ AES-256-GCM blob, no plaintext |
| `vault_run` | `vaultName`, `command`, `cwd`?, `force`?, `allowlist`? | Child output (scrubbed) | ✓ sees output only |
| `vault_lock` | — | Locks session, wipes key from memory | ✓ |
| `vault_unlock` | — | Re-opens via macOS Keychain | ✓ |

`vault_export` is listed but always rejected in the MCP/agent context: exporting
plaintext would expose values, which the agent-first model forbids. It returns
*"Export blocked in MCP/agent context"* and directs you to run
`vaultly export` as a human. For agent-safe portability, use
`vault_export_encrypted` instead — it produces an AES-256-GCM blob (with
embedded salt) that carries no plaintext and can be imported by any vaultly
instance with the same master password via `vault_import_encrypted`.

`vault_run` injects the vault's secrets as environment variables into a child
process whose environment has been **cleared** (`env_clear`), runs it under the
policy command timeout (300 000 ms), and scrubs any echoed secret from
stdout/stderr. It refuses to run when any secret is **expired** — pass
`force: true` to override this guard and proceed anyway. The optional
`allowlist` (array of key names) restricts injection to only the listed
secrets, so the child sees a minimal environment. `vault_generate`/`vault_rotate`
produce cryptographically strong random secrets and store them without ever
displaying them.

**Expiry.** `vault_add`/`vault_generate` accept optional `ttlSeconds` (seconds
from now) or `expiresAt` (RFC 3339) — mutually exclusive. Every secret stores
`createdAt`/`updatedAt`/`expiresAt`; `vault_keys` surfaces these timestamps and
reports `expired`, so agents can watch for expiring credentials without ever
seeing their values.

**Killswitch.** A human running `vaultly kill` locally writes a persistent
killswitch marker in the store directory. While that marker is present, the MCP
server refuses every vault operation until a fresh `vault_unlock` clears it —
so an emergency lock takes effect even for long-running agent processes.

## Audit & policy tools

| Tool | Args | Returns |
|---|---|---|
| `vault_audit` | `lines`? (def 20), `vault`?, `caller`? (`agent`/`human`), `after`? (RFC 3339) | Filtered audit entries + **hash-chain integrity note** |
| `vault_policy` | — | Returns the loaded per-agent policy JSON (`VAULTLY_AGENT_POLICY` file, or defaults) |
| `policy_info` | — | Current limits: session TTL, command timeout, max response output; readonly ops banned |

`vault_audit` reports `✓ audit chain intact` when the hash chain verifies clean,
and `⚠ audit chain tampered at N line(s)` with the offending line indices when
it does not (`verify_audit_chain`). Every entry carries `prevHash` = SHA-256 of
the previous line, so tampering with any past line breaks the chain.

`policy_info` returns the live policy: session TTL **120 min**, command timeout
**300 000 ms**, max response output **10 000 bytes**, and the statement that
read operations (`get`/`env`/`export`) are **banned for agents**.

## Template tools

| Tool | Args | Returns |
|---|---|---|
| `template_list` | — | Template names + descriptions |
| `template_apply` | `vaultName`, `templateName`, `values`? (key→value map) | Creates/populates a vault; values write-only |

## Cloudflare tools

See [`cloudflare.md`](./cloudflare.md) for the credential layout and
reliability guarantees. All responses are scrubbed so no token or key ever
reaches the agent.

| Tool | Args | Returns |
|---|---|---|
| `cf_api` | `vaultName`, `method` (GET/POST/PUT/PATCH/DELETE), `path`, `body`? | Auth'd response (scrubbed) |
| `cf_health` | `vaultName` | Valid/invalid credential report |
| `cf_zones` | `vaultName` | Zone list + IDs |
| `cf_dns_list` | `vaultName`, `zoneId`, `type`? | DNS records (optional type filter) |
| `cf_dns_upsert` | `vaultName`, `zoneId`, `type`, `name`, `content`, `ttl`?, `proxied`? | Record result |
| `cf_dns_delete` | `vaultName`, `zoneId`, `recordId` | Confirmation (no values) |
| `cf_workers_list` | `vaultName` | Deployed Worker list |
| `cf_workers_versions` | `vaultName`, `scriptName` | Worker deployment versions |
| `cf_secrets` | `vaultName`, `scriptName`, `action` (list/set/delete), `name`?, `value`? | List names / set / delete; values write-only |
| `cf_deploy` | `vaultName`, `projectDir`, `extraArgs`? | `npx wrangler deploy` result (scrubbed) |

## Health & error behavior

- The server handles **graceful shutdown** on SIGINT/SIGTERM.
- Unknown tool names return a structured `isError` result and the server stays
  alive (covered by `mcp_unknown_tool_returns_error`).
- Responses are size-capped; oversized child output is truncated with a marker.

All behavior is covered by the integration suite at
`crates/vaultly-mcp/tests/mcp_e2e.rs`.

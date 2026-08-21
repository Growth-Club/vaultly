# Vaultly + Cloudflare

Vaultly stores Cloudflare credentials like any other secret and exposes a
**credential-injecting** API for CF operations. The agent drives these tools
and sees only the API response — never the token. This page covers the `cf`
vault convention, every operation, reliability guarantees, and the backup
Worker endpoint.

## The `cf` vault convention

Tools that talk to Cloudflare reference a vault by **account name**. Vaultly
automatically prefixes non-`cf-` names with `cf-`, so `cf zones personal`
resolves to the vault `cf-personal` (`main.rs cf_vault`). Recommended vault
names: `cf-personal`, `cf-work`, etc.

Two credential layouts are supported (`engine.rs build_cf_headers`):

| Layout | Keys in the vault | Notes |
|---|---|---|
| **Token** (recommended) | `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` | API-token scoped; the account ID unlocks account-level endpoints (Workers, secrets) |
| **Legacy email/key** | `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` | Global API key; less safe, used as a fallback when no token is present |

Add credentials with `vaultly add cf-personal -k CLOUDFLARE_API_TOKEN -v <token>`
(or use `vaultly cf add` which prompts / accepts `-t -a -e -k` flags).

## Operations

These are the Cloudflare capabilities. The MCP tools are exposed over
`vaultly mcp`; a subset is mirrored on the `vaultly cf ...` CLI.

| Operation | MCP tool | CLI | Purpose |
|---|---|---|---|
| Generic authenticated request | `cf_api` | — | Arbitrary CF API call (method, path, body) |
| Health check | `cf_health` | — | Verify credentials are still valid |
| List zones | `cf_zones` | `cf zones <account>` | List zones (domains) and IDs |
| List DNS records | `cf_dns_list` | — | List records in a zone (optional type filter) |
| Create/update DNS record | `cf_dns_upsert` | — | Upsert a record (type/name/content/ttl/proxied) |
| Delete DNS record | `cf_dns_delete` | `cf dns-delete <account> <zone> <record>` | Delete a record |
| List Workers | `cf_workers_list` | — | List deployed Workers |
| List Worker versions | `cf_workers_versions` | — | List deployment versions of a script |
| Manage Worker secrets | `cf_secrets` | `cf secrets <account> <script>` | List / set / delete secrets (values write-only) |
| Deploy a Worker | `cf_deploy` | `cf deploy <account> <dir> [--env e]` | Deploy via `npx wrangler` |

### Health check endpoints

`cf_health` validates credentials before you work with them
(`engine.rs health_check`):

- **Token layout** → `GET /user/tokens/verify`; reports active/valid.
- **Legacy email/key** → `GET /user`; confirms the global key authenticates.

This gives clear errors ("Token status: inactive") rather than a confusing
permission failure deep in a workflow.

## Reliability

- **Retry with backoff.** Cloudflare/network calls retry transient failures up
  to `CF_MAX_ATTEMPTS` (default 3) with **exponential backoff** — 200 ms then
  400 ms, capped at 2 s — before surfacing an error (`engine.rs send_with_retry`).
  Retryable conditions are HTTP 5xx responses and transient transport errors
  (connect / timeout / body). JSON-bodied requests are cloneable, so each
  attempt re-sends an identical request.
- **Credential scrubbing.** Every API response (and any error body) is passed
  through the scrubber, so a token or API key that echoes back is replaced with
  `[REDACTED]` before the agent sees it (`engine.rs cf_scrubs_credentials_from_api_responses`).
- **Agent safety.** No CF tool returns credentials; values set as Worker secrets
  are write-only and never echoed back. Worker deploys run with a cleared
  environment and scrubbed output.
- **Account ID required** for account-level endpoints (Workers, Worker secrets);
  zone/DNS operations work with a token alone.

## Backup Worker endpoint

`vaultly backup <url> --token <t>` pushes the **encrypted** vault set to a
Cloudflare Worker you host, and `vaultly restore <url> --token <t>` pulls it
back. See [`backup-restore.md`](./backup-restore.md) for the payload shape,
integrity checksum, and version gate. Only ciphertext ever leaves your machine.

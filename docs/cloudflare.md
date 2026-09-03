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
| Purge zone cache | `cf_cache_purge` | `cf cache-purge <account> <zone> --purge-everything` | Purge cache (whole zone or targeted URLs/files/tags) |
| List R2 buckets | `cf_r2_buckets` | `cf r2 <account>` | List R2 buckets |
| List R2 objects | `cf_r2_objects` | `cf r2 <account> --bucket b` | List objects in a bucket |
| Write R2 object | `cf_r2_object_put` | — | Write an object (value becomes the body) |
| Read R2 object | `cf_r2_object_get` | — | Read an object's content |
| Delete R2 object | `cf_r2_object_delete` | — | Delete an object |
| List KV namespaces | `cf_kv_namespaces` | `cf kv <account>` | List KV namespaces |
| List KV keys | `cf_kv_keys` | `cf kv <account> --namespace ns` | List keys in a namespace |
| Write KV key | `cf_kv_put` | — | Store a KV value |
| Read KV key | `cf_kv_get` | — | Read a KV value |
| Delete KV key | `cf_kv_delete` | — | Delete a KV key |
| List D1 databases | `cf_d1_databases` | `cf d1 <account>` | List D1 databases |
| D1 database info | `cf_d1_info` | `cf d1 <account> --database id` | Show DB info |
| Run D1 query | `cf_d1_query` | — | Run a SQL query against D1 |
| List Pages projects | `cf_pages_projects` | `cf pages <account>` | List Pages projects |
| Deploy Pages site | `cf_pages_deploy` | — | Deploy a static site via `npx wrangler pages deploy` |
| List Worker bindings | `cf_worker_bindings` | `cf bindings <account> <script>` | List a Worker's bindings |
| List Worker triggers | `cf_worker_triggers` | `cf triggers <account> <script>` | List a Worker's triggers |
| SSL settings | `cf_ssl_settings` | `cf ssl <account> <zone>` | Show a zone's SSL settings |
| List custom certificates | `cf_certificates` | `cf certificates <account> <zone>` | List custom certs |
| Order certificate | `cf_certificate_order` | — | Order an advanced cert pack |
| List firewall rules | `cf_firewall_rules` | `cf firewall <account> <zone>` | List WAF firewall rules |
| Create firewall rule | `cf_firewall_rule_create` | — | Create a rule (expression + action) |
| Delete firewall rule | `cf_firewall_rule_delete` | — | Delete a rule |
| List LB pools | `cf_lb_pools` | `cf lb <account>` | List load balancer pools |
| List load balancers | `cf_lb_list` | `cf lb <account>` | List load balancers |
| Email routing settings | `cf_email_settings` | — | Show email routing settings |
| List email rules | `cf_email_rules` | `cf email <account> <zone>` | List email routing rules |
| Create email rule | `cf_email_rule_create` | — | Create an email routing rule |

> ⚠️ The R2 object, KV key, and D1 query tools hit raw-body / non-standard
> response endpoints and are implemented but **not yet verified against a live
> Cloudflare account**. Smoke-test with real credentials before relying on them.

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

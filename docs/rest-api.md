# Vaultly REST API (`vaultly serve`)

`vaultly serve` runs a local HTTP/1.1 server that exposes the same engine,
policy, and audit trail as the CLI and MCP server. It is the natural endpoint
for automated agents and CI jobs that need to manage credentials without a
terminal.

> **Agent-first invariant — by design.** No endpoint returns a raw secret
> value. Every operation is routed through `VaultEngine::op` (policy) + the
> audit log, identical to the CLI and MCP. There is deliberately **no**
> analogue of `get` / `env` / `export`. Values are only ever *written*
> (`/add`) or *injected into a child process* (`/run`, scrubbed output only).

## Starting the server

```bash
# Bearer token from --token or the VAULTLY_SERVER_TOKEN env var.
# The master password comes from VAULTLY_MASTER_PASSWORD or the macOS Keychain.
VAULTLY_MASTER_PASSWORD='...' vaultly serve --bind 127.0.0.1:8799 --token "$VAULTLY_SERVER_TOKEN"
```

- `--bind` (default `127.0.0.1:8799`) — the server binds loopback by default and
  should stay on loopback; it is a local agent/CI endpoint, not a public service.
- The token is required (`--token` or `VAULTLY_SERVER_TOKEN`). It is never
  logged. Requests with a missing or wrong `Authorization: Bearer <token>`
  header get `401 Unauthorized`.
- `/health` is intentionally **unauthenticated** so CI/uptime probes can check
  liveness without a secret. It returns no vault data.

## Authentication

Every endpoint except `/health` requires:

```
Authorization: Bearer <token>
```

A missing or incorrect token returns `401 {"error":"unauthorized"}`.

## Error format

Non-2xx responses carry a JSON object:

```json
{ "error": "human-readable message" }
```

## Endpoints

### `GET /health` — liveness (no auth)

```bash
curl -s http://127.0.0.1:8799/health
```

204 → `200`:

```json
{ "status": "ok", "service": "vaultly", "version": "1.0.0", "unlocked": true }
```

### `GET /vaults` — vault names (names only)

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8799/vaults
```

```json
{ "vaults": ["personal", "cf-personal"] }
```

### `GET /keys?vault=<vault>` — key names + metadata (never values)

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8799/keys?vault=personal"
```

```json
{
  "vault": "personal",
  "keys": [
    {
      "key": "API_KEY",
      "createdAt": "2026-08-21T00:00:00.000Z",
      "updatedAt": "2026-08-21T00:00:00.000Z",
      "expiresAt": null,
      "expired": false
    }
  ]
}
```

No values appear — only names and timestamps.

### `POST /add` — write a secret (write-only)

Body:

```json
{ "vault": "personal", "key": "STRIPE_KEY", "value": "sk_live_xxx", "expires": "2026-12-31T00:00:00Z" }
```

`expires` is optional (RFC 3339). The stored value is encrypted and can **never
be read back** through any Vaultly interface.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"vault":"personal","key":"STRIPE_KEY","value":"sk_live_xxx"}' \
  http://127.0.0.1:8799/add
```

→ `200`:

```json
{ "stored": true, "vault": "personal", "key": "STRIPE_KEY" }
```

### `POST /run` — execute a command with secrets injected

Body:

```json
{ "vault": "personal", "command": "npx wrangler deploy", "cwd": "/path/to/project", "timeout_ms": 300000 }
```

`command` is parsed with `shell-words` (program + args). Secret values are
injected as environment variables for the child process. Output is **scrubbed**
of any secret value before being returned.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"vault":"personal","command":"npx wrangler deploy","cwd":"/path/to/project"}' \
  http://127.0.0.1:8799/run
```

→ `200`:

```json
{
  "command": "npx wrangler deploy",
  "exitCode": 0,
  "scrubbed": false,
  "injected": ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
  "stdout": "… build output …",
  "stderr": ""
}
```

If the command outputs a secret value, `scrubbed` becomes `true` and the value
is removed from `stdout`/`stderr`.

### `POST /rotate-expired` — rotate every expired secret

Body:

```json
{ "vault": "personal", "length": 32, "symbols": false }
```

`length` (default 32) and `symbols` (default false) control the generated
values. Every expired secret is overwritten with a fresh random value, so the
rest of a pipeline can proceed without a human.

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"vault":"personal"}' http://127.0.0.1:8799/rotate-expired
```

→ `200`:

```json
{ "vault": "personal", "rotated": ["DB_PASS"], "count": 1 }
```

## Using in CI

A typical CI job: if `/keys` shows any expired secret, rotate them first, then
run a deploy through `/run` so the child gets fresh credentials without CI ever
holding a plaintext secret.

```bash
TOKEN=$(vaultly ... )   # token provisioned out-of-band, e.g. a CI secret
# Rotate any expired secrets, then deploy in one step:
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"vault":"cf-personal"}' http://127.0.0.1:8799/rotate-expired
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"vault":"cf-personal","command":"npx wrangler deploy","cwd":"$CI_PROJECT_DIR"}' \
  http://127.0.0.1:8799/run
```

Health gate (no token needed):

```bash
curl -fsS http://127.0.0.1:8799/health || exit 1
```

## Security notes

- Bind to loopback (`127.0.0.1`) — this is not a public service.
- Keep `VAULTLY_MASTER_PASSWORD` and the bearer token out of logs and process
  arguments where possible (`VAULTLY_SERVER_TOKEN` avoids `--token` showing up
  in `ps`).
- The server logs every action to `~/.vaultly/audit.log` as caller `http-agent`,
  so agent-initiated HTTP operations are indistinguishable from MCP/CLI agent
  activity in the audit trail (and just as tamper-evident).

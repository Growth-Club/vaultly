# Vaultly MCP tools

`vaultly mcp` exposes a deliberately small, agent-safe interface over stdio.
It supports 28 tools: encrypted personal credentials, Cloudflare discovery,
write-only Worker secrets, value-blind GitHub secret sync, validated
deployment targets, read-only target preflight, and approved target
maintenance execution.

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
the agent interface. A value supplied in a tool request is visible to the
caller by definition; use `vault_generate` or `vault_rotate` when the caller
must not see the generated value.

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
| `deploy_target_preflight` | Read-only check: worker existence, secret names, per-D1-database applied/pending migrations with safety verdicts |
| `deploy_target_exec` | Run one approved maintenance script (`check:migrations`, `backup:d1`, `backup:verify`, `migrate:apply`, `watchdog`, `smoke`); mutating scripts need typed confirm + granted `run` op |
| `github_secret_sync` | Copy one vault credential into a GitHub Actions repo secret; value never returned |

Agents normally call `deploy_target_adopt` with a selected Cloudflare vault and
a Wrangler config inside the current workspace. The account ID comes only from
that vault, the project/provider come only from the config, and the live
Cloudflare account must contain the resource. The agent cannot supply an
account ID, project name, arbitrary command, or outside-workspace path.

`vaultly target add` remains a legacy human-only fallback for repositories that
cannot be discovered from Wrangler configuration.

For Pages, Vaultly builds without Cloudflare credentials and performs the
Cloudflare upload internally. For Workers, Vaultly invokes the fixed target
deployment path with only the target's approved Cloudflare scope.

`Deploy` authorizes this fixed subprocess; default agents still cannot use
generic `Run`. Agent targets must exactly match registered metadata and reside
inside the server's current working directory. Start the server from the
repository root. Agent Worker targets require dynamic adoption and exactly one
default Wrangler config. Permissions, target/config identity, account identity
and unlock state are rechecked after the build. Expired subprocess credentials
are rejected, and authenticated execution records a `DEPLOY_RUN` audit event.

## Target preflight and maintenance execution

`deploy_target_preflight` answers "is this target safe to deploy?" without
mutating anything: it reports whether the Worker exists, which secret names
are set, and — for every D1 database bound in the target's Wrangler config —
applied vs pending migrations with per-file safety verdicts (destructive
statements are refused unless guarded by a `_migration_guard_abort`
trigger, mirroring the repository migration-gate convention).

`deploy_target_exec` runs one approved maintenance script from the
repository's own `package.json` against the target (`check:migrations`,
`backup:d1`, `backup:verify`, `migrate:apply`, `watchdog`, `smoke`). The
agent supplies only the target ID, the script name, and — for mutating
scripts — the typed confirmation word (`APPLY`, `BACKUP`); command bodies
come from the repo, never from agent input. Execution re-validates the
target exactly like a deploy, runs with a cleared environment plus a fixed
credential key set (`CLOUDFLARE_*` and `D1_BACKUP_*` when present in the
vault), scrubs output, audits (`EXEC_RUN`/`EXEC`), and — for mutating
scripts — independently refuses on pending destructive-but-unguarded
migrations or unverifiable migration state (fail closed, defense in depth
alongside the repository's own guards).

Execution is gated on the `run` operation, which is NOT in the default agent
op set: agents receive `policy_denied` until a human grants it, e.g. via a
policy file giving a deploy agent `["list","read_keys","deploy","cf_api",
"github_sync","run"]` scoped to the Cloudflare vault. Grant `run` only to
agents that may perform production database maintenance.

These checks trust the repository scripts and installed executables. They do
not sandbox a malicious deployment script that receives a Cloudflare token.
See [the implementation plan](validated-deployment-plan.md).

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

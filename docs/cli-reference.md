# Vaultly CLI reference

Vaultly is a local encrypted credential store for personal credentials and
Cloudflare. Agent mode is the default. Human-only commands require
`VAULTLY_HUMAN_MODE=1`; agents never receive raw secret values.

## Human setup

```bash
VAULTLY_HUMAN_MODE=1 vaultly init
VAULTLY_HUMAN_MODE=1 vaultly keychain store
VAULTLY_HUMAN_MODE=1 vaultly add personal -k EXAMPLE_TOKEN -v 'value'
```

Human-only operations include initialization, plaintext reads/exports,
deletion, Cloudflare account registration, and legacy explicit target
registration. Agents manage credentials through the write-only MCP tools and
use dynamic target adoption. The macOS Keychain is the preferred unlock bridge
for agents.

## Core commands

| Command | Purpose |
|---|---|
| `vaultly init` | Create the local encrypted store |
| `vaultly add <VAULT> -k <KEY> -v <VALUE>` | Store or update a credential |
| `vaultly get <VAULT> <KEY>` | Read a credential in human mode only |
| `vaultly list [VAULT] [--json]` | List vaults or credential names |
| `vaultly inspect <VAULT>` | Show metadata and credential names |
| `vaultly stats` | Show aggregate metadata |
| `vaultly status` | Show lock/session status |
| `vaultly delete <VAULT> [KEY]` | Delete a credential or vault |
| `vaultly import <FILE> [--vault NAME]` | Import personal credentials |
| `vaultly export <VAULT> <FILE> --encrypted` | Create an encrypted portable export |
| `vaultly generate` | Generate a random value; human-only output |
| `vaultly rotate <VAULT> <KEY>` | Replace a credential without displaying it |
| `vaultly keychain store\|remove` | Manage automatic Keychain unlock |
| `vaultly kill` | Lock and clear the Keychain entry |
| `vaultly keychain store\|remove` | Manage automatic unlock |
| `vaultly completions <SHELL> [--install]` | Print or install shell completions (bash/zsh/fish) |
| `vaultly doctor [--json]` | Diagnose local setup |
| `vaultly version` | Print the installed version |

## Cloudflare commands

```text
vaultly cf add [NAME] [-t TOKEN] [-a ACCOUNT_ID]
vaultly cf list
vaultly cf remove <NAME>
vaultly cf zones <NAME>
vaultly cf pages <NAME>
vaultly cf d1 <NAME>
vaultly cf r2 <NAME>
vaultly cf kv <NAME>
vaultly cf secrets <NAME> <SCRIPT> [--list|--set|--delete]
vaultly cf sync-github-secret --from-vault <VAULT> --from-key <KEY> --repo <OWNER/NAME> --secret <NAME>
```

Copy one vault credential into a GitHub Actions repository secret. The value
travels vault -> `gh` only (via the human's existing `gh` login) and is never
shown, logged, or placed on a command line. Repo must be `owner/name`;
secret names are `A-Z, 0-9, _`. Agents may use it: authorization is enforced
by the `github_sync` policy op, which is allowed by default.

Cloudflare credentials are stored in normal Vaultly vaults using the `cf-`
prefix. Account/project selection for deployments is never taken from agent
arguments.

## Target-bound deployment

Legacy explicit target registration (only for repositories that cannot be
discovered from Wrangler configuration):

```bash
VAULTLY_HUMAN_MODE=1 vaultly target add <ID> \
  --provider pages \
  --vault cf-example \
  --account-id <32-CHAR-ACCOUNT-ID> \
  --project <PAGES-PROJECT> \
  --project-dir <LOCAL-PROJECT-DIR> \
  --build-command 'npm run build' \
  --output-dir <BUILD-OUTPUT-DIR> \
  --branch main
```

Then an agent may run only:

```bash
vaultly target list --json
vaultly preflight <ID> --json
vaultly deploy <ID> --json
# Maintenance scripts (needs human-granted `run` op + typed confirm):
vaultly exec <ID> migrate:apply --confirm APPLY --json
```

### Agent-safe dynamic adoption

An agent can derive a target from a local Wrangler config without receiving or
choosing a Cloudflare account ID:

```bash
vaultly target adopt \
  --vault cf-example \
  --config apps/api/wrangler.jsonc \
  --json
# First-time provisioning (resource does not exist yet):
vaultly target adopt \
  --vault cf-example \
  --config apps/api/wrangler.jsonc \
  --create \
  --json
```

Vaultly resolves the account from the selected vault, reads the Worker or Pages
identity from the config, verifies the resource exists in that account, and
saves an idempotent target. The config must be inside the current workspace.
Worker adoption requires `npm run deploy`, preserving repository predeploy
guards. No raw credential is returned to the agent.

With `--create`, adoption registers a target whose resource does not exist
yet (audited as provisioning); the first deploy then creates it end to end:
Workers are created by the repository's own `npm run deploy`, and missing D1
databases / R2 buckets declared in the config's `d1_databases` / `r2_buckets`
bindings are provisioned in the vault-bound account first (new D1 ids are
patched back into the config). Only config-declared names in that account can
ever be created; `remote: true` R2 references are skipped.

The target record is validated and stored separately from secrets. The agent
cannot override its account ID, project, branch, paths, or build command.
Pages builds run without Cloudflare environment variables; Vaultly performs the
authenticated upload itself.

### Preflight and maintenance execution

```bash
vaultly preflight <ID> --json
vaultly exec <ID> <script> [--confirm WORD] --json
```

`preflight` is read-only (allowed by default): worker existence, worker
secret names, and per-D1-database applied/pending migrations with safety
verdicts. Run it before any deploy or migration.

`exec` runs one approved maintenance script from the repo's own
`package.json` (`check:migrations`, `backup:d1`, `backup:verify`,
`migrate:apply`, `watchdog`, `smoke`, `purge:test-accounts`) with the target's Cloudflare scope
plus `D1_BACKUP_*` keys when the vault holds them. Mutating scripts require
the typed confirmation (`APPLY`, `BACKUP`, `PURGE`) and fail closed on unsafe or unverifiable migration
state. Execution is gated on the `run` policy operation (default-deny for
agents; a human grants it via policy file). Migration backup keys are added
once by a human: `vaultly add --vault <cf-vault> --key D1_BACKUP_R2_BUCKET
--value ...` (same for `D1_BACKUP_PASSPHRASE`).

## Agent unlock

For local agents, use the Keychain setup once. For isolated CI, set
`VAULTLY_MASTER_PASSWORD` in the process environment. Vaultly never passes the
master password to a child process and never prompts in agent mode.

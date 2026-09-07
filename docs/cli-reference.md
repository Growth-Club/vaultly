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

Human-only operations include initialization, adding/importing credentials,
plaintext reads/exports, deletion, Cloudflare account registration, and target
registration. The macOS Keychain is the preferred unlock bridge for agents.

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
| `vaultly doctor [--json]` | Diagnose local setup |
| `vaultly version` | Print the installed version |

## Cloudflare commands

```text
vaultly cf add [NAME] [-t TOKEN] [-a ACCOUNT_ID]
vaultly cf list
vaultly cf remove <NAME>
vaultly cf zones <NAME>
vaultly cf pages <NAME>
vaultly cf secrets <NAME> <SCRIPT> [--list|--set|--delete]
```

Cloudflare credentials are stored in normal Vaultly vaults using the `cf-`
prefix. Account/project selection for deployments is never taken from agent
arguments.

## Target-bound deployment

Register deployment metadata once as a human:

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
vaultly deploy <ID> --json
```

### Agent-safe dynamic adoption

An agent can derive a target from a local Wrangler config without receiving or
choosing a Cloudflare account ID:

```bash
vaultly target adopt \
  --vault cf-example \
  --config apps/api/wrangler.jsonc \
  --json
```

Vaultly resolves the account from the selected vault, reads the Worker or Pages
identity from the config, verifies the resource exists in that account, and
saves an idempotent target. The config must be inside the current workspace.
Worker adoption requires `npm run deploy`, preserving repository predeploy
guards. No raw credential is returned to the agent.

The target record is validated and stored separately from secrets. The agent
cannot override its account ID, project, branch, paths, or build command.
Pages builds run without Cloudflare environment variables; Vaultly performs the
authenticated upload itself.

## Agent unlock

For local agents, use the Keychain setup once. For isolated CI, set
`VAULTLY_MASTER_PASSWORD` in the process environment. Vaultly never passes the
master password to a child process and never prompts in agent mode.

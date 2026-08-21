# Vaultly CLI Reference

`vaultly` is the command-line client. Run `vaultly --help` for the live list;
this page is the generated reference, grounded in the clap command definitions
(`rust/crates/vaultly/src/main.rs`).

## Usage

```
vaultly [OPTIONS] <COMMAND>
```

Run `vaultly` with no arguments:

- On an interactive terminal → launches the interactive **TUI**.
- Otherwise (piped / non-TTY) → prints help.

## Global options

| Flag | Meaning |
|---|---|
| `-q, --quiet` | Suppress decorative/advisory output (also honored via `VAULTLY_QUIET=1`) |
| `--no-color` | Disable colored output (also honors `NO_COLOR` env var) |
| `-h, --help` | Print help |
| `-V, --version` | Print version (`vaultly <ver>`) |

## Agent mode

`VAULTLY_AGENT_MODE=1` puts the CLI in **agent mode**. Every command that reads
or writes raw secret values is blocked with a clear message and exit code 1:

**Blocked:** `init`, `add`, `get`, `get --export`, `env`, `import`, `backup`,
`restore`, `protect`, `template`, `keychain` (all subs), `kill`, `status`,
`tui`, `copy`, `rename`, `mv`, `cp`, `export`, `cf add`, `cf use`, `cf remove`.

**Available (agent-safe, no raw values):** `list`, `inspect`, `stats`,
`doctor`, `run`, `generate`, `rotate`, `completions`, `version`, `mcp`,
`serve`, `cf list`, `cf zones`, `cf secrets`, `cf deploy`, `cf dns-delete`.

The guiding rule: *agents can never read or write a raw secret value;* use
`vaultly run <vault> -- <command>` for execution.

## Commands

### Core vault operations

| Command | Purpose |
|---|---|
| `vaultly init` | Initialize a vault store with a master password (resets all vaults if rerun, with confirmation) |
| `vaultly status` | Show version, store directory, vault names, keychain status, platform, agent mode; warns if any secret is expired |
| `vaultly stats` | Per-vault key counts + totals (metadata only) |
| `vaultly doctor` | Environment diagnostics: init, directory, config, keychain, password source, file permissions |
| `vaultly list [VAULT] [--json]` | List all vaults (or key **names** of a vault); `--json` for machine-readable output |
| `vaultly inspect <VAULT>` | File-level metadata (path, size, modified) + key names (requires unlock) — no values |
| `vaultly add <VAULT> -k <KEY> -v <VALUE> [--ttl SECONDS] [--expires RFC3339]` | Add or update a secret. Optional expiry: `--ttl` = seconds from now, `--expires` = absolute RFC 3339 timestamp (mutually exclusive) |
| `vaultly get <VAULT> <KEY> [--export]` | Read a secret (human only); `--export` prints a shell-safe `export KEY='…'` line |
| `vaultly env <VAULT>` | Print `export KEY='…'` statements for a vault (human only) |
| `vaultly delete <VAULT> [KEY]` | Delete a secret, or a whole vault when no key is given |
| `vaultly run <VAULT> -- <COMMAND>… [--timeout MS] [--force]` | Run a command with secrets injected; env cleared; output scrubbed. Default timeout 86 400 000 ms (24 h) for CLI. Refuses when any secret is expired unless `--force` is given |
| `vaultly copy <VAULT> <KEY>` | Copy a secret to the macOS clipboard (`pbcopy`) |
| `vaultly rename <OLD> <NEW>` | Rename a vault (moves all secrets, deletes the old vault) |
| `vaultly mv <VAULT> <KEY> <TO_VAULT>` | Move a secret to another vault |
| `vaultly cp <VAULT> <KEY> <TO_VAULT>` | Copy a secret to another vault (keeps the original) |
| `vaultly generate / gen [-l LENGTH] [-s]` | Generate a random secret; `--length` (default 32), `--symbols` for punctuation |
| `vaultly rotate <VAULT> <KEY> [-l LENGTH] [-s] [--expired] [--ttl SECONDS] [--expires RFC3339]` | Overwrite a secret with a new random value (length default 32 via `--length`, `--symbols` for punctuation). `--expired` rotates every **expired** secret in the vault; `--ttl`/`--expires` set the new secret's expiry (mutually exclusive) |
| `vaultly template [NAME] [--list]` | List templates (`--list` or no name) or create a vault from a template |

### Bulk & transfer

| Command | Purpose |
|---|---|
| `vaultly import FILE [--vault NAME] [--delete-after] [--dry-run] [--encrypted]` | Import secrets from `.env` / `.json` / `.yaml` / `.csv`; default target vault `imported`; `--delete-after` securely removes the source; `--dry-run` reports without writing; `--encrypted` imports a portable encrypted export blob |
| `vaultly export <VAULT> <FILE> [--encrypted]` | Export secrets to a plaintext file (confirmed; mode `0600`); `--encrypted` produces a portable, AES-256-GCM encrypted blob importable by any vaultly instance with the same master password |

### Session & keychain

| Command | Purpose |
|---|---|
| `vaultly lock` | Lock the session; wipe the derived key from memory |
| `vaultly unlock` | Re-open via the macOS Keychain |
| `vaultly keychain store \| remove \| status` | Store / remove / check the master password in macOS Keychain for auto-unlock |
| `vaultly kill` | Emergency killswitch: lock the vault **and** clear the Keychain entry |
| `vaultly protect [DIR]` | Add AI-tool ignore rules (`.env`, `*.vault`, `.pem`, …) to `.gitignore` / `.windsurfrules` in DIR (default `.`) |
| `vaultly tui` | Interactive menu (human only) |
| `vaultly mcp` | Start the MCP server for AI agents |
| `vaultly serve [--bind HOST:PORT] [--token TOKEN]` | Start local HTTP/REST server (agent-first, bearer-auth; see `rest-api.md`) |

### REST server (`serve`)

`vaultly serve` runs a local HTTP/1.1 server exposing the same engine, policy,
and audit trail as the CLI and MCP — the natural endpoint for agents and CI
jobs. See [`rest-api.md`](./rest-api.md) for the full reference.

```
vaultly serve [--bind HOST:PORT] [--token TOKEN]
```

- `--bind` (default `127.0.0.1:8799`) — loopback by default; keep it local.
- The bearer token is required, from `--token` or the `VAULTLY_SERVER_TOKEN`
  env var (prefer the env var so it never appears in `ps`). It is never logged.
- Every endpoint except `GET /health` (unauthenticated liveness probe) requires
  `Authorization: Bearer <token>`.
- Endpoints: `GET /health`, `GET /vaults`, `GET /keys?vault=<vault>`,
  `POST /add`, `POST /run`, `POST /rotate-expired`. No endpoint returns a raw
  secret value.



Credentials live in a vault prefixed `cf-` (a bare name is auto-prefixed).

| Command | Purpose |
|---|---|
| `vaultly cf add [NAME] [-t TOKEN] [-a ACCOUNT_ID] [-e EMAIL] [-k API_KEY]` | Add a CF account (API token OR global email+key); flags skip prompts |
| `vaultly cf list` | List CF accounts |
| `vaultly cf use <NAME>` | Print `export` statements to activate an account (for `eval $(vaultly cf use x)`) |
| `vaultly cf deploy <NAME> <DIR> [--env E]` | Deploy a Worker via `npx wrangler deploy` (credentials injected, output scrubbed) |
| `vaultly cf remove <NAME>` | Remove a CF account (confirmed) |
| `vaultly cf zones <NAME>` | List zones (domains) + IDs |
| `vaultly cf secrets <NAME> <SCRIPT> [-l] [-s NAME] [-v VAL] [-d NAME]` | Manage Worker secrets: `--list`, `--set`, `--value` (write-only), `--delete` |
| `vaultly cf dns-delete <NAME> <ZONE_ID> <RECORD_ID>` | Delete a DNS record (agent-safe) |

> The richer DNS/zones/Workers API (list, upsert, workers versions, health,
> generic API call) is exposed only over MCP — see
> [`mcp-tools.md`](./mcp-tools.md) and [`cloudflare.md`](./cloudflare.md).

### Backup & restore

| Command | Purpose |
|---|---|
| `vaultly backup --url <URL> --token <T>` | Push encrypted vaults to your backup Worker |
| `vaultly restore --url <URL> --token <T>` | Pull, validate, then write vaults |

See [`backup-restore.md`](./backup-restore.md) for payload, checksum, and
version gate.

### Completions & version

| Command | Purpose |
|---|---|
| `vaultly completions <SHELL> [--output FILE] [--install]` | Generate shell completions. Shells: bash, zsh, fish, …; `--output` writes to a file; `--install` writes to the standard completion dir |
| `vaultly version` | Print the program version |


Install locations for `completions --install`:
bash → `~/.local/share/bash-completion/completions/vaultly`; zsh →
`~/.zfunc/_vaultly`; fish → `~/.config/fish/completions/vaultly.fish`.

## Usage block (`vaultly --help` style)

```
vaultly -q/--quiet [--no-color] <COMMAND>

Commands:
  init             Initialize Vaultly with a master password
  add <VAULT> -k <KEY> -v <VALUE> [--ttl SECONDS | --expires RFC3339]   Add/update a secret (optional expiry)
  get <VAULT> <KEY> [--export]         Get a secret value (blocked in agent mode)
  list [VAULT] [--json]                List vaults or keys in a vault
  delete <VAULT> [KEY]                 Delete a secret or a whole vault
  env <VAULT>                          Output shell export statements (blocked in agent mode)
  import <FILE> [--vault] [--delete-after] [--dry-run]
  backup --url <URL> --token <T>       Push encrypted vaults to a Worker
  restore --url <URL> --token <T>      Pull encrypted vaults from a Worker
  protect [DIR]                        Add AI-tool ignore rules
  run <VAULT> -- <COMMAND>… [--timeout MS]
  mcp                                  Start MCP server for AI agents
  cf <SUBCOMMAND>                      Manage Cloudflare accounts
  template [NAME] [--list]             Create a vault from a template
  keychain <store|remove|status>       Manage macOS Keychain integration
  kill                                 Emergency killswitch
  status                               Show vault status
  tui                                  Interactive menu (human only)
  version                              Print version
  generate|gen [-l LEN] [-s]           Generate a random secret
  rotate <VAULT> <KEY> [-l LEN] [-s]   Rotate a secret in place
  copy <VAULT> <KEY>                   Copy a secret to the clipboard
  rename <OLD> <NEW>                   Rename a vault
  mv <VAULT> <KEY> <TO_VAULT>          Move a secret
  cp <VAULT> <KEY> <TO_VAULT>          Copy a secret
  completions <SHELL> [--output] [--install]
  inspect <VAULT>                      Show vault metadata
  export <VAULT> <FILE>                Export all secrets (blocked in agent mode)
  stats                                Show usage stats
  doctor                               Run environment diagnostics

cf subcommands:
  add, list, use, deploy, remove, zones, secrets, dns-delete
```

## Exit codes

- `0` — success.
- `1` — any error path: not initialized, wrong master password, missing vault /
  secret, invalid name, import/export failure, Cloudflare or backup/restore
  failure, and any command **blocked in agent mode**.
- Commands that relay a child's exit code (e.g. `run`, `cf deploy`) exit with
  the child's code.

## Environment variables

| Variable | Meaning |
|---|---|
| `VAULTLY_DIR` | Store directory (default `~/.vaultly`); also isolates the test keychain |
| `VAULTLY_MASTER_PASSWORD` | Master password for non-interactive CLI and MCP unlock |
| `VAULTLY_AGENT_MODE=1` | Agent mode: block value-reading/writing commands, `tui` |
| `VAULTLY_MAX_OPS_PER_MINUTE` | Per-agent rate-limit override (default `60`) |
| `VAULTLY_AUTO_LOCK_MINUTES` | Idle auto-lock timeout (minutes): locks the session after inactivity since the last operation; recorded on `config.json` at `init` |
| `VAULTLY_SERVER_TOKEN` | Bearer token for `vaultly serve` REST server (alternative to `--token`; preferred so it never shows in `ps`) |
| `VAULTLY_QUIET=1` | Equivalent to `--quiet` |
| `NO_COLOR` | Disable colored output (equivalent to `--no-color`) |

## Example

```
vaultly init
vaultly add personal -k MY_API_KEY -v sk_live_xxx
vaultly run personal -- ./script.sh
vaultly list personal
vaultly add cf-personal -k CLOUDFLARE_API_TOKEN -v <token>
vaultly cf zones personal
```

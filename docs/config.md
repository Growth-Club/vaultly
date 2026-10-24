# Vaultly local storage

Vaultly stores its local state under `~/.vaultly` by default. Set
`VAULTLY_DIR` for an isolated store or CI workspace.

```text
~/.vaultly/
├── config.json                 # salt, verifier, policy/session settings
├── agent-policy.json           # owner-managed per-agent operation grants
├── audit.log                   # hash-chained metadata-only audit log
├── deployment-targets.json     # non-secret validated deployment targets
└── vaults/                     # encrypted credential files
```

Files are created with restrictive permissions and written atomically. Vault
files contain ciphertext only. Deployment targets contain account/project
metadata but never Cloudflare tokens.

## Agent policy grants

`agent-policy.json` is the owner-managed grant mechanism: per-agent
operation allowlists, optionally scoped to specific vaults. Both the CLI
and the MCP server load it automatically on startup (an explicit
`VAULTLY_AGENT_POLICY` file is loaded afterwards and wins on conflict).
This is how a human grants the `run` operation so approval-gated
maintenance scripts work (`vaultly exec <ID> migrate:apply --confirm
APPLY`): the grant plus the per-run typed confirmation word together
record owner approval. The file must not be group/other-writable —
Vaultly refuses to load it otherwise, so an agent cannot widen its own
permissions.

## Environment variables

| Variable | Purpose |
|---|---|
| `VAULTLY_DIR` | Override the local store directory |
| `VAULTLY_MASTER_PASSWORD` | Non-interactive process-only unlock source |
| `VAULTLY_HUMAN_MODE=1` | Enable human-only CLI operations for one process |
| `VAULTLY_AGENT_MODE=0` | Compatibility opt-out; human mode is clearer |
| `VAULTLY_ALLOW_KEYCHAIN=1` | Explicitly allow the OS credential store with custom `VAULTLY_DIR` |
| `VAULTLY_MAX_OPS_PER_MINUTE` | Override the agent rate limit |
| `VAULTLY_AGENT_POLICY` | Load an additional agent policy file |

The master password is never persisted in `config.json`, passed to builds, or
returned through MCP.


## Linux desktop auto-unlock

Vaultly 1.2.2 supports Linux Secret Service (GNOME Keyring, or a compatible desktop service) directly through encrypted D-Bus sessions. No `secret-tool` executable is required. Build this version with a current stable Rust toolchain; its Linux cryptography dependencies require Rust 1.89 or newer.

The owner runs `VAULTLY_HUMAN_MODE=1 vaultly keychain store` in a desktop terminal and enters the existing vault's master password at Vaultly's hidden prompt. A custom store also needs its exact `VAULTLY_DIR` and the explicit `VAULTLY_ALLOW_KEYCHAIN=1` opt-in on that command and subsequent CLI/MCP launches. This does not change the master password, recreate the vault, or grant deployment/maintenance permissions.

Linux entries are scoped to the canonical store directory. A different store cannot obtain the saved key. Automatic agent reads use already-unlocked entries only; a locked desktop keyring must be unlocked by its owner. Custom test stores remain isolated by default. The optional ignored Linux backend round-trip test creates and removes one synthetic entry bound to a temporary directory; it never reads or changes a production master password.

`VAULTLY_MASTER_PASSWORD` remains a process-only alternative. An empty value and a rejected value produce different errors. A successful invocation does not persist a separate global unlock session. Agents must not collect passwords, enable human mode, modify policy, or read raw credential values.

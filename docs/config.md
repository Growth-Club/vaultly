# Vaultly local storage

Vaultly stores its local state under `~/.vaultly` by default. Set
`VAULTLY_DIR` for an isolated store or CI workspace.

```text
~/.vaultly/
├── config.json                 # salt, verifier, policy/session settings
├── audit.log                   # hash-chained metadata-only audit log
├── deployment-targets.json     # non-secret validated deployment targets
└── vaults/                     # encrypted credential files
```

Files are created with restrictive permissions and written atomically. Vault
files contain ciphertext only. Deployment targets contain account/project
metadata but never Cloudflare tokens.

## Environment variables

| Variable | Purpose |
|---|---|
| `VAULTLY_DIR` | Override the local store directory |
| `VAULTLY_MASTER_PASSWORD` | Non-interactive process-only unlock source |
| `VAULTLY_HUMAN_MODE=1` | Enable human-only CLI operations for one process |
| `VAULTLY_AGENT_MODE=0` | Compatibility opt-out; human mode is clearer |
| `VAULTLY_ALLOW_KEYCHAIN=1` | Explicitly allow Keychain with custom `VAULTLY_DIR` |
| `VAULTLY_MAX_OPS_PER_MINUTE` | Override the agent rate limit |
| `VAULTLY_AGENT_POLICY` | Load an additional agent policy file |

The master password is never persisted in `config.json`, passed to builds, or
returned through MCP.

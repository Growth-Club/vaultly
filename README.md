<div align="center">

# 🔐 Vaultly

### Agent-first encrypted credential manager

**AI agents can _use_ your secrets. They can never _read_ them.**

[![Rust](https://img.shields.io/badge/Rust-1.96-000000?logo=rust&logoColor=white)](https://rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-24_tools-8A2BE2)](#ai-agent-integration-mcp)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![Security](https://img.shields.io/badge/encryption-AES--256--GCM-red)](#security)

</div>

---

## ✨ Overview

Your AI agents need credentials to deploy, call APIs, and manage infrastructure —
but you don't want them **reading** your tokens. Vaultly sits between your agents
and your secrets:

```
Agent: "Deploy my Worker to Cloudflare"
         │
         ▼
    ┌─────────┐     ┌──────────────┐     ┌────────────┐
    │  Agent   │────▶│   Vaultly    │────▶│  Cloudflare │
    │          │◀────│  (scrubbed)  │◀────│   API       │
    └─────────┘     └──────────────┘     └────────────┘
     sees: "✅ Deployed"    holds credential   real API call
     never sees: token ●    returns status     response
```

Agents request approved operations through Vaultly. For deployment, the build
receives no Cloudflare credentials; Vaultly holds the credential only inside
the authenticated API call and returns structured status. The policy engine
lets you grant agents fine-grained access without exposing a raw value.

## 🚀 Quickstart

```bash
# 1. Install (Rust)
git clone https://github.com/Growth-Club/vaultly.git
cd vaultly/rust && cargo build --release
cp target/release/vaultly target/release/vaultly-mcp ~/.local/bin/   # or anywhere on PATH

# 2. Initialize your master password (the rare human-only operation)
VAULTLY_HUMAN_MODE=1 vaultly init

# 3. Add a credential
VAULTLY_HUMAN_MODE=1 vaultly add github -k GITHUB_TOKEN -v "ghp_xxx"

# 4. Read it back (humans only — blocked in agent mode)
VAULTLY_HUMAN_MODE=1 vaultly get github GITHUB_TOKEN

# 5. Register a deployment target as a human
VAULTLY_HUMAN_MODE=1 vaultly target add gateandtech-web \
  --provider pages --vault cf-gateandtech \
  --account-id <ACCOUNT_ID> --project gateandtech-all-in-one-web \
  --project-dir /path/to/GATEAndTech-All-In-One-Web \
  --build-command "npm run build" --output-dir apps/web/dist --branch main

# 6. Let an agent deploy by target ID only
vaultly deploy gateandtech-web --json

# 7. Set up the MCP server for your AI tool
vaultly mcp                          # add to your tool's MCP config (see below)
```

For setup, use the CLI help and the one-time human bootstrap above.

### Human and agent unlock modes

Vaultly runs in agent mode by default. Human-only commands can be enabled for
one command with `VAULTLY_HUMAN_MODE=1`. Human commands use the stored macOS
Keychain credential when available and otherwise prompt securely. For
unattended agents or CI, provide the master password through
`VAULTLY_MASTER_PASSWORD`:

```bash
VAULTLY_MASTER_PASSWORD="$VAULTLY_MASTER_PASSWORD" \
  vaultly deploy gateandtech-web --json
```

Agent mode never prints raw secret values, never forwards the master password
to the child command, and never waits for an interactive password prompt.

One-time human bootstrap for local agents:

```bash
VAULTLY_HUMAN_MODE=1 vaultly keychain store
```

After this, `vaultly mcp` and `vaultly deploy` can unlock through the
Keychain without putting the master password in an agent configuration. If a
custom `VAULTLY_DIR` is required, also set `VAULTLY_ALLOW_KEYCHAIN=1`.

## 📖 Command Cheat-Sheet

```
vaultly init                              Create master password
vaultly add <vault> -k KEY -v VALUE       Add a secret (--ttl/--expires for expiry)
vaultly get <vault> <key>                 Get a secret value (human only)
vaultly list [vault] [--json]             List vaults or key names
vaultly inspect <vault>                   Vault metadata + key names (no values)
vaultly stats                             Aggregated key counts (metadata only)
vaultly delete <vault> [key]              Delete a secret or vault
vaultly env <vault>                       Output shell export statements (human only)
vaultly export <vault> <file>             Export plaintext (--encrypted for portable blob)
vaultly import <file> [--vault name]      Import .env/.json/.yaml/.csv (--encrypted for blob)
vaultly target add|list|remove ...       Manage human-approved deployment targets
vaultly deploy <target> [--json]         Deploy a fixed target without exposing credentials
vaultly gen [-l LENGTH] [-s]              Generate a random secret
vaultly rotate <vault> <key> [--expired]  Rotate a secret (or all expired) to a new random value
vaultly doctor [--json]                   Environment diagnostics + health checks
vaultly cf add|list|remove|zones|pages|secrets  Cloudflare credentials/discovery
vaultly keychain store|remove             macOS Keychain lock/unlock
vaultly mcp                               Start the MCP server (24 agent tools)
vaultly keychain store|remove             Manage Keychain auto-unlock
vaultly kill                              Emergency lock + clear Keychain
vaultly status                            Session and vault info
vaultly version                           Print version
```

## 🤖 AI Agent Integration (MCP)

Add to your AI tool's MCP config:

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

> 💡 With macOS Keychain (`vaultly keychain store`), no password is needed in config.

The MCP interface is intentionally small: encrypted credential operations,
Cloudflare discovery/write-only Worker secret management, and approved
deployment targets. Agents never choose an arbitrary account, project,
directory, branch, or command.

Deployment is target-bound: agents use `deploy_targets` to discover approved
targets and `deploy_target` with only a `targetId`. The old arbitrary
`vault_run` and `cf_pages_deploy` paths are disabled for agents.

> 🚫 **Write-only for agents.** No MCP tool ever returns a raw secret value;
> agent-facing `vault_add`/`cf_secrets` store what you give them, and
> Deployment builds run without vault credentials; Vaultly performs the
> Cloudflare upload internally and returns only structured deployment status.

## 🛡️ Security Model

| Feature | Details |
|---------|---------|
| Encryption | AES-256-GCM + PBKDF2-SHA256 (600,000 iterations) |
| Output scrubbing | Secrets redacted from ALL command output (exact, URL, base64, partial) |
| Session TTL | Auto-lock after 120 minutes |
| Policy engine | Per-agent allowed ops + rate limiting (60 ops/min default) |
| Audit trail | Hash-chained, structured JSON log of every operation |
| Target-bound deployment | Agents cannot select an arbitrary account, project, branch, or command |

**The core invariant:** agents get approved *operations*, never raw secrets.
Arbitrary credential-injecting commands are disabled for agents; deployments
must use a human-registered target.

Useful commands:

```bash
VAULTLY_HUMAN_MODE=1 vaultly keychain store  # auto-unlock via macOS Keychain
VAULTLY_HUMAN_MODE=1 vaultly kill            # 🚨 emergency lock
VAULTLY_HUMAN_MODE=1 vaultly status          # session info
```

## 📁 Storage

```
~/.vaultly/
├── config.json          # salt + verifier (no secrets)
├── audit.log            # structured JSON audit trail
└── vaults/              # one AES-256-GCM file per vault
```

See [docs/config.md](docs/config.md) for the full config reference (fields, env
vars, theme, validation) and [docs/example-config.json](docs/example-config.json)
for an annotated `config.json`.

## 🏗️ Documentation

- [docs/config.md](docs/config.md) — configuration, environment variables, TUI theme, validation
- [docs/example-config.json](docs/example-config.json) — annotated `config.json` example
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design and diagrams
- [CONTRIBUTING.md](CONTRIBUTING.md) — developer setup and PR checklist
- [CHANGELOG.md](CHANGELOG.md) — release history
- [PLAN.md](PLAN.md) — roadmap

---

<div align="center">

**Built for the agent era.** 🔐

[Report Bug](https://github.com/Growth-Club/vaultly/issues) · [Request Feature](https://github.com/Growth-Club/vaultly/issues)

</div>

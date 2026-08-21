<div align="center">

# 🔐 Vaultly

### Agent-first encrypted credential manager

**AI agents can _use_ your secrets. They can never _read_ them.**

[![Rust](https://img.shields.io/badge/Rust-1.96-000000?logo=rust&logoColor=white)](https://rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-28_tools-8A2BE2)](#ai-agent-integration-mcp)
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
     sees: "✅ Deployed"    injects token      real API call
     never sees: token ●    scrubs output      response
```

Agents run real commands with your secrets injected into the environment —
and every trace of those secrets is scrubbed from the output they see. The
policy engine lets you grant agents fine-grained access without ever exposing
a raw value.

## 🚀 Quickstart

```bash
# 1. Install (Rust)
git clone https://github.com/Growth-Club/vaultly.git
cd vaultly/rust && cargo build --release
cp target/release/vaultly target/release/vaultly-mcp ~/.local/bin/   # or anywhere on PATH

# 2. Initialize your master password
vaultly init

# 3. Add a credential
vaultly add github -k GITHUB_TOKEN -v "ghp_xxx"

# 4. Read it back (humans only — blocked in agent mode)
vaultly get github GITHUB_TOKEN

# 5. Let an agent use it
vaultly run github -- git push       # injects env, scrubs output

# 6. Set up the MCP server for your AI tool
vaultly mcp                          # add to your tool's MCP config (see below)
```

For a guided setup — Cloudflare accounts, templates, macOS Keychain — run `bash setup.sh`.

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
vaultly run <vault> -- <cmd>              Run with injected env (scrubbed, --force to override expiry)
vaultly gen [-l LENGTH] [-s]              Generate a random secret
vaultly rotate <vault> <key> [--expired]  Rotate a secret (or all expired) to a new random value
vaultly copy <vault> <key>                Copy secret to macOS clipboard
vaultly rename <old> <new>                Rename a vault
vaultly mv <vault> <key> <to_vault>       Move a secret to another vault
vaultly cp <vault> <key> <to_vault>       Copy a secret to another vault
vaultly serve [--bind ADDR] [--token T]   Start local HTTP/REST server (agent-first)
vaultly doctor [--json]                   Environment diagnostics + health checks
vaultly template [name] [--list]          Create vault from a template (14 built-in)
vaultly completions <SHELL> [--install]   Generate shell completions (bash/zsh/fish)
vaultly cf add|list|use|deploy|secrets|remove|zones|dns-delete  Cloudflare management
vaultly keychain store|remove|status      macOS Keychain lock/unlock
vaultly backup -u URL -t TOKEN            Push encrypted backup (ciphertext only)
vaultly restore -u URL -t TOKEN           Pull encrypted backup
vaultly protect [dir]                     Add AI-tool ignore rules
vaultly mcp                               Start the MCP server (28 agent tools)
vaultly lock                              Wipe key from memory
vaultly unlock                            Re-open via Keychain
vaultly kill                              Emergency lock + clear Keychain
vaultly status                            Session and vault info
vaultly version                           Print version
vaultly tui                               Interactive menu (human only)
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

The 17 MCP tools cover vault operations (`vault_list`, `vault_keys`,
`vault_add`, `vault_delete`, `vault_run`, `vault_status`, `vault_lock`,
`vault_unlock`, `vault_audit`) and Cloudflare management (`cf_api`, `cf_zones`,
`cf_dns_list`, `cf_dns_upsert`, `cf_workers_list`, `cf_secrets`, `cf_deploy`,
`cf_health`).

> 🚫 **Write-only for agents.** No MCP tool ever returns a raw secret value;
> agent-facing `vault_add`/`cf_secrets` store what you give them, and
> `vault_run` surfaces only scrubbed output.

## 🛡️ Security Model

| Feature | Details |
|---------|---------|
| Encryption | AES-256-GCM + PBKDF2-SHA256 (600,000 iterations) |
| Output scrubbing | Secrets redacted from ALL command output (exact, URL, base64, partial) |
| Session TTL | Auto-lock after 120 minutes |
| Policy engine | Per-agent allowed ops + rate limiting (60 ops/min default) |
| Audit trail | Hash-chained, structured JSON log of every operation |
| Zero-knowledge backup | Cloudflare stores ciphertext only |

**The core invariant:** agents get *use*, never *read*. `get`, `env`, and raw
value access are excluded from default agent policies and blocked in agent
mode (`VAULTLY_AGENT_MODE=1`).

Useful commands:

```bash
vaultly keychain store     # auto-unlock via macOS Keychain
vaultly kill               # 🚨 emergency lock
vaultly status             # session info
vaultly tui                # interactive menu (human only)
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

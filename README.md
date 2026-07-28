<div align="center">

# 🔐 Vaultly

### Agent-first encrypted credential manager

**AI agents can _use_ your secrets. They can never _read_ them.**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-16_tools-8A2BE2)](#ai-agent-integration-mcp)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![Security](https://img.shields.io/badge/encryption-AES--256--GCM-red)](#security)
[![Deps](https://img.shields.io/badge/dependencies-2-brightgreen)](package.json)

</div>

---

## ✨ Why Vaultly?

Your AI agents need credentials to deploy, call APIs, and manage infrastructure. But you don't want them **reading** your tokens.

Vaultly sits between your agents and your secrets:

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

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/Growth-Club/vaultly.git
cd vaultly && npm install && npm run build && npm link

# Setup (interactive — creates password, adds accounts)
bash setup.sh

# Or manual
vaultly init
vaultly cf add personal        # prompts for API token
vaultly add github -k GITHUB_TOKEN -v "ghp_xxx"
```

## ☁️ Cloudflare Management

Manage **unlimited** Cloudflare accounts dynamically:

```bash
vaultly cf add personal                          # add (prompts for token)
vaultly cf add work -t "token" -a "account-id"   # or pass flags
vaultly cf list                                  # list all accounts
vaultly cf use work                              # switch active account
vaultly cf deploy personal ~/my-project          # deploy a Worker
vaultly cf zones personal                        # list domains
vaultly cf remove old-client                     # remove account
```

## 📦 Templates

Spin up vaults for any service in seconds:

```bash
vaultly template github        # GITHUB_TOKEN, GITHUB_USERNAME
vaultly template aws           # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
vaultly template stripe        # STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
vaultly template --list        # see all 14 templates
```

<details>
<summary><b>All 14 templates</b></summary>

| Template | Keys |
|----------|------|
| ☁️ `cloudflare` | CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID |
| 🐙 `github` | GITHUB_TOKEN, GITHUB_USERNAME |
| 🟠 `aws` | AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION |
| 🔵 `gcp` | GOOGLE_APPLICATION_CREDENTIALS, GCP_PROJECT_ID |
| ▲ `vercel` | VERCEL_TOKEN, VERCEL_ORG_ID, VERCEL_PROJECT_ID |
| 🗄️ `database` | DATABASE_URL, DATABASE_PASSWORD |
| 💳 `stripe` | STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PUBLISHABLE_KEY |
| 🤖 `openai` | OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_AI_KEY |
| 📧 `smtp` | SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD |
| 🐳 `docker` | DOCKER_USERNAME, DOCKER_PASSWORD, DOCKER_REGISTRY |
| 📦 `npm` | NPM_TOKEN |
| 🖥️ `ssh` | SERVER_HOST, SERVER_USER, SERVER_PASSWORD, SERVER_SSH_KEY |
| 📱 `social-media` | META_ACCESS_TOKEN, TWITTER_BEARER_TOKEN, LINKEDIN_ACCESS_TOKEN |
| 🎨 `custom` | Define your own keys |

</details>

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

> 💡 With macOS Keychain (`vaultly keychain store`), no password needed in config.

### 16 MCP Tools

| Tool | Description |
|------|-------------|
| 📋 `vault_list` | List all vaults |
| 🔑 `vault_keys` | List key names in a vault |
| ✍️ `vault_add` | Store a secret (**write-only**) |
| 🗑️ `vault_delete` | Delete a secret |
| ▶️ `vault_run` | Run command with injected env (**output scrubbed**) |
| 📊 `vault_status` | Session status, TTL, vault count |
| 📜 `vault_audit` | Recent audit log entries |
| 🌐 `cf_api` | Call any Cloudflare API endpoint |
| 🏠 `cf_zones` | List zones (domains) |
| 📡 `cf_dns_list` | List DNS records |
| ✏️ `cf_dns_upsert` | Create/update DNS record |
| ⚡ `cf_workers_list` | List deployed Workers |
| 🚀 `cf_deploy` | Deploy a Worker project |
| 💚 `cf_health` | Verify API token works |

> 🚫 **No MCP tool ever returns a raw secret value.**

## 🛡️ Security

| Feature | Details |
|---------|---------|
| 🔒 Encryption | AES-256-GCM + PBKDF2-SHA256 (600,000 iterations) |
| 🧹 Output scrubbing | Secrets redacted from ALL command output (exact, URL, base64, partial) |
| ⏱️ Session TTL | Auto-lock after 120 minutes |
| 🔑 macOS Keychain | Hardware-backed auto-unlock |
| 🚨 Killswitch | `vaultly kill` — instant lock + keychain wipe |
| 📊 Rate limiting | 60 operations/minute per agent |
| 📝 Audit trail | Structured JSON log of every operation |
| ☁️ Zero-knowledge backup | Cloudflare stores ciphertext only |

```bash
vaultly keychain store     # auto-unlock via macOS Keychain
vaultly kill               # 🚨 emergency lock
vaultly status             # session info
```

### Agent Mode

```bash
export VAULTLY_AGENT_MODE=1

vaultly run github -- git push   # ✅ allowed (scrubbed)
vaultly get github TOKEN         # ❌ blocked
vaultly env github               # ❌ blocked
```

## 💾 Remote Backup

Encrypted vaults backed up to Cloudflare KV (zero-knowledge):

```bash
# Deploy backup Worker
cd worker && npx wrangler deploy

# Backup / Restore
vaultly backup -u https://your-worker.workers.dev -t TOKEN
vaultly restore -u https://your-worker.workers.dev -t TOKEN
```

## 📁 Storage

```
~/.vaultly/
├── config.json          # salt + verifier (no secrets)
├── audit.log            # structured JSON audit trail
└── vaults/
    ├── cf-personal.vault     # encrypted
    ├── cf-work.vault         # encrypted
    ├── github.vault          # encrypted
    └── anything.vault        # unlimited, any name
```

## 📖 All Commands

```
vaultly init                              Create master password
vaultly add <vault> -k KEY -v VALUE       Add a secret
vaultly get <vault> <key>                 Get a secret value
vaultly list [vault]                      List vaults or keys
vaultly delete <vault> [key]              Delete a secret or vault
vaultly env <vault>                       Output shell export statements
vaultly run <vault> -- <cmd>              Run with injected env (scrubbed)
vaultly import <file> [--vault name]      Import from plaintext file
vaultly template [name]                   Create vault from template
vaultly cf add|list|use|deploy|remove|zones
vaultly keychain store|remove|status      macOS Keychain management
vaultly backup -u URL -t TOKEN            Push encrypted backup
vaultly restore -u URL -t TOKEN           Pull encrypted backup
vaultly protect [dir]                     Add AI-tool ignore rules
vaultly mcp                               Start MCP server
vaultly kill                              Emergency lock
vaultly status                            Session and vault info
```

## 🏗️ Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for full system diagrams.

```
2,450 LOC · 9 modules · 2 dependencies · 0 vulnerabilities
```

---

<div align="center">

**Built for the agent era.** 🔐

[Report Bug](https://github.com/Growth-Club/vaultly/issues) · [Request Feature](https://github.com/Growth-Club/vaultly/issues)

</div>

# 🔐 Vaultly

Agent-first encrypted credential manager with Cloudflare integration.

Secrets are encrypted client-side with AES-256-GCM. AI agents can **use** your credentials but **never read** them. Remote backup via Cloudflare stores only ciphertext — zero knowledge.

## Install

```bash
cd vaultly
npm install && npm run build && npm link
```

## Quick Start

```bash
# Interactive setup (creates master password, adds CF accounts)
bash setup.sh

# Or manual:
vaultly init

# Add Cloudflare accounts (unlimited, any name)
vaultly cf add personal
vaultly cf add work
vaultly cf add client-acme

# Add any credential
vaultly add github -k GITHUB_TOKEN -v "ghp_xxx"
vaultly add stripe -k STRIPE_SECRET_KEY -v "sk_live_xxx"
vaultly add wifi -k HOME_WIFI_PASSWORD -v "my-password"

# Or use a template
vaultly template github
vaultly template aws
vaultly template --list    # see all 14 templates
```

## Cloudflare Management

```bash
vaultly cf add personal                          # add account (prompts for token)
vaultly cf add work -t "token" -a "account-id"   # or pass flags
vaultly cf list                                  # list all CF accounts
vaultly cf use work                              # output eval-able exports
vaultly cf deploy personal ~/my-project          # deploy a Worker
vaultly cf zones personal                        # list domains
vaultly cf remove old-client                     # remove account
```

## Run Commands with Injected Secrets

```bash
# Secrets injected as env vars, output scrubbed of secret values
vaultly run github -- git push origin main
vaultly run stripe -- node charge-customer.js
vaultly run databases -- psql $DATABASE_URL -c "SELECT count(*)"

# Deploy to Cloudflare
vaultly cf deploy personal ~/Desktop/ProjectAlpha/tracker
```

## AI Agent Integration (MCP)

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

With macOS Keychain (`vaultly keychain store`), no password needed in config.

### MCP Tools (16)

| Tool | Description |
|------|-------------|
| `vault_list` | List all vaults |
| `vault_keys` | List key names in a vault |
| `vault_add` | Store a secret (write-only) |
| `vault_delete` | Delete a secret |
| `vault_run` | Run command with injected env (output scrubbed) |
| `vault_status` | Session status, TTL, vault count |
| `vault_audit` | Recent audit log entries |
| `cf_api` | Call any Cloudflare API endpoint |
| `cf_zones` | List zones (domains) |
| `cf_dns_list` | List DNS records |
| `cf_dns_upsert` | Create/update DNS record |
| `cf_workers_list` | List deployed Workers |
| `cf_deploy` | Deploy a Worker project |
| `cf_health` | Verify API token works |

**No MCP tool ever returns a raw secret value.**

## Agent Mode (Shell)

```bash
export VAULTLY_AGENT_MODE=1

vaultly list              # ✅ allowed
vaultly run github -- cmd # ✅ allowed (output scrubbed)
vaultly get github TOKEN  # ❌ blocked
vaultly env github        # ❌ blocked
```

## Templates

```bash
vaultly template --list
```

| Template | Keys |
|----------|------|
| `cloudflare` | CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID |
| `github` | GITHUB_TOKEN, GITHUB_USERNAME |
| `aws` | AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION |
| `gcp` | GOOGLE_APPLICATION_CREDENTIALS, GCP_PROJECT_ID |
| `vercel` | VERCEL_TOKEN, VERCEL_ORG_ID, VERCEL_PROJECT_ID |
| `database` | DATABASE_URL, DATABASE_PASSWORD |
| `stripe` | STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PUBLISHABLE_KEY |
| `openai` | OPENAI_API_KEY, ANTHROPIC_API_KEY, GOOGLE_AI_KEY |
| `smtp` | SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD |
| `docker` | DOCKER_USERNAME, DOCKER_PASSWORD, DOCKER_REGISTRY |
| `npm` | NPM_TOKEN |
| `ssh` | SERVER_HOST, SERVER_USER, SERVER_PASSWORD, SERVER_SSH_KEY |
| `social-media` | META_ACCESS_TOKEN, TWITTER_BEARER_TOKEN, LINKEDIN_ACCESS_TOKEN |
| `custom` | Define your own keys |

## Remote Backup (Cloudflare)

```bash
# Deploy the backup Worker
cd worker
npx wrangler kv namespace create VAULTLY_KV
# Update wrangler.toml with the KV namespace ID
npx wrangler secret put BACKUP_TOKEN
npx wrangler deploy

# Backup (encrypted blobs pushed to KV)
vaultly backup -u https://vaultly-backup.YOUR_SUBDOMAIN.workers.dev -t YOUR_TOKEN

# Restore on another machine
vaultly restore -u https://vaultly-backup.YOUR_SUBDOMAIN.workers.dev -t YOUR_TOKEN
```

## Security

```bash
vaultly keychain store     # Store master password in macOS Keychain
vaultly keychain status    # Check Keychain status
vaultly keychain remove    # Remove from Keychain

vaultly kill               # Emergency: lock vaults + clear Keychain
vaultly status             # Session info, TTL, vault count
```

## Import from File

```bash
vaultly import ./secrets.txt --vault my-vault
vaultly import ./secrets.txt --vault my-vault --delete-after   # remove file after
```

Supports `KEY=VALUE`, `KEY: VALUE`, quoted values, and `#` comments.

## Protect Projects

```bash
vaultly protect /path/to/project
```

Adds credential patterns to `.gitignore` and AI-tool ignore rules.

## Storage

```
~/.vaultly/
├── config.json          # Salt + verifier (no secrets)
├── audit.log            # Structured JSON audit trail
└── vaults/
    ├── cf-personal.vault
    ├── cf-work.vault
    ├── github.vault
    ├── stripe.vault
    └── anything.vault   # Unlimited, any name
```

All vault files are AES-256-GCM encrypted. Directory permissions: `700`. File permissions: `600`.

## All Commands

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

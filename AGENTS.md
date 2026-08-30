# 🤖 Vaultly Agent Integration Guide

Vaultly is **agent-first**. Agents manage your credentials, deploy your workers,
and handle Cloudflare — all without ever seeing raw secret values.

## What Agents Can Do

| Tool | What it does | Sees secrets? |
|------|-------------|---------------|
| `vault_list` | List vault names | ❌ No |
| `vault_keys` | List key names in a vault | ❌ Names only |
| `vault_add` | Store a new secret (write-only) | ❌ Can't read back |
| `vault_delete` | Delete a secret | ❌ No |
| `vault_import` | Import secrets from JSON (write-only) | ❌ Can't read back |
| `vault_import_encrypted` | Import an encrypted export blob | ❌ No values exposed |
| `vault_export_encrypted` | Export vault as encrypted blob | ❌ No plaintext |
| `vault_generate` | Generate a random secret | ❌ Value never shown |
| `vault_rotate` | Rotate a secret to a new random value | ❌ Value never shown |
| `vault_run` | Run command with injected env vars | ❌ Sees output only |
| `vault_lock` | Lock session — wipes key from memory | ❌ No |
| `vault_unlock` | Re-open via macOS Keychain | ❌ No |
| `cf_accounts` | List which vaults hold Cloudflare credentials (auth method, label, scope; `health=true` verifies each is valid) | ❌ Names only |
| `cf_account_label` | Set/clear/read a Cloudflare account's human-readable alias | ❌ Non-secret only |
| `cf_api` | Cloudflare API calls (authenticated) | ❌ Sees response only |
| `cf_zones` | List domains/zones | ❌ No |
| `cf_dns_list` | List DNS records | ❌ No |
| `cf_dns_upsert` | Create/update DNS records | ❌ No |
| `cf_workers_list` | List deployed workers | ❌ No |
| `cf_secrets` | Manage Worker secrets (list/set/delete) | ❌ Values are write-only |
| `cf_deploy` | Deploy a Worker project | ❌ Sees build output only |

**There is NO tool that returns a raw secret value. By design.**

---

## Setup for AI Tools

### Claude Desktop / Claude Code

Add to `claude_desktop_config.json` or `.claude/settings.json`:

```json
{
  "mcpServers": {
    "vaultly": {
      "command": "vaultly",
      "args": ["mcp"],
      "env": {
        "VAULTLY_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vaultly": {
      "command": "vaultly",
      "args": ["mcp"],
      "env": {
        "VAULTLY_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "vaultly": {
      "command": "vaultly",
      "args": ["mcp"],
      "env": {
        "VAULTLY_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

### Any MCP-compatible tool

```json
{
  "command": "vaultly",
  "args": ["mcp"],
  "env": {
    "VAULTLY_MASTER_PASSWORD": "your-master-password"
  }
}
```

> ⚠️ The master password in `env` is only visible to the MCP server process.
> The AI agent communicates via JSON-RPC and never sees env vars.

---

## Shell-Based Agents (no MCP needed)

For agents that run shell commands (Codex, Aider, etc.):

```bash
# Set agent mode — blocks `get` and `env` commands
export VAULTLY_AGENT_MODE=1

# Agent can still run commands with injected secrets:
vaultly run cf-personal -- npx wrangler deploy

# Agent can list vaults and key names:
vaultly list
vaultly list cf-personal

# Agent CANNOT do this (blocked):
vaultly get cf-personal CLOUDFLARE_API_TOKEN  # ✗ BLOCKED
vaultly env cf-personal                        # ✗ BLOCKED
vaultly tui                                    # ✗ BLOCKED (interactive menu is human-only)
```

---

## Example Agent Workflows

### "Deploy my tracker project to Cloudflare"

Agent does:
```
1. vault_list → sees "cf-personal"
2. vault_keys("cf-personal") → sees CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID
3. cf_deploy(vault="cf-personal", projectDir="/path/to/tracker")
   → wrangler runs with credentials injected
   → agent sees build output + deploy URL
   → agent NEVER sees the API token
```

### "Add a DNS record for my new app"

Agent does:
```
1. cf_zones("cf-personal") → gets zone list with IDs
2. cf_dns_upsert(vault="cf-personal", zoneId="xxx",
     type="A", name="app.example.com", content="1.2.3.4")
   → record created
   → agent sees confirmation
```

### "Store a new API key for me"

Agent does:
```
1. vault_add(vault="personal", key="STRIPE_SECRET_KEY", value="sk_live_xxx")
   → encrypted and stored
   → agent can NEVER read it back
```

### "Which Cloudflare accounts can I use, and are they healthy?"

Agent does:
```
1. cf_accounts → lists each CF vault, its auth method, label, and scope
   (cf-api / deploy / none) — e.g. "cf-personal (auth: token, scope: cf-api+deploy)"
2. cf_accounts(health=true) → verifies each credential live:
   "cf-personal ✓: token active" / "cf-work ✗: token inactive"
3. cf_account_label(vaultName="cf-personal", label="Personal") → set an alias
   cf_account_label(vaultName="cf-personal") → read it back
   cf_account_label(vaultName="cf-personal", label="") → clear it
   → agent sees names/labels/health only, NEVER the credential values
```

---

## Security Model

```
┌─────────────────────────────────────────────────────┐
│                    AI AGENT                          │
│                                                     │
│  Sees: vault names, key names, command output,      │
│        API responses, deploy logs                   │
│                                                     │
│  NEVER sees: secret values, API tokens, passwords   │
└──────────────────────┬──────────────────────────────┘
                       │ JSON-RPC (MCP) or shell
                       ▼
┌─────────────────────────────────────────────────────┐
│              VAULTLY MCP SERVER                      │
│                                                     │
│  Holds: decrypted key in memory (from master pw)    │
│  Does: injects secrets into child processes/APIs    │
│  Logs: every action to ~/.vaultly/audit.log         │
│                                                     │
│  NO tool returns raw values. Period.                │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│     CHILD PROCESS / CLOUDFLARE API                   │
│     (receives credentials, does the work)            │
└─────────────────────────────────────────────────────┘
```

### Audit Log

Every agent action is logged to `~/.vaultly/audit.log`:

```
2026-07-28T05:18:37Z | VAULT_LIST | listed 3 vaults | by=mcp-agent
2026-07-28T05:18:38Z | CF_DEPLOY | dir=/path/tracker | by=mcp-agent
2026-07-28T05:18:40Z | VAULT_ADD | personal/STRIPE_KEY (value hidden) | by=mcp-agent
```

Review with: `vaultly audit` or the `vault_audit` MCP tool.

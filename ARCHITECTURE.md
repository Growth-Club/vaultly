# Vaultly Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│                    V A U L T L Y   v 2                                      │
│              Agent-First Credential Manager                                 │
│                                                                             │
│         3,261 LOC · 11 modules · 4 deps · 0 vulnerabilities                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


 ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────────┐
 │    AI AGENTS      │  │     HUMANS        │  │     CI/CD (future)        │
 │                   │  │                   │  │                           │
 │  Claude Code      │  │  Terminal         │  │  GitHub Actions           │
 │  Cursor           │  │  (you)            │  │  GitLab CI                │
 │  Windsurf         │  │                   │  │                           │
 │  Codex            │  │                   │  │                           │
 │  Any MCP client   │  │                   │  │                           │
 └────────┬──────────┘  └────────┬──────────┘  └─────────────┬─────────────┘
          │                      │                           │
          │ MCP / JSON-RPC      │ CLI / terminal            │ CLI / env
          │ via stdio           │                           │
          ▼                      ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  🚪  INTERFACE LAYER                                                        │
│                                                                             │
│  │  MCP SERVER                 │  │  CLI + TUI                           │  │
│  │  (mcp-server.ts)            │  │  (index.ts + tui.ts)                 │  │
│  │                             │  │                                      │  │
│  │  17 tools:                  │  │  19 commands + 8 cf + 14 templates   │  │
│  │                             │  │                                      │  │
│  │  ┌───────────────────────┐  │  │  ┌────────────────────────────────┐  │  │
│  │  │ VAULT TOOLS           │  │  │  │ CORE                           │  │  │
│  │  │  vault_list           │  │  │  │  init     add      get*        │  │  │
│  │  │  vault_keys           │  │  │  │  list     delete   env*        │  │  │
│  │  │  vault_add (write-only│  │  │  │  import   run      mcp         │  │  │
│  │  │  vault_delete         │  │  │  │  backup   restore  protect     │  │  │
│  │  │  vault_run (scrubbed) │  │  │  │  status   kill     tui         │  │  │
│  │  │  vault_status         │  │  │  ├────────────────────────────────┤  │  │
│  │  │  vault_lock           │  │  │  │ CLOUDFLARE (vaultly cf ...)    │  │  │
│  │  │  vault_unlock         │  │  │  │  cf add [name]                 │  │  │
│  │  │  vault_audit          │  │  │  │  cf list                       │  │  │
│  │  ├───────────────────────┤  │  │  │  cf use <name>                 │  │  │
│  │  │ CLOUDFLARE TOOLS      │  │  │  │  cf deploy <name> <dir>        │  │  │
│  │  │  cf_api               │  │  │  │  cf remove <name>              │  │  │
│  │  │  cf_zones             │  │  │  │  cf zones <name>               │  │  │
│  │  │  cf_dns_list          │  │  │  ├────────────────────────────────┤  │  │
│  │  │  cf_dns_upsert        │  │  │  │ TEMPLATES (vaultly template)   │  │  │
│  │  │  cf_workers_list      │  │  │  │  cloudflare  github   aws      │  │  │
│  │  │  cf_secrets           │  │  │  │  gcp         vercel   stripe   │  │  │
│  │  │  cf_deploy            │  │  │  │  database    openai   smtp     │  │  │
│  │  │  cf_health            │  │  │  │  docker      npm      ssh      │  │  │
│  │  └───────────────────────┘  │  │  │  social-media  custom          │  │  │
│  │  Unlock:                    │  │  ├────────────────────────────────┤  │  │
│  │  1. macOS Keychain (auto)   │  │  │ KEYCHAIN                       │  │  │
│  │  2. VAULTLY_MASTER_PASSWORD │  │  │  keychain store/remove/status  │  │  │
│  │  3. /dev/tty prompt         │  │  └────────────────────────────────┘  │  │
│  │                             │  │                                      │  │
│  │  * no tool returns raw      │  │  * get/env blocked in agent mode     │  │
│  │    secret values — EVER     │  │                                      │  │
│  │                             │  │  * get/env blocked in agent mode     │  │
│  └──────────────┬──────────────┘  └──────────────────┬───────────────────┘  │
│                 │                                    │                      │
│                 └────────────────┬───────────────────┘                      │
│                                  ▼                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  🛡️  SECURITY LAYER                                                        │
│                                                                             │
│  ┌────────────────────┐ ┌────────────────────┐ ┌──────────────────────────┐ │
│  │  POLICY ENGINE     │ │  OUTPUT SCRUBBER   │ │  SESSION MANAGER         │ │
│  │  (policy.ts)       │ │  (scrubber.ts)     │ │  (engine.ts)             │ │
│  │                    │ │                    │ │                          │ │
│  │  • Per-agent       │ │  Intercepts ALL    │ │  • TTL: 120 min          │ │
│  │    permissions     │ │  output and        │ │    auto-lock             │ │
│  │  • Allowed vaults  │ │  replaces secret   │ │  • Key wiped from        │ │
│  │  • Allowed ops     │ │  values with       │ │    memory on lock        │ │
│  │  • Rate limiting   │ │  [REDACTED]        │ │  • Killswitch:           │ │
│  │    (60 ops/min)    │ │                    │ │    vaultly kill           │ │
│  │  • read_value      │ │  Detection:        │ │    → lock vaults         │ │
│  │    BLOCKED for     │ │  • Exact match     │ │    → clear keychain      │ │
│  │    agents          │ │  • URL-encoded     │ │    → audit "emergency"   │ │
│  │                    │ │  • Base64-encoded  │ │                          │ │
│  │                    │ │  • Quoted strings  │ │                          │ │
│  │                    │ │  • Partial match   │ │                          │ │
│  │                    │ │    (prefix+suffix) │ │                          │ │
│  └────────────────────┘ └────────────────────┘ └──────────────────────────┘ │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  AGENT MODE (VAULTLY_AGENT_MODE=1)                                   │   │
│  │                                                                      │   │
│  │  ✅ ALLOWED: list, add, delete, run, cf deploy, mcp, audit           │   │
│  │  ❌ BLOCKED: get (raw value), env (export vars)                      │   │
│  │  ❌ NEVER:   MCP has no tool that returns raw values                 │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ⚙️  CORE ENGINE  (engine.ts)                                              │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  unlock(password)                                                    │   │
│  │      │                                                               │   │
│  │      ▼                                                               │   │
│  │  ┌──────────────────────────────────────────────────┐                │   │
│  │  │  KEY DERIVATION  (crypto.ts)                     │                │   │
│  │  │                                                  │                │   │
│  │  │  password ──┐                                    │                │   │
│  │  │             ├──▶ PBKDF2-SHA256 ──▶ 256-bit key   │                │   │
│  │  │  salt ──────┘    600,000 rounds                  │                │   │
│  │  │                                                  │                │   │
│  │  └──────────────────────┬───────────────────────────┘                │   │
│  │                         │                                            │   │
│  │                         ▼                                            │   │
│  │  ┌──────────────────────────────────────────────────┐                │   │
│  │  │  ENCRYPTION  (crypto.ts)                         │                │   │
│  │  │                                                  │                │   │
│  │  │  plaintext ──▶ AES-256-GCM ──▶ ciphertext        │                │   │
│  │  │                random IV                          │                │   │
│  │  │                auth tag (tamper-proof)            │                │   │
│  │  │                                                  │                │   │
│  │  └──────────────────────┬───────────────────────────┘                │   │
│  │                         │                                            │   │
│  │  OPERATIONS:            │                                            │   │
│  │  ┌──────────────────────┴───────────────────────────────────────┐    │   │
│  │  │                                                              │    │   │
│  │  │  addSecret(vault, key, value)     WRITE-ONLY for agents      │    │   │
│  │  │  deleteSecret(vault, key)         no read-back               │    │   │
│  │  │  run(vault, cmd) ──────────────▶  spawn ──▶ scrub ──▶ out   │    │   │
│  │  │  cloudflareApi(vault, path) ───▶  fetch ──▶ scrub ──▶ json  │    │   │
│  │  │  healthCheck(vault) ───────────▶  GET /user/tokens/verify   │    │   │
│  │  │                                                              │    │   │
│  │  └──────────────────────────────────────────────────────────────┘    │   │
│  │                                                                      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  💾  STORAGE LAYER                                                          │
│                                                                             │
│  ┌──────────────────────┐ ┌───────────────────┐ ┌────────────────────────┐  │
│  │  LOCAL VAULTS        │ │  macOS KEYCHAIN   │ │  CLOUDFLARE (remote)   │  │
│  │  ~/.vaultly/         │ │                   │ │                        │  │
│  │                      │ │  Hardware-backed  │ │  ┌──────────────────┐  │  │
│  │  config.json         │ │  secure enclave   │ │  │  CF Worker       │  │  │
│  │  ├─ salt             │ │                   │ │  │  (worker/src)    │  │  │
│  │  ├─ verifier         │ │  Stores master    │ │  │                  │  │  │
│  │  └─ backup meta      │ │  password for     │ │  │  PUT  /backup    │  │  │
│  │                      │ │  auto-unlock      │ │  │  GET  /backup    │  │  │
│  │  vaults/             │ │                   │ │  │  GET  /health    │  │  │
│  │  ├─ cf-personal      │ │  No password      │ │  │                  │  │  │
│  │  ├─ cf-work          │ │  needed in MCP    │ │  │  Auth: Bearer    │  │  │
│  │  ├─ cf-client-x      │ │  config!          │ │  │  BACKUP_TOKEN    │  │  │
│  │  ├─ cf-staging       │ │                   │ │  └────────┬─────────┘  │  │
│  │  ├─ cf-anything      │ │  vaultly kill     │ │           │            │  │
│  │  ├─ github           │ │  clears entry     │ │           ▼            │  │
│  │  ├─ aws              │ │                   │ │  ┌──────────────────┐  │  │
│  │  ├─ stripe           │ │  (keychain.ts)    │ │  │  CF KV           │  │  │
│  │  ├─ databases        │ │                   │ │  │                  │  │  │
│  │  ├─ personal         │ │                   │ │  │  Stores ONLY     │  │  │
│  │  ├─ social           │ │                   │ │  │  encrypted       │  │  │
│  │  └─ anything-you-want│ │                   │ │  │  blobs           │  │  │
│  │                      │ │                   │ │  │                  │  │  │
│  │  audit.log           │ │                   │ │  │  ZERO KNOWLEDGE  │  │  │
│  │  (structured JSON)   │ │                   │ │  │  server cannot   │  │  │
│  │                      │ │                   │ │  │  decrypt ANYTHING│  │  │
│  │  Permissions:        │ │                   │ │  │                  │  │  │
│  │  dirs  700 (rwx---)  │ │                   │ │  └──────────────────┘  │  │
│  │  files 600 (rw----)  │ │                   │ │                        │  │
│  │                      │ │                   │ │  vaultly backup        │  │
│  │  (vault.ts)          │ │                   │ │  vaultly restore       │  │
│  └──────────────────────┘ └───────────────────┘ └────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


 ═══════════════════════════════════════════════════════════════════════════

  DATA FLOW: Agent deploys a Cloudflare Worker

  Agent                  MCP Server             Engine             wrangler
    │                        │                     │                    │
    │  cf_deploy(            │                     │                    │
    │   vault="cf-personal"  │                     │                    │
    │   dir="~/tracker")     │                     │                    │
    │───────────────────────▶│                     │                    │
    │                        │                     │                    │
    │                        │  policy.check()     │                    │
    │                        │  ✅ op=cf_deploy    │                    │
    │                        │  ✅ vault=cf-*      │                    │
    │                        │  ✅ rate < 60/min   │                    │
    │                        │────────────────────▶│                    │
    │                        │                     │                    │
    │                        │                     │  AES-256-GCM       │
    │                        │                     │  decrypt vault     │
    │                        │                     │  ┌──────────────┐  │
    │                        │                     │  │ CF_API_TOKEN │  │
    │                        │                     │  │ CF_ACCOUNT_ID│  │
    │                        │                     │  └──────┬───────┘  │
    │                        │                     │         │          │
    │                        │                     │  spawn  │          │
    │                        │                     │─────────┼─────────▶│
    │                        │                     │         │          │
    │                        │                     │  env: { │          │
    │                        │                     │   CF_API_TOKEN: ●  │  ← real
    │                        │                     │   CF_ACCOUNT_ID: ● │    token
    │                        │                     │  }      │          │    (memory
    │                        │                     │         │          │     only)
    │                        │                     │         │          │
    │                        │                     │  stdout:│          │
    │                        │                     │  "Published to     │
    │                        │                     │   https://..."     │
    │                        │                     │◀────────┼──────────│
    │                        │                     │         │          │
    │                        │   scrubber.ts       │         │          │
    │                        │   ● → [REDACTED]    │         │          │
    │                        │◀────────────────────│         │          │
    │                        │                     │         │          │
    │  "✅ Deployed to       │                     │         │          │
    │   https://tracker..."  │                     │         │          │
    │◀───────────────────────│                     │         │          │
    │                        │                     │         │          │
    │  agent NEVER sees      │                     │         │          │
    │  the API token ●       │                     │         │          │


 ═══════════════════════════════════════════════════════════════════════════

  DATA FLOW: Human adds a secret

  Human (terminal)                    CLI                      Disk
    │                                  │                         │
    │  vaultly cf add personal         │                         │
    │─────────────────────────────────▶│                         │
    │                                  │                         │
    │  "Account name: personal"        │                         │
    │  "API Token: ****"               │                         │
    │  "Account ID: abc123"            │                         │
    │◀─────────────────────────────────│                         │
    │                                  │                         │
    │                                  │  PBKDF2(password)       │
    │                                  │  → key                  │
    │                                  │                         │
    │                                  │  AES-256-GCM(key, {     │
    │                                  │    CF_API_TOKEN: "●",   │
    │                                  │    CF_ACCOUNT_ID: "abc" │
    │                                  │  })                     │
    │                                  │────────────────────────▶│
    │                                  │                         │
    │                                  │              ~/.vaultly/vaults/
    │                                  │              cf-personal.vault
    │                                  │              (encrypted blob)
    │                                  │                         │
    │  "✓ cf-personal saved"           │                         │
    │◀─────────────────────────────────│                         │


 ═══════════════════════════════════════════════════════════════════════════

  PERMISSION MATRIX

                        Agent (MCP)    Agent (shell)    Human (CLI)
                        ───────────    ─────────────    ───────────
   vault_list              ✅              ✅               ✅
   vault_keys              ✅              ✅               ✅
   vault_add               ✅              ✅               ✅
   vault_delete            ✅              ✅               ✅
   vault_run               ✅              ✅               ✅
   vault_status            ✅              ✅               ✅
   vault_audit             ✅              ✅               ✅
   cf_api                  ✅              ❌               ✅
   cf_deploy               ✅              ❌               ✅
   cf_zones                ✅              ❌               ✅
   cf_dns_list             ✅              ❌               ✅
   cf_dns_upsert           ✅              ❌               ✅
   cf_workers_list         ✅              ❌               ✅
   cf_secrets              ✅              ❌               ✅
   cf_health               ✅              ❌               ✅
   cf add/list/use         ❌              ✅               ✅
   cf deploy (CLI)         ❌              ✅               ✅
   cf zones (CLI)          ❌              ✅               ✅
   cf secrets (CLI)        ❌              ✅               ✅
   template                ❌              ❌               ✅
   get (raw value)         ❌ NEVER        ❌ BLOCKED       ✅
   env (export vars)       ❌ NEVER        ❌ BLOCKED       ✅
   keychain store/remove   ❌              ❌               ✅
   kill (killswitch)       ❌              ❌               ✅
   init                    ❌              ❌               ✅
   backup / restore        ❌              ❌               ✅


 ═══════════════════════════════════════════════════════════════════════════

  FILE MAP

  vaultly/
  ├── src/
  │   ├── engine.ts         354 LOC   Core engine (shared CLI + MCP)
  │   ├── index.ts          780 LOC   CLI: 18 cmds + 7 cf + 14 templates
  │   ├── mcp-server.ts     409 LOC   MCP server: 16 agent tools
  │   ├── vault.ts          230 LOC   Encrypted file storage
  │   ├── policy.ts         139 LOC   Permissions, rate limits
  │   ├── crypto.ts         122 LOC   AES-256-GCM + PBKDF2
  │   ├── prompt.ts          98 LOC   Secure password input
  │   ├── keychain.ts        93 LOC   macOS Keychain integration
  │   └── scrubber.ts        74 LOC   Output secret redaction
  │                                  ─────────
  │                          3,261 LOC total
  │
  ├── worker/
  │   ├── src/index.ts      Cloudflare Worker (zero-knowledge backup)
  │   └── wrangler.toml     Worker config (KV binding)
  │
  ├── ARCHITECTURE.md       This file
  ├── AGENTS.md             Agent integration guide
  ├── README.md             Usage documentation
  ├── setup.sh              Interactive setup script
  ├── package.json          3 deps: MCP SDK + commander + chalk
  └── tsconfig.json         TypeScript config


 ═══════════════════════════════════════════════════════════════════════════

  VAULT ORGANIZATION (fully dynamic — unlimited)

  ~/.vaultly/vaults/
  │
  ├── cf-personal.vault ─────── CLOUDFLARE_API_TOKEN (or EMAIL+API_KEY)
  │                             CLOUDFLARE_ACCOUNT_ID
  │
  ├── cf-work.vault ─────────── CLOUDFLARE_API_TOKEN
  │                             CLOUDFLARE_ACCOUNT_ID
  │
  ├── cf-client-acme.vault ──── CLOUDFLARE_API_TOKEN        ← N accounts
  ├── cf-client-globex.vault ── CLOUDFLARE_API_TOKEN        ← unlimited
  ├── cf-staging.vault ──────── CLOUDFLARE_API_TOKEN
  │
  ├── github.vault ──────────── GITHUB_TOKEN
  │                             GITHUB_USERNAME
  │
  ├── aws.vault ─────────────── AWS_ACCESS_KEY_ID
  │                             AWS_SECRET_ACCESS_KEY
  │
  ├── stripe.vault ──────────── STRIPE_SECRET_KEY
  │                             STRIPE_WEBHOOK_SECRET
  │
  ├── databases.vault ───────── DATABASE_URL
  │                             REDIS_URL
  │
  ├── personal.vault ────────── META_ACCESS_TOKEN
  │                             OPENAI_API_KEY
  │                             HOME_WIFI_PASSWORD
  │
  └── anything-you-want.vault ─ ANY_KEY = ANY_VALUE         ← literally anything


 ═══════════════════════════════════════════════════════════════════════════

  SECURITY GUARANTEES

  1. Secrets are encrypted at rest (AES-256-GCM, PBKDF2 600k rounds)
  2. Master password is NEVER stored on disk
  3. MCP tools NEVER return raw secret values
  4. Command output is scrubbed of secret values before agent sees it
  5. Agent mode blocks get/env commands entirely
  6. Session auto-locks after 120 minutes
  7. Killswitch wipes memory + keychain instantly
  8. Rate limiting prevents brute-force (60 ops/min)
  9. Remote backup stores ONLY ciphertext (zero-knowledge)
  10. All operations logged to structured JSON audit trail
```

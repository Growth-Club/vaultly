# Vaultly Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│             V A U L T L Y   v 1                                              │
│              Agent-First Credential Manager                                 │
│                                                                             │
│         13,869 LOC Rust · 3 crates · 14 modules · 63 tests                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


 ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────────┐
 │    AI AGENTS      │  │     HUMANS        │  │     CI / SCRIPTS          │
 │                   │  │                   │  │                           │
 │  Claude Code      │  │  Terminal         │  │  GitHub Actions           │
 │  Cursor           │  │  (you)            │  │  GitLab CI                │
 │  Windsurf         │  │                   │  │  Any HTTP client          │
 │  Codex            │  │                   │  │                           │
 │  Any MCP client   │  │                   │  │                           │
 └────────┬──────────┘  └────────┬──────────┘  └─────────────┬─────────────┘
          │                      │                           │
          │ MCP / JSON-RPC      │ CLI / terminal            │ HTTP / REST
          │ via stdio           │                           │ bearer token
          ▼                      ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  🚪  INTERFACE LAYER                                                        │
│                                                                             │
│  │  MCP SERVER       │  │  CLI + TUI        │  │  HTTP SERVER            │  │
│  │  (vaultly-mcp)    │  │  (vaultly)        │  │  (vaultly serve)        │  │
│  │                   │  │                   │  │                         │  │
│  │  28 tools:        │  │  30 commands      │  │  REST edge for CI       │  │
│  │                   │  │  + 9 cf subcmds   │  │                         │  │
│  │  ┌─────────────┐  │  │  + 14 templates   │  │  AGENT-FIRST: no        │  │
│  │  │VAULT TOOLS  │  │  │                   │  │  endpoint returns       │  │
│  │  │ vault_list  │  │  │  ┌─────────────┐  │  │  raw secret values      │  │
│  │  │ vault_keys  │  │  │  │ CORE        │  │  │                         │  │
│  │  │ vault_add   │  │  │  │ init  add   │  │  │  Same VaultEngine,      │  │
│  │  │ vault_delete│  │  │  │ get*  list  │  │  │  policy, and audit      │  │
│  │  │ vault_run   │  │  │  │ del   env*  │  │  │  as CLI + MCP.          │  │
│  │  │ vault_status│  │  │  │ run   import│  │  │                         │  │
│  │  │ vault_lock  │  │  │  │ mcp   serve │  │  │  Routes:                │  │
│  │  │ vault_unlock│  │  │  │ kill  status│  │  │  GET  /vaults           │  │
│  │  │ vault_audit │  │  │  │ tui   version│  │  │  GET  /keys?vault=      │  │
│  │  │ vault_meta  │  │  │  │ gen   rotate│  │  │  POST /run              │  │
│  │  │ vault_policy│  │  │  │ copy  rename│  │  │  POST /add              │  │
│  │  │ vault_import│  │  │  │ mv    cp    │  │  │  POST /rotate-expired   │  │
│  │  │ vault_export│  │  │  │ completions   │  │  │  GET  /health           │  │
│  │  │ vault_gen   │  │  │  │ inspect export│  │  │                         │  │
│  │  │ vault_rotate│  │  │  │ stats  doctor│  │  │  Auth: Bearer token     │  │
│  │  ├─────────────┤  │  │  ├─────────────┤  │  │                         │  │
│  │  │CF TOOLS     │  │  │  │CLOUDFLARE   │  │  └─────────────────────────┘  │
│  │  │ cf_api      │  │  │  │ cf add      │  │                               │
│  │  │ cf_deploy   │  │  │  │ cf list     │  │  │  KEYCHAIN                  │  │
│  │  │ cf_zones    │  │  │  │ cf use      │  │  │  keychain store/remove/   │  │
│  │  │ cf_dns_list │  │  │  │ cf deploy   │  │  │  status                    │  │
│  │  │ cf_dns_upsert│ │  │  │ cf remove   │  │  └────────────────────────────┘ │
│  │  │ cf_dns_del  │  │  │  │ cf zones    │  │                               │
│  │  │ cf_workers  │  │  │  │ cf secrets  │  │  │  TEMPLATES                  │  │
│  │  │ cf_wrkr_ver │  │  │  │ cf dns-del  │  │  │  cloudflare github  aws   │  │
│  │  │ cf_secrets  │  │  │  ├─────────────┤  │  │  gcp      vercel   stripe  │  │
│  │  │ cf_health   │  │  │  │BACKUP/RESTORE│ │  │  database openai  smtp    │  │
│  │  ├─────────────┤  │  │  │ backup restore│ │  │  docker   npm     ssh     │  │
│  │  │META TOOLS   │  │  │  ├─────────────┤  │  │  social   custom          │  │
│  │  │ policy_info │  │  │  │KEYCHAIN     │  │  └────────────────────────────┘ │
│  │  │ tmpl_list   │  │  │  │ store remove │  │                               │
│  │  │ tmpl_apply  │  │  │  │ status       │  │  │  * get/env/export blocked  │  │
│  │  └─────────────┘  │  │  └─────────────┘  │  │    in agent mode             │  │
│  │                   │  │                   │  │                               │  │
│  │  Unlock:          │  │  ratatui TUI      │  │                               │  │
│  │  1. macOS Keychain│  │  (3,308 LOC)      │  │                               │  │
│  │  2. VAULTLY_MASTER│  │  human-only       │  │                               │  │
│  │  3. /dev/tty      │  │                   │  │                               │  │
│  │                   │  │                   │  │                               │  │
│  │  * no tool returns│  │                   │  │                               │  │
│  │    raw values     │  │                   │  │                               │  │
│  └──────────────┬──────┘  └────────┬──────────┘  └──────────────┬────────────┘
                  │                  │                            │
                  └──────────────────┼────────────────────────────┘
                                     ▼
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  🛡️  SECURITY LAYER                                                        │
│                                                                             │
│  ┌────────────────────┐ ┌────────────────────┐ ┌──────────────────────────┐ │
│  │  POLICY ENGINE     │ │  OUTPUT SCRUBBER   │ │  SESSION MANAGER         │ │
│  │  (policy.rs)       │ │  (scrubber.rs)     │ │  (engine.rs)             │ │
│  │   563 LOC          │ │   214 LOC          │ │                          │ │
│  │                    │ │                    │ │  • TTL: 120 min          │ │
│  │  • Per-agent       │ │  Intercepts ALL    │ │    auto-lock             │ │
│  │    permissions     │ │  output and        │ │  • Key wiped from        │ │
│  │  • Allowed vaults  │ │  replaces secret   │ │    memory on lock        │ │
│  │  • Allowed ops     │ │  values with       │ │    (zeroize)             │ │
│  │  • Rate limiting   │ │  [REDACTED]        │ │  • Killswitch:           │ │
│  │    (60 ops/min)    │ │                    │ │    vaultly kill           │ │
│  │  • read_value      │ │  Detection:        │ │    → lock vaults         │ │
│  │    BLOCKED for     │ │  • Exact match     │ │    → clear keychain      │ │
│  │    agents          │ │  • URL-encoded     │ │    → audit "emergency"   │ │
│  │  • Per-op allow/deny│ │  • Base64-encoded │ │                          │ │
│  │    from JSON policy│ │  • Quoted strings  │ │                          │ │
│  │                    │ │  • Partial match   │ │                          │ │
│  │                    │ │    (prefix+suffix) │ │                          │ │
│  └────────────────────┘ └────────────────────┘ └──────────────────────────┘ │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  AGENT MODE (VAULTLY_AGENT_MODE=1)                                   │   │
│  │                                                                      │   │
│  │  ✅ ALLOWED: list, add, delete, run, audit, meta, rotate, gen,       │   │
│  │     import, export, cf_*, templates, policy_info                     │   │
│  │  ❌ BLOCKED: get (raw value), env (export vars), export, tui         │   │
│  │  ❌ NEVER:   MCP/HTTP have no endpoint that returns raw values       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ⚙️  CORE ENGINE  (engine.rs — 2,261 LOC)                                  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                                                                      │   │
│  │  unlock(password)                                                    │   │
│  │      │                                                               │   │
│  │      ▼                                                               │   │
│  │  ┌──────────────────────────────────────────────────┐                │   │
│  │  │  KEY DERIVATION  (crypto.rs — 375 LOC)           │                │   │
│  │  │                                                  │                │   │
│  │  │  password ──┐                                    │                │   │
│  │  │             ├──▶ PBKDF2-SHA256 ──▶ 256-bit key   │                │   │
│  │  │  salt ──────┘    600,000 rounds                  │                │   │
│  │  │                                                  │                │   │
│  │  └──────────────────────┬───────────────────────────┘                │   │
│  │                         │                                            │   │
│  │                         ▼                                            │   │
│  │  ┌──────────────────────────────────────────────────┐                │   │
│  │  │  ENCRYPTION  (crypto.rs)                         │                │   │
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
│  │  │  SECRETS                                                     │    │   │
│  │  │  add_secret(vault, key, value)     write-only for agents     │    │   │
│  │  │  add_secret_with_expiry(...)       TTL / RFC3339 expiry      │    │   │
│  │  │  get_secret_value(vault, key)      raw value (human only)    │    │   │
│  │  │  get_secrets(vault)                all decrypted values      │    │   │
│  │  │  delete_secret(vault, key)         no read-back              │    │   │
│  │  │  delete_vault(vault)               remove entire vault       │    │   │
│  │  │  import_secrets(file)              .env/.json/.yaml/.csv     │    │   │
│  │  │                                                              │    │   │
│  │  │  METADATA (agent-safe)                                       │    │   │
│  │  │  list_vaults()                     vault names               │    │   │
│  │  │  list_keys(vault)                  key names                 │    │   │
│  │  │  list_keys_meta(vault)             names + expiry + created  │    │   │
│  │  │  secret_meta(vault, key)           single-key metadata       │    │   │
│  │  │  expired_keys(vault)               keys past their expiry    │    │   │
│  │  │                                                              │    │   │
│  │  │  EXECUTION                                                   │    │   │
│  │  │  run(vault, cmd) ─────────────▶  spawn ──▶ scrub ──▶ out    │    │   │
│  │  │  run_command(...)              async child process w/ env    │    │   │
│  │  │                                                              │    │   │
│  │  │  CLOUDFLARE                                                   │    │   │
│  │  │  cloudflare_api(vault, path) ──▶  fetch ──▶ scrub ──▶ json  │    │   │
│  │  │  dns_delete(vault, zone, rec)  agent-safe DNS removal        │    │   │
│  │  │  list_workers(vault)           deployed Workers              │    │   │
│  │  │  list_worker_versions(vault)   version history               │    │   │
│  │  │  worker_secrets(vault, ...)    list/set/delete Worker secrets│    │   │
│  │  │  health_check(vault) ─────────▶  GET /user/tokens/verify     │    │   │
│  │  │                                                              │    │   │
│  │  │  BACKUP / RESTORE (zero-knowledge ciphertext)                │    │   │
│  │  │  get_encrypted_vaults()            serialize encrypted blobs │    │   │
│  │  │  restore_encrypted_vaults(vaults)  restore from ciphertext   │    │   │
│  │  │  update_backup_meta(url)           track Worker URL          │    │   │
│  │  │                                                              │    │   │
│  │  │  AUDIT                                                     │    │   │
│  │  │  audit(action, detail, ctx)        structured JSON log       │    │   │
│  │  │  get_audit_log(lines)              recent entries             │    │   │
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
│  │  ├─ salt             │ │                   │ │  │                  │  │  │
│  │  ├─ verifier         │ │  Stores master    │ │  │  PUT  /backup    │  │  │
│  │  └─ backup meta      │ │  password for     │ │  │  GET  /backup    │  │  │
│  │                      │ │  auto-unlock      │ │  │  GET  /health    │  │  │
│  │  vaults/             │ │                   │ │  │                  │  │  │
│  │  ├─ cf-personal      │ │  No password      │ │  │  Auth: Bearer    │  │  │
│  │  ├─ cf-work          │ │  needed in MCP    │ │  │  BACKUP_TOKEN    │  │  │
│  │  ├─ cf-client-x      │ │  config!          │ │  └────────┬─────────┘  │  │
│  │  ├─ cf-staging       │ │                   │ │           │            │  │
│  │  ├─ github           │ │  vaultly kill     │ │           ▼            │  │
│  │  ├─ aws              │ │  clears entry     │ │  ┌──────────────────┐  │  │
│  │  ├─ stripe           │ │                   │ │  │  CF KV           │  │  │
│  │  ├─ databases        │ │  (keychain.rs     │ │  │                  │  │  │
│  │  ├─ personal         │ │   145 LOC)        │ │  │  Stores ONLY     │  │  │
│  │  └─ anything-you-want│ │                   │ │  │  encrypted       │  │  │
│  │                      │ │                   │ │  │  blobs           │  │  │
│  │  audit.log           │ │                   │ │  │                  │  │  │
│  │  (structured JSON)   │ │                   │ │  │  ZERO KNOWLEDGE  │  │  │
│  │                      │ │                   │ │  │  server cannot   │  │  │
│  │  Permissions:        │ │                   │ │  │  decrypt ANYTHING│  │  │
│  │  dirs  700 (rwx---)  │ │                   │ │  │                  │  │  │
│  │  files 600 (rw----)  │ │                   │ │  └──────────────────┘  │  │
│  │                      │ │                   │ │                        │  │
│  │  (vault.rs           │ │                   │ │  vaultly backup        │  │
│  │   1,073 LOC)         │ │                   │ │  vaultly restore       │  │
│  └──────────────────────┘ └───────────────────┘ └────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  SECRET GENERATION  (generate.rs — 71 LOC)                           │   │
│  │                                                                      │   │
│  │  generate_secret(length, use_symbols)  OS-entropy random secrets     │   │
│  │  URL/shell-safe alphabet (no quotes, no backslash, no ambiguous)     │   │
│  │  Used by `vaultly gen`, `vaultly rotate`, MCP `vault_generate`       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
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
    │                        │   scrubber.rs       │         │          │
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

                        Agent (MCP/HTTP)    Agent (shell)    Human (CLI)
                        ────────────────    ─────────────    ───────────
   vault_list                ✅                 ✅               ✅
   vault_keys                ✅                 ✅               ✅
   vault_add                 ✅                 ✅               ✅
   vault_delete              ✅                 ✅               ✅
   vault_run                 ✅                 ✅               ✅
   vault_status              ✅                 ✅               ✅
   vault_audit               ✅                 ✅               ✅
   vault_meta                ✅                 ✅               ✅
   vault_import              ✅                 ✅               ✅
   vault_export              ✅                 ✅               ✅
   vault_generate            ✅                 ✅               ✅
   vault_rotate              ✅                 ✅               ✅
   vault_policy              ✅                 ✅               ✅
   cf_api                    ✅                 ❌               ✅
   cf_deploy                 ✅                 ❌               ✅
   cf_zones                  ✅                 ❌               ✅
   cf_dns_list               ✅                 ❌               ✅
   cf_dns_upsert             ✅                 ❌               ✅
   cf_dns_delete             ✅                 ❌               ✅
   cf_workers_list           ✅                 ❌               ✅
   cf_workers_versions       ✅                 ❌               ✅
   cf_secrets                ✅                 ❌               ✅
   cf_health                 ✅                 ❌               ✅
   template_list/apply        ✅                 ❌               ✅
   policy_info               ✅                 ❌               ✅
   cf add/list/use           ❌                 ✅               ✅
   cf deploy (CLI)           ❌                 ✅               ✅
   cf zones (CLI)            ❌                 ✅               ✅
   cf secrets (CLI)          ❌                 ✅               ✅
   cf dns-delete (CLI)       ❌                 ✅               ✅
   template                  ❌                 ❌               ✅
   get (raw value)           ❌ NEVER           ❌ BLOCKED       ✅
   env (export vars)         ❌ NEVER           ❌ BLOCKED       ✅
   export                    ❌ NEVER           ❌ BLOCKED       ✅
   keychain store/remove     ❌                 ❌               ✅
   kill (killswitch)         ❌                 ❌               ✅
   init                      ❌                 ❌               ✅
   backup / restore          ❌                 ❌               ✅
   serve                     ❌                 ❌               ✅
   gen / rotate              ❌                 ❌               ✅
   copy / rename / mv / cp   ❌                 ❌               ✅
   completions               ❌                 ❌               ✅
   inspect / stats / doctor  ❌                 ❌               ✅


 ═══════════════════════════════════════════════════════════════════════════

  FILE MAP

  vaultly/
  ├── rust/
  │   ├── Cargo.toml          Workspace: tokio, clap, serde, reqwest, aes-gcm
  │   ├── crates/
  │   │   ├── vaultly-core/    Core engine (shared CLI + MCP + HTTP)
  │   │   │   ├── lib.rs          16 LOC   Module exports + public re-exports
  │   │   │   ├── engine.rs    2,261 LOC  VaultEngine: ops, run, CF, audit, backup
  │   │   │   ├── vault.rs     1,073 LOC  Encrypted file storage, import/export
  │   │   │   ├── policy.rs      563 LOC  Permissions, rate limits, JSON policies
  │   │   │   ├── crypto.rs      375 LOC  AES-256-GCM + PBKDF2
  │   │   │   ├── scrubber.rs    214 LOC  Output secret redaction
  │   │   │   ├── generate.rs     71 LOC  CSPRNG secret generation
  │   │   │   ├── keychain.rs    145 LOC  macOS Keychain integration
  │   │   │   ├── templates.rs   129 LOC  14 vault templates
  │   │   │   └── error.rs        129 LOC  thiserror types
  │   │   │                              ─────────
  │   │   │                      4,976 LOC total (core)
  │   │   ├── vaultly/          CLI + TUI + HTTP server + templates
  │   │   │   ├── main.rs     2,515 LOC  CLI: 30 cmds + 9 cf + keychain
  │   │   │   ├── tui.rs      3,308 LOC  Interactive ratatui menu (human-only)
  │   │   │   ├── server.rs     315 LOC  axum HTTP/REST server (bearer auth)
  │   │   │   └── prompt.rs      24 LOC  Secure password input
  │   │   │                              ─────────
  │   │   │                      6,162 LOC total (cli)
  │   │   └── vaultly-mcp/      MCP server: 28 agent tools (JSON-RPC stdio)
  │   │       ├── lib.rs      1,566 LOC  Tool dispatch + schema + e2e tests
  │   │       └── main.rs         6 LOC  Binary entrypoint
  │   │                                  ─────────
  │   │                          1,572 LOC total (mcp)
  │   └── tests/                63 tests (core proptest, CF, MCP e2e, CLI, HTTP)
  │
  ├── ARCHITECTURE.md       This file
  ├── AGENTS.md             Agent integration guide
  ├── README.md             Usage documentation
  ├── PLAN.md               Project roadmap / plan
  ├── CHANGELOG.md          Release notes
  ├── CONTRIBUTING.md       Contributor guide
  ├── setup.sh              Interactive setup script
  ├── install.sh            One-shot installer
  ├── Formula/vaultly.rb    Homebrew formula
  ├── docs/                 Threat model, CLI ref, MCP tools, REST API, config
  └── LICENSE               MIT


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

  1.  Secrets are encrypted at rest (AES-256-GCM, PBKDF2 600k rounds)
  2.  Master password is NEVER stored on disk
  3.  MCP tools NEVER return raw secret values
  4.  HTTP server endpoints NEVER return raw secret values
  5.  Command output is scrubbed of secret values before agent sees it
  6.  Agent mode blocks get/env/export commands entirely
  7.  Session auto-locks after 120 minutes
  8.  Killswitch wipes memory + keychain instantly
  9.  Rate limiting prevents brute-force (60 ops/min)
  10. Remote backup stores ONLY ciphertext (zero-knowledge)
  11. All operations logged to structured JSON audit trail
  12. Child processes (`vaultly run`, `cf deploy`, MCP `run`/`deploy`) run with a
      CLEARED environment — only vault-injected secrets (+ PATH to find the
      executable) are passed; the parent environment, `VAULTLY_MASTER_PASSWORD`
      and `VAULTLY_AGENT_MODE` are never inherited by the child.
  13. `vault_add` rejects empty secret values (no silently-empty secrets).
  14. `vaultly restore` prompts for confirmation before overwriting vaults, and
      aborts (instead of silently doing nothing) if the backup is not valid JSON.
  15. `vaultly import` restricts keys to `[A-Za-z0-9_]` and aborts on duplicate
      keys rather than silently letting the last value win.
  16. On TTL expiry (or `vaultly lock`) the in-memory derivation key buffer is
      zeroed before the reference is dropped.
  17. Secrets support time-to-live (TTL / RFC3339 expiry); expired keys are
      flagged in metadata and rotatable in bulk via `vaultly rotate --expired`.
  18. HTTP server authenticates via constant-time bearer-token comparison and
      routes every op through the same policy + audit pipeline as CLI/MCP.
```

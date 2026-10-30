# Developer-first secret managers: feature inventory and parity baseline (30 October 2026)

*Scope: Doppler, Infisical, 1Password Developer, Bitwarden Secrets Manager, HashiCorp Vault and HCP Vault, Pulumi ESC, Phase, EnvKey, Chamber, aws-vault, plus SOPS, OpenBao, AWS Secrets Manager and dotenv-vault as adjacent references. Every URL below was accessed on **2026-10-30** unless a different date is stated inline. Star/push counts come from the GitHub REST API on that date; GitHub's `open_issues_count` includes pull requests, so it is not a pure bug count.*

*Evidence tags: **[V]** = vendor-authored documentation, pricing page or support notice; **[P]** = project-owned primary artefact (README, source repo); **[I]** = independent or third-party evidence. No independent benchmark, purchaser survey or hands-on comparative test was run for this note. Where a capability is described as absent, that means **not found in the vendor documentation captured in this pass** — not proof that it does not exist in the product. This distinction is carried into the synthesis because a parity checklist built from documentation alone systematically under-counts undocumented features and over-counts marketing pages.*

---

## 1. Which products are actually current, and which are historical?

### Takeaway
As of October 2026 the developer-secret market has eight viable commercial products in this scope — Doppler, Infisical, 1Password Developer, Bitwarden Secrets Manager, HashiCorp Vault/HCP Vault Dedicated, Pulumi ESC, Phase and AWS Secrets Manager — plus four OSS primitives (SOPS, OpenBao, Chamber, aws-vault) that solve narrower slices. Three commonly-cited entries are not current products: **EnvKey Cloud is shut down**, **HCP Vault Secrets is past its end-of-life date**, and **upstream aws-vault is abandoned**. A parity matrix that still lists those three as live competitors is measuring a market that no longer exists.

### Cited Findings

| Product | Status on 2026-10-30 | Primary evidence |
|---|---|---|
| Doppler | Active commercial SaaS | [V] [pricing](https://www.doppler.com/pricing), [docs](https://docs.doppler.com/docs/start) |
| Infisical | Active open-core (MIT core, `ee/` commercial) | [P] [repo](https://github.com/Infisical/infisical), [V] [pricing](https://infisical.com/pricing) |
| 1Password Developer | Active; Environments and service accounts shipping | [V] [Environments](https://www.1password.dev/environments), [service accounts](https://www.1password.dev/service-accounts/manage-service-accounts) |
| Bitwarden Secrets Manager | Active, sold standalone and bundled | [V] [product](https://bitwarden.com/products/secrets-manager/), [overview](https://bitwarden.com/help/secrets-manager-overview/) |
| HashiCorp Vault | Active; HCP Vault Secrets discontinued | [V] [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2), [EOL notice](https://www.ibm.com/support/pages/hcp-vault-secrets-end-life) |
| Pulumi ESC | Active | [V] [concepts](https://www.pulumi.com/docs/esc/concepts/), [pricing](https://www.pulumi.com/pricing/) |
| Phase | Active commercial + self-host | [V] [CLI](https://docs.phase.dev/cli/commands), [pricing](https://phase.dev/pricing) |
| EnvKey | **Cloud shut down 2025-02-01**; new registrations disabled | [P] [README](https://github.com/envkey/envkey) |
| Chamber | Maintained OSS, AWS-native | [P] [README](https://github.com/segmentio/chamber) |
| aws-vault (upstream) | **Abandoned**; active fork at ByteNess | [P] [README](https://github.com/99designs/aws-vault), [fork](https://github.com/ByteNess/aws-vault) |
| SOPS | Active CNCF project | [P] [README](https://github.com/getsops/sops) |
| OpenBao | Active OSI-licensed Vault alternative | [P] [README](https://github.com/openbao/openbao) |
| AWS Secrets Manager | Active cloud baseline | [V] [pricing](https://aws.amazon.com/secrets-manager/pricing/) |
| dotenv-vault | Active but **paid-only** since May 2025 | [P] [README](https://github.com/dotenv-org/dotenv-vault) |

- EnvKey's own README says the cloud began a six-month wind-down on 2024-08-01 and "will shut down on February 1st, 2025"; new registrations were disabled — [EnvKey README](https://github.com/envkey/envkey). The same README still documents the product's feature set (end-to-end NaCl encryption, branches, environment inheritance, version control, audit logs, re-usable blocks) — useful as a historical feature baseline, not as a live option.
- HashiCorp/IBM's support notice sets HCP Vault Secrets **end of sale at 2025-06-30** and **end of life at the earlier of Flex contract expiry or 2026-07-01**, after which applications are deleted; customers are directed to HCP Vault Dedicated or Vault Community — [IBM support notice](https://www.ibm.com/support/pages/hcp-vault-secrets-end-life). The notice's last modified date is 2026-03-16.
- Upstream aws-vault's README opens with "This project has been abandoned and it's not receiving any more updates", directing users to `ByteNess/aws-vault` — [99designs/aws-vault README](https://github.com/99designs/aws-vault).
- dotenv-vault's README states it is "a paid only cloud service for syncing your .env files (as of May 2025)" — [dotenv-vault README](https://github.com/dotenv-org/dotenv-vault). This is a useful signal that the free-tier end of the developer-secret market is being repriced, not that demand disappeared.
- Public attention is concentrated but not aligned with revenue: Infisical's repo had ~30.1k stars and was pushed on 2026-10-30; SOPS ~23.6k; upstream aws-vault ~9.0k despite abandonment; Chamber ~2.6k; Doppler CLI ~400; Bitwarden's SM SDK ~495; Phase CLI ~16 — GitHub REST API, 2026-10-30. Stars measure developer attention, not production adoption; the Doppler CLI's low count relative to Doppler's commercial presence is the clearest counter-example.

### Inferences
- The market has split into **control planes** (Doppler, Infisical, 1Password, Bitwarden, Vault, Pulumi ESC, Phase) and **primitives** (SOPS, Chamber, aws-vault, dotenv-vault). Primitives survive because they are cheap and composable; control planes survive because they own lifecycle, audit and access. A new CLI + MCP product sits between the two and must decide which side it is on.
- HashiCorp's withdrawal from the "easy managed secrets" segment (HCP Vault Secrets) is a strategic signal: the low-end developer experience is being ceded to Doppler/Infisical/1Password/Phase, while HashiCorp concentrates on Vault Dedicated and enterprise governance. That lowers the competitive bar for a developer-first product but raises the bar for enterprise features.
- EnvKey's shutdown and dotenv-vault's paid-only pivot both suggest that **simple `.env` sync alone is not a durable business**. The surviving products bundle sync with access control, audit, rotation or deployment.

### Gaps
- EnvKey's corporate status after the cloud shutdown (dissolved vs. dormant) could not be verified from a primary source; only the README shutdown notice and the mail campaign link are available.
- HCP Vault Secrets' exact deletion state after 2026-07-01 is described in the notice but could not be confirmed against a live account.
- HashiCorp's current source licence for Vault Community could not be re-fetched: both `hashicorp.com/en/license` and the BSL announcement returned HTTP 429 on 2026-10-30. The licence claim is therefore left out of the comparison rather than asserted from memory. See §10.
- Phase's commercial scale is unknown; its public CLI repo is tiny (~16 stars), but the product has a paid cloud and self-host offering, so repo attention is not a reliable proxy.

---

## 2. Data model: what is a secret, and how are environments and versions represented?

### Takeaway
Every commercial product converges on the same four-level model — **organisation → project/app → environment → key/path** — but they diverge on the two things that matter for correctness: **version semantics** and **composition**. Doppler and Pulumi ESC have the richest composition models (branch inheritance, imports, providers); Vault has the most rigorous version/deletion semantics (KV v2 soft delete, undelete, destroy, max versions); Bitwarden and Phase document the least version history. 1Password is the outlier: its primary object is still a vault **item**, with Environments bolted on as a separate key-value surface.

### Cited Findings

| Product | Hierarchy | Versioning | Composition / references | Deletion semantics |
|---|---|---|---|---|
| Doppler | Workplace → project → environment → config (root + branch/personal) | Every secret version retained for the secret's lifetime; rollback for add/update/delete and trusted IPs | Secret references; config inheritance from a parent config; compare across configs/projects | Delete secret to clear history; individual versions can be redacted but remain stored |
| Infisical | Organisation → project (product type: Secrets Management, PAM, PKI) → environment → folder | Every change creates a new secret version; point-in-time recovery per folder | Secret references and overrides; imports; 3 environments on Free | Restore an earlier version creates a new version on top |
| 1Password | Account → vault → item; Environments are a separate project/stage variable set | Item history exists in the product, but the developer docs captured do not document Environment versioning | `op://` secret references; Environments are flat key-value | Item deletion/trash; service-account access immutable after creation |
| Bitwarden SM | Organisation → project → secret; each secret belongs to exactly one project; machine accounts hold access tokens | **No secret version history documented** in the overview, quick start or CLI docs | No secret-reference syntax documented | Secret delete; project delete |
| HashiCorp Vault | Mount → secrets engine → path; KV v2 is a versioned engine | KV v2 versions; soft delete, undelete, destroy; configurable max versions | No native cross-secret reference syntax; consumers compose via templates/API | Soft delete keeps data recoverable; destroy purges the version and marks metadata destroyed |
| Pulumi ESC | Organisation → project → environment (YAML document) | Every change creates an immutable revision; tags; rollback; import by revision/tag | Imports, `fn::open`, `fn::secret`, interpolations, built-in properties | Revision history is append-only; rollback creates a new revision |
| Phase | Organisation → app → environment → path | Version history is not described in the captured docs | Cross-environment and local `${...}` references; sealed/config/secret types | Secret delete; soft-delete/restore not documented |
| Chamber | AWS SSM Parameter Store service → key | SSM parameter versions; `chamber history` exposes them | No cross-secret references; tags | SSM delete; history retained per SSM |
| SOPS | Encrypted file → key | Git history is the version history | File-level references only; no runtime composition | Git revert |

- **Doppler** root configs hold the master list for an environment; branch configs inherit and override; changing a root config propagates to branches. Personal configs give each developer a private branch (`dev_personal`) — [root configs](https://docs.doppler.com/docs/root-configs), [branch configs](https://docs.doppler.com/docs/branch-configs). Config inheritance lets a child config consume a parent config's secrets and reflects parent changes automatically; it is a Team/Enterprise feature and is explicitly incompatible with Dynamic Secrets — [config inheritance](https://docs.doppler.com/docs/config-inheritance).
- **Doppler** retains every version of a secret "for the lifetime of that secret"; rollback is supported for adding, updating and deleting secrets, and for trusted-IP changes. Redacting a version makes it inaccessible and un-rollbackable but "the value itself is still stored on Doppler's end"; only deleting and recreating the secret clears history — [versioning](https://docs.doppler.com/docs/versioning).
- **Infisical** structures an organisation into projects, and a project has a product type (Secrets Management, PAM or PKI). Projects are isolated for permissions and configuration but share billing and the user directory — [platform hierarchy](https://infisical.com/docs/documentation/getting-started/concepts/platform-hierarchy). Every secret change creates a new version; restoring an older version "overwrites the current value and adds a new version at the top of the stack" — [secret versioning](https://infisical.com/docs/documentation/platform/secret-versioning).
- **1Password Environments** are explicitly "separate from the rest of the items in your 1Password vaults": one Environment per project or development stage, key-value variables, locally mounted `.env` files without writing credentials to disk, and `op run --environment` / `op environment read` — [Environments](https://www.1password.dev/environments), [read variables](https://www.1password.dev/environments/read-environment-variables). This is a second data model alongside vault items, not a replacement for them.
- **Bitwarden**'s core objects are secrets, projects, machine accounts and access tokens; a secret can only be associated with a single project at a time — [quick start](https://bitwarden.com/help/secrets-manager-quick-start/), [overview](https://bitwarden.com/help/secrets-manager-overview/). The CLI exposes `bws secret` and `bws project` CRUD but no revision/history command — [CLI docs](https://bitwarden.com/help/secrets-manager-cli/).
- **Vault KV v2** "stores and versions arbitrary static secrets" and uses soft deletes "to make data inaccessible while allowing data recovery"; permanently deleting an entry purges the underlying version data and marks metadata destroyed. Max versions is configurable — [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2).
- **Pulumi ESC** environments are YAML documents that hold configuration and secrets, import other environments, and reference providers; they are **evaluated when opened, not when defined**. Each change creates a new immutable revision; revisions can be tagged and pinned (`@<revision>`), and imports can be pinned to a revision or tag — [concepts](https://www.pulumi.com/docs/esc/concepts/), [versioning](https://www.pulumi.com/docs/esc/environments/versioning/).
- **Phase** documents secret types (`secret`, `sealed` write-only, `config` non-sensitive), paths/folders, personal overrides, tags, and cross-environment references; `secrets get` returns raw `${...}` syntax while `phase run` resolves it — [CLI commands](https://docs.phase.dev/cli/commands). No version-history command appears in the CLI reference.
- **Chamber** stores each secret as an SSM parameter under a service path, encrypts with a KMS key (default alias `parameter_store_key`), and exposes `chamber history <service> <key>` for the SSM version history — [Chamber README](https://github.com/segmentio/chamber).
- **SOPS** is a file format plus CLI: YAML/JSON/ENV/INI/binary values encrypted with AWS KMS, GCP KMS, Azure Key Vault, HuaweiCloud KMS, age or PGP; the encrypted file lives in git, so git is the history — [SOPS README](https://github.com/getsops/sops).

### Inferences
- **Versioning is not yet table stakes in the Bitwarden/Phase tier**, but it is table stakes in every product that expects to be the system of record for production. The absence is a real parity gap, not a documentation nicety: without version history there is no safe rollback after a bad rotation.
- **Composition is the sleeper feature.** Doppler's config inheritance and Pulumi ESC's imports both solve the same problem — one canonical value, many derived environments — and both reduce the "copy the secret into 12 configs" failure mode. Infisical's references/overrides and Phase's cross-environment references are weaker versions of the same idea. Vault deliberately does not do this; composition is left to the consumer.
- **Deletion semantics differ more than feature lists suggest.** Doppler's redaction keeps the value stored; Vault's destroy purges it; Bitwarden's delete is a straightforward destructive operation. A product that claims "secure deletion" must specify which of these it means.
- 1Password's dual model (items + Environments) is a migration strategy, not a clean abstraction: teams will have some secrets in vaults and some in Environments, and the two have different access paths, CLI commands and service-account semantics.

### Gaps
- Phase's version-history capability could not be confirmed either way; the CLI reference has no history command, but the console may.
- 1Password item/Environment version history and restore semantics are not documented on the pages captured.
- Bitwarden's backend may retain secret versions for audit, but no user-facing version/history feature is documented.
- Vault KV v2's default `max_versions` value and the exact behaviour of destroyed metadata were not captured; only the mechanism is confirmed.

---

## 3. CLI and SDK: what can a developer actually do from a terminal?

### Takeaway
`run` is the universal developer primitive: Doppler, Infisical, 1Password, Bitwarden, Phase, Pulumi ESC and Chamber all expose a command that injects secrets into a child process. HashiCorp Vault is the outlier — its CLI is an API/admin client and its runtime consumption path is the agent/API, not a `vault run` command. The new frontier is not another `run` flag; it is the **agent-facing surface**: Infisical's Agent Vault, Phase's AI mode, and Doppler's experimental MCP server are early attempts to let an AI agent use credentials without receiving them.

### Cited Findings

| Product | Injection / runtime command | CRUD / admin surface | Export / import | Repo-local config | SDKs |
|---|---|---|---|---|---|
| Doppler | `doppler run -- <cmd>`; dynamic leases also issued by `doppler secrets download` | `secrets`, `configs`, `environments`, `projects`, `activity`, `setup`, `login` | `secrets download`; `import` | `doppler.yaml` + `doppler setup` | Pricing page lists SDKs; exact language matrix not captured |
| Infisical | `infisical run -- <cmd>`; `infisical agent` renders files; `infisical agent-vault run` proxies agent traffic | `secrets`, `scan`, `agent`, `agent-vault`, `pam` | `export`; `scan` | `.infisical.json` / CLI context (not captured in detail) | Pricing page lists SDKs; CLI is the primary surface |
| 1Password | `op run -- <cmd>`, `op inject`, `op read`, `op run --environment`, `op environment read` (beta) | `op item`, `op vault`, `op service-account` | `op read`/`op inject`; no bulk export emphasised | `.env` / secret references in config files | Go, JavaScript, Python (Environments require current SDKs) |
| Bitwarden | `bws run -- <cmd>`; `--project-id`, `--shell`, `--no-inherit-env` | `bws secret`, `bws project` | `bws secret list` JSON; no bulk export command captured | `BWS_ACCESS_TOKEN` env var or inline token | SM SDK (repo `bitwarden/sdk-sm`) |
| Vault | No `vault run` primitive; consumers use the HTTP API, Vault Agent or client libraries | `vault kv`, `vault read/write`, `vault lease`, `vault audit`, `vault policy`, `vault agent`, `vault server` | API reads; no first-class `.env` export | Vault address/token config; no repo file | Official Go client + community clients |
| Pulumi ESC | `pulumi env run <env> -- <cmd>`; `pulumi env open` | `pulumi env init/list/get/set/edit/remove/clone/diff/version/rotate/tag/schedule/webhook` | `pulumi env open` returns evaluated values | Pulumi project/environment references | Pricing page lists multi-language SDKs |
| Phase | `phase run -- <cmd>`; `phase shell`; `phase dynamic-secrets lease generate` | `phase secrets`, `phase apps`, `phase dynamic-secrets`, `phase auth`, `phase ai` | `phase secrets export` (dotenv, JSON, YAML, CSV, TOML, HCL, INI, XML, Java properties) | `.phase.json` | Python, Go, Node.js |
| Chamber | `chamber exec <service> -- <cmd>`; `chamber env` | `chamber write/read/list/history/delete/find/tag` | `chamber export` / `chamber import` | None; AWS profile/region | Go library |
| aws-vault | `aws-vault exec <profile> -- <cmd>`; `aws-vault login` | `add`, `list`, `remove`, `rotate` | n/a (STS credentials) | `~/.aws/config` profiles | n/a |

- **Doppler CLI** exposes 21 top-level commands including `run`, `secrets`, `configs`, `environments`, `projects`, `setup`, `activity`, `import`, `login`, `open` and a beta `tui`; `doppler run` injects secrets into the environment, and `doppler setup` writes a `doppler.yaml` that binds a directory to a project/config — [CLI guide](https://docs.doppler.com/docs/cli).
- **Doppler MCP** is an npm package (`@dopplerhq/mcp-server`) that authenticates via browser or token and stores credentials in the system keyring. The vendor labels it **experimental** and warns that outputs are non-deterministic, recommending a token scoped only to the intended actions/projects/environments — [MCP server](https://docs.doppler.com/docs/mcp).
- **Infisical CLI** covers `run`, `export`, `scan` (including a pre-commit hook via `infisical scan install`), `agent` (daemon that renders secrets into files, with systemd/Windows service install), `agent-vault` (proxy that attaches real credentials to outbound agent requests, with sessions, access bundles and skills) and `pam` (brokered database/server/Kubernetes access with session recording) — [CLI reference](https://infisical.com/docs/cli/reference).
- **Infisical Agent Vault** is the closest analogue to Vaultly's thesis: "the agent never holds a secret" because a proxy "decides whether the agent's session allows the host and attaches the real credential on the way out"; agents get sessions and access bundles, and skills are installed into `~/.agents/skills` and linked for Claude Code/Hermes — [CLI reference](https://infisical.com/docs/cli/reference).
- **1Password CLI** provides `op read`, `op run`, `op inject`, `op environment read` (beta, CLI 2.33.0-beta.02+), and `op run --environment` (stable, CLI 2.41.0+). `op run` executes a subprocess with variables loaded and masks hidden values by default — [read Environment variables](https://www.1password.dev/environments/read-environment-variables), [CLI](https://www.1password.dev/cli). Service accounts authenticate with `OP_SERVICE_ACCOUNT_TOKEN` and have hourly read/write limits (Business: 10,000 reads, 1,000 writes per hour; Teams: 1,000/100) — [rate limits](https://www.1password.dev/service-accounts/rate-limits).
- **Bitwarden `bws run`** injects secrets as environment variables; it supports a single command or a chained shell command, `--project-id` scoping, `--shell`, `--no-inherit-env` and UUID key names. The CLI warns that `run` executes whatever you pass it, so untrusted commands must not be used — [CLI docs](https://bitwarden.com/help/secrets-manager-cli/).
- **Vault CLI** is broad: `vault kv` for the KV engine, `vault read/write` for arbitrary paths, `vault lease` for renew/revoke, `vault audit enable file` for audit devices, `vault policy` for policy management, plus `vault agent` and `vault server` — [commands](https://developer.hashicorp.com/vault/docs/commands). It is an operator/API surface first; application injection is left to agents, SDKs or templates.
- **Pulumi ESC CLI** exposes `pulumi env run`, `open`, `init`, `list`, `get`, `set`, `edit`, `remove`, `clone`, `diff`, `version`, `rotate`, `tag`, `schedule`, `webhook`, `change-request`, `open-request` and `provider` — [ESC CLI](https://www.pulumi.com/docs/esc/cli/).
- **Phase CLI** exposes `auth` (webauth, token, AWS IAM, Azure), `init`, `run`, `shell`, `apps list`, `secrets` CRUD/import/export, `dynamic-secrets lease generate/get/renew/revoke`, `users`, `console`, `docs` and `completion` — [Phase CLI](https://docs.phase.dev/cli/commands).
- **Phase AI mode** is the most explicit agent guardrail set in the market: when it detects Claude Code, Cursor, Codex, OpenCode or a generic `AGENT` env var, it redacts `secrets list/get/export` by type, blocks `phase shell`, blocks env-dumping commands inside `phase run` (`printenv`, `env`, `export`, `set`, `declare`, `compgen`), and refuses `phase ai enable/disable` from an agent — [Phase CLI](https://docs.phase.dev/cli/commands).
- **Chamber** has `exec`, `env`, `export`, `import`, `history`, `find`, `list`, `read`, `write`, `delete` and tag commands; `chamber exec` injects one or more services into a child process — [Chamber README](https://github.com/segmentio/chamber).
- **aws-vault** stores long-lived AWS credentials in an OS keychain/secret store, exchanges them for STS temporary credentials, and runs a child process (`exec`) or opens the console (`login`); it supports roles and MFA — [aws-vault README](https://github.com/99designs/aws-vault).

### Inferences
- The **minimum developer CLI** is now: `login`, `run`, `secrets` CRUD, `export`, a repo-local config file, and shell completion. Any product missing `run` competes on a different axis (Vault competes on policy and dynamic credentials, not local DX).
- **Agent-facing commands are the new differentiator, and they are being designed defensively.** Phase blocks env-dumping and `shell`; Infisical proxies traffic so the agent never holds the value; Doppler ships an explicitly experimental MCP server with a scoped-token warning. This is evidence that vendors see the same threat model Vaultly is built around — but none of them has made "the agent never receives the credential" the default across all operations.
- **SDK breadth is under-advertised.** Pricing pages list "SDKs" generically, while the CLI docs rarely enumerate languages. A buyer comparing SDK counts will get a misleading picture; the CLI is the real integration surface for most of these products.
- **Repo-local config is table stakes but inconsistent**: Doppler has `doppler.yaml`, Phase has `.phase.json`, 1Password uses secret references in existing files, Bitwarden uses an access-token env var, and Vault has no repo file at all. A new tool can win on this small UX detail by making the config file explicit, diffable and non-secret.

### Gaps
- Exact SDK language matrices for Doppler, Infisical, Bitwarden and Pulumi ESC were not enumerated from primary docs; pricing pages only say "SDKs".
- MCP support for 1Password, Infisical, Bitwarden and Pulumi ESC was not verified. Only Doppler's experimental MCP server and Phase's AI mode were captured.
- Vault Agent's `-exec` child-process mode was not captured in the command reference, so the statement "no `vault run` primitive" refers to the top-level CLI, not to every possible agent mode.
- The maturity/GA status of `op environment read` and 1Password's AWS Secrets Manager sync is beta per the docs; the GA date is unknown.

---

## 4. CI/CD and platform integrations: which are table stakes?

### Takeaway
GitHub Actions, Kubernetes and Terraform are the three integrations that every developer-facing product now claims, and cloud secret-store sync (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager) is becoming expected rather than differentiating. The differentiator is **depth**: OIDC/workload identity instead of long-lived tokens, an operator/injector instead of a sync job, and a documented failure mode for each integration. Breadth of logos is cheap; a secure default is not.

### Cited Findings

| Product | CI/CD | Kubernetes | IaC | Cloud secret sync | Workload identity / OIDC |
|---|---|---|---|---|---|
| Doppler | Config syncs and webhooks; GitHub/GitLab integrations advertised on pricing | Kubernetes Operator referenced in platform limits | Terraform provider advertised on Enterprise | Config syncs (5 Free / 100 Team / unlimited Enterprise) | "Identity Based Authentication" on Team; exact OIDC flow not captured |
| Infisical | GitHub Actions, CircleCI, GitLab CI/CD, AWS Secrets Manager connectors (pricing) | Docker, Kubernetes, Terraform native support (pricing) | Terraform | 10 secret syncs on Free; native syncs to GitHub, Vercel, AWS, Kubernetes | AWS Auth documented; full method list not enumerated |
| 1Password | GitHub Actions, CircleCI, Jenkins | Kubernetes Operator, Secrets Injector, Helm | Terraform provider, Pulumi, Ansible | AWS Secrets Manager sync (beta) | Service accounts; no OIDC flow captured |
| Bitwarden | "Out-of-the-box integrations"; Ansible guide | Kubernetes Operator referenced as caching layer | Not captured | Not captured | SSO (Enterprise), not workload OIDC |
| HashiCorp Vault | Consumed via API/agent in any CI | Vault Agent Injector is the common pattern (not captured here) | Terraform provider ecosystem (not captured here) | Vault is itself the source; cloud secret engines | AppRole, Kubernetes, AWS, OIDC auth methods (not enumerated) |
| Pulumi ESC | `pulumi env run` in any CI | Not a K8s secret operator | `pulumi-stacks`, `terraform-state` providers | Imports from AWS Secrets Manager, Azure, GCP, Vault, 1Password, Doppler, Infisical | `oidc`, `aws-login`, `azure-login`, `gcp-login`, `gh-login`, `vault-login` providers |
| Phase | GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite, Azure Pipelines, etc. (docs nav) | Kubernetes guide | Terraform provider | AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Vault | AWS IAM and Azure external identities; OIDC SSO |

- **1Password** has the clearest first-party integration story in the set: a GitHub Action ("Load Secrets from 1Password"), a CircleCI orb (`onepassword/secrets` with `exec`/`export`), a Jenkins plugin (`withSecrets`), a Kubernetes Operator and Secrets Injector, and Terraform/Pulumi/Ansible providers. Each resolves `op://` secret references at runtime and masks sensitive values in logs — [secure deployment](https://www.1password.dev/get-started/secure-deployment).
- **Infisical**'s pricing page lists native secret syncs to GitHub, Vercel, AWS and Kubernetes (10 on Free), third-party connectors for GitHub Actions, CircleCI, GitLab CI/CD and AWS Secrets Manager, and infrastructure support for Docker, Kubernetes and Terraform — [pricing](https://infisical.com/pricing).
- **Doppler**'s pricing page gates "Config syncs" by plan (5 Free, 100 Team, unlimited Enterprise) and lists "Identity Based Authentication" on Team plus "Integrations" on all plans; the platform-limits page notes that the API read rate limit applies to "direct requests to the API along with requests made by the CLI and Kubernetes Operator" — [pricing](https://www.doppler.com/pricing), [limits](https://docs.doppler.com/docs/platform-limits).
- **Pulumi ESC** is itself an integration hub: providers include `aws-login`, `azure-login`, `gcp-login`, `gh-login`, `vault-login`, `doppler-login`, `infisical-login`, `snowflake-login` and `oidc`; secret providers include `1password-secrets`, `aws-parameter-store`, `aws-secrets`, `azure-secrets`, `doppler-secrets`, `gcp-secrets`, `infisical-secrets`, `vault-secrets` and `external` — [ESC concepts / provider index](https://www.pulumi.com/docs/esc/concepts/). This makes ESC a **broker over other vendors' stores**, not just another store.
- **Phase** documents platform integrations for Docker, Docker Compose, Kubernetes, JetBrains IDEs, AWS IAM, AWS ECS, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Terraform, Vault, Nomad, Cloudflare Workers/Pages, GitHub Actions, GitHub Dependabot, GitLab CI, Vercel, Railway, Render, Supabase, Jenkins, CircleCI, AWS CodeBuild, Azure Pipelines, Travis CI, Bitbucket Pipelines, TeamCity, Drone CI, Buildkite, LiteLLM and OpenAI — [Phase docs navigation](https://docs.phase.dev/), with individual guides such as [GitHub Actions](https://docs.phase.dev/integrations/platforms/github-actions) and [Kubernetes](https://docs.phase.dev/integrations/platforms/kubernetes).
- **Bitwarden**'s product page advertises "out-of-the-box integrations" and links to an Ansible integration guide; the overview notes that some integrations, such as the Kubernetes Operator, act as a caching layer — [product](https://bitwarden.com/products/secrets-manager/), [overview](https://bitwarden.com/help/secrets-manager-overview/).
- **Vault** is the substrate rather than an app integration: CI systems, Kubernetes and Terraform consume it through its API, agent or auth methods; its value is the policy/lease model behind those integrations, not a prebuilt GitHub Action — [Vault commands](https://developer.hashicorp.com/vault/docs/commands), [lease concepts](https://developer.hashicorp.com/vault/docs/concepts/lease).

### Inferences
- **Integration breadth is commoditized.** A product launched in 2026 that ships GitHub Actions + Kubernetes + Terraform + AWS sync is at parity; a product that ships only a CLI is a primitive, not a control plane. This is why Chamber and aws-vault remain niche despite excellent local DX.
- **OIDC/workload identity is the meaningful differentiator inside integrations.** A GitHub Action that stores a long-lived service token in repository secrets has the same blast radius as a hard-coded secret; an action that exchanges a short-lived OIDC token for scoped access does not. Pulumi ESC and Phase document this explicitly; Doppler and Infisical advertise identity-based auth but the exact flows were not captured.
- **Pulumi ESC's broker model is strategically important.** If ESC can import from Doppler, Infisical, 1Password, Vault and the clouds, then it can be the "last mile" for teams that already have a store. A CLI + MCP product should consider the same posture: be consumable by other control planes rather than forcing a rip-and-replace.
- **Integration count is a poor proxy for integration quality.** Phase lists the most logos, but its public CLI footprint is tiny; 1Password lists fewer logos but documents the failure modes, masking and provider setup. Buyers should weight documentation depth over logo count.

### Gaps
- Exact integration inventories for Doppler, Bitwarden and Vault were not captured; the table's "not captured" cells are documentation gaps, not confirmed absences.
- OIDC flows for Doppler and Infisical (issuer, audience, subject mapping, token exchange) were not documented on the pages captured.
- No independent test of integration reliability, latency or failure behaviour was performed.
- Phase's integration pages exist in the docs navigation, but several `.md` URLs returned 404 during capture; the canonical HTML pages are assumed live.

---

## 5. Team collaboration: RBAC, approvals, audit and history

### Takeaway
RBAC is universal; **approvals are the new paid boundary**. Doppler gates change requests to Team, Infisical gates approval workflows to Enterprise, Pulumi gates approvals/advanced RBAC to paid tiers, and Vault gates control groups to Enterprise. Audit **retention** is a pricing lever (Doppler: 3 days Free, 90 days Team, custom Enterprise), not a binary feature. Self-hosting is an enterprise feature almost everywhere except Vault (always self-hosted), Phase (free self-host tier) and Infisical (free core, paid advanced).

### Cited Findings

| Product | RBAC | Approvals / change control | Audit log | SSO / SCIM | Self-host |
|---|---|---|---|---|---|
| Doppler | Workplace/project/environment roles; custom roles Enterprise | Change requests on Team+; change-request policies Enterprise | 3 days Free, 90 days Team, custom Enterprise; per-secret access logs | SAML SSO Team; SCIM Enterprise | On-prem Enterprise |
| Infisical | Org- and project-level RBAC; ABAC; temporary access; custom roles | Approval workflows and access requests **Enterprise** | Audit logs + streaming to SIEM/buckets; retention plan-gated | SAML/SCIM Enterprise | Free core; Advanced/Enterprise licence for advanced features |
| 1Password | Vault permissions, groups, custom roles (Business) | No change-approval workflow documented for Environments | Usage reports and service-account activity; retention not captured | SSO on Business; SCIM not captured | No self-host |
| Bitwarden SM | Project read/write; groups; custom roles Enterprise | No approval workflow documented | Event logs on Teams/Enterprise only | SSO/SCIM Enterprise | Enterprise |
| HashiCorp Vault | Policies (HCL), namespaces Enterprise, control groups Enterprise | Control groups (Enterprise) for required approvals | Audit devices (file/syslog/socket); Enterprise audit features | MFA Enterprise; SCIM Enterprise (beta per docs) | Always self-hosted; HCP Dedicated managed |
| Pulumi ESC | RBAC; custom roles and SAML on Pro; org access tokens | Update approvals + **open approvals** (JIT); drafts; `pulumi env open-request` | Audit logs listed on Pro | SAML/SSO Pro | Enterprise |
| Phase | Managed roles (Owner/Admin/Developer) + custom roles; team-scoped access | No approval workflow documented | Log streams; retention not captured | OAuth/OIDC SSO; SCIM Enterprise | Free and paid self-host |
| Chamber | AWS IAM only | None | AWS CloudTrail/SSM (external) | AWS IAM | n/a |
| aws-vault | AWS IAM only | None | AWS CloudTrail (external) | AWS IAM | n/a |
| SOPS | File/key access only | Git review | Git history | n/a | n/a |

- **Doppler** change requests let a user propose additions, modifications or deletions to configs they may not have write access to; reviewers with the proper access approve or reject. Change-request policies are Enterprise; the feature itself is Team+ — [change requests](https://docs.doppler.com/docs/change-requests). Audit retention is 3 days on Developer, 90 days on Team, custom on Enterprise — [pricing](https://www.doppler.com/pricing). Per-secret access logs record the actor, access method, first read and most recent read; Doppler "optimistically marks the secret as accessed as soon as the payload is returned" — [access logs](https://docs.doppler.com/docs/access-logs).
- **Infisical** approval workflows are explicitly **Enterprise Tier** on Cloud, and self-hosted users must buy an enterprise licence. Policies can require approval for changes in a target environment, support self-approval toggles and break-glass bypass with notifications — [approval workflows](https://infisical.com/docs/documentation/platform/pr-workflows). RBAC operates at organisation and project level, with ABAC, temporary access and additional privileges — [identity and access](https://infisical.com/docs/documentation/getting-started/concepts/platform-iam). Audit logs support filtering by actor/project/environment/path/key and streaming to SIEM, storage buckets or observability stacks — [audit logs](https://infisical.com/docs/documentation/getting-started/concepts/audit-logs).
- **1Password** service accounts are managed by owners/admins; team members with permission can create their own but cannot manage others'. A service account's overview shows vaults, Environments, permissions and recent activity, and usage reports can be generated — [manage service accounts](https://www.1password.dev/service-accounts/manage-service-accounts). No change-approval workflow for secret edits is documented on the pages captured.
- **Bitwarden** event and audit logs are available on Teams and Enterprise, not Free; SSO is Enterprise-only, as are SCIM, custom roles and self-hosting — [product comparison](https://bitwarden.com/products/secrets-manager/). Secrets Manager access is granted per member/group at the project level with read or read/write permissions — [quick start](https://bitwarden.com/help/secrets-manager-quick-start/).
- **Vault** authorisation is policy-based (HCL), with Enterprise adding namespaces, control groups, MFA, replication, HSM support, FIPS and automated credential rotation — [Enterprise features](https://developer.hashicorp.com/vault/docs/enterprise/features). Audit devices are enabled with `vault audit enable file file_path=...`; the CLI also supports `-output-policy` to derive a minimal policy for a command — [commands](https://developer.hashicorp.com/vault/docs/commands).
- **Pulumi ESC** supports two approval types: **update approvals** (a draft must be reviewed before it is applied) and **open approvals** (JIT access to an environment's secrets). Drafts are created with `pulumi env set --draft` or `pulumi env edit --draft`; open requests use `pulumi env open-request`; approvals can require re-approval after edits — [approvals](https://www.pulumi.com/docs/esc/concepts/approvals/). The docs explicitly note that Pulumi Deployments has no native approval gate and that open approvals are a "supported workaround" — [approvals](https://www.pulumi.com/docs/esc/concepts/approvals/). Audit logs and SAML/advanced RBAC are Pro-tier per the pricing page — [pricing](https://www.pulumi.com/pricing/).
- **Phase** has managed roles (Owner, Admin, Developer) plus custom roles with CRUD permissions on organisation- and application-level resources; teams group members/service accounts and grant scoped access, with optional role overrides and SCIM — [access control](https://docs.phase.dev/access-control), [roles](https://docs.phase.dev/access-control/roles). No approval workflow is documented in the captured pages.
- **Chamber, aws-vault and SOPS** have no team layer of their own: authorisation is AWS IAM (Chamber/aws-vault) or file/key access (SOPS); audit is CloudTrail/SSM or git history.

### Inferences
- **Approvals are where collaboration becomes governance.** Every product that sells to teams above ~20 engineers has some approval mechanism, and almost every one gates it above the entry tier. A new product that ships approvals in the free tier would undercut the market, but it would also take on the hardest UX problem (draft diffs, reviewer assignment, stale approvals).
- **Audit retention is a pricing primitive, not a compliance feature.** Doppler's 3-day free / 90-day team split is the clearest example. Buyers who need 1-year retention for SOC 2 will pay, regardless of how good the audit UI is.
- **Self-host is not a universal expectation.** 1Password does not offer it; Bitwarden gates it to Enterprise; Doppler gates it to Enterprise; Infisical and Phase use it as a wedge. For Vaultly, a local-first architecture is closer to Phase/Infisical's self-host posture than to a SaaS-only model.
- **Pulumi's open approvals are the most sophisticated JIT model in the set** — they gate *reading* an environment, not just changing it, and they can gate a deployment indirectly. That is the pattern a credential broker for AI agents should copy: the sensitive event is the **open/read**, not only the write.

### Gaps
- Audit retention periods for Infisical, 1Password, Bitwarden and Phase are not published on the pages captured.
- 1Password SCIM support and audit-log retention were not verified.
- Phase approval workflows may exist in the console but are not documented in the captured access-control pages.
- Vault Enterprise's control-group workflow was confirmed as a feature name, not exercised; the exact approval UX is not captured.

---

## 6. Rotation, expiry, references and drift

### Takeaway
Rotation is **provider-specific and tiered**, not a generic capability: Vault is the reference implementation (dynamic database credentials plus static-role password rotation), Doppler and Infisical approximate it for a subset of providers, Phase limits dynamic secrets to AWS IAM, and 1Password/Bitwarden document no native rotation at all. **Drift comparison is rare** — Doppler's Compare view is the only first-class cross-config/cross-project diff captured — even though drift is the failure mode that causes most production incidents. References are table stakes for composition; leases are the clearest enterprise differentiator.

### Cited Findings

| Product | Static rotation | Dynamic secrets / leases | References | Drift / comparison |
|---|---|---|---|---|
| Doppler | Rotated Secrets on Team+ (250 on Team, 500 Enterprise); proxied rotation via AWS Lambda | **Enterprise only**; TTL default 30 min; lease revealed once; revoke via API; leased by `doppler run` and `secrets download` | Yes (`${KEY}` syntax) | **Compare view** across configs/projects, group by value, diff to reference config |
| Infisical | Secret rotation with dual-phase/single-phase models; plan-gated | **Advanced plan**; unique per identity; revocation after use | Yes (references/overrides/imports) | Point-in-time recovery; no cross-environment diff captured |
| 1Password | None documented | None documented | `op://` references | None documented |
| Bitwarden | None documented | None documented | None documented | None documented |
| HashiCorp Vault | Database **static roles** auto-rotate passwords on a schedule; Enterprise automated credential rotation | **Dynamic roles** generate credentials on demand; all dynamic secrets have leases with TTL, renew and revoke | No native cross-secret refs | Version diff in KV v2; no cross-environment drift view |
| Pulumi ESC | Rotators: `aws-iam`, `azure-app-secret`, `mysql`, `postgres`, `snowflake-user`, `password`, `passphrase` | Dynamic credentials via `fn::open` providers (AWS/Azure/GCP logins, DB credentials); evaluated at open | Imports, interpolations, `fn::secret` | `pulumi env diff` between revisions |
| Phase | Rotating Secrets (plan-gated; lifecycle `rotating` in CLI) | **Enterprise only**, **AWS IAM only**; default/max TTL; lease generate/get/renew/revoke; requires SSE | Cross-environment and local references | None documented |
| Chamber | None (SSM versions only) | None | None | `chamber history` only |
| SOPS | Key rotation is a CLI operation; no schedule | None | File-level only | Git diff |

- **Doppler** defines a dynamic secret as a one-off lease with a required TTL, automatically deleted on expiry; the default TTL is 30 minutes and can be overridden in CLI/API. The lease is revealed once; if you miss it, request another. `doppler run` and `doppler secrets download` lease dynamic secrets automatically, and the lease ID can revoke early via API — [dynamic secrets](https://docs.doppler.com/docs/dynamic-secrets). Rotated Secrets is a separate Team+ feature with proxied rotation via AWS Lambda, least-privilege IAM and audit history in the customer's cloud — [rotated secrets](https://docs.doppler.com/docs/secrets-rotation).
- **Doppler Compare** places secrets from multiple configs side by side to show agreement, difference and absence; it can compare every config in a project or across the whole workplace, group by exact value, and diff against a chosen reference config — [comparing secrets](https://docs.doppler.com/docs/comparing-secrets). This is the clearest drift-detection feature in the survey.
- **Infisical** rotation supports dual-phase (active → inactive → revoked, overlapping) and single-phase models, with a 30-day example cycle; the docs describe provider-specific configuration but the provider list is rendered dynamically and was not captured — [secret rotation](https://infisical.com/docs/documentation/platform/secret-rotation/overview). Dynamic secrets are available on the **Advanced** plan and are unique per identity, generated on demand and revoked after use — [dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/overview).
- **Vault** database secrets engines generate credentials dynamically based on configured roles; static roles are a 1-to-1 mapping to a database username and Vault "stores and automatically rotates passwords" on a configurable period — [databases](https://developer.hashicorp.com/vault/docs/secrets/databases). All dynamic secrets have a lease with a TTL, renewability and revocation; revoking a token revokes all leases created with it — [lease](https://developer.hashicorp.com/vault/docs/concepts/lease).
- **Pulumi ESC** rotators cover AWS IAM, Azure app secrets, MySQL, PostgreSQL, Snowflake users, passwords and passphrases; dynamic credentials are resolved at open time and "never stored in the environment definition" — [concepts](https://www.pulumi.com/docs/esc/concepts/). `pulumi env rotate` rotates secrets in an environment — [ESC CLI](https://www.pulumi.com/docs/esc/cli/).
- **Phase** dynamic secrets are "credentials for third-party services that are *leased* on-demand for a limited time", tied to an account, renewable and revocable; the docs state they are **Enterprise-only** and currently supported only for **AWS IAM**, and that **server-side encryption must be enabled** for the app — [dynamic secrets](https://docs.phase.dev/console/dynamic-secrets). The CLI exposes the full lease lifecycle — [CLI](https://docs.phase.dev/cli/commands).
- **1Password** and **Bitwarden** document no native rotation or dynamic-secret leasing on the pages captured; their rotation story is "change the value and update consumers", optionally via integrations.
- **Chamber** exposes SSM versions and `history` but no rotation; **SOPS** has no scheduler or lease model.

### Inferences
- **Dynamic secrets are the strongest technical moat in the category** because they require a provider integration, a lease store, a revocation path and an audit trail. Vault has all four; Doppler and Infisical have them for a subset; Phase has them for one provider; 1Password and Bitwarden have none. A CLI + MCP product should not attempt to out-build Vault here; it should **delegate** dynamic credentials to Vault/cloud STS and focus on the brokering boundary.
- **Static rotation is the pragmatic middle ground** for teams that cannot adopt dynamic credentials: rotate a database password on a schedule and update the secret store. Doppler and Infisical productise this; 1Password/Bitwarden leave it to the customer.
- **Drift comparison is under-served.** Doppler's Compare is a genuine differentiator because it answers "which environments have diverged, and by how much?" without exporting secrets. A product that can diff *metadata* (key sets, versions, rotation age, policy) without exposing values would be valuable and safer than a value-level diff.
- **References are not a substitute for composition.** Doppler references, Infisical references/imports, Phase cross-environment references and Pulumi imports all reduce duplication, but only Doppler's inheritance and Pulumi's imports create a true parent-child relationship with propagation. The rest require manual updates when the source changes.

### Gaps
- Infisical's supported rotation/dynamic-secret provider list is rendered dynamically and could not be enumerated; the count and coverage are unknown.
- Phase's rotating-secret provider list is not visible in the captured docs; only the `rotating` lifecycle and the pricing-page feature are confirmed.
- Doppler's rotated-secret provider coverage and the exact proxied-rotation setup were not enumerated.
- 1Password and Bitwarden may support rotation through external integrations, but no native, documented rotation feature was found.
- Vault's KV v2 `max_versions` default and the precise difference between delete/undelete/destroy at the storage layer were not captured.

---

## 7. Pricing and free tiers

### Takeaway
Pricing models have diverged, and the model now determines which workloads are cheap: **per-seat** (Doppler, 1Password, Bitwarden, Phase) makes humans expensive and machines cheap or free; **per-identity** (Infisical) makes CI/machine identities expensive; **per-secret** (Pulumi ESC) makes config sprawl expensive; **per-cluster-hour** (HCP Vault Dedicated) makes infrastructure the unit. For a CLI + MCP product, the defensible model is **per-human with free machine identities and metered high-cost operations (deploy/exec)**, not per-secret or per-CI-token.

### Cited Findings

| Product | Free tier | Entry paid tier | Scale tier | Unit |
|---|---|---|---|---|
| Doppler | 3 users; 3-day logs; 10 projects; 4 envs; 10 configs/env; 50 service tokens | **$8/mo per additional user** (Developer) | **$21/user/mo** (Team); Enterprise custom | Per seat |
| Infisical | 5 identities; unlimited projects; 3 envs; 10 secret syncs | **$20/identity/mo annual, $23 monthly** (Pro) | **$40/identity/mo annual, $46 monthly** (Advanced); Enterprise custom | Per identity (human or machine) |
| 1Password | No free business tier; trial | **$8.99/user/mo annual** (Business) | Teams Starter Pack $2.49/user/mo (flat 10 users) | Per seat |
| Bitwarden SM | 2 users; 3 projects; 3 machine accounts; unlimited secrets | **$6/user/mo** (SM Teams) | **$12/user/mo** (SM Enterprise) | Per seat |
| HashiCorp Vault | Community self-host free | HCP Vault Dedicated Development XS **$0.61644/cluster-hour** | Essentials Small **$1.57799/hr**; Standard Small **$1.84299/hr**; client **$72.92/mo** | Per cluster-hour + client |
| Pulumi ESC | 1 user; 25 secrets; 10K API calls/mo | **$40/mo** (Essentials) + **$0.50/secret/mo** after 25 | **$400/mo** (Pro) + **$0.75/secret**; **$2,000/mo** (Enterprise) + **$1.00/secret** | Per secret + platform fee |
| Phase | 5 users; 3 apps; 3 envs | **$10/user/mo** (Pro) | **$25/user/mo** (Enterprise) | Per seat (service accounts free) |
| AWS Secrets Manager | No permanent free tier (credits changed 2025-07-15) | **$0.40/secret/mo** | **$0.05/10,000 API calls** | Per secret + API |
| Chamber / aws-vault / SOPS / OpenBao | Free OSS | You pay AWS/infrastructure | — | Infrastructure |

- **Doppler**: Developer is free for 3 users, then $8/mo per additional user; Team is $21/mo per user after a 14-day trial; Enterprise is custom. The plan comparison confirms 3 days / 90 days / custom audit retention, 10 / 250 / custom projects, 4 / 15 / custom environments, 10 / 100 / custom configs per environment, and 50 / 500 / custom service tokens — [pricing](https://www.doppler.com/pricing). Abuse limits are 1,200 secrets per config, 500 KiB config payload and 50 KiB per secret value — [platform limits](https://docs.doppler.com/docs/platform-limits).
- **Infisical**: Free covers 5 identities and unlimited projects; Pro is $20/identity/month billed annually ($23 month-to-month); Advanced is $40/$46; Enterprise is custom. The pricing page defines an identity as "any human or machine that authenticates to Infisical" — [pricing](https://infisical.com/pricing). This is the most important pricing detail in the survey: a CI pipeline with 20 services can consume 20 identities.
- **1Password**: Business is $8.99/user/month billed annually; the Teams Starter Pack is $2.49/user/month for a flat 10 users. Service accounts are available with Teams and Business — [business pricing](https://1password.com/business/pricing), [service accounts](https://www.1password.dev/service-accounts/manage-service-accounts).
- **Bitwarden**: the Secrets Manager product page prices Teams at **$6/user/month** and Enterprise at **$12/user/month**, with Free limited to 2 users, 3 projects and 3 machine accounts; additional machine accounts are $1 each — [product pricing](https://bitwarden.com/products/secrets-manager/). The business pricing page, on the same day, prices Password Manager Teams at **$4/user/month** and Enterprise at **$6/user/month**, and its comparison table includes Secrets Manager features (machine accounts, projects, event logs) under those plans — [business pricing](https://bitwarden.com/pricing/business/). The product FAQ says an organisation "will have the same plan across any product they are subscribed to" — [product FAQ](https://bitwarden.com/products/secrets-manager/). **These two pages conflict**; see §10.
- **HCP Vault Dedicated** (IBM price list): Development XS $0.61644/cluster-hour; Essentials Small $1.57799; Standard Small $1.84299; Medium Essentials $3.16299 / Standard $3.69099; Large Essentials $7.48857 / Standard $9.40599; a "Product Client" line at $72.92/month — [IBM pricing](https://www.ibm.com/products/hashicorp/pricing). The "client" unit is ambiguous; see Gaps.
- **Pulumi ESC**: Free includes 1 user, 25 secrets, 10K API calls/month; Essentials is $40/month with unlimited users and $0.50/secret/month after 25; Pro is $400/month with $0.75/secret; Enterprise is $2,000/month with $1.00/secret. Plaintext config is free; API calls are 10K free then $0.10/10K — [pricing](https://www.pulumi.com/pricing/).
- **Phase**: Free is 5 users, 3 apps and 3 environments; Pro is $10/user/month; Enterprise is $25/user/month. Service accounts are free and unlimited; only human users are charged — [pricing](https://phase.dev/pricing). Self-hosted plans mirror the cloud tiers, with a free self-host tier.
- **AWS Secrets Manager**: $0.40 per secret per month, prorated hourly, plus $0.05 per 10,000 API calls; replica secrets are billed as distinct secrets — [AWS pricing](https://aws.amazon.com/secrets-manager/pricing/).
- **dotenv-vault**: paid-only since May 2025 — [README](https://github.com/dotenv-org/dotenv-vault).

### Inferences
- **Per-identity pricing is hostile to CI**. Infisical's model is fair for human-heavy teams and expensive for machine-heavy ones; a team with 10 engineers and 100 CI identities pays for 110 identities. Doppler and Phase explicitly make non-human identities free or cheap, which is a direct competitive wedge.
- **Per-secret pricing is hostile to config sprawl**. Pulumi ESC's $0.50–$1.00/secret/month is cheap for 50 secrets and expensive for 5,000; it also creates an incentive to cram multiple values into one secret. Doppler's 1,200-secrets/config limit and Bitwarden's unlimited secrets are the opposite design.
- **Per-seat pricing is predictable but taxes collaboration**. 1Password Business at $8.99 and Bitwarden Teams at $6 are close enough that the decision will be driven by bundling (password manager + SM) rather than marginal seat price.
- **The free tier is disappearing at the edges** (dotenv-vault paid-only; Bitwarden Free capped at 2 users; Doppler Free capped at 3 users and 3-day logs). A generous free tier is now a acquisition strategy, not a market norm.
- **For Vaultly, the pricing model should follow the workload**: charge per human, keep machine identities free, and meter operations that consume external resources (deployments, maintenance runs). Charging per secret would punish the "many small config values" use case that a CLI naturally serves.

### Gaps
- Enterprise/custom pricing for Doppler, Infisical, 1Password, Bitwarden, Vault and Phase is not public.
- The HCP Vault Dedicated "Product Client" unit is not explained on the price list; it may be a per-cluster client charge or a per-seat charge, and the table does not disambiguate.
- 1Password's Teams/Business service-account inclusion and any usage-based limits beyond the hourly rate limits were not fully priced.
- Infisical's annual-vs-monthly display is visually compressed on the page; the $20/$23 and $40/$46 pairs are interpreted as annual/monthly, but the page does not label them in the captured text.
- Bitwarden's standalone SM price and bundled PM price conflict; the effective price depends on how the organisation is provisioned, which the pages do not reconcile.

---

## 8. Per-product assessment: differentiators and documented weaknesses

### Takeaway
Each product's weakness is the shadow of its strength. Doppler's strength is composition and drift; its weakness is that the best parts (dynamic secrets, change-request policies, on-prem) are Enterprise-only. Infisical's strength is breadth (secrets + PAM + PKI + Agent Vault); its weakness is per-identity pricing and Enterprise-gated approvals. 1Password's strength is UX and CI/IaC depth; its weakness is immutable service-account permissions and no dynamic secrets. Bitwarden's strength is price and E2EE; its weakness is a thin SM feature set. Vault's strength is the lease/policy model; its weakness is operational weight. Pulumi ESC's strength is environment-as-code and brokering; its weakness is per-secret pricing and Pulumi-centricity. Phase's strength is E2EE + AI guardrails; its weakness is one-provider dynamic secrets and a small footprint.

### Cited Findings

**Doppler**
- Differentiator: config inheritance + branch/personal configs + Compare + versioning + change requests form a coherent "Git-like" workflow for config, not just a secret store — [config inheritance](https://docs.doppler.com/docs/config-inheritance), [branch configs](https://docs.doppler.com/docs/branch-configs), [comparing secrets](https://docs.doppler.com/docs/comparing-secrets), [versioning](https://docs.doppler.com/docs/versioning), [change requests](https://docs.doppler.com/docs/change-requests).
- Weakness: Dynamic Secrets are **Enterprise-only** — [dynamic secrets](https://docs.doppler.com/docs/dynamic-secrets). Service accounts and config inheritance are Team+ — [service accounts](https://docs.doppler.com/docs/service-accounts), [config inheritance](https://docs.doppler.com/docs/config-inheritance). Free tier is 3 users with 3-day logs — [pricing](https://www.doppler.com/pricing). MCP is experimental — [MCP](https://docs.doppler.com/docs/mcp).
- Operational limit: 1,200 secrets per config, 50 KiB per value, 500 KiB payload — [platform limits](https://docs.doppler.com/docs/platform-limits).

**Infisical**
- Differentiator: one platform with Secrets Management, PAM and PKI project types; per-identity RBAC/ABAC; dynamic secrets; rotation; approval workflows; audit streaming; Agent Vault for AI agents — [platform hierarchy](https://infisical.com/docs/documentation/getting-started/concepts/platform-hierarchy), [IAM](https://infisical.com/docs/documentation/getting-started/concepts/platform-iam), [dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/overview), [Agent Vault CLI](https://infisical.com/docs/cli/reference).
- Weakness: approvals are **Enterprise-only** — [approval workflows](https://infisical.com/docs/documentation/platform/pr-workflows); dynamic secrets are **Advanced** — [dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/overview); pricing is per identity, including machines — [pricing](https://infisical.com/pricing).
- Security detail: machine identities get Universal Auth by default; access tokens expire after the auth method's TTL (30 days default), and Universal Auth client secrets have a TTL default of `0` (never expire) unless configured — [machine identities](https://infisical.com/docs/documentation/platform/identities/machine-identities).

**1Password Developer**
- Differentiator: best-in-class CLI ergonomics (`op run`, `op inject`, `op read`), Environments with local `.env` mounting, service accounts, and a deep CI/IaC integration set — [Environments](https://www.1password.dev/environments), [secure deployment](https://www.1password.dev/get-started/secure-deployment), [CLI](https://www.1password.dev/cli).
- Weakness: after creation, a service account's vault/Environment access and permissions are **immutable**; changing them requires creating a new service account — [manage service accounts](https://www.1password.dev/service-accounts/manage-service-accounts). Service-account rate limits are 10,000 reads/1,000 writes per hour on Business (1,000/100 on Teams) — [rate limits](https://www.1password.dev/service-accounts/rate-limits). Environments are not available on iOS/Android, and creation/editing requires the desktop app — [Environments](https://www.1password.dev/environments). No native dynamic secrets/leases are documented.

**Bitwarden Secrets Manager**
- Differentiator: cheapest credible E2EE option; simple CLI (`bws run`); machine accounts and access tokens; self-host on Enterprise; bundled with Password Manager — [overview](https://bitwarden.com/help/secrets-manager-overview/), [product](https://bitwarden.com/products/secrets-manager/).
- Weakness: SM is a separate product with only web, CLI and SDK clients (no desktop/mobile) — [overview](https://bitwarden.com/help/secrets-manager-overview/); each secret belongs to exactly one project — [quick start](https://bitwarden.com/help/secrets-manager-quick-start/); no version history, approvals, rotation or dynamic secrets are documented in the captured docs; event logs are Teams+ — [product comparison](https://bitwarden.com/products/secrets-manager/).
- Pricing conflict: standalone SM Teams/Enterprise $6/$12 vs PM Teams/Enterprise $4/$6 with SM features included — [SM pricing](https://bitwarden.com/products/secrets-manager/), [business pricing](https://bitwarden.com/pricing/business/).

**HashiCorp Vault**
- Differentiator: the reference implementation of dynamic secrets, leases, revocation and policy; KV v2 versioning with soft delete/undelete/destroy; database dynamic and static roles; audit devices; Enterprise namespaces, replication, HSM, control groups, MFA and automated rotation — [KV v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2), [databases](https://developer.hashicorp.com/vault/docs/secrets/databases), [lease](https://developer.hashicorp.com/vault/docs/concepts/lease), [Enterprise features](https://developer.hashicorp.com/vault/docs/enterprise/features).
- Weakness: operational weight and enterprise gating; HCP Vault Secrets is discontinued (end of sale 2025-06-30, EOL 2026-07-01) — [EOL notice](https://www.ibm.com/support/pages/hcp-vault-secrets-end-life); HCP Vault Dedicated is priced per cluster-hour plus a client charge — [IBM pricing](https://www.ibm.com/products/hashicorp/pricing). Vault has no `vault run` developer primitive comparable to `doppler run`; consumption is via API/agent/SDK — [commands](https://developer.hashicorp.com/vault/docs/commands).

**Pulumi ESC**
- Differentiator: environment-as-code with imports, providers, rotators, `fn::open`/`fn::secret`, immutable revisions, tags, rollback, update approvals and JIT open approvals; can import from AWS/Azure/GCP/Vault/1Password/Doppler/Infisical — [concepts](https://www.pulumi.com/docs/esc/concepts/), [versioning](https://www.pulumi.com/docs/esc/environments/versioning/), [approvals](https://www.pulumi.com/docs/esc/concepts/approvals/).
- Weakness: per-secret pricing after 25 secrets ($0.50–$1.00/secret/month); approvals/audit/advanced RBAC are paid-tier; the docs admit Pulumi Deployments has no native approval gate — [pricing](https://www.pulumi.com/pricing/), [approvals](https://www.pulumi.com/docs/esc/concepts/approvals/).

**Phase**
- Differentiator: E2EE by default with per-environment keys; CLI with dynamic lease lifecycle; free service accounts; custom RBAC; self-host; **AI mode** that redacts values, blocks shell and blocks env-dumping commands when an agent is detected — [security](https://docs.phase.dev/security), [CLI](https://docs.phase.dev/cli/commands), [pricing](https://phase.dev/pricing).
- Weakness: Dynamic Secrets are **Enterprise-only and AWS IAM-only**, and require server-side encryption — [dynamic secrets](https://docs.phase.dev/console/dynamic-secrets); E2EE means the REST API and third-party syncs need SSE opt-in — [security](https://docs.phase.dev/security); public CLI footprint is tiny (~16 stars) — GitHub API, 2026-10-30; several docs URLs returned 404 during capture.

**Chamber**
- Differentiator: minimal AWS-native wrapper over SSM Parameter Store + KMS, with `exec`, `history`, tags, `find` and export/import — [README](https://github.com/segmentio/chamber).
- Weakness: no team UI, RBAC, approvals or audit of its own; authorisation is AWS IAM; inherits SSM limits; no rotation/dynamic secrets.

**aws-vault**
- Differentiator: excellent local AWS credential hygiene — OS keychain backends, STS temporary credentials, roles/MFA, `exec` and `login` — [README](https://github.com/99designs/aws-vault).
- Weakness: upstream abandoned; AWS-only; no team features or secret storage beyond AWS credentials — [README](https://github.com/99designs/aws-vault), active fork [ByteNess/aws-vault](https://github.com/ByteNess/aws-vault).

**SOPS / OpenBao**
- SOPS: git-native encryption with KMS/age/PGP; no server, RBAC, audit or dynamic secrets — [README](https://github.com/getsops/sops).
- OpenBao: OSI-licensed Vault alternative with secure storage, dynamic secrets, leasing, renewal and revocation — [README](https://github.com/openbao/openbao). Its weakness is ecosystem maturity relative to Vault, not capability breadth.

**EnvKey**
- Historical: cloud shut down 2025-02-01; the README still documents E2EE (NaCl), branches, environment inheritance, version control, audit logs and re-usable blocks — [README](https://github.com/envkey/envkey). Not a viable current parity target.

### Inferences
- **Doppler is the closest analogue to a "config workflow" product**, not just a secret store. Its Compare + inheritance + change-request triad is the most coherent answer to multi-environment drift. A new product that only stores secrets is competing with Vault/Chamber, not Doppler.
- **Infisical is the closest analogue to a "platform" strategy**: secrets + PAM + PKI + agent brokering + per-identity pricing. It is also the most direct competitor to Vaultly's agent boundary (Agent Vault), which means differentiation must come from the **local-first, no-server, value-blind** design rather than from feature count.
- **1Password and Bitwarden compete on trust and price**, not on lifecycle. They will win teams that already use the password manager and only need static secrets + `run`; they will lose teams that need rotation, approvals or dynamic credentials.
- **Phase is the most interesting small player for Vaultly**: its AI-mode guardrails (block `shell`, block `printenv`, redact by type) are exactly the primitives a credential broker needs, but its dynamic-secret coverage is one provider and its docs are thin. A product that generalises Phase's AI mode across providers and operations would be differentiated.
- **Vault remains the ceiling for lifecycle features**, but its complexity and enterprise pricing leave a gap for a product that delivers 20% of Vault's lifecycle value at 10% of the operational cost.

### Gaps
- No independent user complaints, churn data or win/loss evidence were collected; all weaknesses above are vendor-documented or documented absences.
- Bitwarden's and 1Password's internal version/audit retention may exist without being documented on the captured pages.
- Phase's rotating-secret provider coverage and approval features are not documented in the captured pages.
- Vault's current source licence and the exact Enterprise feature entitlement by edition were not verified (see §10).
- Chamber's maintenance cadence and security posture were not independently assessed; the last push date is from GitHub metadata only.

---

## 9. Table stakes vs differentiating: what "product ready" means for a CLI + MCP credential manager

### Takeaway
The table-stakes bundle is now a commodity: hierarchy, `run` injection, machine identities, versioning, audit, RBAC, rotation for common providers, GitHub/Kubernetes/Terraform integrations, and a free tier. A new product cannot win by shipping that bundle; it can only lose by missing it. The defensible wedge for a CLI + MCP credential manager is **the credential boundary itself**: value-blind operations, allowlisted mutations, typed confirmations, local audit, and deployment/infrastructure actions that are authorised without ever exposing the credential. That is a narrower product than a secret manager, and it should be positioned as such.

### Cited Findings

**Table stakes (must ship to be considered)**

| Capability | Evidence that it is table stakes | Minimum bar |
|---|---|---|
| Organisation → project → environment → key/path | Every commercial product in §2 uses this shape | Three levels, custom environments on paid tiers |
| CLI `run` injection | Doppler, Infisical, 1Password, Bitwarden, Phase, Pulumi ESC, Chamber all have it | `run -- <cmd>` with env injection, no plaintext file |
| Machine identity / service account | Doppler, Infisical, 1Password, Bitwarden, Phase, Vault, Pulumi all have one | Scoped token, expiry, rotation, audit |
| Versioning + rollback | Doppler, Infisical, Vault KV v2, Pulumi ESC; absent in Bitwarden/Phase docs | Per-key history with restore |
| Audit log | Every commercial product; retention is tiered | Actor, action, target, result, timestamp |
| RBAC | Every commercial product | Project/environment scope, read vs write |
| Rotation for common providers | Doppler Team+, Infisical, Vault, Pulumi rotators, Phase rotating | At least DB/API-key rotation, or a documented delegation path |
| GitHub Actions + Kubernetes + Terraform | 1Password, Infisical, Phase, Pulumi; Vault via API/agent | One documented path per platform, with a secure default |
| Free tier / trial | All commercial products | Individual or small-team tier |
| Self-host or data residency | Vault, Infisical, Phase, Bitwarden Enterprise, Doppler Enterprise | At least a documented deployment model |

**Differentiators (choose two or three, not all)**

| Differentiator | Who does it today | Why it matters | Cost to build |
|---|---|---|---|
| Dynamic secrets with leases | Vault, Doppler Enterprise, Infisical Advanced, Phase Enterprise (AWS only), Pulumi `fn::open` | Eliminates long-lived credentials; revocable on compromise | High: provider integrations, lease store, revocation |
| Approvals / JIT access | Doppler Team+, Infisical Enterprise, Pulumi Pro (update + open), Vault Enterprise control groups | Turns collaboration into governance; satisfies auditors | Medium: draft/diff/reviewer workflow |
| AI-agent credential brokering | Infisical Agent Vault, Phase AI mode, Doppler MCP (experimental) | Lets agents act without holding secrets; the core Vaultly thesis | Medium–high: proxy/session model, policy, redaction |
| Drift comparison | Doppler Compare | Detects environment divergence without exporting values | Medium: metadata diff + value comparison UI |
| Config inheritance / composition | Doppler inheritance, Pulumi imports | Removes copy-paste across environments | Medium: graph resolution, cycle detection |
| E2EE with client-side decryption | Bitwarden, Phase | Server cannot read secrets; strong trust story | High: key management, sharing, recovery |
| OIDC / workload identity | Pulumi ESC, Phase, Infisical (AWS Auth), Doppler identity-based auth | Removes long-lived CI tokens | Medium: issuer/audience/subject mapping |
| Per-human pricing with free machines | Phase (service accounts free), Doppler (agents free) | Aligns price with value; CI-heavy teams not penalised | Pricing decision, not engineering |
| Deployment/infra actions, not just secret sync | Vaultly's proposed Cloudflare deploy/exec surface | Solves the "last mile" after the secret is fetched | High: provider APIs, preflight, rollback |

- **Doppler's plan matrix** is the clearest evidence that the table-stakes bundle is tiered: change requests, service accounts, config inheritance, rotation, SAML SSO and 90-day logs all start at Team ($21/user/mo); dynamic secrets, change-request policies, SCIM, on-prem, EKM and log forwarding are Enterprise — [pricing](https://www.doppler.com/pricing).
- **Infisical's plan matrix** shows the same pattern with different boundaries: dynamic secrets start at Advanced, approvals at Enterprise, while the Free tier still includes 5 identities, unlimited projects, 3 environments and 10 secret syncs — [pricing](https://infisical.com/pricing).
- **Phase's plan matrix** puts dynamic secrets at Enterprise and everything else (including service accounts) at Free/Pro — [pricing](https://phase.dev/pricing). This is the most generous machine-identity posture in the survey.
- **Pulumi ESC's plan matrix** is the most unusual: the platform fee is per organisation, the secret count is metered, and unlimited users start at Essentials — [pricing](https://www.pulumi.com/pricing/). It prices the *resource*, not the *person*.
- **Bitwarden's plan matrix** shows event logs, user groups and unlimited projects starting at Teams; SSO, SCIM, custom roles and self-host at Enterprise — [product comparison](https://bitwarden.com/products/secrets-manager/).
- **Vaultly's own contract** already defines the differentiating surface: 31 MCP tools, write-only credentials, allowlisted maintenance scripts, typed confirmations, preflight-only reads, and no generic run — [AGENTS.md](../../AGENTS.md). That is a product thesis, not a feature list.

### Inferences

**What "product ready" means, concretely.** A CLI + MCP credential manager is product-ready when a security-conscious team can adopt it without also buying a secret manager. That requires the table-stakes bundle above, plus a credible answer to four questions:

1. **Can a developer get secrets into a process without seeing them?** `vaultly run -- <cmd>` (or equivalent) must inject env vars, support a repo config, and never write plaintext to disk by default.
2. **Can a machine authenticate without a long-lived secret?** OIDC/workload identity or a short-lived machine token, scoped to a project/environment, with rotation and revocation.
3. **Can an auditor reconstruct who did what?** Append-only audit with actor, operation, target, result, and a safe error code; no secret values in logs.
4. **Can an AI agent act without receiving the credential?** An MCP server that exposes operations, not values; allowlists; typed confirmations for mutations; a policy that denies by default.

**What to copy, in order.**
- **From Phase:** AI-mode guardrails (block shell/env-dumping, redact by type) and free service accounts.
- **From Infisical:** Agent Vault's proxy model (agent never holds the credential) and `agent` file rendering.
- **From Doppler:** Compare/drift and config inheritance as the answer to multi-environment sprawl.
- **From Pulumi ESC:** open approvals (JIT access to read), immutable revisions and tags.
- **From Vault:** lease semantics and revocation, even if the first version only brokers cloud STS credentials.
- **From 1Password:** `op run`/`op inject` ergonomics and masked output by default.

**What not to build yet.**
- A dynamic-secrets engine for databases. Delegate to Vault/cloud STS; the provider matrix is a multi-year project.
- Full PAM (session recording, SSH brokering). Infisical and Teleport already own it; it is a different product.
- SAML/SCIM, custom roles, and a self-host control plane. These are enterprise table stakes but not differentiators for a small team.
- Secret scanning. Infisical sells it as an add-on; GitHub/GitGuardian own the workflow.
- A generic `run` or shell. The whole point of the credential boundary is that the agent supplies operations, not commands.
- Fifty integrations. Ship GitHub Actions, Cloudflare, Kubernetes and Terraform; let the long tail use the CLI/API.

**Positioning.** The product should not be "another Doppler/Infisical". It should be "the credential boundary for humans and AI agents that operate infrastructure" — narrower than a secret manager, deeper than an MCP wrapper. The comparison set is therefore **Infisical Agent Vault, Phase AI mode, Doppler MCP, 1Password service accounts, and Vault's lease model**, not the full secret-manager market. Against that set, the differentiators are: local-first storage, value-blind operations, allowlisted mutations with typed confirmation, preflight/drift for deployments, and a Cloudflare-native deployment path.

### Gaps
- No willingness-to-pay research or pricing test was conducted; the per-human/free-machine recommendation is an inference from competitor packaging, not validated demand.
- The cost of building OIDC, rotation and approvals was estimated qualitatively; no engineering estimate was produced.
- The MCP threat model and client support matrix are covered in the companion `integrations_and_mcp.md` note, not here.
- "Product ready" is defined for a security-conscious small team; enterprise readiness (SOC 2, SAML, SCIM, audit retention, DLP) is out of scope for this note.

---

## 10. Confidence, conflicts and items explicitly not verified

### Takeaway
The feature inventory is high-confidence where vendor docs are explicit and low-confidence where it relies on absence. Three conflicts need to be carried into the report rather than silently resolved: **Bitwarden's SM pricing**, **HCP Vault Secrets' EOL dates**, and **1Password Environments' GA/beta status**. Two material claims could not be verified at all: Vault's current source licence (HTTP 429) and Phase's version-history/approval features (docs gaps). The market-level conclusions are robust to these gaps; the per-product parity scores are not.

### Cited Findings
- **Bitwarden pricing conflict.** The Secrets Manager product page lists Teams at $6/user/month and Enterprise at $12/user/month — [SM product page](https://bitwarden.com/products/secrets-manager/). The business pricing page lists Password Manager Teams at $4/user/month and Enterprise at $6/user/month, and its comparison table includes Secrets Manager features — [business pricing](https://bitwarden.com/pricing/business/). The SM FAQ says an organisation has the same plan across products — [SM FAQ](https://bitwarden.com/products/secrets-manager/). The most likely explanation is that standalone SM subscriptions are priced separately, while organisations that already have PM Teams/Enterprise get SM features at the PM price; the pages do not state this explicitly.
- **HCP Vault Secrets EOL.** The IBM support notice sets end of sale at 2025-06-30 and end of life at the earlier of Flex contract expiry or 2026-07-01, after which applications are deleted — [IBM support](https://www.ibm.com/support/pages/hcp-vault-secrets-end-life). The notice was last modified 2026-03-16. An earlier working note in this research said "data deleted 2025-08-27"; that date is **not supported** by the primary source and is retracted.
- **1Password Environments status.** The Environments overview presents the feature as available (create in desktop app, policy toggle, `op run --environment` stable since CLI 2.41.0) but `op environment read` is beta (CLI 2.33.0-beta.02+) and AWS Secrets Manager sync is labelled beta — [Environments](https://www.1password.dev/environments), [read variables](https://www.1password.dev/environments/read-environment-variables). Calling the whole feature "beta" would overstate the instability; calling it fully GA would understate the beta APIs.
- **Vault licence.** Both `https://www.hashicorp.com/en/license` and the BSL announcement returned HTTP 429 on 2026-10-30. The widely reported 2023 move of Vault (and other HashiCorp products) to the Business Source License could not be re-verified from a primary source in this pass. OpenBao's README states its intent to provide the software under an OSI-approved licence, which is consistent with a licence change at HashiCorp but does not prove the exact terms — [OpenBao README](https://github.com/openbao/openbao).
- **Phase documentation gaps.** `https://docs.phase.dev/cli/commands.md` resolved, but `docs.phase.dev/cli/commands` (the HTML page) and several `.md` variants returned 404 during capture; the canonical HTML page was fetched successfully. Phase's version-history, approval-workflow and rotating-secret provider coverage are not documented on the pages captured — [Phase CLI](https://docs.phase.dev/cli/commands), [dynamic secrets](https://docs.phase.dev/console/dynamic-secrets).
- **EnvKey corporate status.** The README confirms the cloud shutdown and disabled registrations; it does not confirm whether the company was dissolved or whether self-hosted support continues — [EnvKey README](https://github.com/envkey/envkey).
- **GitHub metadata.** Star/fork/push counts were retrieved from `api.github.com/repos/<owner>/<repo>` on 2026-10-30; a later attempt during the same session hit HTTP 403 (rate limit), so the counts are a single snapshot, not a time series. `open_issues_count` includes pull requests — [GitHub REST API](https://docs.github.com/en/rest).

### Inferences
- **Absence claims should be treated as hypotheses.** "Bitwarden has no versioning" means "no versioning is documented in the overview, quick start and CLI pages"; it does not mean the backend cannot retain versions. The same applies to 1Password approvals and Phase version history. A buyer evaluating parity should ask the vendor for a capability matrix, not rely on documentation alone.
- **The Bitwarden conflict is material for pricing comparisons** because it changes the effective per-seat cost by 33–50% depending on whether SM is bundled. Any market map that uses one page without the other will misprice Bitwarden.
- **The HCP Vault Secrets date correction matters** because it changes the product's status from "sunsetting soon" to "past EOL". A report that repeats the wrong date will look unreliable to anyone who checks the IBM notice.
- **The Vault licence gap is the largest single uncertainty** in the OSS comparison. If Vault Community is BSL (not OSI), then OpenBao is the only OSI-licensed Vault-compatible option, which materially changes the "open-source alternative" recommendation. This should be resolved before publication.

### Gaps
- Vault Community's current licence terms (BSL 1.1 vs. other) were not verified due to HTTP 429 on HashiCorp's licence and announcement pages.
- Bitwarden's effective SM price for an organisation that already has PM Teams/Enterprise was not verified with a live quote.
- Phase's version history, approval workflow and rotating-secret provider coverage were not verified; the docs pages either 404'd or did not mention them.
- 1Password's item/Environment version history and audit retention were not verified.
- No independent user survey, churn data, win/loss analysis or hands-on benchmark was used. Every "weakness" is vendor-documented or a documented absence.
- Enterprise/custom pricing for Doppler, Infisical, 1Password, Bitwarden, Vault and Phase is not public and was not quoted.
- The HCP Vault Dedicated "Product Client" unit and the exact composition of the $72.92/month line were not explained by the price list.
- Infisical's annual-vs-monthly price display and its per-identity definition were read from the pricing page; a live quote could differ by contract terms.
- Star counts are a attention proxy, not adoption; the Doppler CLI's ~400 stars against Doppler's commercial presence is the clearest example of the mismatch.

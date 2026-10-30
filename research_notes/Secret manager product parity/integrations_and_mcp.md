# Integrations and MCP ecosystem expectations for a secret manager (October 2026)

All sources accessed **2026-10-30**. Where a claim comes from a secondary source (directory, blog, vendor marketing) it is labelled as such.

Scope note: this note covers (A) platform/CI integration surface and (B) the MCP ecosystem. Product-specific competitive detail (pricing, feature matrices) is deliberately out of scope; the focus is what Vaultly should expose next and why.

---

## Which 5 integrations would deliver the most adoption for a small team?

### Takeaway
Ship five surfaces, in this order: (1) local process injection (`vaultly run -- <cmd>`, dotenv import/export), (2) GitHub Actions with OIDC fetch plus write-only secret sync, (3) Kubernetes through the External Secrets Operator provider contract, (4) a Terraform provider, (5) Cloudflare Workers/Pages (already built) then Vercel. Everything else is either served for free by (1) or is long-tail support cost with little adoption upside.

### Cited Findings
- Every mature competitor treats "run a child process with secrets injected" as the universal integration: Doppler `doppler run`, Infisical `infisical run -- <command>`, and both document it as the primary local/CI path — [Doppler CLI guide](https://docs.doppler.com/docs/cli); [Infisical agent-facing overview](https://infisical.com/).
- GitHub Actions has the most mature keyless flow: workflows can request short-lived cloud tokens via OIDC and stop storing long-lived cloud secrets — [GitHub OIDC docs](https://docs.github.com/en/actions/concepts/security/openid-connect). GitHub also encrypts secrets client-side with libsodium sealed boxes and gates environment secrets behind required reviewers — [GitHub secrets docs](https://docs.github.com/en/actions/concepts/security/secrets). GitLab has an equivalent primitive (ID tokens to Vault/GCP/Azure/AWS) but only on Premium/Ultimate — [GitLab](https://docs.gitlab.com/ci/secrets/).
- GitLab's equivalent external-secrets feature is gated to **Premium/Ultimate**, and CI/CD variables (always present in jobs) are explicitly distinguished from secrets that a job must request — [GitLab external secrets](https://docs.gitlab.com/ci/secrets/). This makes GitLab a lower-ROI target for a small team's first integration.
- Kubernetes has an established, provider-agnostic contract: External Secrets Operator defines `SecretStore`/`ExternalSecret` CRDs and reconciles external APIs into Kubernetes Secrets — [ESO overview](https://external-secrets.io/latest/introduction/overview/). The Secrets Store CSI driver mounts secrets as CSI volumes and already lists AWS, Azure, GCP, Vault and OpenBao providers — [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/).
- HashiCorp maintains a Terraform Vault provider — [terraform-provider-vault](https://github.com/hashicorp/terraform-provider-vault) — and Pulumi ships a Vault provider at v7.14.1 published 2026-10-27 — [Pulumi Vault provider](https://www.pulumi.com/registry/packages/vault/). Terraform is the de facto way platform teams standardize secret wiring.
- Cloudflare Workers secrets are encrypted bindings readable through the `env` parameter or `cloudflare:workers` — [Cloudflare Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/). Vaultly already ships Cloudflare account discovery, Pages/Workers deployment targets and `github_secret_sync` (see `AGENTS.md`), so this is incremental work rather than a new integration category.
- Doppler's own integration catalogue is broad (AWS, Azure, Bitbucket, CircleCI, Cloudflare Pages, Deno Deploy, …), which is the parity bar a buyer will compare against — [Doppler integrations index](https://docs.doppler.com/docs/integrations) (navigation only; not independently verified page-by-page).

### Inferences
- A CLI-level `run` wrapper is the highest-leverage single feature: it covers local dev, Docker entrypoints, Jenkins/Buildkite/CircleCI/Azure Pipelines (anything that can execute a binary) without building six native plugins. Native CI plugins mostly buy discoverability, not capability.
- Kubernetes adoption should go through ESO rather than a bespoke operator or CSI driver. ESO already owns the reconciliation loop, CRDs, multi-tenancy and upgrade path; Vaultly only needs to satisfy the provider interface. Building a CSI driver or operator duplicates a mature project and creates an on-call burden disproportionate to a small team.
- Terraform is worth more than Pulumi/Ansible/Helm combined for a small team because it is the shared contract platform teams use to hand infrastructure to app teams; Pulumi/Ansible can consume the same HTTP API later.
- Hosting platforms (Vercel, Netlify, Fly, Railway, Render) are all variations of "set an env var via an authenticated API". They are cheap to add one at a time, but none drives adoption on its own; Cloudflare first because the code already exists.

### Gaps
- I could not find public market-share data for CI systems (GitHub vs GitLab vs Jenkins) as of October 2026. The ordering above is a judgement based on feature maturity and switching cost, not measured install base.
- No public data on how many Vaultly-class users run Kubernetes at all; the ESO recommendation assumes a platform-team buyer exists.

---

## What is table stakes across CI/CD, infrastructure, local dev and hosting?

### Takeaway
Table stakes is "a non-interactive way to get a secret into a process or a platform, with scoping and an audit trail". Every category has a dominant mechanism: env-var/secret stores in CI, CRDs in Kubernetes, `run` wrappers locally, and per-platform env-var APIs in hosting. Native SDKs are expected in a handful of languages; everything else can be CLI.

### Cited Findings

**CI/CD**
- GitHub: org/repo/environment-scoped secrets, client-side encryption, environment approval gates, OIDC for short-lived cloud credentials — [GitHub secrets](https://docs.github.com/en/actions/concepts/security/secrets); [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).
- GitLab: external secrets from Vault, GCP Secret Manager, Azure Key Vault, AWS Secrets Manager using ID tokens; Premium/Ultimate only; jobs must explicitly request secrets — [GitLab](https://docs.gitlab.com/ci/secrets/).
- CircleCI: org-level "contexts" holding env vars, restricted by security groups, injected at runtime via the `context` key — [CircleCI contexts](https://circleci.com/docs/guides/security/contexts/).
- Jenkins: credentials provided by the Credentials Binding plugin; secret text, username/password, and other types scoped globally, per-Pipeline project/item, or per-user — [Jenkins using credentials](https://www.jenkins.io/doc/book/using/using-credentials/).
- Buildkite: several secret mechanisms (agent hooks, hosted secrets, third-party stores), plus a native encrypted key-value "Buildkite secrets" store and secrets policies for agent access control — [Buildkite secrets overview](https://buildkite.com/docs/pipelines/security/secrets).
- Azure Pipelines: secret variables encrypted at rest with a 2048-bit RSA key and exposed to the agent; recommended paths are UI, variable group, or Key Vault-linked variable group; the logging-command approach is explicitly "not recommended" — [Azure secret variables](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-secret-variables).

**Infrastructure / IaC**
- External Secrets Operator: CRD-driven sync from external APIs into Kubernetes Secrets, with `SecretStore` separating auth from `ExternalSecret` intent — [ESO](https://external-secrets.io/latest/introduction/overview/).
- Secrets Store CSI Driver: mounts multiple secrets/keys/certs into pods as a CSI volume; auto-rotation and sync-to-Kubernetes-Secret are still marked **Alpha** — [CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/).
- Vault Secrets Operator: writes Vault data directly into destination Kubernetes Secrets, with drift remediation and rotation for Deployment/ReplicaSet/StatefulSet — [VSO](https://developer.hashicorp.com/vault/docs/platform/k8s/vso).
- Terraform Vault provider exists and is maintained by HashiCorp — [repo](https://github.com/hashicorp/terraform-provider-vault); Pulumi ships a first-party Vault provider — [Pulumi](https://www.pulumi.com/registry/packages/vault/); Ansible has a `community.hashi_vault` collection — [Ansible collection](https://docs.ansible.com/ansible/latest/collections/community/hashi_vault/).
- GitOps: Flux documents SOPS- and Sealed-Secrets-based secret handling as guides rather than shipping a secret store — [Flux SOPS guide](https://fluxcd.io/flux/guides/mozilla-sops/). Argo CD's operator manual has a dedicated "Secret Management" section, including "Mitigating Risks of Secret-Injection Plugins", i.e. secret injection is treated as an external, plugin-shaped concern — [Argo CD secret management](https://argo-cd.readthedocs.io/en/stable/operator-manual/secret-management/).

**Local dev**
- Docker Compose supports file-based secrets mounted into the container instead of baked into the image or passed as build args — [Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/).
- Devcontainers' `containerEnv` sets variables on the container itself "so all processes spawned in the container will have access to it" — a direct statement of the leakage surface — [devcontainer spec](https://containers.dev/implementors/json_reference/).
- 1Password ships "Environments" that replace plaintext `.env` files with locally mounted `.env` files plus a validation hook for Cursor/Claude Code/Copilot/Windsurf — [1Password Environments](https://www.1password.dev/environments/).

**Hosting**
- Vercel distinguishes **Config** vs **Secret** env vars, where secret values are not readable after saving; build logs redact sensitive values — [Vercel](https://vercel.com/docs/environment-variables/sensitive-environment-variables).
- Netlify: shared vs site env vars, per-deploy-context values, and a "Contains secret values" flag that engages its Secrets Controller — [Netlify](https://docs.netlify.com/build/environment-variables/overview/).
- Cloudflare Workers: encrypted secret bindings exposed via `env` — [Cloudflare](https://developers.cloudflare.com/workers/configuration/secrets/).
- Fly.io: `fly secrets` stores values in an encrypted vault, injected as env vars on every Machine; "Secret values are never logged" — [Fly](https://fly.io/docs/reference/secrets/).
- Railway exposes project/service variables — [Railway](https://docs.railway.com/reference/variables). Render supports env vars, plaintext secret **files**, and environment groups shared across services — [Render](https://render.com/docs/configure-environment-variables).

**Language SDKs**
- Infisical advertises SDKs for Node.js, Python, Go, Java, .NET, Ruby, PHP, Rust and C++ — [Infisical](https://infisical.com/).
- 1Password's official SDKs are Go, JavaScript and Python only — [1Password SDKs](https://developer.1password.com/docs/sdks/). This is the strongest available signal that a three-language SDK surface is acceptable for a developer-secrets product.
- Vault exposes its functionality through an HTTP API and documents a "Client Libraries" page for language bindings, rather than requiring every consumer to use a HashiCorp-authored SDK — [Vault libraries](https://developer.hashicorp.com/vault/api-docs/libraries).
- Doppler's docs list SDKs for Node.js, Python, Ruby and C#, with "Other Languages" handled by the CLI — [Doppler docs nav](https://docs.doppler.com/docs/integrations).

### Inferences
- The minimal SDK surface that is defensible in 2026 is: **TypeScript/Node, Python, Go** — enough to cover app code, scripts/notebooks and infrastructure tooling. Rust is optional (mostly for the CLI itself and edge runtimes); Java/.NET/Ruby/PHP can be served by the CLI/HTTP API until a customer asks.
- The minimal SDK *API* is not "get secret by name". It is: `fetch(name, {project, environment, path})`, `list()` returning names+metadata only, and `injectIntoProcess()`. Value-returning calls should be opt-in and audited separately from metadata calls.
- Do not build Helm charts, Ansible modules or Argo plugins in the first wave. All three ecosystems already consume Kubernetes Secrets or env vars; ESO + a CLI covers them.

### Gaps
- Railway's and Render's exact secret semantics (sealed vs plaintext, preview scoping) were not fully extractable from their JS-rendered docs; the claims above are limited to what the pages state.
- No primary source found for "process supervisors" (systemd, supervisord, PM2) secret handling. PM2 appears in Doppler's framework list but the mechanism was not verified.
- I could not verify whether Netlify's "Secrets Controller" prevents value read-back via API, only that the flag exists.

---

## Which integrations can be built without a hosted service?

### Takeaway
Anything **push-based or local** can ship with zero server: `run`/dotenv, git hooks and pre-commit scanning, MCP over stdio, generating Compose/Kubernetes manifests, and pushing values into GitHub/Vercel/Netlify/Cloudflare/Fly via the user's own CLI login. Anything **pull-based at runtime** (ESO, CSI, remote MCP, Terraform provider) needs a reachable, authenticated, highly-available endpoint.

### Cited Findings
- Vaultly's existing `github_secret_sync` is explicitly value-blind and uses the human's `gh` login to copy one vault credential into a GitHub Actions repository secret, never returning or logging the value — `AGENTS.md` in this repository.
- Doppler's MCP server is configured by wrapping it in `doppler run`, i.e. the secret is injected into the MCP server process locally rather than fetched from a Doppler-hosted broker — [Doppler MCP](https://docs.doppler.com/docs/mcp).
- 1Password's Environments MCP server runs **locally as part of the desktop app** and requires per-Environment approval prompts in the app — [1Password MCP server](https://developer.1password.com/docs/environments/mcp-server).
- ESO and the CSI driver are controllers/drivers that must reach the external API continuously to reconcile — [ESO](https://external-secrets.io/latest/introduction/overview/); [CSI](https://secrets-store-csi-driver.sigs.k8s.io/).
- Terraform providers execute in whatever environment Terraform runs (often a remote CI runner), so a provider implies a network-reachable API — [terraform-provider-vault](https://github.com/hashicorp/terraform-provider-vault).

### Inferences
- A credible "no server" v1 is: `vaultly run`, `vaultly env --format dotenv|json|compose`, `vaultly sync github|vercel|netlify|cloudflare|fly`, a `pre-commit` secret scanner, and an MCP stdio server. That set covers local dev, most CI (via `run`), and hosting env-var sync — without uptime obligations.
- ESO support without a server is possible only in "generate manifests" mode (`vaultly k8s secret --dry-run | kubectl apply`), which is a CI job, not a controller. That is a legitimate interim feature but should not be marketed as ESO support.
- The MCP server should be local-first precisely because it avoids hosting: the client launches it over stdio, the vault unlocks from the OS keychain, and no credential ever crosses a network boundary.

### Gaps
- No source establishes whether GitHub Actions can reach an on-prem/self-hosted vault through a runner-local agent without a hosted relay; this is an architecture question for Vaultly, not a documented vendor pattern.

---

## What should be explicitly out of scope until there is a server/team offering?

### Takeaway
Out of scope now: Kubernetes operator/CSI driver, remote (Streamable HTTP) MCP with OAuth, dynamic/short-lived database credentials, SSO/SCIM/RBAC admin, a Terraform *provider* (as opposed to a thin data source), and native plugins for Jenkins/Buildkite/Azure Pipelines/GitLab. Each implies 24/7 uptime, multi-tenant isolation, or a support contract that a small team cannot carry.

### Cited Findings
- The Secrets Store CSI driver's rotation and secret-sync features are still **Alpha**, and the project commits to a monthly patch cadence and support for only the latest two minor versions — i.e. operating it is ongoing work, not a one-off — [CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/).
- HashiCorp labels its Vault MCP server **Beta** and warns it "may expose certain Vault data, including Vault secrets, to MCP clients and LLMs" and should not be used with untrusted clients — [Vault MCP](https://developer.hashicorp.com/vault/docs/mcp-server/overview).
- The MCP authorization spec requires OAuth 2.1, protected-resource metadata (RFC 9728), resource indicators (RFC 8707) and issuer validation (RFC 9207) for HTTP transports — a non-trivial auth server surface — [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
- MCP's own security guidance treats token passthrough, audience-validation failures and scope minimization as first-order risks of remote servers — [MCP security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices).
- GitLab's external secrets require Premium/Ultimate — [GitLab](https://docs.gitlab.com/ci/secrets/) — so a free-tier integration would reach a minority of that vendor's users.

### Inferences
- A hosted control plane is the actual product boundary. Until it exists, "integrations" should be client-side adapters that never require Vaultly-operated infrastructure.
- A Terraform *data source* that reads from a local encrypted file or from `vaultly` CLI output is acceptable; a full provider with CRUD, import, drift detection and a stable API contract is a server-team deliverable.
- Remote MCP is the most tempting trap: it looks like a small addition but drags in OAuth authorization-server duties, multi-tenant token isolation, rate limiting, and an incident-response story. 1Password's decision to ship a **local** MCP server inside the desktop app is the strongest precedent for deferring it — [1Password](https://developer.1password.com/docs/environments/mcp-server).

### Gaps
- No public source quantifies the support cost of maintaining a Terraform provider or a CSI driver; the above is an inference from their release/compatibility policies.

---

## What does the MCP specification require in late 2026, and what is experimental?

### Takeaway
The current revision is **2026-07-28**. It is stateless: no `initialize` handshake, no `Mcp-Session-Id`, every request carries protocol version and capabilities in `_meta`, and `server/discover` is mandatory. Tools/resources/prompts and elicitation are core; sampling, roots and logging are **deprecated**; Tasks, MCP Apps and Skills-over-MCP are **extensions**.

### Cited Findings
- The latest spec is the 2026-07-28 revision (schema path `2026-07-28`) — [Specification](https://modelcontextprotocol.io/specification/latest).
- 2026-07-28 removed protocol-level sessions and the `Mcp-Session-Id` header, removed the `initialize`/`notifications/initialized` handshake, and moved protocol version + client capabilities into per-request `_meta` — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog).
- `server/discover` must be implemented by servers; clients may skip it and call any RPC inline — [Discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).
- Server-initiated requests no longer exist; sampling/elicitation/roots are embedded in results as **Multi Round-Trip Requests**, and long-lived notifications use `subscriptions/listen` — [Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).
- Roots, Sampling and Logging are deprecated as of 2026-07-28, with earliest removal in the first revision released on or after **2027-07-28**; migration paths are tool parameters/resource URIs for roots, direct LLM-provider APIs for sampling, and stderr/OpenTelemetry for logging — [Deprecated features](https://modelcontextprotocol.io/specification/2026-07-28/deprecated).
- Dynamic Client Registration is also listed as deprecated in 2026-07-28, with Client ID Metadata Documents as the migration path — [Deprecated features](https://modelcontextprotocol.io/specification/2026-07-28/deprecated).
- Extensions have an explicit lifecycle (Experimental → Beta → Stable) and are opt-in, negotiated at initialization; official extensions include **Tasks**, **MCP Apps** and **Skills over MCP** — [Extensions overview](https://modelcontextprotocol.io/extensions/overview).
- Tools are model-controlled, but the spec says there **SHOULD** always be a human in the loop able to deny invocations, and tool annotations must be treated as untrusted unless the server is trusted — [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).
- Elicitation has two modes; servers **MUST NOT** use form mode to request passwords, API keys, access tokens or payment credentials, and **MUST** use URL mode instead — [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation).
- Structured tool output was added in the 2025-06-18 revision and remains part of the tools surface — [2025-06-18 changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog).
- 2026-07-28 added full JSON Schema 2020-12 for tools, deterministic `tools/list` ordering, and required `ttlMs`/`cacheScope` on list/read results for caching — [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog).
- Authorization is OPTIONAL; HTTP transports SHOULD conform to OAuth 2.1 (draft 13) + RFC 6750/8414/8707/9728/9207 + Client ID Metadata Documents, while **stdio servers SHOULD NOT** implement it and should take credentials from the environment — [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
- SDK v2 implementations serve both eras: the Python SDK's `streamable_http_app()` and stdio server answer a 2025-era `initialize` and a 2026-era request without configuration — [Python SDK v2](https://py.sdk.modelcontextprotocol.io/v2/whats-new/); the C# SDK v2 implements 2026-07-28 — [.NET blog](https://devblogs.microsoft.com/dotnet/announcing-v20-of-the-official-mcp-csharp-sdk/).

### Inferences
- For a secret manager, the correct MCP shape in late 2026 is: **stdio first**, tools + resources only, no sampling, no roots, no reliance on `initialize`. A dual-era server (accept legacy handshake *and* modern `_meta`) is required in practice because installed clients lag the spec.
- "Ask the user for the API key via elicitation" is now explicitly non-compliant. Secret entry must be URL-mode redirect to a trusted UI, or out-of-band via the CLI/desktop app.
- Tasks are attractive for long-running rotation/backup operations, but should be treated as experimental until Tier-1 SDK support lands broadly (the Python SDK v2 does not implement the Tasks extension yet — [Python SDK v2](https://py.sdk.modelcontextprotocol.io/v2/whats-new/)).

### Gaps
- I could not verify which of Claude Desktop, Cursor, VS Code, Windsurf and Zed currently speak 2026-07-28 versus 2025-11-25. Client version support is the single biggest unknown for server design; assume legacy support is still required.
- No source confirms whether any major client implements URL-mode elicitation yet.

---

## What do security-conscious MCP servers do, and who are the notable ones?

### Takeaway
The best-regarded secret-manager MCP servers converge on four behaviours: **never return the value** (1Password), **read-only/tool allowlists by default** (Doppler, Infisical), **per-scope human approval** (1Password, Vaultly's `run` policy), and **audit every access** (Doppler, Vault, AWS). Servers that do return values say so loudly and tell you not to use them with untrusted clients (HashiCorp Vault).

### Cited Findings
- **1Password Environments MCP Server**: runs locally inside the 1Password desktop app, shows a secure authorization prompt per Environment, and "does not return secret values" — [1Password docs](https://developer.1password.com/docs/environments/mcp-server); [1Password blog](https://1password.com/blog/1password-trusted-access-layer-for-openai-codex). Enterprise admins can disable it org-wide via **Policies → Agentic permissions → Local MCP server** — [1Password docs](https://developer.1password.com/docs/environments/mcp-server).
- **Doppler MCP Server**: labelled **experimental**; exposes list projects/configs/secrets, read secret values, create/update secrets, manage environments, view activity logs; offers a `--read-only` flag that hides write tools, while warning that token scoping is the real control — [Doppler MCP](https://docs.doppler.com/docs/mcp).
- **Infisical MCP Server**: official `npx -y @infisical/mcp`, authenticates as a machine identity (`universal-auth` or `access-token`), and documents optional env vars that restrict which tools are exposed and whether secret values are returned — [Infisical MCP repo](https://github.com/Infisical/infisical-mcp-server).
- **HashiCorp Vault MCP Server**: **Beta**; stdio + Streamable HTTP; read/write/list secrets and mounts, plus PKI operations; the docs warn it "may expose certain Vault data, including Vault secrets, to MCP clients and LLMs" and that HTTP mode is "intended for local use only" — [Vault MCP overview](https://developer.hashicorp.com/vault/docs/mcp-server/overview); [changelog](https://github.com/hashicorp/vault-mcp-server/blob/main/CHANGELOG.md). Version 0.2.0 added a middleware stack including **rate limiting** and structured logging — [changelog](https://github.com/hashicorp/vault-mcp-server/blob/main/CHANGELOG.md).
- **AWS MCP Server**: generally available 2026-05-06 as a managed remote server; authenticates with IAM/SigV4 or OAuth 2.1, exposes a small fixed tool set, and logs API calls to CloudTrail with CloudWatch metrics — [AWS News Blog](https://aws.amazon.com/blogs/aws/the-aws-mcp-server-is-now-generally-available); [AWS docs](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/mcp-server.md).
- **CyberArk Secrets Manager MCP**: reads and updates Secrets Manager data; setup explicitly requires a dedicated user account "to maintain an audit trail and limit the MCP server's permissions" — [CyberArk docs](https://docs.cyberark.com/secrets-manager-saas/latest/en/content/conjurcloud/cc-mcp-server.htm).
- Guidance from vendors: Doppler recommends dynamically limiting `list_tools` to the authenticated user's permissions (don't expose `delete_repository` to a read-only user), runtime secret injection instead of `.env`, redacting secrets from logs, and rate-limiting at the MCP proxy layer — [Doppler blog](https://www.doppler.com/blog/secure-mcp-servers-secrets-architecture); [Doppler credential best practices](https://www.doppler.com/blog/mcp-server-credential-security-best-practices).

### Inferences
- "Value-blind" is the strongest differentiator available in this category and the hardest for competitors to retrofit: 1Password built its MCP server around not returning values, while Doppler, Infisical and Vault all expose read tools by default (with opt-outs). Vaultly's contract already forbids returning credentials, so it can own this position.
- The practical tool set for a value-blind server is: `list` (names + metadata), `describe` (scopes, rotation, expiry), `request_injection` (returns a handle/session, not a value), `rotate`, `audit`, `diff`/`drift`. Write operations should require a typed confirmation, mirroring Vaultly's `APPLY`/`BACKUP`/`PURGE` pattern.
- Rate limiting and audit are table stakes for anything that can be invoked in a loop by an agent; Vault's middleware and AWS's CloudTrail/CloudWatch are the reference implementations.

### Gaps
- No independent security audit of any of these MCP servers was found. The claims above are vendor self-descriptions.
- It is unclear whether 1Password's "does not return secret values" holds for all tools (e.g. `.env` file listing) or only for the Environment-variable tools.

---

## How do clients discover and install MCP servers — is there a registry or `mcp install` standard?

### Takeaway
There is a **registry**, but no single install standard. The official MCP Registry is metadata-only and still in preview; hosts are explicitly told not to consume it directly but to use downstream marketplaces. In practice each client has its own config file and its own install verb (`claude mcp add`, Cursor's `mcp.json` + Marketplace, VS Code's `@mcp` gallery + `.vscode/mcp.json`, one-click `vscode.dev/redirect/mcp/install` links). Server Cards (`.well-known/mcp/server-card.json`) are the emerging discovery layer but remain a draft.

### Cited Findings
- The official MCP Registry is a centralized metadata repository (Anthropic, GitHub, PulseMCP, Microsoft as contributors), stores `server.json` metadata pointing at npm/PyPI/OCI packages or remote URLs, and uses DNS/GitHub namespace verification — [MCP Registry about](https://modelcontextprotocol.io/registry/about).
- The registry is **still in preview**: "Breaking changes or data resets may occur before general availability" — [Registry quickstart](https://modelcontextprotocol.io/registry/quickstart).
- The registry is "not intended to be directly consumed by host applications"; hosts should consume downstream marketplaces via a REST API conforming to the official OpenAPI spec — [MCP Registry about](https://modelcontextprotocol.io/registry/about).
- Publishing uses the `mcp-publisher` CLI: `mcp-publisher init` generates `server.json`, `mcp-publisher login github` (or DNS/HTTP), then `mcp-publisher publish` — [Registry quickstart](https://modelcontextprotocol.io/registry/quickstart); [authentication](https://modelcontextprotocol.io/registry/authentication).
- Size signal (secondary): ~30,375 servers / 99,114 version records as of 2026-09-10, growing ~6,000/month, with the caveat that "official" means the MCP project runs it, not that anything is vetted — [devtoolhub analysis](https://devtoolhub.com/mcp-registry-by-the-numbers). Treat as directional only.
- Claude Desktop uses `claude_desktop_config.json` with an `mcpServers` object — [MCP quickstart](https://modelcontextprotocol.io/quickstart/user).
- Claude Code uses `claude mcp add --transport http <name> <url>` and a project `.mcp.json` — [Infisical docs](https://infisical.com/docs/ai/model-context-protocol); [Agent Package Manager docs](https://microsoft.github.io/apm/guides/mcp-servers/).
- Cursor installs/manages servers from the Customize page or `mcp.json`, and has a Marketplace (1Password's Environments server listed there since 2026-07-30) — [Cursor MCP docs](https://cursor.com/docs/context/mcp); [1Password blog](https://1password.com/blog/the-1password-environments-mcp-server-is-now-on-cursor-marketplace).
- VS Code has an MCP server gallery (`@mcp` in the Extensions view), a Customization Marketplace browse flow, and `.vscode/mcp.json` with a `servers` object; it also supports enterprise registry enforcement (Azure API Center), where only approved servers can be installed — [VS Code MCP docs](https://code.visualstudio.com/docs/agent-customization/mcp-servers.md); [Microsoft Azure blog](https://devblogs.microsoft.com/all-things-azure/locking-down-mcp-create-a-private-registry-on-azure-api-center-and-enforce-it-in-github-copilot-and-vs-code).
- One-click install links are already a de facto pattern: GitHub and AWS publish `https://insiders.vscode.dev/redirect/mcp/install?name=...&config=...` URLs — [github-mcp-server](https://github.com/github/github-mcp-server); [awslabs/mcp](https://github.com/awslabs/mcp).
- Package-manager-style installs exist but are fragmented: Microsoft's APM does `apm install --mcp io.github.github/github-mcp-server` (requires a unique registry match) and aliases `apm mcp install` — [APM docs](https://microsoft.github.io/apm/guides/mcp-servers/); third-party `mcpm`/`mcp-fleet` writes configs for Claude Code, Cursor, VS Code, Windsurf, Zed and others — [mcpm](https://github.com/AZERDSQ131/mcpm) (secondary).
- Server Cards: SEP-2127 is still an open/draft proposal developing as an experimental extension; the `.well-known` path is not settled (SEP-2127 draft reserves `<mcp-endpoint>/server-card`, while deployed cards commonly use `/.well-known/mcp/server-card.json`) — [Server Card WG](https://modelcontextprotocol.io/community/working-groups/server-card); [turva.dev analysis](https://turva.dev/guides/mcp-server-card). Infisical already publishes one at `https://infisical.com/.well-known/mcp/server-card.json` — [Infisical](https://infisical.com/).

### Inferences
- Publishing to the official registry is now table stakes for discoverability but delivers little install UX on its own. The higher-yield moves are: a one-click VS Code install URL, a Cursor Marketplace listing, and a copy-paste `mcpServers` block that works unmodified in Claude Desktop and Claude Code.
- A single `mcp install` verb is *not* standard. The closest thing is per-client commands plus registry-backed package managers (APM, mcpm). Vaultly should ship `vaultly mcp install --client claude|cursor|vscode|windsurf|zed` that writes the correct file per client — that is a real convenience gap in the market.
- Serving a Server Card now is cheap and signals maturity, but it must be treated as experimental: publish at both the SEP-2127 path and `/.well-known/mcp/server-card.json`, and keep the fields conservative (`name`, `title`, `description`, `version`, `websiteUrl`, `repository`, `remotes`, `supportedProtocolVersions`).

### Gaps
- No primary documentation was found for Windsurf's or Zed's current MCP config paths; the paths above come from a third-party installer README and should be verified before shipping.
- It is unclear whether any host currently performs automatic Server Card discovery; the working group charter lists it as in-progress.
- The registry's true active-server count is disputed (official registry vs Glama's 111k+ claim, which includes mirrored/aggregated listings) — [Glama](https://glama.ai/) (vendor marketing).

---

## What are the security failure modes of each integration?

### Takeaway
Every integration is a different way to move a plaintext value across a boundary that logs, caches, or inherits it. The recurring failures are: env vars inherited by every child process, values captured in CI logs/artifacts, values persisted in Terraform state or Docker layers, over-broad tokens, and — for MCP specifically — tool poisoning and prompt injection turning the agent into an exfiltration path.

### Cited Findings
- **Env inheritance**: devcontainer `containerEnv` is set on the container itself "so all processes spawned in the container will have access to it" — [devcontainer spec](https://containers.dev/implementors/json_reference/). Any agent, build step or compromised dependency in that container can read it.
- **CI log leakage**: GitHub encrypts secrets client-side specifically to "minimize the risks related to accidental logging (for example, exception logs and request logs)" — i.e. logging is a known exfiltration channel — [GitHub secrets](https://docs.github.com/en/actions/concepts/security/secrets). Azure Pipelines explicitly discourages setting secrets via logging commands because "anyone who can access your pipeline can also see the secret" — [Azure](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/set-secret-variables).
- **Shell/command-string expansion**: Doppler's own docs warn that when a secret is referenced inside a command string you must single-quote or escape it "to guard against shell parsing the variable before the run command executes" — [Doppler CLI](https://docs.doppler.com/docs/cli). The same mechanism causes secrets to appear in shell history and process arguments.
- **Kubernetes**: ESO's job is to write external values into Kubernetes Secrets — [ESO](https://external-secrets.io/latest/introduction/overview/) — so the cluster's etcd encryption, RBAC and Secret read audit become part of the trust boundary. The CSI driver's rotation/sync features are Alpha, so stale mounted values are a real failure mode — [CSI](https://secrets-store-csi-driver.sigs.k8s.io/).
- **Terraform**: providers and state are the boundary; a Vault provider necessarily handles credentials and writes resource attributes into state — [terraform-provider-vault](https://github.com/hashicorp/terraform-provider-vault). (State-plaintext is well-known but not stated on that page — flagged as inference.)
- **Docker**: Compose secrets exist specifically to avoid baking values into images or passing them as build args — [Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/).
- **Hosting**: Vercel had to add build-log redaction for sensitive env vars, and distinguishes Secret vars that cannot be read back — [Vercel](https://vercel.com/docs/environment-variables/sensitive-environment-variables). Fly states secret values "are never logged" — [Fly](https://fly.io/docs/reference/secrets/).
- **MCP — tool poisoning / rug pull**: malicious instructions can be embedded in tool descriptions and acted on by the model; a server approved earlier can later change its tool definitions ("rug pull") — [Microsoft security blog](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp); [MCPTox benchmark](https://arxiv.org/pdf/2508.14925).
- **MCP — config as code execution**: the Cloud Security Alliance notes that an MCP config change is effectively a change to which executables the dev environment runs, and cites a case where a prompt-injection payload rewrote `~/.cursor/mcp.json` to add a server — [CSA research note, 2026-07-01](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-auto-execution-20260701/).
- **MCP — token passthrough / audience confusion**: servers must not accept tokens issued for other resources and pass them downstream; scope minimization is called out as a primary control — [MCP security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices).
- **MCP — local server compromise**: locally installed servers have direct access to the user's machine and may be reachable by other local processes (DNS rebinding against localhost) — [MCP security best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices).
- **MCP — elicitation misuse**: form-mode elicitation must not be used for passwords/API keys/tokens; URL mode is required — [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation).
- **MCP — model-context leakage**: Vault's own docs concede the server "may expose certain Vault data, including Vault secrets, to MCP clients and LLMs" — [Vault MCP](https://developer.hashicorp.com/vault/docs/mcp-server/overview).

### Inferences
- Ranked by likelihood × impact for a Vaultly-class product: (1) value lands in model context via a read tool; (2) value lands in CI logs/artifacts; (3) value inherited by an untrusted child process; (4) over-broad token allows lateral access; (5) tool poisoning causes an agent to exfiltrate to an attacker-controlled destination.
- Concrete mitigations that follow directly: never return values over MCP; inject only into a named child process with a scrubbed environment; redact stdout/stderr by default and require an explicit `--no-redact`; scope every token to one project/environment; make destructive tools require a typed confirmation; log tool name + target + outcome, never arguments that could contain values.
- CI artifacts and caches deserve a first-class warning in docs: a workflow that runs `vaultly env > .env` and then uploads the workspace has defeated the entire product. Prefer `run` + no file, and fail the build if a `.env` is created in CI.

### Gaps
- No primary source was found quantifying how often secrets leak via CI artifacts vs logs; the ranking is a judgement.
- Process-argument visibility (`ps`, `/proc/<pid>/cmdline`) is a well-known Unix property but I did not find a secret-manager vendor doc that states it explicitly; treat as inference.
- Windsurf and Zed were not verified as MCP clients in this pass.

---

## What should Vaultly expose next, in order?

### Takeaway
Ship the universal local layer and the push-based GitHub path now; defer every pull-based runtime integration until there is a served control plane. Value-blindness is the one differentiator that is both cheap for Vaultly and expensive for incumbents to copy.

### Cited Findings
- A CLI `run` wrapper is the common denominator across Doppler, Infisical and Vaultly (`vaultly run`, `doppler run`, `infisical run`), and it requires no per-CI plugin — [Doppler CLI](https://docs.doppler.com/docs/cli); [Infisical](https://infisical.com/).
- Write-only GitHub secret sync already exists in this repository's `AGENTS.md` (`github_secret_sync`), is value-blind, and uses the human's `gh` login rather than a Vaultly-hosted token.
- ESO already owns the Kubernetes reconciliation contract across many providers — [ESO](https://external-secrets.io/latest/introduction/overview/) — while the CSI driver's rotation features remain Alpha — [CSI](https://secrets-store-csi-driver.sigs.k8s.io/).
- 1Password's MCP server is the only major secret-manager server documented as not returning secret values, and it runs locally inside the desktop app — [1Password](https://developer.1password.com/docs/environments/mcp-server).
- The MCP spec forbids form-mode elicitation for API keys/tokens and requires URL mode — [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) — which removes the easiest "just ask the user for the token" shortcut from any agent-facing flow.
- Install UX is fragmented across `claude mcp add`, Cursor's `mcp.json`/Marketplace, VS Code's `@mcp` gallery and one-click `vscode.dev/redirect/mcp/install` links — [VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers.md); [Cursor](https://cursor.com/docs/context/mcp); [Claude Code/Infisical](https://infisical.com/docs/ai/model-context-protocol).

### Inferences
1. **Build the boring universal layer first**: `run`, dotenv import/export, and a stdio MCP server. It covers local dev, most CI, and every agent client with no hosting.
2. **Win GitHub Actions with two modes**: OIDC-verified pull (needs a server) and write-only push via `gh` (works today). Ship the push mode now.
3. **Adopt ESO rather than build an operator.** It keeps Vaultly out of the controller business and out of a monthly patch cadence.
4. **Terraform provider is the platform-team wedge**, but it is a server-team deliverable; until then a data source or CLI-generated tfvars is enough.
5. **Make value-blindness the brand.** Every tool that could return a value should return a handle instead; 1Password is the only major vendor doing this and Vaultly's contract already requires it.
6. **Do not build remote MCP yet.** Local stdio + URL-mode consent + OS keychain unlock covers the use case without OAuth-server, multi-tenancy or uptime obligations.
7. **Ship install ergonomics**: `vaultly mcp install --client …`, a one-click VS Code install URL, a Cursor Marketplace listing, and a Server Card at both well-known paths. Discovery is unsettled, which is exactly where a small team can still stand out.

### Gaps
- The ordering assumes Vaultly remains local-first through 2026. If a hosted control plane lands sooner, ESO and Terraform move up and the GitHub push mode becomes a fallback rather than the primary path.
- No usage data exists to confirm that `run` beats native CI plugins on adoption; the argument rests on implementation cost and portability, not measurement.

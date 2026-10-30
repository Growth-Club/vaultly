# Cloud Secret Managers: Capability Parity for a CLI + MCP Credential Manager

Scope: first-party cloud secret stores — AWS Secrets Manager, Google Cloud Secret Manager, Azure Key Vault (secrets) and Managed HSM, OCI Vault / Secret Management, Alibaba Cloud KMS Secrets Manager, Cloudflare Secrets Store, IBM Cloud Secrets Manager — plus the third-party ecosystem that fills their gaps. All sources were fetched on **2026-10-30**; "Last updated" dates are quoted where the vendor publishes them. Statements labelled *documented* come from vendor reference docs or quotas pages; *marketing* claims are flagged. Inferences are separated from findings.

## Data model: how are secrets, versions, stages, replication, and recovery represented?

### Takeaway

Every hyperscaler converges on the same shape — an immutable, numbered secret version plus a mutable pointer to "current" — but they disagree on how many pointers exist, whether old versions survive, and whether the pointer is a label or a boolean. Cloudflare is the outlier: one value per secret, no versions, no read-back.

### Cited Findings

- A secret is a value plus metadata; its ARN is `arn:aws:secretsmanager:<Region>:<AccountId>:secret:<Name>-<6 random chars>`, and the value can be a string or binary, with JSON key/value recommended for structured credentials — [AWS: What's in a secret](https://docs.aws.amazon.com/secretsmanager/latest/userguide/whats-in-a-secret.html).
- AWS versions are not a linear history. Three staging labels exist — `AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING` — and up to 20 staging labels can be attached per secret. A version with no label is deprecated and removed once a secret exceeds 100 versions, but AWS never removes a version less than 24 hours old — [AWS: Secret versions](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_versions.html).
- AWS supports multi-Region replication: a replica secret is created in another Region and `AWSCURRENT` is promoted there; replicas must be deleted before the primary can be deleted — [AWS: Replicate secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/replicate-secrets.html).
- AWS deletion is a two-phase operation: the minimum recovery window is 7 days, `--force-delete-without-recovery` skips it, and individual versions cannot be deleted — you remove their staging labels instead — [AWS: Delete a secret](https://docs.aws.amazon.com/secretsmanager/latest/userguide/deleting-secrets.html).
- A Google Cloud secret is a global container of versions plus metadata; versions carry a unique ID and can be addressed by alias. Replication is either automatic (Google picks regions, billed as one location) or user-managed (billed per location) — [GCP: Secret Manager overview](https://cloud.google.com/secret-manager/docs/overview).
- GCP also offers regional secrets as a distinct resource for data-residency requirements — [GCP: Regional secrets](https://cloud.google.com/secret-manager/docs/regional-secrets-overview).
- GCP delayed destruction is configurable from 1 to 1,000 days: the version is disabled first, then permanently destroyed, and a `SECRET_VERSION_DESTROY_SCHEDULED` Pub/Sub event fires when destruction is scheduled — [GCP: Secret Manager overview](https://cloud.google.com/secret-manager/docs/overview).
- Azure stores a secret as an octet sequence of **at most 25 KB**, with an optional `contentType` of at most 255 characters and up to 15 tags (512-character name/value) — [Azure: About secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets).
- Azure secret attributes are `exp`, `nbf`, and `enabled`; notably, a `get` succeeds outside the `nbf`/`exp` window — the caller must enforce the window — [Azure: About secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets).
- Azure soft delete retains secrets and vaults for 7–90 days (default 90), is enabled by default on new vaults and cannot be disabled; purge protection is optional and **not** on by default. A soft-deleted vault's name is unusable until retention expires — [Azure: Soft-delete overview](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview).
- OCI models a secret as a container whose contents are versioned; version numbers start at 1 and increment by 1, and a version carries a rotation state (for example `current`). A secret can have **30 active versions and 30 versions pending deletion** — [OCI: Secret versions](https://docs.oracle.com/en-us/iaas/Content/secret-management/Concepts/secret-versions.htm).
- OCI supports cross-Region secret replication, copying secret versions and metadata to replica regions, with rotation always performed in the primary region — [OCI: Replicate a secret](https://docs.oracle.com/en-us/iaas/Content/secret-management/Concepts/secret-replication.htm).
- Alibaba mirrors the AWS label model almost exactly: `ACSCurrent`, `ACSPrevious`, `ACSPending`, plus custom stage labels for generic secrets only, with a hard cap of **eight** built-in plus custom labels per secret. The oldest unlabeled version is auto-deleted when the version limit is exceeded — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cloudflare Secrets Store is an account-level store with **one store per account** and **100 production secrets per account**; a secret is a string of at most 65,536 bytes with no versioning — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/) (page last updated 2026-10-22).
- Once added, a Cloudflare secret "can no longer be decrypted or accessed via API or on the dashboard. Only the service associated with a given secret will be able to access it" — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/).
- IBM Cloud Secrets Manager is built on HashiCorp Vault as a dedicated single-tenant instance; it organizes secrets into secret groups, supports labels and expiration, and offers IAM-credential and arbitrary-secret types — [IBM: Getting started](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-getting-started).

### Inferences

- A portable abstraction needs four concepts, not two: `secret` (identity + metadata), `version` (immutable value), `pointer` (mutable "current"), and `label` (zero or more named pointers). AWS and Alibaba expose all four; GCP exposes pointer + aliases; Azure exposes a version list plus an `enabled` flag; Cloudflare exposes only the first.
- Cloudflare proves a versionless store is shippable for the Workers use case, but it removes rollback, diffing, and "which value was live at incident time" forensics. A credential manager targeting agents should not copy that constraint.
- Azure's `get`-works-outside-validity behavior is a real interoperability trap: any CLI that assumes expiry blocks retrieval will diverge from the platform.

### Gaps

- Azure does not document whether secret version identifiers are strictly monotonic or time-sortable; the docs describe them only as version identifiers.
- Alibaba documents the 8-label cap but not the total version cap per secret.
- Cloudflare publishes no roadmap for versioning, staging labels, or soft delete; absence in docs is not proof of absence on the roadmap.
- IBM Cloud Secrets Manager version limits and rotation semantics were not verified in depth; the page reviewed describes features, not quotas.
- Huawei Cloud CSMS and Tencent Cloud SSM are also first-party secret stores but were not reviewed; coverage is limited to the seven stores named in the scope line.

## Encryption: KMS, envelope encryption, HSM/FIPS, and key rotation

### Takeaway

Envelope encryption with a cloud KMS is universal, but "HSM-backed" means different things. On Azure and OCI the HSM protects the *key*, not the secret ciphertext — secrets remain software objects encrypted by that key. FIPS assurance also differs: OCI documents FIPS 140-2 Level 3, Azure documents FIPS 140-3 Level 3.

### Cited Findings

- AWS uses envelope encryption: Secrets Manager asks KMS for a 256-bit AES data key via `GenerateDataKey`, encrypts the secret value locally, and stores the encrypted data key with the secret. Only symmetric KMS keys are supported, and the default key is `aws/secretsmanager` — [AWS: Encryption at rest](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html).
- AWS binds ciphertext to the secret using encryption context `SecretARN` + `SecretVersionId`. Changing the KMS key re-encrypts `AWSCURRENT`, `AWSPENDING`, and `AWSPREVIOUS` but keeps copies encrypted under the old key. The secret name, description, tags, and rotation settings are **not** encrypted — [AWS: Encryption at rest](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html).
- GCP encrypts secret payloads with AES-256 at rest by default and supports CMEK through Cloud KMS. A CMEK key must be in the same location as the replica; automatic replication requires a `global` multi-Region key — [GCP: CMEK](https://cloud.google.com/secret-manager/docs/cmek).
- GCP's CMEK integration uses the key's `primary` version rather than pinning a version, and rotating the KMS key only affects **new** secret versions — existing versions are not re-encrypted — [GCP: CMEK](https://cloud.google.com/secret-manager/docs/cmek).
- Azure Key Vault has two tiers: Standard (software-protected) and Premium (HSM-protected keys). Premium uses FIPS 140-3 Level 3 validated HSMs (Marvell LiquidSecurity) — [Azure: Key Vault security features](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features).
- Azure Managed HSM is a key-only service: Microsoft's Managed HSM overview describes safeguarding cryptographic **keys** with FIPS 140-3 Level 3 HSMs, while secrets and certificates remain Key Vault objects rather than Managed HSM objects — [Azure: Managed HSM overview](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview); [Azure: About secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets).
- OCI stores keys in HSMs certified **FIPS 140-2 Level 3**, and for secrets: "secret versions are base64-encoded and encrypted by a master encryption key, but are not stored within the HSM" — [OCI: Vaults and key management](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm).
- OCI offers four isolation models: shared vaults, virtual private vaults (an isolated HSM partition, including 1,000 key versions by default), Dedicated KMS (three auto-synchronized HSM partitions), and External KMS/HYOK where master keys live outside OCI — [OCI: Vaults and key management](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm).
- Alibaba encrypts the secret value with a symmetric key that must belong to the same KMS instance; the key encrypts the value only, **not** the secret metadata. Transport is TLS 1.2 — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cloudflare states secrets are "securely encrypted and stored across all Cloudflare data centers" but does not publish the algorithm, key hierarchy, or HSM/FIPS posture for Secrets Store — [Cloudflare: Secrets Store](https://developers.cloudflare.com/secrets-store/).

### Inferences

- The AWS pattern (per-secret DEK, KMS-wrapped, encryption context binding ciphertext to secret+version) is the most portable design for a CLI + MCP manager: it lets the store rotate the wrapping key without rewriting every version, and it makes swap attacks detectable.
- "HSM tier" is a common buyer trap. Azure Premium and OCI virtual private vaults do not put secret payloads inside the HSM; if the requirement is "secret material never leaves an HSM," only a key-only design or client-side encryption satisfies it.
- Metadata being unencrypted is a shared design choice (AWS, Alibaba). A credential manager should still treat names as sensitive, because names leak target systems (`prod/stripe/live-key`).

### Gaps

- Cloudflare publishes no cryptographic design for Secrets Store; the "encrypted across all data centers" statement is marketing-level.
- Azure's FIPS level for the **Standard** tier is not stated consistently across pages; the reviewed page distinguishes only software vs HSM-backed keys.
- Whether AWS re-encrypts *all* historical versions on CMK rotation or only the three labeled ones is documented for the three labels; behavior for unlabeled versions was not verified.

## Access control: IAM, resource policies, cross-account, workload identity, private endpoints

### Takeaway

Cloud IAM is always the primary gate. AWS is the only one of these stores with a first-class *resource* policy that enables cross-account access without a trust relationship on the consumer side; everyone else composes IAM grants, and Cloudflare adds a second, per-secret scope check that is the closest thing to an agent-safe capability model.

### Cited Findings

- AWS authorization combines identity-based IAM policies with resource policies of up to 20,480 characters, enabling cross-account access. `ValidateResourcePolicy` checks policies, and `BlockPublicPolicy` blocks public resource policies — [AWS: Authentication and access control](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html).
- AWS resource policies can restrict access to a VPC endpoint using `aws:sourceVpce` / `aws:sourceVpc` conditions — [AWS: Authentication and access control](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html).
- GCP access is IAM-based at project, folder, organization, or individual-secret scope, with predefined roles such as `roles/secretmanager.secretAccessor` and admin roles for lifecycle operations — [GCP: Access control](https://cloud.google.com/secret-manager/docs/access-control).
- Azure recommends Azure RBAC over the legacy vault access-policy model. Per-secret permissions are `get`, `list`, `set`, `delete`, `recover`, `backup`, `restore`, and `purge` — [Azure: About secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets).
- Azure Private Link exposes Key Vault at `privatelink.vaultcore.azure.net`; when public access is disabled the public DNS name still resolves but requests are denied, and private endpoint connections move through Pending/Approved/Rejected/Disconnected states — [Azure: Private Link service](https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service).
- OCI access is governed by IAM policies and compartments; private access from a VCN uses a service gateway, so resources can reach the vault with private IPs and no internet gateway — [OCI: Vaults and key management](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm).
- Alibaba uses RAM policies, and a caller needs **both** `kms:GetSecretValue` and `kms:Decrypt`; KMS instances can be shared across accounts — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cloudflare enforces two independent checks: account role/API-token permission **and** a per-secret `scopes` list (`workers`, `ai-gateway`). The `Account Secrets Store Edit` permission is required to bind a secret to a Worker or AI Gateway, so CI/CD tokens need Edit, not Read — [Cloudflare: Access control](https://developers.cloudflare.com/secrets-store/access-control/).
- Cloudflare defines four roles — Super Administrator, Secrets Store Admin, Secrets Store Deployer, Secrets Store Reporter — plus account API token permissions "Account Secrets Store Read" and "Account Secrets Store Edit" — [Cloudflare: Access control](https://developers.cloudflare.com/secrets-store/access-control/).
- IBM Cloud Secrets Manager applies IAM plus secret groups as the unit of access control — [IBM: Getting started](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-getting-started).

### Inferences

- AWS's resource-policy model is the most automation-friendly for a multi-account CLI: a target account can grant a tooling account access without the tooling account holding a role in every account. GCP/Azure/OCI require the caller to assume identity in, or be granted on, the target scope.
- Cloudflare's scope list is a capability model, not an identity model: even a fully privileged token cannot make a `workers`-scoped secret readable by AI Gateway. That separation — "who may administer" vs "which workload may consume" — is what an MCP server should expose to agents.
- Private connectivity is table stakes but implemented differently (Private Link, VPC endpoint + resource policy, service gateway). A CLI should report reachability, not assume public endpoints.

### Gaps

- Exact predefined GCP role names beyond `secretAccessor` were not enumerated.
- Azure RBAC built-in role names for per-secret data-plane access were not enumerated.
- Whether AWS resource policies can condition on principal tags for Secrets Manager was not verified.
- Cloudflare's scope enforcement at runtime (vs. binding time) is described for binding; runtime denial behavior was not independently verified.

## Rotation: native engines, hooks, schedules, and version semantics

### Takeaway

Rotation is the weakest parity area. Every cloud can *schedule a notification* or run *your* function; only vendor-owned resource types get true managed rotation. Generic secrets always require customer compute, which is exactly the gap third-party tools exploit.

### Cited Findings

- AWS offers managed rotation (no Lambda) for supported services, managed external secrets, or a Lambda-based rotation with four callbacks: `create_secret`, `set_secret`, `test_secret`, `finish_secret` — [AWS: Rotate secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html).
- AWS rotation strategies are single-user (one secret, one credential) and alternating-users (two users, one active at a time) — [AWS: Rotate secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html).
- AWS schedules use `rate()` or `cron()` in UTC, with a minimum of every 4 hours and a maximum of 999 days; the rotation window must be at least 1 hour and starts on the hour — [AWS: Rotation schedule](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotation-schedule.html).
- GCP publishes a `SECRET_ROTATE` message to Pub/Sub at `next_rotation_time`; `rotation_period` has a minimum of 1 hour, failed rotations retry for up to 7 days and are then canceled, and an in-flight rotation blocks a new one — [GCP: Secret rotation](https://cloud.google.com/secret-manager/docs/secret-rotation).
- GCP now offers automatic rotation of Cloud SQL credentials (Preview): it generates a password, updates the Cloud SQL instance, stores a new secret version, and moves the alias. It is limited to **regional secrets**, supports PostgreSQL and SQL Server, forbids manual versions on that secret type, and can cause brief downtime — [GCP: Secret rotation](https://cloud.google.com/secret-manager/docs/secret-rotation).
- Azure has no native rotation engine for secrets. The documented pattern is an Event Grid `SecretNearExpiry` event (30 days before expiry) triggering a Function or Logic App that writes a new version and updates the target; Event Grid retries for 2 hours, and there is a lag between the secret update and the target update that can cause auth failures — [Azure: Event Grid overview](https://learn.microsoft.com/en-us/azure/key-vault/general/event-grid-overview).
- OCI rotation creates a new secret version; secret rules can prevent reuse of an old version's contents, and old versions remain retrievable with a non-current rotation state unless a rule blocks it — [OCI: Secret Management overview](https://docs.oracle.com/en-us/iaas/Content/secret-management/overview.htm).
- Alibaba fully manages periodic and immediate rotation for RAM, database (ApsaraDB RDS/PolarDB), and ECS secrets; **generic** secrets need Function Compute for scheduled rotation or a manual new version — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cloudflare documents create/update/delete only — no rotation schedule, no versions, no rotation hooks — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/).
- IBM Cloud Secrets Manager supports manual rotation of IAM credentials and arbitrary secrets — [IBM: Getting started](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-getting-started).

### Inferences

- The portable unit is not "a rotation API" but a four-phase contract (create pending → apply to target → verify → promote). AWS's Lambda interface is the de facto reference; a CLI can implement the same phases with any runner.
- Azure's event-driven model is the most decoupled, but the documented lag window means consumers must tolerate a period where the secret and the target disagree. A credential manager should require an explicit "verify" step before promoting.
- Alibaba's split — managed rotation for vendor-owned resource types, Function Compute for generic — is the honest architecture. GCP's Cloud SQL preview is the same idea, applied narrowly.

### Gaps

- Whether OCI offers a **native schedule** for secret rotation (as opposed to key rotation, which is 60–365 days for private vaults) was not found in the secret-management docs.
- GCP Cloud SQL automatic rotation is Preview; no GA date was published.
- Cloudflare has no published rotation roadmap.
- IBM rotation scheduling (as opposed to manual rotate) was not verified.

## Audit and observability

### Takeaway

Audit exists everywhere, but value reads are treated as sensitive data-plane events that are often off by default or cost extra. Only Cloudflare documents per-operation metadata (for example `value_modified`), which is the granularity an agent-facing audit log needs.

### Cited Findings

- AWS integrates with CloudTrail for API activity, CloudWatch for metrics and alarms, EventBridge for events, and GuardDuty — [AWS: Monitoring](https://docs.aws.amazon.com/secretsmanager/latest/userguide/monitoring.html).
- GCP writes Secret Manager operations to Cloud Audit Logs; `AccessSecretVersion` is a `DATA_READ` event while administrative writes are `ADMIN_WRITE`, and Data Access logs must be explicitly enabled — [GCP: Audit logging](https://cloud.google.com/secret-manager/docs/audit-logging).
- Azure Key Vault streams logs to Azure Monitor, Log Analytics, Event Hub, or a storage account, and Defender for Key Vault adds threat detection — [Azure: Key Vault security features](https://learn.microsoft.com/en-us/azure/key-vault/general/security-features).
- Azure Event Grid emits `SecretNearExpiry` and `SecretNewVersionCreated`, enabling automated reaction to lifecycle events — [Azure: Event Grid overview](https://learn.microsoft.com/en-us/azure/key-vault/general/event-grid-overview).
- OCI records operations in OCI Audit and can emit Events for rotation failures and key lifecycle changes — [OCI: Vaults and key management](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm).
- Alibaba records create, rotate, and retrieve operations in ActionTrail — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cloudflare account audit logs record Secrets Store `Access`, `Create` (including `duplicated_from_id`), `Update` (including `value_modified: true`), and `Delete` — [Cloudflare: Audit logs](https://developers.cloudflare.com/secrets-store/audit-logs/).

### Inferences

- A credential manager should log reads **by default**, not behind an opt-in data-access switch. GCP's default-off Data Access logs are a compliance-friendly but incident-hostile choice.
- The useful audit tuple is `who, what secret, which version, which operation, allowed/denied, value_modified`. Cloudflare's `value_modified` flag is a good example: it distinguishes a metadata edit from a credential change without logging the value.

### Gaps

- Whether AWS logs `GetSecretValue` as a management event by default or requires CloudTrail data events (and the associated cost) was not verified.
- Whether Azure secret **reads** appear in the Activity Log or only in diagnostic logs was not verified.
- Cloudflare audit log retention and export options were not verified.

## Limits and pricing

### Takeaway

Pricing models are not comparable line-by-line: AWS charges per secret, GCP per active version, Azure per 10,000 operations, OCI through vault/key-version infrastructure, Alibaba through a KMS instance plus a secret quota, and Cloudflare bundles it with no published line item. Size and version caps vary by roughly 6×.

### Cited Findings

- AWS quotas: 500,000 secrets per Region, 65,536-byte secret value, 100 versions per secret, 20 staging labels, 10,000 `GetSecretValue` TPS, 40,000 `DescribeSecret` TPS, 100 `ListSecrets` TPS — [AWS: Quotas](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html).
- AWS pricing is $0.40 per secret per month plus $0.05 per 10,000 API calls; creating new versions is not charged separately — [AWS: Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/).
- GCP quotas: 64 KiB payload, 50 aliases per secret, 90,000 access operations per minute per project, 600 read operations per minute, 600 write operations per minute, and soft-enforced modification limits of 2 QPS / 120 QPM per global secret (80 QPS / 4,800 QPM per regional secret) — [GCP: Quotas](https://cloud.google.com/secret-manager/quotas).
- GCP pricing: first 6 active secret versions and 10,000 access operations per month are free, then about $0.06 per active version per month and $0.03 per 10,000 access operations; management operations are free, and the first 3 rotation notifications are free, then $0.05 each — [GCP: Secret Manager pricing](https://cloud.google.com/secret-manager/pricing).
- Azure has no documented cap on the number of keys, secrets, or certificates in a vault, and no cap on versions — but backups are limited to 500 versions. Secret `CREATE` is limited to 300 per 10 seconds per vault; all other transactions to 4,000 per 10 seconds — [Azure: Service limits](https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits).
- Azure bills Key Vault secrets on a per-10,000-operations basis rather than per secret; HSM-protected keys are billed only if used in the last 30 days, and Managed HSM is billed hourly per pool — [Azure: Key Vault pricing](https://azure.microsoft.com/en-us/pricing/details/key-vault/).
- Azure's pricing FAQ describes secrets as "under 10 KB" while the product documentation states a 25 KB maximum — [Azure: Key Vault pricing](https://azure.microsoft.com/en-us/pricing/details/key-vault/); contradicted by [Azure: About secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets).
- OCI limits: 30 active + 30 pending-deletion versions per secret, and 5,000 secrets per tenancy on paid accounts; Always Free allows 150 secrets and 20 + 20 versions — [OCI: Secret versions](https://docs.oracle.com/en-us/iaas/Content/secret-management/Concepts/secret-versions.htm); [OCI: Service limits, Secret Management table](https://docs.oracle.com/en-us/iaas/Content/General/service-limits/default.htm).
- OCI cost is driven by vault type and key versions: a virtual private vault includes 1,000 key versions, while shared vaults pay per key version; Dedicated KMS and External KMS are separate offerings — [OCI: Vaults and key management](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm).
- Alibaba requires purchasing a **KMS instance** and configuring a **secret quota** before secrets can be used; there is no serverless per-secret tier — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview); [Alibaba: KMS pricing](https://www.alibabacloud.com/product/kms/pricing).
- Cloudflare caps Secrets Store at 100 secrets and one store per account, and its Workers pricing page has no Secrets Store line item; Workers Paid starts at $5/month — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/); [Cloudflare: Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).

### Inferences

- Normalized per-secret cost is a bad comparison. At low volume Azure and OCI can be near-zero; at high read volume AWS's per-call charge dominates; at high version churn GCP's per-version charge dominates.
- The absence of a Cloudflare price is itself a signal: the feature is in open beta and monetization is undecided, so it is unsafe to model as a free production dependency.
- The Azure 25 KB vs "under 10 KB" conflict should be treated as a documentation defect until Microsoft reconciles it; design to 10 KB if portability matters.

### Gaps

- Cloudflare Secrets Store pricing is not published; the only observable cost is the Workers Paid minimum.
- OCI's Always Free limits are 150 secrets and 20 + 20 versions, so the open question is narrower: whether Secret Management carries a separate per-secret charge. Oracle's cloud price list did not surface a Secret Management line item, and cost appears to attach to vaults and key versions.
- Alibaba's per-secret-quota pricing tiers were not extracted; the pricing page is organized around instance types.
- IBM Cloud Secrets Manager plan pricing was not reviewed.

## Developer experience: CLI, SDKs, local emulation, IaC, Kubernetes

### Takeaway

CLIs, SDKs, and Terraform providers exist for every hyperscaler. Local emulation is the real differentiator: none of these services ships a faithful first-party emulator, and Cloudflare explicitly stores locally created secrets in plaintext. Kubernetes integration is converging on External Secrets Operator for sync and the Secrets Store CSI driver for mounts, but CSI rotation/sync is still alpha.

### Cited Findings

- AWS exposes `aws secretsmanager` CLI commands, SDKs, and the `aws_secretsmanager_secret` Terraform resource; no first-party local emulator is documented — [AWS: What's in a secret](https://docs.aws.amazon.com/secretsmanager/latest/userguide/whats-in-a-secret.html).
- GCP exposes `gcloud secrets`, the REST v1 API, and Terraform; GKE offers a Secret Manager add-on and CSI integration that syncs secrets into Kubernetes — [GCP: Secret Manager overview](https://cloud.google.com/secret-manager/docs/overview).
- Azure exposes `az keyvault`, SDKs, and the `azurerm_key_vault_secret` Terraform resource; no first-party Key Vault emulator is documented — [Azure: About secrets](https://learn.microsoft.com/en-us/azure/key-vault/secrets/about-secrets).
- OCI exposes the Console, CLI, REST API, and SDKs, with Terraform support via the `oci` provider (`oci_vault_secret`) — [OCI: Secret Management overview](https://docs.oracle.com/en-us/iaas/Content/secret-management/overview.htm); [OCI: Vaults and key management](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm).
- Alibaba supports ROS and Terraform for secret management, plus KMS/Secrets SDKs — [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cloudflare offers dashboard, REST API, and Wrangler (`wrangler secrets-store`); secrets created locally without `--remote` are stored **unencrypted** in `.wrangler/state` — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/).
- External Secrets Operator defines `SecretStore`, `ClusterSecretStore`, and `ExternalSecret` CRDs; a controller fetches from an external API and syncs Kubernetes Secrets, with providers including AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, IBM, Oracle Vault, 1Password, Doppler, Infisical, Bitwarden, and Akeyless — [ESO: Overview](https://external-secrets.io/latest/introduction/overview/).
- The Secrets Store CSI Driver mounts secrets, keys, and certificates as an inline CSI volume; providers exist for AWS, Azure, GCP, Vault, Akeyless, Conjur, and OpenBao, and both auto-rotation and sync-to-Kubernetes-Secret are **alpha** — [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/).
- HashiCorp Vault's database secrets engine issues dynamic credentials per service instance with leases/TTLs, and static roles support `rotation_period` or cron-based `rotation_schedule` with a `rotation_window`; it covers Cassandra, Couchbase, Elasticsearch, HanaDB, InfluxDB, MongoDB/Atlas, MSSQL, MySQL/MariaDB, Oracle, PostgreSQL, Redis, Redshift, and Snowflake — [Vault: Database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases).

### Inferences

- "Works locally" is the single biggest DX gap. Cloudflare's plaintext local store is an explicit warning, and the hyperscalers simply expect you to point at a real account. A CLI + MCP manager that offers an encrypted local profile with the same semantics as production would differentiate immediately.
- Terraform coverage is necessary but not sufficient: teams increasingly run ESO/CSI in-cluster. A store that cannot be an ESO provider or CSI provider is invisible to Kubernetes-native workflows.
- CSI's alpha rotation/sync status means "mount a secret as a file" is production-ready, but "keep a Kubernetes Secret in sync" is not. ESO is the safer sync path today.

### Gaps

- No first-party emulator was found for AWS, Azure, or GCP; third-party options (for example LocalStack) exist but were not evaluated.
- Cloudflare's Wrangler `secrets-store` command surface beyond create/update/delete was not enumerated.
- Whether Alibaba's Terraform provider covers all four secret types was not verified.

## Side-by-side comparison

### Takeaway

The matrix below is the compressed view: AWS leads on version/label ergonomics and cross-account policy; GCP leads on rotation signaling and regional residency; Azure leads on enterprise IAM integration and soft-delete safety; OCI's cost is infrastructure-shaped (vault + key versions) rather than per secret; Alibaba leads on managed rotation for its own resource types; Cloudflare leads on agent-safe write-only consumption but lacks nearly everything else.

### Cited Findings

**Data model**

| Store | Unit | Versioning | Replication | Recovery |
|---|---|---|---|---|
| AWS Secrets Manager | Secret + versions | 3 built-in labels, 20 labels max, 100 versions | Multi-Region replicas | 7-day minimum window; force delete |
| GCP Secret Manager | Global secret + versions | Version IDs + aliases (50) | Automatic or user-managed; regional secrets | Delayed destruction 1–1,000 days |
| Azure Key Vault | Vault + secret + versions | Version IDs; enabled/exp/nbf flags | Platform-managed; no per-secret replication control documented | Soft delete 7–90 days; optional purge protection |
| OCI Secret Management | Vault + secret + versions | Version numbers + rotation state; 30 active + 30 pending | Cross-Region replicas | Pending-deletion version state; recovery window not documented |
| Alibaba KMS Secrets | KMS instance + secret + versions | AWS-style labels, 8 max | Not documented on reviewed page | Not documented on reviewed page |
| Cloudflare Secrets Store | Account store + secret | None | Encrypted across Cloudflare data centers | None documented |
| IBM Secrets Manager | Instance + secret group + secret | Vault-backed versions | Instance-scoped | Vault-backed |

Sources: [AWS](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_versions.html); [GCP](https://cloud.google.com/secret-manager/docs/overview); [Azure](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview); [OCI](https://docs.oracle.com/en-us/iaas/Content/secret-management/Concepts/secret-versions.htm); [Alibaba](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview); [Cloudflare](https://developers.cloudflare.com/secrets-store/manage-secrets/); [IBM](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-getting-started).

**Limits and price**

| Store | Max value | Version/label cap | Secret cap | Pricing model |
|---|---|---|---|---|
| AWS | 65,536 bytes | 100 versions / 20 labels | 500,000 per Region | $0.40/secret/mo + $0.05/10k calls |
| GCP | 64 KiB | 50 aliases; no version-count cap documented | Project quota (not stated here) | $0.06/version/mo + $0.03/10k accesses; 6 versions free |
| Azure | 25 KB (docs) / "under 10 KB" (pricing FAQ) | No cap; backup ≤500 versions | No documented cap | Per 10,000 operations |
| OCI | Not stated on reviewed pages | 60 versions (30+30) | 5,000/tenancy (150 free) | Vault type + key versions |
| Alibaba | Not stated on reviewed page | 8 labels | Secret quota on KMS instance | KMS instance + secret quota |
| Cloudflare | 65,536 bytes | None | 100/account, 1 store | No published line item |

Sources as above plus [AWS quotas](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html), [GCP quotas](https://cloud.google.com/secret-manager/quotas), [GCP pricing](https://cloud.google.com/secret-manager/pricing), [Azure limits](https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits), [Azure pricing](https://azure.microsoft.com/en-us/pricing/details/key-vault/), [AWS pricing](https://aws.amazon.com/secrets-manager/pricing/), [Alibaba pricing](https://www.alibabacloud.com/product/kms/pricing), [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/).

**Operations**

| Store | Native rotation | Hooks | Audit | K8s | IaC |
|---|---|---|---|---|---|
| AWS | Managed for supported services | Lambda 4-step; EventBridge | CloudTrail/CloudWatch/EventBridge | ESO, CSI | Terraform |
| GCP | Pub/Sub signal; Cloud SQL preview | Pub/Sub push | Cloud Audit Logs (data access opt-in) | ESO, CSI, GKE add-on | Terraform |
| Azure | None for secrets | Event Grid near-expiry → Function | Azure Monitor/Event Hub | ESO, CSI | Terraform |
| OCI | New version; key auto-rotation 60–365 days | OCI Events/Functions | OCI Audit/Events | ESO | Terraform |
| Alibaba | Managed for RAM/DB/ECS | Function Compute for generic | ActionTrail | None documented | ROS/Terraform |
| Cloudflare | None | None | Account audit logs | None documented | Wrangler/REST |
| IBM | Manual | Vault-backed | IAM/Activity Tracker | ESO | Terraform |

Sources: [AWS rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html); [GCP rotation](https://cloud.google.com/secret-manager/docs/secret-rotation); [Azure Event Grid](https://learn.microsoft.com/en-us/azure/key-vault/general/event-grid-overview); [OCI KMS](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm); [Alibaba](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview); [Cloudflare](https://developers.cloudflare.com/secrets-store/manage-secrets/); [IBM](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-getting-started); [ESO](https://external-secrets.io/latest/introduction/overview/); [CSI](https://secrets-store-csi-driver.sigs.k8s.io/).

### Inferences

- No single store wins on all four axes. A parity-oriented product should pick AWS's version/label model, GCP's rotation signaling, Azure's soft-delete defaults, and Cloudflare's per-secret scope check.
- The matrix also shows which features are commoditized (CLI, SDK, Terraform, audit export) and which are genuinely differentiated (managed rotation, local dev, dynamic credentials, cross-cloud sync).

### Gaps

- Azure's replication behavior is platform-managed and the reviewed docs do not describe per-secret replication controls; how (or whether) a secret can be pinned to a region pair was not verified.
- OCI, Alibaba, and Cloudflare have no documented Kubernetes integration; absence in the reviewed docs is not proof that community providers do not exist.
- IBM's rotation scheduling and Kubernetes story were not verified beyond ESO's provider list.

## Where cloud-native secret stores are weak, and where third-party tools win

### Takeaway

Cloud-native stores are excellent at *storing one value securely inside one cloud account* and poor at everything that spans accounts, clouds, environments, or credential lifetimes. Third-party tools win on dynamic credentials, local development, cross-cloud sync, and developer-facing workflow — not on raw cryptographic assurance.

### Cited Findings

- Dynamic, lease-based database credentials are a Vault feature: the database secrets engine creates credentials per service instance with leases and TTLs, supports static roles with scheduled rotation, and covers 15+ database engines — [Vault: Database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases).
- Cloud-native managed rotation is limited to vendor-owned resource types: AWS managed rotation for supported services, GCP Cloud SQL (Preview, regional only), Alibaba RAM/database/ECS. Generic secrets require customer-written Lambda/Function/Function Compute code — [AWS: Rotate secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html); [GCP: Secret rotation](https://cloud.google.com/secret-manager/docs/secret-rotation); [Alibaba: Secret management](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview).
- Cross-cloud and cross-account synchronization is an ecosystem function, not a cloud function: ESO's provider list spans AWS, Azure, GCP, Vault, IBM, Oracle, 1Password, Doppler, Infisical, Bitwarden, and Akeyless — [ESO: Overview](https://external-secrets.io/latest/introduction/overview/).
- Local development is explicitly unsafe on at least one platform: Cloudflare stores locally created secrets unencrypted in `.wrangler/state` — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/).
- Kubernetes secret sync is still maturing: the CSI driver's auto-rotation and sync-to-Kubernetes-Secret features are alpha — [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/).
- Versioning semantics diverge enough to break portability: AWS 100 versions/20 labels — [AWS](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_versions.html); Alibaba 8 labels — [Alibaba](https://www.alibabacloud.com/help/en/kms/user-guide/secret-management-overview); OCI 60 versions — [OCI](https://docs.oracle.com/en-us/iaas/Content/secret-management/Concepts/secret-versions.htm); GCP 50 aliases — [GCP](https://cloud.google.com/secret-manager/quotas); Azure uncapped — [Azure](https://learn.microsoft.com/en-us/azure/key-vault/general/service-limits); Cloudflare none — [Cloudflare](https://developers.cloudflare.com/secrets-store/manage-secrets/).
- Cloudflare's write-only model means a secret cannot be read back even by an administrator, which is strong for agent safety but breaks verification, diffing, and migration workflows — [Cloudflare: Manage account secrets](https://developers.cloudflare.com/secrets-store/manage-secrets/).

### Inferences

- The cloud-native stores are optimized for the *consuming workload inside the same cloud*, not for the *operator or agent managing credentials across environments*. That is the structural gap a CLI + MCP manager should target.
- Third-party tools do not beat cloud KMS on key custody. They beat it on lifecycle: issuance, rotation orchestration, revocation, and developer ergonomics. A credible product should wrap cloud KMS rather than compete with it.
- Write-only secrets (Cloudflare) and read-anything secrets (AWS/Azure) are two ends of a spectrum. The right default for agents is write-only *to the agent* while remaining auditable and rotatable by a human-controlled control plane.

### Gaps

- No source was found that benchmarks third-party tools against cloud-native stores on security outcomes; the comparison here is capability-based, not empirical.
- Pricing comparisons across third-party tools were out of scope.
- The claim that cloud stores "lack" dynamic credentials is accurate for the reviewed docs, but some clouds offer short-lived tokens through adjacent services (for example database IAM auth); those were not evaluated.

## What a CLI + MCP credential manager should copy

### Takeaway

Match the commoditized surface exactly (versions, labels, soft delete, audit, Terraform, Kubernetes sync) and differentiate on the parts the clouds do badly: encrypted local development, agent-scoped write-only access, portable rotation orchestration, and one audit trail across providers.

### Cited Findings

- AWS's three-label model is the simplest versioning contract that still supports rollback and staged rotation: `AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING` — [AWS: Secret versions](https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_secret_versions.html).
- Azure's soft-delete defaults (on by default, 90-day retention, two-step delete/purge, optional purge protection) are the strongest safety default among the reviewed stores — [Azure: Soft-delete overview](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview).
- Cloudflare's two-check access model (role permission **and** per-secret scope) prevents a privileged token from repurposing a secret for an unintended consumer — [Cloudflare: Access control](https://developers.cloudflare.com/secrets-store/access-control/).
- GCP's rotation signal is a decoupled event (`SECRET_ROTATE` to Pub/Sub), which lets any runner own the rotation logic — [GCP: Secret rotation](https://cloud.google.com/secret-manager/docs/secret-rotation).
- The Secrets Store CSI driver's alpha status for rotation/sync shows that "mount" is solved but "keep in sync" is not; ESO is the mature sync path — [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/); [ESO: Overview](https://external-secrets.io/latest/introduction/overview/).
- Cloudflare's audit log records `value_modified` on updates, distinguishing metadata edits from credential changes without logging the value — [Cloudflare: Audit logs](https://developers.cloudflare.com/secrets-store/audit-logs/).

### Inferences

- Minimum viable parity: `secret create/get-metadata/update/delete`, immutable versions, a `current` pointer plus named labels, soft delete with a configurable 7–30 day window, per-operation audit, and a Terraform provider.
- Differentiators worth building: (1) encrypted local profile with production-identical semantics; (2) agent tokens that are write-only and scope-bound to a target; (3) rotation as an external, resumable four-phase workflow; (4) one audit stream across AWS/GCP/Azure/OCI; (5) preflight that reports reachability, version state, and pending rotation without returning values.
- The MCP surface should mirror the human CLI but never expose a `get value` tool to agents — only metadata, version IDs, rotation state, and write operations. That is consistent with Vaultly's existing contract that agents never receive stored credentials.

### Gaps

- No vendor publishes an agent-specific access model beyond Cloudflare's scopes; the "write-only to the agent, readable by the control plane" design is an inference, not a documented pattern.
- Whether Terraform providers expose rotation state and soft-deleted objects consistently across all six stores was not verified.
- Pricing for a multi-provider sync layer (egress, API calls) was not modelled.

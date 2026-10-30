# Open-source and file-based secret management: landscape inventory (as of 30 Oct 2026)

**Scope and method.** Every URL in this document was accessed on **2026-10-30** unless a different date is stated inline. Star/fork/issue counts come from the GitHub REST API (`https://api.github.com/repos/<owner>/<repo>`) on that date; note that GitHub's `open_issues_count` **includes open pull requests**, so it overstates pure bug backlog. Release dates come from the GitHub releases API. Vendor blogs and third-party guides are labelled as such; the default is the project's own repo or docs. Nothing here contains secret material — only metadata and design descriptions.

**Coverage.** Mozilla SOPS, age, git-crypt, pass, gopass, KeePassXC, Vaultwarden, Sealed Secrets, External Secrets Operator, CyberArk Conjur OSS, Akeyless (OSS components), Teleport, plus OpenBao and Infisical as the two 2024–2026 projects that materially changed the landscape.

---

## Inventory: what each project actually is, and why it gets adopted

### Takeaway
The market splits into four adoption engines, not one: (1) **git-native ciphertext** (SOPS, git-crypt, age, pass/gopass) adopted because secrets live where code lives and review/diff/rollback come free; (2) **cluster-local decryption** (Sealed Secrets) adopted because CI never touches plaintext; (3) **provider fan-in/reconciliation** (ESO) adopted because teams already bought a cloud secret manager and need Kubernetes to consume it; (4) **identity-based access** (Teleport, OpenBao, Conjur) adopted because the real problem is not storage but *who/what can read it, and can you prove it afterwards*. File-based tools win on workflow and lose on lifecycle; platform tools win on lifecycle and lose on developer ergonomics.

### Cited Findings

**Adoption snapshot (GitHub, 2026-10-30)**

| Project | Stars | Forks | Open issues* | Created | License (per API) | Latest release |
|---|---|---|---|---|---|---|
| [Vaultwarden](https://api.github.com/repos/dani-garcia/vaultwarden) | 69,913 | 3,385 | 88 | 2018-02-17 | AGPL-3.0 | 1.37.4 (2026-10-05) |
| [Infisical](https://api.github.com/repos/Infisical/infisical) | 30,144 | 2,400 | 864 | 2022-08-05 | NOASSERTION (MIT + `ee/`) | v0.167.4 (2026-10-26) |
| [KeePassXC](https://api.github.com/repos/keepassxreboot/keepassxc) | 29,609 | 1,992 | 987 | 2016-02-28 | NOASSERTION (GPL-2/3) | 2.8.0 (2026-10-21) |
| [age](https://api.github.com/repos/FiloSottile/age) | 24,116 | 683 | 25 | 2019-05-18 | BSD-3-Clause | v1.3.2 (2026-08-29) |
| [SOPS](https://api.github.com/repos/getsops/sops) | 23,560 | 1,109 | 466 | 2015-08-13 | MPL-2.0 | v3.13.3 (2026-07-23) |
| [Teleport](https://api.github.com/repos/gravitational/teleport) | 21,049 | 2,182 | 3,248 | 2015-03-02 | AGPL-3.0 | v18.10.0 (2026-07-09) |
| [git-crypt](https://api.github.com/repos/AGWA/git-crypt) | 9,975 | 551 | 128 | 2012-12-19 | GPL-3.0 | 0.8.0 (2025-09-24) |
| [Sealed Secrets](https://api.github.com/repos/bitnami-labs/sealed-secrets) | 9,321 | 785 | 67 | 2017-05-29 | Apache-2.0 | v0.41.2 (2026-10-26) |
| [OpenBao](https://api.github.com/repos/openbao/openbao) | 8,770 | 657 | — | 2023-11-09 | MPL-2.0 | v2.7.2 (2026-10-26) |
| [gopass](https://api.github.com/repos/gopasspw/gopass) | 7,298 | 569 | 82 | 2017-02-02 | MIT | v1.17.4 (2026-10-10) |
| [External Secrets Operator](https://api.github.com/repos/external-secrets/external-secrets) | 6,928 | 1,471 | 349 | 2020-11-17 | Apache-2.0 | v2.14.0 (2026-10-23) |
| [Conjur OSS](https://api.github.com/repos/cyberark/conjur) | 953 | 150 | 167 | 2016-06-28 | NOASSERTION (LGPL-3.0) | v1.27.0 (2026-06-16) |
| [pass](https://api.github.com/repos/zx2c4/password-store) (GitHub mirror) | 759 | — | 1 | — | NOASSERTION | tag 1.7.4 (no newer tag) |

\*includes PRs.

**Per-tool characterisation and adoption engine**

- **SOPS** — "an editor of encrypted files" for YAML/JSON/ENV/INI/BINARY, encrypting with AWS KMS, GCP KMS, Azure Key Vault, HuaweiCloud KMS, **age**, and **PGP** ([repo](https://github.com/getsops/sops); [docs](https://getsops.io/docs/)). Adopted because it is a *file format plus a CLI*, not a service: it drops into Helm/Kustomize/Terraform repos, requires no server, and produces reviewable ciphertext. Originally a Mozilla project (2015), donated to the **CNCF as a Sandbox project in 2023** ([docs intro](https://getsops.io/docs/)).
- **age** — "a simple, modern and secure file encryption tool, format, and Go library… small explicit keys, post-quantum support, no config options, and UNIX-style composability" ([README](https://github.com/FiloSottile/age)). Adopted as the *key/recipient primitive* other tools embed (SOPS, gopass, and many CI scripts), and as the humane replacement for GPG in file encryption. Format spec is standardised at C2SP ([age-encryption.org/v1](https://age-encryption.org/v1)); interoperable Rust implementation `rage` and a TypeScript implementation `typage` exist ([README](https://github.com/FiloSottile/age)).
- **git-crypt** — transparent encryption via **git clean/smudge filters**, so files are encrypted on commit and decrypted on checkout; "gracefully degrades, so developers without the secret key can still clone and commit" ([README](https://github.com/AGWA/git-crypt)). Adopted where the repo is *mostly public* and a handful of files (`*.key`, `secrets/**`) must be private, and where nobody wants to change their editor/CI workflow at all.
- **pass** — each password is a GPG-encrypted file whose *filename is the title*, stored under `~/.password-store`, managed by "a very short and simple shell script", with git for history ([passwordstore.org](https://www.passwordstore.org/)). Adopted for zero-infrastructure, Unix-philosophy credential storage and an enormous ecosystem of clients/extensions. **Stale**: latest tag is 1.7.4 and no newer tag exists ([tags API](https://api.github.com/repos/zx2c4/password-store/tags)); the canonical home is [git.zx2c4.com/password-store](https://git.zx2c4.com/password-store/) and the GitHub repo (759 stars) is a mirror.
- **gopass** — self-described "slightly more awesome standard UNIX password manager for teams", a **drop-in pass replacement**; GPG encryption + git storage by default, with **age** crypto and **fossil**/filesystem storage as options; multi-store via `gopass mounts`, `gopass recipients`, `gopass sync` ([README](https://github.com/gopasspw/gopass)). Adopted by teams that liked pass but needed multiple stores, recipient management, and Windows binaries.
- **KeePassXC** — offline **KDBX** database (KeePass-compatible, KDBX3/KDBX4), YubiKey/OnlyKey challenge-response, browser integration incl. passkeys, imports from 1Password/Bitwarden/Proton Pass, and "database reports (password health, HIBP, statistics)" ([README](https://github.com/keepassxreboot/keepassxc)). Adopted because the file is the database: no server, no vendor, works air-gapped, and sync is whatever the user already has (Dropbox, Syncthing, git).
- **Vaultwarden** — "an alternative server implementation of the Bitwarden Client API, written in Rust", for self-hosting where the official service is "resource-heavy" ([README](https://github.com/dani-garcia/vaultwarden)); implements Personal Vault, Send, attachments, **Organizations with Collections, password sharing, member roles, groups, event logs, admin password reset, directory connector, policies**, and 2FA incl. FIDO2/YubiKey/Duo ([README features list](https://github.com/dani-garcia/vaultwarden)). **69.9k stars — the most-starred project in this survey** — because it gives a real Bitwarden-grade UX with team sharing on a €5 VPS.
- **Sealed Secrets** — "Problem: I can manage all my K8s config in git, except Secrets. Solution: encrypt your Secret into a SealedSecret, which *is* safe to store — even inside a public repository" ([README](https://github.com/bitnami-labs/sealed-secrets)). Adopted as the lowest-friction GitOps answer that requires **no external secret manager and no CI-held decryption key**.
- **External Secrets Operator (ESO)** — Kubernetes operator that "extends Kubernetes with Custom Resources, which define where secrets live and how to synchronize them… the controller fetches secrets from an external API and creates Kubernetes secrets" ([overview](https://external-secrets.io/latest/introduction/overview/)). Adopted when the organisation *already* has AWS Secrets Manager / Vault / Azure Key Vault and wants Kubernetes to be a consumer, not a second source of truth.
- **Conjur OSS** — secrets management + application identity with **MAML**, "a role-based access policy language", a REST service for identity lifecycle and authorization, and integrations across CI/CD and orchestration ([README](https://github.com/cyberark/conjur)). Adopted historically by platform teams wanting policy-as-code machine identity without Vault's operational weight; now explicitly steered to a commercial successor (see pain points).
- **Akeyless** — **not meaningfully open source**. The core is a proprietary SaaS/self-hosted product; the `akeyless-community` GitHub org contains only integration glue: cert-manager issuer (Apache-2.0, 1 star), serverless gateway Terraform module (MPL-2.0, 0 stars), ESO provider docs, migration scripts — every repo observed had **0–2 stars** ([org repos API](https://api.github.com/orgs/akeyless-community/repos?per_page=15&sort=updated)). Adopted as a *commercial* product; OSS presence is marketing/integration surface, not a community.
- **Teleport** — not a secret store: "connectivity, authentication, access controls and audit for infrastructure", protecting access to servers, Kubernetes, databases, Windows desktops, web apps and cloud APIs "without long-lived keys or passwords", with session recording and RBAC/ABAC plus JIT access requests ([README](https://github.com/gravitational/teleport)). Adopted to *eliminate* static infrastructure credentials rather than to store application secrets.
- **OpenBao** — MPL-2.0, OpenSSF-hosted fork of Vault created 2023-11-09, promising "software under an OSI-approved open-source license, led by a community run under open-governance principles"; features secure storage, dynamic secrets, and more ([README](https://github.com/openbao/openbao)). Adopted by teams that wanted Vault's API without the licence change; SOPS already supports "HashiCorp Vault / OpenBao" transit as an identity ([SOPS docs nav](https://getsops.io/docs/)).
- **Infisical** — 30.1k stars, MIT except everything under `ee/` which is commercially licensed ([LICENSE](https://github.com/Infisical/infisical/blob/main/LICENSE)); releases multiple times per week (v0.167.2/.3/.4 all within 2026-10-23→26). Adopted as the "modern developer-friendly" open-core alternative to Vault, and it is itself an ESO provider ([ESO provider list](https://external-secrets.io/latest/introduction/overview/)).

### Inferences
- Star count is a poor proxy for enterprise adoption here: Vaultwarden (69.9k) and Infisical (30.1k) are consumer/developer-popular, while Conjur (953) and Sealed Secrets (9.3k) are far more embedded in regulated enterprises. Fork counts are a better signal of integration work — ESO's 1,471 forks against 6,928 stars (21%) is unusually high, consistent with it being forked/patched per-platform.
- The projects that survived 2015→2026 without a server (SOPS, age, git-crypt, pass) all share one property: the artefact is a *file* that outlives the tool. Projects whose value sits in a control plane (Conjur, Teleport, Infisical) must keep shipping or lose relevance; note Conjur's last release is 2026-06-16 and last push 2026-07-14.
- "Open source" is doing heavy marketing work: Akeyless has essentially no OSS core, Infisical is open-core with an `ee/` carve-out, Teleport ships AGPL source but Apache-2.0 binaries, Conjur is LGPL server + Apache clients. A buyer comparing "open source secret managers" on licence alone will be misled.

### Gaps
- No verifiable adopter lists were found for SOPS, age, git-crypt, gopass, Sealed Secrets or Conjur within this pass. Vendor "trusted by" pages are unaudited marketing; I deliberately did not convert them into claims.
- Could not verify Akeyless's current core licence terms (proprietary vs. "source available") from a primary licence file — their repos are integrations only.
- Teleport's latest release per GitHub API is v18.10.0 (2026-07-09); I did not verify whether a v19 line shipped after that date through a non-GitHub channel.

---

## Threat model and encryption model

### Takeaway
There are three genuinely different threat models in this space and they are routinely conflated: **(a) protect ciphertext at rest in a repo** (SOPS, age, git-crypt — the adversary has the git history), **(b) protect against the cluster operator / CI** (Sealed Secrets — the adversary may have repo and CI but not the cluster), and **(c) protect against lateral movement by removing standing credentials** (Teleport, OpenBao dynamic secrets, Conjur). A tool that claims all three is usually lying about one.

### Cited Findings

**SOPS — per-value AEAD with a wrapped data key**
- A random **256-bit data key** is generated per file and encrypted to each KMS/PGP master key; the wrapped copies live in the `sops` metadata block ([Encryption Protocol](https://getsops.io/docs/reference/)).
- Each leaf value is encrypted with **AES256-GCM** using that data key and "a 256 bit random initialization vector"; key names are concatenated and used as **AEAD additional data**, so the tree structure is authenticated ([Encryption Protocol](https://getsops.io/docs/reference/)). Consequence: renaming a key makes decryption fail — structural tampering is detected.
- A **MAC over all values** is stored encrypted under `sops.mac`; `--mac-only-encrypted` / `mac_only_encrypted: true` narrows the MAC to encrypted values only, which means plaintext values become modifiable outside SOPS ([Common operations](https://getsops.io/docs/usage/common-operations/); [Reference](https://getsops.io/docs/reference/)).
- Keys are **not** encrypted: "we expect that keys do not carry sensitive information, and keeping them in cleartext allows for better diff and overall readability" ([Reference](https://getsops.io/docs/reference/)).
- Documented threat model is explicitly "as strong as the weakest cryptographic mechanism": compromised AWS credentials can grant KMS access to the data key; compromised PGP key; factorable RSA key; hypothetical AES-GCM break ([Security](https://getsops.io/docs/security/)).
- Recommended posture from the original authors: **two KMS master keys in different regions + one PGP public key whose private half is stored offline**, as disaster recovery ([Security](https://getsops.io/docs/security/)).

**age — whole-file, recipient-based**
- Explicit small keys (`age1…`), recipients can also be **SSH public keys** (`ssh-ed25519`, `ssh-rsa`), identities are files possibly containing multiple keys, and `--passphrase` mode exists ([README usage](https://github.com/FiloSottile/age)).
- **Post-quantum recipients** since v1.3.0 (2025-12-27): "native post-quantum recipients based on HPKE with a hybrid ML-KEM-768 KEM", recipients `age1pq1…`, identities `AGE-SECRET-KEY-PQ-1…`, generated with `age-keygen -pq` ([release v1.3.0](https://github.com/FiloSottile/age/releases/tag/v1.3.0)).
- Hardware-backed identities via `age-plugin-yubikey` (PIV) ([README](https://github.com/FiloSottile/age)). No key distribution, revocation, audit, or multi-recipient policy engine ships with it — recipients are just a list.

**git-crypt — deterministic whole-file encryption inside git**
- "AES-256 in CTR mode with a synthetic IV derived from the SHA-1 HMAC of the file… provably semantically secure under deterministic chosen-plaintext attack… it leaks no information beyond whether two files are identical or not" ([README Security](https://github.com/AGWA/git-crypt)).
- Explicitly **does not** encrypt file names, commit messages, symlink targets, gitlinks, or other metadata; does not hide *when* a file changed or its length ([README Limitations](https://github.com/AGWA/git-crypt)).
- Integrity caveat: "git-crypt cannot be used securely unless the entire repository is protected against tampering (an attacker who can mutate your repository can alter your `.gitattributes` file to disable encryption)" ([README](https://github.com/AGWA/git-crypt)).

**Sealed Secrets — write-only sealing to a cluster key**
- Envelope: secret encrypted with **AES-256-GCM** under a randomly generated single-use 32-byte session key; the session key is encapsulated with **RSA-OAEP/SHA-256** under the controller's public key; certificates are self-signed X.509, **renewed every 30 days with a 10-year validity**, default RSA **4096-bit** ([crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md)).
- Scope is enforced *cryptographically* via the OAEP **label**: `namespace+name` for `strict` (default), `namespace` for `namespace-wide`, empty for `cluster-wide` ([crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md); [README Scopes](https://github.com/bitnami-labs/sealed-secrets)).
- "not even the original author is able to obtain the original Secret from the SealedSecret" — the user is a write-only device ([README Scopes](https://github.com/bitnami-labs/sealed-secrets)).
- Private key lives **only** in a Secret in the controller namespace; "There are no backdoors — without that private key used to encrypt a given SealedSecrets, you can't decrypt it" ([README FAQ](https://github.com/bitnami-labs/sealed-secrets)).

**ESO — no encryption of its own**
- ESO stores nothing durable and encrypts nothing; it fetches from a provider and writes a Kubernetes `Secret`, re-reconciling on `refreshInterval` ([overview](https://external-secrets.io/latest/introduction/overview/)). Its threat model is therefore a *credential and RBAC* model: the controller "is authorized to read and write secret resources across all namespaces", holds provider credentials that "may vary, potentially providing full access to a cloud provider", and is exposed to data exfiltration "through malicious resources" — e.g. copying data to an unauthorised namespace or pushing it to an attacker-controlled provider account ([threat model](https://external-secrets.io/latest/guides/threat-model/)).

**Conjur / OpenBao / Teleport — identity-centric**
- Conjur's model is policy-first: MAML role-based policy defines components, roles, privileges; the server authorises access to resources and stores secrets ([README](https://github.com/cyberark/conjur)).
- OpenBao encrypts secrets "prior to writing them to persistent storage, so gaining access to the raw storage isn't enough to access your secrets", and adds dynamic secrets ([README](https://github.com/openbao/openbao)).
- Teleport removes the static secret: short-lived certificates issued by its own CA, SSO, RBAC/ABAC, JIT access, session recording ([README](https://github.com/gravitational/teleport)).

### Inferences
- SOPS's per-value AEAD is the single most copyable design decision in this space: it is what makes ciphertext *reviewable* (a one-line diff shows one changed value) and mergeable (two people editing different keys do not conflict). SOPS's own docs say exactly this was the motivation — "Encrypting entire files as blobs makes git conflict resolution almost impossible" ([Security/Motivation](https://getsops.io/docs/security/)).
- Binding ciphertext to a path/namespace via AEAD associated data (SOPS key names; Sealed Secrets OAEP label) is a cheap, powerful anti-relocation control that most newer tools skip.
- age's post-quantum hybrid recipient is currently the strongest "future-proofing" story in file encryption, and it costs users nothing (same CLI). Any new tool choosing a key format in 2026 should assume ML-KEM hybrid recipients are table stakes by 2028.
- git-crypt's deterministic encryption is a deliberate trade (equality leak) to keep git's change detection working; SOPS avoids the leak by randomising per value but then pays with larger diffs. Both are defensible; what is not defensible is claiming "git-friendly" while leaking plaintext structure.

### Gaps
- No primary source quantifies how much metadata leakage (key names, file paths, secret counts) matters in practice; every claim here is qualitative.
- Could not verify whether SOPS's HuaweiCloud KMS and Vault/OpenBao transit identities have been independently audited; the docs list them without audit references.
- Sealed Secrets' crypto doc does not state a security proof or third-party audit; absence of an audit reference is not evidence of absence, but I found none.

---

## Workflow: editing, diffs, CI decryption, key distribution, onboarding/offboarding

### Takeaway
SOPS is the only tool in this set that treats **the diff as the product**. Its workflow (edit in place → per-value ciphertext → `textconv` decryption for `git diff`) is the reference implementation of "secrets in git that a reviewer can actually review". Sealed Secrets achieves the opposite trade: perfect CI hygiene (no decryption key in CI at all) at the cost of never being able to read your own secret back. Onboarding is cheap everywhere; **offboarding is the unsolved step** — it is a bulk re-wrap problem that every tool pushes onto the user.

### Cited Findings

**SOPS**
- Create/edit: `sops edit --kms <arn> --pgp <fp> file.yaml` opens `$EDITOR` on a decrypt-on-open/re-encrypt-on-save buffer ([Common operations](https://getsops.io/docs/usage/common-operations/)).
- In-place: `sops encrypt -i file.yaml` / `sops decrypt -i file.yaml`; binary files are supported and encrypted as a blob under `tree['data']` ([Common operations](https://getsops.io/docs/usage/common-operations/)).
- Scriptable edits without an editor: `sops set <file> '["app2"]["key"]' '"value"'`, `sops set --value-file`, `sops set --value-stdin`, `sops unset`, and `sops decrypt --extract '["an_array"][1]'` for single values ([Common operations](https://getsops.io/docs/usage/common-operations/)).
- **Reviewable diffs**: add `*.yaml diff=sopsdiffer` to `.gitattributes` and `git config diff.sopsdiffer.textconv "sops decrypt"`; then "calls to `git diff` will decrypt both previous and current versions… it even works with git client interfaces" ([Common operations](https://getsops.io/docs/usage/common-operations/)).
- **Selective encryption**: `--unencrypted-suffix`, `--encrypted-suffix`, `--encrypted-regex`, `--unencrypted-regex`, `--encrypted-comment-regex`, `--unencrypted-comment-regex` — mutually exclusive; the K8s idiom is `--encrypted-regex '^(data|stringData)$'` so `metadata` stays readable ([Common operations](https://getsops.io/docs/usage/common-operations/)).
- **Key distribution is config-as-code**: `.sops.yaml` (must be `.sops.yaml`, not `.sops.yml`) is discovered from CWD upward or via `--config`/`SOPS_CONFIG`; `creation_rules` match on `path_regex` and carry `kms`, `age`, `pgp`, `gcp_kms`, `azure_keyvault`, `hc_vault_transit_uri`, `hckms`, or `key_groups` ([Reference](https://getsops.io/docs/reference/)).
- **Onboarding** = add a recipient to `.sops.yaml` + `sops updatekeys` (re-wraps the *existing* data key to the new recipient set, no value re-encryption). **Offboarding** = remove the recipient + `updatekeys` on every file. **Compromise** = `sops updatekeys` **then** `sops rotate --in-place`, in that order — "This ensures that *first* the compromised key is removed… and only *then* rotates the data key. If done in the wrong order, the compromised key could still have access" ([Key management](https://getsops.io/docs/usage/key-management/)).
- `sops rotate` "reencrypt[s] the file with a new data key"; the docs recommend renewing the data key regularly ([Key management](https://getsops.io/docs/usage/key-management/)).
- **CI**: the repo ships an `examples/` folder "for detailed use cases of SOPS in a CI environment" ([Common operations](https://getsops.io/docs/usage/common-operations/)); the practical pattern is a KMS/age identity mounted into the job and `sops decrypt` at deploy time (inference from the identity model, not a quoted doc claim).
- **Ecosystem**: Flux ships a first-class guide "Manage Kubernetes secrets with SOPS" alongside a Sealed Secrets guide in its core docs nav, i.e. SOPS decryption is a documented Kustomization-level concern in the dominant GitOps controller ([Flux docs](https://fluxcd.io/flux/guides/mozilla-sops/)).

**age / git-crypt / pass / gopass**
- age: `age -r <recipient> -R recipients.txt -i identity.txt -a -p -o out` — recipients can come from a file, encryption is stream-oriented, and multiple identity files can be supplied for decryption ([README usage](https://github.com/FiloSottile/age)).
- git-crypt: `git-crypt init`, declare paths in `.gitattributes` (`secretfile filter=git-crypt diff=git-crypt`), then either `git-crypt add-gpg-user USER_ID` (commits a GPG-encrypted key into `.git-crypt/`) or `git-crypt export-key /path/to/key` and convey it out-of-band; collaborators run `git-crypt unlock` ([README](https://github.com/AGWA/git-crypt)). **Critical ordering footgun, stated in the README**: "Make sure your `.gitattributes` rules are in place *before* you add sensitive files, or those files won't be encrypted!"
- pass: files are GPG-encrypted, the filename is the title, hierarchy is directories, git tracks changes, and the whole store is manipulable with ordinary Unix tools ([passwordstore.org](https://www.passwordstore.org/)).
- gopass: `gopass setup` (GPG + git by default, `--crypto=age`, `--storage=fs`), `gopass clone <remote>`, `gopass mounts`, `gopass recipients`, `gopass sync` ([README](https://github.com/gopasspw/gopass)). Multiple mounts are the team/tenant mechanism; recipients are per-mount.
- Sealed Secrets: `kubeseal` encrypts locally against the controller cert (`kubeseal --fetch-cert` or `--cert path`), so "a developer only needs the `kubeseal` command-line tool and the controller's public key… without needing `kubectl` access to the cluster" ([third-party guide, Plural](https://www.plural.sh/blog/sealed-secrets-kubernetes-guide/)); the primary source confirms the cert is served at `GET /v1/cert.pem` and via `kubeseal --cert` ([crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md)).
- ESO: GitOps lives in two CRDs — `SecretStore`/`ClusterSecretStore` (how to authenticate) and `ExternalSecret` (what to fetch, with `refreshInterval`, `target.template`, `dataFrom.extract`); the operator reconciles on a poll loop ([overview](https://external-secrets.io/latest/introduction/overview/)).

### Inferences
- The `textconv` trick is the highest-leverage workflow idea in the entire survey: it makes encrypted files reviewable in *any* git UI without changing the storage format. A new tool that does not ship a one-line `.gitattributes` + diff driver is forfeiting its main advantage over a server.
- `updatekeys` (re-wrap DEK, do not re-encrypt values) is the correct primitive for onboarding/offboarding; tools that conflate "key change" with "value re-encryption" make offboarding expensive enough that teams skip it. git-crypt has neither.
- Sealed Secrets' write-only property is a feature for CI and a bug for operations: you cannot answer "what is currently in this secret?" without cluster read access, which breaks break-glass and audit workflows.
- Onboarding in every file-based tool is a documentation problem (add recipient, commit, updatekeys); offboarding is a *discovery* problem (which files still wrap the old key?). Nobody ships a `grep` for that; SOPS's metadata makes it possible but not packaged.

### Gaps
- No primary source describes an official SOPS GitHub Action or a supported CI plugin matrix; the `examples/` folder exists but I did not enumerate it.
- Could not verify whether `sops updatekeys` fails loudly or silently when a file is unreadable due to a missing identity — this matters for bulk offboarding and is not documented in the pages reviewed.
- No source found for how gopass handles recipient removal across a multi-mount store (whether it re-encrypts history); the README documents `gopass recipients` but not the rewrap semantics.

---

## Team features: sharing, access control, audit, rotation, recovery

### Takeaway
File-based tools have **sharing** (via recipient sets) and **history** (via git), but almost no **access control** (anyone with the key has all the data), **no audit** (git log shows who changed ciphertext, not who decrypted), and **weak recovery** (lose the key, lose the data). Platform tools have ACL/audit/recovery but require a server, a database, and an operator. The gap a new tool can own is: *per-recipient scoping and decryption audit for file-based secrets*.

### Cited Findings

**Sharing / access control**
- SOPS: sharing = adding a master key or recipient; "Multiple master keys allow for sharing encrypted files without sharing master keys, and provide a disaster recovery solution" ([Reference](https://getsops.io/docs/reference/)). There is **no per-key or per-value ACL** — any recipient decrypts the whole file.
- SOPS **key groups + Shamir**: "Having more than one key group allows for the use of Shamir's secret sharing which splits the file's encryption key up into multiple parts, requiring more than one identity to access the file"; `shamir_threshold` must be `0` (disabled) or `>= 2` ([Reference](https://getsops.io/docs/reference/)). This is the only n-of-m control found in any file-based tool surveyed.
- git-crypt: sharing via `add-gpg-user` or a shared symmetric key; **no revocation at all** — "git-crypt does not support revoking access to an encrypted repository which was previously granted… there's no del-gpg-user command… there's no support for rotating the key", because a past key still opens past history ([README](https://github.com/AGWA/git-crypt), which links [issue #47](https://github.com/AGWA/git-crypt/issues/47)).
- Vaultwarden: real ACL primitives — Organizations, **Collections**, member roles, groups, policies, admin password reset ([README](https://github.com/dani-garcia/vaultwarden)).
- Conjur: the strongest policy model surveyed — MAML role-based policy defining components, roles, privileges and metadata, enforced by the server ([README](https://github.com/cyberark/conjur)).
- ESO: access control is Kubernetes RBAC plus provider IAM; the docs warn the operator runs "with elevated privileges… will create/read/update secrets in all namespaces" and tell you to "restrict access of application developers to read only certain keys in a shared environment" and to add OPA/Kyverno for fine-grained control ([overview](https://external-secrets.io/latest/introduction/overview/)).

**Audit**
- SOPS/git-crypt/age/pass/gopass: no decryption audit. git history records *ciphertext changes*, not reads. (Absence of an audit feature in the docs reviewed — stated as a gap, not a quoted claim.)
- Vaultwarden: "Event Logs" are listed as an implemented organisation feature ([README](https://github.com/dani-garcia/vaultwarden)).
- Teleport: session recording and audit across SSH, Kubernetes, database, RDP and web sessions is a headline feature ([README](https://github.com/gravitational/teleport)).
- OpenBao: "detailed audit logs" is named as a core motivation/feature ([README](https://github.com/openbao/openbao)).
- ESO: exposes Prometheus metrics and controller status ([docs nav: Metrics](https://external-secrets.io/latest/introduction/overview/)) but is not an audit system for secret *reads*.

**Rotation**
- SOPS: `sops rotate` for the data key; `updatekeys` for the recipient set; documented correct ordering after compromise ([Key management](https://getsops.io/docs/usage/key-management/)).
- Sealed Secrets: sealing keys auto-renew every 30 days (`--key-renew-period`, `0` disables), old keys are retained so old SealedSecrets still decrypt; the docs are emphatic that this is **not** secret rotation — "SealedSecret key renewal and re-encryption features are **not a substitute** for periodical rotation of your actual secret values" ([README Secret Rotation](https://github.com/bitnami-labs/sealed-secrets)).
- Conjur: built-in **rotators** for variables, plus custom rotators ([README](https://github.com/cyberark/conjur)).
- OpenBao: dynamic secrets (generate on demand) — rotation by construction ([README](https://github.com/openbao/openbao)).
- ESO: no rotation; "There is no Secret Operator that handles the lifecycle of the secret, this is out of scope of ESO" ([overview](https://external-secrets.io/latest/introduction/overview/)).

**Recovery**
- SOPS: multiple master keys incl. an offline PGP key are the documented DR plan ([Security](https://getsops.io/docs/security/)).
- Sealed Secrets: recovery is a manual `kubectl get secret -n kube-system -l sealedsecrets.bitnami.com/sealed-secrets-key -o yaml > main.key` backup, restored before the controller starts; and the backup must be refreshed after key renewal or it "won't be able to decrypt new sealed secrets" ([README FAQ](https://github.com/bitnami-labs/sealed-secrets)). Losing the key means "you will need to regenerate new passwords for everything, seal them again with a new sealing key" ([README FAQ](https://github.com/bitnami-labs/sealed-secrets)).
- Vaultwarden: "We cannot be held liable for any data loss… We highly recommend performing regular backups of your files and database" ([README Disclaimer](https://github.com/dani-garcia/vaultwarden)).
- KeePassXC: recovery = restore the KDBX file from your own backup/sync; the tool itself is offline and stateless ([README](https://github.com/keepassxreboot/keepassxc)).

### Inferences
- Shamir key groups are under-used and under-marketed: they are the only way a file-based tool expresses "two of {platform team, security team, offline escrow} must agree". A new tool should expose this as a first-class "approval policy" rather than a YAML key.
- The absence of decryption audit is the single biggest reason security teams refuse file-based secret tools. It is also the hardest to retrofit, because decryption happens on developer laptops and CI runners outside any control plane. A local, append-only, signed "decryption receipt" (pushed to a log) would be a genuine differentiator.
- Recovery is where Sealed Secrets is objectively worse than SOPS: SOPS's offline-PGP-key pattern is a real DR plan; Sealed Secrets' plan is "hope you backed up a k8s Secret".
- Vaultwarden proves that *team features* (collections, roles, groups, event logs) drive adoption far more than cryptographic elegance — 69.9k stars for an unofficial reimplementation.

### Gaps
- No source found describing SOPS audit hooks or any community tool that logs SOPS decryptions; I could not confirm whether any exists.
- Could not verify KeePassXC's team-sharing guidance (shared KDBX on a network share vs. sync conflicts) from a primary doc in this pass; the README only describes the offline encrypted file.
- Akeyless enterprise features (dynamic secrets, rotation, audit) are not documented in any OSS repo reviewed; all claims about them would be vendor marketing, so none are included.

---

## Kubernetes / GitOps integration: Sealed Secrets vs. External Secrets Operator

### Takeaway
These are not competitors; they answer different questions. **Sealed Secrets = "encrypt at author time, decrypt only in-cluster"** — zero external dependencies, zero CI secrets, but cluster-bound keys and write-only data. **ESO = "the provider is the source of truth, the cluster is a cache"** — full lifecycle from the provider, but you now have a second control plane with cluster-wide secret read access and a bootstrap credential to protect.

### Cited Findings

**Sealed Secrets mechanics**
- Two components: a cluster-side controller/operator and the client `kubeseal`; the `SealedSecret` CRD (`bitnami.com/v1alpha1`) carries `spec.encryptedData` and is "a recipe for creating a secret", analogous to Deployment→Pod ([README Overview](https://github.com/bitnami-labs/sealed-secrets)).
- Installation is a single `kubectl apply -f .../controller.yaml` into `kube-system`, or Helm/Kustomize; `kubeseal` ships via Homebrew, MacPorts, Nixpkgs, and release tarballs ([release v0.41.2 notes](https://github.com/bitnami-labs/sealed-secrets/releases/tag/v0.41.2)).
- **Scopes**: `strict` (default; name+namespace bound), `namespace-wide` (rename freely within a namespace), `cluster-wide` (any namespace, any name), selected with `--scope` or via annotations `sealedsecrets.bitnami.com/namespace-wide` / `cluster-wide` ([README Scopes](https://github.com/bitnami-labs/sealed-secrets)).
- **Multi-cluster**: each controller generates its own key pair, so a SealedSecret sealed for cluster A cannot be decrypted by cluster B — which is the security boundary *and* the operational tax ([third-party: Plural](https://www.plural.sh/blog/sealed-secrets-kubernetes-guide/); primary: [crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md) states the key pair is generated per controller and persisted in a Secret).
- **Key lifecycle**: renewal every 30 days by default; `--key-renew-period` accepts Go durations (no `d` unit); `0` disables; `--key-order-priority` chooses `CertNotBefore` (default) or `SecretCreationTimestamp` for which key is "latest" ([README Secret Rotation](https://github.com/bitnami-labs/sealed-secrets)).
- **Re-encryption** of existing SealedSecrets and "early key renewal" are documented advanced procedures; the docs stress that neither substitutes for rotating the underlying credentials ([README](https://github.com/bitnami-labs/sealed-secrets)).
- Release cadence is healthy: v0.41.2 and Helm chart 2.22.0 both published 2026-10-26 ([releases](https://github.com/bitnami-labs/sealed-secrets/releases)).

**ESO mechanics**
- Architecture: CRDs + a controller that "fetches secrets from an external API and creates Kubernetes secrets… If the secret from the external API changes, the controller will reconcile the state in the cluster and update the secrets accordingly" ([overview](https://external-secrets.io/latest/introduction/overview/)).
- Resource model: **`SecretStore`** (namespaced; auth + provider config), **`ClusterSecretStore`** (cluster-wide gateway), **`ExternalSecret`** (`refreshInterval`, `secretStoreRef`, `target.creationPolicy`, `data[]` with `remoteRef.key/version/property`, `dataFrom.extract`), plus `ClusterExternalSecret`, `PushSecret`, `ClusterPushSecret` ([overview](https://external-secrets.io/latest/introduction/overview/); [API nav](https://external-secrets.io/latest/introduction/overview/)).
- Reconciliation: resolve store by `spec.secretStoreRef` (and `spec.controller` class) → instantiate provider client from `SecretStore` credentials → fetch/decode → render `target.template` → keep in sync ([overview](https://external-secrets.io/latest/introduction/overview/)).
- **Provider breadth** is the moat: AWS Secrets Manager / Parameter Store / Certificate Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, **OpenBao**, **CyberArk Conjur**, **Akeyless**, 1Password (Connect + SDK), **Bitwarden Secrets Manager**, **Infisical**, Doppler, Keeper, Delinea, Passbolt, Pulumi ESC, GitLab variables, GitHub Actions secrets, IBM, Oracle, Scaleway, OVHcloud, Yandex, senhasegura, Fortanix, and more ([provider list](https://external-secrets.io/latest/introduction/overview/)).
- **Roles**: cluster operator owns ESO, provider access policies and `ClusterSecretStore`s; app developer owns `ExternalSecret`s; both roughly map to Kubernetes RBAC roles ([overview](https://external-secrets.io/latest/introduction/overview/)).
- **Explicit non-goal**: "There is no Secret Operator that handles the lifecycle of the secret, this is out of scope of ESO" ([overview](https://external-secrets.io/latest/introduction/overview/)).
- **Threat model highlights**: ESO has cluster-wide read/write on Secrets (A01); its provider credentials may grant full cloud access (A03); it can be abused to exfiltrate via malicious `ClusterSecretStore`/`ExternalSecret` resources (T05); controls are least-privilege RBAC (C02), policy engines such as Kyverno/OPA (C03), restricting `secretRef` auth and `namespaceSelector` usage, and disabling unused CRDs (C05) — and "ESO does not provide pre-packaged network policies / policies, and it is the user's responsibility" ([threat model](https://external-secrets.io/latest/guides/threat-model/)).
- **GitOps**: ESO documents a FluxCD example and the CRDs themselves are GitOps-friendly (declarative, reconciled) ([examples nav](https://external-secrets.io/latest/introduction/overview/)).

### Inferences
- The correct architectural read: Sealed Secrets is a *build-time sealing* tool with no runtime dependency; ESO is a *runtime sync* tool with a hard dependency on an external provider and on network egress. Choosing Sealed Secrets means you never have a "secret zero" in the cluster; choosing ESO means you always do (the `SecretStore` credential), and that credential is now the highest-value object in the cluster.
- ESO's threat model is unusually honest and is itself a useful checklist for any new tool: cluster-wide read, provider creds scope, exfiltration via CRs, supply chain, namespace escape.
- If a new tool wants GitOps adoption, the winning shape is "seal at author time like Sealed Secrets, but with a portable, non-cluster-bound key AND a read path for authorised humans" — that is precisely the gap neither incumbent fills.
- The 30-day automatic sealing-key renewal with retained old keys is a good pattern (no downtime, no re-encryption) but it creates unbounded key accumulation and a misleading sense of rotation; the docs' insistence that it is not rotation is the most important sentence on the page.

### Gaps
- No primary source quantifies Sealed Secrets adoption (downloads, clusters) — Docker Hub pulls exist as a badge but I did not record a number.
- Could not verify ESO's current CNCF maturity beyond Sandbox (accepted 2022-07-26); no graduation announcement was found ([CNCF project page](https://www.cncf.io/projects/external-secrets/)).
- Sealed Secrets has no foundation governance; I found no published governance doc, security policy beyond the repo, or roadmap. Whether Bitnami's corporate ownership changes affect long-term stewardship could not be determined from primary sources in this pass.

---

## Licensing, governance and community signals

### Takeaway
Licences here are a proxy for business model, and they predict the roadmap: **permissive + foundation** (SOPS MPL-2.0/CNCF, ESO Apache-2.0/CNCF, Sealed Secrets Apache-2.0/vendor, age BSD-3/single-author) versus **copyleft as a moat** (Teleport AGPL source + Apache binaries, Vaultwarden AGPL, Conjur LGPL server + Apache clients) versus **open-core with a commercial carve-out** (Infisical MIT + `ee/`, Akeyless essentially closed). Release cadence correlates with commercial backing, not with stars.

### Cited Findings

| Project | Licence | Governance / steward | Cadence evidence |
|---|---|---|---|
| SOPS | MPL-2.0 ([repo](https://github.com/getsops/sops)) | CNCF **Sandbox** since 2023; "new group of maintainers" after Mozilla donation ([docs](https://getsops.io/docs/)) | v3.13.1 2026-05-16, v3.13.2 2026-06-30, v3.13.3 2026-07-23 ([releases](https://github.com/getsops/sops/releases)) |
| age | BSD-3-Clause ([API](https://api.github.com/repos/FiloSottile/age)) | Author-led (Filippo Valsorda; designed with @benjojo per the README); spec at C2SP ([age-encryption.org/v1](https://age-encryption.org/v1)) | v1.3.0 2025-12-27, v1.3.1 2025-12-28, v1.3.2 2026-08-29 |
| git-crypt | GPL-3.0 ([API](https://api.github.com/repos/AGWA/git-crypt)) | Single author (Andrew Ayer) | 0.7.0 2022-04-21 → 0.8.0 2025-09-24; last push 2025-09-24 |
| Sealed Secrets | Apache-2.0 ([API](https://api.github.com/repos/bitnami-labs/sealed-secrets)) | Vendor-governed, `bitnami-labs` org; no foundation | v0.41.2 + helm 2.22.0 both 2026-10-26 |
| ESO | Apache-2.0 ([LICENSE](https://github.com/external-secrets/external-secrets)) | **CNCF Sandbox**, accepted **2022-07-26** ([CNCF](https://www.cncf.io/projects/external-secrets/)); site copyright "The Linux Foundation" ([overview footer](https://external-secrets.io/latest/introduction/overview/)) | v2.13.0 2026-10-16, v2.14.0 2026-10-23 (weekly) |
| Conjur OSS | **LGPL-3.0** server, **Apache-2.0** clients/extensions ([README License](https://github.com/cyberark/conjur)) | CyberArk; commercial licences offered; explicit migration path to CyberArk Secrets Manager Self-Hosted ([README](https://github.com/cyberark/conjur)) | v1.22.3 2025-09-24, v1.24.0 2025-11-20, v1.27.0 2026-06-16; last push 2026-07-14 |
| Teleport | Repo **AGPL-3.0**, `/api` **Apache-2.0**, Community Edition *binaries* under a **modified Apache-2.0** ([README License](https://github.com/gravitational/teleport)) | Gravitational/Teleport Inc. | v18.10.0 2026-07-09 |
| Vaultwarden | **AGPL-3.0** ([README badge](https://github.com/dani-garcia/vaultwarden)) | Community maintainers; "not associated with Bitwarden"; one maintainer employed by Bitwarden contributing on own time ([README Disclaimer](https://github.com/dani-garcia/vaultwarden)) | 1.37.2 2026-08-22, 1.37.3 2026-09-13, 1.37.4 2026-10-05 |
| KeePassXC | **GPL-2 or GPL-3** ([COPYING](https://github.com/keepassxreboot/keepassxc/blob/develop/COPYING)) | Community team | 2.7.12 2026-03-10, 2.8.0-beta1 2026-09-23, 2.8.0 2026-10-21 |
| gopass | MIT ([API](https://api.github.com/repos/gopasspw/gopass)) | Community | v1.17.2 2026-09-10, v1.17.3 2026-09-22, v1.17.4 2026-10-10 |
| pass | GPL-2.0-or-later upstream (not re-verified here); NOASSERTION on the GitHub mirror ([API](https://api.github.com/repos/zx2c4/password-store)) | Single author (Jason A. Donenfeld) | latest tag **1.7.4**; no newer tag |
| OpenBao | **MPL-2.0** ([LICENSE](https://github.com/openbao/openbao)) | **OpenSSF**-hosted (mailing list `lists.openssf.org`, OpenSSF Scorecard/Best Practices badges) ([README](https://github.com/openbao/openbao)); created 2023-11-09 | v2.7.2 2026-10-26 |
| Infisical | **MIT** except `ee/` (commercial) ([LICENSE](https://github.com/Infisical/infisical/blob/main/LICENSE)) | Company (Infisical Inc.) | v0.167.2/3/4 all 2026-10-23→26 |

- SOPS release provenance is unusually strong for an OSS CLI: checksums are **Cosign**-signed with GitHub OIDC, and **SLSA provenance** + SBOMs are attached to releases ([release v3.13.3 notes](https://github.com/getsops/sops/releases/tag/v3.13.3)).
- OpenBao's README frames the project explicitly around licence continuity: "provide this software under an OSI-approved open-source license, led by a community run under open-governance principles" ([README](https://github.com/openbao/openbao)); the LICENSE retains "Copyright (c) 2015 HashiCorp, Inc." with MPL-2.0 ([LICENSE](https://github.com/openbao/openbao)).
- Conjur's README states the server is LGPL-3.0 "to ensure that all contributions to the Conjur server are made available to the community" with "Commercial licenses also available from CyberArk" ([README License](https://github.com/cyberark/conjur)).

### Inferences
- Licence choice tracks the monetisation model almost perfectly: the file-format tools that want to be *embedded* are permissive (MPL/BSD/Apache); the products that want to be *sold as infrastructure* are copyleft or open-core (AGPL/LGPL/`ee/`).
- For a new tool that wants ecosystem adoption, MPL-2.0 or Apache-2.0 with a foundation home is the low-friction path; AGPL kills embedding in commercial products and `ee/` carve-outs create a due-diligence question ("which features will move behind the line?").
- Star counts and release cadence diverge sharply: Vaultwarden has 69.9k stars and monthly releases; SOPS has 23.6k stars, a 466-item backlog and a ~3-month gap since its last release while still being the de-facto GitOps standard. Popularity ≠ maintenance capacity.
- Conjur's cadence (≈2 releases in 12 months, last push 2026-07-14) plus an in-README migration guide to a commercial product is the clearest "soft-deprecation" signal in the survey; treat Conjur OSS as **maintenance-mode for new designs**.

### Gaps
- CLA/DCO status was not verified for any project; none of the repos' CONTRIBUTING files were read in this pass, so claims about contributor licence agreements would be speculation.
- Security-audit status (third-party audits, CVE history) was not verified for any project except where release notes mention fixes; this is a material gap for a procurement decision.
- No reliable download/adoption telemetry exists for CLI tools (SOPS, age, git-crypt); GitHub stars and distro packaging are the only public signals, and distro packaging was not enumerated.

---

## Documented pain points (with primary-source evidence)

### Takeaway
The recurring failures are structural, not bugs: **key sprawl** (N files × M recipients, no central directory), **offboarding** (no revocation primitive in git-crypt; bulk `updatekeys` in SOPS), **recovery** (Sealed Secrets and Vaultwarden both say "back it up or lose it"), **multi-environment/multi-cluster duplication** (Sealed Secrets' per-cluster keys), and **Windows/second-class-platform support** (git-crypt has no native Windows build after 13 years).

### Cited Findings

**Key sprawl and rotation**
- SOPS keeps a wrapped copy of each file's data key per recipient inside every file; the recipient list is duplicated in `.sops.yaml` and in each file's `sops` metadata, so a recipient change is a repo-wide rewrite ([Reference](https://getsops.io/docs/reference/); [Key management](https://getsops.io/docs/usage/key-management/)).
- Rotation is a two-command, order-sensitive procedure after compromise (`updatekeys` then `rotate --in-place`), documented with a footnote about the failure mode if the order is wrong ([Key management](https://getsops.io/docs/usage/key-management/)).
- Open SOPS issues show persistent KMS-rotation confusion: **#1135 "Is AWS KMS automatic key rotation compatible with SOPS?"** (open, 6 comments) and **#1227 "Can SOPS be used with AWS KMS keys that have automatic rotation turned on?"** (open, 2 comments) ([issue search](https://api.github.com/search/issues?q=repo:getsops/sops+rotation+in:title)).
- A data-loss-class bug existed in rotation: **#855 "sops truncates the file to zero after a failed key rotation"** (closed, 6 comments) ([issue](https://api.github.com/search/issues?q=repo:getsops/sops+rotation+in:title)).
- Sealed Secrets' key renewal retains old keys indefinitely and is explicitly *not* rotation; users repeatedly mistake it for rotation — the README devotes a "Common misconceptions about key renewal" section to this ([README](https://github.com/bitnami-labs/sealed-secrets)).

**Revocation / offboarding**
- git-crypt: no `del-gpg-user`, no key rotation, no revocation, by design and documented as an inherent property of encrypting history ([README](https://github.com/AGWA/git-crypt); [issue #47](https://github.com/AGWA/git-crypt/issues/47)).
- Sealed Secrets: revoking a user's ability to seal for a cluster requires rotating the sealing key and re-sealing every secret; losing the key requires "regenerate new passwords for everything" ([README FAQ](https://github.com/bitnami-labs/sealed-secrets)).

**Recovery / disaster**
- Sealed Secrets discussion **#1521** captures the community's core anxiety: "If I ever lose the private key… every single SealedSecret that I do not have in plain form anymore, is effectively a goner" ([discussion](https://github.com/bitnami-labs/sealed-secrets/discussions/1521)).
- Vaultwarden disclaims liability for data loss and pushes backups onto the operator ([README Disclaimer](https://github.com/dani-garcia/vaultwarden)).

**Multi-environment / multi-cluster**
- Sealed Secrets: "Each controller in each cluster generates its own unique encryption key. A secret sealed for one cluster's public key cannot be decrypted by a different cluster's controller… it creates challenges for multi-cluster management" ([third-party: Plural](https://www.plural.sh/blog/sealed-secrets-kubernetes-guide/)); primary confirmation that keys are per-controller ([crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md)).
- ESO: multi-tenancy and controller classes exist but the docs call multiple controllers "not widely tested" ("Testers welcome. This is not widely tested.") ([overview](https://external-secrets.io/latest/introduction/overview/)).

**Windows support**
- git-crypt: **#13 "Add Windows support."** open with 32 comments; **#22 "Windows support"** open with 15 comments; **#84 "Add Windows compilation instructions"** open; **#336 "Windows release build silently failed for 0.8.0, no exe published"** ([issue search](https://api.github.com/search/issues?q=repo:AGWA/git-crypt+windows+in:title)). The README also warns it "does not work reliably with some third-party git GUIs, such as Atlassian SourceTree and GitHub for Mac. Files might be left in an unencrypted state" ([README](https://github.com/AGWA/git-crypt)).
- By contrast age ships `winget`, Chocolatey and Scoop packages ([README](https://github.com/FiloSottile/age)); gopass ships WinGet/Chocolatey/Scoop ([README](https://github.com/gopasspw/gopass)); SOPS ships Windows binaries ([release notes](https://github.com/getsops/sops/releases/tag/v3.13.3)).

**Format / tooling friction**
- SOPS does not support YAML **anchors** ("SOPS uses the path to a value as additional data in the AEAD encryption, and thus dynamic paths generated by anchors break the authentication step") and does not support **top-level arrays** in YAML or JSON ("SOPS needs a top-level `sops` key to store its metadata") ([Reference](https://getsops.io/docs/reference/)). Both are common in real manifests.
- git-crypt: encrypted files are not compressible and "even the smallest change… requires git to store the entire changed file, instead of just a delta"; encrypted files "cannot be patched with git-apply, unless the patch itself is encrypted" ([README](https://github.com/AGWA/git-crypt)).
- ESO: no packaged NetworkPolicies or admission policies — "it is the user's responsibility to implement the necessary security controls" ([threat model](https://external-secrets.io/latest/guides/threat-model/)).
- pass: last tag 1.7.4; the project is effectively feature-frozen while its ecosystem (clients, gopass) moved on ([tags API](https://api.github.com/repos/zx2c4/password-store/tags); [gopass README](https://github.com/gopasspw/gopass)).
- Conjur OSS: README now leads with a migration path to the commercial CyberArk Secrets Manager Self-Hosted ([README](https://github.com/cyberark/conjur)).

### Inferences
- Key sprawl is a *consequence of the file format*, not of user discipline: if each file stores its own recipient set, then "who can read what" is only discoverable by scanning every file. Any new tool should keep a single policy file that is the sole source of truth and have ciphertext reference a policy ID rather than embedding recipients.
- The most damaging documented failure is not a break — it is a **silent** one: git-crypt leaving files unencrypted because `.gitattributes` wasn't in place yet, or a GUI leaving them decrypted. Encryption tools must fail closed and verify on write.
- Windows is a reliable proxy for "is this tool maintained by a team or a person": every single-maintainer tool in this survey has weak or absent Windows support, and every commercially backed one ships Windows binaries.
- ESO's "not widely tested" multi-controller note and Sealed Secrets' per-cluster key model together explain why multi-cluster secret management is the most common reason teams migrate to a centralised system.

### Gaps
- No quantitative data on how often SOPS files are mis-encrypted (e.g. committed plaintext) or how large typical recipient sets are; the claims are qualitative.
- I could not verify whether SOPS has an open issue for "offboarding requires touching every file" — the behaviour is documented but the pain is inferred, not quoted.
- KeePassXC sync-conflict pain (shared KDBX on cloud drives) is widely reported anecdotally but I found no primary-source statement in the README; treat as unverified.

---

## What a new tool should adopt — and which traps to avoid

### Takeaway
Adopt the **SOPS diff contract** (per-value AEAD, cleartext keys, `textconv` review), the **age recipient primitive** (small keys, SSH-key compatibility, hybrid post-quantum), the **Sealed Secrets write-only sealing** idea for CI, and the **ESO provider abstraction** for reading from systems you don't own. Avoid **per-file recipient lists**, **cluster-bound keys**, **deterministic whole-file encryption**, **open-core licence ambiguity**, and **audit-free decryption**.

### Cited Findings (design precedents worth copying, each with its source)

1. **Per-value AEAD with the key path as associated data** — gives reviewable one-line diffs, mergeable concurrent edits, and detects structural tampering ([SOPS Reference](https://getsops.io/docs/reference/); motivation in [SOPS Security](https://getsops.io/docs/security/)).
2. **Cleartext keys, encrypted values** — a deliberate trade so reviewers can see *which* secret changed; the docs acknowledge keys must not be sensitive ([SOPS Reference](https://getsops.io/docs/reference/)).
3. **Envelope encryption with `updatekeys` separate from `rotate`** — re-wrap the DEK for onboarding/offboarding without re-encrypting values; rotate the DEK only on compromise; documented ordering ([SOPS Key management](https://getsops.io/docs/usage/key-management/)).
4. **Key groups + `shamir_threshold >= 2`** — n-of-m approval/escrow inside a file format ([SOPS Reference](https://getsops.io/docs/reference/)).
5. **Offline recovery recipient as a first-class recommendation** — "two KMS master keys in different regions and one PGP public key with the private key stored offline" ([SOPS Security](https://getsops.io/docs/security/)).
6. **Recipient ergonomics from age** — `age1…` keys, SSH public keys as recipients, multi-identity decryption, recipient files, and hardware PIV via plugin ([age README](https://github.com/FiloSottile/age)).
7. **Post-quantum hybrid recipients** — ML-KEM-768 + X25519 HPKE, `age1pq1…`, opt-in via `age-keygen -pq` ([age v1.3.0](https://github.com/FiloSottile/age/releases/tag/v1.3.0)).
8. **Write-only sealing for CI** — `kubeseal` encrypts with a public cert; CI never needs a decryption key ([Sealed Secrets README](https://github.com/bitnami-labs/sealed-secrets); [crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md)).
9. **Cryptographic scope binding** — OAEP `label` = namespace+name makes relocation attacks fail at the crypto layer, not at an admission policy ([crypto doc](https://github.com/bitnami-labs/sealed-secrets/blob/main/docs/developer/crypto.md)).
10. **Provider fan-in over provider replacement** — ESO's value is that it does not ask you to move your secrets; it adapts to ~40 backends including OpenBao, Conjur, Akeyless, Infisical, 1Password, Bitwarden ([ESO overview](https://external-secrets.io/latest/introduction/overview/)).
11. **Explicit, published threat model** — ESO enumerates assets (A01–A04), threats (T01–T07) and controls (C01–C05) in public docs ([ESO threat model](https://external-secrets.io/latest/guides/threat-model/)).
12. **Supply-chain credibility** — Cosign-signed checksums, SLSA provenance, SBOMs on every release is now table stakes for a security tool ([SOPS v3.13.3](https://github.com/getsops/sops/releases/tag/v3.13.3)).
13. **Short-lived credentials instead of stored ones** — Teleport's "without long-lived keys or passwords" plus session recording is the correct end state for infrastructure access ([Teleport README](https://github.com/gravitational/teleport)).
14. **Dynamic secrets** — OpenBao's on-demand generation removes rotation as a human task ([OpenBao README](https://github.com/openbao/openbao)); Conjur's rotators are the same idea in policy form ([Conjur README](https://github.com/cyberark/conjur)).
15. **Team UX beats crypto purity** — Vaultwarden's organisations/collections/roles/groups/event logs are why a Rust reimplementation out-stars every "serious" secret tool ([Vaultwarden README](https://github.com/dani-garcia/vaultwarden)).

### Inferences — the adopt/avoid list

**Adopt**
- A **single policy file as the only source of truth** for recipients, with ciphertext referencing a policy/recipient-set ID; a `doctor`/`grep` command that answers "which files still wrap key X?".
- **Two-tier rotation**: `rewrap` (cheap, on every onboarding/offboarding) vs. `rotate` (new DEK, on compromise), with the ordering enforced by the tool, not by documentation.
- **Fail-closed encryption**: verify on write that the file actually got encrypted (defeats the git-crypt `.gitattributes` ordering trap), and refuse to commit plaintext.
- **First-class diff UX**: ship the `.gitattributes` snippet and diff driver; make `git diff` show plaintext for authorised users without a wrapper script.
- **n-of-m approval** for production secrets (Shamir key groups) exposed as a policy, not a YAML footnote.
- **Write-only sealing path** so CI can produce ciphertext without holding any decryption key; plus a separate, audited read path for humans.
- **Provider adapters** for the systems teams already own (AWS/GCP/Azure/Vault/OpenBao/1Password) rather than a new store of record.
- **Post-quantum-ready recipient format** from day one (hybrid ML-KEM), because re-keying a format later is a migration project.
- **Signed decryption receipts**: append-only, per-recipient log of "who decrypted what, when, from where", even if it's local + optional push. This is the missing feature in every file-based tool surveyed.

**Avoid**
- **Embedding recipient lists in each file** (SOPS's model) — it is the direct cause of key sprawl and bulk-offboarding pain ([SOPS Reference](https://getsops.io/docs/reference/)).
- **Cluster-bound keys** (Sealed Secrets) — elegant isolation, but it makes multi-cluster and disaster recovery a manual, error-prone ritual ([Sealed Secrets FAQ](https://github.com/bitnami-labs/sealed-secrets); [Plural](https://www.plural.sh/blog/sealed-secrets-kubernetes-guide/)).
- **Deterministic whole-file encryption** (git-crypt) — leaks file equality and length, and cannot be revoked ([git-crypt README](https://github.com/AGWA/git-crypt)).
- **Metadata leakage by default** — SOPS leaves keys, structure, file names and change timing in the clear; acceptable for config, unacceptable for e.g. customer data. Make it a documented, tunable trade.
- **Open-core ambiguity** — an `ee/` directory means a due-diligence question about which features stay open ([Infisical LICENSE](https://github.com/Infisical/infisical/blob/main/LICENSE)).
- **OSS-as-marketing** — a community org whose repos have 0–2 stars is not a community ([Akeyless org](https://api.github.com/orgs/akeyless-community/repos)).
- **Vendor-only governance for a security primitive** — Sealed Secrets and Conjur both show the risk: one has no foundation and no published governance; the other now ships a migration guide to a paid product ([Conjur README](https://github.com/cyberark/conjur)).
- **"Not widely tested" multi-tenancy** — if the tool cannot run multiple controllers/tenants cleanly, teams will hit it in year two ([ESO overview](https://external-secrets.io/latest/introduction/overview/)).
- **Requiring cluster read access to answer "what is in this secret?"** — write-only is a CI feature, not an operational model.

### Gaps
- No primary source describes a production system that combines file-based encryption with per-recipient scoping or decryption audit; the recommendation above is a synthesis, not an observed implementation.
- I did not verify whether any 2026 project already implements "policy-ID references instead of embedded recipients"; absence of evidence here is weak evidence of absence, and the report-writer should treat novelty claims cautiously.

---

## Confidence, conflicts and items explicitly not verified

- **High confidence** (primary docs, read in full): SOPS encryption protocol, `.sops.yaml` schema, rotation ordering, YAML anchor/top-level-array limits; age recipient/identity model and v1.3.0 post-quantum recipients; git-crypt crypto and its stated limitations (no revocation, metadata leaks, GUI issues); Sealed Secrets crypto, scopes, key renewal and backup/DR; ESO resource model, provider list, threat model and explicit "no lifecycle management"; licence texts for SOPS/age/git-crypt/ESO/Teleport/Conjur/OpenBao/Infisical/KeePassXC.
- **Medium confidence**: star/fork counts and release dates (GitHub API snapshots on 2026-10-30; `open_issues_count` includes PRs, and counts move daily); "Conjur is in maintenance mode" (inference from cadence + migration guide, not a vendor statement); "Flux has first-class SOPS support" (the guide exists in Flux's core docs nav; I did not read the guide body).
- **Low confidence / explicitly unverified**:
  - Bitnami/Broadcom corporate parentage of Sealed Secrets and any effect on its roadmap — not verified in this pass; do not assert.
  - HashiCorp Vault's exact current licence text (the BSL change is context for OpenBao's existence, but I did not fetch Vault's LICENSE).
  - CLA vs. DCO for every project.
  - Third-party security audits for every project.
  - Akeyless core licence terms and enterprise feature set.
  - KeePassXC team-sharing/sync-conflict guidance.
  - Any adoption numbers beyond GitHub stars.
- **Conflicts observed**: none material. The only tension is between Sealed Secrets' marketing ("safe to store — even inside a public repository") and its own FAQ (loss of the sealing key is unrecoverable, and the docs recommend backing up a private key out of the cluster); both are on the same page and should be presented together, not as a contradiction.
- **Stale/dormant projects to flag in any comparison**: **pass** (last tag 1.7.4, no newer release), **git-crypt** (0.8.0 in Sept 2025 was the first release since April 2022; last push 2025-09-24), **Conjur OSS** (last release 2026-06-16, last push 2026-07-14, commercial migration path in the README). **Actively maintained**: SOPS, age, gopass, KeePassXC, Vaultwarden, Sealed Secrets, ESO, Teleport, OpenBao, Infisical.

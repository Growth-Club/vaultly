# Enterprise PAM and Consumer/Team Password Manager Feature Parity (October 2026)

**Access date: every URL in this document was retrieved on 30 October 2026.** Where a source carries its own publication or update date (press release, support article, report), that date is given in the citation.

**Scope.** Ten products: CyberArk (now branded **Idira**, see below), BeyondTrust, Delinea, Keeper, LastPass, Dashlane, NordPass, Proton Pass, 1Password, Bitwarden. Two distinct markets are covered deliberately: enterprise PAM (CyberArk/Idira, BeyondTrust, Delinea, plus Keeper's PAM add-ons) and workforce/SMB password managers (the other seven, plus Bitwarden Enterprise).

**Citation discipline.** Findings are tagged **[vendor claim]** when the only source is the vendor's own marketing, pricing, or documentation page, and **[independent]** when the source is a third party (regulator, court record, pricing benchmark, analyst). Vendor claims about certifications are *not* independently verified in this pass; see the Gaps in each section.

**Structural change to flag up front:** CyberArk's privileged-access products are now marketed as **Idira** by Palo Alto Networks. CyberArk's own community FAQ states that "Beginning May 31, 2026, customers will begin to see some brand changes with their CyberArk products and services" under the name Idira — [CyberArk is now Idira: FAQ](https://community.cyberark.com/s/article/CyberArk-is-now-Idira-Frequently-Asked-Questions). As of this writing, `cyberark.com/products/privileged-access-manager/` resolves to the Idira PAM page on paloaltonetworks.com — [Idira Privileged Access Management](https://www.paloaltonetworks.com/idira/human/privileged-access-management). Any competitive analysis written before mid-2026 that says "CyberArk" is referring to the same product line now sold as Idira.

---

## Identity: SSO/SAML/OIDC, SCIM provisioning, passkeys, MFA, passwordless, directory sync

### Takeaway
SSO plus SCIM/directory sync is the single hardest tier boundary in the consumer/team market: it is almost always the feature that forces an upgrade from the "team" plan to the "business/enterprise" plan. Passkeys and MFA are now universal, but "passwordless vault login" is where vendors diverge: Keeper and LastPass document passkey/FIDO2 *vault* login explicitly, while Bitwarden sells "passwordless SSO" and 1Password's passkey support is documented without a clear public statement that it replaces the account password.

### Cited Findings

**1Password**
- Automated provisioning (SCIM) is documented for Okta, Microsoft Entra ID, OneLogin, and JumpCloud, and is positioned as a 1Password **Business** capability. Groups holding `Recover Accounts` or `Manage All Groups` permissions are deliberately excluded from automated management "to prevent automated provisioning from having account-wide cryptographic access" — [1Password support: Set up automated provisioning](https://support.1password.com/provisioning) **[vendor claim]**
- Vault access is assigned "by roles and groups, synced from your IdP"; sign-in, item-access, and audit events stream to a SIEM, and compromised accounts can be auto-suspended — [1Password Enterprise Password Manager](https://1password.com/product/enterprise-password-manager) **[vendor claim]**
- Trust center lists MFA and passkey-support documentation as product-security artifacts — [1Password Trust Center](https://trust.1password.io/) **[vendor claim]**

**Bitwarden**
- Teams ($4/user/mo) explicitly includes "Synchronize your existing directory" and "Automate provisioning with SCIM"; Enterprise ($6) adds "Passwordless SSO integration" and "Granular access control" — [Bitwarden pricing](https://bitwarden.com/pricing/) **[vendor claim]**
- Directory sync + SCIM at the *entry* business tier is unusual in this set and is Bitwarden's main structural differentiator against LastPass/Proton/NordPass, which gate it higher.

**Keeper**
- SAML 2.0 SSO, SCIM, AD/LDAP sync (via Keeper Bridge), and Entra ID/Okta/Ping integrations are **Enterprise-only** in the published comparison chart; Business and Business Starter get only basic 2FA (SMS, authenticator, smartwatch, security keys) — [Keeper Business pricing and feature comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**
- Keeper supports "biometric login with passkeys" that "replaces all traditional login methods — including master password, SSO, and 2FA," plus DUO and RSA for advanced 2FA (Enterprise) — same page **[vendor claim]**

**LastPass**
- Federated login (SAML via existing IdP) and directory integrations (AD, Entra ID, Google Workspace, OneLogin, Okta) are **Business-tier and above**; Teams gets none — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**
- Business SSO is capped at **3 SSO apps**; only Business Max gets "Unlimited SSO," advanced MFA, contextual authentication policies, workstation MFA, and MFA for identity providers — same page **[vendor claim]**
- FIDO2 passwordless *vault* login is included on every tier including Free/Premium, but hardware keys require Premium — same page **[vendor claim]**

**Dashlane**
- SSO and SCIM are bundled into the "Password Management" product; SIEM integration is **not** — it sits in the separate "Credential Protection" product — [Dashlane business pricing](https://www.dashlane.com/pricing) **[vendor claim]**
- Yubico is listed as a supported integration in Password Management — same page **[vendor claim]**

**NordPass**
- Teams tier SSO is **Google Workspace only**; Business adds nothing on identity; **Enterprise** adds SSO with Entra ID, MS ADFS and Okta plus "automatic user access management via Entra ID and Okta" (i.e., provisioning) — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- This is the clearest example in the set of identity features being held back two tiers.

**Proton Pass**
- SSO and SCIM appear only on **Pass Professional**; Pass Essentials (3–30 users) does not have them. Professional also adds group management, activity log, SIEM integration, enterprise policies, CLI, SSH agent, and "Proton Sentinel" advanced account protection — [Proton Pass for Business](https://proton.me/business/pass) and [plan comparison](https://proton.me/business/pass/pricing) **[vendor claim]**

**PAM suites**
- Idira claims "phishing-resistant authentication," zero standing privileges, and unification of "IAM, PAM and IGA" into a single policy engine; it explicitly frames JIT vs ZSP: "JIT is a mechanism that enables existing privileges for a set window, while ZSP is an operating model where identities have no entitlements by default" — [Idira PAM](https://www.paloaltonetworks.com/idira/human/privileged-access-management) **[vendor claim]**
- BeyondTrust integrates with IAM/IGA (SailPoint IdentityIQ/IdentityNow bi-directional) rather than replacing them — [BeyondTrust Password Safe](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**
- Delinea Secret Server supports RBAC and approval workflows; its platform markets "Just in Time & Zero Standing Privilege" as a separate solution area — [Delinea Secret Server](https://delinea.com/products/secret-server), [Delinea ZSP](https://delinea.com/solutions/zero-standing-privilege) **[vendor claim]**

### Inferences
- For a product aimed at teams under ~50 people, **SSO (OIDC/SAML) is table stakes; SCIM is not** — SCIM only becomes mandatory once the buyer has an IdP with lifecycle automation and >50–100 seats. Bitwarden is the outlier proving SCIM *can* be cheap to offer.
- "Passwordless" is used by vendors to mean three different things: (a) passkey unlock of the vault, (b) SSO without a master password, (c) FIDO2 hardware key. Any comparison table must disambiguate or it will be wrong.
- Passkey *storage* is fully commoditized by 2026: every one of the seven workforce products claims it.

### Gaps
- Could not verify whether 1Password supports OIDC as well as SAML for SSO; its public pages describe IdP sync/SSO generically without naming protocols. 1Password's trust center has a FedRAMP FAQ but no FedRAMP authorization is listed among certifications — treat FedRAMP status as **unverified**.
- No primary source found for NordPass SCIM specifically (its page says "automatic user access management," which may be SCIM-based provisioning or a proprietary sync).
- CyberArk/Idira, Delinea, and BeyondTrust certification and protocol specifics (SAML vs OIDC, SCIM support) were not documented on the pages reviewed; their identity integration is typically via the customer's IdP/IGA rather than a bundled IdP.

---

## Authorization: roles, groups, least privilege, just-in-time access, approvals, break-glass/emergency access

### Takeaway
This is the sharpest dividing line in the entire market. Consumer/team password managers ship **RBAC-lite (groups + folder/collection permissions) and, at most, an emergency-access feature**. Real JIT, approval chains, session brokering, and break-glass are PAM-suite capabilities, and in the team-PM world they exist only as paid add-ons (Keeper) or as adjacent products (1Password Privileged Access, Bitwarden's 2026 "privileged controls").

### Cited Findings

**Team/workforce password managers**
- **1Password:** team permissions are item-level and explicit — view, create, edit, archive, delete — with vault access assigned by roles and groups from the IdP — [1Password EPM](https://1password.com/product/enterprise-password-manager) **[vendor claim]**. Important nuance: 1Password's public "Access requests" feature is part of **SaaS Manager** and governs access to *SaaS apps* (birthright vs on-demand, approval chains, Slack/Teams approvals, auto-removal after a time limit), **not** just-in-time access to vault secrets — [1Password Access requests](https://1password.com/features/access-requests) **[vendor claim]**. 1Password sells JIT privileged access as a separate product ("Zero standing privileges," "intent-based dynamic guardrails") — [1Password pricing/platform](https://1password.com/pricing) **[vendor claim]**.
- **Keeper:** Enterprise adds "role-based access control" and "advanced admin controls [that] support least-privilege permissions"; a "share admin role" grants elevated rights over shared records. JIT elevation with approval workflow, ephemeral accounts, and approvals surfaced in ServiceNow/Jira/Slack/Teams are **KeeperPAM add-ons**, not password-manager features — [Keeper pricing comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**.
- **Bitwarden:** Enterprise adds "granular access control"; collections + groups are the permission model. Bitwarden began shipping "time-bound credential leasing, automated password rotation, and access rules" in 2026 — a PAM-adjacent capability announced on its own blog — [Bitwarden blog link surfaced on Send page](https://bitwarden.com/blog/bitwarden-privileged-controls-secure-your-most-sensitive-accounts-in-minutes/) **[vendor claim]**. No native approval-chain/JIT workflow for ordinary vault items was found.
- **LastPass:** groups + "customizable user management... different admin roles" on Business; no JIT or approval workflow documented — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**.
- **Dashlane / NordPass / Proton Pass:** collections/shared folders/groups respectively; no approval or JIT mechanism found on their business pages — [Dashlane](https://www.dashlane.com/pricing), [NordPass](https://nordpass.com/business-password-manager/), [Proton](https://proton.me/business/pass) **[vendor claim]**.

**Emergency / break-glass (consumer-grade)**
- Bitwarden: "Emergency Access — designate other Bitwarden users as emergency contacts who can request access to your vault in case of emergencies" (Premium and above) — [Bitwarden pricing](https://bitwarden.com/pricing/) **[vendor claim]**
- LastPass: emergency access grants another LastPass user one-time access; available on Premium/Families/Plus, not Free — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**
- 1Password: no consumer "emergency access" feature was found on the pages reviewed (it historically relied on the Emergency Kit + family organizer recovery). **Gap** — do not assert either way without checking 1Password support.

**PAM suites**
- **Idira:** "Ephemeral privileges are created only when a task starts and destroyed automatically when work ends"; JIT entitlements replace static IAM roles for AWS/Azure/GCP/Kubernetes; sessions are isolated, recorded, and summarized by AI in real time; third-party/vendor access is browser-based, agentless, JIT-scoped, and recorded — [Idira PAM](https://www.paloaltonetworks.com/idira/human/privileged-access-management) **[vendor claim]**
- **Delinea Secret Server:** "check-in/out, role-based access, and approval workflows"; "record and monitor every privileged session with detailed audit trails"; Resilient Secrets for availability — [Delinea Secret Server](https://delinea.com/products/secret-server) **[vendor claim]**
- **BeyondTrust Password Safe:** "Just-in-Time Access Control... considering the day, date, time, and location a user, machine, or AI agent accesses resources"; admins can "record, lock, and document suspicious behavior, with the ability to lock or terminate sessions"; the product FAQ links a dedicated whitepaper on accessing privileged passwords in **break-glass** scenarios — [BeyondTrust Password Safe](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**

### Inferences
- Break-glass in PAM is an *operational procedure plus a sealed credential*, not a UI feature; the BeyondTrust whitepaper framing (recover access to the vault when normal auth is down) is the honest definition. Consumer "emergency access" (Bitwarden/LastPass) is a different, weaker thing: a delegate can request access after a waiting period.
- Keeper is the only vendor in this set that sells JIT/approvals *inside the same SKU family* as the password manager, which is why it appears in both the SMB and PAM shortlists.
- If a product has no server, it cannot enforce approvals or JIT against a determined local user; it can only *record* that policy was followed. This is a hard architectural limit, not a feature gap (see the local-first section).

### Gaps
- No public documentation found on **quorum/multi-party break-glass** (e.g., M-of-N approval) for any of these vendors. Idira, Delinea and BeyondTrust likely support it via approval workflows but I could not verify.
- Could not verify whether Bitwarden's 2026 "time-bound credential leasing" applies to ordinary vault items or only to its Secrets Manager / privileged-controls module.

---

## Sharing: vaults/collections, granular item sharing, expiring links, guest accounts, external sharing controls

### Takeaway
Expiring, recipient-restricted sharing links to **non-users** is the most commonly underestimated requirement, because it needs a hosted link service — it cannot be done by a purely local CLI. It is a *differentiator among the leaders* rather than a universal table stake: Bitwarden, 1Password, Keeper and Proton document it; Dashlane, NordPass and LastPass do not on the pages reviewed. PAM suites solve the same problem differently: time-boxed, recorded, brokered sessions rather than links.

### Cited Findings
- **Bitwarden Send:** end-to-end encrypted text/file sharing to people without a Bitwarden account; expiry from **1 hour to 30 days**, optional password, max-access count, "destruct-on-open," available in web, mobile, extensions, desktop, **and CLI** — [Bitwarden Send](https://bitwarden.com/products/send/) **[vendor claim]**
- **1Password (Psst!):** generate a link to nearly any vault item for people who don't use 1Password; restrict to specific email addresses or anyone with the link; **choose when the link expires**; team sharing supports read-only vs full-edit access, groups, and IP-address restrictions on retrieval — [1Password secure password sharing](https://1password.com/features/secure-password-sharing) **[vendor claim]** (note: the page still brands the feature "Psst!", which 1Password has been de-emphasizing; treat the branding as stale but the capability as current)
- **Keeper:** "Bidirectional One-Time Share" lets you share with non-Keeper users with E2E encryption and *bidirectional editing*; "Time-limited access and self-destructing records" share outside the org and auto-delete the record and disable the link at a specified time — [Keeper pricing comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**
- **Proton Pass:** "Secure vault, item and link sharing" on all business tiers; group sharing only on Professional; a customer quote cites "secure links to facilitate temporary external sharing" as a heavily used workflow at SPIE (55,000 employees) — [Proton Pass for Business](https://proton.me/business/pass) **[vendor claim / customer testimonial]**
- **LastPass:** shared folders on all business tiers; one-to-one sharing on personal plans; **no expiring external link** feature was found on the pricing page — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**
- **Dashlane:** "Collections — Unlimited" and "Secure Sharing" in Password Management; no expiring-link or guest-account feature documented on the pricing page — [Dashlane pricing](https://www.dashlane.com/pricing) **[vendor claim]**
- **NordPass:** Shared Folders for group/folder-level sharing; no expiring-link or guest feature documented — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **PAM:** external/vendor access is granted as a JIT, isolated, recorded session (Idira: "browser-based, JIT access scoped to specific tasks with full session recording"); BeyondTrust sells Privileged Remote Access for third-party users — [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management), [BeyondTrust PRA](https://www.beyondtrust.com/products/privileged-remote-access) **[vendor claim]**

### Inferences
- "Guest account" is largely disappearing as a concept: the 2026 pattern is **link-based, expiry-bound, recipient-constrained sharing with no account creation**. That is cheaper to operate and better for external contractors, but it requires the server to hold ciphertext and enforce expiry/access counts.
- Keeper's bidirectional one-time share (external recipient can edit) is unusual and is effectively a lightweight guest collaboration primitive.
- Sharing *inside* an org has converged on three nouns: vault (1Password), collection (Bitwarden/Dashlane), shared folder/team folder (Keeper/NordPass/LastPass/Proton). The nouns differ; the model (many items, many users, role per user) does not.

### Gaps
- Could not verify whether Dashlane, NordPass, or LastPass offer expiring external links at all; absence from the pricing page is weak evidence of absence. Mark as unverified rather than "no."
- No source found on external-sharing *domain allowlists* or "block sharing outside verified domains" for the SMB products, which is a common enterprise control. Idira/BeyondTrust handle this via brokered access, not sharing policy.

---

## Audit/compliance: audit logs, SIEM export, session recording, certifications, data residency

### Takeaway
Every paid business tier logs activity; **SIEM export is the monetized line** (Keeper requires the ARAM add-on, Dashlane puts it in a different product, NordPass puts it in Enterprise, LastPass in Business+). Session recording exists **only** in PAM suites and as a Keeper add-on — no consumer/team password manager in this set records sessions. Certifications cluster at SOC 2 Type II + ISO 27001; FedRAMP is rare and, where present, scoped to a government cloud.

### Cited Findings

**Audit logs and SIEM**
- **Bitwarden:** Teams includes "Audit activity with event logs"; Enterprise adds "Access Intelligence risk remediation" — [Bitwarden pricing](https://bitwarden.com/pricing/) **[vendor claim]**
- **Keeper:** Activity reporting on all business tiers; **SIEM integration requires the Advanced Reporting & Alerts Module (ARAM) add-on**, as does compliance reporting — [Keeper pricing comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**
- **Dashlane:** SIEM integration and IGA/SOAR integrations appear only under "Credential Protection," not "Password Management" — [Dashlane pricing](https://www.dashlane.com/pricing) **[vendor claim]**
- **NordPass:** Activity Log on all business tiers; Microsoft Sentinel and Splunk integrations only on **Enterprise** — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **Proton Pass:** "Detailed activity logs" and "SIEM integration" only on Professional — [Proton Pass pricing](https://proton.me/business/pass/pricing) **[vendor claim]**
- **LastPass:** "Basic reporting" on Teams vs "Advanced reporting... plus SIEM integrations" on Business; SIEM targets named as Splunk and Microsoft Sentinel — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**
- **1Password:** streams "every sign-in, item access, and audit event to your SIEM," with named integration examples including CrowdStrike — [1Password EPM](https://1password.com/product/enterprise-password-manager) **[vendor claim]**
- **PAM:** session recording + playback with AI summary is a Keeper add-on; Idira records/isolates sessions with AI-generated summaries; Delinea records and monitors privileged sessions; BeyondTrust logs/monitors and can lock or terminate live sessions — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management), [Delinea](https://delinea.com/products/secret-server), [BeyondTrust](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**

**Certifications (vendor-published)**
| Vendor | Claimed certifications | Source |
|---|---|---|
| 1Password | SOC 2 Type 2; ISO/IEC 27001:2022 (+27017, 27018, 27701); TISAX; CSA STAR Level 1; TX-RAMP (incl. Level 2); VPAT; PCI DSS report; GDPR | [Trust Center](https://trust.1password.io/) |
| Bitwarden | SOC 2 Type II + SOC 3 (2026 SOC 3 report public); ISO 27001; HIPAA (annual third-party audit); GDPR/DPF/CCPA-CPRA | [Bitwarden compliance](https://bitwarden.com/compliance/) |
| Keeper | SOC 2 Type 2, SOC 3; ISO 27001/27017/27018; **FedRAMP High + GovRAMP authorized, GovCloud only** | [Keeper pricing comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html) |
| Dashlane | SOC 2 Type II (annual); ISO/IEC 27001 | [Dashlane support: compliance & certifications](https://support.dashlane.com/hc/en-us/articles/32877605633042-9-Compliance-certifications) (updated 16 Jul 2026); [trust center](https://trust.dashlane.com/resources) |
| NordPass | ISO 27001; SOC 2 Type 2; HIPAA; Cure53 assessment badge | [NordPass Business](https://nordpass.com/business-password-manager/) |
| LastPass | ISO 27001; ISO 27701; SOC 2 Type II; BSI C5 | [LastPass pricing FAQ](https://lastpass.com/pricing/) |
| Proton Pass | GDPR and HIPAA *compliance support* claimed; no SOC 2/ISO badge shown on the Pass business pages reviewed | [Proton Pass for Business](https://proton.me/business/pass) |
| Bitwarden (FedRAMP) | **Not authorized.** Announced 15 Sep 2026 a *commitment* to FedRAMP Class D (High); self-hosting on customer-compliant infrastructure is the current federal path | [Bitwarden blog](https://bitwarden.com/blog/bitwarden-committed-fedramp-class-d-certification/); [Business Wire via Yahoo Finance, 15 Sep 2026](https://finance.yahoo.com/technology/ai/articles/bitwarden-announces-commitment-achieve-fedramp-140000611.html) |

**Data residency**
- **1Password:** three independent regions chosen at signup — 1Password.com (US, USD), 1Password.ca (Canada, CAD), 1Password.eu (EU, EUR); data "is never automatically moved from one region to another"; migrating requires creating a new account and copying items — [1Password support: 1Password in your region](https://support.1password.com/regions) **[vendor claim]**
- **Bitwarden:** cloud data storage in **US and EU regions**, chosen at account creation; regions are fully separate; self-hosting also available — [Bitwarden: Server regions](https://bitwarden.com/help/server-geographies) **[vendor claim]**
- **Dashlane:** encrypted data at rest is stored in **EU-West (AWS) by default**; professional teams set up through sales can request **US-East** at team creation — [Dashlane support: Security at Dashlane](https://support.dashlane.com/hc/en-us/articles/360012686840-Security-at-Dashlane) **[vendor claim]**
- **Keeper:** FedRAMP/GovRAMP scoped to GovCloud — [Keeper pricing](https://www.keepersecurity.com/pricing/business-and-enterprise.html). Additional data centers in Japan and Canada were announced in 2022 (secondary source) — [vmblog, 9 Nov 2022](https://vmblog.com/bylines/keeper-security-expands-global-presence-with-cloud-data-centers-in-japan-and-canada); EU and AU data centers are visible in third-party status monitoring — [eaglestatus.io](https://eaglestatus.io/services/keeper-security) **[secondary, not vendor-confirmed on the pages reviewed]**
- **Proton Pass:** Swiss company (Route de la Galaise 32, Geneva); markets Swiss privacy law and end-to-end encryption — [Proton Pass for Business](https://proton.me/business/pass) **[vendor claim]**
- **PAM:** BeyondTrust Password Safe can be deployed as a virtual or physical appliance in AWS or Azure, i.e., residency is the customer's choice — [BeyondTrust Password Safe](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**

**Independent/regulatory facts (LastPass)**
- The UK ICO issued a penalty notice to LastPass UK Ltd on **20 November 2025** for **£1,228,283** under the UK GDPR, covering 31 Dec 2021 – 31 Dec 2024, affecting over one million UK data subjects — reported with citations at [Wikipedia: 2022 LastPass data breach](https://en.wikipedia.org/wiki/2022_LastPass_data_breach) **[secondary]**. The primary ICO notice was not retrieved; treat the exact figure as needing ICO confirmation.
- A class action settled for **$24.5 million**, with final approval granted **30 September 2026** — [LastPass Data Security Incident Litigation settlement site](https://www.lastpasssettlement.com) **[independent/court-supervised]**; the $24.5M figure is reported at [Wikipedia](https://en.wikipedia.org/wiki/2022_LastPass_data_breach) **[secondary]**.

### Inferences
- "SOC 2 Type II" is now the floor, not a differentiator. ISO 27001 is near-universal among the workforce vendors. The *real* differentiators are FedRAMP (Keeper only, GovCloud), HIPAA (Bitwarden, NordPass, Proton claim), and data-residency choice (1Password 3 regions, Bitwarden 2 + self-host, Dashlane EU default).
- Vendors blur "certified," "compliant," and "aligned." Bitwarden says "HIPAA compliant and undergoes annual third-party audits"; Keeper says "certified"; Proton says "compliance support." A buyer's security review should treat these as three different evidentiary levels.
- Keeper's FedRAMP High authorization is the strongest government credential in this set and is confined to GovCloud, which materially limits its usefulness for commercial buyers.
- LastPass's regulatory record is now a *procurement* fact, not just a reputational one: a £1.2M ICO penalty and a court-approved $24.5M settlement are the kind of artifacts that show up in vendor security questionnaires.

### Gaps
- Could not verify certification scope/periods for any vendor (all claims are self-published badges; audit letters are gated behind trust-center access requests).
- No certification data found for Idira/CyberArk, Delinea, or BeyondTrust in this pass — these vendors publish trust centers but the specific FedRAMP/ISO/SOC status was not retrieved. **Do not assume.**
- No data-residency information found for NordPass or LastPass on the pages reviewed.
- Proton's ISO 27001/SOC 2 status is unverified; the Pass business pages only claim GDPR/HIPAA support.

---

## Endpoint surfaces: browser extension, desktop app, mobile, offline mode, autofill, CLI

### Takeaway
The full surface (browser extension + desktop for macOS/Windows/Linux + iOS/Android + autofill + offline cache) is completely commoditized. **CLI is the new differentiator**, and in 2026 it is being used as a *tier gate*: Proton puts CLI in Professional, Keeper puts CLI/TUI in Enterprise, and 1Password/Bitwarden ship CLI as a first-class developer product.

### Cited Findings
- **1Password:** download pages for macOS, Windows, iOS, Android, browser extension, **Linux**, and **command line**; the EPM page markets "pull secrets at runtime through the CLI or SDK" and SSH-key management — [1Password downloads](https://1password.com/downloads/command-line), [1Password EPM](https://1password.com/product/enterprise-password-manager) **[vendor claim]**
- **Bitwarden:** "Browser, Mobile, Desktop apps" on every account, unlimited devices; Bitwarden Send explicitly available in the **Command Line Interface** — [Bitwarden pricing](https://bitwarden.com/pricing/), [Bitwarden Send](https://bitwarden.com/products/send/) **[vendor claim]**
- **Keeper:** "Browser extension and native desktop app... Mac, Windows or Linux"; iOS/Android with instant sync; **CLI and TUI applications** (vault access, admin functions, reports, automations) listed as an **Enterprise** feature — [Keeper pricing comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**
- **Proton Pass:** browser, mobile and desktop apps on all tiers; **CLI only on Professional**; SSH agent only on Professional — [Proton Pass pricing comparison](https://proton.me/business/pass/pricing) **[vendor claim]**
- **NordPass:** apps for iOS, Android, Windows, macOS, Linux; web vault; extensions for Chrome, Firefox, Safari, Opera, Edge; **CLI** linked in the site footer; "offline credential access" listed on the Teams tier — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **LastPass:** access/sync across "browsers, desktop computers, mobile phones, and tablets," including smartwatches; **offline mode** and **travel mode** (select trusted countries) on all tiers including Free/Premium — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**
- **Dashlane:** browser extension + iOS/Android apps; no desktop app or CLI surfaced on the pages reviewed (Dashlane historically has a desktop app for Mac/Windows — **unverified for 2026**) — [Dashlane downloads](https://www.dashlane.com/download) **[vendor claim, partial]**
- **PAM:** Idira supports "native CLI and console workflows" for cloud infrastructure and agentless browser-based access; BeyondTrust supports browser-based third-party access without VPN/bastion — [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management), [BeyondTrust](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**

### Inferences
- Offline mode is now an *expectation*, not a feature: LastPass and NordPass advertise it explicitly, and zero-knowledge architectures (1Password, Bitwarden) are offline-capable by design because decryption happens locally. Any local-first product starts with an advantage here.
- CLI is where the market is splitting: consumer-grade CLIs are read/write vault access + `run`-style secret injection (1Password `op`, Bitwarden `bw`); PAM-grade CLIs are session brokers. The middle ground — a CLI that *never returns the secret to the caller* — is Vaultly's stated position and is **not** how `op`/`bw` work by default (they can inject into a subprocess, but also print values).
- Autofill quality (heuristics, iframe handling, passkey ceremonies) is the least documented and most experience-driven differentiator; no vendor publishes comparative data.

### Gaps
- Could not verify whether Dashlane currently ships a desktop app or CLI, or whether LastPass has a CLI/API for vault access. Absence from the pages reviewed is not proof of absence.
- No primary source found for Bitwarden's offline-mode documentation (widely known but not on the pricing page); do not assert specifics.
- No data on browser-extension market share or autofill accuracy for any vendor.

---

## Security features: breach monitoring, dark-web alerts, password health, TOTP, secure notes, file attachments, passkeys

### Takeaway
This entire cluster is **table stakes and mostly free-tier or low-tier**. By October 2026 the only meaningful segmentation left is (a) whether TOTP and attachments are paywalled, (b) whether breach monitoring covers *domains* (business) vs *emails* (personal), and (c) whether "password health" is a user-facing report or an admin risk dashboard.

### Cited Findings
- **Bitwarden:** free core includes passkey management/usage, generator, encrypted export; **Premium** adds integrated authenticator (TOTP), encrypted file attachments (5 GB, expandable), vault health reports + alerts, emergency access. TOTP is **not** in the free tier — [Bitwarden pricing](https://bitwarden.com/pricing/) **[vendor claim]**
- **Keeper:** encrypted vault stores "passwords, passkeys, files, photos, infrastructure secrets"; password/passphrase generator on all tiers; Security Audit (strength/reuse) and Risk Management Dashboard on all business tiers; breach monitoring sold as a separate **Dark Web Monitoring** add-on for personal and a free **Business Dark Web Scan** — [Keeper pricing comparison](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Keeper site nav](https://www.keepersecurity.com/) **[vendor claim]**
- **Proton Pass:** Dark Web Monitoring, password health check, built-in 2FA authenticator, passkey support, unlimited hide-my-email aliases on **all** business tiers; **file attachment only on Professional** — [Proton Pass pricing comparison](https://proton.me/business/pass/pricing) **[vendor claim]**
- **NordPass:** built-in Authenticator (TOTP next to shared logins), Password Health, Data Breach Scanner for company emails/domains (Business+), Security Dashboard — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **Dashlane:** Password Health dashboard, vault security alerts, Dark Web Insights, passkeys, AI-powered autofill — [Dashlane pricing](https://www.dashlane.com/pricing) **[vendor claim]**
- **1Password:** Watchtower flags weak/reused/breached passwords and missing 2FA "without 1Password ever seeing your data"; developer watchtower finds plaintext secrets on developer devices — [1Password EPM](https://1password.com/product/enterprise-password-manager) **[vendor claim]**
- **LastPass:** dark web monitoring, security dashboard/score, TOTP generation from the vault, secure notes, 1 GB encrypted file storage on all business tiers, passkeys — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**
- **PAM:** adds credential **rotation** (Keeper automated rotation add-on; Delinea automatic password management; BeyondTrust automated rotation; Idira vaulting & rotation) — a capability absent from every consumer PM — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Delinea](https://delinea.com/products/secret-server), [BeyondTrust](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**

### Inferences
- A new entrant in 2026 cannot differentiate on "breach monitoring + password health + TOTP + notes + attachments." Those are the cost of entry and are largely free elsewhere.
- The only defensible security-feature differentiators left are: **rotation** (server + target integration required), **secret scanning on developer endpoints**, **session recording**, and **agent-scoped credential release with human approval** (1Password's "model never seeing the secret").
- Domain-level breach monitoring (as opposed to per-email) is the business-vs-personal line and is a cheap, high-perceived-value feature for a small team product.

### Gaps
- No independent verification of breach-monitoring data sources or coverage for any vendor; all are vendor claims (typically HIBP-derived, but none of the pages reviewed say so).
- No source found on whether Proton's "Dark Web Monitoring" covers domains or only member emails.

---

## Admin/business features: billing, user lifecycle, policies, reporting, SCIM, custom roles

### Takeaway
Billing is annual per-seat self-serve at the low end and quote-only at the top; the 2026 trend is **1Password moving its entire enterprise line to "request a quote"** while Bitwarden keeps transparent list prices ($4/$6). Admin feature depth is now the main reason to buy "Enterprise" rather than "Business": custom roles, delegated admin, multi-tenant, and audit exports.

### Cited Findings
- **1Password:** its enterprise pricing page (`/pricing`) presents five products (Unified Access, Enterprise Password Manager, SaaS Manager, Privileged Access, Device Trust), **all with "Request a quote"** and no published per-seat price — [1Password pricing](https://1password.com/pricing) **[vendor claim]**. Third-party trackers still list Business at **$7.99/user/mo** — [Vendr](https://www.vendr.com/marketplace/1password) **[independent benchmark]** — and **$8.99/user/mo** as of Aug 2026 — [Najar](https://najar.ai/saas-pricing/1password) **[independent tracker]**. These conflict; treat list price as "approximately $8–9/user/mo, with enterprise purchasing routed to sales."
- **Bitwarden:** transparent tiers — Premium $1.65/mo, Families $3.99/mo, **Teams $4/user/mo**, **Enterprise $6/user/mo**, all billed annually; Enterprise adds "enterprise policies," "granular access control," self-host, Access Intelligence, free Families for users — [Bitwarden pricing](https://bitwarden.com/pricing/) **[vendor claim]**
- **Keeper:** Business Starter (5–10 users), Business, Enterprise (quote). Keeper's own 2023 plan explainer quoted starting prices of **$4/user/mo for Business** and **$6/user/mo for Enterprise** (the page's pricing text now renders dynamically) — [Keeper blog, 6 Apr 2023](https://www.keepersecurity.com/blog/2023/04/06/choosing-the-right-keeper-plan-for-your-business) **[vendor claim, dated]**. A 2026 third-party guide lists Business Starter **$2.00** and Business **$3.75**/user/mo — [Securden pricing guide](https://www.securden.com/blog/keeper-pricing-review.html) **[secondary]**. Conflict; the vendor's current page shows no numbers (dynamic pricing widget).
- **Dashlane:** Enterprise is custom; Password Management is sold per-user with a blank list price on the page; Dashlane's own blog table gives **$4/user/mo for Credential Protection** and **$8/user/mo for Password Management** — [Dashlane blog: Is Dashlane worth it](https://www.dashlane.com/blog/is-dashlane-worth-it) **[vendor claim]**. Note the same table labels both as "typical price $4," an internal inconsistency.
- **LastPass:** Teams (≤50 users, 25 policies), Business (100+ policies, groups, SIEM, directory integration, federated login, SSO for 3 apps), Business Max (unlimited SSO, advanced MFA, AI/SaaS/Web monitoring). List prices are rendered as template placeholders (`{LPTeams}`) on the page; third-party estimates span **$4/$7/$9** — [zapro](https://zapro.ai/vendor/lastpass-pricing) **[secondary]** — and **$7–8/$9–10** — [Vendr](https://www.vendr.com/marketplace/lastpass) **[independent benchmark]**. Conflict; do not quote a single number.
- **NordPass:** Teams (10-user pack), Business (5-user minimum), Enterprise (5-user minimum); prices loaded dynamically ("Loading per user/month"); Enterprise adds centralized shared-credential tracking, Entra/ADFS/Okta SSO, automatic access management, Sentinel/Splunk — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **Proton Pass:** Essentials (3–30 users) vs Professional (3+ users) vs Workspace Standard (unlimited); prices omitted from the fetched page (currency selector only); Enterprise is custom with dedicated account manager — [Proton Pass pricing](https://proton.me/business/pass/pricing) **[vendor claim]**
- **PAM:** all three are quote-only. Delinea: "Contact us for pricing," 30-day trial — [Delinea Secret Server](https://delinea.com/products/secret-server) **[vendor claim]**. BeyondTrust: dedicated pricing page exists but not retrieved; Password Safe is sold as a platform with add-ons (Workforce Passwords add-on) — [BeyondTrust](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**
- **Lifecycle:** Keeper has explicit "Vault transfer — securely transfer an employee's vault when they leave"; Proton has "account recovery"; Bitwarden/LastPass have emergency access; all business tiers have group-based offboarding — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Proton](https://proton.me/business/pass/pricing), [Bitwarden](https://bitwarden.com/pricing/) **[vendor claim]**
- **Custom roles:** Keeper Enterprise "advanced admin controls... least-privilege permissions," "delegated administration" on Business, "share admin role" — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**. Bitwarden Enterprise "granular access control" — [Bitwarden](https://bitwarden.com/pricing/) **[vendor claim]**. No vendor in the SMB set documents fully custom role *definitions* (only predefined roles + per-collection permissions); PAM suites do (Delinea RBAC, BeyondTrust roles) — **[vendor claim]**.

### Inferences
- Published list prices in this market are becoming unreliable as a comparison axis: three vendors render prices client-side into placeholders (LastPass, NordPass, Dashlane), one has moved enterprise to quote-only (1Password), and two are transparent (Bitwarden, Proton tier names without numbers). Any pricing table in a report must be dated and sourced or omitted.
- The practical SMB buying motion is self-serve credit card at $4–$9/user/mo; the moment a buyer asks for SCIM + SIEM + custom roles, they are routed to sales. That routing is the real product boundary.
- "Free Families plan for every user" (Bitwarden Enterprise, Keeper Business+, LastPass Business) is a retention tactic that has become standard in the US market.

### Gaps
- No verified 2026 list price for Keeper Business/Enterprise, Dashlane Password Management, LastPass Teams/Business/Business Max, NordPass Business/Enterprise, or Proton Pass Essentials/Professional. All are dynamically rendered and/or inconsistent across secondary sources.
- Could not verify whether 1Password still sells a self-serve Business tier at a published price, or whether all new business purchases now require sales contact.

---

## What small teams actually adopt vs. what only large enterprises buy

### Takeaway
Small teams buy a **shared vault with autofill, MFA, an admin console, and an activity log** — and they buy it on a per-seat, self-serve, annual plan at roughly $4–$9/user/month. They do **not** buy JIT, approvals, session recording, SIEM, FedRAMP, or custom roles; those are enterprise line items, and the vendors' tier design proves it by placing exactly those features above the SMB price point.

### Cited Findings
- **Tier design is the clearest evidence.** LastPass Teams is capped at **50 users** and excludes directory integration, federated login, SIEM, and SSO entirely — [LastPass pricing](https://lastpass.com/pricing/) **[vendor claim]**. NordPass Teams is sold as a **10-user pack** with Google Workspace SSO only; Entra/Okta SSO and provisioning require Enterprise — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**. Keeper Business Starter is scoped to **5–10 users** — [Keeper pricing](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**. Proton Pass Essentials is capped at **30 users** — [Proton pricing](https://proton.me/business/pass/pricing) **[vendor claim]**. These caps are the vendors' own segmentation of "small team."
- **What the SMB tier includes** (i.e., what vendors believe small teams will pay for): shared folders/collections, autofill, password generator, MFA, admin console, activity log, basic reporting, and (Bitwarden only) SCIM/directory sync at $4 — [Bitwarden](https://bitwarden.com/pricing/), [LastPass](https://lastpass.com/pricing/), [NordPass](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **What sits above it:** SIEM export (Keeper ARAM add-on; Dashlane Credential Protection; NordPass Enterprise; LastPass Business; Proton Professional), advanced MFA/contextual auth (LastPass Business Max), unlimited SSO (LastPass Business Max), custom/advanced admin controls (Keeper Enterprise), self-hosting and passwordless SSO (Bitwarden Enterprise), and all of PAM — [sources as above] **[vendor claim]**
- **Audit-driven SMB buying:** NordPass markets "connects with platforms like Vanta, making it easier to gather evidence for SOC 2, ISO 27001, and other audits" — i.e., the SMB's actual compliance need is *evidence collection for someone else's audit*, not FedRAMP — [NordPass Business](https://nordpass.com/business-password-manager/) **[vendor claim]**
- **Market size (context, not adoption):** the US password-management market was estimated at **$993.3M in 2025**, projected to **$4,185.1M by 2034** (16.81% CAGR), segmented into SMB vs large organizations — [IMARC Group](https://www.imarcgroup.com/united-states-password-management-market) **[market-research vendor; treat as directional]**
- **Enterprise-only buying signals:** multi-tenant support and MSP editions (1Password, Keeper, LastPass all sell MSP editions), dedicated account manager/CSM (1Password Enterprise, Dashlane Enterprise, Proton Enterprise), FedRAMP/GovCloud (Keeper), on-prem/self-host (Bitwarden, Delinea, BeyondTrust), and session recording (PAM only) — [1Password](https://1password.com/pricing), [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Dashlane](https://www.dashlane.com/pricing), [Proton](https://proton.me/business/pass/pricing) **[vendor claim]**

### Inferences
- The SMB "job to be done" is **offboarding and shared-account hygiene**, not least-privilege. A 10-person team's real pain is "the marketing Instagram password lives in a spreadsheet and the person who knew it quit." Features that address that (shared folders, vault transfer, activity log, emergency access) are what they adopt.
- SSO adoption is bimodal: a 20-person startup on Google Workspace will use Google SSO where it is included cheaply (NordPass Teams includes Google Workspace SSO), while Proton Pass Essentials offers no SSO at all — a real gap for Google-native startups — and a 20-person company with no IdP will never use SCIM. This is why vendors can get away with gating identity features.
- The "enterprise" features that SMBs *do* end up needing are the boring ones: audit log export for cyber-insurance questionnaires, and per-domain breach alerts. Both are cheap to build and are currently upsells.
- Vendors' own packaging suggests the willingness-to-pay inflection is around **50 seats**: below it, Teams SKUs; above it, Business/Enterprise with SSO+SCIM+SIEM.

### Gaps
- **No rigorous public adoption data was found.** Searches for SMB password-manager adoption statistics returned dictionary noise and market-research abstracts, not survey microdata. The claim "small teams adopt X, not Y" is therefore an inference from vendor tier design + pricing, not from measured adoption. This should be stated as such in any final report.
- No public attach-rate data for SSO/SCIM/SIEM by seat band for any vendor.
- G2/Capterra review segmentation (SMB vs mid-market vs enterprise) exists but was not retrieved; it would be the best available proxy if the report needs a quantitative adoption claim.

---

## Which capabilities a local-first CLI/MCP product can deliver, which need a server, and which should be explicit non-goals

### Takeaway
A local-first CLI/MCP can own the **vault, the crypto boundary, policy *evaluation*, local audit, TOTP/generation/health, and scoped credential injection into approved subprocesses**. It cannot, without a server, deliver **identity federation, multi-user authorization, approvals/JIT, hosted share links, cross-device sync, SIEM aggregation, or any certification that depends on an audited multi-tenant control plane**. Session recording, RDP/SSH brokering, endpoint privilege management, and SaaS discovery should be explicit non-goals.

### Cited Findings (what the market treats as server-side)
- **Identity:** every SSO/SCIM implementation in this set depends on a hosted IdP integration endpoint (1Password's SCIM URL + bearer token; Bitwarden's SSO integration; Keeper's SAML connector; Proton's SSO/SCIM) — [1Password provisioning](https://support.1password.com/provisioning), [Bitwarden pricing](https://bitwarden.com/pricing/), [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Proton](https://proton.me/business/pass/pricing) **[vendor claim]**
- **Hosted share links:** Bitwarden Send's expiry/access-count/destruct-on-open requires server-side ciphertext storage and enforcement; 1Password Psst! links expire server-side; Keeper self-destructing records "automatically delet[e] the record from your vault and disabl[e] the share link at specified time" — [Bitwarden Send](https://bitwarden.com/products/send/), [1Password sharing](https://1password.com/features/secure-password-sharing), [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html) **[vendor claim]**
- **Approvals/JIT:** Keeper's JIT elevation and approval workflows run through ServiceNow/Jira/Slack/Teams integrations (i.e., a server + external workflow engine); Idira's ZSP creates and destroys ephemeral privileges server-side; BeyondTrust evaluates day/date/time/location context at access time — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management), [BeyondTrust](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**
- **SIEM/audit export:** all implementations push to a collector (Splunk, Sentinel, CrowdStrike) from a hosted event stream — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [NordPass](https://nordpass.com/business-password-manager/), [LastPass](https://lastpass.com/pricing/), [1Password](https://1password.com/product/enterprise-password-manager) **[vendor claim]**
- **Agent credential brokering (the 2026 frontier):** 1Password sells "credentials for AI agents... approved by a human, with the model never seeing the secret," plus a Credential Broker product and "1Password for Agents"; Keeper sells "AI agent integration with MCP" as an add-on; Proton ships an SSH agent; Idira markets "Agentic Identities" and "Secure AI Agents"; BeyondTrust markets Password Safe for "people, machines, and AI agents" and a Pathfinder platform that includes AI-agent security — [1Password EPM](https://1password.com/product/enterprise-password-manager), [1Password pricing nav](https://1password.com/pricing), [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Proton](https://proton.me/business/pass/pricing), [Idira](https://www.paloaltonetworks.com/idira), [BeyondTrust](https://www.beyondtrust.com/products/password-safe) **[vendor claim]**
- **What a CLI can do without a server:** generate passwords/passphrases, compute strength/health locally, store TOTP seeds and generate codes, encrypt/decrypt a local vault, export encrypted backups, inject a secret into an approved subprocess without returning it, and write an append-only local audit record. Every one of these is demonstrated by existing CLI surfaces (1Password `op`, Bitwarden `bw`, Keeper Commander/CLI, Proton Pass CLI, NordPass CLI) — [1Password CLI downloads](https://1password.com/downloads/command-line), [Bitwarden Send/CLI](https://bitwarden.com/products/send/), [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Proton](https://proton.me/business/pass/pricing) **[vendor claim]**

### Inferences — build / server / non-goal

**Can be delivered local-first (no server, no account):**
1. Zero-knowledge encrypted vault at rest + OS keychain unlock (Keeper/1Password/Bitwarden all define the bar; a local product can meet it without their infrastructure).
2. CLI + MCP CRUD with write-only credential semantics (add/rotate/delete; never return the value).
3. Scoped credential injection into an allowlisted child process — the one capability where a local product is *stronger* than `op`/`bw`, because those can print secrets to stdout.
4. Password/passphrase generation, TOTP, strength and reuse analysis, local "password health" report.
5. Local append-only audit log with hash chaining; exportable as JSON/CSV for an auditor.
6. Encrypted export/import and local backup/restore.
7. Policy *evaluation* against a signed policy file (deny-by-default), with the caveat that a local root user can bypass it — so it is a guardrail, not an enforcement boundary.
8. Offline operation by construction (a differentiator vs. every SaaS vendor).

**Requires a server (or a trusted coordination service):**
1. SSO (OIDC/SAML), SCIM, directory sync — requires an IdP-facing endpoint and session management.
2. Multi-user vaults/collections with per-user ACLs and revocation that the user cannot override.
3. Approvals, JIT/time-bound access, M-of-N break-glass — requires an out-of-band approver and a clock the requester doesn't control.
4. Expiring/guest share links (Bitwarden Send/Psst!/One-Time Share) — requires hosted ciphertext + expiry enforcement.
5. Cross-device sync and conflict resolution.
6. SIEM export, org-wide reporting, anomaly detection.
7. Billing, seat management, tenant isolation, and the evidence needed for SOC 2/ISO 27001 (a certification is an assertion about an operating environment; a CLI alone cannot hold one).
8. Data-residency guarantees (1Password's three regions, Bitwarden's US/EU split, Dashlane's EU default) — these are hosting promises.
9. Breach monitoring at domain scale and threat-intel feeds.

**Explicit non-goals (do not build; partner or decline):**
1. Privileged session recording/playback and session isolation (Keeper add-on, Idira, Delinea, BeyondTrust). This is a proxy/broker product with its own compliance burden.
2. RDP/SSH/database session brokering, TCP tunneling, remote browser isolation.
3. Endpoint privilege management (removing local admin, sudo policy, application elevation).
4. SaaS/shadow-IT discovery and AI-spend management (1Password SaaS Manager, LastPass AI/SaaS/Web Monitoring).
5. Secrets management for CI/CD at scale (Vault, 1Password Secrets Automation, Bitwarden Secrets Manager, Keeper Secrets Manager) — a different buyer and a different threat model.
6. Browser extension + autofill + passkey ceremony UX. High polish cost, low differentiation, and it puts the product in the browser's trust path.
7. Being the IdP. Integrate; don't authenticate the org.
8. FedRAMP-authorized cloud. Even Bitwarden — with a decade of investment — is only *pursuing* Class D (High) as of Sept 2026.

**Hybrid pattern the market supports:** local-first vault + an optional, end-to-end-encrypted sync/coordination relay that never holds keys. This is exactly the 1Password/Bitwarden architecture (client-side encryption, server holds ciphertext), and it is the only way to add sharing/approvals without breaking the "server never sees secrets" property. The relay should hold: encrypted blobs, ACL metadata, approval state, expiry timers — never plaintext or keys.

### Gaps
- No source found that documents MCP-specific security guidance from any of these vendors beyond marketing ("AI agent integration with MCP" as a Keeper add-on; "1Password for Agents"). The MCP threat model for credential products is not yet standardized, and no vendor published an MCP security whitepaper that I could find.
- Could not verify whether any vendor supports multi-party (M-of-N) approval for break-glass; if this matters, it needs a direct vendor query.
- No independent benchmark exists for CLI secret-handling safety (e.g., whether `op run` leaks to process arguments); this would need hands-on testing, not desk research.

---

## Synthesis: the table-stakes feature set as of October 2026

### Takeaway
There are **three distinct feature sets**, not one. Confusing them is the most common error in credential-product planning: (1) consumer/team table stakes, (2) business/enterprise table stakes, (3) PAM table stakes. A local-first CLI/MCP product should aim to be excellent at (1), honest about (2), and explicitly out of scope for (3).

### The three tiers

| Capability | Consumer / small-team table stakes | Business / enterprise table stakes | PAM / large-enterprise only | Local-first feasible? |
|---|---|---|---|---|
| Encrypted zero-knowledge vault | Yes — universal | Yes | Yes | **Yes** |
| Browser ext / desktop / mobile / autofill | Yes — universal | Yes | Agentless browser access | No (non-goal) |
| Password generator, secure notes, TOTP | Yes — universal (TOTP sometimes paid) | Yes | Yes | **Yes** |
| Passkey storage | Yes — universal | Yes | Partial | Partial (platform APIs) |
| Passkey *vault login* / passwordless | Partial — Keeper and LastPass document it explicitly; Bitwarden sells "passwordless SSO"; 1Password documents passkey support but vault-unlock specifics unverified | Yes | Yes (phishing-resistant auth) | Partial (OS biometrics) |
| Password health / breach monitoring | Yes — universal | Yes + domain-level breach alerts | Yes | Partial (local health; breach feed needs network) |
| File attachments | Paid tier (Bitwarden 5 GB, Proton Pro, LastPass 1 GB) | Yes | n/a | **Yes** (local blob store) |
| Sharing: vault/collection/folder | Yes | Yes | Yes | **No** (needs ACL server) |
| Expiring external share links | Partial — Bitwarden, 1Password, Keeper, Proton; not documented for Dashlane, NordPass, LastPass | Yes | Session-based instead | **No** |
| Guest accounts | Fading; replaced by links | Some | Vendor JIT access | **No** |
| MFA on vault | Yes — universal | Yes + enforced policies | Yes | Partial (local TOTP/security key) |
| SSO (SAML/OIDC) | **No** — SMB tier usually lacks it | **Yes — the tier boundary** | Yes | **No** |
| SCIM / directory sync | Rare (Bitwarden Teams is the exception) | Yes | Yes (IGA) | **No** |
| Groups + granular permissions | Basic (folders/collections) | Yes | Yes | **No** |
| Audit log | Basic activity log | Yes + SIEM export | Yes + forensics | Partial (local log) |
| SIEM export | No | Yes (often add-on/product) | Yes | **No** |
| Custom roles | No | Partial (predefined roles) | Yes | **No** |
| Approvals / JIT | No | Rare (Keeper add-on, 1Password separate product) | **Yes — defining feature** | **No** |
| Session recording | No | No (Keeper add-on only) | **Yes — defining feature** | **No** |
| Credential rotation | No | Emerging (Keeper add-on; Bitwarden announced privileged controls with rotation in 2026) | **Yes** | Partial (local, target-specific) |
| Break-glass / emergency access | Consumer emergency access (Bitwarden, LastPass) | Delegate recovery | Sealed break-glass procedure | Partial (local sealed record; no quorum) |
| Data residency choice | No | Yes (1Password 3 regions, Bitwarden 2, Dashlane EU/US) | Customer-deployed | **No** (single-tenant local = residency by default) |
| SOC 2 / ISO 27001 | Vendor-level, not buyer-facing | **Yes — procurement gate** | Yes | **No** (can't certify a CLI) |
| FedRAMP | No | Rare (Keeper GovCloud only) | Not verified for Idira/Delinea/BeyondTrust | **No** |
| CLI | Differentiator (1Password, Bitwarden, Keeper, Proton Pro, NordPass) | Yes | Yes | **Yes — core strength** |
| Agent/MCP credential access | Emerging (1Password, Keeper add-on, Proton SSH agent) | Emerging | Emerging (Idira, BeyondTrust) | **Yes — core strength, if value-blind** |

### PAM vs. workforce PM: the capability delta

**Only the PAM suites have (and no workforce password manager in this set does):**
- Session recording, playback, live monitoring and the ability to lock or terminate a session — [BeyondTrust](https://www.beyondtrust.com/products/password-safe), [Delinea](https://delinea.com/products/secret-server), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management); in the PM market this exists only as a **KeeperPAM add-on** — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html).
- Automated discovery and **rotation** of privileged credentials, SSH keys, service accounts and secrets across infrastructure — [Delinea](https://delinea.com/products/secret-server), [BeyondTrust](https://www.beyondtrust.com/products/password-safe), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management).
- **JIT/ZSP with context** (day/date/time/location) and ephemeral accounts — [BeyondTrust](https://www.beyondtrust.com/products/password-safe), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management), [Delinea](https://delinea.com/solutions/zero-standing-privilege).
- **Vendor/third-party privileged access without VPN or bastion**, browser-based and recorded — [BeyondTrust PRA](https://www.beyondtrust.com/products/privileged-remote-access), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management).
- **Endpoint privilege management** (removing local admin, application elevation, sudo policy) — [BeyondTrust](https://www.beyondtrust.com/products/password-safe), [Keeper EPM add-on](https://www.keepersecurity.com/pricing/business-and-enterprise.html).
- **IGA/SoD integration** and access reviews as a product (Delinea Fastpath Access Review; BeyondTrust ↔ SailPoint) — [Delinea products](https://delinea.com/products), [BeyondTrust](https://www.beyondtrust.com/products/password-safe).
- **Customer-controlled deployment**: on-prem/appliance in AWS/Azure (BeyondTrust), self-managed (Keeper), which is how these vendors answer data-residency and air-gap requirements — [BeyondTrust](https://www.beyondtrust.com/products/password-safe), [Keeper self-managed](https://www.keepersecurity.com/self-managed-keeper/).

**Only the workforce password managers have (and no PAM suite does):**
- Consumer-grade **autofill** in browsers and apps, browser extensions, and mobile apps designed for non-technical staff — [Bitwarden](https://bitwarden.com/pricing/), [NordPass](https://nordpass.com/business-password-manager/), [Dashlane](https://www.dashlane.com/download).
- **Self-serve, per-seat pricing at $4–$9/user/mo** with free tiers and family plans — [Bitwarden](https://bitwarden.com/pricing/), [LastPass](https://lastpass.com/pricing/), [Proton](https://proton.me/business/pass/pricing).
- **Passkey storage and passkey/FIDO2 vault login** as an end-user feature — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [LastPass](https://lastpass.com/pricing/), [Dashlane](https://www.dashlane.com/pricing).
- **Data-region choice at signup** (1Password US/CA/EU; Bitwarden US/EU) — [1Password](https://support.1password.com/regions), [Bitwarden](https://bitwarden.com/help/server-geographies).
- **Open-source verifiability** (Bitwarden) as a procurement argument — [Bitwarden compliance](https://bitwarden.com/compliance/).
- **Employee personal-exposure monitoring** (dark web alerts for staff emails) — [NordPass](https://nordpass.com/business-password-manager/), [LastPass](https://lastpass.com/pricing/).

**Shared by both:** encrypted vault, RBAC/groups, MFA, SSO, audit trail, SIEM export, and now AI-agent credential access. The convergence is real but asymmetric: PAM suites are adding usability and cloud coverage; password managers are adding rotation and JIT (Keeper, Bitwarden, 1Password) without adding session recording.

### What changed in 2025–2026 (the "current state" deltas a report must not miss)
1. **CyberArk became Idira** (brand changes from 31 May 2026) — [CyberArk FAQ](https://community.cyberark.com/s/article/CyberArk-is-now-Idira-Frequently-Asked-Questions).
2. **The leading vendors now sell AI-agent credential access.** 1Password has a Credential Broker and "1Password for Agents"; Keeper sells MCP integration as an add-on; Proton ships an SSH agent; Idira and BeyondTrust both market agentic-identity security — [1Password](https://1password.com/product/enterprise-password-manager), [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Proton](https://proton.me/business/pass/pricing), [Idira](https://www.paloaltonetworks.com/idira), [BeyondTrust](https://www.beyondtrust.com/products/password-safe).
3. **1Password's enterprise pricing page is now quote-only** — five products, no published per-seat prices — [1Password pricing](https://1password.com/pricing).
4. **Bitwarden is pursuing FedRAMP Class D (High)** (announced 15 Sep 2026) and shipped privileged controls (time-bound leasing, rotation) — [Bitwarden blog](https://bitwarden.com/blog/bitwarden-committed-fedramp-class-d-certification/), [Bitwarden privileged controls](https://bitwarden.com/blog/bitwarden-privileged-controls-secure-your-most-sensitive-accounts-in-minutes/).
5. **LastPass's breach has become a formal procurement artifact**: £1.23M ICO penalty (Nov 2025) and a $24.5M settlement with final approval on 30 Sep 2026 — [ICO via Wikipedia](https://en.wikipedia.org/wiki/2022_LastPass_data_breach), [settlement site](https://www.lastpasssettlement.com).
6. **Session recording with AI summaries** is now table stakes *in PAM* (Keeper, Idira, Delinea) but has not crossed into password managers — [Keeper](https://www.keepersecurity.com/pricing/business-and-enterprise.html), [Idira](https://www.paloaltonetworks.com/idira/human/privileged-access-management), [Delinea](https://delinea.com/products/secret-server).

### Inferences
- **The minimum viable credible product for a small team in 2026** is: encrypted vault, autofill across browser/desktop/mobile, generator, TOTP, passkeys, password health, breach alerts, shared folders, MFA, admin console, activity log, per-seat billing, and SSO *if* you want to sell above ~50 seats.
- **The minimum viable credible product for an enterprise** adds: SCIM, SIEM, custom roles, data residency, SOC 2 Type II + ISO 27001, and either FedRAMP or a self-host option.
- **The minimum viable PAM product** is a different company: vault + rotation + JIT + approvals + session recording + break-glass + IGA integration.
- A local-first CLI/MCP product is structurally closest to the **developer-secrets + agent-credential** slice, not the workforce-password-manager slice. It can beat `op`/`bw` on one axis (never returning the secret to the agent) and should not attempt to beat them on autofill, sharing, or SSO.

### Gaps (aggregate)
- No verified 2026 list pricing for Keeper, Dashlane, LastPass, NordPass, or Proton; vendor pages are dynamic and third-party figures conflict.
- No independent verification of any certification claim; all are vendor badges. FedRAMP status for Idira, Delinea, and BeyondTrust was not established.
- No public SMB feature-adoption data; the "what small teams buy" conclusion is inferred from tier caps and gating, not measured.
- Delinea and BeyondTrust pricing, packaging, and exact identity-protocol support were not retrievable within this pass (Delinea is quote-only; BeyondTrust's pricing page was not fetched).
- Whether 1Password retains a self-serve Business SKU, and whether it supports OIDC (vs SAML), remains unverified.

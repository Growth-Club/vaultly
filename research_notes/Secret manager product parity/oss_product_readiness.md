# What "Product Ready" Means for an Open-Source CLI/Dev Tool (October 2026)

**Scope and method.** This note benchmarks mature OSS CLI/dev tools (GitHub CLI, uv, Turborepo, Supabase CLI, Doppler CLI, Infisical, SOPS, age, Ollama, Bun, Deno) plus primary guidance from GitHub, Homebrew, Microsoft, OpenSSF, SLSA and Sigstore. All web sources were fetched on **2026-10-30** unless otherwise noted; repository metrics come from the live GitHub API on the same date. Where a claim is my synthesis rather than a fetched fact, it is labelled as an inference.

**Headline:** "Product ready" in late 2026 is no longer just "binaries on GitHub Releases." The credible baseline is: a signed, checksummed, attested release for five OS/arch targets (six with Windows arm64); a one-line installer plus Homebrew/Winget/Docker; a docs site with a real information architecture; the standard community-health file set; a public security policy; and a release cadence fast enough that users believe the project is alive. Everything below that line is a trust discount; everything far above it (SLSA L3, reproducible builds, SOC 2) is differentiation, not a launch blocker.

---

## 1. Release matrix: which OS/arch targets are expected, and how are they built/signed?

### Takeaway
The 2026 table stakes matrix is **Linux x86_64 + aarch64 (glibc, plus musl for Rust/static-linked tools and Alpine/container users), macOS arm64 + x86_64 (or one universal binary), Windows x86_64**, with **Windows arm64** increasingly expected of new tools and 32-bit x86 optional legacy. Builds are automated from CI, macOS artifacts are Developer ID-signed and notarized, Windows binaries/MSIs are signed through Microsoft's managed signing service, Linux packages are GPG-signed, and every release carries SHA-256 checksums plus a provenance attestation.

### Cited Findings

**Observed matrices (primary evidence from actual releases)**
- GitHub CLI `v2.103.3` (published 2026-10-26) ships: Linux `386`, `amd64`, `arm64`, `armv6` as `.tar.gz`, `.deb` and `.rpm`; macOS `amd64` and `arm64` `.zip` plus a `macOS_universal.pkg`; Windows `386`, `amd64`, `arm64` as `.zip` and `.msi`; and a `checksums.txt` — [cli/cli release v2.103.3](https://github.com/cli/cli/releases/tag/v2.103.3) (accessed 2026-10-30).
- uv `0.13.6` (published 2026-10-27) ships a much wider Rust target matrix: `aarch64-apple-darwin`, `x86_64-apple-darwin`; `aarch64-pc-windows-msvc`, `x86_64-pc-windows-msvc`, `i686-pc-windows-msvc`; Linux `x86_64`, `aarch64`, `i686`, `armv7`, `arm`, `powerpc64le`, `riscv64gc`, `s390x` in both `gnu` and `musl` variants where applicable; plus per-asset `.sha256` files, a combined `sha256.sum`, `dist-manifest.json`, `source.tar.gz`, and `uv-installer.sh` / `uv-installer.ps1` — [astral-sh/uv release 0.13.6](https://github.com/astral-sh/uv/releases/tag/0.13.6) (accessed 2026-10-30).
- Supabase CLI publishes `.apk`, `.deb`, `.rpm`, and `.pkg.tar.zst` Linux packages directly on GitHub Releases, alongside npm, Homebrew and Scoop channels — [supabase/cli README](https://github.com/supabase/cli) (accessed 2026-10-30).
- age's README lists Homebrew, MacPorts, Winget, Alpine `apk`, Arch `pacman`, and other distro channels, showing the long tail a mature security CLI accumulates — [FiloSottile/age README](https://github.com/FiloSottile/age) (accessed 2026-10-30).

**How mature projects build**
- GitHub CLI's release workflow is split into `linux`, `macos`, `windows` jobs on `ubuntu-latest`, `macos-latest`, `windows-2022`, then a merge/publish job. It pins every action to a full commit SHA (e.g. `actions/checkout@3d3c42e5... # v7.0.1`), pins GoReleaser to `v2.13.1`, and grants only `attestations: write`, `contents: write`, `id-token: write` — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- That workflow signs macOS with a Developer ID certificate imported into a temporary keychain, stores notarization credentials via `xcrun notarytool store-credentials` using an App Store Connect API key, notarizes the zips, and builds/notarizes a universal `.pkg` — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- It signs Windows `.exe`/`.msi` through Azure Code Signing (`Microsoft.Trusted.Signing.Client`, `signtool`, OIDC login via `azure/login`) — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- It GPG-signs RPMs with `rpmsign --addsign`, builds a `createrepo` RPM repository, signs `repodata/repomd.xml`, and publishes `.deb` packages into an apt repo via `reprepro` — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- Apple's notary service requires `notarytool` (Xcode 14+); `altool` uploads stopped being accepted on **2023-11-01**. Notarization gives Gatekeeper a ticket to show users the software was scanned — [Apple: Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution) (accessed 2026-10-30).
- Microsoft's managed signing service (Azure Trusted Signing, presented in 2026 as **Artifact Signing**) provides certificate lifecycle management inside FIPS 140-3 Level 3 HSMs and integrates with build pipelines — [Microsoft Learn: What is Artifact Signing?](https://learn.microsoft.com/en-us/azure/trusted-signing/overview) (accessed 2026-10-30).

**Automation options a small team can actually use**
- GoReleaser's customization tree covers archives, nFPM (deb/rpm/apk), DMG/PKG/MSI/NSIS, checksums, SBOMs, binary/artifact signing, notarization, and publishers for GitHub, Homebrew, Winget, Scoop, AUR, Nix, npm, Krew and Docker — i.e. nearly the whole distribution surface from one YAML file — [GoReleaser customization index](https://goreleaser.com/customization/) (accessed 2026-10-30). Current release at time of access: v2.19 — [GoReleaser](https://goreleaser.com/) (accessed 2026-10-30).
- cargo-dist is the Rust-native equivalent: `dist init` generates a `release.yml` that plans, builds, hosts and publishes; it documents installers for shell, PowerShell, npm, Homebrew and MSI, plus Windows signing and GitHub Attestations — [cargo-dist book, Introduction](https://axodotdev.github.io/cargo-dist/book/introduction.html) (accessed 2026-10-30).
- GoReleaser's "verifiable builds" record module information so `go version -m mybinary` can show exactly what was built, with dependencies verified against `sum.golang.org` — [GoReleaser: Verifiable Builds](https://goreleaser.com/customization/builds/verifiable_builds/) (accessed 2026-10-30).

**Provenance, attestations and immutability**
- GitHub artifact attestations are generated with `actions/attest` and verified by users with `gh attestation verify PATH/TO/ARTIFACT -R ORG/REPO`; the same command supports SBOM predicates (SPDX or CycloneDX) and container images via `oci://` — [GitHub Docs: Using artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) (accessed 2026-10-30).
- GitHub CLI calls `actions/attest@...` with `subject-path: "dist/gh_*"` and `create-storage-record: false` in its publish job — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- **Immutable releases** are generally available since **2025-10-28**: once enabled, the Git tag cannot be moved or deleted while the release exists, and release assets cannot be modified or deleted; publishing also generates a release attestation — [GitHub Docs: Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) and [GitHub Changelog, 2025-10-28](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/) (accessed 2026-10-30).
- SLSA defines Build L1 (provenance exists), L2 (signed provenance from a hosted build platform), L3 (hardened build platform; signing secrets inaccessible to user build steps). **SLSA v1.2 is the current version; v1.1 is retired** — [SLSA security levels](https://slsa.dev/spec/v1.1/levels) (accessed 2026-10-30).
- GoReleaser generates one SBOM per archive by default using **Syft**, in the `dist/` directory — [GoReleaser: SBOMs](https://goreleaser.com/customization/sbom/) (accessed 2026-10-30).

### Inferences
- The practical floor is five OS/arch combinations, usually shipped as six or seven artifacts: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` (containers/Alpine), `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`. Add `aarch64-unknown-linux-musl` and `aarch64-pc-windows-msvc` if CI minutes allow; drop 32-bit x86 unless an enterprise user asks.
- macOS: shipping a single universal binary halves notarization/QA work but doubles artifact size; shipping two arch-specific tarballs is what GitHub CLI does, plus a universal `.pkg` for the "double-click" audience.
- Windows arm64 is now a credible checkbox for new developer tools, but the installed base is still overwhelmingly x86_64; it is "expected of new tools," not yet "required for adoption."
- For a Rust project, cargo-dist gets a small team to a signed, attested, multi-installer release fastest; GoReleaser is the better choice if you also need deb/rpm repos and Homebrew/Winget/Scoop publishing from the same config. Both are viable for one person.
- SLSA L2 is essentially free on GitHub-hosted runners with `actions/attest`; L3 requires a hardened/reusable build workflow and is a multi-week project, not a launch requirement.

### Gaps
- Could not retrieve the SLSA **v1.2** levels page (returned 404 at `/spec/v1.2/levels`); level semantics are quoted from the retired v1.1 page, which still states v1.2 is current. Treat exact v1.2 wording as unverified.
- No fetched evidence of which of these projects actually claims SLSA L3, or of bit-for-bit reproducible builds in the wild; GoReleaser's "verifiable builds" is weaker than reproducible builds.
- Certificate costs (Apple Developer Program, Microsoft Artifact Signing) were not verified on this pass; do not quote prices without checking.
- Code-signing smart-card/HSM options for solo maintainers were not researched.

---

## 2. Install paths: which combinations are table stakes?

### Takeaway
**Table stakes:** GitHub Releases with checksums, a `curl | sh` installer (and PowerShell equivalent), Homebrew, Winget, and a multi-arch Docker image. **Ecosystem-native:** npm and PyPI when the tool's users live there, `cargo install` for Rust. **Expected by mature tools:** Scoop, deb/rpm (or a signed apt/yum repo), and a Homebrew **tap** from day one (core only after notability). GitHub Actions integration is a distribution channel in its own right for CI-centric tools.

### Cited Findings

**Homebrew**
- Homebrew's official taps require *public presence and maintenance*: a homepage, active upstream maintenance, no known unpatched vulnerabilities, and a working `livecheck`. A new package must demonstrate public interest beyond its author: normally **30 forks, 30 watchers or 75 stars**; a **self-submission** by the repo owner/commit author needs **90 forks, 90 watchers or 225 stars** — [Homebrew Package Acceptance Policy](https://docs.brew.sh/Package-Acceptance-Policy) (accessed 2026-10-30).
- Formulae must build from an **immutable release archive/tag** and downloaded archives must be verified with **SHA-256**; self-updating behaviour must be disabled — [Homebrew Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae) (accessed 2026-10-30).
- Third-party taps are explicitly the path for software that does not meet official criteria; a tap does not imply Homebrew endorsement — [Homebrew Package Acceptance Policy](https://docs.brew.sh/Package-Acceptance-Policy) (accessed 2026-10-30).
- Real-world split: Supabase maintains both `supabase/tap/supabase` ("always up to date") and `brew install supabase` ("official formula, may be delayed") — [supabase/cli README](https://github.com/supabase/cli) (accessed 2026-10-30).

**Winget**
- Submission means writing a YAML manifest against the Windows Package Manager schema and opening a PR to the `microsoft/winget-pkgs` repository; submissions must follow the repository policies — [Microsoft Learn: Submit packages to Windows Package Manager](https://learn.microsoft.com/en-us/windows/package-manager/package/) (accessed 2026-10-30).
- Accepted installer types are **MSIX, MSI, APPX, MSIXBundle, APPXBundle, or `.exe`** installers — [winget-pkgs README](https://github.com/microsoft/winget-pkgs) (accessed 2026-10-30).
- Doppler recommends `winget install doppler` as its primary Windows path — [dopplerHQ/cli README](https://github.com/dopplerHQ/cli) (accessed 2026-10-30).

**Scoop**
- Supabase runs its own bucket (`scoop bucket add supabase https://github.com/supabase/scoop-bucket.git`) rather than waiting for the main bucket — [supabase/cli README](https://github.com/supabase/cli) (accessed 2026-10-30).

**curl | sh and PowerShell**
- uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`; the README also advertises "installable without Rust or Python via `curl` or `pip`" — [astral-sh/uv README](https://github.com/astral-sh/uv) and [uv docs](https://docs.astral.sh/uv/) (accessed 2026-10-30).
- Supabase: `curl -fsSL https://raw.githubusercontent.com/supabase/cli/main/install | bash` — [supabase/cli README](https://github.com/supabase/cli) (accessed 2026-10-30).
- Doppler's installer is deliberately defensive: `curl -Ls --tlsv1.2 --proto "=https" --retry 3 ... || wget -t 3 -qO- ... | sh`, recommended for CI rather than desktop — [dopplerHQ/cli README](https://github.com/dopplerHQ/cli) (accessed 2026-10-30).
- Bun positions its script as one of several first-class options ("install script, a package manager, or Docker on macOS, Linux, and Windows") — [Bun installation docs](https://bun.sh/docs/installation) (accessed 2026-10-30).
- Deno's installation page sits at the top of a docs tree that includes `deno install`, `deno upgrade`, and distribution guidance — [Deno installation docs](https://docs.deno.com/runtime/getting_started/installation/) (accessed 2026-10-30).

**Package managers / language ecosystems**
- Supabase ships npm (`npm install -D supabase`), Homebrew (tap + core), Scoop, a shell installer, and Linux packages — [supabase/cli README](https://github.com/supabase/cli) (accessed 2026-10-30).
- Doppler ships Homebrew, Winget, a shell script, Docker, a GitHub Action, and standalone binaries — [dopplerHQ/cli README](https://github.com/dopplerHQ/cli) (accessed 2026-10-30).
- npm supports **provenance statements** linking a published package to its source repo and build — [npm Docs: Generating provenance statements](https://docs.npmjs.com/generating-provenance-statements) (accessed 2026-10-30).
- age lists Homebrew, MacPorts, Winget, Alpine, Arch and more in a single installation table — [FiloSottile/age README](https://github.com/FiloSottile/age) (accessed 2026-10-30).

**Docker**
- Bun documents Docker as a supported install path — [Bun installation docs](https://bun.sh/docs/installation) (accessed 2026-10-30).
- Doppler documents a Docker install path — [dopplerHQ/cli README](https://github.com/dopplerHQ/cli) (accessed 2026-10-30).
- Ollama's README is an unusually pure "install matrix": `curl -fsSL https://ollama.com/install.sh | sh` for macOS/Linux, `irm https://ollama.com/install.ps1 | iex` for Windows, direct `.dmg`/`.exe` downloads as fallbacks, and an official `ollama/ollama` Docker Hub image — [ollama/ollama README](https://github.com/ollama/ollama) (accessed 2026-10-30).
- GoReleaser has first-class Docker image/manifest publishers (v2 `dockers_v2`, `docker_manifest`, `docker_sign`) — [GoReleaser customization index](https://goreleaser.com/customization/) (accessed 2026-10-30).

### Inferences
- A realistic 1–3 person ladder: **Week 1** GitHub Releases + checksums + `install.sh`/`install.ps1`; **Week 2** Homebrew tap + Docker; **Week 3** Winget + Scoop bucket; **Week 4** deb/rpm (artifacts only, no hosted repo yet). Hosted apt/yum repos are the first thing to defer — GitHub CLI's `reprepro`/`createrepo` pipeline is real work and only pays off with enterprise Linux users.
- For a security CLI, the installer itself is a trust surface: support `--version`, install to a user-writable prefix without `sudo`, verify the downloaded artifact's SHA-256 before install, and print the verification command. Doppler's `--proto "=https" --tlsv1.2 --retry 3` flags are a good minimal template.
- Do not chase homebrew-core early: the self-submission threshold (90/90/225) is 3× the normal notability bar, and a tap gives the same `brew install owner/tap/tool` UX immediately.
- Universal fallback matters: every channel above should resolve to the same GitHub Release asset, so a user who distrusts the installer can download, verify and run.

### Gaps
- ripgrep's release matrix could not be verified: GitHub API requests were rate-limited during this pass and release pages are JS-rendered. Do not attribute a target list to ripgrep without rechecking.
- SOPS's install channels were not verified (raw README fetch returned 404 and the API was unavailable); only its release cadence (6 releases/year) is confirmed.
- Scoop's main-bucket acceptance criteria were not verified (the wiki page fetched was mostly GitHub chrome). Treat "submit to ScoopInstaller/Main" as unconfirmed; a self-hosted bucket is confirmed by Supabase's example.
- `cargo-binstall` metadata requirements and `cargo install` norms for Rust CLIs were not verified on this pass.
- No data found on what fraction of users arrive via each channel; channel priority is judgement, not measurement.
- apt/rpm repository hosting costs (Cloudsmith, GemFury, PackageCloud) were not verified.

---

## 3. Supply chain: what is expected vs differentiating?

### Takeaway
The credible 2026 baseline is **SHA-256 checksums + GitHub artifact attestations + immutable releases + a security policy**, all of which a small team can ship in days. **Sigstore/cosign keyless signatures, SBOMs, and SLSA provenance** are now cheap differentiators. **Reproducible builds, SLSA L3, and independent audits** remain enterprise-grade investments and should be explicitly deferred.

### Cited Findings
- GitHub CLI ships a per-release `checksums.txt`, signs RPMs and apt metadata with GPG, publishes `actions/attest` provenance, and pins every third-party action to a full commit SHA — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- GitHub's secure-use reference is the canonical checklist for workflow hardening (least-privilege `GITHUB_TOKEN`, pinned actions, avoiding script injection) — [GitHub Docs: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) (accessed 2026-10-30).
- Artifact attestations are verified with `gh attestation verify <artifact> -R <org>/<repo>`, including SBOM predicates in SPDX or CycloneDX — [GitHub Docs: Using artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) (accessed 2026-10-30).
- Immutable releases lock tags and assets after publication and auto-generate a release attestation — [GitHub Docs: Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) (accessed 2026-10-30).
- Sigstore/cosign provides keyless signing bound to an OIDC identity, with signatures recorded in a transparency log; verification is a separate, documented step — [Sigstore overview](https://docs.sigstore.dev/about/overview/) and [Verifying signatures](https://docs.sigstore.dev/cosign/verifying/verify/) (accessed 2026-10-30).
- OpenSSF Scorecard runs 20 automated checks, including `Binary-Artifacts`, `Branch-Protection`, `CI-Tests`, `CII-Best-Practices`, `Code-Review`, `Dangerous-Workflow`, `Dependency-Update-Tool`, `Fuzzing`, `License`, `Maintained`, `Packaging`, `Pinned-Dependencies`, `SAST`, `SBOM`, `Security-Policy`, `Signed-Releases`, `Token-Permissions`, `Vulnerabilities` — [Scorecard checks.md](https://github.com/ossf/scorecard/blob/main/docs/checks.md) (accessed 2026-10-30).
- The Scorecard GitHub Action is free for public repositories; publishing results requires `id-token: write` — [ossf/scorecard-action README](https://github.com/ossf/scorecard-action) (accessed 2026-10-30).
- GoReleaser emits SBOMs with Syft by default, one per archive — [GoReleaser: SBOMs](https://goreleaser.com/customization/sbom/) (accessed 2026-10-30).
- SLSA L2 requires signed provenance from a hosted build platform; L3 requires a hardened platform where signing material is inaccessible to user build steps — [SLSA levels](https://slsa.dev/spec/v1.1/levels) (accessed 2026-10-30).
- GoReleaser's verifiable builds embed module information and verify dependencies against the Go checksum database, which supports after-the-fact inspection but is not a claim of bit-reproducibility — [GoReleaser: Verifiable Builds](https://goreleaser.com/customization/builds/verifiable_builds/) (accessed 2026-10-30).

### Inferences
- Recommended order for a small team: (1) checksums, (2) `actions/attest` + `gh attestation verify` documented in the README, (3) immutable releases, (4) cosign keyless signature on checksums/archives, (5) SBOM, (6) SLSA L2 claim (automatic on GitHub-hosted runners), (7) defer L3/reproducibility.
- Cosign and GitHub attestations overlap; pick **one primary** verification story for users. GitHub attestations win for GitHub-native audiences because `gh` is already installed; cosign wins for container/registry and non-GitHub consumers.
- Branch protection + required review + pinned actions improve the Scorecard score more than any single signing feature, and cost nothing.
- For a credential-handling tool, the supply chain *is* the product claim; unsigned releases would undermine the threat model more than for a build tool.

### Gaps
- Did not verify whether any of the surveyed projects publish cosign signatures for CLI binaries (vs containers only); the Sigstore docs describe capability, not adoption.
- No source found on the cost/effort of SLSA L3 via GitHub reusable workflows.
- Reproducible-build tooling for Rust (`cargo` + `--remap-path-prefix`, `SOURCE_DATE_EPOCH`) was not researched.
- Sigstore's cosign v3 migration (referenced in GoReleaser's blog index) was not read.

---

## 4. Repository hygiene: the minimum file set and conventions

### Takeaway
The community-health baseline is well codified and cheap: **LICENSE, README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue/PR templates, SUPPORT, CHANGELOG** at the repo root, with GitHub surfacing them automatically. Version with **SemVer**, log changes in **Keep a Changelog** format, and publish an explicit compatibility/deprecation statement — that last item is what separates a "project" from a "product."

### Cited Findings
- GitHub's Open Source Guides say every project should include a license, README, contributing guidelines and code of conduct at launch; the README should answer what it does, why it is useful, how to get started, and where to get help — [Open Source Guides: Starting an Open Source Project](https://opensource.guide/starting-a-project/) (accessed 2026-10-30).
- The same guide's pre-launch checklist requires a LICENSE, basic docs (README/CONTRIBUTING/CODE_OF_CONDUCT), a tidy labelled issue queue, and — for organisations — at least two people with administrative access — [Open Source Guides](https://opensource.guide/starting-a-project/) (accessed 2026-10-30).
- GitHub's community profile surfaces a checklist of health files for public repos (code of conduct, contributing, license, security policy, issue/PR templates, support resources) — [GitHub Docs: About community profiles](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories) (accessed 2026-10-30).
- The Contributor Covenant is used by **over 40,000 open source projects**, including Kubernetes, Rails and Swift — [Open Source Guides](https://opensource.guide/starting-a-project/) (accessed 2026-10-30).
- SemVer 2.0.0: MAJOR for incompatible changes, MINOR for backward-compatible features, PATCH for backward-compatible fixes; pre-release and build metadata are extensions — [semver.org](https://semver.org/) (accessed 2026-10-30).
- Keep a Changelog 1.1.0 defines the `Added/Changed/Deprecated/Removed/Fixed/Security` structure and an `[Unreleased]` section — [keepachangelog.com](https://keepachangelog.com/en/1.1.0/) (accessed 2026-10-30).
- Go publishes an explicit compatibility promise ("Go 1 and the Future of Go Programs"), the strongest mainstream example of a written deprecation/compat policy — [go.dev/doc/go1compat](https://go.dev/doc/go1compat) (accessed 2026-10-30).
- Open Source Guides' governance chapter describes maintainer/contributor/committer roles and when to formalize them — [Open Source Guides: Leadership and Governance](https://opensource.guide/leadership-and-governance/) (accessed 2026-10-30).
- GitHub documents the `good first issue` label as the mechanism for surfacing newcomer-friendly work — [GitHub Docs: Encouraging contributions with labels](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/encouraging-helpful-contributions-to-your-project-with-labels) (accessed 2026-10-30).

### Inferences
- Minimum viable file set for a 1–3 person team (all root-level): `README.md`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `SUPPORT.md`, `.github/ISSUE_TEMPLATE/bug.yml`, `.github/ISSUE_TEMPLATE/feature.yml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/CODEOWNERS`, `GOVERNANCE.md` (even if it says "BDFL: these two people").
- README order that matches how developers evaluate tools: one-sentence what/why → install (copy-paste, per-OS) → 30-second quickstart → verify-the-download command → security model link → docs link → contributing/license. GitHub CLI, uv and Doppler all follow a close variant.
- Write the deprecation policy *before* 1.0, even if it is three sentences: what counts as breaking, how long deprecations last (e.g. one minor release with warnings), and how users are notified (CHANGELOG `Deprecated` + runtime warning).
- A `SECURITY.md` that only says "email us" is weaker than one that enables GitHub private vulnerability reporting and states a response target; the latter is visible in the repo UI.

### Gaps
- No authoritative, quantified "response time" standard was found; response SLAs are project-specific and should be stated as goals, not benchmarks.
- Could not verify a canonical minimal `GOVERNANCE.md` template for small teams (Open Source Guides describes roles but does not prescribe a file).
- The claim that GitHub auto-surfaces every health file was verified only at the checklist level, not file-by-file behaviour.

---

## 5. Documentation site: information architecture that scales

### Takeaway
The pattern that works is **Diátaxis-shaped**: a short Getting Started, task-oriented Guides/How-to, a complete CLI/API Reference, and conceptual Explanation, plus a Migration section and Troubleshooting. Versioned docs are optional before 1.0 and should be deferred until the API stabilizes; search is not optional.

### Cited Findings
- Diátaxis defines four documentation forms — tutorials, how-to guides, technical reference, explanation — and argues the site should be organised around those user needs — [diataxis.fr](https://diataxis.fr/) (accessed 2026-10-30).
- uv's docs navigation is a near-perfect implementation: Introduction, Getting started (Installation, First steps, Features, Getting help), Guides (Installing Python, Running scripts, Using tools, Working on projects, Publishing packages), Migration (From pip), Integrations (Docker, Jupyter, GitHub Actions, GitLab CI, pre-commit, PyTorch, FastAPI, ...), Concepts, Reference (Commands, Settings, Environment variables, Installer options), Troubleshooting, Contributing, Internals, Policies — [uv docs](https://docs.astral.sh/uv/) (accessed 2026-10-30).
- Deno's docs add explicit **migration guides** ("Migrating from Jest", "Migrate from npm/Yarn/pnpm/Bun") and a **Stability and releases** page, alongside Get started / Guides / Concepts / Reference — [Deno docs](https://docs.deno.com/runtime/getting_started/installation/) (accessed 2026-10-30).
- Docusaurus's versioning guide warns that versioning "can become difficult for contributors" and that "most of the time, you don't need versioning"; it is best for high-traffic docs with rapid changes between versions — [Docusaurus versioning](https://docusaurus.io/docs/versioning) (accessed 2026-10-30).
- Algolia DocSearch "is free for eligible documentation sites" and provides crawler-based indexing plus a frontend search UI — [DocSearch: What is DocSearch?](https://docsearch.algolia.com/docs/what-is-docsearch) (accessed 2026-10-30).
- GitHub CLI generates its manual pages from the CLI itself (`go run ./cmd/gen-docs --website --doc-path dist/manual`) and publishes them to its docs site on every release — [cli/cli deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).

### Inferences
- Minimum IA for a CLI: **Install** (per-OS tabs) / **Quickstart** (5 commands to first success) / **Guides** (one page per job-to-be-done) / **CLI reference** (generated, never hand-edited) / **Concepts** (threat model, architecture) / **Troubleshooting** / **Changelog**. Add **Migration** only when you have a predecessor or a breaking change.
- Generate the CLI reference from `--help` output or a schema; hand-maintained command docs drift within two releases.
- For a security tool, a **Threat model** page is documentation, not marketing; it belongs in the docs nav next to Concepts (Vaultly already has `docs/threat-model.md`).
- Search by launch: DocSearch if eligible, otherwise a static index (Pagefind) is a day of work. A docs site without search reads as abandoned at >30 pages.
- Versioned docs: defer until v1.0 or the first breaking change; keep an `unreleased`/`next` branch instead. Docusaurus's own guidance supports this.

### Gaps
- No data on docs-site conversion or support-ticket reduction; the IA recommendation is pattern-based.
- Mintlify/Starlight/Fumadocs pricing and OSS programs were not verified.
- Did not verify whether DocSearch's free tier still covers all open-source projects in 2026 beyond the eligibility statement.

---

## 6. Website: the pages a developer evaluates

### Takeaway
A credible product site is ~7 pages: landing (problem → demo → install → proof), docs, pricing (or "free/self-hosted"), changelog/blog, security/trust, comparisons, and legal (privacy/terms). For a secret manager, the **security page and comparison pages do more selling than the hero**.

### Cited Findings
- Infisical's top-level navigation is: Platform, Pricing, Developers, Docs, Community, Resources (Blog, Videos, Webinars, Case Studies), Compare (including "Infisical vs HashiCorp Vault"), Careers; the hero has dual CTAs ("Get started for free" / "Talk to an expert") and social proof ("27k stars") — [infisical.com](https://infisical.com/) (accessed 2026-10-30).
- Doppler's security page leads with a trust claim, then productised controls (breach detection, access controls, scoped tokens, encrypted fallbacks, trusted IPs, bug bounty) and compliance badges (SOC 2, ISO 27001) — [doppler.com/security](https://www.doppler.com/security) (accessed 2026-10-30).
- uv's README doubles as a landing page: one-line description, benchmark visual, feature bullets, install block, then docs links — [astral-sh/uv README](https://github.com/astral-sh/uv) (accessed 2026-10-30).
- cargo-dist/oranda can generate a landing page with a platform-detecting install widget from the same release metadata — [cargo-dist introduction](https://axodotdev.github.io/cargo-dist/book/introduction.html) (accessed 2026-10-30).

### Inferences
- Landing-page section order for a developer security tool: (1) one-sentence positioning, (2) 20-second terminal demo/GIF, (3) install command with OS tabs, (4) "how it works" diagram, (5) proof (stars, downloads, users, audit), (6) security model summary linking to the trust page, (7) comparison table vs incumbent, (8) footer with docs/status/legal.
- Pricing: publish it even if the answer is "free and open source; paid cloud later." An absent pricing page reads as "enterprise sales only" and filters out individual developers.
- Trust page contents: architecture diagram, threat model summary, crypto primitives, data-flow ("what leaves your machine"), subprocessor list, vulnerability disclosure policy, compliance reports (SOC 2/ISO 27001 if held), and a `security.txt`.
- Comparison pages are commercially important in the secret-manager category because buyers search "X vs Vault" / "X vs Doppler"; Infisical's nav confirms this pattern.
- Changelog and blog should be the same surface early: one URL, RSS feed, release notes cross-posted.

### Gaps
- No fetched evidence on the conversion impact of comparison pages; the claim is strategic inference from their presence in Infisical's nav.
- Status page and legal-page norms were not verified for the surveyed tools; `status.example.com` + privacy/terms/subprocessors are recommended from general practice, not cited.
- Did not verify whether Ollama or Turborepo use different landing-page structures (Ollama's site was not fetched).

---

## 7. Telemetry and analytics: opt-in vs opt-out for a security tool

### Takeaway
Two defensible poles exist: **Go telemetry is local-only by default and uploads only on explicit opt-in**, while **Homebrew collects anonymous aggregate analytics with a pre-enablement notice and opt-out**. For a tool that handles credentials, the only defensible default is **off/local-only, opt-in to upload**, with a published schema and a single env var to disable everything.

### Cited Findings
- Go telemetry: "By default, telemetry data is kept only on the local computer"; uploading requires the user to opt in (`go telemetry on`), and the program documents counters, charts and reporting — [go.dev/doc/telemetry](https://go.dev/doc/telemetry) (accessed 2026-10-30).
- Homebrew "displays a notice before analytics are enabled so a user can opt out before sending an event"; the payload contains **no user identifier and no IP-address field**, is retained **365 days**, and records package/command names, OS/arch, CI/developer mode, and install options — [Homebrew Anonymous Analytics](https://docs.brew.sh/Analytics) (accessed 2026-10-30).
- Homebrew explicitly warns that analytics must not replace technical evidence or maintainer judgement, and that low usage alone does not justify removing a command — [Homebrew Anonymous Analytics](https://docs.brew.sh/Analytics) (accessed 2026-10-30).
- The SLSA website itself uses **GoatCounter**, stating it stores no advertising/tracking cookies and does not identify or track individuals — [slsa.dev footer](https://slsa.dev/spec/v1.1/levels) (accessed 2026-10-30).
- npm provenance and GitHub attestations show the ecosystem's direction: verifiable build metadata is published, not behavioural telemetry — [npm provenance docs](https://docs.npmjs.com/generating-provenance-statements) (accessed 2026-10-30).

### Inferences
- For Vaultly-class software, telemetry must never include secret names, vault paths, target IDs, hostnames, account IDs, or command arguments. A safe event schema is: `event` (install/start/command_name/error_code), `version`, `os`, `arch`, `install_channel`, and a random per-install ID that the user can rotate.
- Default posture: local-only counters, `vaultly telemetry status|on|off`, honour `DO_NOT_TRACK=1`, and print a one-line notice on first run with a link to the schema. This is stricter than Homebrew and matches Go's opt-in model.
- Publish the exact event list in docs and the repo (`docs/telemetry.md`), plus a sample payload. For a security buyer, "here is the JSON we would send" is worth more than a privacy policy paragraph.
- Analytics on the *website* (Plausible/GoatCounter) is separate from product telemetry and should be cookieless; do not conflate them in the privacy page.

### Gaps
- Could not retrieve Infisical's self-hosting telemetry page (404 at the guessed URL); its docs nav does contain a "Monitoring and telemetry" entry, but content and defaults are unverified.
- No authoritative survey of developer attitudes to CLI telemetry was found; the opt-in recommendation is a security-tool judgement, not measured preference.
- Legal requirements (GDPR consent, ePrivacy) for CLI telemetry were not researched.

---

## 8. Community, cadence and maintainer sustainability

### Takeaway
Developers infer health from **release cadence and responsiveness**, not from contributor counts. In the trailing year, mature tools shipped anywhere from 3 to 100+ releases; the credible small-team rhythm is **patch releases as needed, a minor every 4–6 weeks, and a public roadmap**. Label taxonomy and `good first issue` hygiene are cheap signals that the project is run, not merely published.

### Cited Findings

**Measured cadence (GitHub API, releases published 2025-10-30 → 2026-10-30; 100 = API page cap)**
- `cli/cli`: **30** releases, latest `v2.103.3` on 2026-10-26; 46.8k stars — [releases API](https://api.github.com/repos/cli/cli/releases?per_page=100) (accessed 2026-10-30).
- `astral-sh/uv`: **100+** releases (cap), latest `0.13.6` on 2026-10-27; 91.3k stars — [releases API](https://api.github.com/repos/astral-sh/uv/releases?per_page=100) (accessed 2026-10-30).
- `supabase/cli`: **100+** releases, 94% marked pre-release, latest `v3.0.0-beta.15` on 2026-10-30; 2.4k stars — [releases API](https://api.github.com/repos/supabase/cli/releases?per_page=100) (accessed 2026-10-30).
- `getsops/sops`: **6** releases, latest `v3.13.3` on 2026-07-23; 23.6k stars — [releases API](https://api.github.com/repos/getsops/sops/releases?per_page=100) (accessed 2026-10-30).
- `FiloSottile/age`: **3** releases, latest `v1.3.2` on 2026-08-29; 24.1k stars — [releases API](https://api.github.com/repos/FiloSottile/age/releases?per_page=100) (accessed 2026-10-30).
- `vercel/turborepo`: **100+** releases, 73% pre-release (canary channel), latest `v2.11.11-canary.1` on 2026-10-29; 31.3k stars — [releases API](https://api.github.com/repos/vercel/turborepo/releases?per_page=100) (accessed 2026-10-30).
- `oven-sh/bun`: **18** releases, latest `bun-v1.4.4` on 2026-10-22; 96.5k stars — [releases API](https://api.github.com/repos/oven-sh/bun/releases?per_page=100) (accessed 2026-10-30).
- `denoland/deno`: **41** releases, latest `v2.9.8` on 2026-10-21; 108.8k stars — [releases API](https://api.github.com/repos/denoland/deno/releases?per_page=100) (accessed 2026-10-30).
- `dopplerHQ/cli`: **9** releases, latest `3.77.1` on 2026-10-22; 400 stars — [releases API](https://api.github.com/repos/dopplerHQ/cli/releases?per_page=100) (accessed 2026-10-30).
- `Infisical/infisical`: **100+** releases, latest `v0.167.4` on 2026-10-26; 30.1k stars — [releases API](https://api.github.com/repos/Infisical/infisical/releases?per_page=100) (accessed 2026-10-30).

**Other community findings**
- GitHub's `good first issue` label is the documented mechanism for flagging newcomer-friendly issues — [GitHub Docs: labels](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/encouraging-helpful-contributions-to-your-project-with-labels) (accessed 2026-10-30).
- A pre-launch checklist item is "the issue queue is up-to-date, with issues clearly organized and labeled" — [Open Source Guides](https://opensource.guide/starting-a-project/) (accessed 2026-10-30).
- Governance roles (maintainer, contributor, committer) and when to formalize them are covered by Open Source Guides — [Leadership and Governance](https://opensource.guide/leadership-and-governance/) (accessed 2026-10-30).
- The OpenSSF Best Practices badge's passing criteria require a project website that describes what the software does and how to obtain it, give feedback and contribute; a FLOSS license; and published contribution requirements — [OpenSSF Best Practices criteria](https://www.bestpractices.dev/en/criteria/0) (accessed 2026-10-30).

### Inferences
- Benchmarks to aim for as a 1–3 person team: **monthly minor release**, patch within 7 days for security issues, one public roadmap update per quarter. That places you near age/SOPS cadence (3–6/year) rather than uv/Deno (weekly), which is appropriate for a credential tool where stability beats novelty.
- Pre-release channels are a mature-project pattern, not a small-team requirement: Supabase (94%) and Turborepo (73%) use them because they ship continuously; a small team should use `-rc.N` only for breaking releases.
- Label taxonomy that is sufficient: `type: bug|feature|docs|security`, `area: cli|mcp|cloudflare|docs`, `good first issue`, `help wanted`, `needs reproduction`, `blocked`. Anything more becomes maintenance.
- Stars are a weak proxy: Doppler CLI has 400 stars but is a commercial product with a 9-release/year cadence; judge cadence, issue responsiveness, and docs completeness instead.
- Bus factor is the real sustainability risk for a 1–3 person project: document release steps, store signing keys in an organisational account, and give at least two people admin access (the Open Source Guides' checklist for organisations) — [Open Source Guides](https://opensource.guide/starting-a-project/) (accessed 2026-10-30).

### Gaps
- No verified industry benchmark for issue first-response time; any SLA should be presented as a project goal, not an industry norm.
- Could not measure contributor counts or bus factor from the API in this pass.
- No data on whether pre-release channels improve adoption; the Supabase/Turborepo percentages are descriptive only.

---

## 9. What makes developers trust and adopt a new security tool?

### Takeaway
Trust is earned by **verifiability, not claims**: signed and attested releases the user can check with one command, a public threat model, a disclosure policy with a track record, and a security page that states limits as well as guarantees. For a secret manager specifically, the differentiators are **"the credential never leaves the boundary"** (provable in code and docs) and **"we publish what we send"** (telemetry, network calls).

### Cited Findings
- OpenSSF Scorecard scores 20 checks out of 10 each, including `Signed-Releases`, `Security-Policy`, `Token-Permissions`, `Branch-Protection`, `Pinned-Dependencies`, `SBOM`, `Vulnerabilities` and `Maintained`; the action is free for public repos — [Scorecard checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md) and [scorecard-action](https://github.com/ossf/scorecard-action) (accessed 2026-10-30).
- The OpenSSF Best Practices passing badge requires a project website that explains what the software does, how to obtain it, how to give feedback and how to contribute, plus a FLOSS license — [Best Practices criteria](https://www.bestpractices.dev/en/criteria/0) (accessed 2026-10-30).
- GitHub CLI's release pipeline demonstrates the "show, don't tell" pattern: a visible checksums file, signed RPM/apt metadata, attestations, and SHA-pinned build actions — [deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- Immutable releases prevent post-publication tampering with tags/assets — [GitHub Docs](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) (accessed 2026-10-30).
- SLSA L2/L3 give buyers a vocabulary for build integrity; L2 is hosted+signed provenance, L3 adds hardened isolation — [SLSA levels](https://slsa.dev/spec/v1.1/levels) (accessed 2026-10-30).
- Doppler's trust page combines productised controls with third-party compliance (SOC 2, ISO 27001) and a bug bounty — [doppler.com/security](https://www.doppler.com/security) (accessed 2026-10-30).
- Infisical surfaces community proof (star count) and a direct comparison page against HashiCorp Vault in its primary nav — [infisical.com](https://infisical.com/) (accessed 2026-10-30).
- Homebrew's analytics page shows the transparency bar users now expect: a notice before collection, a documented payload, no user identifier or IP field, and a retention period — [Homebrew Analytics](https://docs.brew.sh/Analytics) (accessed 2026-10-30).

### Inferences
Ranked trust signals for a new security CLI, cheapest first:
1. **Verifiable install** — checksums + `gh attestation verify` / `cosign verify-blob` printed in the README, plus immutable releases.
2. **Public threat model** — what the tool protects against, what it explicitly does not (e.g. compromised host, malicious maintainer, memory scraping), and where the trust boundary sits.
3. **Disclosure policy + history** — `SECURITY.md`, GitHub private vulnerability reporting, a `security.txt`, and published advisories with credit.
4. **Independent signals** — OpenSSF Scorecard badge/score, Best Practices badge, SLSA level, SBOM.
5. **Operational transparency** — telemetry schema, network-call list, data-retention statement, status page.
6. **Third-party assurance** — SOC 2 / ISO 27001 / pen-test summary (only when true; buyers check).
7. **Social proof** — named users, case studies, stars/downloads (weakest, but expected).

For a credential boundary product, the single strongest demo is a **negative test**: show the agent attempting to read a secret and receiving a policy error, with the audit log line. That is more persuasive than any badge.

### Gaps
- No empirical study was found quantifying which trust signal changes adoption; the ranking is expert judgement.
- Audit/pen-test costs and timelines for a 1–3 person team were not researched.
- SOC 2 applicability to an OSS-only project (vs a hosted offering) was not verified.

---

## 10. A concrete 4-week checklist for a 1–3 person team

### Takeaway
A small team can reach a defensible "product ready" bar in **four working weeks** by sequencing trust-critical work first: release pipeline → signing/attestation → docs/website → packaging/community. The items below are scoped to what one person can own part-time; estimates are inferences, not measured.

### Cited Findings (patterns the checklist is derived from)
- GitHub CLI's single workflow covers build, sign, notarize, package, attest, publish and docs deployment — a template for a one-pipeline release — [deployment.yml](https://github.com/cli/cli/blob/trunk/.github/workflows/deployment.yml) (accessed 2026-10-30).
- cargo-dist generates the whole release workflow from `dist init`, including shell/PowerShell/npm/Homebrew/MSI installers — [cargo-dist](https://axodotdev.github.io/cargo-dist/book/introduction.html) (accessed 2026-10-30).
- Homebrew tap-first is legitimate and explicitly supported for software that does not yet meet core criteria — [Package Acceptance Policy](https://docs.brew.sh/Package-Acceptance-Policy) (accessed 2026-10-30).
- Winget submission is a manifest + PR, with accepted installer formats — [Microsoft Learn](https://learn.microsoft.com/en-us/windows/package-manager/package/) and [winget-pkgs](https://github.com/microsoft/winget-pkgs) (accessed 2026-10-30).
- The community-health file set and launch checklist are documented by GitHub — [Open Source Guides](https://opensource.guide/starting-a-project/) and [community profiles](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories) (accessed 2026-10-30).
- Docs IA follows Diátaxis and the uv/Deno navigation patterns — [diataxis.fr](https://diataxis.fr/), [uv docs](https://docs.astral.sh/uv/), [Deno docs](https://docs.deno.com/runtime/getting_started/installation/) (accessed 2026-10-30).
- Telemetry defaults follow Go (opt-in upload) and Homebrew (notice + opt-out, anonymised) — [Go telemetry](https://go.dev/doc/telemetry), [Homebrew Analytics](https://docs.brew.sh/Analytics) (accessed 2026-10-30).

### Inferences

**The checklist (all items are recommendations derived from the patterns above; effort estimates are judgement, not measured):**

**Week 1 — Release engineering (one owner, ~5 days)**
- [ ] Pick cargo-dist (Rust-native) or GoReleaser; generate the release workflow; commit it.
- [ ] Build the core matrix: linux x86_64/aarch64 (gnu, plus musl for static/Alpine), macOS arm64/x86_64, windows x86_64; add windows arm64 if the runner matrix allows.
- [ ] Publish `.tar.gz`/`.zip`, `SHA256SUMS`, and a `source.tar.gz` to GitHub Releases on tag push.
- [ ] Write `install.sh` and `install.ps1`: `--version`, no sudo, HTTPS-only, checksum verification, clear error messages.
- [ ] Add `gh attestation verify` instructions to the README and docs.
- [ ] Enable immutable releases in repo settings.
- [ ] Freeze release naming: `vMAJOR.MINOR.PATCH`, pre-releases `-rc.N`; tag protection on `v*`.

**Week 2 — Signing and supply chain (~4 days)**
- [ ] macOS: Developer ID certificate + App Store Connect API key + `notarytool` in CI; staple/notarize zips or pkg.
- [ ] Windows: Microsoft Artifact Signing (Azure Trusted Signing) via OIDC; sign `.exe` and `.msi`.
- [ ] Linux: GPG-sign RPMs if shipping them; sign repo metadata only if hosting a repo.
- [ ] Cosign keyless signature on checksums/archives (`cosign sign-blob --yes`), documented verification.
- [ ] SBOM per archive (Syft via GoReleaser, or `cargo cyclonedx`/`syft` in CI).
- [ ] Add OpenSSF Scorecard action; fix `Token-Permissions`, `Pinned-Dependencies`, `Branch-Protection`.
- [ ] Enable Dependabot + CodeQL; require review on `main`.

**Week 3 — Docs and website (~5 days)**
- [ ] Docs site with nav: Install / Quickstart / Guides / CLI reference (generated) / Concepts / Threat model / Troubleshooting / Changelog.
- [ ] Search (DocSearch if eligible, else Pagefind).
- [ ] One tutorial that reaches a successful real operation in <5 minutes, tested on a clean machine.
- [ ] README rewrite: positioning → install tabs → quickstart → verify → security model → docs.
- [ ] Landing page: hero, terminal demo, install tabs, how-it-works diagram, proof, security summary, comparison table, footer.
- [ ] Trust page: threat model summary, crypto, data flows, telemetry schema, disclosure policy, compliance status.
- [ ] Privacy/terms pages + `security.txt`.

**Week 4 — Packaging and community (~5 days)**
- [ ] Homebrew tap (`brew install owner/tap/tool`); submit to core only after notability thresholds.
- [ ] Winget manifest + PR (`winget install`), Scoop bucket, Docker image (multi-arch) if server-side use applies.
- [ ] npm/PyPI wrapper only if the audience expects it; enable npm provenance.
- [ ] `SECURITY.md` with private vulnerability reporting + response target; `CONTRIBUTING.md`; `CODE_OF_CONDUCT.md` (Contributor Covenant); `SUPPORT.md`; issue forms; PR template; `CODEOWNERS`.
- [ ] `CHANGELOG.md` (Keep a Changelog) + compatibility/deprecation statement.
- [ ] `GOVERNANCE.md` naming maintainers and decision rule; roadmap issue/project.
- [ ] Seed 10–15 `good first issue` / `help wanted` issues; publish label taxonomy.
- [ ] Publish telemetry doc + `--no-telemetry`/`DO_NOT_TRACK` behaviour.
- [ ] Announce cadence: "minor every 4–6 weeks, patches as needed."

**Definition of done (12 gates)**
1. `curl … | sh`, `brew install`, `winget install`, `docker run` all work from a clean machine.
2. Every artifact has a SHA-256 and a verifiable attestation; verification is documented.
3. macOS app opens without Gatekeeper warnings; Windows SmartScreen does not block.
4. Releases are immutable; tags are protected.
5. Docs site has search, a generated CLI reference, and a 5-minute quickstart.
6. `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `CHANGELOG.md` exist and are linked from README.
7. A threat model is public and states non-goals.
8. Telemetry is off/local-only by default and its schema is published.
9. Scorecard score is published and ≥7 on `Signed-Releases`, `Security-Policy`, `Token-Permissions`.
10. At least one release has shipped on the stated cadence, with notes a user can understand.
11. A `good first issue` queue exists and at least one external contribution has been merged.
12. Pricing (even "free") and a security/trust page are live.

**Explicitly defer (not launch blockers):** SLSA L3, bit-reproducible builds, hosted apt/yum repos, SOC 2, independent pen-test, versioned docs, Snap/Flatpak, Nix packaging, a second signing scheme (pick cosign *or* GitHub attestations as primary).

**Vaultly-specific mapping (inference):** the repo already has `install.sh`, `Formula/vaultly.rb`, `docs/threat-model.md`, `docs/cli-reference.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, and a `release.yml`; the gaps versus the gates above are most likely macOS notarization, Windows signing, attestations/SBOM, Winget/Scoop/Docker channels, a public docs site with search, `SECURITY.md`/`CODE_OF_CONDUCT.md`/`SUPPORT.md`, and an immutable-release + tag-protection setting. The highest-leverage next step is to make the existing release workflow produce signed, attested artifacts for the core matrix, because everything else (Homebrew, Winget, Docker) can point at the same assets.

### Gaps
- Effort estimates are judgement based on the cited tooling; no time-tracking data from comparable teams was found.
- The checklist assumes GitHub Actions; GitLab CI equivalents were not researched.
- Windows signing eligibility/identity verification requirements for a new organisation were not verified.
- No verified benchmark for "how many good first issues" or "how fast to respond" exists; those numbers are conventions, not standards.

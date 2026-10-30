import Nav from "@/components/Nav";
import Footer from "@/components/Footer";

export default function Security() {
  return (
    <main className="min-h-screen bg-bg text-fg">
      <Nav />
      <div className="pagehead"><h1>Security model</h1><p>What Vaultly protects against, and what it explicitly does not.</p></div>
      <div className="container py-12">
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            { icon: "🔒", title: "Cryptography", desc: "AES-256-GCM with a 16-byte nonce, PBKDF2-SHA256 at 600k iterations. Master key is never stored." },
            { icon: "📁", title: "Storage", desc: "Vault files are 0600, directory 0700. Atomic writes with fsync. Inter-process write lock. Hash-chained audit log." },
            { icon: "🤖", title: "Agent boundary", desc: "Agents cannot call get, env, export or generic run. Values scrubbed from all subprocess output." },
            { icon: "📋", title: "Audit", desc: "Every operation appended to a hash-chained log. Tampering detected by vaultly audit --verify." },
            { icon: "📦", title: "Supply chain", desc: "SHA-256 checksums, GitHub attestations, immutable releases, cosign signatures, SBOM, pinned actions." },
            { icon: "⚠️", title: "Threat model", desc: "Protects against leaked transcripts, prompt injection, compromised CI logs. Not a compromised host." },
          ].map((c) => (
            <div key={c.title} className="glass rounded-2xl p-7">
              <div className="text-3xl mb-3">{c.icon}</div>
              <h3 className="text-xl font-bold mb-2">{c.title}</h3>
              <p className="text-muted text-sm">{c.desc}</p>
            </div>
          ))}
        </div>
        <div className="mt-16">
          <h2 className="text-3xl font-bold mb-4">Verify a download</h2>
          <pre className="text-sm">gh attestation verify ./vaultly -R Growth-Club/vaultly{"\n"}cosign verify-blob --certificate-identity-regexp &apos;https://github.com/Growth-Club/.*&apos; \{"\n"}  --certificate-oidc-issuer https://token.actions.githubusercontent.com \{"\n"}  vaultly checksums.txt</pre>
        </div>
        <div className="mt-12">
          <h2 className="text-3xl font-bold mb-4">Disclosure</h2>
          <p className="text-muted">Report vulnerabilities via <a href="https://github.com/Growth-Club/vaultly/security/advisories/new" className="text-emerald-400">GitHub private vulnerability reporting</a>. We aim to respond within 72 hours.</p>
        </div>
      </div>
      <Footer />
    </main>
  );
}
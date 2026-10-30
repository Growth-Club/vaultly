import Nav from "@/components/Nav";
import Footer from "@/components/Footer";

export default function Docs() {
  return (
    <main className="min-h-screen bg-bg text-fg">
      <Nav />
      <div className="pagehead"><h1>Documentation</h1><p>Diátaxis-shaped: tutorials, how-to guides, reference, explanation.</p></div>
      <div className="container py-12">
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[
            { icon: "🚀", title: "Quickstart", desc: "From zero to a deployed Worker in 5 minutes.", code: "vaultly init\nvaultly add prod -k DATABASE_URL -v 'postgres://...'\nvaultly list prod\nvaultly run prod -- npm run migrate\nvaultly deploy api" },
            { icon: "📖", title: "Core concepts", desc: "Vault, agent mode, human mode, deployment target, policy, trash.", list: ["Vault — encrypted file holding named credentials","Agent mode — default, blocks value reads","Human mode — VAULTLY_HUMAN_MODE=1","Deployment target — registered metadata","Policy — owner-managed agent-policy.json","Trash — soft-deleted secrets, recoverable"] },
            { icon: "🤖", title: "MCP server", desc: "Start with vaultly mcp. Advertises 38 agent-safe tools over stdio JSON-RPC 2.0." },
            { icon: "🔍", title: "CLI reference", desc: "Generated from vaultly --help. See docs/cli-reference.md in the repo." },
            { icon: "☁️", title: "Cloudflare", desc: "Accounts, zones, Workers, D1, R2, KV discovery. Adopt targets from a Wrangler config." },
            { icon: "🛡️", title: "Threat model", desc: "See docs/threat-model.md in the repository for the full trust boundary analysis." },
          ].map((c) => (
            <div key={c.title} className="glass rounded-2xl p-7">
              <div className="text-3xl mb-3">{c.icon}</div>
              <h3 className="text-xl font-bold mb-2">{c.title}</h3>
              <p className="text-muted text-sm mb-4">{c.desc}</p>
              {c.code && <pre className="text-xs">{c.code}</pre>}
              {c.list && <ul className="space-y-1 text-sm text-muted">{c.list.map((l) => <li key={l}>→ {l}</li>)}</ul>}
            </div>
          ))}
        </div>
        <div className="mt-16 text-center">
          <a href="https://github.com/Growth-Club/vaultly/issues" className="btn btn-primary">Open an issue</a>
          <a href="https://github.com/Growth-Club/vaultly/discussions" className="btn btn-outline ml-3">Discussions</a>
        </div>
      </div>
      <Footer />
    </main>
  );
}
import Nav from "@/components/Nav";
import Footer from "@/components/Footer";

export default function SelfHosted() {
  return (
    <main className="min-h-screen bg-bg text-fg">
      <Nav />
      <div className="pagehead"><h1>Self-hosted</h1><p>Run Vaultly on your own infrastructure. Your data never leaves your machine.</p></div>
      <div className="container py-12">
        <div className="grid md:grid-cols-2 gap-8">
          <div>
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-white/4 border border-white/8 text-emerald-400 mb-4">Community edition</span>
            <h3 className="text-2xl font-bold mb-3">Self-host the CLI & MCP</h3>
            <p className="text-muted mb-6">The core Vaultly CLI and MCP server are a single static binary. No SaaS, no account, no telemetry by default.</p>
            <pre className="text-sm"><span className="text-muted2"># Install</span>{"\n"}<span className="text-emerald-400">$</span> curl -fsSL https://vaultly.dev/install.sh | sh{"\n\n"}<span className="text-muted2"># Initialize</span>{"\n"}<span className="text-emerald-400">$</span> vaultly init{"\n\n"}<span className="text-muted2"># Run MCP server for agents</span>{"\n"}<span className="text-emerald-400">$</span> vaultly mcp</pre>
          </div>
          <div className="glass rounded-2xl p-6">
            <h3 className="text-2xl font-bold mb-3">Docker</h3>
            <p className="text-muted mb-4">Run Vaultly in a container for CI/CD or isolated environments.</p>
            <pre className="text-sm"><span className="text-emerald-400">$</span> docker run -v ~/.vaultly:/data \{"\n"}  -e VAULTLY_MASTER_PASSWORD=... \{"\n"}  ghcr.io/growth-club/vaultly:latest \{"\n"}  vaultly status</pre>
            <p className="mt-4 text-sm text-muted2">Mount a volume for persistent vault storage.</p>
          </div>
        </div>
        <div className="mt-16">
          <h2 className="text-3xl font-bold mb-4">Platform (team features)</h2>
          <p className="text-muted mb-6">Self-host the team control plane with Docker Compose.</p>
          <pre className="text-sm"><span className="text-muted2"># Clone the platform repo</span>{"\n"}<span className="text-emerald-400">$</span> git clone https://github.com/Growth-Club/vaultly-platform.git{"\n"}<span className="text-emerald-400">$</span> cd vaultly-platform{"\n"}<span className="text-emerald-400">$</span> cp .env.example .env{"\n"}<span className="text-emerald-400">$</span> docker compose up -d</pre>
        </div>
        <div className="mt-16 text-center rounded-3xl p-12 border border-white/8 bg-gradient-to-br from-emerald-500/8 to-indigo-500/8">
          <h2 className="text-3xl font-extrabold mb-3">Self-hosted by default</h2>
          <p className="text-muted mb-6">Your data, your infrastructure, your rules.</p>
          <div className="flex gap-3 justify-center">
            <a href="#install" className="btn btn-primary">Get started</a>
            <a href="https://github.com/Growth-Club/vaultly" className="btn btn-outline">View source</a>
          </div>
        </div>
      </div>
      <Footer />
    </main>
  );
}
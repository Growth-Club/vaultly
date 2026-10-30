export default function Home() {
  return (
    <main className="min-h-screen bg-bg text-fg">
      {/* Nav */}
      <nav className="sticky top-0 z-50 flex items-center justify-between px-6 md:px-10 py-4 bg-black/70 backdrop-blur-xl border-b border-white/8">
        <a href="/" className="font-extrabold text-lg tracking-tight flex items-center gap-2">
          <img src="/logo.svg" alt="Vaultly" className="w-7 h-7" />
          <span>Vaultly</span>
        </a>
        <div className="hidden md:flex items-center gap-8 text-sm font-medium text-muted">
          <a href="/docs" className="hover:text-fg transition">Docs</a>
          <a href="/security" className="hover:text-fg transition">Security</a>
          <a href="/self-hosted" className="hover:text-fg transition">Self-hosted</a>
          <a href="/compare" className="hover:text-fg transition">Compare</a>
          <a href="/pricing" className="hover:text-fg transition">Pricing</a>
          <a href="/changelog" className="hover:text-fg transition">Changelog</a>
          <a href="https://github.com/Growth-Club/vaultly" className="px-4 py-2 rounded-lg bg-white text-black font-semibold text-sm hover:bg-zinc-200 transition">GitHub</a>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative px-6 md:px-10 pt-24 pb-20 text-center overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute w-[600px] h-[600px] rounded-full bg-emerald-500/20 blur-[120px] -top-40 -left-20" />
          <div className="absolute w-[500px] h-[500px] rounded-full bg-indigo-500/20 blur-[120px] -bottom-20 -right-20" />
          <div className="absolute w-[400px] h-[400px] rounded-full bg-sky-500/15 blur-[100px] top-40 right-1/4" />
        </div>
        <div className="relative max-w-5xl mx-auto">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-medium bg-white/4 border border-white/8 text-muted mb-8">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399] animate-pulse" />
            Agent-first · Zero-knowledge · Open source
          </div>
          <h1 className="text-5xl md:text-7xl font-black tracking-tighter leading-[0.95] mb-6">
            Bring any agent.<br />
            <span className="grad-text">They never see your secrets.</span>
          </h1>
          <p className="text-lg md:text-xl text-muted max-w-2xl mx-auto mb-8 leading-relaxed">
            One workspace for Claude Code, Codex, Cursor, and any coding agent. Vaultly sits between your agents and your credentials — agents request approved operations and never receive a stored secret.
          </p>
          <div className="flex flex-wrap gap-3 justify-center mb-6">
            <a href="#install" className="btn btn-primary">Download for macOS</a>
            <a href="https://github.com/Growth-Club/vaultly" className="btn btn-outline">Star on GitHub</a>
          </div>
          <p className="text-sm text-muted2">Or ask your coding agent to install the Vaultly CLI.</p>
          <pre className="max-w-md mx-auto mt-4 text-left">$ brew install Growth-Club/tap/vaultly</pre>

          <div className="mt-16 max-w-4xl mx-auto glass rounded-2xl overflow-hidden shadow-2xl">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-white/8 bg-white/[0.02]">
              <span className="w-3 h-3 rounded-full bg-red-500" /><span className="w-3 h-3 rounded-full bg-yellow-500" /><span className="w-3 h-3 rounded-full bg-green-500" />
              <span className="ml-3 text-xs text-muted2 font-mono">vaultly — zsh</span>
            </div>
            <div className="p-6 font-mono text-sm leading-7 text-left">
              <div><span className="text-muted2 select-none mr-4">1</span><span className="text-emerald-400">$</span> vaultly run cf-prod -- npm run deploy</div>
              <div><span className="text-muted2 select-none mr-4">2</span><span className="text-muted">✓ Injected 4 secrets (scrubbed from output)</span></div>
              <div><span className="text-muted2 select-none mr-4">3</span><span className="text-emerald-400">$</span> vaultly preflight api --json</div>
              <div><span className="text-muted2 select-none mr-4">4</span><span className="text-emerald-400">{'{"pendingMigrations":2,"safety":"safe"}'}</span></div>
              <div><span className="text-muted2 select-none mr-4">5</span><span className="text-emerald-400">$</span> vaultly deploy api</div>
              <div><span className="text-muted2 select-none mr-4">6</span><span className="text-emerald-400">✓ Deployed · https://api.example.workers.dev</span></div>
              <div><span className="text-muted2 select-none mr-4">7</span><span className="text-emerald-400">$</span> vaultly audit --verify</div>
              <div><span className="text-muted2 select-none mr-4">8</span><span className="text-emerald-400">✓ Chain intact · 42 entries</span></div>
            </div>
          </div>
        </div>
      </section>

      {/* Trusted by */}
      <section className="py-12 text-center">
        <div className="container">
          <p className="text-xs uppercase tracking-widest text-muted2 mb-8">Built for the open-source ecosystem</p>
          <div className="flex flex-wrap gap-10 justify-center items-center opacity-40 grayscale">
            {["Supabase","Infisical","Doppler","Pulumi","Vercel","Cloudflare","GitHub","HashiCorp"].map((n) => (
              <span key={n} className="text-lg font-bold text-muted">{n}</span>
            ))}
          </div>
        </div>
      </section>

      <div className="h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />

      {/* Install */}
      <section id="install" className="py-24 bg-bg2">
        <div className="container">
          <div className="text-center mb-12">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-white/4 border border-white/8 text-emerald-400 mb-4">Get started</span>
            <h2 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4">Install in seconds</h2>
            <p className="text-muted text-lg max-w-xl mx-auto">One binary, no runtime. Works on macOS, Linux and Windows.</p>
          </div>
          <div className="grid md:grid-cols-2 gap-8 items-start">
            <div>
              <pre className="text-sm"><span className="text-muted2"># macOS / Linux</span>{"\n"}<span className="text-emerald-400">$</span> curl -fsSL https://vaultly.dev/install.sh | sh{"\n\n"}<span className="text-muted2"># Homebrew</span>{"\n"}<span className="text-emerald-400">$</span> brew install Growth-Club/tap/vaultly{"\n\n"}<span className="text-muted2"># Cargo</span>{"\n"}<span className="text-emerald-400">$</span> cargo install vaultly</pre>
              <p className="mt-6 text-sm text-muted2">Every artifact ships with SHA-256 checksums, GitHub attestations and cosign signatures. <a href="/security" className="text-emerald-400">Verify a download →</a></p>
            </div>
            <div className="glass rounded-2xl p-6">
              <h3 className="text-xl font-bold mb-2">First 5 commands</h3>
              <p className="text-muted mb-4">From zero to a deployed Worker.</p>
              <pre className="text-sm"><span className="text-emerald-400">$</span> vaultly init{"\n"}<span className="text-emerald-400">$</span> vaultly add prod -k DATABASE_URL -v &apos;postgres://...&apos;{"\n"}<span className="text-emerald-400">$</span> vaultly list prod{"\n"}<span className="text-emerald-400">$</span> vaultly run prod -- npm run migrate{"\n"}<span className="text-emerald-400">$</span> vaultly deploy api</pre>
            </div>
          </div>
        </div>
      </section>

      {/* Why Vaultly */}
      <section className="py-24">
        <div className="container">
          <div className="text-center mb-12">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-white/4 border border-white/8 text-emerald-400 mb-4">Why Vaultly</span>
            <h2 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4">Built for the agent era</h2>
            <p className="text-muted text-lg max-w-2xl mx-auto">Every competitor was designed for humans typing passwords. Vaultly is designed for agents that must never read them.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-5">
            {[
              { icon: "🔐", title: "Zero-knowledge to agents", desc: "vaultly get, env and generic run are blocked in agent mode by default. Only approved operations pass the boundary." },
              { icon: "🛡️", title: "Policy-gated execution", desc: "Deployment targets are registered metadata. Agents deploy or run allowlisted scripts — never arbitrary commands." },
              { icon: "☁️", title: "Cloudflare-native", desc: "Discover accounts, zones, Workers, D1, R2, KV. Adopt targets from a Wrangler config." },
              { icon: "📋", title: "Tamper-evident audit", desc: "Every operation is hash-chained (prevHash). Verify the whole chain with one command. No value ever logged." },
              { icon: "🔄", title: "Encrypted local dev", desc: "Production-identical semantics on your laptop. No plaintext .wrangler/state, no real cloud account required." },
              { icon: "🤖", title: "MCP server built in", desc: "38 agent-safe tools over stdio JSON-RPC 2.0. Works with Claude Code, Cursor, Codex and OpenCode." },
            ].map((f) => (
              <div key={f.title} className="glass rounded-2xl p-7 hover:border-emerald-500/30 transition hover:-translate-y-1">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-400 to-indigo-500 flex items-center justify-center text-2xl mb-4 text-black shadow-lg shadow-emerald-500/20">{f.icon}</div>
                <h3 className="text-xl font-bold mb-2 tracking-tight">{f.title}</h3>
                <p className="text-muted text-sm leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="py-24 bg-bg2">
        <div className="container">
          <div className="text-center mb-12">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-white/4 border border-white/8 text-emerald-400 mb-4">How it works</span>
            <h2 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4">Three layers, one trust boundary</h2>
            <p className="text-muted text-lg max-w-2xl mx-auto">Humans hold the control plane. Agents hold nothing.</p>
          </div>
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div className="glass rounded-2xl p-6">
              <div className="font-mono text-sm leading-7">
                <div className="text-muted2 italic"># Layer 1 — Human control plane</div>
                <div className="text-muted">master password → OS keychain → unlock</div>
                <div className="text-muted">add · rotate · delete · rekey · policy</div>
                <div className="text-muted2 italic mt-3"># Layer 2 — Agent broker</div>
                <div className="text-muted">MCP / CLI → policy engine → scrubber</div>
                <div className="text-muted">metadata + status only · no values</div>
                <div className="text-muted2 italic mt-3"># Layer 3 — Approved execution</div>
                <div className="text-muted">deploy · exec (allowlisted) · sync</div>
                <div className="text-muted">scoped creds · never in build logs</div>
              </div>
            </div>
            <div>
              <h3 className="text-3xl font-bold tracking-tight mb-4">Humans unlock. Agents request. Vaultly decides.</h3>
              <p className="text-muted mb-6 leading-relaxed">Vaultly sits between your agents and your secrets. The master password lives in your OS keychain. Agents talk to a policy engine that can grant operations but never values.</p>
              <ul className="space-y-3 text-muted">
                {["Master password never leaves the credential store","Secret values scrubbed from all subprocess output","Hash-chained audit trail for every operation","Policy file is owner-managed (mode 0600)","Expired credentials block subprocess execution","Encrypted local profile with production semantics"].map((t) => (
                  <li key={t} className="flex items-start gap-3"><span className="text-emerald-400 font-bold">→</span>{t}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Feature parity */}
      <section className="py-24">
        <div className="container">
          <div className="text-center mb-12">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-white/4 border border-white/8 text-emerald-400 mb-4">Feature parity</span>
            <h2 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4">Matched against the top 20 secret managers</h2>
            <p className="text-muted text-lg max-w-2xl mx-auto">Capability matrix derived from deep competitor research.</p>
          </div>
          <div className="max-w-3xl mx-auto overflow-hidden rounded-2xl border border-white/8 bg-white/[0.02]">
            <table className="w-full">
              <thead><tr className="border-b border-white/8">
                <th className="text-left px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Capability</th>
                <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Vaultly</th>
                <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Typical competitor</th>
              </tr></thead>
              <tbody>
                {[
                  ["Encrypted vault (AES-256-GCM)","✓","✓"],
                  ["Secret versioning + rollback","✓","✓"],
                  ["Soft delete (trash) + restore","✓","partial"],
                  ["Agent never receives values (default)","✓","opt-in"],
                  ["Policy-gated deploy / exec","✓","✗"],
                  ["MCP server","✓ 38 tools","experimental"],
                  ["Tamper-evident audit","✓ hash-chained","plain logs"],
                  ["Cloudflare D1 / R2 bootstrap","✓","✗"],
                  ["Drift comparison","✓","rare"],
                  ["Secret references ($\u007bKEY\u007d)","✓","✓"],
                  ["Free & open source","✓ MIT","varies"],
                ].map(([c,v,t]) => (
                  <tr key={c} className="border-b border-white/8 last:border-0 hover:bg-white/[0.03] transition">
                    <td className="px-6 py-4 font-medium">{c}</td>
                    <td className="px-6 py-4 text-center text-emerald-400 font-bold">{v}</td>
                    <td className="px-6 py-4 text-center text-muted">{t}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-center mt-6"><a href="/compare" className="text-emerald-400">Full comparison →</a></p>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 text-center">
        <div className="container">
          <div className="max-w-3xl mx-auto rounded-3xl p-12 border border-white/8 bg-gradient-to-br from-emerald-500/8 to-indigo-500/8 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent pointer-events-none" />
            <div className="relative">
              <h2 className="text-4xl md:text-5xl font-extrabold tracking-tight mb-4">Ready to put a boundary between your agents and your secrets?</h2>
              <p className="text-muted text-lg mb-8">Open source. Free forever. One binary. No SaaS required.</p>
              <div className="flex flex-wrap gap-3 justify-center">
                <a href="#install" className="btn btn-primary">Install Vaultly</a>
                <a href="https://github.com/Growth-Club/vaultly" className="btn btn-outline">View on GitHub</a>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/8 pt-16 pb-8">
        <div className="container">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-10 mb-12">
            <div>
              <div className="font-extrabold text-xl mb-3 flex items-center gap-2"><img src="/logo.svg" alt="Vaultly" className="w-7 h-7" /> Vaultly</div>
              <p className="text-muted text-sm leading-relaxed">The credential boundary for human and AI work. Agent-first, zero-knowledge, open source.</p>
            </div>
            <div>
              <h4 className="text-xs uppercase tracking-widest text-muted2 font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-muted">
                <li><a href="/docs" className="hover:text-fg transition">Docs</a></li>
                <li><a href="/security" className="hover:text-fg transition">Security</a></li>
                <li><a href="/self-hosted" className="hover:text-fg transition">Self-hosted</a></li>
                <li><a href="/compare" className="hover:text-fg transition">Compare</a></li>
                <li><a href="/pricing" className="hover:text-fg transition">Pricing</a></li>
                <li><a href="/changelog" className="hover:text-fg transition">Changelog</a></li>
              </ul>
            </div>
            <div>
              <h4 className="text-xs uppercase tracking-widest text-muted2 font-semibold mb-4">Resources</h4>
              <ul className="space-y-2 text-sm text-muted">
                <li><a href="https://github.com/Growth-Club/vaultly" className="hover:text-fg transition">GitHub</a></li>
                <li><a href="https://github.com/Growth-Club/vaultly/issues" className="hover:text-fg transition">Issues</a></li>
                <li><a href="https://github.com/Growth-Club/vaultly/discussions" className="hover:text-fg transition">Discussions</a></li>
                <li><a href="https://github.com/Growth-Club/vaultly-platform" className="hover:text-fg transition">Platform</a></li>
              </ul>
            </div>
            <div>
              <h4 className="text-xs uppercase tracking-widest text-muted2 font-semibold mb-4">Legal</h4>
              <ul className="space-y-2 text-sm text-muted">
                <li><a href="/security" className="hover:text-fg transition">Security policy</a></li>
                <li><a href="https://github.com/Growth-Club/vaultly/blob/main/LICENSE" className="hover:text-fg transition">License (MIT)</a></li>
              </ul>
            </div>
          </div>
          <div className="border-t border-white/8 pt-6 flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-muted2">
            <span>© 2026 Vaultly · MIT licensed · Built for the agent era.</span>
            <span>v1.2.2</span>
          </div>
        </div>
      </footer>
    </main>
  );
}
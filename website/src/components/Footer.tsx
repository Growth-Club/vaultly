export default function Footer() {
  return (
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
  );
}
export default function Nav() {
  return (
    <nav className="sticky top-0 z-50 flex items-center justify-between px-6 md:px-10 py-4 bg-black/70 backdrop-blur-xl border-b border-white/8">
      <a href="/" className="font-extrabold text-lg tracking-tight">🔐 Vaultly</a>
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
  );
}
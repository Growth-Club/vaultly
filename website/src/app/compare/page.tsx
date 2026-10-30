import Nav from "@/components/Nav";
import Footer from "@/components/Footer";

export default function Compare() {
  const rows = [
    ["Agent never receives values (default)","✓","✗","partial","✗","✗"],
    ["Policy-gated deploy / exec","✓","✗","✗","✗","policy"],
    ["MCP server","✓ 38 tools","experimental","partial","✗","✗"],
    ["Cloudflare D1 / R2 bootstrap","✓","✗","✗","✗","✗"],
    ["Tamper-evident audit","✓","retention","✓","usage","audit devices"],
    ["Local encrypted dev","✓","✗","self-host","✗","self-host"],
    ["Secret versioning + rollback","✓","✓","✓","items","KV v2"],
    ["Soft delete (trash)","✓","✗","✗","trash","soft delete"],
    ["Secret references","✓","✓","✓","op://","✗"],
    ["Free & open source","✓ MIT","limited","core MIT","✗","BSL"],
  ];
  return (
    <main className="min-h-screen bg-bg text-fg">
      <Nav />
      <div className="pagehead"><h1>How Vaultly compares</h1><p>Capability matrix against the most common alternatives.</p></div>
      <div className="container py-12">
        <div className="overflow-hidden rounded-2xl border border-white/8 bg-white/[0.02]">
          <table className="w-full">
            <thead><tr className="border-b border-white/8">
              <th className="text-left px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Capability</th>
              <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Vaultly</th>
              <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Doppler</th>
              <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Infisical</th>
              <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">1Password</th>
              <th className="text-center px-6 py-4 text-xs uppercase tracking-widest text-muted2 font-semibold">Vault</th>
            </tr></thead>
            <tbody>
              {rows.map(([c,v,d,i,o,vl]) => (
                <tr key={c} className="border-b border-white/8 last:border-0 hover:bg-white/[0.03] transition">
                  <td className="px-6 py-4 font-medium">{c}</td>
                  <td className="px-6 py-4 text-center text-emerald-400 font-bold">{v}</td>
                  <td className="px-6 py-4 text-center text-muted">{d}</td>
                  <td className="px-6 py-4 text-center text-muted">{i}</td>
                  <td className="px-6 py-4 text-center text-muted">{o}</td>
                  <td className="px-6 py-4 text-center text-muted">{vl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-center mt-6 text-muted text-sm">Vaultly is agent-first by default; competitors are human-first with agent features bolted on.</p>
      </div>
      <Footer />
    </main>
  );
}
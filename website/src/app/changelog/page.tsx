import Nav from "@/components/Nav";
import Footer from "@/components/Footer";

export default function Changelog() {
  const entries = [
    { ver: "Unreleased", title: "Product parity expansion", desc: "Added vaultly run, diff, secret versioning + rollback, soft-delete trash, secret references, and a new website." },
    { ver: "v1.2.2", title: "Linux credential-store unlock fix", desc: "Fixed encrypted Secret Service sessions and canonical-store identity on Linux." },
    { ver: "v1.2.0", title: "First tagged release of the Rust port", desc: "Full Rust rewrite: CLI, MCP server, Cloudflare integration, deployment targets, D1/R2 bootstrap." },
  ];
  return (
    <main className="min-h-screen bg-bg text-fg">
      <Nav />
      <div className="pagehead"><h1>Changelog</h1><p>Release notes and updates.</p></div>
      <div className="container py-12 max-w-3xl">
        {entries.map((e) => (
          <div key={e.ver} className="glass rounded-2xl p-7 mb-5">
            <span className="inline-block px-3 py-1 rounded-full text-xs font-semibold bg-white/4 border border-white/8 text-emerald-400 mb-3">{e.ver}</span>
            <h3 className="text-xl font-bold mb-2">{e.title}</h3>
            <p className="text-muted text-sm">{e.desc}</p>
          </div>
        ))}
      </div>
      <Footer />
    </main>
  );
}
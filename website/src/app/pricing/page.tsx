import Nav from "@/components/Nav";
import Footer from "@/components/Footer";
import { Sprout, Users, Building2 } from "lucide-react";

export default function Pricing() {
  const tiers = [
    { name: "Community", price: "Free", desc: "MIT licensed, self-hosted, unlimited vaults and secrets.", featured: false, items: ["AES-256-GCM vaults","CLI + MCP server","Cloudflare integration","Hash-chained audit","Secret versioning + trash","Self-hosted by default"] },
    { name: "Team", price: "$8", unit: "/user/mo", desc: "Managed control plane (coming).", featured: true, items: ["Shared vaults","Change approvals","Audit retention 90 days","SSO","Priority support"] },
    { name: "Enterprise", price: "Custom", desc: "Self-host or dedicated, compliance, SLAs.", featured: false, items: ["SOC 2 / ISO 27001","SCIM + SAML","Custom retention","Dedicated support","On-prem deployment"] },
  ];
  return (
    <main className="min-h-screen bg-bg text-fg">
      <Nav />
      <div className="pagehead"><h1>Pricing</h1><p>Free and open source. Paid cloud later.</p></div>
      <div className="container py-12">
        <div className="grid md:grid-cols-3 gap-6 max-w-5xl mx-auto">
          {tiers.map((t) => (
            <div key={t.name} className={`rounded-2xl p-8 border ${t.featured ? "border-emerald-500/40 bg-gradient-to-b from-white/[0.04] to-emerald-500/5 scale-105" : "border-white/8 bg-white/[0.02]"}`}>
              <h3 className="text-sm font-semibold text-muted uppercase tracking-widest mb-2">{t.name}</h3>
              <div className="text-5xl font-black tracking-tight mb-1">{t.price}<span className="text-lg text-muted font-medium">{t.unit}</span></div>
              <p className="text-muted text-sm mb-6">{t.desc}</p>
              <ul className="space-y-2 mb-8">
                {t.items.map((i) => <li key={i} className="text-sm text-muted flex items-start gap-2"><span className="text-emerald-400 font-bold">✓</span>{i}</li>)}
              </ul>
              <a href={t.name === "Enterprise" ? "mailto:hello@vaultly.dev" : "https://github.com/Growth-Club/vaultly"} className={`btn w-full text-center ${t.featured ? "btn-primary" : ""}`}>{t.name === "Community" ? "Get started" : t.name === "Team" ? "Join waitlist" : "Contact sales"}</a>
            </div>
          ))}
        </div>
      </div>
      <Footer />
    </main>
  );
}
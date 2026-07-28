/**
 * Vaultly Backup Worker
 *
 * Stores ENCRYPTED vault blobs in Cloudflare KV.
 * This Worker CANNOT read your secrets — it only stores ciphertext.
 *
 * Security:
 * - Requires Bearer token auth (set via `wrangler secret put BACKUP_TOKEN`)
 * - Only stores/returns encrypted data
 * - Rate-limited by Cloudflare's built-in protections
 * - Optional: put behind Cloudflare Access for zero-trust
 *
 * Endpoints:
 *   PUT  /backup  — store encrypted vault bundle
 *   GET  /backup  — retrieve encrypted vault bundle
 *   GET  /health  — health check
 */

interface Env {
  VAULTLY_KV: KVNamespace;
  BACKUP_TOKEN: string;
}

const BACKUP_KEY = "vaultly-backup";
const MAX_SIZE = 5 * 1024 * 1024; // 5MB limit

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
    };

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    // Health check (no auth needed)
    if (url.pathname === "/health") {
      return json({ status: "ok", service: "vaultly-backup" }, 200, cors);
    }

    // Auth check
    const authHeader = request.headers.get("Authorization");
    const token = authHeader?.replace("Bearer ", "");
    if (!token || token !== env.BACKUP_TOKEN) {
      return json({ error: "Unauthorized" }, 401, cors);
    }

    // Backup endpoints
    if (url.pathname === "/backup") {
      // PUT: store backup
      if (request.method === "PUT") {
        const contentLength = request.headers.get("Content-Length");
        if (contentLength && parseInt(contentLength) > MAX_SIZE) {
          return json({ error: "Payload too large (max 5MB)" }, 413, cors);
        }

        const body = await request.text();

        // Basic validation: must be JSON with a "vaults" key
        try {
          const parsed = JSON.parse(body);
          if (!parsed.vaults || typeof parsed.vaults !== "object") {
            return json({ error: "Invalid backup format" }, 400, cors);
          }
        } catch {
          return json({ error: "Invalid JSON" }, 400, cors);
        }

        await env.VAULTLY_KV.put(BACKUP_KEY, body, {
          metadata: {
            uploadedAt: new Date().toISOString(),
            size: body.length,
          },
        });

        return json(
          {
            ok: true,
            message: "Backup stored",
            size: body.length,
            at: new Date().toISOString(),
          },
          200,
          cors
        );
      }

      // GET: retrieve backup
      if (request.method === "GET") {
        const data = await env.VAULTLY_KV.get(BACKUP_KEY);
        if (!data) {
          return json({ error: "No backup found" }, 404, cors);
        }
        return new Response(data, {
          headers: { ...cors, "Content-Type": "application/json" },
        });
      }
    }

    return json({ error: "Not found" }, 404, cors);
  },
};

function json(
  data: unknown,
  status: number,
  extraHeaders: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

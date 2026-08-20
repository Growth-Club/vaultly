/**
 * Vaultly MCP Server — Agent-First Zero-Knowledge Interface
 *
 * Agents interact through this MCP server. Every operation goes through:
 * 1. PolicyEngine — permissions, rate limits
 * 2. VaultEngine — encrypted operations
 * 3. Scrubber — secret values removed from output
 *
 * NO tool returns raw secret values. By design.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fs from "node:fs";
import { VaultEngine } from "./engine.js";
import { getFromKeychain, isKeychainAvailable } from "./keychain.js";
import { promptPassword } from "./prompt.js";
import type { CallerContext } from "./policy.js";

const AGENT_CTX: CallerContext = { caller: "agent", agentName: "mcp-agent" };

export async function startMcpServer(): Promise<void> {
  const engine = new VaultEngine({ sessionTtlMinutes: 120 });

  if (!engine.isInitialized) {
    console.error("Vaultly not initialized. Run: vaultly init");
    process.exit(1);
  }

  // ─── Unlock: keychain → env var → terminal prompt ──────
  let unlocked = false;

  // 1. Try macOS Keychain (best: no password needed)
  if (isKeychainAvailable()) {
    const pw = getFromKeychain();
    if (pw) {
      try {
        engine.unlock(pw);
        unlocked = true;
        console.error("✓ Unlocked from macOS Keychain");
      } catch {
        console.error("⚠ Keychain password invalid, falling back...");
      }
    }
  }

  // 2. Try env var
  if (!unlocked && process.env.VAULTLY_MASTER_PASSWORD) {
    try {
      engine.unlock(process.env.VAULTLY_MASTER_PASSWORD);
      unlocked = true;
      delete process.env.VAULTLY_MASTER_PASSWORD;
      console.error("✓ Unlocked from env var");
    } catch {
      console.error("⚠ Env var password invalid");
    }
  }

  // 3. Terminal prompt (reads from /dev/tty, keeps stdin free for MCP)
  if (!unlocked) {
    try {
      const ttyFd = fs.openSync("/dev/tty", "r");
      process.stderr.write("🔑 Master password: ");
      const buf = Buffer.alloc(256);
      const n = fs.readSync(ttyFd, buf, 0, 256, null);
      fs.closeSync(ttyFd);
      const pw = buf.toString("utf8", 0, n).trim();
      process.stderr.write("\n");
      engine.unlock(pw);
      unlocked = true;
    } catch {
      console.error(
        "No password. Set VAULTLY_MASTER_PASSWORD or run from a terminal.\n" +
          "Or run: vaultly keychain store  (saves to macOS Keychain)"
      );
      process.exit(1);
    }
  }

  console.error("✓ Vaultly MCP server ready\n");

  // ─── MCP Server ────────────────────────────────────────
  const server = new McpServer({ name: "vaultly", version: "1.0.0" });

  // Helper: wrap engine errors into MCP responses
  function ok(text: string) {
    return { content: [{ type: "text" as const, text }] };
  }
  function fail(text: string) {
    return { content: [{ type: "text" as const, text: `✗ ${text}` }], isError: true };
  }
  function tryRun(fn: () => any) {
    try {
      return fn();
    } catch (err: any) {
      return fail(err.message);
    }
  }
  async function tryRunAsync(fn: () => Promise<any>) {
    try {
      return await fn();
    } catch (err: any) {
      return fail(err.message);
    }
  }

  // ═══════════════════════════════════════════════════════
  // VAULT TOOLS
  // ═══════════════════════════════════════════════════════

  server.tool(
    "vault_list",
    "List all vault names. Safe — no secrets exposed.",
    {},
    async () =>
      tryRun(() => {
        const vaults = engine.listVaults(AGENT_CTX);
        return ok(
          vaults.length
            ? `Vaults:\n${vaults.map((v) => `  - ${v}`).join("\n")}`
            : "No vaults. Use vault_add to create one."
        );
      })
  );

  server.tool(
    "vault_keys",
    "List secret KEY NAMES in a vault. Names only — never values.",
    { vaultName: z.string().describe("Vault name") },
    async ({ vaultName }) =>
      tryRun(() => {
        const keys = engine.listKeys(vaultName, AGENT_CTX);
        return ok(
          keys.length
            ? `Keys in '${vaultName}':\n${keys.map((k) => `  - ${k}`).join("\n")}`
            : `Vault '${vaultName}' is empty or doesn't exist.`
        );
      })
  );

  server.tool(
    "vault_add",
    "Store a secret (WRITE-ONLY). You provide the value to encrypt and store. You can NEVER read it back — only use it via vault_run or cf_api.",
    {
      vaultName: z.string().describe("Vault name"),
      key: z.string().describe("Secret name (e.g. CLOUDFLARE_API_TOKEN)"),
      value: z.string().describe("Secret value to encrypt and store"),
    },
    async ({ vaultName, key, value }) =>
      tryRun(() => {
        engine.addSecret(vaultName, key, value, AGENT_CTX);
        return ok(`✓ Stored '${key}' in '${vaultName}'. Encrypted. Cannot be read back.`);
      })
  );

  server.tool(
    "vault_delete",
    "Delete a secret from a vault.",
    {
      vaultName: z.string().describe("Vault name"),
      key: z.string().describe("Secret key to delete"),
    },
    async ({ vaultName, key }) =>
      tryRun(() => {
        const deleted = engine.deleteSecret(vaultName, key, AGENT_CTX);
        return deleted
          ? ok(`✓ Deleted '${key}' from '${vaultName}'.`)
          : fail(`'${key}' not found in '${vaultName}'.`);
      })
  );

  server.tool(
    "vault_run",
    "Run a command with vault secrets injected as env vars. Secrets are NEVER printed — output is scrubbed. Use for deploys, builds, API calls, etc.",
    {
      vaultName: z.string().describe("Vault to inject"),
      command: z.string().describe("Command (e.g. 'npx wrangler deploy')"),
      cwd: z.string().optional().describe("Working directory"),
    },
    async ({ vaultName, command, cwd }) =>
      tryRunAsync(async () => {
        const result = await engine.runCommand(vaultName, command, {
          cwd,
          ctx: AGENT_CTX,
          timeoutMs: 300_000,
        });
        const maxLen = 10000;
        const stdout = result.stdout.length > maxLen ? result.stdout.slice(0, maxLen) + "\n...(truncated)" : result.stdout;
        const stderr = result.stderr.length > maxLen ? result.stderr.slice(0, maxLen) + "\n...(truncated)" : result.stderr;

        return {
          content: [
            {
              type: "text" as const,
              text:
                `Command: ${command}\n` +
                `Injected: ${result.secretsInjected.join(", ")}\n` +
                `Exit code: ${result.code}\n` +
                (result.scrubbed ? `⚠ Output scrubbed (secret values removed)\n` : "") +
                `\n${stdout}${stderr ? `\nSTDERR:\n${stderr}` : ""}`,
            },
          ],
          isError: result.code !== 0,
        };
      })
  );

  // ═══════════════════════════════════════════════════════
  // CLOUDFLARE TOOLS
  // ═══════════════════════════════════════════════════════

  server.tool(
    "cf_api",
    "Make an authenticated Cloudflare API call. Token injected from vault — you see the response, NEVER the token.",
    {
      vaultName: z.string().describe("Vault with CLOUDFLARE_API_TOKEN"),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
      path: z.string().describe("API path (e.g. /zones)"),
      body: z.string().optional().describe("JSON body string"),
    },
    async ({ vaultName, method, path: apiPath, body }) =>
      tryRunAsync(async () => {
        const parsed = body ? JSON.parse(body) : undefined;
        const result = await engine.cloudflareApi(vaultName, method, apiPath, parsed, AGENT_CTX);
        return {
          content: [
            {
              type: "text" as const,
              text: `${method} ${apiPath} → ${result.status}\n\n${JSON.stringify(result.data, null, 2)}`,
            },
          ],
          isError: result.status >= 400,
        };
      })
  );

  server.tool(
    "cf_zones",
    "List all zones (domains) in a Cloudflare account.",
    { vaultName: z.string() },
    async ({ vaultName }) =>
      tryRunAsync(async () => {
        const r = await engine.cloudflareApi(vaultName, "GET", "/zones?per_page=50", undefined, AGENT_CTX);
        const zones = (r.data as any)?.result || [];
        return ok(
          `Zones (${zones.length}):\n` +
            zones.map((z: any) => `  - ${z.name} (id: ${z.id}, status: ${z.status})`).join("\n")
        );
      })
  );

  server.tool(
    "cf_dns_list",
    "List DNS records for a zone.",
    {
      vaultName: z.string(),
      zoneId: z.string(),
      type: z.string().optional().describe("Filter: A, CNAME, MX, TXT..."),
    },
    async ({ vaultName, zoneId, type }) =>
      tryRunAsync(async () => {
        const path = `/zones/${zoneId}/dns_records?per_page=100${type ? `&type=${type}` : ""}`;
        const r = await engine.cloudflareApi(vaultName, "GET", path, undefined, AGENT_CTX);
        const records = (r.data as any)?.result || [];
        return ok(
          `DNS records (${records.length}):\n` +
            records.map((d: any) => `  - ${d.type} ${d.name} → ${d.content} (id: ${d.id})`).join("\n")
        );
      })
  );

  server.tool(
    "cf_dns_upsert",
    "Create or update a DNS record.",
    {
      vaultName: z.string(),
      zoneId: z.string(),
      type: z.string().describe("A, AAAA, CNAME, MX, TXT..."),
      name: z.string().describe("Record name (e.g. app.example.com)"),
      content: z.string().describe("Record value (IP, hostname...)"),
      ttl: z.number().optional(),
      proxied: z.boolean().optional(),
    },
    async ({ vaultName, zoneId, type, name, content, ttl, proxied }) =>
      tryRunAsync(async () => {
        // Check existing
        const list = await engine.cloudflareApi(
          vaultName, "GET",
          `/zones/${zoneId}/dns_records?type=${type}&name=${name}`,
          undefined, AGENT_CTX
        );
        const existing = (list.data as any)?.result || [];
        const body = { type, name, content, ttl: ttl || 1, proxied: proxied ?? false };

        let r;
        if (existing.length > 0) {
          r = await engine.cloudflareApi(vaultName, "PUT", `/zones/${zoneId}/dns_records/${existing[0].id}`, body, AGENT_CTX);
          return ok(`✓ Updated ${type} ${name} → ${content}\n${JSON.stringify(r.data, null, 2)}`);
        } else {
          r = await engine.cloudflareApi(vaultName, "POST", `/zones/${zoneId}/dns_records`, body, AGENT_CTX);
          return ok(`✓ Created ${type} ${name} → ${content}\n${JSON.stringify(r.data, null, 2)}`);
        }
      })
  );

  server.tool(
    "cf_workers_list",
    "List deployed Workers in a Cloudflare account.",
    { vaultName: z.string().describe("Vault with CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID") },
    async ({ vaultName }) =>
      tryRunAsync(async () => {
        const result = await engine.listWorkers(vaultName, AGENT_CTX);
        return ok(
          `Workers (${result.workers.length}):\n` +
            result.workers.map((w: string) => `  - ${w}`).join("\n")
        );
      })
  );

  server.tool(
    "cf_deploy",
    "Deploy a Cloudflare Worker project via wrangler. Credentials injected from vault.",
    {
      vaultName: z.string(),
      projectDir: z.string().describe("Path to Worker project"),
      extraArgs: z.string().optional().describe("Extra wrangler args"),
    },
    async ({ vaultName, projectDir, extraArgs }) =>
      tryRunAsync(async () => {
        const cmd = `npx wrangler deploy${extraArgs ? ` ${extraArgs}` : ""}`;
        const result = await engine.runCommand(vaultName, cmd, {
          cwd: projectDir,
          ctx: AGENT_CTX,
          timeoutMs: 300_000,
        });
        const maxLen = 10000;
        const stdout = result.stdout.length > maxLen ? result.stdout.slice(0, maxLen) + "\n...(truncated)" : result.stdout;
        return {
          content: [
            {
              type: "text" as const,
              text:
                `Deploy: ${cmd}\nDir: ${projectDir}\nExit: ${result.code}\n` +
                (result.scrubbed ? "⚠ Output scrubbed\n" : "") +
                `\n${stdout}${result.stderr ? `\nSTDERR:\n${result.stderr}` : ""}`,
            },
          ],
          isError: result.code !== 0,
        };
      })
  );

  server.tool(
    "cf_health",
    "Verify a Cloudflare API token is still valid.",
    { vaultName: z.string() },
    async ({ vaultName }) =>
      tryRunAsync(async () => {
        const result = await engine.healthCheck(vaultName, AGENT_CTX);
        return result.ok ? ok(`✓ ${result.message}`) : fail(result.message);
      })
  );

  // ═══════════════════════════════════════════════════════
  // AUDIT + STATUS
  // ═══════════════════════════════════════════════════════

  server.tool(
    "vault_audit",
    "View recent audit log. Shows all agent + human actions.",
    { lines: z.number().optional().describe("Entries to show (default 20)") },
    async ({ lines }) =>
      tryRun(() => {
        const log = engine.getAuditLog(lines || 20);
        return ok(log.length ? `Audit log:\n${log.join("\n")}` : "No audit entries yet.");
      })
  );

  server.tool(
    "vault_lock",
    "Lock the vault session immediately — wipes the decryption key from memory. Use vault_unlock to re-open.",
    {},
    async () =>
      tryRun(() => {
        engine.lock(AGENT_CTX);
        return ok("✓ Vault locked. Decryption key wiped from memory.");
      })
  );

  server.tool(
    "vault_unlock",
    "Re-open a locked session. Uses the macOS Keychain (hardware-backed) — the agent never handles the password.",
    {},
    async () => {
      if (!isKeychainAvailable()) {
        return fail("Keychain unavailable. Restart the MCP server to unlock.");
      }
      const pw = getFromKeychain();
      if (!pw) {
        return fail("No keychain entry found. Run `vaultly keychain store` or restart the MCP server.");
      }
      try {
        engine.unlock(pw);
        return ok("✓ Vault unlocked.");
      } catch {
        return fail("Keychain password invalid.");
      }
    }
  );

  server.tool(
    "vault_status",
    "Show vault status: session TTL, vault count, keychain status.",
    {},
    async () =>
      tryRun(() => {
        const vaults = engine.listVaults(AGENT_CTX);
        const ttlMin = Math.round(engine.sessionExpiresIn / 60000);
        return ok(
          `Vaultly Status:\n` +
            `  Unlocked: ${engine.isUnlocked ? "yes" : "no"} (expires in ${ttlMin} min)\n` +
            `  Vaults: ${vaults.length} (${vaults.join(", ") || "none"})\n` +
            `  Keychain: ${isKeychainAvailable() ? "available" : "not available"}\n` +
            `  Platform: ${process.platform}`
        );
      })
  );

  // ─── Start ─────────────────────────────────────────────
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

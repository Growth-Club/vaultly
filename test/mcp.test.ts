/**
 * End-to-end MCP server tests — the security-critical surface.
 * Spawns the real `vaultly mcp` server over stdio and connects with the SDK client.
 * Verifies the core guarantee: NO tool returns a raw secret value.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { initVault } from "../src/vault.js";

const dir = () => process.env.VAULTLY_DIR!;
const PASSWORD = "mcp-test-password";

const SECRET_VALUE = "sk-e2e-super-secret-token-1234567890";
const SECRET_KEY = "E2E_SECRET_KEY";

describe("MCP server (end-to-end)", () => {
  let child: ChildProcess;
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    fs.rmSync(dir(), { recursive: true, force: true });
    fs.mkdirSync(dir(), { recursive: true });
    initVault(PASSWORD);

    child = spawn(process.execPath, ["--import", "tsx", "src/index.ts", "mcp"], {
      cwd: path.resolve(import.meta.dirname, ".."),
      env: {
        ...process.env,
        VAULTLY_DIR: dir(),
        VAULTLY_MASTER_PASSWORD: PASSWORD,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderrLog = "";
    child.stderr.on("data", (d) => (stderrLog += d.toString()));

    // The server logs "MCP server ready" once the stdio transport is up
    const deadline = Date.now() + 15_000;
    while (!stderrLog.includes("MCP server ready")) {
      if (Date.now() > deadline) {
        child.kill("SIGKILL");
        throw new Error(`MCP server did not start. stderr: ${stderrLog}`);
      }
      await new Promise((r) => setTimeout(r, 100));
    }

    transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--import", "tsx", "src/index.ts", "mcp"],
      env: {
        ...process.env,
        VAULTLY_DIR: dir(),
        VAULTLY_MASTER_PASSWORD: PASSWORD,
      },
      stderr: "pipe",
    });
    client = new Client({ name: "vaultly-test", version: "1.0.0" });
    await client.connect(transport);
  });

  afterAll(async () => {
    await client?.close().catch(() => {});
    transport?.close();
    child?.kill("SIGKILL");
    fs.rmSync(dir(), { recursive: true, force: true });
  });

  it("exposes exactly the 17 documented tools", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        "cf_api", "cf_deploy", "cf_dns_list", "cf_dns_upsert", "cf_health",
        "cf_secrets", "cf_workers_list", "cf_zones",
        "vault_add", "vault_audit", "vault_delete", "vault_keys", "vault_list",
        "vault_lock", "vault_run", "vault_status", "vault_unlock",
      ].sort()
    );
  });

  it("has no tool that returns a raw secret value", async () => {
    const { tools } = await client.listTools();
    for (const t of tools) {
      expect(t.description?.toLowerCase()).not.toMatch(/returns? (the )?raw (secret )?value/);
    }
  });

  it("validates cf_secrets requires name/value for set", async () => {
    const res = await client.callTool({
      name: "cf_secrets",
      arguments: { vaultName: "e2e", scriptName: "w", action: "set" },
    });
    const text = JSON.stringify(res);
    expect(text).toContain("'name' is required");
  });

  it("stores a secret (write-only) and lists only its name", async () => {
    const add = await client.callTool({
      name: "vault_add",
      arguments: { vaultName: "e2e", key: SECRET_KEY, value: SECRET_VALUE },
    });
    expect(JSON.stringify(add)).not.toContain(SECRET_VALUE);
    expect(JSON.stringify(add)).toContain("Stored");

    const keys = await client.callTool({
      name: "vault_keys",
      arguments: { vaultName: "e2e" },
    });
    const text = JSON.stringify(keys);
    expect(text).toContain(SECRET_KEY);
    expect(text).not.toContain(SECRET_VALUE);
  });

  it("scrubs secret values from command output", async () => {
    const res = await client.callTool({
      name: "vault_run",
      arguments: {
        vaultName: "e2e",
        command: `${process.execPath} -e "console.log(process.env.${SECRET_KEY})"`,
      },
    });
    const text = JSON.stringify(res);
    expect(text).not.toContain(SECRET_VALUE);
    expect(text).toContain("[REDACTED]");
  });

  it("lets agents lock and reports locked status", async () => {
    const lock = await client.callTool({ name: "vault_lock", arguments: {} });
    expect(JSON.stringify(lock)).toContain("locked");

    const status = await client.callTool({ name: "vault_status", arguments: {} });
    expect(JSON.stringify(status)).toContain("Unlocked: no");
  });

  it("rejects raw-value reads that don't exist (no vault_get tool)", async () => {
    const { tools } = await client.listTools();
    expect(tools.some((t) => t.name === "vault_get")).toBe(false);
    expect(tools.some((t) => t.name === "get")).toBe(false);
    expect(tools.some((t) => t.name === "env")).toBe(false);
  });

  it("audits agent actions with agent attribution", async () => {
    const log = (await client.callTool({
      name: "vault_audit",
      arguments: { lines: 20 },
    })) as any;
    const text: string = log.content[0].text;
    expect(text).toContain('"action":"ADD"');
    expect(text).toContain('"agent":"mcp-agent"');
    expect(text).toContain('"caller":"agent"');
  });
});
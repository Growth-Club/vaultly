import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import { VaultEngine } from "../src/engine.js";
import { initVault } from "../src/vault.js";
import type { CallerContext } from "../src/policy.js";

const dir = () => process.env.VAULTLY_DIR!;
const PASSWORD = "test-master-password";
const agentCtx: CallerContext = { caller: "agent", agentName: "test-agent" };

describe("engine robustness", () => {
  let engine: VaultEngine;

  beforeEach(() => {
    fs.rmSync(dir(), { recursive: true, force: true });
    fs.mkdirSync(dir(), { recursive: true });
    engine = new VaultEngine();
    initVault(PASSWORD);
    engine.unlock(PASSWORD);
  });

  afterEach(() => {
    engine.lock();
    fs.rmSync(dir(), { recursive: true, force: true });
  });

  it("kills a command that exceeds the timeout", async () => {
    engine.addSecret("slow", "K", "v", agentCtx);
    const res = await engine.run(
      "slow",
      process.execPath,
      ["-e", "setTimeout(() => {}, 60000)"],
      { ctx: agentCtx, timeoutMs: 500 }
    );
    expect(res.code).toBe(124);
    expect(res.stderr).toContain("timed out");
  });

  it("caps runaway output at 5MB", async () => {
    engine.addSecret("chatty", "K", "v", agentCtx);
    const res = await engine.run(
      "chatty",
      process.execPath,
      ["-e", "process.stdout.write('x'.repeat(20 * 1024 * 1024))"],
      { ctx: agentCtx }
    );
    expect(res.stdout.length).toBeLessThan(6 * 1024 * 1024);
    expect(res.stdout).toContain("output truncated");
  });

  it("records agent attribution for MCP-initiated locks", () => {
    engine.lock(agentCtx);
    const entries = engine.getAuditLog(10).map((l) => JSON.parse(l));
    const lockEntry = entries.find((e) => e.action === "LOCK");
    expect(lockEntry.caller).toBe("agent");
    expect(lockEntry.agent).toBe("test-agent");
  });

  it("records agent attribution for kill", () => {
    engine.kill(agentCtx);
    const entries = engine.getAuditLog(10).map((l) => JSON.parse(l));
    const killEntry = entries.find((e) => e.action === "KILL");
    expect(killEntry.caller).toBe("agent");
  });
});
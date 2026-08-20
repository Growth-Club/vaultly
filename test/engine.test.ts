import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import { VaultEngine } from "../src/engine.js";
import { initVault } from "../src/vault.js";
import type { CallerContext } from "../src/policy.js";

const dir = () => process.env.VAULTLY_DIR!;
const PASSWORD = "test-master-password";
const agentCtx: CallerContext = { caller: "agent", agentName: "test-agent" };

describe("engine", () => {
  let engine: VaultEngine;

  beforeEach(() => {
    fs.rmSync(dir(), { recursive: true, force: true });
    fs.mkdirSync(dir(), { recursive: true });
    engine = new VaultEngine();
    // init + unlock through the storage layer
    initVault(PASSWORD);
    engine.unlock(PASSWORD);
  });

  afterEach(() => {
    engine.lock();
    fs.rmSync(dir(), { recursive: true, force: true });
  });

  it("locks and requires unlock for operations", () => {
    engine.lock();
    expect(engine.isUnlocked).toBe(false);
    expect(() => engine.listKeys("any", agentCtx)).toThrow(/locked/);
    engine.unlock(PASSWORD);
    expect(engine.isUnlocked).toBe(true);
  });

  it("adds secrets and lists vaults/keys", () => {
    engine.addSecret("github", "GITHUB_TOKEN", "ghp_456", agentCtx);
    expect(engine.listVaults(agentCtx)).toContain("github");
    expect(engine.listKeys("github", agentCtx)).toEqual(["GITHUB_TOKEN"]);
  });

  it("deletes secrets", () => {
    engine.addSecret("github", "GITHUB_TOKEN", "ghp_456", agentCtx);
    expect(engine.deleteSecret("github", "GITHUB_TOKEN", agentCtx)).toBe(true);
    expect(engine.listKeys("github", agentCtx)).toEqual([]);
  });

  it("blocks agents from deleting vaults (policy)", () => {
    engine.addSecret("github", "K", "v", agentCtx);
    expect(() => engine.deleteVault("github", agentCtx)).toThrow(/Permission denied/);
  });

  it("injects secrets into the child process (and scrubs them from output)", async () => {
    engine.addSecret("runvault", "API_KEY", "inject-me-123", agentCtx);
    const res = await engine.run(
      "runvault",
      process.execPath,
      ["-e", "console.log('INJECTED:' + process.env.API_KEY)"],
      { ctx: agentCtx }
    );
    expect(res.code).toBe(0);
    // The value WAS injected (child read it) but is scrubbed before we see it
    expect(res.stdout).not.toContain("inject-me-123");
    expect(res.stdout).toContain("INJECTED:[REDACTED]");
    expect(res.scrubbed).toBe(true);
    expect(res.secretsInjected).toEqual(["API_KEY"]);
  });

  it("scrubs secrets from command output", async () => {
    engine.addSecret("runvault", "API_KEY", "super-secret-value-xyz", agentCtx);
    const res = await engine.run(
      "runvault",
      process.execPath,
      ["-e", "console.log(process.env.API_KEY)"],
      { ctx: agentCtx }
    );
    expect(res.stdout).not.toContain("super-secret-value-xyz");
    expect(res.stdout).toContain("[REDACTED]");
    expect(res.scrubbed).toBe(true);
  });

  it("runs a command string with quoting", async () => {
    engine.addSecret("runvault", "API_KEY", "v", agentCtx);
    const res = await engine.runCommand(
      "runvault",
      `${process.execPath} -e "console.log('quoted-run-ok')"`,
      { ctx: agentCtx }
    );
    expect(res.stdout).toContain("quoted-run-ok");
  });

  it("returns an error code and message for a failing command", async () => {
    engine.addSecret("runvault", "API_KEY", "v", agentCtx);
    const res = await engine.run("runvault", process.execPath, ["-e", "process.exit(7)"], {
      ctx: agentCtx,
    });
    expect(res.code).toBe(7);
  });

  it("rejects running with an empty vault", async () => {
    await expect(
      engine.run("empty-vault", process.execPath, ["-e", "1"], { ctx: agentCtx })
    ).rejects.toThrow(/empty or doesn't exist/);
  });

  it("writes structured audit entries for every operation", () => {
    engine.addSecret("github", "K", "SECRET-VALUE-9", agentCtx);
    engine.deleteSecret("github", "K", agentCtx);
    const log = engine.getAuditLog(50);
    const entries = log.map((l) => JSON.parse(l));
    const actions = entries.map((e) => e.action);
    expect(actions).toContain("ADD");
    expect(actions).toContain("DELETE");
    expect(actions).toContain("UNLOCK");
    expect(entries.every((e) => !e.detail.includes("SECRET-VALUE-9"))).toBe(true);
  });

  it("wipes the key from memory on lock", () => {
    const keyRef = (engine as any).key as Buffer;
    engine.lock();
    expect((engine as any).key).toBeNull();
    const allZero = keyRef.every((b: number) => b === 0);
    expect(allZero).toBe(true);
  });

  it("kill locks the engine and audits the event", () => {
    engine.kill();
    expect(engine.isUnlocked).toBe(false);
    const actions = engine.getAuditLog(50).map((l) => JSON.parse(l).action);
    expect(actions).toContain("KILL");
  });
});
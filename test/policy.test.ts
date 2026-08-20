import { describe, expect, it } from "vitest";
import { PolicyEngine, type CallerContext } from "../src/policy.js";

const agent: CallerContext = { caller: "agent", agentName: "test-agent" };

describe("policy engine", () => {
  it("allows humans to do anything", () => {
    const p = new PolicyEngine();
    expect(() => p.check({ caller: "human" }, "read_value", "*")).not.toThrow();
  });

  it("allows callers without context (legacy) to do anything", () => {
    const p = new PolicyEngine();
    expect(() => p.check(undefined, "read_value", "*")).not.toThrow();
  });

  it("blocks read_value for agents by default", () => {
    const p = new PolicyEngine();
    expect(() => p.check(agent, "read_value", "*")).toThrow(/Permission denied/);
  });

  it("allows default agent operations", () => {
    const p = new PolicyEngine();
    for (const op of ["list", "read_keys", "write", "delete", "run", "cf_api"]) {
      expect(() => p.check(agent, op as any, "*")).not.toThrow();
    }
  });

  it("blocks delete_vault and admin for agents by default", () => {
    const p = new PolicyEngine();
    expect(() => p.check(agent, "delete_vault", "*")).toThrow(/Permission denied/);
    expect(() => p.check(agent, "admin", "*")).toThrow(/Permission denied/);
  });

  it("restricts an agent to its allowed vaults", () => {
    const p = new PolicyEngine();
    p.registerAgent("limited", { allowedVaults: ["allowed-vault"] });
    const ctx: CallerContext = { caller: "agent", agentName: "limited" };
    expect(() => p.check(ctx, "run", "allowed-vault")).not.toThrow();
    expect(() => p.check(ctx, "run", "other-vault")).toThrow(/cannot access vault/);
  });

  it("restricts an agent to its allowed operations", () => {
    const p = new PolicyEngine();
    p.registerAgent("readonly", { allowedOperations: ["list", "read_keys"] });
    const ctx: CallerContext = { caller: "agent", agentName: "readonly" };
    expect(() => p.check(ctx, "list", "*")).not.toThrow();
    expect(() => p.check(ctx, "write", "*")).toThrow(/cannot perform 'write'/);
  });

  it("enforces the per-agent rate limit", () => {
    const p = new PolicyEngine();
    p.registerAgent("flooder", { maxOpsPerMinute: 3 });
    const ctx: CallerContext = { caller: "agent", agentName: "flooder" };
    for (let i = 0; i < 3; i++) {
      expect(() => p.check(ctx, "list", "*")).not.toThrow();
    }
    expect(() => p.check(ctx, "list", "*")).toThrow(/Rate limit exceeded/);
  });

  it("falls back to the default policy for unknown agents", () => {
    const p = new PolicyEngine();
    expect(() => p.check({ caller: "agent", agentName: "ghost" }, "list", "*")).not.toThrow();
  });
});
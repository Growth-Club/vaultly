/**
 * Policy Engine
 *
 * Controls what each caller (agent or human) can do.
 * Same rules apply to both — no special treatment.
 *
 * Features:
 * - Per-agent permissions (allowed vaults, allowed operations)
 * - Rate limiting (max operations per minute)
 * - Operation classification (read, write, run, admin)
 * - Extensible rules
 *
 * Adopted from agent-secrets' permission model.
 */

export interface CallerContext {
  caller: "human" | "agent";
  agentName?: string;
  sessionId?: string;
}

export type Operation =
  | "list"
  | "read_keys"
  | "read_value" // blocked for agents by default
  | "write"
  | "delete"
  | "delete_vault"
  | "run"
  | "cf_api"
  | "admin";

interface AgentPolicy {
  name: string;
  allowedVaults: string[] | "*"; // "*" = all vaults
  allowedOperations: Operation[] | "*"; // "*" = all ops
  maxOpsPerMinute: number;
  createdAt: string;
}

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const DEFAULT_AGENT_POLICY: Omit<AgentPolicy, "name" | "createdAt"> = {
  allowedVaults: "*",
  allowedOperations: [
    "list",
    "read_keys",
    "write",
    "delete",
    "run",
    "cf_api",
  ],
  // NOTE: "read_value", "delete_vault", "admin" are NOT in default agent ops
  maxOpsPerMinute: 60,
};

export class PolicyEngine {
  private policies: Map<string, AgentPolicy> = new Map();
  private rateLimits: Map<string, RateLimitEntry> = new Map();

  constructor() {
    // Default policy for any agent
    this.policies.set("*", {
      name: "*",
      ...DEFAULT_AGENT_POLICY,
      createdAt: new Date().toISOString(),
    });
  }

  /** Register a specific agent policy */
  registerAgent(name: string, overrides?: Partial<AgentPolicy>): void {
    this.policies.set(name, {
      name,
      ...DEFAULT_AGENT_POLICY,
      ...overrides,
      createdAt: new Date().toISOString(),
    });
  }

  /** Check if an operation is allowed. Throws if denied. */
  check(ctx: CallerContext | undefined, op: Operation, vaultName: string): void {
    // Humans can do everything (they have the password)
    if (!ctx || ctx.caller === "human") return;

    const policy =
      (ctx.agentName && this.policies.get(ctx.agentName)) ||
      this.policies.get("*");

    if (!policy) {
      throw new Error(`No policy found for agent '${ctx.agentName}'`);
    }

    // Check operation permission
    if (policy.allowedOperations !== "*") {
      if (!policy.allowedOperations.includes(op)) {
        throw new Error(
          `🚫 Permission denied: agent '${ctx.agentName || "unknown"}' cannot perform '${op}'. ` +
            `Allowed: ${policy.allowedOperations.join(", ")}`
        );
      }
    }

    // Check vault permission
    if (policy.allowedVaults !== "*" && vaultName !== "*") {
      if (!policy.allowedVaults.includes(vaultName)) {
        throw new Error(
          `🚫 Permission denied: agent '${ctx.agentName || "unknown"}' cannot access vault '${vaultName}'. ` +
            `Allowed: ${policy.allowedVaults.join(", ")}`
        );
      }
    }

    // Rate limiting
    this.checkRateLimit(ctx.agentName || "unknown", policy.maxOpsPerMinute);
  }

  private checkRateLimit(agentName: string, maxPerMinute: number): void {
    const now = Date.now();
    const entry = this.rateLimits.get(agentName);

    if (!entry || now - entry.windowStart > 60_000) {
      // New window
      this.rateLimits.set(agentName, { count: 1, windowStart: now });
      return;
    }

    if (entry.count >= maxPerMinute) {
      throw new Error(
        `🚫 Rate limit exceeded: agent '${agentName}' has made ${entry.count} operations ` +
          `in the last minute (max: ${maxPerMinute}). Slow down.`
      );
    }

    entry.count++;
  }
}

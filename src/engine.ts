/**
 * Vaultly Core Engine
 *
 * Single source of truth for all vault operations.
 * Both CLI and MCP server use this — same permissions, same audit, same security.
 * No interface-specific logic here.
 */
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import * as vault from "./vault.js";
import * as crypto from "./crypto.js";
import { scrubOutput } from "./scrubber.js";
import { PolicyEngine, type CallerContext } from "./policy.js";

export interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
  secretsInjected: string[];
  scrubbed: boolean;
}

export interface ApiResult {
  status: number;
  data: unknown;
}

export class VaultEngine {
  private key: Buffer | null = null;
  private policy: PolicyEngine;
  private unlockedAt: number | null = null;
  private sessionTtlMs: number;

  constructor(options?: { sessionTtlMinutes?: number }) {
    this.policy = new PolicyEngine();
    this.sessionTtlMs = (options?.sessionTtlMinutes ?? 60) * 60 * 1000;
  }

  // ─── Lifecycle ─────────────────────────────────────────

  get isInitialized(): boolean {
    return vault.isInitialized();
  }

  get isUnlocked(): boolean {
    if (!this.key) return false;
    // Check TTL
    if (this.unlockedAt && Date.now() - this.unlockedAt > this.sessionTtlMs) {
      this.lock();
      return false;
    }
    return true;
  }

  get sessionExpiresIn(): number {
    if (!this.unlockedAt) return 0;
    const remaining = this.sessionTtlMs - (Date.now() - this.unlockedAt);
    return Math.max(0, remaining);
  }

  unlock(password: string): void {
    this.key = vault.unlock(password);
    this.unlockedAt = Date.now();
    this.audit("UNLOCK", "Vault unlocked");
  }

  /** Lock vault — wipe key from memory */
  lock(): void {
    if (this.key) {
      // Overwrite key buffer with zeros before releasing
      this.key.fill(0);
      this.key = null;
    }
    this.unlockedAt = null;
    this.audit("LOCK", "Vault locked");
  }

  /** Killswitch — emergency lock + clear all session data */
  kill(): void {
    this.lock();
    // Remove keychain entry if exists
    try {
      const { execSync } = require("node:child_process");
      execSync(
        'security delete-generic-password -s "vaultly-master-key" 2>/dev/null || true',
        { stdio: "ignore" }
      );
    } catch {
      // Ignore — keychain entry may not exist
    }
    this.audit("KILL", "🚨 Killswitch activated — vault locked, keychain cleared");
  }

  private requireUnlocked(): Buffer {
    if (!this.isUnlocked || !this.key) {
      throw new Error(
        "Vault is locked. " +
          (this.unlockedAt ? "Session expired. " : "") +
          "Unlock first."
      );
    }
    return this.key;
  }

  // ─── Vault Operations ──────────────────────────────────

  listVaults(ctx?: CallerContext): string[] {
    this.policy.check(ctx, "list", "*");
    const vaults = vault.listVaults();
    this.audit("LIST_VAULTS", `${vaults.length} vaults`, ctx);
    return vaults;
  }

  listKeys(vaultName: string, ctx?: CallerContext): string[] {
    this.policy.check(ctx, "read_keys", vaultName);
    const key = this.requireUnlocked();
    const keys = vault.listKeys(vaultName, key);
    this.audit("LIST_KEYS", `${vaultName}: ${keys.length} keys`, ctx);
    return keys;
  }

  /** WRITE-ONLY: store a secret. Cannot read back. */
  addSecret(vaultName: string, secretKey: string, value: string, ctx?: CallerContext): void {
    this.policy.check(ctx, "write", vaultName);
    const key = this.requireUnlocked();
    vault.setSecret(vaultName, secretKey, value, key);
    this.audit("ADD", `${vaultName}/${secretKey} (value hidden)`, ctx);
  }

  /** Delete a secret */
  deleteSecret(vaultName: string, secretKey: string, ctx?: CallerContext): boolean {
    this.policy.check(ctx, "delete", vaultName);
    const key = this.requireUnlocked();
    const deleted = vault.deleteSecret(vaultName, secretKey, key);
    this.audit("DELETE", `${vaultName}/${secretKey} success=${deleted}`, ctx);
    return deleted;
  }

  /** Delete entire vault */
  deleteVault(vaultName: string, ctx?: CallerContext): boolean {
    this.policy.check(ctx, "delete_vault", vaultName);
    const deleted = vault.deleteVault(vaultName);
    this.audit("DELETE_VAULT", `${vaultName} success=${deleted}`, ctx);
    return deleted;
  }

  /** Import secrets from parsed entries */
  importSecrets(vaultName: string, entries: Record<string, string>, ctx?: CallerContext): number {
    this.policy.check(ctx, "write", vaultName);
    const key = this.requireUnlocked();
    const count = vault.importSecrets(vaultName, entries, key);
    this.audit("IMPORT", `${vaultName}: ${count} secrets`, ctx);
    return count;
  }

  /**
   * Get secrets for internal use (run, api calls).
   * NOT exposed to agents directly — only through run/api.
   */
  private getSecrets(vaultName: string): Record<string, string> {
    const key = this.requireUnlocked();
    return vault.getSecrets(vaultName, key);
  }

  // ─── Command Execution (with scrubbing) ────────────────

  async run(
    vaultName: string,
    command: string,
    args: string[],
    options?: { cwd?: string; ctx?: CallerContext }
  ): Promise<RunResult> {
    this.policy.check(options?.ctx, "run", vaultName);

    const secrets = this.getSecrets(vaultName);
    const secretKeys = Object.keys(secrets);
    const secretValues = Object.values(secrets);

    if (secretKeys.length === 0) {
      throw new Error(`Vault '${vaultName}' is empty or doesn't exist.`);
    }

    this.audit(
      "RUN",
      `vault=${vaultName} cmd="${command} ${args.join(" ")}" secrets=[${secretKeys.join(",")}]`,
      options?.ctx
    );

    const result = await this.spawn(command, args, secrets, options?.cwd);

    // SCRUB secret values from output before returning
    const scrubbedStdout = scrubOutput(result.stdout, secretValues);
    const scrubbedStderr = scrubOutput(result.stderr, secretValues);
    const wasScrubbed =
      scrubbedStdout !== result.stdout || scrubbedStderr !== result.stderr;

    if (wasScrubbed) {
      this.audit("SCRUB", `Scrubbed secret values from output of: ${command}`, options?.ctx);
    }

    return {
      stdout: scrubbedStdout,
      stderr: scrubbedStderr,
      code: result.code,
      secretsInjected: secretKeys,
      scrubbed: wasScrubbed,
    };
  }

  /** Run a raw command string (parses into command + args) */
  async runCommand(
    vaultName: string,
    commandStr: string,
    options?: { cwd?: string; ctx?: CallerContext }
  ): Promise<RunResult> {
    const parts = commandStr.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [commandStr];
    const cmd = parts[0];
    const args = parts.slice(1).map((a) => a.replace(/^["']|["']$/g, ""));
    return this.run(vaultName, cmd, args, options);
  }

  // ─── Cloudflare API ────────────────────────────────────

  async cloudflareApi(
    vaultName: string,
    method: string,
    apiPath: string,
    body?: unknown,
    ctx?: CallerContext
  ): Promise<ApiResult> {
    this.policy.check(ctx, "cf_api", vaultName);

    const secrets = this.getSecrets(vaultName);
    const apiToken = secrets["CLOUDFLARE_API_TOKEN"];
    if (!apiToken) {
      throw new Error(
        `No CLOUDFLARE_API_TOKEN in '${vaultName}'. Found: ${Object.keys(secrets).join(", ") || "(empty)"}`
      );
    }

    this.audit("CF_API", `${method} ${apiPath} (vault=${vaultName})`, ctx);

    const url = `https://api.cloudflare.com/client/v4${apiPath}`;
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${apiToken}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await res.json();

    // Scrub token from response (in case it's echoed back)
    const scrubbed = scrubOutput(JSON.stringify(data, null, 2), [apiToken]);

    return { status: res.status, data: JSON.parse(scrubbed) };
  }

  // ─── Health Check ──────────────────────────────────────

  async healthCheck(vaultName: string, ctx?: CallerContext): Promise<{ ok: boolean; message: string }> {
    this.policy.check(ctx, "cf_api", vaultName);

    const secrets = this.getSecrets(vaultName);
    const apiToken = secrets["CLOUDFLARE_API_TOKEN"];
    if (!apiToken) {
      return { ok: false, message: `No CLOUDFLARE_API_TOKEN in '${vaultName}'` };
    }

    try {
      const result = await this.cloudflareApi(vaultName, "GET", "/user/tokens/verify");
      const data = result.data as any;
      if (data?.result?.status === "active") {
        return { ok: true, message: `Token is active and valid ✓` };
      }
      return { ok: false, message: `Token status: ${data?.result?.status || "unknown"}` };
    } catch (err: any) {
      return { ok: false, message: `Health check failed: ${err.message}` };
    }
  }

  // ─── Backup / Restore ─────────────────────────────────

  getEncryptedVaults(): Record<string, any> {
    return vault.getEncryptedVaults();
  }

  restoreEncryptedVaults(vaults: Record<string, any>): number {
    const count = vault.restoreEncryptedVaults(vaults);
    this.audit("RESTORE", `${count} vaults restored`);
    return count;
  }

  getConfigForBackup() {
    return vault.getConfigForBackup();
  }

  updateBackupMeta(url: string) {
    vault.updateBackupMeta(url);
  }

  // ─── Audit ─────────────────────────────────────────────

  getAuditLog(lines = 20): string[] {
    const logPath = path.join(vault.getVaultlyDir(), "audit.log");
    if (!fs.existsSync(logPath)) return [];
    return fs.readFileSync(logPath, "utf8").trim().split("\n").slice(-lines);
  }

  private audit(action: string, detail: string, ctx?: CallerContext): void {
    const caller = ctx?.caller || "human";
    const logPath = path.join(vault.getVaultlyDir(), "audit.log");
    const entry = JSON.stringify({
      ts: new Date().toISOString(),
      action,
      detail,
      caller,
      agent: ctx?.agentName,
    });
    try {
      fs.appendFileSync(logPath, entry + "\n", { mode: 0o600 });
    } catch {
      // Don't fail operations if audit log isn't writable
    }
  }

  // ─── Internal ──────────────────────────────────────────

  private spawn(
    command: string,
    args: string[],
    env: Record<string, string>,
    cwd?: string
  ): Promise<{ stdout: string; stderr: string; code: number }> {
    return new Promise((resolve) => {
      const child = spawn(command, args, {
        env: { ...process.env, ...env, VAULTLY_AGENT_MODE: undefined },
        cwd: cwd || process.cwd(),
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d.toString()));
      child.stderr.on("data", (d) => (stderr += d.toString()));
      child.on("error", (err) => resolve({ stdout, stderr: stderr + err.message, code: 1 }));
      child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 0 }));
    });
  }
}

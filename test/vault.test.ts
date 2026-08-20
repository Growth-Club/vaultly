import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import * as vault from "../src/vault.js";

const dir = () => process.env.VAULTLY_DIR!;
const PASSWORD = "test-master-password";

describe("vault storage", () => {
  beforeEach(() => {
    fs.rmSync(dir(), { recursive: true, force: true });
    fs.mkdirSync(dir(), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(dir(), { recursive: true, force: true });
  });

  it("starts uninitialized and initializes", () => {
    expect(vault.isInitialized()).toBe(false);
    vault.initVault(PASSWORD);
    expect(vault.isInitialized()).toBe(true);
  });

  it("rejects re-initialization", () => {
    vault.initVault(PASSWORD);
    expect(() => vault.initVault(PASSWORD)).toThrow(/already initialized/);
  });

  it("unlocks with the correct password and rejects a wrong one", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);
    expect(key).toBeInstanceOf(Buffer);
    expect(() => vault.unlock("wrong-password")).toThrow(/Wrong master password/);
  });

  it("sets, gets, and deletes secrets", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);

    vault.setSecret("github", "GITHUB_TOKEN", "ghp_123", key);
    expect(vault.getSecret("github", "GITHUB_TOKEN", key)).toBe("ghp_123");
    expect(vault.listKeys("github", key)).toEqual(["GITHUB_TOKEN"]);

    expect(vault.deleteSecret("github", "GITHUB_TOKEN", key)).toBe(true);
    expect(vault.getSecret("github", "GITHUB_TOKEN", key)).toBeUndefined();
    expect(vault.deleteSecret("github", "GITHUB_TOKEN", key)).toBe(false);
  });

  it("stores secrets encrypted on disk (no plaintext)", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);
    vault.setSecret("github", "GITHUB_TOKEN", "ghp_super-secret", key);

    const raw = fs.readFileSync(path.join(dir(), "vaults", "github.vault"), "utf8");
    expect(raw).not.toContain("ghp_super-secret");
    expect(raw).toContain('"iv"');
    expect(raw).toContain('"authTag"');
  });

  it("lists vaults and keys", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);
    vault.setSecret("aaa", "A", "1", key);
    vault.setSecret("bbb", "B", "2", key);

    expect(vault.listVaults()).toEqual(["aaa", "bbb"]);
    expect(vault.listKeys("aaa", key)).toEqual(["A"]);
  });

  it("sanitizes vault names against path traversal", () => {
    const p = vault.getVaultFilePath("../etc/passwd");
    // Result stays inside the vaults dir as a single flat filename
    expect(p).toContain(path.join("vaults"));
    expect(path.basename(p)).toBe("---etc-passwd.vault");
    expect(p).not.toContain("..");
  });

  it("deletes an entire vault", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);
    vault.setSecret("todelete", "K", "v", key);
    expect(vault.deleteVault("todelete")).toBe(true);
    expect(vault.deleteVault("todelete")).toBe(false);
    expect(vault.listVaults()).toEqual([]);
  });

  it("imports multiple secrets", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);
    const count = vault.importSecrets("stripe", {
      STRIPE_SECRET_KEY: "sk_live_1",
      STRIPE_WEBHOOK_SECRET: "whsec_1",
    }, key);
    expect(count).toBe(2);
    expect(vault.getSecret("stripe", "STRIPE_SECRET_KEY", key)).toBe("sk_live_1");
  });

  it("round-trips encrypted backups", () => {
    vault.initVault(PASSWORD);
    const key = vault.unlock(PASSWORD);
    vault.setSecret("db", "DATABASE_URL", "postgres://user:pass@host/db", key);

    const blobs = vault.getEncryptedVaults();
    expect(Object.keys(blobs)).toEqual(["db"]);
    expect(JSON.stringify(blobs)).not.toContain("postgres://user:pass");

    fs.rmSync(path.join(dir(), "vaults"), { recursive: true, force: true });
    expect(vault.restoreEncryptedVaults(blobs)).toBe(1);
    expect(vault.getSecret("db", "DATABASE_URL", key)).toBe("postgres://user:pass@host/db");
  });

  it("tracks backup metadata in config", () => {
    vault.initVault(PASSWORD);
    vault.updateBackupMeta("https://backup.example.com");
    const config = vault.getConfigForBackup();
    expect(config.backup?.workerUrl).toBe("https://backup.example.com");
    expect(config.backup?.lastBackupAt).toBeDefined();
  });

  it("writes an audit log with file mode 0600", () => {
    vault.initVault(PASSWORD);
    const auditPath = path.join(dir(), "audit.log");
    expect(fs.existsSync(auditPath)).toBe(true);
    expect(fs.statSync(auditPath).mode & 0o777).toBe(0o600);
  });
});
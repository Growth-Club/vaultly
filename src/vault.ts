/**
 * Vaultly Vault Module
 * Manages encrypted vault files on disk (~/.vaultly/).
 * All reads/writes go through AES-256-GCM encryption.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  type VaultConfig,
  type VaultFile,
  generateSalt,
  deriveKey,
  encryptVault,
  decryptVault,
  createVerifier,
  verifyPassword,
} from "./crypto.js";

const VAULTLY_DIR = path.join(os.homedir(), ".vaultly");
const CONFIG_PATH = path.join(VAULTLY_DIR, "config.json");
const VAULTS_DIR = path.join(VAULTLY_DIR, "vaults");
const AUDIT_LOG = path.join(VAULTLY_DIR, "audit.log");

// ─── Helpers ───────────────────────────────────────────────

function ensureDirs(): void {
  fs.mkdirSync(VAULTLY_DIR, { recursive: true, mode: 0o700 });
  fs.mkdirSync(VAULTS_DIR, { recursive: true, mode: 0o700 });
}

function vaultPath(name: string): string {
  // Sanitize vault name to prevent path traversal
  const safe = name.replace(/[^a-zA-Z0-9_-]/g, "-");
  return path.join(VAULTS_DIR, `${safe}.vault`);
}

function audit(action: string, detail: string): void {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    action,
    detail,
    caller: "cli",
  });
  fs.appendFileSync(AUDIT_LOG, entry + "\n", { mode: 0o600 });
}

// ─── Config ────────────────────────────────────────────────

export function isInitialized(): boolean {
  return fs.existsSync(CONFIG_PATH);
}

export function loadConfig(): VaultConfig {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"));
}

function saveConfig(config: VaultConfig): void {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
}

// ─── Init ──────────────────────────────────────────────────

export function initVault(password: string): void {
  if (isInitialized()) {
    throw new Error("Vaultly is already initialized. Delete ~/.vaultly to start over.");
  }

  ensureDirs();

  const salt = generateSalt();
  const key = deriveKey(password, salt);
  const verifier = createVerifier(key);

  const config: VaultConfig = {
    version: 1,
    salt,
    verifier,
    createdAt: new Date().toISOString(),
  };

  saveConfig(config);
  audit("INIT", "Vault initialized");
}

/** Unlock: derive key from password, verify, return key buffer */
export function unlock(password: string): Buffer {
  const config = loadConfig();
  const key = deriveKey(password, config.salt);

  if (!verifyPassword(config.verifier, key)) {
    throw new Error("Wrong master password.");
  }

  return key;
}

// ─── Vault CRUD ────────────────────────────────────────────

function loadVaultFile(name: string): VaultFile | null {
  const p = vaultPath(name);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function saveVaultFile(name: string, vault: VaultFile): void {
  ensureDirs();
  fs.writeFileSync(vaultPath(name), JSON.stringify(vault, null, 2), { mode: 0o600 });
}

/** Get all secrets from a vault (decrypted) */
export function getSecrets(name: string, key: Buffer): Record<string, string> {
  const file = loadVaultFile(name);
  if (!file) return {};
  return decryptVault(file, key);
}

/** Get a single secret value */
export function getSecret(vaultName: string, secretKey: string, key: Buffer): string | undefined {
  const secrets = getSecrets(vaultName, key);
  return secrets[secretKey];
}

/** Add or update a secret in a vault */
export function setSecret(
  vaultName: string,
  secretKey: string,
  value: string,
  key: Buffer
): void {
  const secrets = getSecrets(vaultName, key);
  secrets[secretKey] = value;
  saveVaultFile(vaultName, encryptVault(secrets, key));
  audit("SET", `${vaultName}/${secretKey}`);
}

/** Delete a secret from a vault */
export function deleteSecret(vaultName: string, secretKey: string, key: Buffer): boolean {
  const secrets = getSecrets(vaultName, key);
  if (!(secretKey in secrets)) return false;
  delete secrets[secretKey];
  saveVaultFile(vaultName, encryptVault(secrets, key));
  audit("DELETE", `${vaultName}/${secretKey}`);
  return true;
}

/** Delete an entire vault */
export function deleteVault(name: string): boolean {
  const p = vaultPath(name);
  if (!fs.existsSync(p)) return false;
  fs.unlinkSync(p);
  audit("DELETE_VAULT", name);
  return true;
}

/** List all vault names */
export function listVaults(): string[] {
  if (!fs.existsSync(VAULTS_DIR)) return [];
  return fs
    .readdirSync(VAULTS_DIR)
    .filter((f) => f.endsWith(".vault"))
    .map((f) => f.replace(".vault", ""))
    .sort();
}

/** List secret keys in a vault (names only, no values) */
export function listKeys(vaultName: string, key: Buffer): string[] {
  const secrets = getSecrets(vaultName, key);
  return Object.keys(secrets).sort();
}

// ─── Bulk Import ───────────────────────────────────────────

/** Import multiple key-value pairs into a vault */
export function importSecrets(
  vaultName: string,
  entries: Record<string, string>,
  key: Buffer
): number {
  const secrets = getSecrets(vaultName, key);
  let count = 0;
  for (const [k, v] of Object.entries(entries)) {
    secrets[k] = v;
    count++;
  }
  saveVaultFile(vaultName, encryptVault(secrets, key));
  audit("IMPORT", `${vaultName} (${count} secrets)`);
  return count;
}

// ─── Backup / Restore (raw encrypted blobs) ────────────────

/** Get all vault files as raw encrypted data (for remote backup) */
export function getEncryptedVaults(): Record<string, VaultFile> {
  const result: Record<string, VaultFile> = {};
  for (const name of listVaults()) {
    const file = loadVaultFile(name);
    if (file) result[name] = file;
  }
  return result;
}

/** Restore vault files from raw encrypted data */
export function restoreEncryptedVaults(vaults: Record<string, VaultFile>): number {
  ensureDirs();
  let count = 0;
  for (const [name, file] of Object.entries(vaults)) {
    saveVaultFile(name, file);
    count++;
  }
  audit("RESTORE", `${count} vaults restored`);
  return count;
}

/** Get config for backup purposes */
export function getConfigForBackup(): VaultConfig {
  return loadConfig();
}

/** Update backup metadata in config */
export function updateBackupMeta(workerUrl: string): void {
  const config = loadConfig();
  config.backup = { workerUrl, lastBackupAt: new Date().toISOString() };
  saveConfig(config);
}

// ─── Paths (for display) ──────────────────────────────────

export function getVaultlyDir(): string {
  return VAULTLY_DIR;
}

export function getVaultFilePath(name: string): string {
  return vaultPath(name);
}

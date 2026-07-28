/**
 * Vaultly Crypto Module
 * AES-256-GCM authenticated encryption with PBKDF2 key derivation.
 * The master password NEVER leaves the client — only encrypted blobs are stored/synced.
 */
import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits (recommended for GCM)
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 600_000; // OWASP 2023 recommendation for PBKDF2-SHA256
const AUTH_TAG_LENGTH = 16;

export interface EncryptedPayload {
  iv: string; // hex
  authTag: string; // hex
  ciphertext: string; // hex
}

export interface VaultFile {
  version: 1;
  iv: string;
  authTag: string;
  data: string; // encrypted JSON, hex-encoded
  updatedAt: string; // ISO 8601
}

export interface VaultConfig {
  version: 1;
  salt: string; // hex — shared across all vaults
  verifier: EncryptedPayload; // encrypts "vaultly-ok" to verify password
  createdAt: string;
  backup?: {
    workerUrl?: string;
    lastBackupAt?: string;
  };
}

/** Generate a cryptographically secure random salt */
export function generateSalt(): string {
  return crypto.randomBytes(SALT_LENGTH).toString("hex");
}

/** Derive a 256-bit encryption key from password + salt using PBKDF2 */
export function deriveKey(password: string, salt: string): Buffer {
  return crypto.pbkdf2Sync(
    password,
    Buffer.from(salt, "hex"),
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    "sha256"
  );
}

/** Encrypt a plaintext string → EncryptedPayload */
export function encrypt(plaintext: string, key: Buffer): EncryptedPayload {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  let ciphertext = cipher.update(plaintext, "utf8", "hex");
  ciphertext += cipher.final("hex");
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
    ciphertext,
  };
}

/** Decrypt an EncryptedPayload → plaintext string. Throws if password is wrong. */
export function decrypt(payload: EncryptedPayload, key: Buffer): string {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(payload.iv, "hex"),
    { authTagLength: AUTH_TAG_LENGTH }
  );
  decipher.setAuthTag(Buffer.from(payload.authTag, "hex"));

  let plaintext = decipher.update(payload.ciphertext, "hex", "utf8");
  plaintext += decipher.final("utf8"); // throws if auth tag mismatch (wrong password)
  return plaintext;
}

/** Encrypt a JSON-serializable object into a VaultFile */
export function encryptVault(data: Record<string, string>, key: Buffer): VaultFile {
  const payload = encrypt(JSON.stringify(data), key);
  return {
    version: 1,
    iv: payload.iv,
    authTag: payload.authTag,
    data: payload.ciphertext,
    updatedAt: new Date().toISOString(),
  };
}

/** Decrypt a VaultFile back into a key-value object */
export function decryptVault(vault: VaultFile, key: Buffer): Record<string, string> {
  const json = decrypt(
    { iv: vault.iv, authTag: vault.authTag, ciphertext: vault.data },
    key
  );
  return JSON.parse(json);
}

/** Create the verifier payload (encrypts a known string to check password later) */
export function createVerifier(key: Buffer): EncryptedPayload {
  return encrypt("vaultly-ok", key);
}

/** Verify the master password against stored verifier */
export function verifyPassword(verifier: EncryptedPayload, key: Buffer): boolean {
  try {
    return decrypt(verifier, key) === "vaultly-ok";
  } catch {
    return false;
  }
}

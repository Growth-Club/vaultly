/**
 * macOS Keychain Integration
 *
 * Stores the derived encryption key in the macOS Keychain so:
 * - No need for VAULTLY_MASTER_PASSWORD env var
 * - No password prompt on every MCP startup
 * - Key is protected by macOS login password + Secure Enclave
 * - Auto-unlock when user is logged in
 *
 * Falls back gracefully on non-macOS platforms.
 *
 * Adopted from mcp-secrets-plugin's approach.
 */
import { execSync } from "node:child_process";

const SERVICE_NAME = "vaultly-master-key";
const ACCOUNT_NAME = "vaultly";

export function isKeychainAvailable(): boolean {
  if (process.platform !== "darwin") return false;
  try {
    execSync("security -h", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** Store the master password in Keychain (called during `vaultly init`) */
export function storeInKeychain(password: string): boolean {
  if (!isKeychainAvailable()) return false;
  try {
    // Delete existing entry first (ignore errors)
    try {
      execSync(
        `security delete-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" 2>/dev/null`,
        { stdio: "ignore" }
      );
    } catch {
      // Doesn't exist yet, fine
    }

    execSync(
      `security add-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" -w "${password.replace(/"/g, '\\"')}" -T "" -j "Vaultly master password"`,
      { stdio: "ignore" }
    );
    return true;
  } catch {
    return false;
  }
}

/** Retrieve the master password from Keychain */
export function getFromKeychain(): string | null {
  if (!isKeychainAvailable()) return null;
  try {
    const result = execSync(
      `security find-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" -w 2>/dev/null`,
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
    );
    return result.trim() || null;
  } catch {
    return null;
  }
}

/** Delete the master password from Keychain (killswitch) */
export function deleteFromKeychain(): boolean {
  if (!isKeychainAvailable()) return false;
  try {
    execSync(
      `security delete-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}"`,
      { stdio: "ignore" }
    );
    return true;
  } catch {
    return false;
  }
}

/** Check if a keychain entry exists */
export function keychainEntryExists(): boolean {
  if (!isKeychainAvailable()) return false;
  try {
    execSync(
      `security find-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" 2>/dev/null`,
      { stdio: "ignore" }
    );
    return true;
  } catch {
    return false;
  }
}

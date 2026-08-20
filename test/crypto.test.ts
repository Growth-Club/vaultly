import { describe, expect, it } from "vitest";
import {
  createVerifier,
  decrypt,
  decryptVault,
  deriveKey,
  encrypt,
  encryptVault,
  generateSalt,
  verifyPassword,
} from "../src/crypto.js";

const SALT = generateSalt();
const KEY = deriveKey("correct horse battery staple", SALT);

describe("crypto", () => {
  it("encrypts and decrypts a payload", () => {
    const payload = encrypt("hello vaultly", KEY);
    expect(payload.ciphertext).not.toContain("hello vaultly");
    expect(decrypt(payload, KEY)).toBe("hello vaultly");
  });

  it("uses a random IV per encryption (no deterministic ciphertext)", () => {
    const a = encrypt("same value", KEY);
    const b = encrypt("same value", KEY);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("rejects a wrong key (auth tag mismatch)", () => {
    const payload = encrypt("secret", KEY);
    const wrongKey = deriveKey("wrong password", SALT);
    expect(() => decrypt(payload, wrongKey)).toThrow();
  });

  it("rejects a tampered ciphertext", () => {
    const payload = encrypt("tamper me", KEY);
    const flipped = (payload.ciphertext[0] === "0" ? "1" : "0") + payload.ciphertext.slice(1);
    expect(() => decrypt({ ...payload, ciphertext: flipped }, KEY)).toThrow();
  });

  it("round-trips an entire vault", () => {
    const vaultFile = encryptVault({ KEY_ONE: "value-one", KEY_TWO: "value-two" }, KEY);
    expect(decryptVault(vaultFile, KEY)).toEqual({ KEY_ONE: "value-one", KEY_TWO: "value-two" });
  });

  it("verifies the master password via verifier", () => {
    const verifier = createVerifier(KEY);
    expect(verifyPassword(verifier, KEY)).toBe(true);
    expect(verifyPassword(verifier, deriveKey("nope", SALT))).toBe(false);
  });

  it("derives a 256-bit key", () => {
    expect(KEY).toHaveLength(32);
  });
});
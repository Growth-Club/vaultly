import { describe, expect, it } from "vitest";
import { scrubOutput } from "../src/scrubber.js";

const TOKEN = "sk-live-abcdefghijklmnopqrstuvwxyz1234567890";

describe("scrubber", () => {
  it("leaves output without secrets untouched", () => {
    expect(scrubOutput("Deployed to https://example.com", [TOKEN])).toBe(
      "Deployed to https://example.com"
    );
  });

  it("returns output as-is when no secrets are provided", () => {
    expect(scrubOutput("anything", [])).toBe("anything");
  });

  it("redacts an exact secret match", () => {
    const out = scrubOutput(`token=${TOKEN}`, [TOKEN]);
    expect(out).not.toContain(TOKEN);
    expect(out).toContain("[REDACTED]");
  });

  it("redacts the secret in all occurrences", () => {
    const out = scrubOutput(`${TOKEN} and again ${TOKEN}`, [TOKEN]);
    expect((out.match(/\[REDACTED\]/g) || []).length).toBe(2);
  });

  it("redacts a URL-encoded secret", () => {
    const encoded = encodeURIComponent(TOKEN);
    const out = scrubOutput(`auth=${encoded}`, [TOKEN]);
    expect(out).not.toContain(encoded);
    expect(out).toContain("[REDACTED]");
  });

  it("redacts a base64-encoded secret", () => {
    const b64 = Buffer.from(TOKEN).toString("base64");
    const out = scrubOutput(`auth=${b64}`, [TOKEN]);
    expect(out).not.toContain(b64);
    expect(out).toContain("[REDACTED]");
  });

  it("redacts quoted secrets", () => {
    const out = scrubOutput(`--value "${TOKEN}" --flag '${TOKEN}'`, [TOKEN]);
    expect(out).not.toContain(TOKEN);
    expect(out).toContain('"[REDACTED]"');
    expect(out).toContain("'[REDACTED]'");
  });

  it("redacts a prefix...suffix partial leak with a gap", () => {
    const out = scrubOutput(`leaked=${TOKEN.slice(0, 8)}middle-garbage${TOKEN.slice(-8)}`, [TOKEN]);
    expect(out).not.toContain(TOKEN.slice(0, 8));
    expect(out).toContain("[REDACTED]");
  });

  it("redacts a middle-only fragment of a long secret", () => {
    const fragment = TOKEN.slice(15, 35);
    const out = scrubOutput(`leaked=${fragment}`, [TOKEN]);
    expect(out).not.toContain(fragment);
    expect(out).toContain("[REDACTED]");
  });

  it("redacts a prefix fragment", () => {
    const fragment = TOKEN.slice(0, 16);
    const out = scrubOutput(`leaked=${fragment}`, [TOKEN]);
    expect(out).not.toContain(fragment);
    expect(out).toContain("[REDACTED]");
  });

  it("does not scrub passphrase fragments (no-whitespace heuristic)", () => {
    const passphrase = "correct horse battery staple";
    const fragment = passphrase.slice(9, 29);
    const out = scrubOutput(`leaked=${fragment}`, [passphrase]);
    expect(out).toContain(fragment);
  });

  it("ignores secrets shorter than 4 chars", () => {
    expect(scrubOutput("no", ["ab"])).toBe("no");
  });

  it("handles regex metacharacters in secrets", () => {
    const tricky = "a+b*c?d[1].$x^y|z\\w";
    const out = scrubOutput(`value=${tricky}`, [tricky]);
    expect(out).not.toContain(tricky);
    expect(out).toContain("[REDACTED]");
  });
});
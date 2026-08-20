/**
 * Output Scrubber
 *
 * Removes secret values from command output before agents see it.
 * Adopted from AIVault's approach — if a command accidentally prints
 * a secret (e.g. `env`, `echo $TOKEN`, error messages), we replace
 * the value with [REDACTED] before returning to the caller.
 *
 * This is a defense-in-depth measure. The primary protection is that
 * agents never receive raw values. But if a child process leaks them
 * in stdout/stderr, we catch it here.
 */

const REDACTED = "[REDACTED]";

/**
 * Scrub all known secret values from output text.
 * Handles:
 * - Exact value matches
 * - URL-encoded values
 * - Base64-encoded values
 * - Partial matches (first/last 4 chars) for very long values
 */
export function scrubOutput(output: string, secretValues: string[]): string {
  if (!output || secretValues.length === 0) return output;

  let scrubbed = output;

  for (const value of secretValues) {
    if (!value || value.length < 4) continue;

    // 1. Exact match (escaped for regex)
    const escaped = escapeRegex(value);
    scrubbed = scrubbed.replace(new RegExp(escaped, "g"), REDACTED);

    // 2. URL-encoded version
    const urlEncoded = encodeURIComponent(value);
    if (urlEncoded !== value) {
      scrubbed = scrubbed.replace(new RegExp(escapeRegex(urlEncoded), "g"), REDACTED);
    }

    // 3. Base64 version
    try {
      const b64 = Buffer.from(value).toString("base64");
      if (b64 !== value && b64.length > 4) {
        scrubbed = scrubbed.replace(new RegExp(escapeRegex(b64), "g"), REDACTED);
      }
    } catch {
      // Skip if encoding fails
    }

    // 4. Quoted versions: "value" and 'value'
    scrubbed = scrubbed.replace(new RegExp(`"${escaped}"`, "g"), `"${REDACTED}"`);
    scrubbed = scrubbed.replace(new RegExp(`'${escaped}'`, "g"), `'${REDACTED}'`);

    // 5. For long values, also catch partial leaks (first 8 + last 8 chars)
    if (value.length > 20) {
      const prefix = escapeRegex(value.slice(0, 8));
      const suffix = escapeRegex(value.slice(-8));
      // Match prefix...suffix with limited gap (non-greedy, bounded)
      scrubbed = scrubbed.replace(
        new RegExp(`${prefix}.{0,1000}?${suffix}`, "g"),
        REDACTED
      );

      // 6. Interior fragments: prefix/suffix matching misses leaks that
      //    contain only a middle portion of the secret. Dense overlapping
      //    windows across the whole value (single regex pass) catch any
      //    fragment of ~20+ chars. Token-style secrets only (no whitespace)
      //    to avoid false positives on passphrases.
      if (!/\s/.test(value)) {
        const WINDOW = 16;
        const STEP = 4;
        const windows: string[] = [];
        for (let i = 0; i + WINDOW <= value.length; i += STEP) {
          windows.push(value.slice(i, i + WINDOW));
        }
        if (windows.length > 0) {
          scrubbed = scrubbed.replace(
            new RegExp(windows.map(escapeRegex).join("|"), "g"),
            REDACTED
          );
        }
      }
    }
  }

  return scrubbed;
}

/** Escape special regex characters in a string */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

//! Output Scrubber — removes secret values from command output before agents see it.
//! Defense-in-depth: the primary protection is that agents never receive raw values;
//! if a child process leaks them in stdout/stderr, we catch them here.
//! Mirrors the TypeScript scrubber exactly.

use base64::Engine;
use regex::Regex;

pub const REDACTED: &str = "[REDACTED]";

/// JS `encodeURIComponent` compatibility: leaves `A-Za-z0-9-_.!~*'()` unescaped.
fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric() || "-_.!~*'()".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn escape_regex(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 2);
    for c in value.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Scrub all known secret values from output text.
/// Handles: exact, URL-encoded, base64, quoted, prefix/suffix partials,
/// and dense interior windows of long whitespace-free secrets.
pub fn scrub_output(output: &str, secret_values: &[String]) -> String {
    if output.is_empty() || secret_values.is_empty() {
        return output.to_string();
    }

    let mut scrubbed = output.to_string();

    for value in secret_values {
        if value.is_empty() || value.len() < 4 {
            continue;
        }

        // 1. Exact match
        if let Ok(re) = Regex::new(&escape_regex(value)) {
            scrubbed = re.replace_all(&scrubbed, REDACTED).to_string();
        }

        // 2. URL-encoded version
        let url_encoded = encode_uri_component(value);
        if url_encoded != *value {
            if let Ok(re) = Regex::new(&escape_regex(&url_encoded)) {
                scrubbed = re.replace_all(&scrubbed, REDACTED).to_string();
            }
        }

        // 3. Base64 version
        let b64 = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        if b64 != *value && b64.len() > 4 {
            if let Ok(re) = Regex::new(&escape_regex(&b64)) {
                scrubbed = re.replace_all(&scrubbed, REDACTED).to_string();
            }
        }

        // 4. Quoted versions: "value" and 'value'
        let quoted = format!("\"{}\"", escape_regex(value));
        if let Ok(re) = Regex::new(&quoted) {
            scrubbed = re.replace_all(&scrubbed, format!("\"{}\"", REDACTED)).to_string();
        }
        let quoted = format!("'{}'", escape_regex(value));
        if let Ok(re) = Regex::new(&quoted) {
            scrubbed = re.replace_all(&scrubbed, format!("'{}'", REDACTED)).to_string();
        }

        // 5. For long values, also catch partial leaks (first 8 + last 8 chars)
        if value.len() > 20 {
            let prefix = escape_regex(&value[..8]);
            let suffix = escape_regex(&value[value.len() - 8..]);
            if let Ok(re) = Regex::new(&format!("{}.{{0,1000}}?{}", prefix, suffix)) {
                scrubbed = re.replace_all(&scrubbed, REDACTED).to_string();
            }

            // 6. Interior fragments: dense overlapping windows across the whole
            //    value (single regex pass) catch any fragment of ~20+ chars.
            //    Token-style secrets only (no whitespace) to avoid false
            //    positives on passphrases.
            if !value.chars().any(|c| c.is_whitespace()) {
                const WINDOW: usize = 16;
                const STEP: usize = 4;
                let mut windows: Vec<String> = Vec::new();
                let bytes = value.as_bytes();
                let mut i = 0;
                while i + WINDOW <= bytes.len() {
                    windows.push(escape_regex(&value[i..i + WINDOW]));
                    i += STEP;
                }
                if !windows.is_empty() {
                    if let Ok(re) = Regex::new(&windows.join("|")) {
                        scrubbed = re.replace_all(&scrubbed, REDACTED).to_string();
                    }
                }
            }
        }
    }

    scrubbed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn exact_match() {
        let out = scrub_output("token=sk-live-abc123456", &[s("sk-live-abc123456")]);
        assert!(!out.contains("sk-live-abc123456"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn short_values_are_ignored() {
        // TS: values with length < 4 are skipped ("abc"), 4+ chars are scrubbed
        assert_eq!(scrub_output("abc", &[s("abc")]), "abc");
        assert_eq!(scrub_output("abcd", &[s("abcd")]), "[REDACTED]");
    }

    #[test]
    fn url_encoded_match() {
        // JS encodeURIComponent leaves ! ~ * ' ( ) unescaped — same as ours
        let secret = "super secret value!";
        let encoded = "super%20secret%20value!";
        let out = scrub_output(&format!("url={}", encoded), &[s(secret)]);
        assert!(!out.contains("super%20secret"));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn base64_match() {
        let secret = "op://secrets/credential/password";
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let out = scrub_output(&format!("token={}", b64), &[s(secret)]);
        assert!(!out.contains(&b64));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn quoted_versions() {
        let secret = "ghp_abcdef123456";
        let out = scrub_output(&format!("token=\"{}\"", secret), &[s(secret)]);
        assert!(out.contains("\"[REDACTED]\""));
        assert!(!out.contains(secret));
    }

    #[test]
    fn prefix_suffix_partial_leak() {
        let secret = "sk-live-0123456789abcdefghijklmnop";
        // Leak: first 8 + middle + last 8
        let leak = format!("{}middle-chars{}", &secret[..8], &secret[secret.len() - 8..]);
        let out = scrub_output(&leak, &[s(secret)]);
        assert!(!out.contains(&secret[..8]));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn interior_fragment_leak() {
        let secret = "abcdefghijklmnopqrstuvwxyz0123456789"; // >20, no whitespace
        // Only the middle ~20 chars leak (no prefix/suffix match possible)
        let middle = &secret[10..30];
        let out = scrub_output(&format!("leak: {}", middle), &[s(secret)]);
        assert!(!out.contains(middle));
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn passphrases_with_spaces_do_not_window_scrub() {
        // passphrase with spaces: prefix/suffix still applies (>20 chars)
        let secret = "correct horse battery staple 42";
        let leak = format!("{}xxxx{}", &secret[..8], &secret[secret.len() - 8..]);
        let out = scrub_output(&leak, &[s(secret)]);
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn no_values_noop() {
        assert_eq!(scrub_output("hello world", &[]), "hello world");
    }

    #[test]
    fn regex_special_chars_are_escaped() {
        let secret = "tok.en+x?$^{}|()[]\\*";
        let out = scrub_output(&format!("x={}", secret), &[s(secret)]);
        assert!(!out.contains(&secret[..5]));
        assert!(out.contains(REDACTED));
    }
}
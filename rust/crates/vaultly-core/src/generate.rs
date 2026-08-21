//! Cryptographically strong random secret generation.
//! Used by the CLI `gen`/`rotate` commands and the MCP `vault_generate` tool.

use rand::Rng;

/// Characters that are safe in URL query strings and shell-quoted contexts
/// (excludes quotes, backslash, and characters with high ambiguity).
const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";

/// Generate a random secret of `length` characters.
///
/// Uses the cryptographic RNG from `rand` (thread_rng → OS entropy).
/// When `use_symbols` is true, the result includes punctuation but never
/// characters that break shell single-quoting or URL parsing.
pub fn generate_secret(length: usize, use_symbols: bool) -> String {
    let length = length.clamp(1, 4096);
    let mut rng = rand::thread_rng();
    if use_symbols {
        let mut pool = Vec::with_capacity(ALPHANUMERIC.len() + SYMBOLS.len());
        pool.extend_from_slice(ALPHANUMERIC);
        pool.extend_from_slice(SYMBOLS);
        let mut out = String::with_capacity(length);
        for _ in 0..length {
            let idx = rng.gen_range(0..pool.len());
            out.push(pool[idx] as char);
        }
        out
    } else {
        let mut out = String::with_capacity(length);
        for _ in 0..length {
            let idx = rng.gen_range(0..ALPHANUMERIC.len());
            out.push(ALPHANUMERIC[idx] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::generate_secret;

    #[test]
    fn generates_requested_length() {
        assert_eq!(generate_secret(24, false).len(), 24);
        assert_eq!(generate_secret(64, true).len(), 64);
    }

    #[test]
    fn clamps_extreme_lengths() {
        assert_eq!(generate_secret(0, false).len(), 1);
        assert_eq!(generate_secret(10_000, true).len(), 4096);
    }

    #[test]
    fn alphanumeric_output_only() {
        let s = generate_secret(200, false);
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn symbols_mode_is_not_purely_alphanumeric() {
        // Over many draws, symbol mode should include a symbol somewhere.
        let any_symbol = (0..100).any(|_| {
            generate_secret(64, true)
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric())
        });
        assert!(any_symbol, "symbol mode should occasionally emit a symbol");
    }
}

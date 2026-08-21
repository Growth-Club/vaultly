//! Vaultly Crypto
//! AES-256-GCM authenticated encryption with PBKDF2-SHA256 key derivation.
//! File-format compatible with the TypeScript implementation (16-byte GCM nonce,
//! 600k PBKDF2 iterations, hex encoding, identical JSON shapes).
use crate::error::{Result, VaultError};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

pub const KEY_LENGTH: usize = 32; // 256 bits
pub const IV_LENGTH: usize = 16; // must match TS (node crypto allows 16)
pub const SALT_LENGTH: usize = 32;
pub const PBKDF2_ITERATIONS: u32 = 600_000; // OWASP 2023 for PBKDF2-SHA256
pub const AUTH_TAG_LENGTH: usize = 16;

/// Current on-disk vault format version. v1 = bare string per secret; v2 =
/// per-secret `SecretEntry` objects carrying created/updated/expiry metadata.
/// Newer builds read both transparently (see `SecretEntry::from_value`), and
/// old files are migrated on their next write.
pub const FORMAT_VERSION: u32 = 2;

/// Encrypted per-secret payload: the plaintext plus metadata (created/updated
/// timestamps, optional expiry). Stored as `{"value":..,"createdAt":..,
/// "updatedAt":..,"expiresAt":..}` inside a vault's encrypted `data` blob for
/// format version 2. Format version 1 files store a bare string per key;
/// `from_value`/`to_value` bridge the two.
/// Encrypted per-secret payload. NOTE: `Debug` is manually implemented to
/// REDACT the secret `value` — never derive Debug on a type that holds
/// plaintext secrets (a `{:?}` log/panic would leak it).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretEntry {
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEntry")
            .field("value", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SecretEntry {
    pub fn new(value: &str, now: &str) -> Self {
        Self {
            value: value.to_string(),
            created_at: now.to_string(),
            updated_at: now.to_string(),
            expires_at: None,
        }
    }

    pub fn plaintext(&self) -> &str {
        &self.value
    }

    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("SecretEntry always serializes to an object")
    }

    /// Parse a single decrypted value — either a v1 bare string or a v2
    /// `SecretEntry` object. v1 strings carry no timestamps (empty strings).
    pub fn from_value(key: &str, v: &serde_json::Value) -> Result<Self> {
        match v {
            serde_json::Value::String(s) => Ok(Self::new(s, "")),
            serde_json::Value::Object(_) => serde_json::from_value(v.clone()).map_err(|e| {
                VaultError::Decrypt(format!("Invalid secret entry for '{}': {}", key, e))
            }),
            other => Err(VaultError::Decrypt(format!(
                "Invalid secret value type for '{}': {}",
                key, other
            ))),
        }
    }

    pub fn is_expired(&self, now: &chrono::DateTime<chrono::Utc>) -> bool {
        match self.expires_at.as_deref() {
            Some(iso) => chrono::DateTime::parse_from_rfc3339(iso)
                .map(|t| t.with_timezone(&chrono::Utc) < *now)
                .unwrap_or(false),
            None => false,
        }
    }
}

/// Agent-safe secret metadata — deliberately NO value. Returned by meta APIs
/// so agents and the TUI can surface per-secret timestamps and expiry without
/// ever seeing the plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SecretMeta {
    pub key: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub expired: bool,
    /// true when timestamps are unknown (a v1-origin secret not yet rewritten)
    pub unknown_timestamps: bool,
}

impl SecretMeta {
    pub fn from_entry(key: &str, e: &SecretEntry, now: &chrono::DateTime<chrono::Utc>) -> Self {
        let unknown_timestamps = e.created_at.is_empty() && e.updated_at.is_empty();
        Self {
            key: key.to_string(),
            created_at: e.created_at.clone(),
            updated_at: e.updated_at.clone(),
            expires_at: e.expires_at.clone(),
            expired: e.is_expired(now),
            unknown_timestamps,
        }
    }
}

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::generic_array::typenum::U16>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedPayload {
    pub iv: String,         // hex
    pub auth_tag: String,   // hex — serialized as authTag
    pub ciphertext: String, // hex
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultFile {
    pub version: u32,
    pub iv: String,
    pub auth_tag: String,   // serialized as authTag
    pub data: String,       // encrypted JSON, hex-encoded
    pub updated_at: String, // ISO 8601 — serialized as updatedAt
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BackupMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_backup_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub version: u32,
    pub salt: String, // hex — shared across all vaults
    pub verifier: EncryptedPayload,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupMeta>,
    /// Idle auto-lock: wipe the key after this many minutes of inactivity.
    /// `None` disables idle auto-lock (session TTL still applies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_lock_minutes: Option<u64>,
}

/// Cryptographically secure random hex salt
pub fn generate_salt() -> String {
    let mut bytes = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Derive a 256-bit key from password + salt using PBKDF2-SHA256.
/// Returns a `Zeroizing` buffer so the key bytes are wiped on drop.
pub fn derive_key(password: &str, salt_hex: &str) -> Result<Zeroizing<Vec<u8>>> {
    let salt = hex::decode(salt_hex)
        .map_err(|e| VaultError::Crypto(format!("Invalid salt hex: {}", e)))?;
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key)
        .map_err(|e| VaultError::KeyDerivation(e.to_string()))?;
    Ok(Zeroizing::new(key.to_vec()))
}

pub(crate) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Encrypt plaintext → EncryptedPayload
pub fn encrypt(plaintext: &str, key: &[u8]) -> Result<EncryptedPayload> {
    let cipher = Aes256Gcm16::new(GenericArray::from_slice(key));
    let mut iv = [0u8; IV_LENGTH];
    rand::thread_rng().fill_bytes(&mut iv);

    let ciphertext = cipher
        .encrypt(GenericArray::from_slice(&iv), plaintext.as_bytes())
        .map_err(|_| VaultError::Crypto("Encryption failed".into()))?;

    let (ct, tag) = ciphertext.split_at(ciphertext.len() - AUTH_TAG_LENGTH);
    Ok(EncryptedPayload {
        iv: hex::encode(iv),
        auth_tag: hex::encode(tag),
        ciphertext: hex::encode(ct),
    })
}

/// Decrypt an EncryptedPayload → plaintext. Err if auth fails (wrong key).
pub fn decrypt(payload: &EncryptedPayload, key: &[u8]) -> Result<String> {
    let cipher = Aes256Gcm16::new(GenericArray::from_slice(key));
    let iv = hex::decode(&payload.iv).map_err(|_| VaultError::Crypto("Invalid IV".into()))?;
    let mut ct = hex::decode(&payload.ciphertext)
        .map_err(|_| VaultError::Crypto("Invalid ciphertext".into()))?;
    let tag = hex::decode(&payload.auth_tag)
        .map_err(|_| VaultError::Crypto("Invalid auth tag".into()))?;
    ct.extend_from_slice(&tag);

    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&iv), ct.as_slice())
        .map_err(|_| VaultError::Decrypt("Decryption failed (wrong key)".into()))?;
    String::from_utf8(plaintext)
        .map_err(|_| VaultError::Decrypt("Decrypted data is not UTF-8".into()))
}

/// Encrypt a key-value map into a VaultFile
pub fn encrypt_vault(
    data: &serde_json::Map<String, serde_json::Value>,
    key: &[u8],
) -> Result<VaultFile> {
    let payload = encrypt(&serde_json::to_string(data)?, key)?;
    Ok(VaultFile {
        version: FORMAT_VERSION,
        iv: payload.iv,
        auth_tag: payload.auth_tag,
        data: payload.ciphertext,
        updated_at: now_iso(),
    })
}

/// Decrypt a VaultFile back into a key-value map
pub fn decrypt_vault(
    vault: &VaultFile,
    key: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let json = decrypt(
        &EncryptedPayload {
            iv: vault.iv.clone(),
            auth_tag: vault.auth_tag.clone(),
            ciphertext: vault.data.clone(),
        },
        key,
    )?;
    match serde_json::from_str::<serde_json::Value>(&json)
        .map_err(|e| VaultError::Decrypt(format!("Invalid decrypted JSON: {}", e)))?
    {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(VaultError::Decrypt(
            "Decrypted vault is not an object".into(),
        )),
    }
}

/// Verifier encrypts a known string to check the password later
pub fn create_verifier(key: &[u8]) -> Result<EncryptedPayload> {
    encrypt("vaultly-ok", key)
}

/// Portable encrypted export blob. Self-contained: carries its own salt so it
/// can be imported by any vaultly instance that knows the master password.
/// Format: `{"version":1,"salt":<hex>,"iv":<hex>,"authTag":<hex>,"ciphertext":<hex>}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedExport {
    pub version: u32,
    pub salt: String, // hex
    #[serde(flatten)]
    pub payload: EncryptedPayload,
}

/// Format version for `EncryptedExport`. Bumped if the on-disk format changes.
pub const EXPORT_FORMAT_VERSION: u32 = 1;

/// Serialize secret entries into an encrypted, portable export blob.
/// `password` is used to derive a fresh key (with a new random salt) and is
/// never stored. The returned blob can be written to disk and imported on any
/// vaultly instance with the same master password.
pub fn encrypt_export(
    entries: &BTreeMap<String, SecretEntry>,
    password: &str,
) -> Result<EncryptedExport> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    let json = serde_json::to_string(entries)
        .map_err(|e| VaultError::Crypto(format!("Export serialization failed: {e}")))?;
    let payload = encrypt(&json, &key)?;
    Ok(EncryptedExport {
        version: EXPORT_FORMAT_VERSION,
        salt,
        payload,
    })
}

/// Decrypt an `EncryptedExport` blob back into secret entries.
pub fn decrypt_export(
    blob: &EncryptedExport,
    password: &str,
) -> Result<BTreeMap<String, SecretEntry>> {
    if blob.version != EXPORT_FORMAT_VERSION {
        return Err(VaultError::Decrypt(format!(
            "Unsupported export version {} (expected {})",
            blob.version, EXPORT_FORMAT_VERSION
        )));
    }
    let key = derive_key(password, &blob.salt)?;
    let json = decrypt(&blob.payload, &key)?;
    serde_json::from_str(&json)
        .map_err(|e| VaultError::Decrypt(format!("Export deserialization failed: {e}")))
}
/// Verify the master password against the stored verifier
pub fn verify_password(verifier: &EncryptedPayload, key: &[u8]) -> bool {
    decrypt(verifier, key)
        .map(|p| p == "vaultly-ok")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_entry_debug_redacts_value() {
        let entry = SecretEntry::new("super-secret-value-12345", "2024-01-01T00:00:00Z");
        let debug = format!("{:?}", entry);
        assert!(
            !debug.contains("super-secret-value-12345"),
            "SecretEntry Debug must not contain the secret value: {debug}"
        );
        assert!(debug.contains("[REDACTED]"));
        // Metadata should still be present.
        assert!(debug.contains("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn secret_entry_debug_with_expiry() {
        let mut entry = SecretEntry::new("hidden", "2024-01-01T00:00:00Z");
        entry.expires_at = Some("2025-01-01T00:00:00Z".into());
        let debug = format!("{:?}", entry);
        assert!(!debug.contains("hidden"));
        assert!(debug.contains("2025-01-01T00:00:00Z"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = vec![7u8; 32];
        let payload = encrypt("hello vaultly", &key).unwrap();
        assert_eq!(decrypt(&payload, &key).unwrap(), "hello vaultly");
    }

    #[test]
    fn wrong_key_fails_auth() {
        let key = vec![1u8; 32];
        let other = vec![2u8; 32];
        let payload = encrypt("secret", &key).unwrap();
        assert!(decrypt(&payload, &other).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = vec![3u8; 32];
        let mut payload = encrypt("secret-data", &key).unwrap();
        let bytes = hex::decode(&payload.ciphertext).unwrap();
        let mut new_ct = hex::encode([bytes[0] ^ 0xff]);
        new_ct.push_str(&hex::encode(&bytes[1..]));
        payload.ciphertext = new_ct;
        assert!(decrypt(&payload, &key).is_err());
    }

    #[test]
    fn iv_is_16_bytes_random() {
        let key = vec![0u8; 32];
        let a = encrypt("x", &key).unwrap();
        let b = encrypt("x", &key).unwrap();
        assert_eq!(a.iv.len(), 32); // 16 bytes hex
        assert_ne!(a.iv, b.iv);
    }

    #[test]
    fn verifier_roundtrip() {
        let key = derive_key("master-pass", &generate_salt()).unwrap();
        let verifier = create_verifier(&key).unwrap();
        assert!(verify_password(&verifier, &key));
        let wrong = derive_key("wrong-pass", &generate_salt()).unwrap();
        assert!(!verify_password(&verifier, &wrong));
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = generate_salt();
        let k1 = derive_key("pw", &salt).unwrap();
        let k2 = derive_key("pw", &salt).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        let k3 = derive_key("pw2", &salt).unwrap();
        assert_ne!(k1, k3);
    }

    #[test]
    fn vault_file_roundtrip() {
        let key = derive_key("pw", &generate_salt()).unwrap();
        let mut map = serde_json::Map::new();
        map.insert("K1".into(), serde_json::Value::String("v1".into()));
        map.insert("K2".into(), serde_json::Value::String("v2".into()));
        let file = encrypt_vault(&map, &key).unwrap();
        let back = decrypt_vault(&file, &key).unwrap();
        assert_eq!(back, map);
    }

    #[test]
    fn serialization_is_camel_case_compatible() {
        // TS emits {"version":1,"iv":..,"authTag":..,"data":..,"updatedAt":..}
        let key = derive_key("pw", &generate_salt()).unwrap();
        let mut map = serde_json::Map::new();
        map.insert("A".into(), serde_json::Value::String("B".into()));
        let file = encrypt_vault(&map, &key).unwrap();
        let json = serde_json::to_string(&file).unwrap();
        assert!(json.contains("\"authTag\""));
        assert!(json.contains("\"updatedAt\""));
        assert!(!json.contains("auth_tag"));
        assert!(!json.contains("updated_at"));
        // And it parses back
        let parsed: VaultFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, file);
    }

    #[test]
    fn encrypted_export_roundtrip() {
        let mut entries = BTreeMap::new();
        entries.insert(
            "API_KEY".into(),
            SecretEntry::new("sk-live-abcdef123456", "2024-01-01T00:00:00Z"),
        );
        entries.insert(
            "TOKEN".into(),
            SecretEntry::new("ghp_xxx", "2024-02-02T00:00:00Z"),
        );

        let blob = encrypt_export(&entries, "master-pw").unwrap();
        assert_eq!(blob.version, EXPORT_FORMAT_VERSION);
        assert!(!blob.salt.is_empty());

        // Same password → decrypts.
        let decrypted = decrypt_export(&blob, "master-pw").unwrap();
        assert_eq!(decrypted, entries);

        // Wrong password → fails.
        assert!(decrypt_export(&blob, "wrong-pw").is_err());
    }

    #[test]
    fn encrypted_export_wrong_version_rejected() {
        let mut entries = BTreeMap::new();
        entries.insert("K".into(), SecretEntry::new("v", "2024-01-01T00:00:00Z"));
        let mut blob = encrypt_export(&entries, "pw").unwrap();
        blob.version = 99;
        assert!(decrypt_export(&blob, "pw").is_err());
    }

    proptest::proptest! {
        /// Arbitrary strings (incl. multi-byte unicode) must round-trip through
        /// AES-256-GCM untouched.
        #[test]
        fn proptest_encrypt_decrypt_roundtrip(s in "\\PC*") {
            let key = vec![42u8; 32];
            let payload = encrypt(&s, &key).unwrap();
            assert_eq!(decrypt(&payload, &key).unwrap(), s);
        }

        /// Ciphertext is authenticated and never equal to the plaintext bytes
        /// for non-empty inputs (empty input legitimately maps to empty
        /// AES-GCM output, so it is excluded here).
        #[test]
        fn proptest_ciphertext_differs_from_plaintext(s in "[a-z0-9_]{1,96}") {
            let key = vec![9u8; 32];
            let payload = encrypt(&s, &key).unwrap();
            let ct = hex::decode(&payload.ciphertext).unwrap();
            assert_ne!(ct, s.as_bytes(), "ciphertext echoes plaintext");
        }

        /// SecretEntry (value + metadata) must round-trip through JSON with the
        /// value intact and the Debug/redactor never interfering.
        #[test]
        fn proptest_secret_entry_roundtrip(
            value in "[a-zA-Z0-9._~+/-]{1,120}",
            created in "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z",
            updated in "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z",
        ) {
            let entry = SecretEntry {
                value: value.clone(),
                created_at: created,
                updated_at: updated,
                expires_at: None,
            };
            let json = serde_json::to_value(&entry).unwrap();
            let parsed: SecretEntry = serde_json::from_value(json).unwrap();
            assert_eq!(parsed.value, value);
            // Debug must never surface the value regardless of content.
            assert!(!format!("{:?}", parsed).contains(&value));
        }
    }
}

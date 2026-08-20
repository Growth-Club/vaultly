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

pub const KEY_LENGTH: usize = 32; // 256 bits
pub const IV_LENGTH: usize = 16; // must match TS (node crypto allows 16)
pub const SALT_LENGTH: usize = 32;
pub const PBKDF2_ITERATIONS: u32 = 600_000; // OWASP 2023 for PBKDF2-SHA256
pub const AUTH_TAG_LENGTH: usize = 16;

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
}

/// Cryptographically secure random hex salt
pub fn generate_salt() -> String {
    let mut bytes = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Derive a 256-bit key from password + salt using PBKDF2-SHA256
pub fn derive_key(password: &str, salt_hex: &str) -> Result<Vec<u8>> {
    let salt = hex::decode(salt_hex)
        .map_err(|e| VaultError::Crypto(format!("Invalid salt hex: {}", e)))?;
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key)
        .expect("PBKDF2 should not fail");
    Ok(key.to_vec())
}

fn now_iso() -> String {
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
    let mut ct = hex::decode(&payload.ciphertext).map_err(|_| VaultError::Crypto("Invalid ciphertext".into()))?;
    let tag = hex::decode(&payload.auth_tag).map_err(|_| VaultError::Crypto("Invalid auth tag".into()))?;
    ct.extend_from_slice(&tag);

    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&iv), ct.as_slice())
        .map_err(|_| VaultError::Decrypt("Decryption failed (wrong key)".into()))?;
    String::from_utf8(plaintext).map_err(|_| VaultError::Decrypt("Decrypted data is not UTF-8".into()))
}

/// Encrypt a key-value map into a VaultFile
pub fn encrypt_vault(
    data: &serde_json::Map<String, serde_json::Value>,
    key: &[u8],
) -> Result<VaultFile> {
    let payload = encrypt(&serde_json::to_string(data)?, key)?;
    Ok(VaultFile {
        version: 1,
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
        _ => Err(VaultError::Decrypt("Decrypted vault is not an object".into())),
    }
}

/// Verifier encrypts a known string to check the password later
pub fn create_verifier(key: &[u8]) -> Result<EncryptedPayload> {
    encrypt("vaultly-ok", key)
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
}

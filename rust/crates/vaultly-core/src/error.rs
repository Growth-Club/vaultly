//! Vaultly error types — structured, actionable, agent-safe.
//!
//! Replaces ad-hoc `String` errors with typed enums so callers can match
//! on failure modes without parsing text.  Every variant is safe to show
//! to an agent: no raw secret values are ever embedded.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vaultly is not initialized. Run `vaultly init` first.")]
    NotInitialized,

    #[error("Vaultly is already initialized. Delete {0} to start over.")]
    AlreadyInitialized(String),

    #[error("Vault is locked. Unlock first.")]
    Locked,

    #[error("Vault is locked. Session expired. Unlock again.")]
    SessionExpired,

    #[error("Wrong master password.")]
    WrongPassword,

    #[error("Vault '{0}' not found. Create it with: vaultly add {0} -k KEY -v VALUE")]
    VaultNotFound(String),

    #[error("Vault '{0}' exists but has no secrets.")]
    VaultEmpty(String),

    #[error("Secret '{0}' not found in vault '{1}'.")]
    SecretNotFound(String, String),

    #[error("Vault name '{0}' is invalid. Use letters, numbers, hyphens, and underscores.")]
    InvalidVaultName(String),

    #[error("Vault file '{0}' is corrupt: {1}")]
    VaultCorrupt(String, String),

    #[error("Config file is corrupt: {0}")]
    ConfigCorrupt(String),

    #[error("Encryption failed: {0}")]
    Crypto(String),

    #[error("Decryption failed: {0}")]
    Decrypt(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Policy denied: {0}")]
    Policy(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Cloudflare request failed: {0}")]
    CloudflareRequest(#[source] reqwest::Error),

    #[error("Invalid Cloudflare response: {0}")]
    CloudflareResponse(String),

    #[error("No valid Cloudflare credentials in vault '{0}': {1}")]
    CloudflareCredentials(String, String),

    #[error("Missing CLOUDFLARE_ACCOUNT_ID in vault '{0}'. Found: {1}")]
    MissingAccountId(String, String),

    #[error("Command '{0}' failed to start: {1}")]
    CommandSpawn(String, String),

    #[error("Unknown worker secret action: {0}")]
    UnknownSecretAction(String),

    #[error("'{0}' is required for worker secret {1}.")]
    RequiredField(String, String),

    #[error("Audit log unavailable: {0}")]
    Audit(String),

    #[error("Backup metadata update failed: {0}")]
    BackupMetaUpdate(String),
}

impl From<reqwest::Error> for VaultError {
    fn from(e: reqwest::Error) -> Self {
        VaultError::CloudflareRequest(e)
    }
}

impl From<shell_words::ParseError> for VaultError {
    fn from(e: shell_words::ParseError) -> Self {
        VaultError::CommandSpawn("shell-parse".into(), e.to_string())
    }
}

impl From<String> for VaultError {
    fn from(e: String) -> Self {
        VaultError::Policy(e)
    }
}

impl From<&str> for VaultError {
    fn from(e: &str) -> Self {
        VaultError::Policy(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

impl VaultError {
    pub fn into_string(self) -> String {
        self.to_string()
    }
}

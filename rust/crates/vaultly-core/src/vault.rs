//! Vault storage — encrypted vault files on disk (~/.vaultly/).
//! Mirrors the TypeScript vault.ts exactly (paths, formats, permissions).

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::crypto::{
    create_verifier, decrypt_vault, derive_key, encrypt_vault, generate_salt, verify_password,
    BackupMeta, VaultConfig, VaultFile,
};
use crate::error::{VaultError, Result};

pub struct VaultStore {
    dir: PathBuf,
}

/// Maximum audit log size before rotation (1 MiB)
pub const AUDIT_MAX_BYTES: u64 = 1024 * 1024;

fn default_dir() -> PathBuf {
    if let Ok(d) = std::env::var("VAULTLY_DIR") {
        PathBuf::from(d)
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".vaultly")
    }
}

impl VaultStore {
    pub fn new() -> Self {
        Self { dir: default_dir() }
    }

    /// Explicit directory (tests, custom setups). Bypasses VAULTLY_DIR.
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    fn vaults_dir(&self) -> PathBuf {
        self.dir.join("vaults")
    }

    fn audit_path(&self) -> PathBuf {
        self.dir.join("audit.log")
    }

    /// Public path accessor for CLI/TUI display and MCP audit tool
    pub fn audit_log_path(&self) -> PathBuf {
        self.audit_path()
    }

    fn ensure_dirs(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(&self.dir)?;
        fs::create_dir_all(self.vaults_dir())?;
        fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).ok();
        fs::set_permissions(self.vaults_dir(), fs::Permissions::from_mode(0o700)).ok();
        Ok(())
    }

    fn sanitize_name(name: &str) -> Result<String> {
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        if safe.is_empty() || safe == "-" {
            return Err(VaultError::InvalidVaultName(name.to_string()));
        }
        Ok(safe)
    }

    fn vault_path(&self, name: &str) -> Result<PathBuf> {
        let safe = Self::sanitize_name(name)?;
        Ok(self.vaults_dir().join(format!("{}.vault", safe)))
    }

    fn write_secure(path: &PathBuf, contents: &str) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    pub fn audit(&self, action: &str, detail: &str) {
        let path = self.audit_path();
        Self::rotate_if_needed(&path);
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "action": action,
            "detail": detail,
            "caller": "cli",
        });
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
        {
            let _ = writeln!(f, "{}", entry);
        }
    }

    fn rotate_if_needed(path: &PathBuf) {
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() <= AUDIT_MAX_BYTES {
                return;
            }
        }
        let rotated = format!("{}.1", path.display());
        let _ = fs::rename(path, &rotated);
    }

    // ─── Config ───────────────────────────────────────────

    pub fn is_initialized(&self) -> bool {
        self.config_path().exists()
    }

    pub fn load_config(&self) -> Result<VaultConfig> {
        let raw = fs::read_to_string(self.config_path())?;
        serde_json::from_str(&raw).map_err(|e| VaultError::ConfigCorrupt(e.to_string()))
    }

    fn save_config(&self, config: &VaultConfig) -> Result<()> {
        self.ensure_dirs()?;
        let json = serde_json::to_string_pretty(config)?;
        Self::write_secure(&self.config_path(), &json)?;
        Ok(())
    }

    // ─── Init / Unlock ────────────────────────────────────

    pub fn init_vault(&self, password: &str) -> Result<()> {
        if self.is_initialized() {
            return Err(VaultError::AlreadyInitialized(self.config_path().display().to_string()));
        }
        self.ensure_dirs()?;

        let salt = generate_salt();
        let key = derive_key(password, &salt)?;
        let verifier = create_verifier(&key)?;

        let config = VaultConfig {
            version: 1,
            salt,
            verifier,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            backup: None,
        };
        self.save_config(&config)?;
        self.audit("INIT", "Vault initialized");
        Ok(())
    }

    /// Unlock: derive key from password, verify, return key.
    pub fn unlock(&self, password: &str) -> Result<Vec<u8>> {
        let config = self.load_config()?;
        let key = derive_key(password, &config.salt)?;
        if !verify_password(&config.verifier, &key) {
            return Err(VaultError::WrongPassword);
        }
        Ok(key)
    }

    // ─── Vault CRUD ───────────────────────────────────────

    fn load_vault_file(&self, name: &str) -> Result<Option<VaultFile>> {
        let p = self.vault_path(name)?;
        if !p.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&p)?;
        Ok(serde_json::from_str(&raw).map(Some)?)
    }

    fn save_vault_file(&self, name: &str, vault: &VaultFile) -> Result<()> {
        self.ensure_dirs()?;
        let json = serde_json::to_string_pretty(vault)?;
        Self::write_secure(&self.vault_path(name)?, &json)?;
        Ok(())
    }

    /// Get all secrets from a vault (decrypted). Missing vault → empty map.
    pub fn get_secrets(
        &self,
        name: &str,
        key: &[u8],
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        match self.load_vault_file(name)? {
            Some(file) => decrypt_vault(&file, key),
            None => Ok(serde_json::Map::new()),
        }
    }

    pub fn vault_exists(&self, name: &str) -> Result<bool> {
        Ok(self.vault_path(name)?.exists())
    }

    pub fn get_secret(
        &self,
        vault_name: &str,
        secret_key: &str,
        key: &[u8],
    ) -> Result<Option<String>> {
        let secrets = self.get_secrets(vault_name, key)?;
        Ok(secrets
            .get(secret_key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()))
    }

    pub fn set_secret(
        &self,
        vault_name: &str,
        secret_key: &str,
        value: &str,
        key: &[u8],
    ) -> Result<()> {
        let mut secrets = self.get_secrets(vault_name, key)?;
        secrets.insert(
            secret_key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
        let file = encrypt_vault(&secrets, key)?;
        self.save_vault_file(vault_name, &file)?;
        self.audit("SET", &format!("{}/{}", vault_name, secret_key));
        Ok(())
    }

    pub fn delete_secret(
        &self,
        vault_name: &str,
        secret_key: &str,
        key: &[u8],
    ) -> Result<bool> {
        let mut secrets = self.get_secrets(vault_name, key)?;
        if secrets.remove(secret_key).is_none() {
            return Ok(false);
        }
        let file = encrypt_vault(&secrets, key)?;
        self.save_vault_file(vault_name, &file)?;
        self.audit("DELETE", &format!("{}/{}", vault_name, secret_key));
        Ok(true)
    }

    pub fn delete_vault(&self, name: &str) -> Result<bool> {
        let p = self.vault_path(name)?;
        if !p.exists() {
            return Ok(false);
        }
        fs::remove_file(&p)?;
        self.audit("DELETE_VAULT", name);
        Ok(true)
    }

    pub fn list_vaults(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(self.vaults_dir()) else {
            return vec![];
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "vault").unwrap_or(false))
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .map(|s| s.trim_end_matches(".vault").to_string())
            .collect();
        names.sort();
        names
    }

    /// List secret keys in a vault (names only)
    pub fn list_keys(&self, vault_name: &str, key: &[u8]) -> Result<Vec<String>> {
        let secrets = self.get_secrets(vault_name, key)?;
        let mut keys: Vec<String> = secrets.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }

    // ─── Bulk Import ──────────────────────────────────────

    pub fn import_secrets(
        &self,
        vault_name: &str,
        entries: &serde_json::Map<String, serde_json::Value>,
        key: &[u8],
    ) -> Result<usize> {
        let mut secrets = self.get_secrets(vault_name, key)?;
        let count = entries.len();
        for (k, v) in entries {
            secrets.insert(k.clone(), v.clone());
        }
        let file = encrypt_vault(&secrets, key)?;
        self.save_vault_file(vault_name, &file)?;
        self.audit("IMPORT", &format!("{} ({} secrets)", vault_name, count));
        Ok(count)
    }

    // ─── Backup / Restore (raw encrypted blobs) ───────────

    pub fn get_encrypted_vaults(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut result = serde_json::Map::new();
        for name in self.list_vaults() {
            if let Ok(Some(file)) = self.load_vault_file(&name) {
                if let Ok(v) = serde_json::to_value(&file) {
                    result.insert(name, v);
                }
            }
        }
        result
    }

    pub fn restore_encrypted_vaults(
        &self,
        vaults: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<usize> {
        self.ensure_dirs()?;
        let mut count = 0;
        for (name, value) in vaults {
            let file: VaultFile = serde_json::from_value(value.clone())
                .map_err(|e| VaultError::VaultCorrupt(name.clone(), e.to_string()))?;
            self.save_vault_file(name, &file)?;
            count += 1;
        }
        self.audit("RESTORE", &format!("{} vaults restored", count));
        Ok(count)
    }

    pub fn get_config_for_backup(&self) -> Result<VaultConfig> {
        self.load_config()
    }

    pub fn update_backup_meta(&self, worker_url: &str) -> Result<()> {
        let mut config = self.load_config()?;
        config.backup = Some(BackupMeta {
            worker_url: Some(worker_url.to_string()),
            last_backup_at: Some(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
        });
        self.save_config(&config)
    }

    pub fn get_vault_file_path(&self, name: &str) -> Result<PathBuf> {
        self.vault_path(name)
    }
}

impl Default for VaultStore {
    fn default() -> Self {
        Self::new()
    }
}

// Sanitization is also useful for CLI validation
pub fn sanitize_vault_name(name: &str) -> Result<String> {
    VaultStore::sanitize_name(name)
}

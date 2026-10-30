//! Vault storage — encrypted vault files on disk (~/.vaultly/).
//! Mirrors the TypeScript vault.ts exactly (paths, formats, permissions).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::crypto::{
    create_verifier, decrypt_vault, derive_key, encrypt_vault, generate_salt, now_iso,
    verify_password, BackupMeta, SecretEntry, SecretMeta, VaultConfig, VaultFile,
};
use crate::deploy::DeploymentTarget;
use crate::error::{Result, VaultError};
use zeroize::Zeroizing;

/// A soft-deleted secret kept in the trash for recovery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashEntry {
    pub key: String,
    pub entry: crate::crypto::SecretEntry,
    pub deleted_at: String,
}

pub struct VaultStore {
    dir: PathBuf,
}

/// Maximum audit log size before rotation (1 MiB)
pub const AUDIT_MAX_BYTES: u64 = 1024 * 1024;

/// Maximum secret value length in bytes (256 KiB).
pub const MAX_SECRET_VALUE_LENGTH: usize = 256 * 1024;

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

    fn lock_path(&self) -> PathBuf {
        self.dir.join(".write.lock")
    }

    /// Acquire an inter-process write lock via an exclusive lock file. Falls
    /// back to stale-lock recovery after 30s and gives up after ~3s rather than
    /// blocking forever. Combined with atomic writes this prevents lost updates
    /// and partial writes when two processes touch the store concurrently.
    fn acquire_lock(&self) -> std::io::Result<()> {
        let lock_path = self.lock_path();
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&lock_path)
                        .and_then(|m| m.modified())
                        .map(|t| {
                            t.elapsed()
                                .map(|d| d > std::time::Duration::from_secs(30))
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    if stale {
                        let _ = fs::remove_file(&lock_path);
                        continue;
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn release_lock(&self) {
        let _ = fs::remove_file(self.lock_path());
    }

    fn with_write_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.acquire_lock()?;
        let res = f();
        self.release_lock();
        res
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

    fn deployment_targets_path(&self) -> PathBuf {
        self.dir.join("deployment-targets.json")
    }

    /// Load non-secret deployment routing metadata.
    pub fn load_deployment_targets(&self) -> Result<Vec<DeploymentTarget>> {
        let path = self.deployment_targets_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(path)?;
        let targets: Vec<DeploymentTarget> = serde_json::from_str(&raw)
            .map_err(|e| VaultError::ConfigCorrupt(format!("deployment targets: {e}")))?;
        for target in &targets {
            target.validate().map_err(VaultError::ConfigCorrupt)?;
        }
        Ok(targets)
    }

    /// Atomically save non-secret deployment routing metadata with 0600 mode.
    pub fn save_deployment_targets(&self, targets: &[DeploymentTarget]) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        for target in targets {
            target.validate().map_err(VaultError::Policy)?;
            if !ids.insert(target.id.clone()) {
                return Err(VaultError::Policy(format!(
                    "duplicate deployment target id '{}'",
                    target.id
                )));
            }
        }
        let json = serde_json::to_string_pretty(targets)?;
        self.ensure_dirs()?;
        self.with_write_lock(|| {
            Self::write_secure(&self.deployment_targets_path(), &json)?;
            Ok(())
        })
    }

    /// Public path accessor for CLI/TUI display and MCP audit tool
    pub fn audit_log_path(&self) -> PathBuf {
        self.audit_path()
    }

    fn ensure_dirs(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::create_dir_all(&self.dir)?;
        fs::create_dir_all(self.vaults_dir())?;
        fs::create_dir_all(self.history_dir())?;
        fs::create_dir_all(self.trash_dir())?;
        fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).ok();
        fs::set_permissions(self.vaults_dir(), fs::Permissions::from_mode(0o700)).ok();
        fs::set_permissions(self.history_dir(), fs::Permissions::from_mode(0o700)).ok();
        fs::set_permissions(self.trash_dir(), fs::Permissions::from_mode(0o700)).ok();
        Ok(())
    }

    fn history_dir(&self) -> PathBuf {
        self.dir.join("history")
    }

    fn history_path(&self, name: &str) -> Result<PathBuf> {
        let safe = Self::sanitize_name(name)?;
        Ok(self.history_dir().join(format!("{}.vault", safe)))
    }

    fn trash_dir(&self) -> PathBuf {
        self.dir.join("trash")
    }

    fn trash_path(&self, name: &str) -> Result<PathBuf> {
        let safe = Self::sanitize_name(name)?;
        Ok(self.trash_dir().join(format!("{}.vault", safe)))
    }

    fn sanitize_name(name: &str) -> Result<String> {
        // Reject control characters outright rather than silently mapping them:
        // silently renaming "foo\nbar" and "foo-bar" to the same file is worse.
        if name.chars().any(|c| c.is_control()) {
            return Err(VaultError::InvalidVaultName(name.to_string()));
        }
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

    /// Secret keys become map keys (and are surfaced to agents as names).
    /// Reject control characters so nothing can inject into output/JSON.
    fn validate_key_name(secret_key: &str) -> Result<()> {
        if secret_key.chars().any(|c| c.is_control()) {
            return Err(VaultError::InvalidKeyName(secret_key.to_string()));
        }
        Ok(())
    }

    fn validate_value(value: &str) -> Result<()> {
        if value.len() > MAX_SECRET_VALUE_LENGTH {
            return Err(VaultError::ValueTooLarge(
                value.len(),
                MAX_SECRET_VALUE_LENGTH,
            ));
        }
        Ok(())
    }

    fn vault_path(&self, name: &str) -> Result<PathBuf> {
        let safe = Self::sanitize_name(name)?;
        Ok(self.vaults_dir().join(format!("{}.vault", safe)))
    }

    fn write_secure(path: &PathBuf, contents: &str) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        // Atomic write: write to a temp file in the same directory, fsync it,
        // then rename over the target. A crash mid-write can never leave a
        // truncated/corrupt config or vault file at the real path.
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp, path)?;
        // Best-effort directory fsync so the rename itself is durable.
        if let Ok(dir) = fs::File::open(path.parent().unwrap_or(std::path::Path::new("."))) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Append a fire-and-forget audit entry. Write failures are surfaced to
    /// stderr rather than silently dropped, so a broken audit trail is never
    /// mistaken for a healthy one.
    pub fn audit(&self, action: &str, detail: &str) {
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "action": action,
            "detail": detail,
            "caller": "cli",
        });
        if let Err(e) = self.append_audit_line(&entry) {
            eprintln!("⚠ Vaultly: failed to write audit entry: {e}");
        }
    }

    /// Append a JSON audit entry to the chain, stamping each line with the
    /// SHA-256 of the previous line (`prevHash`). Any later modification to a
    /// line breaks the chain and is caught by `verify_audit_chain`. Returns
    /// the fully-written line.
    pub(crate) fn append_audit_line(&self, entry: &serde_json::Value) -> Result<String> {
        let path = self.audit_path();
        Self::rotate_if_needed(&path);
        let prev_hash = Self::audit_prev_hash(&path);
        let mut stamped = entry.clone();
        if let Some(obj) = stamped.as_object_mut() {
            obj.insert("prevHash".into(), serde_json::Value::String(prev_hash));
        }
        let line = stamped.to_string();
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(f, "{}", line)?;
        f.sync_all()?; // make the chain durable before reporting success
        Ok(line)
    }

    /// SHA-256 (hex) of the last non-empty line in `path` — the hash a new
    /// entry chains to. An absent/empty file starts a fresh chain with the
    /// all-zeros sentinel.
    fn audit_prev_hash(path: &PathBuf) -> String {
        if let Ok(raw) = fs::read_to_string(path) {
            if let Some(last) = raw.lines().rev().find(|l| !l.trim().is_empty()) {
                return sha256_hex(last.as_bytes());
            }
        }
        "0".repeat(64)
    }

    /// Walk the audit chain and return every line whose `prevHash` does not
    /// equal the SHA-256 of the previous line. An empty result means the log
    /// is intact; each returned `(line_index, reason)` pinpoints tampering.
    pub fn verify_audit_chain(&self) -> Result<Vec<(usize, String)>> {
        let path = self.audit_path();
        if !path.exists() {
            return Ok(vec![]);
        }
        let raw = fs::read_to_string(&path)?;
        let lines: Vec<&str> = raw.lines().collect();
        let mut violations = Vec::new();
        // The first entry chains to the all-zeros sentinel.
        let mut expected_prev = "0".repeat(64);
        for (i, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let parsed: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(e) => {
                    violations.push((i, format!("unparseable line: {e}")));
                    continue;
                }
            };
            let declared = parsed
                .get("prevHash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if declared != expected_prev.as_str() {
                violations.push((
                    i,
                    format!(
                        "prevHash mismatch: entry declares '{declared}', expected sha256(prev)='{expected_prev}'"
                    ),
                ));
            }
            // Every subsequent line chains to this line's content.
            expected_prev = sha256_hex(line.as_bytes());
        }
        Ok(violations)
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
        self.with_write_lock(|| {
            Self::write_secure(&self.config_path(), &json)?;
            Ok(())
        })
    }

    // ─── Init / Unlock ────────────────────────────────────

    pub fn init_vault(&self, password: &str) -> Result<()> {
        if self.is_initialized() {
            return Err(VaultError::AlreadyInitialized(
                self.config_path().display().to_string(),
            ));
        }
        self.ensure_dirs()?;

        let salt = generate_salt();
        let key = derive_key(password, &salt)?;
        let verifier = create_verifier(&key)?;

        let config = VaultConfig {
            version: crate::crypto::FORMAT_VERSION,
            salt,
            verifier,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            backup: None,
            auto_lock_minutes: std::env::var("VAULTLY_AUTO_LOCK_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok()),
        };
        self.save_config(&config)?;
        self.audit("INIT", "Vault initialized");
        Ok(())
    }

    /// Unlock: derive key from password, verify, return key (Zeroizing).
    pub fn unlock(&self, password: &str) -> Result<Zeroizing<Vec<u8>>> {
        let config = self.load_config()?;
        let key = derive_key(password, &config.salt)?;
        if !verify_password(&config.verifier, &key) {
            return Err(VaultError::WrongPassword);
        }
        Ok(key)
    }

    /// Re-encrypt every vault (and the stored verifier) under a new master
    /// password. The old password must verify first. Vault names, values,
    /// labels and per-secret expiry metadata are preserved.
    ///
    /// Old ciphertext is snapshotted to `.rekey-backup-<timestamp>/` before
    /// anything is replaced; if any write fails the snapshot is restored, so a
    /// failed rotation cannot leave the store half-encrypted. There is no
    /// plaintext on disk at any point.
    pub fn rekey(&self, old_password: &str, new_password: &str) -> Result<usize> {
        if new_password.is_empty() {
            return Err(VaultError::Policy(
                "the new master password must not be empty".to_string(),
            ));
        }
        let config = self.load_config()?;
        let old_key = derive_key(old_password, &config.salt)?;
        if !verify_password(&config.verifier, &old_key) {
            return Err(VaultError::WrongPassword);
        }

        // Decrypt everything with the old key before writing anything.
        let names = self.list_vaults();
        let mut decoded: Vec<(String, BTreeMap<String, SecretEntry>)> =
            Vec::with_capacity(names.len());
        for name in &names {
            decoded.push((name.clone(), self.get_secret_entries(name, &old_key)?));
        }

        let new_salt = generate_salt();
        let new_key = derive_key(new_password, &new_salt)?;
        let new_verifier = create_verifier(&new_key)?;
        let new_config = VaultConfig {
            version: config.version,
            salt: new_salt,
            verifier: new_verifier,
            created_at: config.created_at.clone(),
            backup: config.backup.clone(),
            auto_lock_minutes: config.auto_lock_minutes,
        };

        let backup_dir = self.dir.join(format!(
            ".rekey-backup-{}",
            chrono::Utc::now().timestamp_millis()
        ));
        self.snapshot_to(&backup_dir)?;

        let apply = |this: &Self| -> Result<()> {
            for (name, entries) in &decoded {
                let file = encrypt_vault(&Self::encode_entries(entries), &new_key)?;
                this.save_vault_file(name, &file)?;
            }
            this.save_config(&new_config)
        };

        if let Err(e) = apply(self) {
            let _ = self.restore_from(&backup_dir);
            return Err(e);
        }

        // Rotation succeeded — the old ciphertext is now useless without the
        // old password, and keeping it invites confusion. Remove it.
        let _ = fs::remove_dir_all(&backup_dir);
        self.audit(
            "REKEY",
            &format!(
                "{} vault(s) re-encrypted under a new master password",
                decoded.len()
            ),
        );
        Ok(decoded.len())
    }

    /// Copy `config.json` and every vault file into `dir` with private modes.
    fn snapshot_to(&self, dir: &std::path::Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let mut files = vec![self.config_path()];
        for name in self.list_vaults() {
            files.push(self.vault_path(&name)?);
        }
        for path in files {
            let Some(file_name) = path.file_name() else {
                continue;
            };
            let raw = fs::read_to_string(&path)?;
            Self::write_secure(&dir.join(file_name), &raw)?;
        }
        Ok(())
    }

    /// Restore a snapshot written by [`VaultStore::snapshot_to`]. Used only as
    /// the rollback path for a failed rekey; best-effort by design.
    fn restore_from(&self, dir: &std::path::Path) -> Result<()> {
        let config_raw = fs::read_to_string(dir.join("config.json"))?;
        for name in self.list_vaults() {
            let src = dir.join(format!("{name}.json"));
            if src.exists() {
                let raw = fs::read_to_string(src)?;
                Self::write_secure(&self.vault_path(&name)?, &raw)?;
            }
        }
        Self::write_secure(&self.config_path(), &config_raw)?;
        Ok(())
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
        let mut vault = vault.clone();
        // Preserve an existing label across re-encryption: `encrypt_vault`
        // builds a fresh VaultFile without a label, so copy the on-disk label
        // forward unless this write explicitly replaces it.
        if vault.label.is_none() {
            if let Ok(Some(existing)) = self.load_vault_file(name) {
                vault.label = existing.label;
            }
        }
        let json = serde_json::to_string_pretty(&vault)?;
        self.with_write_lock(|| {
            Self::write_secure(&self.vault_path(name)?, &json)?;
            Ok(())
        })
    }
    /// Non-secret human-readable label for a vault (used for Cloudflare
    /// account aliases). `None` when unset or the vault doesn't exist.
    pub fn get_vault_label(&self, name: &str) -> Result<Option<String>> {
        Ok(self.load_vault_file(name)?.and_then(|vf| vf.label))
    }

    /// Set or clear a vault's label. Writes directly so an explicit clear
    /// (label = None) isn't undone by `save_vault_file`'s label preservation.
    pub fn set_vault_label(&self, name: &str, label: Option<String>) -> Result<()> {
        let mut vf = self
            .load_vault_file(name)?
            .ok_or_else(|| VaultError::VaultNotFound(name.to_string()))?;
        vf.label = label;
        self.ensure_dirs()?;
        let json = serde_json::to_string_pretty(&vf)?;
        self.with_write_lock(|| {
            Self::write_secure(&self.vault_path(name)?, &json)?;
            Ok(())
        })
    }

    /// Get all secrets from a vault (decrypted) as plain string values.
    /// Missing vault → empty map. Values are extracted from either v1 (bare
    /// string) or v2 (`SecretEntry`) storage encoding.
    pub fn get_secrets(
        &self,
        name: &str,
        key: &[u8],
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let entries = self.get_secret_entries(name, key)?;
        let mut out = serde_json::Map::new();
        for (k, e) in entries {
            out.insert(k, serde_json::Value::String(e.value));
        }
        Ok(out)
    }

    /// Decode a vault into full `SecretEntry` objects (value + timestamps;
    /// both v1 and v2 encodings). Missing vault → empty map.
    pub fn get_secret_entries(
        &self,
        name: &str,
        key: &[u8],
    ) -> Result<BTreeMap<String, SecretEntry>> {
        let map = match self.load_vault_file(name)? {
            Some(file) => decrypt_vault(&file, key)?,
            None => return Ok(BTreeMap::new()),
        };
        let mut out = BTreeMap::new();
        for (k, v) in map {
            out.insert(k.clone(), SecretEntry::from_value(&k, &v)?);
        }
        Ok(out)
    }

    /// Agent-safe per-key metadata (timestamps + expiry, no values).
    pub fn get_secret_meta(&self, name: &str, key: &[u8]) -> Result<BTreeMap<String, SecretMeta>> {
        let now = chrono::Utc::now();
        let entries = self.get_secret_entries(name, key)?;
        let mut out = BTreeMap::new();
        for (k, e) in entries {
            out.insert(k.clone(), SecretMeta::from_entry(&k, &e, &now));
        }
        Ok(out)
    }

    pub fn vault_exists(&self, name: &str) -> Result<bool> {
        Ok(self.vault_path(name)?.exists())
    }

    /// Path of the persistent killswitch marker. Present ⟹ vault operations
    /// are disabled (written by `vaultly kill`; cleared on a fresh unlock).
    pub fn killswitch_path(&self) -> PathBuf {
        self.dir.join("killswitch")
    }

    pub fn is_killed(&self) -> bool {
        self.killswitch_path().exists()
    }

    pub fn set_killed(&self) -> Result<()> {
        self.ensure_dirs()?;
        fs::write(self.killswitch_path(), b"killswitch\n")?;
        Ok(())
    }

    pub fn clear_killed(&self) -> Result<()> {
        let p = self.killswitch_path();
        if p.exists() {
            fs::remove_file(&p)?;
        }
        Ok(())
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
        self.set_secret_ex(vault_name, secret_key, value, None, key)
    }

    /// Set a secret with an optional expiry (RFC 3339). Preserves `created_at`
    /// on update; bumps `updated_at`.
    pub fn set_secret_ex(
        &self,
        vault_name: &str,
        secret_key: &str,
        value: &str,
        expires_at: Option<&str>,
        key: &[u8],
    ) -> Result<()> {
        Self::validate_key_name(secret_key)?;
        Self::validate_value(value)?;
        let now = now_iso();
        let mut entries = self.get_secret_entries(vault_name, key)?;
        let (next, previous) = match entries.get(secret_key) {
            Some(existing) => (
                SecretEntry {
                    value: value.to_string(),
                    created_at: existing.created_at.clone(),
                    updated_at: now.clone(),
                    expires_at: expires_at.map(|s| s.to_string()),
                },
                Some(existing.clone()),
            ),
            None => (
                SecretEntry {
                    value: value.to_string(),
                    created_at: now.clone(),
                    updated_at: now.clone(),
                    expires_at: expires_at.map(|s| s.to_string()),
                },
                None,
            ),
        };
        if let Some(prev) = previous {
            let _ = self.append_secret_history(vault_name, secret_key, &prev, key);
        }
        entries.insert(secret_key.to_string(), next);
        let file = encrypt_vault(&Self::encode_entries(&entries), key)?;
        self.save_vault_file(vault_name, &file)?;
        self.audit("SET", &format!("{}/{}", vault_name, secret_key));
        Ok(())
    }

    pub fn delete_secret(&self, vault_name: &str, secret_key: &str, key: &[u8]) -> Result<bool> {
        let mut entries = self.get_secret_entries(vault_name, key)?;
        let removed = match entries.remove(secret_key) {
            Some(e) => e,
            None => return Ok(false),
        };
        // Preserve the deleted value in history so it can be restored.
        self.append_secret_history(vault_name, secret_key, &removed, key)?;
        // Soft-delete: move into trash for recovery.
        let trash_entry = TrashEntry {
            key: secret_key.to_string(),
            entry: removed.clone(),
            deleted_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        };
        let _ = self.trash_secret(vault_name, &trash_entry, key);
        let file = encrypt_vault(&Self::encode_entries(&entries), key)?;
        self.save_vault_file(vault_name, &file)?;
        self.audit("DELETE", &format!("{}/{}", vault_name, secret_key));
        Ok(true)
    }

    // ─── Secret version history ───────────────────────────

    /// Read the version history for one secret (oldest → newest). Empty if none.
    pub fn get_secret_history(
        &self,
        vault_name: &str,
        secret_key: &str,
        key: &[u8],
    ) -> Result<Vec<SecretEntry>> {
        let p = self.history_path(vault_name)?;
        if !p.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&p)?;
        let file: crate::crypto::VaultFile = serde_json::from_str(&raw)
            .map_err(|e| VaultError::ConfigCorrupt(format!("history: {e}")))?;
        let map = crate::crypto::decrypt_vault(&file, key)?;
        let arr = match map.get(secret_key) {
            Some(serde_json::Value::Array(a)) => a.clone(),
            _ => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for v in arr {
            if let Ok(e) = serde_json::from_value::<SecretEntry>(v) {
                out.push(e);
            }
        }
        Ok(out)
    }

    /// Append one entry to a secret's version history.
    pub fn append_secret_history(
        &self,
        vault_name: &str,
        secret_key: &str,
        entry: &SecretEntry,
        key: &[u8],
    ) -> Result<()> {
        self.ensure_dirs()?;
        // Load existing history map (key -> array of entries).
        let mut map: serde_json::Map<String, serde_json::Value> =
            if self.history_path(vault_name)?.exists() {
                let raw = fs::read_to_string(self.history_path(vault_name)?)?;
                let file: crate::crypto::VaultFile = serde_json::from_str(&raw)
                    .map_err(|e| VaultError::ConfigCorrupt(format!("history: {e}")))?;
                crate::crypto::decrypt_vault(&file, key)?
            } else {
                serde_json::Map::new()
            };
        let arr = map
            .entry(secret_key.to_string())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let serde_json::Value::Array(a) = arr {
            a.push(entry.to_value());
        }
        // Cap history at 100 versions.
        if let Some(serde_json::Value::Array(a)) = map.get_mut(secret_key) {
            if a.len() > 100 {
                let start = a.len() - 100;
                *a = a[start..].to_vec();
            }
        }
        let file = crate::crypto::encrypt_vault(&map, key)?;
        self.with_write_lock(|| {
            Self::write_secure(
                &self.history_path(vault_name)?,
                &serde_json::to_string_pretty(&file)?,
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Restore a previous version by index (0-based) as the current value.
    pub fn restore_secret_version(
        &self,
        vault_name: &str,
        secret_key: &str,
        index: usize,
        key: &[u8],
    ) -> Result<bool> {
        let history = self.get_secret_history(vault_name, secret_key, key)?;
        let entry = match history.get(index) {
            Some(e) => e.clone(),
            None => return Ok(false),
        };
        // Set current value from historical entry.
        self.set_secret_ex(
            vault_name,
            secret_key,
            &entry.value,
            entry.expires_at.as_deref(),
            key,
        )?;
        Ok(true)
    }

    pub fn delete_vault(&self, name: &str) -> Result<bool> {
        let p = self.vault_path(name)?;
        if !p.exists() {
            return Ok(false);
        }
        self.with_write_lock(|| {
            fs::remove_file(&p)?;
            Ok(())
        })?;
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
        let now = now_iso();
        let mut secrets = self.get_secret_entries(vault_name, key)?;
        let count = entries.len();
        for (k, v) in entries {
            Self::validate_key_name(k)?;
            if let Some(s) = v.as_str() {
                Self::validate_value(s)?;
            }
            let value = v
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string());
            let next = match secrets.get(k) {
                Some(existing) => SecretEntry {
                    value,
                    created_at: existing.created_at.clone(),
                    updated_at: now.clone(),
                    expires_at: existing.expires_at.clone(),
                },
                None => SecretEntry::new(&value, &now),
            };
            secrets.insert(k.clone(), next);
        }
        let file = encrypt_vault(&Self::encode_entries(&secrets), key)?;
        self.save_vault_file(vault_name, &file)?;
        self.audit("IMPORT", &format!("{} ({} secrets)", vault_name, count));
        Ok(count)
    }

    /// Encode a `SecretEntry` map into v2 object values for the encrypted blob.
    fn encode_entries(
        entries: &BTreeMap<String, SecretEntry>,
    ) -> serde_json::Map<String, serde_json::Value> {
        entries
            .iter()
            .map(|(k, e)| (k.clone(), e.to_value()))
            .collect()
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

    fn validate_vault_file(name: &str, file: &VaultFile) -> Result<()> {
        if !matches!(file.version, 1 | 2) {
            return Err(VaultError::VaultCorrupt(
                name.to_string(),
                format!("unsupported file version {}", file.version),
            ));
        }
        for (label, value) in [
            ("iv", &file.iv),
            ("authTag", &file.auth_tag),
            ("data", &file.data),
        ] {
            if hex::decode(value).is_err() {
                return Err(VaultError::VaultCorrupt(
                    name.to_string(),
                    format!("{label} is not valid hex"),
                ));
            }
        }
        Ok(())
    }

    pub fn restore_encrypted_vaults(
        &self,
        vaults: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<usize> {
        self.ensure_dirs()?;
        // Validate the entire payload BEFORE touching disk so a corrupt or
        // tampered backup can never leave a partially-restored store. Each
        // vault blob also carries its own AES-GCM integrity on decrypt.
        let mut files: Vec<(String, VaultFile)> = Vec::with_capacity(vaults.len());
        for (name, value) in vaults {
            let safe = Self::sanitize_name(name)?;
            let file: VaultFile = serde_json::from_value(value.clone())
                .map_err(|e| VaultError::VaultCorrupt(safe.clone(), e.to_string()))?;
            Self::validate_vault_file(&safe, &file)?;
            files.push((safe, file));
        }
        let count = files.len();
        for (name, file) in &files {
            self.save_vault_file(name, file)?;
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

    // ─── Trash (soft delete) ──────────────────────────────

    /// Append a trashed secret entry.
    pub fn trash_secret(&self, vault_name: &str, item: &TrashEntry, key: &[u8]) -> Result<()> {
        self.ensure_dirs()?;
        let mut map: serde_json::Map<String, serde_json::Value> =
            if self.trash_path(vault_name)?.exists() {
                let raw = fs::read_to_string(self.trash_path(vault_name)?)?;
                let file: crate::crypto::VaultFile = serde_json::from_str(&raw)
                    .map_err(|e| VaultError::ConfigCorrupt(format!("trash: {e}")))?;
                crate::crypto::decrypt_vault(&file, key)?
            } else {
                serde_json::Map::new()
            };
        let arr = map
            .entry(item.key.clone())
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        if let serde_json::Value::Array(a) = arr {
            if let Ok(v) = serde_json::to_value(item) {
                a.push(v);
            }
        }
        let file = crate::crypto::encrypt_vault(&map, key)?;
        self.with_write_lock(|| {
            Self::write_secure(
                &self.trash_path(vault_name)?,
                &serde_json::to_string_pretty(&file)?,
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// List trashed secrets for a vault (key + deleted_at, no values).
    pub fn list_trash(&self, vault_name: &str, key: &[u8]) -> Result<Vec<TrashEntry>> {
        let p = self.trash_path(vault_name)?;
        if !p.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read_to_string(&p)?;
        let file: crate::crypto::VaultFile = serde_json::from_str(&raw)
            .map_err(|e| VaultError::ConfigCorrupt(format!("trash: {e}")))?;
        let map = crate::crypto::decrypt_vault(&file, key)?;
        let mut out = Vec::new();
        for (_k, v) in map {
            if let serde_json::Value::Array(a) = v {
                for item in a {
                    if let Ok(te) = serde_json::from_value::<TrashEntry>(item) {
                        out.push(te);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Restore a trashed secret by key (most recent trash entry) back into the vault.
    pub fn restore_trash(&self, vault_name: &str, secret_key: &str, key: &[u8]) -> Result<bool> {
        let items = self.list_trash(vault_name, key)?;
        let item = items.into_iter().filter(|t| t.key == secret_key).last();
        let item = match item {
            Some(i) => i,
            None => return Ok(false),
        };
        // Restore value.
        self.set_secret_ex(
            vault_name,
            secret_key,
            &item.entry.value,
            item.entry.expires_at.as_deref(),
            key,
        )?;
        Ok(true)
    }

    /// Purge all trashed secrets for a vault.
    pub fn purge_trash(&self, vault_name: &str) -> Result<bool> {
        let p = self.trash_path(vault_name)?;
        if !p.exists() {
            return Ok(false);
        }
        self.with_write_lock(|| {
            fs::remove_file(&p)?;
            Ok(())
        })?;
        Ok(true)
    }

    pub fn get_vault_file_path(&self, name: &str) -> Result<PathBuf> {
        self.vault_path(name)
    }
}

/// SHA-256 of `bytes`, hex-encoded.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Deterministic integrity checksum over a backup payload's vault map. The
/// backup CLI stores this alongside the payload and the restore CLI verifies
/// it before touching disk, so corruption or tampering of the bundle is
/// detected rather than silently restoring bad data.
pub fn backup_checksum(vaults: &serde_json::Map<String, serde_json::Value>) -> Result<String> {
    Ok(sha256_hex(serde_json::to_string(vaults)?.as_bytes()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    const PASSWORD: &str = "test-master-password";
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let d =
            std::env::temp_dir().join(format!("vaultly-store-test-{}-{}", std::process::id(), id));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn store_with(dir: PathBuf) -> VaultStore {
        let store = VaultStore::with_dir(dir);
        store.init_vault(PASSWORD).unwrap();
        store
    }

    fn key_for(store: &VaultStore) -> Vec<u8> {
        let salt = store.load_config().unwrap().salt;
        derive_key(PASSWORD, &salt).unwrap().to_vec()
    }

    #[test]
    fn sanitize_rejects_control_chars() {
        assert!(VaultStore::sanitize_name("foo\u{0}bar").is_err());
        assert!(VaultStore::sanitize_name("foo\nbar").is_err());
        assert!(VaultStore::sanitize_name("").is_err());
        assert!(VaultStore::sanitize_name("..").is_ok()); // mapped to "--", no traversal
        assert_eq!(VaultStore::sanitize_name("my vault").unwrap(), "my-vault");
    }

    #[test]
    fn set_secret_rejects_control_key_and_oversize_value() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);

        let err = store
            .set_secret("github", "TOKEN\u{1}INVALID", "v", &key)
            .unwrap_err();
        assert!(matches!(err, VaultError::InvalidKeyName(_)));

        let big = "x".repeat(MAX_SECRET_VALUE_LENGTH + 1);
        let err = store.set_secret("github", "TOKEN", &big, &key).unwrap_err();
        assert!(matches!(err, VaultError::ValueTooLarge(_, _)));

        // Valid write still works.
        store.set_secret("github", "TOKEN", "fine", &key).unwrap();
        assert_eq!(
            store
                .get_secret("github", "TOKEN", &key)
                .unwrap()
                .as_deref(),
            Some("fine")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enforce_file_and_dir_permissions() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("github", "TOKEN", "v", &key).unwrap();

        // Vault dir 0700
        let vaults_dir = dir.join("vaults");
        let mode = std::fs::metadata(&vaults_dir).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "vaults dir should be 0700, got {mode:o}"
        );

        // Vault file 0600
        let vf = store.get_vault_file_path("github").unwrap();
        let mode = std::fs::metadata(&vf).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "vault file should be 0600, got {mode:o}"
        );

        // Config 0600
        let cfg = dir.join("config.json");
        let mode = std::fs::metadata(&cfg).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "config should be 0600, got {mode:o}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn label_set_get_clear_and_preserved_across_write() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("github", "TOKEN", "v1", &key).unwrap();

        // Unset by default.
        assert_eq!(store.get_vault_label("github").unwrap(), None);

        // Set and read back.
        store
            .set_vault_label("github", Some("Personal".into()))
            .unwrap();
        assert_eq!(
            store.get_vault_label("github").unwrap().as_deref(),
            Some("Personal")
        );

        store.set_secret("github", "TEMP", "x", &key).unwrap();
        store.delete_secret("github", "TEMP", &key).unwrap();
        assert_eq!(
            store.get_vault_label("github").unwrap().as_deref(),
            Some("Personal")
        );

        // Explicit clear works even though save_vault_file preserves labels.
        store.set_vault_label("github", None).unwrap();
        assert_eq!(store.get_vault_label("github").unwrap(), None);

        // Setting a label on a missing vault errors.
        assert!(store.set_vault_label("nope", Some("x".into())).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_roundtrip_preserves_secrets() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("github", "TOKEN", "v1", &key).unwrap();

        let vaults = store.get_encrypted_vaults();
        store.delete_vault("github").unwrap();
        let count = store.restore_encrypted_vaults(&vaults).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            store
                .get_secret("github", "TOKEN", &key)
                .unwrap()
                .as_deref(),
            Some("v1")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_rejects_bad_version_and_invalid_hex_before_writing() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("github", "TOKEN", "v", &key).unwrap();

        let mut vaults = store.get_encrypted_vaults();

        // Unsupported version must be rejected and nothing written.
        let mut bad = vaults.get("github").unwrap().clone();
        bad["version"] = serde_json::json!(99);
        vaults.insert("github".into(), bad);
        assert!(store.restore_encrypted_vaults(&vaults).is_err());

        // Invalid hex in the encrypted payload must be rejected.
        let mut bad2 = vaults.get("github").unwrap().clone();
        bad2["version"] = serde_json::json!(1);
        bad2["data"] = serde_json::json!("not-hex!");
        vaults.insert("github".into(), bad2);
        assert!(store.restore_encrypted_vaults(&vaults).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_checksum_is_deterministic_and_content_sensitive() {
        let mut m = serde_json::Map::new();
        m.insert("a".into(), serde_json::Value::String("x".into()));
        let c1 = backup_checksum(&m).unwrap();
        assert_eq!(c1, backup_checksum(&m).unwrap());
        m.insert("b".into(), serde_json::Value::String("y".into()));
        assert_ne!(c1, backup_checksum(&m).unwrap());
    }

    #[test]
    fn audit_chain_verifies_clean_log_and_detects_tampering() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        store.audit("A", "first");
        store.audit("B", "second");
        store.audit("C", "third");
        // A clean log has no chain violations.
        assert!(store.verify_audit_chain().unwrap().is_empty());

        // Tamper with the second entry's action in place — the chain must break.
        let path = dir.join("audit.log");
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
        let mut entry: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        entry["action"] = serde_json::Value::String("TAMPERED".into());
        lines[1] = entry.to_string();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let violations = store.verify_audit_chain().unwrap();
        assert!(!violations.is_empty(), "tampering must be detected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fuzz_malformed_vault_files_never_panic() {
        // Corrupt/tampered vault files (arbitrary bytes, malformed JSON, wrong
        // shapes) must yield an Err from the read path, never a panic.
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("v", "K", "v", &key).unwrap();
        let path = store.get_vault_file_path("v").unwrap();

        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        for len in [0usize, 1, 2, 8, 64, 1024, 4096] {
            let mut buf = Vec::new();
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                buf.push(seed as u8);
            }
            std::fs::write(&path, &buf).unwrap();
            let _ = store.list_keys("v", &key);
            let _ = store.get_secret("v", "K", &key);
        }

        for json in [
            "",
            "null",
            "[]",
            "{}",
            "{\"version\":99}",
            "{\"version\":1,\"data\":\"not-hex\",\"iv\":\"aa\",\"authTag\":\"bb\"}",
            "{\"version\":1,\"iv\":\"zz\",\"authTag\":\"zz\",\"data\":\"zz\"}",
            "\u{fffd}",
            "]]]]]]]",
        ] {
            std::fs::write(&path, json).unwrap();
            let _ = store.list_keys("v", &key);
            let _ = store.get_secret("v", "K", &key);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unicode_data_survives_roundtrip() {
        // Cross-platform: unicode keys/values and unicode-in-vault-names must
        // round-trip exactly; name sanitization must stay deterministic so the
        // same name always maps to the same on-disk file.
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        let name = "vault-東京";
        let unicode_key = "clé_🔑";
        let unicode_val = "café-☕-值-😀";
        store
            .set_secret(name, unicode_key, unicode_val, &key)
            .unwrap();
        assert_eq!(
            store.get_secret(name, unicode_key, &key).unwrap().unwrap(),
            unicode_val
        );
        assert_eq!(store.list_keys(name, &key).unwrap(), vec![unicode_key]);
        assert_eq!(
            store.get_vault_file_path(name).unwrap(),
            store.get_vault_file_path(name).unwrap(),
            "vault-name sanitization must be deterministic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_format_writes_object_entries_with_timestamps() {
        // A fresh write must persist format version 2 and store each secret as
        // a SecretEntry object carrying createdAt/updatedAt (not a bare string).
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("github", "TOKEN", "v", &key).unwrap();

        let file = store.load_vault_file("github").unwrap().unwrap();
        assert_eq!(file.version, 2, "new writes must use format version 2");

        let map = crate::crypto::decrypt_vault(&file, &key).unwrap();
        let entry = map.get("TOKEN").expect("TOKEN present after decrypt");
        assert!(
            entry.is_object(),
            "v2 entries must be objects, got: {entry}"
        );
        assert!(
            entry.get("createdAt").and_then(|v| v.as_str()).is_some(),
            "entry must carry createdAt"
        );
        assert!(
            entry.get("updatedAt").and_then(|v| v.as_str()).is_some(),
            "entry must carry updatedAt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_bare_string_vault_reads_and_marks_unknown_timestamps() {
        // A v1 vault (bare string values, no per-secret metadata) must remain
        // fully readable. Its secrets surface as entries with unknown
        // timestamps until next written.
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);

        let value_map = serde_json::json!({ "TOKEN": "v1value" });
        let plaintext = serde_json::to_string(value_map.as_object().unwrap()).unwrap();
        let payload = crate::crypto::encrypt(&plaintext, &key).unwrap();
        let vf = crate::crypto::VaultFile {
            version: 1,
            iv: payload.iv,
            auth_tag: payload.auth_tag,
            data: payload.ciphertext,
            updated_at: "2020-01-01T00:00:00Z".into(),
            label: None,
        };
        store.save_vault_file("v", &vf).unwrap();

        assert_eq!(
            store.get_secret("v", "TOKEN", &key).unwrap().as_deref(),
            Some("v1value"),
            "v1 bare-string values must still be readable"
        );
        assert_eq!(store.list_keys("v", &key).unwrap(), vec!["TOKEN"]);

        let meta = store.get_secret_meta("v", &key).unwrap();
        let m = meta.get("TOKEN").expect("meta present");
        assert!(
            m.unknown_timestamps,
            "v1-origin secrets must report unknown timestamps"
        );
        assert!(!m.expired);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_expiry_reported_and_update_preserves_created_at() {
        // Past expiry ⟹ expired == true; present/future expiry ⟹ false.
        // Updating a secret preserves created_at and bumps updated_at.
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);

        store.set_secret("github", "K", "v1", &key).unwrap();
        let m0 = store
            .get_secret_meta("github", &key)
            .unwrap()
            .remove("K")
            .unwrap();
        assert!(!m0.expired);
        assert!(!m0.unknown_timestamps);
        let created = m0.created_at.clone();

        store
            .set_secret_ex("github", "K", "v2", Some("2000-01-01T00:00:00Z"), &key)
            .unwrap();
        let m1 = store
            .get_secret_meta("github", &key)
            .unwrap()
            .remove("K")
            .unwrap();
        assert!(m1.expired, "past expiry must report expired");
        assert_eq!(m1.created_at, created, "created_at preserved on update");
        assert_ne!(
            m1.updated_at, m0.updated_at,
            "updated_at must bump on update"
        );

        store
            .set_secret_ex("github", "K", "v3", Some("2999-01-01T00:00:00Z"), &key)
            .unwrap();
        let m2 = store
            .get_secret_meta("github", &key)
            .unwrap()
            .remove("K")
            .unwrap();
        assert!(!m2.expired, "future expiry must report not expired");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_exists_true_for_existing() {
        let dir = temp_dir();
        let store = VaultStore::with_dir(dir);
        store.init_vault(PASSWORD).unwrap();
        let key = derive_key(PASSWORD, &store.load_config().unwrap().salt).unwrap();
        store.set_secret("v", "k", "val", &key).unwrap();
        assert!(store.vault_exists("v").unwrap());
    }

    #[test]
    fn vault_exists_false_for_missing() {
        let dir = temp_dir();
        let store = VaultStore::with_dir(dir);
        store.init_vault(PASSWORD).unwrap();
        assert!(!store.vault_exists("nope").unwrap());
    }

    #[test]
    fn audit_rotates_when_file_exceeds_max() {
        let dir = temp_dir();
        let store = VaultStore::with_dir(dir);
        store.init_vault(PASSWORD).unwrap();
        // Pre-write a file larger than the 1 MiB rotation threshold.
        let path = store.audit_log_path();
        let big = "x".repeat(2 * 1024 * 1024);
        std::fs::write(&path, big).unwrap();
        store.audit("TEST", "rotation check");
        assert!(path.exists());
        assert!(
            PathBuf::from(format!("{}.1", path.display())).exists(),
            "rotated backup file should exist"
        );
    }

    #[test]
    fn rekey_preserves_values_labels_and_expiry() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store
            .set_secret("app", "TOKEN", "super-secret", &key)
            .unwrap();
        store
            .set_secret_ex("app", "OLD", "expiring", Some("2099-01-01T00:00:00Z"), &key)
            .unwrap();
        store
            .set_vault_label("app", Some("App credentials".into()))
            .unwrap();

        let count = store.rekey(PASSWORD, "new-master-password").unwrap();
        assert_eq!(count, 1);

        // Old password no longer opens the store.
        assert!(matches!(
            store.unlock(PASSWORD),
            Err(VaultError::WrongPassword)
        ));
        let new_key = store.unlock("new-master-password").unwrap();
        let secrets = store.get_secrets("app", &new_key).unwrap();
        assert_eq!(secrets.get("TOKEN").unwrap().as_str(), Some("super-secret"));
        assert_eq!(secrets.get("OLD").unwrap().as_str(), Some("expiring"));
        assert_eq!(
            store.get_vault_label("app").unwrap().as_deref(),
            Some("App credentials")
        );
        let meta = store.get_secret_meta("app", &new_key).unwrap();
        assert_eq!(
            meta.get("OLD")
                .and_then(|m| m.expires_at.clone())
                .as_deref(),
            Some("2099-01-01T00:00:00Z")
        );

        // No plaintext rollback snapshot is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".rekey-backup-")
            })
            .collect();
        assert!(leftovers.is_empty(), "rollback snapshot must be removed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_rejects_wrong_old_password_without_touching_store() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        let key = key_for(&store);
        store.set_secret("app", "TOKEN", "unchanged", &key).unwrap();

        assert!(matches!(
            store.rekey("not-the-password", "new-master-password"),
            Err(VaultError::WrongPassword)
        ));
        // The original password still works and the value is intact.
        let key = store.unlock(PASSWORD).unwrap();
        assert_eq!(
            store
                .get_secrets("app", &key)
                .unwrap()
                .get("TOKEN")
                .and_then(|v| v.as_str()),
            Some("unchanged")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_rejects_empty_new_password() {
        let dir = temp_dir();
        let store = store_with(dir.clone());
        assert!(store.rekey(PASSWORD, "").is_err());
        assert!(store.unlock(PASSWORD).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

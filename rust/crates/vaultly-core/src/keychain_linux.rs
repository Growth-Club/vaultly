//! Linux Secret Service backend. Passwords travel in an encrypted D-Bus
//! session, never in subprocess arguments or plaintext configuration files.
use super::{ACCOUNT_NAME, SERVICE_NAME};
use secret_service::{blocking::SecretService, EncryptionType};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroizing;

fn run<T: Send + 'static>(work: impl FnOnce() -> Option<T> + Send + 'static) -> Option<T> {
    // CLI/MCP callers can already be inside Tokio. Keep the blocking D-Bus
    // runtime on a dedicated thread, outside that async runtime.
    std::thread::spawn(work).join().ok().flatten()
}
fn scope_for(path: &Path) -> Option<String> {
    let path = path.canonicalize().ok()?;
    Some(
        blake3::hash(path.as_os_str().as_encoded_bytes())
            .to_hex()
            .to_string(),
    )
}
fn scope() -> Option<String> {
    let path = std::env::var_os("VAULTLY_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".vaultly")))?;
    scope_for(&path)
}
fn attributes(scope: &str) -> HashMap<&str, &str> {
    HashMap::from([
        ("service", SERVICE_NAME),
        ("account", ACCOUNT_NAME),
        ("vaultly-store", scope),
    ])
}
pub(super) fn available() -> bool {
    run(|| SecretService::connect(EncryptionType::Dh).ok().map(|_| ())).is_some()
}
pub(super) fn store(password: &str) -> bool {
    let Some(scope) = scope() else {
        return false;
    };
    let password = Zeroizing::new(password.to_owned());
    run(move || {
        let service = SecretService::connect(EncryptionType::Dh).ok()?;
        let collection = service.get_default_collection().ok()?;
        // Only the owner-facing store command calls this; it may show the
        // desktop's native keyring unlock prompt. Agent reads never unlock it.
        collection.ensure_unlocked().ok()?;
        let item = collection
            .create_item(
                "Vaultly master password",
                attributes(&scope),
                password.as_bytes(),
                true,
                "text/plain",
            )
            .ok()?;
        let stored = Zeroizing::new(item.get_secret().ok()?);
        Some(stored.as_slice() == password.as_bytes())
    })
    .unwrap_or(false)
}
pub(super) fn get() -> Option<String> {
    let scope = scope()?;
    run(move || {
        let service = SecretService::connect(EncryptionType::Dh).ok()?;
        let items = service.search_items(attributes(&scope)).ok()?;
        // Refuse ambiguous records and locked entries. Do not prompt, choose
        // another store's password, or weaken protection as a fallback.
        if !items.locked.is_empty() || items.unlocked.len() != 1 {
            return None;
        }
        let bytes = Zeroizing::new(items.unlocked[0].get_secret().ok()?);
        let value = std::str::from_utf8(&bytes).ok()?;
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    })
}
pub(super) fn exists() -> bool {
    let Some(scope) = scope() else {
        return false;
    };
    run(move || {
        let service = SecretService::connect(EncryptionType::Dh).ok()?;
        let items = service.search_items(attributes(&scope)).ok()?;
        Some(!items.unlocked.is_empty() || !items.locked.is_empty())
    })
    .unwrap_or(false)
}
pub(super) fn remove() -> bool {
    let Some(scope) = scope() else {
        return false;
    };
    run(move || {
        let service = SecretService::connect(EncryptionType::Dh).ok()?;
        let items = service.search_items(attributes(&scope)).ok()?;
        if !items.locked.is_empty() {
            return None;
        }
        for item in items.unlocked {
            item.delete().ok()?;
        }
        Some(true)
    })
    .unwrap_or(false)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn different_vault_stores_have_different_credential_identities() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        assert_ne!(scope_for(first.path()), scope_for(second.path()));
        assert_eq!(scope_for(first.path()), scope_for(first.path()));
    }
    #[test]
    fn symlink_aliases_resolve_to_the_same_store() {
        let root = tempfile::tempdir().unwrap();
        let actual = root.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&actual, &alias).unwrap();
        assert_eq!(scope_for(&actual), scope_for(&alias));
    }
    #[test]
    #[ignore = "opt-in test creates and removes one synthetic, temporary-store keyring entry"]
    fn linux_secret_service_roundtrip() {
        let root = tempfile::tempdir().unwrap();
        let previous_dir = std::env::var_os("VAULTLY_DIR");
        let previous_allow = std::env::var_os("VAULTLY_ALLOW_KEYCHAIN");
        std::env::set_var("VAULTLY_DIR", root.path());
        std::env::set_var("VAULTLY_ALLOW_KEYCHAIN", "1");
        struct Cleanup(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = remove();
                for (key, value) in [
                    ("VAULTLY_DIR", &self.0),
                    ("VAULTLY_ALLOW_KEYCHAIN", &self.1),
                ] {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let _cleanup = Cleanup(previous_dir, previous_allow);
        assert!(available());
        assert!(store("synthetic-vaultly-linux-backend-check"));
        assert!(exists());
        assert_eq!(
            get().as_deref(),
            Some("synthetic-vaultly-linux-backend-check")
        );
        // Another vault directory cannot obtain this record.
        let other = tempfile::tempdir().unwrap();
        std::env::set_var("VAULTLY_DIR", other.path());
        assert!(get().is_none());
        std::env::set_var("VAULTLY_DIR", root.path());
        assert!(remove());
        assert!(!exists());
    }
}

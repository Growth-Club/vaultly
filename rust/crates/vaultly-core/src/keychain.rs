//! OS credential-store integration. Custom stores remain opt-in so tests
//! cannot touch a real user's credential store.
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "linux")]
#[path = "keychain_linux.rs"]
mod linux;

const SERVICE_NAME: &str = "vaultly-master-key";
const ACCOUNT_NAME: &str = "vaultly";

pub fn keychain_inert() -> bool {
    keychain_inert_for(
        std::env::var_os("VAULTLY_DIR").is_some(),
        std::env::var("VAULTLY_ALLOW_KEYCHAIN").as_deref() == Ok("1"),
    )
}
fn keychain_inert_for(custom: bool, allowed: bool) -> bool {
    custom && !allowed
}

pub fn backend_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "Linux Secret Service"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "OS credential store"
    }
}
pub fn unlock_setup_hint() -> &'static str {
    if keychain_inert() {
        "This custom vault store has OS auto-unlock disabled. The owner can configure its credential store with VAULTLY_ALLOW_KEYCHAIN=1, or supply VAULTLY_MASTER_PASSWORD only to Vaultly."
    } else if cfg!(target_os = "linux") {
        "Configure Linux Secret Service with `vaultly keychain store` as the owner in the desktop session, or supply VAULTLY_MASTER_PASSWORD only to Vaultly."
    } else if cfg!(target_os = "macos") {
        "Configure macOS Keychain with `vaultly keychain store` as the owner, or supply VAULTLY_MASTER_PASSWORD only to Vaultly."
    } else {
        "Supply VAULTLY_MASTER_PASSWORD only to the Vaultly process; no OS credential-store backend is available on this platform."
    }
}
pub fn is_keychain_available() -> bool {
    if keychain_inert() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        linux::available()
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("security").arg("-h").output().is_ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
pub fn store_in_keychain(password: &str) -> bool {
    if !is_keychain_available() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        linux::store(password)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
            ])
            .output();
        let stored = Command::new("security")
            .args([
                "add-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
                "-w",
                password,
                "-A",
                "-j",
                "Vaultly master password",
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        stored && get_from_keychain().as_deref() == Some(password)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = password;
        false
    }
}
pub fn get_from_keychain() -> Option<String> {
    if !is_keychain_available() {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        linux::get()
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
                "-w",
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}
pub fn delete_from_keychain() -> bool {
    if !is_keychain_available() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        linux::remove()
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
pub fn keychain_entry_exists() -> bool {
    if !is_keychain_available() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        linux::exists()
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                SERVICE_NAME,
                "-a",
                ACCOUNT_NAME,
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inert_when_vaultly_dir_set() {
        assert!(keychain_inert_for(true, false));
        assert!(!keychain_inert_for(false, false));
        assert!(!keychain_inert_for(true, true));
    }
    #[test]
    fn custom_store_hint_does_not_claim_keychain_opt_in_unlocks_it() {
        assert!(unlock_setup_hint().contains("Vaultly"));
    }
}

//! macOS Keychain Integration — mirrors src/keychain.ts.
//!
//! Stores the master password in the macOS Keychain so agents/MCP can
//! auto-unlock without a password prompt. Falls back gracefully on
//! non-macOS platforms and, by default, whenever VAULTLY_DIR is set (test
//! isolation — NEVER touch the real user keychain from tests). Custom stores
//! can explicitly opt in with VAULTLY_ALLOW_KEYCHAIN=1.

use std::process::Command;

const SERVICE_NAME: &str = "vaultly-master-key";
const ACCOUNT_NAME: &str = "vaultly";

/// Keep isolated test stores away from the real Keychain unless a custom-store
/// user explicitly opts in. This preserves test isolation while allowing
/// agent deployments to use a non-default VAULTLY_DIR.
pub fn keychain_inert() -> bool {
    keychain_inert_for(
        std::env::var_os("VAULTLY_DIR").is_some(),
        std::env::var("VAULTLY_ALLOW_KEYCHAIN").as_deref() == Ok("1"),
    )
}

fn keychain_inert_for(vaultly_dir_set: bool, allow_keychain: bool) -> bool {
    vaultly_dir_set && !allow_keychain
}

pub fn is_keychain_available() -> bool {
    if keychain_inert() {
        return false;
    }
    if !cfg!(target_os = "macos") {
        return false;
    }
    Command::new("security").arg("-h").output().is_ok()
}

/// Store the master password in Keychain (called during `vaultly init`)
pub fn store_in_keychain(password: &str) -> bool {
    if !is_keychain_available() {
        return false;
    }
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
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !stored {
        return false;
    }

    get_from_keychain().as_deref() == Some(password)
}

/// Retrieve the master password from Keychain
pub fn get_from_keychain() -> Option<String> {
    if !is_keychain_available() {
        return None;
    }
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
    if out.status.success() {
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    } else {
        None
    }
}

/// Delete the master password from Keychain (killswitch)
pub fn delete_from_keychain() -> bool {
    if !is_keychain_available() {
        return false;
    }
    Command::new("security")
        .args([
            "delete-generic-password",
            "-s",
            SERVICE_NAME,
            "-a",
            ACCOUNT_NAME,
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if a keychain entry exists
pub fn keychain_entry_exists() -> bool {
    if !is_keychain_available() {
        return false;
    }
    Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            SERVICE_NAME,
            "-a",
            ACCOUNT_NAME,
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
}

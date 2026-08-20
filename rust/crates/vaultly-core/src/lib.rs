//! Vaultly — agent-first encrypted credential manager.
//! Rust port of the TypeScript implementation (file-format compatible).

pub mod crypto;
pub mod engine;
pub mod keychain;
pub mod policy;
pub mod scrubber;
pub mod vault;

pub use engine::{ApiResult, RunResult, VaultEngine};
pub use policy::CallerContext;
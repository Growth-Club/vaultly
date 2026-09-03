//! Vaultly — agent-first encrypted credential manager.
//! Rust port of the TypeScript implementation (file-format compatible).

pub mod crypto;
pub mod engine;
pub mod error;
pub mod generate;
pub mod keychain;
pub mod policy;
pub mod scrubber;
pub mod templates;
pub mod vault;

pub use engine::{urlencode, ApiResult, RunOptions, RunResult, VaultEngine};
pub use error::VaultError;
pub use policy::{AgentPolicy, AllowedOperations, AllowedVaults, Caller, CallerContext, Operation};

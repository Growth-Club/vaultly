//! Policy Engine — controls what each caller (agent or human) can do.
//! Mirrors the TypeScript policy.ts.

use crate::error::{VaultError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerContext {
    pub caller: Caller,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Caller {
    Human,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    List,
    ReadKeys,
    #[serde(rename = "read_value")]
    ReadValue, // blocked for agents by default
    Write,
    Delete,
    DeleteVault,
    Run,
    CfApi,
    Admin,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::List => "list",
            Operation::ReadKeys => "read_keys",
            Operation::ReadValue => "read_value",
            Operation::Write => "write",
            Operation::Delete => "delete",
            Operation::DeleteVault => "delete_vault",
            Operation::Run => "run",
            Operation::CfApi => "cf_api",
            Operation::Admin => "admin",
        }
    }
}

const DEFAULT_AGENT_OPS: &[Operation] = &[
    Operation::List,
    Operation::ReadKeys,
    Operation::Write,
    Operation::Delete,
    Operation::Run,
    Operation::CfApi,
];
// NOTE: read_value, delete_vault, admin are NOT in default agent ops

const DEFAULT_MAX_OPS_PER_MINUTE: u32 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub name: String,
    #[serde(default)]
    pub allowed_vaults: AllowedVaults, // "*" = all vaults
    #[serde(default)]
    pub allowed_operations: AllowedOperations, // "*" = all ops
    #[serde(default = "default_max_ops")]
    pub max_ops_per_minute: u32,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowedVaults {
    #[default]
    All,
    List(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AllowedOperations {
    All,
    List(Vec<Operation>),
}

impl Default for AllowedOperations {
    fn default() -> Self {
        AllowedOperations::List(DEFAULT_AGENT_OPS.to_vec())
    }
}

fn default_max_ops() -> u32 {
    DEFAULT_MAX_OPS_PER_MINUTE
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

pub struct PolicyEngine {
    policies: HashMap<String, AgentPolicy>,
    rate_limits: Mutex<HashMap<String, RateLimitEntry>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        let mut policies = HashMap::new();
        // Default policy for any agent
        policies.insert(
            "*".to_string(),
            AgentPolicy {
                name: "*".to_string(),
                allowed_vaults: AllowedVaults::All,
                allowed_operations: AllowedOperations::List(DEFAULT_AGENT_OPS.to_vec()),
                max_ops_per_minute: DEFAULT_MAX_OPS_PER_MINUTE,
                created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            },
        );
        Self {
            policies,
            rate_limits: Mutex::new(HashMap::new()),
        }
    }

    /// Register a specific agent policy
    pub fn register_agent(&mut self, name: &str, overrides: Option<AgentPolicy>) {
        let mut policy = overrides.unwrap_or_else(|| AgentPolicy {
            name: name.to_string(),
            allowed_vaults: AllowedVaults::All,
            allowed_operations: AllowedOperations::List(DEFAULT_AGENT_OPS.to_vec()),
            max_ops_per_minute: DEFAULT_MAX_OPS_PER_MINUTE,
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        policy.name = name.to_string();
        self.policies.insert(name.to_string(), policy);
    }

    /// Check if an operation is allowed. Err if denied.
    pub fn check(
        &self,
        ctx: Option<&CallerContext>,
        op: Operation,
        vault_name: &str,
    ) -> Result<()> {
        // Humans can do everything (they have the password)
        let Some(ctx) = ctx else {
            return Ok(());
        };
        if ctx.caller == Caller::Human {
            return Ok(());
        }

        let agent_name = ctx.agent_name.as_deref().unwrap_or("unknown");
        let policy = self
            .policies
            .get(agent_name)
            .or_else(|| self.policies.get("*"))
            .cloned();

        let Some(policy) = policy else {
            return Err(VaultError::Policy(format!("No policy found for agent '{}'", agent_name)));
        };

        // Check operation permission
        match &policy.allowed_operations {
            AllowedOperations::All => {}
            AllowedOperations::List(ops) => {
                if !ops.contains(&op) {
                    return Err(VaultError::Policy(format!(
                        "🚫 Permission denied: agent '{}' cannot perform '{}'. Allowed: {}",
                        agent_name,
                        op.as_str(),
                        ops.iter()
                            .map(|o| o.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
        }

        // Check vault permission
        if let AllowedVaults::List(vaults) = &policy.allowed_vaults {
            if vault_name != "*" && !vaults.iter().any(|v| v == vault_name) {
                return Err(VaultError::Policy(format!(
                    "🚫 Permission denied: agent '{}' cannot access vault '{}'. Allowed: {}",
                    agent_name,
                    vault_name,
                    vaults.join(", ")
                )));
            }
        }

        // Rate limiting
        self.check_rate_limit(agent_name, policy.max_ops_per_minute)?;
        Ok(())
    }

    fn check_rate_limit(&self, agent_name: &str, max_per_minute: u32) -> Result<()> {
        let now = Instant::now();
        let mut limits = self.rate_limits.lock().unwrap();
        let entry = limits.get_mut(agent_name);

        match entry {
            None => {
                limits.insert(
                    agent_name.to_string(),
                    RateLimitEntry {
                        count: 1,
                        window_start: now,
                    },
                );
                Ok(())
            }
            Some(e) => {
                if now.duration_since(e.window_start) > Duration::from_secs(60) {
                    e.count = 1;
                    e.window_start = now;
                    Ok(())
                } else if e.count >= max_per_minute {
                    Err(VaultError::RateLimit(format!(
                        "🚫 Rate limit exceeded: agent '{}' has made {} operations in the last minute (max: {}). Slow down.",
                        agent_name, e.count, max_per_minute
                    )))
                } else {
                    e.count += 1;
                    Ok(())
                }
            }
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(name: &str) -> CallerContext {
        CallerContext {
            caller: Caller::Agent,
            agent_name: Some(name.to_string()),
            session_id: None,
        }
    }

    #[test]
    fn humans_can_do_everything() {
        let p = PolicyEngine::new();
        let human = CallerContext {
            caller: Caller::Human,
            agent_name: None,
            session_id: None,
        };
        assert!(p.check(Some(&human), Operation::ReadValue, "any").is_ok());
        assert!(p.check(Some(&human), Operation::DeleteVault, "any").is_ok());
        assert!(p.check(Some(&human), Operation::Admin, "any").is_ok());
        assert!(p.check(None, Operation::Admin, "any").is_ok());
    }

    #[test]
    fn agents_cannot_read_values_by_default() {
        let p = PolicyEngine::new();
        assert!(p
            .check(Some(&agent("a")), Operation::ReadValue, "v")
            .is_err());
        assert!(p
            .check(Some(&agent("a")), Operation::DeleteVault, "v")
            .is_err());
        assert!(p.check(Some(&agent("a")), Operation::Admin, "v").is_err());
        assert!(p.check(Some(&agent("a")), Operation::List, "v").is_ok());
        assert!(p.check(Some(&agent("a")), Operation::Write, "v").is_ok());
        assert!(p.check(Some(&agent("a")), Operation::Run, "v").is_ok());
        assert!(p.check(Some(&agent("a")), Operation::CfApi, "v").is_ok());
    }

    #[test]
    fn agent_policy_can_restrict_vaults() {
        let mut p = PolicyEngine::new();
        p.register_agent(
            "limited",
            Some(AgentPolicy {
                name: "limited".into(),
                allowed_vaults: AllowedVaults::List(vec!["github".into()]),
                allowed_operations: AllowedOperations::All,
                max_ops_per_minute: 60,
                created_at: String::new(),
            }),
        );
        assert!(p
            .check(Some(&agent("limited")), Operation::List, "github")
            .is_ok());
        assert!(p
            .check(Some(&agent("limited")), Operation::List, "aws")
            .is_err());
    }

    #[test]
    fn rate_limiting_blocks_after_max() {
        let p = PolicyEngine::new();
        let a = agent("busy");
        for _ in 0..60 {
            assert!(p.check(Some(&a), Operation::List, "v").is_ok());
        }
        let err = p.check(Some(&a), Operation::List, "v").unwrap_err();
        assert!(err.to_string().contains("Rate limit exceeded"));
    }

    #[test]
    fn unknown_agent_falls_back_to_default_policy() {
        let p = PolicyEngine::new();
        assert!(p
            .check(Some(&agent("stranger")), Operation::List, "v")
            .is_ok());
        assert!(p
            .check(Some(&agent("stranger")), Operation::ReadValue, "v")
            .is_err());
    }

    #[test]
    fn error_message_lists_allowed_ops() {
        let p = PolicyEngine::new();
        let err = p
            .check(Some(&agent("a")), Operation::ReadValue, "v")
            .unwrap_err();
        assert!(err.to_string().contains("read_value"));
        assert!(err.to_string().contains("allowed") || err.to_string().contains("Allowed"));
    }
}

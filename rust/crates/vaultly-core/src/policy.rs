//! Policy Engine — controls what each caller (agent or human) can do.
//! Mirrors the TypeScript policy.ts.

use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
    Deploy,
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
            Operation::Deploy => "deploy",
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
    Operation::Deploy,
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
    /// Named roles mapping role-name -> operations it permits. Roles let a
    /// single policy express fine-grained per-vault scoping.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roles: BTreeMap<String, AllowedOperations>,
    /// Per-vault role assignment: vault-name -> role-name. When present, the
    /// agent's allowed operations for that vault are the *intersection* of
    /// `allowed_operations` and the role's operations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vault_roles: BTreeMap<String, String>,
    #[serde(default = "default_max_ops")]
    pub max_ops_per_minute: u32,
    pub created_at: String,
}

/// Does `allowed` permit `op`?
fn ops_allowed(allowed: &AllowedOperations, op: Operation) -> bool {
    match allowed {
        AllowedOperations::All => true,
        AllowedOperations::List(ops) => ops.contains(&op),
    }
}

/// Human-readable listing of allowed operations (for error messages).
fn allowed_ops_str(allowed: &AllowedOperations) -> String {
    match allowed {
        AllowedOperations::All => "*".to_string(),
        AllowedOperations::List(ops) => ops
            .iter()
            .map(|o| o.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    }
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
    std::env::var("VAULTLY_MAX_OPS_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_OPS_PER_MINUTE)
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
                roles: Default::default(),
                vault_roles: Default::default(),
                max_ops_per_minute: default_max_ops(),
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
            roles: Default::default(),
            vault_roles: Default::default(),
            max_ops_per_minute: default_max_ops(),
            created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        policy.name = name.to_string();
        self.policies.insert(name.to_string(), policy);
    }

    /// Load agent policies from a JSON policy file. Accepts either a JSON
    /// array of `AgentPolicy` objects or an object mapping agent-name ->
    /// `AgentPolicy`. Returns the number of agents registered.
    pub fn load(&mut self, path: &str) -> Result<usize> {
        let raw = std::fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| VaultError::ConfigCorrupt(format!("policy file '{path}': {e}")))?;
        let agents: Vec<AgentPolicy> = match value {
            serde_json::Value::Array(_) => serde_json::from_value(value)
                .map_err(|e| VaultError::ConfigCorrupt(format!("policy file '{path}': {e}")))?,
            serde_json::Value::Object(map) => {
                let mut agents = Vec::new();
                for (name, body) in map {
                    if let serde_json::Value::Object(mut obj) = body {
                        // The agent name is the map key; make it authoritative.
                        obj.insert("name".to_string(), serde_json::Value::String(name.clone()));
                        let policy: AgentPolicy =
                            serde_json::from_value(serde_json::Value::Object(obj)).map_err(
                                |e| VaultError::ConfigCorrupt(format!("policy file '{path}': {e}")),
                            )?;
                        agents.push(policy);
                    } else {
                        return Err(VaultError::ConfigCorrupt(format!(
                            "policy file '{path}': policy for '{name}' must be an object"
                        )));
                    }
                }
                agents
            }
            _ => {
                return Err(VaultError::ConfigCorrupt(format!(
                    "policy file '{path}' must be a JSON array or object"
                )))
            }
        };
        for policy in agents {
            let name = policy.name.clone();
            self.register_agent(&name, Some(policy));
        }
        Ok(self.policies.len())
    }

    /// Programmatically replace the agent policy set (used by tests, the REST
    /// edge, and the MCP server).
    pub fn set_agents<I: IntoIterator<Item = AgentPolicy>>(&mut self, agents: I) {
        for policy in agents {
            let name = policy.name.clone();
            self.policies.insert(name, policy);
        }
    }

    /// Snapshot of the registered agent policies (agent-safe: names, op
    /// allowlists, vault/role scopes — never secret values).
    pub fn policy_summaries(&self) -> Vec<AgentPolicy> {
        self.policies.clone().into_values().collect()
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
            return Err(VaultError::Policy(format!(
                "No policy found for agent '{}'",
                agent_name
            )));
        };

        // Check global operation permission (baseline for every vault)
        if !ops_allowed(&policy.allowed_operations, op) {
            return Err(VaultError::Policy(format!(
                "🚫 Permission denied: agent '{}' cannot perform '{}'. Allowed: {}",
                agent_name,
                op.as_str(),
                allowed_ops_str(&policy.allowed_operations)
            )));
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

        // Per-vault role scoping: an assigned role further narrows the ops
        // this agent may perform on this specific vault (intersection with the
        // global `allowed_operations` baseline already enforced above).
        if let Some(role_name) = policy.vault_roles.get(vault_name) {
            let role_ops = policy.roles.get(role_name).ok_or_else(|| {
                VaultError::Policy(format!(
                    "🚫 Agent '{}' has role '{}' assigned to vault '{}' but no such role is defined.",
                    agent_name, role_name, vault_name
                ))
            })?;
            if !ops_allowed(role_ops, op) {
                return Err(VaultError::Policy(format!(
                    "🚫 Permission denied: agent '{}' role '{}' cannot perform '{}' on vault '{}'. Allowed: {}",
                    agent_name,
                    role_name,
                    op.as_str(),
                    vault_name,
                    allowed_ops_str(role_ops)
                )));
            }
        }

        // Rate limiting
        self.check_rate_limit(agent_name, policy.max_ops_per_minute)?;
        Ok(())
    }

    fn check_rate_limit(&self, agent_name: &str, max_per_minute: u32) -> Result<()> {
        let now = Instant::now();
        let mut limits = match self.rate_limits.lock() {
            Ok(l) => l,
            // A panicked holder must not take the whole server down with a
            // poisoned-lock panic; recover and continue.
            Err(poisoned) => poisoned.into_inner(),
        };
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
        assert!(p.check(Some(&agent("a")), Operation::Run, "v").is_err());
        assert!(p.check(Some(&agent("a")), Operation::Deploy, "v").is_ok());
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
                roles: Default::default(),
                vault_roles: Default::default(),
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
    fn per_vault_role_narrows_operations() {
        let mut p = PolicyEngine::new();
        p.register_agent(
            "deploy-bot",
            Some(AgentPolicy {
                name: "deploy-bot".into(),
                allowed_vaults: AllowedVaults::List(vec!["cf-personal".into(), "ci".into()]),
                // Global baseline allows the full default agent set.
                allowed_operations: AllowedOperations::List(DEFAULT_AGENT_OPS.to_vec()),
                roles: BTreeMap::from([(
                    "readonly".to_string(),
                    AllowedOperations::List(vec![Operation::List, Operation::ReadKeys]),
                )]),
                vault_roles: BTreeMap::from([("ci".to_string(), "readonly".to_string())]),
                max_ops_per_minute: 60,
                created_at: String::new(),
            }),
        );
        let ctx = agent("deploy-bot");
        // Role-narrowed vault: ReadKeys ok, Write denied.
        assert!(p.check(Some(&ctx), Operation::ReadKeys, "ci").is_ok());
        let err = p.check(Some(&ctx), Operation::Write, "ci").unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot perform 'write' on vault 'ci'"),
            "got: {err}"
        );
        // Vault without a role uses the global baseline.
        assert!(p.check(Some(&ctx), Operation::Write, "cf-personal").is_ok());
        assert!(p
            .check(Some(&ctx), Operation::ReadKeys, "cf-personal")
            .is_ok());
    }

    #[test]
    fn per_vault_role_must_be_defined() {
        let mut p = PolicyEngine::new();
        p.register_agent(
            "broken",
            Some(AgentPolicy {
                name: "broken".into(),
                allowed_vaults: AllowedVaults::All,
                allowed_operations: AllowedOperations::All,
                roles: Default::default(),
                vault_roles: BTreeMap::from([("v".to_string(), "ghost".to_string())]),
                max_ops_per_minute: 60,
                created_at: String::new(),
            }),
        );
        let err = p
            .check(Some(&agent("broken")), Operation::List, "v")
            .unwrap_err();
        assert!(
            err.to_string().contains("no such role is defined"),
            "got: {err}"
        );
    }

    #[test]
    fn policy_file_loads_array_and_object_forms() {
        // Array form
        let dir = std::env::temp_dir().join(format!("vaultly-policy-test-{}", 0));
        std::fs::create_dir_all(&dir).unwrap();
        let arr = dir.join("arr.json");
        std::fs::write(
            &arr,
            r#"[{"name":"bot-a","allowed_vaults":["github"],"allowed_operations":["list","read_keys"],"roles":{"ro":["list","read_keys"]},"vault_roles":{"github":"ro"},"created_at":"2026-01-01T00:00:00Z"}]"#,
        )
        .unwrap();
        let mut p = PolicyEngine::new();
        let n = p.load(arr.to_str().unwrap()).unwrap();
        assert_eq!(n, 2); // "*" default + bot-a
        assert!(p
            .check(Some(&agent("bot-a")), Operation::List, "github")
            .is_ok());
        assert!(p
            .check(Some(&agent("bot-a")), Operation::Run, "github")
            .is_err());

        // Object form
        let obj = dir.join("obj.json");
        std::fs::write(
            &obj,
            r#"{"bot-b":{"allowed_operations":["list"],"created_at":"2026-01-01T00:00:00Z"}}"#,
        )
        .unwrap();
        let mut p2 = PolicyEngine::new();
        let n2 = p2.load(obj.to_str().unwrap()).unwrap();
        assert_eq!(n2, 2);
        assert!(p2
            .check(Some(&agent("bot-b")), Operation::List, "v")
            .is_ok());
        assert!(p2
            .check(Some(&agent("bot-b")), Operation::Run, "v")
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
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

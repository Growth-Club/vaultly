//! Data-driven deployment targets.
//!
//! Targets are non-secret routing metadata. They are deliberately separate
//! from vault contents so an agent can select a deployment by stable ID
//! without ever receiving an account credential or choosing an arbitrary
//! Cloudflare project.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentProvider {
    Pages,
    Worker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentTarget {
    pub id: String,
    pub provider: DeploymentProvider,
    pub vault: String,
    pub account_id: String,
    /// Pages project name or Worker script name.
    pub project: String,
    /// Repository/workspace directory used for the build.
    pub project_dir: String,
    /// Build command is executed without any vault credentials.
    pub build_command: String,
    /// Pages output directory, relative to `project_dir`.
    pub output_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentResult {
    pub target: String,
    pub provider: DeploymentProvider,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub files: usize,
}

impl DeploymentTarget {
    pub fn validate(&self) -> Result<(), String> {
        for (label, value) in [
            ("id", self.id.as_str()),
            ("vault", self.vault.as_str()),
            ("account_id", self.account_id.as_str()),
            ("project", self.project.as_str()),
            ("project_dir", self.project_dir.as_str()),
            ("build_command", self.build_command.as_str()),
            ("output_dir", self.output_dir.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "deployment target {label} is empty or contains control characters"
                ));
            }
        }
        if self.id.contains('/') || self.id.contains('\\') || self.id == "." || self.id == ".." {
            return Err("deployment target id must be a simple name".into());
        }
        if self.account_id.len() != 32 || !self.account_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(
                "deployment target account_id must be a 32-character hexadecimal ID".into(),
            );
        }
        if std::path::Path::new(&self.output_dir).is_absolute()
            || self.output_dir.split('/').any(|part| part == "..")
        {
            return Err("deployment target output_dir must stay inside project_dir".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> DeploymentTarget {
        DeploymentTarget {
            id: "site-prod".into(),
            provider: DeploymentProvider::Pages,
            vault: "cf-main".into(),
            account_id: "10ce11a119a2e4fa37d71ebfab30ab26".into(),
            project: "site".into(),
            project_dir: "/tmp/site".into(),
            build_command: "npm run build".into(),
            output_dir: "dist".into(),
            branch: Some("main".into()),
            created_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn target_validation_accepts_fixed_metadata() {
        assert!(target().validate().is_ok());
    }

    #[test]
    fn target_validation_rejects_output_escape() {
        let mut value = target();
        value.output_dir = "../secrets".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn target_serialization_never_contains_credentials() {
        let encoded = serde_json::to_string(&target()).unwrap();
        assert!(!encoded.contains("TOKEN"));
        assert!(encoded.contains("site-prod"));
    }
}

//! Data-driven deployment targets.
//!
//! Targets are non-secret routing metadata. They are deliberately separate
//! from vault contents so an agent can select a deployment by stable ID
//! without ever receiving an account credential or choosing an arbitrary
//! Cloudflare project.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    /// Dynamically adopted Workers use the repository's fixed `npm run
    /// deploy` script so package-level predeploy guards remain in force.
    /// `false` preserves compatibility with older manually registered targets.
    #[serde(default)]
    pub worker_package_deploy: bool,
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
        if self.worker_package_deploy && self.provider != DeploymentProvider::Worker {
            return Err("worker_package_deploy is valid only for Worker targets".into());
        }
        Ok(())
    }
}

/// Local deployment metadata inferred from a Wrangler config. This type has
/// no account or vault fields; those are bound by the engine after policy and
/// credential checks, never by an agent-supplied discovery argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredDeploymentSpec {
    pub provider: DeploymentProvider,
    pub project: String,
    pub project_dir: PathBuf,
    pub build_command: String,
    pub output_dir: String,
    pub worker_package_deploy: bool,
}

impl DiscoveredDeploymentSpec {
    pub fn target_id(&self, account_id: &str) -> String {
        format!(
            "auto-{}-{}-{}",
            account_id,
            match self.provider {
                DeploymentProvider::Pages => "pages",
                DeploymentProvider::Worker => "worker",
            },
            sanitize_target_id(&self.project)
        )
    }
}

/// Infer local deployment metadata from a Wrangler JSON/JSONC/TOML config.
/// The config is read but never executed, and only the current workspace may
/// be used as the source directory.
pub fn discover_deployment_spec(config_path: &Path) -> Result<DiscoveredDeploymentSpec, String> {
    let config_path = fs::canonicalize(config_path)
        .map_err(|e| format!("invalid Wrangler config '{}': {e}", config_path.display()))?;
    let project_dir = config_path
        .parent()
        .ok_or_else(|| "Wrangler config has no parent directory".to_string())?
        .to_path_buf();
    let workspace = fs::canonicalize(std::env::current_dir().map_err(|e| e.to_string())?)
        .map_err(|e| format!("cannot resolve current workspace: {e}"))?;
    if !project_dir.starts_with(&workspace) {
        return Err(format!(
            "deployment config must be inside the current workspace ({})",
            workspace.display()
        ));
    }

    let raw = fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "cannot read Wrangler config '{}': {e}",
            config_path.display()
        )
    })?;
    let config = parse_wrangler_config(&config_path, &raw)?;
    let project = config
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| "Wrangler config must contain a non-empty 'name'".to_string())?
        .to_string();

    let pages_output = config
        .get("pages_build_output_dir")
        .and_then(Value::as_str)
        .filter(|dir| !dir.trim().is_empty());
    let provider = if pages_output.is_some() {
        DeploymentProvider::Pages
    } else if config.get("main").and_then(Value::as_str).is_some() {
        DeploymentProvider::Worker
    } else {
        return Err(
            "Wrangler config must describe a Worker ('main') or Pages ('pages_build_output_dir')"
                .into(),
        );
    };

    let package_path = project_dir.join("package.json");
    let package: Value = serde_json::from_str(
        &fs::read_to_string(&package_path)
            .map_err(|e| format!("cannot read '{}': {e}", package_path.display()))?,
    )
    .map_err(|e| format!("invalid package.json '{}': {e}", package_path.display()))?;
    let scripts = package
        .get("scripts")
        .and_then(Value::as_object)
        .ok_or_else(|| "package.json must contain a scripts object".to_string())?;
    let build_command = if scripts.contains_key("build") {
        "npm run build".to_string()
    } else if project_dir.join("tsconfig.json").is_file() {
        "npm exec tsc -- --noEmit -p tsconfig.json".to_string()
    } else {
        return Err(
            "target needs a package build script or tsconfig.json for a credential-free prebuild"
                .into(),
        );
    };
    let worker_package_deploy = match provider {
        DeploymentProvider::Worker => {
            if !scripts.contains_key("deploy") {
                return Err("Worker adoption requires an npm deploy script so repository predeploy guards cannot be bypassed".into());
            }
            true
        }
        DeploymentProvider::Pages => false,
    };

    Ok(DiscoveredDeploymentSpec {
        provider,
        project,
        project_dir,
        build_command,
        output_dir: pages_output.unwrap_or(".").to_string(),
        worker_package_deploy,
    })
}

fn parse_wrangler_config(path: &Path, raw: &str) -> Result<Value, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if ext == "toml" {
        parse_simple_toml(raw, path)
    } else {
        let stripped = strip_json_comments(raw)?;
        serde_json::from_str(&stripped)
            .map_err(|e| format!("invalid Wrangler JSON '{}': {e}", path.display()))
    }
}

/// Parse the top-level string identity fields needed from Wrangler TOML
/// without adding a parser dependency to the credential boundary. Nested
/// bindings are intentionally ignored; deployment identity is top-level.
fn parse_simple_toml(raw: &str, path: &Path) -> Result<Value, String> {
    let mut value = serde_json::Map::new();
    let mut section = String::new();
    for (line_number, raw_line) in raw.lines().enumerate() {
        let uncommented = strip_toml_comment(raw_line);
        let line = uncommented.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(format!(
                    "invalid Wrangler TOML '{}' line {}: malformed section",
                    path.display(),
                    line_number + 1
                ));
            }
            section = line[1..line.len() - 1].trim().to_string();
            continue;
        }
        if !section.is_empty() {
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            format!(
                "invalid Wrangler TOML '{}' line {}: expected key = value",
                path.display(),
                line_number + 1
            )
        })?;
        let key = key.trim();
        if key != "name" && key != "main" && key != "pages_build_output_dir" {
            continue;
        }
        let parsed = parse_toml_string(raw_value.trim()).ok_or_else(|| {
            format!(
                "invalid Wrangler TOML '{}' line {}: {} must be a string",
                path.display(),
                line_number + 1,
                key
            )
        })?;
        value.insert(key.to_string(), Value::String(parsed));
    }
    Ok(Value::Object(value))
}

fn strip_toml_comment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut quote = None;
    let mut escaped = false;
    for c in raw.chars() {
        if let Some(delimiter) = quote {
            out.push(c);
            if delimiter == '"' && escaped {
                escaped = false;
            } else if delimiter == '"' && c == '\\' {
                escaped = true;
            } else if c == delimiter {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            out.push(c);
        } else if c == '#' {
            break;
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_toml_string(raw: &str) -> Option<String> {
    let quote = raw.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let end = raw.rfind(quote)?;
    if end == 0 || !raw[end + 1..].trim().is_empty() {
        return None;
    }
    let body = &raw[1..end];
    if quote == '\'' {
        Some(body.to_string())
    } else {
        let mut result = String::new();
        let mut escaped = false;
        for c in body.chars() {
            if escaped {
                result.push(match c {
                    '"' => '"',
                    '\\' => '\\',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => return None,
                });
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else {
                result.push(c);
            }
        }
        if escaped {
            None
        } else {
            Some(result)
        }
    }
}

fn strip_json_comments(raw: &str) -> Result<String, String> {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            let mut closed = false;
            while i + 1 < chars.len() {
                if chars[i] == '*' && chars[i + 1] == '/' {
                    i += 2;
                    closed = true;
                    break;
                }
                if chars[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            if !closed {
                return Err("unterminated comment in Wrangler JSON".into());
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    if in_string || escaped {
        return Err("unterminated string in Wrangler JSON".into());
    }
    Ok(out)
}

fn sanitize_target_id(project: &str) -> String {
    let mut out = String::new();
    for c in project.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let value = out.trim_matches('-');
    if value.is_empty() {
        "project".into()
    } else {
        value.into()
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
            worker_package_deploy: false,
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

    #[test]
    fn jsonc_parser_ignores_comments_but_preserves_strings() {
        let parsed = strip_json_comments(
            r#"{ // comment
              "name": "https://example.test//not-comment", /* block */
              "main": "src/index.ts"
            }"#,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&parsed).unwrap();
        assert_eq!(value["name"], "https://example.test//not-comment");
        assert_eq!(value["main"], "src/index.ts");
    }

    #[test]
    fn toml_parser_reads_top_level_wrangler_identity_fields() {
        let value = parse_simple_toml(
            r#"
name = 'site'
pages_build_output_dir = "dist" # comment
[vars]
IGNORED = "value"
"#,
            Path::new("wrangler.toml"),
        )
        .unwrap();
        assert_eq!(value["name"], "site");
        assert_eq!(value["pages_build_output_dir"], "dist");
        assert!(value.get("IGNORED").is_none());
    }

    #[test]
    fn target_id_sanitization_is_stable_and_safe() {
        assert_eq!(sanitize_target_id("Gate 2027/API"), "gate-2027-api");
        assert_eq!(sanitize_target_id("___"), "___");
    }

    #[test]
    fn generated_target_ids_are_account_scoped() {
        let spec = DiscoveredDeploymentSpec {
            provider: DeploymentProvider::Worker,
            project: "same-name".into(),
            project_dir: PathBuf::from("/tmp/project"),
            build_command: "npm run build".into(),
            output_dir: ".".into(),
            worker_package_deploy: true,
        };
        assert_ne!(
            spec.target_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            spec.target_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }
}

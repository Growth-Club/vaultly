//! Vaultly CLI — agent-first encrypted credential manager with Cloudflare integration.
//! Rust port of src/index.ts (clap). All commands route through vaultly_core::VaultEngine
//! for identical audit + policy + encryption behavior.

use std::io::IsTerminal;
use std::path::Path;
use std::process::exit;

use clap::{Parser, Subcommand};
use colored::Colorize;
use serde_json::{Map, Value};
use vaultly_core::keychain;
use vaultly_core::{Caller, CallerContext, DeploymentProvider, DeploymentTarget, VaultEngine};

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
    if let Ok(password) = std::env::var("VAULTLY_MASTER_PASSWORD") {
        candidates.push(password);
    }
    if let Some(password) = keychain::get_from_keychain() {
        candidates.push(password);
    }

    for password in candidates {
        if engine.unlock(&password).is_ok() {
            return engine;
        }
    }

    if non_interactive() {
        let detail = if std::env::var("VAULTLY_DIR").is_ok()
            && std::env::var("VAULTLY_ALLOW_KEYCHAIN").as_deref() != Ok("1")
        {
            "VAULTLY_DIR is set; use the default store or set VAULTLY_ALLOW_KEYCHAIN=1 for an intentional custom-store Keychain setup."
        } else if keychain::is_keychain_available() && !keychain::keychain_entry_exists() {
            "No macOS Keychain entry exists yet; run `VAULTLY_HUMAN_MODE=1 vaultly keychain store` once as a human."
        } else {
            "Set VAULTLY_MASTER_PASSWORD or configure macOS Keychain with `VAULTLY_HUMAN_MODE=1 vaultly keychain store`."
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
    /// Deploy a validated target (agent-safe; no arbitrary account/project args)
    Deploy {
        target: String,
        #[arg(long, help = "Output one JSON object for automation")]
        json: bool,
    },
    /// Manage deployment targets
    Target {
        #[command(subcommand)]
        sub: TargetCommand,
    },
    /// Start MCP server for AI agents
    Mcp,
    /// Manage Cloudflare accounts
    Cf {
        #[command(subcommand)]
        sub: CfCommand,
    },
    /// Manage macOS Keychain integration
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
    /// Store master password in macOS Keychain for auto-unlock
    Store,
    /// Remove master password from macOS Keychain
    Remove,
    /// Check Keychain status
    Status,
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
        Some(Command::Deploy { target, json }) => cmd_deploy_target(&target, json).await,
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
                json,
            } => cmd_target_adopt(&vault, &config, json).await,
            TargetCommand::List { json } => cmd_target_list(json),
            TargetCommand::Remove { id } => {
                block_in_agent_mode("target remove");
                cmd_target_remove(&id)
            }
        },
        Some(Command::Mcp) => {
            vaultly_mcp::start_mcp_server().await;
        }
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
        Some(Command::Doctor { json }) => cmd_doctor(json),
        None => {
            // No subcommand (piped/non-TTY): print help
            use clap::CommandFactory;
            let mut cli = Cli::command();
            let _ = cli.print_help();
            println!();
        }
    }
}

// ─── completions ─────────────────────────────────────────────

/// Install completions to the standard directory for the shell.
/// Non-destructive: only ever creates directories and writes the
/// completion file for vaultly; leaves other files untouched.
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
        && prompt::prompt_confirm("Store master password in macOS Keychain for auto-unlock?")
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

async fn cmd_target_adopt(vault: &str, config: &str, json_output: bool) {
    let vault_name = cf_vault(vault);
    let mut engine = require_unlock();
    match engine
        .adopt_deployment_target(&vault_name, Path::new(config), target_context().as_ref())
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
                    "{} Adopted target '{}' for {} '{}'",
                    "✓".green(),
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

// ─── cf bindings / triggers ─────────────────────────────────

// ─── cf ssl / certificates ──────────────────────────────────

// ─── cf firewall ────────────────────────────────────────────

// ─── cf lb ──────────────────────────────────────────────────

// ─── cf email ───────────────────────────────────────────────

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
            "{} macOS Keychain not available (requires macOS).",
            "✗".red()
        );
        exit(1);
    }
    let pw = std::env::var("VAULTLY_MASTER_PASSWORD")
        .unwrap_or_else(|_| prompt::prompt_password("🔑 Master password to store in Keychain: "));

    let mut engine = engine();
    if engine.unlock(&pw).is_err() {
        eprintln!("{} Wrong password.", "✗".red());
        exit(1);
    }
    if keychain::store_in_keychain(&pw) {
        println!("{} Master password stored in macOS Keychain.", "✓".green());
        println!(
            "{}",
            "  MCP server will auto-unlock without password prompt.".dimmed()
        );
    } else {
        eprintln!("{} Failed to store in Keychain.", "✗".red());
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
        println!("{} Keychain not available (requires macOS).", "⚠".yellow());
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
        "not available (macOS only)".dimmed().to_string()
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
            "{} Non-interactive encrypted export needs VAULTLY_MASTER_PASSWORD or a configured macOS Keychain.",
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

fn cmd_doctor(json: bool) {
    let engine = engine();
    let mut findings: Vec<DoctorFinding> = Vec::new();

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
            message: "Keychain N/A (macOS only)".into(),
        });
    }

    // 6. Password source
    let pw_source = if std::env::var_os("VAULTLY_MASTER_PASSWORD").is_some() {
        "VAULTLY_MASTER_PASSWORD env"
    } else if keychain::keychain_entry_exists() {
        "macOS Keychain"
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

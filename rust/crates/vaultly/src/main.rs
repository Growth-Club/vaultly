//! Vaultly CLI — agent-first encrypted credential manager with Cloudflare integration.
//! Rust port of src/index.ts (clap). All commands route through vaultly_core::VaultEngine
//! for identical audit + policy + encryption behavior.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::exit;

use clap::{Parser, Subcommand};
use colored::Colorize;
use serde_json::{Map, Value};
use vaultly_core::keychain;
use vaultly_core::{RunOptions, VaultEngine};

mod prompt;
pub use vaultly_core::templates;
mod server;
mod tui;

fn agent_mode() -> bool {
    std::env::var("VAULTLY_AGENT_MODE").as_deref() == Ok("1")
}

fn block_in_agent_mode(command_name: &str) {
    if agent_mode() {
        eprintln!(
            "{} '{}' is blocked in agent mode.\n  Agents cannot read raw secrets. Use instead:\n    vaultly run <vault> -- <command>   (execute with injected env)\n    vaultly mcp                        (MCP server for AI agents)",
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
    let password = std::env::var("VAULTLY_MASTER_PASSWORD")
        .unwrap_or_else(|_| prompt::prompt_password("🔑 Master password: "));
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
    /// Push encrypted vaults to Cloudflare Worker (remote backup)
    Backup {
        #[arg(short, long, help = "Your Vaultly Worker URL")]
        url: String,
        #[arg(short, long, help = "Backup API token (set in Worker)")]
        token: String,
    },
    /// Pull encrypted vaults from Cloudflare Worker
    Restore {
        #[arg(short, long, help = "Your Vaultly Worker URL")]
        url: String,
        #[arg(short, long, help = "Backup API token")]
        token: String,
    },
    /// Add AI-tool ignore rules to protect secrets
    Protect { project_dir: Option<String> },
    /// Run a command with vault secrets injected (agent-safe, output scrubbed)
    Run {
        vault_name: String,
        #[arg(
            trailing_var_arg = true,
            required = true,
            allow_hyphen_values = true,
            help = "Command and arguments to run, e.g. -- 'npx wrangler deploy'"
        )]
        command: Vec<String>,
        #[arg(
            long,
            help = "Timeout in milliseconds (default: 86400000 for CLI, 300000 for MCP)"
        )]
        timeout: Option<u64>,
        #[arg(
            short,
            long,
            help = "Run even if the vault has expired secrets (proceeds knowingly)"
        )]
        force: bool,
    },
    /// Start MCP server for AI agents
    Mcp,
    /// Start a local HTTP/REST server (bearer-token auth, agent-first)
    Serve {
        #[arg(long, default_value = "127.0.0.1:8799", help = "Bind address")]
        bind: String,
        #[arg(long, help = "Bearer token (default: VAULTLY_SERVER_TOKEN env var)")]
        token: Option<String>,
    },
    /// Manage Cloudflare accounts
    Cf {
        #[command(subcommand)]
        sub: CfCommand,
    },
    /// Create a vault from a pre-built template
    Template {
        name: Option<String>,
        #[arg(long, help = "List available templates")]
        list: bool,
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
    /// Interactive menu (human-only, blocked in agent mode)
    Tui,
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
    /// Copy a secret value to the clipboard (macOS pbcopy)
    Copy {
        vault_name: String,
        secret_key: String,
    },
    /// Rename a vault (moves all secrets and deletes the old vault)
    Rename { old_name: String, new_name: String },
    /// Move a secret to another vault
    Mv {
        vault_name: String,
        secret_key: String,
        to_vault: String,
    },
    /// Copy a secret to another vault (keeps the original)
    Cp {
        vault_name: String,
        secret_key: String,
        to_vault: String,
    },
    /// Generate shell completion scripts (bash, zsh, fish, ...)
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
        #[arg(long, help = "Write completions to a specific file instead of stdout")]
        output: Option<PathBuf>,
        #[arg(
            long,
            help = "Install to the standard completion dir for the shell (bash/zsh/fish)"
        )]
        install: bool,
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
    /// Output shell eval to activate a CF account (use with eval)
    Use { name: String },
    /// Deploy a Worker project using a CF account (agent-safe, output scrubbed)
    Deploy {
        name: String,
        project_dir: String,
        #[arg(long, help = "Wrangler environment (e.g. staging)")]
        env: Option<String>,
    },
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
    /// Delete a DNS record from a zone (agent-safe — never returns values)
    DnsDelete {
        name: String,
        zone_id: String,
        record_id: String,
    },
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
    // `vaultly` with no args + a real terminal → interactive TUI
    if std::env::args().count() <= 1 && std::io::stdin().is_terminal() {
        tui::start_tui().await;
        return;
    }

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
        Some(Command::Backup { url, token }) => {
            block_in_agent_mode("backup");
            cmd_backup(&url, &token).await
        }
        Some(Command::Restore { url, token }) => {
            block_in_agent_mode("restore");
            cmd_restore(&url, &token).await
        }
        Some(Command::Protect { project_dir }) => {
            block_in_agent_mode("protect");
            cmd_protect(project_dir.as_deref().unwrap_or("."))
        }
        Some(Command::Run {
            vault_name,
            command,
            timeout,
            force,
        }) => cmd_run(&vault_name, &command, timeout, force).await,
        Some(Command::Mcp) => {
            vaultly_mcp::start_mcp_server().await;
        }
        Some(Command::Serve { bind, token }) => {
            cmd_serve(&bind, token.as_deref()).await;
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
            CfCommand::Use { name } => {
                block_in_agent_mode("cf use");
                let mut engine = require_unlock();
                let vault_name = cf_vault(&name);
                match engine.get_secrets(&vault_name, None) {
                    Ok(secrets) => {
                        if secrets.is_empty() {
                            eprintln!("{} Account '{}' not found.", "✗".red(), vault_name);
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
            CfCommand::Deploy {
                name,
                project_dir,
                env,
            } => cmd_cf_deploy(&name, &project_dir, env.as_deref()).await,
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
            CfCommand::DnsDelete {
                name,
                zone_id,
                record_id,
            } => cmd_cf_dns_delete(&name, &zone_id, &record_id).await,
        },
        Some(Command::Template { name, list }) => {
            block_in_agent_mode("template");
            cmd_template(name.as_deref(), list)
        }
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
        Some(Command::Tui) => {
            block_in_agent_mode("tui");
            tui::start_tui().await
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
        Some(Command::Copy {
            vault_name,
            secret_key,
        }) => {
            block_in_agent_mode("copy");
            cmd_copy(&vault_name, &secret_key)
        }
        Some(Command::Rename { old_name, new_name }) => {
            block_in_agent_mode("rename");
            cmd_rename(&old_name, &new_name)
        }
        Some(Command::Mv {
            vault_name,
            secret_key,
            to_vault,
        }) => {
            block_in_agent_mode("mv");
            cmd_mv(&vault_name, &secret_key, &to_vault)
        }
        Some(Command::Cp {
            vault_name,
            secret_key,
            to_vault,
        }) => {
            block_in_agent_mode("cp");
            cmd_cp(&vault_name, &secret_key, &to_vault)
        }
        Some(Command::Completions {
            shell,
            output,
            install,
        }) => {
            use std::io::Write;
            let script = completion_script(shell);
            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            eprintln!("{} Failed to create {}: {}", "✗".red(), parent.display(), e);
                            exit(1);
                        }
                    }
                }
                if let Err(e) = std::fs::write(&path, &script) {
                    eprintln!("{} Failed to write '{}': {}", "✗".red(), path.display(), e);
                    exit(1);
                }
                println!("{} Wrote completions to '{}'", "✓".green(), path.display());
            } else if install {
                install_completions(shell, &script);
            } else {
                let mut out = std::io::stdout();
                if let Err(e) = out.write_all(script.as_bytes()) {
                    eprintln!("{} Failed to write stdout: {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
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

fn completion_script(shell: clap_complete::Shell) -> String {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    let mut buf: Vec<u8> = Vec::new();
    clap_complete::generate(shell, &mut cmd, "vaultly", &mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Install completions to the standard directory for the shell.
/// Non-destructive: only ever creates directories and writes the
/// completion file for vaultly; leaves other files untouched.
fn install_completions(shell: clap_complete::Shell, script: &str) {
    let Some(home) = dirs::home_dir() else {
        eprintln!("{} Could not determine home directory.", "✗".red());
        exit(1);
    };
    let (dir, file_name) = match shell {
        clap_complete::Shell::Bash => (
            home.join(".local/share/bash-completion/completions"),
            "vaultly".to_string(),
        ),
        clap_complete::Shell::Zsh => (home.join(".zfunc"), "_vaultly".to_string()),
        clap_complete::Shell::Fish => (
            home.join(".config/fish/completions"),
            "vaultly.fish".to_string(),
        ),
        other => (
            home.join(".local/share/vaultly/completions"),
            format!("{other}.vaultly"),
        ),
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("{} Failed to create {}: {}", "✗".red(), dir.display(), e);
        exit(1);
    }
    let path = dir.join(file_name);
    if let Err(e) = std::fs::write(&path, script) {
        eprintln!("{} Failed to write '{}': {}", "✗".red(), path.display(), e);
        exit(1);
    }
    println!(
        "{} Installed {shell} completions to '{}'",
        "✓".green(),
        path.display()
    );
    match shell {
        clap_complete::Shell::Zsh => println!("  Add to your ~/.zshrc: fpath+=({})", dir.display()),
        clap_complete::Shell::Fish => {
            println!("  Restart your shell or run: . ~/.config/fish/config.fish")
        }
        _ => println!("  Restart your shell to activate."),
    }
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

fn cmd_copy(vault_name: &str, secret_key: &str) {
    let mut engine = require_unlock();
    let value = match engine.get_secret_value(vault_name, secret_key, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = match Command::new("pbcopy").stdin(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{} Could not start clipboard: {}", "✗".red(), e);
                eprintln!(
                    "{} value available via: vaultly get {} {}",
                    "→".dimmed(),
                    vault_name,
                    secret_key
                );
                exit(1);
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(value.as_bytes());
        }
        // stdout is captured here; wait for pbcopy to flush
        match child.wait() {
            Ok(_) => println!(
                "{} {}/{} copied to clipboard",
                "✓".green(),
                vault_name,
                secret_key
            ),
            Err(e) => {
                eprintln!("{} Clipboard error: {}", "✗".red(), e);
                exit(1);
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!(
            "{} Clipboard not supported on this platform; using: {}",
            "✗".red(),
            value
        );
    }
}

fn cmd_rename(old_name: &str, new_name: &str) {
    let mut engine = require_unlock();
    let secrets = match engine.get_secrets(old_name, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    if secrets.is_empty() {
        eprintln!("{} Vault '{}' not found or empty.", "✗".red(), old_name);
        exit(1);
    }
    for (k, v) in &secrets {
        if let Some(val) = v.as_str() {
            if let Err(e) = engine.add_secret(new_name, k, val, None) {
                eprintln!("{} Failed to copy key '{}': {}", "✗".red(), k, e);
                exit(1);
            }
        }
    }
    match engine.delete_vault(old_name, None) {
        Ok(true) => println!("{} Renamed '{}' → '{}'", "✓".green(), old_name, new_name),
        Ok(false) => println!(
            "{} Copied to '{}' but could not remove '{}'",
            "⚠".yellow(),
            new_name,
            old_name
        ),
        Err(e) => eprintln!("{} Could not remove old vault: {}", "✗".red(), e),
    }
}

fn cmd_mv(vault_name: &str, secret_key: &str, to_vault: &str) {
    let mut engine = require_unlock();
    let value = match engine.get_secret_value(vault_name, secret_key, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    if let Err(e) = engine.add_secret(to_vault, secret_key, &value, None) {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }
    match engine.delete_secret(vault_name, secret_key, None) {
        Ok(true) => println!(
            "{} Moved {}/{} → {}",
            "✓".green(),
            vault_name,
            secret_key,
            to_vault
        ),
        _ => eprintln!(
            "{} Copied to {} but could not delete from {}",
            "⚠".yellow(),
            to_vault,
            vault_name
        ),
    }
}

fn cmd_cp(vault_name: &str, secret_key: &str, to_vault: &str) {
    let mut engine = require_unlock();
    let value = match engine.get_secret_value(vault_name, secret_key, None) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    match engine.add_secret(to_vault, secret_key, &value, None) {
        Ok(()) => println!(
            "{} Copied {}/{} → {}",
            "✓".green(),
            vault_name,
            secret_key,
            to_vault
        ),
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    }
}

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

async fn cmd_backup(url: &str, token: &str) {
    let mut engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    println!(
        "{} Backing up encrypted vaults to Cloudflare...",
        "📤".cyan()
    );

    let vaults = engine.get_encrypted_vaults();
    if vaults.is_empty() {
        println!("{} No vaults to backup.", "⚠".yellow());
        return;
    }
    let names: Vec<String> = vaults.keys().cloned().collect();

    let config = engine.store().get_config_for_backup().ok();
    let checksum = match vaultly_core::vault::backup_checksum(&vaults) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to checksum backup: {}", "✗".red(), e);
            exit(1);
        }
    };
    let payload = serde_json::json!({
        "version": 1,
        "checksum": checksum,
        "vaults": vaults,
        "config": config
    });

    let client = reqwest::Client::new();
    let res = client
        .put(format!("{}/backup", url.trim_end_matches('/')))
        .header("Content-Type", "application/json")
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => {
            if let Err(e) = engine.update_backup_meta(url) {
                eprintln!("{} Failed to update backup metadata: {}", "⚠".yellow(), e);
            }
            println!(
                "{} Backed up {} vault(s): {}",
                "✓".green(),
                names.len(),
                names.join(", ")
            );
            println!(
                "{}",
                "  Data is encrypted — Cloudflare only stores ciphertext.".dimmed()
            );
        }
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            eprintln!("{} Backup failed: HTTP {}: {}", "✗".red(), status, text);
            exit(1);
        }
        Err(e) => {
            eprintln!("{} Backup failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

async fn cmd_restore(url: &str, token: &str) {
    println!(
        "{} Restoring encrypted vaults from Cloudflare...",
        "📥".cyan()
    );
    if !prompt::prompt_confirm(
        "Restore overwrites existing vaults. Continue?"
            .red()
            .to_string()
            .as_str(),
    ) {
        return;
    }

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/backup", url.trim_end_matches('/')))
        .bearer_auth(token)
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => {
            let data: Value = match r.json().await {
                Ok(v) => v,
                Err(_) => {
                    eprintln!("{} Restore failed: response was not valid JSON.", "✗".red());
                    exit(1);
                }
            };
            let vaults = data
                .get("vaults")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();

            // Reject unsupported backup versions before touching any files.
            let version = data.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
            if version != 1 {
                eprintln!(
                    "{} Restore failed: unsupported backup version {}.",
                    "✗".red(),
                    version
                );
                exit(1);
            }

            // Verify the integrity checksum so corruption/tampering can never
            // silently overwrite a local store with bad data.
            let expected = data.get("checksum").and_then(|c| c.as_str());
            match expected {
                Some(c) => {
                    let computed =
                        vaultly_core::vault::backup_checksum(&vaults).unwrap_or_default();
                    if computed != *c {
                        eprintln!(
                            "{} Restore failed: backup checksum mismatch (data corrupt or tampered).",
                            "✗".red()
                        );
                        exit(1);
                    }
                }
                None => {
                    eprintln!(
                        "{} Restore failed: backup has no integrity checksum. Re-run `vaultly backup` to regenerate.",
                        "✗".red()
                    );
                    exit(1);
                }
            }

            let mut engine = engine();
            match engine.restore_encrypted_vaults(&vaults) {
                Ok(count) => {
                    println!("{} Restored {} vault(s).", "✓".green(), count);
                    println!("{}", "  Use your master password to decrypt them.".dimmed());
                }
                Err(e) => {
                    eprintln!("{} Restore failed: {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            eprintln!("{} Restore failed: HTTP {}: {}", "✗".red(), status, text);
            exit(1);
        }
        Err(e) => {
            eprintln!("{} Restore failed: {}", "✗".red(), e);
            exit(1);
        }
    }
}

// ─── protect ────────────────────────────────────────────────

fn cmd_protect(dir: &str) {
    let patterns = [
        "# Vaultly secrets protection",
        ".env",
        ".env.*",
        "*.vault",
        ".production-keys",
        "credentials*",
        "*-keys*",
        "*.pem",
    ];
    let targets = [".gitignore", ".windsurfrules"];
    let mut updated = 0;

    for file in targets {
        let path = PathBuf::from(dir).join(file);
        let mut content = std::fs::read_to_string(&path).unwrap_or_default();
        if content.contains("Vaultly secrets protection") {
            println!("{} {} (already protected)", "⏭".dimmed(), file);
            continue;
        }
        content.push('\n');
        content.push_str(&patterns.join("\n"));
        content.push('\n');
        std::fs::create_dir_all(path.parent().unwrap_or(&PathBuf::from("."))).ok();
        if std::fs::write(&path, content).is_ok() {
            println!("{} {} updated", "✓".green(), file);
            updated += 1;
        }
    }

    println!(
        "{} Protected {} config file(s) in {}",
        "✓".green(),
        updated,
        dir
    );
    println!(
        "{}",
        "  AI tools that respect these files won't read your secrets.".dimmed()
    );
}

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

async fn cmd_serve(bind: &str, token: Option<&str>) {
    let token = match token {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => match std::env::var("VAULTLY_SERVER_TOKEN") {
            Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => {
                eprintln!(
                    "{} Missing server token. Pass --token or set VAULTLY_SERVER_TOKEN.",
                    "✗".red()
                );
                exit(1);
            }
        },
    };
    if let Err(e) = server::serve(bind, &token).await {
        eprintln!("{} {}", "✗".red(), e);
        exit(1);
    }
}

async fn cmd_run(vault_name: &str, command: &[String], timeout_ms: Option<u64>, force: bool) {
    let args: Vec<String> = command.to_vec();
    if args.is_empty() {
        eprintln!(
            "{} No command given. Usage: vaultly run <vault> -- <command>",
            "✗".red()
        );
        exit(1);
    }

    let mut engine = require_unlock();

    if !force {
        match engine.expired_keys(vault_name, None) {
            Ok(expired) if !expired.is_empty() => {
                eprintln!(
                    "{} {} expired secret(s) in '{}' ({}). Rotate them first (`vaultly rotate {} --expired`), or pass --force to override.",
                    "⛔".red(),
                    expired.len(),
                    vault_name,
                    expired.join(", "),
                    vault_name
                );
                exit(1);
            }
            Ok(_) => {}
            Err(e) => {
                // Unknown/empty vault is reported by list_keys below.
                eprintln!("{} {}", "✗".red(), e);
                exit(1);
            }
        }
    }

    let (program, program_args) = args.split_first().expect("args non-empty guaranteed");
    let cmd_display = args.join(" ");

    let keys = engine.list_keys(vault_name, None).unwrap_or_default();
    if keys.is_empty() {
        eprintln!(
            "{} Vault '{}' is empty or doesn't exist.",
            "✗".red(),
            vault_name
        );
        exit(1);
    }
    eprintln!(
        "{} Injecting {} secret(s) from '{}': {}",
        "🔐".dimmed(),
        keys.len(),
        vault_name,
        keys.join(", ")
    );
    eprintln!("{} Running: {}\n", "▶".dimmed(), cmd_display);

    let timeout = timeout_ms.unwrap_or(86_400_000);
    let opts = RunOptions {
        cwd: None,
        timeout_ms: Some(timeout),
        allowed_keys: None,
    };
    let result = engine
        .run(vault_name, program, program_args, &opts, None)
        .await;

    match result {
        Ok(res) => {
            if !res.stdout.is_empty() {
                println!("{}", res.stdout);
            }
            if !res.stderr.is_empty() {
                eprintln!("{}", res.stderr);
            }
            if res.scrubbed {
                eprintln!("{} Secret values were scrubbed from output.", "⚠".yellow());
            }
            exit(res.code);
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
    println!("{} Use it:  vaultly cf use {}", "".dimmed(), name);
    println!(
        "{} Deploy:  vaultly cf deploy {} /path/to/project",
        "".dimmed(),
        name
    );
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

// ─── cf deploy ──────────────────────────────────────────────

async fn cmd_cf_deploy(name: &str, project_dir: &str, env: Option<&str>) {
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();

    let secrets = match engine.get_secrets(&vault_name, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} {}", "✗".red(), e);
            exit(1);
        }
    };
    if secrets
        .get("CLOUDFLARE_API_TOKEN")
        .and_then(|v| v.as_str())
        .is_none()
    {
        eprintln!("{} No CLOUDFLARE_API_TOKEN in '{}'", "✗".red(), vault_name);
        exit(1);
    }

    let mut args = vec!["deploy".to_string()];
    if let Some(e) = env {
        args.push("--env".to_string());
        args.push(e.to_string());
    }

    eprintln!(
        "{} Deploying with account '{}' → {}",
        "☁️".dimmed(),
        name,
        project_dir
    );
    eprintln!("{} npx wrangler {}\n", "▶".dimmed(), args.join(" "));

    let opts = RunOptions {
        cwd: Some(project_dir),
        timeout_ms: Some(86_400_000),
        allowed_keys: None,
    };
    let result = engine.run(&vault_name, "npx", &args, &opts, None).await;

    match result {
        Ok(res) => {
            if !res.stdout.is_empty() {
                println!("{}", res.stdout);
            }
            if !res.stderr.is_empty() {
                eprintln!("{}", res.stderr);
            }
            if res.scrubbed {
                eprintln!("{} Secret values were scrubbed from output.", "⚠".yellow());
            }
            exit(res.code);
        }
        Err(e) => {
            eprintln!("{} Failed to start deploy: {}", "✗".red(), e);
            exit(1);
        }
    }
}

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

async fn cmd_cf_dns_delete(name: &str, zone_id: &str, record_id: &str) {
    // Deleting a DNS record is safe for agents (no values are involved), so
    // this command is NOT agent-blocked — mirror the agent-safe cf_zones.
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();
    match engine
        .dns_delete(&vault_name, zone_id, record_id, None)
        .await
    {
        Ok(r) => print_cf_result(
            &r,
            &format!(
                "Deleted DNS record '{}' in zone '{}' (account '{}')",
                record_id, zone_id, name
            ),
        ),
        Err(e) => {
            eprintln!("{} Failed to delete DNS record: {}", "✗".red(), e);
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

fn cmd_template(name: Option<&str>, list: bool) {
    if list || name.is_none() {
        println!("{}", "\n📋 Available templates:\n".bold());
        for (key, tpl) in templates::TEMPLATES {
            println!("  {} {}", key.cyan(), tpl.description.dimmed());
            if !tpl.keys.is_empty() {
                println!(
                    "  {} {}",
                    "".dimmed(),
                    format!("Keys: {}", tpl.keys.join(", ")).dimmed()
                );
            }
        }
        println!("{}", "\nUsage: vaultly template github my-github".dimmed());
        return;
    }

    let name = name.unwrap();
    let tpl = match templates::get_template(name) {
        Some(t) => t,
        None => {
            eprintln!("{} Unknown template '{}'.", "✗".red(), name);
            eprintln!(
                "{} Available: {}",
                "".dimmed(),
                templates::template_names().join(", ")
            );
            exit(1);
        }
    };

    let mut engine = require_unlock();

    let vault_name = prompt::prompt_line(&format!("Vault name [{}]: ", name));
    let vault_name = if vault_name.is_empty() {
        name.to_string()
    } else {
        vault_name
    };

    let keys: Vec<String> = if tpl.keys.is_empty() {
        println!("{}", "Enter keys (comma-separated, e.g. A,B,C):".dimmed());
        prompt::prompt_line("  Keys: ")
            .split(',')
            .map(|k| {
                k.trim()
                    .to_uppercase()
                    .replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "_")
            })
            .filter(|k| !k.is_empty())
            .collect()
    } else {
        println!("{}", format!("\nTemplate: {}", tpl.description).dimmed());
        println!("{}", "(press Enter to skip any key)\n".dimmed());
        tpl.keys.iter().map(|k| k.to_string()).collect()
    };

    let mut added = 0;
    for k in &keys {
        let v = prompt::prompt_password(&format!("  {}: ", k));
        if !v.is_empty() && engine.add_secret(&vault_name, k, &v, None).is_ok() {
            added += 1;
        }
    }

    if added == 0 {
        eprintln!(
            "{} No values entered — vault '{}' not created.",
            "✗".red(),
            vault_name
        );
        exit(1);
    }

    println!(
        "{} Vault '{}' created with {} key(s)",
        "✓".green(),
        vault_name,
        added
    );
    println!(
        "{} Use: vaultly run {} -- <command>",
        "".dimmed(),
        vault_name
    );
}

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

/// Read the master password from env or interactive prompt (same source as
/// `require_unlock`), without consuming the engine.
fn master_password() -> String {
    std::env::var("VAULTLY_MASTER_PASSWORD")
        .unwrap_or_else(|_| prompt::prompt_password("🔑 Master password: "))
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

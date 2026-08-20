//! Vaultly CLI — agent-first encrypted credential manager with Cloudflare integration.
//! Rust port of src/index.ts (clap). All commands route through vaultly_core::VaultEngine
//! for identical audit + policy + encryption behavior.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::exit;

use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use serde_json::{Map, Value};
use vaultly_core::keychain;
use vaultly_core::VaultEngine;

mod prompt;
mod templates;
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

fn engine() -> VaultEngine {
    VaultEngine::new(None)
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
    version = "1.0.0",
    about = "🔐 Agent-first encrypted credential manager with Cloudflare integration"
)]
struct Cli {
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
    },
    /// Get a secret value (blocked in agent mode)
    Get {
        vault_name: String,
        secret_key: String,
    },
    /// List all vaults, or keys in a specific vault
    List { vault_name: Option<String> },
    /// Delete a secret key, or an entire vault if no key given
    Delete {
        vault_name: String,
        secret_key: Option<String>,
    },
    /// Output shell export statements (blocked in agent mode)
    Env { vault_name: String },
    /// Import secrets from a plaintext file (KEY=VALUE or KEY: VALUE per line)
    Import {
        file: String,
        #[arg(long, default_value = "imported", help = "Target vault name")]
        vault: String,
        #[arg(long, help = "Securely delete the source file after import")]
        delete_after: bool,
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
        #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
        command: Vec<String>,
        #[arg(
            long,
            help = "Timeout in milliseconds (default: 86400000 for CLI, 300000 for MCP)"
        )]
        timeout: Option<u64>,
    },
    /// Start MCP server for AI agents
    Mcp,
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
}

#[derive(Args)]
struct CfSecretsArgs {
    list: bool,
    set: Option<String>,
    value: Option<String>,
    delete: Option<String>,
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

    match cli.command {
        Some(Command::Init) => {
            block_in_agent_mode("init");
            cmd_init().await
        }
        Some(Command::Add {
            vault_name,
            key,
            value,
        }) => {
            block_in_agent_mode("add");
            let mut engine = require_unlock();
            match engine.add_secret(&vault_name, &key, &value, None) {
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
        }) => {
            block_in_agent_mode("get");
            let mut engine = require_unlock();
            match engine.get_secret_value(&vault_name, &secret_key, None) {
                Ok(value) => println!("{}", value),
                Err(e) => {
                    eprintln!("{} {}", "✗".red(), e);
                    exit(1);
                }
            }
        }
        Some(Command::List { vault_name }) => cmd_list(&vault_name),
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
        }) => {
            block_in_agent_mode("import");
            cmd_import(&file, &vault, delete_after)
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
        }) => cmd_run(&vault_name, &command, timeout).await,
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
            } => {
                cmd_cf_secrets(
                    &name,
                    &script_name,
                    CfSecretsArgs {
                        list,
                        set,
                        value,
                        delete,
                    },
                )
                .await
            }
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
        None => {
            // No subcommand (piped/non-TTY): print help
            use clap::CommandFactory;
            let mut cli = Cli::command();
            let _ = cli.print_help();
            println!();
        }
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
        std::fs::remove_dir_all(engine.store().dir()).ok();
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

fn cmd_list(vault_name: &Option<String>) {
    let engine = engine();
    if !engine.is_initialized() {
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        exit(1);
    }
    match vault_name {
        None => {
            let vaults = engine.store().list_vaults();
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

fn cmd_import(file: &str, vault_name: &str, delete_after: bool) {
    if !std::path::Path::new(file).exists() {
        eprintln!("{} File not found: {}", "✗".red(), file);
        exit(1);
    }
    let mut engine = require_unlock();

    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} Failed to read file: {}", "✗".red(), e);
            exit(1);
        }
    };

    let mut entries: Map<String, Value> = Map::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        if let Some(eq) = trimmed.find(['=', ':']) {
            let key = trimmed[..eq].trim();
            let mut value = trimmed[eq + 1..].trim().to_string();
            let valid_key = !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
            if !valid_key {
                continue;
            }
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                value = value[1..value.len() - 1].to_string();
            }
            entries.insert(key.to_string(), Value::String(value));
        }
    }

    if entries.is_empty() {
        println!("{} No KEY=VALUE pairs found in file.", "⚠".yellow());
        return;
    }

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
            println!("{} Failed to securely delete source file: {}", "✗".red(), file);
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
    let payload = serde_json::json!({ "vaults": vaults, "config": config });

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
            let _ = engine.update_backup_meta(url);
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

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/backup", url.trim_end_matches('/')))
        .bearer_auth(token)
        .send()
        .await;

    match res {
        Ok(r) if r.status().is_success() => {
            let data: Value = r.json().await.unwrap_or(Value::Null);
            let vaults = data
                .get("vaults")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
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
        "credentails*",
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

async fn cmd_run(vault_name: &str, command: &[String], timeout_ms: Option<u64>) {
    let args: Vec<String> = if command.first().map(|s| s == "--").unwrap_or(false) {
        command[1..].to_vec()
    } else {
        command.to_vec()
    };
    if args.is_empty() {
        eprintln!(
            "{} No command given. Usage: vaultly run <vault> -- <command>",
            "✗".red()
        );
        exit(1);
    }

    let mut engine = require_unlock();
    let cmd_str = args.join(" ");

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
    eprintln!("{} Running: {}\n", "▶".dimmed(), cmd_str);

    let timeout = timeout_ms.unwrap_or(86_400_000);
    let result = engine
        .run_command(vault_name, &cmd_str, None, Some(timeout), None)
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

    if let Some(t) = token {
        let _ = engine.add_secret(&vault_name, "CLOUDFLARE_API_TOKEN", &t, None);
    }
    let had_email = email.is_some();
    let had_api_key = api_key.is_some();
    if let Some(e) = email {
        let _ = engine.add_secret(&vault_name, "CLOUDFLARE_EMAIL", &e, None);
    }
    if let Some(k) = api_key {
        let _ = engine.add_secret(&vault_name, "CLOUDFLARE_API_KEY", &k, None);
    }
    if let Some(id) = account_id {
        let _ = engine.add_secret(&vault_name, "CLOUDFLARE_ACCOUNT_ID", &id, None);
    }

    let auth = if had_email && had_api_key {
        "global API key"
    } else {
        "API token"
    };
    println!(
        "{} Cloudflare account '{}' saved ({})",
        "✓".green(),
        vault_name,
        auth
    );
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

    let result = engine
        .run(
            &vault_name,
            "npx",
            &args,
            Some(project_dir),
            Some(86_400_000),
            None,
        )
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

// ─── cf secrets ─────────────────────────────────────────────

async fn cmd_cf_secrets(name: &str, script_name: &str, opts: CfSecretsArgs) {
    block_in_agent_mode("cf secrets");
    let vault_name = cf_vault(name);
    let mut engine = require_unlock();

    let action = if opts.list {
        "list"
    } else if opts.set.is_some() {
        "set"
    } else if opts.delete.is_some() {
        "delete"
    } else {
        eprintln!(
            "{} Pick an action: --list, --set <key>, or --delete <key>",
            "✗".red()
        );
        exit(1);
    };

    let mut value = opts.value;
    if action == "set" && value.is_none() {
        value = Some(prompt::prompt_password(&format!(
            "Secret value for '{}': ",
            opts.set.clone().unwrap()
        )));
    }

    match engine
        .worker_secrets(
            &vault_name,
            script_name,
            action,
            opts.set.as_deref().or(opts.delete.as_deref()),
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
                    &format!(
                        "Set secret '{}' on '{}'",
                        opts.set.clone().unwrap(),
                        script_name
                    ),
                );
            }
            _ => {
                print_cf_result(
                    &r,
                    &format!(
                        "Deleted secret '{}' from '{}'",
                        opts.delete.clone().unwrap(),
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
        if !v.is_empty() {
            let _ = engine.add_secret(&vault_name, k, &v, None);
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
    let engine = engine();
    if !engine.is_initialized() {
        println!("{} Not initialized. Run: vaultly init", "⚠".yellow());
        return;
    }
    let vaults = engine.store().list_vaults();
    println!("{}", "\n🔐 Vaultly Status\n".bold());
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
}

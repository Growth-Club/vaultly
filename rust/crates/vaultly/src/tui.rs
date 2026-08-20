//! Vaultly TUI — interactive menu for humans.
//! Port of src/tui.ts using `inquire`. Everything routes through VaultEngine
//! (same audit, policy, encryption as CLI/MCP). Human-only: refused in agent mode.

use std::io::IsTerminal;

use colored::Colorize;
use inquire::{Confirm, Password, Select, Text};
use vaultly_core::{keychain, VaultEngine};

trait VaultResultExt<T> {
    fn s(self) -> Result<T, String>;
}

impl<T, E: std::fmt::Display> VaultResultExt<T> for Result<T, E> {
    fn s(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

pub async fn start_tui() {
    if std::env::var("VAULTLY_AGENT_MODE").as_deref() == Ok("1") {
        eprintln!(
            "{} The TUI is blocked in agent mode.\n  Agents use: vaultly run <vault> -- <cmd>  or  vaultly mcp",
            "✗".red()
        );
        std::process::exit(1);
    }

    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{} The TUI is interactive-only. Run it in a terminal (no pipes).",
            "⚠".yellow()
        );
        std::process::exit(0);
    }

    let mut engine = VaultEngine::new(Some(120));

    if !engine.is_initialized() {
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        std::process::exit(1);
    }

    // Unlock: macOS Keychain first, then password prompt
    if keychain::is_keychain_available() {
        if let Some(pw) = keychain::get_from_keychain() {
            if engine.unlock(&pw).is_ok() {
                println!("{} Unlocked from Keychain\n", "✓".dimmed());
            }
        }
    }
    if !engine.is_unlocked() {
        let pw = match Password::new("🔑 Master password:").prompt() {
            Ok(p) => p,
            Err(_) => std::process::exit(1),
        };
        if engine.unlock(&pw).is_err() {
            eprintln!("{} Wrong master password.", "✗".red());
            std::process::exit(1);
        }
    }

    println!("{}", "🔐 Vaultly — interactive".cyan().bold());
    println!(
        "{}",
        "  arrow keys to navigate, enter to select, ctrl+c to exit\n".dimmed()
    );

    loop {
        let action = match Select::new("What do you want to do?", menu_options())
            .with_page_size(14)
            .prompt()
        {
            Ok(a) => a,
            Err(_) => std::process::exit(1),
        };

        let result = match action {
            "list" => tui_list(&mut engine),
            "add" => tui_add(&mut engine),
            "get" => tui_get(&mut engine),
            "delete" => tui_delete(&mut engine),
            "run" => tui_run(&mut engine).await,
            "template" => tui_template(&mut engine),
            "cf_add" => tui_cf_add(&mut engine),
            "cf_zones" => tui_cf_zones(&mut engine).await,
            "cf_deploy" => tui_cf_deploy(&mut engine).await,
            "cf_secrets" => tui_cf_secrets(&mut engine).await,
            "keychain" => tui_keychain(),
            "status" => tui_status(&mut engine),
            "exit" => {
                engine.lock(None);
                println!("{}", "\n🔒 Vault locked. Bye!\n".dimmed());
                std::process::exit(0);
            }
            _ => Ok(()),
        };

        if let Err(e) = result {
            eprintln!("{} {}", "✗".red(), e);
        }
        println!();
    }
}

fn menu_options() -> Vec<&'static str> {
    vec![
        "📋  List vaults & keys",
        "➕  Add / update a secret",
        "🔑  Read a secret value",
        "🗑️  Delete secret or vault",
        "▶️  Run command with secrets",
        "📦  Create vault from template",
        "☁️  Add Cloudflare account",
        "🌐  List accounts & zones",
        "🚀  Deploy a Worker",
        "🔐  Worker secrets",
        "🔒  Keychain (auto-unlock)",
        "📊  Status",
        "🚪  Lock & exit",
    ]
}

fn pick_vault(engine: &mut VaultEngine, message: &str) -> Result<String, String> {
    let vaults = engine.list_vaults(None).s()?;
    if vaults.is_empty() {
        let name = Text::new("No vaults yet. New vault name:")
            .prompt()
            .map_err(|e| e.to_string())?;
        return Ok(name.trim().to_string());
    }
    let mut options = vaults.clone();
    options.push("➕  New vault...".to_string());
    let choice = Select::new(message, options)
        .prompt()
        .map_err(|e| e.to_string())?;
    if choice == "➕  New vault..." {
        let name = Text::new("New vault name:")
            .prompt()
            .map_err(|e| e.to_string())?;
        Ok(name.trim().to_string())
    } else {
        Ok(choice)
    }
}

fn pick_key(engine: &mut VaultEngine, vault_name: &str) -> Result<String, String> {
    let keys = engine.list_keys(vault_name, None).s()?;
    Select::new(&format!("Key in '{}':", vault_name), keys)
        .prompt()
        .map_err(|e| e.to_string())
}

// ─── Actions ──────────────────────────────────────────────

fn tui_list(engine: &mut VaultEngine) -> Result<(), String> {
    let vaults = engine.list_vaults(None).s()?;
    if vaults.is_empty() {
        println!(
            "{}",
            "No vaults yet. Pick 'Add a secret' to create one.".dimmed()
        );
        return Ok(());
    }
    for v in vaults {
        let keys = engine.list_keys(&v, None).s()?;
        let suffix = if keys.is_empty() {
            "(empty)".dimmed().to_string()
        } else {
            format!(" — {}", keys.join(", ")).dimmed().to_string()
        };
        println!("  {}{}", v.cyan(), suffix);
    }
    Ok(())
}

fn tui_add(engine: &mut VaultEngine) -> Result<(), String> {
    let vault_name = pick_vault(engine, "Vault to store in:")?;
    let key = Text::new("Secret name (e.g. GITHUB_TOKEN):")
        .prompt()
        .map_err(|e| e.to_string())?;
    let value = Password::new(&format!("Value for {} (hidden):", key))
        .prompt()
        .map_err(|e| e.to_string())?;
    if key.trim().is_empty() || value.is_empty() {
        return Err("Name and value are required.".into());
    }
    engine.add_secret(&vault_name, key.trim(), &value, None).s()?;
    println!(
        "{} Stored '{}' in '{}'",
        "✓".green(),
        key.trim(),
        vault_name
    );
    Ok(())
}

fn tui_get(engine: &mut VaultEngine) -> Result<(), String> {
    let vault_name = pick_vault(engine, "Vault:")?;
    let key = pick_key(engine, &vault_name)?;
    let value = engine.get_secret_value(&vault_name, &key, None).s()?;
    println!("  {}: {}", key.green(), value);
    Ok(())
}

fn tui_delete(engine: &mut VaultEngine) -> Result<(), String> {
    let vaults = engine.list_vaults(None).s()?;
    if vaults.is_empty() {
        println!("{}", "Nothing to delete.".dimmed());
        return Ok(());
    }
    let vault_name = pick_vault(engine, "Delete from vault:").s()?;
    let keys = engine.list_keys(&vault_name, None).s()?;
    let mut options: Vec<String> = keys.iter().map(|k| format!("Secret: {}", k)).collect();
    options.push(format!("🚨  Whole vault '{}'", vault_name));
    let choice = Select::new(&format!("Delete what from '{}'?", vault_name), options)
        .prompt()
        .map_err(|e| e.to_string())?;

    if let Some(key) = choice.strip_prefix("Secret: ") {
        engine.delete_secret(&vault_name, key, None).s()?;
        println!("{} Deleted '{}'", "✓".green(), key);
    } else {
        let yes = Confirm::new(&format!(
            "Really delete vault '{}'? This cannot be undone.",
            vault_name
        ))
        .with_default(false)
        .prompt()
        .map_err(|e| e.to_string())?;
        if !yes {
            return Ok(());
        }
        engine.delete_vault(&vault_name, None).s()?;
        println!("{} Deleted vault '{}'", "✓".green(), vault_name);
    }
    Ok(())
}

async fn tui_run(engine: &mut VaultEngine) -> Result<(), String> {
    let vault_name = pick_vault(engine, "Vault to inject:").s()?;
    let command = Text::new("Command (e.g. npx wrangler deploy):")
        .prompt()
        .map_err(|e| e.to_string())?;
    if command.trim().is_empty() {
        return Ok(());
    }
    println!("{} {}\n", "▶".dimmed(), command.trim());
    let result = engine
        .run_command(&vault_name, command.trim(), None, None, None)
        .await.s()?;
    if !result.stdout.is_empty() {
        println!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprintln!("{}", result.stderr);
    }
    if result.scrubbed {
        println!("{} Secret values were scrubbed from output.", "⚠".yellow());
    }
    println!("{} Exit code: {}", "".dimmed(), result.code);
    Ok(())
}

fn tui_template(engine: &mut VaultEngine) -> Result<(), String> {
    use crate::templates;

    let options: Vec<String> = templates::TEMPLATES
        .iter()
        .map(|(n, t)| format!("{:<14} {}", n, t.description))
        .collect();
    let pick = Select::new("Template:", options)
        .with_page_size(16)
        .prompt()
        .map_err(|e| e.to_string())?;
    let name = templates::TEMPLATES
        .iter()
        .find(|(n, t)| format!("{:<14} {}", n, t.description) == pick)
        .map(|(n, _)| *n)
        .ok_or("Unknown template")?;
    let tpl = templates::get_template(name).ok_or("Unknown template")?;

    let vault_name = if name == "custom" {
        Text::new("Vault name:")
            .prompt()
            .map_err(|e| e.to_string())?
    } else {
        if Confirm::new(&format!("Use vault name '{}'?", name))
            .with_default(true)
            .prompt()
            .map_err(|e| e.to_string())?
        {
            name.to_string()
        } else {
            Text::new("Vault name:")
                .prompt()
                .map_err(|e| e.to_string())?
        }
    };

    let keys: Vec<String> = if tpl.keys.is_empty() {
        Text::new("Custom key names (comma-separated, e.g. A,B,C):")
            .prompt()
            .map_err(|e| e.to_string())?
            .split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect()
    } else {
        tpl.keys.iter().map(|k| k.to_string()).collect()
    };

    let mut saved = 0;
    for k in &keys {
        let value = Password::new(&format!("  {}:", k))
            .prompt()
            .map_err(|e| e.to_string())?;
        if !value.is_empty() {
            engine.add_secret(vault_name.trim(), k, &value, None).s()?;
            saved += 1;
        }
    }
    println!(
        "{} Vault '{}' created with {} secret(s)",
        "✓".green(),
        vault_name.trim(),
        saved
    );
    Ok(())
}

fn tui_cf_add(engine: &mut VaultEngine) -> Result<(), String> {
    let name = Text::new("Account name (e.g. personal, work):")
        .prompt()
        .map_err(|e| e.to_string())?;
    let vault_name = if name.trim().starts_with("cf-") {
        name.trim().to_string()
    } else {
        format!("cf-{}", name.trim())
    };
    let method = Select::new(
        "Auth method:",
        vec![
            "API token (recommended, scoped)",
            "Global API key (email + key)",
        ],
    )
    .prompt()
    .map_err(|e| e.to_string())?;

    if method.starts_with("API token") {
        let token = Password::new("CLOUDFLARE_API_TOKEN:")
            .prompt()
            .map_err(|e| e.to_string())?;
        if !token.is_empty() {
            engine.add_secret(&vault_name, "CLOUDFLARE_API_TOKEN", &token, None).s()?;
        }
    } else {
        let email = Text::new("CLOUDFLARE_EMAIL:")
            .prompt()
            .map_err(|e| e.to_string())?;
        let api_key = Password::new("CLOUDFLARE_API_KEY:")
            .prompt()
            .map_err(|e| e.to_string())?;
        if !email.trim().is_empty() && !api_key.is_empty() {
            engine.add_secret(&vault_name, "CLOUDFLARE_EMAIL", email.trim(), None).s()?;
            engine.add_secret(&vault_name, "CLOUDFLARE_API_KEY", &api_key, None).s()?;
        }
    }
    let account_id = Text::new("CLOUDFLARE_ACCOUNT_ID:")
        .prompt()
        .map_err(|e| e.to_string())?;
    if !account_id.trim().is_empty() {
        engine
            .add_secret(
                &vault_name,
                "CLOUDFLARE_ACCOUNT_ID",
                account_id.trim(),
                None,
            )
            .s()?;
    }
    println!("{} Cloudflare account '{}' saved", "✓".green(), vault_name);
    Ok(())
}

fn cf_vaults(engine: &mut VaultEngine) -> Result<Vec<String>, String> {
    let vaults: Vec<String> = engine
        .list_vaults(None)
        .s()?
        .into_iter()
        .filter(|v| v.starts_with("cf-"))
        .collect();
    Ok(vaults)
}

async fn tui_cf_zones(engine: &mut VaultEngine) -> Result<(), String> {
    let vaults = cf_vaults(engine)?;
    if vaults.is_empty() {
        println!("{}", "No Cloudflare accounts. Add one first.".dimmed());
        return Ok(());
    }
    let vault_name = Select::new("Account:", vaults.clone())
        .prompt()
        .map_err(|e| e.to_string())?;
    let r = engine
        .cloudflare_api(&vault_name, "GET", "/zones?per_page=50", None, None)
        .await.s()?;
    let zones = r
        .data
        .get("result")
        .and_then(|z| z.as_array())
        .cloned()
        .unwrap_or_default();
    if zones.is_empty() {
        println!("{}", "No zones found (check token permissions).".dimmed());
        return Ok(());
    }
    for z in zones {
        let zone_name = z.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let id = z.get("id").and_then(|i| i.as_str()).unwrap_or("?");
        let status = z.get("status").and_then(|s| s.as_str()).unwrap_or("?");
        println!("  {} ({}, id={})", zone_name.green(), status, id);
    }
    Ok(())
}

async fn tui_cf_deploy(engine: &mut VaultEngine) -> Result<(), String> {
    let vaults = cf_vaults(engine)?;
    if vaults.is_empty() {
        println!("{}", "No Cloudflare accounts. Add one first.".dimmed());
        return Ok(());
    }
    let vault_name = Select::new("Account:", vaults.clone())
        .prompt()
        .map_err(|e| e.to_string())?;
    let project_dir = Text::new("Worker project directory:")
        .prompt()
        .map_err(|e| e.to_string())?;
    if project_dir.trim().is_empty() {
        return Ok(());
    }
    let result = engine
        .run_command(
            &vault_name,
            "npx wrangler deploy",
            Some(project_dir.trim()),
            Some(86_400_000),
            None,
        )
        .await.s()?;
    if !result.stdout.is_empty() {
        println!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprintln!("{}", result.stderr);
    }
    println!("{} Exit code: {}", "".dimmed(), result.code);
    Ok(())
}

async fn tui_cf_secrets(engine: &mut VaultEngine) -> Result<(), String> {
    let vaults = cf_vaults(engine)?;
    if vaults.is_empty() {
        println!("{}", "No Cloudflare accounts. Add one first.".dimmed());
        return Ok(());
    }
    let vault_name = Select::new("Account:", vaults.clone())
        .prompt()
        .map_err(|e| e.to_string())?;
    let script_name = Text::new("Worker script name:")
        .prompt()
        .map_err(|e| e.to_string())?;
    if script_name.trim().is_empty() {
        return Ok(());
    }
    let action = Select::new(
        &format!("Secrets for '{}':", script_name.trim()),
        vec!["📋  List", "➕  Set a secret", "🗑️  Delete a secret"],
    )
    .prompt()
    .map_err(|e| e.to_string())?;

    if action.contains("List") {
        let r = engine
            .worker_secrets(&vault_name, script_name.trim(), "list", None, None, None)
            .await.s()?;
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
        if names.is_empty() {
            println!("{}", "No secrets on this Worker.".dimmed());
        } else {
            for n in names {
                println!("  - {}", n);
            }
        }
        return Ok(());
    }

    let name = Text::new("Secret name:")
        .prompt()
        .map_err(|e| e.to_string())?;
    if name.trim().is_empty() {
        return Ok(());
    }
    if action.contains("Set") {
        let value = Password::new(&format!("Value for {} (hidden):", name.trim()))
            .prompt()
            .map_err(|e| e.to_string())?;
        if value.is_empty() {
            return Ok(());
        }
        engine
            .worker_secrets(
                &vault_name,
                script_name.trim(),
                "set",
                Some(name.trim()),
                Some(&value),
                None,
            )
            .await.s()?;
        println!(
            "{} Set '{}' on '{}'",
            "✓".green(),
            name.trim(),
            script_name.trim()
        );
    } else {
        engine
            .worker_secrets(
                &vault_name,
                script_name.trim(),
                "delete",
                Some(name.trim()),
                None,
                None,
            )
            .await.s()?;
        println!(
            "{} Deleted '{}' from '{}'",
            "✓".green(),
            name.trim(),
            script_name.trim()
        );
    }
    Ok(())
}

fn tui_keychain() -> Result<(), String> {
    if !keychain::is_keychain_available() {
        println!("{}", "Keychain not available (macOS only).".dimmed());
        return Ok(());
    }
    let has_entry = keychain::keychain_entry_exists();
    let mut options: Vec<String> = vec![];
    if has_entry {
        options.push("🗑️  Remove entry (password needed every time)".to_string());
    }
    options.push("🔒  Store master password (auto-unlock)".to_string());
    options.push("📊  Status".to_string());

    let action = Select::new(
        if has_entry {
            "Keychain entry exists. What next?"
        } else {
            "No keychain entry yet."
        },
        options,
    )
    .prompt()
    .map_err(|e| e.to_string())?;

    if action.contains("Store") {
        let pw = Password::new("Master password to store:")
            .prompt()
            .map_err(|e| e.to_string())?;
        if keychain::store_in_keychain(&pw) {
            println!(
                "{} Stored — MCP server and TUI will auto-unlock.",
                "✓".green()
            );
        } else {
            eprintln!("{} Failed to store in Keychain.", "✗".red());
        }
    } else if action.contains("Remove") {
        keychain::delete_from_keychain();
        println!("{} Removed from Keychain.", "✓".green());
    } else {
        println!(
            "{}",
            if keychain::keychain_entry_exists() {
                "  Keychain: stored ✓".green().to_string()
            } else {
                "  Keychain: not stored".dimmed().to_string()
            }
        );
    }
    Ok(())
}

fn tui_status(engine: &mut VaultEngine) -> Result<(), String> {
    let vaults = engine.list_vaults(None).s()?;
    let ttl_min = engine.session_expires_in() / 60;
    println!("  Unlocked: {}", "yes".green());
    println!("  Session:  ~{} min remaining", ttl_min);
    println!(
        "  Vaults:   {}",
        if vaults.is_empty() {
            "none".to_string()
        } else {
            vaults.join(", ")
        }
    );
    println!(
        "  Keychain: {}",
        if !keychain::is_keychain_available() {
            "not available (macOS only)".dimmed().to_string()
        } else if keychain::keychain_entry_exists() {
            "stored ✓".green().to_string()
        } else {
            "not stored".dimmed().to_string()
        }
    );
    Ok(())
}

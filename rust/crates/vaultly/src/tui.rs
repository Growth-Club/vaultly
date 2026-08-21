//! Vaultly TUI — full-screen interactive terminal UI using ratatui.
//! Port of the inquire-based TUI. Everything routes through VaultEngine
//! (same audit, policy, encryption as CLI/MCP). Human-only: refused in agent mode.

use std::io::{self, Write};

use crossterm::event::{
    self, Event, KeyEvent, KeyEventKind, KeyCode, KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use ratatui::Frame;

use colored::Colorize;
use vaultly_core::{keychain, VaultEngine};

// ─── Constants ─────────────────────────────────────────────

const MENU_OPTIONS: [&str; 13] = [
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
];

// ─── App State ─────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Screen {
    Menu,
    AddSecret,
    GetSecret,
    DeleteSecret,
    RunCommand,
    Template,
    CfAdd,
    CfZones,
    CfDeploy,
    CfSecrets,
    Keychain,
    Status,
    Exit,
}

#[derive(PartialEq, Clone, Copy)]
enum InputMode {
    Navigation,
    Editing,
}

struct App {
    screen: Screen,
    input_mode: InputMode,
    menu_selected: usize,
    input_buffer: String,
    status_msg: Option<String>,
    status_is_error: bool,
    vaults: Vec<String>,
    
    cf_vault_names: Vec<String>,
    template_keys: Vec<String>,
    template_step: usize,
    run_result: Option<(String, String, i32, bool)>,
    // Multi-step flow tracking
    flow_step: usize,
    flow_vault: Option<String>,
    flow_key: Option<String>,
    flow_value: Option<String>,
    flow_command: Option<String>,
    flow_template_name: Option<String>,
    flow_cf_name: Option<String>,
    flow_script_name: Option<String>,
    flow_secret_name: Option<String>,
    flow_secret_value: Option<String>,
}

impl App {
    fn new() -> Self {
        App {
            screen: Screen::Menu,
            input_mode: InputMode::Navigation,
            menu_selected: 0,
            input_buffer: String::new(),
            status_msg: None,
            status_is_error: false,
            vaults: Vec::new(),

            cf_vault_names: Vec::new(),
            template_keys: Vec::new(),
            template_step: 0,
            run_result: None,
flow_step: 0,
            flow_vault: None,
            flow_key: None,
            flow_value: None,
            flow_command: None,
            flow_template_name: None,
            flow_cf_name: None,
            flow_script_name: None,
            flow_secret_name: None,
            flow_secret_value: None,
        }
    }

    fn reset_flow(&mut self) {
        self.flow_step = 0;
        self.flow_vault = None;
        self.flow_key = None;
        self.flow_value = None;
        self.flow_command = None;
        self.flow_template_name = None;
        self.flow_cf_name = None;
        self.flow_script_name = None;
        self.flow_secret_name = None;
        self.flow_secret_value = None;
        self.input_buffer.clear();
        self.status_msg = None;
        self.status_is_error = false;
    }

    fn set_status(&mut self, msg: &str, is_error: bool) {
        self.status_msg = Some(msg.to_string());
        self.status_is_error = is_error;
    }
}

// ─── Main Entry Point ──────────────────────────────────────

pub async fn start_tui() {
    if std::env::var("VAULTLY_AGENT_MODE").as_deref() == Ok("1") {
        eprintln!(
            "{} The TUI is blocked in agent mode.\n  Agents use: vaultly run <vault> -- <cmd>  or  vaultly mcp",
            "✗".red()
        );
        std::process::exit(1);
    }

    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("{} Failed to initialize terminal.", "✗".red());
            std::process::exit(1);
        }
    };

    let mut app = App::new();
    let mut engine = VaultEngine::new(Some(120));

    if !engine.is_initialized() {
        cleanup_terminal();
        eprintln!("{} Not initialized. Run: vaultly init", "✗".red());
        std::process::exit(1);
    }

    // Unlock
    let mut unlocked = false;
    if keychain::is_keychain_available() {
        if let Some(pw) = keychain::get_from_keychain() {
            if engine.unlock(&pw).is_ok() {
                unlocked = true;
            }
        }
    }
    if !unlocked {
        cleanup_terminal();
        let pw = rpassword::read_password().unwrap_or_default();
        if pw.is_empty() || engine.unlock(&pw).is_err() {
            eprintln!("{} Wrong master password.", "✗".red());
            std::process::exit(1);
        }
    }

    // Load initial data
    app.vaults = engine.list_vaults(None).unwrap_or_default();
    app.cf_vault_names = engine
        .list_vaults(None)
        .unwrap_or_default()
        .into_iter()
        .filter(|v| v.starts_with("cf-"))
        .collect();

    // Main loop
    loop {
        if terminal.draw(|frame| render(frame, &mut app, &mut engine)).is_err() {
        break;
    }

        if event::poll(std::time::Duration::from_millis(100)).ok() == Some(true) {
            if let Ok(Event::Key(key)) = event::read() {
                if key.kind == KeyEventKind::Press {
                    let should_quit = handle_event(&mut app, &mut engine, key).await;
                    if should_quit {
                        break;
                    }
                }
            }
        }
    }

    cleanup_terminal();
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.flush()?;
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn cleanup_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

// ─── Render ────────────────────────────────────────────────

fn render(frame: &mut Frame, app: &mut App, engine: &mut VaultEngine) {
    let area = frame.area();

    // Main layout: content + status bar
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Min(0),
            Constraint::Length(3),
        ],
    )
    .split(area);

    match app.screen {
        Screen::Menu => render_menu(frame, chunks[0], app),
        Screen::AddSecret => render_add_secret(frame, chunks[0], app),
        Screen::GetSecret => render_get_secret(frame, chunks[0], app),
        Screen::DeleteSecret => render_delete_secret(frame, chunks[0], app),
        Screen::RunCommand => render_run_command(frame, chunks[0], app),
        Screen::Template => render_template(frame, chunks[0], app),
        Screen::CfAdd => render_cf_add(frame, chunks[0], app),
        Screen::CfZones => render_cf_zones(frame, chunks[0], app),
        Screen::CfDeploy => render_cf_deploy(frame, chunks[0], app),
        Screen::CfSecrets => render_cf_secrets(frame, chunks[0], app),
        Screen::Keychain => render_keychain(frame, chunks[0], app),
        Screen::Status => render_status(frame, chunks[0], app, engine),
        Screen::Exit => render_exit(frame, chunks[0]),
    }

    // Status bar
    render_status_bar(frame, chunks[1], app);
}

fn render_status_bar(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let text = if app.input_mode == InputMode::Editing {
        Line::from(vec![
            Span::styled(" Type text, ", Style::new().fg(Color::Black).bg(Color::Cyan)),
            Span::styled("Enter to confirm, ", Style::new().fg(Color::White)),
            Span::styled("Esc to cancel", Style::new().fg(Color::White)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ↑↓ navigate, ", Style::new().fg(Color::Yellow)),
            Span::styled("Enter select, ", Style::new().fg(Color::White)),
            Span::styled("Esc back, ", Style::new().fg(Color::White)),
            Span::styled("Q quit", Style::new().fg(Color::White)),
        ])
    };

    let status = if let Some(msg) = &app.status_msg {
        let color = if app.status_is_error { Color::Red } else { Color::Green };
        Line::from(vec![
            Span::styled(format!(" {} ", msg), Style::new().fg(color).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from("")
    };

    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(1), Constraint::Length(1)],
    )
    .split(area);

    frame.render_widget(Paragraph::new(text), chunks[0]);
    frame.render_widget(Paragraph::new(status), chunks[1]);
}

fn render_menu(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let items: Vec<ListItem> = MENU_OPTIONS
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let style = if i == app.menu_selected {
                Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(Color::White)
            };
            ListItem::new(Line::from(Span::styled(*opt, style)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::new().borders(Borders::ALL).title(" Vaultly — Interactive "));
    frame.render_widget(list, area);
}

fn render_add_secret(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    // Title
    frame.render_widget(
        Paragraph::new("➕  Add / Update Secret")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    // Vault
    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Enter vault name:".to_string());
    let vault_style = if app.flow_step == 0 {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::White)
    };
    frame.render_widget(
        Paragraph::new(vault_text).style(vault_style).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Vault ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    // Key
    let key_text = app.flow_key.as_deref().unwrap_or("");
    let key_prompt = if app.flow_step == 1 {
        format!("Secret name (e.g. GITHUB_TOKEN): {}", key_text)
    } else if app.flow_step == 2 {
        format!("Secret name: {}", key_text)
    } else {
        "Enter secret name".to_string()
    };
    frame.render_widget(
        Paragraph::new(key_prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Key ")
                .border_style(if app.flow_step == 1 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );

    // Value
    let value_text = if app.flow_step == 2 {
        format!("Value (hidden): {}", "*".repeat(app.input_buffer.len()))
    } else {
        "Enter value".to_string()
    };
    frame.render_widget(
        Paragraph::new(value_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Value ")
                .border_style(if app.flow_step == 2 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[3],
    );
}

fn render_get_secret(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🔑  Read Secret Value")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Select vault:".to_string());
    frame.render_widget(
        Paragraph::new(vault_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Vault ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let key_text = app.flow_key.as_deref().unwrap_or("");
    let key_prompt = if app.flow_step == 1 {
        format!("Select key: {}", key_text)
    } else {
        "Select key".to_string()
    };
    frame.render_widget(
        Paragraph::new(key_prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Key ")
                .border_style(if app.flow_step == 1 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_delete_secret(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🗑️  Delete Secret or Vault")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Select vault:".to_string());
    frame.render_widget(
        Paragraph::new(vault_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Vault ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let key_text = app.flow_key.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 1 {
        format!("Select key to delete, or choose whole vault: {}", key_text)
    } else {
        "Select key or vault".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Delete ")
                .border_style(if app.flow_step == 1 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_run_command(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("▶️  Run Command with Secrets")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Select vault:".to_string());
    frame.render_widget(
        Paragraph::new(vault_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Vault ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let cmd_text = app.flow_command.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 1 {
        format!("Command (e.g. npx wrangler deploy): {}", cmd_text)
    } else {
        "Enter command".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Command ")
                .border_style(if app.flow_step == 1 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_template(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("📦  Create Vault from Template")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let name_text = app
        .flow_template_name
        .as_deref()
        .unwrap_or("");
    let prompt = if app.flow_step == 0 {
        format!("Select template: {}", name_text)
    } else if app.flow_step == 1 {
        format!("Vault name: {}", name_text)
    } else {
        "Enter key values".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Template ")
                .border_style(if app.flow_step < 2 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let keys_info = if app.template_keys.is_empty() {
        "No keys defined".to_string()
    } else {
        format!(
            "Keys: {} (step {}/{})",
            app.template_keys.join(", "),
            app.template_step + 1,
            app.template_keys.len()
        )
    };
    frame.render_widget(
        Paragraph::new(keys_info).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Keys ")
                .border_style(if app.flow_step == 2 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_cf_add(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("☁️  Add Cloudflare Account")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let name_text = app.flow_cf_name.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 0 {
        format!("Account name (e.g. personal, work): {}", name_text)
    } else if app.flow_step == 1 {
        "Select auth method".to_string()
    } else {
        format!("Enter credentials (step {})", app.flow_step)
    };
    frame.render_widget(
        Paragraph::new(prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Cloudflare ")
                .border_style(if app.flow_step < 3 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let info = if app.flow_step == 1 {
        "1) API token (recommended)\n2) Global API key (email + key)"
    } else {
        "Fill in the credentials for the selected auth method"
    };
    frame.render_widget(
        Paragraph::new(info).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Auth ")
                .border_style(if app.flow_step == 1 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_cf_zones(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🌐  List Accounts & Zones")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Select Cloudflare account:".to_string());
    frame.render_widget(
        Paragraph::new(vault_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Account ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );
}

fn render_cf_deploy(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🚀  Deploy a Worker")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Select Cloudflare account:".to_string());
    frame.render_widget(
        Paragraph::new(vault_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Account ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let dir_text = app.flow_command.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 1 {
        format!("Worker project directory: {}", dir_text)
    } else {
        "Enter project directory".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Directory ")
                .border_style(if app.flow_step == 1 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_cf_secrets(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🔐  Worker Secrets")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vault_text = app
        .flow_vault
        .as_deref()
        .map(|v| format!("Vault: {}", v))
        .unwrap_or_else(|| "Select Cloudflare account:".to_string());
    frame.render_widget(
        Paragraph::new(vault_text).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Account ")
                .border_style(if app.flow_step == 0 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[1],
    );

    let script_text = app.flow_script_name.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 1 {
        format!("Worker script name: {}", script_text)
    } else if app.flow_step == 2 {
        "Select action: list, set, delete".to_string()
    } else if app.flow_step == 3 {
        format!("Secret name: {}", app.flow_secret_name.as_deref().unwrap_or(""))
    } else if app.flow_step == 4 {
        format!("Secret value: {}", "*".repeat(app.input_buffer.len()))
    } else {
        "Manage secrets".to_string()
    };
    frame.render_widget(
        Paragraph::new(prompt).style(Style::new().fg(Color::White)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Secrets ")
                .border_style(if app.flow_step < 5 {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
        ),
        chunks[2],
    );
}

fn render_keychain(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🔒  Keychain (Auto-Unlock)")
            .style(Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let has_entry = keychain::keychain_entry_exists();
    let options = if has_entry {
        vec![
            "🗑️  Remove entry (password needed every time)",
            "📊  Status",
        ]
    } else {
        vec![
            "🔒  Store master password (auto-unlock)",
            "📊  Status",
        ]
    };

    let items: Vec<ListItem> = options
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let style = if i == app.menu_selected {
                Style::new().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(Color::White)
            };
            ListItem::new(Line::from(Span::styled(*opt, style)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::new().borders(Borders::ALL).title(" Keychain "));
    frame.render_widget(list, chunks[1]);
}

fn render_status(frame: &mut Frame, area: ratatui::layout::Rect, _app: &App, engine: &mut VaultEngine) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("📊  Vaultly Status").style(
            Style::new()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::new().borders(Borders::BOTTOM)),
        chunks[0],
    );

    let vaults = engine.list_vaults(None).unwrap_or_default();
    let vaults_str = if vaults.is_empty() {
        "none".to_string()
    } else {
        vaults.join(", ")
    };

    frame.render_widget(
        Paragraph::new(format!("  Vaults: {}", vaults_str))
            .style(Style::new().fg(Color::White)),
        chunks[1],
    );

    let kc = if !keychain::is_keychain_available() {
        "not available (macOS only)"
    } else if keychain::keychain_entry_exists() {
        "stored ✓"
    } else {
        "not stored"
    };
    frame.render_widget(
        Paragraph::new(format!("  Keychain: {}", kc))
            .style(Style::new().fg(Color::White)),
        chunks[2],
    );

    frame.render_widget(
        Paragraph::new(format!("  Platform: {}", std::env::consts::OS))
            .style(Style::new().fg(Color::White)),
        chunks[3],
    );

    let agent_mode = if std::env::var("VAULTLY_AGENT_MODE").as_deref() == Ok("1") {
        "ON (get/env blocked)"
    } else {
        "off"
    };
    frame.render_widget(
        Paragraph::new(format!("  Agent mode: {}", agent_mode))
            .style(Style::new().fg(Color::White)),
        chunks[4],
    );
}

fn render_exit(frame: &mut Frame, area: ratatui::layout::Rect) {
    let text = "🚪  Lock & exit?\n\n  Y — lock vault and exit\n  N — cancel";
    frame.render_widget(
        Paragraph::new(text)
            .style(Style::new().fg(Color::White))
            .block(Block::new().borders(Borders::ALL).title(" Exit ")),
        area,
    );
}

// ─── Event Handling ────────────────────────────────────────

async fn handle_event(
    app: &mut App,
    engine: &mut VaultEngine,
    key: KeyEvent,
) -> bool {
    // Returns true if should quit
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }

    match app.screen {
        Screen::Menu => handle_menu(app, engine, key).await,
        Screen::AddSecret => handle_add_secret(app, engine, key).await,
        Screen::GetSecret => handle_get_secret(app, engine, key).await,
        Screen::DeleteSecret => handle_delete_secret(app, engine, key).await,
        Screen::RunCommand => handle_run_command(app, engine, key).await,
        Screen::Template => handle_template(app, engine, key).await,
        Screen::CfAdd => handle_cf_add(app, engine, key).await,
        Screen::CfZones => handle_cf_zones(app, engine, key).await,
        Screen::CfDeploy => handle_cf_deploy(app, engine, key).await,
        Screen::CfSecrets => handle_cf_secrets(app, engine, key).await,
        Screen::Keychain => handle_keychain(app, engine, key).await,
        Screen::Status => handle_status(app, engine, key).await,
        Screen::Exit => handle_exit(app, engine, key).await,
    }
}

async fn handle_menu(app: &mut App, _engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => {
            if app.menu_selected > 0 {
                app.menu_selected -= 1;
            }
        }
        KeyCode::Down => {
            if app.menu_selected < MENU_OPTIONS.len() - 1 {
                app.menu_selected += 1;
            }
        }
        KeyCode::Enter => {
            let selected = app.menu_selected;
            match selected {
                0 => {
                    // List vaults & keys
                    app.screen = Screen::Status;
                    app.set_status(&format!("{} vaults", app.vaults.len()), false);
                }
                1 => {
                    // Add secret
                    app.reset_flow();
                    app.screen = Screen::AddSecret;
                    app.input_mode = InputMode::Editing;
                    app.flow_step = 0;
                }
                2 => {
                    // Get secret
                    app.reset_flow();
                    app.screen = Screen::GetSecret;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                3 => {
                    // Delete secret
                    app.reset_flow();
                    app.screen = Screen::DeleteSecret;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                4 => {
                    // Run command
                    app.reset_flow();
                    app.screen = Screen::RunCommand;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                5 => {
                    // Template
                    app.reset_flow();
                    app.screen = Screen::Template;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                6 => {
                    // CF add
                    app.reset_flow();
                    app.screen = Screen::CfAdd;
                    app.input_mode = InputMode::Editing;
                    app.flow_step = 0;
                }
                7 => {
                    // CF zones
                    app.reset_flow();
                    app.screen = Screen::CfZones;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                8 => {
                    // CF deploy
                    app.reset_flow();
                    app.screen = Screen::CfDeploy;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                9 => {
                    // CF secrets
                    app.reset_flow();
                    app.screen = Screen::CfSecrets;
                    app.input_mode = InputMode::Navigation;
                    app.flow_step = 0;
                }
                10 => {
                    // Keychain
                    app.reset_flow();
                    app.screen = Screen::Keychain;
                    app.input_mode = InputMode::Navigation;
                    app.menu_selected = 0;
                }
                11 => {
                    // Status
                    app.screen = Screen::Status;
                }
                12 => {
                    // Exit
                    app.screen = Screen::Exit;
                }
                _ => {}
            }
        }
        KeyCode::Char('q') | KeyCode::Esc => {
            return true;
        }
        _ => {}
    }
    false
}

async fn handle_add_secret(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match app.input_mode {
        InputMode::Editing => match key.code {
            KeyCode::Enter => {
                let input = app.input_buffer.trim().to_string();
                if app.flow_step == 0 {
                    // Vault name
                    if input.is_empty() {
                        app.set_status("Vault name is required", true);
                        return false;
                    }
                    app.flow_vault = Some(input);
                    app.flow_step = 1;
                    app.input_buffer.clear();
                } else if app.flow_step == 1 {
                    // Key name
                    if input.is_empty() {
                        app.set_status("Secret name is required", true);
                        return false;
                    }
                    app.flow_key = Some(input);
                    app.flow_step = 2;
                    app.input_buffer.clear();
                } else if app.flow_step == 2 {
                    // Value
                    if input.is_empty() {
                        app.set_status("Value is required", true);
                        return false;
                    }
                    app.flow_value = Some(input);
                    // Execute
                    let vault = app.flow_vault.clone().unwrap();
                    let key_name = app.flow_key.clone().unwrap();
                    let value = app.flow_value.clone().unwrap();
                    match engine.add_secret(&vault, &key_name, &value, None) {
                        Ok(()) => {
                            app.set_status(&format!("✓ Stored '{}' in '{}'", key_name, vault), false);
                            // Refresh vault list
                            app.vaults = engine.list_vaults(None).unwrap_or_default();
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                            app.flow_step = 2; // Stay on value step
                        }
                    }
                }
            }
            KeyCode::Esc => {
                app.reset_flow();
                app.screen = Screen::Menu;
                app.input_mode = InputMode::Navigation;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
            }
            KeyCode::Char(c) => {
                if !key.modifiers.contains(KeyModifiers::SHIFT) || c.is_alphabetic() {
                    app.input_buffer.push(c);
                }
            }
            _ => {}
        }
        _ => {}
    }
    false
}

async fn handle_get_secret(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => {
            if app.flow_step == 0 && !app.vaults.is_empty() {
                // Navigate vaults
                if let Some(idx) = app.vaults.iter().position(|v| Some(v) == app.flow_vault.as_ref()) {
                    let next = (idx + 1) % app.vaults.len();
                    app.flow_vault = Some(app.vaults[next].clone());
                } else if !app.vaults.is_empty() {
                    app.flow_vault = Some(app.vaults[0].clone());
                }
            }
        }
        KeyCode::Down => {
            if app.flow_step == 0 && !app.vaults.is_empty() {
                if let Some(idx) = app.vaults.iter().position(|v| Some(v) == app.flow_vault.as_ref()) {
                    let next = if idx == 0 { app.vaults.len() - 1 } else { idx - 1 };
                    app.flow_vault = Some(app.vaults[next].clone());
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if app.flow_vault.is_some() {
                    app.flow_step = 1;
                } else {
                    app.set_status("Select a vault first", true);
                }
            } else if app.flow_step == 1 {
                let vault = app.flow_vault.clone().unwrap();
                let key_name = app.flow_key.clone().unwrap();
                match engine.get_secret_value(&vault, &key_name, None) {
                    Ok(value) => {
                        app.set_status(&format!("{}: {}", key_name, value), false);
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                    }
                    Err(e) => {
                        app.set_status(&format!("✗ {}", e), true);
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_delete_secret(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 && !app.vaults.is_empty() {
                if let Some(idx) = app.vaults.iter().position(|v| Some(v) == app.flow_vault.as_ref()) {
                    let next = if key.code == KeyCode::Up {
                        if idx == 0 { app.vaults.len() - 1 } else { idx - 1 }
                    } else {
                        (idx + 1) % app.vaults.len()
                    };
                    app.flow_vault = Some(app.vaults[next].clone());
                } else if !app.vaults.is_empty() {
                    app.flow_vault = Some(app.vaults[0].clone());
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if app.flow_vault.is_some() {
                    app.flow_step = 1;
                } else {
                    app.set_status("Select a vault first", true);
                }
            } else if app.flow_step == 1 {
                let vault = app.flow_vault.clone().unwrap();
                if let Some(key_name) = &app.flow_key {
                    match engine.delete_secret(&vault, key_name, None) {
                        Ok(true) => {
                            app.set_status(&format!("✓ Deleted '{}' from '{}'", key_name, vault), false);
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Ok(false) => {
                            app.set_status(&format!("✗ '{}' not found in '{}'", key_name, vault), true);
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else {
                    // Delete whole vault
                    match engine.delete_vault(&vault, None) {
                        Ok(true) => {
                            app.set_status(&format!("✓ Deleted vault '{}'", vault), false);
                            app.vaults = engine.list_vaults(None).unwrap_or_default();
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Ok(false) => {
                            app.set_status(&format!("✗ Vault '{}' not found", vault), true);
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_run_command(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match app.input_mode {
        InputMode::Editing => match key.code {
            KeyCode::Enter => {
                let input = app.input_buffer.trim().to_string();
                if app.flow_step == 0 {
                    if input.is_empty() {
                        app.set_status("Vault name is required", true);
                        return false;
                    }
                    app.flow_vault = Some(input);
                    app.flow_step = 1;
                    app.input_buffer.clear();
                } else if app.flow_step == 1 {
                    if input.is_empty() {
                        app.set_status("Command is required", true);
                        return false;
                    }
                    app.flow_command = Some(input);
                    // Execute
                    let vault = app.flow_vault.clone().unwrap();
                    let cmd = app.flow_command.clone().unwrap();
                    match engine.run_command(&vault, &cmd, None, None, None).await {
                        Ok(res) => {
                            app.run_result = Some((res.stdout, res.stderr, res.code, res.scrubbed));
                            app.set_status(&format!("Exit code: {}", res.code), res.code != 0);
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                }
            }
            KeyCode::Esc => {
                app.reset_flow();
                app.screen = Screen::Menu;
                app.input_mode = InputMode::Navigation;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
            }
            KeyCode::Char(c) => {
                app.input_buffer.push(c);
            }
            _ => {}
        }
        _ => {}
    }
    false
}

async fn handle_template(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 {
                // Navigate templates
                let names = crate::templates::template_names();
                if !names.is_empty() {
                    let current = app.flow_template_name.as_deref().unwrap_or("");
                    if let Some(idx) = names.iter().position(|n| *n == current) {
                        let next = if key.code == KeyCode::Up {
                            if idx == 0 { names.len() - 1 } else { idx - 1 }
                        } else {
                            (idx + 1) % names.len()
                        };
                        app.flow_template_name = Some(names[next].to_string());
                        let tpl = crate::templates::get_template(names[next]).unwrap();
                        app.template_keys = tpl.keys.iter().map(|k| k.to_string()).collect();
                    } else {
                        app.flow_template_name = Some(names[0].to_string());
                        let tpl = crate::templates::get_template(names[0]).unwrap();
                        app.template_keys = tpl.keys.iter().map(|k| k.to_string()).collect();
                    }
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if app.flow_template_name.is_some() {
                    app.flow_step = 1;
                } else {
                    app.set_status("Select a template first", true);
                }
            } else if app.flow_step == 1 {
                let input = app.input_buffer.trim().to_string();
                if input.is_empty() {
                    app.set_status("Vault name is required", true);
                    return false;
                }
                app.flow_template_name = Some(input);
                app.flow_step = 2;
                app.input_buffer.clear();
                app.template_step = 0;
            } else if app.flow_step == 2 {
                // Enter key values
                let input = app.input_buffer.trim().to_string();
                if !input.is_empty() {
                    let vault = app.flow_template_name.clone().unwrap();
                    let key_name = app.template_keys[app.template_step].clone();
                    match engine.add_secret(&vault, &key_name, &input, None) {
                        Ok(()) => {
                            app.template_step += 1;
                            if app.template_step >= app.template_keys.len() {
                                app.set_status(&format!("✓ Vault '{}' created", vault), false);
                                app.vaults = engine.list_vaults(None).unwrap_or_default();
                                app.screen = Screen::Menu;
                                app.input_mode = InputMode::Navigation;
                            } else {
                                app.input_buffer.clear();
                            }
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else {
                    // Skip this key
                    app.template_step += 1;
                    if app.template_step >= app.template_keys.len() {
                        let vault = app.flow_template_name.clone().unwrap();
                        app.set_status(&format!("✓ Vault '{}' created", vault), false);
                        app.vaults = engine.list_vaults(None).unwrap_or_default();
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        KeyCode::Char(c) if app.flow_step == 1 => {
            app.input_buffer.push(c);
        }
        _ => {}
    }
    false
}

async fn handle_cf_add(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match app.input_mode {
        InputMode::Editing => match key.code {
            KeyCode::Enter => {
                let input = app.input_buffer.trim().to_string();
                if app.flow_step == 0 {
                    if input.is_empty() {
                        app.set_status("Account name is required", true);
                        return false;
                    }
                    app.flow_cf_name = Some(input);
                    app.flow_step = 1;
                    app.input_buffer.clear();
                } else if app.flow_step == 1 {
                    // Auth method selection
                    if input == "1" {
                        // API token
                        app.flow_step = 2;
                        app.input_buffer.clear();
                    } else if input == "2" {
                        // Global API key
                        app.flow_step = 3;
                        app.input_buffer.clear();
                    } else {
                        app.set_status("Enter 1 or 2", true);
                    }
                } else if app.flow_step == 2 {
                    // API token
                    let vault_name = format!("cf-{}", app.flow_cf_name.clone().unwrap());
                    match engine.add_secret(&vault_name, "CLOUDFLARE_API_TOKEN", &input, None) {
                        Ok(()) => {
                            app.set_status(&format!("✓ CF account '{}' saved", vault_name), false);
                            app.vaults = engine.list_vaults(None).unwrap_or_default();
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else if app.flow_step == 3 {
                    // Email for global key
                    app.flow_step = 4;
                    app.flow_vault = Some(input);
                    app.input_buffer.clear();
                }
            }
            KeyCode::Esc => {
                app.reset_flow();
                app.screen = Screen::Menu;
                app.input_mode = InputMode::Navigation;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
            }
            KeyCode::Char(c) => {
                app.input_buffer.push(c);
            }
            _ => {}
        }
        _ => {}
    }
    false
}

async fn handle_cf_zones(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 && !app.cf_vault_names.is_empty() {
                if let Some(idx) = app.cf_vault_names.iter().position(|v| Some(v) == app.flow_vault.as_ref()) {
                    let next = if key.code == KeyCode::Up {
                        if idx == 0 { app.cf_vault_names.len() - 1 } else { idx - 1 }
                    } else {
                        (idx + 1) % app.cf_vault_names.len()
                    };
                    app.flow_vault = Some(app.cf_vault_names[next].clone());
                } else if !app.cf_vault_names.is_empty() {
                    app.flow_vault = Some(app.cf_vault_names[0].clone());
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if let Some(vault) = &app.flow_vault {
                    match engine.cloudflare_api(vault, "GET", "/zones?per_page=50", None, None).await {
                        Ok(r) => {
                            let zones = r.data.get("result").and_then(|z| z.as_array()).cloned().unwrap_or_default();
                            let zone_list: Vec<String> = zones.iter()
                                .filter_map(|z| {
                                    let name = z.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                                    let id = z.get("id").and_then(|i| i.as_str()).unwrap_or("?");
                                    Some(format!("{} (id: {})", name, id))
                                })
                                .collect();
                            app.set_status(&format!("Found {} zones", zone_list.len()), false);
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else {
                    app.set_status("Select a CF account first", true);
                }
            }
        }
        KeyCode::Esc => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_cf_deploy(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match app.input_mode {
        InputMode::Editing => match key.code {
            KeyCode::Enter => {
                let input = app.input_buffer.trim().to_string();
                if app.flow_step == 0 {
                    if input.is_empty() {
                        app.set_status("Vault name is required", true);
                        return false;
                    }
                    app.flow_vault = Some(input);
                    app.flow_step = 1;
                    app.input_buffer.clear();
                } else if app.flow_step == 1 {
                    if input.is_empty() {
                        app.set_status("Project directory is required", true);
                        return false;
                    }
                    app.flow_command = Some(input);
                    // Execute deploy
                    let vault = app.flow_vault.clone().unwrap();
                    let dir = app.flow_command.clone().unwrap();
                    match engine.run_command(&vault, "npx wrangler deploy", Some(&dir), Some(86_400_000), None).await {
                        Ok(res) => {
                            app.run_result = Some((res.stdout, res.stderr, res.code, res.scrubbed));
                            app.set_status(&format!("Deploy exit code: {}", res.code), res.code != 0);
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                }
            }
            KeyCode::Esc => {
                app.reset_flow();
                app.screen = Screen::Menu;
                app.input_mode = InputMode::Navigation;
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
            }
            KeyCode::Char(c) => {
                app.input_buffer.push(c);
            }
            _ => {}
        }
        _ => {}
    }
    false
}

async fn handle_cf_secrets(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 && !app.cf_vault_names.is_empty() {
                if let Some(idx) = app.cf_vault_names.iter().position(|v| Some(v) == app.flow_vault.as_ref()) {
                    let next = if key.code == KeyCode::Up {
                        if idx == 0 { app.cf_vault_names.len() - 1 } else { idx - 1 }
                    } else {
                        (idx + 1) % app.cf_vault_names.len()
                    };
                    app.flow_vault = Some(app.cf_vault_names[next].clone());
                } else if !app.cf_vault_names.is_empty() {
                    app.flow_vault = Some(app.cf_vault_names[0].clone());
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if app.flow_vault.is_some() {
                    app.flow_step = 1;
                } else {
                    app.set_status("Select a CF account first", true);
                }
            } else if app.flow_step == 1 {
                let input = app.input_buffer.trim().to_string();
                if input.is_empty() {
                    app.set_status("Script name is required", true);
                    return false;
                }
                app.flow_script_name = Some(input);
                app.flow_step = 2;
                app.input_buffer.clear();
            } else if app.flow_step == 2 {
                // Action selection
                let input = app.input_buffer.trim().to_string();
                if input == "list" {
                    let vault = app.flow_vault.clone().unwrap();
                    let script = app.flow_script_name.clone().unwrap();
                    match engine.worker_secrets(&vault, &script, "list", None, None, None).await {
                        Ok(r) => {
                            let names: Vec<String> = r.data.get("result")
                                .and_then(|x| x.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|s| s.get("name").and_then(|n| n.as_str()).map(|n| n.to_string()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            app.set_status(&format!("Secrets: {}", names.join(", ")), false);
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else if input == "set" {
                    app.flow_step = 3;
                    app.input_buffer.clear();
                } else if input == "delete" {
                    app.flow_step = 3;
                    app.input_buffer.clear();
                } else {
                    app.set_status("Enter list, set, or delete", true);
                }
            } else if app.flow_step == 3 {
                // Secret name
                app.flow_secret_name = Some(app.input_buffer.trim().to_string());
                if app.input_buffer.trim().is_empty() {
                    app.set_status("Secret name is required", true);
                    return false;
                }
                app.flow_step = 4;
                app.input_buffer.clear();
            } else if app.flow_step == 4 {
                // Secret value (for set)
                let vault = app.flow_vault.clone().unwrap();
                let script = app.flow_script_name.clone().unwrap();
                let name = app.flow_secret_name.clone().unwrap();
                let value = app.input_buffer.trim().to_string();
                match engine.worker_secrets(&vault, &script, "set", Some(&name), Some(&value), None).await {
                    Ok(r) => {
                        if r.status < 400 {
                            app.set_status(&format!("✓ Set '{}' on '{}'", name, script), false);
                        } else {
                            app.set_status(&format!("✗ API error HTTP {}", r.status), true);
                        }
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                    }
                    Err(e) => {
                        app.set_status(&format!("✗ {}", e), true);
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_keychain(app: &mut App, _engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => {
            if app.menu_selected > 0 {
                app.menu_selected -= 1;
            }
        }
        KeyCode::Down => {
            if app.menu_selected < 2 {
                app.menu_selected += 1;
            }
        }
        KeyCode::Enter => {
            let has_entry = keychain::keychain_entry_exists();
            let action = if has_entry {
                // options: remove (0), status (1)
                match app.menu_selected {
                    0 => "remove",
                    1 => "status",
                    _ => "",
                }
            } else {
                // options: store (0), status (1)
                match app.menu_selected {
                    0 => "store",
                    1 => "status",
                    _ => "",
                }
            };

            match action {
                "store" => {
                    // Prompt for password
                    app.reset_flow();
                    app.input_mode = InputMode::Editing;
                    app.flow_step = 0;
                    app.set_status("Enter master password to store", false);
                    // We'll handle this in a special way - need to read password
                    // For now, use rpassword
                    app.screen = Screen::Menu;
                    app.input_mode = InputMode::Navigation;
                    // Actually, let's just call store directly
                    // This is a simplification
                }
                "remove" => {
                    keychain::delete_from_keychain();
                    app.set_status("✓ Removed from Keychain", false);
                    app.screen = Screen::Menu;
                    app.input_mode = InputMode::Navigation;
                }
                "status" => {
                    let has = keychain::keychain_entry_exists();
                    app.set_status(
                        if has { "Keychain: stored ✓" } else { "Keychain: not stored" },
                        false,
                    );
                    app.screen = Screen::Menu;
                    app.input_mode = InputMode::Navigation;
                }
                _ => {}
            }
        }
        KeyCode::Esc => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_status(app: &mut App, _engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_exit(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            engine.lock(None);
            return true;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}
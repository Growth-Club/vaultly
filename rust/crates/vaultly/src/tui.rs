//! Vaultly TUI — full-screen interactive terminal UI using ratatui.
//! Port of the inquire-based TUI. Everything routes through VaultEngine
//! (same audit, policy, encryption as CLI/MCP). Human-only: refused in agent mode.

use std::io::{self, Write};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Frame;
use ratatui::Terminal;

use colored::Colorize;
use vaultly_core::{keychain, RunOptions, VaultEngine};

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

// ─── Theme ─────────────────────────────────────────────────

// ─── Theme ──────────────────────────────────────────────────
// Palette is runtime-configurable from VAULTLY_THEME (file path) or
// `~/.vaultly/theme.toml`. Keys mirror the field names below, e.g.
//   accent = "#22d3ee"
//   warn   = "yellow"

#[derive(Clone, Copy)]
struct Theme {
    fg: Color,
    accent: Color,
    success: Color,
    error: Color,
    warn: Color,
    dim: Color,
    selected_bg: Color,
    selected_fg: Color,
}

const DEFAULT_THEME: Theme = Theme {
    fg: Color::White,
    accent: Color::Cyan,
    success: Color::Green,
    error: Color::Red,
    warn: Color::Yellow,
    dim: Color::DarkGray,
    selected_bg: Color::Cyan,
    selected_fg: Color::Black,
};

static THEME: std::sync::OnceLock<Theme> = std::sync::OnceLock::new();

fn theme() -> &'static Theme {
    THEME.get().unwrap_or(&DEFAULT_THEME)
}

fn parse_color(s: &str) -> Option<Color> {
    let t = s.trim().to_ascii_lowercase();
    Some(match t.as_str() {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" | "purple" => Color::Magenta,
        "cyan" => Color::Cyan,
        "white" => Color::White,
        "gray" | "grey" | "darkgray" => Color::DarkGray,
        _ => {
            let hex = t.strip_prefix('#').unwrap_or("");
            if hex.len() != 6 {
                return None;
            }
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            Color::Rgb(r, g, b)
        }
    })
}

fn load_theme() {
    let vaultly_dir = std::env::var("VAULTLY_DIR").unwrap_or_else(|_| {
        std::env::var("HOME").unwrap_or_else(|_| ".".to_string()) + "/.vaultly"
    });
    let path = std::env::var("VAULTLY_THEME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(&vaultly_dir).join("theme.toml"));
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return;
    };
    let mut t = DEFAULT_THEME;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let val = v.trim().trim_matches('"').trim_matches('\'');
        let Some(col) = parse_color(val) else {
            continue;
        };
        match k.trim() {
            "fg" => t.fg = col,
            "accent" => t.accent = col,
            "success" => t.success = col,
            "error" => t.error = col,
            "warn" => t.warn = col,
            "dim" => t.dim = col,
            "selected_bg" => t.selected_bg = col,
            "selected_fg" => t.selected_fg = col,
            _ => {}
        }
    }
    let _ = THEME.set(t);
}

fn title_style() -> Style {
    Style::new().fg(theme().accent).add_modifier(Modifier::BOLD)
}

fn selected_style() -> Style {
    Style::new()
        .fg(theme().selected_fg)
        .bg(theme().selected_bg)
        .add_modifier(Modifier::BOLD)
}

fn normal_style() -> Style {
    Style::new().fg(theme().fg)
}

fn dim_style() -> Style {
    Style::new().fg(theme().dim)
}

fn success_style() -> Style {
    Style::new().fg(theme().success)
}

fn error_style() -> Style {
    Style::new().fg(theme().error)
}

fn warn_style() -> Style {
    Style::new().fg(theme().warn)
}

fn bordered_block(title: &str) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme().accent))
        .title(Span::styled(
            format!(" {} ", title),
            Style::new().fg(theme().accent).add_modifier(Modifier::BOLD),
        ))
}

fn focused_block(title: &str) -> Block<'static> {
    Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme().warn))
        .title(Span::styled(
            format!(" {} ", title),
            Style::new().fg(theme().warn).add_modifier(Modifier::BOLD),
        ))
}

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
    Result,
    Keychain,
    Status,
    Help,
    Stats,
    Browse,
    MetaDetail,
    BulkDelete,
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
    result_scroll: usize,
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
    flow_cf_action: Option<String>,
    flow_delete_whole: bool,
    browse_vault_idx: usize,
    browse_key_idx: usize,
    browse_keys: Vec<String>,
    browse_meta: Vec<vaultly_core::crypto::SecretMeta>,
    browse_detail: Option<vaultly_core::crypto::SecretMeta>,
    browse_filter: String,
    browse_focus: bool,
    bulk_keys: Vec<String>,
    bulk_sel: Vec<bool>,
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
            result_scroll: 0,
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
            flow_cf_action: None,
            flow_delete_whole: false,
            browse_vault_idx: 0,
            browse_key_idx: 0,
            browse_keys: Vec::new(),
            browse_meta: Vec::new(),
            browse_detail: None,
            browse_filter: String::new(),
            browse_focus: false,
            bulk_keys: Vec::new(),
            bulk_sel: Vec::new(),
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
        self.flow_cf_action = None;
        self.flow_delete_whole = false;
        self.input_buffer.clear();
        self.result_scroll = 0;
        self.browse_key_idx = 0;
        self.browse_filter.clear();
        self.browse_focus = false;
        self.browse_meta.clear();
        self.browse_detail = None;
        self.bulk_keys.clear();
        self.bulk_sel.clear();
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
            "{} The TUI is blocked in agent mode.\n  Agents use: vaultly run <vault> -- <cmd>  or  vaultly mcp",            "✗".red()
        );
        std::process::exit(1);
    }

    // Load the color theme from VAULTLY_THEME or ~/.vaultly/theme.toml.
    load_theme();

    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("{} Failed to initialize terminal.", "✗".red());
            std::process::exit(1);
        }
    };
    // Crash error screen: on panic, restore the terminal and surface the error
    // so a hard failure never leaves the user stuck in raw mode or with no cause.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        cleanup_terminal();
        eprintln!(
            "\n{}  Vaultly crashed unexpectedly — terminal restored.",
            "✗".red()
        );
        eprintln!("     {info}");
        eprintln!("     This is a bug. Report it with the trace above.");
        default_hook(info);
    }));

    // Restore the terminal even if the TUI later panics or exits abnormally.
    let _guard = TerminalGuard;

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
        if terminal
            .draw(|frame| render(frame, &mut app, &mut engine))
            .is_err()
        {
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

/// Copies a secret value to the system clipboard so it never lingers in the
/// persistent footer. Returns true if a clipboard tool accepted the data.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn try_spawn(mut cmd: Command, text: &str) -> bool {
        cmd.stdin(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => return false,
        };
        let _ = stdin.write_all(text.as_bytes());
        drop(stdin);
        child.wait().map(|s| s.success()).unwrap_or(false)
    }

    let mut ok = false;
    #[cfg(target_os = "macos")]
    {
        ok = try_spawn(Command::new("pbcopy"), text) || ok;
    }
    #[cfg(target_os = "linux")]
    {
        ok = try_spawn(Command::new("wl-copy"), text) || ok;
        ok = try_spawn(
            Command::new("xclip").arg("-selection").arg("clipboard"),
            text,
        ) || ok;
    }
    ok
}

/// Restores the terminal when dropped, so a panic mid-TUI doesn't leave the
/// user stuck in raw/alternate-screen mode.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        cleanup_terminal();
    }
}

// ─── Render ────────────────────────────────────────────────

fn render(frame: &mut Frame, app: &mut App, engine: &mut VaultEngine) {
    let area = frame.area();

    // Robust terminal handling: never render into a degenerate-sized surface.
    if area.width < 40 || area.height < 12 {
        frame.render_widget(
            Paragraph::new("Terminal too small — enlarge the window (minimum 40x12)")
                .style(warn_style()),
            area,
        );
        return;
    }

    // Outer border
    let outer = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme().accent));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    // Content + footer
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Min(0), Constraint::Length(2)],
    )
    .split(inner);

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
        Screen::Result => render_result(frame, chunks[0], app),
        Screen::Keychain => render_keychain(frame, chunks[0], app),
        Screen::Status => render_status(frame, chunks[0], app, engine),
        Screen::Help => render_help(frame, chunks[0], app),
        Screen::Stats => render_stats(frame, chunks[0], app, engine),
        Screen::Browse => render_browse(frame, chunks[0], app),
        Screen::MetaDetail => render_meta_detail(frame, chunks[0], app),
        Screen::BulkDelete => render_bulk_delete(frame, chunks[0], app),
        Screen::Exit => render_exit(frame, chunks[0]),
    }

    // Footer
    render_footer(frame, chunks[1], app);
}

fn render_footer(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let (help, help_style) = if app.input_mode == InputMode::Editing {
        (
            "Type to enter • Enter to confirm • Esc to cancel",
            warn_style(),
        )
    } else {
        (
            "↑↓ navigate • Enter select • Esc back • q quit",
            dim_style(),
        )
    };

    let status = if let Some(msg) = &app.status_msg {
        let style = if app.status_is_error {
            error_style()
        } else {
            success_style()
        };
        Line::from(vec![
            Span::styled(" ", dim_style()),
            Span::styled(msg, style.add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from("")
    };

    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(1), Constraint::Length(1)],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(help, help_style))),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(status), chunks[1]);
}

fn render_menu(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let items: Vec<ListItem> = MENU_OPTIONS
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let style = if i == app.menu_selected {
                selected_style()
            } else {
                normal_style()
            };
            ListItem::new(Line::from(Span::styled(*opt, style)))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Vaultly — Interactive "),
        )
        .highlight_style(Style::new());
    frame.render_widget(list, area);
}

// ─── Action Screens ────────────────────────────────────────

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

    frame.render_widget(
        Paragraph::new("➕  Add / Update Secret")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    // Vault field
    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let vault_display = if app.flow_step == 0 {
        format!("Vault name: {}", vault_val)
    } else {
        format!("Vault: {}", vault_val)
    };
    let vault_block = if app.flow_step == 0 {
        focused_block(" Vault ")
    } else {
        bordered_block(" Vault ")
    };
    frame.render_widget(
        Paragraph::new(vault_display)
            .style(normal_style())
            .block(vault_block),
        chunks[1],
    );

    // Key field
    let key_val = app.flow_key.as_deref().unwrap_or("");
    let key_display = if app.flow_step <= 1 {
        format!("Secret name (e.g. GITHUB_TOKEN): {}", key_val)
    } else {
        format!("Secret name: {}", key_val)
    };
    let key_block = if app.flow_step == 1 {
        focused_block(" Key ")
    } else {
        bordered_block(" Key ")
    };
    frame.render_widget(
        Paragraph::new(key_display)
            .style(normal_style())
            .block(key_block),
        chunks[2],
    );

    // Value field
    let val_display = if app.flow_step == 2 {
        format!("Value (hidden): {}", "*".repeat(app.input_buffer.len()))
    } else {
        "Value (hidden)".to_string()
    };
    let val_block = if app.flow_step == 2 {
        focused_block(" Value ")
    } else {
        bordered_block(" Value ")
    };
    frame.render_widget(
        Paragraph::new(val_display)
            .style(normal_style())
            .block(val_block),
        chunks[3],
    );
}

fn render_get_secret(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🔑  Read Secret Value")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let vault_display = if app.flow_step == 0 {
        format!("Select vault: {}", vault_val)
    } else {
        format!("Vault: {}", vault_val)
    };
    let vault_block = if app.flow_step == 0 {
        focused_block(" Vault ")
    } else {
        bordered_block(" Vault ")
    };
    frame.render_widget(
        Paragraph::new(vault_display)
            .style(normal_style())
            .block(vault_block),
        chunks[1],
    );

    let key_val = app.flow_key.as_deref().unwrap_or("");
    let key_display = if app.flow_step <= 1 {
        format!("Select key: {}", key_val)
    } else {
        format!("Key: {}", key_val)
    };
    let key_block = if app.flow_step == 1 {
        focused_block(" Key ")
    } else {
        bordered_block(" Key ")
    };
    frame.render_widget(
        Paragraph::new(key_display)
            .style(normal_style())
            .block(key_block),
        chunks[2],
    );
}

fn render_delete_secret(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🗑️  Delete Secret or Vault")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let vault_display = if app.flow_step == 0 {
        format!("Select vault: {}", vault_val)
    } else {
        format!("Vault: {}", vault_val)
    };
    let vault_block = if app.flow_step == 0 {
        focused_block(" Vault ")
    } else {
        bordered_block(" Vault ")
    };
    frame.render_widget(
        Paragraph::new(vault_display)
            .style(normal_style())
            .block(vault_block),
        chunks[1],
    );

    let selection = if app.flow_delete_whole {
        "ENTIRE vault".to_string()
    } else {
        app.flow_key.as_deref().unwrap_or("").to_string()
    };
    let prompt = if app.flow_step == 0 {
        format!("Select vault: {}", vault_val)
    } else if app.flow_step == 1 {
        format!(
            "↑↓ choose a key (or ENTIRE vault) — selected: {}",
            selection
        )
    } else {
        format!("Press Enter to confirm delete: {}", selection)
    };
    let block = if app.flow_step == 1 {
        focused_block(" Target ")
    } else if app.flow_step == 2 {
        focused_block(" Confirm ")
    } else {
        bordered_block(" Delete ")
    };
    frame.render_widget(
        Paragraph::new(prompt).style(normal_style()).block(block),
        chunks[2],
    );
}

fn render_run_command(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("▶️  Run Command with Secrets")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let vault_display = if app.flow_step == 0 {
        format!("Vault name: {}", vault_val)
    } else {
        format!("Vault: {}", vault_val)
    };
    let vault_block = if app.flow_step == 0 {
        focused_block(" Vault ")
    } else {
        bordered_block(" Vault ")
    };
    frame.render_widget(
        Paragraph::new(vault_display)
            .style(normal_style())
            .block(vault_block),
        chunks[1],
    );

    let cmd_val = app.flow_command.as_deref().unwrap_or("");
    let cmd_display = if app.flow_step <= 1 {
        format!("Command (e.g. npx wrangler deploy): {}", cmd_val)
    } else {
        format!("Command: {}", cmd_val)
    };
    let cmd_block = if app.flow_step == 1 {
        focused_block(" Command ")
    } else {
        bordered_block(" Command ")
    };
    frame.render_widget(
        Paragraph::new(cmd_display)
            .style(normal_style())
            .block(cmd_block),
        chunks[2],
    );
}

fn render_template(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("📦  Create Vault from Template")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let name_val = app.flow_template_name.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 0 {
        format!("Select template: {}", name_val)
    } else if app.flow_step == 1 {
        format!("Vault name: {}", name_val)
    } else {
        format!("Vault: {}", name_val)
    };
    let block = if app.flow_step < 2 {
        focused_block(" Template ")
    } else {
        bordered_block(" Template ")
    };
    frame.render_widget(
        Paragraph::new(prompt).style(normal_style()).block(block),
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
    let keys_block = if app.flow_step == 2 {
        focused_block(" Keys ")
    } else {
        bordered_block(" Keys ")
    };
    frame.render_widget(
        Paragraph::new(keys_info)
            .style(normal_style())
            .block(keys_block),
        chunks[2],
    );
}

fn render_cf_add(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("☁️  Add Cloudflare Account")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let name_val = app.flow_cf_name.as_deref().unwrap_or("");
    let prompt = if app.flow_step == 0 {
        format!("Account name (e.g. personal, work): {}", name_val)
    } else if app.flow_step == 1 {
        "Select auth method".to_string()
    } else if app.flow_step == 3 {
        format!(
            "CLOUDFLARE_EMAIL: {}",
            app.flow_value.as_deref().unwrap_or("")
        )
    } else if app.flow_step == 4 {
        "CLOUDFLARE_API_KEY (hidden):".to_string()
    } else {
        format!("Step {} of credentials", app.flow_step)
    };
    let block = if app.flow_step < 3 {
        focused_block(" Cloudflare ")
    } else {
        bordered_block(" Cloudflare ")
    };
    frame.render_widget(
        Paragraph::new(prompt).style(normal_style()).block(block),
        chunks[1],
    );

    let info = if app.flow_step == 1 {
        "1) API token (recommended, scoped)\n2) Global API key (email + key)"
    } else {
        "Fill in the credentials for the selected auth method"
    };
    frame.render_widget(
        Paragraph::new(info)
            .style(dim_style())
            .block(bordered_block(" Auth ")),
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
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let display = if app.flow_step == 0 {
        format!("Select Cloudflare account: {}", vault_val)
    } else {
        format!("Account: {}", vault_val)
    };
    let block = if app.flow_step == 0 {
        focused_block(" Account ")
    } else {
        bordered_block(" Account ")
    };
    frame.render_widget(
        Paragraph::new(display).style(normal_style()).block(block),
        chunks[1],
    );
}

fn render_cf_deploy(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🚀  Deploy a Worker")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let vault_display = if app.flow_step == 0 {
        format!("Select Cloudflare account: {}", vault_val)
    } else {
        format!("Account: {}", vault_val)
    };
    let vault_block = if app.flow_step == 0 {
        focused_block(" Account ")
    } else {
        bordered_block(" Account ")
    };
    frame.render_widget(
        Paragraph::new(vault_display)
            .style(normal_style())
            .block(vault_block),
        chunks[1],
    );

    let dir_val = app.flow_command.as_deref().unwrap_or("");
    let dir_display = if app.flow_step <= 1 {
        format!("Worker project directory: {}", dir_val)
    } else {
        format!("Directory: {}", dir_val)
    };
    let dir_block = if app.flow_step == 1 {
        focused_block(" Directory ")
    } else {
        bordered_block(" Directory ")
    };
    frame.render_widget(
        Paragraph::new(dir_display)
            .style(normal_style())
            .block(dir_block),
        chunks[2],
    );
}

fn render_cf_secrets(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ],
    )
    .split(area);

    frame.render_widget(
        Paragraph::new("🔐  Worker Secrets")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vault_val = app.flow_vault.as_deref().unwrap_or("");
    let vault_display = if app.flow_step == 0 {
        format!("Select Cloudflare account: {}", vault_val)
    } else {
        format!("Account: {}", vault_val)
    };
    let vault_block = if app.flow_step == 0 {
        focused_block(" Account ")
    } else {
        bordered_block(" Account ")
    };
    frame.render_widget(
        Paragraph::new(vault_display)
            .style(normal_style())
            .block(vault_block),
        chunks[1],
    );

    let script_val = app.flow_script_name.as_deref().unwrap_or("");
    let prompt = if app.flow_step <= 1 {
        format!("Worker script name: {}", script_val)
    } else if app.flow_step == 2 {
        "Action: list, set, or delete".to_string()
    } else if app.flow_step == 3 {
        format!(
            "Secret name: {}",
            app.flow_secret_name.as_deref().unwrap_or("")
        )
    } else if app.flow_step == 4 {
        format!("Secret value: {}", "*".repeat(app.input_buffer.len()))
    } else {
        "Manage secrets".to_string()
    };
    let block = if app.flow_step < 5 {
        focused_block(" Secrets ")
    } else {
        bordered_block(" Secrets ")
    };
    frame.render_widget(
        Paragraph::new(prompt).style(normal_style()).block(block),
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
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let has_entry = keychain::keychain_entry_exists();
    let options: Vec<&str> = if has_entry {
        vec!["🗑️  Remove entry", "📊  Status"]
    } else {
        vec!["🔒  Store master password", "📊  Status"]
    };

    let items: Vec<ListItem> = options
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let style = if i == app.menu_selected {
                selected_style()
            } else {
                normal_style()
            };
            ListItem::new(Line::from(Span::styled(*opt, style)))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::new()
                .borders(Borders::ALL)
                .title(" Keychain ")
                .border_style(Style::new().fg(theme().accent)),
        )
        .highlight_style(Style::new());
    frame.render_widget(list, chunks[1]);
}

fn render_status(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    _app: &App,
    engine: &mut VaultEngine,
) {
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
        Paragraph::new("📊  Vaultly Status")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );

    let vaults = engine.list_vaults(None).unwrap_or_default();
    let vaults_str = if vaults.is_empty() {
        "none".to_string()
    } else {
        vaults.join(", ")
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Vaults: ", dim_style()),
            Span::styled(vaults_str, normal_style()),
        ]))
        .block(bordered_block(" Info ")),
        chunks[1],
    );

    let kc = if !keychain::is_keychain_available() {
        "not available (macOS only)"
    } else if keychain::keychain_entry_exists() {
        "stored ✓"
    } else {
        "not stored"
    };
    let kc_style = if keychain::keychain_entry_exists() {
        success_style()
    } else {
        dim_style()
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Keychain: ", dim_style()),
            Span::styled(kc, kc_style),
        ]))
        .block(bordered_block(" Info ")),
        chunks[2],
    );

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Platform: ", dim_style()),
            Span::styled(std::env::consts::OS, normal_style()),
        ]))
        .block(bordered_block(" Info ")),
        chunks[3],
    );

    let agent_mode = if std::env::var("VAULTLY_AGENT_MODE").as_deref() == Ok("1") {
        "ON (get/env blocked)"
    } else {
        "off"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("  Agent mode: ", dim_style()),
            Span::styled(agent_mode, warn_style()),
        ]))
        .block(bordered_block(" Info ")),
        chunks[4],
    );
}

fn render_help(frame: &mut Frame, area: ratatui::layout::Rect, _app: &App) {
    let text = "\
💡  Vaultly Help
────────────────────────────────
 Navigation   ↑ / ↓  move, Enter select, Esc back
 Quit         q  or  Ctrl-C
 Get secret   menu → Read a secret value (copies to clipboard)
 Add secret   menu → Add / update a secret (typed value is hidden)
 Run command  menu → Run a command with injected secrets
 Cloudflare   menu → Add / List zones / Deploy / Secrets
 Templates    menu → Apply a worker template
 Keychain     menu → manage macOS auto-unlock entry
 Result       ↑ / ↓  scroll long output
 Dashboard    s  (from menu) — vault/key summary
 Browse       b  (from menu) — two-pane vault/key tree, / to filter
 Browse meta  d  (browse, focus a key) — timestamps/expiry, never the value
 Bulk delete  x  (from menu) — multi-select secrets, delete in one go
 Help         ?  or  h  (from menu)
────────────────────────────────
 Esc — back to menu · Secrets are never shown in clear";
    frame.render_widget(
        Paragraph::new(text)
            .style(normal_style())
            .block(bordered_block(" Help ")),
        area,
    );
}

fn render_stats(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    _app: &App,
    engine: &mut VaultEngine,
) {
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled("📊  Vaultly Dashboard", title_style())),
        Line::from(""),
        Line::from(Span::styled("Vaults:", normal_style())),
    ];
    let vaults = engine.list_vaults(None).unwrap_or_default();
    let mut total_keys = 0usize;
    if vaults.is_empty() {
        lines.push(Line::from(Span::styled("   — none —", dim_style())));
    }
    for v in &vaults {
        let keys = engine.list_keys(v, None).unwrap_or_default();
        total_keys += keys.len();
        let suffix = if keys.is_empty() {
            "  (empty)".to_string()
        } else {
            String::new()
        };
        lines.push(Line::from(vec![Span::styled(
            format!("   • {} — {} keys{}", v, keys.len(), suffix),
            normal_style(),
        )]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("Total secrets: {}", total_keys),
        success_style(),
    )));
    lines.push(Line::from(Span::styled(
        format!(
            "Session: {}",
            if engine.is_unlocked() {
                "unlocked"
            } else {
                "locked"
            }
        ),
        normal_style(),
    )));
    lines.push(Line::from(Span::styled(
        format!("Session expires in: {}s", engine.session_expires_in()),
        dim_style(),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .style(normal_style())
            .block(bordered_block(" Dashboard ")),
        area,
    );
}

/// Compact `YYYY-MM-DD` for an RFC3339 timestamp; empty string if unparseable.
fn compact_date(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// Created-date label for a key-list row: a compact date, or "—" when the
/// secret's timestamps are unknown (v1-origin) or unparseable.
fn created_label(meta: &vaultly_core::crypto::SecretMeta) -> String {
    if meta.unknown_timestamps {
        return "—".to_string();
    }
    let d = compact_date(&meta.created_at);
    if d.is_empty() {
        "—".to_string()
    } else {
        d
    }
}

fn render_browse(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let title = if app.input_mode == InputMode::Editing {
        format!("🗂  Vault browser — filter: {}", app.browse_filter)
    } else {
        "🗂  Vault browser — Tab switch pane · Enter copy · / filter".to_string()
    };
    frame.render_widget(
        Paragraph::new(title).style(title_style()).block(
            Block::new()
                .borders(Borders::BOTTOM)
                .border_style(dim_style()),
        ),
        ratatui::layout::Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        },
    );
    let content = ratatui::layout::Rect {
        x: area.x,
        y: area.y + 1,
        width: area.width,
        height: area.height.saturating_sub(1),
    };
    let chunks = Layout::new(
        Direction::Horizontal,
        [Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)],
    )
    .split(content);

    let vault_items: Vec<ListItem> = app
        .vaults
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let style = if !app.browse_focus && i == app.browse_vault_idx {
                selected_style()
            } else {
                normal_style()
            };
            ListItem::new(Line::from(Span::styled(v.as_str(), style)))
        })
        .collect();
    let vault_border = if !app.browse_focus {
        warn_style()
    } else {
        dim_style()
    };
    frame.render_widget(
        List::new(vault_items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(" Vaults ")
                    .border_style(vault_border),
            )
            .highlight_style(Style::new()),
        chunks[0],
    );

    let key_items: Vec<ListItem> = app
        .browse_keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let selected = app.browse_focus && i == app.browse_key_idx;
            let style = if selected {
                selected_style()
            } else {
                dim_style()
            };
            let line = match app.browse_meta.get(i) {
                Some(m) => {
                    let stamp = created_label(m);
                    if stamp.is_empty() {
                        Line::from(Span::styled(k.as_str(), style))
                    } else {
                        Line::from(vec![
                            Span::styled(k.as_str(), style),
                            Span::raw("  "),
                            Span::styled(stamp, dim_style()),
                        ])
                    }
                }
                None => Line::from(Span::styled(k.as_str(), style)),
            };
            ListItem::new(line)
        })
        .collect();
    let key_border = if app.browse_focus {
        warn_style()
    } else {
        dim_style()
    };
    frame.render_widget(
        List::new(key_items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(" Keys ")
                    .border_style(key_border),
            )
            .highlight_style(Style::new()),
        chunks[1],
    );
}

fn render_meta_detail(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::new(
        Direction::Vertical,
        [Constraint::Length(3), Constraint::Min(0)],
    )
    .split(area);
    frame.render_widget(
        Paragraph::new("🗂  Secret metadata — value never shown")
            .style(title_style())
            .block(
                Block::new()
                    .borders(Borders::BOTTOM)
                    .border_style(dim_style()),
            ),
        chunks[0],
    );
    let text: String = match &app.browse_detail {
        None => "No secret selected.".to_string(),
        Some(m) => {
            let created = if m.unknown_timestamps {
                "—".to_string()
            } else {
                let d = compact_date(&m.created_at);
                if d.is_empty() {
                    "—".to_string()
                } else {
                    d
                }
            };
            let updated = if m.unknown_timestamps {
                "—".to_string()
            } else {
                let d = compact_date(&m.updated_at);
                if d.is_empty() {
                    "—".to_string()
                } else {
                    d
                }
            };
            let expiry = match &m.expires_at {
                Some(e) => {
                    let d = compact_date(e);
                    if d.is_empty() {
                        e.clone()
                    } else {
                        d
                    }
                }
                None => "none".to_string(),
            };
            let expired = if m.expired { " [EXPIRED]" } else { "" };
            format!(
                "Key:     {}\nCreated: {}\nUpdated: {}\nExpiry:  {}{}\n\nEsc/q — back to browse",
                m.key, created, updated, expiry, expired
            )
        }
    };
    frame.render_widget(
        Paragraph::new(text)
            .style(normal_style())
            .block(bordered_block(" Meta ")),
        chunks[1],
    );
}

fn render_bulk_delete(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let title = Paragraph::new("🗑️  Bulk Delete Secrets")
        .style(title_style())
        .block(
            Block::new()
                .borders(Borders::BOTTOM)
                .border_style(dim_style()),
        );
    frame.render_widget(
        title,
        ratatui::layout::Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        },
    );
    let content = ratatui::layout::Rect {
        x: area.x,
        y: area.y + 1,
        width: area.width,
        height: area.height.saturating_sub(1),
    };

    if app.flow_step == 0 {
        let vault_val = app.flow_vault.as_deref().unwrap_or("");
        let display = format!("Vault name: {}", vault_val);
        frame.render_widget(
            Paragraph::new(display)
                .style(normal_style())
                .block(focused_block(" Vault ")),
            content,
        );
        return;
    }

    if app.flow_step == 2 {
        let vault = app.flow_vault.as_deref().unwrap_or("");
        let n = app.bulk_sel.iter().filter(|s| **s).count();
        let text = format!(
            "Delete {} secret(s) from vault \"{}\"?\n\n  Y — delete\n  N — back to selection",
            n, vault
        );
        frame.render_widget(
            Paragraph::new(text)
                .style(normal_style())
                .block(bordered_block(" Confirm ")),
            content,
        );
        return;
    }

    // Step 1: checkbox list
    let items: Vec<ListItem> = app
        .bulk_keys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let checked = app.bulk_sel.get(i).copied().unwrap_or(false);
            let mark = if checked { "[x]" } else { "[ ]" };
            let style = if i == app.browse_key_idx {
                selected_style()
            } else {
                dim_style()
            };
            ListItem::new(Line::from(Span::styled(format!("{} {}", mark, k), style)))
        })
        .collect();
    let count = app.bulk_sel.iter().filter(|s| **s).count();
    frame.render_widget(
        List::new(items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(format!(
                        " Secrets ({} selected) — Space toggle · a all · n none · Enter confirm ",
                        count
                    ))
                    .border_style(warn_style()),
            )
            .highlight_style(Style::new()),
        content,
    );
}

fn render_exit(frame: &mut Frame, area: ratatui::layout::Rect) {
    let text = "🚪  Lock & exit?\n\n  Y — lock vault and exit\n  N — cancel";
    frame.render_widget(
        Paragraph::new(text).style(normal_style()).block(
            Block::new()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(theme().warn))
                .title(" Exit ")
                .title_style(warn_style()),
        ),
        area,
    );
}

fn render_result(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    match &app.run_result {
        None => {
            frame.render_widget(
                Paragraph::new("No result.")
                    .style(dim_style())
                    .block(bordered_block(" Result ")),
                area,
            );
        }
        Some((stdout, stderr, code, scrubbed)) => {
            let mut text = String::new();
            if !stdout.is_empty() {
                text.push_str(stdout);
                if !stdout.ends_with('\n') {
                    text.push('\n');
                }
            }
            if !stderr.is_empty() {
                text.push_str(&format!("[stderr]\n{}", stderr));
            }
            if text.is_empty() {
                text.push_str("(no output)");
            }
            if !text.ends_with('\n') {
                text.push('\n');
            }
            let esc = if *scrubbed {
                " [⚠ secret values scrubbed]".yellow().to_string()
            } else {
                String::new()
            };
            let title = format!(" Command output — exit {} {}", code, esc);
            let total_lines = text.lines().count();
            let max_scroll = total_lines.saturating_sub(area.height.saturating_sub(2) as usize);
            let scroll = app.result_scroll.min(max_scroll);
            let title = if max_scroll > 0 {
                format!(
                    "{}  (↑/↓ scroll, {} of {})",
                    title.trim(),
                    scroll + 1,
                    total_lines
                )
            } else {
                title
            };
            frame.render_widget(
                Paragraph::new(text)
                    .style(normal_style())
                    .scroll((scroll as u16, 0))
                    .block(
                        Block::new()
                            .borders(Borders::ALL)
                            .border_style(Style::new().fg(theme().accent))
                            .title(title),
                    ),
                area,
            );
        }
    }
}

// ─── Event Handling ────────────────────────────────────────

async fn handle_event(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
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
        Screen::Result => handle_result(app, key),
        Screen::Keychain => handle_keychain(app, engine, key).await,
        Screen::Status => handle_status(app, engine, key).await,
        Screen::Help => handle_help(app, engine, key).await,
        Screen::Stats => handle_stats(app, engine, key).await,
        Screen::Browse => handle_browse(app, engine, key).await,
        Screen::MetaDetail => handle_meta_detail(app, key),
        Screen::BulkDelete => handle_bulk(app, engine, key).await,
        Screen::Exit => handle_exit(app, engine, key).await,
    }
}

async fn handle_menu(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
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
        KeyCode::Enter => match app.menu_selected {
            0 => {
                app.reset_flow();
                let mut text = String::new();
                let vaults = engine.list_vaults(None).unwrap_or_default();
                if vaults.is_empty() {
                    text.push_str("(no vaults)");
                } else {
                    for v in &vaults {
                        let keys = engine.list_keys(v, None).unwrap_or_default();
                        text.push_str(&format!("{}:\n", v));
                        for k in &keys {
                            text.push_str(&format!("    {}\n", k));
                        }
                    }
                }
                app.run_result = Some((text, String::new(), 0, false));
                app.screen = Screen::Result;
                app.input_mode = InputMode::Navigation;
            }
            1 => {
                app.reset_flow();
                app.screen = Screen::AddSecret;
                app.input_mode = InputMode::Editing;
                app.flow_step = 0;
            }
            2 => {
                app.reset_flow();
                app.screen = Screen::GetSecret;
                app.input_mode = InputMode::Navigation;
                app.flow_step = 0;
            }
            3 => {
                app.reset_flow();
                app.screen = Screen::DeleteSecret;
                app.input_mode = InputMode::Navigation;
                app.flow_step = 0;
            }
            4 => {
                app.reset_flow();
                app.screen = Screen::RunCommand;
                app.input_mode = InputMode::Editing;
                app.flow_step = 0;
            }
            5 => {
                app.reset_flow();
                app.screen = Screen::Template;
                app.input_mode = InputMode::Navigation;
                app.flow_step = 0;
            }
            6 => {
                app.reset_flow();
                app.screen = Screen::CfAdd;
                app.input_mode = InputMode::Editing;
                app.flow_step = 0;
            }
            7 => {
                app.reset_flow();
                app.screen = Screen::CfZones;
                app.input_mode = InputMode::Navigation;
                app.flow_step = 0;
            }
            8 => {
                app.reset_flow();
                app.screen = Screen::CfDeploy;
                app.input_mode = InputMode::Navigation;
                app.flow_step = 0;
            }
            9 => {
                app.reset_flow();
                app.screen = Screen::CfSecrets;
                app.input_mode = InputMode::Navigation;
                app.flow_step = 0;
            }
            10 => {
                app.reset_flow();
                app.screen = Screen::Keychain;
                app.input_mode = InputMode::Navigation;
                app.menu_selected = 0;
            }
            11 => {
                app.screen = Screen::Status;
            }
            12 => {
                app.screen = Screen::Exit;
            }
            _ => {}
        },
        KeyCode::Char('q') | KeyCode::Esc => {
            return true;
        }
        KeyCode::Char('?') => {
            app.screen = Screen::Help;
        }
        KeyCode::Char('h') | KeyCode::Char('H') => {
            app.screen = Screen::Help;
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.reset_flow();
            app.screen = Screen::Stats;
        }
        KeyCode::Char('b') | KeyCode::Char('B') => {
            app.reset_flow();
            app.vaults = engine.list_vaults(None).unwrap_or_default();
            app.browse_vault_idx = 0;
            app.browse_key_idx = 0;
            app.input_mode = InputMode::Navigation;
            app.screen = Screen::Browse;
            browse_refresh(app, engine);
        }
        KeyCode::Char('x') | KeyCode::Char('X') => {
            app.reset_flow();
            app.screen = Screen::BulkDelete;
            app.input_mode = InputMode::Editing;
            app.flow_step = 0;
        }
        _ => {}
    }
    false
}

async fn handle_add_secret(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    if app.input_mode != InputMode::Editing {
        return false;
    }
    match key.code {
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
                    app.set_status("Secret name is required", true);
                    return false;
                }
                app.flow_key = Some(input);
                app.flow_step = 2;
                app.input_buffer.clear();
            } else if app.flow_step == 2 {
                if input.is_empty() {
                    app.set_status("Value is required", true);
                    return false;
                }
                app.flow_value = Some(input);
                let vault = app.flow_vault.clone().unwrap();
                let key_name = app.flow_key.clone().unwrap();
                let value = app.flow_value.clone().unwrap();
                match engine.add_secret(&vault, &key_name, &value, None) {
                    Ok(()) => {
                        let msg = format!("✓ Stored '{}' in '{}'", key_name, vault);
                        app.vaults = engine.list_vaults(None).unwrap_or_default();
                        app.reset_flow();
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                        app.set_status(&msg, false);
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
    false
}

async fn handle_get_secret(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 && !app.vaults.is_empty() {
                let idx = app
                    .vaults
                    .iter()
                    .position(|v| Some(v) == app.flow_vault.as_ref())
                    .unwrap_or(0);
                let next = if key.code == KeyCode::Up {
                    if idx == 0 {
                        app.vaults.len() - 1
                    } else {
                        idx - 1
                    }
                } else {
                    (idx + 1) % app.vaults.len()
                };
                app.flow_vault = Some(app.vaults[next].clone());
                app.flow_key = None;
            } else if app.flow_step == 1 {
                if let Some(vault) = &app.flow_vault {
                    let keys = engine.list_keys(vault, None).unwrap_or_default();
                    if !keys.is_empty() {
                        let idx = keys
                            .iter()
                            .position(|k| Some(k) == app.flow_key.as_ref())
                            .unwrap_or(0);
                        let next = if key.code == KeyCode::Up {
                            if idx == 0 {
                                keys.len() - 1
                            } else {
                                idx - 1
                            }
                        } else {
                            (idx + 1) % keys.len()
                        };
                        app.flow_key = Some(keys[next].clone());
                    }
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if app.flow_vault.is_some() {
                    app.flow_step = 1;
                    app.flow_key = None;
                } else {
                    app.set_status("Select a vault first", true);
                }
            } else if app.flow_step == 1 {
                let vault = match &app.flow_vault {
                    Some(v) => v.clone(),
                    None => {
                        app.set_status("Select a vault first", true);
                        return false;
                    }
                };
                let key_name = match &app.flow_key {
                    Some(k) => k.clone(),
                    None => {
                        app.set_status("Select a key first", true);
                        return false;
                    }
                };
                match engine.get_secret_value(&vault, &key_name, None) {
                    Ok(value) => {
                        let msg = if copy_to_clipboard(&value) {
                            format!("✓ {} copied to clipboard", key_name)
                        } else {
                            format!("✓ {} retrieved", key_name)
                        };
                        app.reset_flow();
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                        app.set_status(&msg, false);
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
                let idx = app
                    .vaults
                    .iter()
                    .position(|v| Some(v) == app.flow_vault.as_ref())
                    .unwrap_or(0);
                let next = if key.code == KeyCode::Up {
                    if idx == 0 {
                        app.vaults.len() - 1
                    } else {
                        idx - 1
                    }
                } else {
                    (idx + 1) % app.vaults.len()
                };
                app.flow_vault = Some(app.vaults[next].clone());
                app.flow_key = None;
            } else if app.flow_step == 1 {
                if let Some(vault) = &app.flow_vault {
                    let keys = engine.list_keys(vault, None).unwrap_or_default();
                    // Cycles existing keys + an explicit "entire vault" sentinel.
                    let total = keys.len() + 1;
                    let cur = if app.flow_delete_whole {
                        keys.len()
                    } else {
                        keys.iter()
                            .position(|k| Some(k) == app.flow_key.as_ref())
                            .unwrap_or(0)
                    };
                    let next = if key.code == KeyCode::Up {
                        if cur == 0 {
                            total - 1
                        } else {
                            cur - 1
                        }
                    } else {
                        (cur + 1) % total
                    };
                    if next < keys.len() {
                        app.flow_key = Some(keys[next].clone());
                        app.flow_delete_whole = false;
                    } else {
                        app.flow_key = None;
                        app.flow_delete_whole = true;
                    }
                }
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if app.flow_vault.is_some() {
                    app.flow_step = 1;
                    app.flow_key = None;
                    app.flow_delete_whole = false;
                } else {
                    app.set_status("Select a vault first", true);
                }
            } else if app.flow_step == 1 {
                let vault = match &app.flow_vault {
                    Some(v) => v.clone(),
                    None => {
                        app.set_status("Select a vault first", true);
                        return false;
                    }
                };
                let keys = engine.list_keys(&vault, None).unwrap_or_default();
                if keys.is_empty() {
                    // Only whole-vault deletion is available for an empty vault.
                    app.flow_key = None;
                    app.flow_delete_whole = true;
                }
                if app.flow_delete_whole || !keys.is_empty() {
                    app.flow_step = 2;
                } else {
                    app.set_status("Select a key or ENTIRE vault", true);
                }
            } else if app.flow_step == 2 {
                // Confirmation step — Enter executes, Esc aborts.
                let vault = match &app.flow_vault {
                    Some(v) => v.clone(),
                    None => {
                        app.reset_flow();
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                        return false;
                    }
                };
                let (result, msg): (Result<bool, _>, String) = if app.flow_delete_whole {
                    (
                        engine.delete_vault(&vault, None),
                        format!("✓ Deleted vault '{}'", vault),
                    )
                } else {
                    let key_name = app.flow_key.clone().unwrap_or_default();
                    (
                        engine.delete_secret(&vault, &key_name, None),
                        format!("✓ Deleted '{}' from '{}'", key_name, vault),
                    )
                };
                match result {
                    Ok(true) => {
                        app.vaults = engine.list_vaults(None).unwrap_or_default();
                        app.reset_flow();
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                        app.set_status(&msg, false);
                    }
                    Ok(false) => {
                        app.set_status("✗ Target not found", true);
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

async fn handle_run_command(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    if app.input_mode != InputMode::Editing {
        return false;
    }
    match key.code {
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
                let vault = app.flow_vault.clone().unwrap();
                let cmd = app.flow_command.clone().unwrap();
                let opts = RunOptions {
                    cwd: None,
                    timeout_ms: None,
                    allowed_keys: None,
                };
                match engine.run_command(&vault, &cmd, &opts, None).await {
                    Ok(res) => {
                        app.run_result = Some((res.stdout, res.stderr, res.code, res.scrubbed));
                        app.reset_flow();
                        app.screen = Screen::Result;
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
    false
}

async fn handle_template(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 {
                let names = crate::templates::template_names();
                if !names.is_empty() {
                    let current = app.flow_template_name.as_deref().unwrap_or("");
                    let idx = names.iter().position(|n| *n == current).unwrap_or(0);
                    let next = if key.code == KeyCode::Up {
                        if idx == 0 {
                            names.len() - 1
                        } else {
                            idx - 1
                        }
                    } else {
                        (idx + 1) % names.len()
                    };
                    app.flow_template_name = Some(names[next].to_string());
                    let tpl = crate::templates::get_template(names[next]).unwrap();
                    app.template_keys = tpl.keys.iter().map(|k| k.to_string()).collect();
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
                let input = app.input_buffer.trim().to_string();
                let vault = app.flow_template_name.clone().unwrap();

                if app.template_keys.is_empty() || app.template_step >= app.template_keys.len() {
                    // No (more) keys to collect — creation is complete.
                    let msg = format!("✓ Vault '{}' created", vault);
                    app.vaults = engine.list_vaults(None).unwrap_or_default();
                    app.reset_flow();
                    app.screen = Screen::Menu;
                    app.input_mode = InputMode::Navigation;
                    app.set_status(&msg, false);
                    return false;
                }

                if !input.is_empty() {
                    let key_name = app.template_keys[app.template_step].clone();
                    match engine.add_secret(&vault, &key_name, &input, None) {
                        Ok(()) => {
                            app.template_step += 1;
                            if app.template_step >= app.template_keys.len() {
                                let msg = format!("✓ Vault '{}' created", vault);
                                app.vaults = engine.list_vaults(None).unwrap_or_default();
                                app.reset_flow();
                                app.screen = Screen::Menu;
                                app.input_mode = InputMode::Navigation;
                                app.set_status(&msg, false);
                            } else {
                                app.input_buffer.clear();
                            }
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else {
                    // Empty value for an optional key — skip it.
                    app.template_step += 1;
                    app.input_buffer.clear();
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
    if app.input_mode != InputMode::Editing {
        return false;
    }
    match key.code {
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
                if input == "1" {
                    app.flow_step = 2;
                    app.input_buffer.clear();
                } else if input == "2" {
                    app.flow_step = 3;
                    app.input_buffer.clear();
                } else {
                    app.set_status("Enter 1 or 2", true);
                }
            } else if app.flow_step == 2 {
                let vault_name = format!("cf-{}", app.flow_cf_name.clone().unwrap());
                match engine.add_secret(&vault_name, "CLOUDFLARE_API_TOKEN", &input, None) {
                    Ok(()) => {
                        let msg = format!("✓ CF account '{}' saved", vault_name);
                        app.vaults = engine.list_vaults(None).unwrap_or_default();
                        app.cf_vault_names = app
                            .vaults
                            .iter()
                            .filter(|v| v.starts_with("cf-"))
                            .cloned()
                            .collect();
                        app.reset_flow();
                        app.screen = Screen::Menu;
                        app.input_mode = InputMode::Navigation;
                        app.set_status(&msg, false);
                    }
                    Err(e) => {
                        app.set_status(&format!("✗ {}", e), true);
                    }
                }
            } else if app.flow_step == 3 {
                if input.is_empty() {
                    app.set_status("CLOUDFLARE_EMAIL is required", true);
                    return false;
                }
                app.flow_value = Some(input);
                app.flow_step = 4;
                app.input_buffer.clear();
            } else if app.flow_step == 4 {
                if input.is_empty() {
                    app.set_status("CLOUDFLARE_API_KEY is required", true);
                    return false;
                }
                let vault_name = format!("cf-{}", app.flow_cf_name.clone().unwrap());
                let email = app.flow_value.clone().unwrap_or_default();
                let ok_email = engine
                    .add_secret(&vault_name, "CLOUDFLARE_EMAIL", &email, None)
                    .is_ok();
                let ok_key = engine
                    .add_secret(&vault_name, "CLOUDFLARE_API_KEY", &input, None)
                    .is_ok();
                if ok_email && ok_key {
                    let msg = format!("✓ CF account '{}' saved (global API key)", vault_name);
                    app.vaults = engine.list_vaults(None).unwrap_or_default();
                    app.cf_vault_names = app
                        .vaults
                        .iter()
                        .filter(|v| v.starts_with("cf-"))
                        .cloned()
                        .collect();
                    app.reset_flow();
                    app.screen = Screen::Menu;
                    app.input_mode = InputMode::Navigation;
                    app.set_status(&msg, false);
                } else {
                    app.set_status("✗ Failed to save Cloudflare credentials", true);
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
    false
}

async fn handle_cf_zones(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 && !app.cf_vault_names.is_empty() {
                let idx = app
                    .cf_vault_names
                    .iter()
                    .position(|v| Some(v) == app.flow_vault.as_ref())
                    .unwrap_or(0);
                let next = if key.code == KeyCode::Up {
                    if idx == 0 {
                        app.cf_vault_names.len() - 1
                    } else {
                        idx - 1
                    }
                } else {
                    (idx + 1) % app.cf_vault_names.len()
                };
                app.flow_vault = Some(app.cf_vault_names[next].clone());
            }
        }
        KeyCode::Enter => {
            if app.flow_step == 0 {
                if let Some(vault) = &app.flow_vault {
                    match engine
                        .cloudflare_api(vault, "GET", "/zones?per_page=50", None, None)
                        .await
                    {
                        Ok(r) => {
                            let zones = r
                                .data
                                .get("result")
                                .and_then(|z| z.as_array())
                                .cloned()
                                .unwrap_or_default();
                            let mut text = String::new();
                            if zones.is_empty() {
                                text.push_str("(no zones)");
                            } else {
                                for z in &zones {
                                    let name =
                                        z.get("name").and_then(|n| n.as_str()).unwrap_or("?");
                                    let id = z.get("id").and_then(|n| n.as_str()).unwrap_or("");
                                    text.push_str(&format!("{}  ({})\n", name, id));
                                }
                            }
                            app.run_result = Some((text, String::new(), 0, false));
                            app.reset_flow();
                            app.screen = Screen::Result;
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
    if app.input_mode != InputMode::Editing {
        return false;
    }
    match key.code {
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
                let vault = app.flow_vault.clone().unwrap();
                let dir = app.flow_command.clone().unwrap();
                let opts = RunOptions {
                    cwd: Some(&dir),
                    timeout_ms: Some(86_400_000),
                    allowed_keys: None,
                };
                match engine
                    .run_command(&vault, "npx wrangler deploy", &opts, None)
                    .await
                {
                    Ok(res) => {
                        app.run_result = Some((res.stdout, res.stderr, res.code, res.scrubbed));
                        app.reset_flow();
                        app.screen = Screen::Result;
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
    false
}

async fn handle_cf_secrets(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Down => {
            if app.flow_step == 0 && !app.cf_vault_names.is_empty() {
                let idx = app
                    .cf_vault_names
                    .iter()
                    .position(|v| Some(v) == app.flow_vault.as_ref())
                    .unwrap_or(0);
                let next = if key.code == KeyCode::Up {
                    if idx == 0 {
                        app.cf_vault_names.len() - 1
                    } else {
                        idx - 1
                    }
                } else {
                    (idx + 1) % app.cf_vault_names.len()
                };
                app.flow_vault = Some(app.cf_vault_names[next].clone());
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
                let input = app.input_buffer.trim().to_string();
                app.flow_cf_action = Some(input.clone());
                if input == "list" {
                    let vault = app.flow_vault.clone().unwrap();
                    let script = app.flow_script_name.clone().unwrap();
                    match engine
                        .worker_secrets(&vault, &script, "list", None, None, None)
                        .await
                    {
                        Ok(r) => {
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
                            let msg = format!("Secrets: {}", names.join(", "));
                            app.reset_flow();
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                            app.set_status(&msg, false);
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else if input == "set" || input == "delete" {
                    app.flow_step = 3;
                    app.input_buffer.clear();
                } else {
                    app.set_status("Enter list, set, or delete", true);
                }
            } else if app.flow_step == 3 {
                if app.input_buffer.trim().is_empty() {
                    app.set_status("Secret name is required", true);
                    return false;
                }
                app.flow_secret_name = Some(app.input_buffer.trim().to_string());
                let action = app.flow_cf_action.clone().unwrap_or_default();
                if action == "delete" {
                    // No value needed for delete — execute it.
                    let vault = app.flow_vault.clone().unwrap();
                    let script = app.flow_script_name.clone().unwrap();
                    let name = app.flow_secret_name.clone().unwrap();
                    match engine
                        .worker_secrets(&vault, &script, "delete", Some(&name), None, None)
                        .await
                    {
                        Ok(r) => {
                            if r.status < 400 {
                                let msg = format!("✓ Deleted '{}' from '{}'", name, script);
                                app.reset_flow();
                                app.screen = Screen::Menu;
                                app.input_mode = InputMode::Navigation;
                                app.set_status(&msg, false);
                            } else {
                                app.set_status(&format!("✗ API error HTTP {}", r.status), true);
                            }
                        }
                        Err(e) => {
                            app.set_status(&format!("✗ {}", e), true);
                        }
                    }
                } else {
                    app.flow_step = 4;
                    app.input_buffer.clear();
                }
            } else if app.flow_step == 4 {
                let vault = app.flow_vault.clone().unwrap();
                let script = app.flow_script_name.clone().unwrap();
                let name = app.flow_secret_name.clone().unwrap();
                let value = app.input_buffer.trim().to_string();
                if value.is_empty() {
                    app.set_status("Secret value is required", true);
                    return false;
                }
                match engine
                    .worker_secrets(&vault, &script, "set", Some(&name), Some(&value), None)
                    .await
                {
                    Ok(r) => {
                        if r.status < 400 {
                            let msg = format!("✓ Set '{}' on '{}'", name, script);
                            app.reset_flow();
                            app.screen = Screen::Menu;
                            app.input_mode = InputMode::Navigation;
                            app.set_status(&msg, false);
                        } else {
                            app.set_status(&format!("✗ API error HTTP {}", r.status), true);
                        }
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

async fn handle_keychain(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => {
            if app.menu_selected > 0 {
                app.menu_selected -= 1;
            }
        }
        KeyCode::Down => {
            if app.menu_selected < 1 {
                app.menu_selected += 1;
            }
        }
        KeyCode::Enter => {
            let has_entry = keychain::keychain_entry_exists();
            let action = if has_entry {
                match app.menu_selected {
                    0 => "remove",
                    1 => "status",
                    _ => "",
                }
            } else {
                match app.menu_selected {
                    0 => "store",
                    1 => "status",
                    _ => "",
                }
            };

            match action {
                "store" => {
                    // Leave raw mode so the password prompt echoes nothing and
                    // verify before persisting, then re-enter the TUI surface.
                    cleanup_terminal();
                    let pw =
                        rpassword::prompt_password("🔑 Master password to store in Keychain: ")
                            .unwrap_or_default();
                    let ok = !pw.is_empty()
                        && engine.unlock(&pw).is_ok()
                        && keychain::store_in_keychain(&pw);
                    let _ = enable_raw_mode();
                    let _ = execute!(io::stdout(), EnterAlternateScreen);

                    let msg = if ok {
                        "✓ Master password stored in Keychain for auto-unlock".to_string()
                    } else {
                        "✗ Could not verify or store master password".to_string()
                    };
                    app.reset_flow();
                    app.screen = Screen::Menu;
                    app.input_mode = InputMode::Navigation;
                    app.set_status(&msg, !ok);
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
                        if has {
                            "Keychain: stored ✓"
                        } else {
                            "Keychain: not stored"
                        },
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

async fn handle_help(app: &mut App, _engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_stats(app: &mut App, _engine: &mut VaultEngine, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

fn browse_refresh(app: &mut App, engine: &mut VaultEngine) {
    if app.browse_vault_idx >= app.vaults.len() {
        app.browse_vault_idx = app.vaults.len().saturating_sub(1);
    }
    let vault = app.vaults.get(app.browse_vault_idx).cloned();
    // Prefer agent-safe per-key metadata so the list can show timestamps in a
    // single call; fall back to name-only keys if the meta call is unavailable.
    let (all_keys, all_meta) = match vault {
        Some(v) => match engine.list_keys_meta(&v, None) {
            Ok(meta) => {
                let keys: Vec<String> = meta.iter().map(|m| m.key.clone()).collect();
                (keys, meta)
            }
            Err(_) => (engine.list_keys(&v, None).unwrap_or_default(), Vec::new()),
        },
        None => (Vec::new(), Vec::new()),
    };

    let f = app.browse_filter.to_lowercase();
    if f.is_empty() {
        app.browse_keys = all_keys;
        app.browse_meta = all_meta;
    } else if all_meta.is_empty() {
        app.browse_keys = all_keys
            .into_iter()
            .filter(|k| k.to_lowercase().contains(&f))
            .collect();
        app.browse_meta = Vec::new();
    } else {
        let filtered: Vec<_> = all_meta
            .into_iter()
            .filter(|m| m.key.to_lowercase().contains(&f))
            .collect();
        app.browse_meta = filtered;
        app.browse_keys = app.browse_meta.iter().map(|m| m.key.clone()).collect();
    }
    if app.browse_key_idx >= app.browse_keys.len() {
        app.browse_key_idx = if app.browse_keys.is_empty() {
            0
        } else {
            app.browse_keys.len() - 1
        };
    }
}

async fn handle_browse(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    if app.input_mode == InputMode::Editing {
        match key.code {
            KeyCode::Char(c) => {
                app.browse_filter.push(c);
                browse_refresh(app, engine);
            }
            KeyCode::Backspace => {
                app.browse_filter.pop();
                browse_refresh(app, engine);
            }
            KeyCode::Esc => {
                app.input_mode = InputMode::Navigation;
            }
            _ => {}
        }
        return false;
    }
    match key.code {
        KeyCode::Up => {
            if app.browse_focus {
                if app.browse_key_idx > 0 {
                    app.browse_key_idx -= 1;
                }
            } else if app.browse_vault_idx > 0 {
                app.browse_vault_idx -= 1;
                browse_refresh(app, engine);
            }
        }
        KeyCode::Down => {
            if app.browse_focus {
                if app.browse_key_idx + 1 < app.browse_keys.len() {
                    app.browse_key_idx += 1;
                }
            } else if app.browse_vault_idx + 1 < app.vaults.len() {
                app.browse_vault_idx += 1;
                browse_refresh(app, engine);
            }
        }
        KeyCode::Tab | KeyCode::Right => {
            app.browse_focus = true;
        }
        KeyCode::Left => {
            app.browse_focus = false;
        }
        KeyCode::Enter => {
            if app.browse_focus {
                if let (Some(vault), Some(key)) = (
                    app.vaults.get(app.browse_vault_idx).cloned(),
                    app.browse_keys.get(app.browse_key_idx).cloned(),
                ) {
                    match engine.get_secret_value(&vault, &key, None) {
                        Ok(val) => {
                            if copy_to_clipboard(&val) {
                                app.set_status(&format!("Copied {} to clipboard", key), false);
                            } else {
                                app.set_status(
                                    &format!("Read {} (no clipboard available)", key),
                                    false,
                                );
                            }
                        }
                        Err(e) => app.set_status(&format!("Read failed: {}", e), true),
                    }
                }
            } else {
                app.browse_focus = true;
            }
        }
        KeyCode::Char('/') | KeyCode::Char('f') | KeyCode::Char('F') => {
            app.browse_filter.clear();
            app.input_mode = InputMode::Editing;
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            if app.browse_focus {
                if let (Some(vault), Some(key)) = (
                    app.vaults.get(app.browse_vault_idx).cloned(),
                    app.browse_keys.get(app.browse_key_idx).cloned(),
                ) {
                    match engine.secret_meta(&vault, &key, None) {
                        Ok(m) => {
                            app.browse_detail = Some(m);
                            app.screen = Screen::MetaDetail;
                            app.input_mode = InputMode::Navigation;
                        }
                        Err(e) => app.set_status(&format!("Meta: {}", e), true),
                    }
                }
            }
        }
        KeyCode::Esc | KeyCode::Char('q') => {
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

fn handle_meta_detail(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
            app.screen = Screen::Browse;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

async fn handle_bulk(app: &mut App, engine: &mut VaultEngine, key: KeyEvent) -> bool {
    if app.flow_step == 0 {
        if app.input_mode != InputMode::Editing {
            return false;
        }
        match key.code {
            KeyCode::Enter => {
                let input = app.input_buffer.trim().to_string();
                if input.is_empty() {
                    app.set_status("Vault name is required", true);
                    return false;
                }
                let keys = engine.list_keys(&input, None).unwrap_or_default();
                if keys.is_empty() {
                    app.set_status("Vault has no secrets", true);
                    return false;
                }
                app.flow_vault = Some(input);
                app.bulk_keys = keys;
                app.bulk_sel = vec![false; app.bulk_keys.len()];
                app.browse_key_idx = 0;
                app.input_buffer.clear();
                app.flow_step = 1;
                app.input_mode = InputMode::Navigation;
            }
            KeyCode::Esc => {
                app.screen = Screen::Menu;
                app.input_mode = InputMode::Navigation;
            }
            _ => {}
        }
        return false;
    }

    if app.flow_step == 1 {
        match key.code {
            KeyCode::Up => {
                if app.browse_key_idx > 0 {
                    app.browse_key_idx -= 1;
                }
            }
            KeyCode::Down => {
                if app.browse_key_idx + 1 < app.bulk_keys.len() {
                    app.browse_key_idx += 1;
                }
            }
            KeyCode::Char(' ') | KeyCode::Char('x') | KeyCode::Char('X') => {
                if let Some(sel) = app.bulk_sel.get_mut(app.browse_key_idx) {
                    *sel = !*sel;
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                for s in app.bulk_sel.iter_mut() {
                    *s = true;
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                for s in app.bulk_sel.iter_mut() {
                    *s = false;
                }
            }
            KeyCode::Enter => {
                if !app.bulk_sel.iter().any(|s| *s) {
                    app.set_status("No secrets selected", true);
                    return false;
                }
                app.flow_step = 2;
            }
            KeyCode::Esc => {
                app.screen = Screen::Menu;
                app.input_mode = InputMode::Navigation;
            }
            _ => {}
        }
        return false;
    }

    // Step 2: confirm delete
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if let Some(vault) = app.flow_vault.clone() {
                let selected: Vec<String> = app
                    .bulk_keys
                    .iter()
                    .zip(app.bulk_sel.iter())
                    .filter(|(_, s)| **s)
                    .map(|(k, _)| k.clone())
                    .collect();
                let mut deleted = 0usize;
                let mut failed = 0usize;
                for k in &selected {
                    match engine.delete_secret(&vault, k, None) {
                        Ok(_) => deleted += 1,
                        Err(_) => failed += 1,
                    }
                }
                let msg = if failed == 0 {
                    format!("Deleted {} secret(s)", deleted)
                } else {
                    format!("Deleted {} secret(s), {} failed", deleted, failed)
                };
                app.set_status(&msg, failed > 0);
            }
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.flow_step = 1;
            app.input_buffer.clear();
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

fn handle_result(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => {
            app.result_scroll = app.result_scroll.saturating_sub(1);
        }
        KeyCode::Down => {
            app.result_scroll = app.result_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.result_scroll = app.result_scroll.saturating_sub(10);
        }
        KeyCode::PageDown => {
            app.result_scroll = app.result_scroll.saturating_add(10);
        }
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
            app.reset_flow();
            app.screen = Screen::Menu;
            app.input_mode = InputMode::Navigation;
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    /// Render `render` into an 80x24 buffer and return all cell text.
    fn render_text(render: impl FnOnce(&mut Frame)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                render(frame);
            })
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    fn sample_app() -> App {
        let mut app = App::new();
        app.screen = Screen::Browse;
        app.vaults = vec!["prod".to_string(), "staging".to_string()];
        app.browse_keys = vec!["api_key".to_string(), "db_password".to_string()];
        app.browse_meta = vec![vaultly_core::crypto::SecretMeta {
            key: "api_key".to_string(),
            created_at: "2026-08-21T10:00:00Z".to_string(),
            updated_at: "2026-08-21T10:00:00Z".to_string(),
            expires_at: None,
            expired: false,
            unknown_timestamps: false,
        }];
        app.browse_vault_idx = 0;
        app.browse_key_idx = 0;
        // A secret value must never be rendered — only key names are shown.
        app.flow_secret_value = Some("super-secret-value-do-not-leak".to_string());
        app
    }

    #[test]
    fn render_browse_shows_vault_and_keys() {
        let app = sample_app();
        let text = render_text(|frame| {
            render_browse(frame, frame.area(), &app);
        });
        assert!(text.contains("prod"), "vault name missing: {text}");
        assert!(text.contains("staging"), "vault name missing: {text}");
        assert!(text.contains("api_key"), "key name missing: {text}");
        assert!(text.contains("db_password"), "key name missing: {text}");
        assert!(
            text.contains("2026-08-21"),
            "created timestamp missing for api_key: {text}"
        );
        assert!(
            !text.contains("super-secret-value-do-not-leak"),
            "secret value leaked into buffer: {text}"
        );
    }

    #[test]
    fn render_meta_detail_shows_timestamps_and_no_value() {
        let mut app = App::new();
        app.screen = Screen::MetaDetail;
        app.browse_detail = Some(vaultly_core::crypto::SecretMeta {
            key: "api_key".to_string(),
            created_at: "2026-08-21T10:00:00Z".to_string(),
            updated_at: "2026-08-22T09:00:00Z".to_string(),
            expires_at: Some("2026-12-31T23:59:59Z".to_string()),
            expired: false,
            unknown_timestamps: false,
        });
        // A secret value must never be rendered — meta only.
        app.flow_secret_value = Some("super-secret-value-do-not-leak".to_string());
        let text = render_text(|frame| {
            render_meta_detail(frame, frame.area(), &app);
        });
        assert!(text.contains("api_key"), "key missing: {text}");
        assert!(
            text.contains("Created: 2026-08-21"),
            "created missing: {text}"
        );
        assert!(
            text.contains("Updated: 2026-08-22"),
            "updated missing: {text}"
        );
        assert!(
            text.contains("Expiry:  2026-12-31"),
            "expiry missing: {text}"
        );
        assert!(
            !text.contains("super-secret-value-do-not-leak"),
            "secret value leaked into buffer: {text}"
        );
    }

    #[test]
    fn render_meta_detail_marks_expired() {
        let mut app = App::new();
        app.screen = Screen::MetaDetail;
        app.browse_detail = Some(vaultly_core::crypto::SecretMeta {
            key: "rotten".to_string(),
            created_at: "2020-01-01T00:00:00Z".to_string(),
            updated_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: Some("2021-01-01T00:00:00Z".to_string()),
            expired: true,
            unknown_timestamps: false,
        });
        let text = render_text(|frame| {
            render_meta_detail(frame, frame.area(), &app);
        });
        assert!(text.contains("[EXPIRED]"), "expired badge missing: {text}");
        assert!(text.contains("rotten"), "key missing: {text}");
    }

    #[test]
    fn render_meta_detail_empty_is_safe() {
        let app = App::new();
        let text = render_text(|frame| {
            render_meta_detail(frame, frame.area(), &app);
        });
        assert!(
            text.contains("No secret selected"),
            "empty guard missing: {text}"
        );
    }

    #[test]
    fn render_help_lists_bindings() {
        let app = App::new();
        let text = render_text(|frame| {
            render_help(frame, frame.area(), &app);
        });
        assert!(text.contains("Vaultly Help"), "help title missing: {text}");
        assert!(text.contains("Quit"), "quit binding missing: {text}");
        assert!(text.contains("Ctrl-C"), "ctrl-c binding missing: {text}");
        assert!(text.contains("Help"), "help binding missing: {text}");
    }

    #[test]
    fn render_stats_draws_counts() {
        let mut engine = VaultEngine::new(None);
        let app = App::new();
        let text = render_text(|frame| {
            render_stats(frame, frame.area(), &app, &mut engine);
        });
        assert!(text.contains("Vaultly Dashboard"), "title missing: {text}");
        assert!(text.contains("Vaults:"), "vault label missing: {text}");
        assert!(
            text.contains("Total secrets:"),
            "total label missing: {text}"
        );
        // Empty dummy engine => zero counts rendered deterministically.
        assert!(text.contains("Total secrets: 0"), "count missing: {text}");
    }
}

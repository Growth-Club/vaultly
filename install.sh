#!/usr/bin/env bash
# ─── Vaultly Installer ──────────────────────────────────────────
# Builds Vaultly from source (Rust) and installs shell completions.
# Usage: bash install.sh
set -euo pipefail

# ── Colors (safe when not a TTY) ────────────────────────────────
if [ -t 1 ]; then
  GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; DIM=""; RESET=""
fi

say()  { printf '%s\n' "$*"; }
log()  { printf '%s%s%s\n' "$GREEN" "$*" "$RESET"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"; }
die()  { printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

# ── Locate this script's repo root ──────────────────────────────
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PKG_PATH="$SCRIPT_DIR/rust/crates/vaultly"

# ── Platform detection ──────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Darwin)  PLATFORM="macOS" ;;
  Linux)   PLATFORM="Linux" ;;
  *)       warn "Unsupported platform: $OS. Vaultly may not build here." ;;
esac

say ""
log "🔐 Vaultly Installer"
log "================"
say ""

# ── Check for a prebuilt binary first ───────────────────────────
if command -v vaultly >/dev/null 2>&1; then
  warn "A 'vaultly' binary is already on your PATH: $(command -v vaultly)"
  if [ -n "${VAULTLY_FORCE_REINSTALL:-}" ]; then
    warn "VAULTLY_FORCE_REINSTALL is set — reinstalling anyway."
  else
    say "Run 'vaultly version' to check it. Re-run with VAULTLY_FORCE_REINSTALL=1 to override."
  fi
fi

# ── Ensure a Rust toolchain ─────────────────────────────────────
if ! command -v rustup >/dev/null 2>&1; then
  if ! command -v cargo >/dev/null 2>&1; then
    die "No Rust toolchain found. Install via https://rustup.rs then re-run this script."
  fi
  warn "rustup not found; using standalone 'cargo' ($(command -v cargo))."
else
  log "Using rustup toolchain: $(rustup show active-toolchain 2>/dev/null || echo 'default')"
fi
command -v cargo >/dev/null 2>&1 || die "cargo not found on PATH."

# ── Build & install from source ─────────────────────────────────
log "Building Vaultly with cargo (this may take a few minutes)..."
if [ -d "$PKG_PATH" ]; then
  cargo install --path "$PKG_PATH" --locked
else
  warn "Local source not found at '$PKG_PATH'."
  say "Falling back to installing the published crate..."
  cargo install vaultly --locked
fi

command -v vaultly >/dev/null 2>&1 || die "Install succeeded but 'vaultly' is not on PATH. Check your cargo bin dir (usually ~/.cargo/bin)."

log "Installed: $(command -v vaultly)"

# ── Install shell completions ───────────────────────────────────
SHELL_NAME="$(basename -- "${SHELL:-}")"
case "$SHELL_NAME" in
  bash)   COMP_SHELL="bash" ;;
  zsh)    COMP_SHELL="zsh" ;;
  fish)   COMP_SHELL="fish" ;;
  *)      COMP_SHELL="" ;;
esac
if [ -n "$COMP_SHELL" ]; then
  log "Installing ${COMP_SHELL} completions..."
  vaultly completions "$COMP_SHELL" --install
else
  warn "Could not detect your shell. Install completions manually, e.g.:"
  warn "  vaultly completions bash --install"
fi

# ── Next steps ──────────────────────────────────────────────────
say ""
log "✅ Vaultly installed successfully!"
say ""
say "Next steps:"
say "  1. Initialize:  vaultly init"
say "  2. Store master password in macOS Keychain:  vaultly keychain store"
say "  3. Add Cloudflare accounts:  vaultly cf add <name>"
say "  4. Connect your AI tool (MCP config):"
say '     { "vaultly": { "command": "vaultly", "args": ["mcp"] } }'
say ""
if [ -n "$COMP_SHELL" ]; then
  say "  Restart your shell (or open a new terminal) to enable completions."
fi
say ""

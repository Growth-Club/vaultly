//! `vaultly serve` — local REST edge for agents and CI.
//!
//! Serves an HTTP/1.1 server that reuses the SAME `VaultEngine`, policy, and
//! audit trail as the CLI and MCP server. Agents/CI authenticate with a bearer
//! token and interact via JSON.
//!
//! AGENT-FIRST INVARIANT: no endpoint returns a raw secret value. Every op is
//! routed through `VaultEngine::op` (policy) + audit, so the same rules that
//! govern the CLI and MCP apply verbatim. There is deliberately no analogue of
//! `get` / `env` / `export` here.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use colored::Colorize;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use vaultly_core::{generate, CallerContext, RunOptions, VaultEngine};

/// Session TTL for the server-managed engine (matches the MCP server).
const SESSION_TTL_MINUTES: u64 = 120;
/// Caller identity logged for every server op.
const AGENT_NAME: &str = "http-agent";

#[derive(Clone)]
struct AppState {
    engine: Arc<Mutex<VaultEngine>>,
    token: Arc<str>,
}

fn agent_ctx() -> CallerContext {
    CallerContext {
        caller: vaultly_core::policy::Caller::Agent,
        agent_name: Some(AGENT_NAME.to_owned()),
        session_id: None,
    }
}

// ─── Auth ─────────────────────────────────────────────

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR-fold so we never short-circuit on the first differing byte.
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Bearer-token gate. Rejects anything without a matching `Authorization:
/// Bearer <token>`. The token is never logged.
async fn require_auth(
    State(st): State<AppState>,
    headers: HeaderMap,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.trim());
    let ok = presented
        .map(|t| constant_time_eq(t, &st.token))
        .unwrap_or(false);
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    next.run(req).await
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

// ─── Request bodies ───────────────────────────────────

#[derive(Deserialize)]
struct KeysQuery {
    vault: String,
}

#[derive(Deserialize)]
struct RunBody {
    vault: String,
    command: String,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
struct AddBody {
    vault: String,
    key: String,
    value: String,
    #[serde(default)]
    expires: Option<String>,
}

#[derive(Deserialize)]
struct RotateBody {
    vault: String,
    #[serde(default)]
    length: Option<usize>,
    #[serde(default)]
    symbols: Option<bool>,
}

// ─── Handlers ─────────────────────────────────────────

async fn health(State(st): State<AppState>) -> Response {
    let unlocked = st.engine.lock().await.is_unlocked();
    Json(json!({
        "status": "ok",
        "service": "vaultly",
        "version": env!("CARGO_PKG_VERSION"),
        "unlocked": unlocked,
    }))
    .into_response()
}

async fn vaults(State(st): State<AppState>) -> Response {
    let ctx = agent_ctx();
    let mut eng = st.engine.lock().await;
    match eng.list_vaults(Some(&ctx)) {
        Ok(v) => Json(json!({ "vaults": v })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn keys(State(st): State<AppState>, Query(q): Query<KeysQuery>) -> Response {
    let ctx = agent_ctx();
    let mut eng = st.engine.lock().await;
    match eng.list_keys_meta(&q.vault, Some(&ctx)) {
        Ok(meta) => {
            let arr: Vec<Value> = meta
                .iter()
                .map(|m| {
                    json!({
                        "key": m.key,
                        "createdAt": m.created_at,
                        "updatedAt": m.updated_at,
                        "expiresAt": m.expires_at,
                        "expired": m.expired,
                    })
                })
                .collect();
            Json(json!({ "vault": q.vault, "keys": arr })).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn run(State(st): State<AppState>, Json(body): Json<RunBody>) -> Response {
    let ctx = agent_ctx();
    let timeout = body
        .timeout_ms
        .unwrap_or(vaultly_core::engine::DEFAULT_TIMEOUT_MS);
    let mut eng = st.engine.lock().await;
    let opts = RunOptions {
        cwd: body.cwd.as_deref(),
        timeout_ms: Some(timeout),
        allowed_keys: None,
    };
    match eng
        .run_command(&body.vault, &body.command, &opts, Some(&ctx))
        .await
    {
        Ok(r) => Json(json!({
            "command": body.command,
            "exitCode": r.code,
            "scrubbed": r.scrubbed,
            "injected": r.secrets_injected,
            "stdout": r.stdout,
            "stderr": r.stderr,
        }))
        .into_response(),
        // Missing vault or empty vault is a client error; a policy denial is 4xx too.
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn add(State(st): State<AppState>, Json(body): Json<AddBody>) -> Response {
    let ctx = agent_ctx();
    let mut eng = st.engine.lock().await;
    match eng.add_secret_with_expiry(
        &body.vault,
        &body.key,
        &body.value,
        body.expires.as_deref(),
        Some(&ctx),
    ) {
        Ok(()) => Json(json!({
            "stored": true,
            "vault": body.vault,
            "key": body.key,
        }))
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn rotate_expired(State(st): State<AppState>, Json(body): Json<RotateBody>) -> Response {
    let ctx = agent_ctx();
    let length = body.length.unwrap_or(32);
    let symbols = body.symbols.unwrap_or(false);
    let mut eng = st.engine.lock().await;
    match eng.expired_keys(&body.vault, Some(&ctx)) {
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()),
        Ok(targets) => {
            let mut rotated: Vec<String> = Vec::new();
            for key in &targets {
                let new_value = generate::generate_secret(length, symbols);
                if eng
                    .add_secret_with_expiry(&body.vault, key, &new_value, None, Some(&ctx))
                    .is_ok()
                {
                    rotated.push(key.clone());
                }
            }
            Json(json!({
                "vault": body.vault,
                "rotated": rotated,
                "count": rotated.len(),
            }))
            .into_response()
        }
    }
}

// ─── Assembly ─────────────────────────────────────────

fn build_router(state: AppState) -> Router {
    // Everything except /health requires a bearer token. /health is left open
    // as a liveness probe for CI/uptime checks — it reveals no secrets.
    let authed = Router::new()
        .route("/vaults", get(vaults))
        .route("/keys", get(keys))
        .route("/run", post(run))
        .route("/add", post(add))
        .route("/rotate-expired", post(rotate_expired))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Router::new()
        .route("/health", get(health))
        .merge(authed)
        .with_state(state)
}

/// Unlock with `VAULTLY_MASTER_PASSWORD` (env) then macOS Keychain. Returns
/// true if the engine is usable. Never prompts — `serve` is expected to run
/// headless (CI/agents), so a missing password is a hard error, not a prompt.
fn unlock_engine(engine: &mut VaultEngine) -> bool {
    if let Ok(pw) = std::env::var("VAULTLY_MASTER_PASSWORD") {
        if engine.unlock(pw.trim()).is_ok() {
            std::env::remove_var("VAULTLY_MASTER_PASSWORD");
            return true;
        }
    }
    if let Some(pw) = vaultly_core::keychain::get_from_keychain() {
        if engine.unlock(&pw).is_ok() {
            return true;
        }
    }
    false
}

/// Run the REST server forever on `bind` (e.g. "127.0.0.1:8799") until the
/// process is interrupted. `token` is the bearer token clients must present.
pub async fn serve(bind: &str, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut engine = VaultEngine::new(Some(SESSION_TTL_MINUTES));
    if let Err(e) = engine.load_policy_from_env() {
        eprintln!(
            "{} Failed to load VAULTLY_AGENT_POLICY: {}",
            "⚠".yellow(),
            e
        );
    }
    if !unlock_engine(&mut engine) {
        eprintln!(
            "{} Vaultly is locked and no password is available.\n  Set VAULTLY_MASTER_PASSWORD (or configure the macOS Keychain), then start serve.",
            "✗".red()
        );
        std::process::exit(1);
    }

    let state = AppState {
        engine: Arc::new(Mutex::new(engine)),
        token: Arc::from(token),
    };
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!(
        "{} vaultly REST server listening on http://{} (agent mode, bearer auth)",
        "✓".green(),
        bind
    );
    axum::serve(listener, app).await?;
    Ok(())
}

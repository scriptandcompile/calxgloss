//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod actions;
mod events;
mod handlers;
mod types;

pub use self::actions::*;
pub use self::handlers::*;
pub use self::types::*;
pub use events::{EventsBridge, SessionManager, WebSocketHandler};

use axum::{
    Router,
    extract::{DefaultBodyLimit, WebSocketUpgrade},
    middleware,
    routing::{get, post},
    extract::FromRef,
};
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::ReviewDashboard;
use std::path::{Path, PathBuf};
use tracing::info;

/// Shared state for the API server.
#[derive(Clone)]
pub struct ServerState {
    repo_path: PathBuf,
}

impl ServerState {
    pub fn new(repo_path: PathBuf) -> Self { Self { repo_path } }
    pub fn repo_path(&self) -> &Path { &self.repo_path }
}

/// Combined state for WebSocket support and review actions.
#[derive(Clone)]
pub struct CombinedState {
    pub server: ServerState,
    pub manager: Option<SessionManager>,
    pub bridge: Option<EventsBridge>,
    /// Review action backend — wires accept/send-back/patch into Git + Translator.
    pub actions: Option<ActionsState>,
}

impl FromRef<CombinedState> for ServerState {
    fn from_ref(c: &CombinedState) -> Self { c.server.clone() }
}

impl FromRef<CombinedState> for SessionManager {
    fn from_ref(c: &CombinedState) -> Self {
        c.manager.clone().expect("SessionManager not configured")
    }
}

impl FromRef<CombinedState> for EventsBridge {
    fn from_ref(c: &CombinedState) -> Self {
        c.bridge.clone().expect("EventsBridge not configured")
    }
}

impl FromRef<CombinedState> for ActionsState {
    fn from_ref(c: &CombinedState) -> Self {
        c.actions.clone().expect("ActionsState not configured")
    }
}

/// Builds a [`ReviewDashboard`] from the state of a Git repository.
pub fn build_dashboard(repo_path: &Path) -> Result<ReviewDashboard, anyhow::Error> {
    let git = calxgloss_git::GitManager::open(repo_path)?;
    let builder = DashboardBuilder::new(&git);
    let dashboard = builder.build()?;
    Ok(dashboard)
}

/// Build the axum router with all API endpoints.
pub fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/api/dashboard", get(handlers::api_get_dashboard))
        .route("/api/units/{id}", get(handlers::api_get_unit))
        .route("/api/units/{id}/diff", get(handlers::api_get_unit_diff))
        .route("/api/units/{id}/ghidra", get(handlers::api_get_unit_ghidra))
        .route("/api/units/{id}/accept", post(handlers::api_accept_unit))
        .route("/api/units/{id}/send-back", post(handlers::api_send_back_unit))
        .route("/api/units/{id}/patch", post(handlers::api_request_patch))
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/health", get(handlers::api_health))
        .fallback_service(axum::routing::get(handlers::static_fallback))
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(CombinedState {
            server: state,
            manager: None,
            bridge: None,
            actions: None,
        })
}

/// Build a router with WebSocket support and review-actions backend.
pub fn build_router_with_actions(
    state: ServerState,
    actions: ActionsState,
) -> Router {
    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/api/dashboard", get(handlers::api_get_dashboard))
        .route("/api/units/{id}", get(handlers::api_get_unit))
        .route("/api/units/{id}/diff", get(handlers::api_get_unit_diff))
        .route("/api/units/{id}/ghidra", get(handlers::api_get_unit_ghidra))
        .route("/api/units/{id}/accept", post(handlers::api_accept_unit))
        .route("/api/units/{id}/send-back", post(handlers::api_send_back_unit))
        .route("/api/units/{id}/patch", post(handlers::api_request_patch))
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/health", get(handlers::api_health))
        .fallback_service(axum::routing::get(handlers::static_fallback))
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(CombinedState {
            server: state,
            manager: None,
            bridge: None,
            actions: Some(actions),
        })
}

/// Build a router with WebSocket support.
pub fn build_router_with_ws(
    state: ServerState,
    manager: SessionManager,
    bridge: EventsBridge,
) -> Router {
    Router::new()
        .route("/api/dashboard", get(handlers::api_get_dashboard))
        .route("/api/units/{id}", get(handlers::api_get_unit))
        .route("/api/units/{id}/diff", get(handlers::api_get_unit_diff))
        .route("/api/units/{id}/ghidra", get(handlers::api_get_unit_ghidra))
        .route("/api/units/{id}/accept", post(handlers::api_accept_unit))
        .route("/api/units/{id}/send-back", post(handlers::api_send_back_unit))
        .route("/api/units/{id}/patch", post(handlers::api_request_patch))
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/health", get(handlers::api_health))
        .route("/", get(handlers::serve_index))
        .fallback_service(axum::routing::get(handlers::static_fallback))
        .route("/api/events/upgrade", get(api_events_upgrade_ws))
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(CombinedState {
            server: state,
            manager: Some(manager),
            bridge: Some(bridge),
            actions: None,
        })
}

/// WebSocket upgrade handler for live progress events.
async fn api_events_upgrade_ws(
    ws: WebSocketUpgrade,
    axum::extract::State(combined): axum::extract::State<CombinedState>,
) -> axum::response::Response {
    let manager = combined.manager.expect("SessionManager not configured");
    ws.on_upgrade(move |ws| async move {
        let (handler, _sender) = manager.register_client().await;
        handler.process(ws).await;
    })
}

/// Start the API server on the given address.
///
/// If `ready` is provided, its sender is notified (with the local address)
/// immediately after the TCP listener is bound, before any requests are
/// accepted.  Callers can use this to wait until the server is reachable
/// before proceeding.
///
/// **Note:** `ready_tx` is consumed even on bind failure so that the caller
/// never has to handle a `RecvError`.  The error is sent through the channel
/// instead.
pub async fn serve(
    state: ServerState,
    port: u16,
    ready: Option<
        tokio::sync::oneshot::Sender<std::result::Result<std::net::SocketAddr, anyhow::Error>>,
    >,
) -> Result<(), anyhow::Error> {
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => {
            let io_err = std::io::Error::new(e.kind(), e.to_string());
            let err: anyhow::Error = io_err.into();
            if let Some(tx) = ready {
                let _ = tx.send(Err(e.into()));
            }
            return Err(err);
        }
    };
    let local_addr = listener.local_addr()?;
    info!("API server listening on {local_addr}");

    // Signal readiness **after** the socket is bound and listening.
    if let Some(tx) = ready {
        let _ = tx.send(Ok(local_addr));
    }

    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

/// Start the API server using a pre-bound TCP listener.
///
/// Used internally by `handle_live` to bind outside of `serve()` so that
/// bind failures can be reported through the ready channel.
pub async fn serve_with_listener(
    listener: tokio::net::TcpListener,
    state: ServerState,
) -> Result<(), anyhow::Error> {
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

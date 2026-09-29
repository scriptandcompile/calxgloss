//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod events;
mod handlers;
mod types;

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

/// Combined state for WebSocket support.
#[derive(Clone)]
pub struct CombinedState {
    pub server: ServerState,
    pub manager: Option<SessionManager>,
    pub bridge: Option<EventsBridge>,
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
        .route("/api/units/:id", get(handlers::api_get_unit))
        .route("/api/units/:id/accept", post(handlers::api_accept_unit))
        .route("/api/units/:id/send-back", post(handlers::api_send_back_unit))
        .route("/api/units/:id/patch", post(handlers::api_request_patch))
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
        .route("/api/units/:id", get(handlers::api_get_unit))
        .route("/api/units/:id/accept", post(handlers::api_accept_unit))
        .route("/api/units/:id/send-back", post(handlers::api_send_back_unit))
        .route("/api/units/:id/patch", post(handlers::api_request_patch))
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
pub async fn serve(state: ServerState, port: u16) -> Result<(), anyhow::Error> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("API server listening on {}", listener.local_addr()?);
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

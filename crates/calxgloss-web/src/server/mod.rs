//! Axum API server for the review dashboard.
//!
//! This module is only compiled when the `server` feature is enabled.

mod handlers;
mod types;

pub use self::handlers::*;
pub use self::types::*;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::ReviewDashboard;
use std::path::{Path, PathBuf};
use tracing::info;

/// Shared state for the API server.
///
/// Holds the repository path so that dashboard and unit data can be
/// read from Git branches and translation artifacts on each request.
pub struct ServerState {
    /// Path to the Git repository that tracks translation work.
    repo_path: PathBuf,
}

impl ServerState {
    /// Creates a new server state pointing at the given repository path.
    pub fn new(repo_path: PathBuf) -> Self {
        Self { repo_path }
    }

    /// Returns the repository path.
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }
}

/// Builds a [`ReviewDashboard`] from the state of a Git repository.
///
/// This function is used by both the API server and any other consumer
/// that needs the current dashboard view. It walks the repository's
/// translation branches, patch records, and baseline files to construct
/// a complete picture of all units of work.
pub fn build_dashboard(repo_path: &Path) -> Result<ReviewDashboard, anyhow::Error> {
    let git = calxgloss_git::GitManager::open(repo_path)?;
    let builder = DashboardBuilder::new(&git);
    let dashboard = builder.build()?;
    Ok(dashboard)
}

/// Build the axum router with all API endpoints.
///
/// Routes:
/// - `GET /api/dashboard` — Full review dashboard (queue, counts, recent activity)
/// - `GET /api/units/:id` — Detail view for a single unit of work
/// - `POST /api/units/:id/accept` — Accept unit (merge branch to main)
/// - `POST /api/units/:id/send-back` — Send back unit with reviewer comments
/// - `POST /api/units/:id/patch` — Request a patch for a specific issue
/// - `GET /api/queue` — Dependency-sorted review queue (Phase 5, Step 5.2)
/// - `GET /api/queue/next` — Next unit to review (Phase 5, Step 5.2)
/// - `GET /api/graph` — Dependency graph for visualization
/// - `GET /health` — Health check
pub fn build_router(state: ServerState) -> Router {
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
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

/// Start the API server on the given address.
///
/// Binds to `0.0.0.0:port` so the server is accessible from outside
/// the host machine (useful for containerized or remote development).
pub async fn serve(state: ServerState, port: u16) -> Result<(), anyhow::Error> {
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("API server listening on {}", listener.local_addr()?);
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

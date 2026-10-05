//! Calxgloss Web — Web Review UI (API layer + static HTML/JS/CSS frontend)
//!
//! ## Features
//!
//! - `server` — enables the axum HTTP server for the REST API and static file serving

// Re-export types from calxgloss-types
pub use calxgloss_types::{
    DependencyEdge, DependencyGraph, DependencyNode, ReviewAction, ReviewActionKind,
    ReviewDashboard, ReviewStatus, StatusCounts, UnitOfWork, WorkUnitKind,
};

// Server module (behind server feature)
#[cfg(feature = "server")]
mod server;

#[cfg(feature = "server")]
pub use server::*;

#[cfg(feature = "server")]
use std::path::Path;

#[cfg(feature = "server")]
pub fn build_dashboard(repo_path: &Path) -> Result<ReviewDashboard, anyhow::Error> {
    let git = calxgloss_git::GitManager::open(repo_path)?;
    let builder = calxgloss_reports::dashboard::DashboardBuilder::new(&git);
    let dashboard = builder.build()?;
    Ok(dashboard)
}

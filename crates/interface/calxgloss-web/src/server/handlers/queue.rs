//! Queue management: listing units and computing dependency order.

use super::super::{QueueEntry, QueuePosition, QueueResponse, ServerError, ServerState};
use calxgloss_types::ReviewStatus;

use axum::{Json, extract::State};

// ─── GET /api/queue ──────────────────────────────────────────────────

/// Returns the full review queue sorted by dependency order.
pub async fn api_get_queue(
    State(state): State<ServerState>,
) -> Result<Json<QueueResponse>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(QueueResponse::from_dashboard(&dashboard)))
}

// ─── GET /api/queue/next ─────────────────────────────────────────────

/// Returns the next unit in the review queue based on dependency order.
pub async fn api_get_next_unit(
    State(state): State<ServerState>,
) -> Result<Json<Option<QueueEntry>>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(dashboard.next_in_dependency_order().map(|u| {
        QueueEntry {
            id: u.id.clone(),
            name: u.name.clone(),
            kind: u.kind.to_string(),
            binary: u.binary.clone(),
            function: u.function.clone(),
            status: u.status.to_string(),
            stale: u.stale.to_string(),
            blocked: matches!(u.status, ReviewStatus::Blocked),
        }
    })))
}

// ─── Helper functions ─────────────────────────────────────────────────

/// Find a unit by ID using the repository's review dashboard.
pub(crate) fn find_unit(
    state: &ServerState,
    unit_id: &str,
) -> Result<calxgloss_types::UnitOfWork, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .cloned()
        .ok_or_else(|| ServerError::not_found(&format!("Unit not found: {unit_id}")))
}

/// Compute the position of a unit in the dependency-ordered queue.
pub(crate) fn compute_queue_position(
    dashboard: &calxgloss_types::ReviewDashboard,
    unit: &calxgloss_types::UnitOfWork,
) -> QueuePosition {
    let sorted = dashboard.sorted_queue();
    let total = sorted.len();
    let index = sorted.iter().position(|u| u.id == unit.id);
    QueuePosition { index, total }
}

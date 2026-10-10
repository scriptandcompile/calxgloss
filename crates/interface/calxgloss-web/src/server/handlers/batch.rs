//! Batch review actions (issue #78): apply accept, send-back, or skip to a
//! set of units in one request. Each unit goes through exactly the same
//! per-unit action logic the single-unit endpoints run — conflict checks,
//! persistence, git operations — and every unit gets its own success/failure
//! result, so one bad unit never aborts the rest of the batch.

use super::super::{
    BatchActionRequest, BatchActionResponse, BatchItemResult, CombinedState, ServerError,
};

use axum::{Json, extract::State};
use tracing::info;

// ─── POST /api/batch/accept ──────────────────────────────────────────

/// Accepts every requested unit: each merge and action record is the same as
/// a single `POST /api/units/{id}/accept`. Registered in every router — the
/// same routes the per-unit accept registers into.
pub async fn api_batch_accept(
    State(combined): State<CombinedState>,
    Json(request): Json<BatchActionRequest>,
) -> Result<Json<BatchActionResponse>, ServerError> {
    let unit_ids = selected_units(&request)?;
    let response = run_batch("accept", &unit_ids, |unit_id| {
        let combined = combined.clone();
        async move {
            super::api::perform_accept(&combined, &unit_id)
                .await
                .map(|result| result.message)
        }
    })
    .await;
    Ok(Json(response))
}

// ─── POST /api/batch/send-back ───────────────────────────────────────

/// Sends every requested unit back with one shared reason (defaulting to
/// "Needs revision", like the per-unit endpoint). Registered in every router.
pub async fn api_batch_send_back(
    State(combined): State<CombinedState>,
    Json(request): Json<BatchActionRequest>,
) -> Result<Json<BatchActionResponse>, ServerError> {
    let unit_ids = selected_units(&request)?;
    let reason = request
        .reason
        .unwrap_or_else(|| "Needs revision".to_string());
    let response = run_batch("send_back", &unit_ids, |unit_id| {
        let combined = combined.clone();
        let reason = reason.clone();
        async move {
            super::api::perform_send_back(&combined, &unit_id, &reason)
                .await
                .map(|result| result.message)
        }
    })
    .await;
    Ok(Json(response))
}

// ─── POST /api/batch/skip ────────────────────────────────────────────

/// Skips every requested unit: each skip is the same persisted-set update as
/// a single `POST /api/units/{id}/skip` (issue #75). Registered in every
/// router — skip is persisted review state, not live pipeline state.
pub async fn api_batch_skip(
    State(combined): State<CombinedState>,
    Json(request): Json<BatchActionRequest>,
) -> Result<Json<BatchActionResponse>, ServerError> {
    let unit_ids = selected_units(&request)?;
    let response = run_batch("skip", &unit_ids, |unit_id| {
        let server = combined.server.clone();
        async move {
            super::queue::set_unit_skipped(&server, &unit_id, true)
                .map(|result| result.0.message)
        }
    })
    .await;
    Ok(Json(response))
}

// ─── Shared batch plumbing ───────────────────────────────────────────

/// Rejects an empty selection — a batch with no units is a client bug, not
/// an honest no-op.
fn selected_units(request: &BatchActionRequest) -> Result<Vec<String>, ServerError> {
    if request.unit_ids.is_empty() {
        return Err(ServerError::BadRequest(
            "No units selected for the batch action".to_string(),
        ));
    }
    Ok(request.unit_ids.clone())
}

/// Applies `apply` to each unit sequentially — git operations share one
/// repository, and sequential application keeps per-item results in request
/// order and deterministic — collecting one result per unit. A failure on
/// one unit is recorded and the batch continues with the next.
async fn run_batch<F, Fut>(
    action: &str,
    unit_ids: &[String],
    mut apply: F,
) -> BatchActionResponse
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, ServerError>>,
{
    let mut results = Vec::with_capacity(unit_ids.len());
    let mut succeeded = 0usize;

    for unit_id in unit_ids.iter().cloned() {
        let (success, message) = match apply(unit_id.clone()).await {
            Ok(message) => {
                succeeded += 1;
                (true, message)
            }
            Err(e) => (false, e.to_string()),
        };
        results.push(BatchItemResult {
            unit_id,
            success,
            message,
        });
    }

    let failed = unit_ids.len() - succeeded;
    info!(
        action,
        succeeded,
        failed,
        units_total = unit_ids.len(),
        "Batch review action complete"
    );

    BatchActionResponse {
        success: failed == 0,
        action: action.to_string(),
        results,
        succeeded,
        failed,
    }
}

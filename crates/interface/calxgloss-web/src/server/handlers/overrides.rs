//! Per-unit reviewer override endpoints (issue #96, W2.7).
//!
//! A reviewer steering a live run can override how one unit's next attempt
//! runs: force the context tier, force the retry strategy, append custom
//! hints, skip the unit, and record notes. All three endpoints are
//! live-router only — a plain `serve` router has no pipeline to steer —
//! and each answers 503 when the live router was built without an
//! override handle attached, mirroring the scope endpoints' honesty rule.

use super::super::{CombinedState, ServerError, UnitOverrideRequest, UnitOverrideResponse};

use axum::{
    Json,
    extract::{Path, State},
};
use calxgloss_types::{OverrideControl, parse_branch_name};
use tracing::info;

/// The override handle every endpoint needs: 503 when this live router was
/// built without one — honest rather than steering a pipeline that does
/// not exist.
fn override_handle(combined: &CombinedState) -> Result<OverrideControl, ServerError> {
    combined.server.override_control().ok_or_else(|| {
        ServerError::unavailable("this server has no unit override control attached")
    })
}

/// Split a dashboard unit id — `{binary}/{function}/v{N}`, or a bare
/// `{binary}/{function}` unit key — into its binary and function parts
/// using the shared branch-name grammar.
fn parse_unit_id(unit_id: &str) -> Result<(String, String), ServerError> {
    let parts = parse_branch_name(unit_id).ok_or_else(|| {
        ServerError::bad_request(&format!("unit id '{unit_id}' does not name a unit"))
    })?;
    let function = parts.function.ok_or_else(|| {
        ServerError::bad_request(&format!("unit id '{unit_id}' does not name a function"))
    })?;
    Ok((parts.binary.as_str().to_string(), function))
}

/// Map a persistence failure — the record could not be written under the
/// workspace's record tree — to an internal error the reviewer cannot fix
/// by changing the request.
fn persist_error(e: calxgloss_types::PersistError) -> ServerError {
    ServerError::internal(&format!("failed to persist unit override record: {e}"))
}

/// The response every override endpoint echoes: the unit addressed and the
/// override now in force for it.
fn override_response(
    unit_id: &str,
    overrides: &OverrideControl,
    binary: &str,
    function: &str,
) -> Json<UnitOverrideResponse> {
    Json(UnitOverrideResponse {
        unit: unit_id.to_string(),
        r#override: overrides.get(binary, function),
    })
}

/// Handle `GET /api/units/{id}/override` — the override currently in force
/// for this unit, or `null` when none is set. Live router only.
pub async fn api_get_unit_override(
    State(combined): State<CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<UnitOverrideResponse>, ServerError> {
    let overrides = override_handle(&combined)?;
    let (binary, function) = parse_unit_id(&unit_id)?;
    Ok(override_response(&unit_id, &overrides, &binary, &function))
}

/// Handle `POST /api/units/{id}/override` — apply (replace) the reviewer's
/// override record for this unit. An all-defaults record removes it. A
/// forced retry strategy is the shared `RetryStrategy` enum, so an unknown
/// label is refused by serde on the failed JSON extraction (422) rather
/// than stored and silently ignored at build time (issue #120). The
/// translator honors the change on the unit's next attempt; a skip takes
/// effect at the next queue selection. Live router only.
pub async fn api_apply_unit_override(
    State(combined): State<CombinedState>,
    Path(unit_id): Path<String>,
    Json(request): Json<UnitOverrideRequest>,
) -> Result<Json<UnitOverrideResponse>, ServerError> {
    let overrides = override_handle(&combined)?;
    let (binary, function) = parse_unit_id(&unit_id)?;
    overrides
        .set(&binary, &function, request.r#override)
        .map_err(persist_error)?;
    info!(binary, function, "override: unit override applied via API");
    Ok(override_response(&unit_id, &overrides, &binary, &function))
}

/// Handle `DELETE /api/units/{id}/override` — drop the unit's override;
/// the unit falls back to automatic behavior. Removing an absent override
/// is not an error. Live router only.
pub async fn api_remove_unit_override(
    State(combined): State<CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<UnitOverrideResponse>, ServerError> {
    let overrides = override_handle(&combined)?;
    let (binary, function) = parse_unit_id(&unit_id)?;
    overrides
        .remove(&binary, &function)
        .map_err(persist_error)?;
    info!(binary, function, "override: unit override removed via API");
    Ok(override_response(&unit_id, &overrides, &binary, &function))
}

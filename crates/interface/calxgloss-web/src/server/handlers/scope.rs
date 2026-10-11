//! Translation scope control endpoints (issue #93, W2.5).
//!
//! The operator steers the live run over REST: which binaries to translate,
//! which functions to skip or prioritize, and the constraints that bound
//! consumption. All six endpoints are live-router only — a plain `serve`
//! router has no pipeline to steer — and each answers 503 when the live
//! router was built without a scope handle attached, mirroring the
//! lifecycle endpoints' honesty rule.

use super::super::{
    CombinedState, ScopeBinariesRequest, ScopeFunctionRequest, ScopeStatusResponse, ServerError,
};

use axum::{Json, extract::State};
use calxgloss_types::{BinaryIdentity, ScopeControl, TranslationConstraints};
use tracing::info;

/// The scope handle every endpoint needs: 503 when this live router was
/// built without one — honest rather than steering a pipeline that does
/// not exist.
fn scope_handle(combined: &CombinedState) -> Result<ScopeControl, ServerError> {
    combined
        .server
        .scope_control()
        .ok_or_else(|| ServerError::unavailable("this server has no scope control attached"))
}

/// The status payload every endpoint echoes: current scope, constraints,
/// and the run's token spend.
fn status(scope: &ScopeControl) -> Json<ScopeStatusResponse> {
    Json(ScopeStatusResponse {
        scope: scope.scope(),
        constraints: scope.constraints(),
        tokens_spent: scope.tokens_spent(),
    })
}

/// Map a persistence failure — the record could not be written under the
/// workspace's record tree — to an internal error the operator cannot fix
/// by changing the request.
fn persist_error(e: calxgloss_types::PersistError) -> ServerError {
    ServerError::internal(&format!("failed to persist scope record: {e}"))
}

/// Handle `GET /api/scope` — the operator's current scope, the constraints
/// in force, and the tokens spent against the budget. Live router only.
pub async fn api_scope_status(
    State(combined): State<CombinedState>,
) -> Result<Json<ScopeStatusResponse>, ServerError> {
    Ok(status(&scope_handle(&combined)?))
}

/// Handle `POST /api/scope/binaries` — replace the list of target
/// binaries. An empty list puts every discovered binary back in scope.
/// The next queue selection honors the change. Live router only.
pub async fn api_scope_set_binaries(
    State(combined): State<CombinedState>,
    Json(request): Json<ScopeBinariesRequest>,
) -> Result<Json<ScopeStatusResponse>, ServerError> {
    let scope = scope_handle(&combined)?;
    let binaries: Vec<BinaryIdentity> = request
        .binaries
        .into_iter()
        .map(BinaryIdentity::new)
        .collect();
    scope.set_binaries(binaries).map_err(persist_error)?;
    info!("scope: binary list replaced via API");
    Ok(status(&scope))
}

/// Handle `POST /api/scope/skip-function` — the function leaves the queue
/// plan at the next queue selection and is never attempted. Live router
/// only.
pub async fn api_scope_skip_function(
    State(combined): State<CombinedState>,
    Json(request): Json<ScopeFunctionRequest>,
) -> Result<Json<ScopeStatusResponse>, ServerError> {
    let scope = scope_handle(&combined)?;
    scope
        .skip_function(&request.binary, &request.function)
        .map_err(persist_error)?;
    info!(
        binary = %request.binary,
        function = %request.function,
        "scope: function skipped via API"
    );
    Ok(status(&scope))
}

/// Handle `POST /api/scope/priority-function` — the function sorts ahead
/// of the rest of the queue at the next queue selection. Live router only.
pub async fn api_scope_priority_function(
    State(combined): State<CombinedState>,
    Json(request): Json<ScopeFunctionRequest>,
) -> Result<Json<ScopeStatusResponse>, ServerError> {
    let scope = scope_handle(&combined)?;
    scope
        .prioritize_function(&request.binary, &request.function)
        .map_err(persist_error)?;
    info!(
        binary = %request.binary,
        function = %request.function,
        "scope: function prioritized via API"
    );
    Ok(status(&scope))
}

/// Handle `POST /api/scope/remove-priority-function` — the function drops
/// out of the priority list (issue #95, W2.6 panel's remove button); the
/// next queue selection no longer sorts it ahead. Removing a function that
/// is not prioritized is not an error. Live router only.
pub async fn api_scope_remove_priority_function(
    State(combined): State<CombinedState>,
    Json(request): Json<ScopeFunctionRequest>,
) -> Result<Json<ScopeStatusResponse>, ServerError> {
    let scope = scope_handle(&combined)?;
    scope
        .remove_priority_function(&request.binary, &request.function)
        .map_err(persist_error)?;
    info!(
        binary = %request.binary,
        function = %request.function,
        "scope: function priority removed via API"
    );
    Ok(status(&scope))
}

/// Handle `POST /api/scope/constraints` — replace the consumption caps
/// (max attempts, max context tier, token budget). A missing field means
/// no cap for that dimension; the caps land on the next unit boundary or
/// escalation, never mid-attempt. Live router only.
pub async fn api_scope_set_constraints(
    State(combined): State<CombinedState>,
    Json(request): Json<TranslationConstraints>,
) -> Result<Json<ScopeStatusResponse>, ServerError> {
    let scope = scope_handle(&combined)?;
    scope.set_constraints(request).map_err(persist_error)?;
    info!("scope: constraints replaced via API");
    Ok(status(&scope))
}

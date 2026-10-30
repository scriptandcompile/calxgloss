//! Core API endpoint handlers: dashboard, units, accept, send-back, patch, graph, health.
//!
//! Also includes the `OptionalJson` body extractor and `trace_middleware`.

use axum::{
    Json,
    extract::{Path, State},
};
use tracing::info;

use super::super::PatchRequest;
use super::super::{
    ActionResponse, CombinedState, HealthResponse, LifecycleStatus, LogLevelRequest,
    LogLevelResponse, PipelineStatus, SendBackRequest, ServerError, ServerLifecycleResponse,
    ServerState, ServerStatus, UnitResponse, UnitResponseInner, UnknownSettleRequest,
};

/// Optional JSON body extractor — `None` when no body is present.
///
/// A body that is present but does not parse is **refused** with 400 and the
/// parser's reason: a malformed request must not look like an absent one, or
/// the operator's send-back note or patch request silently disappears.
pub struct OptionalJson<T>(pub Option<T>);

impl<S, T> axum::extract::FromRequest<S> for OptionalJson<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        use axum::response::IntoResponse as _;

        let body_bytes = match axum::body::Bytes::from_request(req, state).await {
            Ok(bytes) => bytes,
            // The body could not be read at all (too large, connection
            // dropped): pass axum's own rejection through.
            Err(err) => return Err(err.into_response()),
        };
        if body_bytes.is_empty() {
            return Ok(OptionalJson(None));
        }
        match serde_json::from_slice(&body_bytes) {
            Ok(val) => Ok(OptionalJson(Some(val))),
            Err(err) => Err((
                axum::http::StatusCode::BAD_REQUEST,
                format!("request body is not valid JSON: {err}"),
            )
                .into_response()),
        }
    }
}

/// Middleware: log every incoming request with method, path, and status.
pub async fn trace_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;
    let status = response.status();
    info!(%method, %uri, %status, "request");
    response
}

// ─── GET /api/dashboard ──────────────────────────────────────────────

/// Returns the full review dashboard including queue, dependency graph,
/// recent activity, and status counts.
///
/// When the server is running in live mode (e.g. `calxgloss live`), this
/// also merges in-progress translation state so units currently being
/// translated appear as `"in_progress"` on the dashboard.
pub async fn api_get_dashboard(
    State(combined): State<super::super::CombinedState>,
) -> Result<Json<super::super::DashboardResponse>, ServerError> {
    let server_state = combined.server.clone();
    let mut dashboard = super::super::build_dashboard(server_state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;

    // Merge live progress: update units currently being translated.
    if let Some(progress) = &combined.progress {
        let entries = progress.read().await.snapshot().await;
        let in_progress_ids: std::collections::HashSet<&str> =
            entries.keys().map(|k| k.as_str()).collect();

        // Helper: match a dashboard unit against a progress entry.
        let match_unit = |u: &calxgloss_types::UnitOfWork| -> bool {
            let key = format!("{}/{}", u.binary, u.function.as_deref().unwrap_or(""));
            in_progress_ids.contains(key.as_str())
        };

        // Update review_queue: mark matching units as InProgress.
        let mut matched_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

        for unit in &mut dashboard.review_queue {
            if match_unit(unit) {
                let old =
                    std::mem::replace(&mut unit.status, calxgloss_types::ReviewStatus::InProgress);
                if !matches!(old, calxgloss_types::ReviewStatus::Accepted) {
                    unit.updated_at = chrono::Utc::now();
                }
                let key = format!("{}/{}", unit.binary, unit.function.as_deref().unwrap_or(""));
                matched_keys.insert(key);
            }
        }

        // Also check recent_activity
        for unit in &mut dashboard.recent_activity {
            if match_unit(unit) {
                unit.status = calxgloss_types::ReviewStatus::InProgress;
                unit.updated_at = chrono::Utc::now();
                let key = format!("{}/{}", unit.binary, unit.function.as_deref().unwrap_or(""));
                matched_keys.insert(key);
            }
        }

        // Add synthetic units for in-progress items not yet in the dashboard
        for (key, entry) in &entries {
            if matched_keys.contains(key) {
                continue;
            }
            // Create a synthetic unit for this in-progress translation.
            let name = if entry.function.is_empty() {
                format!("Classify {}", entry.binary)
            } else {
                format!("{}!{}", entry.binary, entry.function)
            };
            let unit_id = format!("live/{}/v{}", key, entry.attempt);

            dashboard.review_queue.push(calxgloss_types::UnitOfWork {
                id: unit_id,
                name,
                kind: calxgloss_types::WorkKind::FunctionTranslation,
                binary: entry.binary.clone(),
                function: if entry.function.is_empty() {
                    None
                } else {
                    Some(entry.function.clone())
                },
                attempt: entry.attempt,
                status: calxgloss_types::ReviewStatus::InProgress,
                accepted: false,
                unit_confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                context_tier: None,
                dependencies: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                known_gaps: Vec::new(),
                stale: calxgloss_types::dashboard::Staleness::Fresh,
            });
        }
    }

    let queue_metadata = super::super::QueueMetadata {
        total: dashboard.review_queue.len(),
        queued: dashboard.status_counts.queued,
        pending_review: dashboard.status_counts.pending_review,
        blocked: dashboard.status_counts.blocked,
    };
    let queue_effort =
        super::process::build_queue_effort(server_state.repo_path(), &dashboard.review_queue);

    // Dashboard summary data (issue #66): category counts from the
    // classification artifacts, quality metrics over every dashboard unit,
    // and token totals from the usage log.
    let quality_summary = {
        let mut all_units = dashboard.review_queue.clone();
        all_units.extend(dashboard.recent_activity.iter().cloned());
        super::summary::compute_quality_summary(&all_units)
    };
    let binary_categories = super::summary::compute_binary_categories(server_state.repo_path());
    let token_usage = super::summary::compute_token_usage(server_state.repo_path());

    // Manual queue overlay (issue #74): the persisted manual order and
    // priorities, plus the effective order they produce over this dashboard
    // — dependency order with the overlay breaking same-depth ties.
    let queue_overlay = super::queue::load_queue_overlay(server_state.repo_path());
    let queue_order = super::queue::queue_order(&dashboard, &queue_overlay)
        .into_iter()
        .map(|u| u.id.clone())
        .collect();

    Ok(Json(super::super::DashboardResponse {
        success: true,
        dashboard,
        queue_metadata: Some(queue_metadata),
        queue_effort,
        binary_categories,
        quality_summary,
        token_usage,
        queue_overlay,
        queue_order,
    }))
}

// ─── GET /api/units/:id ──────────────────────────────────────────────

/// Returns detailed information for a single unit of work.
pub async fn api_get_unit(
    State(combined): State<super::super::CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<UnitResponse>, ServerError> {
    let mut dashboard = super::super::build_dashboard(combined.server.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;

    // Merge live progress entries (in-progress translations not yet in the dashboard).
    if let Some(progress) = &combined.progress {
        let entries = progress.read().await.snapshot().await;
        let in_progress_keys: std::collections::HashSet<&str> =
            entries.keys().map(|k| k.as_str()).collect();

        let mut matched_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Update existing units that match progress entries
        for unit in &mut dashboard.review_queue {
            let key = format!("{}/{}", unit.binary, unit.function.as_deref().unwrap_or(""));
            if in_progress_keys.contains(key.as_str()) {
                unit.status = calxgloss_types::ReviewStatus::InProgress;
                unit.updated_at = chrono::Utc::now();
                matched_keys.insert(key);
            }
        }
        for unit in &mut dashboard.recent_activity {
            let key = format!("{}/{}", unit.binary, unit.function.as_deref().unwrap_or(""));
            if in_progress_keys.contains(key.as_str()) {
                unit.status = calxgloss_types::ReviewStatus::InProgress;
                matched_keys.insert(key);
            }
        }

        // Add synthetic units for in-progress entries not yet in the dashboard
        for (key, entry) in &entries {
            if matched_keys.contains(key.as_str()) {
                continue;
            }
            let name = if entry.function.is_empty() {
                format!("Classify {}", entry.binary)
            } else {
                format!("{}!{}", entry.binary, entry.function)
            };
            let synthetic_id = format!("live/{}/v{}", key, entry.attempt);
            dashboard.review_queue.push(calxgloss_types::UnitOfWork {
                id: synthetic_id,
                name,
                kind: calxgloss_types::WorkKind::FunctionTranslation,
                binary: entry.binary.clone(),
                function: if entry.function.is_empty() {
                    None
                } else {
                    Some(entry.function.clone())
                },
                attempt: entry.attempt,
                status: calxgloss_types::ReviewStatus::InProgress,
                accepted: false,
                unit_confidence: None,
                baseline_tests_passed: None,
                baseline_tests_total: None,
                verification_tests_passed: None,
                verification_tests_total: None,
                llm_model: None,
                context_tier: None,
                dependencies: Vec::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                known_gaps: Vec::new(),
                stale: calxgloss_types::dashboard::Staleness::Fresh,
            });
        }
    }

    let unit = dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .ok_or_else(|| ServerError::not_found("Unit not found"))?;

    let state = combined.server.clone();

    let diff_summary = super::diff::compute_diff_summary(&state, unit);
    let attempt_history = super::decomp::load_attempt_history(state.repo_path(), &unit_id);
    let revision_count = super::decomp::compute_revision_count(&state, unit);
    let queue_position = super::queue::compute_queue_position(
        &dashboard,
        unit,
        &super::queue::load_queue_overlay(state.repo_path()),
    );
    let process = super::process::build_unit_process(state.repo_path(), unit);
    let analysis = super::analysis::build_unit_analysis(state.repo_path(), unit);

    Ok(Json(UnitResponse {
        success: true,
        unit: UnitResponseInner {
            id: unit.id.clone(),
            name: unit.name.clone(),
            kind: unit.kind.to_string(),
            binary: unit.binary.clone(),
            function: unit.function.clone(),
            attempt: unit.attempt,
            status: unit.status.to_string(),
            accepted: unit.accepted,
            unit_confidence: unit.unit_confidence,
            baseline_tests_passed: unit.baseline_tests_passed,
            baseline_tests_total: unit.baseline_tests_total,
            verification_tests_passed: unit.verification_tests_passed,
            verification_tests_total: unit.verification_tests_total,
            llm_model: unit.llm_model.clone(),
            context_tier: unit.context_tier,
            dependencies: unit.dependencies.clone(),
            created_at: unit.created_at.to_rfc3339(),
            updated_at: unit.updated_at.to_rfc3339(),
            known_gaps: unit.known_gaps.clone(),
            stale: unit.stale.to_string(),
            diff_summary,
            attempt_history,
            revision_count,
            queue_position,
            process,
            analysis,
        },
    }))
}

// ─── POST /api/units/:id/accept ──────────────────────────────────────

/// Maps a review-action failure to a status: a conflict with the unit's
/// persisted action state becomes a 409 naming the current state (issue #86);
/// an unknown disposition refused because the record changed underneath the
/// reviewer becomes a 409 naming the landed state, and a reasonless settle a
/// 400 the reviewer can fix (issue #374); a record that is not in this unit's
/// reach reads as a 404 — the ledger's unknown reading included, never a
/// false zero; everything else stays a 500.
fn action_error(e: anyhow::Error) -> ServerError {
    if let Some(conflict) = e.downcast_ref::<super::super::actions::ActionConflictError>() {
        return ServerError::Conflict(conflict.to_string());
    }
    if let Some(conflict) = e.downcast_ref::<calxgloss_types::UnknownActionError>() {
        return match conflict {
            calxgloss_types::UnknownActionError::ChangedUnderneath { .. } => {
                ServerError::Conflict(conflict.to_string())
            }
            calxgloss_types::UnknownActionError::EmptyReason { .. } => {
                ServerError::BadRequest(conflict.to_string())
            }
        };
    }
    if let Some(missing) = e.downcast_ref::<super::super::unknown_actions::UnknownReviewError>() {
        return ServerError::not_found(&missing.to_string());
    }
    ServerError::internal(&e.to_string())
}

/// Accepts a unit of work: merges its Git branch into `main` and records the acceptance.
///
/// When the `ActionsState` is configured (via `build_router_with_actions`), this
/// delegates to [`crate::accept_unit`] which also writes
/// a persistent action record.  In the basic router (no actions backend) the Git
/// operation runs directly.
pub async fn api_accept_unit(
    State(combined): State<super::super::CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<ActionResponse>, ServerError> {
    let result = perform_accept(&combined, &unit_id).await?;
    Ok(Json(result))
}

/// The per-unit accept logic, shared by the single-unit endpoint and the
/// batch endpoint (issue #78) so a batch accept is exactly N accepts — same
/// conflict checks, same persistence, no duplicated state transitions.
pub(crate) async fn perform_accept(
    combined: &super::super::CombinedState,
    unit_id: &str,
) -> Result<ActionResponse, ServerError> {
    // If ActionsState is present, use it — it provides richer side-effects
    // (persistent action state, translator integration).
    if let Some(actions) = &combined.actions {
        let result = super::super::actions::accept_unit(actions, unit_id)
            .await
            .map_err(action_error)?;
        return Ok(ActionResponse {
            unit_id: result.unit_id,
            action: result.action,
            merge_hash: result.merge_hash,
            branch_name: result.branch_name,
            message: result.message,
            rejection_path: result.rejection_path,
        });
    }

    // Legacy path: direct Git operation (basic router, no actions backend)
    let state = &combined.server;
    let unit = super::queue::find_unit(state, unit_id)?;

    let branch = calxgloss_types::GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )
    .map_err(|e| ServerError::internal(&format!("Invalid branch name: {e}")))?;

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let result = git
        .accept_branch(&branch)
        .map_err(|e| ServerError::internal(&format!("Failed to accept branch: {e}")))?;

    let merge_hash = match &result {
        calxgloss_git::MergeResult::Merged { merge_hash } => Some(merge_hash.clone()),
        calxgloss_git::MergeResult::AlreadyUpToDate => None,
        // A conflicted merge adds nothing to main — report the conflict
        // instead of answering as if the unit had been accepted (issue #83).
        calxgloss_git::MergeResult::Conflicts {
            conflicted_files,
            error,
        } => {
            return Err(ServerError::internal(&format!(
                "Cannot accept unit {unit_id}: {error} — conflicted files: {}",
                conflicted_files.join(", ")
            )));
        }
    };

    info!("Unit {unit_id} accepted — branch {} merged", branch.name);

    Ok(ActionResponse {
        unit_id: unit_id.to_string(),
        action: "accept".to_string(),
        merge_hash,
        branch_name: Some(branch.name),
        message: "Unit accepted and merged to main".to_string(),
        rejection_path: None,
    })
}

// ─── POST /api/units/:id/send-back ───────────────────────────────────

/// Sends a unit back to the LLM with the reviewer's reason.
///
/// When `ActionsState` is present this also writes a persistent action record.
pub async fn api_send_back_unit(
    State(combined): State<super::super::CombinedState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<SendBackRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let reason = body
        .map(|b| b.reason)
        .unwrap_or_else(|| "Needs revision".to_string());
    let result = perform_send_back(&combined, &unit_id, &reason).await?;
    Ok(Json(result))
}

/// The per-unit send-back logic, shared by the single-unit endpoint and the
/// batch endpoint (issue #78) so a batch send-back is exactly N send-backs —
/// same conflict checks, same persistence, no duplicated state transitions.
pub(crate) async fn perform_send_back(
    combined: &super::super::CombinedState,
    unit_id: &str,
    reason: &str,
) -> Result<ActionResponse, ServerError> {
    // If ActionsState is present, use it
    if let Some(actions) = &combined.actions {
        let result = super::super::actions::send_back_unit(actions, unit_id, reason)
            .await
            .map_err(action_error)?;
        return Ok(ActionResponse {
            unit_id: result.unit_id,
            action: result.action,
            merge_hash: result.merge_hash,
            branch_name: result.branch_name,
            message: result.message,
            rejection_path: result.rejection_path,
        });
    }

    // Legacy path
    let state = &combined.server;
    let unit = super::queue::find_unit(state, unit_id)?;

    let branch = calxgloss_types::GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )
    .map_err(|e| ServerError::internal(&format!("Invalid branch name: {e}")))?;

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let rejection_path = git
        .reject_branch(&branch, reason)
        .map_err(|e| ServerError::internal(&format!("Failed to reject branch: {e}")))?;

    info!("Unit {unit_id} send back — reason: {reason:?}");

    Ok(ActionResponse {
        unit_id: unit_id.to_string(),
        action: "send_back".to_string(),
        merge_hash: None,
        branch_name: Some(branch.name),
        message: format!("Unit sent back: {reason}"),
        rejection_path: Some(rejection_path.to_string_lossy().to_string()),
    })
}

// ─── POST /api/units/:id/patch ──────────────────────────────────────

/// Requests a patch for a unit of work, identifying the specific issue.
///
/// Delegates to [`crate::request_patch`] which:
/// 1. Returns the existing in-progress patch if the unit's next attempt
///    already has one (`action: "patch_already_in_progress"`, issue #84).
/// 2. Creates a new version branch (v{N+1}) via `calxgloss-git`.
/// 3. Persists the patch request record to `re/patches/`.
/// 4. Spawns an async retry translation via `calxgloss-translator`.
///
/// The retry pass itself is assembled per request from the actions
/// backend's settings-folded description (issue #327) — the canned
/// "patch requested" response this endpoint used to fabricate when the
/// router had no actions backend is gone: a router built without one now
/// honestly refuses instead of pretending a retry started.
pub async fn api_request_patch(
    State(combined): State<super::super::CombinedState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<PatchRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let issue = body
        .map(|b| b.issue)
        .unwrap_or_else(|| "Unknown issue".to_string());

    let actions = combined.actions.ok_or_else(|| {
        ServerError::internal(
            "patch retry needs the settings-backed actions backend — this server was built without one",
        )
    })?;
    let result = super::super::actions::request_patch(&actions, &unit_id, &issue)
        .await
        .map_err(action_error)?;
    Ok(Json(ActionResponse {
        unit_id: result.unit_id,
        action: result.action,
        merge_hash: result.merge_hash,
        branch_name: result.branch_name,
        message: result.message,
        rejection_path: result.rejection_path,
    }))
}

// ─── POST /api/units/:id/unknowns/:unknown_id/{resolve,dismiss,reopen} ──

/// Settles one of the unit's open unknown records as *resolved* (issue
/// #374): the reviewer established the fact the filed record asks about,
/// on the grounds the body's reason line states. The settlement lands in
/// the reviewer's own resolutions document under the same action lock the
/// unit actions take; the pipeline's ledger is never written here, and the
/// unit's review status, verdict, and branch stay exactly as they were —
/// resolving an unknown is deliberately not a review status. A settle
/// against a record that changed underneath the reviewer loses with a 409
/// naming the landed state.
pub async fn api_resolve_unknown(
    State(combined): State<super::super::CombinedState>,
    Path((unit_id, unknown_id)): Path<(String, String)>,
    Json(request): Json<UnknownSettleRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let actions = unknown_actions_backend(&combined)?;
    let result = super::super::unknown_actions::resolve_unknown(
        actions,
        &unit_id,
        &unknown_id,
        &request.reason,
        request.expected_revision,
    )
    .await
    .map_err(action_error)?;
    Ok(Json(ActionResponse {
        unit_id: result.unit_id,
        action: result.action,
        merge_hash: result.merge_hash,
        branch_name: result.branch_name,
        message: result.message,
        rejection_path: result.rejection_path,
    }))
}

/// Settles one of the unit's open unknown records as *dismissed* (issue
/// #374): the reviewer judged the question irrelevant and says so with a
/// reason. A dismissed record is still visible as dismissed — the
/// disposition records what was decided, never pretends the gap was never
/// there — and the revision guard and document discipline are exactly the
/// resolve ones.
pub async fn api_dismiss_unknown(
    State(combined): State<super::super::CombinedState>,
    Path((unit_id, unknown_id)): Path<(String, String)>,
    Json(request): Json<UnknownSettleRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let actions = unknown_actions_backend(&combined)?;
    let result = super::super::unknown_actions::dismiss_unknown(
        actions,
        &unit_id,
        &unknown_id,
        &request.reason,
        request.expected_revision,
    )
    .await
    .map_err(action_error)?;
    Ok(Json(ActionResponse {
        unit_id: result.unit_id,
        action: result.action,
        merge_hash: result.merge_hash,
        branch_name: result.branch_name,
        message: result.message,
        rejection_path: result.rejection_path,
    }))
}

/// Takes a settled unknown record back to open (issue #374): a resolution
/// is a revision, never a deletion. The reopen appends a durable mark in
/// the reviewer's document naming the revision the settlement was taken
/// back from — the pipeline's next ledger write appends one revision above
/// the landed one at that mark — and an unsettled record refuses with a
/// 409 naming the landed open state.
pub async fn api_reopen_unknown(
    State(combined): State<super::super::CombinedState>,
    Path((unit_id, unknown_id)): Path<(String, String)>,
) -> Result<Json<ActionResponse>, ServerError> {
    let actions = unknown_actions_backend(&combined)?;
    let result = super::super::unknown_actions::reopen_unknown(actions, &unit_id, &unknown_id)
        .await
        .map_err(action_error)?;
    Ok(Json(ActionResponse {
        unit_id: result.unit_id,
        action: result.action,
        merge_hash: result.merge_hash,
        branch_name: result.branch_name,
        message: result.message,
        rejection_path: result.rejection_path,
    }))
}

/// The disposition endpoints ride the actions backend for its action lock —
/// the same one accept, send-back, and patch serialize on. A server built
/// without one refuses honestly instead of racing an unlocked
/// read-modify-write of the reviewer's resolutions document (issue #374),
/// exactly as the patch endpoint names its missing backend.
fn unknown_actions_backend(
    combined: &super::super::CombinedState,
) -> Result<&super::super::ActionsState, ServerError> {
    combined.actions.as_ref().ok_or_else(|| {
        ServerError::internal(
            "unknown dispositions need the actions backend — this server was built without one",
        )
    })
}

// ─── GET /api/graph ──────────────────────────────────────────────────

/// Returns the dependency graph for visualization in the web UI.
///
/// The dashboard units already supply each node's binary and confidence.
/// This handler adds each node's total token usage, read from
/// `re/analysis/token_usage.json` (issue #76). A unit with no recorded
/// attempts keeps `token_usage: null` — absence is reported honestly, never
/// as zero.
pub async fn api_get_dependency_graph(
    State(state): State<ServerState>,
) -> Result<Json<super::super::DependencyGraphResponse>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    let mut graph = dashboard.dependency_graph;
    enrich_graph_token_usage(&mut graph, state.repo_path());
    Ok(Json(super::super::DependencyGraphResponse::ok(graph)))
}

/// Attaches per-node token totals to the graph from the token-usage log.
///
/// A node's total is the sum of `tokens_used` over the log entries whose
/// (binary, function) pair matches the node's unit — the same join the unit
/// detail process section uses. The pair is read from the node's own unit
/// reference (`{binary}/{function}/v{N}`, parsed by the shared branch-name
/// grammar), so
/// every graph node is joined regardless of which dashboard list its status
/// routes it into. A missing or corrupt log, or no entries for the unit,
/// leaves the node at `None`; entries that sum to zero are a real total.
fn enrich_graph_token_usage(
    graph: &mut calxgloss_types::DependencyGraph,
    repo_path: &std::path::Path,
) {
    let entries = super::process::load_json_or_default::<calxgloss_types::TokenUsageLog>(
        &super::process::token_usage_log_path(repo_path),
    )
    .entries;
    if entries.is_empty() {
        return;
    }

    for node in &mut graph.nodes {
        let Some(parts) = calxgloss_types::parse_branch_name(&node.unit_id) else {
            continue;
        };
        let Some(function) = parts.function.as_deref() else {
            continue;
        };
        let matched: Vec<&calxgloss_types::TokenUsageEntry> = entries
            .iter()
            .filter(|e| {
                super::process::binary_matches(&e.binary, parts.binary.as_str())
                    && e.function == function
            })
            .collect();
        if !matched.is_empty() {
            node.token_usage = Some(matched.iter().map(|e| e.tokens_used).sum());
        }
    }
}

// ─── GET /health ─────────────────────────────────────────────────────

/// Health check endpoint — one endpoint, enhanced in place (issue #59):
/// liveness plus workspace accessibility, uptime, and version. There is
/// deliberately no second health alias.
pub async fn api_health(
    State(state): State<ServerState>,
) -> Result<Json<HealthResponse>, ServerError> {
    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        repo_accessible: state.repo_path().exists(),
        uptime_secs: state.uptime().as_secs(),
        version: ServerState::version().to_string(),
    }))
}

// ─── GET /api/server/status ──────────────────────────────────────────

/// Server status endpoint: pipeline state, uptime, version, host, log level,
/// memory/CPU usage, live WebSocket connection count, and open file handles.
///
/// Registered in **all** routers. Routers without live state report
/// [`PipelineStatus::Unavailable`] and zero connections rather than
/// fabricating live data.
pub async fn api_server_status(State(combined): State<CombinedState>) -> Json<ServerStatus> {
    let server = &combined.server;

    // Issue #90: when a live run shares its PipelineControl, the reported
    // status is the state machine's own state — the dashboard header and
    // the pipeline always agree, even while a paused run still holds a
    // unit record in flight. Without a control (live router built without
    // one, or plain live wiring predating W2.1) fall back to the old
    // in-flight-unit inference.
    let pipeline_status = match server.pipeline_control() {
        Some(control) => PipelineStatus::from(control.state()),
        None => match &combined.progress {
            None => PipelineStatus::Unavailable,
            Some(progress) => {
                if progress.read().await.in_flight_count().await > 0 {
                    PipelineStatus::Running
                } else {
                    PipelineStatus::Idle
                }
            }
        },
    };
    let ws_connections = match &combined.manager {
        Some(manager) => manager.connection_count().await,
        None => 0,
    };
    let sample = server.metrics.sample();

    Json(ServerStatus {
        pipeline_status,
        uptime_secs: server.uptime().as_secs(),
        version: ServerState::version().to_string(),
        host: server.host().to_string(),
        log_level: server.log_level(),
        memory_mb: sample.memory_mb,
        cpu_percent: sample.cpu_percent,
        ws_connections,
        open_file_handles: sample.open_file_handles,
    })
}

// ─── POST /api/server/shutdown ───────────────────────────────────────

/// The action both lifecycle endpoints share (issue #60): pause a live run at
/// its unit boundary through the shared stop signal, then stop the accept
/// loop. On plain `serve` there is no pipeline attached, so only the server
/// stops.
fn stop_pipeline_and_server(state: &ServerState) {
    state.stop_signal().stop();
    state.request_shutdown();
}

/// Whether this router is serving a live run (`calxgloss live`) rather than
/// a plain review server — decides how the operator-facing message should
/// describe what is stopping.
fn is_live_router(combined: &CombinedState) -> bool {
    combined.manager.is_some()
}

/// Graceful shutdown (issue #60): stops accepting new requests (in-flight
/// ones finish), and — when a live pipeline is attached — pauses the run at
/// the current **unit boundary** via the shared stop signal. The unit in
/// flight completes and its result is saved (each unit is persisted and
/// committed as it finishes), then the process exits.
///
/// Registered in **all** routers; on plain `serve` there is no pipeline to
/// pause, so only the server stops.
pub async fn api_server_shutdown(
    State(combined): State<CombinedState>,
) -> Json<ServerLifecycleResponse> {
    info!("graceful shutdown requested via API");
    let live = is_live_router(&combined);
    stop_pipeline_and_server(&combined.server);
    Json(ServerLifecycleResponse {
        status: LifecycleStatus::ShuttingDown,
        message: if live {
            "Pipeline will stop at the current unit boundary; the server is shutting down."
                .to_string()
        } else {
            "Server is shutting down.".to_string()
        },
        restart_required: false,
    })
}

// ─── POST /api/server/restart ────────────────────────────────────────

/// Restart, MVP form (issue #60): saves state the same way shutdown does
/// (current unit completes and persists), stops the process, and returns a
/// clear **manual restart** signal. The web server does not own the
/// pipeline process, so zero-downtime forking is deliberately not attempted
/// — the operator restarts the command themselves.
///
/// Registered in **all** routers.
pub async fn api_server_restart(
    State(combined): State<CombinedState>,
) -> Json<ServerLifecycleResponse> {
    info!("restart requested via API — stopping process, manual restart required");
    let live = is_live_router(&combined);
    stop_pipeline_and_server(&combined.server);
    Json(ServerLifecycleResponse {
        status: LifecycleStatus::Stopping,
        message: if live {
            "Server stopped. Restart manually with the same command (`calxgloss live`) — the run \
             picks up from the state saved so far."
                .to_string()
        } else {
            "Server stopped. Restart manually with the same command (`calxgloss serve`)."
                .to_string()
        },
        restart_required: true,
    })
}

// ─── PATCH /api/server/log-level ─────────────────────────────────────

/// Runtime log-level change (issue #60): validates the level name and
/// reloads the process's tracing `EnvFilter`. The change is scoped to the
/// running process — nothing persists, and the next start re-reads the CLI
/// verbosity flags. An invalid level name answers 400.
///
/// Registered in **all** routers.
pub async fn api_server_log_level(
    State(combined): State<CombinedState>,
    Json(req): Json<LogLevelRequest>,
) -> Result<Json<LogLevelResponse>, ServerError> {
    let level = combined.server.set_log_level(&req.level)?;
    info!(%level, "log level changed at runtime (process-lifetime only)");
    Ok(Json(LogLevelResponse { level }))
}

/// Serve the frontend index page.
///
/// Reads from the `static/` directory relative to this crate's manifest
/// directory so it works regardless of the process's current working dir.
pub async fn serve_index() -> axum::response::Html<String> {
    let base = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(base).join("static/index.html");
    axum::response::Html(
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {}", path.display(), e);
                "<!DOCTYPE html><html><head><title>Calxgloss</title></head><body><h1>Static frontend not found</h1></body></html>".to_string()
            })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::FromRequest as _;

    #[tokio::test]
    async fn optional_json_reports_an_absent_body_as_absent() {
        let req = axum::extract::Request::builder()
            .method("POST")
            .body(axum::body::Body::empty())
            .expect("build request");

        let OptionalJson(body) = OptionalJson::<SendBackRequest>::from_request(req, &())
            .await
            .expect("an absent body is accepted");
        assert!(body.is_none(), "no body means no request data");
    }

    #[tokio::test]
    async fn optional_json_refuses_a_malformed_body_with_400() {
        let req = axum::extract::Request::builder()
            .method("POST")
            .body(axum::body::Body::from(r#"{"reason": "#))
            .expect("build request");

        let outcome = OptionalJson::<SendBackRequest>::from_request(req, &()).await;
        let err = match outcome {
            Ok(_) => panic!("a malformed body must be refused, not mistaken for an absent one"),
            Err(err) => err,
        };
        assert_eq!(err.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}

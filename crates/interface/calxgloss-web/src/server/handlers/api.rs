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
    ServerState, ServerStatus, UnitResponse, UnitResponseInner,
};

/// Optional JSON body extractor — returns None when no body is present.
pub struct OptionalJson<T>(pub Option<T>);

impl<S, T> axum::extract::FromRequest<S> for OptionalJson<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let body_bytes = match axum::body::Bytes::from_request(req, state).await {
            Ok(bytes) => bytes,
            Err(_) => return Ok(OptionalJson(None)),
        };
        if body_bytes.is_empty() {
            return Ok(OptionalJson(None));
        }
        match serde_json::from_slice(&body_bytes) {
            Ok(val) => Ok(OptionalJson(Some(val))),
            Err(_) => Ok(OptionalJson(None)),
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

    Ok(Json(super::super::DashboardResponse {
        success: true,
        dashboard,
        queue_metadata: Some(queue_metadata),
        queue_effort,
        binary_categories,
        quality_summary,
        token_usage,
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
    let attempt_history = super::ghidra::load_attempt_history(state.repo_path(), &unit_id);
    let revision_count = super::ghidra::compute_revision_count(&state, unit);
    let queue_position = super::queue::compute_queue_position(&dashboard, unit);
    let process = super::process::build_unit_process(state.repo_path(), unit);

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
        },
    }))
}

// ─── POST /api/units/:id/accept ──────────────────────────────────────

/// Accepts a unit of work: merges its Git branch into `main` and records the acceptance.
///
/// When the `ActionsState` is configured (via `build_router_with_actions`), this
/// delegates to [`calxgloss_web::server::actions::accept_unit`] which also writes
/// a persistent action record.  In the basic router (no actions backend) the Git
/// operation runs directly as before.
pub async fn api_accept_unit(
    State(combined): State<super::super::CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<ActionResponse>, ServerError> {
    // If ActionsState is present, use it — it provides richer side-effects
    // (persistent action state, translator integration).
    if let Some(actions) = combined.actions {
        let result = super::super::actions::accept_unit(&actions, &unit_id)
            .await
            .map_err(|e| ServerError::internal(&e.to_string()))?;
        return Ok(Json(ActionResponse {
            unit_id: result.unit_id,
            action: result.action,
            merge_hash: result.merge_hash,
            branch_name: result.branch_name,
            message: result.message,
            rejection_path: result.rejection_path,
        }));
    }

    // Legacy path: direct Git operation (basic router, no actions backend)
    let state = combined.server;
    let unit = super::queue::find_unit(&state, &unit_id)?;

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
        calxgloss_git::MergeResult::Conflicts { .. } => None,
    };

    info!("Unit {unit_id} accepted — branch {} merged", branch.name);

    Ok(Json(ActionResponse {
        unit_id,
        action: "accept".to_string(),
        merge_hash,
        branch_name: Some(branch.name),
        message: "Unit accepted and merged to main".to_string(),
        rejection_path: None,
    }))
}

// ─── POST /api/units/:id/send-back ───────────────────────────────────

/// Sends a unit back to the LLM with reviewer comments.
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

    // If ActionsState is present, use it
    if let Some(actions) = combined.actions {
        let result = super::super::actions::send_back_unit(&actions, &unit_id, &reason)
            .await
            .map_err(|e| ServerError::internal(&e.to_string()))?;
        return Ok(Json(ActionResponse {
            unit_id: result.unit_id,
            action: result.action,
            merge_hash: result.merge_hash,
            branch_name: result.branch_name,
            message: result.message,
            rejection_path: result.rejection_path,
        }));
    }

    // Legacy path
    let state = combined.server;
    let unit = super::queue::find_unit(&state, &unit_id)?;

    let branch = calxgloss_types::GitBranch::new(
        &unit.binary,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )
    .map_err(|e| ServerError::internal(&format!("Invalid branch name: {e}")))?;

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let rejection_path = git
        .reject_branch(&branch, &reason)
        .map_err(|e| ServerError::internal(&format!("Failed to reject branch: {e}")))?;

    info!("Unit {unit_id} send back — reason: {reason:?}");

    Ok(Json(ActionResponse {
        unit_id,
        action: "send_back".to_string(),
        merge_hash: None,
        branch_name: Some(branch.name),
        message: format!("Unit sent back: {reason}"),
        rejection_path: Some(rejection_path.to_string_lossy().to_string()),
    }))
}

// ─── POST /api/units/:id/patch ──────────────────────────────────────

/// Requests a patch for a unit of work, identifying the specific issue.
///
/// This is the real implementation (step 5.7): it delegates to
/// [`calxgloss_web::server::actions::request_patch`] which:
/// 1. Creates a new version branch (v{N+1}) via `calxgloss-git`.
/// 2. Persists the patch request record to `re/patches/`.
/// 3. Spawns an async retry translation via `calxgloss-translator`.
pub async fn api_request_patch(
    State(combined): State<super::super::CombinedState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<PatchRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let issue = body
        .map(|b| b.issue)
        .unwrap_or_else(|| "Unknown issue".to_string());

    // If ActionsState is present, use the real implementation
    if let Some(actions) = combined.actions {
        let result = super::super::actions::request_patch(&actions, &unit_id, &issue)
            .await
            .map_err(|e| ServerError::internal(&e.to_string()))?;
        return Ok(Json(ActionResponse {
            unit_id: result.unit_id,
            action: result.action,
            merge_hash: result.merge_hash,
            branch_name: result.branch_name,
            message: result.message,
            rejection_path: result.rejection_path,
        }));
    }

    // Fallback for basic router (no translator integration): return stub response
    // This keeps the API working even without the full pipeline set up.
    let state = combined.server;
    let unit = super::queue::find_unit(&state, &unit_id)?;

    let branch_name = format!(
        "re/{}{}/v{}",
        unit.binary,
        unit.function
            .as_deref()
            .map(|f| format!("/{f}"))
            .unwrap_or_default(),
        unit.attempt
    );

    Ok(Json(ActionResponse {
        unit_id,
        action: "patch_requested".to_string(),
        merge_hash: None,
        branch_name: Some(branch_name),
        message: format!("Patch requested: {issue}"),
        rejection_path: None,
    }))
}

// ─── GET /api/graph ──────────────────────────────────────────────────

/// Returns the dependency graph for visualization in the web UI.
pub async fn api_get_dependency_graph(
    State(state): State<ServerState>,
) -> Result<Json<super::super::DependencyGraphResponse>, ServerError> {
    let dashboard = super::super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(super::super::DependencyGraphResponse::ok(
        dashboard.dependency_graph,
    )))
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

    let pipeline_status = match &combined.progress {
        None => PipelineStatus::Unavailable,
        Some(progress) => {
            if progress.read().await.in_flight_count().await > 0 {
                PipelineStatus::Running
            } else {
                PipelineStatus::Idle
            }
        }
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
/// verbosity flags. Invalid names are rejected with 400.
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

//! Axum handler functions for the review dashboard API.

use axum::{
    Json,
    extract::{Path, Request, State},
    extract::FromRequest,
    response::Response,
    body::Bytes,
};
use tracing::info;

use super::{
    ServerState, ActionResponse, DiffSummary, PatchRequest, QueueEntry,
    QueuePosition, QueueResponse, SendBackRequest, ServerError, UnitResponse, UnitResponseInner,
};
use calxgloss_types::ReviewStatus;

/// Optional JSON body extractor — returns None when no body is present.
pub struct OptionalJson<T>(pub Option<T>);

impl<S, T> FromRequest<S> for OptionalJson<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let body_bytes = match Bytes::from_request(req, state).await {
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
    let request_id = uuid::Uuid::new_v4();

    let response = next.run(request).await;
    let status = response.status();

    info!(
        request_id = %request_id,
        method = %method,
        path = %uri,
        status = %status,
        "HTTP request",
    );

    response
}

/// ─── GET /api/dashboard ──────────────────────────────────────────────

/// Returns the full review dashboard including queue, dependency graph,
/// recent activity, and status counts.
pub async fn api_get_dashboard(
    State(state): State<ServerState>,
) -> Result<Json<super::DashboardResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path()).map_err(|e| ServerError::internal(&e.to_string()))?;
    let queue_metadata = super::QueueMetadata {
        total: dashboard.review_queue.len(),
        queued: dashboard.status_counts.queued,
        pending_review: dashboard.status_counts.pending_review,
        blocked: dashboard.status_counts.blocked,
    };
    Ok(Json(super::DashboardResponse {
        success: true,
        dashboard,
        queue_metadata: Some(queue_metadata),
    }))
}

/// ─── GET /api/units/:id ──────────────────────────────────────────────

/// Returns detailed information for a single unit of work.
pub async fn api_get_unit(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<UnitResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path()).map_err(|e| ServerError::internal(&e.to_string()))?;

    let unit = dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .ok_or_else(|| ServerError::not_found("Unit not found"))?;

    let diff_summary = compute_diff_summary(&state, &unit);
    let attempt_history = load_attempt_history(state.repo_path(), &unit_id);
    let revision_count = compute_revision_count(&state, &unit);
    let queue_position = compute_queue_position(&dashboard, &unit);

    Ok(Json(UnitResponse {
        success: true,
        unit: UnitResponseInner {
            id: unit.id.clone(),
            name: unit.name.clone(),
            kind: unit.kind.to_string(),
            dll: unit.dll.clone(),
            function: unit.function.clone(),
            attempt: unit.attempt,
            status: unit.status.to_string(),
            accepted: unit.accepted,
            confidence: unit.confidence,
            baseline_tests_passed: unit.baseline_tests_passed,
            baseline_tests_total: unit.baseline_tests_total,
            verification_tests_passed: unit.verification_tests_passed,
            verification_tests_total: unit.verification_tests_total,
            llm_model: unit.llm_model.clone(),
            prompt_tier: unit.prompt_tier,
            dependencies: unit.dependencies.clone(),
            created_at: unit.created_at.to_rfc3339(),
            updated_at: unit.updated_at.to_rfc3339(),
            known_gaps: unit.known_gaps.clone(),
            stale: unit.stale.to_string(),
            diff_summary,
            attempt_history,
            revision_count,
            queue_position,
        },
    }))
}

/// ─── POST /api/units/:id/accept ──────────────────────────────────────

/// Accepts a unit of work: merges its Git branch into `main` and records the acceptance.
pub async fn api_accept_unit(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<ActionResponse>, ServerError> {
    let unit = find_unit(&state, &unit_id)?;

    let branch = calxgloss_types::GitBranch::new(
        &unit.dll,
        unit.function.as_deref().unwrap_or(""),
        unit.attempt,
    )
    .map_err(|e| ServerError::internal(&format!("Invalid branch name: {e}")))?;

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let result = git.accept_branch(&branch).map_err(|e| {
        ServerError::internal(&format!("Failed to accept branch: {e}"))
    })?;

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

/// ─── POST /api/units/:id/send-back ───────────────────────────────────

/// Sends a unit back to the LLM with reviewer comments.
pub async fn api_send_back_unit(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<SendBackRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let unit = find_unit(&state, &unit_id)?;
    let reason = body.map(|b| b.reason).unwrap_or_else(|| "Needs revision".to_string());

    let branch = calxgloss_types::GitBranch::new(
        &unit.dll,
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
        rejection_path: Some(
            rejection_path
                .to_string_lossy()
                .to_string(),
        ),
    }))
}

/// ─── POST /api/units/:id/patch ──────────────────────────────────────

/// Requests a patch for a unit of work, identifying the specific issue.
pub async fn api_request_patch(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<PatchRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let unit = find_unit(&state, &unit_id)?;
    let issue = body.map(|b| b.issue).unwrap_or_else(|| "Unknown issue".to_string());

    info!("Unit {unit_id} patch requested — issue: {issue:?}");

    let branch_name = format!(
        "re/{}{}/v{}",
        unit.dll,
        unit
            .function
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

/// ─── GET /api/graph ──────────────────────────────────────────────────

/// Returns the dependency graph for visualization in the web UI.
pub async fn api_get_dependency_graph(
    State(state): State<ServerState>,
) -> Result<Json<super::DependencyGraphResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path()).map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(super::DependencyGraphResponse::ok(
        dashboard.dependency_graph,
    )))
}

/// ─── GET /api/queue ──────────────────────────────────────────────────

/// Returns the full review queue sorted by dependency order.
pub async fn api_get_queue(
    State(state): State<ServerState>,
) -> Result<Json<QueueResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path()).map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(QueueResponse::from_dashboard(&dashboard)))
}

/// ─── GET /api/queue/next ─────────────────────────────────────────────

/// Returns the next unit in the review queue based on dependency order.
pub async fn api_get_next_unit(
    State(state): State<ServerState>,
) -> Result<Json<Option<QueueEntry>>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path()).map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(
        dashboard
            .next_in_dependency_order()
            .map(|u| QueueEntry {
                id: u.id.clone(),
                name: u.name.clone(),
                kind: u.kind.to_string(),
                dll: u.dll.clone(),
                function: u.function.clone(),
                status: u.status.to_string(),
                stale: u.stale.to_string(),
                blocked: matches!(u.status, ReviewStatus::Blocked),
            }),
    ))
}

// ─── Helper functions ─────────────────────────────────────────────────

/// Find a unit by ID using the repository's review dashboard.
fn find_unit(state: &ServerState, unit_id: &str) -> Result<calxgloss_types::UnitOfWork, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path()).map_err(|e| ServerError::internal(&e.to_string()))?;
    dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .cloned()
        .ok_or_else(|| ServerError::not_found(&format!("Unit not found: {unit_id}")))
}

/// Compute the position of a unit in the dependency-ordered queue.
fn compute_queue_position(
    dashboard: &calxgloss_types::ReviewDashboard,
    unit: &calxgloss_types::UnitOfWork,
) -> QueuePosition {
    let sorted = dashboard.sorted_queue();
    let total = sorted.len();
    let index = sorted.iter().position(|u| u.id == unit.id);
    QueuePosition { index, total }
}

/// ─── GET /health ─────────────────────────────────────────────────────

/// Health check endpoint.
pub async fn api_health(
    State(state): State<ServerState>,
) -> Result<Json<serde_json::Value>, ServerError> {
    let repo_accessible = state.repo_path().exists();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "repo_accessible": repo_accessible,
    })))
}

/// Compute a diff summary between a unit's branch and `main`.
fn compute_diff_summary(
    state: &ServerState,
    unit: &calxgloss_types::UnitOfWork,
) -> DiffSummary {
    let dll = &unit.dll;
    if let Some(function) = unit.function.as_deref() {
        let branch_name = format!("re/{dll}/{function}v{}", unit.attempt);
        if let Ok(git) = calxgloss_git::GitManager::open(state.repo_path()) {
            if let Ok(summary) = compute_branch_diff(&git, &branch_name) {
                return summary;
            }
        }
    }
    DiffSummary { files_changed: 0, insertions: 0, deletions: 0 }
}

/// Compute a diff summary for a specific branch.
fn compute_branch_diff(
    git: &calxgloss_git::GitManager,
    branch_name: &str,
) -> Result<DiffSummary, anyhow::Error> {
    use git2::{DiffFindOptions, DiffOptions};

    let main_ref = git
        .repo()
        .find_branch("main", git2::BranchType::Local)
        .ok()
        .and_then(|b| b.get().peel_to_commit().ok());

    let branch_ref = git
        .repo()
        .find_branch(branch_name, git2::BranchType::Local)
        .ok()
        .and_then(|b| b.get().peel_to_commit().ok());

    let (main_commit, branch_commit) = match (main_ref, branch_ref) {
        (Some(m), Some(b)) => (m, b),
        _ => return Ok(DiffSummary { files_changed: 0, insertions: 0, deletions: 0 }),
    };

    let mut diff_opts = DiffOptions::new();
    let mut diff = git.repo().diff_tree_to_tree(
        Some(&main_commit.tree()?),
        Some(&branch_commit.tree()?),
        Some(&mut diff_opts),
    )?;

    let mut find_opts = DiffFindOptions::new();
    find_opts.renames(true);
    find_opts.rewrites(true);
    diff.find_similar(Some(&mut find_opts))?;

    let stats = diff.stats()?;
    Ok(DiffSummary {
        files_changed: stats.files_changed(),
        insertions: stats.insertions(),
        deletions: stats.deletions(),
    })
}

/// Load attempt history for a unit from patch records on disk.
fn load_attempt_history(
    repo_path: &std::path::Path,
    unit_id: &str,
) -> Vec<super::AttemptRecord> {
    let (dll, function, _attempt) = if let Some(attempt_suffix) = unit_id.rsplit_once('/') {
        let base = attempt_suffix.0;
        if let Some(v) = attempt_suffix.1.strip_prefix('v') {
            let attempt = v.parse::<u32>().unwrap_or(0);
            let parts: Vec<&str> = base.splitn(2, '/').collect();
            let dll = parts[0];
            let function = parts.get(1).copied().unwrap_or("");
            (dll, function, attempt)
        } else {
            return Vec::new();
        }
    } else {
        return Vec::new();
    };

    let patch_dir = repo_path.join("re").join("patches").join(dll).join(function);
    if !patch_dir.exists() {
        return Vec::new();
    }

    let mut records = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&patch_dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if !file_name.ends_with(".json") {
                continue;
            }
            let attempt = file_name
                .strip_prefix('v')
                .and_then(|s| s.trim_end_matches(".json").parse().ok())
                .unwrap_or(0);

            let content = match std::fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let record: calxgloss_git::PatchRecord =
                match serde_json::from_str(&content) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

            records.push(super::AttemptRecord {
                attempt,
                compiled: record.compilation_errors.is_empty(),
                compilation_errors: record.compilation_errors,
                tests_passed: 0,
                tests_total: record.test_failures.len(),
                failed_tests: record.test_failures,
                commit_hash: record.commit_hash,
                committed_at: record.committed_at,
            });
        }
    }

    records.sort_by_key(|r| r.attempt);
    records
}

/// Compute the total number of revisions (attempts) for a unit.
fn compute_revision_count(
    state: &ServerState,
    unit: &calxgloss_types::UnitOfWork,
) -> usize {
    let dll = &unit.dll;
    if let Some(function) = unit.function.as_deref() {
        let branch_prefix = format!("re/{dll}/{function}v");
        if let Ok(git) = calxgloss_git::GitManager::open(state.repo_path()) {
            if let Ok(all_branches) = git.list_branches() {
                return all_branches
                    .iter()
                    .filter(|b| b.starts_with(&branch_prefix))
                    .count();
            }
        }
    }
    1
}

/// Serve the frontend index page.
pub async fn serve_index() -> axum::response::Html<String> {
    axum::response::Html(
        std::fs::read_to_string("static/index.html")
            .unwrap_or_else(|_| "<!DOCTYPE html><html><head><title>Calxgloss</title></head><body><div id=\"app\"></div></body></html>".to_string())
    )
}

/// Fallback for static file requests.
pub async fn static_fallback(path: axum::extract::Path<String>) -> axum::response::Html<String> {
    let file_path = format!("static/{}", path.0);
    if std::path::Path::new(&file_path).exists() {
        let content = std::fs::read_to_string(&file_path).unwrap_or_default();
        axum::response::Html(content)
    } else {
        axum::response::Html("<h1>404 Not Found</h1>".to_string())
    }
}


//! Axum handler functions for the review dashboard API.

use axum::{
    Json,
    body::Bytes,
    extract::FromRequest,
    extract::{Path, Request, State},
    response::Response,
};
use tracing::info;

use super::{
    ActionResponse, DiffFile, DiffHunk, DiffLine, DiffLineType, DiffResponse, DiffSummary,
    GhidraApiCall, GhidraContext, GhidraContextResponse, PatchRequest, QueueEntry, QueuePosition,
    QueueResponse, SendBackRequest, ServerError, ServerState, UnitResponse, UnitResponseInner,
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

// ─── GET /api/dashboard ──────────────────────────────────────────────

/// Returns the full review dashboard including queue, dependency graph,
/// recent activity, and status counts.
pub async fn api_get_dashboard(
    State(state): State<ServerState>,
) -> Result<Json<super::DashboardResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
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

// ─── GET /api/units/:id ──────────────────────────────────────────────

/// Returns detailed information for a single unit of work.
pub async fn api_get_unit(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<UnitResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;

    let unit = dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == unit_id)
        .ok_or_else(|| ServerError::not_found("Unit not found"))?;

    let diff_summary = compute_diff_summary(&state, unit);
    let attempt_history = load_attempt_history(state.repo_path(), &unit_id);
    let revision_count = compute_revision_count(&state, unit);
    let queue_position = compute_queue_position(&dashboard, unit);

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

// ─── POST /api/units/:id/accept ──────────────────────────────────────

/// Accepts a unit of work: merges its Git branch into `main` and records the acceptance.
///
/// When the `ActionsState` is configured (via `build_router_with_actions`), this
/// delegates to [`calxgloss_web::server::actions::accept_unit`] which also writes
/// a persistent action record.  In the basic router (no actions backend) the Git
/// operation runs directly as before.
pub async fn api_accept_unit(
    State(combined): State<super::CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<ActionResponse>, ServerError> {
    // If ActionsState is present, use it — it provides richer side-effects
    // (persistent action state, translator integration).
    if let Some(actions) = combined.actions {
        let result = super::actions::accept_unit(&actions, &unit_id)
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
    let unit = find_unit(&state, &unit_id)?;

    let branch = calxgloss_types::GitBranch::new(
        &unit.dll,
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
    State(combined): State<super::CombinedState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<SendBackRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let reason = body
        .map(|b| b.reason)
        .unwrap_or_else(|| "Needs revision".to_string());

    // If ActionsState is present, use it
    if let Some(actions) = combined.actions {
        let result = super::actions::send_back_unit(&actions, &unit_id, &reason)
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
    let unit = find_unit(&state, &unit_id)?;

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
    State(combined): State<super::CombinedState>,
    Path(unit_id): Path<String>,
    OptionalJson(body): OptionalJson<PatchRequest>,
) -> Result<Json<ActionResponse>, ServerError> {
    let issue = body
        .map(|b| b.issue)
        .unwrap_or_else(|| "Unknown issue".to_string());

    // If ActionsState is present, use the real implementation
    if let Some(actions) = combined.actions {
        let result = super::actions::request_patch(&actions, &unit_id, &issue)
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
    let unit = find_unit(&state, &unit_id)?;

    let branch_name = format!(
        "re/{}{}/v{}",
        unit.dll,
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
) -> Result<Json<super::DependencyGraphResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(super::DependencyGraphResponse::ok(
        dashboard.dependency_graph,
    )))
}

// ─── GET /api/queue ──────────────────────────────────────────────────

/// Returns the full review queue sorted by dependency order.
pub async fn api_get_queue(
    State(state): State<ServerState>,
) -> Result<Json<QueueResponse>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(QueueResponse::from_dashboard(&dashboard)))
}

// ─── GET /api/queue/next ─────────────────────────────────────────────

/// Returns the next unit in the review queue based on dependency order.
pub async fn api_get_next_unit(
    State(state): State<ServerState>,
) -> Result<Json<Option<QueueEntry>>, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path())
        .map_err(|e| ServerError::internal(&e.to_string()))?;
    Ok(Json(dashboard.next_in_dependency_order().map(|u| {
        QueueEntry {
            id: u.id.clone(),
            name: u.name.clone(),
            kind: u.kind.to_string(),
            dll: u.dll.clone(),
            function: u.function.clone(),
            status: u.status.to_string(),
            stale: u.stale.to_string(),
            blocked: matches!(u.status, ReviewStatus::Blocked),
        }
    })))
}

// ─── Helper functions ─────────────────────────────────────────────────

/// Find a unit by ID using the repository's review dashboard.
fn find_unit(
    state: &ServerState,
    unit_id: &str,
) -> Result<calxgloss_types::UnitOfWork, ServerError> {
    let dashboard = super::build_dashboard(state.repo_path())
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
fn compute_queue_position(
    dashboard: &calxgloss_types::ReviewDashboard,
    unit: &calxgloss_types::UnitOfWork,
) -> QueuePosition {
    let sorted = dashboard.sorted_queue();
    let total = sorted.len();
    let index = sorted.iter().position(|u| u.id == unit.id);
    QueuePosition { index, total }
}

// ─── GET /health ─────────────────────────────────────────────────────

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

// ─── GET /api/units/:id/diff ─────────────────────────────────────────

/// Returns the full line-by-line diff between a unit's branch and main.
pub async fn api_get_unit_diff(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<DiffResponse>, ServerError> {
    let unit = find_unit(&state, &unit_id)?;

    let branch_name = match (unit.dll.as_str(), unit.function.as_deref()) {
        (dll, Some(func)) => format!("re/{dll}/{func}v{}", unit.attempt),
        (dll, None) => format!("re/{dll}v{}", unit.attempt),
    };

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let diff_files = compute_line_diff(&git, &branch_name)
        .map_err(|e| ServerError::internal(&format!("Failed to compute diff: {e}")))?;

    Ok(Json(DiffResponse::ok(diff_files)))
}

// ─── GET /api/units/:id/ghidra ───────────────────────────────────────

/// Returns Ghidra context (decompiler output, disassembly, API tags) for a unit's function.
pub async fn api_get_unit_ghidra(
    State(state): State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<GhidraContextResponse>, ServerError> {
    let unit = find_unit(&state, &unit_id)?;

    let func_name = match unit.function {
        Some(ref f) if !f.is_empty() => f.clone(),
        _ => return Ok(Json(GhidraContextResponse::not_found(&unit_id))),
    };

    let dll = unit.dll.clone();

    // Try to read Ghidra data from analysis artifacts on disk
    if let Ok(ctx) = load_ghidra_artifacts(state.repo_path(), &dll, &func_name) {
        return Ok(Json(GhidraContextResponse::ok(ctx)));
    }

    Ok(Json(GhidraContextResponse::not_found(&func_name)))
}

/// Compute a diff summary between a unit's branch and `main`.
fn compute_diff_summary(state: &ServerState, unit: &calxgloss_types::UnitOfWork) -> DiffSummary {
    let dll = &unit.dll;
    if let Some(function) = unit.function.as_deref() {
        let branch_name = format!("re/{dll}/{function}v{}", unit.attempt);
        if let Ok(git) = calxgloss_git::GitManager::open(state.repo_path())
            && let Ok(summary) = compute_branch_diff(&git, &branch_name)
        {
            return summary;
        }
    }
    DiffSummary {
        files_changed: 0,
        insertions: 0,
        deletions: 0,
    }
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
        _ => {
            return Ok(DiffSummary {
                files_changed: 0,
                insertions: 0,
                deletions: 0,
            });
        }
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

/// Compute a full line-by-line diff between a branch and `main`, returning
/// structured `DiffFile` entries suitable for a line-by-line diff viewer.
fn compute_line_diff(
    git: &calxgloss_git::GitManager,
    branch_name: &str,
) -> Result<Vec<DiffFile>, anyhow::Error> {
    let main_ref = git
        .repo()
        .find_branch("main", git2::BranchType::Local)
        .ok()
        .and_then(|b| b.get().peel_to_commit().ok())
        .map(|c| c.id().to_string());

    let branch_ref = git
        .repo()
        .find_branch(branch_name, git2::BranchType::Local)
        .ok()
        .and_then(|b| b.get().peel_to_commit().ok())
        .map(|c| c.id().to_string());

    let (main_hash, branch_hash) = match (main_ref, branch_ref) {
        (Some(m), Some(b)) => (m, b),
        _ => return Ok(Vec::new()),
    };

    // Run `git diff main...branch` to get a unified diff
    let diff_output = std::process::Command::new("git")
        .args(["diff", "--no-color", "--", &main_hash, &branch_hash])
        .current_dir(git.repo().path())
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run git diff: {e}"))?;

    if !diff_output.status.success() {
        return Ok(Vec::new());
    }

    let raw_text = std::str::from_utf8(&diff_output.stdout)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in git diff output: {e}"))?;

    // Parse raw unified diff into files
    let blocks: Vec<&str> = raw_text
        .split("\n@@ -")
        .filter(|s| !s.trim().is_empty())
        .collect();

    let mut files = Vec::new();
    for block in blocks {
        let full_block = format!("@@ -{block}");
        if let Some(file) = parse_diff_block(&full_block) {
            files.push(file);
        }
    }

    Ok(files)
}

/// Parse the raw text output of `git diff --unified` into structured hunks.
fn parse_diff_hunks(raw: &str) -> Vec<DiffHunk> {
    let mut hunks = Vec::new();
    let lines: Vec<&str> = raw.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i];
        // Detect hunk header: @@ -old_start,old_count +new_start,new_count @@ header
        if line.starts_with("@@") && line.ends_with("@@") {
            let mut hunk_lines = Vec::new();
            let header = Some(line.to_string());

            // Parse hunk metadata
            let new_start = extract_hunk_number(line, true).unwrap_or(1);
            let new_lines = extract_hunk_line_count(line, true).unwrap_or(0);
            let old_start = extract_hunk_number(line, false).unwrap_or(1);
            let old_lines = extract_hunk_line_count(line, false).unwrap_or(0);

            let mut new_line = new_start;
            let mut old_line = old_start;

            i += 1; // skip header line

            // Collect lines until the next hunk header or EOF
            while i < lines.len() {
                let next_line = lines[i];
                match next_line {
                    s if s.starts_with("@@") => break,
                    s if s.starts_with("diff --git") => break,
                    s if s.starts_with("index ") => break,
                    s if s.starts_with("new file") => break,
                    s if s.starts_with("deleted file") => break,
                    s if s.starts_with("old mode") => break,
                    s if s.starts_with("new mode") => break,
                    s if s.starts_with("similarity index") => break,
                    s if s.starts_with("rename from") => break,
                    s if s.starts_with("rename to") => break,
                    s if s.starts_with("copy from") => break,
                    s if s.starts_with("copy to") => break,
                    s if s.starts_with("--- ") => break,
                    s if s.starts_with("+++ ") => break,
                    s if s.starts_with("\\ No newline") => {
                        i += 1; // skip annotation
                        continue;
                    }
                    _ => {
                        i += 1;
                        let kind = match next_line.chars().next() {
                            Some('+') => DiffLineType::Addition,
                            Some('-') => DiffLineType::Deletion,
                            _ => DiffLineType::Context,
                        };

                        let content: String = next_line.chars().skip(1).collect();
                        let diff_line = DiffLine {
                            kind,
                            content,
                            new_line: if matches!(
                                kind,
                                DiffLineType::Addition | DiffLineType::Context
                            ) {
                                let l = new_line;
                                if matches!(kind, DiffLineType::Addition) {
                                    new_line += 1;
                                } else {
                                    new_line += 1;
                                }
                                Some(l)
                            } else {
                                None
                            },
                            old_line: if matches!(
                                kind,
                                DiffLineType::Deletion | DiffLineType::Context
                            ) {
                                let l = old_line;
                                if matches!(kind, DiffLineType::Deletion) {
                                    old_line += 1;
                                } else {
                                    old_line += 1;
                                }
                                Some(l)
                            } else {
                                None
                            },
                        };
                        hunk_lines.push(diff_line);
                    }
                }
            }

            hunks.push(DiffHunk {
                new_start,
                new_lines,
                old_start,
                old_lines,
                header,
                lines: hunk_lines,
            });
        } else {
            i += 1;
        }
    }

    hunks
}

/// Extract the start number from a hunk header.
fn extract_hunk_number(hunk_header: &str, is_new: bool) -> Option<usize> {
    let parts: Vec<&str> = hunk_header.split(|c: char| c == ' ' || c == ',').collect();
    // Format: @@ -old_start,old_count +new_start,new_count @@
    // Find the part starting with + (new file) or - (old file)
    for part in parts {
        let part = part.trim();
        if is_new && part.starts_with('+') {
            return part[1..].parse().ok();
        }
        if !is_new && part.starts_with('-') {
            return part[1..].parse().ok();
        }
    }
    None
}

/// Extract the line count from a hunk header.
fn extract_hunk_line_count(hunk_header: &str, is_new: bool) -> Option<usize> {
    let parts: Vec<&str> = hunk_header.split(|c: char| c == ' ' || c == ',').collect();
    for part in parts {
        let part = part.trim();
        if is_new && part.starts_with('+') {
            // Could be just the start number without a comma
            if let Some(idx) = part.find(',') {
                return part[idx + 1..].parse().ok();
            }
        }
        if !is_new && part.starts_with('-') {
            if let Some(idx) = part.find(',') {
                return part[idx + 1..].parse().ok();
            }
        }
    }
    None
}

// ─── Ghidra Context Helpers ─────────────────────────────────────────────

/// Load Ghidra artifacts from the analysis directory on disk.
fn load_ghidra_artifacts(
    repo_path: &std::path::Path,
    dll: &str,
    function: &str,
) -> Result<GhidraContext, anyhow::Error> {
    let analysis_dir = repo_path.join("re").join("analysis").join(dll);
    let func_file = analysis_dir.join(format!("{function}.json"));

    if !func_file.exists() {
        return Err(anyhow::anyhow!(
            "Ghidra analysis file not found: {}",
            func_file.display()
        ));
    }

    let content = std::fs::read_to_string(&func_file)?;

    // Try to deserialize as a FunctionInfo from calxgloss-types
    #[derive(serde::Deserialize)]
    struct GhidraArtifact {
        #[serde(skip_serializing_if = "Option::is_none")]
        decompiler_output: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        windows_apis: Option<Vec<GhidraApiCall>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        function_name: Option<String>,
    }

    let artifact: GhidraArtifact = serde_json::from_str(&content)?;

    Ok(GhidraContext {
        function_name: artifact
            .function_name
            .unwrap_or_else(|| function.to_string()),
        address: None,
        dll: Some(dll.to_string()),
        decompiler_output: artifact.decompiler_output,
        disassembly: None,
        windows_apis: artifact.windows_apis,
        note: None,
    })
}

/// Parse a diff block (starting with `@@`) into a `DiffFile` with file name and hunks.
fn parse_diff_block(block: &str) -> Option<DiffFile> {
    let lines: Vec<&str> = block.lines().collect();
    if lines.is_empty() {
        return None;
    }

    // Extract file path from hunk header
    // Format: @@ -old_start,old_count +new_start,new_count @@ file_path
    let header_line = lines[0];
    let path = if header_line.contains("@@") {
        // Find the last @@ and take everything after it
        if let Some(at_idx) = header_line.rfind("@@") {
            let after_at = header_line[at_idx + 2..].trim();
            if after_at.is_empty() {
                "unknown".to_string()
            } else {
                after_at.to_string()
            }
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    // Re-parse using the unified diff parser (which already handles @@ lines)
    let hunks = parse_diff_hunks(block);

    if hunks.is_empty() {
        return None;
    }

    Some(DiffFile {
        path,
        old_path: None,
        added: false,
        deleted: false,
        renamed: false,
        hunks,
    })
}

/// Load attempt history for a unit from patch records on disk.
fn load_attempt_history(repo_path: &std::path::Path, unit_id: &str) -> Vec<super::AttemptRecord> {
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

    let patch_dir = repo_path
        .join("re")
        .join("patches")
        .join(dll)
        .join(function);
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

            let record: calxgloss_git::PatchRecord = match serde_json::from_str(&content) {
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
fn compute_revision_count(state: &ServerState, unit: &calxgloss_types::UnitOfWork) -> usize {
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

//! Garbage collection (branch cleanup/archive) handlers.

use super::super::{
    GcArchiveRequest, GcArchiveResponse, GcArchiveResult, GcCandidate, GcCandidatesResponse,
    OptionalJson, ServerError, ServerState,
};
use chrono::{Duration, Utc};
use git2::BranchType;

use axum::{
    Json,
    extract::{Query, State},
};
use tracing::info;

// ─── GET /api/gc/candidates ──────────────────────────────────────────

/// Returns stale branch candidates eligible for archival.
///
/// Walks all unmerged `re/*` translation branches, checks their last commit
/// date, and returns those older than the threshold (default 7 days).
pub async fn api_get_gc_candidates(
    State(state): State<ServerState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<GcCandidatesResponse>, ServerError> {
    let days: u64 = params.get("days").and_then(|d| d.parse().ok()).unwrap_or(7);

    let threshold = Duration::days(days as i64);
    let now = Utc::now();

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let branches = git
        .list_translation_branches()
        .map_err(|e| ServerError::internal(&format!("Failed to list branches: {e}")))?;

    let mut candidates: Vec<GcCandidate> = Vec::new();
    let mut recent_count = 0usize;

    for branch_name in &branches {
        // Skip already merged branches
        if git
            .is_branch_merged_into_main(branch_name)
            .map_err(|e| ServerError::internal(&format!("Merge check failed: {e}")))?
        {
            continue;
        }

        // Parse branch name into components
        let (binary, function, attempt) = match parse_gc_branch(branch_name) {
            Some(p) => p,
            None => continue,
        };

        // Get the last commit date for this branch
        let last_commit = match get_gc_branch_head_date(&git, branch_name) {
            Ok(date) => date,
            Err(_) => continue,
        };

        let age = now.signed_duration_since(last_commit);
        let days_old = age.num_seconds() as f64 / 86400.0;

        if age > threshold {
            candidates.push(GcCandidate {
                branch: branch_name.clone(),
                binary: binary.into(),
                function,
                attempt,
                days_old,
                last_commit: last_commit.to_rfc3339(),
            });
        } else {
            recent_count += 1;
        }
    }

    // Sort candidates by age (oldest first)
    candidates.sort_by(|a, b| {
        b.days_old
            .partial_cmp(&a.days_old)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(Json(GcCandidatesResponse {
        success: true,
        candidates,
        recent_count,
        threshold_days: days,
    }))
}

// ─── POST /api/gc/archive ────────────────────────────────────────────

/// Archives one or more stale branches to `refs/archive/`.
///
/// When `branches` is empty, all available candidates are archived.
/// When specific branches are listed, only those are archived.
pub async fn api_archive_gc(
    State(state): State<ServerState>,
    OptionalJson(body): OptionalJson<GcArchiveRequest>,
) -> Result<Json<GcArchiveResponse>, ServerError> {
    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let request = body.unwrap_or_else(GcArchiveRequest::default);
    let mut results: Vec<GcArchiveResult> = Vec::new();
    let mut archived = 0usize;
    let mut failed = 0usize;

    // If no specific branches requested, get all unmerged translation branches
    let branches_to_archive: Vec<String> = if request.branches.is_empty() {
        let all_branches = git
            .list_translation_branches()
            .map_err(|e| ServerError::internal(&format!("Failed to list branches: {e}")))?;

        let mut unmerged = Vec::new();
        for branch in &all_branches {
            if !git
                .is_branch_merged_into_main(branch)
                .map_err(|e| ServerError::internal(&format!("Merge check failed: {e}")))?
            {
                unmerged.push(branch.clone());
            }
        }
        unmerged
    } else {
        request.branches
    };

    for branch_name in &branches_to_archive {
        let (binary, function, attempt) = match parse_gc_branch(branch_name) {
            Some(p) => p,
            None => {
                results.push(GcArchiveResult {
                    branch: branch_name.to_string(),
                    success: false,
                    archive_ref: String::new(),
                    error: Some("Could not parse branch name".to_string()),
                });
                failed += 1;
                continue;
            }
        };

        let archive_ref = if let Some(func) = &function {
            format!("refs/archive/re/{binary}/{func}v{attempt}")
        } else {
            format!("refs/archive/re/{binary}v{attempt}")
        };

        match git.archive_branch(branch_name, &archive_ref) {
            Ok(()) => {
                archived += 1;
                results.push(GcArchiveResult {
                    branch: branch_name.clone(),
                    success: true,
                    archive_ref,
                    error: None,
                });
            }
            Err(e) => {
                failed += 1;
                results.push(GcArchiveResult {
                    branch: branch_name.clone(),
                    success: false,
                    archive_ref,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    info!(
        archived,
        failed,
        branches_total = branches_to_archive.len(),
        "GC archive complete"
    );

    Ok(Json(GcArchiveResponse {
        success: failed == 0 || archived > 0,
        results,
        archived,
        failed,
    }))
}

// ─── GC helper functions ─────────────────────────────────────────────

/// Parse a translation branch name into (binary, function, attempt).
///
/// Handles both `re/{binary}/{function}v{N}` and branches without a function
/// component (e.g. classify or shim branches).
fn parse_gc_branch(branch: &str) -> Option<(String, Option<String>, u32)> {
    let rest = branch.strip_prefix("re/")?;

    // Split off the attempt suffix (v{N} at the end)
    let (rest, attempt) = if let Some(vpos) = rest.rfind('v') {
        let after_v = &rest[vpos + 1..];
        if after_v.chars().all(|c| c.is_ascii_digit()) && !after_v.is_empty() {
            let attempt: u32 = after_v.parse().ok()?;
            (&rest[..vpos], attempt)
        } else {
            (rest, 1)
        }
    } else {
        (rest, 1)
    };

    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    let kind = parts[0];

    // Skip non-translation branch kinds
    if matches!(
        kind,
        "classify" | "shim" | "pal" | "test" | "fix" | "integration"
    ) {
        return None;
    }

    let binary = parts[0].to_string();
    let function = parts.get(1).map(|s| s.to_string());

    Some((binary, function, attempt))
}

/// Get the commit date of the HEAD commit for a branch.
fn get_gc_branch_head_date(
    git: &calxgloss_git::GitManager,
    branch_name: &str,
) -> Result<chrono::DateTime<Utc>, String> {
    let branch = git
        .repo()
        .find_branch(branch_name, BranchType::Local)
        .map_err(|e| format!("Branch not found: {e}"))?;

    let commit = branch
        .get()
        .peel_to_commit()
        .map_err(|e| format!("Failed to resolve commit: {e}"))?;

    let committer = commit.committer();
    let secs = if committer.when().seconds() != 0 {
        committer.when().seconds()
    } else {
        let author = commit.author();
        author.when().seconds()
    };

    Ok(chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now))
}

//! decompiler context helpers: loading analysis artifacts, parsing diff blocks,
//! computing revision counts, and the `/api/units/:id/decomp` endpoint.

use super::super::{
    CombinedState, DecompApiCall, DecompContext, DecompContextResponse, ReviewSurfaceReader,
    ServerError, ServerState,
};
use axum::{
    Json,
    extract::{Path, State},
};

// ─── GET /api/units/:id/decomp ───────────────────────────────────────

/// Returns decompiler context (decompiler output, disassembly, API tags) for a unit's function.
pub async fn api_get_unit_decomp(
    State(combined): State<CombinedState>,
    Path(unit_id): Path<String>,
) -> Result<Json<DecompContextResponse>, ServerError> {
    let unit = super::queue::find_unit(&combined.server, &unit_id)?;

    let func_name = match unit.function {
        Some(ref f) if !f.is_empty() => f.clone(),
        _ => return Ok(Json(DecompContextResponse::not_found(&unit_id))),
    };

    let binary = unit.binary.clone();

    // The function's decompiler data reads through the review-surface
    // reader (issue #464); an artifact the reader cannot read — missing
    // or corrupt — is the honest not-found answer.
    if let Some(ctx) = load_decomp_artifacts(&combined.reader, &binary, &func_name) {
        return Ok(Json(DecompContextResponse::ok(ctx)));
    }

    Ok(Json(DecompContextResponse::not_found(&func_name)))
}

// ─── Decompiler Context Helpers ──────────────────────────────────────────

/// Load the function's analysis artifact through the review-surface
/// reader (issue #464). A missing, unreadable, or corrupt artifact is
/// `None` — the endpoint states its own not-found policy at the read site.
pub(crate) fn load_decomp_artifacts(
    reader: &ReviewSurfaceReader,
    binary: &str,
    function: &str,
) -> Option<DecompContext> {
    let artifact = reader.function_artifact(binary, function)?;

    Some(DecompContext {
        function_name: artifact
            .function_name
            .unwrap_or_else(|| function.to_string()),
        address: None,
        binary: Some(binary.to_string()),
        decompiler_output: artifact.decompiler_output,
        disassembly: None,
        windows_apis: artifact.windows_apis.map(|apis| {
            apis.into_iter()
                .map(|api| DecompApiCall {
                    name: api.name,
                    category: api.category,
                    pal_mapping: api.pal_mapping,
                })
                .collect()
        }),
        note: None,
    })
}

/// Parse a diff block (starting with `@@`) into a `DiffFile` with file name and hunks.
pub(crate) fn parse_diff_block(block: &str) -> Option<super::super::DiffFile> {
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
    let hunks = super::diff::parse_diff_hunks(block);

    if hunks.is_empty() {
        return None;
    }

    Some(super::super::DiffFile {
        path,
        old_path: None,
        added: false,
        deleted: false,
        renamed: false,
        hunks,
    })
}

/// Compute the total number of revisions (attempts) for a unit.
pub(crate) fn compute_revision_count(
    state: &ServerState,
    unit: &calxgloss_types::UnitOfWork,
) -> usize {
    let binary = &unit.binary;
    if let Some(function) = unit.function.as_deref() {
        let branch_prefix = format!("re/{binary}/{function}v");
        if let Ok(git) = calxgloss_git::GitManager::open(state.repo_path())
            && let Ok(all_branches) = git.list_branches()
        {
            return all_branches
                .iter()
                .filter(|b| b.starts_with(&branch_prefix))
                .count();
        }
    }
    1
}

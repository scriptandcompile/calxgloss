//! Ghidra context helpers: loading analysis artifacts, parsing diff blocks,
//! computing revision counts, and the `/api/units/:id/ghidra` endpoint.

use super::super::{GhidraApiCall, GhidraContext, GhidraContextResponse, ServerError, ServerState};
use axum::{
    Json,
    extract::{Path, State},
};

// ─── GET /api/units/:id/ghidra ───────────────────────────────────────

/// Returns Ghidra context (decompiler output, disassembly, API tags) for a unit's function.
pub async fn api_get_unit_ghidra(
    state: State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<GhidraContextResponse>, ServerError> {
    let unit = super::queue::find_unit(&state, &unit_id)?;

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

// ─── Ghidra Context Helpers ──────────────────────────────────────────

/// Load Ghidra artifacts from the analysis directory on disk.
pub(crate) fn load_ghidra_artifacts(
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

/// Load attempt history for a unit from patch records on disk.
pub(crate) fn load_attempt_history(
    repo_path: &std::path::Path,
    unit_id: &str,
) -> Vec<super::super::AttemptRecord> {
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

            records.push(super::super::AttemptRecord {
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
pub(crate) fn compute_revision_count(
    state: &ServerState,
    unit: &calxgloss_types::UnitOfWork,
) -> usize {
    let dll = &unit.dll;
    if let Some(function) = unit.function.as_deref() {
        let branch_prefix = format!("re/{dll}/{function}v");
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

//! Diff computation and line-by-line diff handlers.

use super::super::{
    DiffFile, DiffHunk, DiffLine, DiffLineType, DiffResponse, DiffSummary, ServerError, ServerState,
};
use axum::{
    Json,
    extract::{Path, State},
};

/// Compute a diff summary between a unit's branch and `main`.
pub fn compute_diff_summary(
    state: &ServerState,
    unit: &calxgloss_types::UnitOfWork,
) -> DiffSummary {
    let binary = &unit.binary;
    if let Some(function) = unit.function.as_deref() {
        let branch_name = format!("re/{binary}/{function}v{}", unit.attempt);
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
pub(crate) fn compute_branch_diff(
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
pub(crate) fn compute_line_diff(
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
        if let Some(file) = super::ghidra::parse_diff_block(&full_block) {
            files.push(file);
        }
    }

    Ok(files)
}

// ─── GET /api/units/:id/diff ─────────────────────────────────────────

/// Returns the full line-by-line diff between a unit's branch and main.
pub async fn api_get_unit_diff(
    state: State<ServerState>,
    Path(unit_id): Path<String>,
) -> Result<Json<DiffResponse>, ServerError> {
    let unit = super::queue::find_unit(&state, &unit_id)?;

    let branch_name = match (unit.binary.as_str(), unit.function.as_deref()) {
        (binary, Some(func)) => format!("re/{binary}/{func}v{}", unit.attempt),
        (binary, None) => format!("re/{binary}v{}", unit.attempt),
    };

    let git = calxgloss_git::GitManager::open(state.repo_path())
        .map_err(|e| ServerError::internal(&format!("Failed to open repo: {e}")))?;

    let diff_files = compute_line_diff(&git, &branch_name)
        .map_err(|e| ServerError::internal(&format!("Failed to compute diff: {e}")))?;

    Ok(Json(DiffResponse::ok(diff_files)))
}

/// Parse the raw text output of `git diff --unified` into structured hunks.
pub(crate) fn parse_diff_hunks(raw: &str) -> Vec<DiffHunk> {
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
                                new_line += 1;
                                Some(l)
                            } else {
                                None
                            },
                            old_line: if matches!(
                                kind,
                                DiffLineType::Deletion | DiffLineType::Context
                            ) {
                                let l = old_line;
                                old_line += 1;
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
    let parts: Vec<&str> = hunk_header.split([' ', ',']).collect();
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
    let parts: Vec<&str> = hunk_header.split([' ', ',']).collect();
    for part in parts {
        let part = part.trim();
        if is_new && part.starts_with('+') {
            // Could be just the start number without a comma
            if let Some(idx) = part.find(',') {
                return part[idx + 1..].parse().ok();
            }
        }
        if !is_new
            && part.starts_with('-')
            && let Some(idx) = part.find(',')
        {
            return part[idx + 1..].parse().ok();
        }
    }
    None
}

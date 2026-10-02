//! Branch garbage collection — archive old translation branches.
//!
//! Walks all unmerged `re/*` branches, checks their last commit date, and
//! renames branches older than the staleness threshold to `refs/archive/...`
//! so they remain reachable for reference instead of being deleted.

use anyhow::{Context, Result};
use calxgloss_git::GitManager;
use chrono::{DateTime, Duration, Utc};
use git2::BranchType;
use tracing::debug;

use crate::utils::*;

/// Represents a branch eligible for archival.
#[derive(Debug)]
struct GcCandidate {
    name: String,
    dll: String,
    function: Option<String>,
    attempt: u32,
    days_old: f64,
}

/// Handle the `gc` subcommand: archive old unmerged translation branches.
pub fn handle_gc(days: u64, dry_run: bool) -> Result<()> {
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    let threshold = Duration::days(days as i64);
    let now = Utc::now();

    // Discover all translation branches
    let branches = git.list_translation_branches()?;
    if branches.is_empty() {
        println!();
        println!("  {} No translation branches found.", dim("◉"));
        println!();
        return Ok(());
    }

    // Filter to unmerged branches and collect candidates
    let mut candidates: Vec<GcCandidate> = Vec::new();
    let mut recent_branches: Vec<String> = Vec::new();

    for branch_name in &branches {
        // Skip already merged branches
        if git.is_branch_merged_into_main(branch_name)? {
            continue;
        }

        // Parse branch name into components using the same pattern as dashboard
        let (dll, function, attempt) = match parse_translation_branch(branch_name) {
            Some(p) => p,
            None => continue,
        };

        // Get the last commit date for this branch
        let last_commit = match get_branch_head_commit_date(&git, branch_name) {
            Ok(date) => date,
            Err(e) => {
                debug!(branch = %branch_name, error = %e, "Failed to get commit date, skipping");
                continue;
            }
        };

        let age = now.signed_duration_since(last_commit);
        let days_old = age.num_seconds() as f64 / 86400.0;

        if age > threshold {
            candidates.push(GcCandidate {
                name: branch_name.clone(),
                dll,
                function: function.clone(),
                attempt,
                days_old,
            });
        } else {
            recent_branches.push(branch_name.clone());
        }
    }

    if candidates.is_empty() && recent_branches.is_empty() {
        println!();
        println!("  {} No translation branches found.", dim("◉"));
        println!();
        return Ok(());
    }

    // Render results
    println!();
    hsep_bold();
    if dry_run {
        println_content("  GC Dry Run — branches eligible for archive");
    } else {
        println_content("  GC — archiving old branches");
    }
    hsep();
    println!();

    println_content(format!(
        "  Threshold: {} day(s) since last commit",
        bold(&days.to_string())
    ));
    println_content(format!(
        "  Recent branches kept: {}",
        bold(&recent_branches.len().to_string())
    ));
    println_content(format!(
        "  Candidates to archive: {}",
        bold(&candidates.len().to_string())
    ));
    println!();

    if !recent_branches.is_empty() {
        hsep();
        println_content("  Recent (kept):");
        hsep();
        for branch in &recent_branches {
            if let Some((dll, function, _attempt)) = parse_translation_branch(branch) {
                let display = match &function {
                    Some(func) => format!("  {}  {}/{}", dim("●"), dll, func),
                    None => format!("  {}  {}", dim("●"), dll),
                };
                println_content(display);
            }
        }
        println!();
    }

    if candidates.is_empty() {
        println!("  {} Nothing to archive — all branches are recent.", green_bold("✓"));
        println!();
        return Ok(());
    }

    // List candidates
    hsep();
    println_content("  Candidates:");
    hsep();
    for candidate in &candidates {
        let display = match &candidate.function {
            Some(func) => format!(
                "  {}  {}/{} v{}  ({:.1}d ago)",
                red_bold("○"),
                candidate.dll,
                func,
                candidate.attempt,
                candidate.days_old,
            ),
            None => format!(
                "  {}  {} v{}  ({:.1}d ago)",
                red_bold("○"),
                candidate.dll,
                candidate.attempt,
                candidate.days_old,
            ),
        };
        println_content(display);
    }
    println!();

    if dry_run {
        println!("  {} Dry run complete — no branches were archived.", yellow_bold("◉"));
        println!();
        println!("  Re-run without --dry-run to archive these branches.");
        println!();
        return Ok(());
    }

    // Archive each candidate
    let mut archived = 0;
    let mut failed = 0;

    for candidate in &candidates {
        let archive_ref = format!(
            "refs/archive/re/{}/v{}",
            candidate
                .function
                .as_ref()
                .map(|f| format!("{}/{}", candidate.dll, f))
                .unwrap_or_else(|| candidate.dll.clone()),
            candidate.attempt
        );

        match git.archive_branch(&candidate.name, &archive_ref) {
            Ok(()) => {
                let display = match &candidate.function {
                    Some(func) => format!("{}/{}", candidate.dll, func),
                    None => candidate.dll.clone(),
                };
                println_content(format!(
                    "  {}  {} [v{}] → {}",
                    green_bold("✓"),
                    display,
                    candidate.attempt,
                    cyan_bold(&archive_ref)
                ));
                archived += 1;
            }
            Err(e) => {
                println_content(format!(
                    "  {}  {} [v{}] — {}",
                    red_bold("✗"),
                    candidate.dll,
                    candidate.attempt,
                    e
                ));
                failed += 1;
            }
        }
    }

    println!();
    hsep();
    let summary_parts = [
        green_bold(&format!("Archived:  {}", archived)),
        red_bold(&format!("Failed:    {}", failed)),
    ];
    println_content(summary_parts.join("  │  "));
    hsep_bold();
    println!();

    if failed > 0 {
        return Err(anyhow::anyhow!(
            "GC completed with {} failure(s)",
            failed
        ));
    }

    Ok(())
}

/// Parse a translation branch name into (dll, function, attempt).
///
/// Handles both `re/{dll}/{function}v{N}` and branches without a function
/// component (e.g. shim or classify branches).
fn parse_translation_branch(branch: &str) -> Option<(String, Option<String>, u32)> {
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

    // Split into top-level kind and the rest
    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    let kind = parts[0];

    // Skip non-translation branch kinds (classify, shim, pal, test, fix, integration)
    if matches!(
        kind,
        "classify" | "shim" | "pal" | "test" | "fix" | "integration"
    ) {
        return None;
    }

    let dll = parts[0].to_string();
    let function = parts.get(1).map(|s| s.to_string());

    Some((dll, function, attempt))
}

/// Get the commit date of the HEAD commit for a branch.
fn get_branch_head_commit_date(
    git: &GitManager,
    branch_name: &str,
) -> Result<DateTime<Utc>, String> {
    let branch = git
        .repo()
        .find_branch(branch_name, BranchType::Local)
        .map_err(|e| format!("Branch not found: {}", e))?;

    let commit = branch
        .get()
        .peel_to_commit()
        .map_err(|e| format!("Failed to resolve commit: {}", e))?;

    // Check if committer is valid (non-zero timestamp means valid)
    let committer = commit.committer();
    let secs = if committer.when().seconds() != 0 {
        committer.when().seconds()
    } else {
        // Fall back to author
        let author = commit.author();
        author.when().seconds()
    };

    Ok(DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now))
}

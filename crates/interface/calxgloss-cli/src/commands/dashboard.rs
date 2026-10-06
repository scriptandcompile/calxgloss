//! Dashboard-related handlers: dashboard, view, accept, reject, accept-all.

use anyhow::{Context, Result};
use calxgloss::ReviewStatus;
use calxgloss::UnitOfWork;
use calxgloss_git::GitBranch;
use calxgloss_git::GitManager;
use calxgloss_reports::dashboard::{
    DashboardBuilder, UnitViewData, ViewTarget, render_dashboard, render_dashboard_follow,
    render_unit_view,
};
use tracing::info;

use crate::utils::*;

/// Handle the `dashboard` subcommand: show a structured terminal review dashboard.
pub async fn handle_dashboard(follow: bool, interval_secs: u64) -> Result<()> {
    info!("Starting dashboard");

    // Find the git repository — walk up from CWD
    let mut repo_path = std::env::current_dir()?;

    // Walk up to find the .git directory
    let mut found_git = false;
    let mut search_path = repo_path.clone();
    for _ in 0..10 {
        if search_path.join(".git").exists() || search_path.join(".git").is_dir() {
            found_git = true;
            repo_path = search_path.clone();
            break;
        }
        if !search_path.pop() {
            break;
        }
    }

    if !found_git {
        // Try the current directory anyway (it might be a repo)
        repo_path = std::env::current_dir()?;
    }

    info!(path = ?repo_path, "Found git repository");

    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    let interval = std::time::Duration::from_secs(interval_secs);

    if follow {
        info!(interval_secs = interval_secs, "Entering follow mode");
        render_dashboard_follow(&git, interval).context("Follow mode failed")?;
    } else {
        let builder = DashboardBuilder::new(&git);
        let dashboard = builder.build().context("Failed to build dashboard")?;
        render_dashboard(&dashboard, false);
    }

    Ok(())
}

/// Handle the `dashboard view <target>` subcommand.
pub async fn handle_dashboard_view(target: &str) -> Result<()> {
    info!(target = %target, "Starting dashboard view");

    // Parse target using the shared type from reports crate
    let view_target = ViewTarget::parse(target)
        .context("Invalid target format. Use: <dll>/<function> or <dll>/<function>/vN")?;
    info!(
        dll = %view_target.dll,
        function = %view_target.function,
        attempt = ?view_target.specific_attempt,
        "Parsed view target"
    );

    // Find the git repository — walk up from CWD
    let mut repo_path = std::env::current_dir()?;
    let mut found_git = false;
    let mut search_path = repo_path.clone();
    for _ in 0..10 {
        if search_path.join(".git").exists() || search_path.join(".git").is_dir() {
            found_git = true;
            repo_path = search_path.clone();
            break;
        }
        if !search_path.pop() {
            break;
        }
    }
    if !found_git {
        repo_path = std::env::current_dir()?;
    }

    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Build the unit view data using the shared type from reports crate
    let unit_data = UnitViewData::load(&git, &view_target, &repo_path)
        .context("Failed to load unit view data")?;

    // Render the view
    render_unit_view(&unit_data);

    Ok(())
}

/// Handle the `dashboard accept <target>` subcommand.
///
/// Merges the named branch into `main` and writes an acceptance record.
pub async fn handle_dashboard_accept(target: &str) -> Result<()> {
    info!(target = %target, "Handling dashboard accept");

    let view_target =
        ViewTarget::parse(target).context("Invalid target format. Use: <dll>/<function>/vN")?;
    info!(
        dll = %view_target.dll,
        function = %view_target.function,
        attempt = ?view_target.specific_attempt,
        "Parsed accept target"
    );

    // Find the git repository
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Resolve the branch name: find the matching translation branch
    let branch_name = resolve_branch(&git, &view_target)
        .context("Could not find a matching branch for this unit")?;

    info!(branch = %branch_name, "Resolved branch for acceptance");

    // Parse the branch name into a GitBranch for the accept operation
    let (dll, function, attempt) = parse_branch_for_accept(&branch_name);
    let branch = GitBranch::new(&dll, &function, attempt).context("Invalid branch name")?;

    // Check if already merged
    if git.is_branch_merged_into_main(&branch.name)? {
        println!();
        println!(
            "  {} Branch '{}' is already merged into main.",
            yellow_bold("◉"),
            branch.name
        );
        println!();
        return Ok(());
    }

    // Perform the merge + accept
    println!();
    println!("  Merging branch '{}' into main...", bold(&branch.name));

    match git.accept_branch(&branch) {
        Ok(calxgloss_git::MergeResult::Merged { merge_hash }) => {
            println!(
                "  {} Branch '{}' merged into main (commit: {}).",
                green_bold("✓"),
                branch.name,
                &merge_hash[..7]
            );
            println!(
                "  {} Unit '{}/{}' is now accepted.",
                green_bold("✓"),
                view_target.dll,
                view_target.function
            );
        }
        Ok(calxgloss_git::MergeResult::AlreadyUpToDate) => {
            println!(
                "  {} Branch '{}' is already up to date with main.",
                yellow_bold("◉"),
                branch.name
            );
        }
        Ok(calxgloss_git::MergeResult::Conflicts {
            conflicted_files,
            error,
        }) => {
            println!(
                "  {} Merge conflicts on branch '{}': {}",
                red_bold("✗"),
                branch.name,
                error
            );
            println!("  Conflicted files: {}", conflicted_files.join(", "));
            return Err(anyhow::anyhow!(
                "Merge conflicts: {}",
                conflicted_files.join(", ")
            ));
        }
        Err(e) => {
            println!(
                "  {} Failed to accept branch '{}': {}",
                red_bold("✗"),
                branch.name,
                e
            );
            return Err(anyhow::anyhow!("Accept failed: {}", e));
        }
    }

    println!();
    Ok(())
}

/// Handle the `dashboard reject <target> --reason "..."` subcommand.
///
/// Records the rejection in `re/rejections/{dll}/{function}/vN.json`.
pub async fn handle_dashboard_reject(target: &str, reason: Option<&str>) -> Result<()> {
    info!(target = %target, reason = ?reason, "Handling dashboard reject");

    let view_target =
        ViewTarget::parse(target).context("Invalid target format. Use: <dll>/<function>/vN")?;
    info!(
        dll = %view_target.dll,
        function = %view_target.function,
        attempt = ?view_target.specific_attempt,
        "Parsed reject target"
    );

    let reason = reason.unwrap_or("no reason provided");

    // Find the git repository
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Resolve the branch name: find the matching translation branch
    let branch_name = resolve_branch(&git, &view_target)
        .context("Could not find a matching branch for this unit")?;

    info!(branch = %branch_name, "Resolved branch for rejection");

    // Parse the branch name into a GitBranch for the reject operation
    let (dll, function, attempt) = parse_branch_for_accept(&branch_name);
    let branch = GitBranch::new(&dll, &function, attempt).context("Invalid branch name")?;

    // Perform the rejection
    println!();
    println!(
        "  {} Branch '{}' will be sent back for fixes.",
        red_bold("✗"),
        branch.name
    );
    println!("  {} Rejection reason: \"{}\"", bold("Reason:"), reason);

    match git.reject_branch(&branch, reason) {
        Ok(rejection_path) => {
            println!(
                "  {} Rejection recorded at: {}",
                green_bold("✓"),
                rejection_path.display()
            );
            println!(
                "  {} Unit '{}/{}' has been sent back.",
                red_bold("✗"),
                view_target.dll,
                view_target.function
            );
        }
        Err(e) => {
            println!(
                "  {} Failed to reject branch '{}': {}",
                red_bold("✗"),
                branch.name,
                e
            );
            return Err(anyhow::anyhow!("Reject failed: {}", e));
        }
    }

    println!();
    Ok(())
}

/// Handle the `dashboard accept-all` subcommand.
///
/// Builds the dashboard, topologically sorts pending units by dependency,
/// and accepts each one in order.
pub async fn handle_dashboard_accept_all(all_flag: bool) -> Result<()> {
    // Find the git repository
    let repo_path = find_repo_path()?;
    let git = GitManager::open(&repo_path).context("Failed to open git repository")?;

    // Build the dashboard
    let builder = DashboardBuilder::new(&git);
    let dashboard = builder
        .build()
        .context("Failed to build review dashboard")?;

    // Determine which units to accept
    let to_accept: Vec<&UnitOfWork> = if all_flag {
        // Accept every not-yet-accepted branch in the dashboard
        dashboard
            .review_queue
            .iter()
            .filter(|u| !matches!(u.status, ReviewStatus::Accepted))
            .collect()
    } else {
        // Accept only queued and pending-review units, in dependency order
        dashboard.pending_in_dependency_order()
    };

    if to_accept.is_empty() {
        println!();
        if all_flag {
            println!("  {} No unmerged branches to accept.", dim("◉"));
        } else {
            println!("  {} No pending units to accept.", dim("◉"));
        }
        println!();
        return Ok(());
    }

    let total = to_accept.len();
    println!();
    hsep_bold();
    println_content(format!(
        "  Batch Accept: {} units — dependency order",
        bold(&total.to_string())
    ));
    hsep();
    println_content("");

    let mut accepted = 0;
    let mut skipped = 0;
    let mut failed = 0;

    for unit in &to_accept {
        // Quick check: if already merged, skip
        let branch_name = resolve_branch(
            &git,
            &ViewTarget {
                dll: unit.dll.clone(),
                function: unit.function.clone().unwrap_or_default(),
                specific_attempt: Some(unit.attempt),
            },
        );

        let branch_name = match branch_name {
            Ok(name) => name,
            Err(_) => {
                println!(
                    "  {} {} [{}] — branch not found",
                    yellow_bold("◉"),
                    dim(&format!("{}/{}", unit.dll, unit.name)),
                    red_bold("skip")
                );
                skipped += 1;
                continue;
            }
        };

        // Check if already merged
        if git.is_branch_merged_into_main(&branch_name)? {
            println!(
                "  {} {} [v{}] — already merged",
                dim(" "),
                format_dim(&format!("{}/{}", unit.dll, unit.name)),
                unit.attempt
            );
            skipped += 1;
            continue;
        }

        // Parse the branch into a GitBranch
        let (dll, function, attempt) = parse_branch_for_accept(&branch_name);
        let branch = match GitBranch::new(&dll, &function, attempt) {
            Ok(b) => b,
            Err(e) => {
                println!(
                    "  {} {} [{}] — {}",
                    red_bold("✗"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    red_bold("error"),
                    e
                );
                failed += 1;
                continue;
            }
        };

        // Accept the branch
        match git.accept_branch(&branch) {
            Ok(calxgloss_git::MergeResult::Merged { merge_hash }) => {
                println!(
                    "  {} {} [v{}] — {} ({})",
                    green_bold("✓"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    green_bold("accepted"),
                    &merge_hash[..7]
                );
                accepted += 1;
            }
            Ok(calxgloss_git::MergeResult::AlreadyUpToDate) => {
                println!(
                    "  {} {} [v{}] — {}",
                    yellow_bold("◉"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    yellow_bold("up to date")
                );
                skipped += 1;
            }
            Ok(calxgloss_git::MergeResult::Conflicts {
                conflicted_files,
                error,
            }) => {
                println!(
                    "  {} {} [v{}] — {} ({})",
                    red_bold("✗"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    red_bold("conflict"),
                    error
                );
                println_content(format!(
                    "    Conflicted files: {}",
                    conflicted_files.join(", ")
                ));
                failed += 1;
            }
            Err(e) => {
                println!(
                    "  {} {} [v{}] — {} ({})",
                    red_bold("✗"),
                    format_dim(&format!("{}/{}", unit.dll, unit.name)),
                    unit.attempt,
                    red_bold("failed"),
                    e
                );
                failed += 1;
            }
        }
    }

    println_content("");
    hsep();
    let summary_parts = [
        green_bold(&format!("Accepted:  {}", accepted)),
        yellow_bold(&format!("Skipped:   {}", skipped)),
        red_bold(&format!("Failed:    {}", failed)),
    ];
    println_content(summary_parts.join("  │  "));
    hsep_bold();
    println!();

    if failed > 0 {
        return Err(anyhow::anyhow!(
            "Batch accept completed with {} failure(s)",
            failed
        ));
    }

    Ok(())
}

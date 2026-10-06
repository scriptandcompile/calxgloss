//! Integration tests for [`DashboardBuilder`] — review verdicts must survive
//! a dashboard rebuild (issue #9).
//!
//! The builder recomputes every unit's status from branch state on each
//! build; these tests pin the fix that makes the failing verdicts durable:
//! rejection records (`re/rejections/`) report `SendBack`, patch-request
//! records (`re/patches/` with a `patch_request` field) report
//! `PatchRequested`, and a merged branch stays `Accepted` whichever records
//! exist — branch state remains authoritative for acceptance.

use calxgloss_git::{GitManager, InitConfig};
use calxgloss_reports::dashboard::{DashboardBuilder, ReviewDashboard, ReviewStatus, UnitOfWork};
use calxgloss_types::GitBranch;

/// A temp workspace with an initialized git repo (README on `main`).
fn temp_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = InitConfig {
        author_name: "Calxgloss Test".into(),
        author_email: "test@calxgloss.test".into(),
        committer_name: None,
        committer_email: None,
    };
    GitManager::init_repo(dir.path(), Some(config)).expect("init git repo");
    dir
}

/// Creates the attempt branch `re/{dll}/{function}v{attempt}` off `main`,
/// commits a stub source file on it, and returns HEAD to `main`.
fn commit_on_branch(git: &GitManager, dll: &str, function: &str, attempt: u32) {
    git.create_branch(dll, function, attempt, None)
        .expect("create branch");
    let branch = GitBranch::new(dll, function, attempt).expect("branch name");

    let file = format!("src/{function}_v{attempt}.rs");
    std::fs::create_dir_all(git.repo_path().join("src")).expect("src dir");
    std::fs::write(
        git.repo_path().join(&file),
        format!("// {function} — attempt {attempt}\n"),
    )
    .expect("write source file");
    git.commit(
        &branch,
        &format!("translate {function} attempt {attempt}"),
        &[&file],
    )
    .expect("commit on branch");

    return_to_main(git);
}

/// Moves HEAD back to `main` so later branch operations start clean.
fn return_to_main(git: &GitManager) {
    let main_commit = git
        .repo()
        .find_branch("main", git2::BranchType::Local)
        .expect("main branch")
        .get()
        .peel_to_commit()
        .expect("main commit");
    let mut checkout_opts = git2::build::CheckoutBuilder::new();
    checkout_opts.force();
    git.repo()
        .set_head("refs/heads/main")
        .expect("set head to main");
    git.repo()
        .reset(
            main_commit.as_object(),
            git2::ResetType::Hard,
            Some(&mut checkout_opts),
        )
        .expect("reset to main");
}

/// Writes a failure-shaped patch record at
/// `re/patches/{dll}/{function}/v{attempt}.json` — the shape
/// `GitManager::store_failure` writes. With `patch_request` set it becomes
/// the shape the review UI's request-patch action writes instead.
fn write_patch_record(
    git: &GitManager,
    dll: &str,
    function: &str,
    attempt: u32,
    patch_request: Option<&str>,
) {
    let patch_dir = git
        .repo_path()
        .join("re")
        .join("patches")
        .join(dll)
        .join(function);
    std::fs::create_dir_all(&patch_dir).expect("create patch dir");

    let mut record = serde_json::json!({
        "dll": dll,
        "function": function,
        "attempt": attempt,
        "branch_name": format!("re/{dll}/{function}v{attempt}"),
        "committed_at": "2026-10-05T10:00:00Z",
        "error_message": "type mismatch",
        "compilation_errors": ["mismatched types"],
        "test_failures": [],
        "commit_hash": "abc123",
    });
    if let Some(issue) = patch_request {
        record["patch_request"] = serde_json::Value::String(issue.to_string());
    }
    std::fs::write(
        patch_dir.join(format!("v{attempt}.json")),
        serde_json::to_string_pretty(&record).expect("serialize patch record"),
    )
    .expect("write patch record");
}

/// Builds the dashboard from the repo's current state.
fn build(git: &GitManager) -> ReviewDashboard {
    DashboardBuilder::new(git).build().expect("build dashboard")
}

/// Finds a built unit by id across the review queue and recent activity.
fn find_unit<'a>(dashboard: &'a ReviewDashboard, id: &str) -> &'a UnitOfWork {
    dashboard
        .review_queue
        .iter()
        .chain(dashboard.recent_activity.iter())
        .find(|u| u.id == id)
        .unwrap_or_else(|| panic!("unit {id} present in dashboard (queue + recent)"))
}

#[test]
fn send_back_verdict_survives_rebuild() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic", "DrawSprite", 1);

    let branch = GitBranch::new("game_logic", "DrawSprite", 1).expect("branch name");
    git.reject_branch(&branch, "wrong blend mode mapping")
        .expect("write rejection record");

    // The verdict must hold across rebuilds, not just the build that saw
    // the action — the builder reads `re/rejections/`, not in-memory state.
    for round in 1..=2 {
        let dashboard = build(&git);
        let unit = find_unit(&dashboard, "game_logic/DrawSprite/v1");
        assert_eq!(
            unit.status,
            ReviewStatus::SendBack,
            "round {round}: sent-back unit reports SendBack after rebuild"
        );
        assert!(
            dashboard.status_counts.send_back >= 1,
            "round {round}: status counts include the send-back"
        );
    }
}

#[test]
fn patch_request_record_reports_patch_requested() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic", "DrawSprite", 1);
    // request_patch spawns the next-attempt branch and records the request there.
    commit_on_branch(&git, "game_logic", "DrawSprite", 2);
    write_patch_record(
        &git,
        "game_logic",
        "DrawSprite",
        2,
        Some("index buffer stride wrong"),
    );

    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "game_logic/DrawSprite/v2");
    assert_eq!(
        unit.status,
        ReviewStatus::PatchRequested,
        "a patch-request record reports PatchRequested"
    );
    assert!(dashboard.status_counts.patch_requested >= 1);
}

#[test]
fn failure_record_without_patch_request_reports_pending_review() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic", "DrawSprite", 1);
    write_patch_record(&git, "game_logic", "DrawSprite", 1, None);

    // A plain pipeline failure record is not a reviewer verdict — the
    // attempt simply failed and awaits review as before.
    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "game_logic/DrawSprite/v1");
    assert_eq!(
        unit.status,
        ReviewStatus::PendingReview,
        "a failure record without patch_request still reports PendingReview"
    );
    assert_eq!(dashboard.status_counts.patch_requested, 0);
}

#[test]
fn merged_branch_with_rejection_reports_accepted() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic", "DrawSprite", 1);

    let branch = GitBranch::new("game_logic", "DrawSprite", 1).expect("branch name");
    git.merge_to_main(&branch).expect("merge to main");
    git.reject_branch(&branch, "stale rejection")
        .expect("write rejection record");

    // Branch state stays authoritative for acceptance: a merged branch is
    // Accepted whichever records sit beside it.
    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "game_logic/DrawSprite/v1");
    assert_eq!(
        unit.status,
        ReviewStatus::Accepted,
        "a merged branch reports Accepted despite a rejection record"
    );
}

#[test]
fn rejection_is_scoped_to_its_attempt() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic", "DrawSprite", 1);
    let branch_v1 = GitBranch::new("game_logic", "DrawSprite", 1).expect("branch name");
    git.reject_branch(&branch_v1, "wrong blend mode mapping")
        .expect("write rejection record");
    commit_on_branch(&git, "game_logic", "DrawSprite", 2);

    let dashboard = build(&git);
    assert_eq!(
        find_unit(&dashboard, "game_logic/DrawSprite/v1").status,
        ReviewStatus::SendBack,
        "the rejected attempt keeps its verdict"
    );
    assert_eq!(
        find_unit(&dashboard, "game_logic/DrawSprite/v2").status,
        ReviewStatus::Queued,
        "the fresh attempt carries no verdict from the previous attempt"
    );
}

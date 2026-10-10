//! Accept-path merge-conflict tests (issue #83).
//!
//! Accepting a unit whose branch can no longer merge cleanly onto main must
//! fail loudly: the error names the conflicting files, no `Accepted` action
//! record is persisted, and the unit keeps its pre-accept dashboard status.
//!
//! Run with: `cargo test --features server --test accept_conflict`

use axum::extract::{Path, State};
use calxgloss_git::GitManager;
use calxgloss_web::{
    ActionsState, CombinedState, ServerState, accept_unit, api_accept_unit, build_dashboard,
};

/// Builds a repo where `re/game_logic.dll/DrawSpritev1` is merged into main
/// and `re/game_logic.dll/DrawSpritev2` edits the same file from the same
/// base — so accepting v2 hits a merge conflict.
fn make_conflicting_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let git = GitManager::init_repo(dir.path(), None).expect("init git repo");

    let branch_v1 =
        calxgloss_types::GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("v1 branch name");
    git.create_branch("game_logic.dll", "DrawSprite", 1, None)
        .expect("create v1 branch");
    std::fs::write(dir.path().join("shared.rs"), "// version 1").expect("write v1 file");
    git.commit(&branch_v1, "attempt 1 edits shared", &["shared.rs"])
        .expect("commit v1");

    // v2 branches off the same base (create_branch always starts from main,
    // which v1 has not merged into yet).
    let branch_v2 =
        calxgloss_types::GitBranch::new("game_logic.dll", "DrawSprite", 2).expect("v2 branch name");
    git.create_branch("game_logic.dll", "DrawSprite", 2, None)
        .expect("create v2 branch");
    std::fs::write(dir.path().join("shared.rs"), "// version 2").expect("write v2 file");
    git.commit(&branch_v2, "attempt 2 edits shared", &["shared.rs"])
        .expect("commit v2");

    // v1 lands on main first, making v2 unmergeable.
    git.merge_to_main(&branch_v1).expect("merge v1");

    dir
}

#[tokio::test]
async fn accepting_conflicting_unit_fails_without_marking_accepted() {
    let dir = make_conflicting_repo();
    let state = ActionsState::new(dir.path().to_path_buf());

    let result = accept_unit(&state, "game_logic.dll/DrawSprite/v2").await;

    // The accept must fail, naming the conflicting file.
    let err = result.expect_err("conflicting accept must fail");
    let message = err.to_string();
    assert!(
        message.contains("shared.rs"),
        "error should name the conflicting file, got: {message}"
    );

    // No Accepted action record may be persisted for the unit.
    let action_record = dir
        .path()
        .join("re")
        .join("actions")
        .join("game_logic.dll")
        .join("DrawSprite")
        .join("v2.json");
    assert!(
        !action_record.exists(),
        "no action record should be written for a conflicted accept"
    );

    // The unit keeps its pre-accept status on the dashboard.
    let dashboard = build_dashboard(dir.path()).expect("dashboard builds");
    let unit = dashboard
        .review_queue
        .iter()
        .find(|u| u.id == "game_logic.dll/DrawSprite/v2")
        .expect("v2 unit still in the review queue");
    assert_ne!(
        unit.status,
        calxgloss_types::ReviewStatus::Accepted,
        "conflicted unit must not show as accepted"
    );

    // main still carries only v1's content — nothing from v2 landed.
    let main_content = std::fs::read_to_string(dir.path().join("shared.rs")).expect("main file");
    assert_eq!(main_content, "// version 1");
}

#[tokio::test]
async fn legacy_api_accept_of_conflicting_unit_reports_conflict() {
    let dir = make_conflicting_repo();
    // The basic router's actions-less path: `api_accept_unit` runs the git
    // accept directly and must answer with the conflict, not an accept.
    let combined = CombinedState {
        server: ServerState::new(dir.path().to_path_buf()),
        manager: None,
        bridge: None,
        actions: None,
        progress: None,
    };

    let result = api_accept_unit(
        State(combined),
        Path("game_logic.dll/DrawSprite/v2".to_string()),
    )
    .await;

    let err = result.expect_err("conflicting accept must fail");
    assert!(
        err.to_string().contains("shared.rs"),
        "error should name the conflicting file, got: {err}"
    );

    // Nothing was merged: main still carries only v1's content.
    let main_content = std::fs::read_to_string(dir.path().join("shared.rs")).expect("main file");
    assert_eq!(main_content, "// version 1");
}

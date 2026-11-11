//! Accept-path merge-conflict tests (issue #83).
//!
//! Accepting a unit whose branch can no longer merge cleanly onto main must
//! fail with an error that names the conflicting files: no `Accepted` action
//! record is persisted, and the unit keeps its pre-accept dashboard status.
//! The conflicting-repository fixture and both world boots come from the
//! shared e2e support module, the same one the e2e family and the
//! Kuna-scan e2e ride (issue #478).
//!
//! Run with: `cargo test --features server --test accept_conflict`

use axum::extract::{Path, State};
use calxgloss_web::{accept_unit, api_accept_unit, build_dashboard};

// This target rides part of the shared support module: the fixture
// writers and boot rules its two pins need. The other web test targets
// exercise the rest of the adapter (issue #478).
#[allow(dead_code)]
#[path = "e2e/support.rs"]
mod support;

#[tokio::test]
async fn accepting_conflicting_unit_fails_without_marking_accepted() {
    let fixture = support::TestFixture::with_conflicting_attempts();
    // Issue #327: the actions backend takes a pass description; the accept
    // path never builds one, so the support module's default backend is
    // enough here.
    let actions = support::build_actions_state(&fixture);

    let result = accept_unit(&actions, "game_logic.dll/DrawSprite/v2").await;

    // The accept must fail, naming the conflicting file.
    let err = result.expect_err("conflicting accept must fail");
    let message = err.to_string();
    assert!(
        message.contains("shared.rs"),
        "error should name the conflicting file, got: {message}"
    );

    // No Accepted action record may be persisted for the unit.
    let action_record = fixture
        .repo_path()
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
    let dashboard = build_dashboard(&fixture.repo_path()).expect("dashboard builds");
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

    // main still has only v1's content — nothing from v2 landed.
    let main_content =
        std::fs::read_to_string(fixture.repo_path().join("shared.rs")).expect("main file");
    assert_eq!(main_content, "// version 1");
}

#[tokio::test]
async fn legacy_api_accept_of_conflicting_unit_reports_conflict() {
    let fixture = support::TestFixture::with_conflicting_attempts();
    // The basic router's actions-less path: `api_accept_unit` runs the git
    // accept directly and must answer with the conflict, not an accept.
    // The support module assembles the plain-serve world, the same shape
    // `build_router` wires (issue #478).
    let combined = support::build_plain_combined_state(&fixture);

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

    // Nothing was merged: main still has only v1's content.
    let main_content =
        std::fs::read_to_string(fixture.repo_path().join("shared.rs")).expect("main file");
    assert_eq!(main_content, "// version 1");
}

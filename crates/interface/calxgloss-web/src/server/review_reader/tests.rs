//! The reader's seam tests: a temp workspace and real record/store reads,
//! no router, no port, no sleeps.

use super::*;
use calxgloss_types::{BinaryIdentity, ReviewStatus, UnitOfWork, WorkKind};

fn unit(binary: &str, function: &str, status: ReviewStatus) -> UnitOfWork {
    UnitOfWork {
        id: format!("{binary}/{function}/v1"),
        name: format!("{binary}!{function}"),
        kind: WorkKind::FunctionTranslation,
        binary: BinaryIdentity::new(binary),
        function: Some(function.to_string()),
        attempt: 1,
        status,
        accepted: false,
        unit_confidence: None,
        baseline_tests_passed: None,
        baseline_tests_total: None,
        verification_tests_passed: None,
        verification_tests_total: None,
        llm_model: None,
        context_tier: None,
        dependencies: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        known_gaps: Vec::new(),
        unknowns: calxgloss_types::UnitUnknowns::unknown(),
        obligation: calxgloss_types::UnitObligation::unknown(),
        stale: calxgloss_types::dashboard::Staleness::Fresh,
    }
}

/// The store read the fold consumes: apply events to a real live store
/// and take its snapshot, exactly as the reader will.
async fn store_entries(
    events: Vec<calxgloss_types::ProgressEvent>,
) -> HashMap<String, LiveUnitProgress> {
    let store = super::super::ProgressState::new();
    for event in events {
        store.apply(&event).await;
    }
    store.snapshot().await
}

fn started(binary: &str, function: &str) -> calxgloss_types::ProgressEvent {
    calxgloss_types::ProgressEvent::TranslationStarted {
        binary: binary.into(),
        function: function.to_string(),
    }
}

#[tokio::test]
async fn a_matching_review_row_is_patched_to_in_progress() {
    let mut dashboard = ReviewDashboard::new(vec![unit(
        "game_logic.dll",
        "DrawPrimitive",
        ReviewStatus::PendingReview,
    )]);
    let entries = store_entries(vec![started("game_logic.dll", "DrawPrimitive")]).await;

    merge_live_progress(&mut dashboard, &entries);

    assert_eq!(
        dashboard.review_queue[0].status,
        ReviewStatus::InProgress,
        "a unit the live store names reads as in flight"
    );
}

#[tokio::test]
async fn an_in_flight_unit_the_dashboard_does_not_list_is_added_once() {
    let mut dashboard = ReviewDashboard::new(vec![unit(
        "game_logic.dll",
        "DrawPrimitive",
        ReviewStatus::PendingReview,
    )]);
    let entries = store_entries(vec![
        started("game_logic.dll", "DrawPrimitive"),
        started("kernel32.dll", "CreateFile"),
    ])
    .await;

    merge_live_progress(&mut dashboard, &entries);

    let added: Vec<&UnitOfWork> = dashboard
        .review_queue
        .iter()
        .filter(|u| u.id == "live/kernel32.dll/CreateFile/v1")
        .collect();
    assert_eq!(
        added.len(),
        1,
        "the in-flight unit the dashboard lacks arrives as exactly one synthetic row"
    );
    assert_eq!(added[0].status, ReviewStatus::InProgress);
    assert_eq!(
        dashboard.review_queue.len(),
        2,
        "no other row is fabricated"
    );
}

#[tokio::test]
async fn an_accepted_unit_patched_in_place_keeps_its_recorded_timestamp() {
    let mut accepted = unit("game_logic.dll", "Update", ReviewStatus::Accepted);
    accepted.accepted = true;
    let filed_at = chrono::Utc::now() - chrono::Duration::days(3);
    accepted.updated_at = filed_at;
    let pending = unit(
        "game_logic.dll",
        "DrawPrimitive",
        ReviewStatus::PendingReview,
    );
    let pending_before = pending.updated_at;
    // ReviewDashboard::new files accepted rows in recent_activity.
    let mut dashboard = ReviewDashboard::new(vec![accepted, pending]);
    let entries = store_entries(vec![
        started("game_logic.dll", "Update"),
        started("game_logic.dll", "DrawPrimitive"),
    ])
    .await;

    merge_live_progress(&mut dashboard, &entries);

    assert_eq!(
        dashboard.recent_activity[0].status,
        ReviewStatus::InProgress,
        "a running translation reads in flight wherever its row sits"
    );
    assert_eq!(
        dashboard.recent_activity[0].updated_at, filed_at,
        "patching an accepted row's status is a live reading, not a new review event"
    );
    assert!(
        dashboard.review_queue[0].updated_at > pending_before,
        "an unaccepted patched row is re-stamped, as today"
    );
}

#[tokio::test]
async fn a_unit_matched_in_recent_activity_is_not_added_again_as_synthetic() {
    let mut accepted = unit("kernel32.dll", "CreateFile", ReviewStatus::Accepted);
    accepted.accepted = true;
    let mut dashboard = ReviewDashboard::new(vec![accepted]);
    let entries = store_entries(vec![started("kernel32.dll", "CreateFile")]).await;

    merge_live_progress(&mut dashboard, &entries);

    assert!(
        dashboard
            .review_queue
            .iter()
            .all(|u| !u.id.starts_with("live/")),
        "the accepted row in recent_activity already shows the unit — no second row"
    );
    assert_eq!(
        dashboard.recent_activity[0].status,
        ReviewStatus::InProgress
    );
}

/// A repo with one review unit — branch `re/game_logic.dll/DrawSpritev1`
/// with one translated commit, the shape the `actions.rs` tests use —
/// so the dashboard really lists `game_logic.dll/DrawSprite/v1`.
fn make_repo_with_unit() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    let git = calxgloss_git::GitManager::init_repo(dir.path(), None).expect("init git repo");
    git.create_branch("game_logic.dll", "DrawSprite", 1, None)
        .expect("create v1 branch");

    let branch =
        calxgloss_types::GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
    std::fs::create_dir_all(dir.path().join("src").join("modules")).expect("src dir");
    std::fs::write(
        dir.path().join("src").join("modules").join("game_logic.rs"),
        "pub fn draw_sprite() {}\n",
    )
    .expect("write translation");
    git.commit(
        &branch,
        "Translate DrawSprite",
        &["src/modules/game_logic.rs"],
    )
    .expect("commit translation");
    dir
}

// ── Classification reads (issue #461) ──────────────────────────────

/// A workspace that exists and nothing else — the clean empty record tree.
fn temp_workspace() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp workspace")
}

fn reader_over(workspace: &std::path::Path) -> ReviewSurfaceReader {
    ReviewSurfaceReader::new(workspace.to_path_buf(), None)
}

fn file_classification_record(
    workspace: &std::path::Path,
    binary: &str,
    record: serde_json::Value,
) {
    let classify = calxgloss_types::classification_record_dir(workspace);
    std::fs::create_dir_all(&classify).expect("classify dir");
    std::fs::write(classify.join(format!("{binary}.json")), record.to_string())
        .expect("file the classification record");
}

fn file_corrupt_classification_record(workspace: &std::path::Path, binary: &str) {
    let classify = calxgloss_types::classification_record_dir(workspace);
    std::fs::create_dir_all(&classify).expect("classify dir");
    std::fs::write(classify.join(format!("{binary}.json")), "{ not json")
        .expect("corrupt the classification record");
}

fn file_corrupt_overrides_document(workspace: &std::path::Path) {
    let analysis = workspace.join("re").join("analysis");
    std::fs::create_dir_all(&analysis).expect("analysis dir");
    std::fs::write(analysis.join("classification_overrides.json"), "{ not json")
        .expect("corrupt the override document");
}

#[test]
fn a_corrupt_classification_record_is_listed_with_its_category_unknown_and_cause_named() {
    // The classification panel's honesty rule (issue #461): bytes that
    // do not parse keep the binary listed — its category reads honestly
    // unknown and the fault that stopped it reads named, never the
    // silent "this binary was never classified" the old hand-joined
    // read gave.
    let dir = temp_workspace();
    file_corrupt_classification_record(dir.path(), "broken.dll");
    let reader = reader_over(dir.path());

    let pair = reader
        .classification_pair("broken.dll")
        .expect("the panel reading survives a corrupt record");
    let recorded = pair
        .recorded
        .expect("the corrupt record still lists the binary");
    assert_eq!(
        recorded.category, "unknown",
        "the category is honestly unknown"
    );
    let cause = recorded.reason.expect("the cause is named");
    assert!(
        cause.contains("broken.dll.json"),
        "the cause names the unreadable document: {cause}"
    );
}

#[test]
fn a_missing_classification_record_is_honest_absence() {
    // Absence stays visibly different from corruption (issue #461):
    // a never-filed record answers no classification at all.
    let dir = temp_workspace();
    let reader = reader_over(dir.path());

    let pair = reader
        .classification_pair("never-classified.dll")
        .expect("absence is not a fault");
    assert!(pair.recorded.is_none(), "no record was ever filed");
    assert!(pair.r#override.is_none());
}

#[test]
fn a_corrupt_overrides_document_reaches_the_panel_as_a_named_fault() {
    // The panel composes its override from the shared read, so a
    // corrupt override document renders the same honest way the
    // binaries pages already take (issue #459): refusal naming the
    // document, never "no override in force".
    let dir = temp_workspace();
    file_corrupt_overrides_document(dir.path());
    let reader = reader_over(dir.path());

    let err = reader
        .classification_pair("game_logic.dll")
        .expect_err("corrupt override bytes are a fault");
    assert!(
        err.to_string().contains("classification_overrides.json"),
        "the fault names the document: {err}"
    );
}

#[test]
fn a_readable_record_and_override_pair_reads_through_the_reader_as_today() {
    // The hazard pin (issue #461): for a readable pair the reader's
    // answer is exactly what the handlers' hand-joined reads gave —
    // every recorded field verbatim, the strategy tag extracted the
    // way the pipeline rows read it, and the override keyed verbatim.
    let dir = temp_workspace();
    file_classification_record(
        dir.path(),
        "d3d9.dll",
        serde_json::json!({
            "binary": "d3d9.dll",
            "category": "MicrosoftSdk",
            "strategy": { "CrateReplacement": { "crate_name": "wgpu" } },
            "exports_count": 100,
            "imports_count": 5,
            "crate_replacement": "wgpu",
            "known_runtime": false,
            "reason": "Direct3D 9 — replaced with wgpu behind a shim layer"
        }),
    );
    let analysis = dir.path().join("re").join("analysis");
    std::fs::create_dir_all(&analysis).expect("analysis dir");
    std::fs::write(
        analysis.join("classification_overrides.json"),
        serde_json::json!({
            "overrides": {
                "d3d9.dll": {
                    "category": "KnownThirdParty",
                    "crate_replacement": "wgpu-rs",
                    "known_runtime": false
                }
            }
        })
        .to_string(),
    )
    .expect("file the override");
    let reader = reader_over(dir.path());

    let pair = reader
        .classification_pair("d3d9.dll")
        .expect("the pair reads");
    let recorded = pair.recorded.expect("the record reads");
    assert_eq!(recorded.category, "MicrosoftSdk");
    assert_eq!(recorded.strategy, "CrateReplacement");
    assert_eq!(recorded.crate_replacement.as_deref(), Some("wgpu"));
    assert!(!recorded.known_runtime);
    assert_eq!(
        recorded.reason.as_deref(),
        Some("Direct3D 9 — replaced with wgpu behind a shim layer")
    );
    let r#override = pair.r#override.expect("the override reads");
    assert_eq!(
        r#override.category,
        calxgloss_types::DllCategory::KnownThirdParty
    );
    assert_eq!(r#override.crate_replacement.as_deref(), Some("wgpu-rs"));
}

#[test]
fn the_binaries_surface_keeps_corrupt_and_nameless_records_out_and_finds_case_insensitively() {
    // The binaries pages' stated keep policy (issue #461, unchanged
    // behavior): a record that is corrupt, or names no binary, or
    // names no category is no record at all — the row set stays
    // honest instead of a wall of unknowns. A readable record joins,
    // keyed by the identity its body names; the requested spelling
    // folds case, and an unknown name answers a 404 naming it.
    let dir = temp_workspace();
    file_corrupt_classification_record(dir.path(), "broken.dll");
    file_classification_record(
        dir.path(),
        "nameless.dll",
        serde_json::json!({ "category": "ProjectSpecific" }),
    );
    file_classification_record(
        dir.path(),
        "game_logic.dll",
        serde_json::json!({
            "binary": "game_logic.dll",
            "category": "ProjectSpecific",
            "strategy": "ReverseEngineer",
            "exports_count": 24,
            "imports_count": 12,
            "reason": "project-built binary"
        }),
    );
    let reader = reader_over(dir.path());

    let surface = reader
        .binary_classifications()
        .expect("no override document is the clean state");
    assert_eq!(surface.count(), 1, "only the readable record is kept");
    let found = surface
        .find("GAME_LOGIC.DLL")
        .expect("the lookup folds case");
    assert_eq!(found.binary.as_deref(), Some("game_logic.dll"));
    assert_eq!(found.exports_count, 24, "the counts ride with the record");
    assert_eq!(found.imports_count, 12);
    assert_eq!(found.reason.as_deref(), Some("project-built binary"));
    let err = surface
        .find("broken.dll")
        .expect_err("a corrupt record is honestly no record");
    assert!(
        err.to_string().contains("broken.dll"),
        "the 404 names the binary the request asked for: {err}"
    );
}

#[test]
fn in_force_decision_prefers_the_override_layer() {
    // The same combination the summary rows and the analyzer honor:
    // category, strategy label, crate, and reason come from the
    // override; without one, the record answers verbatim.
    let record = ClassificationReading {
        binary: Some("d3d9.dll".into()),
        category: Some(calxgloss_types::DllCategory::MicrosoftSdk),
        strategy: "CrateReplacement".into(),
        crate_replacement: Some("wgpu".into()),
        exports_count: 100,
        imports_count: 5,
        known_runtime: false,
        reason: Some("heuristic reason".into()),
    };
    let plain = in_force_decision(&record, None);
    assert_eq!(plain.category, "MicrosoftSdk");
    assert_eq!(plain.strategy, "CrateReplacement");
    assert_eq!(plain.crate_replacement.as_deref(), Some("wgpu"));
    assert_eq!(plain.reason.as_deref(), Some("heuristic reason"));
    assert!(!plain.overridden);

    let r#override = calxgloss_types::BinaryClassificationOverride {
        category: calxgloss_types::DllCategory::KnownThirdParty,
        crate_replacement: Some("wgpu-rs".into()),
        known_runtime: false,
    };
    let steered = in_force_decision(&record, Some(&r#override));
    assert_eq!(steered.category, "KnownThirdParty");
    assert_eq!(steered.strategy, "CrateReplacement");
    assert_eq!(steered.crate_replacement.as_deref(), Some("wgpu-rs"));
    // The reason is the analyzer's own account of an overridden
    // decision — the recorded heuristic reason does not carry over.
    assert_eq!(
        steered.reason.as_deref(),
        Some("operator override — KnownThirdParty (category set from the dashboard)")
    );
    assert!(steered.overridden);
}

#[test]
fn override_crate_follows_the_analyzers_category_rule() {
    // A crate name means something only in crate-replacement modes:
    // elsewhere the analyzer drops it, and in those modes an override
    // naming no crate falls back to the recorded one (the web stand-in
    // for the analyzer's table lookup).
    let record = ClassificationReading {
        binary: Some("game_logic.dll".into()),
        category: Some(calxgloss_types::DllCategory::ProjectSpecific),
        strategy: "ReverseEngineer".into(),
        crate_replacement: Some("recorded-crate".into()),
        exports_count: 1,
        imports_count: 1,
        known_runtime: false,
        reason: None,
    };
    let steered = in_force_decision(
        &record,
        Some(&calxgloss_types::BinaryClassificationOverride {
            category: calxgloss_types::DllCategory::ProjectSpecific,
            crate_replacement: Some("ignored-crate".into()),
            known_runtime: false,
        }),
    );
    assert_eq!(
        steered.crate_replacement, None,
        "a non-crate-replacement category drops the crate, as the analyzer does"
    );

    let steered = in_force_decision(
        &record,
        Some(&calxgloss_types::BinaryClassificationOverride {
            category: calxgloss_types::DllCategory::KnownThirdParty,
            crate_replacement: None,
            known_runtime: false,
        }),
    );
    assert_eq!(
        steered.crate_replacement.as_deref(),
        Some("recorded-crate"),
        "a crate-replacement override naming no crate keeps the recorded one"
    );
}

#[test]
fn no_override_document_is_no_overrides_and_not_a_fault() {
    // A never-filed record is the documented clean state: the
    // binary surfaces render an override as absent (issue #459).
    let dir = temp_workspace();
    let reader = reader_over(dir.path());
    let overrides = reader
        .classification_overrides()
        .expect("no document is the clean state");
    assert!(overrides.overrides.is_empty());
}

#[test]
fn a_corrupt_override_document_stops_the_binary_surfaces_naming_the_document() {
    // Corrupt override bytes never render as "the reviewer never
    // overrode anything": every binaries page surface composes through
    // this one read, so it stops and names the document (issue #459,
    // read through the reader per issue #461).
    let dir = temp_workspace();
    file_corrupt_overrides_document(dir.path());
    // A readable record is filed so the surfaces would otherwise have
    // found the binary — the fault, not a 404, is what stops them.
    file_classification_record(
        dir.path(),
        "game_logic.dll",
        serde_json::json!({ "binary": "game_logic.dll", "category": "ProjectSpecific" }),
    );
    let reader = reader_over(dir.path());

    let err = reader
        .binary_classifications()
        .expect_err("corrupt bytes are a fault");
    assert!(
        err.to_string().contains("classification_overrides.json"),
        "the fault names the document: {err}"
    );
}

#[tokio::test]
async fn the_reader_serves_the_workspaces_dashboard_with_the_live_store_folded_in() {
    let dir = make_repo_with_unit();
    let store = super::super::ProgressState::new();
    store.apply(&started("game_logic.dll", "DrawSprite")).await;
    store
        .apply(&started("game_logic.dll", "LateFunction"))
        .await;
    let reader = ReviewSurfaceReader::new(
        dir.path().to_path_buf(),
        Some(std::sync::Arc::new(tokio::sync::RwLock::new(store))),
    );

    let dashboard = reader
        .review_dashboard()
        .await
        .expect("the workspace dashboard builds");

    let listed = dashboard
        .review_queue
        .iter()
        .find(|u| u.id == "game_logic.dll/DrawSprite/v1")
        .expect("the workspace's unit is listed");
    assert_eq!(
        listed.status,
        ReviewStatus::InProgress,
        "the store's in-flight reading reaches the built dashboard"
    );
    let synthetic: Vec<&UnitOfWork> = dashboard
        .review_queue
        .iter()
        .filter(|u| u.function.as_deref() == Some("LateFunction"))
        .collect();
    assert_eq!(
        synthetic.len(),
        1,
        "the unit only the store names arrives exactly once"
    );
    assert_eq!(synthetic[0].id, "live/game_logic.dll/LateFunction/v1");
}

//! Integration tests for [`DashboardBuilder`] — review verdicts must survive
//! a dashboard rebuild (issue #9), and the dependency edges the builder wires
//! must be dense enough for the `Blocked` cascade to bite (issue #10).
//!
//! The builder recomputes every unit's status from branch state on each
//! build; these tests pin the fix that makes the failing verdicts durable:
//! rejection records (`re/rejections/`) report `SendBack`, patch-request
//! records (`re/patches/` with a `patch_request` field) report
//! `PatchRequested`, and a merged branch stays `Accepted` whichever records
//! exist — branch state remains authoritative for acceptance.
//!
//! The cascade tests pin the branch-model edges: a function unit depends on
//! the shim-layer unit its classification requires (the same dependency the
//! branch-creation policy checks) and on its DLL's classification unit, so a
//! sent-back dependency cascades `Blocked` to everything translating on top
//! of it.

use calxgloss_git::{GitManager, InitConfig};
use calxgloss_reports::dashboard::{
    DashboardBuilder, ReviewDashboard, ReviewStatus, UnitOfWork, UnitViewData, ViewTarget,
};
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

/// Writes a classification record at `re/classify/{dll}.json` in the shape
/// the `classify` command writes (a serialized `DllClassification`), carrying
/// the category and crate replacement the branch-creation policy checks.
fn write_classification_record(
    git: &GitManager,
    dll: &str,
    category: &str,
    crate_replacement: Option<&str>,
) {
    let classify_dir = git.repo_path().join("re").join("classify");
    std::fs::create_dir_all(&classify_dir).expect("create classify dir");

    let mut record = serde_json::json!({
        "dll": dll,
        "category": category,
        "strategy": "ReverseEngineer",
        "exports_count": 10,
        "imports_count": 2,
    });
    if let Some(krate) = crate_replacement {
        record["strategy"] = serde_json::json!({ "CrateReplacement": { "crate_name": krate } });
        record["crate_replacement"] = serde_json::Value::String(krate.to_string());
    }
    std::fs::write(
        classify_dir.join(format!("{dll}.json")),
        serde_json::to_string_pretty(&record).expect("serialize classification record"),
    )
    .expect("write classification record");
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
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 1);

    let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
    git.reject_branch(&branch, "wrong blend mode mapping")
        .expect("write send-back record");

    // The verdict must hold across rebuilds, not just the build that saw
    // the action — the builder reads `re/rejections/`, not in-memory state.
    for round in 1..=2 {
        let dashboard = build(&git);
        let unit = find_unit(&dashboard, "game_logic.dll/DrawSprite/v1");
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
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 1);
    // request_patch spawns the next-attempt branch and records the request there.
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 2);
    write_patch_record(
        &git,
        "game_logic.dll",
        "DrawSprite",
        2,
        Some("index buffer stride wrong"),
    );

    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "game_logic.dll/DrawSprite/v2");
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
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 1);
    write_patch_record(&git, "game_logic.dll", "DrawSprite", 1, None);

    // A plain pipeline failure record is not a reviewer verdict — the
    // attempt simply failed and awaits review as before.
    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "game_logic.dll/DrawSprite/v1");
    assert_eq!(
        unit.status,
        ReviewStatus::PendingReview,
        "a failure record without patch_request still reports PendingReview"
    );
    assert_eq!(dashboard.status_counts.patch_requested, 0);
}

#[test]
fn merged_branch_with_send_back_reports_accepted() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 1);

    let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
    git.merge_to_main(&branch).expect("merge to main");
    git.reject_branch(&branch, "stale rejection")
        .expect("write send-back record");

    // Branch state stays authoritative for acceptance: a merged branch is
    // Accepted whichever records sit beside it.
    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "game_logic.dll/DrawSprite/v1");
    assert_eq!(
        unit.status,
        ReviewStatus::Accepted,
        "a merged branch reports Accepted despite a send-back record"
    );
}

#[test]
fn send_back_is_scoped_to_its_attempt() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 1);
    let branch_v1 = GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
    git.reject_branch(&branch_v1, "wrong blend mode mapping")
        .expect("write send-back record");
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 2);

    let dashboard = build(&git);
    assert_eq!(
        find_unit(&dashboard, "game_logic.dll/DrawSprite/v1").status,
        ReviewStatus::SendBack,
        "the sent-back attempt keeps its verdict"
    );
    assert_eq!(
        find_unit(&dashboard, "game_logic.dll/DrawSprite/v2").status,
        ReviewStatus::Queued,
        "the fresh attempt carries no verdict from the previous attempt"
    );
}

#[test]
fn foo_dll_and_foo_exe_coexist_as_distinct_units() {
    // Binary identity is the filename verbatim, extension included: a
    // workspace holding both `foo.dll` and `foo.exe` must key their units
    // apart end-to-end — branches, unit ids, and the dashboard (issue #68).
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    commit_on_branch(&git, "foo.dll", "DrawSprite", 1);
    commit_on_branch(&git, "foo.exe", "DrawSprite", 1);

    let branches = git.list_translation_branches().expect("list branches");
    assert!(branches.contains(&"re/foo.dll/DrawSpritev1".to_string()));
    assert!(branches.contains(&"re/foo.exe/DrawSpritev1".to_string()));

    let dashboard = build(&git);
    assert_eq!(
        find_unit(&dashboard, "foo.dll/DrawSprite/v1").dll,
        "foo.dll"
    );
    assert_eq!(
        find_unit(&dashboard, "foo.exe/DrawSprite/v1").dll,
        "foo.exe"
    );

    // Both units surface in the review queue side by side.
    let queued: Vec<&str> = dashboard
        .review_queue
        .iter()
        .filter(|u| u.dll == "foo.dll" || u.dll == "foo.exe")
        .map(|u| u.id.as_str())
        .collect();
    assert!(
        queued.contains(&"foo.dll/DrawSprite/v1") && queued.contains(&"foo.exe/DrawSprite/v1"),
        "both units sit in the review queue: {queued:?}"
    );

    // The unit-detail seam parses both identities verbatim.
    for dll in ["foo.dll", "foo.exe"] {
        let target = ViewTarget::parse(&format!("{dll}/DrawSprite/v1"))
            .expect("unit id parses as a view target");
        assert_eq!(target.dll, dll);
        assert_eq!(target.function, "DrawSprite");
    }
}

#[test]
fn accepted_units_keep_stable_recent_activity_across_rebuilds() {
    // The web Recent activity panel showed every accepted unit as "just
    // now" and cycled its order between refreshes: the builder stamped
    // `updated_at` with the build time and left the list in filesystem
    // order. Timestamps must come from the work, not the build.
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    write_classification_record(&git, "game_logic.dll", "MicrosoftSdk", None);
    commit_on_branch(&git, "game_logic.dll", "DrawSprite", 1);
    let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).expect("branch name");
    git.merge_to_main(&branch).expect("merge to main");

    let first = build(&git);
    let second = build(&git);

    let ids = |d: &ReviewDashboard| -> Vec<String> {
        d.recent_activity.iter().map(|u| u.id.clone()).collect()
    };
    assert_eq!(
        ids(&first),
        ids(&second),
        "recent activity order is identical across rebuilds"
    );

    let unit = find_unit(&first, "game_logic.dll/DrawSprite/v1");
    let rebuilt = find_unit(&second, "game_logic.dll/DrawSprite/v1");
    assert_eq!(
        unit.updated_at, rebuilt.updated_at,
        "a merged unit's updated_at is its branch commit time, not the build time"
    );

    // The classification unit timestamps from its record file, not the build.
    let classify = find_unit(&first, "classify/game_logic.dll");
    let mtime = std::fs::metadata(dir.path().join("re/classify/game_logic.dll.json"))
        .expect("classification record")
        .modified()
        .expect("record mtime");
    assert_eq!(
        classify.updated_at,
        chrono::DateTime::<chrono::Utc>::from(mtime),
        "the classify unit's updated_at is the record file's mtime"
    );
}

/// The `classify` command serializes `Strategy` as an enum: unit variants
/// as bare strings, crate replacement as a tagged object. The dashboard
/// must read the variant name from either form — a record whose strategy
/// is an object must not fail to parse and lose its category too.
#[test]
fn tagged_object_strategy_hydrates_category_and_strategy() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    write_classification_record(
        &git,
        "steam_api64.dll",
        "KnownThirdParty",
        Some("steamworks"),
    );
    commit_on_branch(&git, "steam_api64.dll", "SteamAPI_Init", 1);

    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "steam_api64.dll/SteamAPI_Init/v1");
    assert_eq!(unit.dll, "steam_api64.dll", "the unit exists to be viewed");

    let target = ViewTarget {
        dll: "steam_api64.dll".into(),
        function: "SteamAPI_Init".into(),
        specific_attempt: None,
    };
    let view = UnitViewData::load(&git, &target, dir.path()).expect("unit view loads");
    assert_eq!(
        view.dll_category.as_deref(),
        Some("KnownThirdParty"),
        "the tagged-object strategy must not sink the whole record"
    );
    assert_eq!(
        view.dll_strategy.as_deref(),
        Some("CrateReplacement"),
        "the strategy's variant name is the strategy"
    );
}

#[test]
fn sent_back_shim_blocks_dependent_function_unit() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    // d3d9.dll is a crate-replacement target: the branch model requires the
    // wgpu shim layer merged into main before its functions translate.
    write_classification_record(&git, "d3d9.dll", "MicrosoftSdk", Some("wgpu"));

    commit_on_branch(&git, "shim", "wgpu", 1);
    let shim_branch = GitBranch::new("shim", "wgpu", 1).expect("branch name");
    git.reject_branch(&shim_branch, "wgpu shim drops the present() stride")
        .expect("write send-back record");

    // A function translating on top of the sent-back shim.
    commit_on_branch(&git, "d3d9.dll", "Present", 1);

    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "d3d9.dll/Present/v1");
    assert!(
        unit.dependencies.iter().any(|d| d == "shim/wgpu/v1"),
        "the function unit carries the branch-model shim edge"
    );
    assert_eq!(
        unit.status,
        ReviewStatus::Blocked,
        "a sent-back shim blocks the function translating on top of it"
    );
    assert_eq!(
        find_unit(&dashboard, "shim/wgpu/v1").status,
        ReviewStatus::SendBack,
        "the failing root keeps its own verdict"
    );
    assert!(dashboard.status_counts.blocked >= 1);
    assert!(
        dashboard
            .dependency_graph
            .edges
            .iter()
            .any(|e| e.from == "d3d9.dll/Present/v1" && e.to == "shim/wgpu/v1"),
        "the dependency graph carries the shim edge"
    );
}

#[test]
fn merged_shim_wires_the_edge_without_blocking() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");
    write_classification_record(&git, "d3d9.dll", "MicrosoftSdk", Some("wgpu"));

    commit_on_branch(&git, "shim", "wgpu", 1);
    let shim_branch = GitBranch::new("shim", "wgpu", 1).expect("branch name");
    git.merge_to_main(&shim_branch).expect("merge shim to main");

    commit_on_branch(&git, "d3d9.dll", "Present", 1);

    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "d3d9.dll/Present/v1");
    assert!(
        unit.dependencies.iter().any(|d| d == "shim/wgpu/v1"),
        "the shim edge is wired whichever way the shim went"
    );
    assert_eq!(
        unit.status,
        ReviewStatus::Queued,
        "a merged (Accepted) shim blocks nothing"
    );
    assert_eq!(dashboard.status_counts.blocked, 0);
}

#[test]
fn no_classification_record_means_no_shim_edge_and_no_blocking() {
    let dir = temp_workspace();
    let git = GitManager::open(dir.path()).expect("open repo");

    // A shim branch sent back, but no classification record naming the shim:
    // the branch model has no declared dependency, so nothing is blocked.
    commit_on_branch(&git, "shim", "wgpu", 1);
    let shim_branch = GitBranch::new("shim", "wgpu", 1).expect("branch name");
    git.reject_branch(&shim_branch, "shim rejected")
        .expect("write send-back record");

    commit_on_branch(&git, "d3d9.dll", "Present", 1);

    let dashboard = build(&git);
    let unit = find_unit(&dashboard, "d3d9.dll/Present/v1");
    assert!(
        !unit.dependencies.iter().any(|d| d == "shim/wgpu/v1"),
        "no classification record, no declared shim dependency"
    );
    assert_eq!(unit.status, ReviewStatus::Queued);
    assert_eq!(dashboard.status_counts.blocked, 0);
}

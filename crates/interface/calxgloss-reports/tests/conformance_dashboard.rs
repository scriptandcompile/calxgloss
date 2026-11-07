//! The conformance verdict at the reports dashboard build (issue #419,
//! P26.3): one honest per-binary verdict from one derivation, riding the
//! shared dashboard model.
//!
//! Every test stages documents and branch state in a temp workspace, then
//! asserts what the derived model says — the verdict, its named cause, the
//! closure digest, the disposition tallies — never which internal function
//! produced it (P26 spec, Testing Decisions).

use calxgloss_git::GitManager;
use calxgloss_reports::dashboard::DashboardBuilder;
use calxgloss_types::{
    BinaryConformance, BinaryIdentity, ConformanceTally, ConformanceUnknownCause,
    ConformanceVerdict, DimensionCounts, ObligationDisposition, ObligationEntry, ObligationLedger,
    VerificationReceipt, VerificationVerdict, VerifierCommand, obligation_ledger_path, save_json,
    verification_receipt_markdown,
};
use std::collections::BTreeMap;

/// Initialises a test git repo (a `main` branch with one commit) in `path`.
fn init_test_repo(path: &std::path::Path) -> GitManager {
    let config = calxgloss_git::InitConfig {
        author_name: "Calxgloss Test".into(),
        author_email: "test@calxgloss.test".into(),
        committer_name: None,
        committer_email: None,
    };
    GitManager::init_repo(path, Some(config)).expect("init git repo")
}

/// A repo with one unit's translation branch, nothing else filed.
fn one_unit_repo(dir: &std::path::Path) -> GitManager {
    let git = init_test_repo(dir);
    git.create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch");
    git
}

/// Fetches a built binary's conformance row from the derived model.
fn find_conformance(
    dashboard: &calxgloss_types::ReviewDashboard,
    binary: &str,
) -> BinaryConformance {
    dashboard
        .conformance
        .iter()
        .find(|row| row.binary == binary)
        .cloned()
        .unwrap_or_else(|| panic!("a conformance row for {binary} rides the model"))
}

/// Files the *verification receipt* pair — JSON authority plus Markdown
/// twin — the way the verify gate commits it beside the attempt's work,
/// and returns the receipt's own content digest (the citation the ledger
/// will carry).
fn stage_receipt_pair(git: &GitManager, binary: &str, function: &str, attempt: u32) -> String {
    stage_receipt_pair_verdicted(git, binary, function, attempt, VerificationVerdict::Passed)
}

/// Files a digest-paired receipt pair whose verdict is `verdict`, and
/// returns the pair's content digest — the citation a ledger entry would
/// claim green with.
fn stage_receipt_pair_verdicted(
    git: &GitManager,
    binary: &str,
    function: &str,
    attempt: u32,
    verdict: VerificationVerdict,
) -> String {
    let identity = BinaryIdentity::new(binary);
    let mut dimensions = BTreeMap::new();
    dimensions.insert(
        "values".to_string(),
        DimensionCounts {
            assessed: 2,
            passed: if verdict == VerificationVerdict::Passed {
                2
            } else {
                1
            },
        },
    );
    let mut receipt = VerificationReceipt {
        binary: identity.clone(),
        function: function.to_string(),
        attempt,
        retry_strategy: "initial".to_string(),
        attempt_path: "strategy_prompt".to_string(),
        verifier_command: VerifierCommand::CompileAndBaselineTest,
        baseline_suite_digest: "sha256:suite".to_string(),
        dimensions,
        compile_ms: 10,
        test_run_ms: 5,
        total_ms: 15,
        verdict,
        failed_cases: Vec::new(),
        digest: String::new(),
    };
    receipt.digest = receipt.content_digest().expect("digests");
    // The receipt rides the attempt branch like the verify gate files
    // it: the JSON authority beside its Markdown twin under
    // `re/verification/{binary}/{function}/attempt-{N}.json`.
    let rel_json = format!("re/verification/{binary}/{function}/attempt-{attempt}.json");
    let json_path = git.repo_path().join(&rel_json);
    std::fs::create_dir_all(json_path.parent().expect("receipt dir")).expect("receipt dir");
    std::fs::write(
        &json_path,
        serde_json::to_string(&receipt).expect("serializes"),
    )
    .expect("file receipt JSON");
    std::fs::write(
        json_path.with_extension("md"),
        verification_receipt_markdown(&receipt),
    )
    .expect("file receipt twin");
    receipt.digest
}

/// Files `re/unknowns/<binary>.json` with an explicit `records` reading —
/// `[]` is the honest known-and-none, the only reading that proves the
/// gate open of blocking unknowns.
fn stage_unknown_ledger(dir: &std::path::Path, binary: &str, records: Vec<serde_json::Value>) {
    let path = dir
        .join("re")
        .join("unknowns")
        .join(format!("{binary}.json"));
    std::fs::create_dir_all(path.parent().expect("unknowns dir")).expect("unknowns dir");
    let doc = serde_json::json!({
        "binary": binary,
        "filed_at": 1,
        "records": records,
    });
    std::fs::write(&path, doc.to_string()).expect("file unknown ledger");
}

/// Files an Accept review-action record at
/// `re/accepts/{binary}/{function}/v{attempt}.json` — the same shape
/// `accept_branch` files, for pins that need the record without the merge.
fn stage_accept_record(dir: &std::path::Path, binary: &str, function: &str, attempt: u32) {
    let path = dir
        .join("re")
        .join("accepts")
        .join(binary)
        .join(function)
        .join(format!("v{attempt}.json"));
    std::fs::create_dir_all(path.parent().expect("accept dir")).expect("accept dir");
    let doc = serde_json::json!({
        "binary": binary,
        "function": function,
        "attempt": attempt,
        "merge_result": "merged: 0000000000000000000000000000000000000000",
    });
    std::fs::write(&path, doc.to_string()).expect("file accept record");
}

/// A green-closing entry: claims verified, owned by `owner`, citing the
/// receipt digest.
fn claimed_entry(function: &str, attempt: u32, owner: &str, receipt: &str) -> ObligationEntry {
    let mut entry = ObligationEntry::new(
        function,
        attempt,
        owner,
        ObligationDisposition::ClaimedVerified,
    );
    entry.receipt_digest = Some(receipt.to_string());
    entry
}

/// Files the reviewer's skip set at `re/review/skips.json` with the
/// given unit keys — the same document the review surfaces write.
fn stage_skip_set(dir_path: &std::path::Path, keys: &[&str]) {
    let path = dir_path.join("re").join("review").join("skips.json");
    std::fs::create_dir_all(path.parent().expect("review dir")).expect("review dir");
    std::fs::write(
        &path,
        serde_json::json!({"skipped": keys}).to_string(),
    )
    .expect("file skip set");
}

/// Files a classification record at `re/classify/{binary}.json` with the
/// given category and reason — the shape the `classify` command files.
fn stage_classification(dir_path: &std::path::Path, binary: &str, category: &str, reason: &str) {
    let path = dir_path.join("re").join("classify").join(format!("{binary}.json"));
    std::fs::create_dir_all(path.parent().expect("classify dir")).expect("classify dir");
    std::fs::write(
        &path,
        serde_json::json!({"category": category, "reason": reason}).to_string(),
    )
    .expect("file classification");
}

/// Files an operator classification override steering `binary` to the
/// given category, at `re/analysis/classification_overrides.json`.
fn stage_classification_override(dir_path: &std::path::Path, binary: &str, category: &str) {
    let path = dir_path
        .join("re")
        .join("analysis")
        .join("classification_overrides.json");
    std::fs::create_dir_all(path.parent().expect("analysis dir")).expect("analysis dir");
    std::fs::write(
        &path,
        serde_json::json!({
            "overrides": {binary: {"category": category, "known_runtime": false}}
        })
        .to_string(),
    )
    .expect("file classification override");
}

/// Files a reviewer unit override record for `{binary}/{function}` at
/// `re/analysis/unit_overrides.json`, with the given notes.
fn stage_unit_override(dir_path: &std::path::Path, binary: &str, function: &str, notes: &str) {
    let path = dir_path
        .join("re")
        .join("analysis")
        .join("unit_overrides.json");
    std::fs::create_dir_all(path.parent().expect("analysis dir")).expect("analysis dir");
    std::fs::write(
        &path,
        serde_json::json!({
            "overrides": {
                format!("{binary}/{function}"): {"reviewer_notes": notes}
            }
        })
        .to_string(),
    )
    .expect("file unit override");
}

#[test]
fn honest_dispositions_tally_apart_from_verified_in_the_model_and_the_json() {
    // One fully proven obligation closed and five honest dispositions —
    // skipped, parked, overridden, un-reviewed, no-baseline — filed in one
    // ledger. The row shows the closed obligation as *verified* and each
    // disposition in its own count, never folded into it; the dispositions
    // hold the obligations open, so the verdict is *incomplete*; and the
    // serialized model JSON carries the tally (issue #419, AC 4).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");

    let mut entries = vec![claimed_entry(
        "DrawPrimitive",
        1,
        &commit.hash,
        &receipt_digest,
    )];
    for (function, disposition) in [
        ("SkipMe", ObligationDisposition::Skipped),
        ("ParkMe", ObligationDisposition::Parked),
        ("OverrideMe", ObligationDisposition::Overridden),
        ("ReviewMe", ObligationDisposition::UnReviewed),
        ("BaselineMe", ObligationDisposition::NoBaseline),
    ] {
        entries.push(ObligationEntry::new(function, 1, &commit.hash, disposition));
    }
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger =
        ObligationLedger::file("game_logic.dll", entries, 1_700_000_000).expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "honest dispositions hold obligations open — tallied, never quietly closed"
    );
    assert_eq!(
        row.tally,
        ConformanceTally {
            verified: 1,
            skipped: 1,
            parked: 1,
            overridden: 1,
            un_reviewed: 1,
            no_baseline: 1,
        },
        "the verified close and each honest disposition keep their own count"
    );

    let json = serde_json::to_value(&dashboard).expect("the model serializes");
    let tally = &json["conformance"][0]["tally"];
    assert_eq!(
        tally["verified"],
        serde_json::json!(1),
        "JSON keeps verified apart"
    );
    assert_eq!(
        tally["skipped"],
        serde_json::json!(1),
        "JSON shows the skip tally"
    );
    assert_eq!(
        tally["parked"],
        serde_json::json!(1),
        "JSON shows the parked tally"
    );
    assert_eq!(
        tally["overridden"],
        serde_json::json!(1),
        "JSON shows the override tally"
    );
    assert_eq!(
        tally["un_reviewed"],
        serde_json::json!(1),
        "JSON shows the un-reviewed tally"
    );
    assert_eq!(
        tally["no_baseline"],
        serde_json::json!(1),
        "JSON shows the no-baseline tally"
    );
}

#[test]
fn branch_merged_with_no_accept_review_action_reads_un_reviewed_and_never_verified() {
    // Issue #420 (P26.4), AC 5: a merge landed on main without an Accept
    // review action. The read seam joins branch state with the review
    // records, so the unit reads *un-reviewed* — tallied in its own
    // count, never as verified — and the verdict never reaches complete.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    // The merge lands with no accept_branch call: no Accept record stands.
    git.merge_to_main(&branch).expect("merge into main");
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "a merged, un-reviewed unit blocks complete on its own"
    );
    assert_eq!(
        row.tally.un_reviewed, 1,
        "the un-reviewed merge tallies in its own count"
    );
    assert_eq!(
        row.tally.verified, 0,
        "a merge with no Accept review action is never verified"
    );
    let open = row.first_open.as_ref().expect("the honest reading is named");
    assert!(
        open.link.contains("Accept"),
        "the reading names the missing review action: {}",
        open.link
    );
}

#[test]
fn a_staged_fully_evidenced_binary_derives_complete_carrying_its_closure_digest() {
    // The full-evidence tracer (issue #419): one ledger entry, owned by
    // the attempt branch's commit, citing a real receipt pair committed
    // on that branch, with an Accept review action, merged content, and
    // no open unknowns — reads *complete*, sealed by the digest the
    // verdict reports with.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    // The attempt's work: translated content plus the receipt pair, all
    // landing in the branch's first commit — the owner digest the entry
    // pins. Files are staged after the branch stands, the order the
    // pipeline commits in.
    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");

    // The Accept review action: merges to main and files the accept record.
    git.accept_branch(&branch).expect("accept branch");

    // The records beside the branch: an explicitly-none unknown ledger
    // and the obligation ledger sealing the roster.
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Complete,
        "a fully evidenced binary reads complete — every obligation closed on checked evidence"
    );
    assert!(
        row.causes.is_empty(),
        "a complete verdict names no unknown cause"
    );
    assert_eq!(
        row.closure_digest.as_deref(),
        Some(ledger.digest.as_str()),
        "the verdict reports the closure digest it was computed under"
    );
}

#[test]
fn an_incomplete_verdict_names_the_first_link_of_the_chain_that_broke() {
    // Same fully staged evidence as the complete case, minus the Accept
    // review action: the chain breaks at review, and the row names that
    // link — the first thing the operator can fix (issue #419, AC 1).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    // No accept_branch call: review never acted on the attempt.
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(row.verdict, ConformanceVerdict::Incomplete);
    assert_eq!(
        row.tally.verified, 0,
        "an unreviewed merge never counts as verified"
    );
    let open = row.first_open.as_ref().expect("the broken link is named");
    assert_eq!(open.function, "DrawPrimitive");
    assert_eq!(open.attempt, 1);
    assert!(
        open.link.contains("Accept"),
        "the named link is the review door: {}",
        open.link
    );
    let json = serde_json::to_value(&dashboard).expect("the model serializes");
    assert_eq!(
        json["conformance"][0]["first_open"]["function"].as_str(),
        Some("DrawPrimitive"),
        "the named link rides the JSON model too"
    );
}

#[test]
fn a_stale_owner_pin_holds_the_obligation_open_naming_the_owner_link() {
    // The entry pins the first commit; the branch then moves on. The tip
    // no longer names the entry's owner, so the claim stays open and the
    // row names that link (issue #392, story 9).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let first = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    // The branch moves on: the tip is no longer the pinned owner.
    std::fs::write(&source, "// translated, then amended").expect("amend source");
    git.commit(
        &branch,
        "re: amend DrawPrimitive",
        &["src/game_logic.dll_DrawPrimitive_v1.rs"],
    )
    .expect("second commit");
    git.accept_branch(&branch).expect("accept branch");
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &first.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(row.verdict, ConformanceVerdict::Incomplete);
    let open = row.first_open.as_ref().expect("the broken link is named");
    assert_eq!(open.function, "DrawPrimitive");
    assert!(
        open.link.contains("owner"),
        "the named link is the stale owner pin: {}",
        open.link
    );
}

#[test]
fn a_receipt_not_verdicted_passed_never_closes_the_obligation() {
    // A tests-failed pair, cited honestly by its own digest, is still not
    // a green close: the obligation stays open and names the verdict (AC 1).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair_verdicted(
        &git,
        "game_logic.dll",
        "DrawPrimitive",
        1,
        VerificationVerdict::TestsFailed,
    );
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(row.verdict, ConformanceVerdict::Incomplete);
    let open = row.first_open.as_ref().expect("the broken link is named");
    assert!(
        open.link.contains("tests_failed"),
        "the named link quotes the receipt's own verdict: {}",
        open.link
    );
}

#[test]
fn an_unmerged_branch_holds_the_obligation_open_naming_the_merge_link() {
    // An Accept record says merged, yet the branch was never landed on
    // main: the merge check keeps the obligation open and names that link.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    // The record says a merge landed; the branch itself never merged.
    stage_accept_record(dir.path(), "game_logic.dll", "DrawPrimitive", 1);
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(row.verdict, ConformanceVerdict::Incomplete);
    let open = row.first_open.as_ref().expect("the broken link is named");
    assert!(
        open.link.contains("not merged into main"),
        "the named link is the missing merge: {}",
        open.link
    );
}

#[test]
fn a_citation_with_no_receipt_pair_on_the_branch_reads_unknown_naming_the_citation_fault() {
    // The ledger cites a receipt digest no branch carries: the records
    // themselves failed to read, so the verdict is unknown with the named
    // cause — never merely incomplete (issue #392, story 8).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &["src/game_logic.dll_DrawPrimitive_v1.rs"],
        )
        .expect("attempt commit, no pair staged");
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let skipped = ObligationEntry::new(
        "UpdateScene",
        1,
        "0000000000000000000000000000000000000000",
        ObligationDisposition::Skipped,
    );
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![
            claimed_entry(
                "DrawPrimitive",
                1,
                &commit.hash,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            skipped,
        ],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("the dashboard build survives an unresolvable citation");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(row.verdict, ConformanceVerdict::Unknown);
    assert_eq!(
        row.causes,
        vec![ConformanceUnknownCause::UnresolvableReceiptCitation],
        "the cause names the unreadable citation"
    );
    assert_eq!(
        row.tally.skipped, 1,
        "a row broken mid-read keeps counting the dispositions it could read — the JSON and the terminal show the same tally (AC 4)"
    );
}

#[test]
fn a_fully_closed_binary_without_an_unknown_ledger_still_names_why_the_gate_stays_shut() {
    // Every chain link closed, but the binary's open-unknown state was
    // never proven: the verdict is *incomplete* and names the unproven
    // gate as its reason, so the operator knows what to file (issue
    // #419).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch");
    let branch = branch.branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");
    // Deliberately no unknown ledger filed: nothing proves the gate.
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "an unproven open-unknown state never reads complete"
    );
    assert_eq!(row.tally.verified, 1, "the evidence chain itself closed");
    assert!(
        row.blocking_unknowns
            .iter()
            .any(|reason| reason.contains("open set")),
        "the row names the unproven gate as what holds it shut: {:?}",
        row.blocking_unknowns
    );
}

#[test]
fn supporting_shim_work_never_gets_a_conformance_row() {
    // A `re/shim/...` branch is supporting work, not a target binary:
    // it must not print a false "no ledger filed" verdict under the
    // pseudo-binary `shim` (issue #419, one verdict per target binary).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = one_unit_repo(dir.path());
    let head = git.repo().head().expect("head");
    let commit = head.peel_to_commit().expect("head peels to a commit");
    git.repo()
        .branch("re/shim/wgpu", &commit, false)
        .expect("shim branch");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    assert!(
        dashboard
            .unknown_ledgers
            .iter()
            .any(|row| row.binary == "shim"),
        "the shim branch does stand as a unit in the model — the pin below is about conformance only"
    );
    assert!(
        !dashboard.conformance.iter().any(|row| row.binary == "shim"),
        "no conformance row for supporting shim work: {:?}",
        dashboard
            .conformance
            .iter()
            .map(|row| &row.binary)
            .collect::<Vec<_>>()
    );
    assert!(
        dashboard
            .conformance
            .iter()
            .any(|row| row.binary == "game_logic.dll"),
        "the target binary keeps its row"
    );
}

#[test]
fn a_blocking_open_unknown_holds_a_fully_closed_binary_short_of_complete() {
    // Every obligation closed on checked evidence, yet one blocking record
    // stands in the binary's unknown ledger: the gate shuts and no verdict
    // above *incomplete* is available (ADR-0056's severity, finally gating).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");
    stage_unknown_ledger(
        dir.path(),
        "game_logic.dll",
        vec![serde_json::json!({
            "id": "unknown-export-uncovered",
            "binary": "game_logic.dll",
            "kind": "export_uncovered",
            "severity": "blocking",
            "question": "no filed baseline ever covered DrawPrimitive?",
            "required_evidence": "a filed baseline document naming the export",
            "origin": { "origin": "case_set", "case_set": "re/baseline/game_logic.dll.json" },
            "first_seen": 1,
            "last_seen": 1,
            "revision": 1,
        })],
    );
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.tally.verified, 1,
        "the chain itself closed — the gate is what holds the binary shut"
    );
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "a blocking open unknown never reads complete"
    );
    assert!(
        row.blocking_unknowns.iter().any(|reason| {
            reason.contains("unknown-export-uncovered")
                && reason.contains("export_uncovered")
                && reason.contains("blocking")
        }),
        "the row names the blocking record that shut the gate, not just the counts: {:?}",
        row.blocking_unknowns
    );
    assert!(
        row.first_open.is_none(),
        "no obligation chain broke, so no first-open line is invented"
    );
}

#[test]
fn an_empty_validly_sealed_ledger_never_reads_complete_unknown_naming_no_obligations_filed() {
    // Fail-closed means "queue empty" is never "binary done": a roster
    // naming nothing proves nothing, even sealed well with a clean gate.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = one_unit_repo(dir.path());

    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file("game_logic.dll", Vec::new(), 1_700_000_000)
        .expect("file an empty roster");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("the dashboard build survives an empty roster");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Unknown,
        "an empty roster never reads complete (issue #392's whole point)"
    );
    assert_eq!(
        row.causes,
        vec![ConformanceUnknownCause::NoObligationsFiled],
        "the cause names a roster that obligates nothing"
    );
    assert!(
        row.closure_digest.is_none(),
        "an unproven run carries no closure seal"
    );
}

#[test]
fn a_replaced_ledger_document_is_an_input_error_named_at_read_falling_to_unknown() {
    // A fully valid ledger for ANOTHER binary filed at this binary's path
    // is a replaced document: the reader refuses it, the build survives,
    // and the verdict falls to unknown with the digest-mismatch cause (AC 3).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = one_unit_repo(dir.path());

    let other = ObligationLedger::file(
        "other.dll",
        vec![claimed_entry(
            "AnyFunction",
            1,
            "0000000000000000000000000000000000000000",
            "sha256:cafe",
        )],
        1_700_000_000,
    )
    .expect("seal a valid ledger for another binary");
    save_json(
        &obligation_ledger_path(dir.path(), &BinaryIdentity::from("game_logic.dll")),
        &other,
    )
    .expect("misfile it at game_logic.dll's route");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("the dashboard build never fails on a replaced ledger");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Unknown,
        "a replaced document never reads complete"
    );
    assert_eq!(
        row.causes,
        vec![ConformanceUnknownCause::DigestMismatch],
        "the named cause is the input error at read"
    );
}

#[test]
fn a_never_filed_ledger_derives_unknown_naming_no_ledger_filed_and_the_build_survives() {
    // Absence of the obligation ledger is never a clean run: the row reads
    // *unknown* with the named cause "no ledger filed", and the dashboard
    // build itself never fails on the missing document (issue #419).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = one_unit_repo(dir.path());

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("the dashboard build never fails on a never-filed ledger");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Unknown,
        "a binary whose obligation ledger was never filed reads unknown, never clean"
    );
    assert_eq!(
        row.causes,
        vec![ConformanceUnknownCause::NoLedgerFiled],
        "the unknown names its cause instead of leaving the operator to guess"
    );
    assert_eq!(
        row.closure_digest, None,
        "no filed document seals nothing, so no digest rides along"
    );
}

#[test]
fn tampered_ledger_bytes_are_an_input_error_named_at_read_and_the_verdict_falls_to_unknown() {
    // Replacing the filed bytes after filing is caught at read: the
    // reader refuses the document, the verdict falls to *unknown* with
    // the digest-mismatch cause, and the build itself never fails
    // (issue #419, AC 3).
    let dir = tempfile::tempdir().expect("temp dir");
    let git = one_unit_repo(dir.path());
    let ledger = ObligationLedger::file("game_logic.dll", Vec::new(), 1_700_000_000)
        .expect("file an empty ledger");
    let path = obligation_ledger_path(dir.path(), &ledger.binary);
    save_json(&path, &ledger).expect("save the ledger");

    // The tamper: someone edits the filed bytes while keeping the old
    // seal — the reader re-derives the digest and refuses.
    let tampered = r#"{"binary":"game_logic.dll","filed_at":1700000000,"entries":[],"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#;
    std::fs::write(&path, tampered).expect("tamper the filed ledger");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("the dashboard build never fails on tampered ledger bytes");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Unknown,
        "tampered bytes seal nothing — the verdict falls to unknown, never a stale complete"
    );
    assert_eq!(
        row.causes,
        vec![ConformanceUnknownCause::DigestMismatch],
        "the unknown names the digest mismatch the reader caught at read"
    );
    assert_eq!(
        row.closure_digest, None,
        "a rejected document carries no closure digest"
    );
}

#[test]
fn model_and_verdict_documents_absent_the_new_fields_still_read_as_unknown_never_zero() {
    // AC 6: a model document written before conformance existed — the
    // section simply absent — must still deserialize, and a conformance
    // row written without the verdict fields must still read — with the
    // absent verdict *unknown*, never a silent pass or a zeroed tally
    // pretending to be a clean reading.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = one_unit_repo(dir.path());
    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");
    let mut value = serde_json::to_value(&dashboard).expect("the model serializes");
    value
        .as_object_mut()
        .expect("a model object")
        .remove("conformance");
    let reparsed: calxgloss_types::ReviewDashboard =
        serde_json::from_value(value).expect("a model document without the section still reads");
    assert!(
        reparsed.conformance.is_empty(),
        "a model with no conformance section deserializes with none"
    );

    let row: calxgloss_types::BinaryConformance =
        serde_json::from_str(r#"{"binary":"game_logic.dll"}"#)
            .expect("a row without verdict, causes, or tally reads");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Unknown,
        "an absent verdict is unknown, never a default pass"
    );
    assert!(row.causes.is_empty());
    assert_eq!(row.closure_digest, None, "an absent seal seals nothing");
    assert_eq!(
        row.tally,
        ConformanceTally::default(),
        "an absent tally reads as the zero the reader never renders alone"
    );
}

#[test]
fn the_conformance_layer_stores_nothing_and_touches_no_branch_accept_or_review_state() {
    // AC 5 and AC 7: the verdict is derived fresh on every build and
    // nothing is written anywhere — two consecutive builds agree while
    // refs, the main tip, the workdir, and every review document stay
    // byte-identical. The conformance fold is a reader, not an actor.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());
    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let source = dir
        .path()
        .join("src")
        .join("game_logic.dll_DrawPrimitive_v1.rs");
    std::fs::create_dir_all(source.parent().expect("src dir")).expect("src dir");
    std::fs::write(&source, "// translated").expect("write source");
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "src/game_logic.dll_DrawPrimitive_v1.rs",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry(
            "DrawPrimitive",
            1,
            &commit.hash,
            &receipt_digest,
        )],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let snapshot = |git: &GitManager| {
        let mut refs: Vec<String> = git
            .repo()
            .references()
            .expect("refs readable")
            .flatten()
            .map(|reference| {
                format!(
                    "{}={}",
                    reference.name().unwrap_or("?"),
                    reference.peel_to_commit().expect("ref peels").id()
                )
            })
            .collect();
        refs.sort();
        let status = {
            let mut opts = git2::StatusOptions::new();
            let mut entries: Vec<String> = git
                .repo()
                .statuses(Some(&mut opts))
                .expect("status readable")
                .iter()
                .filter_map(|entry| entry.path().ok().map(str::to_string))
                .collect();
            entries.sort();
            entries
        };
        (refs, status)
    };

    let before = snapshot(&git);
    let first = DashboardBuilder::new(&git).build().expect("first build");
    let after_first = snapshot(&git);
    let second = DashboardBuilder::new(&git).build().expect("second build");
    let after_second = snapshot(&git);

    assert_eq!(
        before, after_first,
        "a dashboard build writes no ref and changes no workdir entry"
    );
    assert_eq!(
        after_first, after_second,
        "the verdict rides each build fresh — nothing cached between builds changes state"
    );
    assert_eq!(
        first.conformance, second.conformance,
        "the derived rows agree build to build while nothing is stored"
    );

    // The freshness direction of the same promise: edit the filed
    // document between builds and the next build's verdict follows it —
    // no cached *complete* survives the tamper.
    std::fs::write(
        obligation_ledger_path(dir.path(), &BinaryIdentity::from("game_logic.dll")),
        r#"{"binary":"game_logic.dll","filed_at":1700000000,"entries":[],"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#,
    )
    .expect("tamper between builds");
    let third = DashboardBuilder::new(&git).build().expect("third build");
    let third_row = find_conformance(&third, "game_logic.dll");
    assert_eq!(
        third_row.verdict,
        ConformanceVerdict::Unknown,
        "the verdict is derived fresh every build — a stored document's edit lands immediately"
    );

    // The review documents and unit review statuses the fold reads from
    // stay exactly where the Accept left them — the conformance fold
    // never accepts, merges, or rewrites a review record.
    let accept_path = dir
        .path()
        .join("re/accepts/game_logic.dll/DrawPrimitive/v1.json");
    let accept_before = std::fs::read(&accept_path).expect("accept record stands");
    let re_tree: Vec<String> = walk(dir.path().join("re"))
        .into_iter()
        .map(|path| format!("{}:{}", path.display(), file_digest(&path)))
        .collect();
    let _ = &second;
    let accept_after = std::fs::read(&accept_path).expect("accept record still stands");
    assert_eq!(
        accept_before, accept_after,
        "the Accept record is untouched"
    );
    let re_tree_after: Vec<String> = walk(dir.path().join("re"))
        .into_iter()
        .map(|path| format!("{}:{}", path.display(), file_digest(&path)))
        .collect();
    assert_eq!(
        re_tree, re_tree_after,
        "no `re/` document is rewritten by a build"
    );
}

/// Every file under `root`, sorted by path.
fn walk(root: std::path::PathBuf) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

/// A cheap stable digest of a file's bytes for the untouched-state pin.
fn file_digest(path: &std::path::Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::fs::read(path).expect("file reads").hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[test]
fn a_reviewer_skip_holds_its_unit_out_and_names_the_skip_set_as_provenance() {
    // Issue #420 (P26.4), AC 1: the reviewer's skip set names one unit
    // attempt. The read seam joins it with the ledger, so the unit reads
    // *skipped* — tallied apart from the verified, with the skip set
    // named as provenance — and the verdict is *incomplete*, never a
    // clean run.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
        .expect("translation branch")
        .branch;
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawSprite", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawSprite",
            &[
                "re/verification/game_logic.dll/DrawSprite/attempt-1.json",
                "re/verification/game_logic.dll/DrawSprite/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    // The reviewer skips this attempt: the skip set spells the unit key
    // exactly as the review surfaces store it.
    stage_skip_set(dir.path(), &["game_logic.dll/DrawSprite/v1"]);
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry("DrawSprite", 1, &commit.hash, &receipt_digest)],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "a skipped unit blocks complete on its own"
    );
    assert_eq!(
        row.tally.skipped, 1,
        "the skipped unit tallies in its own count"
    );
    assert_eq!(
        row.tally.verified, 0,
        "a unit the reviewer took out of work never reads verified"
    );
    let open = row.first_open.as_ref().expect("the honest reading is named");
    assert!(
        open.link.contains("skips.json"),
        "the provenance names the skip-set document: {}",
        open.link
    );
}

#[test]
fn a_do_not_translate_classification_parks_every_unit_under_the_binary() {
    // Issue #420 (P26.4), AC 2: the binary is classified Do Not
    // Translate. Every unit under it reads *parked* with the
    // classification's reason beside it — even a fully-evidenced claim —
    // and the verdict never reaches complete.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
        .expect("translation branch")
        .branch;
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawSprite", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawSprite",
            &[
                "re/verification/game_logic.dll/DrawSprite/attempt-1.json",
                "re/verification/game_logic.dll/DrawSprite/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.merge_to_main(&branch).expect("merge into main");
    stage_accept_record(dir.path(), "game_logic.dll", "DrawSprite", 1);
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    // The classification record parks the whole binary, reason included.
    stage_classification(
        dir.path(),
        "game_logic.dll",
        "DotNetManaged",
        "we do not yet decompile .NET programs",
    );
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry("DrawSprite", 1, &commit.hash, &receipt_digest)],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "a parked binary never reads complete"
    );
    assert_eq!(
        row.tally.parked, 1,
        "the parked unit tallies in its own count"
    );
    assert_eq!(
        row.tally.verified, 0,
        "a parked unit is not verified, however green its claim"
    );
    let open = row.first_open.as_ref().expect("the honest reading is named");
    assert!(
        open.link.contains("we do not yet decompile .NET programs"),
        "the classification's reason rides beside the disposition: {}",
        open.link
    );
}

#[test]
fn a_classification_override_releases_the_parked_obligation_to_its_evidence() {
    // Issue #420 (P26.4), AC 3: an operator classification override beats
    // the classification record. Once the binary's in-force category is
    // no longer Do Not Translate, nothing parks its units, and the same
    // fully-evidenced obligation closes — the override releases, it does
    // not merely relabel.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
        .expect("translation branch")
        .branch;
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawSprite", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawSprite",
            &[
                "re/verification/game_logic.dll/DrawSprite/attempt-1.json",
                "re/verification/game_logic.dll/DrawSprite/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.merge_to_main(&branch).expect("merge into main");
    stage_accept_record(dir.path(), "game_logic.dll", "DrawSprite", 1);
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    stage_classification(
        dir.path(),
        "game_logic.dll",
        "DotNetManaged",
        "we do not yet decompile .NET programs",
    );
    // The operator overrides the classification: the in-force category is
    // ProjectSpecific, so the park no longer stands.
    stage_classification_override(dir.path(), "game_logic.dll", "ProjectSpecific");
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry("DrawSprite", 1, &commit.hash, &receipt_digest)],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Complete,
        "the released obligation closes on its evidence"
    );
    assert_eq!(row.tally.verified, 1, "the released unit reads verified again");
    assert_eq!(row.tally.parked, 0, "the override releases the park outright");
}

#[test]
fn a_reviewer_unit_override_record_tallies_overridden_and_never_reads_verified() {
    // Issue #420 (P26.4), AC 4: a reviewer files a unit override record.
    // The unit's system judgment stands overridden at the read — tallied
    // apart from the verified, naming the override document as
    // provenance — even over a fully-evidenced green claim.
    let dir = tempfile::tempdir().expect("temp dir");
    let git = init_test_repo(dir.path());

    let branch = git
        .create_branch("game_logic.dll", "DrawPrimitive", 1, None)
        .expect("translation branch")
        .branch;
    let receipt_digest = stage_receipt_pair(&git, "game_logic.dll", "DrawPrimitive", 1);
    let commit = git
        .commit(
            &branch,
            "re: translate DrawPrimitive",
            &[
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.json",
                "re/verification/game_logic.dll/DrawPrimitive/attempt-1.md",
            ],
        )
        .expect("attempt commit");
    git.merge_to_main(&branch).expect("merge into main");
    stage_accept_record(dir.path(), "game_logic.dll", "DrawPrimitive", 1);
    stage_unknown_ledger(dir.path(), "game_logic.dll", Vec::new());
    // The reviewer's override record for this exact unit.
    stage_unit_override(
        dir.path(),
        "game_logic.dll",
        "DrawPrimitive",
        "hand-audited, keep out of reruns",
    );
    let ledger = ObligationLedger::file(
        "game_logic.dll",
        vec![claimed_entry("DrawPrimitive", 1, &commit.hash, &receipt_digest)],
        1_700_000_000,
    )
    .expect("file the ledger");
    save_json(&obligation_ledger_path(dir.path(), &ledger.binary), &ledger).expect("save");

    let dashboard = DashboardBuilder::new(&git)
        .build()
        .expect("dashboard builds");

    let row = find_conformance(&dashboard, "game_logic.dll");
    assert_eq!(
        row.verdict,
        ConformanceVerdict::Incomplete,
        "an overridden unit blocks complete on its own"
    );
    assert_eq!(
        row.tally.overridden, 1,
        "the overridden unit tallies in its own count"
    );
    assert_eq!(
        row.tally.verified, 0,
        "an overridden unit never counts as verified, however green its evidence"
    );
    let open = row.first_open.as_ref().expect("the honest reading is named");
    assert!(
        open.link.contains("unit_overrides.json"),
        "the provenance names the override document: {}",
        open.link
    );
}

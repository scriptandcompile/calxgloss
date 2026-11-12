//! Issue #424 (P26.8) at the web e2e seam: the one *conformance verdict*
//! and each unit's *obligation entry* reach the review payloads. The
//! queue's per-binary reading — verdict, disposition tallies, closure
//! digest — rides `GET /api/dashboard` whole from the shared derived
//! model, and `GET /api/units/{id}` carries the unit's own entry with
//! the attempt, owner digest, required case kinds, disposition, and
//! receipt citation. A payload with nothing filed for its binary reads
//! *unknown* — never zero, never closed — and no conformance evidence
//! touches per-unit review state: statuses stand, no action record is
//! written, and accept is not blocked on a verdict's say-so.
//!
//! Issue #482 (P56.2) re-pins the rest of the terminal conformance suite's
//! claims at this same seam: a fully-evidenced binary reading *complete*
//! sealed by its own ledger digest, every honest disposition keeping its
//! own tally apart from the verified, a merged unit with no standing
//! Accept reading *un-reviewed* with the broken link named, tampered
//! ledger bytes falling to *unknown* with the digest mismatch named, and
//! an unreadable unknown ledger keeping a green row short of complete.

use super::*;

use calxgloss_git::GitManager;

/// GET `/api/dashboard` and return the parsed body.
async fn dashboard_body(world: &support::ReviewWorld) -> serde_json::Value {
    let (status, body) = world.client().get_json("/api/dashboard").await;
    assert_eq!(status, 200);
    body
}

/// GET `/api/units/{id}` and return the unit object — the client encodes
/// the unit id (which carries slashes) the way the route's path parameter
/// expects.
async fn unit_payload(world: &support::ReviewWorld, unit_id: &str) -> serde_json::Value {
    let (status, body) = world.client().unit_detail(unit_id).await;
    assert_eq!(status, 200, "unit {unit_id} must still render");
    body["unit"].clone()
}

/// File the obligation ledger for `binary`, in the shape the `obligations
/// file` command seals it at `re/obligations/{binary}.json`. Shared with
/// the headless render pins beside it.
pub(super) fn stage_obligation_ledger(
    repo: &std::path::Path,
    binary: &str,
    entries: Vec<calxgloss_types::ObligationEntry>,
) {
    let ledger = calxgloss_types::ObligationLedger::file(binary, entries, 1_700_000_000)
        .expect("the ledger seals");
    calxgloss_types::save_json(
        &calxgloss_types::obligation_ledger_path(repo, &ledger.binary),
        &ledger,
    )
    .expect("file the obligation ledger");
}

#[tokio::test]
async fn the_unit_detail_payload_carries_the_filed_obligation_entry_whole() {
    // AC 2: the unit detail names the attempt the entry speaks for, its
    // owner digest, the required case kinds, the standing disposition,
    // and the receipt citation (issue #424).
    let world = support::ReviewWorld::boot_plain().await;

    stage_obligation_ledger(
        world.repo_path().as_path(),
        "game_logic.dll",
        vec![
            {
                let mut entry = calxgloss_types::ObligationEntry::new(
                    "DrawPrimitive",
                    2,
                    "aaaa1111",
                    calxgloss_types::ObligationDisposition::ClaimedVerified,
                );
                entry.receipt_digest = Some("sha256:cafe".to_string());
                entry
            },
            {
                let mut entry = calxgloss_types::ObligationEntry::new(
                    "DrawPrimitive",
                    1,
                    "bbbb2222",
                    calxgloss_types::ObligationDisposition::ClaimedVerified,
                );
                entry.receipt_digest = Some("sha256:beef".to_string());
                entry
            },
        ],
    );

    // Attempt 2's entry rides the open unit, whole and exactly as filed.
    let unit = unit_payload(&world, "game_logic.dll/DrawPrimitive/v2").await;
    assert_eq!(
        unit["obligation"],
        serde_json::json!({
            "entry": {
                "attempt": 2,
                "owner_commit": "aaaa1111",
                "required_case_kinds": ["positive", "negative", "malformed"],
                "disposition": "claimed_verified",
                "receipt_digest": "sha256:cafe"
            }
        }),
        "the open unit's entry rides with every field the unit detail names"
    );

    // Attempt 1's entry rides the merged unit — each attempt reads its
    // own ledger entry, not the newest one for the function.
    let unit = unit_payload(&world, "game_logic.dll/DrawPrimitive/v1").await;
    assert_eq!(
        unit["obligation"]["entry"]["attempt"],
        serde_json::json!(1),
        "the merged unit reads its own attempt's entry"
    );
    assert_eq!(unit["obligation"]["entry"]["owner_commit"], "bbbb2222");
    assert_eq!(unit["obligation"]["entry"]["receipt_digest"], "sha256:beef");
}

#[tokio::test]
async fn an_older_unit_payload_without_the_obligation_field_reads_unknown_never_zero() {
    // AC 4: the fixture's committed unit documents predate the field.
    // The unit must still render, reading *unknown* — never a clean
    // `[]`-style zero, never a closed obligation (issue #424).
    let world = support::ReviewWorld::boot_plain().await;

    // No ledger filed for the binary at all: the unit's reading is the
    // unknown, serialized whole as a null entry.
    let unit = unit_payload(&world, "game_logic.dll/DrawPrimitive/v2").await;
    assert_eq!(
        unit["obligation"],
        serde_json::json!({ "entry": null }),
        "nothing filed for the binary reads unknown, never zero"
    );
    assert!(
        unit["obligation"].get("disposition").is_none(),
        "the unknown reading never invents a disposition"
    );

    // A ledger filed but naming no entry for this unit is the same
    // honest unknown — a closed reading for a neighbour is not a
    // reading for this unit.
    stage_obligation_ledger(
        world.repo_path().as_path(),
        "game_logic.dll",
        vec![calxgloss_types::ObligationEntry::new(
            "SomeOtherFunction",
            1,
            "cccc3333",
            calxgloss_types::ObligationDisposition::ClaimedVerified,
        )],
    );
    let unit = unit_payload(&world, "game_logic.dll/DrawPrimitive/v2").await;
    assert_eq!(
        unit["obligation"],
        serde_json::json!({ "entry": null }),
        "a ledger with no entry for this unit reads unknown too"
    );
}

#[tokio::test]
async fn the_dashboard_payload_carries_the_per_binary_conformance_verdict_and_tallies_whole() {
    // AC 1: the queue view's per-binary reading arrives whole in the
    // shared model's payload — one derivation, no second computation
    // (issue #424).
    let world = support::ReviewWorld::boot_plain().await;

    // Nothing filed: the only target binary's row reads unknown with
    // its named cause — never a clean verdict, never an absent row.
    let body = dashboard_body(&world).await;
    assert_eq!(
        support::conformance_row(&body, "game_logic.dll"),
        serde_json::json!({
            "binary": "game_logic.dll",
            "verdict": "unknown",
            "causes": ["no_ledger_filed"],
            "closure_digest": null,
            "tally": {
                "verified": 0,
                "skipped": 0,
                "parked": 0,
                "overridden": 0,
                "un_reviewed": 0,
                "no_baseline": 0
            },
            "first_open": null,
            "blocking_unknowns": []
        }),
        "a never-filed ledger renders the unknown verdict with its cause"
    );

    // A filed ledger turns the row into the reading the reports tests
    // derived for it: the verdict stops being unknown, the ledger's own
    // seal rides as the closure digest, and the dispositions stand
    // counted apart from the verified ones.
    stage_obligation_ledger(
        world.repo_path().as_path(),
        "game_logic.dll",
        vec![calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            2,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::NoBaseline,
        )],
    );
    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        row["verdict"], "incomplete",
        "a filed ledger with an obligation that never closed reads incomplete"
    );
    assert!(
        row["closure_digest"].is_string(),
        "the filed ledger's seal rides as the closure digest: {row}"
    );
    assert_eq!(
        row["tally"]["no_baseline"],
        serde_json::json!(1),
        "the disposition tallies count the honest hold-out apart, never as verified"
    );
    assert_eq!(row["tally"]["verified"], serde_json::json!(0));
}

#[tokio::test]
async fn one_build_answers_the_unit_and_the_row_from_the_same_ledger_read() {
    // AC 1's agreement pin without a browser: the unit's entry and the
    // per-binary row ride one `/api/dashboard` payload from one build.
    // A filed green claim whose evidence chain the read refuses shows
    // its filed disposition honestly on the unit while the same build
    // counts nothing verified on the row — the unit reading never
    // launders the row into a pass (issue #424).
    let world = support::ReviewWorld::boot_plain().await;

    {
        let mut entry = calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            2,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::ClaimedVerified,
        );
        // No receipt pair named "sha256:cafe" stands committed, so the
        // close walk breaks on this claim — the row cannot read
        // complete no matter what the filed entry says.
        entry.receipt_digest = Some("sha256:cafe".to_string());
        stage_obligation_ledger(world.repo_path().as_path(), "game_logic.dll", vec![entry]);
    }
    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_ne!(
        row["verdict"], "complete",
        "the broken chain keeps the row short of complete: {row}"
    );
    assert_eq!(
        row["tally"]["verified"],
        serde_json::json!(0),
        "a claim whose chain broke counts nothing verified: {row}"
    );

    // The same payload's unit carries its entry with the filed facts —
    // the attempt, the standing as filed, and the citation as cited.
    let unit = body["dashboard"]["review_queue"]
        .as_array()
        .expect("review_queue is an array")
        .iter()
        .find(|unit| unit["id"] == "game_logic.dll/DrawPrimitive/v2")
        .expect("the open unit rides the payload")
        .clone();
    let entry = unit["obligation"]["entry"].clone();
    assert_eq!(entry["attempt"], serde_json::json!(2));
    assert_eq!(
        entry["disposition"], "claimed_verified",
        "the unit states the disposition as the read seam decides it"
    );
    assert_eq!(
        entry["receipt_digest"], "sha256:cafe",
        "the citation rides as cited"
    );

    // And the row says out loud where it broke — naming this unit, or
    // naming the cause when the citation resolves nowhere at all.
    let names_this_unit = row["first_open"]
        .get("function")
        .and_then(|f| f.as_str())
        .is_some_and(|f| {
            f == "DrawPrimitive" && row["first_open"]["attempt"] == serde_json::json!(2)
        });
    let names_the_cause = row["causes"]
        .as_array()
        .map(|causes| causes.contains(&serde_json::json!("unresolvable_receipt_citation")))
        .unwrap_or(false);
    assert!(
        names_this_unit || names_the_cause,
        "the row names the broken link or the named cause, never silence: {row}"
    );
}

#[tokio::test]
async fn conformance_evidence_triggers_no_per_unit_review_action() {
    // The standing rule this lineage keeps pinning (issue #419 onward,
    // restated in ADR-0060): a conformance verdict is per-binary
    // evidence. It never moves a unit's review status, writes no action
    // record, and blocks no Accept on its own (issue #424, AC 3).
    let world = support::ReviewWorld::boot_plain().await;

    let before = dashboard_body(&world).await;
    let statuses = |body: &serde_json::Value| -> Vec<(String, String)> {
        body["dashboard"]["review_queue"]
            .as_array()
            .expect("review_queue is an array")
            .iter()
            .map(|unit| {
                (
                    unit["id"].as_str().expect("unit id").to_string(),
                    unit["status"].as_str().expect("status").to_string(),
                )
            })
            .collect()
    };

    stage_obligation_ledger(
        world.repo_path().as_path(),
        "game_logic.dll",
        vec![calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            2,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::NoBaseline,
        )],
    );
    let after = dashboard_body(&world).await;

    // The row went from unknown to incomplete — real movement at the
    // per-binary seam, so the statuses pin below is not vacuous.
    assert_eq!(
        support::conformance_row(&after, "game_logic.dll")["verdict"],
        "incomplete"
    );
    assert_eq!(
        support::conformance_row(&before, "game_logic.dll")["verdict"],
        "unknown"
    );
    assert_eq!(
        statuses(&after),
        statuses(&before),
        "an incomplete conformance verdict leaves every unit's review status untouched"
    );
    assert!(
        !world.repo_path().join("re").join("actions").exists(),
        "no review action record is ever written for a conformance verdict"
    );

    // The reading also never touches branch state: the open unit's
    // branch stays unmerged, the same half of the pattern the
    // unknown-disposition pin holds.
    let git = GitManager::open(world.repo_path().as_path()).expect("open git");
    assert!(
        !git.is_branch_merged_into_main("re/game_logic.dll/DrawPrimitivev2")
            .expect("merged check"),
        "a conformance reading never merges a branch"
    );

    // And accept stands on its own: accepting the open unit with the
    // incomplete verdict filed is a reviewer decision, never blocked by
    // the row.
    let unit_id = statuses(&after)
        .into_iter()
        .find(|(_, status)| status == "Queued" || status == "PendingReview")
        .expect("an open unit stands")
        .0;
    let (status, body) = world
        .client()
        .post_lifecycle(&format!(
            "/api/units/{}/accept",
            unit_id.replace('/', "%2F")
        ))
        .await;
    assert_eq!(
        status, 200,
        "accept is not blocked by a filed conformance verdict — \
         unit {unit_id} answered {status}: {body}"
    );
    assert_eq!(body["action"], "accept");
}

// ── Issue #482 (P56.2): the terminal suite's remaining claims at this seam ──

/// Stage a fully-evidenced translation attempt the way the verify gate
/// and the review door file it: the attempt branch carries the translated
/// source and a sealed, committed receipt pair, and `accept_branch`
/// leaves a standing Accept review action and the merge into main.
/// Returns the branch tip an obligation entry must cite as its owner and
/// the receipt digest it must cite. Shared by the complete, un-reviewed,
/// and tampered-bytes pins below, mirroring the single fixture the CLI
/// suite stood its claims on.
fn stage_fully_evidenced_attempt(repo: &std::path::Path, function: &str) -> (String, String) {
    let git = GitManager::open(repo).expect("open the booted world's repository");
    let branch = git
        .create_branch("game_logic.dll", function, 1, None)
        .expect("translation branch")
        .branch;
    let source = format!("src/game_logic.dll_{function}_v1.rs");
    std::fs::write(repo.join(&source), "// translated").expect("write source");

    let mut dimensions = std::collections::BTreeMap::new();
    dimensions.insert(
        "values".to_string(),
        calxgloss_types::DimensionCounts {
            assessed: 2,
            passed: 2,
        },
    );
    let mut receipt = calxgloss_types::VerificationReceipt {
        binary: calxgloss_types::BinaryIdentity::from("game_logic.dll"),
        function: function.to_string(),
        attempt: 1,
        retry_strategy: "initial".to_string(),
        attempt_path: "strategy_prompt".to_string(),
        verifier_command: calxgloss_types::VerifierCommand::CompileAndBaselineTest,
        baseline_suite_digest: "sha256:suite".to_string(),
        covered_case_kinds: calxgloss_types::CaseKind::ALL.iter().copied().collect(),
        dimensions,
        compile_ms: 10,
        test_run_ms: 5,
        total_ms: 15,
        verdict: calxgloss_types::VerificationVerdict::Passed,
        failed_cases: Vec::new(),
        harness_error_reason: None,
        digest: String::new(),
    };
    receipt.digest = receipt.content_digest().expect("digests");
    let json_rel = format!("re/verification/game_logic.dll/{function}/attempt-1.json");
    let md_rel = format!("re/verification/game_logic.dll/{function}/attempt-1.md");
    let json_path = repo.join(&json_rel);
    std::fs::create_dir_all(json_path.parent().expect("receipt dir")).expect("receipt dir");
    std::fs::write(
        &json_path,
        serde_json::to_string(&receipt).expect("serializes"),
    )
    .expect("file receipt JSON");
    std::fs::write(
        json_path.with_extension("md"),
        calxgloss_types::verification_receipt_markdown(&receipt),
    )
    .expect("file receipt twin");

    let commit = git
        .commit(
            &branch,
            &format!("re: translate {function}"),
            &[source.as_str(), json_rel.as_str(), md_rel.as_str()],
        )
        .expect("attempt commit");
    git.accept_branch(&branch).expect("accept branch");
    (commit.hash, receipt.digest)
}

/// File the binary's unknown ledger with no records: the gate proven
/// open-free, the way the CLI suite's fully-evidenced fixture filed it.
fn file_empty_unknown_ledger(repo: &std::path::Path) {
    calxgloss_types::save_json(
        &calxgloss_types::unknown_ledger_path(
            repo,
            &calxgloss_types::BinaryIdentity::from("game_logic.dll"),
        ),
        &calxgloss_types::UnknownLedger {
            binary: calxgloss_types::BinaryIdentity::from("game_logic.dll"),
            filed_at: 1_700_000_000,
            records: Some(Vec::new()),
        },
    )
    .expect("file the open-free ledger");
}

/// File the obligation ledger for one fully-closed green claim.
fn stage_closed_claim(repo: &std::path::Path, function: &str, owner: &str, citation: &str) {
    let mut entry = calxgloss_types::ObligationEntry::new(
        function,
        1,
        owner,
        calxgloss_types::ObligationDisposition::ClaimedVerified,
    );
    entry.receipt_digest = Some(citation.to_string());
    stage_obligation_ledger(repo, "game_logic.dll", vec![entry]);
}

#[tokio::test]
async fn the_dashboard_payload_prints_a_complete_row_sealed_by_its_own_ledger_digest() {
    // The CLI suite's complete line — "complete (1 verified, sealed
    // {digest})" — re-pinned at the payload: the closed evidence chain
    // counts one verified, the filed ledger's own seal rides as the
    // closure digest, and a proven open-free unknown gate lets the row
    // read complete at all.
    let world = support::ReviewWorld::boot_plain().await;
    let (owner, citation) = stage_fully_evidenced_attempt(world.repo_path().as_path(), "Restitch");
    stage_closed_claim(world.repo_path().as_path(), "Restitch", &owner, &citation);
    file_empty_unknown_ledger(world.repo_path().as_path());

    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    let filed = std::fs::read_to_string(calxgloss_types::obligation_ledger_path(
        world.repo_path().as_path(),
        &calxgloss_types::BinaryIdentity::from("game_logic.dll"),
    ))
    .expect("filed ledger text");
    let digest = serde_json::from_str::<serde_json::Value>(&filed).expect("ledger json")["digest"]
        .as_str()
        .expect("digest field")
        .to_string();
    assert_eq!(
        row,
        serde_json::json!({
            "binary": "game_logic.dll",
            "verdict": "complete",
            "causes": [],
            "closure_digest": digest,
            "tally": {
                "verified": 1,
                "skipped": 0,
                "parked": 0,
                "overridden": 0,
                "un_reviewed": 0,
                "no_baseline": 0
            },
            "first_open": null,
            "blocking_unknowns": []
        }),
        "the fully-evidenced binary reads complete whole, sealed by the \
         digest its own filed ledger carries: {row}"
    );
}

#[tokio::test]
async fn the_dashboard_payload_tallies_every_honest_disposition_apart_from_verified() {
    // The CLI suite's tally line — "incomplete (1 verified, 1 skipped,
    // 1 parked, 1 overridden, 1 un-reviewed, 1 no-baseline)" — re-pinned:
    // every honest disposition keeps its own tally slot, never folded
    // into the verified, and the row stays short of complete.
    let world = support::ReviewWorld::boot_plain().await;
    stage_obligation_ledger(
        world.repo_path().as_path(),
        "game_logic.dll",
        [
            ("SkipMe", calxgloss_types::ObligationDisposition::Skipped),
            ("ParkMe", calxgloss_types::ObligationDisposition::Parked),
            (
                "OverrideMe",
                calxgloss_types::ObligationDisposition::Overridden,
            ),
            (
                "ReviewMeNot",
                calxgloss_types::ObligationDisposition::UnReviewed,
            ),
            (
                "NoCover",
                calxgloss_types::ObligationDisposition::NoBaseline,
            ),
        ]
        .into_iter()
        .map(|(function, disposition)| {
            calxgloss_types::ObligationEntry::new(
                function,
                1,
                "0000000000000000000000000000000000000000",
                disposition,
            )
        })
        .collect(),
    );

    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        row["verdict"], "incomplete",
        "honest dispositions hold the binary short of complete: {row}"
    );
    assert_eq!(
        row["tally"],
        serde_json::json!({
            "verified": 0,
            "skipped": 1,
            "parked": 1,
            "overridden": 1,
            "un_reviewed": 1,
            "no_baseline": 1
        }),
        "each honest disposition tallies apart from the verified, never \
         as verified: {row}"
    );
}

#[tokio::test]
async fn a_merged_unit_with_no_accept_record_reads_un_reviewed_naming_the_link() {
    // The CLI suite's join-derived line — "incomplete (0 verified,
    // 1 un-reviewed)" beside "no Accept review action stands" —
    // re-pinned: review is the only door into verified. A merged branch
    // with every other leg standing, minus the Accept record, counts
    // un-reviewed in its own slot and names the broken link as first
    // open.
    let world = support::ReviewWorld::boot_plain().await;
    let (owner, citation) = stage_fully_evidenced_attempt(world.repo_path().as_path(), "Restitch");
    std::fs::remove_file(
        world
            .repo_path()
            .join("re/accepts/game_logic.dll/Restitch/v1.json"),
    )
    .expect("withdraw the Accept record");
    stage_closed_claim(world.repo_path().as_path(), "Restitch", &owner, &citation);
    file_empty_unknown_ledger(world.repo_path().as_path());

    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        row["verdict"], "incomplete",
        "a merged unit nobody reviewed never reads complete: {row}"
    );
    assert_eq!(
        row["tally"],
        serde_json::json!({
            "verified": 0,
            "skipped": 0,
            "parked": 0,
            "overridden": 0,
            "un_reviewed": 1,
            "no_baseline": 0
        }),
        "the join counts the never-reviewed attempt in its own slot, \
         never verified: {row}"
    );
    assert_eq!(
        row["first_open"],
        serde_json::json!({
            "function": "Restitch",
            "attempt": 1,
            "link": "no Accept review action stands for this attempt",
        }),
        "the broken review link names itself beside the counts: {row}"
    );
}

#[tokio::test]
async fn tampered_obligation_ledger_bytes_fall_to_unknown_naming_the_digest_mismatch() {
    // The CLI suite's tampered-bytes edge, re-pinned at the payload: an
    // entry edited under an unchanged seal is an input error at the read.
    // The row falls to *unknown* with the digest mismatch named, and the
    // broken document's seal rides nothing — never a stale complete.
    // (Unreadable bytes already stand pinned in `honest_degradation.rs`;
    // this is the quiet tamper that still parses.)
    let world = support::ReviewWorld::boot_plain().await;
    let (owner, citation) = stage_fully_evidenced_attempt(world.repo_path().as_path(), "Restitch");
    stage_closed_claim(world.repo_path().as_path(), "Restitch", &owner, &citation);
    file_empty_unknown_ledger(world.repo_path().as_path());

    let path = calxgloss_types::obligation_ledger_path(
        world.repo_path().as_path(),
        &calxgloss_types::BinaryIdentity::from("game_logic.dll"),
    );
    let filed = std::fs::read_to_string(&path).expect("filed ledger text");
    let mut doc: serde_json::Value = serde_json::from_str(&filed).expect("ledger json");
    let owner_field = doc["entries"][0]["owner_commit"]
        .as_str()
        .expect("the entry carries its owner")
        .to_string();
    let forged = if owner_field.starts_with('0') {
        '1'
    } else {
        '0'
    };
    doc["entries"][0]["owner_commit"] = serde_json::json!(format!("{forged}{}", &owner_field[1..]));
    std::fs::write(&path, doc.to_string()).expect("edit a sealed entry under the unchanged seal");

    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        row["verdict"], "unknown",
        "tampered bytes fall the verdict to unknown, never the sealed claim: {row}"
    );
    assert_eq!(
        row["causes"],
        serde_json::json!(["digest_mismatch"]),
        "the read names the mismatch as the cause: {row}"
    );
    assert!(
        row["closure_digest"].is_null(),
        "the seal over broken bytes rides nothing: {row}"
    );
    assert_eq!(
        row["tally"]["verified"],
        serde_json::json!(0),
        "a tampered roster verifies nothing: {row}"
    );
}

#[tokio::test]
async fn an_unreadable_unknown_ledger_keeps_a_green_row_short_of_complete_naming_the_fault() {
    // The payload names the fault the CLI read printed to stderr: an
    // unreadable *unknown* ledger proves no gate. A row that reached
    // *complete* on the green chain falls back short of complete once
    // the ledger's bytes stop parsing, and it says why — the ledger
    // never reported its open set. The ledger row itself falls to the
    // unknown reading, pinned beside it in `unknown_ledger_web.rs`.
    let world = support::ReviewWorld::boot_plain().await;
    let (owner, citation) = stage_fully_evidenced_attempt(world.repo_path().as_path(), "Restitch");
    stage_closed_claim(world.repo_path().as_path(), "Restitch", &owner, &citation);
    file_empty_unknown_ledger(world.repo_path().as_path());

    // The green chain reaches complete first — the corrupt bytes are
    // what move it, so the fall below is proven real.
    let body = dashboard_body(&world).await;
    assert_eq!(
        support::conformance_row(&body, "game_logic.dll")["verdict"],
        "complete"
    );

    support::file_unreadable_record_bytes(&calxgloss_types::unknown_ledger_path(
        world.repo_path().as_path(),
        &calxgloss_types::BinaryIdentity::from("game_logic.dll"),
    ));
    let body = dashboard_body(&world).await;
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        row["verdict"], "incomplete",
        "an unproven gate never reads as a clean run: {row}"
    );
    assert!(
        row["blocking_unknowns"]
            .as_array()
            .expect("blocking_unknowns is an array")
            .iter()
            .any(|reason| {
                reason
                    .as_str()
                    .is_some_and(|reason| reason.contains("never reported its open set"))
            }),
        "the row names the unreadable ledger as the fault holding it shut: {row}"
    );
    let ledger_row = body["dashboard"]["unknown_ledgers"]
        .as_array()
        .expect("unknown_ledgers is an array")
        .iter()
        .find(|row| row["binary"] == "game_logic.dll")
        .expect("the unknown-ledger row rides the model")
        .clone();
    assert_eq!(
        ledger_row["unknowns"]["open"],
        serde_json::Value::Null,
        "the unreadable ledger's own reading falls to unknown: {ledger_row}"
    );
}

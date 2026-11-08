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

use super::*;

/// GET `/api/dashboard` and return the parsed body.
async fn dashboard_body(port: u16) -> serde_json::Value {
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", port))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("dashboard body is JSON")
}

/// GET `/api/units/{id}` and return the unit object, unit ids encoded
/// the way the web UI's own client encodes them (they carry slashes).
async fn unit_payload(port: u16, unit_id: &str) -> serde_json::Value {
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}",
        port,
        unit_id.replace('/', "%2F")
    ))
    .await
    .expect("unit request succeeds");
    assert_eq!(resp.status(), 200, "unit {unit_id} must still render");
    resp.json::<serde_json::Value>()
        .await
        .expect("unit body is JSON")["unit"]
        .clone()
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

/// The conformance row for `binary` in the dashboard payload.
fn conformance_row(body: &serde_json::Value, binary: &str) -> serde_json::Value {
    body["dashboard"]["conformance"]
        .as_array()
        .expect("conformance is an array")
        .iter()
        .find(|row| row["binary"] == binary)
        .cloned()
        .expect("the conformance row for {binary} rides the model")
}

#[tokio::test]
async fn the_unit_detail_payload_carries_the_filed_obligation_entry_whole() {
    // AC 2: the unit detail names the attempt the entry speaks for, its
    // owner digest, the required case kinds, the standing disposition,
    // and the receipt citation (issue #424).
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    stage_obligation_ledger(
        fixture.repo_path().as_path(),
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
    let unit = unit_payload(fixture.port(), "game_logic.dll/DrawPrimitive/v2").await;
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
    let unit = unit_payload(fixture.port(), "game_logic.dll/DrawPrimitive/v1").await;
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // No ledger filed for the binary at all: the unit's reading is the
    // unknown, serialized whole as a null entry.
    let unit = unit_payload(fixture.port(), "game_logic.dll/DrawPrimitive/v2").await;
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
        fixture.repo_path().as_path(),
        "game_logic.dll",
        vec![calxgloss_types::ObligationEntry::new(
            "SomeOtherFunction",
            1,
            "cccc3333",
            calxgloss_types::ObligationDisposition::ClaimedVerified,
        )],
    );
    let unit = unit_payload(fixture.port(), "game_logic.dll/DrawPrimitive/v2").await;
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Nothing filed: the only target binary's row reads unknown with
    // its named cause — never a clean verdict, never an absent row.
    let body = dashboard_body(fixture.port()).await;
    assert_eq!(
        conformance_row(&body, "game_logic.dll"),
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
        fixture.repo_path().as_path(),
        "game_logic.dll",
        vec![calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            2,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::NoBaseline,
        )],
    );
    let body = dashboard_body(fixture.port()).await;
    let row = conformance_row(&body, "game_logic.dll");
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

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
        stage_obligation_ledger(fixture.repo_path().as_path(), "game_logic.dll", vec![entry]);
    }
    let body = dashboard_body(fixture.port()).await;
    let row = conformance_row(&body, "game_logic.dll");
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let before = dashboard_body(fixture.port()).await;
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
        fixture.repo_path().as_path(),
        "game_logic.dll",
        vec![calxgloss_types::ObligationEntry::new(
            "DrawPrimitive",
            2,
            "aaaa1111",
            calxgloss_types::ObligationDisposition::NoBaseline,
        )],
    );
    let after = dashboard_body(fixture.port()).await;

    // The row went from unknown to incomplete — real movement at the
    // per-binary seam, so the statuses pin below is not vacuous.
    assert_eq!(
        conformance_row(&after, "game_logic.dll")["verdict"],
        "incomplete"
    );
    assert_eq!(
        conformance_row(&before, "game_logic.dll")["verdict"],
        "unknown"
    );
    assert_eq!(
        statuses(&after),
        statuses(&before),
        "an incomplete conformance verdict leaves every unit's review status untouched"
    );
    assert!(
        !fixture.repo_path().join("re").join("actions").exists(),
        "no review action record is ever written for a conformance verdict"
    );

    // The reading also never touches branch state: the open unit's
    // branch stays unmerged, the same half of the pattern the
    // unknown-disposition pin holds.
    let git = GitManager::open(fixture.repo_path().as_path()).expect("open git");
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
    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/units/{}/accept",
            fixture.port(),
            unit_id.replace('/', "%2F")
        ))
        .send()
        .await
        .expect("accept request succeeds");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("accept body is JSON");
    assert_eq!(
        status, 200,
        "accept is not blocked by a filed conformance verdict — \
         unit {unit_id} answered {status}: {body}"
    );
    assert_eq!(body["action"], "accept");
}

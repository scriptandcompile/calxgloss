//! Issue #482 (P56.2) at the web e2e seam: the per-binary *unknown audit
//! ledger* the terminal dashboard pinned now rides `GET /api/dashboard`
//! whole — every target binary the model knows, its filed ledger joined
//! to the reviewer's resolutions. The open records ride named by severity
//! with their question and required evidence; the settled and dismissed
//! counts stand beside the open ones, never folded into them and never
//! riding the open set; a never-filed or silent (`records` key absent)
//! ledger reads *unknown* — never zero, never "none open" — and a filed,
//! explicitly empty ledger is the only honest clean reading. Unreadable
//! ledger bytes fall to *unknown* at the payload while the read seam
//! names the fault; the conformance row's fail-closed gate, pinned in
//! `conformance_web.rs`, is where the payload says that fault out loud.

use super::*;

use calxgloss_types::{
    BinaryIdentity, UnknownKind, UnknownLedger, UnknownOrigin, UnknownRecord, UnknownResolutions,
    UnknownSeverity, save_json, unknown_ledger_path, unknown_resolutions_path,
};

/// GET `/api/dashboard` and return the parsed body.
async fn dashboard_body(world: &support::ReviewWorld) -> serde_json::Value {
    let (status, body) = world.client().get_json("/api/dashboard").await;
    assert_eq!(status, 200);
    body
}

/// The unknown-ledger row for `binary` in a `/api/dashboard` payload.
fn ledger_row(body: &serde_json::Value, binary: &str) -> serde_json::Value {
    body["dashboard"]["unknown_ledgers"]
        .as_array()
        .expect("unknown_ledgers is an array")
        .iter()
        .find(|row| row["binary"] == binary)
        .unwrap_or_else(|| panic!("the unknown-ledger row for {binary} rides the model"))
        .clone()
}

/// One filed ledger record, derived the way the pipeline's producers
/// derive them — the same fixture shape the CLI audit-ledger suite filed.
fn record(id: &str, severity: UnknownSeverity, question: &str) -> UnknownRecord {
    UnknownRecord::derive(
        "game_logic.dll",
        Some("DrawPrimitive".to_string()),
        UnknownKind::CoverageFacet,
        severity,
        question,
        "call-site survey",
        UnknownOrigin::CaseSet {
            case_set: format!("cs-{id}"),
        },
        1_700_000_000,
    )
}

/// File the binary's unknown ledger at `re/unknowns/{binary}.json`.
/// `None` records is the silent document: filed, but its `records` key
/// absent — an absent key never means the list is empty (ADR-0053).
fn file_unknown_ledger(repo: &std::path::Path, records: Option<Vec<UnknownRecord>>) {
    save_json(
        &unknown_ledger_path(repo, &BinaryIdentity::from("game_logic.dll")),
        &UnknownLedger {
            binary: BinaryIdentity::from("game_logic.dll"),
            filed_at: 1_700_000_000,
            records,
        },
    )
    .expect("file ledger");
}

#[tokio::test]
async fn the_dashboard_payload_carries_the_ledger_with_settles_counted_apart() {
    // The CLI suite's central pin, re-pinned at the payload: the open
    // record rides named by severity with its question and required
    // evidence, the reviewer's settled rides count beside open — never
    // folded — and a settled record never rides the open set or reads as
    // established.
    let world = support::ReviewWorld::boot_plain().await;
    let open = record(
        "u-open",
        UnknownSeverity::Blocking,
        "Which side owns the buffer?",
    );
    let settled = record(
        "u-settled",
        UnknownSeverity::Material,
        "Answered by review.",
    );
    let dismissed = record(
        "u-dismissed",
        UnknownSeverity::Notable,
        "Ruled out of scope.",
    );
    file_unknown_ledger(
        world.repo_path().as_path(),
        Some(vec![open.clone(), settled.clone(), dismissed.clone()]),
    );
    let mut resolutions = UnknownResolutions::default();
    resolutions
        .resolve(
            &settled,
            "the answer landed in the type database",
            1,
            1_700_000_500,
        )
        .expect("resolve");
    resolutions
        .dismiss(
            &dismissed,
            "the reviewer ruled it out of scope",
            1,
            1_700_000_500,
        )
        .expect("dismiss");
    save_json(
        &unknown_resolutions_path(world.repo_path().as_path()),
        &resolutions,
    )
    .expect("file resolutions");

    let body = dashboard_body(&world).await;
    let row = ledger_row(&body, "game_logic.dll");
    assert_eq!(
        row["unknowns"],
        serde_json::json!({
            "open": [{
                "id": open.id,
                "kind": "coverage_facet",
                "severity": "blocking",
                "question": "Which side owns the buffer?",
                "required_evidence": "call-site survey",
                "revision": 1,
            }],
            "open_by_severity": { "blocking": 1 },
            "resolved": 1,
            "dismissed": 1,
        }),
        "the open record rides named by severity, and the settled counts \
         stand apart from it, whole: {row}"
    );
    let rendered = row.to_string();
    assert!(
        !rendered.contains("Answered by review."),
        "a resolved record counts but never rides the open set: {rendered}"
    );
    assert!(
        !rendered.contains("Ruled out of scope."),
        "a dismissed record counts but never rides the open set: {rendered}"
    );
}

#[tokio::test]
async fn a_never_filed_or_silent_ledger_reads_unknown_never_a_clean_run() {
    // The CLI suite's honesty edge, re-pinned at the payload: a binary
    // whose ledger was never filed rides with an *unknown* open state —
    // never zero, never an empty list — and a filed document whose
    // `records` key is absent reads the same way (ADR-0053).
    let world = support::ReviewWorld::boot_plain().await;

    let body = dashboard_body(&world).await;
    assert_eq!(
        ledger_row(&body, "game_logic.dll")["unknowns"],
        serde_json::json!({
            "open": null,
            "open_by_severity": {},
            "resolved": 0,
            "dismissed": 0,
        }),
        "a never-filed ledger reads unknown, never a clean run"
    );

    file_unknown_ledger(world.repo_path().as_path(), None);
    let body = dashboard_body(&world).await;
    assert_eq!(
        ledger_row(&body, "game_logic.dll")["unknowns"]["open"],
        serde_json::Value::Null,
        "a silent document whose records key is absent is unknown too, \
         never a none-open reading"
    );
}

#[tokio::test]
async fn a_filed_empty_ledger_reads_the_honest_empty_open_set() {
    // The only honest clean line: a filed ledger that explicitly names
    // no records reads as an empty open set — the empty list, standing
    // apart from the unknown's null, is what proves it was read.
    let world = support::ReviewWorld::boot_plain().await;
    file_unknown_ledger(world.repo_path().as_path(), Some(Vec::new()));

    let body = dashboard_body(&world).await;
    let unknowns = ledger_row(&body, "game_logic.dll")["unknowns"].clone();
    assert_eq!(
        unknowns["open"],
        serde_json::json!([]),
        "the filed, explicitly empty ledger reads as the empty open set: {unknowns}"
    );
    assert_eq!(unknowns["resolved"], serde_json::json!(0));
    assert_eq!(unknowns["dismissed"], serde_json::json!(0));
}

#[tokio::test]
async fn unreadable_unknown_ledger_bytes_fall_to_unknown_never_a_clean_run() {
    // The payload half of the tampered-ledger edge: bytes that parse as
    // no ledger shape fall the reading to *unknown* — never the clean
    // empty set, never the bytes' last good reading. The fault itself is
    // named at the read seam (`read_unknown_ledger`'s corrupt fault
    // names the unreadable path, pinned in the shared types tests), and
    // the payload says that fault out loud through the conformance
    // gate — pinned in `conformance_web.rs` beside the row.
    let world = support::ReviewWorld::boot_plain().await;
    file_unknown_ledger(
        world.repo_path().as_path(),
        Some(vec![record(
            "u-open",
            UnknownSeverity::Blocking,
            "Which side owns the buffer?",
        )]),
    );
    support::file_unreadable_record_bytes(&unknown_ledger_path(
        world.repo_path().as_path(),
        &BinaryIdentity::from("game_logic.dll"),
    ));

    let body = dashboard_body(&world).await;
    let row = ledger_row(&body, "game_logic.dll");
    assert_eq!(
        row["unknowns"]["open"],
        serde_json::Value::Null,
        "unreadable ledger bytes fall the open state to unknown, never a \
         clean reading: {row}"
    );
    assert_eq!(
        row["unknowns"]["resolved"],
        serde_json::json!(0),
        "an unreadable ledger settles nothing it cannot read: {row}"
    );
}

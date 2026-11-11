//! Review surfaces must never fabricate a clean reading. ADR-0060 and
//! ADR-0061 set that rule for every surface that renders a filed record.
//! This module pins each rule with one short e2e test (issue #479). Each
//! test boots one world through the adapter, files its fixture through
//! the shared record writers, and asserts one reading of the served
//! payload: a missing artifact reads as no artifact, a corrupt record
//! reports as unreadable with its cause named, an unmeasured value
//! renders blank, an obligation with no backing record reads unknown, and
//! an unreported evidence count reads unknown rather than zero.
//!
//! The missing-artifact pins cover the per-function analysis artifact
//! (`re/analysis/{binary}/{function}.json`) at four of the surfaces that
//! read it: the unit detail's analysis sections, the decomp endpoint, the
//! tier rationale, and the PAL status tracker. The fifth such surface,
//! the dashboard's PAL-readiness summary, keeps its own honest-absence
//! pin beside the other readiness pins in `pipeline_progress_and_llm_log.rs`
//! (`test_pipeline_pal_binary_without_categories_reports_no_summary`).

use super::*;

// ── A missing artifact reads as no artifact (AC 1) ─────────────────────

/// The unit detail's analysis sections — the API-mappings panel's feed and
/// the call-graph context — read empty when the function owns no analysis
/// artifact. The surface never invents a mapping (ADR-0060).
#[tokio::test]
async fn a_missing_artifact_reads_as_no_api_mappings_at_the_unit_detail() {
    let world = support::ReviewWorld::boot_plain().await;

    let (status, body) = world
        .client()
        .unit_detail("game_logic.dll/DrawPrimitive/v2")
        .await;
    assert_eq!(status, 200, "a unit with no artifact still renders");
    assert_eq!(
        body["unit"]["analysis"],
        serde_json::json!({
            "api_mappings": [],
            "call_graph": { "callers": [], "callees": [] },
        }),
        "no filed artifact is no API mapping and no caller — never a clean reading"
    );
}

/// The decomp panel's endpoint answers with its own not-available payload
/// and names the function when no artifact stands for it. No context
/// object arrives to be rendered as empty output (ADR-0060).
#[tokio::test]
async fn a_missing_artifact_reads_as_no_decompiler_context_at_the_decomp_endpoint() {
    let world = support::ReviewWorld::boot_plain().await;

    let (status, body) = world
        .client()
        .unit_decomp("game_logic.dll/DrawPrimitive/v2")
        .await;
    assert_eq!(status, 200);
    assert!(
        body.get("context").is_none(),
        "no artifact, no decompiler context: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("DrawPrimitive")),
        "the answer names the function it has no context for: {body}"
    );
}

/// The tier section recomputes its rationale from the analysis artifact.
/// With none filed the section still renders, and its rationale is null
/// — never a complexity or a call count the artifact never recorded
/// (ADR-0060).
#[tokio::test]
async fn a_missing_artifact_reads_as_no_tier_rationale_at_the_process_section() {
    let world = support::ReviewWorld::boot_plain().await;

    let (status, body) = world
        .client()
        .unit_detail("game_logic.dll/DrawPrimitive/v2")
        .await;
    assert_eq!(status, 200);
    let tier = &body["unit"]["process"]["tier"];
    assert!(tier.is_object(), "the tier section still renders: {body}");
    assert_eq!(
        tier["rationale"],
        serde_json::Value::Null,
        "a unit with no artifact has no recomputed rationale, never a zeroed one"
    );
}

/// The PAL status tracker reads its API categories off the binary's
/// readable function artifacts. With none filed it answers the classified
/// binary with an empty trait roster rather than inventing one (ADR-0060).
#[tokio::test]
async fn a_missing_artifact_reads_as_no_pal_traits_at_the_pal_status_surface() {
    let fixture = support::TestFixture::new();
    support::write_binaries_list_fixtures(&fixture);
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let (status, body) = world
        .client()
        .get_json("/api/binaries/game_logic.dll/pal-status")
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({ "binary": "game_logic.dll", "traits": [] }),
        "no readable artifact is no recorded category and no needed trait"
    );
}

// ── A corrupt record reports as unreadable, cause named (AC 2) ─────────

/// A corrupt classification record is not an unclassified binary. The
/// binary detail refuses the name with an error payload that names it,
/// never rendering the empty shell of an honest reading (issue #457's
/// corrupt-never-missing rule at the web seam).
#[tokio::test]
async fn a_corrupt_classification_record_is_refused_by_name_never_rendered_empty() {
    let fixture = support::TestFixture::new();
    support::write_binaries_list_fixtures(&fixture);
    let world = support::ReviewWorld::boot_plain_on(&fixture).await;

    let (status, body) = world.client().get_json("/api/binaries/broken.dll").await;
    assert_eq!(status, 404, "unreadable bytes are refused, not served");
    assert_eq!(body["error"].as_bool(), Some(true), "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("broken.dll")),
        "the refusal names the binary whose record it could not read: {body}"
    );
}

/// A corrupt obligation ledger never reads as a clean run. The queue's
/// conformance row stays present and its verdict stays *unknown*, and the
/// row names its cause (`digest_mismatch`) instead of an empty roster
/// (ADR-0060's unreadable-is-unknown rule with the cause spelled out).
#[tokio::test]
async fn a_corrupt_obligation_ledger_reports_unknown_with_its_named_cause() {
    let world = support::ReviewWorld::boot_plain().await;
    support::file_unreadable_record_bytes(&calxgloss_types::obligation_ledger_path(
        world.repo_path().as_path(),
        &calxgloss_types::BinaryIdentity::new("game_logic.dll"),
    ));

    let (status, body) = world.client().get_json("/api/dashboard").await;
    assert_eq!(status, 200);
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        (row["verdict"].as_str(), row["causes"].as_array().cloned()),
        (
            Some("unknown"),
            Some(vec![serde_json::json!("digest_mismatch")]),
        ),
        "unreadable bytes report unknown with the cause named, never clean: {row}"
    );
}

// ── An unmeasured value renders blank, never zero (AC 3) ───────────────

/// Token-log entries written before duration tracking carry no duration
/// field. They still count as attempts, and `measured_attempts` honestly
/// reports zero of them measured. The percentiles over an all-unmeasured
/// set render null, so the card shows a blank — never a fabricated
/// zero-second P50 (ADR-0053's unreadable-is-unknown rule on measured
/// history).
#[tokio::test]
async fn an_unmeasured_attempt_duration_renders_blank_percentiles_never_zero() {
    let world = support::ReviewWorld::boot_plain().await;
    support::write_token_usage_fixture(
        world.repo_path().as_path(),
        &[
            support::token_usage_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "initial",
                4096,
                true,
                "stub",
                1_790_812_800,
            ),
            support::token_usage_entry(
                "game_logic.dll",
                "UpdateScene",
                1,
                "initial",
                2048,
                true,
                "stub",
                1_790_812_900,
            ),
        ],
    );

    let (status, body) = world.client().get_json("/api/llm-metrics/summary").await;
    assert_eq!(status, 200);
    assert_eq!(
        body["total_attempts"],
        serde_json::json!(2),
        "the attempts still count"
    );
    assert_eq!(
        body["measured_attempts"],
        serde_json::json!(0),
        "none of them was measured"
    );
    for key in ["p50_secs", "p95_secs", "p99_secs"] {
        assert!(
            body[key].is_null(),
            "unmeasured history leaves {key} blank, never 0: {body}"
        );
    }
}

// ── An obligation with no backing record reads honestly unknown (AC 4) ──

/// No obligation ledger was ever filed for the fixture binary. The
/// queue's conformance row reads *unknown* with its cause named
/// (`no_ledger_filed`) — the absent record never renders as a clean,
/// obligation-free run (ADR-0060: an absent field reads as unknown,
/// never zero).
#[tokio::test]
async fn an_obligation_with_no_backing_record_reads_unknown_never_clean() {
    let world = support::ReviewWorld::boot_plain().await;

    let (status, body) = world.client().get_json("/api/dashboard").await;
    assert_eq!(status, 200);
    let row = support::conformance_row(&body, "game_logic.dll");
    assert_eq!(
        (row["verdict"].as_str(), row["causes"].as_array().cloned()),
        (
            Some("unknown"),
            Some(vec![serde_json::json!("no_ledger_filed")]),
        ),
        "nothing filed is unknown with a named cause, never a clean roster: {row}"
    );
}

// ── An unreported evidence count reads unknown, not zero (AC 5) ────────

/// A completed evidence scan whose engine reported no count arrives on
/// the live view with its findings field absent — never `0`. A second
/// scan that did report a count rides it whole, so the blank is proven
/// to be the unknown reading and not a lost number (ADR-0061's
/// unreported-count rule, pinned at the live-view endpoint the browser
/// reads).
#[tokio::test]
async fn an_unreported_evidence_count_reads_unknown_on_the_live_view_never_zero() {
    let fixture = support::TestFixture::new();
    let world = support::ReviewWorld::boot_ws_on(&fixture).await;

    let scan_events = [
        calxgloss_types::ProgressEvent::EvidenceScanStarted {
            binary: "game_logic.dll".into(),
            scan: "sync".into(),
        },
        calxgloss_types::ProgressEvent::EvidenceScanCompleted {
            binary: "game_logic.dll".into(),
            scan: "sync".into(),
            elapsed_secs: 3.0,
            findings: None,
            error: None,
        },
        calxgloss_types::ProgressEvent::EvidenceScanStarted {
            binary: "game_logic.dll".into(),
            scan: "control-flow".into(),
        },
        calxgloss_types::ProgressEvent::EvidenceScanCompleted {
            binary: "game_logic.dll".into(),
            scan: "control-flow".into(),
            elapsed_secs: 2.5,
            findings: Some(9),
            error: None,
        },
    ];
    let last = scan_events
        .last()
        .cloned()
        .expect("the pass ends with a completed scan");
    for event in scan_events {
        world.emitter().emit(event);
    }
    world
        .wait_until_enhanced_progress_applied(&last, |view| {
            view["scans"].as_array().is_some_and(|scans| {
                scans
                    .iter()
                    .any(|s| s["scan"] == "sync" && s["finished"] == true)
                    && scans
                        .iter()
                        .any(|s| s["scan"] == "control-flow" && s["finished"] == true)
            })
        })
        .await;

    let (status, view) = world.client().get_json("/api/progress/enhanced").await;
    assert_eq!(status, 200);
    let scans = view["scans"].as_array().expect("scans is an array");
    let row = |name: &str| {
        scans
            .iter()
            .find(|s| s["scan"] == name)
            .expect("the finished scan row rides the live view")
            .clone()
    };
    let uncounted = row("sync");
    assert!(
        uncounted.get("findings").is_none(),
        "an unreported count is absent — the view renders `findings: unknown` — \
         never a fabricated zero: {uncounted}"
    );
    let counted = row("control-flow");
    assert_eq!(
        counted["findings"],
        serde_json::json!(9),
        "a reported count still rides the row whole: {counted}"
    );
}

//! Issue #409 (P24.8) at the web e2e seam: the per-binary *scenario
//! status* on the review dashboard. The filed scenario documents —
//! contract set, capture, verdict — reach `/api/dashboard` through
//! `ReviewDashboard.scenario_statuses`, every state renders from the
//! documents that stand, and every missing record renders as its honest
//! negative: no contract renders not-declared, no capture renders
//! not-captured, no verdict renders unassessed — an unassessed dimension
//! never renders as a pass. A failing verdict names its dimensions and
//! triggers no per-unit review action: no unit silently goes back, and
//! accept is not blocked on its own. Issue #483 (P56.3) adds browser
//! pins on the queue view's scenario-status section: the section
//! renders one group per binary straight from the payload rows, and a
//! payload with no rows shows its honest negative, never empty success.

use super::*;

/// GET `/api/dashboard` and return the parsed body.
async fn dashboard_body(world: &support::ReviewWorld) -> serde_json::Value {
    let (status, body) = world.client().get_json("/api/dashboard").await;
    assert_eq!(status, 200);
    body
}

/// One scenario's contract document body, as the scenario lane files it.
fn contract_document(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "working_dir": ".",
        "cols": 80,
        "rows": 24,
        "idle_timeout_ms": 5000,
        "max_run_ms": 15000,
        "finalization_grace_ms": 1000,
        "max_output_bytes": 65536,
        "normalization": { "version": "norm-v1" }
    })
}

/// File a one-scenario contract document for `binary` — enough for the
/// model to name a second binary's scenario section.
fn file_contract(world: &support::ReviewWorld, binary: &str, scenario: &str) {
    std::fs::write(
        world
            .repo_path()
            .join("re")
            .join("scenarios")
            .join(format!("{binary}.json")),
        serde_json::json!({
            "binary": binary,
            "filed_at": 1,
            "scenarios": { scenario: contract_document(scenario) }
        })
        .to_string(),
    )
    .expect("file contract document");
}

/// File the scenario documents the dashboard reads: a contract set for
/// `eqgame.exe` declaring `boot` and `print-config`, a capture for
/// `boot`, and a failing verdict for `boot` (exit assessed fail) beside a
/// passing verdict for `orphan` — a scenario `orphan` has never been
/// declared for and was captured without a standing contract.
fn file_scenario_records(repo: &std::path::Path) {
    let scenarios = repo.join("re").join("scenarios");
    std::fs::create_dir_all(scenarios.join("captures")).expect("captures dir");
    std::fs::create_dir_all(scenarios.join("verdicts")).expect("verdicts dir");

    std::fs::write(
        scenarios.join("eqgame.exe.json"),
        serde_json::json!({
            "binary": "eqgame.exe",
            "filed_at": 1,
            "scenarios": {
                "boot": contract_document("boot"),
                "print-config": contract_document("print-config")
            }
        })
        .to_string(),
    )
    .expect("file contract document");

    std::fs::write(
        scenarios.join("captures").join("eqgame.exe-boot.json"),
        serde_json::json!({"scenario": "boot", "filed_at": 1}).to_string(),
    )
    .expect("file boot capture");
    std::fs::write(
        scenarios.join("captures").join("eqgame.exe-orphan.json"),
        serde_json::json!({"scenario": "orphan", "filed_at": 1}).to_string(),
    )
    .expect("file orphan capture");

    let verdict = |scenario: &str, verdict: serde_json::Value| {
        serde_json::json!({
            "binary": "eqgame.exe",
            "scenario": scenario,
            "filed_at": 1,
            "normalization_version": "norm-v1",
            "left_capture_sha256": "sha256:left-bytes",
            "right_capture_sha256": "sha256:right-bytes",
            "verdict": verdict,
            "divergences": [],
            "residual_unknowns": [],
            "claims_complete_equivalence": false,
            "digest": "sha256:digest"
        })
    };
    std::fs::write(
        scenarios.join("verdicts").join("eqgame.exe-boot.json"),
        verdict("boot", serde_json::json!({"exit": "assessed_fail"})).to_string(),
    )
    .expect("file boot verdict");
    std::fs::write(
        scenarios.join("verdicts").join("eqgame.exe-orphan.json"),
        verdict(
            "orphan",
            serde_json::json!({
                "terminal": "assessed_pass",
                "interaction": "assessed_pass",
                "exit": "assessed_pass",
                "filesystem": "assessed_pass",
                "process": "assessed_pass"
            }),
        )
        .to_string(),
    )
    .expect("file orphan verdict");
}

/// The `eqgame.exe` entry of the payload's `scenario_statuses`.
fn eqgame_entry(body: &serde_json::Value) -> serde_json::Value {
    body["dashboard"]["scenario_statuses"]
        .as_array()
        .expect("scenario_statuses is an array")
        .iter()
        .find(|entry| entry["binary"] == "eqgame.exe")
        .cloned()
        .expect("the filed documents name eqgame.exe")
}

#[tokio::test]
async fn scenario_status_renders_every_state_from_the_filed_documents() {
    let world = support::ReviewWorld::boot_plain().await;

    // Nothing filed: the surface names nothing — no binary with a unit
    // branch gets a fabricated checklist row.
    let body = dashboard_body(&world).await;
    assert_eq!(
        body["dashboard"]["scenario_statuses"],
        serde_json::json!([]),
        "no filed scenario documents render no rows at all"
    );

    file_scenario_records(world.repo_path().as_path());
    let body = dashboard_body(&world).await;
    let eqgame = eqgame_entry(&body);

    // The exact payload for all five states, pinned whole: `boot` is
    // declared, captured, assessed fail naming its dimension; `orphan`
    // is not declared (its capture and passing verdict never launder a
    // contract), captured, assessed pass on all five dimensions;
    // `print-config` is declared, not captured (no capture filed, never
    // an empty success), unassessed (no verdict filed, never a pass).
    // Side by side by name, never folded into one per-binary claim.
    assert_eq!(
        eqgame,
        serde_json::json!({
            "binary": "eqgame.exe",
            "scenarios": [
                {
                    "scenario": "boot",
                    "declared": true,
                    "captured": true,
                    "verdict": { "assessed_fail": { "failed_dimensions": ["exit"] } }
                },
                {
                    "scenario": "orphan",
                    "declared": false,
                    "captured": true,
                    "verdict": "assessed_pass"
                },
                {
                    "scenario": "print-config",
                    "declared": true,
                    "captured": false,
                    "verdict": "unassessed"
                }
            ]
        }),
        "every state renders from the documents that stand, whole"
    );

    // The unit binaries with no scenario documents get no rows.
    let binaries: Vec<&str> = body["dashboard"]["scenario_statuses"]
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry["binary"].as_str().expect("binary name"))
        .collect();
    assert_eq!(binaries, vec!["eqgame.exe"], "only the named binary rides");
}

// ─── Headless render seam (issue #483) ──────────────────────────────────
//
// The queue view renders a per-binary *scenario status* section from the
// payload's `scenario_statuses` rows alone. It computes nothing in the
// client. A payload with no rows renders the honest negative, never
// empty success. These pins ride the booted world and its browser
// helpers (issue #471), and self-skip when no Chrome/Chromium exists.

/// JS expression reading the queue view's scenario strip text,
/// empty while absent.
const SCENARIO_STRIP: &str = "document.getElementById('queue-scenarios')?.textContent || ''";

/// JS expression counting the strip's per-binary sections.
const SCENARIO_SECTIONS: &str =
    "document.querySelectorAll('#queue-scenarios [data-scenario-binary]').length";

fn scenario_strip_text(tab: &support::DashboardTab) -> String {
    tab.eval_text(SCENARIO_STRIP)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_scenario_section_renders_the_honest_negative_with_no_rows() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };

    // Switch to the queue view; the strip renders with the list.
    tab.click(".nav-tab[data-view=\"queue\"]");

    // Nothing filed anywhere: the strip names its own absence — no
    // scenario documents stand, nothing is declared — the honest
    // reading, never an empty success and never a pass.
    let negative_visible = tab
        .wait_for_text(SCENARIO_STRIP, |strip| {
            strip.contains("no scenario documents stand filed")
                && strip.contains("never a clean run")
        })
        .await;
    let strip = scenario_strip_text(&tab);
    assert!(
        negative_visible,
        "the queue scenario strip should render the honest negative, got: {strip:?}"
    );
    assert!(
        !strip.contains("assessed pass"),
        "with no documents filed the strip never renders an assessed pass: {strip:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_headless_scenario_section_names_every_state_of_the_filed_documents() {
    let world = support::ReviewWorld::boot_plain().await;

    let Some(tab) = world.open_dashboard_tab() else {
        return;
    };
    tab.click(".nav-tab[data-view=\"queue\"]");

    // File the five-state documents the payload pin files, plus a
    // second binary's lone contract: `boot` declared, captured,
    // assessed fail naming its dimension; `orphan` not declared,
    // captured, assessed pass; `print-config` declared, not captured,
    // unassessed; `launch` declared, with its capture and verdict
    // never filed. Each scenario gets its own row, under its binary's
    // own section — and the assessed-fail row names the dimension it
    // failed.
    file_scenario_records(world.repo_path().as_path());
    file_contract(&world, "d3d9.dll", "launch");
    tab.reload();
    tab.click(".nav-tab[data-view=\"queue\"]");

    let states_visible = tab
        .wait_for_text(SCENARIO_STRIP, |strip| {
            strip.contains("boot — declared, captured, assessed fail (exit)")
                && strip.contains("orphan — not declared, captured, assessed pass")
                && strip.contains("print-config — declared, not captured, unassessed")
                && strip.contains("launch — declared, not captured, unassessed")
        })
        .await;
    let strip = scenario_strip_text(&tab);
    assert!(
        states_visible,
        "the strip should render each filed scenario's state, the assessed-fail row \
         naming its failed dimension, got: {strip:?}"
    );

    // One section per binary: each named binary stands in its own
    // section, never folded into the other's rows.
    let sections_visible = tab
        .wait_for_bool(&format!("{} === 2", SCENARIO_SECTIONS))
        .await;
    let sections = tab.eval_count(SCENARIO_SECTIONS);
    assert_eq!(
        sections, 2,
        "the strip should hold one section per named binary, saw {sections}"
    );
    assert!(sections_visible, "sections settle at two for: {strip:?}");

    // The honest negative is gone once documents stand — and no row
    // launders an unassessed or not-captured slot into a success word.
    assert!(
        !strip.contains("no scenario documents stand filed"),
        "filed documents replace the honest negative: {strip:?}"
    );
    assert!(
        !strip.contains("print-config — declared, captured"),
        "a scenario with no capture never reads as captured: {strip:?}"
    );
}

#[tokio::test]
async fn a_failing_scenario_verdict_triggers_no_per_unit_review_action() {
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

    file_scenario_records(world.repo_path().as_path());
    let after = dashboard_body(&world).await;

    // The boundary this track pins: a scenario verdict is target-binary-
    // level evidence. With a failing verdict filed, every unit's derived
    // review status is exactly what it was — no unit silently goes back.
    assert_eq!(
        statuses(&after),
        statuses(&before),
        "a failing scenario leaves every unit's review status untouched"
    );
    assert!(
        !world.repo_path().join("re").join("actions").exists(),
        "no review action record is ever written for a scenario verdict"
    );

    // And accept stands on its own: accepting a queued unit with the
    // failing verdict filed succeeds — blocking on scenario evidence is
    // a later track's decision machinery, never this surface's.
    let queued = after["dashboard"]["review_queue"]
        .as_array()
        .expect("array")
        .iter()
        .find(|unit| unit["status"] == "Queued" || unit["status"] == "PendingReview")
        .expect("a queued unit stands");
    let unit_id = queued["id"].as_str().expect("unit id").to_string();
    let (status, body) = world
        .client()
        .post_lifecycle(&format!(
            "/api/units/{}/accept",
            // Same encoding the web UI's own client uses: unit ids carry slashes.
            unit_id.replace('/', "%2F")
        ))
        .await;
    assert_eq!(
        status, 200,
        "accept is not blocked by a filed failing scenario verdict — \
         unit {unit_id} answered {status}: {body}"
    );
    assert_eq!(body["action"], "accept");
}

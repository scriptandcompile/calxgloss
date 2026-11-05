//! Issue #409 (P24.8) at the web e2e seam: the per-binary *scenario
//! status* on the review dashboard. The filed scenario documents —
//! contract set, capture, verdict — reach `/api/dashboard` through
//! `ReviewDashboard.scenario_statuses`, every state renders from the
//! documents that stand, and every missing record renders as its honest
//! negative: no contract renders not-declared, no capture renders
//! not-captured, no verdict renders unassessed — an unassessed dimension
//! never renders as a pass. A failing verdict names its dimensions and
//! triggers no per-unit review action: no unit silently goes back, and
//! accept is not blocked on its own.

use super::*;

/// GET `/api/dashboard` and return the parsed body.
async fn dashboard_body(port: u16) -> serde_json::Value {
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/dashboard", port))
        .await
        .expect("dashboard request succeeds");
    assert_eq!(resp.status(), 200);
    resp.json().await.expect("dashboard body is JSON")
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

    let contract = |name: &str| {
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
    };
    std::fs::write(
        scenarios.join("eqgame.exe.json"),
        serde_json::json!({
            "binary": "eqgame.exe",
            "filed_at": 1,
            "scenarios": { "boot": contract("boot"), "print-config": contract("print-config") }
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
    let fixture = TestFixture::new();
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Nothing filed: the surface names nothing — no binary with a unit
    // branch gets a fabricated checklist row.
    let body = dashboard_body(fixture.port()).await;
    assert_eq!(
        body["dashboard"]["scenario_statuses"],
        serde_json::json!([]),
        "no filed scenario documents render no rows at all"
    );

    file_scenario_records(fixture.repo_path().as_path());
    let body = dashboard_body(fixture.port()).await;
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

#[tokio::test]
async fn a_failing_scenario_verdict_triggers_no_per_unit_review_action() {
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

    file_scenario_records(fixture.repo_path().as_path());
    let after = dashboard_body(fixture.port()).await;

    // The boundary this track pins: a scenario verdict is target-binary-
    // level evidence. With a failing verdict filed, every unit's derived
    // review status is exactly what it was — no unit silently goes back.
    assert_eq!(
        statuses(&after),
        statuses(&before),
        "a failing scenario leaves every unit's review status untouched"
    );
    assert!(
        !fixture.repo_path().join("re").join("actions").exists(),
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
    let resp = reqwest::Client::new()
        .post(format!(
            "http://127.0.0.1:{}/api/units/{}/accept",
            fixture.port(),
            // Same encoding the web UI's own client uses: unit ids carry slashes.
            unit_id.replace('/', "%2F")
        ))
        .send()
        .await
        .expect("accept request succeeds");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("accept body is JSON");
    assert_eq!(
        status, 200,
        "accept is not blocked by a filed failing scenario verdict — \
         unit {unit_id} answered {status}: {body}"
    );
    assert_eq!(body["action"], "accept");
}

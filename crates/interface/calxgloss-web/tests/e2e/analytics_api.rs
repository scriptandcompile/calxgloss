//! Scenario tests split from `tests/e2e.rs`.

use super::*;

/// Issue #125 filter contract: category, binary, and the inclusive
/// `from`/`to` UTC date range narrow every endpoint — the cards, bars,
/// trend, and table always describe the same filtered set — while
/// `total_in_log` keeps reporting the unfiltered log size.
#[tokio::test]
async fn test_faults_api_filters_narrow_every_endpoint() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Category filter: only the two hallucination faults survive.
    let (status, body) = get_json(&format!("{base}/api/faults?category=hallucination")).await;
    assert_eq!(status, 200);
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(
        entries.len(),
        2,
        "category filter leaves the two hallucinations"
    );
    assert!(
        entries
            .iter()
            .all(|e| e["category"] == "hallucination" && e["severity"] == "error")
    );
    assert_eq!(
        body["total_in_log"].as_u64().expect("total_in_log"),
        6,
        "the log's own size survives filtering"
    );
    let (status, body) =
        get_json(&format!("{base}/api/faults/summary?category=hallucination")).await;
    assert_eq!(status, 200);
    assert_eq!(body["total"].as_u64().expect("total"), 2);
    assert_eq!(
        body["by_category"],
        serde_json::json!([{"name": "hallucination", "count": 2}])
    );
    let (status, body) = get_json(&format!("{base}/api/faults/trend?category=hallucination")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["days"],
        serde_json::json!([
            {"date": "2026-10-01", "count": 1, "moving_average": 1.0},
            {"date": "2026-10-02", "count": 0, "moving_average": 0.5},
            {"date": "2026-10-03", "count": 0, "moving_average": 0.3333333333333333},
            {"date": "2026-10-04", "count": 1, "moving_average": 0.3333333333333333},
        ]),
        "the trend buckets the filtered set the same way"
    );

    // Binary filter: only the d3d9.dll faults.
    let (status, body) = get_json(&format!("{base}/api/faults?binary=d3d9.dll")).await;
    assert_eq!(status, 200);
    let entries = body["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|e| e["binary"] == "d3d9.dll" && e["function"] == "UpdateScene")
    );
    let (status, body) = get_json(&format!("{base}/api/faults/by-binary?binary=d3d9.dll")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([{"binary": "d3d9.dll", "count": 3}])
    );
    let (status, body) = get_json(&format!("{base}/api/faults?binary=D3D9.DLL")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        3,
        "the binary filter matches case-insensitively, like every other binary comparison"
    );

    // Date range: inclusive on both ends, compared on UTC days. The gap
    // days alone match nothing — the trend then honestly answers empty.
    let (status, body) =
        get_json(&format!("{base}/api/faults?from=2026-10-02&to=2026-10-03")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        0,
        "the gap days hold no faults"
    );
    let (status, body) = get_json(&format!(
        "{base}/api/faults/trend?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["days"].as_array().expect("days array").len(),
        0,
        "no matching faults means no fabricated zero run"
    );

    // `from` alone keeps everything from that day on.
    let (status, body) = get_json(&format!("{base}/api/faults?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["entries"].as_array().expect("entries array").len(),
        3,
        "the inclusive from bound keeps the 10-04 faults"
    );
}

/// Issue #125 filter honesty: a malformed filter value is refused with 400
/// naming the accepted shape — an operator who typed a filter is never
/// silently shown unfiltered data.
#[tokio::test]
async fn test_faults_api_bad_filter_answers_400() {
    let fixture = TestFixture::new();
    write_fault_log_fixture(&fixture.repo_path(), &sample_fault_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/faults?category=nonsense")).await;
    assert_eq!(status, 400, "an unknown category is refused, not ignored");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("nonsense") && message.contains("hallucination"),
        "the 400 names the bad value and the vocabulary, got: {message}"
    );

    let (status, _) = get_json(&format!("{base}/api/faults/summary?from=not-a-date")).await;
    assert_eq!(status, 400, "a malformed from date is refused");

    let (status, _) = get_json(&format!("{base}/api/faults/trend?to=2026-13-01")).await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #125 honest degradation: a corrupt fault log loads as empty — the
/// analytics endpoints answer 200 with empty payloads, and the view's
/// empty state (driven by `total_in_log` and `total`) never renders a
/// wall of zeros for a log it cannot read.
#[tokio::test]
async fn test_faults_api_corrupt_log_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("fault_log.json"), "{ not json").expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/faults")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["entries"].as_array().expect("entries array").len(), 0);
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);

    let (status, body) = get_json(&format!("{base}/api/faults/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(body["total"].as_u64().expect("total"), 0);
    assert_eq!(
        body["by_category"].as_array().expect("by_category").len(),
        0
    );

    let (status, body) = get_json(&format!("{base}/api/faults/trend")).await;
    assert_eq!(status, 200);
    assert_eq!(body["days"].as_array().expect("days array").len(), 0);
}

/// Issue #126 router contract: every token-usage analytics endpoint is
/// registered in the shared routes — they read the persisted token usage
/// log, never live pipeline state — so both the plain and the live router
/// answer them. With no log on disk they serve honest empty payloads.
#[tokio::test]
async fn test_token_usage_analytics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());

        let (status, body) = get_json(&format!("{base}/api/token-usage/summary")).await;
        assert_eq!(status, 200, "{kind} router serves /api/token-usage/summary");
        assert_eq!(
            body["total_tokens"].as_u64().expect("total_tokens"),
            0,
            "{kind} router reports zero tokens with no log"
        );
        assert_eq!(
            body["total_in_log"].as_u64().expect("total_in_log"),
            0,
            "{kind} router reports an empty log with no log"
        );

        for path in [
            "/api/token-usage/by-binary",
            "/api/token-usage/by-tier",
            "/api/token-usage/by-strategy",
        ] {
            let (status, _) = get_json(&format!("{base}{path}")).await;
            assert_eq!(status, 200, "{kind} router serves {path}");
        }

        let (_, body) = get_json(&format!("{base}/api/token-usage/by-binary")).await;
        assert!(
            body["binaries"]
                .as_array()
                .expect("binaries array")
                .is_empty(),
            "no log means no fabricated bars"
        );
        let (_, body) = get_json(&format!("{base}/api/token-usage/by-tier")).await;
        assert!(
            body["tiers"].as_array().expect("tiers array").is_empty(),
            "no log means no fabricated tiers"
        );
        let (_, body) = get_json(&format!("{base}/api/token-usage/by-strategy")).await;
        assert!(
            body["strategies"]
                .as_array()
                .expect("strategies array")
                .is_empty(),
            "no log means no fabricated strategies"
        );
    }
}

/// Issue #126 exact-JSON contract: against a deterministic fixture log,
/// each endpoint answers with exactly the totals, percentage shares, and
/// per-strategy success rates the fixture implies — ordering highest first,
/// ties alphabetical.
#[tokio::test]
async fn test_token_usage_api_exact_json_from_fixture_log() {
    let fixture = TestFixture::new();
    write_token_usage_fixture(&fixture.repo_path(), &sample_token_usage_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Summary split: total tokens consumed, split into successful and
    // failed attempts, plus the log's own size for the honest empty state.
    let (status, body) = get_json(&format!("{base}/api/token-usage/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_tokens": 20_000,
            "successful_tokens": 5_000,
            "failed_tokens": 15_000,
            "total_attempts": 5,
            "total_in_log": 5,
        })
    );

    // Per-binary breakdown with percentage shares of the filtered total.
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-binary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([
            {"binary": "game_logic.dll", "tokens": 15_000, "share_percent": 75.0},
            {"binary": "d3d9.dll", "tokens": 5_000, "share_percent": 25.0},
        ])
    );

    // Per-tier breakdown — the untracked (no `context_tier`) entries form
    // their own honest bucket; the 3000-token tie sorts alphabetically.
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-tier")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["tiers"],
        serde_json::json!([
            {"tier": "module_context", "tokens": 8_000, "attempts": 1},
            {"tier": "stub", "tokens": 6_000, "attempts": 2},
            {"tier": "", "tokens": 3_000, "attempts": 1},
            {"tier": "disassembly", "tokens": 3_000, "attempts": 1},
        ])
    );

    // Per-strategy breakdown with a success rate per strategy — the 3000-
    // token tie between compile_fix and retry sorts alphabetically.
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-strategy")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["strategies"],
        serde_json::json!([
            {"strategy": "escalate", "tokens": 8_000, "attempts": 1, "successes": 0, "success_rate": 0.0},
            {"strategy": "initial", "tokens": 6_000, "attempts": 2, "successes": 1, "success_rate": 50.0},
            {"strategy": "compile_fix", "tokens": 3_000, "attempts": 1, "successes": 1, "success_rate": 100.0},
            {"strategy": "retry", "tokens": 3_000, "attempts": 1, "successes": 0, "success_rate": 0.0},
        ])
    );
}

/// Issue #126 time-range contract: the `from`/`to` inclusive UTC date range
/// narrows every endpoint the same way — summary, bars, tiers, and strategy
/// rows always describe the same filtered set — while `total_in_log` keeps
/// reporting the unfiltered log size. A malformed date is refused with 400.
#[tokio::test]
async fn test_token_usage_api_time_range_narrows_every_endpoint() {
    let fixture = TestFixture::new();
    write_token_usage_fixture(&fixture.repo_path(), &sample_token_usage_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // `from` alone keeps everything from that UTC day on: only the two
    // 2026-10-04 d3d9.dll attempts survive.
    let (status, body) = get_json(&format!("{base}/api/token-usage/summary?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_tokens": 5_000,
            "successful_tokens": 2_000,
            "failed_tokens": 3_000,
            "total_attempts": 2,
            "total_in_log": 5,
        })
    );
    let (status, body) =
        get_json(&format!("{base}/api/token-usage/by-binary?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["binaries"],
        serde_json::json!([
            {"binary": "d3d9.dll", "tokens": 5_000, "share_percent": 100.0},
        ]),
        "the share is of the filtered total, not the whole log"
    );
    let (status, body) = get_json(&format!("{base}/api/token-usage/by-tier?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["tiers"],
        serde_json::json!([
            {"tier": "", "tokens": 3_000, "attempts": 1},
            {"tier": "stub", "tokens": 2_000, "attempts": 1},
        ])
    );
    let (status, body) = get_json(&format!(
        "{base}/api/token-usage/by-strategy?from=2026-10-04"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["strategies"],
        serde_json::json!([
            {"strategy": "retry", "tokens": 3_000, "attempts": 1, "successes": 0, "success_rate": 0.0},
            {"strategy": "initial", "tokens": 2_000, "attempts": 1, "successes": 1, "success_rate": 100.0},
        ])
    );

    // An inclusive range holding no attempts answers with zeros and empty
    // breakdowns — never a fabricated row of buckets.
    let (status, body) = get_json(&format!(
        "{base}/api/token-usage/summary?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["total_tokens"].as_u64().expect("total_tokens"), 0);
    assert_eq!(
        body["total_in_log"].as_u64().expect("total_in_log"),
        5,
        "the log's own size survives filtering"
    );
    let (_, body) = get_json(&format!(
        "{base}/api/token-usage/by-binary?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert!(
        body["binaries"]
            .as_array()
            .expect("binaries array")
            .is_empty(),
        "no matching attempts means no bars"
    );

    // Malformed dates are refused with 400 naming the accepted shape —
    // an operator who typed a filter is never silently shown everything.
    let (status, body) = get_json(&format!("{base}/api/token-usage/summary?from=not-a-date")).await;
    assert_eq!(status, 400, "a malformed from date is refused");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not-a-date") && message.contains("YYYY-MM-DD"),
        "the 400 names the bad value and the accepted shape, got: {message}"
    );

    let (status, _) = get_json(&format!("{base}/api/token-usage/by-strategy?to=2026-13-01")).await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #126 honest degradation: a corrupt token usage log loads as empty —
/// the endpoints answer 200 with empty payloads so the view's empty state
/// (driven by `total_in_log`) never renders a wall of zeros for a log it
/// cannot read.
#[tokio::test]
async fn test_token_usage_api_corrupt_log_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("token_usage.json"), "{ not json").expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/token-usage/summary")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["total_tokens"].as_u64().expect("total_tokens"), 0);
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);

    let (status, body) = get_json(&format!("{base}/api/token-usage/by-binary")).await;
    assert_eq!(status, 200);
    assert!(
        body["binaries"]
            .as_array()
            .expect("binaries array")
            .is_empty(),
        "a corrupt log means no bars, not zero bars"
    );
}

/// Issue #127 router contract: both strategy-analytics endpoints are
/// registered in the shared routes — they read the persisted prompt-
/// strategy log, never live pipeline state — so both the plain and the
/// live router answer them. With no log on disk they serve honest empty
/// payloads.
#[tokio::test]
async fn test_strategy_analytics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());

        for path in [
            "/api/strategy-analytics/by-strategy",
            "/api/strategy-analytics/by-category",
        ] {
            let (status, body) = get_json(&format!("{base}{path}")).await;
            assert_eq!(status, 200, "{kind} router serves {path}");
            assert_eq!(
                body["total_in_log"].as_u64().expect("total_in_log"),
                0,
                "{kind} router reports an empty log with no log"
            );
        }

        let (_, body) = get_json(&format!("{base}/api/strategy-analytics/by-strategy")).await;
        assert!(
            body["strategies"]
                .as_array()
                .expect("strategies array")
                .is_empty(),
            "no log means no fabricated strategies"
        );
        let (_, body) = get_json(&format!("{base}/api/strategy-analytics/by-category")).await;
        assert!(
            body["categories"]
                .as_array()
                .expect("categories array")
                .is_empty(),
            "no log means no fabricated categories"
        );
    }
}

/// Issue #127 exact-JSON contract: against a deterministic fixture log,
/// each endpoint answers with exactly the attempt, success, failure, and
/// pass-rate numbers the fixture implies — most attempts first, ties
/// alphabetical.
#[tokio::test]
async fn test_strategy_analytics_api_exact_json_from_fixture_log() {
    let fixture = TestFixture::new();
    write_strategy_fixture(&fixture.repo_path(), &sample_strategy_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Per-strategy breakdown — the initial/retry tie at two attempts
    // sorts alphabetically ahead of the single-attempt strategies.
    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-strategy")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "strategies": [
                {"strategy": "initial", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
                {"strategy": "retry", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
                {"strategy": "compile_fix", "attempts": 1, "successes": 1, "failures": 0, "pass_rate": 100.0},
                {"strategy": "escalate", "attempts": 1, "successes": 0, "failures": 1, "pass_rate": 0.0},
            ],
            "total_in_log": 6,
        })
    );

    // Per-category breakdown — ProjectSpecific (4 attempts) before
    // KnownThirdParty (2), pass rates as percentages.
    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-category")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "categories": [
                {"category": "ProjectSpecific", "attempts": 4, "successes": 2, "failures": 2, "pass_rate": 50.0},
                {"category": "KnownThirdParty", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
            ],
            "total_in_log": 6,
        })
    );
}

/// Issue #127 time-range contract: the `from`/`to` inclusive UTC date
/// range narrows both endpoints the same way — the strategy table and the
/// category bars always describe the same filtered set — while
/// `total_in_log` keeps reporting the unfiltered log size. A malformed
/// date is refused with 400.
#[tokio::test]
async fn test_strategy_analytics_api_time_range_narrows_every_endpoint() {
    let fixture = TestFixture::new();
    write_strategy_fixture(&fixture.repo_path(), &sample_strategy_entries());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // `from` alone keeps everything from that UTC day on: only the two
    // 2026-10-04 d3d9.dll attempts survive.
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-strategy?from=2026-10-04"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["strategies"],
        serde_json::json!([
            {"strategy": "initial", "attempts": 1, "successes": 1, "failures": 0, "pass_rate": 100.0},
            {"strategy": "retry", "attempts": 1, "successes": 0, "failures": 1, "pass_rate": 0.0},
        ])
    );
    assert_eq!(
        body["total_in_log"].as_u64().expect("total_in_log"),
        6,
        "the log's own size survives filtering"
    );
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-category?from=2026-10-04"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["categories"],
        serde_json::json!([
            {"category": "KnownThirdParty", "attempts": 2, "successes": 1, "failures": 1, "pass_rate": 50.0},
        ]),
        "only the in-range category survives"
    );

    // An inclusive range holding no attempts answers with empty breakdowns
    // — never a fabricated row of buckets.
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-strategy?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert!(
        body["strategies"]
            .as_array()
            .expect("strategies array")
            .is_empty(),
        "no matching attempts means no rows"
    );
    let (_, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-category?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert!(
        body["categories"]
            .as_array()
            .expect("categories array")
            .is_empty(),
        "no matching attempts means no bars"
    );

    // Malformed dates are refused with 400 naming the accepted shape —
    // an operator who typed a filter is never silently shown everything.
    let (status, body) = get_json(&format!(
        "{base}/api/strategy-analytics/by-strategy?from=not-a-date"
    ))
    .await;
    assert_eq!(status, 400, "a malformed from date is refused");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not-a-date") && message.contains("YYYY-MM-DD"),
        "the 400 names the bad value and the accepted shape, got: {message}"
    );

    let (status, _) = get_json(&format!(
        "{base}/api/strategy-analytics/by-category?to=2026-13-01"
    ))
    .await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #127 honest degradation: a corrupt prompt-strategy log loads as
/// empty — the endpoints answer 200 with empty payloads so the view's
/// empty state (driven by `total_in_log`) never renders a wall of zeros
/// for a log it cannot read.
#[tokio::test]
async fn test_strategy_analytics_api_corrupt_log_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("prompt_strategy_log.json"), "{ not json")
        .expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-strategy")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);
    assert!(
        body["strategies"]
            .as_array()
            .expect("strategies array")
            .is_empty(),
        "a corrupt log means no rows, not zero rows"
    );

    let (status, body) = get_json(&format!("{base}/api/strategy-analytics/by-category")).await;
    assert_eq!(status, 200);
    assert!(
        body["categories"]
            .as_array()
            .expect("categories array")
            .is_empty(),
        "a corrupt log means no bars, not zero bars"
    );
}

/// Issue #128 router contract: both llm-metrics endpoints are registered
/// in the shared routes — they read the persisted logs, never live
/// pipeline state — so both the plain and the live router answer them.
/// With no logs on disk they serve honest empty payloads: null
/// percentiles, not zeros.
#[tokio::test]
async fn test_llm_metrics_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());

        for path in ["/api/llm-metrics/summary", "/api/llm-metrics/by-tier"] {
            let (status, _) = get_json(&format!("{base}{path}")).await;
            assert_eq!(status, 200, "{kind} router serves {path}");
        }

        let (_, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
        assert_eq!(
            body["total_in_log"].as_u64().expect("total_in_log"),
            0,
            "{kind} router reports an empty log with no log"
        );
        for key in ["p50_secs", "p95_secs", "p99_secs"] {
            assert!(
                body[key].is_null(),
                "{kind} router answers {key} as unmeasured, never a fabricated zero"
            );
        }
        assert!(
            body["timeout_trend"]
                .as_array()
                .expect("timeout_trend array")
                .is_empty(),
            "no log means no fabricated trend buckets"
        );
        let (_, body) = get_json(&format!("{base}/api/llm-metrics/by-tier")).await;
        assert!(
            body["tiers"].as_array().expect("tiers array").is_empty(),
            "no log means no fabricated tiers"
        );
    }
}

/// Issue #128 exact-JSON contract: against deterministic fixture logs,
/// the summary pins exact nearest-rank P50/P95/P99 over the *recorded*
/// durations — the two entries without a duration are excluded, never
/// counted as zero — and counts exactly the two timeout-kind faults, bucketed
/// per UTC day with the gap days filled. The by-tier endpoint pins the
/// per-tier correlation, including the untracked empty-label bucket.
#[tokio::test]
async fn test_llm_metrics_api_exact_json_from_fixture_logs() {
    let fixture = TestFixture::new();
    write_llm_metrics_fixtures(&fixture.repo_path());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_attempts": 9,
            "measured_attempts": 7,
            "p50_secs": 40,
            "p95_secs": 70,
            "p99_secs": 70,
            "timeouts": 2,
            "timeout_trend": [
                {"date": "2026-10-01", "count": 1},
                {"date": "2026-10-02", "count": 0},
                {"date": "2026-10-03", "count": 0},
                {"date": "2026-10-04", "count": 1},
            ],
            "total_in_log": 9,
        }),
        "percentiles cover only the measured durations; the overloaded and \
         slow-response faults stay out of the timeout count"
    );

    // Most attempts first; the 2-attempt tie sorts alphabetically, with
    // the untracked empty label honestly first. The disassembly tier has
    // one measured and one unmeasured attempt; a tier with nothing
    // measured would answer null percentiles.
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/by-tier")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "tiers": [
                {"tier": "stub", "attempts": 3, "measured_attempts": 2, "p50_secs": 10, "p95_secs": 30},
                {"tier": "", "attempts": 2, "measured_attempts": 2, "p50_secs": 20, "p95_secs": 40},
                {"tier": "disassembly", "attempts": 2, "measured_attempts": 1, "p50_secs": 50, "p95_secs": 50},
                {"tier": "module_context", "attempts": 2, "measured_attempts": 2, "p50_secs": 60, "p95_secs": 70},
            ],
            "total_in_log": 9,
        })
    );
}

/// Issue #128 time-range contract: the `from`/`to` inclusive UTC date
/// range narrows both endpoints the same way — cards, trend, and tier
/// table always describe the same window — while `total_in_log` keeps
/// reporting the unfiltered log size. A malformed date is refused with
/// 400 naming the accepted shape.
#[tokio::test]
async fn test_llm_metrics_api_time_range_narrows_every_endpoint() {
    let fixture = TestFixture::new();
    write_llm_metrics_fixtures(&fixture.repo_path());
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // `from` alone keeps everything from that UTC day on: only the five
    // 2026-10-04 attempts survive — four measured (20/40/60/70, so P50
    // pins at 40) and one unmeasured — and only the 2026-10-04 timeout.
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "total_attempts": 5,
            "measured_attempts": 4,
            "p50_secs": 40,
            "p95_secs": 70,
            "p99_secs": 70,
            "timeouts": 1,
            "timeout_trend": [
                {"date": "2026-10-04", "count": 1},
            ],
            "total_in_log": 9,
        }),
        "the log's own size survives filtering"
    );
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/by-tier?from=2026-10-04")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body["tiers"],
        serde_json::json!([
            {"tier": "", "attempts": 2, "measured_attempts": 2, "p50_secs": 20, "p95_secs": 40},
            {"tier": "module_context", "attempts": 2, "measured_attempts": 2, "p50_secs": 60, "p95_secs": 70},
            {"tier": "disassembly", "attempts": 1, "measured_attempts": 0, "p50_secs": null, "p95_secs": null},
        ]),
        "the in-range disassembly attempt is unmeasured — percentiles stay \
         null, never imputed"
    );

    // An inclusive range holding no attempts answers with null percentiles
    // and empty breakdowns — never a fabricated run of zeros.
    let (status, body) = get_json(&format!(
        "{base}/api/llm-metrics/summary?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert_eq!(status, 200);
    assert!(
        body["p50_secs"].is_null(),
        "nothing measured means no percentile"
    );
    assert_eq!(body["timeouts"].as_u64().expect("timeouts"), 0);
    assert!(
        body["timeout_trend"]
            .as_array()
            .expect("timeout_trend array")
            .is_empty(),
        "no matching timeouts means no buckets"
    );
    let (_, body) = get_json(&format!(
        "{base}/api/llm-metrics/by-tier?from=2026-10-02&to=2026-10-03"
    ))
    .await;
    assert!(
        body["tiers"].as_array().expect("tiers array").is_empty(),
        "no matching attempts means no rows"
    );

    // Malformed dates are refused with 400 naming the accepted shape —
    // an operator who typed a filter is never silently shown everything.
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary?from=not-a-date")).await;
    assert_eq!(status, 400, "a malformed from date is refused");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("not-a-date") && message.contains("YYYY-MM-DD"),
        "the 400 names the bad value and the accepted shape, got: {message}"
    );

    let (status, _) = get_json(&format!("{base}/api/llm-metrics/by-tier?to=2026-13-01")).await;
    assert_eq!(status, 400, "an out-of-range to date is refused");
}

/// Issue #128 honest degradation: a corrupt token usage log loads as
/// empty — the endpoints answer 200 with null percentiles and empty
/// breakdowns so the view's empty state (driven by `total_in_log`) never
/// renders a wall of zeros. A corrupt fault log likewise answers zero
/// timeouts while the duration percentiles keep computing from the
/// intact token log.
#[tokio::test]
async fn test_llm_metrics_api_corrupt_logs_honest_empty() {
    let fixture = TestFixture::new();
    let dir = fixture.repo_path().join("re").join("analysis");
    std::fs::create_dir_all(&dir).expect("analysis dir exists");
    std::fs::write(dir.join("token_usage.json"), "{ not json").expect("corrupt log written");
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
    assert_eq!(status, 200, "a corrupt log degrades, never errors");
    assert_eq!(body["total_in_log"].as_u64().expect("total_in_log"), 0);
    assert!(
        body["p50_secs"].is_null(),
        "a corrupt log means unmeasured, not zero"
    );
    assert_eq!(body["timeouts"].as_u64().expect("timeouts"), 0);

    let (status, body) = get_json(&format!("{base}/api/llm-metrics/by-tier")).await;
    assert_eq!(status, 200);
    assert!(
        body["tiers"].as_array().expect("tiers array").is_empty(),
        "a corrupt log means no rows, not zero rows"
    );

    // The other direction: the fault log corrupts, the token log survives.
    std::fs::write(dir.join("fault_log.json"), "{ not json").expect("corrupt fault log written");
    write_token_usage_fixture(
        &fixture.repo_path(),
        &[llm_metrics_token_entry(
            "game_logic.dll",
            "DrawSprite",
            1,
            "initial",
            4000,
            false,
            "stub",
            FAULT_DAY_1 + 60,
            Some(10),
        )],
    );
    let (status, body) = get_json(&format!("{base}/api/llm-metrics/summary")).await;
    assert_eq!(status, 200);
    assert_eq!(body["p50_secs"].as_u64().expect("p50_secs"), 10);
    assert_eq!(body["timeouts"].as_u64().expect("timeouts"), 0);
    assert!(
        body["timeout_trend"]
            .as_array()
            .expect("timeout_trend array")
            .is_empty(),
        "a corrupt fault log means no buckets, not zero buckets"
    );
}

// ─────────────────────────────────────────────────────────────
// Binaries view (issue #130, W4.1)
// ─────────────────────────────────────────────────────────────

/// Issue #130 router contract: `/api/binaries/list` is registered in the
/// shared routes — it reads only persisted history, never live pipeline
/// state — so both the plain and the live router answer it. The fixture's
/// initial classification records carry no `binary` field, so
/// `disk_classifications` skips them and the list is honestly empty.
#[tokio::test]
async fn test_binaries_list_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/list")).await;
        assert_eq!(status, 200, "{kind} router serves /api/binaries/list");
        assert!(
            body["binaries"]
                .as_array()
                .expect("binaries array")
                .is_empty(),
            "{kind} router answers an empty list when no classification \
             record is readable — never a wall of zero rows"
        );
    }
}

/// Issue #130 exact-JSON contract: rows aggregate category/strategy from
/// the classification records with the persisted override layer applied,
/// function counts from all the review dashboard's units (queue plus
/// recent activity — where the merged, accepted ones live), and token
/// totals from the token-usage log with a case-insensitive join. Corrupt
/// records are skipped; rows sort alphabetically.
#[tokio::test]
async fn test_binaries_list_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!("{base}/api/binaries/list")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binaries": [
                {
                    "binary": "d3d9.dll",
                    // The override wins over the recorded MicrosoftSdk
                    // classification, and its strategy label follows the
                    // category — CrateReplacement, with the override's
                    // target crate shown.
                    "category": "KnownThirdParty",
                    "strategy": "CrateReplacement",
                    "crate_replacement": "wgpu-rs",
                    "overridden": true,
                    // The merged `re/d3d9.dll/wgpu` branch is an accepted
                    // unit in the dashboard — the row counts what the
                    // dashboard holds.
                    "functions_total": 1,
                    "functions_done": 1,
                    "functions_queued": 0,
                    "functions_failed": 0,
                    "tokens_used": 75,
                },
                {
                    "binary": "game_logic.dll",
                    "category": "ProjectSpecific",
                    "strategy": "ReverseEngineer",
                    "overridden": false,
                    // Three units: merged DrawPrimitive v1 and UpdateScene
                    // v1 (accepted) plus the unmerged v2 branch (patch
                    // record → pending review); the "GAME_LOGIC.DLL" token
                    // entry joins in case-insensitively.
                    "functions_total": 3,
                    "functions_done": 2,
                    "functions_queued": 1,
                    "functions_failed": 0,
                    "tokens_used": 175,
                },
            ],
        }),
        "the corrupt record is skipped, the override layer is applied, and \
         other.dll's tokens belong to no row"
    );
}

/// Issue #132 router contract: `/api/binaries/{name}` is registered in
/// the shared routes — it reads only persisted history, never live
/// pipeline state — so both the plain and the live router answer it with
/// the full detail payload.
#[tokio::test]
async fn test_binaries_detail_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        write_binaries_list_fixtures(&fixture);
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll")).await;
        assert_eq!(status, 200, "{kind} router serves /api/binaries/{{name}}");
        assert_eq!(body["binary"].as_str().expect("binary"), "game_logic.dll");
        assert_eq!(
            body["functions"].as_array().expect("functions array").len(),
            3,
            "{kind} router: the same three dashboard units the summary row counts"
        );
    }
}

/// Issue #132 exact-JSON contract: the detail reports the classification
/// decision in force — the override layer applied, exactly what the
/// analyzer would act on — with its reasoning and symbol counts, plus
/// the per-function list with each unit's review status. The lookup
/// is case-insensitive like every other server binary join; an unknown
/// or corrupt-record name honestly 404s rather than rendering an empty
/// shell.
#[tokio::test]
async fn test_binaries_detail_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The overridden binary: category, strategy, and crate come from the
    // override in force, and so does the reason — the analyzer's own
    // account of an overridden decision, not the heuristic's.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "crate_replacement": "wgpu-rs",
            "overridden": true,
            "known_runtime": false,
            "reason": "operator override — KnownThirdParty (category set from the dashboard)",
            "exports_count": 100,
            "imports_count": 5,
            "functions": [
                { "function": "wgpu", "attempt": 1, "status": "Accepted" },
            ],
        }),
        "the override-in-force decision exactly as the analyzer would act \
         on it, with the per-function list"
    );

    // The un-overridden binary: the recorded decision verbatim, and the
    // function list spelling out where each attempt stands — the stalled
    // v2 sits right next to the accepted v1.
    let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "game_logic.dll",
            "category": "ProjectSpecific",
            "strategy": "ReverseEngineer",
            "overridden": false,
            "known_runtime": false,
            "reason": "project-built binary — reverse engineer from disassembly",
            "exports_count": 24,
            "imports_count": 12,
            "functions": [
                { "function": "DrawPrimitive", "attempt": 1, "status": "Accepted" },
                { "function": "DrawPrimitive", "attempt": 2, "status": "PendingReview" },
                { "function": "UpdateScene", "attempt": 1, "status": "Accepted" },
            ],
        }),
        "the recorded decision with the per-function review statuses"
    );

    // A differently-spelled name finds the same binary — the
    // case-insensitive join every other server comparison makes — and
    // the response shows the record's verbatim identity.
    let (status, body) = get_json(&format!("{base}/api/binaries/GAME_LOGIC.DLL")).await;
    assert_eq!(status, 200, "the lookup is case-insensitive");
    assert_eq!(
        body["binary"].as_str().expect("binary"),
        "game_logic.dll",
        "the verbatim record name answers, not the requested spelling"
    );

    // Unknown names honestly 404 — no empty shell.
    for name in ["nope.dll", "broken.dll"] {
        let (status, body) = get_json(&format!("{base}/api/binaries/{name}")).await;
        assert_eq!(status, 404, "{name} has no readable classification record");
        assert_eq!(
            body["error"].as_bool(),
            Some(true),
            "{name}: the 404 carries the honest error payload"
        );
        assert!(
            body["message"].as_str().expect("message").contains(name),
            "the message names the binary the request asked for"
        );
    }
}

/// Issue #133 router contract: `/api/binaries/{name}/shim-status` is
/// registered in the shared routes — it reads only persisted artifacts,
/// never live pipeline state — so both the plain and the live router
/// answer it with the tracker payload.
#[tokio::test]
async fn test_binaries_shim_status_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        write_binaries_list_fixtures(&fixture);
        write_shim_tracker_fixtures(&fixture);
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/shim-status")).await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/binaries/{{name}}/shim-status"
        );
        assert_eq!(
            body["generated"].as_bool(),
            Some(true),
            "{kind} router: the persisted shim artifacts answer"
        );
        assert_eq!(body["mapping_count"].as_u64().expect("mapping_count"), 2);
    }
}

/// Issue #133 exact-JSON contract: the tracker reports existence,
/// mapping count, verification outcome, and merged/sent-back state from
/// persisted artifacts only. The crate joined to is the one the
/// override in force names (`wgpu-rs`, not the recorded `wgpu`); a
/// reverse-engineered binary honestly reports no shim expected; a
/// crate-replacement binary whose branch a reviewer sent back reports
/// the sent-back verdict. The lookup is case-insensitive; unknown and
/// corrupt-record names honestly 404.
#[tokio::test]
async fn test_binaries_shim_status_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The crate-replacement binary with artifacts and a merged shim
    // branch: every fact comes from the persisted shim files and the
    // branch model.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "shim_expected": true,
            // The crate in force is the override's, and so is the
            // branch joined to.
            "crate_replacement": "wgpu-rs",
            "generated": true,
            "mapping_count": 2,
            "verification": {
                "compiled": true,
                "tests_passed": 7,
                "tests_total": 8,
                "edge_tests_passed": 2,
                "edge_tests_total": 2,
            },
            "branch": { "name": "re/shim/wgpu-rs", "merged": true, "sent_back": false },
        }),
        "existence, mapping count, verification, and merged state from \
         persisted artifacts only"
    );

    // The reverse-engineered binary: honestly no shim expected, and no
    // derived fields on the wire at all.
    let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "game_logic.dll",
            "shim_expected": false,
            "generated": false,
        }),
        "a reverse-engineered binary honestly reports no shim expected"
    );

    // The crate-replacement binary whose shim was generated but whose branch
    // was sent back: the artifacts and the reviewer's verdict both answer.
    let (status, body) = get_json(&format!("{base}/api/binaries/fmod.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "fmod.dll",
            "shim_expected": true,
            "crate_replacement": "fmod-rs",
            "generated": true,
            "mapping_count": 2,
            "branch": { "name": "re/shim/fmod-rs", "merged": false, "sent_back": true },
        }),
        "no artifacts is honestly not generated; the send-back record \
         still shows through in the branch's acceptance state"
    );

    // A differently-spelled name finds the same binary — the
    // case-insensitive join every other server comparison makes — and
    // the response shows the record's verbatim identity.
    let (status, body) = get_json(&format!("{base}/api/binaries/D3D9.DLL/shim-status")).await;
    assert_eq!(status, 200, "the lookup is case-insensitive");
    assert_eq!(
        body["binary"].as_str().expect("binary"),
        "d3d9.dll",
        "the verbatim record name answers, not the requested spelling"
    );

    // Unknown names honestly 404 — no empty shell.
    for name in ["nope.dll", "broken.dll"] {
        let (status, body) = get_json(&format!("{base}/api/binaries/{name}/shim-status")).await;
        assert_eq!(status, 404, "{name} has no readable classification record");
        assert_eq!(
            body["error"].as_bool(),
            Some(true),
            "{name}: the 404 carries the honest error payload"
        );
    }
}

/// Issue #133 honest-degradation contract: a corrupt `mappings.json` is
/// no shim — the tracker answers "not generated" with the derived
/// fields absent, never a zeroed count; a corrupt `verification.json`
/// leaves the verification absent while the readable mappings still
/// answer.
#[tokio::test]
async fn test_binaries_shim_status_honest_missing_and_corrupt_artifacts() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_shim_tracker_fixtures(&fixture);

    // d3d9.dll's mappings go corrupt — the verification file stays
    // readable, but the shim's existence itself is unreadable.
    let shim_dir = fixture
        .repo_path()
        .join("re")
        .join("shims")
        .join("d3d9.dll");
    std::fs::write(shim_dir.join("mappings.json"), "{ not json").expect("corrupt mappings");

    // A second crate-replacement binary with both artifacts corrupt.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::write(
        classify.join("ogg.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "ogg.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "exports_count": 10,
            "imports_count": 1,
            "crate_replacement": "ogg-rs",
            "known_runtime": false,
            "reason": "audio codec — replaced with ogg-rs"
        }))
        .unwrap(),
    )
    .expect("ogg classification written");
    let ogg_dir = fixture.repo_path().join("re").join("shims").join("ogg.dll");
    std::fs::create_dir_all(&ogg_dir).expect("ogg shim dir");
    std::fs::write(ogg_dir.join("mappings.json"), "not json at all").expect("corrupt mappings");
    std::fs::write(ogg_dir.join("verification.json"), "{{{").expect("corrupt verification");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // Corrupt mappings: honestly not generated — no mapping count, even
    // though the verification artifact is still readable.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "shim_expected": true,
            "crate_replacement": "wgpu-rs",
            "generated": false,
            "verification": {
                "compiled": true,
                "tests_passed": 7,
                "tests_total": 8,
                "edge_tests_passed": 2,
                "edge_tests_total": 2,
            },
            "branch": { "name": "re/shim/wgpu-rs", "merged": true, "sent_back": false },
        }),
        "a corrupt mappings.json is no shim — honestly not generated, \
         never a zeroed count"
    );

    // Both artifacts corrupt: the honest empty payload — not generated,
    // no mapping count, no verification, no branch in the model.
    let (status, body) = get_json(&format!("{base}/api/binaries/ogg.dll/shim-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "ogg.dll",
            "shim_expected": true,
            "crate_replacement": "ogg-rs",
            "generated": false,
        }),
        "corrupt artifacts are no artifacts — the payload stays empty"
    );
}

/// Issue #134 router contract: `/api/binaries/{name}/pal-status` is in the
/// shared routes, so both the plain `serve` router and the live router
/// answer it. The payload is computed on request from saved artifacts,
/// never from live pipeline state.
#[tokio::test]
async fn test_binaries_pal_status_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        write_binaries_list_fixtures(&fixture);
        write_pal_tracker_fixtures(&fixture);
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/pal-status")).await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/binaries/{{name}}/pal-status"
        );
        assert_eq!(
            body["traits"].as_array().map(|t| t.len()),
            Some(2),
            "{kind} router: the derived traits answer"
        );
    }
}

/// Issue #134 exact-JSON contract. The needed traits come only from the
/// API-call categories in the saved per-function analysis artifacts. Each
/// category maps to a trait with the translator's Tier-4 shape: DirectX and
/// DirectX11 group into one GraphicsDevice, Win32Core into PlatformCore.
/// Traits are sorted by name, and each one lists its categories verbatim,
/// sorted. Whether a trait exists is read from the workspace's generated
/// PAL and shim source: GraphicsDevice exists (the scratch PAL crate
/// defines it) and PlatformCore is missing. A binary with no API-call
/// artifacts honestly answers an empty trait list, the name lookup ignores
/// case, and unknown or corrupt-record names honestly 404.
#[tokio::test]
async fn test_binaries_pal_status_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);
    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The binary that has API-call artifacts and a generated PAL source:
    // every fact in the payload comes only from saved artifacts.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "traits": [
                {
                    "name": "GraphicsDevice",
                    "categories": ["DirectX", "DirectX11"],
                    "exists": true,
                },
                {
                    "name": "PlatformCore",
                    "categories": ["Win32Core"],
                    "exists": false,
                },
            ],
        }),
        "needed traits derive from the persisted API-call categories, \
         existence from the generated PAL source"
    );

    // The binary with no per-function artifacts at all: the honest empty
    // payload — no fabricated trait list.
    let (status, body) = get_json(&format!("{base}/api/binaries/game_logic.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "game_logic.dll",
            "traits": [],
        }),
        "no API-call artifacts means no derived traits — never a \
         fabricated list"
    );

    // A differently-spelled name finds the same binary — the server
    // compares names ignoring case, as it does everywhere — and the
    // response reports the record's identity exactly as it is stored.
    let (status, body) = get_json(&format!("{base}/api/binaries/D3D9.DLL/pal-status")).await;
    assert_eq!(status, 200, "the lookup is case-insensitive");
    assert_eq!(
        body["binary"].as_str().expect("binary"),
        "d3d9.dll",
        "the verbatim record name answers, not the requested spelling"
    );

    // Unknown names honestly 404 — no empty shell.
    for name in ["nope.dll", "broken.dll"] {
        let (status, body) = get_json(&format!("{base}/api/binaries/{name}/pal-status")).await;
        assert_eq!(status, 404, "{name} has no readable classification record");
        assert_eq!(
            body["error"].as_bool(),
            Some(true),
            "{name}: the 404 carries the honest error payload"
        );
    }
}

/// Issue #134 honest-degradation contract. A corrupt function artifact
/// gives no category, while the readable ones still yield traits. With no
/// generated PAL or shim source anywhere, every needed trait honestly
/// reads as missing. With no readable API-call artifacts at all, the
/// payload is the honest empty list.
#[tokio::test]
async fn test_binaries_pal_status_honest_missing_and_corrupt_artifacts() {
    let fixture = TestFixture::new();
    write_binaries_list_fixtures(&fixture);
    write_pal_tracker_fixtures(&fixture);

    // No generated PAL/shim source anywhere: delete the scratch PAL
    // crate and the shim source.
    std::fs::remove_dir_all(fixture.repo_path().join("scratch"))
        .expect("scratch pal crate removed");
    std::fs::remove_file(
        fixture
            .repo_path()
            .join("re")
            .join("shims")
            .join("d3d9.dll")
            .join("shim.rs"),
    )
    .expect("shim source removed");

    // A second binary whose only readable artifact records an Audio
    // category — its other artifact is corrupt and gives nothing.
    let classify = fixture.repo_path().join("re").join("classify");
    std::fs::write(
        classify.join("ogg.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "ogg.dll",
            "category": "KnownThirdParty",
            "strategy": "CrateReplacement",
            "exports_count": 10,
            "imports_count": 1,
            "crate_replacement": "ogg-rs",
            "known_runtime": false,
            "reason": "audio codec — replaced with ogg-rs"
        }))
        .unwrap(),
    )
    .expect("ogg classification written");
    let ogg_dir = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("ogg.dll");
    std::fs::create_dir_all(&ogg_dir).expect("ogg analysis dir");
    std::fs::write(
        ogg_dir.join("PlaySample.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "function_name": "PlaySample",
            "windows_apis": [
                { "name": "waveOutWrite", "category": "Audio", "pal_mapping": "cpal" }
            ]
        }))
        .unwrap(),
    )
    .expect("PlaySample artifact written");
    std::fs::write(ogg_dir.join("broken.json"), "not json at all")
        .expect("corrupt artifact written");

    // A third binary whose every artifact is corrupt: no artifact at all.
    let dsound_dir = fixture
        .repo_path()
        .join("re")
        .join("analysis")
        .join("dsound.dll");
    std::fs::create_dir_all(&dsound_dir).expect("dsound analysis dir");
    std::fs::write(dsound_dir.join("DirectSoundCreate.json"), "{{{")
        .expect("corrupt artifact written");
    std::fs::write(
        classify.join("dsound.dll.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "binary": "dsound.dll",
            "category": "WindowsOs",
            "strategy": "PalMapping",
            "exports_count": 8,
            "imports_count": 2,
            "known_runtime": false,
            "reason": "Windows OS dll — PAL mapping"
        }))
        .unwrap(),
    )
    .expect("dsound classification written");

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());

    // The needed traits still appear (the corrupt d3d9 artifact gave
    // nothing); with no generated PAL or shim source every trait honestly
    // reads as missing.
    let (status, body) = get_json(&format!("{base}/api/binaries/d3d9.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "d3d9.dll",
            "traits": [
                { "name": "GraphicsDevice", "categories": ["DirectX", "DirectX11"], "exists": false },
                { "name": "PlatformCore", "categories": ["Win32Core"], "exists": false },
            ],
        }),
        "no generated PAL/shim source means every needed trait is \
         honestly missing"
    );

    // The corrupt artifact is skipped; the readable one still counts.
    let (status, body) = get_json(&format!("{base}/api/binaries/ogg.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "ogg.dll",
            "traits": [
                { "name": "AudioDevice", "categories": ["Audio"], "exists": false },
            ],
        }),
        "a corrupt artifact names no category; the readable one still answers"
    );

    // Every artifact corrupt: the honest empty payload.
    let (status, body) = get_json(&format!("{base}/api/binaries/dsound.dll/pal-status")).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "binary": "dsound.dll",
            "traits": [],
        }),
        "corrupt artifacts are no artifacts — the trait list stays empty"
    );
}

// ── Unit attempts API (issue #131, W4.5) ───────────────────────────────

/// Issue #131 router contract: `/api/units/{id}/attempts` is in the shared
/// routes, so both the plain `serve` router and the live router answer it.
/// It reads only saved history, never live pipeline state. The fixture's
/// two DrawPrimitive branches and two patch records make up the attempt
/// set; with no token or fault log written, the metadata fields honestly
/// stay absent rather than showing zero.
#[tokio::test]
async fn test_unit_attempts_registered_in_plain_and_live_routers() {
    for kind in ["plain", "live"] {
        let fixture = TestFixture::new();
        let state = ServerState::new(fixture.repo_path());
        let router = if kind == "plain" {
            build_router(state)
        } else {
            let events = TranslationEvents::new(128);
            let manager = SessionManager::new_with_broadcast(events.subscribe());
            build_router_with_ws(state, manager, ProgressState::new(), ws_actions(&fixture))
        };
        let _server = spawn_server(router, fixture.port()).await;

        tokio::time::sleep(Duration::from_millis(200)).await;

        let base = format!("http://127.0.0.1:{}", fixture.port());
        let (status, body) = get_json(&format!(
            "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts"
        ))
        .await;
        assert_eq!(
            status, 200,
            "{kind} router serves /api/units/{{id}}/attempts"
        );
        assert_eq!(
            body["unit_id"].as_str().expect("unit_id"),
            "game_logic.dll/DrawPrimitive/v2"
        );
        let attempts = body["attempts"].as_array().expect("attempts array");
        assert_eq!(attempts.len(), 2, "{kind} router: both persisted attempts");
        assert!(body["comparable"].as_bool().expect("comparable"));
        let v1 = &attempts[0];
        assert_eq!(v1["attempt"].as_u64().expect("attempt"), 1);
        assert_eq!(
            v1["branch"].as_str().expect("branch"),
            "re/game_logic.dll/DrawPrimitivev1"
        );
        assert!(
            v1.get("strategy").is_none() && v1.get("tokens_used").is_none(),
            "{kind} router: no token log means absent fields, not zeros"
        );
        assert_eq!(v1["commit_hash"].as_str().expect("commit_hash"), "abc123");
    }
}

/// The exact-JSON pin for the attempt join. The result is the union of the
/// fixture's branches and patch records, including a v3 branch made in the
/// test that has no patch record. The token-log lookup ignores case
/// ("GAME_LOGIC.DLL"). For the attempt the token log never recorded, the
/// fault log supplies the strategy. Where both logs name an attempt, the
/// token log wins. Metadata that is absent is left out of the response.
#[tokio::test]
async fn test_unit_attempts_api_exact_json_from_fixture() {
    let fixture = TestFixture::new();

    // A third attempt that exists only as a branch — no patch record, no
    // token entry — so this pins the other half of the union: none dropped.
    let git = GitManager::open(&fixture.repo_path()).expect("open fixture repo");
    git.create_branch("game_logic.dll", "DrawPrimitive", 3, None)
        .expect("v3 branch");

    write_token_usage_fixture(
        &fixture.repo_path(),
        &[
            token_usage_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "initial",
                4000,
                false,
                "stub",
                1759053600,
            ),
            // The differently-spelled binary must still match, ignoring case.
            token_usage_entry(
                "GAME_LOGIC.DLL",
                "DrawPrimitive",
                2,
                "escalate",
                2500,
                true,
                "with_tests",
                1759059000,
            ),
            // Same attempt number, different function — must not match.
            token_usage_entry(
                "game_logic.dll",
                "UpdateScene",
                1,
                "initial",
                999,
                true,
                "stub",
                1759053600,
            ),
        ],
    );
    write_fault_log_fixture(
        &fixture.repo_path(),
        &[
            // Also names attempt 1 — where both logs have it, the token log wins.
            fault_entry(
                "game_logic.dll",
                "DrawPrimitive",
                1,
                "compile_fix",
                "infinite_loop",
                "critical",
                1759053700,
            ),
            // The only source that gives attempt 3's strategy.
            fault_entry(
                "game_logic.dll",
                "DrawPrimitive",
                3,
                "test_fix",
                "behavior_divergence",
                "warning",
                1759060000,
            ),
        ],
    );

    let state = ServerState::new(fixture.repo_path());
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let base = format!("http://127.0.0.1:{}", fixture.port());
    let (status, body) = get_json(&format!(
        "{base}/api/units/game_logic.dll%2FDrawPrimitive%2Fv2/attempts"
    ))
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        serde_json::json!({
            "unit_id": "game_logic.dll/DrawPrimitive/v2",
            "attempts": [
                {
                    "attempt": 1,
                    "branch": "re/game_logic.dll/DrawPrimitivev1",
                    "strategy": "initial",
                    "context_tier": "stub",
                    "tokens_used": 4000,
                    "success": false,
                    "compiled": true,
                    "compilation_errors": [],
                    "commit_hash": "abc123",
                    "committed_at": "2025-09-28T10:00:00Z",
                },
                {
                    "attempt": 2,
                    "branch": "re/game_logic.dll/DrawPrimitivev2",
                    "strategy": "escalate",
                    "context_tier": "with_tests",
                    "tokens_used": 2500,
                    "success": true,
                    "compiled": false,
                    "compilation_errors": ["mismatched types"],
                    "tests_failed": 1,
                    "test_failures": ["shader_constant_map_wrong"],
                    "commit_hash": "def456",
                    "committed_at": "2025-09-28T11:30:00Z",
                },
                {
                    "attempt": 3,
                    "branch": "re/game_logic.dll/DrawPrimitivev3",
                    "strategy": "test_fix",
                },
            ],
            "comparable": true,
        }),
        "the attempt set is the union of branches and patch records, the \
         token log joins case-insensitively and wins over the fault log, \
         and every absent source leaves its field off the wire"
    );
}

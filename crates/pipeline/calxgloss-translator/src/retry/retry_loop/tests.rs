// Tests for the module above, split out of the file they test.
use super::*;
use crate::retry::is_edge_case_failure;
use crate::retry::{
    EscalatePromptCtx, FixPromptCtx, build_compile_fix_prompt,
    build_failure_informed_compile_fix_prompt, build_failure_informed_edge_case_fix_prompt,
    build_failure_informed_escalate_prompt, build_failure_informed_test_fix_prompt,
    build_test_fix_prompt,
};

#[test]
fn test_retry_config_default() {
    let config = RetryConfig::default();
    assert_eq!(config.max_attempts, 3);
    assert_eq!(config.retry_strategy, RetryStrategy::CompileFix);
    assert!(config.escalate_on_failure);
}

#[test]
fn test_translation_attempt_is_successful() {
    let mut attempt = TranslationAttempt {
        attempt: 1,
        rust_code: "fn foo() {}".to_string(),
        compiled: true,
        compilation_errors: Vec::new(),
        tests_passed: 5,
        tests_total: 5,
        failed_tests: Vec::new(),
        retry_strategy: "initial".to_string(),
        tokens_used: Some(1024),
        context_tier: None,
    };
    assert!(attempt.is_successful());

    attempt.tests_passed = 4;
    assert!(!attempt.is_successful());

    // No tests = successful by definition
    attempt.tests_passed = 0;
    attempt.tests_total = 0;
    assert!(attempt.is_successful());

    // But code that doesn't compile is never successful, even with no tests.
    attempt.compiled = false;
    assert!(!attempt.is_successful());
}

#[test]
fn test_retry_result_new() {
    let result = RetryResult::new();
    assert!(!result.success);
    assert!(result.rust_code.is_none());
    assert!(result.attempts.is_empty());
}

#[test]
fn test_retry_result_add_successful_attempt() {
    let mut result = RetryResult::new();
    result.add_attempt(TranslationAttempt {
        attempt: 1,
        rust_code: "fn foo() -> i32 { 42 }".to_string(),
        compiled: true,
        compilation_errors: Vec::new(),
        tests_passed: 3,
        tests_total: 3,
        failed_tests: Vec::new(),
        retry_strategy: "initial".to_string(),
        tokens_used: Some(512),
        context_tier: None,
    });
    assert!(result.success);
    assert!(result.rust_code.is_some());
    assert_eq!(
        result.rust_code.as_deref().unwrap(),
        "fn foo() -> i32 { 42 }"
    );
    assert_eq!(result.success_strategy.as_deref().unwrap(), "initial");
}

#[test]
fn test_build_compile_fix_prompt() {
    let prompt = build_compile_fix_prompt(&FixPromptCtx {
        function_name: "entry".to_string(),
        dll_name: "eqmain.dll".to_string(),
        original_rust_code: "fn entry() { __security_init_cookie(); }".to_string(),
        compilation_errors: vec!["error[E0425]: not found: `__security_init_cookie`".to_string()],
        failed_tests: Vec::new(),
        history: Vec::new(),
    });
    assert!(prompt.contains("entry"));
    assert!(prompt.contains("eqmain.dll"));
    assert!(prompt.contains("__security_init_cookie"));
    assert!(prompt.contains("E0425"));
}

#[test]
fn test_build_test_fix_prompt() {
    let prompt = build_test_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
        compilation_errors: Vec::new(),
        failed_tests: vec![
            "Test 0: expected 42, got 10 — input was 10".to_string(),
            "Test 1: expected 0, got 5 — input was 5".to_string(),
        ],
        history: Vec::new(),
    });
    assert!(prompt.contains("DrawSprite"));
    assert!(prompt.contains("expected 42"));
    assert!(prompt.contains("expected 0"));
}

#[test]
fn test_is_edge_case_failure_boundary() {
    let failed = vec![
        "Test 0: expected 0, got 1 — input was 0 (zero check)".to_string(),
        "Test 1: expected 2147483647, got 0 — input was max (overflow)".to_string(),
    ];
    assert!(is_edge_case_failure(&failed, 0, 2));
}

#[test]
fn test_is_edge_case_failure_normal_failure() {
    let failed = vec![
        "Test 0: expected 100, got 50 — wrong multiplication".to_string(),
        "Test 1: expected 200, got 100 — wrong addition".to_string(),
    ];
    assert!(!is_edge_case_failure(&failed, 0, 2));
}

#[test]
fn test_is_edge_case_failure_mixed() {
    // Mixed: 2 boundary + 1 normal — should be edge case (majority)
    let failed = vec![
        "Test 0: expected 0, got 1 — zero input".to_string(),
        "Test 1: expected 0, got -1 — negative input".to_string(),
        "Test 2: expected 100, got 50 — wrong value".to_string(),
    ];
    assert!(is_edge_case_failure(&failed, 0, 3));
}

#[test]
fn test_is_edge_case_failure_all_passed() {
    let failed: Vec<String> = vec![];
    assert!(!is_edge_case_failure(&failed, 5, 5));
}

// ============================================================
// Failure-informed prompt builder tests
// ============================================================

#[test]
fn test_failure_informed_compile_fix_includes_history() {
    let hints = vec![
        FailureHint::new(
            1,
            "compile_fix",
            "Compilation failed: E0425 — `__security_init_cookie` not found",
        ),
        FailureHint::new(2, "test_fix", "Wrong result on boundary input"),
    ];

    let prompt = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
        function_name: "entry".to_string(),
        dll_name: "eqmain.dll".to_string(),
        original_rust_code: "fn entry() { __security_init_cookie(); }".to_string(),
        compilation_errors: vec!["error[E0425]: not found: `__security_init_cookie`".to_string()],
        failed_tests: Vec::new(),
        history: hints,
    });

    assert!(prompt.contains("entry"));
    assert!(prompt.contains("eqmain.dll"));
    assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
    assert!(prompt.contains("Attempt #1"));
    assert!(prompt.contains("compile_fix"));
    assert!(prompt.contains("Attempt #2"));
    assert!(prompt.contains("test_fix"));
}

#[test]
fn test_failure_informed_compile_fix_empty_history() {
    let prompt = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
        function_name: "entry".to_string(),
        dll_name: "eqmain.dll".to_string(),
        original_rust_code: "fn entry() { }".to_string(),
        compilation_errors: vec!["error[E0425]: not found: `foo`".to_string()],
        failed_tests: Vec::new(),
        history: Vec::new(), // empty history — should not include history section
    });

    assert!(prompt.contains("entry"));
    assert!(!prompt.contains("PREVIOUS ATTEMPT HISTORY"));
}

#[test]
fn test_failure_informed_test_fix_includes_history() {
    let hints = vec![FailureHint::new(
        1,
        "compile_fix",
        "Compilation failed: E0412",
    )];

    let prompt = build_failure_informed_test_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
        compilation_errors: Vec::new(),
        failed_tests: vec!["Test 0: expected 42, got 10 — input was 10".to_string()],
        history: hints,
    });

    assert!(prompt.contains("DrawSprite"));
    assert!(prompt.contains("game_logic.dll"));
    assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
    assert!(prompt.contains("compile_fix"));
    assert!(prompt.contains("Compilation failed: E0412"));
}

#[test]
fn test_failure_informed_edge_case_fix_includes_history() {
    let hints = vec![
        FailureHint::new(1, "test_fix", "Wrong result on zero input"),
        FailureHint::new(2, "escalate", "Still wrong on zero after adding context"),
    ];

    let failed_tests = vec![calxgloss_prompts::EdgeCaseTest {
        index: 1,
        inputs: serde_json::json!({"x": 0}),
        expected: serde_json::json!(0),
        actual: serde_json::json!(1),
        error: "Expected 0, got 1".to_string(),
        disassembly_hints: "cmp eax, 0\nje .zero_branch".to_string(),
    }];

    let prompt = build_failure_informed_edge_case_fix_prompt(
        &FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: "fn draw_sprite(x: i32) -> i32 { x + 1 }".to_string(),
            compilation_errors: Vec::new(),
            failed_tests: Vec::new(),
            history: hints,
        },
        &failed_tests,
    );

    assert!(prompt.contains("DrawSprite"));
    assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
    assert!(prompt.contains("Learn from past failures"));
}

// ─── Attempt-duration recording (issue #64) ──────────────────────

/// A fake LLM server that sleeps ~1.1s before answering with empty code
/// and a token count, so the retry loop's wall-clock measurement for the
/// attempt is guaranteed to be at least one second. Returns the base URL
/// to point an [`LlmClient`] at.
async fn fake_llm() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake LLM should bind");
    let addr = listener.local_addr().expect("fake LLM address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                // Make the attempt measurably slow so the recorded
                // duration is >= 1s rather than rounding to 0.
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                let body = r#"{"choices":[{"message":{"role":"assistant","content":""}}],"usage":{"completion_tokens":123,"total_tokens":123}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn retry_loop_records_attempt_duration_in_token_usage_log() {
    let ws = tempfile::TempDir::new().expect("temp workspace");

    // Broken initial code → attempt 1 fails compile → retry loop runs.
    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: Vec::new(),
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    let llm_base = fake_llm().await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let config = RetryConfig {
        max_attempts: 2,
        retry_strategy: RetryStrategy::CompileFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };

    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: None,
        resource_detector: None,
        fault_logger: None,
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;
    assert!(
        !result.success,
        "the canned LLM returns empty code; attempts={:?}",
        result.attempts
    );

    let log = calxgloss_analysis::TokenUsageLogger::new(ws.path())
        .load()
        .expect("token usage log should exist");

    let entry = log
        .entries
        .iter()
        .find(|e| e.attempt == 2)
        .expect("attempt 2 should be logged");
    assert_eq!(entry.strategy, "compile_fix");
    assert_eq!(entry.tokens_used, 123);
    assert!(
        entry.duration_secs.is_some_and(|d| d >= 1),
        "attempt duration should be recorded and >= 1s, got {:?}",
        entry.duration_secs
    );
}

// ─── The loop uses the seam: today's event stream, zero divergence ───
// (issue #332 — the deleted probe's absence is pinned here too)

/// A canned LLM server answering the first call with broken code and
/// every later call with code that compiles — the canned failing-then-
/// succeeding run the event stream is captured over.
async fn flaky_llm() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("flaky LLM should bind");
    let addr = listener.local_addr().expect("flaky LLM address");
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_server = calls;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let calls = calls_server.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let content = if n == 0 {
                    "fn draw_sprite(x: i32) -> i32 { let y: = ; x }"
                } else {
                    "fn draw_sprite(x: i32) -> i32 { x }"
                };
                let body = format!(
                    "{{\"choices\":[{{\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}}}}],\"usage\":{{\"completion_tokens\":123,\"total_tokens\":123}}}}"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn retry_loop_streams_todays_event_order_and_records_no_divergence() {
    let ws = tempfile::TempDir::new().expect("temp workspace");

    // Broken initial code → attempt 1 fails compile; attempt 2 gets the
    // canned broken fix (verification fails, ladder stays put because
    // escalation is off); attempt 3 gets the canned compiling fix and
    // the run stops passed.
    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: Vec::new(),
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    let llm_base = flaky_llm().await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let fault_logger = calxgloss_analysis::FaultLogger::new(ws.path());
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();
    let config = RetryConfig {
        max_attempts: 3,
        retry_strategy: RetryStrategy::CompileFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };

    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: Some(&fault_logger),
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;
    assert!(
        result.success,
        "the canned fix should pass on attempt 3, attempts={:?}",
        result.attempts
    );
    assert_eq!(result.attempts.len(), 3);

    // The run is over — everything published is queued; drain the stream.
    let mut captured: Vec<calxgloss_types::ProgressEvent> = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        captured.push(ev);
    }

    // Today's per-attempt ordering on both retry attempts: every LLM
    // attempt streams request → call-start → response → completed.
    let streamed: Vec<(u32, &'static str)> = captured
        .iter()
        .filter_map(|ev| match ev {
            ProgressEvent::LlmRequest { attempt, .. } => Some((*attempt, "request")),
            ProgressEvent::LlmCallStart { attempt, .. } => Some((*attempt, "call-start")),
            ProgressEvent::LlmResponse { attempt, .. } => Some((*attempt, "response")),
            ProgressEvent::TranslationAttemptCompleted { attempt, .. } => {
                Some((*attempt, "completed"))
            }
            _ => None,
        })
        .collect();
    for num in [2u32, 3] {
        let per_attempt: Vec<&str> = streamed
            .iter()
            .filter(|(a, _)| *a == num)
            .map(|(_, name)| *name)
            .collect();
        assert_eq!(
            per_attempt,
            vec!["request", "call-start", "response", "completed"],
            "attempt {num} should stream request → call-start → response → completed, full stream: {streamed:?}"
        );
    }

    // Today's payloads on the completion events: strategy names and the
    // verdicts, attempt 1 riding verify_and_record untouched.
    let completions: Vec<(u32, String, bool)> = captured
        .iter()
        .filter_map(|ev| match ev {
            ProgressEvent::TranslationAttemptCompleted {
                attempt,
                retry_strategy,
                success,
                ..
            } => Some((*attempt, retry_strategy.clone(), *success)),
            _ => None,
        })
        .collect();
    assert_eq!(
        completions,
        vec![
            (1, "initial".to_string(), false),
            (2, "compile_fix".to_string(), false),
            (3, "compile_fix".to_string(), true),
        ]
    );

    // #333: the dispatched compile_fix prompt equals the pre-adapter
    // inline arm's result byte for byte — same recipe, same inputs,
    // demanded identical.
    let sent: std::collections::BTreeMap<u32, String> = captured
        .iter()
        .filter_map(|ev| match ev {
            ProgressEvent::LlmRequest {
                attempt, prompt, ..
            } => Some((*attempt, prompt.clone())),
            _ => None,
        })
        .collect();
    let expected2 = build_compile_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
        compilation_errors: result.attempts[0].compilation_errors.clone(),
        failed_tests: Vec::new(),
        history: Vec::new(),
    });
    assert_eq!(
        sent[&2], expected2,
        "the dispatched compile_fix prompt must be byte-identical to the pre-adapter arm's"
    );
    // By attempt 3 the seam's push from attempt 2's failed verification
    // seeds the history, and the verdict is attempt 2's own record
    // (#334's routing — the canned code matches the initial one here,
    // bytes and all), so the informed variant is the plain variant's
    // only difference — rebuild it the same way and demand equality.
    let expected3 = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: result.attempts[1].rust_code.clone(),
        compilation_errors: result.attempts[1].compilation_errors.clone(),
        failed_tests: Vec::new(),
        history: vec![FailureHint::new(
            2,
            "compile_fix",
            format!(
                "Compilation failed: {}",
                result.attempts[1].compilation_errors.join("; ")
            ),
        )],
    });
    assert_eq!(
        sent[&3], expected3,
        "attempt 3's dispatched informed-variant prompt must match the pre-adapter recipe bytes"
    );

    // The deleted probes fabricated all-true edge results against a
    // detector that reports only failing edges — they could never fire.
    // A passing verified run pins their absence: zero divergence events
    // on the stream and zero divergence faults in the log.
    assert!(
        !captured
            .iter()
            .any(|ev| matches!(ev, ProgressEvent::BehaviorDivergenceDetected { .. })),
        "no divergence event may appear on a passing verified run"
    );
    let faults = calxgloss_analysis::FaultLogger::new(ws.path())
        .load()
        .map(|l| l.entries)
        .unwrap_or_default();
    assert!(
        !faults.iter().any(|f| matches!(
            f.category,
            calxgloss_types::FaultCategory::BehaviorDivergence
        )),
        "no divergence fault may be recorded, faults={faults:?}"
    );
}

/// A canned LLM server alternating between the initial broken code and
/// a broken variant one identifier apart on every call — every attempt
/// still fails verification, so the strategy ladder walks its full
/// cycle, but consecutive attempts never produce the same output three
/// times running and the infinite-loop detector — which now stops the
/// chain wherever it fires (#334) — stays quiet through the run.
async fn alternating_broken_llm() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("canned LLM should bind");
    let addr = listener.local_addr().expect("canned LLM address");
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_server = calls;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let n = calls_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let content = if n % 2 == 0 {
                    "fn draw_sprite(x: i32) -> i32 { let y: = ; x }"
                } else {
                    "fn draw_sprite(x: i32) -> i32 { let z: = ; x }"
                };
                let body = format!(
                    "{{\"choices\":[{{\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}}}}],\"usage\":{{\"completion_tokens\":123,\"total_tokens\":123}}}}"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn strategy_ladder_walks_the_full_cycle_quoting_each_attempts_own_verdict() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let broken = "fn draw_sprite(x: i32) -> i32 { let y: = ; x }";

    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: broken.to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: Vec::new(),
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    let llm_base = alternating_broken_llm().await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();

    // The cap pins the tier at Signature — Signature's next tier would
    // breach it — so no attempt ever takes the tier-escalated path and
    // the ladder's compile_fix → test_fix → escalate walk is what
    // dispatches all three retry prompts.
    let config = RetryConfig {
        max_attempts: 6,
        retry_strategy: RetryStrategy::CompileFix,
        escalate_on_failure: true,
        max_context_tier: Some(calxgloss_types::ContextTier::Signature),
    };

    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: None,
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;
    assert!(
        !result.success,
        "the canned code is broken on every attempt"
    );
    assert_eq!(result.attempts.len(), 6);
    assert_eq!(result.attempts[1].retry_strategy, "compile_fix");
    assert_eq!(result.attempts[2].retry_strategy, "test_fix");
    assert_eq!(result.attempts[3].retry_strategy, "escalate");
    assert_eq!(result.attempts[4].retry_strategy, "edge_case_fix");
    assert_eq!(result.attempts[5].retry_strategy, "compile_fix");

    let mut captured: Vec<calxgloss_types::ProgressEvent> = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        captured.push(ev);
    }
    assert!(
        !captured
            .iter()
            .any(|ev| matches!(ev, ProgressEvent::InfiniteLoopDetected { .. })),
        "alternating outputs must not streak the detector to a fire — one would stop the chain (#334)"
    );
    let sent: std::collections::BTreeMap<u32, String> = captured
        .iter()
        .filter_map(|ev| match ev {
            ProgressEvent::LlmRequest {
                attempt, prompt, ..
            } => Some((*attempt, prompt.clone())),
            _ => None,
        })
        .collect();

    // #334: each fix prompt is built from the verdict of the code it
    // repairs — the previous attempt's recorded evidence, routed — and
    // replaces that attempt's own code. Rebuild every prompt through
    // the builders from the recorded routed inputs and demand byte
    // equality; the recipe reads the loop's own records, so it pins
    // the routing exactly.

    // Attempt 2, compile_fix — history still empty, plain variant;
    // the verdict is the initial attempt's own record.
    let initial_errors = result.attempts[0].compilation_errors.clone();
    assert!(
        !initial_errors.is_empty(),
        "the broken start must not compile"
    );
    let expected = build_compile_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: broken.to_string(),
        compilation_errors: initial_errors.clone(),
        failed_tests: Vec::new(),
        history: Vec::new(),
    });
    assert_eq!(sent[&2], expected, "attempt 2 compile_fix prompt");

    // Attempt 3, test_fix — attempt 2's candidate (the canned code,
    // identical to the initial) failed, so this prompt quotes THAT
    // record's evidence and repairs that code; the seam's push after
    // attempt 2 seeds the history. No re-verification feeds this
    // prompt anymore — the record is the payload.
    let history3 = vec![FailureHint::new(
        2,
        "compile_fix",
        format!(
            "Compilation failed: {}",
            result.attempts[1].compilation_errors.join("; ")
        ),
    )];
    let expected = build_failure_informed_test_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: result.attempts[1].rust_code.clone(),
        compilation_errors: Vec::new(),
        failed_tests: result.attempts[1].failed_tests.clone(),
        history: history3.clone(),
    });
    assert_eq!(sent[&3], expected, "attempt 3 test_fix prompt");

    // Attempt 4, escalate — attempt 3's candidate was the *other*
    // broken variant, so this prompt quotes the variant's own compile
    // errors and repairs the variant's code, and the history carries
    // both pushes.
    let history4: Vec<FailureHint> = history3
        .into_iter()
        .chain(std::iter::once(FailureHint::new(
            3,
            "test_fix",
            format!(
                "Compilation failed: {}",
                result.attempts[2].compilation_errors.join("; ")
            ),
        )))
        .collect();
    let variant_errors = result.attempts[2].compilation_errors.clone();
    let failure_description = format!(
        "Compilation failed with {} error(s):\n\n{}",
        variant_errors.len(),
        variant_errors.join("\n\n")
    );
    let expected = build_failure_informed_escalate_prompt(EscalatePromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: result.attempts[2].rust_code.clone(),
        failure_description,
        source: source.clone(),
        address: 0,
        call_graph: Vec::new(),
        history: history4.clone(),
        call_graph_context: Vec::new(),
        workspace: Some(ws.path().to_path_buf()),
        seam_report: calxgloss_types::CapabilityReport::default(),
    })
    .await;
    assert_eq!(sent[&4], expected, "attempt 4 escalate prompt");

    // Attempt 5, edge_case_fix — attempt 4's candidate was the initial
    // variant again and did not compile, so there are no structured
    // failing cases to carry: nothing fabricates a placeholder from a
    // re-run anymore, the payload is simply the verdict's empty slice.
    let history5: Vec<FailureHint> = history4
        .into_iter()
        .chain(std::iter::once(FailureHint::new(
            4,
            "escalate",
            format!(
                "Compilation failed: {}",
                result.attempts[3].compilation_errors.join("; ")
            ),
        )))
        .collect();
    let expected = build_failure_informed_edge_case_fix_prompt(
        &FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: result.attempts[3].rust_code.clone(),
            compilation_errors: Vec::new(),
            failed_tests: Vec::new(),
            history: history5.clone(),
        },
        &[],
    );
    assert_eq!(sent[&5], expected, "attempt 5 edge_case_fix prompt");

    // Attempt 6, the cycle back to compile_fix — attempt 5's variant
    // verdict and code, with the full history.
    let history6: Vec<FailureHint> = history5
        .into_iter()
        .chain(std::iter::once(FailureHint::new(
            5,
            "edge_case_fix",
            format!(
                "Compilation failed: {}",
                result.attempts[4].compilation_errors.join("; ")
            ),
        )))
        .collect();
    let expected = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: result.attempts[4].rust_code.clone(),
        compilation_errors: result.attempts[4].compilation_errors.clone(),
        failed_tests: Vec::new(),
        history: history6,
    });
    assert_eq!(sent[&6], expected, "attempt 6 compile_fix prompt");

    // #334's routing, visible in the wire bytes: attempt 4's fix slot
    // names attempt 3's own variant — the initial code it replaces is
    // gone from that section.
    let section4 = original_section(&sent[&4]);
    assert!(
        section4.contains("let z: = ; x"),
        "the escalate prompt must repair attempt 3's own code, not the initial one:\n{section4}"
    );
    assert!(
        !section4.contains("let y: = ; x"),
        "the replaced initial code must not sit in attempt 4's repair slot:\n{section4}"
    );
}

/// The "ORIGINAL TRANSLATION (FAILED)" section of a fix prompt — the
/// code the prompt tells the LLM to replace.
fn original_section(prompt: &str) -> &str {
    const HEADER: &str = "## ORIGINAL TRANSLATION (FAILED)";
    let start = prompt
        .find(HEADER)
        .expect("fix prompts carry the failing code section");
    let rest = &prompt[start + HEADER.len()..];
    let end = rest.find("\n## ").unwrap_or(rest.len());
    &rest[..end]
}

/// A canned LLM server answering every call with the same code — the
/// same-output run that streaks the infinite-loop detector, or the
/// compiling-but-failing run a suite pins over.
async fn same_code_llm(content: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("canned LLM should bind");
    let addr = listener.local_addr().expect("canned LLM address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let body = format!(
                    "{{\"choices\":[{{\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}}}}],\"usage\":{{\"completion_tokens\":123,\"total_tokens\":123}}}}"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// A canned LLM server naming each reply with its own marker — every
/// attempt fails to compile for its OWN reason (an unresolved name),
/// so each attempt's recorded errors quote its own source and the
/// routing can be told apart from the initial translation's evidence.
async fn marker_rotating_llm() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("canned LLM should bind");
    let addr = listener.local_addr().expect("canned LLM address");
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_server = calls;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let n = calls_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let content = if n == 0 {
                    "fn draw_sprite(x: i32) -> i32 { marker_alpha(x) }"
                } else {
                    "fn draw_sprite(x: i32) -> i32 { marker_beta(x) }"
                };
                let body = format!(
                    "{{\"choices\":[{{\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}}}}],\"usage\":{{\"completion_tokens\":123,\"total_tokens\":123}}}}"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// #334 criterion 1, end to end: the initial translation goes through the
/// seam with its baseline suite — a merely-compiling unit with a non-
/// empty suite is NOT done. The attempt-1 record carries the suite's real
/// counts, the run reports failure, and the retry prompt is the test-fix
/// one built from that verdict's payload. (The scratch toolchain's suite
/// runner currently fails to build — a verify-crate defect out of this
/// ticket's scope — so the honest verdict lands as 0-of-1 with no per-
/// case lines; what is pinned is that the suite was consulted at all and
/// the record tells the truth about it, which is what closes the compile-
/// only success hole.)
#[tokio::test]
async fn a_compiling_unit_with_a_failing_suite_is_not_reported_success() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let good = "fn draw_sprite(x: i32) -> i32 { x + 1 }";

    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: good.to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: vec![calxgloss_types::TestCase {
            inputs: serde_json::json!([5]),
            expected_return: serde_json::json!(4),
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
        }],
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    // The canned fix compiles too — with the runner defect nothing can
    // pass, and max_attempts 2 keeps the run inside the detector's
    // streak threshold whatever the code.
    let llm_base = same_code_llm(good).await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();

    let config = RetryConfig {
        max_attempts: 2,
        retry_strategy: RetryStrategy::TestFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };
    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: None,
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;

    assert!(
        !result.success,
        "a compiling unit whose baseline suite failed is not done — the compile-only hole is closed"
    );
    assert_eq!(
        result.attempts.len(),
        2,
        "the failing suite leads to a retry"
    );
    let first = &result.attempts[0];
    assert_eq!(first.retry_strategy, "initial");
    assert!(first.compiled, "the code does compile");
    assert_eq!(
        first.tests_total, 1,
        "the attempt-1 record carries the suite's real size"
    );
    assert_eq!(
        first.tests_passed, 0,
        "and honestly reports the suite as failed"
    );
    assert_eq!(result.attempts[1].retry_strategy, "test_fix");

    // The retry prompt is the test-fix one, byte-built from the
    // attempt-1 verdict's payload — the record's failed-test lines are
    // the payload, empty under the runner defect and named as such by
    // the builder's fallback.
    let sent: std::collections::BTreeMap<u32, String> = {
        let mut captured = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }
        captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => Some((*attempt, prompt.clone())),
                _ => None,
            })
            .collect()
    };
    let expected = build_test_fix_prompt(&FixPromptCtx {
        function_name: "DrawSprite".to_string(),
        dll_name: "game_logic.dll".to_string(),
        original_rust_code: first.rust_code.clone(),
        compilation_errors: Vec::new(),
        failed_tests: first.failed_tests.clone(),
        history: Vec::new(),
    });
    assert_eq!(
        sent[&2], expected,
        "the retry prompt is built from the initial verdict's payload"
    );
}

/// #386 criterion 3, through the seam: a baseline case whose value matches
/// but whose ordered surface calls diverge from the captured trace fails
/// on the trace dimension alone, and the failure routes into the next
/// attempt's test-fix prompt naming which call was substituted. The
/// expected trace here is exactly the fold's shape — a baseline capture of
/// `ReadFile → CreateFileA`, both in the API roster, spells to
/// `read → open` — and the body reaches the captured value 7 opening
/// before it reads: value clean, route wrong. (This pins the routing
/// carrying the divergence, end to end through the real verifier and
/// runner; the fold itself is pinned at the pipeline seam in
/// `pipeline/tests.rs`.)
#[tokio::test]
async fn a_trace_divergent_failed_test_routes_the_divergence_into_the_next_fix_prompt() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    const BODY: &str = r#"
pub fn call_no_params() -> serde_json::Value {
    let fs = FileSystemStub::default();
    let handle = fs.open("pin_trace.txt", FileMode::Read).expect("the stub open always works");
    let mut buf = [0u8; 8];
    let _ = fs.read(&handle, &mut buf);
    serde_json::Value::from(7)
}
"#;

    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "RestitchTrace".to_string(),
        function_address: None,
        rust_code: BODY.to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: vec![calxgloss_types::TestCase {
            inputs: serde_json::json!(null),
            expected_return: serde_json::json!(7),
            expected_side_effects: Vec::new(),
            expected_api_calls: vec!["read".to_string(), "open".to_string()],
        }],
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    // The canned LLM answers both calls with this body; max_attempts 2
    // keeps the run inside the streak threshold whatever the code.
    let llm_base = same_code_llm(BODY).await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();

    let config = RetryConfig {
        max_attempts: 2,
        retry_strategy: RetryStrategy::TestFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };
    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: None,
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;

    assert!(
        !result.success,
        "a value-matching unit whose call route diverges is not done"
    );
    let first = &result.attempts[0];
    assert!(first.compiled, "the body compiles in the scratch project");
    assert_eq!(first.tests_total, 1, "the folded case ran as the suite");
    let divergence = first
        .failed_tests
        .iter()
        .find(|line| line.contains("API-call trace divergence"));
    assert!(
        divergence.is_some(),
        "the value-clean case failing on the trace dimension records the divergence: {:?}",
        first.failed_tests
    );

    // Attempt 2's prompt — the test-fix one built from that verdict —
    // carries which call was substituted.
    let sent: std::collections::BTreeMap<u32, String> = {
        let mut captured = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }
        captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => Some((*attempt, prompt.clone())),
                _ => None,
            })
            .collect()
    };
    let prompt = &sent[&2];
    assert!(
        prompt.contains("API-call trace divergence at position 2"),
        "the next attempt's fix prompt carries the trace divergence:\n{prompt}"
    );
    assert!(
        prompt.contains("expected [read, open], got [open, read]"),
        "and it names exactly which call was substituted:\n{prompt}"
    );
}

/// #334 criterion 2, pinned through the captured request bodies: once
/// attempt N has failed, attempt N+1's prompt names N's OWN code and
/// quotes N's OWN failure evidence — the initial translation is no longer
/// the repair target or the evidence source. (The structured failing
/// cases of a tests-failed verdict go through the same routing; they are
/// pinned at seam and adapter level because this toolchain's suite runner
/// cannot produce real case lines — defect note above.)
#[tokio::test]
async fn fix_prompts_quote_the_latest_failed_attempts_code_and_evidence() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let start = "fn draw_sprite(x: i32) -> i32 { let q: = ; x }";

    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: start.to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: Vec::new(),
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    let llm_base = marker_rotating_llm().await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();

    let config = RetryConfig {
        max_attempts: 3,
        retry_strategy: RetryStrategy::CompileFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };
    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: None,
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;
    assert!(!result.success, "every canned variant is broken");
    assert_eq!(result.attempts.len(), 3);

    let sent: std::collections::BTreeMap<u32, String> = {
        let mut captured = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }
        captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => Some((*attempt, prompt.clone())),
                _ => None,
            })
            .collect()
    };

    // Attempt 2 repairs the initial code — nothing has replaced it yet.
    let section2 = original_section(&sent[&2]);
    assert!(
        section2.contains("let q: = ; x"),
        "attempt 2 repairs the initial translation:\n{section2}"
    );

    // Attempt 3 repairs attempt 2's code — the alpha variant — and
    // quotes attempt 2's own errors: the marker names both the repair
    // slot and the error text, so it occurs at least twice.
    let section3 = original_section(&sent[&3]);
    assert!(
        section3.contains("marker_alpha"),
        "attempt 3 must repair attempt 2's own code:\n{section3}"
    );
    assert!(
        !section3.contains("let q: = ; x"),
        "the initial code is gone from attempt 3's repair slot:\n{section3}"
    );
    assert!(
        sent[&3].matches("marker_alpha").count() >= 2,
        "attempt 3's prompt must also quote attempt 2's own compile errors:\n{}",
        sent[&3]
    );
}

/// #334's "the verifier is asked exactly once per candidate code",
/// held at the source level: the retry loop module's own body never
/// asks the verifier anything — every verification belongs to the
/// attempt seam, and the re-verification arms are gone for good.
#[test]
fn retry_loop_never_reverifies_a_previous_attempts_code() {
    let src = include_str!("../retry_loop.rs");
    let body = src
        .split("#[cfg(test)]")
        .next()
        .expect("a module body ahead of the test module");
    let needle = concat!(".", "verify", "(");
    assert!(
        !body.contains(needle),
        "the retry loop body must not call the verifier itself (#334): the seam owns every verification"
    );
}

/// #334: a fired infinite-loop detector ends the chain wherever it lands.
/// Same canned code as the initial translation on every call — the
/// initial attempt goes through the detector too, so the third straight
/// identical failing output fires at attempt 3. Today's loop merely
/// observed the mid-chain fire; this one stops on it, leaving its one
/// event and one fault record as the whole story past attempt 3.
#[tokio::test]
async fn a_fired_loop_detector_ends_the_chain_where_it_lands() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let broken = "fn draw_sprite(x: i32) -> i32 { let y: = ; x }";

    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: broken.to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: Vec::new(),
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };

    let llm_base = same_code_llm(broken).await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let events = calxgloss_types::TranslationEvents::new(64);
    let mut rx = events.subscribe();
    let fault_logger = calxgloss_analysis::FaultLogger::new(ws.path());

    let config = RetryConfig {
        max_attempts: 6,
        retry_strategy: RetryStrategy::CompileFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };
    let seam_report = calxgloss_types::CapabilityReport::default();
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: Some(&fault_logger),
        reviewer_hints: &[],
        seam_report: &seam_report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;

    assert!(!result.success, "every output is the same broken code");
    assert_eq!(
        result.attempts.len(),
        3,
        "the chain stops at the firing attempt — no attempt 4"
    );

    let mut loop_events = 0;
    let mut requests = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev, ProgressEvent::InfiniteLoopDetected { .. }) {
            loop_events += 1;
        }
        if let ProgressEvent::LlmRequest { attempt, .. } = ev {
            requests.push(attempt);
        }
    }
    assert_eq!(loop_events, 1, "exactly one InfiniteLoopDetected event");
    assert_eq!(
        requests,
        vec![2, 3],
        "no fix request is built past the fire"
    );

    let faults = fault_logger.load().expect("fault log").entries;
    assert_eq!(faults.len(), 1, "one fault record for the fired detector");
    assert!(
        matches!(
            faults[0].category,
            calxgloss_types::FaultCategory::InfiniteLoop
        ),
        "the one fault is the loop fire, faults={faults:?}"
    );
}

// ---- #356: the capability-aware ladder — an escalate-shaped retry that
// would re-ask a family the report calls unavailable prunes/rotates, with
// the decision itself surviving as reviewable evidence ----

/// A hand-declared report stating `id` is unanswerable right now, with the
/// engine's own reason. The engine never declares this family, so a ladder
/// that walks differently is demonstrably deciding off the held report, not
/// the live seam.
fn unavailable_report(id: &str, reason: &str) -> calxgloss_types::CapabilityReport {
    calxgloss_types::CapabilityReport {
        families: vec![calxgloss_types::FamilyCapability {
            id: id.to_string(),
            status: calxgloss_types::AvailabilityStatus::Unavailable,
            reason: Some(reason.to_string()),
        }],
    }
}

/// One whole report-driven ladder run: what the walk recorded, what it
/// asked of the LLM and the seam, and what the stream said it chose.
struct CapLadderRun {
    result: RetryResult,
    kuna: calxgloss_kuna::KunaSource,
    prompts: std::collections::BTreeMap<u32, String>,
    completions: Vec<(u32, String)>,
    tier_steps: Vec<String>,
}

async fn run_ladder_with_report(
    report: calxgloss_types::CapabilityReport,
    max_attempts: u32,
    max_context_tier: Option<calxgloss_types::ContextTier>,
) -> CapLadderRun {
    run_ladder_prepared(report, max_attempts, max_context_tier, |_| {}).await
}

/// The same ladder run, with a hook that stages workspace documents
/// before the batch starts — what a real workspace would already hold
/// when the ladder reads it (issue #370's unknowns ledger pin files its
/// fixture here). The captured prompts are exactly what the web LLM
/// I/O log records, so they prove what the model actually received.
async fn run_ladder_prepared(
    report: calxgloss_types::CapabilityReport,
    max_attempts: u32,
    max_context_tier: Option<calxgloss_types::ContextTier>,
    prepare: impl FnOnce(&std::path::Path),
) -> CapLadderRun {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    prepare(ws.path());
    // Today's ladder-pin unit, with a real fixture function in the call
    // graph so a rung that does re-ask the seam leaves its mark in the
    // engine-call log.
    let translation = Translation {
        binary: "game_logic.dll".to_string().into(),
        function: "DrawSprite".to_string(),
        function_address: None,
        rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
        prompt_used: "prompt".to_string(),
        model: "test-model".to_string(),
        tokens_used: Some(10),
        baseline_tests: Vec::new(),
        call_graph: vec!["UpdateScene".to_string()],
        disassembly_hints: Vec::new(),
        context_tier: calxgloss_types::ContextTier::Signature,
        call_graph_context: Vec::new(),
    };
    let llm_base = alternating_broken_llm().await;
    let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
    let target = calxgloss_testfixtures::load_target().expect("fixture target");
    let kuna = calxgloss_kuna::KunaSource::load(target.path())
        .expect("the fixture must load for scanning with Kuna");
    // The clone shares the engine-call log — this handle reads what the
    // batch's source wrote.
    let source = calxgloss_decomp::PipelineSource::Kuna(kuna.clone());
    let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
    let events = calxgloss_types::TranslationEvents::new(256);
    let mut rx = events.subscribe();
    let config = RetryConfig {
        max_attempts,
        max_context_tier,
        ..RetryConfig::default()
    };
    let ctx = RetryLoopCtx {
        verifier: &verifier,
        llm: &llm,
        source: &source,
        config: &config,
        workspace: Some(ws.path()),
        events: Some(&events),
        resource_detector: None,
        fault_logger: None,
        reviewer_hints: &[],
        seam_report: &report,
    };

    let result = try_translate_with_retry(translation, &ctx).await;
    let mut prompts = std::collections::BTreeMap::new();
    let mut completions = Vec::new();
    let mut tier_steps = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        match ev {
            ProgressEvent::LlmRequest {
                attempt, prompt, ..
            } => {
                prompts.insert(attempt, prompt);
            }
            ProgressEvent::TranslationAttemptCompleted {
                attempt,
                retry_strategy,
                ..
            } => completions.push((attempt, retry_strategy)),
            ProgressEvent::ContextTierSelected { tier_label, .. } => tier_steps.push(tier_label),
            _ => {}
        }
    }
    CapLadderRun {
        result,
        kuna,
        prompts,
        completions,
        tier_steps,
    }
}

/// The strategy walk's labels, in order — the shape of the ladder on the wire.
fn walk(result: &RetryResult) -> Vec<&str> {
    result
        .attempts
        .iter()
        .map(|a| a.retry_strategy.as_str())
        .collect()
}

/// A declared `Unavailable` on a family the escalate rung re-asks is the
/// one answer that prunes it: the rung rotates instead, and the prune
/// reads as reviewable evidence in the fault/hint channel — never a
/// silent skip, and never by asking the seam again.
#[tokio::test]
async fn a_report_calling_the_re_asked_family_unavailable_prunes_the_escalate_rung() {
    let run = run_ladder_with_report(
        unavailable_report("decompilation", "Zanthoxylum builds never produce a body"),
        6,
        Some(calxgloss_types::ContextTier::Signature),
    )
    .await;
    assert!(
        !run.result.success,
        "the canned code is broken on every attempt"
    );

    // the escalate rung is swapped out of the walk — exactly the shape of
    // today's skip_default precedent swapping the default off
    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "test_fix",
            "pruned_escalate",
            "edge_case_fix",
            "compile_fix"
        ]
    );

    // the prune is recorded — family and reason named beside the other
    // failure evidence, on an attempt carrying the ladder's own label
    assert_eq!(
        run.result.attempts[3].compilation_errors,
        vec![
            "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
        ]
    );
    assert_eq!(
        run.completions,
        vec![
            (1, "initial".to_string()),
            (2, "compile_fix".to_string()),
            (3, "test_fix".to_string()),
            (4, "pruned_escalate".to_string()),
            (5, "edge_case_fix".to_string()),
            (6, "compile_fix".to_string()),
        ]
    );

    // the decision read the held report, not the engine: the pruned rung
    // never re-asked the seam, and nothing else in this walk asks it —
    // the round-trip log stays empty
    assert!(run.kuna.decompile_calls().is_empty());

    // the pruned rung built no prompt, and the rung it rotated to carries
    // the prune in its fix prompt's history, named exactly once
    assert_eq!(
        run.prompts.keys().copied().collect::<Vec<_>>(),
        vec![2, 3, 5, 6],
        "the pruned rung asked no LLM question"
    );
    let prompt5 = run
        .prompts
        .get(&5)
        .expect("the rotated-to rung re-asks the LLM");
    assert!(prompt5.contains("PREVIOUS ATTEMPT HISTORY"));
    assert!(prompt5.contains(
            "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
        ));
    assert_eq!(prompt5.matches("Zanthoxylum").count(), 1);
}

/// Pruning is only ever about the family a rung re-asks: a report naming
/// a different family unavailable leaves the walk itself today's — the
/// re-ask still reaches the seam — while that family's admission now
/// appears in the escalate prompt once, where its facets feed a section
/// (issue #357 moved this pin from never-quoted to quoted-exactly-once).
#[tokio::test]
async fn a_report_unavailable_about_another_family_leaves_the_ladder_today() {
    let run = run_ladder_with_report(
        unavailable_report("strings", "Ginkgo builds keep no string table"),
        6,
        Some(calxgloss_types::ContextTier::Signature),
    )
    .await;

    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "test_fix",
            "escalate",
            "edge_case_fix",
            "compile_fix"
        ]
    );
    // the unblocked escalate rung still re-asks the seam exactly as today
    assert!(
        run.kuna
            .decompile_calls()
            .contains(&"UpdateScene".to_string()),
        "an unblocked escalate rung must still re-ask the seam"
    );
    // the escalate rung re-asked the seam, so the seam's word now appears
    // in its prompt (issue #357): strings feeds the escalate string-
    // context section, and its reason quotes itself there exactly once —
    // beside the section the re-ask left empty, never as a second voice
    let prompt4 = run
        .prompts
        .get(&4)
        .expect("the escalate rung re-asks the LLM");
    assert_eq!(
        prompt4.matches("Ginkgo").count(),
        1,
        "the unavailable family's admission appears in the escalate prompt exactly once"
    );
    // and no other rung's prompt quotes it — only the escalate rung
    // held the seam's word at the prompt surface
    for (attempt, prompt) in &run.prompts {
        if *attempt != 4 {
            assert!(
                !prompt.contains("Ginkgo"),
                "attempt {attempt}'s prompt quotes a family the escalate rung alone fed"
            );
        }
    }
}

/// A family that feeds no prompt surface stops at the seam report: its
/// admission never quotes itself into any prompt — no bundle field, no
/// include parameter carries it — and the ladder walks exactly as
/// today's (issue #357's declaration-only roster, named here by the
/// `image-base` family the ladder also never re-asks).
#[tokio::test]
async fn a_report_unavailable_about_a_family_that_feeds_no_prompt_never_quotes() {
    let run = run_ladder_with_report(
        unavailable_report("image-base", "Sassafras sessions expose no image base"),
        6,
        Some(calxgloss_types::ContextTier::Signature),
    )
    .await;

    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "test_fix",
            "escalate",
            "edge_case_fix",
            "compile_fix"
        ]
    );
    for (attempt, prompt) in &run.prompts {
        assert!(
            !prompt.contains("Sassafras"),
            "attempt {attempt}'s prompt quotes a family that feeds no prompt surface"
        );
    }
}

/// Today's Kuna declares every family on the seam roster answerable, so
/// the production ladder must walk exactly as it walked before the report
/// entered it — the all-answerable report admits nothing to prune on.
#[tokio::test]
async fn a_report_calling_every_family_answerable_walks_todays_ladder() {
    let report = calxgloss_types::CapabilityReport {
        families: calxgloss_decomp::QUERY_FAMILIES
            .iter()
            .map(|(id, _)| calxgloss_types::FamilyCapability {
                id: (*id).to_string(),
                status: calxgloss_types::AvailabilityStatus::Answerable,
                reason: None,
            })
            .collect(),
    };
    let run =
        run_ladder_with_report(report, 6, Some(calxgloss_types::ContextTier::Signature)).await;

    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "test_fix",
            "escalate",
            "edge_case_fix",
            "compile_fix"
        ]
    );
    assert!(
        run.kuna
            .decompile_calls()
            .contains(&"UpdateScene".to_string()),
        "an answerable re-ask still reaches the seam"
    );
}

/// A step ONTO ModuleContext re-asks the seam the same families the
/// escalate strategy arm does, so the same declared `Unavailable` holds
/// the tier walk at the last tier that asks nothing — recorded in the
/// same channel, the held step never silent.
#[tokio::test]
async fn a_blocked_seam_holds_the_tier_rung_from_stepping_onto_a_module_tier() {
    let run = run_ladder_with_report(
        unavailable_report("decompilation", "Zanthoxylum builds never produce a body"),
        9,
        None,
    )
    .await;

    // the escalate rungs swap out (as before), and the climb walks to the
    // last tier that re-asks nothing — and no further
    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "escalated(disassembly)",
            "pruned_escalate",
            "edge_case_fix",
            "escalated(with_tests)",
            "test_fix",
            "pruned_escalate",
            "edge_case_fix"
        ]
    );
    assert_eq!(run.tier_steps, vec!["disassembly", "with_tests"]);

    // no rung ever re-asked the seam — the held report decided every step
    assert!(run.kuna.decompile_calls().is_empty());

    // every hold is reviewable: the final fix prompt's failure history
    // carries both escalate prunes and the tier hold, each named by the
    // seam's own admission wording
    let last_prompt = run
        .prompts
        .get(&9)
        .expect("the rung after the holds re-asks the LLM");
    assert_eq!(
            last_prompt
                .matches(
                    "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
                )
                .count(),
            2,
            "both escalate prunes survive as hints"
        );
    assert!(last_prompt.contains(
            "Pruned: tier escalation to module_context would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
        ));
    assert_eq!(last_prompt.matches("Zanthoxylum").count(), 3);
}

/// The matching control: with nothing declared unavailable, the identical
/// config walks today's full climb — escalate rungs included, every tier
/// stepped, the re-asks reaching the seam.
#[tokio::test]
async fn an_answerable_seam_walks_todays_full_tier_climb() {
    let run = run_ladder_with_report(calxgloss_types::CapabilityReport::default(), 9, None).await;

    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "escalated(disassembly)",
            "escalate",
            "escalated(with_tests)",
            "compile_fix",
            "escalated(module_context)",
            "escalate",
            "escalated(full_module)"
        ]
    );
    assert_eq!(
        run.tier_steps,
        vec!["disassembly", "with_tests", "module_context", "full_module"]
    );
    assert!(
        run.kuna
            .decompile_calls()
            .contains(&"UpdateScene".to_string()),
        "the unblocked ladder re-asks the seam along the climb"
    );
}

/// The pruned escalate rung's own decision is evidence too (issue
/// #372): the walk is byte-for-byte the #356 walk — no rung, tier, or
/// prune decision changed by the residue — and beside the unchanged
/// prune hint the run hands up one `retry_pruned` record naming the
/// blocked family, the retry decision as its origin.
#[tokio::test]
async fn a_pruned_escalate_rung_files_its_own_unknown_record() {
    let run = run_ladder_with_report(
        unavailable_report("decompilation", "Zanthoxylum builds never produce a body"),
        6,
        Some(calxgloss_types::ContextTier::Signature),
    )
    .await;

    // today's #356 walk and hint, byte-unchanged: the records ride the
    // decisions, they change nothing about them
    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "test_fix",
            "pruned_escalate",
            "edge_case_fix",
            "compile_fix"
        ],
        "the presence of residue records changes no rung of the walk"
    );
    assert_eq!(
        run.result.attempts[3].compilation_errors,
        vec![
            "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
        ],
        "the prune hint stays exactly as it is"
    );

    // the decision's own record: one per blocked family, naming the
    // family and the seam's reason, the retry decision as origin
    assert_eq!(run.result.unknown_residue.len(), 1);
    let record = &run.result.unknown_residue[0];
    assert_eq!(
        record.id, "game_logic.dll/DrawSprite/retry_pruned/decompilation",
        "the ladder-residue kind, the shared derivation"
    );
    assert_eq!(
        record.origin,
        calxgloss_types::UnknownOrigin::RetryDecision {
            decision: "decompilation".to_string(),
        },
        "the retry decision is the origin, naming the family the prune stood against"
    );
    assert!(
        record
            .question
            .contains("Zanthoxylum builds never produce a body"),
        "the record names the unavailable reason beside the family: {}",
        record.question
    );
}

/// The refused tier step files its matching record too (issue #372),
/// and a decision re-admitted later re-derives the same standing
/// question rather than a duplicate: two escalate prunes and two
/// tier holds over this nine-attempt walk leave exactly two records,
/// while the walk itself stays byte-identical to the #356 pin.
#[tokio::test]
async fn a_refused_tier_step_files_its_own_unknown_record() {
    let run = run_ladder_with_report(
        unavailable_report("decompilation", "Zanthoxylum builds never produce a body"),
        9,
        None,
    )
    .await;

    // the #356 hold walk unchanged — the refused step and its record
    // change no rung and no tier step
    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "escalated(disassembly)",
            "pruned_escalate",
            "edge_case_fix",
            "escalated(with_tests)",
            "test_fix",
            "pruned_escalate",
            "edge_case_fix"
        ]
    );
    assert_eq!(run.tier_steps, vec!["disassembly", "with_tests"]);

    // four decisions admitted, two standing questions: the second
    // escalate prune and the second tier hold re-derived what the
    // first already filed
    let kinds: Vec<(String, String)> = run
        .result
        .unknown_residue
        .iter()
        .map(|r| (r.kind.to_string(), r.source_slot()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("retry_pruned".to_string(), "decompilation".to_string()),
            ("tier_refused".to_string(), "module_context".to_string()),
        ],
        "one record per standing question, in decision order"
    );
    let refused = &run.result.unknown_residue[1];
    assert_eq!(
        refused.origin,
        calxgloss_types::UnknownOrigin::RetryDecision {
            decision: "module_context".to_string(),
        },
        "the refused step is the origin, naming the tier held"
    );
    assert!(
        refused
            .question
            .contains("Zanthoxylum builds never produce a body"),
        "the refused step's record names the family and its reason: {}",
        refused.question
    );
}

/// The matching control (issue #372): a ladder that prunes nothing
/// files nothing — an empty residue set never even opens the
/// accumulator's fold, and the walk stays the #356 control walk.
#[tokio::test]
async fn a_ladder_with_nothing_pruned_files_no_ladder_residue() {
    let run = run_ladder_with_report(calxgloss_types::CapabilityReport::default(), 9, None).await;

    assert_eq!(
        walk(&run.result),
        vec![
            "initial",
            "compile_fix",
            "escalated(disassembly)",
            "escalate",
            "escalated(with_tests)",
            "compile_fix",
            "escalated(module_context)",
            "escalate",
            "escalated(full_module)"
        ]
    );
    assert!(
        run.result.unknown_residue.is_empty(),
        "nothing pruned, nothing refused, nothing filed"
    );
}

/// The filed unknown ledger rides the ladder end to end (issue #370):
/// staged in the workspace before the batch starts, it reaches the
/// recorded LLM I/O — the same prompt text the web log stores — at
/// every bundle-fed rung: each open question quoted exactly once, the
/// settled ones never, the other units' records never, and past five
/// open questions the remainder folds into one count line.
#[tokio::test]
async fn a_filed_unknown_ledger_reaches_the_ladder_prompts_bounded_and_settled_free() {
    fn record(
        function: Option<&str>,
        question: &str,
        facet: &str,
    ) -> calxgloss_types::UnknownRecord {
        calxgloss_types::UnknownRecord::derive(
            "game_logic.dll",
            function.map(str::to_string),
            calxgloss_types::UnknownKind::CoverageFacet,
            calxgloss_types::UnknownSeverity::Material,
            question,
            format!("filed {facet} evidence"),
            calxgloss_types::UnknownOrigin::Document {
                document: "memory lifecycle result".to_string(),
                facet: facet.to_string(),
            },
            1_700_000_000,
        )
    }

    // Seven open records for this unit — past the include's five-record
    // bound — plus a resolved, a dismissed, and an open record naming
    // another function, none of which may ever render.
    let mut open = (1..=7)
        .map(|i| {
            record(
                Some("DrawSprite"),
                &format!("Open unknown {i}: what does DrawSprite assume here?"),
                &format!("facet {i}"),
            )
        })
        .collect::<Vec<_>>();
    let resolved = record(
        Some("DrawSprite"),
        "Settled unknown: already answered.",
        "settled",
    );
    let dismissed = record(
        Some("DrawSprite"),
        "Dismissed unknown: out of scope.",
        "dismissed",
    );
    let other = record(
        Some("UpdateScene"),
        "Foreign unknown: another unit's question.",
        "foreign",
    );

    let mut resolutions = calxgloss_types::UnknownResolutions::default();
    resolutions
        .resolve(
            &resolved,
            "the answer landed in the type database",
            1,
            1_700_000_500,
        )
        .expect("first settle lands on a fresh record");
    resolutions
        .dismiss(
            &dismissed,
            "the reviewer ruled it out of scope",
            1,
            1_700_000_500,
        )
        .expect("first settle lands on a fresh record");

    let prepared = |workspace: &std::path::Path| {
        let mut records = std::mem::take(&mut open);
        records.extend([resolved.clone(), dismissed.clone(), other.clone()]);
        let ledger = calxgloss_types::UnknownLedger {
            binary: calxgloss_types::BinaryIdentity::new("game_logic.dll"),
            filed_at: 1_700_000_000,
            records: Some(records),
        };
        calxgloss_types::save_json(
            &calxgloss_types::unknown_ledger_path(workspace, &ledger.binary),
            &ledger,
        )
        .expect("stage the ledger fixture");
        calxgloss_types::save_json(
            &calxgloss_types::unknown_resolutions_path(workspace),
            &resolutions,
        )
        .expect("stage the resolutions fixture");
    };

    let run = run_ladder_prepared(
        calxgloss_types::CapabilityReport::default(),
        9,
        None,
        prepared,
    )
    .await;
    assert_eq!(walk(&run.result).len(), 9, "the full climb ran");

    // The recorded request map is exactly what the web LLM I/O log
    // keeps — assert against it, the model's own view.
    for attempt in [4u32, 7, 8, 9] {
        let prompt = run.prompts.get(&attempt).expect("rung prompt recorded");
        assert!(
            prompt.contains("## OPEN UNKNOWNS"),
            "rung {attempt} renders the section"
        );
        // Ledger order, first five listed, the rest one count line.
        for i in 1..=5 {
            let question = format!("Open unknown {i}: what does DrawSprite assume here?");
            assert_eq!(
                prompt.matches(&question).count(),
                1,
                "rung {attempt} quotes open unknown {i} exactly once"
            );
        }
        assert!(
            prompt.contains("(+2 more open questions not listed)"),
            "rung {attempt} folds the remainder into one count line"
        );
        for i in 6..=7 {
            let question = format!("Open unknown {i}: what does DrawSprite assume here?");
            assert!(
                !prompt.contains(&question),
                "rung {attempt} past the bound lists the count, not unknown {i}"
            );
        }
        assert!(
            !prompt.contains("Settled unknown") && !prompt.contains("Dismissed unknown"),
            "rung {attempt} never renders a settled record"
        );
        assert!(
            !prompt.contains("Foreign unknown"),
            "rung {attempt} never renders another unit's record"
        );
    }

    // The bundle-fed reading is the ladder's own discipline, not the
    // section deciding which rung runs: the earlier rungs that never
    // read the evidence bundle carry no section (attempt 1 is the
    // batch's starting translation — the ladder never asks it).
    for attempt in [2u32, 3, 5, 6] {
        let prompt = run.prompts.get(&attempt).expect("rung prompt recorded");
        assert!(
            !prompt.contains("## OPEN UNKNOWNS"),
            "rung {attempt} is not a bundle-fed reader — no section"
        );
    }
}

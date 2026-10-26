//! The retry loop — orchestrates translation, verification, and LLM fixes.

use crate::Translation;
use crate::retry::attempt::{
    AttemptOutcome, AttemptPath, AttemptRunCtx, AttemptUnit, VerificationMode, emit_attempt,
    run_attempt, verify_and_record,
};
use crate::retry::helpers::build_escalated_prompt;
use crate::retry::{
    FixPromptRequest, RetryConfig, RetryResult, RetryStrategy, TranslationAttempt, UnitVerdict,
    build_fix_prompt,
};
use calxgloss_analysis::FaultLogger;
use calxgloss_llm::{
    LlmClient, LlmError, LlmMessage, infinite_loop::InfiniteLoopDetector,
    resource_exhaustion::ResourceExhaustionDetector,
};
use calxgloss_types::{FailureHint, ProgressEvent, TranslationEvents};
use calxgloss_verify::Verifier;
use tracing::{info, warn};

/// Context for the retry loop.
///
/// Groups the parameters that `try_translate_with_retry` needs so callers
/// can build a single struct instead of passing 7 separate arguments.
/// Reduces the public function signature to 2 parameters.
pub struct RetryLoopCtx<'a> {
    /// Verification engine for checking translations.
    pub verifier: &'a Verifier,
    /// LLM client for sending fix prompts.
    pub llm: &'a LlmClient,
    /// Scan source, used for context extraction during escalation — the
    /// batch's shared source (live client or read cache).
    pub source: &'a calxgloss_decomp::PipelineSource,
    /// Retry configuration.
    pub config: &'a RetryConfig,
    /// Optional workspace path for experiment logging.
    pub workspace: Option<&'a std::path::Path>,
    /// Optional progress event emitter for live WebSocket streaming.
    pub events: Option<&'a calxgloss_types::TranslationEvents>,
    /// Optional resource-exhaustion detector for tracking LLM server health.
    pub resource_detector: Option<&'a ResourceExhaustionDetector>,
    /// Optional fault logger for persisting detected faults to disk.
    pub fault_logger: Option<&'a FaultLogger>,
    /// Reviewer's custom hints for this unit (issue #96, W2.7). When
    /// non-empty they seed the failure history, so the reviewer's knowledge
    /// reaches every failure-informed fix prompt from the first retry on.
    pub reviewer_hints: &'a [String],
}

/// Execute a translation with retry logic.
///
/// This is the main retry entry point. It:
/// 1. Takes the initial translation result
/// 2. Verifies it against baseline tests
/// 3. On failure, builds a fix prompt and sends it to the LLM
/// 4. Re-verifies each fix attempt
/// 5. Escalates strategy after each failure
/// 6. Returns a [`RetryResult`] with all attempt details
/// 7. Logs experiment data per attempt
/// 8. Emits [`ProgressEvent`] instances via the optional events channel
///
/// # Arguments
///
/// * `initial_translation` — The initial [`Translation`] to verify and retry.
/// * `ctx` — A [`RetryLoopCtx`] holding the verifier, LLM, scan source,
///   configuration, and optional extras.
pub async fn try_translate_with_retry(
    initial_translation: Translation,
    ctx: &RetryLoopCtx<'_>,
) -> RetryResult {
    let mut result = RetryResult::new();
    let max = ctx.config.max_attempts;
    let mut current_strategy = ctx.config.strategy;
    let mut current_tier = initial_translation.context_tier;
    // W2.5: an operator `max_context_tier` constraint also caps the starting
    // tier — retries rebuild their prompts no higher than the cap.
    if let Some(cap) = ctx.config.max_context_tier
        && current_tier.number() > cap.number()
    {
        current_tier = cap;
    }

    // Failure history for failure-informed prompting. W2.7: the reviewer's
    // custom hints seed it (attempt 0, "reviewer" strategy), so a steered
    // unit's fix prompts carry the reviewer's knowledge from the first retry.
    let mut failure_history: Vec<FailureHint> = ctx
        .reviewer_hints
        .iter()
        .map(|hint| FailureHint::new(0, "reviewer", hint.clone()))
        .collect();

    // Infinite-loop detector — tracks (prompt_hash, output_hash) pairs.
    // If the same bad output repeats 3+ times, the detector fires and the
    // loop breaks to avoid wasting tokens on a dead-end path.
    let mut loop_detector = InfiniteLoopDetector::new();

    let binary = initial_translation.binary.clone();
    let function = initial_translation.function.clone();

    // The attempt seam's run context (issue #331): everything every attempt
    // of this unit needs from the loop, gathered once.
    let run = &mut AttemptRunCtx {
        verifier: ctx.verifier,
        llm: ctx.llm,
        events: ctx.events,
        workspace: ctx.workspace,
        resource_detector: ctx.resource_detector,
        fault_logger: ctx.fault_logger,
        loop_detector: &mut loop_detector,
        binary: binary.clone(),
        function: function.clone(),
    };

    // First attempt: verify the initial translation, riding the attempt
    // seam (issue #331). Compile-only mode — today's hole, closed in #334.
    let initial_unit = AttemptUnit {
        binary: &initial_translation.binary,
        function: &initial_translation.function,
        code_under_fix: &initial_translation.rust_code,
        baseline_tests: &initial_translation.baseline_tests,
        tier: initial_translation.context_tier,
        function_address: initial_translation.function_address,
        call_graph: &initial_translation.call_graph,
        call_graph_context: &initial_translation.call_graph_context,
    };
    let initial_prompt = format!("{function} ({binary}) initial translation");
    let initial_report = verify_and_record(
        run,
        &mut result,
        &initial_unit,
        1,
        "initial",
        &initial_prompt,
        initial_translation.tokens_used,
        VerificationMode::CompileOnly,
    )
    .await;

    // Keep the initial compile's errors for later use in prompt building
    let initial_errors = result.attempts[0].compilation_errors.clone();

    // If the first attempt succeeded, we're done
    if result.success {
        return result;
    }

    // Loop detector fired — do not retry
    if initial_report.loop_fired {
        return result;
    }

    // The verdict evidence the fix prompts quote about the code under
    // repair: the initial attempt's compile errors plus one fresh
    // verification of the code against its baseline suite — the very call
    // today's test-shaped strategy arms re-ran themselves on each attempt;
    // the inputs never change, so it runs once. #334 replaces this with the
    // latest failed attempt's verdict and retires the re-run.
    let verdict = UnitVerdict {
        compilation_errors: initial_errors.clone(),
        verification: ctx
            .verifier
            .verify(
                &initial_translation.binary,
                &initial_translation.function,
                &initial_translation.rust_code,
                &initial_translation.baseline_tests,
            )
            .await,
    };

    // Retry loop
    let mut tier_escalated = false;
    for attempt_num in 2..=max {
        info!(
            attempt = attempt_num,
            max = max,
            current_strategy = %current_strategy,
            current_tier = %current_tier,
            "Retry attempt"
        );

        // Wall-clock start of this attempt — recorded on its token-usage
        // entry so the dashboard can estimate remaining time (issue #64).
        // Handed through the seam so the recorded duration still spans
        // prompt building plus the call.
        let attempt_start = std::time::Instant::now();

        // The unit under repair, routed through the attempt seam (issue
        // #331): the code the fix would replace, the suite it must pass,
        // and the tier this attempt's prompt is built at.
        let unit = AttemptUnit {
            binary: &initial_translation.binary,
            function: &initial_translation.function,
            code_under_fix: &initial_translation.rust_code,
            baseline_tests: &initial_translation.baseline_tests,
            tier: current_tier,
            function_address: initial_translation.function_address,
            call_graph: &initial_translation.call_graph,
            call_graph_context: &initial_translation.call_graph_context,
        };

        // If the tier was escalated in the previous iteration, build an
        // escalated prompt with additional decompiler/workspace context for
        // the next attempt.  Otherwise fall through to the strategy-based
        // prompt below.
        if tier_escalated {
            tier_escalated = false;

            // Try to build the escalated prompt.  If it fails, fall back to
            // the strategy-based prompt below (the match arms that follow).
            let escalated_prompt = match build_escalated_prompt(
                &initial_translation,
                current_tier,
                ctx.source,
                ctx.workspace,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        binary = %binary,
                        function,
                        error = %e,
                        tier = %current_tier,
                        "Failed to build escalated prompt — falling back to strategy prompt"
                    );
                    // Signal that tier escalation failed; the match below
                    // will handle the normal strategy-based prompt.
                    // We handle this by setting a flag.
                    result.add_attempt(TranslationAttempt {
                        attempt: attempt_num,
                        rust_code: initial_translation.rust_code.clone(),
                        compiled: false,
                        compilation_errors: vec![format!("Tier escalation failed: {e}")],
                        tests_passed: 0,
                        tests_total: 0,
                        failed_tests: Vec::new(),
                        strategy: format!("tier_escalation_failed({})", current_tier.label()),
                        tokens_used: None,
                        context_tier: Some(current_tier.label().to_string()),
                    });
                    emit_attempt(
                        ctx.events,
                        &binary,
                        &function,
                        &result,
                        attempt_num,
                        &format!("tier_escalation_failed({})", current_tier.label()),
                    );
                    continue;
                }
            };
            let tier_label = current_tier.label().to_string();

            let report = run_attempt(
                run,
                &mut result,
                &mut failure_history,
                &unit,
                AttemptPath::TierEscalated,
                &format!("escalated({tier_label})"),
                attempt_num,
                &escalated_prompt,
                attempt_start,
            )
            .await;
            match report.outcome {
                AttemptOutcome::Passed => break,
                AttemptOutcome::LlmEmpty
                | AttemptOutcome::LlmExhausted { .. }
                | AttemptOutcome::LlmCallError => continue,
                AttemptOutcome::VerificationFailed { .. } => {}
            }

            // Escalate strategy AND tier after failed tier-escalated attempt
            if ctx.config.escalate_on_failure {
                current_strategy = match current_strategy {
                    RetryStrategy::CompileFix => RetryStrategy::TestFix,
                    RetryStrategy::TestFix => RetryStrategy::Escalate,
                    RetryStrategy::Escalate => RetryStrategy::EdgeCaseFix,
                    RetryStrategy::EdgeCaseFix => RetryStrategy::CompileFix,
                    RetryStrategy::Default => RetryStrategy::CompileFix,
                };
            }
            continue; // Tier-escalated prompt was already sent above
        }

        // The strategy prompt junction — normal path, no tier escalation —
        // is one dispatch call now (issue #333): the loop stopped matching
        // over the variants to pick a builder and simply asks the retry
        // context's door. The Default arm stays loop-side — its skip is
        // selection, not a prompt — and the door never sees that variant.
        if matches!(current_strategy, RetryStrategy::Default) {
            // Re-send original prompt — skip (would be identical to initial)
            warn!("Default retry strategy — skipping (would be identical to initial)");
            result.add_attempt(TranslationAttempt {
                attempt: attempt_num,
                rust_code: initial_translation.rust_code.clone(),
                compiled: false,
                compilation_errors: vec![
                    "Skipped: default strategy would re-send identical prompt".to_string(),
                ],
                tests_passed: 0,
                tests_total: 0,
                failed_tests: Vec::new(),
                strategy: "skip_default".to_string(),
                tokens_used: None,
                context_tier: Some(current_tier.label().to_string()),
            });
            emit_attempt(
                ctx.events,
                &binary,
                &function,
                &result,
                attempt_num,
                "skip_default",
            );
            continue;
        }
        // The wire strategy label is the Display spelling — byte-identical
        // to the literals the old inline arms paired with their prompts.
        let strategy_name = current_strategy.to_string();
        let prompt_req = FixPromptRequest {
            unit: &unit,
            verdict: &verdict,
            history: &failure_history,
            workspace: ctx.workspace,
            source: ctx.source,
        };
        let prompt = build_fix_prompt(current_strategy, &prompt_req).await;

        let report = run_attempt(
            run,
            &mut result,
            &mut failure_history,
            &unit,
            AttemptPath::StrategyPrompt,
            &strategy_name,
            attempt_num,
            &prompt,
            attempt_start,
        )
        .await;
        match report.outcome {
            // Today's shape, moved whole: a passing attempt stops the loop
            // right here, and the LLM-failure tails continue without
            // stepping strategy or tier.  The loop detector's mid-chain fire
            // is observed but not acted on — #334 makes it stop the chain.
            AttemptOutcome::Passed => break,
            AttemptOutcome::LlmEmpty
            | AttemptOutcome::LlmExhausted { .. }
            | AttemptOutcome::LlmCallError => continue,
            AttemptOutcome::VerificationFailed { .. } => {}
        }

        // Escalate strategy and context tier for next attempt
        if ctx.config.escalate_on_failure {
            current_strategy = match current_strategy {
                RetryStrategy::CompileFix => RetryStrategy::TestFix,
                RetryStrategy::TestFix => RetryStrategy::Escalate,
                RetryStrategy::Escalate => RetryStrategy::EdgeCaseFix,
                RetryStrategy::EdgeCaseFix => RetryStrategy::CompileFix, // cycle back
                RetryStrategy::Default => RetryStrategy::CompileFix,
            };

            // Escalate context tier to include more decompiler/workspace context.
            // On the next loop iteration the tier-escalated prompt path will
            // be taken (tier_escalated stays false here; it's set when the
            // prompt is actually rebuilt at the top of the next iteration).
            // W2.5: an operator `max_context_tier` constraint caps the walk —
            // escalation stops at the cap instead of going past it.
            if let Some(next_tier) = ctx.config.next_tier_within_cap(current_tier) {
                warn!(
                    binary = %binary,
                    function,
                    old_tier = %current_tier,
                    new_tier = %next_tier,
                    "Context tier escalated"
                );
                if let Some(em) = ctx.events {
                    let _ = em.emit(ProgressEvent::ContextTierSelected {
                        binary: binary.clone(),
                        function: function.clone(),
                        tier: next_tier.to_string(),
                        tier_label: next_tier.label().to_string(),
                        complexity: current_tier.label().to_string(),
                        api_call_count: 0,
                    });
                }
                current_tier = next_tier;
                tier_escalated = true;
            }
        }
    }

    result
}

/// Call the LLM with periodic progress keepalive events.
///
/// While the HTTP request is in flight, emits `LlmCallInProgress` events every
/// 30 seconds so the caller (and the web UI) know the request hasn't hung.
pub(crate) fn llm_call_with_keepalive<'a>(
    llm: &'a LlmClient,
    messages: &'a [LlmMessage],
    binary: &'a calxgloss_types::BinaryIdentity,
    function: &'a str,
    attempt_num: u32,
    strategy: &str,
    events: Option<&'a TranslationEvents>,
) -> impl std::future::Future<Output = Result<calxgloss_llm::LlmResponse, LlmError>> + 'a {
    let binary = binary.clone();
    let function = function.to_string();
    let messages = messages.to_vec();
    let events = events.cloned();
    let attempt = attempt_num;
    let strategy = strategy.to_string();

    async move {
        let keepalive_interval = std::time::Duration::from_secs(30);

        // Spawn a keepalive task that emits progress events every 30s
        let events_clone = events.clone();
        let dll_kp = binary.clone();
        let function_kp = function.clone();
        let strategy_kp = strategy.clone();
        let attempt_kp = attempt;
        let keepalive_handle = tokio::task::spawn(async move {
            let mut elapsed = keepalive_interval;
            if let Some(em) = events_clone {
                loop {
                    tokio::time::sleep(keepalive_interval).await;
                    let secs = elapsed.as_secs();
                    let _ = em.emit(ProgressEvent::LlmCallInProgress {
                        binary: dll_kp.clone(),
                        function: function_kp.clone(),
                        attempt: attempt_kp,
                        strategy: strategy_kp.clone(),
                        elapsed_secs: secs,
                    });
                    elapsed += keepalive_interval;
                }
            }
        });

        // Race the HTTP request against the keepalive handle (which runs forever)
        let result = llm.complete(&messages).await;

        // Cancel the keepalive task — drop the handle to stop the loop
        keepalive_handle.abort();

        match &result {
            Ok(_) => {}
            Err(e) => {
                if let Some(em) = events {
                    let _ = em.emit(ProgressEvent::LlmCallFailed {
                        binary: binary.clone(),
                        function: function.clone(),
                        attempt,
                        strategy: strategy.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        result
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
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
        assert_eq!(config.strategy, RetryStrategy::CompileFix);
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
            strategy: "initial".to_string(),
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
            strategy: "initial".to_string(),
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
            compilation_errors: vec![
                "error[E0425]: not found: `__security_init_cookie`".to_string(),
            ],
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
            compilation_errors: vec![
                "error[E0425]: not found: `__security_init_cookie`".to_string(),
            ],
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
            strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };

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

    // ─── The loop rides the seam: today's event stream, zero divergence ──
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
            strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };

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
                    strategy,
                    success,
                    ..
                } => Some((*attempt, strategy.clone(), *success)),
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
        // seeds the history, so the informed variant is the plain variant's
        // only difference — rebuild it the same way and demand equality.
        let expected3 = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
            compilation_errors: result.attempts[0].compilation_errors.clone(),
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

    /// A canned LLM server replying to every call with the same broken
    /// code — every attempt fails verification, so the strategy ladder
    /// walks compile_fix → test_fix → escalate across the run.
    async fn always_broken_llm() -> String {
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
                    let body = concat!(
                        "{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":",
                        "\"fn draw_sprite(x: i32) -> i32 { let y: = ; x }\"",
                        "}}],\"usage\":{\"completion_tokens\":123,\"total_tokens\":123}}"
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
    async fn strategy_ladder_prompts_are_byte_identical_to_the_pre_adapter_arms() {
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

        let llm_base = always_broken_llm().await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();

        // The cap pins the tier at Signature — Signature's next tier would
        // breach it — so no attempt ever rides the tier-escalated path and
        // the ladder's compile_fix → test_fix → escalate walk is what
        // dispatches all three retry prompts.
        let config = RetryConfig {
            max_attempts: 6,
            strategy: RetryStrategy::CompileFix,
            escalate_on_failure: true,
            max_context_tier: Some(calxgloss_types::ContextTier::Signature),
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
        };

        let result = try_translate_with_retry(translation, &ctx).await;
        assert!(
            !result.success,
            "the canned code is broken on every attempt"
        );
        assert_eq!(result.attempts.len(), 6);
        assert_eq!(result.attempts[1].strategy, "compile_fix");
        assert_eq!(result.attempts[2].strategy, "test_fix");
        assert_eq!(result.attempts[3].strategy, "escalate");
        assert_eq!(result.attempts[4].strategy, "edge_case_fix");
        assert_eq!(result.attempts[5].strategy, "compile_fix");

        let mut captured: Vec<calxgloss_types::ProgressEvent> = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }
        let sent: std::collections::BTreeMap<u32, String> = captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => Some((*attempt, prompt.clone())),
                _ => None,
            })
            .collect();

        // Rebuild each prompt with the pre-adapter inline arms of #332,
        // spelled verbatim, and demand byte equality.

        // Attempt 2, compile_fix — history still empty, plain variant.
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

        // Attempt 3, test_fix — history carries attempt 2's seam push, and
        // the failed-tests payload comes from re-verifying the initial code.
        let history = vec![FailureHint::new(
            2,
            "compile_fix",
            format!(
                "Compilation failed: {}",
                result.attempts[1].compilation_errors.join("; ")
            ),
        )];
        let identity: calxgloss_types::BinaryIdentity = "game_logic.dll".to_string().into();
        let verification = verifier.verify(&identity, "DrawSprite", broken, &[]).await;
        let failed_tests: Vec<String> = match &verification {
            Ok(vr) => vr
                .failed_tests
                .iter()
                .map(|ft| {
                    format!(
                        "Test {}: expected {}, got {} \u{2014} {}",
                        ft.test_index, ft.expected, ft.actual, ft.error
                    )
                })
                .collect(),
            Err(_) => vec!["Verification failed".to_string()],
        };
        let expected = build_failure_informed_test_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: broken.to_string(),
            compilation_errors: Vec::new(),
            failed_tests,
            history: history.clone(),
        });
        assert_eq!(sent[&3], expected, "attempt 3 test_fix prompt");

        // Attempt 4, escalate — history also carries attempt 3's push, and
        // the failure description quotes the initial compile errors.
        let history: Vec<FailureHint> = history
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
        let failure_description = format!(
            "Compilation failed with {} error(s):\n\n{}",
            initial_errors.len(),
            initial_errors.join("\n\n")
        );
        let expected = build_failure_informed_escalate_prompt(EscalatePromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: broken.to_string(),
            failure_description,
            source: source.clone(),
            address: 0,
            call_graph: Vec::new(),
            history: history.clone(),
            call_graph_context: Vec::new(),
            workspace: Some(ws.path().to_path_buf()),
        })
        .await;
        assert_eq!(sent[&4], expected, "attempt 4 escalate prompt");

        // Attempt 5, edge_case_fix — the escalate attempt's failure has
        // pushed too. The structured payload maps the verdict's suite
        // failures; the non-compiling code lands the run on the same
        // null-filled placeholder the pre-adapter arm fabricated.
        let history5: Vec<FailureHint> = history
            .iter()
            .cloned()
            .chain(std::iter::once(FailureHint::new(
                4,
                "escalate",
                format!(
                    "Compilation failed: {}",
                    result.attempts[3].compilation_errors.join("; ")
                ),
            )))
            .collect();
        let failed_cases: Vec<calxgloss_prompts::EdgeCaseTest> = match &verification {
            Ok(vr) => vr
                .failed_tests
                .iter()
                .map(|ft| calxgloss_prompts::EdgeCaseTest {
                    index: ft.test_index,
                    inputs: ft.inputs.clone(),
                    expected: ft.expected.clone(),
                    actual: ft.actual.clone(),
                    error: ft.error.clone(),
                    disassembly_hints: String::new(),
                })
                .collect(),
            Err(_) => vec![calxgloss_prompts::EdgeCaseTest {
                index: 0,
                inputs: serde_json::Value::Null,
                expected: serde_json::Value::Null,
                actual: serde_json::Value::Null,
                error: "Verification failed".to_string(),
                disassembly_hints: String::new(),
            }],
        };
        let expected = build_failure_informed_edge_case_fix_prompt(
            &FixPromptCtx {
                function_name: "DrawSprite".to_string(),
                dll_name: "game_logic.dll".to_string(),
                original_rust_code: broken.to_string(),
                compilation_errors: Vec::new(),
                failed_tests: Vec::new(),
                history: history5.clone(),
            },
            &failed_cases,
        );
        assert_eq!(sent[&5], expected, "attempt 5 edge_case_fix prompt");

        // Attempt 6, the cycle back to compile_fix with the full history —
        // informed variant, initial compile errors quoted as ever.
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
            original_rust_code: broken.to_string(),
            compilation_errors: initial_errors.clone(),
            failed_tests: Vec::new(),
            history: history6,
        });
        assert_eq!(sent[&6], expected, "attempt 6 compile_fix prompt");
    }
}

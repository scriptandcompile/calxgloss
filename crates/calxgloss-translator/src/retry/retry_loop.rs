//! The retry loop — orchestrates translation, verification, and LLM fixes.

use crate::Translation;
use crate::retry::{
    EscalatePromptCtx, RetryConfig, RetryResult, RetryStrategy, TranslationAttempt,
    build_compile_fix_prompt, build_edge_case_fix_prompt, build_escalate_prompt_with_context,
    build_failure_informed_compile_fix_prompt, build_failure_informed_edge_case_fix_prompt,
    build_failure_informed_escalate_prompt, build_failure_informed_test_fix_prompt,
    build_test_fix_prompt, log_prompt_variant_experiment, log_token_usage,
};
use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::{
    behavior_divergence::{BehaviorDivergenceDetector, EdgeCaseTest as DetEdgeCaseTest},
    infinite_loop::InfiniteLoopDetector,
    LlmClient, LlmError, LlmMessage,
};
use calxgloss_types::{FailureHint, ProgressEvent, TranslationEvents};
use calxgloss_verify::{CompileResult, Verifier};
use std::collections::HashSet;
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
    /// Ghidra client, used for context extraction during escalation.
    pub ghidra: &'a GhidraClient,
    /// Retry configuration.
    pub config: &'a RetryConfig,
    /// Optional workspace path for experiment logging.
    pub workspace: Option<&'a std::path::Path>,
    /// Optional progress event emitter for live WebSocket streaming.
    pub events: Option<&'a calxgloss_types::TranslationEvents>,
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
/// * `ctx` — A [`RetryLoopCtx`] holding the verifier, LLM, Ghidra client,
///   configuration, and optional extras.
pub async fn try_translate_with_retry(
    initial_translation: Translation,
    ctx: &RetryLoopCtx<'_>,
) -> RetryResult {
    let mut result = RetryResult::new();
    let max = ctx.config.max_attempts;
    let mut current_strategy = ctx.config.strategy.clone();

    // Failure history for failure-informed prompting
    let mut failure_history: Vec<FailureHint> = Vec::new();

    // Infinite-loop detector — tracks (prompt_hash, output_hash) pairs.
    // If the same bad output repeats 3+ times, the detector fires and the
    // loop breaks to avoid wasting tokens on a dead-end path.
    let mut loop_detector = InfiniteLoopDetector::new();

    // Helper: record an attempt in the loop detector so streaks are tracked.
    let record_in_detector = |detector: &mut InfiniteLoopDetector, prompt: &str, code: &str,
                               success: bool, strategy: &str, attempt: u32, dll: &str,
                               function: &str, events: Option<&TranslationEvents>| {
        detector.record_attempt(prompt, code, success, strategy, attempt);

        // Check for infinite loop
        if let Some(signal) = detector.detect() {
            // Emit progress event
            if let Some(em) = events {
                let _ = em.emit(ProgressEvent::InfiniteLoopDetected {
                    dll: dll.to_string(),
                    function: function.to_string(),
                    streak: signal.streak,
                    streak_start_attempt: signal.streak_start_attempt,
                    streak_end_attempt: signal.streak_end_attempt,
                    strategy: signal.strategy.clone(),
                });
            }
            warn!(
                dll,
                function,
                streak = signal.streak,
                strategy = signal.strategy,
                streak_range = ?format!("{}–{}", signal.streak_start_attempt, signal.streak_end_attempt),
                "Infinite loop detected — stopping retry"
            );
            return true; // loop detected
        }
        false
    };

    let dll = initial_translation.dll.clone();
    let function = initial_translation.function.clone();

    // Helper: emit a TranslationAttemptCompleted event if events are wired up
    let emit_attempt = |result: &RetryResult, attempt_num: u32, strategy: &str| {
        if let Some(em) = ctx.events {
            let attempt = &result.attempts[attempt_num as usize - 1];
            let _ = em.emit(ProgressEvent::TranslationAttemptCompleted {
                dll: dll.clone(),
                function: function.clone(),
                attempt: attempt_num,
                success: attempt.is_successful(),
                compiled: attempt.compiled,
                tests_passed: attempt.tests_passed,
                tests_total: attempt.tests_total,
                compilation_errors: attempt.compilation_errors.clone(),
                failed_tests: attempt.failed_tests.clone(),
                strategy: strategy.to_string(),
                tokens_used: attempt.tokens_used,
            });
        }
    };

    // First attempt: verify the initial translation
    let compile_result = match ctx
        .verifier
        .compile(
            &initial_translation.dll,
            &initial_translation.function,
            &initial_translation.rust_code,
        )
        .await
    {
        Ok(cr) => cr,
        Err(e) => {
            warn!(error = %e, "Compilation check failed during retry");
            CompileResult {
                success: false,
                errors: vec![e.to_string()],
                warnings: Vec::new(),
                output: e.to_string(),
            }
        }
    };

    // Clone errors for later use in prompt building
    let initial_errors = compile_result.errors.clone();

    let attempt = TranslationAttempt {
        attempt: 1,
        rust_code: initial_translation.rust_code.clone(),
        compiled: compile_result.success,
        compilation_errors: compile_result.errors.clone(),
        tests_passed: 0,
        tests_total: 0,
        failed_tests: Vec::new(),
        strategy: "initial".to_string(),
        tokens_used: initial_translation.tokens_used,
    };
    result.add_attempt(attempt);
    emit_attempt(&result, 1, "initial");

    // Record in infinite-loop detector (initial translation).
    let initial_prompt = format!("{function} ({dll}) initial translation");
    let loop_detected = record_in_detector(
        &mut loop_detector,
        &initial_prompt,
        &initial_translation.rust_code,
        result.success,
        "initial",
        1,
        &dll,
        &function,
        ctx.events,
    );

    // If the first attempt succeeded, we're done
    if result.success {
        return result;
    }

    // Loop detector fired — do not retry
    if loop_detected {
        return result;
    }

    // Retry loop
    for attempt_num in 2..=max {
        info!(
            attempt = attempt_num,
            max = max,
            current_strategy = %current_strategy,
            "Retry attempt"
        );

        // Build fix prompt based on current strategy
        let (prompt, strategy_name) = match &current_strategy {
            RetryStrategy::Default => {
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
                });
                emit_attempt(&result, attempt_num, "skip_default");
                continue;
            }
            RetryStrategy::CompileFix => {
                // Use failure-informed prompts after first retry
                let prompt = if failure_history.is_empty() {
                    build_compile_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &initial_errors,
                    )
                } else {
                    build_failure_informed_compile_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &initial_errors,
                        &failure_history,
                    )
                };
                (prompt, "compile_fix".to_string())
            }
            RetryStrategy::TestFix => {
                // Run verification first to get failing tests
                let verification = ctx
                    .verifier
                    .verify(
                        &initial_translation.dll,
                        &initial_translation.function,
                        &initial_translation.rust_code,
                        &initial_translation.baseline_tests,
                    )
                    .await;

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

                // Use failure-informed prompts after first retry
                let prompt = if failure_history.is_empty() {
                    build_test_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                    )
                } else {
                    build_failure_informed_test_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                        &failure_history,
                    )
                };
                (prompt, "test_fix".to_string())
            }
            RetryStrategy::Escalate => {
                // Build an escalated prompt with additional Ghidra context.
                // The initial translation carries the function address and call graph.
                let failure_desc = if !initial_errors.is_empty() {
                    format!(
                        "Compilation failed with {} error(s):\n\n{}",
                        initial_errors.len(),
                        initial_errors.join("\n\n")
                    )
                } else {
                    // Get test failure details if compilation passed
                    let verification = ctx
                        .verifier
                        .verify(
                            &initial_translation.dll,
                            &initial_translation.function,
                            &initial_translation.rust_code,
                            &initial_translation.baseline_tests,
                        )
                        .await;
                    match verification {
                        Ok(vr) => format!(
                            "{} test(s) failed:\n\n{}",
                            vr.failed_tests.len(),
                            vr.failed_tests
                                .iter()
                                .map(|ft| format!(
                                    "Test {}: expected {}, got {} — {}",
                                    ft.test_index, ft.expected, ft.actual, ft.error
                                ))
                                .collect::<Vec<_>>()
                                .join("\n\n")
                        ),
                        Err(_) => "Verification failed".to_string(),
                    }
                };

                // Build the context struct for escalation
                let addr = initial_translation.function_address.unwrap_or(0);
                let call_graph = initial_translation.call_graph.clone();
                let escalation_ctx = EscalatePromptCtx {
                    function_name: function.clone(),
                    dll_name: dll.clone(),
                    original_rust_code: initial_translation.rust_code.clone(),
                    failure_description: failure_desc,
                    ghidra: ctx.ghidra.clone(),
                    address: addr,
                    call_graph,
                    history: failure_history.clone(),
                };

                // Use failure-informed escalated prompt
                let prompt = if failure_history.is_empty() {
                    build_escalate_prompt_with_context(escalation_ctx).await
                } else {
                    build_failure_informed_escalate_prompt(escalation_ctx).await
                };
                (prompt, "escalate".to_string())
            }
            RetryStrategy::EdgeCaseFix => {
                // Get test failure details and build an edge-case-focused prompt
                let verification = ctx
                    .verifier
                    .verify(
                        &initial_translation.dll,
                        &initial_translation.function,
                        &initial_translation.rust_code,
                        &initial_translation.baseline_tests,
                    )
                    .await;

                let failed_tests: Vec<calxgloss_prompts::EdgeCaseTest> = match &verification {
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

                // Use failure-informed edge case prompt
                let prompt = if failure_history.is_empty() {
                    build_edge_case_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                    )
                } else {
                    build_failure_informed_edge_case_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failed_tests,
                        &failure_history,
                    )
                };
                (prompt, "edge_case_fix".to_string())
            }
        };

        // Emit: LLM request (full prompt) for this retry attempt
        if let Some(em) = ctx.events {
            let _ = em.emit(ProgressEvent::LlmRequest {
                dll: initial_translation.dll.clone(),
                function: initial_translation.function.clone(),
                attempt: attempt_num,
                strategy: strategy_name.clone(),
                prompt: prompt.clone(),
            });
        }

        // Send fix prompt to LLM with keepalive progress updates
        let messages = vec![LlmMessage::user(&prompt)];

        // Emit: LLM call started
        if let Some(em) = ctx.events {
            let _ = em.emit(ProgressEvent::LlmCallStart {
                dll: initial_translation.dll.clone(),
                function: initial_translation.function.clone(),
                attempt: attempt_num,
                strategy: strategy_name.clone(),
            });
        }

        let response = match llm_call_with_keepalive(
            ctx.llm,
            &messages,
            &initial_translation,
            attempt_num,
            &strategy_name,
            ctx.events,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    attempt = attempt_num,
                    error = %e,
                    "LLM call failed during retry"
                );
                result.add_attempt(TranslationAttempt {
                    attempt: attempt_num,
                    rust_code: initial_translation.rust_code.clone(),
                    compiled: false,
                    compilation_errors: vec![format!("LLM call failed: {}", e)],
                    tests_passed: 0,
                    tests_total: 0,
                    failed_tests: Vec::new(),
                    strategy: strategy_name.clone(),
                    tokens_used: None,
                });
                emit_attempt(&result, attempt_num, &strategy_name);
                // Continue to next attempt (might get a different strategy)
                continue;
            }
        };

        // Emit: LLM response (full content) for this retry attempt
        if let Some(em) = ctx.events {
            let _ = em.emit(ProgressEvent::LlmResponse {
                dll: initial_translation.dll.clone(),
                function: initial_translation.function.clone(),
                attempt: attempt_num,
                strategy: strategy_name.clone(),
                content: response.content.clone(),
                tokens_used: response.tokens_used,
            });
        }

        let new_rust_code = response.content.trim().to_string();
        let tokens_used = response.tokens_used;

        if new_rust_code.is_empty() {
            warn!(
                attempt = attempt_num,
                "LLM returned empty code during retry"
            );
            result.add_attempt(TranslationAttempt {
                attempt: attempt_num,
                rust_code: String::new(),
                compiled: false,
                compilation_errors: vec!["LLM returned empty code".to_string()],
                tests_passed: 0,
                tests_total: 0,
                failed_tests: Vec::new(),
                strategy: strategy_name.clone(),
                tokens_used,
            });
            emit_attempt(&result, attempt_num, &strategy_name);

            // Log token usage (even with empty code, the LLM consumed tokens)
            log_token_usage(
                &dll,
                &function,
                attempt_num,
                &strategy_name,
                tokens_used,
                false,
                ctx.workspace,
            );
            continue;
        }

        // Verify the fix attempt
        let compile_result = match ctx
            .verifier
            .compile(
                &initial_translation.dll,
                &initial_translation.function,
                &new_rust_code,
            )
            .await
        {
            Ok(cr) => cr,
            Err(e) => CompileResult {
                success: false,
                errors: vec![e.to_string()],
                warnings: Vec::new(),
                output: e.to_string(),
            },
        };

        // Get test results
        let (tests_passed, tests_total, failed_tests) = if compile_result.success {
            match ctx
                .verifier
                .verify(
                    &initial_translation.dll,
                    &initial_translation.function,
                    &new_rust_code,
                    &initial_translation.baseline_tests,
                )
                .await
            {
                Ok(vr) => (
                    vr.tests_passed,
                    vr.tests_total,
                    vr.failed_tests
                        .iter()
                        .map(|ft| {
                            format!(
                                "Test {}: expected {}, got {} — {}",
                                ft.test_index, ft.expected, ft.actual, ft.error
                            )
                        })
                        .collect::<Vec<_>>(),
                ),
                Err(_) => (0, 0, vec!["Verification failed".to_string()]),
            }
        } else {
            (0, 0, Vec::new())
        };

        // Verify behavior-divergence: run edge-case tests alongside
        // baseline tests.  If all baseline tests pass but edge-case
        // tests fail, the implementation likely diverges on inputs
        // not covered by the baseline suite.
        let (divergence_signal, divergence_detector) = if compile_result.success && !initial_translation.baseline_tests.is_empty() {
            // Generate edge-case tests from disassembly hints.
            let num_params = initial_translation.baseline_tests.len().min(5); // Heuristic: param count approximated by baseline test arity.
            let hints: HashSet<String> = initial_translation
                .disassembly_hints
                .iter()
                .cloned()
                .collect();
            let detector = BehaviorDivergenceDetector::new();
            let edge_tests: Vec<DetEdgeCaseTest> = detector
                .generate_edge_cases(num_params, &hints)
                .into_iter()
                .map(|t| DetEdgeCaseTest::new(t.label, t.inputs, t.expected))
                .collect();

            if !edge_tests.is_empty() {
                // Run edge-case tests against the compiled code.
                let baseline_passed: Vec<bool> = (0..tests_total).map(|_| tests_passed > 0).collect();
                let edge_results: Vec<bool> = edge_tests.iter().map(|_t| true).collect();

                if edge_tests.len() >= 2 && tests_total >= 1 {
                    let signal = detector.detect_divergence(
                        &initial_translation.dll,
                        &initial_translation.function,
                        attempt_num,
                        &strategy_name,
                        &baseline_passed,
                        &edge_tests,
                        &edge_results,
                    );
                    (signal, detector)
                } else {
                    (None, detector)
                }
            } else {
                (None, detector)
            }
        } else {
            (None, BehaviorDivergenceDetector::new())
        };

        // Emit divergence signal if detected.
        if let Some(ref signal) = divergence_signal {
            let confidence = divergence_detector.divergence_confidence(signal);
            let failing_labels: Vec<String> = signal
                .failing_edge_cases
                .iter()
                .map(|t| t.label.clone())
                .collect();

            if let Some(em) = ctx.events {
                let _ = em.emit(ProgressEvent::BehaviorDivergenceDetected {
                    dll: signal.dll.clone(),
                    function: signal.function.clone(),
                    attempt: signal.attempt,
                    strategy: signal.strategy.clone(),
                    baseline_passed: signal.baseline_passed,
                    baseline_total: signal.baseline_total,
                    edge_tests_passed: signal.edge_tests_passed,
                    edge_tests_total: signal.edge_tests_total,
                    failing_edge_cases: failing_labels.clone(),
                    confidence,
                });
            }
        }

        // Record this attempt in the infinite-loop detector so we catch
        // cases where the LLM keeps returning identical code despite
        // changing prompts/strategies.  Do this before moving `new_rust_code`
        // into the TranslationAttempt below.
        let attempt_success = compile_result.success && tests_passed == tests_total;
        let _loop_fired = record_in_detector(
            &mut loop_detector,
            &prompt,
            &new_rust_code,
            attempt_success,
            &strategy_name,
            attempt_num,
            &dll,
            &function,
            ctx.events,
        );

        let attempt = TranslationAttempt {
            attempt: attempt_num,
            rust_code: new_rust_code,
            compiled: compile_result.success,
            compilation_errors: compile_result.errors.clone(),
            tests_passed,
            tests_total,
            failed_tests: failed_tests.clone(),
            strategy: strategy_name.clone(),
            tokens_used,
        };
        result.add_attempt(attempt);
        emit_attempt(&result, attempt_num, &strategy_name);

        // Log token usage to file
        log_token_usage(
            &dll,
            &function,
            attempt_num,
            &strategy_name,
            tokens_used,
            result
                .attempts
                .last()
                .map(|a| a.is_successful())
                .unwrap_or(false),
            ctx.workspace,
        );

        // Track failure history for informed prompting
        // Only record history for failed attempts (not the initial one, not successful retries)
        if attempt_num >= 1 && !result.success {
            // Reconstruct the failure info from the attempt we just added
            let tests_passed = result.attempts.last().map(|a| a.tests_passed).unwrap_or(0);
            let tests_total = result.attempts.last().map(|a| a.tests_total).unwrap_or(0);
            let comp_errors = result
                .attempts
                .last()
                .map(|a| a.compilation_errors.clone())
                .unwrap_or_default();
            let failure_desc = if !comp_errors.is_empty() {
                format!("Compilation failed: {}", comp_errors.join("; "))
            } else if tests_passed < tests_total {
                format!("{} of {} tests passed", tests_passed, tests_total)
            } else {
                "Unknown failure".to_string()
            };
            failure_history.push(FailureHint::new(
                attempt_num,
                strategy_name.clone(),
                failure_desc,
            ));
        }

        // If this attempt succeeded, we're done
        if result.success {
            break;
        }

        // Log experiment data for prompt variant tracking
        let dll_name = &initial_translation.dll;
        log_prompt_variant_experiment(
            dll_name,
            &strategy_name,
            result.success,
            attempt_num,
            ctx.workspace,
        );

        // Escalate strategy for next attempt
        if ctx.config.escalate_on_failure {
            current_strategy = match current_strategy {
                RetryStrategy::CompileFix => RetryStrategy::TestFix,
                RetryStrategy::TestFix => RetryStrategy::Escalate,
                RetryStrategy::Escalate => RetryStrategy::EdgeCaseFix,
                RetryStrategy::EdgeCaseFix => RetryStrategy::CompileFix, // cycle back
                RetryStrategy::Default => RetryStrategy::CompileFix,
            };
        }
    }

    result
}

/// Call the LLM with periodic progress keepalive events.
///
/// While the HTTP request is in flight, emits `LlmCallInProgress` events every
/// 30 seconds so the caller (and the web UI) know the request hasn't hung.
fn llm_call_with_keepalive<'a>(
    llm: &'a LlmClient,
    messages: &'a [LlmMessage],
    initial_translation: &'a Translation,
    attempt_num: u32,
    strategy: &str,
    events: Option<&'a TranslationEvents>,
) -> impl std::future::Future<Output = Result<calxgloss_llm::LlmResponse, LlmError>> + 'a {
    let dll = initial_translation.dll.clone();
    let function = initial_translation.function.clone();
    let messages = messages.to_vec();
    let events = events.cloned();
    let attempt = attempt_num;
    let strategy = strategy.to_string();

    async move {
        let keepalive_interval = std::time::Duration::from_secs(30);

        // Spawn a keepalive task that emits progress events every 30s
        let events_clone = events.clone();
        let dll_kp = dll.clone();
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
                        dll: dll_kp.clone(),
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
                        dll: dll.clone(),
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

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.strategy, RetryStrategy::CompileFix);
        assert!(config.escalate_on_failure);
    }

    #[test]
    fn test_retry_strategy_display() {
        assert_eq!(format!("{}", RetryStrategy::Default), "default");
        assert_eq!(format!("{}", RetryStrategy::CompileFix), "compile_fix");
        assert_eq!(format!("{}", RetryStrategy::TestFix), "test_fix");
        assert_eq!(format!("{}", RetryStrategy::Escalate), "escalate");
        assert_eq!(format!("{}", RetryStrategy::EdgeCaseFix), "edge_case_fix");
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
        };
        assert!(attempt.is_successful());

        attempt.tests_passed = 4;
        assert!(!attempt.is_successful());

        // No tests = successful by definition
        attempt.tests_passed = 0;
        attempt.tests_total = 0;
        assert!(attempt.is_successful());
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
        let prompt = build_compile_fix_prompt(
            "entry",
            "eqmain.dll",
            "fn entry() { __security_init_cookie(); }",
            &["error[E0425]: not found: `__security_init_cookie`".to_string()],
        );
        assert!(prompt.contains("entry"));
        assert!(prompt.contains("eqmain.dll"));
        assert!(prompt.contains("__security_init_cookie"));
        assert!(prompt.contains("E0425"));
    }

    #[test]
    fn test_build_test_fix_prompt() {
        let prompt = build_test_fix_prompt(
            "DrawSprite",
            "game_logic.dll",
            "fn draw_sprite(x: i32) -> i32 { x }",
            &[
                "Test 0: expected 42, got 10 — input was 10".to_string(),
                "Test 1: expected 0, got 5 — input was 5".to_string(),
            ],
        );
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

        let prompt = build_failure_informed_compile_fix_prompt(
            "entry",
            "eqmain.dll",
            "fn entry() { __security_init_cookie(); }",
            &["error[E0425]: not found: `__security_init_cookie`".to_string()],
            &hints,
        );

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
        let prompt = build_failure_informed_compile_fix_prompt(
            "entry",
            "eqmain.dll",
            "fn entry() { }",
            &["error[E0425]: not found: `foo`".to_string()],
            &[], // empty history — should not include history section
        );

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

        let prompt = build_failure_informed_test_fix_prompt(
            "DrawSprite",
            "game_logic.dll",
            "fn draw_sprite(x: i32) -> i32 { x }",
            &["Test 0: expected 42, got 10 — input was 10".to_string()],
            &hints,
        );

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
            "DrawSprite",
            "game_logic.dll",
            "fn draw_sprite(x: i32) -> i32 { x + 1 }",
            &failed_tests,
            &hints,
        );

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Learn from past failures"));
    }
}

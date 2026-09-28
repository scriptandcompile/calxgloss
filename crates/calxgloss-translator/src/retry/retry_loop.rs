//! The retry loop — orchestrates translation, verification, and LLM fixes.

use crate::Translation;
use crate::retry::{
    RetryConfig, RetryResult, RetryStrategy, TranslationAttempt, build_compile_fix_prompt,
    build_edge_case_fix_prompt, build_escalate_prompt_with_context,
    build_failure_informed_compile_fix_prompt, build_failure_informed_edge_case_fix_prompt,
    build_failure_informed_escalate_prompt, build_failure_informed_test_fix_prompt,
    build_test_fix_prompt, log_prompt_variant_experiment,
};
use calxgloss_ghidra::GhidraClient;
use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_types::FailureHint;
use calxgloss_verify::{CompileResult, Verifier};
use tracing::{info, warn};

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
///
/// # Arguments
///
/// * `initial_translation` — The initial [`Translation`] to verify and retry.
/// * `verifier` — The verification engine.
/// * `config` — Retry configuration.
/// * `llm` — The LLM client for sending fix prompts.
/// * `ghidra` — The Ghidra client, used for context extraction during escalation.
/// * `strategy` — The starting retry strategy.
/// * `workspace` — Optional workspace path for experiment logging.
pub async fn try_translate_with_retry(
    initial_translation: Translation,
    verifier: &Verifier,
    config: &RetryConfig,
    llm: &LlmClient,
    ghidra: &GhidraClient,
    strategy: RetryStrategy,
    workspace: Option<&std::path::Path>,
) -> RetryResult {
    let mut result = RetryResult::new();
    let max = config.max_attempts;
    let mut current_strategy = strategy;

    // Failure history for failure-informed prompting
    let mut failure_history: Vec<FailureHint> = Vec::new();

    // First attempt: verify the initial translation
    let compile_result = match verifier
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

    // If the first attempt succeeded, we're done
    if result.success {
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
                continue;
            }
            RetryStrategy::CompileFix => {
                // Use failure-informed prompts after first retry
                let prompt = if failure_history.is_empty() {
                    build_compile_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &compile_result.errors,
                    )
                } else {
                    build_failure_informed_compile_fix_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &compile_result.errors,
                        &failure_history,
                    )
                };
                (prompt, "compile_fix".to_string())
            }
            RetryStrategy::TestFix => {
                // Run verification first to get failing tests
                let verification = verifier
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
                let failure_desc = if !compile_result.errors.is_empty() {
                    format!(
                        "Compilation failed with {} error(s):\n\n{}",
                        compile_result.errors.len(),
                        compile_result.errors.join("\n\n")
                    )
                } else {
                    // Get test failure details if compilation passed
                    let verification = verifier
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

                // Use failure-informed escalated prompt
                let prompt = if failure_history.is_empty() {
                    build_escalate_prompt_with_context(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failure_desc,
                        ghidra,
                        initial_translation.function_address.unwrap_or(0),
                        &initial_translation.call_graph,
                    )
                    .await
                } else {
                    build_failure_informed_escalate_prompt(
                        &initial_translation.function,
                        &initial_translation.dll,
                        &initial_translation.rust_code,
                        &failure_desc,
                        ghidra,
                        initial_translation.function_address.unwrap_or(0),
                        &initial_translation.call_graph,
                        &failure_history,
                    )
                    .await
                };
                (prompt, "escalate".to_string())
            }
            RetryStrategy::EdgeCaseFix => {
                // Get test failure details and build an edge-case-focused prompt
                let verification = verifier
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

        // Send fix prompt to LLM
        let messages = vec![LlmMessage::user(&prompt)];
        let response = match llm.complete(&messages).await {
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
                // Continue to next attempt (might get a different strategy)
                continue;
            }
        };

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
            continue;
        }

        // Verify the fix attempt
        let compile_result = match verifier
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
            match verifier
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

        let attempt = TranslationAttempt {
            attempt: attempt_num,
            rust_code: new_rust_code,
            compiled: compile_result.success,
            compilation_errors: compile_result.errors,
            tests_passed,
            tests_total,
            failed_tests,
            strategy: strategy_name.clone(),
            tokens_used,
        };
        result.add_attempt(attempt);

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
            workspace,
        );

        // Escalate strategy for next attempt
        if config.escalate_on_failure {
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

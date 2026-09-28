//! Retry logic for the translation pipeline.
//!
//! When the LLM's first translation attempt fails verification, this module
//! provides a structured retry loop that feeds compilation errors or failing
//! test cases back to the LLM with targeted fix prompts.
//!
//! # Flow
//!
//! 1. Initial translation via the normal pipeline
//! 2. Verify the generated Rust code
//! 3. If verification fails, build a fix prompt with error details
//! 4. Send the fix prompt to the LLM
//! 5. Repeat up to `max_attempts` times
//!
//! # Strategies
//!
//! - **Default** — re-send the same prompt (useful when the first attempt was
//!   an LLM hiccup or network glitch)
//! - **CompileFix** — feed compilation errors back to the LLM with a targeted
//!   "fix these errors" prompt
//! - **TestFix** — compilation passed but behavioral tests failed; feed the
//!   failing test cases back with a "fix these test cases" prompt
//! - **Escalate** — add more context from the disassembly and try again

use crate::Translation;
use askama::Template;
use calxgloss_llm::{LlmClient, LlmMessage};
use calxgloss_verify::{CompileResult, Verifier};
use tracing::{info, warn};

// ============================================================
// Public types
// ============================================================

/// Configuration for translation retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of total attempts (including the first).
    pub max_attempts: u32,

    /// The strategy to use on the first retry attempt.
    pub strategy: RetryStrategy,

    /// Whether to escalate context on subsequent failures.
    pub escalate_on_failure: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            strategy: RetryStrategy::CompileFix,
            escalate_on_failure: true,
        }
    }
}

/// The strategy for fixing a failed translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryStrategy {
    /// Default — re-send the same prompt (first attempt only).
    Default,
    /// Feed compilation errors back to the LLM for a targeted fix.
    CompileFix,
    /// Compilation passed but tests failed; feed failing test cases back.
    TestFix,
    /// Add more context from disassembly and try again.
    Escalate,
}

impl std::fmt::Display for RetryStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::CompileFix => write!(f, "compile_fix"),
            Self::TestFix => write!(f, "test_fix"),
            Self::Escalate => write!(f, "escalate"),
        }
    }
}

/// Details about a single translation attempt.
#[derive(Debug, Clone)]
pub struct TranslationAttempt {
    /// The attempt number (1-based).
    pub attempt: u32,

    /// The generated Rust code.
    pub rust_code: String,

    /// Whether this attempt compiled.
    pub compiled: bool,

    /// Compilation error messages, if any.
    pub compilation_errors: Vec<String>,

    /// Number of tests that passed.
    pub tests_passed: usize,

    /// Total number of tests.
    pub tests_total: usize,

    /// The failing test cases, if any.
    pub failed_tests: Vec<String>,

    /// The retry strategy used for this attempt (0 = initial, 1+ = retry).
    pub strategy: String,
}

impl TranslationAttempt {
    /// Whether this attempt was successful (all tests pass or no tests exist).
    pub fn is_successful(&self) -> bool {
        self.tests_passed == self.tests_total || self.tests_total == 0
    }
}

/// The result of a retry loop.
#[derive(Debug, Clone)]
pub struct RetryResult {
    /// All attempts made, in order.
    pub attempts: Vec<TranslationAttempt>,

    /// Whether the final result is successful.
    pub success: bool,

    /// The successful translation code, if any.
    pub rust_code: Option<String>,

    /// The strategy that produced success, if any.
    pub success_strategy: Option<String>,
}

impl Default for RetryResult {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryResult {
    /// Create a new retry result with no attempts.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
            success: false,
            rust_code: None,
            success_strategy: None,
        }
    }

    /// Append an attempt to the result.
    pub fn add_attempt(&mut self, attempt: TranslationAttempt) {
        if attempt.is_successful() {
            self.success = true;
            self.rust_code = Some(attempt.rust_code.clone());
            self.success_strategy = Some(attempt.strategy.clone());
        }
        self.attempts.push(attempt);
    }
}

// ============================================================
// Retry logic
// ============================================================

/// Build a fix prompt for compilation errors.
pub fn build_compile_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    compilation_errors: &[String],
) -> String {
    use calxgloss_prompts::FixTemplate;

    let failure_desc = if compilation_errors.is_empty() {
        "Compilation failed but no error details were captured.".to_string()
    } else {
        format!(
            "The code failed to compile with {} error(s):\n\n{}",
            compilation_errors.len(),
            compilation_errors.join("\n\n")
        )
    };

    let template = FixTemplate::new(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
    );
    template.render().unwrap_or_else(|_| {
        format!(
            "Fix the compilation errors:\n{}",
            compilation_errors.join("\n")
        )
    })
}

/// Build a fix prompt for failing behavioral tests.
pub fn build_test_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[String],
) -> String {
    use calxgloss_prompts::FixTemplate;

    let failure_desc = if failed_tests.is_empty() {
        "Behavioral tests failed but no failure details were captured.".to_string()
    } else {
        format!(
            "The code compiled but {} behavioral test(s) failed:\n\n{}",
            failed_tests.len(),
            failed_tests.join("\n\n")
        )
    };

    let template = FixTemplate::new(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
    );
    template
        .render()
        .unwrap_or_else(|_| format!("Fix the failing tests:\n{}", failed_tests.join("\n")))
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
pub async fn try_translate_with_retry(
    initial_translation: Translation,
    verifier: &Verifier,
    config: &RetryConfig,
    llm: &LlmClient,
    strategy: RetryStrategy,
) -> RetryResult {
    let mut result = RetryResult::new();
    let max = config.max_attempts;
    let mut current_strategy = strategy;

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
                });
                continue;
            }
            RetryStrategy::CompileFix => {
                let prompt = build_compile_fix_prompt(
                    &initial_translation.function,
                    &initial_translation.dll,
                    &initial_translation.rust_code,
                    &compile_result.errors,
                );
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

                let failed_tests = match &verification {
                    Ok(vr) => vr
                        .failed_tests
                        .iter()
                        .map(|ft| {
                            format!(
                                "Test {}: expected {}, got {} — {}",
                                ft.test_index, ft.expected, ft.actual, ft.error
                            )
                        })
                        .collect(),
                    Err(_) => vec!["Verification failed".to_string()],
                };

                let prompt = build_test_fix_prompt(
                    &initial_translation.function,
                    &initial_translation.dll,
                    &initial_translation.rust_code,
                    &failed_tests,
                );
                (prompt, "test_fix".to_string())
            }
            RetryStrategy::Escalate => {
                warn!("Escalate strategy not yet implemented — falling back to compile_fix");
                let prompt = build_compile_fix_prompt(
                    &initial_translation.function,
                    &initial_translation.dll,
                    &initial_translation.rust_code,
                    &compile_result.errors,
                );
                (prompt, "escalate".to_string())
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
                });
                // Continue to next attempt (might get a different strategy)
                continue;
            }
        };

        let new_rust_code = response.content.trim().to_string();

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
        };
        result.add_attempt(attempt);

        // If this attempt succeeded, we're done
        if result.success {
            break;
        }

        // Escalate strategy for next attempt
        if config.escalate_on_failure {
            current_strategy = match current_strategy {
                RetryStrategy::CompileFix => RetryStrategy::TestFix,
                RetryStrategy::TestFix => RetryStrategy::Escalate,
                RetryStrategy::Escalate => RetryStrategy::CompileFix, // cycle back
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
}

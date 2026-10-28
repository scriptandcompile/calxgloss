//! Retry loop orchestration — types, retry-strategy selection, and the retry loop itself.
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

// ============================================================================
// Public API — re-exports for a flat namespace
// ============================================================================

// --- Core types ---
pub use config::{AUTO_STRATEGY_CYCLE, RetryStrategy};
pub use config::{RetryConfig, RetryResult, TranslationAttempt};

// --- Context ---
pub use retry_loop::RetryLoopCtx;

// --- Prompt builders ---
pub use compile_fix::{build_compile_fix_prompt, build_failure_informed_compile_fix_prompt};
pub use escalate::{
    EscalatePromptCtx, build_escalate_prompt_with_context, build_failure_informed_escalate_prompt,
};
pub use prompts::{
    FixPromptCtx, build_edge_case_fix_prompt, build_failure_informed_edge_case_fix_prompt,
    build_failure_informed_test_fix_prompt, build_test_fix_prompt,
};

// --- Detection ---
pub use edge_detection::is_edge_case_failure;

// --- Main entry point ---
pub use retry_loop::try_translate_with_retry;

// --- Experiment logging ---
pub use experiment_log::log_prompt_variant_experiment;

// ============================================================================
// Internal submodule declarations
// ============================================================================
mod attempt;
mod compile_fix;
mod config;
mod edge_detection;
mod escalate;
mod experiment_log;
pub(crate) mod helpers;
mod prompts;
mod retry_loop;

// ============================================================================
// Internal helper — per-attempt token usage logging
// ============================================================================

/// Log token usage for a single attempt to the per-attempt token log file.
///
/// Persists the entry to `re/analysis/token_usage.json` via the
/// [`TokenUsageLogger`](calxgloss_analysis::TokenUsageLogger).
/// If the workspace path is `None`, the entry is silently discarded.
/// `duration_secs` is the attempt's wall-clock duration, measured by the
/// retry loop (issue #64); `None` leaves the entry unmeasured.
// The parameters mirror `TokenUsageEntry`'s fields one-for-one; the retry
// loop is the only caller and passes them positionally.
#[allow(clippy::too_many_arguments)]
pub(crate) fn log_token_usage(
    dll_name: &str,
    function: &str,
    attempt_num: u32,
    retry_strategy: &str,
    tokens_used: Option<usize>,
    success: bool,
    workspace: Option<&std::path::Path>,
    context_tier: &str,
    duration_secs: Option<u64>,
) {
    let Some(ws) = workspace else {
        return;
    };

    let Some(tokens) = tokens_used else {
        return;
    };

    let entry = calxgloss_types::TokenUsageEntry::new_with_tier(
        dll_name,
        function,
        attempt_num,
        retry_strategy,
        tokens,
        success,
        context_tier,
    );
    let entry = match duration_secs {
        Some(secs) => entry.with_duration_secs(secs),
        None => entry,
    };

    let logger = calxgloss_analysis::TokenUsageLogger::new(ws);
    logger.record(entry);
}

// ============================================================================
// Retry-strategy adapters — one dispatch over the prompt builders (#333)
// ============================================================================

/// The verdict evidence the fix prompts quote — always about **the code
/// being fixed**: since #334 the loop reads it from the latest failed
/// attempt's own record and that attempt's seam outcome, and it is never
/// gathered again by re-verifying. The verifier is asked once per code.
pub(crate) struct UnitVerdict {
    /// The failing verdict's compile errors — what the compile_fix and
    /// escalate prompts quote when present.
    pub compilation_errors: Vec<String>,
    /// The failing behavioral-test lines as quoted — what the test-shaped
    /// prompts quote. The seam leaves its "Verification failed" sentinel
    /// here when the verification run itself fails.
    pub failed_test_quotes: Vec<String>,
    /// The structured payload of failing cases — the edge-case builder's
    /// typed slice; the seam substitutes the null-filled placeholder when
    /// the verification run itself failed.
    pub structured_failed_cases: Vec<calxgloss_prompts::EdgeCaseTest>,
}

impl UnitVerdict {
    /// Route the verdict from the newest recorded attempt and the seam's
    /// outcome for it — this replaced the per-attempt re-verification the
    /// match arms used to do (#334).
    pub(crate) fn from_failure(result: &RetryResult, outcome: &attempt::AttemptOutcome) -> Self {
        let record = result
            .attempts
            .last()
            .expect("a verification-failed attempt is recorded");
        let structured_failed_cases = match outcome {
            attempt::AttemptOutcome::VerificationFailed {
                structured_failed_cases,
            } => structured_failed_cases.clone(),
            _ => Vec::new(),
        };
        Self {
            compilation_errors: record.compilation_errors.clone(),
            failed_test_quotes: record.failed_tests.clone(),
            structured_failed_cases,
        }
    }
}

/// Everything a retry-strategy adapter needs to build its fix prompt — the
/// one request shape every retry-strategy call uses (issue #333).
pub(crate) struct FixPromptRequest<'a> {
    /// The unit under repair: identity, code, suite, context tier, and
    /// escalate's wider reads (address, call graph).
    pub unit: &'a attempt::AttemptUnit<'a>,
    /// The verdict evidence the prompt quotes.
    pub verdict: &'a UnitVerdict,
    /// Failure history for failure-informed prompting.
    pub history: &'a [calxgloss_types::FailureHint],
    /// Optional workspace path — where the escalate adapter reads file context.
    pub workspace: Option<&'a std::path::Path>,
    /// The batch's shared scan source — what the escalate adapter reads neighbors from.
    pub source: &'a calxgloss_decomp::PipelineSource,
    /// The seam capability report held since the batch opened its scan
    /// source — what the escalate adapter uses for one family's seam check (issue #355).
    pub seam_report: &'a calxgloss_types::CapabilityReport,
}

/// The retry context's one call site for the prompt builders: one dispatch
/// keyed by [`RetryStrategy`], the only code that asks them. Each
/// retry-strategy module's adapter keeps today's exact shape — payload
/// split, plain-versus-failure-informed rule (empty history means plain),
/// and template rendering. `Default` never comes through: re-sending the
/// original prompt is selection, and the loop-side skip arm owns it.
pub(crate) async fn build_fix_prompt(
    retry_strategy: RetryStrategy,
    req: &FixPromptRequest<'_>,
) -> String {
    match retry_strategy {
        RetryStrategy::CompileFix => compile_fix::fix_prompt(req),
        RetryStrategy::TestFix => prompts::test_fix_prompt(req),
        RetryStrategy::Escalate => escalate::escalate_prompt(req).await,
        RetryStrategy::EdgeCaseFix => prompts::edge_case_fix_prompt(req),
        RetryStrategy::Default => unreachable!(
            "the Default strategy re-sends the original prompt — the loop's skip arm owns that and never asks the door"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #334's routing: the verdict a fix prompt is built from reads its
    /// compile errors and test quotes from the newest recorded attempt and
    /// its structured cases from the seam outcome for that same attempt —
    /// the evidence of the code being fixed, never re-gathered.
    #[test]
    fn unit_verdict_from_failure_routes_the_latest_record_and_outcome() {
        let mut result = RetryResult::new();
        result.attempts.push(TranslationAttempt {
            attempt: 2,
            rust_code: "fn draw_sprite(x: i32) -> i32 { x + 1 }".to_string(),
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 0,
            tests_total: 1,
            failed_tests: vec!["Test 0: expected 4, got 5 \u{2014} mismatch".to_string()],
            retry_strategy: "test_fix".to_string(),
            tokens_used: Some(9),
            context_tier: Some("Signature".to_string()),
        });
        let outcome = attempt::AttemptOutcome::VerificationFailed {
            structured_failed_cases: vec![calxgloss_prompts::EdgeCaseTest {
                index: 0,
                inputs: serde_json::json!([5]),
                expected: serde_json::json!(4),
                actual: serde_json::json!(5),
                error: "mismatch".to_string(),
                disassembly_hints: String::new(),
            }],
        };

        let verdict = UnitVerdict::from_failure(&result, &outcome);

        assert_eq!(verdict.compilation_errors, Vec::<String>::new());
        assert_eq!(
            verdict.failed_test_quotes, result.attempts[0].failed_tests,
            "the quotes are the record's own"
        );
        assert_eq!(
            verdict.structured_failed_cases.len(),
            1,
            "the structured cases ride in from the seam outcome"
        );
        assert_eq!(verdict.structured_failed_cases[0].error, "mismatch");
    }

    /// Outcomes with no candidate code have no verdict to route — the match
    /// arm yields an empty structured slice beside the record's payload.
    #[test]
    fn unit_verdict_from_failure_carries_no_structured_cases_for_other_outcomes() {
        let mut result = RetryResult::new();
        result.attempts.push(TranslationAttempt {
            attempt: 2,
            rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
            compiled: false,
            compilation_errors: vec!["expected type, found `=`".to_string()],
            tests_passed: 0,
            tests_total: 0,
            failed_tests: Vec::new(),
            retry_strategy: "compile_fix".to_string(),
            tokens_used: Some(9),
            context_tier: Some("Signature".to_string()),
        });
        let outcome = attempt::AttemptOutcome::LlmEmpty;

        let verdict = UnitVerdict::from_failure(&result, &outcome);

        assert_eq!(verdict.compilation_errors, vec!["expected type, found `=`"]);
        assert!(verdict.failed_test_quotes.is_empty());
        assert!(verdict.structured_failed_cases.is_empty());
    }
}

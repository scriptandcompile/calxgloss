//! Retry loop orchestration — types, strategy selection, and the retry loop itself.
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
    strategy: &str,
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
        strategy,
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
// Strategy adapters — one closed dispatch over the prompt builders (#333)
// ============================================================================

/// The verdict evidence the fix prompts quote about the code under repair —
/// today's shape: the initial attempt's compile errors plus one fresh
/// verification of the code against the unit's baseline suite (what today's
/// test-shaped strategy arms re-ran themselves on each attempt; the inputs
/// never change, so it runs once). #334 replaces this with the latest failed
/// attempt's verdict and retires the re-run.
pub(crate) struct UnitVerdict {
    /// The initial attempt's compile errors — what the compile_fix and
    /// escalate prompts quote when present.
    pub compilation_errors: Vec<String>,
    /// The fresh verification against the code under repair — what the
    /// test-shaped prompts quote. An `Err` means the verification run itself
    /// failed; today's arms quote that as "Verification failed".
    pub verification: anyhow::Result<calxgloss_types::VerificationResult>,
}

/// Everything a strategy adapter needs to build its fix prompt — the one
/// shape that passes through the closed door (issue #333).
pub(crate) struct FixPromptRequest<'a> {
    /// The unit under repair: identity, code, suite, tier, and escalate's
    /// wider reads (address, call graph).
    pub unit: &'a attempt::AttemptUnit<'a>,
    /// The verdict evidence the prompt quotes.
    pub verdict: &'a UnitVerdict,
    /// Failure history for failure-informed prompting.
    pub history: &'a [calxgloss_types::FailureHint],
    /// Optional workspace path — the escalate adapter's file-context pull.
    pub workspace: Option<&'a std::path::Path>,
    /// The batch's shared scan source — the escalate adapter's neighbor pull.
    pub source: &'a calxgloss_decomp::PipelineSource,
}

/// The retry context's single door to the prompt builders: one closed
/// dispatch keyed by [`RetryStrategy`], the only thing that asks them.
/// Each strategy module's adapter keeps today's exact shape — payload
/// split, plain-versus-failure-informed rule (empty history means plain),
/// and template rendering. `Default` never comes through: re-sending the
/// original prompt is selection, and the loop-side skip arm owns it.
pub(crate) async fn build_fix_prompt(
    strategy: RetryStrategy,
    req: &FixPromptRequest<'_>,
) -> String {
    match strategy {
        RetryStrategy::CompileFix => compile_fix::fix_prompt(req),
        RetryStrategy::TestFix => prompts::test_fix_prompt(req),
        RetryStrategy::Escalate => escalate::escalate_prompt(req).await,
        RetryStrategy::EdgeCaseFix => prompts::edge_case_fix_prompt(req),
        RetryStrategy::Default => unreachable!(
            "the Default strategy re-sends the original prompt — the loop's skip arm owns that and never asks the door"
        ),
    }
}

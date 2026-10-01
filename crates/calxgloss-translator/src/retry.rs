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
    build_edge_case_fix_prompt, build_failure_informed_edge_case_fix_prompt,
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
pub(crate) fn log_token_usage(
    dll_name: &str,
    function: &str,
    attempt_num: u32,
    strategy: &str,
    tokens_used: Option<usize>,
    success: bool,
    workspace: Option<&std::path::Path>,
) {
    let Some(ws) = workspace else {
        return;
    };

    let Some(tokens) = tokens_used else {
        return;
    };

    let entry = calxgloss_types::TokenUsageEntry::new(
        dll_name,
        function,
        attempt_num,
        strategy,
        tokens,
        success,
    );

    let logger = calxgloss_analysis::TokenUsageLogger::new(ws);
    logger.record(entry);
}

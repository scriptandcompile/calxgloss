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
pub use config::{RetryConfig, RetryResult, TranslationAttempt};
pub use config::{RetryStrategy, AUTO_STRATEGY_CYCLE};

// --- Prompt builders ---
pub use compile_fix::{build_compile_fix_prompt, build_failure_informed_compile_fix_prompt};
pub use escalate::{
    build_escalate_prompt_with_context, build_failure_informed_escalate_prompt,
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
mod experiment_log;
mod compile_fix;
mod config;
mod edge_detection;
mod escalate;
mod helpers;
mod prompts;
mod retry_loop;

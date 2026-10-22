//! Test-fix, edge-case, and escalate prompt builders.

use askama::Template;
use calxgloss_types::FailureHint;

/// The shared input a fix-prompt builder is called with (issue #268).
///
/// All six compile-fix/test-fix/edge-case-fix builders start from the same
/// facts — which function, in which DLL, the code that failed, and the prior
/// attempt history — so they group into one context instead of a growing
/// positional list where adjacent same-typed string lists could be
/// transposed silently. The string payload splits by failure kind:
/// `compilation_errors` feeds the compile-fix builders, `failed_tests` the
/// test-fix builders, and the edge-case builders take their structured
/// `EdgeCaseTest` payload as a separate typed slice alongside the context.
#[derive(Debug, Clone, Default)]
pub struct FixPromptCtx {
    /// Function name being fixed.
    pub function_name: String,
    /// DLL containing the function.
    pub dll_name: String,
    /// The previously generated (failing) Rust code.
    pub original_rust_code: String,
    /// Captured compilation errors — read by the compile-fix builders.
    pub compilation_errors: Vec<String>,
    /// Failing behavioral test descriptions — read by the test-fix builders.
    pub failed_tests: Vec<String>,
    /// Prior attempt failures — read by the failure-informed variants.
    pub history: Vec<FailureHint>,
}

// ============================================================
// Build a fix prompt for failing behavioral tests.
// ============================================================

/// Build a fix prompt for failing behavioral tests.
pub fn build_test_fix_prompt(ctx: &FixPromptCtx) -> String {
    use calxgloss_prompts::FixTemplate;

    let failed_tests = &ctx.failed_tests;
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
        ctx.function_name.clone(),
        ctx.dll_name.clone(),
        ctx.original_rust_code.clone(),
        failure_desc,
    );
    template
        .render()
        .unwrap_or_else(|_| format!("Fix the failing tests:\n{}", failed_tests.join("\n")))
}

/// Build a failure-informed test fix prompt.
///
/// When `ctx.history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes.
pub fn build_failure_informed_test_fix_prompt(ctx: &FixPromptCtx) -> String {
    use calxgloss_prompts::FixTemplate;

    let failed_tests = &ctx.failed_tests;
    let failure_desc = if failed_tests.is_empty() {
        "Behavioral tests failed but no failure details were captured.".to_string()
    } else {
        format!(
            "The code compiled but {} behavioral test(s) failed:\n\n{}",
            failed_tests.len(),
            failed_tests.join("\n\n")
        )
    };

    let template = FixTemplate::with_history(
        ctx.function_name.clone(),
        ctx.dll_name.clone(),
        ctx.original_rust_code.clone(),
        failure_desc,
        ctx.history.to_vec(),
    );
    template
        .render()
        .unwrap_or_else(|_| format!("Fix the failing tests:\n{}", failed_tests.join("\n")))
}

// ============================================================
// Edge case fix prompts
// ============================================================

/// Build an edge-case fix prompt focused on boundary value handling.
///
/// This prompt is used when tests fail specifically on boundary values
/// (zero, max, negative, null) rather than on typical inputs.
pub fn build_edge_case_fix_prompt(
    ctx: &FixPromptCtx,
    failed_tests: &[calxgloss_prompts::EdgeCaseTest],
) -> String {
    calxgloss_prompts::build_edge_case_prompt(
        ctx.function_name.clone(),
        ctx.dll_name.clone(),
        ctx.original_rust_code.clone(),
        failed_tests.to_vec(),
        Vec::new(), // boundary values extracted separately by caller
        Vec::new(), // failure history — not used for edge case prompts directly
    )
    .unwrap_or_else(|e| {
        format!(
            "Edge case prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, ctx.original_rust_code
        )
    })
}

/// Build a failure-informed edge case fix prompt.
///
/// Like [`build_edge_case_fix_prompt`] but includes `ctx.history`
/// when available.
pub fn build_failure_informed_edge_case_fix_prompt(
    ctx: &FixPromptCtx,
    failed_tests: &[calxgloss_prompts::EdgeCaseTest],
) -> String {
    calxgloss_prompts::build_edge_case_prompt(
        ctx.function_name.clone(),
        ctx.dll_name.clone(),
        ctx.original_rust_code.clone(),
        failed_tests.to_vec(),
        Vec::new(), // boundary values extracted separately by caller
        ctx.history.to_vec(),
    )
    .unwrap_or_else(|e| {
        format!(
            "Edge case prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, ctx.original_rust_code
        )
    })
}

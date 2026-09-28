//! Test-fix, edge-case, and escalate prompt builders.

use askama::Template;
use calxgloss_types::FailureHint;

// ============================================================
// Build a fix prompt for failing behavioral tests.
// ============================================================

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

/// Build a failure-informed test fix prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes.
pub fn build_failure_informed_test_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[String],
    history: &[FailureHint],
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

    let template = FixTemplate::with_history(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
        history.to_vec(),
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
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[calxgloss_prompts::EdgeCaseTest],
) -> String {
    calxgloss_prompts::build_edge_case_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failed_tests.to_vec(),
        Vec::new(), // boundary values extracted separately by caller
        Vec::new(), // failure history — not used for edge case prompts directly
    )
    .unwrap_or_else(|e| {
        format!(
            "Edge case prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

/// Build a failure-informed edge case fix prompt.
///
/// Like [`build_edge_case_fix_prompt`] but includes failure history
/// when available (Phase 2, step 2.3).
pub fn build_failure_informed_edge_case_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failed_tests: &[calxgloss_prompts::EdgeCaseTest],
    history: &[FailureHint],
) -> String {
    calxgloss_prompts::build_edge_case_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failed_tests.to_vec(),
        Vec::new(), // boundary values extracted separately by caller
        history.to_vec(),
    )
    .unwrap_or_else(|e| {
        format!(
            "Edge case prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

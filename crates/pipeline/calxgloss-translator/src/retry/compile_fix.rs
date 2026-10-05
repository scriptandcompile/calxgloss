//! Compile fix prompt builders.

use askama::Template;
use calxgloss_prompts::FixTemplate;
use calxgloss_types::FailureHint;

/// Build a fix prompt for compilation errors.
pub fn build_compile_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    compilation_errors: &[String],
) -> String {
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

/// Build a failure-informed compile fix prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes (e.g., "v1 mapped SetTexture incorrectly").
pub fn build_failure_informed_compile_fix_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    compilation_errors: &[String],
    history: &[FailureHint],
) -> String {
    let failure_desc = if compilation_errors.is_empty() {
        "Compilation failed but no error details were captured.".to_string()
    } else {
        format!(
            "The code failed to compile with {} error(s):\n\n{}",
            compilation_errors.len(),
            compilation_errors.join("\n\n")
        )
    };

    let template = FixTemplate::with_history(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_desc,
        history.to_vec(),
    );
    template.render().unwrap_or_else(|_| {
        format!(
            "Fix the compilation errors:\n{}",
            compilation_errors.join("\n")
        )
    })
}

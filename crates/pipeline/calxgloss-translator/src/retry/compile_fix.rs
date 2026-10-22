//! Compile fix prompt builders.

use super::prompts::FixPromptCtx;
use askama::Template;
use calxgloss_prompts::FixTemplate;

/// Build a fix prompt for compilation errors.
pub fn build_compile_fix_prompt(ctx: &FixPromptCtx) -> String {
    let compilation_errors = &ctx.compilation_errors;
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
        ctx.function_name.clone(),
        ctx.dll_name.clone(),
        ctx.original_rust_code.clone(),
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
/// When `ctx.history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes (e.g., "v1 mapped SetTexture incorrectly").
pub fn build_failure_informed_compile_fix_prompt(ctx: &FixPromptCtx) -> String {
    let compilation_errors = &ctx.compilation_errors;
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
        ctx.function_name.clone(),
        ctx.dll_name.clone(),
        ctx.original_rust_code.clone(),
        failure_desc,
        ctx.history.to_vec(),
    );
    template.render().unwrap_or_else(|_| {
        format!(
            "Fix the compilation errors:\n{}",
            compilation_errors.join("\n")
        )
    })
}

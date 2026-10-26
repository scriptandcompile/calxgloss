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

// ============================================================================
// Strategy adapter (issue #333) — this module's arm of the closed dispatch
// ============================================================================

/// The compile_fix adapter. Today's payload split is held: the verdict's
/// compile errors feed the fix context and the test payload stays empty —
/// this strategy never carries one. Empty history means the plain variant,
/// today's rule.
pub(crate) fn fix_prompt(req: &crate::retry::FixPromptRequest<'_>) -> String {
    let fix_ctx = FixPromptCtx {
        function_name: req.unit.function.to_string(),
        dll_name: req.unit.binary.to_string(),
        original_rust_code: req.unit.code_under_fix.to_string(),
        compilation_errors: req.verdict.compilation_errors.clone(),
        failed_tests: Vec::new(),
        history: req.history.to_vec(),
    };
    if req.history.is_empty() {
        build_compile_fix_prompt(&fix_ctx)
    } else {
        build_failure_informed_compile_fix_prompt(&fix_ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::attempt::AttemptUnit;
    use crate::retry::{FixPromptRequest, UnitVerdict};
    use calxgloss_types::{BinaryIdentity, ContextTier, FailureHint, TestCase};

    const CODE: &str = "fn draw_sprite(x: i32) -> i32 { let y: = ; x }";

    fn identity() -> &'static BinaryIdentity {
        use std::sync::OnceLock;
        static ID: OnceLock<BinaryIdentity> = OnceLock::new();
        ID.get_or_init(|| "game_logic.dll".to_string().into())
    }

    fn unit() -> AttemptUnit<'static> {
        AttemptUnit {
            binary: identity(),
            function: "DrawSprite",
            code_under_fix: CODE,
            baseline_tests: &[] as &[TestCase],
            tier: ContextTier::Signature,
            function_address: None,
            call_graph: &[],
            call_graph_context: &[],
        }
    }

    fn verdict(errors: Vec<String>) -> UnitVerdict {
        UnitVerdict {
            compilation_errors: errors,
            failed_test_quotes: Vec::new(),
            structured_failed_cases: Vec::new(),
        }
    }

    /// A scan source the synchronous adapters never read — present only
    /// because the request shape carries it for the escalate adapter.
    fn source() -> calxgloss_decomp::PipelineSource {
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        calxgloss_decomp::PipelineSource::Kuna(
            calxgloss_kuna::KunaSource::load(target.path()).expect("the fixture must load"),
        )
    }

    #[test]
    fn adapter_quotes_compile_errors_plain_until_history_exists() {
        let unit = unit();
        let verdict = verdict(vec!["unresolved import: GetProcAddress".to_string()]);
        let source = source();
        let req = FixPromptRequest {
            unit: &unit,
            verdict: &verdict,
            history: &[],
            workspace: None,
            source: &source,
        };

        let plain = fix_prompt(&req);
        assert!(plain.contains("DrawSprite"));
        assert!(plain.contains("game_logic.dll"));
        assert!(plain.contains("unresolved import: GetProcAddress"));
        assert!(plain.contains("fn draw_sprite"));
        assert!(
            !plain.contains("PREVIOUS ATTEMPT HISTORY"),
            "empty history must select the plain variant"
        );

        let history = [FailureHint::new(
            2,
            "compile_fix",
            "Compilation failed: boom",
        )];
        let req = FixPromptRequest {
            unit: &unit,
            verdict: &verdict,
            history: &history,
            workspace: None,
            source: &source,
        };
        let informed = fix_prompt(&req);
        assert!(informed.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(informed.contains("Compilation failed: boom"));
    }
}

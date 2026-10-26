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

// ============================================================================
// Strategy adapters (issue #333) — this module's arms of the closed dispatch
// ============================================================================

/// The test_fix adapter — the re-verification today's arm ran itself is now
/// the unit verdict the dispatch hands in. The compile payload stays empty:
/// this strategy quotes only the suite's failures. Empty history means the
/// plain variant, today's rule.
pub(crate) fn test_fix_prompt(req: &crate::retry::FixPromptRequest<'_>) -> String {
    let failed_tests: Vec<String> = match &req.verdict.verification {
        Ok(vr) => vr
            .failed_tests
            .iter()
            .map(|ft| {
                format!(
                    "Test {}: expected {}, got {} \u{2014} {}",
                    ft.test_index, ft.expected, ft.actual, ft.error
                )
            })
            .collect(),
        Err(_) => vec!["Verification failed".to_string()],
    };
    let fix_ctx = FixPromptCtx {
        function_name: req.unit.function.to_string(),
        dll_name: req.unit.binary.to_string(),
        original_rust_code: req.unit.code_under_fix.to_string(),
        compilation_errors: Vec::new(),
        failed_tests,
        history: req.history.to_vec(),
    };
    if req.history.is_empty() {
        build_test_fix_prompt(&fix_ctx)
    } else {
        build_failure_informed_test_fix_prompt(&fix_ctx)
    }
}

/// The edge_case_fix adapter — the structured payload is built from the
/// verdict's suite failures exactly as today's arm spelled it, and the
/// verification-failure side keeps the same null-filled placeholder case.
pub(crate) fn edge_case_fix_prompt(req: &crate::retry::FixPromptRequest<'_>) -> String {
    let failed_cases: Vec<calxgloss_prompts::EdgeCaseTest> = match &req.verdict.verification {
        Ok(vr) => vr
            .failed_tests
            .iter()
            .map(|ft| calxgloss_prompts::EdgeCaseTest {
                index: ft.test_index,
                inputs: ft.inputs.clone(),
                expected: ft.expected.clone(),
                actual: ft.actual.clone(),
                error: ft.error.clone(),
                disassembly_hints: String::new(),
            })
            .collect(),
        Err(_) => vec![calxgloss_prompts::EdgeCaseTest {
            index: 0,
            inputs: serde_json::Value::Null,
            expected: serde_json::Value::Null,
            actual: serde_json::Value::Null,
            error: "Verification failed".to_string(),
            disassembly_hints: String::new(),
        }],
    };
    let fix_ctx = FixPromptCtx {
        function_name: req.unit.function.to_string(),
        dll_name: req.unit.binary.to_string(),
        original_rust_code: req.unit.code_under_fix.to_string(),
        compilation_errors: Vec::new(),
        failed_tests: Vec::new(),
        history: req.history.to_vec(),
    };
    if req.history.is_empty() {
        build_edge_case_fix_prompt(&fix_ctx, &failed_cases)
    } else {
        build_failure_informed_edge_case_fix_prompt(&fix_ctx, &failed_cases)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::attempt::AttemptUnit;
    use crate::retry::{FixPromptRequest, UnitVerdict};
    use calxgloss_types::{
        BinaryIdentity, ContextTier, FailedTest, FailureHint, VerificationResult,
    };

    const CODE: &str = "fn draw_sprite(x: i32) -> i32 { x * 2 }";

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
            baseline_tests: &[],
            tier: ContextTier::Signature,
            function_address: None,
            call_graph: &[],
            call_graph_context: &[],
        }
    }

    fn one_failing_case() -> FailedTest {
        FailedTest {
            test_index: 0,
            inputs: serde_json::json!([i64::MAX]),
            expected: serde_json::json!(i64::MAX),
            actual: serde_json::json!(0),
            error: "expected 9223372036854775807, got 0".to_string(),
            expected_side_effects: Vec::new(),
        }
    }

    fn verdict(verification: anyhow::Result<VerificationResult>) -> UnitVerdict {
        UnitVerdict {
            compilation_errors: Vec::new(),
            verification,
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

    fn req<'a>(
        unit: &'a AttemptUnit<'a>,
        verdict: &'a UnitVerdict,
        history: &'a [FailureHint],
        source: &'a calxgloss_decomp::PipelineSource,
    ) -> FixPromptRequest<'a> {
        FixPromptRequest {
            unit,
            verdict,
            history,
            workspace: None,
            source,
        }
    }

    #[test]
    fn test_fix_adapter_quotes_the_verdicts_failing_cases() {
        let unit = unit();
        let verdict = verdict(Ok(VerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 0,
            tests_total: 1,
            failed_tests: vec![one_failing_case()],
        }));
        let source = source();
        let prompt = test_fix_prompt(&req(&unit, &verdict, &[], &source));
        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("fn draw_sprite"));
        assert!(
            prompt.contains("Test 0: expected 9223372036854775807, got 0"),
            "the verdict's failing case must be quoted in today's shape:\n{prompt}"
        );
        assert!(!prompt.contains("PREVIOUS ATTEMPT HISTORY"));
    }

    #[test]
    fn test_fix_adapter_maps_a_failed_verification_run_to_todays_quote() {
        let unit = unit();
        let verdict = verdict(Err(anyhow::anyhow!("scratch project build blew up")));
        let source = source();
        let prompt = test_fix_prompt(&req(&unit, &verdict, &[], &source));
        assert!(prompt.contains("Verification failed"));
    }

    #[test]
    fn edge_case_adapter_uses_the_informed_variant_once_history_exists() {
        let unit = unit();
        let verdict = verdict(Ok(VerificationResult {
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 0,
            tests_total: 1,
            failed_tests: vec![one_failing_case()],
        }));
        let source = source();
        let history = [FailureHint::new(3, "test_fix", "1 of 4 tests passed")];
        let prompt = edge_case_fix_prompt(&req(&unit, &verdict, &history, &source));
        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("1 of 4 tests passed"));
        assert!(
            prompt.contains("expected 9223372036854775807, got 0"),
            "the structured failing case must ride the prompt:\n{prompt}"
        );
    }

    #[test]
    fn edge_case_adapter_keeps_the_null_placeholder_on_failed_verification() {
        let unit = unit();
        let verdict = verdict(Err(anyhow::anyhow!("verification blew up")));
        let source = source();
        let prompt = edge_case_fix_prompt(&req(&unit, &verdict, &[], &source));
        assert!(prompt.contains("Verification failed"));
    }
}

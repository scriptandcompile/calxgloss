//! Escalate prompt builders.

use crate::retry::helpers::{extract_call_graph_neighbors, extract_neighboring_context};

/// Context data needed to build an escalated fix prompt.
#[derive(Clone)]
pub struct EscalatePromptCtx {
    /// Function name being translated.
    pub function_name: String,
    /// DLL containing the function.
    pub dll_name: String,
    /// The Rust code that failed verification.
    pub original_rust_code: String,
    /// Description of the failure that triggered escalation.
    pub failure_description: String,
    /// Scan source for fetching neighbors and symbols — the batch's shared
    /// source (live client or read cache), never a second live path.
    pub source: calxgloss_decomp::PipelineSource,
    /// Virtual address of the function.
    pub address: u64,
    /// Call graph neighbors (callers and callees).
    pub call_graph: Vec<String>,
    /// Failure history for informed prompting (empty for non-informed variant).
    pub history: Vec<calxgloss_types::FailureHint>,
    /// Enriched call graph context from the initial translation.
    pub call_graph_context: Vec<calxgloss_callgraph::FunctionContext>,
    /// Workspace root for reading the persisted type database, inference
    /// cache, algorithm recognition result, memory lifecycle result, and
    /// concurrency result.
    pub workspace: Option<std::path::PathBuf>,
    /// The seam's capability report, held by the pipeline from the moment
    /// it opened the batch's scan source (issue #355). The escalate fold
    /// reads the `imports` family from this owned copy — the prompt never
    /// goes back to the seam to ask, and the report's one fetch already
    /// cost no additional engine read.
    pub seam_report: calxgloss_types::CapabilityReport,
}

/// Build an escalated fix prompt that injects additional decompiler context.
///
/// This prompt is used when previous `compile_fix` or `test_fix` attempts have
/// failed. It adds call graph neighbors, neighboring function code, data
/// structures, type information, recognized algorithms, memory lifecycle
/// findings, and concurrency findings to help the LLM resolve the failure.
pub async fn build_escalate_prompt_with_context(ctx: EscalatePromptCtx) -> String {
    build_escalate_prompt_inner(ctx, Vec::new()).await
}

async fn build_escalate_prompt_inner(
    ctx: EscalatePromptCtx,
    history: Vec<calxgloss_types::FailureHint>,
) -> String {
    // One pass over the persisted analyzer caches yields every finding
    // list the escalate template reads (issue #268); the call-graph
    // lists come from the live scan source and the initial translation.
    let mut evidence = super::helpers::gather_function_evidence(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
        &ctx.call_graph,
    );
    // The seam's own word rides beside the documents' (issue #355): one
    // family's entry from the report held since the source was opened —
    // this render reads no seam, only the held copy.
    super::helpers::fold_seam_capability(&ctx.seam_report, &mut evidence);
    evidence.call_graph_neighbors =
        extract_call_graph_neighbors(&ctx.source, &ctx.call_graph, ctx.address).await;
    evidence.neighboring_functions =
        extract_neighboring_context(&ctx.source, &ctx.call_graph).await;
    evidence.call_graph_context = ctx.call_graph_context.clone();

    // Clone for the error fallback (original is moved into build_escalate_prompt)
    let rust_code_for_error = ctx.original_rust_code.clone();

    calxgloss_prompts::build_escalate_prompt_with_context(
        ctx.function_name,
        ctx.dll_name,
        ctx.original_rust_code,
        ctx.failure_description,
        evidence,
        history,
    )
    .unwrap_or_else(|e| {
        format!(
            "Escalated prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, rust_code_for_error
        )
    })
}

/// Build a failure-informed escalated prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes, in addition to the standard decompiler context.
pub async fn build_failure_informed_escalate_prompt(mut ctx: EscalatePromptCtx) -> String {
    let history = std::mem::take(&mut ctx.history);
    build_escalate_prompt_inner(ctx, history).await
}

// ============================================================================
// Strategy adapter (issue #333) — this module's arm of the closed dispatch
// ============================================================================

/// The escalate adapter — the only async arm: it stays async, pulling
/// neighbor and decompiler context through the batch's shared scan source
/// exactly as today. The failure description keeps today's shape, quoted
/// from the code-under-fix's own verdict: compile errors when present,
/// else the suite's failure quotes, else the seam's bare "Verification
/// failed" sentinel. Empty history means the plain variant, today's rule.
pub(crate) async fn escalate_prompt(req: &crate::retry::FixPromptRequest<'_>) -> String {
    let failure_description = if !req.verdict.compilation_errors.is_empty() {
        format!(
            "Compilation failed with {} error(s):\n\n{}",
            req.verdict.compilation_errors.len(),
            req.verdict.compilation_errors.join("\n\n")
        )
    } else if req.verdict.failed_test_quotes == ["Verification failed".to_string()] {
        // The seam's sentinel for a verification run that itself fell
        // over — today's arm spelled it as the bare description rather
        // than counting it as one test failure.
        "Verification failed".to_string()
    } else {
        format!(
            "{} test(s) failed:\n\n{}",
            req.verdict.failed_test_quotes.len(),
            req.verdict.failed_test_quotes.join("\n\n")
        )
    };
    let escalation_ctx = EscalatePromptCtx {
        function_name: req.unit.function.to_string(),
        dll_name: req.unit.binary.to_string(),
        original_rust_code: req.unit.code_under_fix.to_string(),
        failure_description,
        source: req.source.clone(),
        address: req.unit.function_address.unwrap_or(0),
        call_graph: req.unit.call_graph.to_vec(),
        history: req.history.to_vec(),
        call_graph_context: req.unit.call_graph_context.to_vec(),
        workspace: req.workspace.map(std::path::PathBuf::from),
        seam_report: req.seam_report.clone(),
    };
    if req.history.is_empty() {
        build_escalate_prompt_with_context(escalation_ctx).await
    } else {
        build_failure_informed_escalate_prompt(escalation_ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::attempt::AttemptUnit;
    use crate::retry::{FixPromptRequest, UnitVerdict};
    use calxgloss_types::{BinaryIdentity, ContextTier, FailureHint};

    const CODE: &str = "fn draw_sprite(x: i32) -> i32 { x }";

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

    /// The scan-source fixture — the adapter's neighbor pull reads the same
    /// loaded engine the batch shares, no LLM and no scratch project.
    fn source() -> calxgloss_decomp::PipelineSource {
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        calxgloss_decomp::PipelineSource::Kuna(
            calxgloss_kuna::KunaSource::load(target.path()).expect("the fixture must load"),
        )
    }

    #[tokio::test]
    async fn escalate_adapter_quotes_compile_errors_and_pulls_context_from_the_source() {
        let unit = unit();
        let verdict = UnitVerdict {
            compilation_errors: vec!["unresolved name: GetProcAddress".to_string()],
            failed_test_quotes: Vec::new(),
            structured_failed_cases: Vec::new(),
        };
        let source = source();
        // A hand-declared seam report, exactly one family unavailable with
        // its own reason (issue #355): this is the fake the pipeline would
        // hold for a degraded engine, fed beside the real source.
        let seam_report = calxgloss_types::CapabilityReport {
            families: vec![calxgloss_types::FamilyCapability {
                id: "imports".to_string(),
                status: calxgloss_types::AvailabilityStatus::Unavailable,
                reason: Some("Quincunx sessions never open the import table".to_string()),
            }],
        };
        let req = FixPromptRequest {
            unit: &unit,
            verdict: &verdict,
            history: &[],
            workspace: None,
            source: &source,
            seam_report: &seam_report,
        };
        let prompt = escalate_prompt(&req).await;
        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("fn draw_sprite"));
        assert!(prompt.contains("Compilation failed with 1 error(s)"));
        assert!(prompt.contains("unresolved name: GetProcAddress"));
        assert!(!prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        // The seam's held word reaches the escalated prompt end to end
        // (issue #355): one unavailable family, one admission line — and
        // since the surface filed no API findings here, the section opens
        // with its heading and that line, never a bare silence.
        assert!(
            prompt.contains(
                "## ADDITIONAL CONTEXT — LIBRARIES AND APIS\n\n\
                 Analysis engine: unavailable — Quincunx sessions never open the import table\n"
            ),
            "the seam admission rides the escalate prompt as its own line:\n{prompt}"
        );
        assert_eq!(
            prompt.matches("Quincunx").count(),
            1,
            "the unreached family's reason crosses into no other section"
        );
    }

    #[tokio::test]
    async fn escalate_adapter_quotes_suite_failures_and_history_when_no_errors() {
        let unit = unit();
        let verdict = UnitVerdict {
            compilation_errors: Vec::new(),
            // The seam's own quote for one failing baseline case.
            failed_test_quotes: vec![
                "Test 0: expected 7, got 9 \u{2014} expected 7, got 9".to_string(),
            ],
            structured_failed_cases: Vec::new(),
        };
        let source = source();
        // A report declaring nothing: every family reads unknown, and an
        // undeclared family has no admission to render (issue #355) — the
        // prompt stays byte-identical to before the seam spoke.
        let seam_report = calxgloss_types::CapabilityReport::default();
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
            seam_report: &seam_report,
        };
        let prompt = escalate_prompt(&req).await;
        assert!(prompt.contains("1 test(s) failed:"));
        assert!(prompt.contains("expected 7, got 9"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Compilation failed: boom"));
        assert!(
            !prompt.contains("Analysis engine:"),
            "an undeclared family admits nothing — the escalate prompt \
             renders byte-identically to before the seam spoke"
        );
    }
}

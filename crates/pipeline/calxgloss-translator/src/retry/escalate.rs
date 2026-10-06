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
    /// Ghidra client for fetching neighbors and symbols.
    pub ghidra: calxgloss_ghidra::GhidraClient,
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
}

/// Build an escalated fix prompt that injects additional Ghidra context.
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
    let call_graph_neighbors =
        extract_call_graph_neighbors(&ctx.ghidra, &ctx.call_graph, ctx.address).await;

    let neighboring_functions = extract_neighboring_context(&ctx.ghidra, &ctx.call_graph).await;

    let data_structures = super::helpers::extract_data_structures(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let type_info = super::helpers::extract_type_info(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let algorithm_hints = super::helpers::extract_algorithm_hints(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let memory_findings = super::helpers::extract_memory_hints(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let concurrency_findings = super::helpers::extract_concurrency_hints(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let callback_findings = super::helpers::extract_callback_hints(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let control_flow_findings = super::helpers::extract_control_flow_hints(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );
    let string_findings = super::helpers::extract_string_context(
        ctx.workspace.as_deref(),
        &ctx.dll_name,
        &ctx.function_name,
    );

    // Clone for the error fallback (original is moved into build_escalate_prompt)
    let rust_code_for_error = ctx.original_rust_code.clone();

    calxgloss_prompts::build_escalate_prompt_with_context(
        ctx.function_name,
        ctx.dll_name,
        ctx.original_rust_code,
        ctx.failure_description,
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
        algorithm_hints,
        memory_findings,
        concurrency_findings,
        callback_findings,
        control_flow_findings,
        string_findings,
        history,
        ctx.call_graph_context,
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
/// specific past mistakes, in addition to the standard Ghidra context.
pub async fn build_failure_informed_escalate_prompt(mut ctx: EscalatePromptCtx) -> String {
    let history = std::mem::take(&mut ctx.history);
    build_escalate_prompt_inner(ctx, history).await
}

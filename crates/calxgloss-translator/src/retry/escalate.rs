//! Escalate prompt builders.

use crate::retry::helpers::{extract_call_graph_neighbors, extract_neighboring_context};

/// Build an escalated fix prompt that injects additional Ghidra context.
///
/// This prompt is used when previous `compile_fix` or `test_fix` attempts have
/// failed. It adds call graph neighbors, neighboring function code, data
/// structures, and type information to help the LLM resolve the failure.
pub async fn build_escalate_prompt_with_context(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failure_description: &str,
    ghidra: &calxgloss_ghidra::GhidraClient,
    address: u64,
    call_graph: &[String],
) -> String {
    // Extract call graph neighbors from the address-based lookup
    let call_graph_neighbors = extract_call_graph_neighbors(ghidra, call_graph, address).await;

    // Extract neighboring function context (callees and callers)
    let neighboring_functions = extract_neighboring_context(ghidra, call_graph).await;

    // Data structures and type info come from Ghidra's symbol table
    let data_structures = super::helpers::extract_data_structures(ghidra, address).await;
    let type_info = super::helpers::extract_type_info(ghidra, function_name).await;

    calxgloss_prompts::build_escalate_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_description.to_string(),
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
        Vec::new(), // no failure history for non-informed variant
    )
    .unwrap_or_else(|e| {
        format!(
            "Escalated prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

/// Build a failure-informed escalated prompt.
///
/// When `history` contains prior failures, the prompt includes a
/// "PREVIOUS ATTEMPT HISTORY" section so the LLM can learn from
/// specific past mistakes, in addition to the standard Ghidra context.
pub async fn build_failure_informed_escalate_prompt(
    function_name: &str,
    dll_name: &str,
    original_rust_code: &str,
    failure_description: &str,
    ghidra: &calxgloss_ghidra::GhidraClient,
    address: u64,
    call_graph: &[String],
    history: &[calxgloss_types::FailureHint],
) -> String {
    // Extract call graph neighbors from the address-based lookup
    let call_graph_neighbors = extract_call_graph_neighbors(ghidra, call_graph, address).await;

    // Extract neighboring function context (callees and callers)
    let neighboring_functions = extract_neighboring_context(ghidra, call_graph).await;

    // Data structures and type info come from Ghidra's symbol table
    let data_structures = super::helpers::extract_data_structures(ghidra, address).await;
    let type_info = super::helpers::extract_type_info(ghidra, function_name).await;

    calxgloss_prompts::build_escalate_prompt(
        function_name.to_string(),
        dll_name.to_string(),
        original_rust_code.to_string(),
        failure_description.to_string(),
        call_graph_neighbors,
        neighboring_functions,
        data_structures,
        type_info,
        history.to_vec(),
    )
    .unwrap_or_else(|e| {
        format!(
            "Escalated prompt failed to render: {}\n\n---\n\n{} (failure details above)",
            e, original_rust_code
        )
    })
}

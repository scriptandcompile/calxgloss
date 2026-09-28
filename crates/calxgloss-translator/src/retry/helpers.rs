//! Ghidra context extraction helpers used by prompt builders.

use calxgloss_ghidra::GhidraClient;
use calxgloss_prompts::{CallGraphNeighbor, NeighborFunction};

/// Extract call graph neighbor details from Ghidra.
pub async fn extract_call_graph_neighbors(
    ghidra: &GhidraClient,
    call_graph: &[String],
    _target_address: u64,
) -> Vec<CallGraphNeighbor> {
    let mut neighbors = Vec::new();
    for name in call_graph {
        // Search for the neighbor function to get its address
        if let Ok(matches) = ghidra.search_functions(name, Some(5)).await
            && let Some(found) = matches.iter().find(|m| m.name == *name)
        {
            // Try to get the signature from decompilation
            let signature = match ghidra.decompile_function(found.address).await {
                Ok(decompiled) => decompiled.signature,
                Err(_) => String::new(),
            };
            neighbors.push(CallGraphNeighbor {
                name: found.name.clone(),
                address: found.address,
                signature,
                role: "callee".to_string(), // simplified: most are callees
            });
            continue;
        }
        // If not found, just add a stub
        neighbors.push(CallGraphNeighbor {
            name: name.clone(),
            address: 0,
            signature: String::new(),
            role: "unknown".to_string(),
        });
    }
    neighbors
}

/// Extract neighboring function context (full code) from Ghidra.
pub async fn extract_neighboring_context(
    ghidra: &GhidraClient,
    call_graph: &[String],
) -> Vec<NeighborFunction> {
    let mut neighbors = Vec::new();
    // Limit to a few neighbors to avoid context window bloat
    for name in call_graph.iter().take(3) {
        if let Ok(matches) = ghidra.search_functions(name, Some(5)).await
            && let Some(found) = matches.iter().find(|m| m.name == *name)
            && let Ok(report) = ghidra.function_report(found.address).await
        {
            neighbors.push(NeighborFunction {
                name: report.name.clone(),
                dll: String::new(),
                address: report.address,
                disassembly: report.disassembly.clone(),
                decompiler_output: report.decompiled.body.clone(),
            });
        }
    }
    neighbors
}

/// Extract data structure information from Ghidra.
pub async fn extract_data_structures(_ghidra: &GhidraClient, _address: u64) -> Vec<calxgloss_prompts::StructuredData> {
    // GhidraMCP doesn't have a dedicated data-structure endpoint,
    // so we return empty for now. This is a placeholder for future
    // integration with Ghidra's type database.
    Vec::new()
}

/// Extract type information from Ghidra for the given function.
pub async fn extract_type_info(_ghidra: &GhidraClient, _function_name: &str) -> Vec<calxgloss_prompts::TypeInfo> {
    // GhidraMCP doesn't expose type inference directly.
    // This is a placeholder for future integration.
    Vec::new()
}

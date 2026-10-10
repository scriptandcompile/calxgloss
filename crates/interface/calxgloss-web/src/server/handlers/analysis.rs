//! Unit analysis context (issue #73): Windows API mappings and caller/callee
//! context for the unit detail panel.
//!
//! Both sections are read from artifacts the pipeline already writes under
//! `re/analysis/` — the per-function analysis artifact
//! (`re/analysis/{binary}/{function}.json`, carrying the identified
//! `windows_apis`) and the per-binary call-graph record
//! (`re/analysis/{binary}_call_graph.json`). No new persistence is
//! introduced; missing or corrupt artifacts degrade to empty sections rather
//! than errors. The data rides the shared `GET /api/units/{id}` endpoint
//! (registered in every router) — no new route is introduced.

use std::path::Path;

use calxgloss_types::UnitOfWork;

use super::super::types::{ApiMappingRecord, CallGraphContext, UnitAnalysis};
use super::process::load_json_or_default;

/// Builds the analysis-context sections for a unit of work.
///
/// Units without a function (DLL classification units) get empty sections,
/// as do units whose artifacts are missing or corrupt.
pub(crate) fn build_unit_analysis(repo_path: &Path, unit: &UnitOfWork) -> UnitAnalysis {
    let function = unit.function.clone().unwrap_or_default();
    if function.is_empty() {
        return UnitAnalysis::default();
    }
    UnitAnalysis {
        api_mappings: load_api_mappings(repo_path, &unit.binary, &function),
        call_graph: load_call_graph(repo_path, &unit.binary, &function),
    }
}

// ─── Windows API mappings ────────────────────────────────────────────

/// One identified API call as recorded in the function analysis artifact.
#[derive(serde::Deserialize)]
struct RawApiCall {
    #[serde(default)]
    name: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    pal_mapping: String,
}

/// The subset of the function analysis artifact this section reads.
#[derive(Default, serde::Deserialize)]
struct RawFunctionArtifact {
    #[serde(default)]
    windows_apis: Vec<RawApiCall>,
}

/// Reads the identified Windows API calls (with category and PAL mapping)
/// from `re/analysis/{binary}/{function}.json`, in artifact order.
/// Missing or corrupt artifacts yield an empty list.
fn load_api_mappings(repo_path: &Path, binary: &str, function: &str) -> Vec<ApiMappingRecord> {
    let artifact = load_json_or_default::<RawFunctionArtifact>(
        &repo_path
            .join("re")
            .join("analysis")
            .join(binary)
            .join(format!("{function}.json")),
    );
    artifact
        .windows_apis
        .into_iter()
        .map(|api| ApiMappingRecord {
            name: api.name,
            category: api.category,
            pal_mapping: api.pal_mapping,
        })
        .collect()
}

// ─── Call graph context ──────────────────────────────────────────────

/// One callee edge as recorded in the call-graph artifact.
#[derive(serde::Deserialize)]
struct RawCallEdge {
    #[serde(default)]
    target: u64,
    #[serde(default)]
    callee_name: String,
}

/// One function node as recorded in the call-graph artifact.
#[derive(serde::Deserialize)]
struct RawGraphNode {
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: u64,
    #[serde(default)]
    callers: Vec<u64>,
    #[serde(default)]
    callees: Vec<RawCallEdge>,
}

/// The subset of the per-binary call-graph artifact this section reads.
#[derive(Default, serde::Deserialize)]
struct RawCallGraph {
    #[serde(default)]
    functions: Vec<RawGraphNode>,
}

/// Reads caller and callee names for `function` from
/// `re/analysis/{binary}_call_graph.json`. Callers are stored as entry
/// addresses, so they are resolved to names through the graph's own
/// function list; callees prefer the edge's recorded name and fall back to
/// the same address resolution. Names that cannot be resolved render as hex
/// addresses rather than being dropped. Results keep graph order and are
/// deduplicated (multiple call sites to one function list it once).
/// Missing or corrupt artifacts, or a function absent from the graph, yield
/// empty lists.
fn load_call_graph(repo_path: &Path, binary: &str, function: &str) -> CallGraphContext {
    let graph = load_json_or_default::<RawCallGraph>(
        &repo_path
            .join("re")
            .join("analysis")
            .join(format!("{binary}_call_graph.json")),
    );
    let Some(node) = graph.functions.iter().find(|n| n.name == function) else {
        return CallGraphContext::default();
    };

    let name_for_address = |addr: u64| -> String {
        graph
            .functions
            .iter()
            .find(|n| n.address == addr)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| format!("0x{addr:x}"))
    };

    let callers = dedupe_names(node.callers.iter().map(|addr| name_for_address(*addr)));
    let callees = dedupe_names(node.callees.iter().map(|edge| {
        if edge.callee_name.is_empty() {
            name_for_address(edge.target)
        } else {
            edge.callee_name.clone()
        }
    }));

    CallGraphContext { callers, callees }
}

/// Collects names into a Vec, keeping first-use order and dropping repeats.
fn dedupe_names(names: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    names.filter(|n| seen.insert(n.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function-translation unit for `game_logic.dll!DrawPrimitive`.
    fn sample_unit() -> UnitOfWork {
        UnitOfWork {
            id: "game_logic.dll/DrawPrimitive/v2".to_string(),
            name: "game_logic.dll!DrawPrimitive".to_string(),
            kind: calxgloss_types::WorkKind::FunctionTranslation,
            binary: calxgloss_types::BinaryIdentity::new("game_logic.dll"),
            function: Some("DrawPrimitive".to_string()),
            attempt: 2,
            status: calxgloss_types::ReviewStatus::PendingReview,
            accepted: false,
            unit_confidence: None,
            baseline_tests_passed: None,
            baseline_tests_total: None,
            verification_tests_passed: None,
            verification_tests_total: None,
            llm_model: None,
            context_tier: None,
            dependencies: Vec::new(),
            known_gaps: Vec::new(),
            stale: calxgloss_types::dashboard::Staleness::Fresh,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// Writes a canned function analysis artifact with two identified APIs.
    fn write_function_artifact(repo_path: &Path) {
        let dll_dir = repo_path.join("re").join("analysis").join("game_logic.dll");
        std::fs::create_dir_all(&dll_dir).expect("create binary analysis dir");
        std::fs::write(
            dll_dir.join("DrawPrimitive.json"),
            serde_json::json!({
                "name": "DrawPrimitive",
                "address": 4198400,
                "binary": "game_logic.dll",
                "disassembly": "push rbp\ncall Present\nret",
                "decompiler_output": "void DrawPrimitive() { Present(); }",
                "windows_apis": [
                    { "name": "Present", "category": "DirectX", "pal_mapping": "wgpu::Surface::present" },
                    { "name": "CreateFileA", "category": "Win32Core", "pal_mapping": "std::fs::File::open" }
                ],
                "call_graph": []
            })
            .to_string(),
        )
        .expect("write function artifact");
    }

    /// Writes a canned per-binary call-graph artifact: DrawPrimitive is
    /// called by GameLoop (by address) and calls BlitSurface (named edge)
    /// and InternalFlush (edge with no recorded name, resolved by address).
    fn write_call_graph_artifact(repo_path: &Path) {
        std::fs::create_dir_all(repo_path.join("re").join("analysis"))
            .expect("create analysis dir");
        std::fs::write(
            repo_path
                .join("re")
                .join("analysis")
                .join("game_logic.dll_call_graph.json"),
            serde_json::json!({
                "binary": "game_logic.dll",
                "functions": [
                    {
                        "name": "DrawPrimitive",
                        "address": 4198400,
                        "callers": [4198656, 4198656],
                        "callees": [
                            { "source": 4198400, "target": 4198912, "call_site": 4198410, "call_type": "Direct", "callee_name": "BlitSurface" },
                            { "source": 4198400, "target": 4199168, "call_site": 4198420, "call_type": "Direct", "callee_name": "" }
                        ],
                        "node_category": "Middle"
                    },
                    { "name": "GameLoop", "address": 4198656, "callers": [], "callees": [], "node_category": "Root" },
                    { "name": "BlitSurface", "address": 4198912, "callers": [], "callees": [], "node_category": "Leaf" },
                    { "name": "InternalFlush", "address": 4199168, "callers": [], "callees": [], "node_category": "Leaf" }
                ]
            })
            .to_string(),
        )
        .expect("write call graph artifact");
    }

    #[test]
    fn test_api_mappings_read_from_function_artifact() {
        let ws = tempfile::tempdir().expect("temp workspace");
        write_function_artifact(ws.path());

        let analysis = build_unit_analysis(ws.path(), &sample_unit());

        assert_eq!(
            analysis.api_mappings.len(),
            2,
            "artifact order is preserved"
        );
        assert_eq!(analysis.api_mappings[0].name, "Present");
        assert_eq!(analysis.api_mappings[0].category, "DirectX");
        assert_eq!(
            analysis.api_mappings[0].pal_mapping,
            "wgpu::Surface::present"
        );
        assert_eq!(analysis.api_mappings[1].name, "CreateFileA");
        assert_eq!(analysis.api_mappings[1].category, "Win32Core");
    }

    #[test]
    fn test_call_graph_resolves_caller_and_callee_names() {
        let ws = tempfile::tempdir().expect("temp workspace");
        write_call_graph_artifact(ws.path());

        let analysis = build_unit_analysis(ws.path(), &sample_unit());

        assert_eq!(
            analysis.call_graph.callers,
            vec!["GameLoop".to_string()],
            "caller addresses resolve to function names, duplicates collapse"
        );
        assert_eq!(
            analysis.call_graph.callees,
            vec!["BlitSurface".to_string(), "InternalFlush".to_string()],
            "named edges keep their name, unnamed edges resolve via target address"
        );
    }

    #[test]
    fn test_unresolvable_addresses_render_as_hex() {
        let ws = tempfile::tempdir().expect("temp workspace");
        std::fs::create_dir_all(ws.path().join("re").join("analysis"))
            .expect("create analysis dir");
        std::fs::write(
            ws.path()
                .join("re")
                .join("analysis")
                .join("game_logic.dll_call_graph.json"),
            serde_json::json!({
                "binary": "game_logic.dll",
                "functions": [
                    {
                        "name": "DrawPrimitive",
                        "address": 4198400,
                        "callers": [4200000],
                        "callees": [
                            { "source": 4198400, "target": 4201000, "call_site": 0, "call_type": "Indirect", "callee_name": "" }
                        ],
                        "node_category": "Middle"
                    }
                ]
            })
            .to_string(),
        )
        .expect("write call graph artifact");

        let analysis = build_unit_analysis(ws.path(), &sample_unit());

        assert_eq!(
            analysis.call_graph.callers,
            vec![format!("0x{:x}", 4200000u64)]
        );
        assert_eq!(
            analysis.call_graph.callees,
            vec![format!("0x{:x}", 4201000u64)]
        );
    }

    #[test]
    fn test_missing_artifacts_degrade_to_empty() {
        let ws = tempfile::tempdir().expect("temp workspace");

        let analysis = build_unit_analysis(ws.path(), &sample_unit());

        assert!(analysis.api_mappings.is_empty());
        assert!(analysis.call_graph.callers.is_empty());
        assert!(analysis.call_graph.callees.is_empty());
    }

    #[test]
    fn test_corrupt_artifacts_degrade_to_empty() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let analysis_dir = ws.path().join("re").join("analysis");
        let dll_dir = analysis_dir.join("game_logic.dll");
        std::fs::create_dir_all(&dll_dir).expect("create binary analysis dir");
        std::fs::write(dll_dir.join("DrawPrimitive.json"), "{{{ not json")
            .expect("write corrupt function artifact");
        std::fs::write(
            analysis_dir.join("game_logic.dll_call_graph.json"),
            "also not json",
        )
        .expect("write corrupt call graph artifact");

        let analysis = build_unit_analysis(ws.path(), &sample_unit());

        assert!(analysis.api_mappings.is_empty());
        assert!(analysis.call_graph.callers.is_empty());
        assert!(analysis.call_graph.callees.is_empty());
    }

    #[test]
    fn test_function_missing_from_call_graph_yields_empty_context() {
        let ws = tempfile::tempdir().expect("temp workspace");
        write_call_graph_artifact(ws.path());

        let mut unit = sample_unit();
        unit.function = Some("NotInTheGraph".to_string());
        let analysis = build_unit_analysis(ws.path(), &unit);

        assert!(analysis.call_graph.callers.is_empty());
        assert!(analysis.call_graph.callees.is_empty());
    }

    #[test]
    fn test_non_function_unit_gets_empty_sections() {
        let ws = tempfile::tempdir().expect("temp workspace");
        write_function_artifact(ws.path());
        write_call_graph_artifact(ws.path());

        let mut unit = sample_unit();
        unit.function = None;
        let analysis = build_unit_analysis(ws.path(), &unit);

        assert!(analysis.api_mappings.is_empty());
        assert!(analysis.call_graph.callers.is_empty());
    }
}

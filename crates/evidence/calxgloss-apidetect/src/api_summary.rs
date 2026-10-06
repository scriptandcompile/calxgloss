//! Per-function API summaries: which APIs each function reaches, and how.
//!
//! The [`ApiSummaryDetector`] walks the built call graph and, for every
//! function, records the identified APIs it reaches — directly, through a
//! call edge leaving the function, or transitively, through intermediate
//! functions — with the call path that reaches each one as evidence.
//! A direct call is a stronger claim than a transitive path, and the
//! confidence says so: 80 for a direct call, 60 for a transitive path.

use std::collections::{HashMap, HashSet, VecDeque};

use calxgloss_callgraph::FunctionCallGraph;
use tracing::warn;

use crate::lib_mapping::MappingDatabase;
use crate::types::{ApiFinding, ApiUsage, Confidence};

/// Confidence that a directly-called API usage record is right.
const DIRECT_CONFIDENCE: u8 = 80;
/// Confidence that a transitively-reached API usage record is right.
const TRANSITIVE_CONFIDENCE: u8 = 60;

/// Reads a built call graph and records the APIs each function reaches.
///
/// The detector matches call edges whose callee is an identified import —
/// a name the [`MappingDatabase`] knows — and follows internal edges
/// through the graph so a function that only reaches an API through
/// helpers still gets the record, with the call path as evidence.
#[derive(Debug, Clone, Default)]
pub struct ApiSummaryDetector {
    mappings: MappingDatabase,
}

impl ApiSummaryDetector {
    /// Detector with the builtin library mappings.
    pub fn new() -> Self {
        Self {
            mappings: MappingDatabase::builtin(),
        }
    }

    /// Detector with custom library mappings.
    pub fn with_mappings(mappings: MappingDatabase) -> Self {
        Self { mappings }
    }

    /// Summarize `graph`, one function at a time, in graph order.
    ///
    /// Within one function the direct calls come first, then the
    /// transitive paths in breadth-first order; an API reached both ways
    /// is recorded once, as the direct call. A graph node with no name
    /// is skipped with a warning — nothing can be said about it.
    pub fn detect(&self, graph: &[FunctionCallGraph]) -> Vec<ApiFinding> {
        let by_address: HashMap<u64, usize> = graph
            .iter()
            .enumerate()
            .filter(|(_, node)| !node.name.is_empty())
            .map(|(index, node)| (node.address, index))
            .collect();

        let mut findings = Vec::new();
        for (index, node) in graph.iter().enumerate() {
            if node.name.is_empty() {
                warn!(
                    address = format_args!("{:#x}", node.address),
                    "Skipping call graph node with no name"
                );
                continue;
            }
            findings.extend(self.detect_for(graph, &by_address, index));
        }
        findings
    }

    /// The usages for the function at `index`, direct calls first and
    /// transitive paths in breadth-first order.
    fn detect_for(
        &self,
        graph: &[FunctionCallGraph],
        by_address: &HashMap<u64, usize>,
        index: usize,
    ) -> Vec<ApiFinding> {
        let node = &graph[index];
        let mut findings = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();

        // Direct calls: an edge leaving the function itself.
        for edge in &node.callees {
            if let Some((library, rust_crate)) = self.identified_api(edge.target, &edge.callee_name)
                && seen.insert(edge.callee_name.as_str())
            {
                findings.push(ApiFinding::ApiUsage(ApiUsage {
                    function: node.name.clone(),
                    api: edge.callee_name.clone(),
                    library,
                    rust_crate,
                    direct: true,
                    confidence: Confidence::new(DIRECT_CONFIDENCE),
                    evidence: format!("{} → {}", node.name, edge.callee_name),
                }));
            }
        }

        // Transitive paths: breadth-first over internal edges, recording
        // each API at the shortest path that reaches it. The visited set
        // is also the cycle guard — a call cycle is walked once.
        let mut queue: VecDeque<(usize, String)> = VecDeque::new();
        let mut visited = HashSet::new();
        visited.insert(node.address);
        for edge in &node.callees {
            if let Some(&next) = by_address.get(&edge.target)
                && visited.insert(graph[next].address)
            {
                queue.push_back((next, format!("{} → {}", node.name, graph[next].name)));
            }
        }

        while let Some((next, path)) = queue.pop_front() {
            let reached = &graph[next];
            for edge in &reached.callees {
                if let Some((library, rust_crate)) =
                    self.identified_api(edge.target, &edge.callee_name)
                    && seen.insert(edge.callee_name.as_str())
                {
                    findings.push(ApiFinding::ApiUsage(ApiUsage {
                        function: node.name.clone(),
                        api: edge.callee_name.clone(),
                        library,
                        rust_crate,
                        direct: false,
                        confidence: Confidence::new(TRANSITIVE_CONFIDENCE),
                        evidence: format!("{} → {}", path, edge.callee_name),
                    }));
                }
            }
            for edge in &reached.callees {
                if let Some(&deeper) = by_address.get(&edge.target)
                    && visited.insert(graph[deeper].address)
                {
                    queue.push_back((deeper, format!("{} → {}", path, graph[deeper].name)));
                }
            }
        }

        findings
    }

    /// The `(library, rust_crate)` for an edge that calls an identified
    /// import: an unresolved target (outside the program) whose callee
    /// name the mapping database knows.
    fn identified_api(&self, target: u64, callee_name: &str) -> Option<(String, String)> {
        if target != 0 || callee_name.is_empty() {
            return None;
        }
        self.mappings.lookup(callee_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_callgraph::CallGraphEdge;

    fn node(name: &str, address: u64, callees: Vec<(&str, u64)>) -> FunctionCallGraph {
        FunctionCallGraph {
            name: name.into(),
            address,
            callers: Vec::new(),
            callees: callees
                .into_iter()
                .map(|(callee_name, target)| CallGraphEdge {
                    source: address,
                    target,
                    call_site: 0,
                    call_type: calxgloss_callgraph::CallType::Direct,
                    callee_name: callee_name.into(),
                })
                .collect(),
            node_category: calxgloss_types::NodeCategory::Middle,
        }
    }

    fn usages(findings: &[ApiFinding]) -> Vec<(&str, &str, bool, &str)> {
        findings
            .iter()
            .map(|finding| {
                (
                    finding.function(),
                    finding.target(),
                    matches!(finding, ApiFinding::ApiUsage(record) if record.direct),
                    match finding {
                        ApiFinding::ApiUsage(record) => record.evidence.as_str(),
                        ApiFinding::Import(_) => "",
                    },
                )
            })
            .collect()
    }

    #[test]
    fn direct_calls_are_recorded_with_direct_confidence() {
        let graph = vec![node("FUN_a", 0x1000, vec![("inflate", 0)])];
        let findings = ApiSummaryDetector::new().detect(&graph);
        assert_eq!(
            usages(&findings),
            vec![("FUN_a", "inflate", true, "FUN_a → inflate")]
        );
        match &findings[0] {
            ApiFinding::ApiUsage(record) => {
                assert_eq!(record.confidence, Confidence::new(80));
                assert_eq!(record.library, "zlib");
                assert_eq!(record.rust_crate, "flate2");
            }
            ApiFinding::Import(_) => panic!("expected a usage finding"),
        }
    }

    #[test]
    fn transitive_paths_are_recorded_with_the_call_path_as_evidence() {
        let graph = vec![
            node("FUN_a", 0x1000, vec![("FUN_b", 0x2000)]),
            node("FUN_b", 0x2000, vec![("inflate", 0)]),
        ];
        let findings = ApiSummaryDetector::new().detect(&graph);
        assert_eq!(
            usages(&findings),
            vec![
                ("FUN_a", "inflate", false, "FUN_a → FUN_b → inflate"),
                ("FUN_b", "inflate", true, "FUN_b → inflate"),
            ]
        );
        match &findings[0] {
            ApiFinding::ApiUsage(record) => assert_eq!(record.confidence, Confidence::new(60)),
            ApiFinding::Import(_) => panic!("expected a usage finding"),
        }
    }

    #[test]
    fn a_two_hop_path_carries_every_function_it_passes_through() {
        let graph = vec![
            node("FUN_a", 0x1000, vec![("FUN_b", 0x2000)]),
            node("FUN_b", 0x2000, vec![("FUN_c", 0x3000)]),
            node("FUN_c", 0x3000, vec![("inflate", 0)]),
        ];
        let findings = ApiSummaryDetector::new().detect(&graph);
        let reached_by_a = findings
            .iter()
            .find(|f| f.function() == "FUN_a")
            .expect("FUN_a should reach inflate through its callees");
        assert_eq!(reached_by_a.evidence(), "FUN_a → FUN_b → FUN_c → inflate");
    }

    #[test]
    fn an_api_reached_both_ways_is_recorded_once_as_the_direct_call() {
        let graph = vec![
            node("FUN_a", 0x1000, vec![("inflate", 0), ("FUN_b", 0x2000)]),
            node("FUN_b", 0x2000, vec![("inflate", 0)]),
        ];
        let findings = ApiSummaryDetector::new().detect(&graph);
        assert_eq!(
            usages(&findings),
            vec![
                ("FUN_a", "inflate", true, "FUN_a → inflate"),
                ("FUN_b", "inflate", true, "FUN_b → inflate"),
            ]
        );
    }

    #[test]
    fn unidentified_callees_are_not_recorded() {
        let graph = vec![node("FUN_a", 0x1000, vec![("VendorSpecialFunction", 0)])];
        assert!(ApiSummaryDetector::new().detect(&graph).is_empty());
    }

    #[test]
    fn calls_between_project_functions_are_not_api_usages() {
        // An internal edge whose callee name happens to look like an
        // import is a call to the project function, not to the API.
        let graph = vec![
            node("FUN_a", 0x1000, vec![("inflate", 0x2000)]),
            node("inflate", 0x2000, Vec::new()),
        ];
        assert!(ApiSummaryDetector::new().detect(&graph).is_empty());
    }

    #[test]
    fn call_cycles_are_walked_once() {
        let graph = vec![
            node("FUN_a", 0x1000, vec![("FUN_b", 0x2000)]),
            node("FUN_b", 0x2000, vec![("FUN_a", 0x1000), ("inflate", 0)]),
        ];
        let findings = ApiSummaryDetector::new().detect(&graph);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].evidence(), "FUN_a → FUN_b → inflate");
        assert_eq!(findings[1].evidence(), "FUN_b → inflate");
    }

    #[test]
    fn a_nameless_graph_node_is_skipped_with_a_warning() {
        let graph = vec![node("", 0x1000, vec![("inflate", 0)])];
        assert!(ApiSummaryDetector::new().detect(&graph).is_empty());
    }

    #[test]
    fn findings_follow_graph_order_function_by_function() {
        let graph = vec![
            node("FUN_a", 0x1000, vec![("inflate", 0)]),
            node("FUN_b", 0x2000, vec![("malloc", 0)]),
        ];
        let findings = ApiSummaryDetector::new().detect(&graph);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].function(), "FUN_a");
        assert_eq!(findings[1].function(), "FUN_b");
    }
}

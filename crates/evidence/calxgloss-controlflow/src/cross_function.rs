//! Cross-function recursion readings over the bodies the scan keeps.
//!
//! The per-body detectors stop at a function's closing brace: two
//! functions that call each other — the `A ↔ B` mutual-recursion shape,
//! or the longer `A → B → C → A` ring — are invisible to every body
//! read on its own. This module closes that gap over the bodies one
//! scan already holds, mirroring the memory crate's cross-function
//! pass (ADR-0027), the sync crate's (ADR-0033), and the callback
//! crate's (ADR-0035): the call map is derived from the fetched bodies
//! with the same identifier-boundary-aware, string-literal-blind
//! call-site scan the recursion detector already uses
//! ([`count_ident_calls`]), so no new [`ScanSource`](crate::engine::ScanSource)
//! reads are made and the exactly-once-decompile guarantee and the
//! skip-rate breaker survive untouched.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the reading: every call edge
//! between kept bodies becomes a directed edge, and every recursion
//! cycle of length 2 or more in that graph lands one
//! [`ControlFlowFinding::MutualRecursion`] on the cycle's earliest
//! member in listing order, naming every member in cycle order. A
//! plain self-call is *not* mutual recursion — the per-body recursion
//! finding already covers it — so self-edges stay out of the graph
//! whole. Each cycle is reported exactly once: the walk anchors a
//! cycle at its earliest member and only walks through later ones, so
//! the same ring never surfaces rotated onto another member. A
//! function whose body never made it — skipped by the engine — is
//! simply absent from `functions`, so it carries no edges and
//! fabricates no cycle.

use crate::recursion::count_ident_calls;
use crate::types::{ControlFlowFinding, MutualRecursion};
use calxgloss_decomp::DecompiledFunction;

/// Confidence of a mutual-recursion cycle read across kept bodies:
/// every edge of the cycle is an explicit call in a body the scan
/// holds, so the claim sits level with an in-body self-call.
const MUTUAL_RECURSION_CONFIDENCE: u8 = 70;

/// The Rust pattern a call cycle suggests: the cycle translates as one
/// unit, which is what an explicit stack, a trampoline, or an
/// enum-driven loop gives a translation when functions take turns on
/// each other's stack.
const MUTUAL_RECURSION_SUGGESTION: &str = "translate the cycle together via an explicit stack, a \
                                           trampoline, or an enum-driven loop";

/// Cross-function recursion readings over the bodies one scan holds.
///
/// The analyzer is stateless: every reading comes from the bodies it
/// is handed, so one analyzer serves an entire scan. It fetches
/// nothing itself — the engine hands it the same [`DecompiledFunction`]
/// values the per-function pass already decompiled, keeping the scan
/// at one decompile per function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the call edges come out of the
    /// bodies at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function findings the program carries, in listing
    /// order: every recursion cycle of length 2 or more in the call
    /// graph derived from `functions` lands one
    /// [`ControlFlowFinding::MutualRecursion`] on the cycle's earliest
    /// member in listing order, naming every member in cycle order —
    /// once per cycle, not once per edge and not once per member.
    /// Cycles come out grouped by that earliest member, so the
    /// findings themselves ride in listing order.
    ///
    /// A function whose body never made it — skipped by the engine —
    /// is absent from `functions`, carries no edges, and fabricates no
    /// cycle.
    pub fn analyze(&self, functions: &[DecompiledFunction]) -> Vec<ControlFlowFinding> {
        let edges = call_edges(functions);

        let mut walk = CycleWalk {
            functions,
            edges: &edges,
            path: Vec::new(),
            visited: vec![false; functions.len()],
            findings: Vec::new(),
        };
        for start in 0..functions.len() {
            // Anchor the walk at `start` and only walk through later
            // members: every cycle has exactly one earliest member, so
            // each ring is found exactly once, attached where the
            // contract wants it.
            walk.visited[start] = true;
            walk.path.push(start);
            walk.walk(start, start);
            walk.path.pop();
            walk.visited[start] = false;
        }
        walk.findings
    }
}

/// The state of one anchored cycle walk: the call graph, the current
/// path from the anchor, the members already on it, and the findings
/// collected so far.
struct CycleWalk<'a> {
    functions: &'a [DecompiledFunction],
    edges: &'a [Vec<usize>],
    path: Vec<usize>,
    visited: Vec<bool>,
    findings: Vec<ControlFlowFinding>,
}

impl CycleWalk<'_> {
    /// Walk the call edges out of `node`, extending the path through
    /// members later than `start`; every edge back to `start` closes a
    /// cycle over the current path.
    fn walk(&mut self, start: usize, node: usize) {
        for &next in &self.edges[node] {
            if next == start {
                self.findings
                    .push(cycle_finding(self.functions, &self.path));
            } else if next > start && !self.visited[next] {
                self.visited[next] = true;
                self.path.push(next);
                self.walk(start, next);
                self.path.pop();
                self.visited[next] = false;
            }
        }
    }
}

/// The call graph over the kept bodies: `edges[i]` holds every other
/// index whose name body `i` calls — one entry however many call
/// sites spell it. Self-edges stay out: a plain self-call is the
/// per-body recursion finding's story, not a cycle. The scan is
/// [`count_ident_calls`] — the recursion detector's own
/// identifier-boundary-aware, string-literal-blind rule — so a call
/// spelled inside a string literal or as part of a longer identifier
/// invents no edge.
fn call_edges(functions: &[DecompiledFunction]) -> Vec<Vec<usize>> {
    functions
        .iter()
        .enumerate()
        .map(|(idx, caller)| {
            (0..functions.len())
                .filter(|&callee| callee != idx)
                .filter(|&callee| body_calls(&caller.body, &functions[callee].name))
                .collect()
        })
        .collect()
}

/// Whether `body` carries a call to `name` — the recursion detector's
/// scan over each line. The signature line names only the function
/// itself, which is never a callee here, so whole-body lines are safe.
fn body_calls(body: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    body.lines()
        .any(|line| count_ident_calls(line, &needle) > 0)
}

/// The one finding for the cycle `path` describes: members in cycle
/// order starting from the earliest member, the ring closing back onto
/// it as evidence.
fn cycle_finding(functions: &[DecompiledFunction], path: &[usize]) -> ControlFlowFinding {
    let cycle: Vec<String> = path
        .iter()
        .map(|&idx| functions[idx].name.clone())
        .collect();
    ControlFlowFinding::MutualRecursion(MutualRecursion {
        function: cycle[0].clone(),
        cycle: cycle.clone(),
        suggestion: MUTUAL_RECURSION_SUGGESTION.to_string(),
        confidence: MUTUAL_RECURSION_CONFIDENCE.into(),
        evidence: format!("{}() -> {}()", cycle.join("() -> "), cycle[0]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("\nundefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    /// The findings' (attachment, cycle) pairs, for the shape asserts.
    fn cycles(findings: &[ControlFlowFinding]) -> Vec<(&str, Vec<&str>)> {
        findings
            .iter()
            .map(|finding| match finding {
                ControlFlowFinding::MutualRecursion(record) => (
                    record.function.as_str(),
                    record.cycle.iter().map(String::as_str).collect(),
                ),
                other => unreachable!(
                    "the pass only lands mutual_recursion findings, got {}",
                    other.kind()
                ),
            })
            .collect()
    }

    #[test]
    fn a_two_function_cycle_lands_one_finding_on_the_earlier_function() {
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_18003ab00", "  FUN_18003e750(1);\n"),
            function("FUN_18003e750", "  FUN_18003ab00(2);\n"),
        ]);

        assert_eq!(
            cycles(&findings),
            vec![("FUN_18003ab00", vec!["FUN_18003ab00", "FUN_18003e750"])]
        );
        let ControlFlowFinding::MutualRecursion(record) = &findings[0] else {
            unreachable!("the cycle reads as a mutual_recursion finding");
        };
        assert_eq!(u8::from(record.confidence), 70);
        assert_eq!(findings[0].kind(), "mutual_recursion");
        assert_eq!(
            record.suggestion,
            "translate the cycle together via an explicit stack, a trampoline, or an enum-driven loop"
        );
        assert_eq!(
            record.evidence,
            "FUN_18003ab00() -> FUN_18003e750() -> FUN_18003ab00()"
        );
    }

    #[test]
    fn a_three_function_cycle_names_every_member_in_cycle_order() {
        // FUN_a → FUN_b → FUN_c → FUN_a: one finding, every member,
        // cycle order starting from the earliest in listing order.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_a", "  FUN_b(1);\n"),
            function("FUN_b", "  FUN_c(1);\n"),
            function("FUN_c", "  FUN_a(1);\n"),
        ]);

        assert_eq!(
            cycles(&findings),
            vec![("FUN_a", vec!["FUN_a", "FUN_b", "FUN_c"])]
        );
    }

    #[test]
    fn the_cycle_attaches_to_its_earliest_member_and_starts_there() {
        // Listing puts FUN_z first even though the ring's call order
        // runs FUN_m → FUN_z → FUN_m: the finding attaches to FUN_z
        // and names the cycle from there.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_z", "  FUN_m(1);\n"),
            function("FUN_m", "  FUN_z(1);\n"),
        ]);

        assert_eq!(cycles(&findings), vec![("FUN_z", vec!["FUN_z", "FUN_m"])]);
    }

    #[test]
    fn an_acyclic_call_shape_fabricates_no_cycle() {
        // A plain call tree: FUN_a → FUN_b → FUN_d, FUN_a → FUN_d.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_a", "  FUN_b(1);\n  FUN_d(2);\n"),
            function("FUN_b", "  FUN_d(1);\n"),
            function("FUN_d", "  return;\n"),
        ]);

        assert!(findings.is_empty(), "a call tree is not recursion");
    }

    #[test]
    fn a_plain_self_call_is_not_mutual_recursion() {
        // The per-body recursion finding already covers the self-call;
        // the cross-function pass must not double-report it as a cycle.
        let findings = CrossFunctionAnalyzer::new()
            .analyze(&[function("FUN_a", "  if (n) return FUN_a(n - 1);\n")]);

        assert!(findings.is_empty(), "a self-call is not a 2-cycle");
    }

    #[test]
    fn each_cycle_lands_once_however_many_edges_and_rotations_it_carries() {
        // FUN_a ↔ FUN_b with three call sites between them, and the
        // 3-cycle reached from every member's perspective: still one
        // finding per cycle.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_a", "  FUN_b(1);\n  FUN_b(2);\n  FUN_c(3);\n"),
            function("FUN_b", "  FUN_a(1);\n  FUN_a(2);\n"),
            function("FUN_c", "  FUN_a(1);\n"),
        ]);

        let found = cycles(&findings);
        assert_eq!(
            found,
            vec![
                ("FUN_a", vec!["FUN_a", "FUN_b"]),
                ("FUN_a", vec!["FUN_a", "FUN_c"]),
            ],
            "each ring once, not once per edge or per member"
        );
    }

    #[test]
    fn two_distinct_cycles_sharing_a_function_land_two_findings() {
        // FUN_a ↔ FUN_b and FUN_a → FUN_c → FUN_a: two rings, two
        // findings, both attached to the earliest shared member.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_a", "  FUN_b(1);\n  FUN_c(1);\n"),
            function("FUN_b", "  FUN_a(1);\n"),
            function("FUN_c", "  FUN_a(1);\n"),
        ]);

        assert_eq!(
            cycles(&findings),
            vec![
                ("FUN_a", vec!["FUN_a", "FUN_b"]),
                ("FUN_a", vec!["FUN_a", "FUN_c"]),
            ]
        );
    }

    #[test]
    fn calls_spelled_inside_string_literals_fabricate_no_edges() {
        // FUN_b only names FUN_a inside a string literal, so the only
        // visible edge is FUN_a → FUN_b and no ring closes.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_a", "  FUN_b(1);\n"),
            function("FUN_b", "  puts(\"FUN_a(keeps calling me)\");\n"),
        ]);

        assert!(findings.is_empty(), "a string literal is not a call");
    }

    #[test]
    fn longer_identifiers_sharing_a_name_prefix_fabricate_no_edges() {
        // FUN_b calls FUN_a_helper and myFUN_a — neither is FUN_a — so
        // the FUN_a → FUN_b edge stands alone and no ring closes.
        let findings = CrossFunctionAnalyzer::new().analyze(&[
            function("FUN_a", "  FUN_b(1);\n"),
            function("FUN_b", "  FUN_a_helper(1);\n  myFUN_a(2);\n"),
        ]);

        assert!(
            findings.is_empty(),
            "a longer identifier sharing the prefix is not a call"
        );
    }

    #[test]
    fn the_analyzer_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionAnalyzer>();
    }
}

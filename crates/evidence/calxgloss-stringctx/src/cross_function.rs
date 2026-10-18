//! Cross-function string correlation over the bodies the scan keeps.
//!
//! The per-body readings stop at a function's closing brace: a function
//! that holds a string and hands it into another program function — a
//! logger, an error reporter, an output routine — is invisible to a scan
//! that reads one body at a time, and the translator sees the callee's
//! string parameter as opaque and the caller's payload as an unrelated
//! literal. This module closes that gap over the bodies one scan already
//! holds, mirroring the memory crate's cross-function pass (ADR-0027),
//! the sync crate's (ADR-0033), and the callback crate's (ADR-0035): the
//! call map is derived from the kept bodies with the shared
//! identifier-boundary-aware, string-literal-blind call-site scan
//! ([`call_sites`]), and the argument reading reuses the mapper's own
//! literal and `DAT_` resolution, so no new
//! [`ScanSource`](crate::engine::ScanSource) reads are made and the
//! exactly-once-decompile guarantee and the skip-rate breaker survive
//! untouched.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the reading: a kept body
//! spelling a call whose callee is *another program function* — present
//! among the kept bodies, so not an import, and not one of the mapper's
//! format functions, whose calls the format reading already owns — with a
//! readable string argument lands one [`CrossFunctionFlow`] per (passing
//! function, receiving function, string) triple, attached to whichever
//! end comes earlier in listing order, the first matching call site
//! winning.
//!
//! The honesty gates mirror the crate's existing rules: a string handed
//! to an imported API claims no internal flow; a string held in a
//! variable the mapper cannot resolve claims nothing — the same rule as
//! an unreadable format argument; a function whose decompile failed
//! contributes no body and binds no edge; a name spelled inside a string
//! literal or only as part of a longer identifier invents no edge; and a
//! truncated body correlates its visible call lines — a call whose `(`
//! never closes claims no use the scan cannot see.

use std::collections::{HashMap, HashSet};

use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::{NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at};

use crate::hybrid_mapper::{HybridXrefMapper, index_by_value, read_string_arg};
use crate::types::{Confidence, CrossFunctionFlow};

/// Confidence of a string flow read across a call boundary: the edge is
/// an explicit call in a body the scan holds, so the claim sits level
/// with an in-body call claim — and with a callback chain.
pub const CROSS_FUNCTION_CONFIDENCE: u8 = 70;

/// The Rust shape a cross-function string flow suggests: the callee's
/// opaque parameter reads as a string pointer, and the caller's payload
/// is that string.
pub const CROSS_FUNCTION_SUGGESTION: &str = "the receiving parameter translates as a string type \
                                             (`*const i8`/`&str`) and the caller's payload is \
                                             that string";

/// The call scan: plain-identifier callees, member accesses and
/// qualified tails skipped, and C keywords are not calls — the same
/// shared pseudo-C configuration every other cross-function pass uses,
/// quote-aware so a name spelled inside a string literal calls nothing
/// and an unterminated call (a truncated decompile) yields nothing.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>:",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Cross-function string flows over the bodies one scan holds.
///
/// The analyzer is stateless: every reading comes from the bodies it is
/// handed, the string table, and the mapper's configured format-function
/// list, so one analyzer serves an entire scan. It fetches nothing
/// itself — the engine hands it the same [`DecompiledFunction`] values
/// the per-function pass already decompiled and the same string table
/// the walk already holds, keeping the scan at one decompile per
/// function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the bodies, string table, and
    /// format-function list come in at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function flows the program carries, in listing order:
    /// for every pair of kept bodies in listing order, a readable string
    /// one passes into the other lands one [`CrossFunctionFlow`] on the
    /// earlier function, naming the partner as the other end. A pair
    /// claims at most one flow per (passing, receiving, string) triple,
    /// the first matching call site in body order winning, and the two
    /// directions of one pair are different flows — the passing end and
    /// the receiving end swap.
    ///
    /// A callee the kept bodies do not name is an import (or a function
    /// whose decompile failed) and claims no flow; so do the mapper's
    /// format functions, whose calls the format reading already owns,
    /// and a function's own name, which crosses no function boundary. A
    /// function whose body never made it — skipped by the engine — is
    /// simply absent from `functions`, so it passes nothing, receives
    /// nothing, and fabricates no flow.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        string_table: &HashMap<u64, String>,
        mapper: &HybridXrefMapper,
    ) -> Vec<CrossFunctionFlow> {
        // Name → listing position. A kept body is a listing entry the
        // scan holds, so membership in this map is exactly the "program
        // function, not an import, not a skipped function" gate.
        let mut program: HashMap<&str, usize> = HashMap::new();
        for (position, function) in functions.iter().enumerate() {
            program.entry(function.name.as_str()).or_insert(position);
        }
        let format_functions: HashSet<&str> = mapper.format_function_names().collect();
        let by_value = index_by_value(string_table);

        // The flow edges each body carries, in body order: every call to
        // another program function with a readable string argument,
        // deduped by (callee, string) so the first call site wins.
        let edges: Vec<Vec<FlowEdge>> = functions
            .iter()
            .map(|function| {
                flow_edges(
                    function,
                    &program,
                    &format_functions,
                    string_table,
                    &by_value,
                )
            })
            .collect();

        // Pair-major in listing order, both directions of one pair
        // apart from each other (the callback-chain precedent): every
        // flow attaches to the pair's earlier function, so the findings
        // come out attached to the listing's functions in order.
        let mut findings = Vec::new();
        for earlier in 0..functions.len() {
            for later in (earlier + 1)..functions.len() {
                for (passer, receiver) in [(earlier, later), (later, earlier)] {
                    for edge in edges[passer].iter().filter(|edge| edge.callee == receiver) {
                        findings.push(CrossFunctionFlow {
                            function: functions[earlier].name.clone(),
                            passing_function: functions[passer].name.clone(),
                            receiving_function: functions[receiver].name.clone(),
                            string_value: edge.string_value.clone(),
                            string_address: edge.string_address,
                            evidence: edge.evidence.clone(),
                            confidence: Confidence::new(CROSS_FUNCTION_CONFIDENCE),
                        });
                    }
                }
            }
        }
        findings
    }
}

/// One readable string a body hands to another program function: the
/// callee's listing position, the string and its address, and the call's
/// own line kept as evidence.
struct FlowEdge {
    callee: usize,
    string_value: String,
    string_address: u64,
    evidence: String,
}

/// The flow edges one body carries, in body order.
///
/// The calls come from the shared quote-aware, boundary-aware scan, so a
/// callee name spelled inside a string literal or as the tail of a
/// longer name claims no edge here. A callee that is the body's own
/// function, one of the mapper's format functions, or no kept body at
/// all claims nothing; each surviving (callee, string) pair keeps only
/// its first call site.
fn flow_edges(
    function: &DecompiledFunction,
    program: &HashMap<&str, usize>,
    format_functions: &HashSet<&str>,
    string_table: &HashMap<u64, String>,
    by_value: &HashMap<&str, u64>,
) -> Vec<FlowEdge> {
    let mut edges = Vec::new();
    let mut seen: HashSet<(usize, String)> = HashSet::new();
    for call in call_sites(&function.body, &CALL_SCAN) {
        if call.callee == function.name || format_functions.contains(call.callee) {
            continue;
        }
        let Some(&callee) = program.get(call.callee) else {
            continue;
        };
        for arg in &call.args {
            let Some((string_value, string_address)) = read_string_arg(arg, string_table, by_value)
            else {
                continue;
            };
            if !seen.insert((callee, string_value.clone())) {
                continue;
            }
            edges.push(FlowEdge {
                callee,
                string_value,
                string_address,
                evidence: line_at(&function.body, call.offset),
            });
        }
    }
    edges
}

// ============================================================
// Tests
// ============================================================

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

    /// The analyzer over hand-written bodies, in listing order, with the
    /// standard mapper's format-function list and no string table.
    fn analyze(bodies: &[(&str, &str)]) -> Vec<CrossFunctionFlow> {
        analyze_with(bodies, &HashMap::new())
    }

    fn analyze_with(
        bodies: &[(&str, &str)],
        string_table: &HashMap<u64, String>,
    ) -> Vec<CrossFunctionFlow> {
        let functions: Vec<DecompiledFunction> = bodies
            .iter()
            .map(|(name, body)| function(name, body))
            .collect();
        CrossFunctionAnalyzer::new().analyze(&functions, string_table, &HybridXrefMapper::new())
    }

    /// A string table naming one value at `0x180128cf0`.
    fn table() -> HashMap<u64, String> {
        [(
            0x180128cf0u64,
            "********** Chat logging turned OFF.".to_string(),
        )]
        .into_iter()
        .collect()
    }

    #[test]
    fn a_direct_literal_handed_to_another_program_function_lands_one_flow() {
        let flows = analyze(&[
            ("FUN_18003ab00", "  FUN_18003e750(\"Journal.txt\");\n"),
            ("FUN_18003e750", "  return;\n"),
        ]);

        assert_eq!(flows.len(), 1);
        let flow = &flows[0];
        // Attached to the earlier of the two in listing order, naming
        // both ends and the flowing string.
        assert_eq!(flow.function, "FUN_18003ab00");
        assert_eq!(flow.passing_function, "FUN_18003ab00");
        assert_eq!(flow.receiving_function, "FUN_18003e750");
        assert_eq!(flow.string_value, "Journal.txt");
        // The literal's value the table names no address for carries 0,
        // the classified records' convention.
        assert_eq!(flow.string_address, 0);
        // The passing call line is the evidence.
        assert_eq!(flow.evidence, "FUN_18003e750(\"Journal.txt\");");
        // Level with an in-body call claim and a callback chain.
        assert_eq!(flow.confidence, Confidence::new(70));
    }

    #[test]
    fn a_resolved_dat_reference_flows_like_a_direct_literal() {
        let flows = analyze_with(
            &[
                ("FUN_18003ab00", "  FUN_18003e750(DAT_180128cf0);\n"),
                ("FUN_18003e750", "  return;\n"),
            ],
            &table(),
        );

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].string_value, "********** Chat logging turned OFF.");
        assert_eq!(flows[0].string_address, 0x180128cf0);
        assert_eq!(flows[0].evidence, "FUN_18003e750(DAT_180128cf0);");
    }

    #[test]
    fn one_flow_per_triple_and_the_first_call_site_wins() {
        // The same string handed to the same callee twice records once,
        // on its first call site; a different string is a different
        // triple and lands its own flow.
        let flows = analyze(&[
            (
                "FUN_18003ab00",
                "  FUN_18003e750(\"Journal.txt\");\n\
                 \x20 FUN_18003e750(\"Journal.txt\");\n\
                 \x20 FUN_18003e750(\"eqgame.ini\");\n",
            ),
            ("FUN_18003e750", "  return;\n"),
        ]);

        assert_eq!(flows.len(), 2, "one flow per (passing, receiving, string)");
        assert_eq!(flows[0].string_value, "Journal.txt");
        assert_eq!(flows[0].evidence, "FUN_18003e750(\"Journal.txt\");");
        assert_eq!(flows[1].string_value, "eqgame.ini");
    }

    #[test]
    fn the_flow_attaches_to_the_earlier_function_whichever_end_passes() {
        // The later function passes; the finding still attaches to the
        // listing's earlier one, naming the passer as the other end.
        let flows = analyze(&[
            ("FUN_18003e750", "  return;\n"),
            ("FUN_18003ab00", "  FUN_18003e750(\"Journal.txt\");\n"),
        ]);

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].function, "FUN_18003e750");
        assert_eq!(flows[0].passing_function, "FUN_18003ab00");
        assert_eq!(flows[0].receiving_function, "FUN_18003e750");
    }

    #[test]
    fn both_directions_of_one_pair_land_their_own_flow() {
        // The passing and receiving ends swap, so these are different
        // flows — both attached to the earlier function, the pair's own
        // direction order deciding.
        let flows = analyze(&[
            ("FUN_18003ab00", "  FUN_18003e750(\"out\");\n"),
            ("FUN_18003e750", "  FUN_18003ab00(\"in\");\n"),
        ]);

        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].passing_function, "FUN_18003ab00");
        assert_eq!(flows[0].string_value, "out");
        assert_eq!(flows[1].passing_function, "FUN_18003e750");
        assert_eq!(flows[1].string_value, "in");
        assert_eq!(flows[0].function, "FUN_18003ab00");
        assert_eq!(flows[1].function, "FUN_18003ab00");
    }

    #[test]
    fn flows_come_back_in_listing_order() {
        // Pair-major over the listing: every flow attached to the
        // listing's earlier function comes before any flow attached to
        // a later one, so the appended block stays diffable.
        let flows = analyze(&[
            ("FUN_18003ab00", "  FUN_1800412a0(\"late\");\n"),
            ("FUN_18003e750", "  FUN_1800412a0(\"own\");\n"),
            ("FUN_1800412a0", "  return;\n"),
        ]);

        let attached: Vec<&str> = flows.iter().map(|flow| flow.function.as_str()).collect();
        assert_eq!(attached, ["FUN_18003ab00", "FUN_18003e750"]);
    }

    #[test]
    fn a_string_handed_to_an_import_claims_no_flow() {
        // Ordinary API usage — a string straight into `CreateFileA` or a
        // `DAT_` into `OutputDebugStringA` — is not internal plumbing.
        let flows = analyze_with(
            &[
                (
                    "FUN_18003ab00",
                    "  lFile = CreateFileA(\"Journal.txt\",0xc0000000,0,0,3,0x80,0);\n\
                     \x20 OutputDebugStringA(DAT_180128cf0);\n",
                ),
                ("FUN_18003e750", "  return;\n"),
            ],
            &table(),
        );

        assert!(flows.is_empty(), "an imported API receives no claimed flow");
    }

    #[test]
    fn a_string_held_in_an_unresolved_variable_claims_no_flow() {
        // The same honesty rule as an unreadable format argument: a
        // variable, a cast, and a `DAT_` the table names no string for
        // are all strings the scan cannot read, so they bind nothing.
        let flows = analyze_with(
            &[
                (
                    "FUN_18003ab00",
                    "  FUN_18003e750(pcVar1);\n\
                     \x20 FUN_18003e750((char *)DAT_180128cf0);\n\
                     \x20 FUN_18003e750(DAT_180129999);\n",
                ),
                ("FUN_18003e750", "  return;\n"),
            ],
            &table(),
        );

        assert!(flows.is_empty(), "an unreadable argument binds no edge");
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_calls_nothing() {
        // The mapper's blindness, held across the pass: a call shape —
        // even one carrying a readable string or a resolvable `DAT_` —
        // written inside a quoted span is text, not a call.
        let flows = analyze_with(
            &[
                (
                    "FUN_18003ab00",
                    "  log_line(\"call FUN_18003e750(\\\"Journal.txt\\\") now\");\n\
                     \x20 log_line(\"FUN_18003e750(DAT_180128cf0)\");\n",
                ),
                ("FUN_18003e750", "  return;\n"),
            ],
            &table(),
        );

        assert!(flows.is_empty(), "a string literal spells no call");
    }

    #[test]
    fn a_longer_or_qualified_name_calls_nothing() {
        // A thunk or wrapper whose name carries the program function's
        // name as a tail, and a member access, are not calls to it.
        let flows = analyze(&[
            (
                "FUN_18003ab00",
                "  thunk_FUN_18003e750(\"Journal.txt\");\n\
                 \x20 obj.FUN_18003e750(\"Journal.txt\");\n",
            ),
            ("FUN_18003e750", "  return;\n"),
        ]);

        assert!(flows.is_empty(), "a longer name calls nothing");
    }

    #[test]
    fn a_format_function_call_is_read_as_a_format_call_not_a_flow() {
        // Even a program function spelled like one of the mapper's
        // format functions keeps its calls to the format reading — the
        // cross-function pass never claims them too.
        let flows = analyze(&[
            (
                "FUN_18003ab00",
                "  sprintf(local_10, \"%s: %d hits\", pcVar1, uVar2);\n",
            ),
            ("sprintf", "  return;\n"),
        ]);

        assert!(flows.is_empty(), "the format reading owns the call");
    }

    #[test]
    fn a_function_passing_a_string_to_itself_crosses_no_boundary() {
        let flows = analyze(&[("FUN_18003ab00", "  FUN_18003ab00(\"again\");\n")]);

        assert!(flows.is_empty(), "a self-call is not a cross-function flow");
    }

    #[test]
    fn a_truncated_body_correlates_its_visible_calls_and_invents_no_use_it_cannot_see() {
        // A cut-off call claims nothing — its arguments are not there to
        // read — but a complete call line above the cut still flows.
        let flows = analyze(&[
            (
                "FUN_18003ab00",
                "  FUN_18003e750(\"visible\");\n\
                 \x20 FUN_18003e750(\"cut\n",
            ),
            ("FUN_18003e750", "  return;\n"),
        ]);

        assert_eq!(flows.len(), 1, "only the visible call line correlates");
        assert_eq!(flows[0].string_value, "visible");
        assert_eq!(flows[0].evidence, "FUN_18003e750(\"visible\");");

        let flows = analyze(&[
            ("FUN_18003ab00", "  FUN_18003e750(\"cut\n"),
            ("FUN_18003e750", "  return;\n"),
        ]);
        assert!(
            flows.is_empty(),
            "a body with nothing visible claims nothing"
        );
    }

    #[test]
    fn a_single_function_or_an_empty_program_flows_nothing() {
        assert!(analyze(&[("FUN_18003ab00", "  FUN_18003e750(\"x\");\n")]).is_empty());
        assert!(analyze(&[]).is_empty());
    }

    #[test]
    fn the_analyzer_can_be_shared_across_scans() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionAnalyzer>();
    }
}

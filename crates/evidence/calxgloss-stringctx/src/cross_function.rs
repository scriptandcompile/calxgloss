//! Cross-function string correlation over the bodies the scan keeps.
//!
//! Read one body at a time, and a string passing between functions is
//! invisible: a function may hold a string and pass it to another program
//! function — a logger, an error reporter, an output routine. The
//! translator then sees the callee's string parameter as opaque and the
//! caller's payload as an unrelated literal. This module closes that gap
//! over the bodies one scan already holds. It mirrors the memory crate's
//! cross-function pass (ADR-0027), the sync crate's (ADR-0033), and the
//! callback crate's (ADR-0035). The call map is derived from the kept
//! bodies with the shared call-site scan, which respects identifier
//! boundaries and ignores string literals ([`call_sites`]). The argument
//! reading reuses the mapper's own literal and `DAT_` resolution. So no
//! new [`ScanSource`](crate::engine::ScanSource) reads are made: the
//! exactly-once-decompile guarantee holds, and the skip-rate breaker still
//! works.
//!
//! [`CrossFunctionAnalyzer::analyze`] does the reading. A kept body shows
//! a call whose callee is *another program function* — it is present among
//! the kept bodies, so it is not an import — and it is not one of the
//! mapper's format functions, because the format reading already owns
//! those calls. When that call has a readable string argument, the reading
//! lands one [`CrossFunctionFlow`] per (passing function, receiving
//! function, string) triple. The flow attaches to whichever end comes
//! earlier in listing order, and the first matching call site wins.
//!
//! The honesty gates follow the crate's existing rules. A string passed to
//! an imported API claims no internal flow. A string held in a variable the
//! mapper cannot resolve claims nothing — the same rule as an unreadable
//! format argument. A function whose decompile failed contributes no body
//! and binds no edge. A name inside a string literal, or only part of a
//! longer identifier, invents no edge. A truncated body correlates only
//! its visible call lines: a call whose `(` never closes claims no use the
//! scan cannot see.

use std::collections::{HashMap, HashSet};

use calxgloss_decomp::DecompiledFunction;
use calxgloss_types::{NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at};

use crate::hybrid_mapper::{HybridXrefMapper, index_by_value, read_string_arg};
use crate::types::{Confidence, CrossFunctionFlow};

/// Evidence confidence for a string flow read across a call boundary. The
/// edge is an explicit call in a body the scan holds, so the claim sits
/// level with an in-body call claim, and with a callback chain.
pub const CROSS_FUNCTION_CONFIDENCE: u8 = 70;

/// The Rust shape a cross-function string flow suggests: the callee's
/// opaque parameter reads as a string pointer, and the caller's payload
/// is that string.
pub const CROSS_FUNCTION_SUGGESTION: &str = "the receiving parameter translates as a string type \
                                             (`*const i8`/`&str`) and the caller's payload is \
                                             that string";

/// The call scan. Callees are plain identifiers; member accesses and
/// qualified tails are skipped, and C keywords are never calls. This is
/// the same shared pseudo-C configuration every other cross-function pass
/// uses. It is aware of quotes, so a name inside a string literal calls
/// nothing, and an unterminated call (a truncated decompile) yields
/// nothing.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>:",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Cross-function string flows over the bodies one scan holds.
///
/// The analyzer keeps no state. Every reading comes from the bodies the
/// scan gives it, the string table, and the mapper's configured
/// format-function list, so one analyzer serves a whole scan. It fetches
/// nothing itself: the scan gives it the same [`DecompiledFunction`]
/// values the per-function pass already decompiled and the same string
/// table the walk already holds. The scan therefore still decompiles each
/// function once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state. The bodies, string table, and
    /// format-function list come in at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function flows the program has, in listing order. For
    /// every pair of kept bodies in listing order, a readable string that
    /// one passes into the other lands one [`CrossFunctionFlow`] on the
    /// earlier function, naming the partner as the other end. A pair claims
    /// at most one flow per (passing, receiving, string) triple, and the
    /// first matching call site in body order wins. The two directions of
    /// one pair are different flows: the passing end and the receiving end
    /// swap.
    ///
    /// If the kept bodies do not name a callee, it is an import or a
    /// function whose decompile failed, and it claims no flow. The
    /// mapper's format functions claim no flow either, because the format
    /// reading already owns those calls. A function's own name crosses no
    /// function boundary, so it claims no flow. A function whose decompile
    /// was skipped is simply absent from `functions`, so it passes nothing,
    /// receives nothing, and produces no flow.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        string_table: &HashMap<u64, String>,
        mapper: &HybridXrefMapper,
    ) -> Vec<CrossFunctionFlow> {
        // Name → listing position. A kept body is a listing entry the
        // scan holds, so being in this map is exactly the "program
        // function, not an import, not a skipped function" gate.
        let mut program: HashMap<&str, usize> = HashMap::new();
        for (position, function) in functions.iter().enumerate() {
            program.entry(function.name.as_str()).or_insert(position);
        }
        let format_functions: HashSet<&str> = mapper.format_function_names().collect();
        let by_value = index_by_value(string_table);

        // The flow edges each body has, in body order: every call to
        // another program function with a readable string argument.
        // Duplicate (callee, string) pairs are dropped, so the first call
        // site wins.
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

        // Go pair by pair in listing order, and keep the two directions of
        // one pair apart (the callback-chain precedent). Every flow
        // attaches to the pair's earlier function, so the findings come out
        // attached to the listing's functions in order.
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

/// One readable string a body passes to another program function: the
/// callee's listing position, the string and its address, and the call's
/// own line, kept as evidence.
struct FlowEdge {
    callee: usize,
    string_value: String,
    string_address: u64,
    evidence: String,
}

/// The flow edges one body has, in body order.
///
/// The calls come from the shared scan that respects identifier boundaries
/// and ignores string literals. So a callee name inside a string literal,
/// or at the end of a longer name, claims no edge here. A callee that is
/// the body's own function, one of the mapper's format functions, or not a
/// kept body at all, claims nothing. Each surviving (callee, string) pair
/// keeps only its first call site.
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

    /// Run the analyzer over hand-written bodies, in listing order, with
    /// the standard mapper's format-function list and no string table.
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

    /// A string table with one value at `0x180128cf0`.
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
        // The finding attaches to the earlier of the two in listing order,
        // naming both ends and the string that flows.
        assert_eq!(flow.function, "FUN_18003ab00");
        assert_eq!(flow.passing_function, "FUN_18003ab00");
        assert_eq!(flow.receiving_function, "FUN_18003e750");
        assert_eq!(flow.string_value, "Journal.txt");
        // A literal the table names no address for has address 0, the
        // convention the classified records use.
        assert_eq!(flow.string_address, 0);
        // The passing call line is the evidence.
        assert_eq!(flow.evidence, "FUN_18003e750(\"Journal.txt\");");
        // Equal to an in-body call claim and to a callback chain.
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
        // The same string passed to the same callee twice is recorded once,
        // at its first call site. A different string is a different triple
        // and lands its own flow.
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
        // The later function does the passing. The finding still attaches
        // to the listing's earlier one, naming the passing function as the
        // other end.
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
        // flows. Both attach to the earlier function, in the pair's own
        // direction order.
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
        // Pair by pair over the listing: every flow attached to an earlier
        // function comes before any flow attached to a later one, so the
        // appended block stays diffable.
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
        // Ordinary API use — a string passed straight to `CreateFileA`, or
        // a `DAT_` to `OutputDebugStringA` — is not internal plumbing.
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
        // variable, a cast, and a `DAT_` the table names no string for are
        // all strings the scan cannot read, so they bind nothing.
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
        // The same blindness the mapper has, held across this pass: a call
        // shape — even one with a readable string or a resolvable `DAT_` —
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
        // A thunk or wrapper whose name ends with the program function's
        // name is not a call to it, and neither is a member access.
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
        // Even a program function named like one of the mapper's format
        // functions belongs to the format reading. The cross-function pass
        // never claims those calls too.
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
        // A cut-off call claims nothing: its arguments are not there to
        // read. A complete call line above the cut still flows.
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

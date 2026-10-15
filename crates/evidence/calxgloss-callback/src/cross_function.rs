//! Cross-function callback readings over the bodies the scan keeps.
//!
//! The per-body detectors stop at a function's closing brace: a
//! callback registered in one function and invoked in another — the
//! actual lifecycle of a callback — is invisible to each body read on
//! its own. This module closes that gap over the bodies one scan
//! already holds, mirroring the memory crate's cross-function pass
//! (ADR-0027) and the sync crate's (ADR-0033): the chain map is
//! derived from the fetched bodies with the same call-site scans the
//! detectors already use, so no new
//! [`ScanSource`](crate::engine::ScanSource) reads are made and the
//! exactly-once-decompile guarantee and the skip-rate breaker survive
//! untouched.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the reading: per body, the
//! registrations the registration detector binds, the direct-call
//! targets the shared call-site scan walks, and the tables the
//! fp-array and jump-table detectors read being called — all keyed on
//! the detectors' **configured name sets**, so custom spellings reach
//! this pass through the same sets the per-body readings use and the
//! two cannot disagree about what a registration or a table names. A
//! registration's bound callback name standing as a direct call
//! target in another kept body, or a table named at a registration
//! site being the same table an fp-array or jump-table reading calls
//! through, lands one [`CallbackFinding::Chain`] per (registering
//! function, calling function) pair on the earlier function in
//! listing order, naming the partner function, the callback, and the
//! table, with both ends' call lines as evidence.

use crate::callback_reg::{CallbackRegDetector, RegistrationSite, direct_calls};
use crate::fp_array::FpArrayDetector;
use crate::jump_table::JumpTableDetector;
use crate::types::{CallbackChain, CallbackFinding};
use calxgloss_ghidra::DecompiledFunction;
use calxgloss_types::line_at;

/// Confidence of a chain read across two bodies: both ends are
/// explicit body evidence — a recognized registration binding a named
/// callback on one side, that callback (or the table it was handed
/// through) being called on the other — so the claim sits level with
/// an in-body registration.
const CHAIN_CONFIDENCE: u8 = 70;

/// The Rust pattern a chain suggests: one boxed closure the
/// registering function hands out and the calling function reaches
/// through — the same closure shape a registration suggests, held
/// across the boundary instead of inside one body.
const CHAIN_SUGGESTION: &str =
    "Box<dyn Fn(...)> shared between the registering and calling functions";

/// Cross-function callback readings over the bodies one scan holds.
///
/// The analyzer is stateless: every reading comes from the bodies it
/// is handed and the three detectors' configured name sets it is
/// given, so one analyzer serves an entire scan. It fetches nothing
/// itself — the engine hands it the same [`DecompiledFunction`]
/// values the per-function pass already decompiled, keeping the scan
/// at one decompile per function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the name sets come in through the
    /// detectors at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function findings the program carries, in listing
    /// order: for every pair of kept bodies in listing order, a
    /// registration in one whose bound callback the other calls — by
    /// name, or through the same table the registration site named —
    /// lands one [`CallbackFinding::Chain`] on the earlier function,
    /// naming the later one as its partner. A pair claims at most one
    /// chain per direction (registering → calling), the first match
    /// in body order winning, so one registration pair reads once
    /// however many callbacks tie the two bodies.
    ///
    /// A function whose body never made it — skipped by the engine —
    /// is simply absent from `functions`, so it binds no registration,
    /// calls nothing, and fabricates no chain.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        registration: &CallbackRegDetector,
        fp_array: &FpArrayDetector,
        jump_table: &JumpTableDetector,
    ) -> Vec<CallbackFinding> {
        // The chain map, derived from the kept bodies themselves:
        // what each body registers, what each body calls directly,
        // and what each body calls a table through.
        let registrations: Vec<Vec<RegistrationSite>> = functions
            .iter()
            .map(|func| registration.detect_sites(func))
            .collect();
        let targets: Vec<Vec<CallTarget>> = functions.iter().map(call_targets).collect();
        let tables: Vec<Vec<TableCall>> = functions
            .iter()
            .map(|func| table_calls(func, fp_array, jump_table))
            .collect();

        let mut findings = Vec::new();
        for i in 0..functions.len() {
            for j in (i + 1)..functions.len() {
                let (earlier, later) = (&functions[i], &functions[j]);
                // Both directions of one pair are different chains:
                // the registering end and the calling end swap. Either
                // way the finding attaches to the earlier function in
                // listing order.
                for (reg_idx, call_idx) in [(i, j), (j, i)] {
                    if let Some(finding) = chain_for_pair(
                        earlier,
                        later,
                        &functions[reg_idx],
                        &functions[call_idx],
                        &registrations[reg_idx],
                        &targets[call_idx],
                        &tables[call_idx],
                    ) {
                        findings.push(finding);
                    }
                }
            }
        }
        findings
    }
}

/// A direct call target in a body: the callee name and the call's own
/// line, kept as chain evidence.
struct CallTarget {
    callee: String,
    line: String,
}

/// A call through a table in a body: the table name as the table
/// detectors read it and the call's own line, kept as chain evidence.
struct TableCall {
    table: String,
    line: String,
}

/// The direct-call targets one body carries, from the same shared
/// call-site scan the registration and plugin detectors use — outside
/// string literals, whole names only — so a name spelled in a format
/// string or as the tail of a longer or qualified name calls nothing
/// here either.
fn call_targets(func: &DecompiledFunction) -> Vec<CallTarget> {
    direct_calls(&func.body)
        .into_iter()
        .map(|call| CallTarget {
            callee: call.callee.to_string(),
            line: line_at(&func.body, call.offset),
        })
        .collect()
}

/// The table calls one body carries, from the two table detectors
/// themselves — the fp-array reading over its configured names and
/// the jump-table reading over its configured prefixes, each with its
/// own gates — so this pass calls through a table exactly when the
/// per-body detectors would report a table finding for it.
fn table_calls(
    func: &DecompiledFunction,
    fp_array: &FpArrayDetector,
    jump_table: &JumpTableDetector,
) -> Vec<TableCall> {
    let mut calls: Vec<TableCall> = fp_array
        .detect(func)
        .into_iter()
        .map(|call| TableCall {
            table: call.table,
            line: call.evidence,
        })
        .collect();
    calls.extend(jump_table.detect(func).into_iter().map(|table| TableCall {
        table: table.table,
        line: table.evidence,
    }));
    calls
}

/// The chain one pair of bodies carries, if any: the first
/// registration the registering body binds whose bound callback the
/// calling body calls — directly by name, or through a table under a
/// name the registration site spelled — wins, and the pair claims no
/// other. The finding attaches to `earlier`, the earlier of the two in
/// listing order, whichever end registered, and names `later` as its
/// partner.
fn chain_for_pair(
    earlier: &DecompiledFunction,
    later: &DecompiledFunction,
    registering: &DecompiledFunction,
    calling: &DecompiledFunction,
    registrations: &[RegistrationSite],
    targets: &[CallTarget],
    tables: &[TableCall],
) -> Option<CallbackFinding> {
    for site in registrations {
        let record = &site.record;
        // The callback's own spelling called directly in the partner
        // body: the whole chain is one name, no table in sight.
        let (table, call_line) = match targets.iter().find(|t| t.callee == record.callback) {
            Some(target) => (None, target.line.clone()),
            None => {
                // A name the registration site spelled — the handler
                // itself or a table handed over beside it — is a
                // configured table the partner body dispatches
                // through.
                match tables.iter().find(|t| site.named.contains(&t.table)) {
                    Some(call) => (Some(call.table.clone()), call.line.clone()),
                    None => continue,
                }
            }
        };
        return Some(CallbackFinding::Chain(CallbackChain {
            function: earlier.name.clone(),
            partner: later.name.clone(),
            callback: record.callback.clone(),
            table,
            suggestion: CHAIN_SUGGESTION.to_string(),
            confidence: CHAIN_CONFIDENCE.into(),
            evidence: format!(
                "{}: {} | {}: {}",
                registering.name, record.evidence, calling.name, call_line
            ),
        }));
    }
    None
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.into(),
            signature: format!("undefined {name}(void)"),
            body: body.into(),
        }
    }

    /// The pass over hand-written bodies with the detectors' standard
    /// name sets.
    fn analyze(bodies: &[(&str, &str)]) -> Vec<CallbackFinding> {
        analyze_with(
            bodies,
            &CallbackRegDetector::with_default_names(),
            &FpArrayDetector::with_default_names(),
            &JumpTableDetector::with_default_prefixes(),
        )
    }

    fn analyze_with(
        bodies: &[(&str, &str)],
        registration: &CallbackRegDetector,
        fp_array: &FpArrayDetector,
        jump_table: &JumpTableDetector,
    ) -> Vec<CallbackFinding> {
        let functions: Vec<DecompiledFunction> = bodies
            .iter()
            .map(|(name, body)| function(name, body))
            .collect();
        CrossFunctionAnalyzer::new().analyze(&functions, registration, fp_array, jump_table)
    }

    /// The single chain a two-function program lands, unwrapped.
    fn one_chain(bodies: &[(&str, &str)]) -> CallbackChain {
        let findings = analyze(bodies);
        assert_eq!(findings.len(), 1, "exactly one chain");
        let CallbackFinding::Chain(record) = &findings[0] else {
            unreachable!("the reading lands a chain finding");
        };
        record.clone()
    }

    #[test]
    fn a_registered_callback_called_in_another_body_lands_one_chain() {
        let record = one_chain(&[
            ("FUN_18003ab00", "  register_callback(my_handler);\n"),
            ("FUN_18003e750", "  my_handler(param_1);\n"),
        ]);
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.callback, "my_handler");
        assert_eq!(record.table, None, "a direct call runs through no table");
        assert_eq!(record.confidence.value(), CHAIN_CONFIDENCE);
        assert_eq!(record.suggestion, CHAIN_SUGGESTION);
        // Both ends' call lines ride as evidence, each named by its
        // function.
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: register_callback(my_handler); | \
             FUN_18003e750: my_handler(param_1);"
        );
    }

    #[test]
    fn the_chain_attaches_to_the_earlier_function_whichever_end_registers() {
        // The calling function stands first in the listing; the
        // finding still rides on it and names the registering one as
        // its partner.
        let record = one_chain(&[
            ("FUN_18003ab00", "  my_handler(param_1);\n"),
            ("FUN_18003e750", "  register_callback(my_handler);\n"),
        ]);
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.callback, "my_handler");
        // The evidence still names the registration first.
        assert_eq!(
            record.evidence,
            "FUN_18003e750: register_callback(my_handler); | \
             FUN_18003ab00: my_handler(param_1);"
        );
    }

    #[test]
    fn a_registration_naming_a_table_the_partner_calls_through_lands_a_chain() {
        // The registration site hands the table itself over; the
        // partner dispatches through that same name.
        let record = one_chain(&[
            ("FUN_18003ab00", "  register_callback(handlers);\n"),
            (
                "FUN_18003e750",
                "  (*(int (**)(int))handlers[uVar1])(param_1);\n",
            ),
        ]);
        assert_eq!(record.callback, "handlers");
        assert_eq!(record.table.as_deref(), Some("handlers"));
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: register_callback(handlers); | \
             FUN_18003e750: (*(int (**)(int))handlers[uVar1])(param_1);"
        );
    }

    #[test]
    fn a_jump_table_reading_calls_through_the_registered_table() {
        // The registered name is a configured jump-table symbol and
        // the partner body dispatches through it.
        let record = one_chain(&[
            ("FUN_18003ab00", "  SetOnMessage(switchD_1800412a0);\n"),
            (
                "FUN_18003e750",
                "  if (uVar3 < 5) {\n    (*(code *)(&switchD_1800412a0)[uVar3])();\n  }\n",
            ),
        ]);
        assert_eq!(record.callback, "switchD_1800412a0");
        assert_eq!(record.table.as_deref(), Some("switchD_1800412a0"));
    }

    #[test]
    fn a_table_handed_over_beside_the_handler_names_the_chain() {
        // The registration site spells two names: the handler it
        // binds first and a table handed over beside it. The partner
        // dispatches through that table — the chain names the handler
        // as the callback and the table as the way through, even
        // though the handler's own name never appears in the partner.
        let record = one_chain(&[
            (
                "FUN_18003ab00",
                "  register_callback(on_message, &handler_table);\n",
            ),
            ("FUN_18003e750", "  handler_table[2](0, NULL);\n"),
        ]);
        assert_eq!(record.callback, "on_message");
        assert_eq!(record.table.as_deref(), Some("handler_table"));
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
    }

    #[test]
    fn a_callback_never_visibly_called_lands_no_chain() {
        // The registration stands alone: no kept body calls the name.
        assert!(
            analyze(&[
                ("FUN_18003ab00", "  register_callback(my_handler);\n"),
                ("FUN_18003e750", "  return;\n"),
            ])
            .is_empty()
        );
    }

    #[test]
    fn a_registration_and_its_call_in_one_body_claim_no_chain() {
        // The pass is cross-function: a body that registers a
        // callback and calls it itself says nothing about a boundary
        // the per-body readings already saw whole.
        assert!(
            analyze(&[(
                "FUN_18003ab00",
                "  register_callback(my_handler);\n  my_handler(param_1);\n",
            )])
            .is_empty()
        );
    }

    #[test]
    fn one_chain_per_registering_and_calling_pair() {
        // Two callbacks tie the same pair of bodies; the pair still
        // reads once, the first registration's chain winning.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "  register_callback(handler_a);\n  set_handler(handler_b);\n",
            ),
            (
                "FUN_18003e750",
                "  handler_a(param_1);\n  handler_b(param_2);\n",
            ),
        ]);
        assert_eq!(findings.len(), 1);
        let CallbackFinding::Chain(record) = &findings[0] else {
            unreachable!("the reading lands a chain finding");
        };
        assert_eq!(record.callback, "handler_a");
    }

    #[test]
    fn both_directions_land_their_own_chain() {
        // Each function registers a callback the other calls: two
        // (registering, calling) pairs, two chains, both attached to
        // the earlier function.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "  register_callback(handler_a);\n  handler_b(param_2);\n",
            ),
            (
                "FUN_18003e750",
                "  register_callback(handler_b);\n  handler_a(param_1);\n",
            ),
        ]);
        assert_eq!(findings.len(), 2);
        let callbacks: Vec<&str> = findings
            .iter()
            .map(|finding| match finding {
                CallbackFinding::Chain(record) => record.callback.as_str(),
                other => unreachable!("both findings are chains, got {other:?}"),
            })
            .collect();
        assert_eq!(callbacks, ["handler_a", "handler_b"]);
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
        }
    }

    #[test]
    fn one_registration_called_in_two_bodies_lands_one_chain_per_pair() {
        let findings = analyze(&[
            ("FUN_18003ab00", "  register_callback(my_handler);\n"),
            ("FUN_18003e750", "  my_handler(param_1);\n"),
            ("FUN_1800412a0", "  my_handler(param_2);\n"),
        ]);
        assert_eq!(findings.len(), 2);
        let partners: Vec<&str> = findings
            .iter()
            .map(|finding| match finding {
                CallbackFinding::Chain(record) => record.partner.as_str(),
                other => unreachable!("both findings are chains, got {other:?}"),
            })
            .collect();
        assert_eq!(partners, ["FUN_18003e750", "FUN_1800412a0"]);
    }

    #[test]
    fn findings_come_back_in_listing_order() {
        // Pairs walk in listing order: the (a, b) chain before the
        // (a, c) and (b, c) ones.
        let findings = analyze(&[
            ("FUN_a", "  register_callback(handler_a);\n"),
            (
                "FUN_b",
                "  handler_a(param_1);\n  register_callback(handler_b);\n",
            ),
            ("FUN_c", "  handler_b(param_2);\n"),
        ]);
        let pairs: Vec<(&str, &str)> = findings
            .iter()
            .map(|finding| match finding {
                CallbackFinding::Chain(record) => {
                    (record.function.as_str(), record.partner.as_str())
                }
                other => unreachable!("every finding is a chain, got {other:?}"),
            })
            .collect();
        assert_eq!(pairs, vec![("FUN_a", "FUN_b"), ("FUN_b", "FUN_c")]);
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_calls_nothing() {
        assert!(
            analyze(&[
                ("FUN_18003ab00", "  register_callback(my_handler);\n"),
                ("FUN_18003e750", "  printf(\"my_handler called me\");\n"),
            ])
            .is_empty()
        );
    }

    #[test]
    fn a_longer_or_qualified_name_calls_nothing() {
        // Whole names only: a longer spelling is a different callee,
        // and a member or qualified name the decompiler resolved is
        // another one.
        assert!(analyze(&[
            ("FUN_18003ab00", "  register_callback(my_handler);\n"),
            (
                "FUN_18003e750",
                "  my_handler_extra(param_1);\n  obj.my_handler(param_2);\n  ns::my_handler(param_3);\n",
            ),
        ])
        .is_empty());
    }

    #[test]
    fn an_indexed_read_that_is_not_called_dispatches_through_nothing() {
        // The partner body stores the table element rather than
        // calling through it — no table call, no chain.
        assert!(
            analyze(&[
                ("FUN_18003ab00", "  register_callback(handlers);\n"),
                ("FUN_18003e750", "  pf = handlers[uVar1];\n"),
            ])
            .is_empty()
        );
    }

    #[test]
    fn a_truncated_body_contributes_nothing() {
        // An unclosed registration call binds nothing and an unclosed
        // call names no target: a partial decompile fabricates no
        // chain from either side.
        assert!(
            analyze(&[
                ("FUN_18003ab00", "  register_callback(my_handler;\n"),
                ("FUN_18003e750", "  my_handler(param_1;\n"),
            ])
            .is_empty()
        );
    }

    #[test]
    fn custom_configured_names_reach_the_pass() {
        // The pass keys on the detectors' configured sets, not a
        // private default: a custom registration spelling and a
        // custom table name chain together, while the standard names
        // the swap replaced claim nothing on the same bodies.
        let registration = CallbackRegDetector::with_names(["HookMessage"]);
        let fp_array = FpArrayDetector::with_names(["msg_table"]);
        let jump_table = JumpTableDetector::with_default_prefixes();
        let bodies = [
            (
                "FUN_a",
                "  HookMessage(msg_table);\n  register_callback(handlers);\n",
            ),
            (
                "FUN_b",
                "  (*(code *)msg_table[uVar1])(param_1);\n  handlers[uVar2](param_2);\n",
            ),
        ];
        let findings = analyze_with(&bodies, &registration, &fp_array, &jump_table);
        assert_eq!(findings.len(), 1, "only the configured spellings chain");
        let CallbackFinding::Chain(record) = &findings[0] else {
            unreachable!("the reading lands a chain finding");
        };
        assert_eq!(record.callback, "msg_table");
        assert_eq!(record.table.as_deref(), Some("msg_table"));
    }

    #[test]
    fn detectors_with_no_names_claim_nothing() {
        // Empty configured sets mean the pass reads no registrations
        // and no tables, however shaped the bodies are.
        let findings = analyze_with(
            &[
                ("FUN_a", "  register_callback(handlers);\n"),
                ("FUN_b", "  handlers[uVar1](param_1);\n"),
            ],
            &CallbackRegDetector::new(),
            &FpArrayDetector::new(),
            &JumpTableDetector::new(),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn a_single_function_or_an_empty_program_claims_nothing() {
        assert!(analyze(&[("FUN_a", "  register_callback(my_handler);\n")]).is_empty());
        assert!(analyze(&[]).is_empty());
    }

    #[test]
    fn the_analyzer_can_be_shared_across_scans() {
        // One analyzer is driven over every scan of an engine, so
        // sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionAnalyzer>();
    }
}

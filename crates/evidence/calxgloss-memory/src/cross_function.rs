//! Cross-function lifecycle tracking.
//!
//! The per-function detectors stop at a body's closing brace: an
//! allocation the function never releases is invisible to the pairing,
//! and the callee that does release it pairs nothing because no
//! allocation sits in its own body. This module closes that gap over
//! the bodies one scan already holds: it derives the call map from the
//! fetched bodies — no extra Ghidra round trips — and reports the
//! lifecycles that cross a call boundary.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the reading for this ticket:
//! an allocation left open by [`open_allocations`](AllocatorTracker::open_allocations),
//! handed as a plain argument at a call site to a function this scan
//! decompiled, and released in that callee's body through a configured
//! deallocator naming the parameter it arrived in — one
//! [`MemoryFinding::CrossFunction`] on the allocating function, naming
//! the partner and the variable.

use std::collections::HashMap;

use crate::allocator::AllocatorTracker;
use crate::types::{CrossFunctionLifecycle, MemoryFinding};
use calxgloss_ghidra::DecompiledFunction;

use calxgloss_types::{
    NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, line_at, strip_casts,
};

/// The scan: demangled `operator.new` spellings stay whole (including
/// the `[]` of `operator.new[]`), member accesses are skipped, and C
/// keywords are not calls — the same configuration the pairing walk
/// uses, so both read the same call sites.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::DemangledDot,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Confidence of a lifecycle read across two bodies: both sides are
/// explicit calls to recognized names and the hand-off site is
/// concrete — this call, this argument — but the tie from the caller's
/// variable to the callee's parameter is the decompiler's positional
/// naming, not resolved data flow, so it sits level with an in-body
/// pair.
const CROSS_CONFIDENCE: u8 = 70;

/// The ownership pattern a cross-function pair reads as: the block
/// outlives its allocating function by moving into the callee, which
/// is exactly what a boxed value owns when it is handed over.
const CROSS_SUGGESTION: &str = "Box<T>";

/// Cross-function lifecycle readings over the bodies one scan holds.
///
/// The analyzer is stateless: every reading comes from the bodies it
/// is handed and the tracker's name sets it is given, so one analyzer
/// serves an entire scan. It fetches nothing itself — the engine hands
/// it the same [`DecompiledFunction`] values the per-function pass
/// already decompiled, keeping the scan at one decompile per function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the allocator name sets come in
    /// through the [`AllocatorTracker`] at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function findings the program carries, in listing
    /// order and, within one function, in allocation order.
    ///
    /// For every allocation the body leaves open, the reading looks
    /// for a direct call site where the variable appears as a plain
    /// argument (seen through any cast) to a callee this scan
    /// decompiled, and checks that callee's body for a release of the
    /// parameter that position names. The first such callee in source
    /// order wins — one moved block moves once — and a callee outside
    /// the scanned set (a library routine, a thunk that never
    /// decompiled) releases nothing this scan can see, so it claims
    /// nothing.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        tracker: &AllocatorTracker,
    ) -> Vec<MemoryFinding> {
        let scanned: HashMap<&str, usize> = functions
            .iter()
            .enumerate()
            .map(|(index, func)| (func.name.as_str(), index))
            .collect();
        let mut findings = Vec::new();
        for func in functions {
            for allocation in tracker.open_allocations(func) {
                for call in call_sites(&func.body, &CALL_SCAN) {
                    let Some(&callee_index) = scanned.get(call.callee) else {
                        continue;
                    };
                    let Some(position) = call.args.iter().position(|arg| {
                        let freed = strip_casts(arg, crate::allocator::is_type_word);
                        crate::allocator::plain_variable(&freed).as_deref()
                            == Some(allocation.variable.as_str())
                    }) else {
                        continue;
                    };
                    let callee = &functions[callee_index];
                    let Some(release) = release_of_parameter(callee, position, tracker) else {
                        continue;
                    };
                    findings.push(MemoryFinding::CrossFunction(CrossFunctionLifecycle {
                        function: func.name.clone(),
                        partner: callee.name.clone(),
                        variable: allocation.variable.clone(),
                        allocation_type: allocation.allocation_type,
                        suggestion: CROSS_SUGGESTION.to_string(),
                        confidence: CROSS_CONFIDENCE.into(),
                        evidence: format!(
                            "{} {} {}",
                            allocation.line,
                            line_at(&func.body, call.offset),
                            release
                        ),
                    }));
                    break;
                }
            }
        }
        findings
    }
}

/// The line in `callee`'s body where a configured deallocator releases
/// the parameter declared at `position`, or `None` when the body
/// releases that parameter nowhere.
///
/// The tie is positional: the argument sitting at `position` in the
/// call arrives in the parameter the callee's signature declares at
/// `position`, and the release must name that parameter as its first
/// argument, seen through any cast — the same reading the in-body
/// pairing applies to a local variable.
fn release_of_parameter(
    callee: &DecompiledFunction,
    position: usize,
    tracker: &AllocatorTracker,
) -> Option<String> {
    let parameter = callee.parameter_names().into_iter().nth(position)?;
    for call in call_sites(&callee.body, &CALL_SCAN) {
        if !tracker.deallocators().iter().any(|d| d == call.callee) {
            continue;
        }
        let freed = call
            .args
            .first()
            .map(|arg| strip_casts(arg, crate::allocator::is_type_word));
        if freed.as_deref().and_then(crate::allocator::plain_variable) == Some(parameter.as_str()) {
            return Some(line_at(&callee.body, call.offset));
        }
    }
    None
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocator::AllocatorSignature;
    use crate::types::AllocationType;

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.into(),
            signature: signature.into(),
            body: body.into(),
        }
    }

    fn analyze(functions: &[DecompiledFunction]) -> Vec<MemoryFinding> {
        CrossFunctionAnalyzer::new().analyze(functions, &AllocatorTracker::with_default_names())
    }

    fn cross(records: &[MemoryFinding]) -> Vec<(&str, &str, &str)> {
        records
            .iter()
            .map(|finding| match finding {
                MemoryFinding::CrossFunction(record) => (
                    record.function.as_str(),
                    record.partner.as_str(),
                    record.variable.as_str(),
                ),
                other => panic!("expected a cross-function finding, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn an_analyzer_carries_no_state() {
        assert_eq!(CrossFunctionAnalyzer::new(), CrossFunctionAnalyzer::new());
    }

    #[test]
    fn an_analyzer_can_be_shared_across_scans() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionAnalyzer>();
    }

    #[test]
    fn an_allocation_released_by_a_callee_is_reported() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        let findings = analyze(&program);
        assert_eq!(
            cross(&findings),
            vec![("FUN_18003ab00", "FUN_18003e750", "pvVar1")]
        );
        let MemoryFinding::CrossFunction(record) = &findings[0] else {
            unreachable!()
        };
        assert_eq!(record.allocation_type, AllocationType::Malloc);
        assert_eq!(record.suggestion, "Box<T>");
        assert_eq!(record.confidence.value(), 70);
        // The evidence spans both bodies: the allocation line, the
        // hand-off call, and the partner's release.
        assert!(record.evidence.contains("pvVar1 = malloc(0x20);"));
        assert!(record.evidence.contains("FUN_18003e750(pvVar1);"));
        assert!(record.evidence.contains("free(param_1);"));
    }

    #[test]
    fn an_allocation_released_in_its_own_body_claims_nothing() {
        // The pairing already owns this lifecycle; the cross-function
        // pass starts from what the pairing leaves open.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n  free(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn a_callee_outside_the_scanned_set_releases_nothing() {
        // `free` on a library callee's parameter is invisible: the
        // callee is not a function this scan decompiled.
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  external_free(pvVar1);\n",
        )];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn a_callee_that_never_releases_the_parameter_claims_nothing() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  use(param_1);\n",
            ),
        ];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn a_release_of_another_parameter_claims_nothing() {
        // The hand-off is at position 0; the callee releases the
        // parameter at position 1 — a different value.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1, other);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1, void *param_2)",
                "  free(param_2);\n",
            ),
        ];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn a_cast_over_the_argument_is_seen_through() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750((void *)pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        assert_eq!(cross(&analyze(&program)).len(), 1);
    }

    #[test]
    fn a_call_spelled_inside_a_string_literal_invents_nothing() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  printf(\"FUN_18003e750(pvVar1);\");\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn a_member_or_vtable_call_is_not_a_plain_call_site() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  obj.FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn the_first_releasing_callee_in_source_order_wins() {
        // One moved block moves once: the variable reaches two
        // releasing callees and only the first call site claims it.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n  FUN_18003abcd(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
            function(
                "FUN_18003abcd",
                "undefined FUN_18003abcd(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        assert_eq!(
            cross(&analyze(&program)),
            vec![("FUN_18003ab00", "FUN_18003e750", "pvVar1")]
        );
    }

    #[test]
    fn findings_follow_listing_order_then_allocation_order() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  pvVar2 = calloc(2, 0x10);\n  FUN_18003e750(pvVar2);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        assert_eq!(
            cross(&analyze(&program)),
            vec![
                ("FUN_18003ab00", "FUN_18003e750", "pvVar1"),
                ("FUN_18003ab00", "FUN_18003e750", "pvVar2"),
            ]
        );
    }

    #[test]
    fn a_void_callee_releases_nothing() {
        // A `(void)` signature declares no parameter for the argument
        // to arrive in.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  free(global_ptr);\n",
            ),
        ];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn custom_name_sets_reach_the_cross_function_reading() {
        let mut tracker = AllocatorTracker::new();
        tracker.add_allocator(AllocatorSignature::new(
            "mine_alloc",
            crate::types::AllocationType::Malloc,
        ));
        tracker.add_deallocator("mine_free");
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = mine_alloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  mine_free(param_1);\n",
            ),
        ];
        let findings = CrossFunctionAnalyzer::new().analyze(&program, &tracker);
        assert_eq!(cross(&findings).len(), 1);
    }
}

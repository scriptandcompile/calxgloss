//! Cross-function lifecycle tracking.
//!
//! The per-function detectors stop at a body's closing brace: an
//! allocation the function never releases is invisible to the pairing,
//! and the callee that does release it pairs nothing because no
//! allocation sits in its own body. This module closes that gap over
//! the bodies one scan already holds: it derives the call map from the
//! fetched bodies — no extra engine reads — and reports the
//! lifecycles that cross a call boundary.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the reading: an allocation
//! left open by [`open_allocations`](AllocatorTracker::open_allocations)
//! either pairs — handed as a plain argument to a function this scan
//! decompiled whose body releases the parameter it arrived in, one
//! [`MemoryFinding::CrossFunction`] naming the partner and the
//! variable — or escapes: handed to any callee or returned whole, one
//! [`MemoryFinding::Ownership`] naming the direction of the move — or
//! goes nowhere at all, one [`MemoryFinding::Leak`]: the block never
//! released and never handed on. The same escape gate reads the
//! handles [`open_handles`](HandleDetector::open_handles) leaves
//! standing: an unclosed handle that escapes is passed over, one that
//! escapes nowhere leaks by its opener.

use std::collections::HashMap;

use crate::allocator::AllocatorTracker;
use crate::handle::HandleDetector;
use crate::types::{
    CrossFunctionLifecycle, LeakResource, MemoryFinding, OwnershipTransfer, ResourceLeak,
    TransferDirection,
};
use calxgloss_decomp::DecompiledFunction;

use calxgloss_types::{
    NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites, is_ident_byte, line_at,
    skip_string, strip_casts,
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

/// Confidence of a transfer read from one body alone: the allocation
/// and the escape are both explicit body evidence, but what the far
/// side does with the value is unseen — the callee may store it, free
/// it, or just borrow it — so a transfer sits below a pair whose
/// release was actually read, at the same rung as the short-lived
/// stack reading.
const TRANSFER_CONFIDENCE: u8 = 65;

/// The ownership pattern a transfer reads as: the block outlives its
/// allocating function by moving out — into a callee or to the caller
/// — which is what a boxed value owns when it is moved.
const TRANSFER_SUGGESTION: &str = "Box<T>";

/// Confidence of a leak read from one body: the acquisition is
/// explicit and the absence of any release or escape is checked
/// against every call site the body carries, but an absence is only
/// what this body shows — the resource may be a deliberate
/// process-lifetime allocation, or released through a path the scan
/// cannot read — so a leak sits one rung below the transfer whose
/// move was actually read.
const LEAK_CONFIDENCE: u8 = 60;

/// The Rust pattern a leaked block suggests: a value boxed into the
/// scope that should have owned it, so the block is freed on exit and
/// the leak disappears with the owner.
const LEAK_SUGGESTION: &str = "Box<T>";

/// The Rust pattern a kept pointer suggests: the callee stored the
/// block somewhere the call survives — a global, a struct field — so
/// more than one place holds it at once, which is shared ownership,
/// not a move. `Arc<T>` stays the reference-count detector's
/// spelling; thread-awareness is out of scope.
const RC_SUGGESTION: &str = "Rc<T>";

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
    /// order and, within one function, in allocation order then open-
    /// handle order — one claim per open allocation.
    ///
    /// For every allocation the body leaves open, the reading looks
    /// for a direct call site where the variable appears as a plain
    /// argument (seen through any cast) to a callee this scan
    /// decompiled, and checks that callee's body for a release of the
    /// parameter that position names: a releasing callee makes a
    /// [`MemoryFinding::CrossFunction`] pair. An open allocation that
    /// reaches no releasing callee but does escape — handed as a plain
    /// argument at any call site, or returned whole to the caller —
    /// makes a [`MemoryFinding::Ownership`] transfer naming the
    /// direction. An open allocation that neither pairs nor escapes
    /// is a [`MemoryFinding::Leak`]: the block was taken and goes
    /// nowhere. The same escape gate reads the handles
    /// [`HandleDetector::open_handles`] leaves standing — an unclosed
    /// handle that escapes is someone else's problem and says
    /// nothing, one that escapes nowhere leaks by its opener. A callee
    /// outside the scanned set (a library routine, a thunk that never
    /// decompiled) releases nothing this scan can see, so it forms no
    /// pair — but the hand-off itself is still an escape, and the
    /// transfer reads it. Where one open variable both pairs and
    /// escapes, the pair wins: one moved block moves once. Where the
    /// callee reached by the pair or the transfer also *keeps* the
    /// block — stores the parameter into a global or a struct field
    /// — the suggestion upgrades from `Box<T>` to `Rc<T>` and the
    /// store line joins the evidence: more than one place holds the
    /// block, so the pattern is shared ownership, not a move.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        tracker: &AllocatorTracker,
        handles: &HandleDetector,
    ) -> Vec<MemoryFinding> {
        let scanned: HashMap<&str, usize> = functions
            .iter()
            .enumerate()
            .map(|(index, func)| (func.name.as_str(), index))
            .collect();
        let mut findings = Vec::new();
        for func in functions {
            for allocation in tracker.open_allocations(func) {
                let mut pair: Option<(&DecompiledFunction, String, usize)> = None;
                let mut escape: Option<Escape<'_>> = None;
                for call in call_sites(&func.body, &CALL_SCAN) {
                    let Some(position) = call.args.iter().position(|arg| {
                        let freed = strip_casts(arg, crate::allocator::is_type_word);
                        crate::allocator::plain_variable(&freed)
                            == Some(allocation.variable.as_str())
                    }) else {
                        continue;
                    };
                    if escape.is_none() {
                        escape = Some(Escape {
                            direction: TransferDirection::HandedToCallee,
                            partner: Some(call.callee),
                            position: Some(position),
                            line: line_at(&func.body, call.offset),
                        });
                    }
                    if pair.is_none()
                        && let Some(&callee_index) = scanned.get(call.callee)
                    {
                        let callee = &functions[callee_index];
                        if let Some(release) = release_of_parameter(callee, position, tracker) {
                            pair = Some((callee, release, position));
                        }
                    }
                }
                if let Some(offset) = return_site(&func.body, &allocation.variable)
                    && escape.is_none()
                {
                    escape = Some(Escape {
                        direction: TransferDirection::ReturnedToCaller,
                        partner: None,
                        position: None,
                        line: line_at(&func.body, offset),
                    });
                }
                if let Some((callee, release, position)) = pair {
                    // A callee that keeps the block — stores the
                    // parameter into a global or a field — shares it
                    // past the release, so the pattern is shared
                    // ownership, not a move.
                    let kept = keep_site(callee, position);
                    let mut evidence = format!(
                        "{} {} {}",
                        allocation.line,
                        // The releasing call is the first hand-off
                        // to the partner that named the variable.
                        line_at(
                            &func.body,
                            first_handoff(&func.body, &allocation.variable, callee)
                        ),
                        release
                    );
                    if let Some(keep) = &kept {
                        evidence.push(' ');
                        evidence.push_str(keep);
                    }
                    findings.push(MemoryFinding::CrossFunction(CrossFunctionLifecycle {
                        function: func.name.clone(),
                        partner: callee.name.clone(),
                        variable: allocation.variable.clone(),
                        allocation_type: allocation.allocation_type,
                        suggestion: if kept.is_some() {
                            RC_SUGGESTION
                        } else {
                            CROSS_SUGGESTION
                        }
                        .to_string(),
                        confidence: CROSS_CONFIDENCE.into(),
                        evidence,
                    }));
                } else if let Some(escape) = escape {
                    // The same keep reading upgrades a transfer to a
                    // scanned callee: the block was handed over *and*
                    // stored, so more than one place holds it.
                    let kept = escape
                        .position
                        .zip(escape.partner)
                        .and_then(|(position, name)| {
                            scanned
                                .get(name)
                                .map(|&index| (position, &functions[index]))
                        })
                        .and_then(|(position, callee)| keep_site(callee, position));
                    let mut evidence = format!("{} {}", allocation.line, escape.line);
                    if let Some(keep) = &kept {
                        evidence.push(' ');
                        evidence.push_str(keep);
                    }
                    findings.push(MemoryFinding::Ownership(OwnershipTransfer {
                        function: func.name.clone(),
                        direction: escape.direction,
                        partner: escape.partner.map(str::to_string),
                        variable: allocation.variable.clone(),
                        allocation_type: allocation.allocation_type,
                        suggestion: if kept.is_some() {
                            RC_SUGGESTION
                        } else {
                            TRANSFER_SUGGESTION
                        }
                        .to_string(),
                        confidence: TRANSFER_CONFIDENCE.into(),
                        evidence,
                    }));
                } else {
                    findings.push(MemoryFinding::Leak(ResourceLeak {
                        function: func.name.clone(),
                        variable: allocation.variable.clone(),
                        resource: LeakResource::Allocation {
                            allocation_type: allocation.allocation_type,
                        },
                        suggestion: LEAK_SUGGESTION.to_string(),
                        confidence: LEAK_CONFIDENCE.into(),
                        evidence: allocation.line.clone(),
                    }));
                }
            }
            for handle in handles.open_handles(func) {
                // The same escape gate: a handle handed to any callee
                // or returned whole left the function — whoever holds
                // it now answers for closing it. Only a handle that
                // goes nowhere leaks.
                if escapes(&func.body, &handle.variable) {
                    continue;
                }
                findings.push(MemoryFinding::Leak(ResourceLeak {
                    function: func.name.clone(),
                    variable: handle.variable,
                    resource: LeakResource::Handle {
                        handle_type: handle.handle_type,
                        opener: handle.opener,
                    },
                    suggestion: crate::handle::GUARD_SUGGESTION.to_string(),
                    confidence: LEAK_CONFIDENCE.into(),
                    evidence: handle.line,
                }));
            }
        }
        findings
    }
}

/// The escape an open allocation took: the direction it crossed the
/// boundary, the callee it reached and the argument position it
/// arrived at (a return names neither), and the line that shows it.
struct Escape<'a> {
    direction: TransferDirection,
    partner: Option<&'a str>,
    position: Option<usize>,
    line: String,
}

/// The line in `callee`'s body where the parameter declared at
/// `position` is kept — stored somewhere the call survives — or
/// `None` when the body keeps it nowhere.
///
/// The keep is an assignment whose right side, seen through any
/// cast, is the parameter whole, and whose left side names a place
/// outside the callee's own frame: a struct field (`obj.field =
/// param_1;`, `this->ptr = param_1;`) or a plain identifier the
/// decompiler did not name as one of its own locals — Ghidra names
/// locals `param_N`, `local_N`, and the `*Var<N>` families, so any
/// other plain name is a program symbol the block outlives the call
/// in. A store through a bare dereference names no place the scan
/// can tell from a stack slot, so it keeps nothing.
fn keep_site(callee: &DecompiledFunction, position: usize) -> Option<String> {
    let parameter = callee.parameter_names().into_iter().nth(position)?;
    let body = &callee.body;
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i = skip_string(bytes, i + 1);
                continue;
            }
            b'=' => {}
            _ => {
                i += 1;
                continue;
            }
        }
        // A comparison (`==`) or a compound assignment (`+=` and
        // friends) stores nothing.
        if bytes.get(i + 1).is_some_and(|b| *b == b'=')
            || i > 0
                && matches!(
                    bytes[i - 1],
                    b'=' | b'!'
                        | b'<'
                        | b'>'
                        | b'+'
                        | b'-'
                        | b'*'
                        | b'/'
                        | b'%'
                        | b'&'
                        | b'|'
                        | b'^'
                )
        {
            i += 1;
            continue;
        }
        let line_start = body[..i].rfind('\n').map(|start| start + 1).unwrap_or(0);
        let left = body[line_start..i].trim();
        let Some(right_end) = body[i + 1..].find(';').map(|rest| i + 1 + rest) else {
            i += 1;
            continue;
        };
        let right = strip_casts(&body[i + 1..right_end], crate::allocator::is_type_word);
        if crate::allocator::plain_variable(&right) != Some(parameter.as_str()) {
            i += 1;
            continue;
        }
        if keeps_place(left) {
            return Some(line_at(body, i));
        }
        i += 1;
    }
    None
}

/// Whether an assignment's left side names a place outside the
/// callee's own frame: a field access, or a plain identifier the
/// decompiler did not name as one of its own locals.
fn keeps_place(left: &str) -> bool {
    if left.is_empty() {
        return false;
    }
    if left.contains('.') || left.contains("->") {
        return true;
    }
    crate::allocator::plain_variable(left).is_some_and(|name| !is_decompiler_local(name))
}

/// Whether `name` is one of the decompiler's own local spellings: a
/// parameter, a stack slot, or one of the typed-variable families
/// (`iVar1`, `uVar2`, `pcVar3`, …) — a `Var` followed by digits and
/// nothing else. Anything else a body assigns to is a program
/// symbol, which is what makes it a global.
fn is_decompiler_local(name: &str) -> bool {
    name.starts_with("param_")
        || name.starts_with("local_")
        || name.find("Var").is_some_and(|at| {
            let suffix = &name[at + 3..];
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Whether `variable` leaves this body: a plain argument (seen
/// through any cast) at any call site, or a whole return. The same
/// rule that turns an open allocation into a transfer gates the
/// handle leaks — a resource that left is someone else's to close,
/// not a leak.
fn escapes(body: &str, variable: &str) -> bool {
    call_sites(body, &CALL_SCAN).into_iter().any(|call| {
        call.args.iter().any(|arg| {
            let freed = strip_casts(arg, crate::allocator::is_type_word);
            crate::allocator::plain_variable(&freed) == Some(variable)
        })
    }) || return_site(body, variable).is_some()
}

/// The offset of the first call site handing `variable` (as a plain
/// argument, seen through any cast) to `callee`, for the pair's
/// evidence line. Falls back to the allocation line's own position —
/// the pair cannot form without such a site, so this only guards the
/// type.
fn first_handoff(body: &str, variable: &str, callee: &DecompiledFunction) -> usize {
    call_sites(body, &CALL_SCAN)
        .into_iter()
        .find(|call| {
            call.callee == callee.name
                && call.args.iter().any(|arg| {
                    let freed = strip_casts(arg, crate::allocator::is_type_word);
                    crate::allocator::plain_variable(&freed) == Some(variable)
                })
        })
        .map(|call| call.offset)
        .unwrap_or(0)
}

/// The offset of the `return` statement that hands `variable` whole to
/// the caller — seen through any cast — or `None` when the body never
/// returns it. `return pvVar1;` and `return (void *)pvVar1;` return
/// the block; `return;`, `return pvVar1 + 1;`, and a return of
/// anything else move nothing.
fn return_site(body: &str, variable: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i = skip_string(bytes, i + 1);
            continue;
        }
        if bytes[i..].starts_with(b"return")
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
            && !bytes.get(i + 6).is_some_and(|b| is_ident_byte(*b))
        {
            let expression_end = body[i + 6..].find(';').map(|rest| i + 6 + rest);
            if let Some(end) = expression_end {
                let expression = body[i + 6..end].trim();
                let seen = strip_casts(expression, crate::allocator::is_type_word);
                if crate::allocator::plain_variable(&seen) == Some(variable) {
                    return Some(i);
                }
            }
            i += 6;
            continue;
        }
        i += 1;
    }
    None
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
        CrossFunctionAnalyzer::new().analyze(
            functions,
            &AllocatorTracker::with_default_names(),
            &HandleDetector::with_default_names(),
        )
    }

    fn claims(records: &[MemoryFinding]) -> Vec<(&str, &str, &str)> {
        records
            .iter()
            .filter_map(|finding| match finding {
                MemoryFinding::CrossFunction(record) => Some((
                    record.function.as_str(),
                    record.partner.as_str(),
                    record.variable.as_str(),
                )),
                _ => None,
            })
            .collect()
    }

    fn transfers(records: &[MemoryFinding]) -> Vec<(&str, &str, &str, Option<&str>)> {
        records
            .iter()
            .filter_map(|finding| match finding {
                MemoryFinding::Ownership(record) => Some((
                    record.function.as_str(),
                    record.variable.as_str(),
                    match record.direction {
                        TransferDirection::HandedToCallee => "handed_to_callee",
                        TransferDirection::ReturnedToCaller => "returned_to_caller",
                    },
                    record.partner.as_deref(),
                )),
                _ => None,
            })
            .collect()
    }

    /// The leak findings in `findings`, in report order: the function,
    /// the variable, and the resource the record names — the
    /// allocation family or the opener.
    fn leaks(records: &[MemoryFinding]) -> Vec<(&str, &str, String)> {
        records
            .iter()
            .filter_map(|finding| match finding {
                MemoryFinding::Leak(record) => Some((
                    record.function.as_str(),
                    record.variable.as_str(),
                    match &record.resource {
                        LeakResource::Allocation { allocation_type } => allocation_type.to_string(),
                        LeakResource::Handle { opener, .. } => opener.clone(),
                    },
                )),
                _ => None,
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
            claims(&findings),
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
    fn a_callee_outside_the_scanned_set_hands_the_pointer_over() {
        // The release cannot be *named* — the callee was not scanned —
        // but the hand-off itself is still what a Rust author should
        // see, so the escape reads as a transfer.
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  external_free(pvVar1);\n",
        )];
        let findings = analyze(&program);
        assert!(claims(&findings).is_empty());
        assert_eq!(
            transfers(&findings),
            vec![(
                "FUN_18003ab00",
                "pvVar1",
                "handed_to_callee",
                Some("external_free")
            )]
        );
    }

    #[test]
    fn a_callee_that_never_releases_the_parameter_hands_it_over() {
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
        let findings = analyze(&program);
        assert!(claims(&findings).is_empty());
        assert_eq!(
            transfers(&findings),
            vec![(
                "FUN_18003ab00",
                "pvVar1",
                "handed_to_callee",
                Some("FUN_18003e750")
            )]
        );
    }

    #[test]
    fn a_release_of_another_parameter_claims_nothing_but_the_hand_off() {
        // The hand-off is at position 0; the callee releases the
        // parameter at position 1 — a different value. The pair fails,
        // the escape stands.
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
        let findings = analyze(&program);
        assert!(claims(&findings).is_empty());
        assert_eq!(
            transfers(&findings),
            vec![(
                "FUN_18003ab00",
                "pvVar1",
                "handed_to_callee",
                Some("FUN_18003e750")
            )]
        );
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
        assert_eq!(claims(&analyze(&program)).len(), 1);
    }

    #[test]
    fn a_call_spelled_inside_a_string_literal_invents_nothing() {
        // The spelled call inside the string forms no hand-off and no
        // pair — but the allocation really does stand open and reaches
        // nowhere, so the leak reading still sees it.
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
        let findings = analyze(&program);
        assert!(claims(&findings).is_empty());
        assert!(transfers(&findings).is_empty());
        assert_eq!(
            leaks(&findings),
            vec![("FUN_18003ab00", "pvVar1", "malloc".to_string())]
        );
    }

    #[test]
    fn a_member_call_pairs_with_nothing_but_hands_the_pointer_over() {
        // `obj.FUN_18003e750` is not a plain call to the scanned
        // function — the implicit receiver shifts the positional tie,
        // so no pair is claimed against that body — but the pointer
        // still leaves at this site, so the escape reads it with the
        // dotted callee as the named partner.
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
        let findings = analyze(&program);
        assert!(claims(&findings).is_empty());
        assert_eq!(
            transfers(&findings),
            vec![(
                "FUN_18003ab00",
                "pvVar1",
                "handed_to_callee",
                Some("obj.FUN_18003e750")
            )]
        );
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
            claims(&analyze(&program)),
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
            claims(&analyze(&program)),
            vec![
                ("FUN_18003ab00", "FUN_18003e750", "pvVar1"),
                ("FUN_18003ab00", "FUN_18003e750", "pvVar2"),
            ]
        );
    }

    #[test]
    fn a_void_callee_releases_nothing_but_hands_the_pointer_over() {
        // A `(void)` signature declares no parameter for the argument
        // to arrive in — the pair fails, the escape stands.
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
        let findings = analyze(&program);
        assert!(claims(&findings).is_empty());
        assert_eq!(
            transfers(&findings),
            vec![(
                "FUN_18003ab00",
                "pvVar1",
                "handed_to_callee",
                Some("FUN_18003e750")
            )]
        );
    }

    #[test]
    fn a_pointer_returned_whole_is_a_transfer_to_the_caller() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  return pvVar1;\n",
        )];
        assert_eq!(
            transfers(&analyze(&program)),
            vec![("FUN_18003ab00", "pvVar1", "returned_to_caller", None)]
        );
    }

    #[test]
    fn a_pointer_returned_through_a_cast_is_still_a_transfer() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  return (void *)pvVar1;\n",
        )];
        assert_eq!(
            transfers(&analyze(&program)),
            vec![("FUN_18003ab00", "pvVar1", "returned_to_caller", None)]
        );
    }

    #[test]
    fn a_return_of_something_else_transfers_nothing() {
        // `return pvVar1 + 1;` hands back an interior pointer, not the
        // block; a bare `return;` hands back nothing at all. Neither
        // escapes, so both blocks stand open and leak.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  return pvVar1 + 1;\n",
            ),
            function(
                "FUN_18003abcd",
                "undefined FUN_18003abcd(void)",
                "  pvVar1 = malloc(0x20);\n  return;\n",
            ),
        ];
        let findings = analyze(&program);
        assert!(transfers(&findings).is_empty());
        assert_eq!(
            leaks(&findings),
            vec![
                ("FUN_18003ab00", "pvVar1", "malloc".to_string()),
                ("FUN_18003abcd", "pvVar1", "malloc".to_string()),
            ]
        );
    }

    #[test]
    fn a_pair_wins_over_an_escape_of_the_same_allocation() {
        // The variable is both handed to a releasing callee and
        // returned — one moved block moves once, and the pair, whose
        // release was actually read, is the stronger claim.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n  return pvVar1;\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  free(param_1);\n",
            ),
        ];
        let findings = analyze(&program);
        assert_eq!(
            claims(&findings),
            vec![("FUN_18003ab00", "FUN_18003e750", "pvVar1")]
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_transfer_carries_the_move_evidence_and_confidence() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  parse(pvVar1);\n",
        )];
        let findings = analyze(&program);
        let MemoryFinding::Ownership(record) = &findings[0] else {
            unreachable!()
        };
        assert_eq!(record.allocation_type, AllocationType::Malloc);
        assert_eq!(record.suggestion, "Box<T>");
        assert_eq!(record.confidence.value(), 65);
        assert!(record.evidence.contains("pvVar1 = malloc(0x20);"));
        assert!(record.evidence.contains("parse(pvVar1);"));
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
        let findings = CrossFunctionAnalyzer::new().analyze(
            &program,
            &tracker,
            &HandleDetector::with_default_names(),
        );
        assert_eq!(claims(&findings).len(), 1);
    }

    // ------------------------------------------------------------
    // Leaks
    // ------------------------------------------------------------

    #[test]
    fn an_allocation_released_nowhere_and_handed_to_nothing_leaks() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  *pvVar1 = 0;\n",
        )];
        assert_eq!(
            leaks(&analyze(&program)),
            vec![("FUN_18003ab00", "pvVar1", "malloc".to_string())]
        );
    }

    #[test]
    fn an_escaped_allocation_is_a_transfer_not_a_leak() {
        // The escape rule is the false-positive gate: the same open
        // allocation reads as a transfer when it leaves, and the leak
        // reading stays silent.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  parse(pvVar1);\n  return pvVar2;\n",
            ),
            function(
                "FUN_18003abcd",
                "undefined FUN_18003abcd(void)",
                "  pvVar2 = malloc(0x20);\n  return pvVar2;\n",
            ),
        ];
        let findings = analyze(&program);
        assert_eq!(transfers(&findings).len(), 2);
        assert!(leaks(&findings).is_empty());
    }

    #[test]
    fn an_allocation_released_in_its_own_body_leaks_nothing() {
        // The pairing owns the released lifecycle; the leak reading
        // starts from what the pairing leaves open, never from what
        // it closed.
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  free(pvVar1);\n",
        )];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn a_leak_carries_the_acquisition_line_and_its_own_confidence() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar1 = malloc(0x20);\n  *pvVar1 = 0;\n",
        )];
        let findings = analyze(&program);
        let MemoryFinding::Leak(record) = &findings[0] else {
            unreachable!()
        };
        assert_eq!(
            record.resource,
            LeakResource::Allocation {
                allocation_type: AllocationType::Malloc,
            }
        );
        assert_eq!(record.suggestion, "Box<T>");
        assert_eq!(record.confidence.value(), 60);
        assert_eq!(record.evidence, "pvVar1 = malloc(0x20);");
    }

    #[test]
    fn an_unclosed_handle_that_escapes_nowhere_leaks_by_its_opener() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n  bVar1 = hFile != (void *)0x0;\n",
        )];
        let findings = analyze(&program);
        assert_eq!(
            leaks(&findings),
            vec![("FUN_18003ab00", "hFile", "CreateFileW".to_string())]
        );
        let MemoryFinding::Leak(record) = &findings[0] else {
            unreachable!()
        };
        assert_eq!(record.suggestion, "RAII guard struct with Drop impl");
        assert_eq!(record.confidence.value(), 60);
        assert!(record.evidence.contains("hFile = CreateFileW("));
    }

    #[test]
    fn a_handle_handed_over_or_returned_leaks_nothing() {
        // The same escape gate reads handles: handed to a callee or
        // returned whole, the handle left — whoever holds it answers
        // for closing it.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n  FUN_18003e750(hFile);\n",
            ),
            function(
                "FUN_18003abcd",
                "undefined FUN_18003abcd(void)",
                "  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n  return hFile;\n",
            ),
        ];
        assert!(leaks(&analyze(&program)).is_empty());
    }

    #[test]
    fn a_closed_handle_leaks_nothing() {
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n  CloseHandle(hFile);\n",
        )];
        assert!(analyze(&program).is_empty());
    }

    #[test]
    fn leaks_follow_allocation_order_then_open_handles() {
        // Within one function the cross-function group keeps its
        // order: open allocations in allocation order, then open
        // handles in open order.
        let program = vec![function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  pvVar2 = malloc(0x20);\n  pvVar1 = calloc(2, 0x10);\n  hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0);\n",
        )];
        assert_eq!(
            leaks(&analyze(&program)),
            vec![
                ("FUN_18003ab00", "pvVar2", "malloc".to_string()),
                ("FUN_18003ab00", "pvVar1", "calloc".to_string()),
                ("FUN_18003ab00", "hFile", "CreateFileW".to_string()),
            ]
        );
    }

    // ------------------------------------------------------------
    // Kept pointers: the Rc upgrade
    // ------------------------------------------------------------

    /// The suggestion of the first finding, whatever kind it is.
    fn suggestion(findings: &[MemoryFinding]) -> String {
        findings[0].suggestion().to_string()
    }

    #[test]
    fn a_callee_that_keeps_the_parameter_upgrades_the_pair_to_rc() {
        // The callee frees the block *and* stores the parameter into
        // a global: the stored copy outlives the release, so more
        // than one place holds the block — shared ownership.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  global_ptr = param_1;\n  free(param_1);\n",
            ),
        ];
        let findings = analyze(&program);
        assert_eq!(suggestion(&findings), "Rc<T>");
        assert_eq!(findings[0].confidence().value(), 70);
        // The evidence names the kept relationship: the store line.
        assert!(findings[0].evidence().contains("global_ptr = param_1;"));
    }

    #[test]
    fn a_callee_that_only_reads_the_parameter_keeps_the_plain_reading() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  use(param_1);\n  free(param_1);\n",
            ),
        ];
        assert_eq!(suggestion(&analyze(&program)), "Box<T>");
    }

    #[test]
    fn a_field_store_keeps_the_parameter_too() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  this->ptr = param_1;\n  free(param_1);\n",
            ),
        ];
        assert_eq!(suggestion(&analyze(&program)), "Rc<T>");
    }

    #[test]
    fn a_store_into_the_callee_s_own_frame_keeps_nothing() {
        // A stack slot or a typed local is gone when the call
        // returns — the block is not kept anywhere.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  local_8 = param_1;\n  iVar1 = 0;\n  free(param_1);\n",
            ),
        ];
        assert_eq!(suggestion(&analyze(&program)), "Box<T>");
    }

    #[test]
    fn a_keep_upgrades_a_transfer_to_a_scanned_callee() {
        // No release, but the callee stores the parameter into a
        // global: the block was handed over *and* kept, so the
        // transfer reads as shared ownership at its own confidence.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  global_ptr = param_1;\n  use(param_1);\n",
            ),
        ];
        let findings = analyze(&program);
        assert_eq!(transfers(&findings).len(), 1);
        assert_eq!(suggestion(&findings), "Rc<T>");
        assert_eq!(findings[0].confidence().value(), 65);
        assert!(findings[0].evidence().contains("global_ptr = param_1;"));
    }

    #[test]
    fn a_keep_of_a_handed_over_or_returned_pointer_upgrades_nothing_else() {
        // A return has no callee body to read, and a hand-off to a
        // callee outside the scanned set has no body this scan holds
        // — neither can be shown to keep, so both keep the plain
        // transfer reading.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  return pvVar1;\n",
            ),
            function(
                "FUN_18003abcd",
                "undefined FUN_18003abcd(void)",
                "  pvVar1 = malloc(0x20);\n  external_store(pvVar1);\n",
            ),
        ];
        let findings = analyze(&program);
        assert_eq!(transfers(&findings).len(), 2);
        assert!(findings.iter().all(|f| f.suggestion() == "Box<T>"));
    }

    #[test]
    fn a_keep_through_a_cast_is_seen_through() {
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1)",
                "  global_ptr = (void *)param_1;\n  free(param_1);\n",
            ),
        ];
        assert_eq!(suggestion(&analyze(&program)), "Rc<T>");
    }

    #[test]
    fn a_store_of_something_else_keeps_nothing() {
        // An interior pointer and a different parameter are not the
        // block being kept.
        let program = vec![
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  pvVar1 = malloc(0x20);\n  FUN_18003e750(pvVar1);\n",
            ),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void *param_1, void *param_2)",
                "  global_ptr = param_1 + 1;\n  other_ptr = param_2;\n  free(param_1);\n",
            ),
        ];
        assert_eq!(suggestion(&analyze(&program)), "Box<T>");
    }
}

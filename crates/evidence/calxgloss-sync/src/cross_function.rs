//! Cross-function concurrency readings over the bodies the scan keeps.
//!
//! The per-body detectors stop at a function's closing brace: two
//! functions that acquire the same two locks in opposite orders — the
//! classic deadlock shape — are invisible to each body read on its
//! own. This module closes that gap over the bodies one scan already
//! holds, mirroring the memory crate's cross-function pass
//! (ADR-0027): the lock map is derived from the fetched bodies with
//! the same call-site scan the mutex detector already uses, so no new
//! [`ScanSource`](crate::engine::ScanSource) reads are made and the
//! exactly-once-decompile guarantee and the skip-rate breaker survive
//! untouched.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the reading: per function,
//! the sequence of distinct lock objects acquired in body order, tied
//! to lock objects by the pairing detector's own extraction and
//! matched against the mutex detector's configured acquire names —
//! custom spellings reach this pass through the same name set the
//! pairing reads. Two functions whose sequences hold the same two
//! locks in opposite relative orders land one
//! [`SyncFinding::LockOrder`] per conflicting lock pair, naming both
//! functions and both lock objects, with the two acquire orders as
//! evidence. Data races build on the same kept bodies in a follow-up
//! pass.

use crate::mutex::{MutexDetector, lock_object};
use crate::types::{LockOrder, SyncFinding};
use calxgloss_ghidra::DecompiledFunction;

use calxgloss_types::{NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites};

/// The scan: plain-identifier callees, member accesses skipped, and C
/// keywords not calls — the same configuration the mutex pairing walk
/// uses, so both read the same call sites.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Confidence of a lock-order conflict read across two bodies: both
/// orders are explicit acquisitions of recognized names, so the
/// conflict sits level with an in-body mutex pairing — but the tie
/// between the two bodies is the decompiler's naming, not resolved
/// data flow, and a branch could leave either acquisition unreached.
const LOCK_ORDER_CONFIDENCE: u8 = 70;

/// The Rust pattern a lock-order conflict suggests: one acquisition
/// order held consistently across the program, which is what nested
/// Rust locks give a translation when it picks a single order.
const LOCK_ORDER_SUGGESTION: &str = "pick one consistent lock acquisition order";

/// Cross-function concurrency readings over the bodies one scan holds.
///
/// The analyzer is stateless: every reading comes from the bodies it
/// is handed and the mutex detector's configured name sets it is
/// given, so one analyzer serves an entire scan. It fetches nothing
/// itself — the engine hands it the same [`DecompiledFunction`]
/// values the per-function pass already decompiled, keeping the scan
/// at one decompile per function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the mutex name set comes in through
    /// the [`MutexDetector`] at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function findings the program carries, in listing
    /// order: for every pair of functions in listing order, each pair
    /// of lock objects the two acquire in opposite relative orders
    /// lands one [`SyncFinding::LockOrder`] on the earlier function,
    /// naming the later one as its partner — once per conflicting lock
    /// pair, so a full reversal of three locks reads as three
    /// two-lock conflicts, the shape a deadlock review takes one lock
    /// pair at a time.
    ///
    /// A function whose body never made it — skipped by the engine —
    /// is simply absent from `functions`, so it forms no sequence and
    /// fabricates no conflict.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        mutex: &MutexDetector,
    ) -> Vec<SyncFinding> {
        let sequences: Vec<Vec<String>> = functions
            .iter()
            .map(|func| lock_sequence(func, mutex))
            .collect();

        let mut findings = Vec::new();
        for i in 0..functions.len() {
            for j in (i + 1)..functions.len() {
                let (seq_i, seq_j) = (&sequences[i], &sequences[j]);
                for a_pos in 0..seq_i.len() {
                    for b_pos in (a_pos + 1)..seq_i.len() {
                        let (a, b) = (&seq_i[a_pos], &seq_i[b_pos]);
                        // The pair conflicts when the later function
                        // holds both locks with `b` before `a`.
                        let opposite = seq_j
                            .iter()
                            .position(|lock| lock == a)
                            .zip(seq_j.iter().position(|lock| lock == b))
                            .is_some_and(|(ja, jb)| jb < ja);
                        if opposite {
                            findings.push(SyncFinding::LockOrder(LockOrder {
                                function: functions[i].name.clone(),
                                partner: functions[j].name.clone(),
                                first_lock: a.clone(),
                                second_lock: b.clone(),
                                suggestion: LOCK_ORDER_SUGGESTION.to_string(),
                                confidence: LOCK_ORDER_CONFIDENCE.into(),
                                evidence: format!(
                                    "{}: {}; {}: {}",
                                    functions[i].name,
                                    seq_i.join(" -> "),
                                    functions[j].name,
                                    seq_j.join(" -> ")
                                ),
                            }));
                        }
                    }
                }
            }
        }
        findings
    }
}

/// The sequence of distinct lock objects one body acquires, in body
/// order: every direct call to a configured acquire name, tied to its
/// lock object by [`lock_object`] — the pairing detector's own
/// extraction, so an acquire naming anything but a plain variable
/// (a field, an indexed element) names nothing this pass can key on.
/// Repeats of one lock object count once: the reading is about
/// relative order, not counts.
fn lock_sequence(func: &DecompiledFunction, mutex: &MutexDetector) -> Vec<String> {
    let mut sequence: Vec<String> = Vec::new();
    for call in call_sites(&func.body, &CALL_SCAN) {
        if mutex.acquires().iter().any(|a| a.name == call.callee)
            && let Some(lock) = call.args.first().and_then(|arg| lock_object(arg))
            && !sequence.contains(&lock)
        {
            sequence.push(lock);
        }
    }
    sequence
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SyncType;

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.into(),
            signature: format!("undefined {name}(void)"),
            body: format!("  {body}\n"),
        }
    }

    fn analyze(bodies: &[(&str, &str)]) -> Vec<SyncFinding> {
        let functions: Vec<DecompiledFunction> = bodies
            .iter()
            .map(|(name, body)| function(name, body))
            .collect();
        CrossFunctionAnalyzer::new().analyze(&functions, &MutexDetector::with_default_names())
    }

    #[test]
    fn reversed_acquisition_orders_land_one_conflict() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&local_20); EnterCriticalSection(&local_40);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_40); EnterCriticalSection(&local_20);",
            ),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::LockOrder(record) = &findings[0] else {
            unreachable!("the reversed orders read as a lock-order finding");
        };
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.first_lock, "local_20");
        assert_eq!(record.second_lock, "local_40");
        assert_eq!(
            record.suggestion,
            "pick one consistent lock acquisition order"
        );
        assert_eq!(record.confidence, LOCK_ORDER_CONFIDENCE);
        // The evidence carries both functions' acquire orders.
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: local_20 -> local_40; FUN_18003e750: local_40 -> local_20"
        );
    }

    #[test]
    fn consistent_acquisition_orders_claim_nothing() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&local_20); EnterCriticalSection(&local_40);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_20); EnterCriticalSection(&local_40);",
            ),
        ]);
        assert!(findings.is_empty(), "one shared order is not a conflict");
    }

    #[test]
    fn functions_sharing_only_one_lock_object_conflict_nothing() {
        // The later function never acquires `local_20`, so there is no
        // pair whose order could disagree.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&local_20); EnterCriticalSection(&local_40);",
            ),
            ("FUN_18003e750", "EnterCriticalSection(&local_40);"),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_repeated_acquire_of_one_lock_counts_once() {
        // The reading is about relative order, not counts: two
        // acquisitions of `local_20` before `local_40` still form one
        // sequence, so the conflict lands once.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&local_20); EnterCriticalSection(&local_20); \
                 EnterCriticalSection(&local_40);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_40); EnterCriticalSection(&local_20);",
            ),
        ]);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_full_three_lock_reversal_lands_one_finding_per_conflicting_pair() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "pthread_mutex_lock(&a); pthread_mutex_lock(&b); pthread_mutex_lock(&c);",
            ),
            (
                "FUN_18003e750",
                "pthread_mutex_lock(&c); pthread_mutex_lock(&b); pthread_mutex_lock(&a);",
            ),
        ]);
        let pairs: Vec<(&str, &str)> = findings
            .iter()
            .map(|finding| {
                let SyncFinding::LockOrder(record) = finding else {
                    unreachable!("every finding here is a lock-order conflict");
                };
                (record.first_lock.as_str(), record.second_lock.as_str())
            })
            .collect();
        assert_eq!(pairs, [("a", "b"), ("a", "c"), ("b", "c")]);
    }

    #[test]
    fn findings_come_back_in_listing_order() {
        // The earlier function carries the finding against each later
        // one it conflicts with, in listing order.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&x); EnterCriticalSection(&y);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&y); EnterCriticalSection(&x);",
            ),
            (
                "FUN_180041230",
                "EnterCriticalSection(&y); EnterCriticalSection(&x);",
            ),
        ]);
        let named: Vec<(&str, &str)> = findings
            .iter()
            .map(|finding| {
                let SyncFinding::LockOrder(record) = finding else {
                    unreachable!("every finding here is a lock-order conflict");
                };
                (record.function.as_str(), record.partner.as_str())
            })
            .collect();
        assert_eq!(
            named,
            [
                ("FUN_18003ab00", "FUN_18003e750"),
                ("FUN_18003ab00", "FUN_180041230"),
            ]
        );
    }

    #[test]
    fn lock_objects_are_seen_through_casts_and_address_of() {
        // The pairing's extraction: `(pthread_mutex_t *)mtx` and `mtx`
        // name the same lock, and either configured acquire family
        // feeds the same sequence.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "pthread_mutex_lock((pthread_mutex_t *)mtx); EnterCriticalSection(&guard);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); pthread_mutex_lock(mtx);",
            ),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::LockOrder(record) = &findings[0] else {
            unreachable!("the reversed orders read as a lock-order finding");
        };
        assert_eq!(record.first_lock, "mtx");
        assert_eq!(record.second_lock, "guard");
    }

    #[test]
    fn an_acquire_naming_something_other_than_a_variable_keys_on_nothing() {
        // A field of a struct names no lock object the pairing — or
        // this pass — can key on.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&(local_10.field_0)); EnterCriticalSection(&local_40);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_40); EnterCriticalSection(&(local_10.field_0));",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_conflict() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "printf(\"EnterCriticalSection(&local_20) then &local_40\");",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_40); EnterCriticalSection(&local_20);",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_longer_or_qualified_name_matches_no_configured_acquire() {
        // Whole names only: `pthread_mutex_trylock` is a different
        // callee, and a member access through an object is no plain
        // call.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "iVar1 = pthread_mutex_trylock(&local_20); x.EnterCriticalSection(&local_40);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_40); pthread_mutex_trylock(&local_20);",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_truncated_body_contributes_no_sequence() {
        let findings = analyze(&[
            ("FUN_18003ab00", "EnterCriticalSection(&local_20;"),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_40); EnterCriticalSection(&local_20);",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn custom_acquire_names_reach_the_pass() {
        // The pass reads the mutex detector's configured set, not a
        // private default: custom spellings conflict, and the standard
        // names the swap replaced claim nothing.
        let functions = [
            function("FUN_18003ab00", "my_lock(&a); my_lock(&b);"),
            function("FUN_18003e750", "my_lock(&b); my_lock(&a);"),
        ];
        let custom = MutexDetector::with_names(
            [crate::mutex::MutexSignature::new(
                "my_lock",
                SyncType::ParkingMutex,
            )],
            ["my_unlock"],
        );
        let findings = CrossFunctionAnalyzer::new().analyze(&functions, &custom);
        assert_eq!(findings.len(), 1);

        let standard_only = [
            function(
                "FUN_18003ab00",
                "EnterCriticalSection(&a); EnterCriticalSection(&b);",
            ),
            function(
                "FUN_18003e750",
                "EnterCriticalSection(&b); EnterCriticalSection(&a);",
            ),
        ];
        assert!(
            CrossFunctionAnalyzer::new()
                .analyze(&standard_only, &custom)
                .is_empty(),
            "the replaced standard names match nothing once swapped out"
        );
    }

    #[test]
    fn a_mutex_detector_with_no_names_conflicts_nothing() {
        let functions = [
            function(
                "FUN_18003ab00",
                "EnterCriticalSection(&a); EnterCriticalSection(&b);",
            ),
            function(
                "FUN_18003e750",
                "EnterCriticalSection(&b); EnterCriticalSection(&a);",
            ),
        ];
        let findings = CrossFunctionAnalyzer::new().analyze(&functions, &MutexDetector::new());
        assert!(findings.is_empty());
    }

    #[test]
    fn a_single_function_or_an_empty_program_claims_nothing() {
        assert!(analyze(&[("FUN_18003ab00", "EnterCriticalSection(&a);")]).is_empty());
        assert!(analyze(&[]).is_empty());
    }

    #[test]
    fn the_analyzer_can_be_shared_across_scans() {
        // One analyzer is driven over every scan the engine runs, so
        // sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionAnalyzer>();
    }
}

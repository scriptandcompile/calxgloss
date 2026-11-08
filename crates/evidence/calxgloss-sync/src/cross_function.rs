//! Cross-function concurrency readings over the bodies the scan keeps.
//!
//! The per-body detectors stop at a function's closing brace. Two
//! functions that acquire the same two locks in opposite orders — the
//! classic deadlock shape — are invisible to each body read on its
//! own. This module closes that gap over the bodies one scan already
//! holds, mirroring the memory crate's cross-function pass (ADR-0027).
//! The lock sequences and spans it compares are derived from the kept
//! bodies with the same call-site scan the mutex detector already
//! uses. So no new [`ScanSource`](crate::engine::ScanSource) reads are
//! made: the exactly-once-decompile guarantee and the skip-rate
//! breaker stay untouched.
//!
//! [`CrossFunctionAnalyzer::analyze`] runs the readings. For each
//! function it reads the sequence of distinct lock objects acquired
//! in body order, tied to lock objects by the pairing detector's own
//! extraction and matched against the mutex detector's configured
//! acquire names — custom spellings reach this pass through the same
//! name set the pairing reads. Two functions whose sequences hold the
//! same two locks in opposite relative orders land one
//! [`SyncFinding::LockOrder`] per conflicting lock pair, naming both
//! functions and both lock objects, with the two acquire orders as
//! evidence. A deadlock claim stays two functions; the conflict
//! keeps its pair shape. The pass gates its inputs: the global-state
//! crate's shared rule admits only lock objects that could be one
//! instance in both bodies, so two same-named stack slots like
//! `local_20` invent no deadlock (issue #435).
//!
//! The data-race reading then uses the same kept bodies. Which
//! identifiers name program globals is the global-state crate's
//! shared rule, consumed through its pure reading
//! ([`calxgloss_globalstate::global_sites`]) — so a race finding and
//! a global-state record can never name different accesses for the
//! same identifier. This crate adds only its lock-span attribution on
//! top: an access inside a recognized acquire→release span counts as
//! protected by that span's lock object. Shared globals with two or
//! more accessor functions — at least one reading and at least one
//! writing — land one [`SyncFinding::DataRace`] per global (issue
//! #434), the same aggregation shape the global-state crate's rollup
//! uses, not one per pair of functions. The same-lock rule is the
//! false-positive gate in its generalized shape: one lock object
//! whose span covers every access of the global across every accessor
//! claims nothing, so properly locked data stays silent (issue #113).

use std::collections::HashMap;

use crate::mutex::{MutexDetector, lock_object};
use crate::threading::ThreadingDetector;
use crate::types::{DataRace, LockOrder, RaceSide, SyncFinding};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_globalstate::{AccessKind, global_sites, is_global_name, statement_at};

use calxgloss_types::{NON_CALL_KEYWORDS, NameContinuation, ScanOptions, call_sites};

/// The scan: plain-identifier callees, member accesses skipped, and C
/// keywords not calls. The mutex detector's own scan configuration is
/// the same, so both read the same call sites.
const CALL_SCAN: ScanOptions = ScanOptions {
    continuation: NameContinuation::Ident,
    reject_preceding: b".>",
    skip_keywords: &NON_CALL_KEYWORDS,
};

/// Evidence confidence of a lock-order conflict read across two
/// bodies: both orders are explicit acquisitions of recognized names,
/// so the conflict sits level with an in-body mutex pairing. But the
/// tie between the two bodies is the decompiler's naming, not resolved
/// data flow, and a branch could leave either acquisition unreached.
const LOCK_ORDER_CONFIDENCE: u8 = 70;

/// The Rust pattern a lock-order conflict suggests: one acquisition
/// order held consistently across the program, which is what nested
/// Rust locks give a translation when it picks a single order.
const LOCK_ORDER_SUGGESTION: &str = "pick one consistent lock acquisition order";

/// Evidence confidence of a data race read across two bodies: the
/// shared global and both access sites are explicit body evidence.
/// But the unprotected side is absence-of-evidence — the body shows
/// no lock, which is not proof that no lock exists — so the claim
/// sits one band below the evidence-based kinds: 60 against the
/// pairing-level 70.
const DATA_RACE_CONFIDENCE: u8 = 60;

/// The Rust pattern a data race suggests: one lock object guarding the
/// global with both functions holding it, which is what a translation
/// reaches for when it wraps shared data in a `Mutex`.
const DATA_RACE_SUGGESTION: &str = "guard the shared global with one lock held by both functions";

/// Cross-function concurrency readings over the bodies one scan holds.
///
/// The analyzer is stateless: every reading comes from the bodies it
/// is handed and the mutex detector's configured name sets it is
/// given, so one analyzer serves an entire scan. It fetches nothing
/// itself — the scan hands it the same [`DecompiledFunction`] values
/// the per-function pass already decompiled, so the scan stays at one
/// decompile per function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CrossFunctionAnalyzer;

impl CrossFunctionAnalyzer {
    /// An analyzer with no state — the mutex name set comes in through
    /// the [`MutexDetector`] at call time.
    pub fn new() -> Self {
        Self
    }

    /// The cross-function findings read from the program's bodies, in
    /// listing order. For every pair of functions in listing order,
    /// each pair of lock objects the two acquire in opposite relative
    /// orders lands one [`SyncFinding::LockOrder`] on the earlier
    /// function, naming the later one as its partner — once per
    /// conflicting lock pair. Only lock objects the global-state
    /// crate's shared rule reads as naming program data enter that
    /// comparison. A stack-slot lock in one body never matches a
    /// same-named slot in another. A full reversal of three locks
    /// therefore reads as three two-lock conflicts, the shape a
    /// deadlock review takes one lock pair at a time. Then the data
    /// races: every global named by two or more accessor functions
    /// lands one [`SyncFinding::DataRace`] — one per shared global
    /// (issue #434) — unless one lock object's span covers every
    /// access on every side.
    ///
    /// The pass pairs only functions that could run at the same
    /// moment (issue #436). `exports` names the program's exported
    /// symbols and `threads` reads the configured spawn spellings:
    /// from those entries the walk follows the kept bodies' own call
    /// edges, and a body the walk never reaches shares no lock order
    /// and no racing global with any other body.
    /// [`analyze_report`](Self::analyze_report) states which
    /// bodies the gate excluded, so the scan admits the narrower
    /// comparison rather than hiding it.
    ///
    /// A function whose body never made it — skipped when its
    /// decompile failed — is simply absent from `functions`, so it
    /// forms no sequence, names no global, and fabricates no conflict
    /// or race.
    pub fn analyze(
        &self,
        functions: &[DecompiledFunction],
        mutex: &MutexDetector,
        threads: &ThreadingDetector,
        exports: &[String],
    ) -> Vec<SyncFinding> {
        self.analyze_report(functions, mutex, threads, exports)
            .findings
    }

    /// [`analyze`](Self::analyze) with the gate's admission report:
    /// the findings, plus the kept bodies the concurrent-reachability
    /// gate excluded from the comparison, in listing order.
    pub(crate) fn analyze_report(
        &self,
        functions: &[DecompiledFunction],
        mutex: &MutexDetector,
        threads: &ThreadingDetector,
        exports: &[String],
    ) -> CrossFunctionReport {
        let gate = pair_gate(functions, threads, exports);
        let sequences: Vec<Vec<String>> = functions
            .iter()
            .map(|func| lock_sequence(func, mutex))
            .collect();

        let mut findings = Vec::new();
        for i in 0..functions.len() {
            if !gate.pairable[i] {
                continue;
            }
            for j in (i + 1)..functions.len() {
                if !gate.pairable[j] {
                    continue;
                }
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

        // The data-race reading over the same kept bodies: shared
        // variables are the globals named in the bodies, each access
        // annotated with the lock objects whose recognized
        // acquire→release spans cover it. One finding per shared
        // global (issue #434): the accesses bucket under their global
        // in first-sighting order — the first body to name it starts
        // the bucket, in listing order, first to name a not-yet-bucketed
        // global buckets first — so one global read and written by
        // several functions claims its race once.
        let accesses: Vec<Vec<GlobalAccess>> = functions
            .iter()
            .map(|func| global_accesses(func, mutex))
            .collect();
        let mut buckets: Vec<GlobalSites> = Vec::new();
        let mut bucket_of: HashMap<String, usize> = HashMap::new();
        for (index, body) in accesses.iter().enumerate() {
            // A gated body names no bucket: it forms no pair, so its
            // accesses claim no race (issue #436).
            if !gate.pairable[index] {
                continue;
            }
            for access in body {
                let slot = match bucket_of.get(&access.name) {
                    Some(slot) => *slot,
                    None => {
                        let slot = buckets.len();
                        bucket_of.insert(access.name.clone(), slot);
                        buckets.push(GlobalSites {
                            global: access.name.clone(),
                            accessors: Vec::new(),
                            sites: Vec::new(),
                        });
                        slot
                    }
                };
                let bucket = &mut buckets[slot];
                if !bucket.accessors.contains(&index) {
                    bucket.accessors.push(index);
                }
                bucket.sites.push(access.clone());
            }
        }
        for bucket in buckets {
            // Two or more accessor functions, at least one reading
            // and at least one writing among all their accesses —
            // the qualification the pair reading used, read over the
            // whole bucket: functions that only overwrite one slot
            // lose updates but watch no half-written value.
            if bucket.accessors.len() < 2 {
                continue;
            }
            let reads = bucket.sites.iter().any(|a| a.kind == AccessKind::Read);
            let writes = bucket.sites.iter().any(|a| a.kind == AccessKind::Write);
            if !(reads && writes) {
                continue;
            }
            // The same-lock rule, generalized to the whole bucket:
            // one lock object whose spans cover every access of the
            // global across every accessor means the accessors guard
            // the data with the same lock, and properly locked data
            // is not a race. Any unprotected access, or accessors
            // guarded by different locks, leaves the claim standing.
            if one_lock_covers_every_access(&bucket.sites) {
                continue;
            }
            let mut readers: Vec<String> = Vec::new();
            let mut writers: Vec<String> = Vec::new();
            let mut sides: Vec<RaceSide> = Vec::new();
            for &index in &bucket.accessors {
                let accesses_of_side = &accesses[index];
                if accesses_of_side
                    .iter()
                    .any(|a| a.name == bucket.global && a.kind == AccessKind::Read)
                {
                    readers.push(functions[index].name.clone());
                }
                if accesses_of_side
                    .iter()
                    .any(|a| a.name == bucket.global && a.kind == AccessKind::Write)
                {
                    writers.push(functions[index].name.clone());
                }
                let statement =
                    access_statement(&functions[index].body, accesses_of_side, &bucket.global);
                sides.push(RaceSide {
                    function: functions[index].name.clone(),
                    statement,
                });
            }
            // The evidence string keeps the pair reading's shape —
            // each side's statement, semicolon-separated — so an old
            // evidence check still reads the same for two sides.
            let evidence = sides
                .iter()
                .map(|side| format!("{}: {};", side.function, side.statement))
                .collect::<Vec<String>>()
                .join(" ");
            findings.push(SyncFinding::DataRace(DataRace {
                variable: bucket.global,
                readers,
                writers,
                unguarded_reads: bucket
                    .sites
                    .iter()
                    .filter(|a| a.kind == AccessKind::Read && a.locks.is_empty())
                    .count(),
                unguarded_writes: bucket
                    .sites
                    .iter()
                    .filter(|a| a.kind == AccessKind::Write && a.locks.is_empty())
                    .count(),
                sides,
                suggestion: DATA_RACE_SUGGESTION.to_string(),
                confidence: DATA_RACE_CONFIDENCE.into(),
                evidence,
            }));
        }
        CrossFunctionReport {
            findings,
            gate_excluded: gate.excluded,
        }
    }
}

/// What one cross-function pass produced, with the concurrent-
/// reachability gate's admission: the findings, and the kept bodies
/// the gate excluded from the pairing, in listing order (issue #436).
/// The scan files the excluded names in its coverage record so a
/// gated findings list never renders alike with a full-coverage one.
pub(crate) struct CrossFunctionReport {
    pub(crate) findings: Vec<SyncFinding>,
    pub(crate) gate_excluded: Vec<String>,
}

/// Which kept bodies could share a moment with another kept body.
struct PairGate {
    /// One flag per function index: bodies the forward walk from any
    /// entry reached — an export, or a thread started by a configured
    /// spawn call.
    pairable: Vec<bool>,
    /// The bodies the walk never reached, in listing order.
    excluded: Vec<String>,
}

/// The concurrent-reachability gate over the kept bodies (issue
/// #436). Entries are the kept bodies named by the export listing
/// and by any kept body's thread-start arguments; from each entry
/// the walk follows direct call edges whose targets are also kept
/// bodies — the same call reading the data-race and error-handling
/// passes use, so no extra analysis-engine reads. A body the walk
/// never reaches can only run sequentially: it shares no lock order
/// and no racing global with any other body.
fn pair_gate(
    functions: &[DecompiledFunction],
    threads: &ThreadingDetector,
    exports: &[String],
) -> PairGate {
    let index_of: HashMap<&str, usize> = functions
        .iter()
        .enumerate()
        .map(|(index, func)| (func.name.as_str(), index))
        .collect();

    // The call map derived purely from the kept bodies: each body's
    // direct calls, kept to names this scan has a body for — the same
    // pseudo-C scan this module's own reading uses, so no extra
    // analysis-engine reads.
    let edges: Vec<Vec<usize>> = functions
        .iter()
        .map(|func| {
            call_sites(&func.body, &CALL_SCAN)
                .into_iter()
                .filter_map(|call| index_of.get(call.callee).copied())
                .collect()
        })
        .collect();

    let mut reached = vec![false; functions.len()];
    let mut queue: Vec<usize> = Vec::new();
    let enter = |name: &str, reached: &mut Vec<bool>, queue: &mut Vec<usize>| {
        if let Some(&index) = index_of.get(name)
            && !reached[index]
        {
            reached[index] = true;
            queue.push(index);
        }
    };
    // The entries: the exported names, and every kept body's
    // thread-start arguments — the functions a thread could start.
    // The gate does not chase whether the spawning body itself runs:
    // the call map never resolves liveness either, and a body named
    // as a thread's routine gets the same benefit of the doubt as an
    // export does. From the entries, one forward walk over the call
    // edges closes the pairable set.
    for export in exports {
        enter(export, &mut reached, &mut queue);
    }
    for func in functions {
        for candidate in threads.spawn_start_candidates(func) {
            enter(&candidate, &mut reached, &mut queue);
        }
    }
    let mut head = 0;
    while head < queue.len() {
        let here = queue[head];
        head += 1;
        for &next in &edges[here] {
            if !reached[next] {
                reached[next] = true;
                queue.push(next);
            }
        }
    }

    let excluded: Vec<String> = functions
        .iter()
        .zip(&reached)
        .filter(|(_, reached)| !**reached)
        .map(|(func, _)| func.name.clone())
        .collect();
    PairGate {
        pairable: reached,
        excluded,
    }
}

/// The sequence of distinct lock objects one body acquires that
/// another body could share, in body order: every direct call to a
/// configured acquire name, tied to its lock object by
/// [`lock_object`] — the pairing detector's own extraction, so an
/// acquire naming anything but a plain variable (a field, an indexed
/// element) names nothing this pass can key on. The global-state
/// crate's shared rule then drops the decompiler-minted names: a
/// `local_20` lock never leaves its own frame, so it never joins a
/// pair two functions could disagree about (issue #435). Repeats of
/// one lock object count once: the reading is about relative order,
/// not counts.
fn lock_sequence(func: &DecompiledFunction, mutex: &MutexDetector) -> Vec<String> {
    let mut sequence: Vec<String> = Vec::new();
    for call in call_sites(&func.body, &CALL_SCAN) {
        if mutex.acquires().iter().any(|a| a.name == call.callee)
            && let Some(lock) = call.args.first().and_then(|arg| lock_object(arg))
            && is_global_name(&lock)
            && !sequence.contains(&lock)
        {
            sequence.push(lock);
        }
    }
    sequence
}

// ============================================================
// The data-race reading
// ============================================================

/// One global access site as the data-race reading keeps it: the
/// name, position, and kind the global-state crate's shared reading
/// produced ([`calxgloss_globalstate::GlobalSite`]), annotated with
/// the lock objects whose recognized acquire→release spans cover the
/// site. An empty `locks` means the access stands outside every
/// pairing — unprotected as far as this reading can see.
#[derive(Clone)]
struct GlobalAccess {
    name: String,
    offset: usize,
    kind: AccessKind,
    locks: Vec<String>,
}

/// Every access one scan's bodies make to one global, kept as the
/// race reading buckets it: the global's name, the indices of the
/// functions naming it — in listing order, each once however often
/// it visits — and every access site, in body order per accessor.
/// One bucket per global, not one per pair: the same rollup shape
/// the global-state crate's shared reading files (issue #434).
struct GlobalSites {
    global: String,
    accessors: Vec<usize>,
    sites: Vec<GlobalAccess>,
}

/// One recognized acquire→release span: the lock object the pairing
/// named, and the body range the lock guards — from the acquire call
/// to the closing `)` of the release that closed it.
struct LockSpan {
    lock: String,
    start: usize,
    end: usize,
}

/// The global accesses one body makes, in body order: every site the
/// shared global-identification reading produces, annotated with the
/// lock objects whose spans cover it. An access inside a span is
/// protected by that span's lock; one inside nested spans is
/// protected by each of them.
fn global_accesses(func: &DecompiledFunction, mutex: &MutexDetector) -> Vec<GlobalAccess> {
    let spans = lock_spans(&func.body, mutex);
    global_sites(&func.body)
        .into_iter()
        .map(|site| GlobalAccess {
            locks: spans
                .iter()
                .filter(|span| span.start < site.offset && site.offset < span.end)
                .map(|span| span.lock.clone())
                .collect(),
            name: site.name,
            offset: site.offset,
            kind: site.kind,
        })
        .collect()
}

/// The recognized acquire→release spans in a body: every direct call
/// to a configured acquire name naming one plain lock object opens a
/// span, and a configured release naming the same object closes the
/// most recent still-open acquire of that object — the pairing
/// detector's own rule, so the two readings cannot disagree about what
/// a span covers. An acquire no release closes in this body guards
/// nothing: whether the lock is held across a return is a
/// cross-function question this reading does not answer.
fn lock_spans(body: &str, mutex: &MutexDetector) -> Vec<LockSpan> {
    let mut open: Vec<(String, usize)> = Vec::new();
    let mut spans = Vec::new();
    for call in call_sites(body, &CALL_SCAN) {
        if mutex.acquires().iter().any(|a| a.name == call.callee)
            && let Some(lock) = call.args.first().and_then(|arg| lock_object(arg))
        {
            open.push((lock, call.offset));
        } else if mutex.releases().iter().any(|r| r == call.callee)
            && let Some(lock) = call.args.first().and_then(|arg| lock_object(arg))
            && let Some(at) = open.iter().rposition(|(l, _)| *l == lock)
        {
            let (_, start) = open.remove(at);
            spans.push(LockSpan {
                lock,
                start,
                end: call.close,
            });
        }
    }
    spans
}

/// Whether one lock object's spans cover every access of the global
/// across every accessor: the accessors guard the data with the same
/// lock, which is the false-positive gate — properly locked data is
/// not a race. An unprotected access anywhere, or accessors guarded
/// by different locks, leaves the claim standing. The generalized
/// shape of the pair rule, which asked the same question of two
/// bodies at a time (issue #434).
fn one_lock_covers_every_access(sites: &[GlobalAccess]) -> bool {
    let Some(mut covering) = sites.first().map(|access| access.locks.clone()) else {
        return false;
    };
    for access in sites {
        if access.locks.is_empty() {
            return false;
        }
        covering.retain(|lock| access.locks.contains(lock));
        if covering.is_empty() {
            return false;
        }
    }
    !covering.is_empty()
}

/// The access statement the evidence names for one body's side of the
/// race: the first access standing outside every span when there is
/// one — the unprotected side is the claim — and the first access
/// otherwise. The statement, not the whole line: a locked body writes
/// its acquire and release around the access, and the claim is the
/// access itself.
fn access_statement(body: &str, accesses: &[GlobalAccess], name: &str) -> String {
    let mut first: Option<usize> = None;
    for access in accesses.iter().filter(|a| a.name == name) {
        if access.locks.is_empty() {
            return statement_at(body, access.offset);
        }
        if first.is_none() {
            first = Some(access.offset);
        }
    }
    // The name is shared, so a side always has an access; the
    // fallback only guards the type.
    statement_at(body, first.unwrap_or(0))
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
        // These pins are about pairing, not reachability: every body
        // is an export, so the concurrent-reachability gate lets every
        // pair through. The gate has its own pins below.
        let exports: Vec<String> = functions.iter().map(|f| f.name.clone()).collect();
        CrossFunctionAnalyzer::new().analyze(
            &functions,
            &MutexDetector::with_default_names(),
            &ThreadingDetector::with_default_names(),
            &exports,
        )
    }

    /// Every function's name as an export: the entry set that lets a
    /// pairing pin reach the comparison itself, gate out of the way.
    fn all_exports(functions: &[DecompiledFunction]) -> Vec<String> {
        functions.iter().map(|func| func.name.clone()).collect()
    }

    #[test]
    fn reversed_acquisition_orders_land_one_conflict() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&DAT_guard); EnterCriticalSection(&DAT_monitor);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&DAT_monitor); EnterCriticalSection(&DAT_guard);",
            ),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::LockOrder(record) = &findings[0] else {
            unreachable!("the reversed orders read as a lock-order finding");
        };
        assert_eq!(record.function, "FUN_18003ab00");
        assert_eq!(record.partner, "FUN_18003e750");
        assert_eq!(record.first_lock, "DAT_guard");
        assert_eq!(record.second_lock, "DAT_monitor");
        assert_eq!(
            record.suggestion,
            "pick one consistent lock acquisition order"
        );
        assert_eq!(record.confidence, LOCK_ORDER_CONFIDENCE);
        // The evidence records both functions' acquire orders.
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: DAT_guard -> DAT_monitor; \
             FUN_18003e750: DAT_monitor -> DAT_guard"
        );
    }

    #[test]
    fn two_functions_reversing_same_named_stack_slot_locks_conflict_nothing() {
        // The shared rule's gate (issue #435): `local_20` in one body
        // is that body's own stack slot, so reversed same-named slots
        // share no lock instance and the pass compares nothing.
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
        assert!(
            findings.is_empty(),
            "two stack slots sharing a name are not one lock"
        );
    }

    #[test]
    fn a_stack_slot_lock_never_pairs_with_a_comparable_lock() {
        // Half the pair is a stack slot: one body takes `mtx` before
        // `local_20`, the other the other way round. The slot leaves
        // no sequence to compare, and one comparable lock alone is
        // not a pair, so the reversed orders claim nothing.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&mtx); EnterCriticalSection(&local_20);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&local_20); EnterCriticalSection(&mtx);",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn consistent_acquisition_orders_claim_nothing() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&DAT_guard); EnterCriticalSection(&DAT_monitor);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&DAT_guard); EnterCriticalSection(&DAT_monitor);",
            ),
        ]);
        assert!(findings.is_empty(), "one shared order is not a conflict");
    }

    #[test]
    fn functions_sharing_only_one_lock_object_conflict_nothing() {
        // The later function never acquires `DAT_guard`, so there is
        // no pair whose order could disagree.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&DAT_guard); EnterCriticalSection(&DAT_monitor);",
            ),
            ("FUN_18003e750", "EnterCriticalSection(&DAT_monitor);"),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_repeated_acquire_of_one_lock_counts_once() {
        // The reading is about relative order, not counts: two
        // acquisitions of `DAT_guard` before `DAT_monitor` still form
        // one sequence, so the conflict lands once.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&DAT_guard); EnterCriticalSection(&DAT_guard); \
                 EnterCriticalSection(&DAT_monitor);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&DAT_monitor); EnterCriticalSection(&DAT_guard);",
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
        // Findings land on the earlier function, one against each
        // later one it conflicts with, in listing order.
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
                "EnterCriticalSection(&(monitor.field_0)); EnterCriticalSection(&guard);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); EnterCriticalSection(&(monitor.field_0));",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_name_spelled_inside_a_string_literal_invents_no_conflict() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "printf(\"EnterCriticalSection(&mtx) then &guard\");",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); EnterCriticalSection(&mtx);",
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
                "iVar1 = pthread_mutex_trylock(&mtx); x.EnterCriticalSection(&guard);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); pthread_mutex_trylock(&mtx);",
            ),
        ]);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_truncated_body_contributes_no_sequence() {
        let findings = analyze(&[
            ("FUN_18003ab00", "EnterCriticalSection(&mtx;"),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); EnterCriticalSection(&mtx);",
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
        let findings = CrossFunctionAnalyzer::new().analyze(
            &functions,
            &custom,
            &ThreadingDetector::with_default_names(),
            &all_exports(&functions),
        );
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
                .analyze(
                    &standard_only,
                    &custom,
                    &ThreadingDetector::with_default_names(),
                    &all_exports(&standard_only),
                )
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
        let findings = CrossFunctionAnalyzer::new().analyze(
            &functions,
            &MutexDetector::new(),
            &ThreadingDetector::with_default_names(),
            &all_exports(&functions),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn a_single_function_or_an_empty_program_claims_nothing() {
        assert!(analyze(&[("FUN_18003ab00", "EnterCriticalSection(&a);")]).is_empty());
        assert!(analyze(&[]).is_empty());
    }

    #[test]
    fn the_analyzer_can_be_shared_across_scans() {
        // SyncEngine keeps one analyzer and runs it over every scan,
        // so sharing one by reference across tasks must stay sound.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CrossFunctionAnalyzer>();
    }

    // ------------------------------------------------------------
    // Data races
    // ------------------------------------------------------------

    #[test]
    fn an_unprotected_write_and_read_of_one_global_land_one_race() {
        let findings = analyze(&[
            ("FUN_18003ab00", "DAT_counter = iVar1 + 1;"),
            ("FUN_18003e750", "uVar1 = DAT_counter;"),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::DataRace(record) = &findings[0] else {
            unreachable!("the shared global reads as a data race");
        };
        assert_eq!(record.variable, "DAT_counter");
        assert_eq!(record.readers, ["FUN_18003e750"]);
        assert_eq!(record.writers, ["FUN_18003ab00"]);
        // Every access sits outside every span, so both sides count
        // as unguarded.
        assert_eq!(record.unguarded_reads, 1);
        assert_eq!(record.unguarded_writes, 1);
        assert_eq!(
            record.suggestion,
            "guard the shared global with one lock held by both functions"
        );
        // The unprotected side is absence-of-evidence: one band below
        // the evidence-based kinds.
        assert_eq!(record.confidence, DATA_RACE_CONFIDENCE);
        // Each accessor side carries one example access statement, in
        // listing order, and the evidence spells the sides out.
        let sides: Vec<(&str, &str)> = record
            .sides
            .iter()
            .map(|side| (side.function.as_str(), side.statement.as_str()))
            .collect();
        assert_eq!(
            sides,
            [
                ("FUN_18003ab00", "DAT_counter = iVar1 + 1"),
                ("FUN_18003e750", "uVar1 = DAT_counter"),
            ]
        );
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: DAT_counter = iVar1 + 1; FUN_18003e750: uVar1 = DAT_counter;"
        );
    }

    #[test]
    fn the_same_lock_object_protecting_both_accesses_suppresses_the_race() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&guard); DAT_counter = 5; LeaveCriticalSection(&guard);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); uVar1 = DAT_counter; LeaveCriticalSection(&guard);",
            ),
        ]);
        assert!(
            findings.is_empty(),
            "both sides hold the same lock over the data"
        );
    }

    #[test]
    fn accesses_protected_by_different_locks_do_not_suppress_the_race() {
        // Each side locks, but with a different object — neither lock
        // keeps the other side out, so the race stands.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&lock_a); DAT_counter = 5; LeaveCriticalSection(&lock_a);",
            ),
            (
                "FUN_18003e750",
                "pthread_mutex_lock(&lock_b); uVar1 = DAT_counter; pthread_mutex_unlock(&lock_b);",
            ),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::DataRace(record) = &findings[0] else {
            unreachable!("the shared global reads as a data race");
        };
        assert_eq!(record.variable, "DAT_counter");
    }

    #[test]
    fn one_side_under_a_lock_the_other_outside_still_races() {
        // The classic shape: one function reads the global under a
        // lock, the other writes it under no lock at all.
        let findings = analyze(&[
            ("FUN_18003ab00", "DAT_counter = 0;"),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); uVar1 = DAT_counter; LeaveCriticalSection(&guard);",
            ),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::DataRace(record) = &findings[0] else {
            unreachable!("the shared global reads as a data race");
        };
        assert_eq!(
            record.evidence,
            "FUN_18003ab00: DAT_counter = 0; FUN_18003e750: uVar1 = DAT_counter;"
        );
    }

    #[test]
    fn an_unpaired_acquire_protects_nothing() {
        // A span is a recognized acquire→release pairing, not a lone
        // acquire: with no release naming its lock object, the access
        // stands unprotected.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&guard); DAT_counter = 5;",
            ),
            ("FUN_18003e750", "uVar1 = DAT_counter;"),
        ]);
        assert_eq!(findings.len(), 1, "the acquire guards nothing on its own");
    }

    #[test]
    fn a_nested_span_protects_by_both_locks_and_one_common_lock_suppresses() {
        // The earlier body's access sits inside x{y{...}} — protected
        // by x and y; the later body's sits under x alone. x covers
        // every access on both sides, so the same-lock rule holds.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&x); EnterCriticalSection(&y); DAT_g = 1; \
                 LeaveCriticalSection(&y); LeaveCriticalSection(&x);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&x); uVar1 = DAT_g; LeaveCriticalSection(&x);",
            ),
        ]);
        assert!(findings.is_empty(), "both sides hold x over the access");
    }

    #[test]
    fn three_functions_reading_and_writing_two_globals_land_two_races() {
        // The pair-era shape claimed three findings here (one pair per
        // global per pair). The aggregate reading claims one per
        // global: DAT_x, read by two functions, and DAT_y — each
        // named once, each function once across the findings.
        let findings = analyze(&[
            ("FUN_18003ab00", "DAT_x = 1; DAT_y = 2;"),
            ("FUN_18003e750", "iVar1 = DAT_x; iVar2 = DAT_y;"),
            ("FUN_180041230", "iVar3 = DAT_x;"),
        ]);
        assert_eq!(findings.len(), 2, "one finding per shared global");
        let SyncFinding::DataRace(first) = &findings[0] else {
            panic!("first finding should be a data race");
        };
        assert_eq!(first.variable, "DAT_x");
        assert_eq!(
            first.readers,
            ["FUN_18003e750".to_string(), "FUN_180041230".to_string()],
            "both readers named once, in listing order"
        );
        assert_eq!(first.writers, ["FUN_18003ab00".to_string()]);
        assert_eq!(first.sides.len(), 3, "all three accessors carry a side");
        let SyncFinding::DataRace(second) = &findings[1] else {
            panic!("second finding should be a data race");
        };
        assert_eq!(second.variable, "DAT_y");
        assert_eq!(second.readers, ["FUN_18003e750".to_string()]);
        assert_eq!(second.writers, ["FUN_18003ab00".to_string()]);
    }

    #[test]
    fn races_land_in_the_order_the_scan_first_sighted_each_global() {
        // Two shared globals order by where the scan first sighted
        // each, not by name: `DAT_z`'s access starts the first body,
        // so its finding stands first even though `DAT_a` sorts
        // earlier. A third global, `DAT_m`, every accessor touches
        // under one lock object, and it claims nothing — its absence
        // from the list is the same-lock rule asking its question of
        // all accessors at once.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "DAT_z = 1; DAT_a = 2; EnterCriticalSection(&guard); DAT_m = 3; LeaveCriticalSection(&guard);",
            ),
            (
                "FUN_18003e750",
                "iVar1 = DAT_z; iVar2 = DAT_a; EnterCriticalSection(&guard); iVar3 = DAT_m; LeaveCriticalSection(&guard);",
            ),
        ]);
        let globals: Vec<&str> = findings
            .iter()
            .map(|finding| {
                let SyncFinding::DataRace(record) = finding else {
                    unreachable!("every finding here is a data race");
                };
                record.variable.as_str()
            })
            .collect();
        assert_eq!(globals, ["DAT_z", "DAT_a"], "first-sighting order wins");
    }

    #[test]
    fn an_accessor_that_reads_and_writes_names_itself_once_in_each_list_once_on_the_sides() {
        // `FUN_18003ab00` both loads and stores the global. The
        // record answers "each function named once": once in
        // `readers`, once in `writers`, and one side — not three
        // entries for one accessor.
        let findings = analyze(&[
            ("FUN_18003ab00", "iVar1 = DAT_g; DAT_g = iVar1 + 1;"),
            ("FUN_18003e750", "DAT_g = 2;"),
        ]);
        assert_eq!(findings.len(), 1, "one finding for the one shared global");
        let SyncFinding::DataRace(record) = &findings[0] else {
            unreachable!("the shared global reads as a data race");
        };
        assert_eq!(record.readers, ["FUN_18003ab00".to_string()]);
        assert_eq!(
            record.writers,
            ["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()],
            "listing order, the dual-role accessor named once"
        );
        assert_eq!(record.sides.len(), 2, "one side per accessor function");
        assert_eq!(record.unguarded_reads, 1);
        assert_eq!(record.unguarded_writes, 2);
    }

    #[test]
    fn one_lock_three_accessors_under_it_claims_no_race() {
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&guard); DAT_g = 1; LeaveCriticalSection(&guard);",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&guard); uVar1 = DAT_g; LeaveCriticalSection(&guard);",
            ),
            (
                "FUN_180041230",
                "EnterCriticalSection(&guard); uVar2 = DAT_g; LeaveCriticalSection(&guard);",
            ),
        ]);
        assert!(findings.is_empty(), "every accessor holds the same lock");
    }

    #[test]
    fn an_accessor_s_side_quotes_its_unguarded_access_when_it_also_has_a_guarded_one() {
        // The claim is the unprotected access, so the side's example
        // statement comes from outside every span even though the
        // body also touches the global under a lock.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&guard); DAT_g = 1; LeaveCriticalSection(&guard); DAT_g = 2;",
            ),
            ("FUN_18003e750", "uVar1 = DAT_g;"),
        ]);
        assert_eq!(findings.len(), 1);
        let SyncFinding::DataRace(record) = &findings[0] else {
            unreachable!("the shared global reads as a data race");
        };
        let writer = record
            .sides
            .iter()
            .find(|side| side.function == "FUN_18003ab00")
            .expect("the writer carries a side");
        assert_eq!(
            writer.statement, "DAT_g = 2",
            "the unguarded access stands as the example"
        );
        assert_eq!(
            record.unguarded_writes, 1,
            "only the second store stands unguarded"
        );
    }

    #[test]
    fn the_lock_order_findings_come_before_the_race_findings() {
        // One function pair produces both cross-function shapes: the
        // persisted list runs the conflicts first, then the races, so
        // two scans diff cleanly.
        let findings = analyze(&[
            (
                "FUN_18003ab00",
                "EnterCriticalSection(&DAT_guard); EnterCriticalSection(&DAT_monitor); DAT_g = 1;",
            ),
            (
                "FUN_18003e750",
                "EnterCriticalSection(&DAT_monitor); EnterCriticalSection(&DAT_guard); uVar1 = DAT_g;",
            ),
        ]);
        let kinds: Vec<&str> = findings.iter().map(|finding| finding.kind()).collect();
        assert_eq!(kinds, ["lock_order", "data_race"]);
    }

    #[test]
    fn a_global_one_function_names_claims_nothing() {
        let findings = analyze(&[
            ("FUN_18003ab00", "DAT_counter = 5;"),
            ("FUN_18003e750", "uVar1 = DAT_other;"),
        ]);
        assert!(findings.is_empty(), "one side alone is not a pair");
    }

    #[test]
    fn two_functions_that_only_overwrite_the_same_global_race_nothing() {
        // Each body stores a fresh value and never looks at the old
        // one — two `hThread = CreateThread(...)` bodies. Updates get
        // lost, but nobody watches a half-written value, and the
        // mixed read/write gate keeps this shape off the list.
        let spawn = "hThread = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,worker,0x0,0,&local_14);";
        let findings = analyze(&[("FUN_18003ab00", spawn), ("FUN_18003e750", spawn)]);
        assert!(findings.is_empty(), "two blind stores are not a race");
    }

    #[test]
    fn an_unrelated_read_qualifies_no_pair() {
        // `DAT_x` is stored by both sides and never read; the only
        // read in view belongs to a variable one body names alone.
        // The mixed gate reads per global, so nothing here claims.
        let findings = analyze(&[
            ("FUN_18003ab00", "DAT_x = 1;"),
            ("FUN_18003e750", "DAT_x = 2; iVar1 = DAT_y;"),
        ]);
        assert!(findings.is_empty(), "DAT_x never shows a read half");
    }

    #[test]
    fn a_body_that_never_arrived_names_no_global() {
        // The scan hands the pass only the bodies that survived the
        // decompile: a missing body forms no access and no race.
        let findings = analyze(&[("FUN_18003ab00", "DAT_g = 1;")]);
        assert!(findings.is_empty());
    }

    #[test]
    fn custom_acquire_and_release_spellings_open_the_protecting_span() {
        // The span reading comes from the configured name sets, not a
        // private default: custom spellings pair into a span that
        // suppresses the race, and the standard names the swap
        // replaced guard nothing.
        let bodies = [
            function(
                "FUN_18003ab00",
                "my_lock(&guard); DAT_counter = 5; my_unlock(&guard);",
            ),
            function(
                "FUN_18003e750",
                "my_lock(&guard); uVar1 = DAT_counter; my_unlock(&guard);",
            ),
        ];
        let custom = MutexDetector::with_names(
            [crate::mutex::MutexSignature::new(
                "my_lock",
                SyncType::ParkingMutex,
            )],
            ["my_unlock"],
        );
        assert!(
            CrossFunctionAnalyzer::new()
                .analyze(
                    &bodies,
                    &custom,
                    &ThreadingDetector::with_default_names(),
                    &all_exports(&bodies),
                )
                .is_empty(),
            "the configured spellings close the span and suppress the race"
        );
        assert_eq!(
            CrossFunctionAnalyzer::new()
                .analyze(
                    &bodies,
                    &MutexDetector::with_default_names(),
                    &ThreadingDetector::with_default_names(),
                    &all_exports(&bodies),
                )
                .len(),
            1,
            "the replaced standard names see no span, so the access stands unprotected"
        );
    }
}

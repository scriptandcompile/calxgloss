//! Concurrency scan orchestration.
//!
//! [`SyncEngine`] runs the per-body detectors — mutex/lock pair
//! tracking, atomic operation detection, thread spawn detection,
//! thread-local storage detection, async-runtime shape detection, and
//! futex-based synchronization detection — over every function of one
//! open program, then the cross-function pass over the bodies
//! it kept, and assembles their findings into a single [`SyncResult`]
//! with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body. The
//! sync scan fetches each function's pseudo-C exactly once and reads
//! it with all of them, rather than having each detector pull its own
//! copy; the cross-function pass reads those same kept bodies, so the
//! scan stays at one decompile per function.
//!
//! The scan is one sequential pass over the function listing. Unlike
//! typeinfer's competing families, there is nothing to resolve between
//! the detectors: they read disjoint body shapes. Keeping the pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order.

use crate::async_runtime::AsyncDetector;
use crate::atomic::AtomicDetector;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::futex::FutexDetector;
use crate::mutex::MutexDetector;
use crate::threading::ThreadingDetector;
use crate::tls::TlsDetector;
use crate::types::{ScanMetadata, SyncFinding, SyncResult};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a concurrency scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here;
/// `SyncEngine`'s generic bound has always named it at this path.
/// [`KunaSource`] implements it over the in-process analysis engine,
/// and tests implement it over canned bodies so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven
/// from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names
/// inline before the rest are replaced by a count — bounded prose
/// beside the counts, not a dump (the P19-5 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The cap on cross-function findings, a protocol constant: how many
/// one scan may file (issue #438). Aggregation already bounds a normal
/// program's cross-function output — one race per shared global, one
/// conflict per reversed lock pair. A scan past this cap is therefore
/// a pathological one. Past the cap the scan keeps the first findings
/// in scan order and keeps the whole count, and the coverage record
/// stamps the truncation, so the scan never cuts silently. The
/// precedent is the constants engine's inline-table value cap: the
/// list truncates while the count stays whole.
const MAX_CROSS_FUNCTION_FINDINGS: usize = 512;

/// The facets a concurrency scan declares, in order — the roster the
/// record must name exactly once each. The concurrency scan reads two:
/// the decompiled bodies every per-body detector shares, and the
/// cross-function pairing the concurrent-reachability gate narrows
/// (issue #436).
pub const DECLARED_FACETS: &[&str] = &["function-bodies", "cross-function-pairs"];

/// The coverage record every concurrency scan stamps about itself
/// (issue #349), beside the provenance and the timing.
///
/// The first facet is `function-bodies` — the decompiled bodies every
/// per-body detector reads. The function listing is always read end to
/// end. A failed listing aborts the run, and more than half failing to
/// decompile trips the skip-rate breaker in the scan below. So what a
/// finished scan could not have read is exactly the bodies it skipped
/// along the way: a nameless listing entry, or a decompile that failed.
///
/// The second facet is `cross-function-pairs`. The cross-function pass
/// reads only kept bodies, but pairs only the ones that could run at
/// the same moment (issue #436), so a kept body the walk never reached
/// was still read by every detector while standing outside every
/// pairing. When the gate excluded any body, that facet is `partial`
/// and its admission line names the excluded count — function names up
/// to [`MAX_NAMED_UNREACHED`], a count beyond. A gated findings list
/// then never renders alike with a full-coverage one. An engaged
/// findings cap (issue #438) stamps its own admission line through this
/// same facet. The line names the whole cross-function count beside the
/// cap and states that the first findings in scan order stand, so a
/// truncated list never reads as a scan that saw everything and found
/// nothing.
///
/// With nothing skipped and nothing excluded, both facets are
/// `complete`. That is the admission's point: a function no finding
/// mentions was examined and clean, never silently unchecked. With any
/// skips or any exclusions the record is `partial`, so silence and
/// never-reaching are distinguishable in the filed record itself.
fn coverage_stamp(
    unreached: &[String],
    nameless: usize,
    gate_excluded: &[String],
    findings_truncated: Option<usize>,
) -> ScanCoverage {
    // One bounded name list per facet: names up to the cap inline,
    // everything else — counted leftovers and nameless entries
    // alike — folded into a trailing count.
    let bounded = |names: &[String], extra_hidden: usize| -> String {
        let mut kept = names
            .iter()
            .take(MAX_NAMED_UNREACHED)
            .cloned()
            .collect::<Vec<_>>();
        let hidden = names.len().saturating_sub(kept.len()) + extra_hidden;
        if hidden > 0 {
            kept.push(format!("+{hidden} more"));
        }
        kept.join(", ")
    };
    let total = unreached.len() + nameless;
    let bodies = if total == 0 {
        FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else {
        let body = if total == 1 { "body" } else { "bodies" };
        FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} function {body} unreached: {}",
                bounded(unreached, nameless)
            )),
        }
    };
    let mut pair_admissions: Vec<String> = Vec::new();
    if !gate_excluded.is_empty() {
        let noun = if gate_excluded.len() == 1 {
            "function"
        } else {
            "functions"
        };
        pair_admissions.push(format!(
            "{} {noun} excluded from cross-function pairing: {}",
            gate_excluded.len(),
            bounded(gate_excluded, 0)
        ));
    }
    if let Some(total_findings) = findings_truncated {
        pair_admissions.push(format!(
            "{total_findings} cross-function findings truncated at the cap of \
             {MAX_CROSS_FUNCTION_FINDINGS}: first {MAX_CROSS_FUNCTION_FINDINGS} kept in scan order"
        ));
    }
    let pairs = if pair_admissions.is_empty() {
        FacetCoverage {
            id: "cross-function-pairs".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else {
        FacetCoverage {
            id: "cross-function-pairs".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(pair_admissions.join("; ")),
        }
    };
    let status = if total == 0 && pair_admissions.is_empty() {
        CoverageStatus::Complete
    } else {
        CoverageStatus::Partial
    };
    ScanCoverage {
        status,
        facets: vec![bodies, pairs],
    }
}

/// Orchestrates the per-body detectors and the cross-function pass
/// into one [`SyncResult`].
///
/// `SyncEngine` is generic over its [`ScanSource`], so tests can run
/// the whole orchestration over canned bodies. [`new`](Self::new)
/// builds one over a loaded [`KunaSource`].
///
/// Each detector is stateless and starts configured with its standard
/// name sets.
/// [`with_mutex`](Self::with_mutex), [`with_atomics`](Self::with_atomics),
/// [`with_threads`](Self::with_threads), and [`with_tls`](Self::with_tls)
/// swap a detector's sets whole, so one instance of each serves the
/// whole scan. The cross-function pass has no name set of its own: it
/// reads the mutex detector's configured acquire names, so custom
/// spellings reach it through [`with_mutex`](Self::with_mutex).
#[derive(Debug, Clone)]
pub struct SyncEngine<S = KunaSource> {
    source: S,
    mutex: MutexDetector,
    atomics: AtomicDetector,
    threads: ThreadingDetector,
    tls: TlsDetector,
    async_runtime: AsyncDetector,
    futex: FutexDetector,
    cross_function: CrossFunctionAnalyzer,
}

impl SyncEngine<KunaSource> {
    /// A `SyncEngine` over a loaded Kuna program, scanning with the
    /// six per-body detectors' standard name sets.
    pub fn new(source: &KunaSource) -> SyncEngine<KunaSource> {
        SyncEngine {
            source: source.clone(),
            mutex: MutexDetector::with_default_names(),
            atomics: AtomicDetector::with_default_names(),
            threads: ThreadingDetector::with_default_names(),
            tls: TlsDetector::with_default_names(),
            async_runtime: AsyncDetector::with_default_names(),
            futex: FutexDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> SyncEngine<S> {
    /// A `SyncEngine` whose decompiles come from `source`, scanning
    /// with the six per-body detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        SyncEngine {
            source,
            mutex: MutexDetector::with_default_names(),
            atomics: AtomicDetector::with_default_names(),
            threads: ThreadingDetector::with_default_names(),
            tls: TlsDetector::with_default_names(),
            async_runtime: AsyncDetector::with_default_names(),
            futex: FutexDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }

    /// Pair lock acquisitions against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_mutex(mut self, detector: MutexDetector) -> Self {
        self.mutex = detector;
        self
    }

    /// Read atomic calls against `detector`'s name set instead of the
    /// standard one.
    pub fn with_atomics(mut self, detector: AtomicDetector) -> Self {
        self.atomics = detector;
        self
    }

    /// Read thread spawns against `detector`'s name sets instead of
    /// the standard ones.
    pub fn with_threads(mut self, detector: ThreadingDetector) -> Self {
        self.threads = detector;
        self
    }

    /// Read thread-local keys against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_tls(mut self, detector: TlsDetector) -> Self {
        self.tls = detector;
        self
    }

    /// Read async runtime loops against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_async(mut self, detector: AsyncDetector) -> Self {
        self.async_runtime = detector;
        self
    }

    /// Detect concurrency constructs across `binary`, decompiling
    /// each function exactly once and reading it with all the per-body
    /// detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing, function by function.
    /// Within one function they run in order: the mutex pairings,
    /// then the atomic calls, then the thread spawns, then the TLS
    /// records, then the async-runtime shapes, then the futex calls.
    /// After the whole per-function walk, the cross-function pass
    /// adds its findings, in listing order, over the bodies this
    /// walk already decompiled — no extra analysis engine calls.
    /// So two scans of the same program diff cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning. Only a failure of
    /// the listing itself — the server being down — aborts the run,
    /// since then nothing was scanned.
    ///
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the seam answering about the wrong program, and skipping on
    /// would persist a record that looks clean but is not (issue #71).
    ///
    /// The detectors read disjoint body shapes, so a function can
    /// have findings of every kind at once and nothing is resolved
    /// between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<SyncResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        // The concurrent-reachability gate's entry set (issue #436):
        // the export listing, read once per scan exactly like the
        // function listing. A failure of the export listing aborts
        // the run the same way a listing failure does — pairing every
        // body against none, and reporting a clean look, is worse
        // than failing.
        let exports: Vec<String> = self
            .source
            .exports()
            .await?
            .into_iter()
            .map(|symbol| symbol.name)
            .collect();

        let mut findings = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-5: which bodies the scan could NOT read — named where a
        // name exists, counted where the listing entry is nameless.
        // The coverage record below states it, so an unmentioned
        // function means examined-and-clean, never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry could land the name lookup
                // on some other function's body. Nothing can be said
                // about it, so it is skipped and counted in the
                // nameless coverage figure.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
                continue;
            }
            let decompiled = match self.source.decompile(&function.name).await {
                Ok(decompiled) => decompiled,
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping function: decompile failed"
                    );
                    skipped += 1;
                    decompile_failures += 1;
                    unreached.push(function.name.clone());
                    // Skip-rate breaker: once more than half the listing
                    // has failed to decompile, the scan is reading a
                    // program the analysis engine cannot analyze, and an
                    // empty result would persist as a record that looks
                    // clean but is not. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::SyncError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            findings.extend(
                self.mutex
                    .detect_pairs(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Mutex),
            );
            findings.extend(
                self.atomics
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Atomic),
            );
            findings.extend(
                self.threads
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Thread),
            );
            findings.extend(
                self.tls
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Tls),
            );
            findings.extend(
                self.async_runtime
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::AsyncRuntime),
            );
            findings.extend(
                self.futex
                    .detect(&decompiled)
                    .into_iter()
                    .map(SyncFinding::Futex),
            );
            bodies.push(decompiled);
        }

        // The cross-function pass runs after the per-function walk,
        // over the bodies the scan already decompiled — no extra
        // calls to the analysis engine. It pairs only bodies that
        // could run at the same moment (issue #436), and its findings
        // append in listing order, after the per-function findings.
        let cross = self.cross_function.analyze_report(
            &bodies,
            &self.mutex,
            &self.atomics,
            &self.threads,
            &self.tls,
            &exports,
        );
        // The last-resort cap (issue #438): aggregation bounds a normal
        // program's cross-function output, so a scan past the cap is a
        // pathological one. The scan then keeps the first findings in
        // scan order, keeps the whole count, and lets the coverage
        // record below admit the truncation instead of cutting silently.
        let cross_total = cross.findings.len();
        let cross_truncated = cross_total > MAX_CROSS_FUNCTION_FINDINGS;
        let mut cross_findings = cross.findings;
        if cross_truncated {
            cross_findings.truncate(MAX_CROSS_FUNCTION_FINDINGS);
        }
        findings.extend(cross_findings);

        let mut metadata = ScanMetadata::new(binary);
        // The scan source names the analysis engine behind it, with
        // its pinned release, under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage, inside scan() where the
        // truth lives — not the registry row and not the CLI (issue
        // #349): every listed body was read by every per-body detector
        // unless the record says which bodies the scan could not
        // reach. The batch scan phase and the CLI's force-rescan file
        // the same admission through this one definition.
        metadata.coverage = Some(coverage_stamp(
            &unreached,
            nameless,
            &cross.gate_excluded,
            cross_truncated.then_some(cross_total),
        ));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected concurrency constructs"
        );
        Ok(SyncResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

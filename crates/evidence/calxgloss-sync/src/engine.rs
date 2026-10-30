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

/// The facets a concurrency scan declares, in order — the roster the
/// record must name exactly once each. The concurrency scan reads one
/// facet: the decompiled bodies every per-body detector shares.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every concurrency scan stamps about itself
/// (issue #349), beside the provenance and the timing.
///
/// The concurrency scan has one facet: `function-bodies` — the
/// decompiled bodies every per-body detector reads. The function
/// listing is always read end to end. A failed listing aborts the
/// run, and more than half failing to decompile trips the skip-rate
/// breaker in the scan below. So what a finished scan could not have
/// read is exactly the bodies it skipped along the way: a nameless
/// listing entry, or a decompile that failed.
///
/// The cross-function pass reads only bodies this walk already kept,
/// so it adds no coverage border of its own.
///
/// With nothing skipped, the facet is `complete`. That is the
/// admission's point: a function no finding mentions was examined and
/// clean, never silently unchecked. With any skips, the facet is
/// `partial` and the limitation line names the unreached bodies
/// (bounded at [`MAX_NAMED_UNREACHED`]), so silence and never-reaching
/// are distinguishable in the filed record itself. The whole picture
/// mirrors the single facet: the sync scan reads nothing else.
fn coverage_stamp(unreached: &[String], nameless: usize) -> ScanCoverage {
    let total = unreached.len() + nameless;
    if total == 0 {
        return ScanCoverage {
            status: CoverageStatus::Complete,
            facets: vec![FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }],
        };
    }
    let mut names = unreached
        .iter()
        .take(MAX_NAMED_UNREACHED)
        .cloned()
        .collect::<Vec<_>>();
    let hidden = unreached.len().saturating_sub(names.len()) + nameless;
    if hidden > 0 {
        names.push(format!("+{hidden} more"));
    }
    let body = if total == 1 { "body" } else { "bodies" };
    ScanCoverage {
        status: CoverageStatus::Partial,
        facets: vec![FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} function {body} unreached: {}",
                names.join(", ")
            )),
        }],
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

    /// Read async runtime loops against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_async_runtime(mut self, detector: AsyncDetector) -> Self {
        self.async_runtime = detector;
        self
    }

    /// Read futex synchronization against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_futex(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    /// Read futex synchronization against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_futexes(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    /// Read futex synchronization against `detector`'s name sets instead
    /// of the standard ones.
    pub fn with_futex_detector(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    pub fn with_futexes_detector(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    pub fn with_futex_runtime(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
        self
    }

    pub fn with_futex_detection(mut self, detector: FutexDetector) -> Self {
        self.futex = detector;
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
        // calls to the analysis engine. Its findings append in
        // listing order, after the per-function findings.
        findings.extend(self.cross_function.analyze(&bodies, &self.mutex));

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
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
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

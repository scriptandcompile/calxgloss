//! Algorithm recognition orchestration.
//!
//! [`AlgorithmEngine`] runs the detectors. It matches control flow
//! signatures, reads string-guided hints, and detects callback
//! patterns over each function, then runs multi-function correlation
//! over the whole listing. It assembles their records into a single
//! [`AlgorithmRecognitionResult`] with its scan provenance.
//!
//! The control flow and callback detectors are pure text analysis
//! over one decompiled body. The string engine additionally reads
//! the program's literal listing, so the scan fetches the listing and
//! the literals exactly once and reads them with every function — the
//! way the typeinfer detectors share one decompile.
//!
//! The scan is then one pass over the function listing, run with
//! bounded concurrency — at most eight decompiles in flight — while
//! results are collected in listing order, so the persisted hint list
//! stays stable and diffable. Where several detectors claim one
//! algorithm for one function, the scan reports it once with the
//! strongest evidence — the [`confidence`](crate::confidence)
//! module's resolution — and a configured minimum-confidence floor
//! ([`with_min_confidence`](AlgorithmEngine::with_min_confidence))
//! keeps weak claims out of the persisted result.
//!
//! The callback detector is the only reader of the call graph, and it
//! runs only for functions whose arity a configured contract could
//! fit: a function of the wrong arity fits no contract however it is
//! used, so fetching its callers would be a round trip guaranteed to
//! be refused. The correlation detector reads no graph at all. It
//! derives the call map from the bodies this scan already fetched, so
//! it adds no round trip and runs once the whole listing is in hand.

use crate::callback_db::CallbackPatternDb;
use crate::cfg_patterns::CfgPatternMatcher;
use crate::confidence::resolve_conflicts;
use crate::cross_function::CrossFunctionDetector;
use crate::error::Result;
use crate::string_hints::StringHintEngine;
use crate::types::{AlgorithmHint, AlgorithmRecognitionResult, ScanMetadata};
use calxgloss_decomp::{DecompiledFunction, StringLiteral};
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use futures_util::stream::{self, StreamExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{info, warn};

/// The cap on decompiles one scan keeps in flight at once.
///
/// The per-function pass runs several functions' program reads
/// concurrently to hide the bridge's round-trip latency. The bridge
/// answers one program at a time, so the pass keeps only a bounded
/// handful of decompiles in flight: that shrinks wall time on a large
/// binary without overloading the bridge. The scan tests' concurrency
/// accounting proves the scan never exceeds this cap (issue #156).
const MAX_IN_FLIGHT_DECOMPILES: usize = 8;

/// What one function's turn in the concurrent per-function pass produced.
///
/// The pass works down the function listing, running each function's
/// reads and detectors, and hands the results back in listing order,
/// so the assembled hint list is exactly what a sequential walk would
/// assemble. The variants say what the scan owes the skip count and
/// the breaker.
enum PassOutcome {
    /// The body, the per-function hints read from it in detector
    /// order — control flow, then string-guided, then callback — and a
    /// flag saying whether the caller fetch the callback detector
    /// needed failed.
    Read {
        body: DecompiledFunction,
        hints: Vec<AlgorithmHint>,
        callers_unreadable: bool,
    },
    /// The decompile failed; the skip-rate breaker counts it, and the
    /// coverage stamp names it.
    Failed { name: String },
    /// A nameless listing entry, skipped without a decompile.
    Nameless,
    /// The breaker had already tripped before this function's
    /// decompile was issued — the pass read nothing. The collector
    /// normally aborts at the counted [`Failed`](PassOutcome::Failed)
    /// that tripped the breaker, before one of these lands. This
    /// variant is the backstop: it keeps the abort carrying the counts
    /// either way.
    Halted,
}

/// The skip-rate breaker: one shared decompile-failure count that a
/// concurrent scan judges against the listing's size.
///
/// The rule is the sequential scan's: the run is reading the wrong
/// program once *most* of the listing — more than half of it — has
/// failed to decompile, and an empty result would then persist as a
/// phantom-clean record (issue #71). Under the concurrent pass the
/// count is shared, not just counted along the walk: every failed
/// decompile joins it as it lands, and every function not yet started
/// consults it before issuing its decompile. A tripped breaker
/// therefore stops new decompiles rather than merely ending the walk
/// (issue #156).
struct SkipRateBreaker {
    failures: AtomicUsize,
    total: usize,
}

impl SkipRateBreaker {
    /// A breaker over a listing of `total` functions, nothing failed
    /// yet.
    fn new(total: usize) -> Self {
        SkipRateBreaker {
            failures: AtomicUsize::new(0),
            total,
        }
    }

    /// Record one failed decompile.
    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::SeqCst);
    }

    /// Whether more than half the listing has failed to decompile.
    fn tripped(&self) -> bool {
        self.failures.load(Ordering::SeqCst) * 2 > self.total
    }

    /// The abort error, carrying the counts the breaker holds.
    fn error(&self) -> crate::AlgorithmError {
        crate::AlgorithmError::DecompileBreaker {
            failed: self.failures.load(Ordering::SeqCst),
            total: self.total,
        }
    }
}

/// The program reads a recognition scan performs.
///
/// The shared trait from the decompiler seam crate, re-exported here,
/// where [`AlgorithmEngine`]'s generic signature has always named it.
/// [`KunaSource`] implements it over the in-process analysis engine,
/// and tests implement it over canned bodies so the orchestration runs
/// without a server. The futures are `Send` so a scan can be driven
/// from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreadable regions one coverage limitation line names by
/// name before putting the rest into a count — bounded prose beside
/// the counts, not a dump (the P19-7 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets an algorithm-recognition scan declares, in order. The
/// record must name each one exactly once: the bodies every detector
/// reads, and the caller edges the callback detector reads.
pub const DECLARED_FACETS: &[&str] = &["function-bodies", "caller-edges"];

/// The coverage record every algorithm-recognition scan stamps about
/// itself (issue #351), beside the provenance and the timing.
///
/// The algorithm scan reads two facets. `function-bodies` covers the
/// decompiled bodies every detector reads. The function listing and
/// the program string listing are always read end to end: a failure
/// of either aborts the run, and more than half the listing failing
/// to decompile trips the skip-rate breaker. So what a finished scan
/// can not have read is exactly the bodies it skipped: a nameless
/// listing entry, or a decompile that failed. `caller-edges` covers
/// the call-graph reads the callback detector makes, issued only
/// where some contract could fit. A failed fetch costs that function
/// its callback readings and nothing else, so it is admitted by name
/// rather than aborting the run. The correlation pass reads the call
/// map from the bodies the scan already kept, so it adds no coverage
/// border of its own.
///
/// With nothing skipped, both facets are `complete`, and that is the
/// admission's point: a function no hint mentions was examined and
/// clean, never silently unchecked. With any skip, the facet is
/// `partial` and its limitation line names the regions (bounded at
/// [`MAX_NAMED_UNREACHED`]), so silence and never-reaching stay
/// distinguishable in the filed record itself. The whole picture
/// mirrors the two facets together.
fn coverage_stamp(
    unreached: &[String],
    nameless: usize,
    callers_unreadable: &[String],
) -> ScanCoverage {
    let bodies = {
        let total = unreached.len() + nameless;
        if total == 0 {
            FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }
        } else {
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
            FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Partial,
                limitation: Some(format!(
                    "{total} function {body} unreached: {}",
                    names.join(", ")
                )),
            }
        }
    };
    let edges = if callers_unreadable.is_empty() {
        FacetCoverage {
            id: "caller-edges".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        }
    } else {
        let total = callers_unreadable.len();
        let mut names = callers_unreadable
            .iter()
            .take(MAX_NAMED_UNREACHED)
            .cloned()
            .collect::<Vec<_>>();
        let hidden = total.saturating_sub(names.len());
        if hidden > 0 {
            names.push(format!("+{hidden} more"));
        }
        let edge = if total == 1 { "edge" } else { "edges" };
        FacetCoverage {
            id: "caller-edges".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} caller {edge} unreadable: {}",
                names.join(", ")
            )),
        }
    };
    let status =
        if bodies.status == CoverageStatus::Complete && edges.status == CoverageStatus::Complete {
            CoverageStatus::Complete
        } else {
            CoverageStatus::Partial
        };
    ScanCoverage {
        status,
        facets: vec![bodies, edges],
    }
}

/// The reads and detectors the concurrent per-function pass shares.
///
/// The pass holds this behind one [`Arc`] — every in-flight function
/// read owns its handle — so no in-flight future borrows the scan's
/// frame. That keeps the scan future provably `Send + 'static` for the
/// translator's scan-phase fan-out (issue #240, rust#100013). The
/// literals are program-wide evidence read by every function: one
/// fetch, shared across the pass.
struct SharedPass<S> {
    source: S,
    cfg: CfgPatternMatcher,
    strings: StringHintEngine,
    callbacks: CallbackPatternDb,
    literals: Vec<StringLiteral>,
}

/// Orchestrates the detectors into one [`AlgorithmRecognitionResult`].
///
/// `AlgorithmEngine` is generic over its [`ScanSource`], so tests can
/// run the whole orchestration over canned bodies;
/// [`new`](Self::new) builds one over a loaded [`KunaSource`].
///
/// Each detector carries no state and starts configured with its
/// standard signature set.
/// [`with_matcher`](Self::with_matcher),
/// [`with_string_engine`](Self::with_string_engine),
/// [`with_callback_db`](Self::with_callback_db), and
/// [`with_cross_detector`](Self::with_cross_detector) swap a
/// detector's set whole, and
/// [`with_pattern_database`](Self::with_pattern_database) swaps the
/// three per-function sets at once from one [database
/// document](crate::pattern_db). One instance of each serves the
/// whole scan. A scan keeps every hint it resolves by default;
/// [`with_min_confidence`](Self::with_min_confidence) sets a floor
/// below which hints never reach the persisted result.
#[derive(Debug, Clone)]
pub struct AlgorithmEngine<S = KunaSource> {
    source: S,
    cfg: CfgPatternMatcher,
    strings: StringHintEngine,
    callbacks: CallbackPatternDb,
    cross: CrossFunctionDetector,
    min_confidence: u8,
}

impl AlgorithmEngine<KunaSource> {
    /// An `AlgorithmEngine` over a loaded Kuna program, scanning with
    /// the standard signature sets.
    pub fn new(source: &KunaSource) -> AlgorithmEngine<KunaSource> {
        AlgorithmEngine {
            source: source.clone(),
            cfg: CfgPatternMatcher::with_default_patterns(),
            strings: StringHintEngine::with_default_signatures(),
            callbacks: CallbackPatternDb::with_default_patterns(),
            cross: CrossFunctionDetector::with_default_relationships(),
            min_confidence: 0,
        }
    }
}

impl<S> AlgorithmEngine<S> {
    /// An `AlgorithmEngine` whose program reads come from `source`,
    /// scanning with the standard signature sets.
    pub fn with_source(source: S) -> Self {
        AlgorithmEngine {
            source,
            cfg: CfgPatternMatcher::with_default_patterns(),
            strings: StringHintEngine::with_default_signatures(),
            callbacks: CallbackPatternDb::with_default_patterns(),
            cross: CrossFunctionDetector::with_default_relationships(),
            min_confidence: 0,
        }
    }

    /// Match control flow against `matcher`'s signatures instead of the
    /// standard set.
    pub fn with_matcher(mut self, matcher: CfgPatternMatcher) -> Self {
        self.cfg = matcher;
        self
    }

    /// Read string signatures from `engine` instead of the standard set.
    pub fn with_string_engine(mut self, engine: StringHintEngine) -> Self {
        self.strings = engine;
        self
    }

    /// Match callback contracts from `db` instead of the standard set.
    pub fn with_callback_db(mut self, db: CallbackPatternDb) -> Self {
        self.callbacks = db;
        self
    }

    /// Correlate call relationships with `detector`'s relationships
    /// instead of the standard set.
    pub fn with_cross_detector(mut self, detector: CrossFunctionDetector) -> Self {
        self.cross = detector;
        self
    }

    /// Scan with `database`'s sets for the detectors instead of the
    /// standard sets.
    ///
    /// The swap is whole, never a merge: each detector reads exactly
    /// the entries the [database](crate::pattern_db) carries, and a
    /// section the document omitted leaves that detector with nothing
    /// to read. Entries keep the detectors' semantics whole — the
    /// `{name}` placeholder, the lenient uncompilable-regex rule, and
    /// the per-entry confidence that overrides the standard score in
    /// resolution. The correlation section is no exception: a supplied
    /// database replaces the built-in relationship set whole, and only
    /// a scan with no database at all keeps the built-in relationships.
    pub fn with_pattern_database(mut self, database: crate::pattern_db::PatternDatabase) -> Self {
        self.cfg = CfgPatternMatcher::with_patterns(database.control_flow);
        self.strings = StringHintEngine::with_signatures(database.string_signatures);
        self.callbacks = CallbackPatternDb::with_patterns(database.callback_contracts);
        self.cross = CrossFunctionDetector::with_relationships(database.correlation_patterns);
        self
    }

    /// Persist only hints scoring `threshold` or higher.
    ///
    /// This mirrors the typesdb evidence engine's filter: the floor
    /// drops hints below `threshold` and keeps those at or above it.
    /// It applies after conflict resolution — to the surviving claim —
    /// so a reading another detector strengthened clears a threshold
    /// its first claim would have missed.
    pub fn with_min_confidence(mut self, threshold: u8) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Recognize algorithms across `binary`, decompiling each function
    /// exactly once and reading it with all three per-function
    /// detectors, then correlating the whole listing.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// hints follow the function listing: function by function, and
    /// within one function the control flow matches first, then the
    /// string-guided hints, then the callback matches. The correlation
    /// pass needs every body in hand to derive the call map, so it
    /// runs after the whole listing is in and reports its own hints in
    /// listing order. Two scans of the same program therefore diff
    /// cleanly.
    ///
    /// The per-function pass is concurrent: up to eight functions'
    /// reads run in flight at once, so a large binary scans faster
    /// without flooding the bridge. Each function's result is held
    /// until the one before it lands, so the assembled hint list is
    /// identical to the sequential walk's.
    ///
    /// Where several detectors claim the same algorithm for one
    /// function, the scan reports it once with its strongest evidence:
    /// a tie keeps the claim the scan surfaced first, and the survivor
    /// stands where that algorithm first appeared. Different
    /// algorithms claimed for one function all stand. A configured
    /// minimum-confidence floor
    /// ([`with_min_confidence`](Self::with_min_confidence)) then drops
    /// hints below the threshold — after resolution, so the floor
    /// judges each algorithm's surviving strongest claim.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning. A function whose
    /// callers cannot be read keeps its other hints with only its
    /// callback readings dropped. Only a failure of the program
    /// listing or the string listing — the server being down — aborts
    /// the run: a program listing failure means nothing was scanned,
    /// and a string listing failure would silently cost every function
    /// its string-guided evidence. But when more than half the listing
    /// fails to decompile, the skip-rate breaker aborts the run too:
    /// that is the signature of the bridge answering from the wrong
    /// program, and skipping on would persist a phantom-clean record
    /// (issue #71). The breaker counts failures across the concurrent
    /// pass, and once it trips no new decompile is issued
    /// (issue #156).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<AlgorithmRecognitionResult>
    where
        S: ScanSource + Clone,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        let total = functions.len();

        // The skip-rate breaker is shared across the concurrent pass,
        // not counted along behind the walk: every failed decompile
        // joins the count as it lands, and every function not yet
        // started reads the count before issuing its decompile. Once
        // the run has clearly lost most of the listing, no new
        // decompile is issued.
        let breaker = Arc::new(SkipRateBreaker::new(total));

        // The concurrent pass owns its reads: one clone of the source
        // and the three per-function detectors, plus the one literals
        // fetch, shared behind one `Arc`. Every in-flight function read
        // holds its own handle, so the pass borrows nothing from this
        // frame. The scan future stays provably `Send + 'static`,
        // which the translator's scan-phase fan-out needs to move the
        // scan onto a task (issue #240, rust#100013).
        let shared = Arc::new(SharedPass {
            source: self.source.clone(),
            cfg: self.cfg.clone(),
            strings: self.strings.clone(),
            callbacks: self.callbacks.clone(),
            literals: self.source.strings().await?,
        });
        let pass_breaker = Arc::clone(&breaker);

        let mut pass = stream::iter(functions.into_iter().map(move |function| {
            let shared = Arc::clone(&shared);
            let breaker = Arc::clone(&pass_breaker);
            async move {
                if function.name.is_empty() {
                    // A nameless listing entry has no name to look
                    // up: a lookup on it could land in some other
                    // function's body. Nothing can be recognized about
                    // it, so it passes unrecorded.
                    warn!(
                        address = format_args!("{:#x}", function.address),
                        "Skipping function with no name"
                    );
                    return PassOutcome::Nameless;
                }
                if breaker.tripped() {
                    // The breaker already tripped: this function's
                    // decompile is never issued.
                    return PassOutcome::Halted;
                }
                let decompiled = match shared.source.decompile(&function.name).await {
                    Ok(decompiled) => decompiled,
                    Err(error) => {
                        warn!(
                            function = %function.name,
                            error = %error,
                            "Skipping function: decompile failed"
                        );
                        breaker.record_failure();
                        return PassOutcome::Failed {
                            name: function.name.clone(),
                        };
                    }
                };

                let mut hints = Vec::new();
                hints.extend(shared.cfg.match_patterns(&decompiled));
                hints.extend(
                    shared
                        .strings
                        .detect_string_hints(&decompiled, &shared.literals),
                );

                // A contract fits only a function of exactly its arity, so
                // the caller fetch — the scan's only call-graph read — runs
                // just where some contract could still fit.
                let arity = decompiled.parameter_names().len();
                let mut callers_unreadable = false;
                if shared
                    .callbacks
                    .patterns()
                    .iter()
                    .any(|p| p.param_count == arity)
                {
                    let callers = match shared.source.callers(function.address).await {
                        Ok(callers) => callers,
                        Err(error) => {
                            warn!(
                                function = %function.name,
                                error = %error,
                                "Could not read callers: callback detection skips the function"
                            );
                            // The fetch was attempted and the answer
                            // never arrived — the coverage stamp below
                            // admits it by name (issue #351).
                            callers_unreadable = true;
                            Vec::new()
                        }
                    };
                    hints.extend(
                        shared
                            .callbacks
                            .detect_callback_patterns(&decompiled, callers)
                            .into_iter()
                            .map(|detection| detection.hint),
                    );
                }

                PassOutcome::Read {
                    body: decompiled,
                    hints,
                    callers_unreadable,
                }
            }
        }))
        .buffered(MAX_IN_FLIGHT_DECOMPILES);

        // Results land in listing order — `buffered` holds each
        // function's result until the one before it has been taken —
        // so the assembled hints and the kept bodies see exactly the
        // order the sequential walk saw.
        let mut hints = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::with_capacity(total);
        let mut skipped = 0usize;
        // Names of functions the parallel pass could not get a body for,
        // collected in listing order as the pass lands them, so the
        // coverage record below can admit them by name (issue #351).
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        let mut unreadable_edges: Vec<String> = Vec::new();
        while let Some(outcome) = pass.next().await {
            match outcome {
                PassOutcome::Read {
                    body,
                    hints: own,
                    callers_unreadable,
                } => {
                    if callers_unreadable {
                        unreadable_edges.push(body.name.clone());
                    }
                    hints.extend(own);
                    // Keep the body: the correlation pass derives the
                    // call map from the bodies this scan already
                    // fetched, so it costs no extra round trip.
                    bodies.push(body);
                }
                PassOutcome::Nameless => {
                    skipped += 1;
                    nameless += 1;
                }
                PassOutcome::Failed { name } => {
                    unreached.push(name);
                    skipped += 1;
                    if breaker.tripped() {
                        return Err(breaker.error());
                    }
                }
                PassOutcome::Halted => return Err(breaker.error()),
            }
        }

        // The correlation pass runs once the whole listing is in hand —
        // a relationship spans a call, and the callee's body may sit
        // anywhere in the listing — and reports in listing order.
        hints.extend(self.cross.detect_correlations(&bodies));

        let mut metadata = ScanMetadata::new(binary);
        // The evidence engine records its coverage here, where the
        // skips happened, so the filed record names what the scan never
        // read (issue #351). A complete record lets an unmentioned
        // function read as examined and clean.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless, &unreadable_edges));
        // The source names its analysis engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        // Competing claims for one (function, algorithm) resolve to
        // their strongest reading before the floor applies, so the
        // threshold judges each algorithm's best claim rather than
        // every duplicate, and the survivor keeps the position where
        // that algorithm first appeared in scan order.
        let hints: Vec<AlgorithmHint> = resolve_conflicts(hints)
            .into_iter()
            .filter(|hint| hint.confidence >= self.min_confidence)
            .collect();
        info!(
            binary = %metadata.binary,
            functions = total,
            hints = hints.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Recognized algorithms"
        );
        Ok(AlgorithmRecognitionResult { metadata, hints })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

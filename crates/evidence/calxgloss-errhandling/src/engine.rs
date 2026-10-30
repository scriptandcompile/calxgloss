//! The scan over one program: read every function body once and
//! collect the error-handling findings (ADR-0046).
//!
//! [`ErrhandlingEngine`] follows the established evidence-engine
//! shape: it reads through any [`ScanSource`], walks the function
//! listing in order, decompiles each function once, runs the idiom
//! detectors over each kept body, and assembles an [`ErrhandlingResult`]
//! stamped with the scan metadata — the same loop the libmatch and
//! globalstate scans run, with the detector set as its only difference.
//! Every finding behaviour is asserted here, never inside a detector.

use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::error_code::ErrorCodeDetector;
use crate::exception_api::ExceptionApiDetector;
use crate::goto_cleanup::GotoCleanupDetector;
use crate::named_handler::NamedHandlerDetector;
use crate::raise_exception::RaiseExceptionDetector;
use crate::seh_frame::SehFrameDetector;
use crate::types::{ErrhandlingFinding, ErrhandlingResult};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage, ScanMetadata};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler an error-handling scan reads through.
///
/// A shared trait from the decompiler seam crate, re-exported so
/// this evidence engine's generic shape names it in one place;
/// [`KunaSource`] implements it over the in-process analysis engine,
/// and tests implement it over canned bodies so the whole scan runs
/// without a server. The futures are `Send` so a scan can be driven
/// from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line lists by
/// name before the rest become a count — bounded prose beside the
/// counts, not a dump (the P19-6 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets an error-handling scan declares, in order — the roster
/// the record must name exactly once each. The error-handling scan
/// reads one facet: the decompiled bodies the six detectors read from.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every error-handling scan stamps about itself
/// (issue #350), beside the provenance and the timing.
///
/// The error-handling scan has one facet: `function-bodies`, the
/// decompiled bodies the six detectors read. The scan reads the
/// function listing end to end — a failed listing aborts the run, and
/// more than half failing to decompile trips the skip-rate breaker in
/// the scan loop — so what a finished scan can not have read is
/// exactly the bodies it skipped along the way: a nameless listing
/// entry, or a decompile that failed. The cross-function pass reads
/// only bodies this loop already kept, so it adds no coverage border
/// of its own. With nothing skipped, the facet is `complete`, and
/// that is the admission's point: a function with no idiom or code
/// record was examined and clean, never silently unchecked. With any
/// skips, the facet is `partial` and the limitation line lists the
/// unreached bodies by name (bounded at [`MAX_NAMED_UNREACHED`]), so
/// the filed record itself tells silence about a clean function apart
/// from a function it never reached. The whole picture mirrors the
/// single facet — the scan examines nothing else.
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

/// Orchestrates the per-body idiom readings into one
/// [`ErrhandlingResult`].
///
/// One loop, six detectors, per the ADR-0046 family ladder: the
/// spelled SEH frame, the named personality-handler thunk, the
/// exception-API call, the direct `RaiseException` call, the
/// goto-cleanup ladder, and the per-function failure-code reading.
/// The SEH detectors run strongest first, and **the strongest
/// family that fires takes the function's one SEH claim** — a body
/// showing a spelled block beside a thunk registration lands one
/// finding at the spelled band, never a stack of duplicates for the
/// same frame (issue #288). The `RaiseException` reading is a
/// different fact — the function *raising*, not being guarded — and
/// it sits beside the SEH claim, as does the `GotoCleanup` reading —
/// the function *cleaning up on failure*, whether or not any
/// exception mechanism is involved (issue #289). One function
/// therefore contributes at most three idiom findings, in
/// strongest-first order, plus its own failure-code records: one
/// record per distinct code, keyed to the function beside the
/// idioms (issue #290). After the loop one cross-function pass over
/// the whole kept set propagates those codes along the call map onto
/// the callers that guard on or re-return a callee's return (issue
/// #291, ADR-0047): codes travel, idioms never, and the inherited
/// findings append after every per-function record. It keeps every
/// body for that pass, so the pass costs no second decompile.
/// Follow-up P15 bullets add detectors, not new control flow, so
/// the scan-order, skip, and breaker behaviour — the behaviour
/// contract every evidence engine keeps — stays written in exactly
/// one place. The scan is generic over its [`ScanSource`], so tests
/// can run the whole orchestration over canned bodies;
/// [`new`](Self::new) builds one over a loaded [`KunaSource`]. The
/// SEH and raise detectors carry no state, so one instance of each
/// serves the whole scan, and [`with_seh_frame`](Self::with_seh_frame),
/// [`with_named_handler`](Self::with_named_handler),
/// [`with_exception_api`](Self::with_exception_api),
/// [`with_raise_exception`](Self::with_raise_exception),
/// [`with_goto_cleanup`](Self::with_goto_cleanup), and
/// [`with_error_code`](Self::with_error_code) swap one detector for a
/// configured one.
#[derive(Debug, Clone)]
pub struct ErrhandlingEngine<S = KunaSource> {
    source: S,
    seh_frame: SehFrameDetector,
    named_handler: NamedHandlerDetector,
    exception_api: ExceptionApiDetector,
    raise_exception: RaiseExceptionDetector,
    goto_cleanup: GotoCleanupDetector,
    error_code: ErrorCodeDetector,
    cross_function: CrossFunctionAnalyzer,
}

/// The standard detector set, spelled once so `new` and
/// `with_source` cannot drift apart.
fn standard_detectors() -> (
    SehFrameDetector,
    NamedHandlerDetector,
    ExceptionApiDetector,
    RaiseExceptionDetector,
    GotoCleanupDetector,
    ErrorCodeDetector,
) {
    (
        SehFrameDetector,
        NamedHandlerDetector,
        ExceptionApiDetector,
        RaiseExceptionDetector,
        GotoCleanupDetector::new(),
        ErrorCodeDetector,
    )
}

impl ErrhandlingEngine<KunaSource> {
    /// An evidence engine over a loaded Kuna program: it detects the
    /// SEH frame across its three body-text families, the direct
    /// `RaiseException` call, the goto-cleanup ladder, and records
    /// each function's shaped failure codes beside those findings.
    pub fn new(source: &KunaSource) -> ErrhandlingEngine<KunaSource> {
        let (seh_frame, named_handler, exception_api, raise_exception, goto_cleanup, error_code) =
            standard_detectors();
        ErrhandlingEngine {
            source: source.clone(),
            seh_frame,
            named_handler,
            exception_api,
            raise_exception,
            goto_cleanup,
            error_code,
            // The propagation pass has no detectors of its own to
            // configure — the configured code reading is handed to
            // it as its argument — so the standard analyzer serves
            // every scan (issue #291).
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> ErrhandlingEngine<S> {
    /// An evidence engine whose decompiles come from `source`, using
    /// the detectors' standard bands and name sets.
    pub fn with_source(source: S) -> Self {
        let (seh_frame, named_handler, exception_api, raise_exception, goto_cleanup, error_code) =
            standard_detectors();
        ErrhandlingEngine {
            source,
            seh_frame,
            named_handler,
            exception_api,
            raise_exception,
            goto_cleanup,
            error_code,
            // Standard here too; see `new` (issue #291).
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }

    /// Read spelled SEH frames with `detector` instead of the
    /// standard one — where a follow-up family can set its own
    /// configured detector without changing the loop.
    pub fn with_seh_frame(mut self, detector: SehFrameDetector) -> Self {
        self.seh_frame = detector;
        self
    }

    /// Read named personality-handler thunks with `detector` instead
    /// of the standard one.
    pub fn with_named_handler(mut self, detector: NamedHandlerDetector) -> Self {
        self.named_handler = detector;
        self
    }

    /// Read exception-API calls with `detector` instead of the
    /// standard one.
    pub fn with_exception_api(mut self, detector: ExceptionApiDetector) -> Self {
        self.exception_api = detector;
        self
    }

    /// Read direct `RaiseException` calls with `detector` instead of
    /// the standard one.
    pub fn with_raise_exception(mut self, detector: RaiseExceptionDetector) -> Self {
        self.raise_exception = detector;
        self
    }

    /// Read goto-cleanup ladders with `detector` instead of the
    /// standard one — where a binary's own release names are set
    /// through [`GotoCleanupDetector::with_releases`] without
    /// changing the loop.
    pub fn with_goto_cleanup(mut self, detector: GotoCleanupDetector) -> Self {
        self.goto_cleanup = detector;
        self
    }

    /// Read per-function failure codes with `detector` instead of the
    /// standard one — where a follow-up reading can set its own
    /// configured code detector without changing the loop.
    pub fn with_error_code(mut self, detector: ErrorCodeDetector) -> Self {
        self.error_code = detector;
        self
    }

    /// Replace the cross-function propagation pass. The pass has no
    /// detector names or bands of its own to configure — the
    /// configured code reading above is handed to it as its
    /// argument — so this setter exists for tests that want to drive
    /// the propagation seam directly (issue #291).
    pub fn with_cross_function(mut self, analyzer: CrossFunctionAnalyzer) -> Self {
        self.cross_function = analyzer;
        self
    }

    /// Scan every listed function, one decompile each, and collect
    /// the findings in listing order.
    ///
    /// The contract mirrors the other evidence engines: the listing
    /// is read once; a function whose body the decompiler cannot
    /// produce (a thunk, a bad entry point) is skipped with a warning
    /// and claims nothing — absence of a body is not evidence of the
    /// idiom's absence; only a failure of the listing itself aborts
    /// the run, since then nothing was scanned. But when more than
    /// half the listing fails to decompile, the skip-rate breaker
    /// aborts too: a high skip rate is the signature of the seam
    /// answering about the wrong program, and skipping on would
    /// persist a record that looks clean but is not (issue #71).
    /// Findings land in listing order, one function's findings grouped
    /// together, so two scans of the same program diff cleanly; after
    /// the loop the cross-function pass runs once over the whole kept
    /// set, and its inherited findings append after every per-function
    /// record — a caller's first-hand contract is read before its
    /// second-hand codes are added on top (issue #291, ADR-0047).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ErrhandlingResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings: Vec<ErrhandlingFinding> = Vec::new();
        // The kept bodies are held for the cross-function pass after
        // the loop: the call map and every callee's code set come
        // from this same text, so the pass costs no second decompile
        // (issue #291).
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-6: which bodies the scan could not read, listed by name
        // where one exists, counted where the listing entry is
        // nameless — the coverage record below states it, so an
        // unmentioned function means examined-and-clean, not unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless entry would send the name lookup into
                // some other function's body; nothing can be said
                // about it, so it is skipped and left unrecorded.
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
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the seam is answering about
                    // the wrong program, and an empty result would
                    // persist as a record that looks clean but is not.
                    // Abort with the counts instead of skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::ErrhandlingError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };
            // Keep the name and body for the detectors, and the
            // whole entry for the cross-function pass after the
            // loop; it reads call edges and code sets from this
            // same text, so it costs no second decompile (issue #291).
            let name = decompiled.name.clone();
            let body = decompiled.body.clone();
            bodies.push(decompiled);
            // The strongest SEH family wins: the detectors run in
            // ADR-0046's ladder order — spelled frame, named
            // handler, exception-API call — and the first that
            // fires takes the function's one SEH claim. A body
            // showing a spelled block beside a thunk registration
            // lands one finding at the spelled band, never a stack
            // of duplicates for the same frame (issue #288). The
            // RaiseException reading records a different fact — the
            // function raising, not being guarded — and the
            // GotoCleanup reading records a third — the function
            // cleaning up on failure, an idiom that is part of no
            // exception mechanism — both standing beside the SEH
            // claim (issue #289).
            for mut finding in self
                .seh_frame
                .detect(&body)
                .or_else(|| self.named_handler.detect(&body))
                .or_else(|| self.exception_api.detect(&body))
                .into_iter()
                .chain(self.raise_exception.detect(&body))
                .chain(self.goto_cleanup.detect(&body))
                .chain(self.error_code.detect(&body))
                .collect::<Vec<_>>()
            {
                // The detectors fill in no function name (they never
                // see one); the scan stamps it here, at the seam
                // where every finding behaviour is asserted.
                finding.set_function(&name);
                findings.push(finding);
            }
        }

        // The cross-function pass runs once over the whole kept set,
        // and its records append after every per-function finding:
        // the caller's own contract was read first-hand, the
        // second-hand codes come after it, and two scans of one
        // program still diff cleanly (issue #291, ADR-0047).
        findings.extend(self.cross_function.analyze(&bodies, &self.error_code));

        let mut metadata = ScanMetadata::new(binary);
        // The source names its analysis engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage, where the truth lives —
        // not the registry row and not the CLI (issue #350): every
        // listed body was read by all six detectors unless the scan
        // says which ones it could not reach. The batch scan phase
        // and the CLI's force-rescan file the same admission through
        // this one definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected error-handling idioms"
        );
        Ok(ErrhandlingResult { metadata, findings })
    }
}

#[cfg(test)]
mod tests;

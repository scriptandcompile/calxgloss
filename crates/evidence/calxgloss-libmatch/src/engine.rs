//! Known-library identification scan orchestration.
//!
//! [`LibmatchEngine`] runs the body-signature matcher over every function
//! of one loaded program and assembles its findings into a single
//! [`LibmatchResult`] with its scan provenance.
//!
//! The matcher reads only the text of one decompiled body, so the scan
//! decompiles each function exactly once — its per-function pass runs
//! one function at a time down the function listing. Keeping that pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order. Where two signatures claim one function, the resolution step
//! ([`resolve_matches`](crate::confidence::resolve_matches)) keeps only
//! the strongest claim, standing where the function first appeared.

use std::time::Instant;

use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use tracing::{info, warn};

use crate::error::Result;
use crate::matcher::LibmatchMatcher;
use crate::types::{LibmatchFinding, LibmatchResult, ScanMetadata};

/// The decompiler reads a known-library identification scan performs.
///
/// This is the shared trait from the decompiler seam crate, re-exported
/// here so this crate names it directly. [`KunaSource`] implements it
/// over the in-process analysis engine; tests implement it over canned
/// bodies, so the orchestration runs without a server. Its futures are
/// `Send`, so a scan can be driven from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names inline
/// before the rest are replaced by a count — bounded prose beside the
/// counts, not a dump (the P19-3 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a libmatch scan declares, in order — the roster the
/// record must name exactly once each. libmatch reads one facet: the
/// decompiled bodies.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every libmatch scan stamps about itself (issue
/// #347), beside the provenance and the timing.
///
/// libmatch has one facet: `function-bodies`, the decompiled bodies the
/// body-signature matcher reads. The scan always reads the function
/// listing end to end: a failed listing aborts the run, and more than
/// half of the listing failing to decompile trips the skip-rate
/// breaker. So what a finished scan can not have read is exactly the
/// bodies it skipped along the way: a nameless listing entry, or a
/// decompile that failed. With none, the facet is `complete`, and that
/// is the admission's point: a function no finding mentions was
/// examined and clean, never silently unchecked. With any, the facet is
/// `partial` and the limitation line names the unreached bodies
/// (bounded at [`MAX_NAMED_UNREACHED`]), so silence and never-reaching
/// are distinguishable in the filed record itself. The whole picture
/// mirrors the single facet — there is nothing else this scan examines.
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

/// Orchestrates the body-signature matcher into one [`LibmatchResult`].
///
/// The type is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one
/// over a loaded [`KunaSource`]. The matcher carries no state and starts
/// with the built-in starter set — [`with_matcher`](Self::with_matcher)
/// swaps the set whole — so one instance serves the whole scan.
#[derive(Debug, Clone)]
pub struct LibmatchEngine<S = KunaSource> {
    source: S,
    matcher: LibmatchMatcher,
}

impl LibmatchEngine<KunaSource> {
    /// An evidence engine over a loaded Kuna program, scanning with the
    /// built-in starter signature set.
    pub fn new(source: &KunaSource) -> LibmatchEngine<KunaSource> {
        LibmatchEngine {
            source: source.clone(),
            matcher: LibmatchMatcher::with_default_signatures(),
        }
    }
}

impl<S> LibmatchEngine<S> {
    /// An evidence engine whose decompiles come from `source`, scanning
    /// with the built-in starter signature set.
    pub fn with_source(source: S) -> Self {
        LibmatchEngine {
            source,
            matcher: LibmatchMatcher::with_default_signatures(),
        }
    }

    /// Match bodies against `matcher`'s signature set instead of the
    /// built-in starter set.
    pub fn with_matcher(mut self, matcher: LibmatchMatcher) -> Self {
        self.matcher = matcher;
        self
    }

    /// Match bodies against an operator-supplied
    /// [database](crate::signature_db::SignatureDatabase)'s signature
    /// set instead of the built-in starter set — the file's set
    /// replaces the built-in one whole, never merged into it.
    pub fn with_signature_database(
        mut self,
        database: crate::signature_db::SignatureDatabase,
    ) -> Self {
        self.matcher = LibmatchMatcher::with_signatures(database.signatures);
        self
    }

    /// Identify known-library functions across `binary`, decompiling
    /// each function exactly once and matching its normalized body
    /// against every configured signature.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The findings
    /// follow the function listing — function by function, and within
    /// one function the signature matches in configuration order — so
    /// two scans of the same program diff cleanly. Where two signatures
    /// claim one function, only the strongest claim survives resolution,
    /// standing where the function first appeared. Cross-function
    /// propagation findings — identical-body duplicates and tail-call
    /// thunks inheriting a match — append after every per-function
    /// finding, identical-body findings first and thunks after, each
    /// group in listing order.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning. Only a failure of the
    /// listing read itself — the analysis engine being down — aborts the
    /// run, since then nothing was scanned. When more than half of the
    /// function listing has failed to decompile, the skip-rate breaker
    /// aborts the run too. A high skip rate is the signature of the
    /// seam answering about the wrong program. The breaker is a fuse,
    /// not a post-mortem: it aborts rather than let the scan persist a
    /// record that looks clean but is not (issue #71).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<LibmatchResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings: Vec<LibmatchFinding> = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-3: which bodies the scan could NOT read, named where a name
        // exists, counted where the listing entry is nameless — the
        // coverage record below states it, so an unmentioned function
        // means examined-and-clean, never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry is skipped: looking up an
                // empty name could fetch some other function's body,
                // and nothing can be said about the entry itself, so it
                // passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
                continue;
            }
            let decompiled: DecompiledFunction = match self.source.decompile(&function.name).await {
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
                    // Skip-rate breaker: a high skip rate is the
                    // signature of the seam answering about the wrong
                    // program. The breaker is a fuse, not a
                    // post-mortem: once more than half of the function
                    // listing has failed to decompile, abort with the
                    // counts instead of skipping on and persisting a
                    // record that looks clean but is not.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::LibmatchError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            findings.extend(self.matcher.match_function(&decompiled));
            bodies.push(decompiled);
        }

        // Two signatures can fit one body; one function is one function,
        // so the strongest claim per function stands, in listing order
        // (ADR-0022's precedent).
        let mut findings = crate::confidence::resolve_matches(findings);

        // The cross-function pass then propagates those claims over the
        // bodies the scan already holds — no new reads from the analysis
        // engine — and its findings append after every per-function
        // finding, identical-body duplicates first and thunks after,
        // each group in listing order.
        findings.extend(crate::cross_function::propagate(&bodies, &findings));

        let mut metadata = ScanMetadata::new(binary);
        // The source names the analysis engine and its version pin
        // under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage, where the truth lives — not
        // the registry row and not the CLI (issue #347): every listed
        // body was read unless the scan says which ones it could not
        // reach, and the match records themselves carry their
        // version-authority note. The batch scan phase and the CLI's
        // force-rescan file the same admission through this same single
        // definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Identified known-library functions"
        );
        Ok(LibmatchResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

//! Callback-table scan orchestration.
//!
//! [`CallbackEngine`] runs the callback detectors — function-pointer
//! array calls, callback registrations, jump-table dispatches, and
//! dynamic-loading plugin shapes — over every function of one open
//! program, then the cross-function pass over the bodies it
//! kept, and assembles their findings into a single
//! [`CallbackResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the scan fetches each function's pseudo-C exactly once and reads
//! it with every configured detector, instead of letting each
//! detector fetch its own copy. The cross-function pass reads those
//! same kept bodies, so the scan stays at one decompile per function.
//!
//! The scan is one sequential pass over the function listing. Unlike
//! typeinfer's competing families, the callback detectors have
//! nothing to resolve between them — they read disjoint body
//! shapes — and keeping the pass sequential keeps the persisted
//! finding list in a stable, diffable order.

use crate::callback_reg::CallbackRegDetector;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::fp_array::FpArrayDetector;
use crate::jump_table::JumpTableDetector;
use crate::plugin::PluginDetector;
use crate::signatures::{SignatureMap, enrich_suggestion};
use crate::types::{CallbackFinding, CallbackResult, ScanMetadata};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a callback scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic parameters can name it right where they
/// use it. [`KunaSource`] implements it on top of the in-process
/// analysis engine, and tests implement it over canned bodies so the
/// whole orchestration runs without a server. The futures are `Send`
/// so a scan can be driven from an orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names
/// inline before it reports the rest as a count. This keeps the
/// admission line beside the counts bounded, not a name dump (the
/// P19-6 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a callback-detection scan declares, in order — the
/// roster the record must name exactly once each. The callback scan
/// reads one facet: the decompiled bodies every detector reads.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every callback-detection scan stamps about
/// itself (issue #350), beside the provenance and the timing.
///
/// The callback scan has one facet: `function-bodies`, the decompiled
/// bodies every detector reads. It always reads the function listing
/// end to end: a failed listing aborts the run, and more than half
/// failing to decompile trips the skip-rate breaker in the scan
/// below. So what a finished scan cannot have read is exactly the
/// bodies it skipped along the way: a nameless listing entry, or a
/// decompile that failed. The cross-function pass reads only the
/// bodies this walk already kept, so it adds no coverage border of
/// its own.
///
/// With nothing skipped, the facet is `complete`. That is the point
/// of the admission: a function no callback finding mentions was
/// examined and clean, never silently unchecked. With anything
/// skipped, the facet is `partial` and the limitation line names the
/// unreached bodies, bounded at [`MAX_NAMED_UNREACHED`]. Silence and
/// never-reaching are therefore distinguishable in the filed record
/// itself. The whole picture mirrors the single facet — there is
/// nothing else this scan examines.
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

/// Orchestrates the callback detectors into one [`CallbackResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run
/// the whole orchestration over canned bodies; [`new`](Self::new)
/// builds one over a loaded [`KunaSource`]. Each detector holds no
/// state and starts with its standard name set, so one instance of
/// each serves the whole scan; [`with_fp_array`](Self::with_fp_array),
/// [`with_registration`](Self::with_registration),
/// [`with_jump_table`](Self::with_jump_table) and
/// [`with_plugin`](Self::with_plugin) each replace one detector's
/// set whole. A [`SignatureMap`] composed by the caller and injected
/// through [`with_signatures`](Self::with_signatures) fills the real
/// closure contracts into the registration and chain suggestions in
/// place; with no map the scan is exactly what it was.
#[derive(Debug, Clone)]
pub struct CallbackEngine<S = KunaSource> {
    source: S,
    fp_array: FpArrayDetector,
    registration: CallbackRegDetector,
    jump_table: JumpTableDetector,
    plugin: PluginDetector,
    cross_function: CrossFunctionAnalyzer,
    signatures: SignatureMap,
}

impl CallbackEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the
    /// detectors' standard name sets.
    pub fn new(source: &KunaSource) -> CallbackEngine<KunaSource> {
        CallbackEngine {
            source: source.clone(),
            fp_array: FpArrayDetector::with_default_names(),
            registration: CallbackRegDetector::with_default_names(),
            jump_table: JumpTableDetector::with_default_prefixes(),
            plugin: PluginDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
            signatures: SignatureMap::new(),
        }
    }
}

impl<S> CallbackEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        CallbackEngine {
            source,
            fp_array: FpArrayDetector::with_default_names(),
            registration: CallbackRegDetector::with_default_names(),
            jump_table: JumpTableDetector::with_default_prefixes(),
            plugin: PluginDetector::with_default_names(),
            cross_function: CrossFunctionAnalyzer::new(),
            signatures: SignatureMap::new(),
        }
    }

    /// Read function-pointer array calls against `detector`'s name set
    /// instead of the standard one.
    pub fn with_fp_array(mut self, detector: FpArrayDetector) -> Self {
        self.fp_array = detector;
        self
    }

    /// Read callback registrations against `detector`'s name set
    /// instead of the standard one.
    pub fn with_registration(mut self, detector: CallbackRegDetector) -> Self {
        self.registration = detector;
        self
    }

    /// Read jump-table dispatches against `detector`'s prefix set
    /// instead of the standard one.
    pub fn with_jump_table(mut self, detector: JumpTableDetector) -> Self {
        self.jump_table = detector;
        self
    }

    /// Read dynamic-loading plugin shapes against `detector`'s name
    /// sets instead of the standard ones.
    pub fn with_plugin(mut self, detector: PluginDetector) -> Self {
        self.plugin = detector;
        self
    }

    /// Fill the real closure contract into every suggestion whose
    /// callback `signatures` names.
    ///
    /// The map looks up a registration's bound callback, and a
    /// chain's callback, by its spelled name. A hit renders
    /// `Box<dyn Fn(i32) -> bool>` in place of the open
    /// `Box<dyn Fn(...)>` (see [`crate::signatures`]). The map is
    /// composed by the **caller** from another scan's persisted
    /// records — the CLI `callback` command and the batch
    /// pre-analysis read the type-inference document — because this
    /// crate takes no dependency on the type-inference crate
    /// (ADR-0036). An empty map, or a name the map does not carry,
    /// leaves every suggestion exactly as the detectors wrote it;
    /// function-pointer-array and jump-table suggestions are never
    /// touched, because their callees are unnamed.
    pub fn with_signatures(mut self, signatures: SignatureMap) -> Self {
        self.signatures = signatures;
        self
    }

    /// When `callback` has a known closure contract in the map, fill
    /// it into `suggestion` in place; anything else stands as written.
    fn enrich(&self, callback: &str, suggestion: &mut String) {
        if let Some(signature) = self.signatures.get(callback) {
            *suggestion = enrich_suggestion(suggestion, signature);
        }
    }

    /// Detect callback tables across `binary`, decompiling each
    /// function exactly once and reading it with every configured
    /// detector.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing, function by function.
    /// Within one function they come in detector order: the
    /// function-pointer array calls, then the registrations, then the
    /// jump tables, then the plugin shapes. After the whole walk,
    /// the cross-function pass adds its findings — chains, then
    /// event systems — in listing order, over the bodies this walk
    /// already decompiled: no extra engine reads. So two scans of
    /// the same program diff cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning. Only a failure of
    /// the listing itself — the server being down — aborts the run,
    /// because then nothing was scanned. But when more than half the
    /// listing fails to decompile, the skip-rate breaker aborts the
    /// run too: that is the signature of the bridge answering from the
    /// wrong program, and skipping on would persist a record that
    /// looks clean but is not (issue #71). The detectors read disjoint
    /// body shapes, so a function can carry findings of every kind at
    /// once and nothing is resolved between them. Where a
    /// [`with_signatures`](Self::with_signatures) map names a bound
    /// callback, the registration and chain suggestions carry its
    /// real closure contract out of the scan — into the persisted
    /// document, the CLI report, and the escalate prompt alike.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<CallbackResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-6: keep track of which bodies the scan could not read —
        // named where a name exists, counted where the listing entry
        // is nameless. The coverage record below states this, so a
        // function no finding mentions means examined and clean,
        // never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the by-name
                // lookup into some other function's body. Nothing can
                // be said about it, so it passes without a record.
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
                    // Skip-rate breaker: once more than half of the
                    // listing has failed to decompile, the scan is
                    // reading a program the analysis engine cannot
                    // analyze, and an empty result would persist as a
                    // record that looks clean but is not. Abort with
                    // the counts instead of skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::CallbackError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            findings.extend(
                self.fp_array
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::FpArray),
            );
            findings.extend(
                self.registration
                    .detect(&decompiled)
                    .into_iter()
                    .map(|mut record| {
                        self.enrich(&record.callback, &mut record.suggestion);
                        CallbackFinding::Registration(record)
                    }),
            );
            findings.extend(
                self.jump_table
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::JumpTable),
            );
            findings.extend(
                self.plugin
                    .detect(&decompiled)
                    .into_iter()
                    .map(CallbackFinding::Plugin),
            );
            bodies.push(decompiled);
        }

        // The cross-function pass runs after the per-function walk,
        // over the bodies the scan already decompiled — no extra
        // engine reads — and its findings append in listing order,
        // after the per-function findings. A chain's callback is
        // enriched the same way a registration's is. The event-system
        // suggestion names a crowd of handlers whose contracts can
        // differ, so no single one of them stands for the crowd and
        // the signature map never applies to it (ADR-0036).
        let mut cross_findings = self.cross_function.analyze(
            &bodies,
            &self.registration,
            &self.fp_array,
            &self.jump_table,
        );
        for finding in &mut cross_findings {
            if let CallbackFinding::Chain(record) = finding {
                self.enrich(&record.callback, &mut record.suggestion);
            }
        }
        findings.extend(cross_findings);

        let mut metadata = ScanMetadata::new(binary);
        // The source reports its analysis engine's name and version
        // pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage where the truth lives, not
        // the registry row and not the CLI (issue #350): every listed
        // body was read by every configured detector unless the scan
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
            "Detected callback tables"
        );
        Ok(CallbackResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

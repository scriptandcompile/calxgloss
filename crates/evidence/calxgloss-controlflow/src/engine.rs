//! Control-flow scan orchestration.
//!
//! [`ControlFlowEngine`] runs the six detectors — switch-shaped
//! if/else-if chains, self-recursion, state machines, loop
//! structure, branch density, and the branch inventory — over every function of one loaded program and
//! assembles their findings
//! into a single [`ControlFlowResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the scan fetches each function's pseudo-C exactly once and reads
//! it with all six, instead of each detector pulling its own copy.
//! The scan is one sequential pass over the function listing. Like
//! sync, there is nothing to resolve between the detectors: they
//! read disjoint shapes. Keeping the pass sequential keeps the
//! persisted finding list in a stable, diffable order.
//!
//! The walk keeps each body it successfully decompiled. After the
//! per-function pass, the cross-function pass reads mutual-recursion
//! call cycles off those kept bodies. Like the memory (ADR-0027),
//! sync (ADR-0033), and callback (ADR-0035) cross-function passes,
//! it adds no new [`ScanSource`] reads, so the exactly-once-decompile
//! guarantee and the skip-rate breaker still hold.

use crate::branch_density::BranchDensityDetector;
use crate::branch_inventory::BranchInventoryDetector;
use crate::cross_function::CrossFunctionAnalyzer;
use crate::error::Result;
use crate::loop_detect::LoopDetector;
use crate::recursion::RecursionDetector;
use crate::state_machine::StateMachineDetector;
use crate::switch::SwitchChainDetector;
use crate::types::{ControlFlowFinding, ControlFlowResult, ScanMetadata};
use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a control-flow scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here so
/// the scan's generic shape names it where it always has. [`KunaSource`]
/// implements it over the in-process analysis engine; tests implement it
/// over canned bodies so the orchestration runs without a server. The
/// futures are `Send` so a scan can be driven from an orchestrating
/// task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names
/// inline before it reports the rest as a count. This keeps the
/// admission line beside the counts bounded, not a name dump (the
/// P19-5 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a control-flow scan declares, in order — the roster the
/// record must name exactly once each. The control-flow scan reads one
/// facet: the decompiled bodies all six detectors share.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every control-flow scan stamps about itself (issue
/// #349), beside the provenance and the timing.
///
/// The control-flow scan has one facet: `function-bodies`, the decompiled
/// bodies all six detectors read. The function listing is always read end
/// to end. A failed listing aborts the run, and more than half failing to
/// decompile trips the skip-rate breaker. So what a finished scan can not
/// have read is exactly the bodies it skipped along the way: a nameless
/// listing entry, or a decompile that failed. The cross-function pass
/// reads only bodies this walk already kept, so it adds no coverage
/// border of its own.
///
/// With nothing skipped, the facet is `complete`. That is the admission's
/// point: a function no finding mentions was examined and clean, never
/// silently unchecked. With any skipped, the facet is `partial` and the
/// limitation line names the unreached bodies, bounded at
/// [`MAX_NAMED_UNREACHED`], so silence and never-reaching stay
/// distinguishable in the filed record itself. The whole picture mirrors
/// the single facet — there is nothing else this scan examines.
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

/// Orchestrates the six detectors into one [`ControlFlowResult`].
///
/// The scan is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a loaded [`KunaSource`]. Each detector carries no state and
/// starts configured with its standard thresholds and name set —
/// [`with_switch`](Self::with_switch), [`with_recursion`](Self::with_recursion),
/// [`with_state_machine`](Self::with_state_machine), [`with_loop`](Self::with_loop),
/// [`with_branch_density`](Self::with_branch_density),
/// and [`with_branch_inventory`](Self::with_branch_inventory) swap a detector
/// whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ControlFlowEngine<S = KunaSource> {
    source: S,
    switch: SwitchChainDetector,
    recursion: RecursionDetector,
    state_machine: StateMachineDetector,
    loops: LoopDetector,
    branch_density: BranchDensityDetector,
    branch_inventory: BranchInventoryDetector,
    cross_function: CrossFunctionAnalyzer,
}

impl ControlFlowEngine<KunaSource> {
    /// A scan over a loaded Kuna program, using the six detectors'
    /// standard thresholds and name set.
    pub fn new(source: &KunaSource) -> ControlFlowEngine<KunaSource> {
        ControlFlowEngine {
            source: source.clone(),
            switch: SwitchChainDetector::default(),
            recursion: RecursionDetector,
            state_machine: StateMachineDetector::default(),
            loops: LoopDetector::default(),
            branch_density: BranchDensityDetector::default(),
            branch_inventory: BranchInventoryDetector::default(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }
}

impl<S> ControlFlowEngine<S> {
    /// A scan whose decompiles come from `source`, using the six
    /// detectors' standard thresholds and name set.
    pub fn with_source(source: S) -> Self {
        ControlFlowEngine {
            source,
            switch: SwitchChainDetector::default(),
            recursion: RecursionDetector,
            state_machine: StateMachineDetector::default(),
            loops: LoopDetector::default(),
            branch_density: BranchDensityDetector::default(),
            branch_inventory: BranchInventoryDetector::default(),
            cross_function: CrossFunctionAnalyzer::new(),
        }
    }

    /// Read switch-shaped chains against `detector`'s thresholds
    /// instead of the standard ones.
    pub fn with_switch(mut self, detector: SwitchChainDetector) -> Self {
        self.switch = detector;
        self
    }

    /// Read self-recursion against `detector` instead of the standard
    /// one.
    pub fn with_recursion(mut self, detector: RecursionDetector) -> Self {
        self.recursion = detector;
        self
    }

    /// Read state machines against `detector`'s name set and threshold
    /// instead of the standard ones.
    pub fn with_state_machine(mut self, detector: StateMachineDetector) -> Self {
        self.state_machine = detector;
        self
    }

    /// Read loop structure against `detector`'s threshold instead of
    /// the standard one.
    pub fn with_loop(mut self, detector: LoopDetector) -> Self {
        self.loops = detector;
        self
    }

    /// Read branch density against `detector`'s thresholds and minimum
    /// body size instead of the standard ones.
    pub fn with_branch_density(mut self, detector: BranchDensityDetector) -> Self {
        self.branch_density = detector;
        self
    }

    /// Read the branch inventory against `detector`'s confidence floor
    /// instead of the standard one.
    pub fn with_branch_inventory(mut self, detector: BranchInventoryDetector) -> Self {
        self.branch_inventory = detector;
        self
    }

    /// Detect control-flow patterns across `binary`, decompiling each
    /// function exactly once and reading it with all six detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function, and
    /// within one function the switch chains, then the recursion, then
    /// the state machines, then the loop reading, then the branch
    /// density, then the branch inventory — and after every function the cross-function
    /// mutual-recursion cycles, in listing order of their earliest
    /// member; two scans of the same program diff cleanly.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned. But when more than half the listing
    /// fails to decompile, the skip-rate breaker aborts the run too: a
    /// high skip rate is the signature of the seam answering about the
    /// wrong program, and skipping on would persist a record that looks
    /// clean but is not (issue #71).
    /// A chain can read as both a switch and
    /// a state machine, so a function can carry findings of every kind
    /// at once and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ControlFlowResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut kept: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-5: keep track of which bodies the scan could not read —
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
                        return Err(crate::ControlFlowError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };
            let body = &decompiled.body;

            findings.extend(
                self.switch
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::Switch),
            );
            findings.extend(
                self.recursion
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::Recursion),
            );
            findings.extend(
                self.state_machine
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::StateMachine),
            );
            findings.extend(
                self.loops
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::Loop),
            );
            findings.extend(
                self.branch_density
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::BranchDensity),
            );
            findings.extend(
                self.branch_inventory
                    .detect(&function.name, body)
                    .into_iter()
                    .map(ControlFlowFinding::BranchSite),
            );
            kept.push(decompiled);
        }

        // The cross-function pass runs after the per-function pass,
        // over the kept bodies the scan already decompiled — no extra
        // reads from the analysis engine — and its mutual-recursion
        // cycles append in listing order, after the per-function
        // findings.
        findings.extend(self.cross_function.analyze(&kept));

        let mut metadata = ScanMetadata::new(binary);
        // The source names its analysis engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage inside its own scan, where
        // the truth lives — not the registry row and not the CLI (issue
        // #349): every listed body was read by all six detectors unless
        // the scan says which ones it could not reach. The batch scan
        // phase and the CLI's force-rescan file the same admission
        // through this one definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected control-flow patterns"
        );
        Ok(ControlFlowResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

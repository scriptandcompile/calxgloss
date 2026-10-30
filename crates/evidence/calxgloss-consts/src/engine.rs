//! Constant scan orchestration.
//!
//! [`ConstEngine`] runs the three detectors — bitmask group detection,
//! sequential enum candidate detection, and repeated-value frequency
//! analysis — over every function of one loaded program and
//! assembles their findings into a single [`ConstResult`] with its
//! scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the scan fetches each function's pseudo-C exactly once and reads
//! it with all three, instead of each detector pulling its own copy.
//! The frequency analyzer counts literals during that same pass, and
//! its program-level findings are appended after the per-function
//! ones. The context-naming reading (`naming`) walks the same bodies
//! in that same pass. The first qualifying name it saw across the
//! scan becomes the name on each repeated value's record. After the
//! walk, the scan's flag-family merge post-pass (`flag_family`)
//! links the scan's own bitflag groups through shared bits, and the
//! merged program-level families are appended after the named
//! constants. The known-magic reading (`protocol`) matches the full
//! literal tally — before the frequency threshold applies — against
//! a built-in table of well-known protocol/format magics and
//! sentinels, appending one named `protocol_constant` finding per
//! matched value after the families. The frequency pass skips
//! matched values, so each value lands exactly once. The
//! color-grouping reading (`color`) then groups the color-shaped
//! values the tally still holds — ≤ 24-bit, not powers of two —
//! into at most one program-level `color_constant` palette finding.
//! The data-table reading (`data_table`) last walks the analysis
//! engine's data-object listing and what the kept bodies do with
//! each object, appending one `data_table` finding per object whose
//! bytes decode uniformly at one corroborated stride and which the
//! gates leave alone — no kept body stores through its symbol, and
//! no entry resolves to a function start the listing names — kept in
//! listing order. It reads only existing seam methods
//! (`data_items`, `read_memory`, `xrefs_to`), cached under ADR-0043,
//! and writes nothing back to the program (ADR-0020).
//!
//! The scan is one sequential pass over the function listing. Like
//! sync, there is nothing to resolve between the detectors: they
//! read disjoint shapes. Keeping the pass sequential keeps the
//! persisted finding list in a stable, diffable order.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use tracing::{info, warn};

use crate::bitmask::BitmaskDetector;
use crate::color::color_palette;
use crate::error::Result;
use crate::flag_family::merge_families;
use crate::frequency::{FrequencyAnalyzer, ProgramTally};
use crate::naming::context_names;
use crate::protocol::protocol_constants;
use crate::sequential::SequentialDetector;
use crate::types::{BitflagGroup, ConstFinding, ConstResult, ScanMetadata};

/// The decompiler a constant scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here so
/// the scan's generic shape names it where it always has. [`KunaSource`]
/// implements it over the in-process analysis engine; tests implement it
/// over canned bodies so the orchestration runs without a server. The
/// futures are `Send` so a scan can be driven from an orchestrating
/// task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached names one coverage limitation line names inline
/// before the rest become a count. The prose stays bounded beside the
/// counts, not a dump, and uses the same bound floatsimd's admission
/// carries (the P19 admitted-semantics track, issues #347 and #348).
const MAX_NAMED_LIMITS: usize = 5;

/// The names one limitation line prints inline — at most
/// [`MAX_NAMED_LIMITS`] of them. The names it drops, and the `nameless`
/// entries that carry no name to print at all, become a single trailing
/// count.
fn bounded_names(names: &[String], nameless: usize) -> Vec<String> {
    let mut shown = names
        .iter()
        .take(MAX_NAMED_LIMITS)
        .cloned()
        .collect::<Vec<_>>();
    let hidden = names.len().saturating_sub(shown.len()) + nameless;
    if hidden > 0 {
        shown.push(format!("+{hidden} more"));
    }
    shown
}

/// The facet ids consts declares — the roster, written once here the
/// way the CLI pairing pin (#342) writes its roster and the way
/// apidetect (#346), floatsimd (#347) and typesdb (#348) write theirs.
/// The pin below reads every facet a freshly stamped coverage record
/// names against this list, and every drift direction is a fault: a
/// declared facet the scan stopped stamping, a facet stamped twice, and
/// an id the scan invented outside the roster all fail loudly.
pub const DECLARED_FACETS: &[&str] = &["function-bodies", "data-objects"];

/// The coverage record every consts scan stamps about itself (issue
/// #348), beside the provenance and the timing.
///
/// Two facets, one per listing the scan reads through.
///
/// `function-bodies` is the decompiled bodies the three detectors read.
/// The function listing itself is always read end to end — a failed
/// listing aborts the run, and more than half failing to decompile trips
/// the skip-rate breaker — so what a finished scan can not have read is
/// exactly the bodies it skipped along the way: a nameless listing entry,
/// or a decompile that failed. With none, the facet is `complete`, and
/// that is the admission's point: a constant the detectors did not name
/// in a body they read was examined and absent, never silently unchecked.
/// With any, the facet is `partial` and the limitation line names the
/// unreached bodies (bounded at [`MAX_NAMED_LIMITS`]) and nothing else.
///
/// `data-objects` is the memory windows the data-table reading decodes.
/// A window that failed to read, or arrived shorter than the listing
/// says, left that object unexamined; the objects the scan read and
/// claimed no table for are not a limit and name nothing. With no missing
/// window the facet is `complete`; with any it is `partial` beside the
/// objects whose windows never arrived.
///
/// The whole picture is `partial` when either facet falls short — the
/// regions the scan could not read — and `complete` when neither does,
/// with no third state: a consts scan either read both listings through
/// or says which part it could not.
fn coverage_stamp(unreached: &[String], nameless: usize, unreadable: &[String]) -> ScanCoverage {
    let mut facets = Vec::new();
    let bodies_total = unreached.len() + nameless;
    if bodies_total == 0 {
        facets.push(FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        });
    } else {
        // The names the scan can print. The names it drops, and the
        // nameless entries that carry no name at all, become one
        // trailing count.
        let shown = bounded_names(unreached, nameless);
        let body = if bodies_total == 1 { "body" } else { "bodies" };
        facets.push(FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{bodies_total} function {body} unreached: {}",
                shown.join(", ")
            )),
        });
    }
    if unreadable.is_empty() {
        facets.push(FacetCoverage {
            id: "data-objects".to_string(),
            status: CoverageStatus::Complete,
            limitation: None,
        });
    } else {
        let window = if unreadable.len() == 1 {
            "window"
        } else {
            "windows"
        };
        facets.push(FacetCoverage {
            id: "data-objects".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{} data-object memory {window} unreadable: {}",
                unreadable.len(),
                bounded_names(unreadable, 0).join(", ")
            )),
        });
    }
    let fell_short = facets
        .iter()
        .any(|facet| facet.status != CoverageStatus::Complete);
    ScanCoverage {
        status: if fell_short {
            CoverageStatus::Partial
        } else {
            CoverageStatus::Complete
        },
        facets,
    }
}

/// Orchestrates the three detectors into one [`ConstResult`].
///
/// It is generic over its [`ScanSource`], so tests can run the whole
/// orchestration over canned bodies; [`new`](Self::new) builds one over
/// a loaded [`KunaSource`]. Each detector carries no state and starts
/// configured with its standard thresholds —
/// [`with_bitmask`](Self::with_bitmask), [`with_sequential`](Self::with_sequential),
/// and [`with_frequency`](Self::with_frequency) swap a detector's
/// thresholds whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ConstEngine<S = KunaSource> {
    source: S,
    bitmask: BitmaskDetector,
    sequential: SequentialDetector,
    frequency: FrequencyAnalyzer,
}

impl ConstEngine<KunaSource> {
    /// A scan over a loaded Kuna program, using the three detectors'
    /// standard thresholds.
    pub fn new(source: &KunaSource) -> ConstEngine<KunaSource> {
        ConstEngine {
            source: source.clone(),
            bitmask: BitmaskDetector::with_default_threshold(),
            sequential: SequentialDetector::with_default_threshold(),
            frequency: FrequencyAnalyzer::with_default_thresholds(),
        }
    }
}

impl<S> ConstEngine<S> {
    /// A scan whose decompiles come from `source`, using the three
    /// detectors' standard thresholds.
    pub fn with_source(source: S) -> Self {
        ConstEngine {
            source,
            bitmask: BitmaskDetector::with_default_threshold(),
            sequential: SequentialDetector::with_default_threshold(),
            frequency: FrequencyAnalyzer::with_default_thresholds(),
        }
    }

    /// Read flag groups against `detector`'s threshold instead of the
    /// standard one.
    pub fn with_bitmask(mut self, detector: BitmaskDetector) -> Self {
        self.bitmask = detector;
        self
    }

    /// Read enum candidates against `detector`'s threshold instead of
    /// the standard one.
    pub fn with_sequential(mut self, detector: SequentialDetector) -> Self {
        self.sequential = detector;
        self
    }

    /// Count repeated values against `detector`'s thresholds instead
    /// of the standard ones.
    pub fn with_frequency(mut self, detector: FrequencyAnalyzer) -> Self {
        self.frequency = detector;
        self
    }

    /// Detect constant structures across `binary`, decompiling each
    /// function exactly once and reading it with all three detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// per-function findings follow the function listing — function by
    /// function, bitmask group then enum candidates. The program-level
    /// findings are appended after them, in this order: the named
    /// constants the frequency analyzer tallied across the pass, each
    /// carrying the context name of the first qualifying assignment or
    /// comparison the bodies made of its value; the flag families the
    /// scan's own bitflag groups merged into — groups sharing at least
    /// one bit, transitively; the protocol constants the known-magic
    /// reading matched against the full tally before the frequency
    /// threshold applied; and the one color palette the color-grouping
    /// reading grouped from the remaining color-shaped values. Each
    /// list is internally sorted, so two scans of the same program diff
    /// cleanly and name their constants identically. A value the
    /// protocol table matches lands only as its protocol finding: the
    /// frequency pass and the color reading skip matched values. The
    /// data-table reading then appends one `data_table` finding per
    /// object the data listing defines that the kept bodies index and
    /// whose bytes decode uniformly at one corroborated stride — an
    /// object a kept body stores through, or whose entries resolve to
    /// the function starts the listing names, claims nothing — kept in
    /// data-listing order.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned. But when more than half the listing
    /// fails to decompile, the skip-rate breaker aborts the run too: a
    /// high skip rate is the signature of the seam answering about the
    /// wrong program, and skipping on would persist a record that looks
    /// clean but is not (issue #71). The three detectors read disjoint
    /// shapes, so a function can carry findings of every kind at once
    /// and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ConstResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;
        // The data objects the data listing defines, read up front like
        // the function listing: a failing data listing fails the run
        // the same way.
        let data_objects = self.source.data_items().await?;

        let mut findings = Vec::new();
        let mut tally = ProgramTally::new();
        // The groups the walk built, kept only long enough for the
        // scan's flag-family merge post-pass to link them through
        // shared bits — the merge needs the detector's final contents,
        // not the bodies.
        let mut groups: Vec<BitflagGroup> = Vec::new();
        // The addresses the function listing names, as the data-table
        // reading's pointer gate resolves table entries against them:
        // an entry equal to a listed start is a pointer to a function,
        // the callback crate's jump-table territory, not a scalar.
        let function_starts: BTreeSet<u64> =
            functions.iter().map(|function| function.address).collect();
        // What the kept bodies do with each data object, recorded
        // parallel to the data listing: the indexed reads a table claim
        // rests on, and whether anything stores through the symbol.
        // Collected without keeping the bodies themselves.
        let mut table_usage: Vec<crate::data_table::ObjectUsage> =
            data_objects.iter().map(|_| Default::default()).collect();
        // The context names the bodies gave the literals as the tally
        // filled: first qualifying sighting per value wins, so naming
        // follows listing order and two scans name identically.
        let mut names: BTreeMap<u64, String> = BTreeMap::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // What the walk could not read, kept by name so the coverage
        // record can say so beside the counts (issue #348): the listing
        // entries whose decompile failed, and the nameless entries with
        // no name to print.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // into some other function's body; nothing can be said
                // about it, so it passes unrecorded.
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
                    // Skip-rate breaker: once more than half the
                    // listing has failed to decompile, the seam is
                    // answering about the wrong program, and an empty
                    // result would persist as a record that looks
                    // clean but is not. Abort with the counts instead
                    // of skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::ConstError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            if let Some(group) = self.bitmask.detect(&function.name, &decompiled.body) {
                groups.push(group.clone());
                findings.push(ConstFinding::BitflagGroup(group));
            }
            findings.extend(
                self.sequential
                    .detect(&function.name, &decompiled.body)
                    .into_iter()
                    .map(ConstFinding::EnumCandidate),
            );
            for value in self.frequency.literals(&decompiled.body) {
                let entry = tally.entry(value).or_default();
                entry.count += 1;
                entry.functions.insert(function.name.clone());
            }
            for (value, name) in context_names(&decompiled.body) {
                names.entry(value).or_insert(name);
            }
            for (item, usage) in data_objects.iter().zip(table_usage.iter_mut()) {
                for line in decompiled.body.lines() {
                    if crate::data_table::stores_through(line, &item.label) {
                        // The mutation gate: some kept body stores
                        // through the symbol, so the object is mutable
                        // global state — the global-state track's
                        // territory — and claims no table. The reads
                        // it also carries would only be evidence for a
                        // claim the gate refuses anyway.
                        usage.written = true;
                    } else if let Some(read) =
                        crate::data_table::indexed_read(&decompiled, &item.label, line, item.length)
                    {
                        usage.reads.push(read);
                    }
                }
            }
        }

        // The protocol reading runs over the full tally before the
        // frequency threshold applies, so a recognised magic seen once
        // still reports. A matched value lands exactly once: its
        // protocol claim is strictly stronger than the frequency-only
        // named-constant reading and carries the same usage data, so
        // the frequency pass is handed the tally with matched values
        // removed and never reports them again.
        let protocol = protocol_constants(&tally);
        let matched: std::collections::BTreeSet<u64> =
            protocol.iter().map(|record| record.value).collect();
        let frequency_tally: ProgramTally = tally
            .into_iter()
            .filter(|(value, _)| !matched.contains(value))
            .collect();

        findings.extend(
            self.frequency
                .constants(&frequency_tally, &names)
                .into_iter()
                .map(ConstFinding::NamedConstant),
        );
        findings.extend(
            merge_families(&groups)
                .into_iter()
                .map(ConstFinding::FlagFamily),
        );
        findings.extend(protocol.into_iter().map(ConstFinding::ProtocolConstant));
        // The color reading groups the color-shaped values the tally
        // still holds: a protocol-matched value already carries its
        // strictly stronger claim, so it never joins a palette. The
        // palette lands after the protocol findings, before the
        // data-table findings.
        findings.extend(color_palette(&frequency_tally).map(ConstFinding::ColorConstant));
        // The data-table reading (#278's tracer, #279's gates, #280's
        // stride viability and bands): objects the data listing
        // defines, indexed by the kept bodies and decoded coherently
        // at a viable stride, land as program-level table findings
        // after the palette, kept in listing order — an object any
        // kept body stored through, or whose entries resolve to the
        // function starts the listing names, claims nothing. Several
        // viable strides resolve through the analysis engine's applied
        // listing type or an indexed read's guard width, and the band
        // follows the evidence: 90 applied type, 70 decode plus
        // indexed read, 50 Xrefs-only, 30 bytes-only. The objects
        // whose memory window never arrived come back beside the
        // tables so the coverage record can name them (issue #348).
        let (tables, unreadable_windows) = crate::data_table::data_tables(
            &self.source,
            &data_objects,
            &table_usage,
            &function_starts,
        )
        .await;
        findings.extend(tables.into_iter().map(ConstFinding::DataTable));
        let mut metadata = ScanMetadata::new(binary);
        // The source names its analysis engine and pin under `kuna`
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The scan admits its own coverage where the truth lives,
        // beside the provenance and the timing (issue #348).
        metadata.coverage = Some(coverage_stamp(&unreached, nameless, &unreadable_windows));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected constant structures"
        );
        Ok(ConstResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

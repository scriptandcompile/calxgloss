//! Serialization scan orchestration.
//!
//! [`SerializeEngine`] runs the serialization detectors over every
//! function of one loaded program and assembles their findings into a
//! single [`SerializeResult`] with its scan provenance. The detectors
//! are: byte-swap call matching, bit-pack shape reading, magic-byte
//! comparison matching, cross-field validation reading, the format
//! combiner's composition of the swap and pack readings, and the
//! protocol combiner's promotion of a corroborated protocol sniff.
//!
//! The format and protocol-message findings come last within each
//! function's findings. They read the records the pass already made,
//! so they cost no extra body pass and no extra decompiler round
//! trips. The endianness profile is the one binary-level finding. The
//! profiler aggregates the whole scan's byte-swap findings by width
//! after the loop, so the map appends after every per-function finding.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the scan fetches each function's pseudo-C exactly once and reads
//! it with all of them, instead of each detector pulling its own
//! copy. The scan is one sequential pass over the function listing.
//! There is nothing to resolve between the detectors — they read
//! disjoint body shapes — and keeping the pass sequential keeps the
//! persisted finding list in a stable, diffable order. The one gate
//! between detectors is honesty, not ranking: the validation reading
//! sees the magic findings already made for the same body, so a
//! signature comparison never lands twice — once as magic and once as
//! a validation check.

use crate::bitpack::BitPackDetector;
use crate::byteswap::ByteSwapDetector;
use crate::endianness::EndiannessProfiler;
use crate::error::Result;
use crate::format::FormatCombiner;
use crate::magic_bytes::MagicByteDetector;
use crate::protocol::ProtocolMessageCombiner;
use crate::types::{ScanMetadata, SerializeFinding, SerializeResult};
use crate::validation::ValidationDetector;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a serialization scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so this crate's serialization scan names it directly;
/// [`KunaSource`] implements it over the analysis engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names
/// before the rest becomes a count. The line stays bounded prose
/// beside the counts, not a dump (the P19-7 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a serialization scan declares, in order. Every record
/// names each of them exactly once. The serialization scan reads one
/// facet: the decompiled bodies every detector reads.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every serialization scan stamps about itself
/// (issue #351), beside the provenance and the timing.
///
/// The serialization scan has one facet: `function-bodies`, the
/// decompiled bodies every detector reads. The function listing is
/// always read end to end. A failed listing aborts the run, and more
/// than half failing to decompile trips the skip-rate breaker in the
/// scan below. So what a finished scan cannot have read is exactly the
/// bodies it skipped along the way: a nameless listing entry, or a
/// decompile that failed. The endianness profile aggregates the
/// byte-swap findings the body pass already made, so it adds no
/// coverage border of its own.
///
/// With nothing skipped, the facet is `complete`, and that is the
/// admission's point: a function no finding mentions was examined and
/// clean, never silently unchecked. With any skips, the facet is
/// `partial` and the limitation line names the unreached bodies
/// (bounded at [`MAX_NAMED_UNREACHED`]), so silence and never-reaching
/// are distinguishable in the filed record itself. The whole picture
/// mirrors the single facet — there is nothing else this scan
/// examines.
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

/// Orchestrates the serialization detectors into one [`SerializeResult`].
///
/// The scan is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a loaded [`KunaSource`]. Each detector holds no state and
/// starts configured with its standard name sets —
/// [`with_byteswap`](Self::with_byteswap) swaps a detector whole — so
/// one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct SerializeEngine<S = KunaSource> {
    source: S,
    byteswap: ByteSwapDetector,
    bitpack: BitPackDetector,
    magic: MagicByteDetector,
    validation: ValidationDetector,
    format: FormatCombiner,
    protocol: ProtocolMessageCombiner,
    endianness: EndiannessProfiler,
}

impl SerializeEngine<KunaSource> {
    /// A serialization scan over a loaded Kuna program, using the
    /// detectors' standard name sets.
    pub fn new(source: &KunaSource) -> SerializeEngine<KunaSource> {
        Self::with_source(source.clone())
    }
}

impl<S> SerializeEngine<S> {
    /// A serialization scan whose decompiles come from `source`, using
    /// the detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        SerializeEngine {
            source,
            byteswap: ByteSwapDetector::with_default_names(),
            bitpack: BitPackDetector::new(),
            magic: MagicByteDetector::with_default_signatures(),
            validation: ValidationDetector::new(),
            format: FormatCombiner::new(),
            protocol: ProtocolMessageCombiner::new(),
            endianness: EndiannessProfiler::new(),
        }
    }

    /// Read byte-swap calls against `detector`'s name set instead of
    /// the standard one.
    pub fn with_byteswap(mut self, detector: ByteSwapDetector) -> Self {
        self.byteswap = detector;
        self
    }

    /// Read bit-packing chains against `detector` instead of the
    /// standard shape reading.
    pub fn with_bitpack(mut self, detector: BitPackDetector) -> Self {
        self.bitpack = detector;
        self
    }

    /// Read format-signature comparisons against `detector`'s
    /// signature table instead of the standard one.
    pub fn with_magic(mut self, detector: MagicByteDetector) -> Self {
        self.magic = detector;
        self
    }

    /// Read message-integrity comparisons against `detector` instead
    /// of the standard shape reading.
    pub fn with_validation(mut self, detector: ValidationDetector) -> Self {
        self.validation = detector;
        self
    }

    /// Detect serialization patterns across `binary`, decompiling each
    /// function exactly once and reading it with every detector.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing: function by function.
    /// Within one function the order is byte swaps, then bit packs,
    /// then magic-byte comparisons, then the cross-field validation
    /// checks, then the composed format layout, then the
    /// protocol-message identification. The binary-level endianness
    /// map appends after every per-function finding. Two scans of the
    /// same program therefore diff cleanly.
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
    /// The detectors read disjoint body shapes, so one function can
    /// have findings of every kind at once and nothing is resolved
    /// between them. The one exception: the validation reading stays
    /// silent about the comparisons the magic reading already reported
    /// for the same body.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<SerializeResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // The function bodies this walk never reached, named as the
        // scan goes, so the coverage record below can admit them
        // (issue #351).
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the by-name lookup
                // into some other function's body; nothing can be said
                // about it, so the entry is skipped with no finding.
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
                        return Err(crate::SerializeError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            let swap_records = self.byteswap.detect(&decompiled);
            let pack_records = self.bitpack.detect(&decompiled);
            let magic_records = self.magic.detect(&decompiled);
            // The validation reading sees exactly the comparisons the
            // magic reading reported for this body, so a signature
            // check lands once — as magic — and claims no validation
            // finding on top.
            let validation_records = self.validation.detect(&decompiled, &magic_records);
            // The format stage composes the swap and pack readings just
            // made into one end-to-end layout when the function has two
            // or more of them (P11.5-2). It reads only those records, so
            // it costs no extra body pass.
            let format_record = self
                .format
                .combine(&decompiled, &swap_records, &pack_records);
            // The protocol stage promotes the function to one message
            // handler when a protocol-table magic hit is corroborated
            // by a network-order swap or a cross-field validation
            // (P11.5-3). It reads only the records the pass already
            // made and the configured table's protocol flags, so it
            // too costs no extra body pass.
            let protocol_record = self.protocol.identify(
                self.magic.signatures(),
                &magic_records,
                &swap_records,
                &validation_records,
            );
            findings.extend(swap_records.into_iter().map(SerializeFinding::ByteSwap));
            findings.extend(pack_records.into_iter().map(SerializeFinding::BitPack));
            findings.extend(magic_records.into_iter().map(SerializeFinding::Magic));
            findings.extend(
                validation_records
                    .into_iter()
                    .map(SerializeFinding::CrossFieldValidation),
            );
            findings.extend(format_record.map(SerializeFinding::SerializationFormat));
            findings.extend(protocol_record.map(SerializeFinding::ProtocolMessage));
        }

        // The endianness profile is the one binary-level finding. It
        // aggregates the whole scan's byte-swap findings by width, so
        // it can only be made after the loop. It appends after every
        // per-function finding (P11.5-4).
        if let Some(record) = self.endianness.profile(&findings) {
            findings.push(SerializeFinding::EndiannessMap(record));
        }

        let mut metadata = ScanMetadata::new(binary);
        // The scan admits its own coverage, where the skips happened,
        // so the filed record says what the walk never read (issue
        // #351). A complete record lets a function no finding mentions
        // read as examined and clean.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
        // The source names the analysis engine and its pin under `kuna`
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Detected serialization patterns"
        );
        Ok(SerializeResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

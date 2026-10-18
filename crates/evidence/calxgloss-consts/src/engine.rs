//! Constant scan orchestration.
//!
//! [`ConstEngine`] runs the three detectors — bitmask group detection,
//! sequential enum candidate detection, and repeated-value frequency
//! analysis — over every function of one open Ghidra program and
//! assembles their findings into a single [`ConstResult`] with its
//! scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with all three, rather than having each detector pull its own
//! copy. The frequency analyzer counts literals during that same
//! pass, and its program-level findings are appended after the
//! per-function ones. The context-naming reading (`naming`)
//! walks the same bodies in that same pass, and the first qualifying
//! name it saw across the scan rides each repeated value's record.
//! After the walk, the flag-family merge (`flag_family`) ties the
//! scan's own bitflag groups through shared bits and appends the
//! merged program-level families after the named constants, and the
//! known-magic reading (`protocol`) matches the full literal tally —
//! before the frequency threshold applies — against a built-in table
//! of well-known protocol/format magics and sentinels, appending one
//! named `protocol_constant` finding per matched value after the
//! families; the frequency pass skips matched values so each lands
//! exactly once. The color-grouping reading (`color`) then groups
//! the color-shaped values the tally still holds — ≤ 24-bit, not
//! powers of two — into at most one program-level `color_constant`
//! palette finding, appended last. No bodies kept, no new reads. The
//! scan is one sequential pass over the function listing — like
//! sync, there is nothing to resolve between the detectors, they
//! read disjoint shapes — and keeping the pass sequential keeps the
//! persisted finding list in a stable, diffable order.

use std::collections::BTreeMap;
use std::time::Instant;

use calxgloss_ghidra::GhidraClient;
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
/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// Orchestrates the three detectors into one [`ConstResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a live [`GhidraClient`]. Each detector carries no state
/// and starts configured with its standard thresholds —
/// [`with_bitmask`](Self::with_bitmask), [`with_sequential`](Self::with_sequential),
/// and [`with_frequency`](Self::with_frequency) swap a detector's
/// thresholds whole — so one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct ConstEngine<S = GhidraClient> {
    source: S,
    bitmask: BitmaskDetector,
    sequential: SequentialDetector,
    frequency: FrequencyAnalyzer,
}

impl ConstEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the three
    /// detectors' standard thresholds.
    pub fn new(client: &GhidraClient) -> ConstEngine<GhidraClient> {
        ConstEngine {
            source: client.clone(),
            bitmask: BitmaskDetector::with_default_threshold(),
            sequential: SequentialDetector::with_default_threshold(),
            frequency: FrequencyAnalyzer::with_default_thresholds(),
        }
    }
}

impl<S> ConstEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the three detectors' standard thresholds.
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
    /// function, bitmask group then enum candidates — and the
    /// program-level findings are appended after them: first the
    /// named constants the frequency analyzer tallied across the pass,
    /// each carrying the context name of the first qualifying
    /// assignment or comparison the bodies made of its value, then
    /// the flag families the scan's own bitflag groups merged into —
    /// groups sharing at least one bit, transitively — then the
    /// protocol constants the known-magic reading matched against the
    /// full tally before the frequency threshold applied, then the
    /// one color palette the color-grouping reading grouped from the
    /// remaining color-shaped values, each internally sorted, so two
    /// scans of the same program diff cleanly and name their
    /// constants identically. A value the protocol table matches
    /// lands only as its protocol finding: the frequency pass skips
    /// matched values, and so does the color reading.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// The three detectors read disjoint
    /// shapes, so a function can carry findings of every kind at once
    /// and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ConstResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut tally = ProgramTally::new();
        // The groups the walk built, kept only long enough for the
        // flag-family merge to tie them through shared bits — the
        // merge needs the detector's final contents, not the bodies.
        let mut groups: Vec<BitflagGroup> = Vec::new();
        // The context names the bodies gave the literals as the tally
        // filled: first qualifying sighting per value wins, so naming
        // follows listing order and two scans name identically.
        let mut names: BTreeMap<u64, String> = BTreeMap::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing
                // can be said about it, so it passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
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
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading the
                    // wrong program (or a half-broken server), and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
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
        }

        // The protocol reading runs over the full tally before the
        // frequency threshold applies, so a recognised magic seen once
        // still reports. A matched value lands exactly once: the
        // protocol claim is strictly stronger than the frequency-only
        // named-constant reading and carries the same usage data, so
        // the frequency pass is handed the tally with matched values
        // removed and never also reports them.
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
        // strictly stronger claim, so it never joins a palette, and
        // the palette lands last among the program-level findings.
        findings.extend(color_palette(&frequency_tally).map(ConstFinding::ColorConstant));
        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna`; the Ghidra
        // path names nothing and the record stays exactly as it was
        // (issue #208).
        metadata.engine = self.source.engine_provenance();
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
mod tests {
    use super::*;
    use crate::bitmask::BitmaskDetector;
    use crate::sequential::SequentialDetector;
    use crate::types::Confidence;
    use calxgloss_ghidra::{
        DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn summary(name: &str) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address: 0x1800_3ab00,
        }
    }

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    /// State shared by every clone of a [`FakeProgram`], so a test can
    /// read what the scan did after the engine has consumed its
    /// source.
    #[derive(Debug, Default)]
    struct Stats {
        decompiles: Mutex<Vec<String>>,
    }

    /// A canned program implementing [`ScanSource`], so the whole
    /// orchestration runs without a server.
    #[derive(Clone)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        fail_decompiles: Vec<String>,
        fail_listing: bool,
        stats: Arc<Stats>,
    }

    impl FakeProgram {
        fn empty() -> Self {
            Self {
                listing: Vec::new(),
                bodies: HashMap::new(),
                fail_decompiles: Vec::new(),
                fail_listing: false,
                stats: Arc::new(Stats::default()),
            }
        }

        fn decompiled(&self) -> Vec<String> {
            self.stats.decompiles.lock().unwrap().clone()
        }
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(GhidraError::Reported {
                    status: Some(200),
                    message: "Ghidra is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        // The rest of the shared trait's reads: this engine never makes
        // them, so they answer with empty or not-found data.
        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, _address: u64) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn xrefs_to(&self, _address: u64) -> Result<Vec<Xref>> {
            Ok(Vec::new())
        }

        async fn data_types(&self, _category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
            Err(GhidraError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(GhidraError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn exports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> Result<u64> {
            Ok(0)
        }

        async fn read_memory(&self, _address: u64, _length: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        // Story 9 (#203): the fake source names itself, so the tests can pin
        // that scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
        }
    }

    /// A body carrying a flag-bit pair, a four-case switch run, and a
    /// repeated magic number — one finding family per detector — all
    /// in one function.
    const EVERY_SHAPE_BODY: &str = "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n  switch(local_10) {\n  case 0:\n  case 1:\n  case 2:\n  case 3:\n    dispatch();\n  }\n  size = 0x280;\n  copy(dst, 0x280);\n";

    /// The canned program: one function whose body carries every
    /// shape, and one plain function that repeats the magic number so
    /// the frequency analyzer sees it across two functions.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                EVERY_SHAPE_BODY,
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  reserve(0x280);\n  return;\n",
            ),
        );
        program
    }

    async fn scan(program: FakeProgram) -> ConstResult {
        ConstEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn kinds(result: &ConstResult, function: &str) -> Vec<&'static str> {
        result
            .for_function(function)
            .map(|finding| finding.kind())
            .collect()
    }

    /// The scan's one program-level named constant, whichever value it
    /// carries.
    fn named_constant(result: &ConstResult) -> &crate::types::NamedConstant {
        result
            .findings
            .iter()
            .find_map(|finding| match finding {
                ConstFinding::NamedConstant(record) => Some(record),
                _ => None,
            })
            .expect("the scan should have reported the repeated literal")
    }

    /// The scan's one program-level flag family, whichever bits it
    /// carries.
    fn flag_family(result: &ConstResult) -> &crate::types::FlagFamily {
        result
            .findings
            .iter()
            .find_map(|finding| match finding {
                ConstFinding::FlagFamily(record) => Some(record),
                _ => None,
            })
            .expect("the scan should have merged the shared-bit groups")
    }

    /// The scan's program-level protocol constants, whichever values
    /// they carry. Named apart from the crate's `protocol_constants`
    /// matcher so the test module's glob import cannot shadow it.
    fn protocol_findings(result: &ConstResult) -> Vec<&crate::types::ProtocolConstant> {
        result
            .findings
            .iter()
            .filter_map(|finding| match finding {
                ConstFinding::ProtocolConstant(record) => Some(record),
                _ => None,
            })
            .collect()
    }

    /// The scan's palette findings — at most one per binary. Named
    /// apart from the crate's `color_palette` matcher so the test
    /// module's glob import cannot shadow it.
    fn color_findings(result: &ConstResult) -> Vec<&crate::types::ColorConstant> {
        result
            .findings
            .iter()
            .filter_map(|finding| match finding {
                ConstFinding::ColorConstant(record) => Some(record),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_named_assignment_in_the_bodies_names_the_repeated_constant() {
        // The canned program spells `size = 0x280;` in one function and
        // repeats the value in another: the named constant carries the
        // context name, and its suggestion — the string the report and
        // the escalate prompt render — carries it too.
        let result = scan(program()).await;

        let constant = named_constant(&result);
        assert_eq!(constant.value, 0x280);
        assert_eq!(constant.name.as_deref(), Some("SIZE_0x280"));
        assert_eq!(constant.suggestion, "const SIZE_0x280: u32 = 0x280;");
    }

    #[tokio::test]
    async fn placeholder_assignments_leave_the_constant_mechanically_named() {
        // Every sighting of the repeated value sits beside a
        // decompiler-minted name — a stack slot, an undefined variable,
        // a bare letter plus digits — so nothing names it and the
        // mechanical suggestion stands.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  local_10 = 0x280;\n  uVar1 = 0x280;\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  x1 = 0x280;\n  return;\n",
            ),
        );
        let result = scan(program).await;

        let constant = named_constant(&result);
        assert_eq!(constant.count, 3, "the value still qualifies");
        assert_eq!(constant.name, None);
        assert_eq!(constant.suggestion, "const VALUE_0x280: u32 = 0x280;");
    }

    #[tokio::test]
    async fn the_first_named_sighting_across_the_scan_names_the_constant() {
        // Two functions name the same value differently; the sighting
        // earlier in the listing wins, and swapping the listing order
        // swaps the name — deterministic either way.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  count = 0x280;\n  copy(dst, 0x280);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  size = 0x280;\n  return;\n",
            ),
        );
        let result = scan(program.clone()).await;
        assert_eq!(
            named_constant(&result).name.as_deref(),
            Some("COUNT_0x280"),
            "the first function in listing order wins"
        );

        program.listing.reverse();
        let result = scan(program).await;
        assert_eq!(
            named_constant(&result).name.as_deref(),
            Some("SIZE_0x280"),
            "the scan names from whichever function comes first"
        );
    }

    #[tokio::test]
    async fn a_composite_mask_beside_its_independently_seen_bits_completes_the_group() {
        // A fake-program body combining 0x700 in a bitwise context
        // beside bits 8, 9, and 10 each seen singly: the scan's group
        // comes back complete — widened mask, widened width, the
        // composite line in the evidence.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n  local_10 = 0x200;\n  uVar1 &= 0x700;\n",
            ),
        );
        let result = scan(program).await;

        let group = result
            .findings
            .iter()
            .find_map(|finding| match finding {
                ConstFinding::BitflagGroup(record) => Some(record),
                _ => None,
            })
            .expect("the scan should have reported the completed flag group");
        assert_eq!(group.bits, vec![8, 9, 10]);
        assert_eq!(group.mask, 0x700);
        assert_eq!(group.bit_width, 11);
        assert!(group.evidence.contains("uVar1 &= 0x700"));
    }

    #[tokio::test]
    async fn two_functions_sharing_a_flag_bit_yield_one_program_level_family() {
        // The same flag surface read through two bodies — FUN_a
        // carries bits 8 and 10, FUN_b bits 10 and 11: the scan keeps
        // both per-function groups beside exactly one family record
        // carrying the union of bits, the contributors ascending, and
        // a confidence above the per-function tier.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  uVar2 &= 0x400;\n  uVar2 |= 0x800;\n",
            ),
        );
        let result = scan(program).await;

        let groups: Vec<&crate::types::BitflagGroup> = result
            .findings
            .iter()
            .filter_map(|finding| match finding {
                ConstFinding::BitflagGroup(record) => Some(record),
                _ => None,
            })
            .collect();
        assert_eq!(groups.len(), 2, "the per-function groups stay beside");

        let family = flag_family(&result);
        assert_eq!(family.bits, vec![8, 10, 11]);
        assert_eq!(family.mask, 0xd00);
        assert_eq!(family.bit_width, 12);
        assert_eq!(
            family.functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
        assert_eq!(
            family.suggestion,
            "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }"
        );
        assert_eq!(
            family.evidence,
            "FUN_18003ab00: bits 0x100, 0x400; FUN_18003e750: bits 0x400, 0x800"
        );
        assert_eq!(family.confidence, Confidence::new(80));
        assert!(
            family.confidence.value() > groups[0].confidence.value(),
            "corroboration across functions reads stronger than one body"
        );

        // The family answers the per-function lookup of each
        // contributor, beside that function's own group.
        assert_eq!(
            kinds(&result, "FUN_18003ab00"),
            ["bitflag_group", "flag_family"]
        );
        assert_eq!(
            kinds(&result, "FUN_18003e750"),
            ["bitflag_group", "flag_family"]
        );
    }

    #[tokio::test]
    async fn groups_sharing_no_bit_merge_into_no_family() {
        // Two functions reading unrelated flag types — bits 8 and 10
        // against bits 20 and 21 — keep their per-function records
        // alone: nothing merged, so nothing joins at the program
        // level, and the lone groups claim no family of their own.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  if ((uVar2 & 0x100000) != 0) {\n    uVar2 |= 0x200000;\n  }\n",
            ),
        );
        let result = scan(program).await;

        let families = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "flag_family")
            .count();
        assert_eq!(families, 0, "disjoint groups stay separate records");
        assert_eq!(kinds(&result, "FUN_18003ab00"), ["bitflag_group"]);
        assert_eq!(kinds(&result, "FUN_18003e750"), ["bitflag_group"]);
    }

    #[tokio::test]
    async fn a_single_use_table_magic_yields_a_protocol_constant_finding() {
        // A fake-program body carrying a PNG magic in a comparison,
        // seen exactly once in one function — far below the repetition
        // threshold: the protocol reading matches it off the full
        // tally anyway, naming the const after the table entry and
        // naming the protocol, and the finding answers the using
        // function's per-function lookup.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if (signature == 0x89504e47) {\n    parse();\n  }\n",
            ),
        );
        let result = scan(program).await;

        let records = protocol_findings(&result);
        assert_eq!(records.len(), 1, "the single-use magic still reports");
        let record = records[0];
        assert_eq!(record.value, 0x89504e47);
        assert_eq!(record.name, "PNG_MAGIC");
        assert_eq!(record.protocol, "PNG image format");
        assert_eq!(record.count, 1);
        assert_eq!(record.functions, vec!["FUN_18003ab00".to_string()]);
        assert_eq!(record.suggestion, "const PNG_MAGIC: u32 = 0x89504e47;");
        assert_eq!(record.confidence, Confidence::new(75));
        assert!(
            record
                .evidence
                .contains("0x89504e47 used 1 times in FUN_18003ab00")
        );
        assert!(record.evidence.contains("PNG_MAGIC (PNG image format)"));

        // The protocol claim replaces the frequency reading: the value
        // never clears the repetition bar, so it is not also a named
        // constant, and the protocol finding answers the lookup.
        assert!(
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == "named_constant")
                .count()
                == 0
        );
        assert_eq!(kinds(&result, "FUN_18003ab00"), ["protocol_constant"]);
    }

    #[tokio::test]
    async fn a_table_value_that_clears_the_frequency_threshold_lands_once() {
        // A table value repeated enough to clear the frequency bar too
        // — 0xdeadbeef three times across two functions: it appears
        // once, as the protocol finding, never also as a named
        // constant, and the protocol record carries the full usage
        // data the frequency pass would have.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  marker = 0xdeadbeef;\n  fill(dst, 0xdeadbeef);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  check(0xdeadbeef);\n  return;\n",
            ),
        );
        let result = scan(program).await;

        let records = protocol_findings(&result);
        assert_eq!(records.len(), 1, "one finding per matched value");
        let record = records[0];
        assert_eq!(record.value, 0xdeadbeef);
        assert_eq!(record.name, "DEAD_BEEF_MARKER");
        assert_eq!(record.count, 3);
        assert_eq!(
            record.functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );

        let named = result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "named_constant")
            .count();
        assert_eq!(
            named, 0,
            "the protocol claim is the only record for the value"
        );
        assert_eq!(kinds(&result, "FUN_18003e750"), ["protocol_constant"]);
    }

    #[tokio::test]
    async fn values_outside_the_table_stay_ordinary_named_constants() {
        // A repeated literal the table does not name keeps the
        // frequency reading's mechanical suggestion: the protocol
        // claim never dresses an unknown value up as known.
        let result = scan(program()).await;

        assert!(
            protocol_findings(&result).is_empty(),
            "the canned program carries no table magic"
        );
        let constant = named_constant(&result);
        assert_eq!(constant.value, 0x280);
        assert_eq!(constant.suggestion, "const SIZE_0x280: u32 = 0x280;");
    }

    #[tokio::test]
    async fn two_palette_literals_across_two_functions_yield_one_color_finding() {
        // FUN_a carries 0x123456 and FUN_b carries 0xff00ff, each in
        // a call argument, each seen once — far below the repetition
        // bar: the color reading groups the two color-shaped values
        // off the tally into exactly one program-level palette
        // naming both values and both functions, and the finding
        // answers each using function's per-function lookup.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  fill(dst, 0x123456);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  fill(dst, 0xff00ff);\n",
            ),
        );
        let result = scan(program).await;

        let records = color_findings(&result);
        assert_eq!(records.len(), 1, "one palette finding per binary");
        let record = records[0];
        assert_eq!(record.values, vec![0x123456, 0xff00ff]);
        assert_eq!(
            record.functions,
            vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
        );
        assert_eq!(
            record.suggestion,
            "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = 0xff00ff;"
        );
        assert_eq!(record.confidence, Confidence::new(60));
        assert!(
            record
                .evidence
                .contains("0x123456 used 1 times in FUN_18003ab00")
        );
        assert!(
            record
                .evidence
                .contains("0xff00ff used 1 times in FUN_18003e750")
        );

        // The palette answers the per-function lookup of every
        // function that uses one of its colors.
        assert_eq!(kinds(&result, "FUN_18003ab00"), ["color_constant"]);
        assert_eq!(kinds(&result, "FUN_18003e750"), ["color_constant"]);
    }

    #[tokio::test]
    async fn a_table_magic_that_is_color_shape_claims_no_palette() {
        // 0xc0ffee is both a table sentinel and 24-bit-shaped: the
        // protocol claim is strictly stronger, so the matched value
        // never joins a palette — and one remaining color-shaped
        // value alone is below the floor, so no palette forms.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if (marker == 0xc0ffee) {\n    log();\n  }\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  fill(dst, 0x123456);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(protocol_findings(&result).len(), 1, "the magic reports");
        assert!(
            color_findings(&result).is_empty(),
            "the matched magic never reads as a color, and the lone \
             remaining value claims nothing"
        );
    }

    #[tokio::test]
    async fn scan_collects_findings_from_all_three_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&ConstFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 4);

        let ConstFinding::BitflagGroup(group) = findings[0] else {
            unreachable!("the flag bits read as a bitflag finding");
        };
        assert_eq!(group.bits, vec![8, 10]);
        assert_eq!(group.mask, 0x500);
        assert_eq!(group.confidence, Confidence::new(70));

        let ConstFinding::EnumCandidate(candidate) = findings[1] else {
            unreachable!("the case run reads as an enum finding");
        };
        assert_eq!(candidate.values, vec![0, 1, 2, 3]);
        assert_eq!(
            candidate.suggestion,
            "enum State { /* variants for 0..=3 */ }"
        );

        let ConstFinding::NamedConstant(constant) = findings[2] else {
            unreachable!("the repeated literal reads as a named-constant finding");
        };
        assert_eq!(constant.value, 0x280);
        assert_eq!(constant.count, 3);
        assert_eq!(constant.confidence, Confidence::new(60));

        let ConstFinding::ColorConstant(palette) = findings[3] else {
            unreachable!("the color-shaped literals read as a palette finding");
        };
        assert_eq!(palette.values, vec![3, 0x280]);

        // The named constant and the palette belong to both functions
        // that use their values.
        assert_eq!(
            kinds(&result, "FUN_18003e750"),
            ["named_constant", "color_constant"]
        );
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry every shape and one carries a table
        // magic, so the persisted list must group their per-function
        // findings by function in listing order — bitmask then enum —
        // and append the program-level findings after them: the named
        // constants, then the flag family the two identical groups
        // merge into, then the protocol constant the magic matched,
        // then the color palette the color reading grouped, never
        // interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                &format!(
                    "{EVERY_SHAPE_BODY}  if (magic == 0xcafebabe) {{\n    dispatch();\n  }}\n"
                ),
            ),
        );
        let result = scan(program).await;

        let order: Vec<(&str, &str)> = result
            .findings
            .iter()
            .map(|finding| (finding.function(), finding.kind()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("FUN_18003e750", "bitflag_group"),
                ("FUN_18003e750", "enum_candidate"),
                ("FUN_18003ab00", "bitflag_group"),
                ("FUN_18003ab00", "enum_candidate"),
                ("", "named_constant"),
                ("", "flag_family"),
                ("", "protocol_constant"),
                ("", "color_constant"),
            ]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan
        // that asked each detector for its own copy would triple the
        // wall time.
        let program = program();
        let result = scan(program.clone()).await;
        assert!(!result.is_empty());
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750"],
            "one decompile per function, in listing order"
        );
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // Ghidra cannot produce a body for every function; one bad
        // entry point must not cost the whole program its scan.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into()];
        let result = scan(program.clone()).await;

        assert!(
            result.is_empty(),
            "the failing function contributed nothing and the plain one carries no shape alone"
        );
        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
    }

    #[tokio::test]
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The 2026-10-08 incident: the bridge answered the listing from
        // one program and the decompiles from another, every decompile
        // failed, and the scan nearly persisted a phantom-clean record
        // under the target's name. The skip-rate breaker aborts with
        // the counts instead, so nothing is persisted.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = ConstEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::ConstError::DecompileBreaker {
                failed: 2,
                total: 2
            })
        ));
    }

    #[tokio::test]
    async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
        // The breaker is a circuit breaker, not a post-mortem: once
        // most of the listing has failed, the remaining decompiles are
        // wasted round-trips against the wrong program.
        let mut program = program();
        program.listing.push(summary("FUN_1800412a0"));
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  return;\n",
            ),
        );
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = ConstEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::ConstError::DecompileBreaker {
                failed: 2,
                total: 3
            })
        ));
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18003ab00", "FUN_18003e750"],
            "the scan stopped once the breaker tripped"
        );
    }

    #[tokio::test]
    async fn a_nameless_listing_entry_is_skipped() {
        // An empty name would send the by-name lookup into an
        // arbitrary function's body, so the entry passes without a
        // decompile.
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by
        // detection.
        let mut program = program();
        program.fail_listing = true;
        let result = ConstEngine::with_source(program).scan("eqmain.dll").await;
        assert!(matches!(
            result,
            Err(crate::ConstError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn custom_thresholds_reach_every_detector() {
        // Swapping a detector's thresholds whole reaches the scan: the
        // configured bars find shapes the standard ones miss, and the
        // standard bars miss these shapes.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  x &= 0x1;\n  switch(u) {\n  case 0:\n  case 1:\n    a();\n  }\n  b(7);\n  c(7);\n  d(7);\n  e(7);\n",
            ),
        );

        let engine = ConstEngine::with_source(program.clone())
            .with_bitmask(BitmaskDetector::with_min_bits(1))
            .with_sequential(SequentialDetector::with_min_run(2))
            .with_frequency(FrequencyAnalyzer::with_thresholds(4, 1, [0, 1, 2]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        assert_eq!(
            kinds(&result, "FUN_1800412a0"),
            ["bitflag_group", "enum_candidate", "named_constant"]
        );
        // The standard configuration finds none of these shapes.
        let standard = ConstEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        assert!(standard.is_empty());
    }

    #[tokio::test]
    async fn scan_stamps_the_scan_provenance() {
        // The metadata names the binary, carries a finish time, and
        // the duration is stamped from the wall clock — a canned scan
        // is instant, so it reads as zero seconds rather than never
        // set.
        let result = scan(program()).await;
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
        assert!(result.metadata.duration_secs < 60);
        // Story 9 (#203): the record also names the engine that produced it —
        // scan() copies the source's provenance through (#208).
        let engine = result
            .metadata
            .engine
            .expect("scan record names its engine");
        assert_eq!(engine.name, "fake-engine");
        assert_eq!(engine.version.as_deref(), Some("9.9"));
        assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}

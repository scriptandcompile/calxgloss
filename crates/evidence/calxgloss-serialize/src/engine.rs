//! Serialization scan orchestration.
//!
//! [`SerializeEngine`] runs the serialization detectors — byte-swap
//! call matching, bit-pack shape reading, and magic-byte comparison
//! matching — over every function of one open Ghidra program and
//! assembles their findings into a single [`SerializeResult`] with its
//! scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so
//! the engine fetches each function's pseudo-C exactly once and reads
//! it with all of them, rather than having each detector pull its own
//! copy. The scan is then one sequential pass over the function
//! listing: there is nothing to resolve between the detectors — they
//! read disjoint body shapes — and keeping the pass sequential keeps
//! the persisted finding list in a stable, diffable order.

use crate::bitpack::BitPackDetector;
use crate::byteswap::ByteSwapDetector;
use crate::error::Result;
use crate::magic_bytes::MagicByteDetector;
use crate::types::{ScanMetadata, SerializeFinding, SerializeResult};
use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler a serialization scan reads.
///
/// [`GhidraClient`] implements it directly; tests implement it over
/// canned bodies so the orchestration runs without a server. The
/// futures are `Send` so a scan can be driven from an orchestrating
/// task.
pub trait ScanSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;
}

impl ScanSource for GhidraClient {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(self.decompile_function_by_name(name).await?)
    }
}

/// Orchestrates the serialization detectors into one [`SerializeResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds
/// one over a live [`GhidraClient`]. Each detector carries no state and
/// starts configured with its standard name sets —
/// [`with_byteswap`](Self::with_byteswap) swaps a detector whole — so
/// one instance of each serves the whole scan.
#[derive(Debug, Clone)]
pub struct SerializeEngine<S = GhidraClient> {
    source: S,
    byteswap: ByteSwapDetector,
    bitpack: BitPackDetector,
    magic: MagicByteDetector,
}

impl SerializeEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client, scanning with the
    /// detectors' standard name sets.
    pub fn new(client: &GhidraClient) -> SerializeEngine<GhidraClient> {
        Self::with_source(client.clone())
    }
}

impl<S> SerializeEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the detectors' standard name sets.
    pub fn with_source(source: S) -> Self {
        SerializeEngine {
            source,
            byteswap: ByteSwapDetector::with_default_names(),
            bitpack: BitPackDetector::new(),
            magic: MagicByteDetector::with_default_signatures(),
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

    /// Detect serialization patterns across `binary`, decompiling each
    /// function exactly once and reading it with every detector.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`)
    /// and becomes the key a persisted result is filed under. The
    /// findings follow the function listing — function by function,
    /// and within one function the byte swaps, then the bit packs,
    /// then the magic-byte comparisons — so two scans of the same
    /// program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad
    /// entry point) is skipped with a warning; only a failure of the
    /// listing itself — the server being down — aborts the run, since
    /// then nothing was scanned. The detectors read disjoint body
    /// shapes, so a function can carry findings of every kind at once
    /// and nothing is resolved between them.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<SerializeResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings = Vec::new();
        let mut skipped = 0usize;
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
                    continue;
                }
            };

            findings.extend(
                self.byteswap
                    .detect(&decompiled)
                    .into_iter()
                    .map(SerializeFinding::ByteSwap),
            );
            findings.extend(
                self.bitpack
                    .detect(&decompiled)
                    .into_iter()
                    .map(SerializeFinding::BitPack),
            );
            findings.extend(
                self.magic
                    .detect(&decompiled)
                    .into_iter()
                    .map(SerializeFinding::Magic),
            );
        }

        let mut metadata = ScanMetadata::new(binary);
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
mod tests {
    use super::*;
    use crate::byteswap::ByteSwapSignature;
    use calxgloss_ghidra::GhidraError;
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
                }
                .into());
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into());
            }
            self.bodies.get(name).cloned().ok_or_else(|| {
                GhidraError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                }
                .into()
            })
        }
    }

    /// A body carrying two `ntohl` calls — the byte-swap shape — in
    /// one function.
    const SWAP_SHAPE_BODY: &str = "\
  uVar1 = ntohl(local_18);
  uVar2 = uVar1 + 1;
  uVar3 = ntohl(local_20);
";

    /// The canned program: one function whose body carries the swap
    /// shape, and one plain function that finds nothing.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                SWAP_SHAPE_BODY,
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  return;\n",
            ),
        );
        program
    }

    async fn scan(program: FakeProgram) -> SerializeResult {
        SerializeEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    #[tokio::test]
    async fn scan_collects_findings_from_the_detector() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&SerializeFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 2);

        let SerializeFinding::ByteSwap(record) = findings[0] else {
            unreachable!("the swap call reads as a byteswap finding");
        };
        assert_eq!(record.operation, "ntohl");
        assert_eq!(record.width, 32);
        assert_eq!(record.suggestion, "byteorder::BE::read_u32");
        assert_eq!(record.evidence, "uVar1 = ntohl(local_18);");

        let SerializeFinding::ByteSwap(record) = findings[1] else {
            unreachable!("the second swap call reads as a byteswap finding");
        };
        assert_eq!(record.evidence, "uVar3 = ntohl(local_20);");

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn one_scan_interleaves_all_three_kinds_in_scan_order() {
        // A function whose body carries a swap call, a pack chain, and
        // a signature comparison: the findings come back in detector
        // order — swap, pack, magic — and the plain function stays
        // empty.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "\
  if (uVar6 == 0x89504e47) {
  uVar1 = ntohl(local_18);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
",
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                "  return;\n",
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
                ("FUN_18003ab00", "byteswap"),
                ("FUN_18003ab00", "bitpack"),
                ("FUN_18003ab00", "magic"),
            ]
        );

        let findings: Vec<&SerializeFinding> = result.for_function("FUN_18003ab00").collect();
        let SerializeFinding::BitPack(record) = findings[1] else {
            unreachable!("the pack chain reads as a bitpack finding");
        };
        assert_eq!(record.widths, [8, 8, 8, 8]);
        assert_eq!(record.suggestion, "bitvec or named-field masking/shifting");

        let SerializeFinding::Magic(record) = findings[2] else {
            unreachable!("the signature comparison reads as a magic finding");
        };
        assert_eq!(record.format, "PNG");
        assert_eq!(record.suggestion, "png::Decoder");
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry the swap shape, so the persisted list
        // must group their findings by function in listing order —
        // never interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(void)",
                SWAP_SHAPE_BODY,
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
                ("FUN_18003e750", "byteswap"),
                ("FUN_18003e750", "byteswap"),
                ("FUN_18003ab00", "byteswap"),
                ("FUN_18003ab00", "byteswap"),
            ]
        );
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The detectors share one fetch per function; a scan that
        // asked each detector for its own copy would multiply the
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
            "the failing function contributed nothing"
        );
        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
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
        let result = SerializeEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::SerializeError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn a_custom_detector_reaches_the_scan() {
        // Swapping the detector whole reaches the scan: the
        // configured custom spelling reads in the body, and the
        // standard names the swap replaced read nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "\
  uVar1 = my_swap(local_18);
  uVar2 = ntohl(local_20);",
            ),
        );

        let engine =
            SerializeEngine::with_source(program).with_byteswap(ByteSwapDetector::with_names([
                ByteSwapSignature::new("my_swap", 32),
            ]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        let findings: Vec<&SerializeFinding> = result.for_function("FUN_1800412a0").collect();
        assert_eq!(findings.len(), 1);
        let SerializeFinding::ByteSwap(record) = findings[0] else {
            unreachable!("the swap call reads as a byteswap finding");
        };
        assert_eq!(record.operation, "my_swap");
        assert_eq!(record.suggestion, "byteorder::BE::read_u32");
    }

    #[tokio::test]
    async fn a_custom_signature_table_reaches_the_scan() {
        // Swapping the signature table whole reaches the scan: the
        // configured custom magic reads in the body, and the standard
        // signatures the table replaced read nothing.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "\
  if (uVar1 == 0x43414c58) {
  if (uVar2 == 0x89504e47) {",
            ),
        );

        let engine =
            SerializeEngine::with_source(program).with_magic(MagicByteDetector::with_signatures([
                crate::magic_bytes::MagicSignature::new("CALX", 0x4341_4C58, "calx::Header"),
            ]));
        let result = engine.scan("eqmain.dll").await.expect("scan");

        let findings: Vec<&SerializeFinding> = result.for_function("FUN_1800412a0").collect();
        assert_eq!(findings.len(), 1);
        let SerializeFinding::Magic(record) = findings[0] else {
            unreachable!("the signature comparison reads as a magic finding");
        };
        assert_eq!(record.format, "CALX");
        assert_eq!(record.suggestion, "calx::Header");
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
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}

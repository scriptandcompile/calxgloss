//! The scan over one program: read every kept function body once and
//! collect the error-handling findings (ADR-0046).
//!
//! [`ErrhandlingEngine`] follows the established evidence-engine
//! shape: it borrows any [`ScanSource`], walks the function listing in
//! order, decompiles each function once, runs the idiom detector over
//! the kept body, and assembles an [`ErrhandlingResult`] stamped with
//! the scan metadata — the same loop the libmatch and globalstate
//! engines run, with the idiom detector as its only difference. All
//! findings are asserted at this seam, never inside a detector.

use crate::error::Result;
use crate::seh_frame::SehFrameDetector;
use crate::types::{ErrhandlingFinding, ErrhandlingResult};
use calxgloss_kuna::KunaSource;
use calxgloss_types::ScanMetadata;
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler an error-handling scan reads.
///
/// The shared trait from the decompiler seam crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// Orchestrates the per-body idiom readings into one
/// [`ErrhandlingResult`].
///
/// One loop, one family for now: the follow-up P15 bullets add
/// detectors and finding variants, not new control flow, so the
/// scan-order, skip and breaker behaviour — the behaviour contract
/// every evidence engine keeps — stays written in exactly one place.
/// The engine is generic over its [`ScanSource`], so tests can run
/// the whole orchestration over canned bodies; [`new`](Self::new)
/// builds one over a loaded [`KunaSource`]. The detector carries no
/// state, so one instance serves the whole scan, and
/// [`with_detector`](Self::with_detector) swaps it for a configured
/// one.
#[derive(Debug, Clone)]
pub struct ErrhandlingEngine<S = KunaSource> {
    source: S,
    detector: SehFrameDetector,
}

impl ErrhandlingEngine<KunaSource> {
    /// An engine over a loaded Kuna program, detecting the spelled
    /// SEH frame — the family this slice implements.
    pub fn new(source: &KunaSource) -> ErrhandlingEngine<KunaSource> {
        ErrhandlingEngine {
            source: source.clone(),
            detector: SehFrameDetector,
        }
    }
}

impl<S> ErrhandlingEngine<S> {
    /// An engine whose decompiles come from `source`, detecting the
    /// spelled SEH frame.
    pub fn with_source(source: S) -> Self {
        ErrhandlingEngine {
            source,
            detector: SehFrameDetector,
        }
    }

    /// Read bodies with `detector` instead of the standard spelled-
    /// frame one — the seam the follow-up families plug their own
    /// detectors into without touching the loop.
    pub fn with_detector(mut self, detector: SehFrameDetector) -> Self {
        self.detector = detector;
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
    /// aborts too: that is the signature of the bridge answering from
    /// the wrong program, and skipping on would persist a
    /// phantom-clean record (issue #71). Findings ride in listing
    /// order, one function's findings grouped together, so two scans
    /// of the same program diff cleanly.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<ErrhandlingResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings: Vec<ErrhandlingFinding> = Vec::new();
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
                    // failed to decompile, the scan is reading a
                    // program the engine cannot analyze, and an empty
                    // result would persist as a phantom-clean record.
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
            if let Some(mut finding) = self.detector.detect(&decompiled.body) {
                // The detector fills no function name (it never sees
                // one); the engine owns the stamp, at the seam where
                // every finding behaviour is asserted.
                match &mut finding {
                    ErrhandlingFinding::SehFrame(record) => {
                        record.function = decompiled.name.clone();
                    }
                }
                findings.push(finding);
            }
        }

        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
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
mod tests {
    use super::*;
    use crate::ErrhandlingError;
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
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

    fn function(name: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: format!("undefined {name}(void)"),
            body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
        }
    }

    /// A body spelling the SEH frame the decompiler produces (the
    /// shape pinned by issue #286's tests).
    const SEH_BODY: &str = "  try {\n    work();\n  }\n  catch(...){\n    recover();\n  }\n";

    /// A `ScanSource` over canned data, recording every call.
    #[derive(Clone, Default)]
    struct FakeProgram {
        functions: Vec<FunctionSummary>,
        bodies: HashMap<String, String>,
        fail_decompiles: Vec<String>,
        fail_listing: bool,
        stats: Arc<FakeStats>,
    }

    #[derive(Default)]
    struct FakeStats {
        decompiles: Mutex<Vec<String>>,
    }

    impl FakeProgram {
        fn decompiled(&self) -> Vec<String> {
            self.stats.decompiles.lock().unwrap().clone()
        }
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.functions.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            self.stats.decompiles.lock().unwrap().push(name.to_string());
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .map(|body| function(name, &body))
                .ok_or_else(|| EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        async fn disassembly(&self, _name: &str) -> Result<String> {
            Ok(String::new())
        }

        // The rest of the shared trait's reads: this engine never
        // makes them, so they answer with empty or not-found data.
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
            Err(EngineError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }
        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(EngineError::NotFound {
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
    }

    #[tokio::test]
    async fn scan_finds_the_frame_in_body_text_without_new_reads() {
        // The whole point of the reading: a body that spells the
        // frame lands as a finding, and the scan made no read beyond
        // the listing and the one decompile per function.
        let source = FakeProgram {
            functions: vec![summary("handler_fn"), summary("plain_fn")],
            bodies: HashMap::from([
                ("handler_fn".to_string(), SEH_BODY.to_string()),
                ("plain_fn".to_string(), "  run();\n".to_string()),
            ]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].function(), "handler_fn");
        assert_eq!(result.findings[0].kind(), "seh_frame");
        // Only the listing read and one decompile per function: the
        // frame comes off the kept body text, no new source reads.
        let decompiles = source.decompiled();
        assert_eq!(decompiles.len(), 2);
        assert!(decompiles.contains(&"handler_fn".to_string()));
        assert!(decompiles.contains(&"plain_fn".to_string()));
    }

    #[tokio::test]
    async fn functions_are_decompiled_exactly_once() {
        let source = FakeProgram {
            functions: vec![summary("a"), summary("b"), summary("c")],
            bodies: HashMap::from([
                ("a".to_string(), SEH_BODY.to_string()),
                ("b".to_string(), "  run();\n".to_string()),
                ("c".to_string(), "  run();\n".to_string()),
            ]),
            ..FakeProgram::default()
        };
        ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        let mut decompiles = source.decompiled();
        decompiles.sort();
        assert_eq!(decompiles, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn findings_follow_listing_order() {
        // The scan-order contract two scans rely on for diffing: one
        // function's findings land grouped, in listing order — even
        // when later functions find nothing, and even when earlier
        // ones do.
        let source = FakeProgram {
            functions: vec![summary("first"), summary("second"), summary("third")],
            bodies: HashMap::from([
                (
                    "first".to_string(),
                    "  try {\n    a();\n  }\n  catch(...){\n    ha();\n  }\n".to_string(),
                ),
                ("second".to_string(), "  run();\n".to_string()),
                (
                    "third".to_string(),
                    "  try {\n    b();\n  }\n  catch(DWORD code){\n    hb(code);\n  }\n"
                        .to_string(),
                ),
            ]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        let names: Vec<&str> = result.findings.iter().map(|f| f.function()).collect();
        assert_eq!(names, vec!["first", "third"]);
    }

    #[tokio::test]
    async fn function_names_are_stamped_by_the_engine() {
        // The detector fills no name (it never sees one); the engine
        // owns the stamp — assert it at this seam.
        let source = FakeProgram {
            functions: vec![summary("guarded")],
            bodies: HashMap::from([("guarded".to_string(), SEH_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings[0].function(), "guarded");
    }

    #[tokio::test]
    async fn empty_listing_yields_an_empty_scan() {
        // An empty program is not an error — it persists as an
        // honest empty record, the no-findings case that the skip-rate
        // breaker exists to keep distinct from a wrong-program run.
        let source = FakeProgram::default();
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("empty.exe")
            .await
            .expect("empty program must scan cleanly");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn listing_failure_aborts_the_run() {
        // Only the listing failure aborts: nothing was scanned, so
        // there is nothing to persist.
        let source = FakeProgram {
            fail_listing: true,
            ..FakeProgram::default()
        };
        let error = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect_err("listing failure must abort the scan");
        assert!(matches!(error, ErrhandlingError::Engine(_)));
    }

    #[tokio::test]
    async fn decompile_failure_skips_the_function() {
        // A single decompile failure is a skip, not an abort — and
        // the skipped function claims nothing and counts nothing as
        // scanned.
        let source = FakeProgram {
            functions: vec![summary("ok"), summary("thunk")],
            bodies: HashMap::from([("ok".to_string(), SEH_BODY.to_string())]),
            fail_decompiles: vec!["thunk".to_string()],
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("one decompile failure must not abort the scan");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].function(), "ok");
    }

    #[tokio::test]
    async fn all_decompiles_failing_aborts_the_scan() {
        // The skip-rate breaker, asserted at the engine seam like
        // every contract here: every function failing to decompile
        // is the wrong-program signature, and an empty result would
        // persist as a phantom-clean record. The scan aborts with
        // counts rather than skipping its way to a clean answer
        // (issue #71).
        let source = FakeProgram {
            functions: vec![summary("a"), summary("b"), summary("c")],
            fail_decompiles: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..FakeProgram::default()
        };
        let error = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect_err("every decompile failing must abort the scan");
        assert!(
            matches!(
                error,
                ErrhandlingError::DecompileBreaker {
                    failed: 2,
                    total: 3
                }
            ),
            "expected the decompile breaker, got {error:?}"
        );
    }

    #[tokio::test]
    async fn majority_decompile_failure_aborts_the_scan() {
        // More than half failing trips the breaker; a minority is a
        // skippable gap. With four functions, three failures are a
        // majority — the third failure aborts before the fourth is
        // even attempted, the breaker cutting off the run rather
        // than reporting after.
        let source = FakeProgram {
            functions: vec![summary("a"), summary("b"), summary("c"), summary("d")],
            fail_decompiles: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..FakeProgram::default()
        };
        let error = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect_err("majority decompile failure must abort the scan");
        assert!(matches!(
            error,
            ErrhandlingError::DecompileBreaker {
                failed: 3,
                total: 4
            }
        ));
        let attempted = source.decompiled();
        assert!(
            !attempted.iter().any(|name| name == "d"),
            "the breaker must cut the run off, not decompile the rest"
        );
    }

    #[tokio::test]
    async fn nameless_listing_entries_are_skipped() {
        // A name can't be looked up, so nothing can be claimed: the
        // entry passes unrecorded and without a decompile attempt.
        let source = FakeProgram {
            functions: vec![summary(""), summary("real")],
            bodies: HashMap::from([("real".to_string(), SEH_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].function(), "real");
        assert_eq!(source.decompiled(), vec!["real".to_string()]);
    }

    #[tokio::test]
    async fn provenance_lands_on_the_result() {
        // Issue #208's shared rule asserted at this engine's seam:
        // the source's engine stamp rides through to the scan
        // result. A `ScanSource` that names its engine gets the
        // stamp verbatim — the real Kunna-backed source names
        // itself — and one that stays silent lands as `None`, never
        // as a guess about what read the program.
        #[derive(Default, Clone)]
        struct NamedSource(FakeProgram);
        impl ScanSource for NamedSource {
            async fn functions(&self) -> Result<Vec<FunctionSummary>> {
                self.0.functions().await
            }
            async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
                self.0.decompile(name).await
            }
            async fn disassembly(&self, name: &str) -> Result<String> {
                self.0.disassembly(name).await
            }
            async fn strings(&self) -> Result<Vec<StringLiteral>> {
                self.0.strings().await
            }
            async fn callers(&self, address: u64) -> Result<Vec<String>> {
                self.0.callers(address).await
            }
            async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
                self.0.xrefs_to(address).await
            }
            async fn data_types(&self, category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
                self.0.data_types(category).await
            }
            async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
                self.0.struct_layout(name).await
            }
            async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
                self.0.enum_values(name).await
            }
            async fn data_items(&self) -> Result<Vec<DataItem>> {
                self.0.data_items().await
            }
            async fn imports(&self) -> Result<Vec<Symbol>> {
                self.0.imports().await
            }
            async fn exports(&self) -> Result<Vec<Symbol>> {
                self.0.exports().await
            }
            async fn image_base(&self) -> Result<u64> {
                self.0.image_base().await
            }
            async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
                self.0.read_memory(address, length).await
            }
            fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
                Some(calxgloss_types::EngineProvenance {
                    name: "kunnaproxy".to_string(),
                    version: Some("v1.878".to_string()),
                    fingerprint: Some("cb68db1".to_string()),
                })
            }
        }

        let source = NamedSource::default();
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        let provenance = result
            .metadata
            .engine
            .expect("a source that names its engine lands the stamp");
        assert_eq!(provenance.name, "kunnaproxy");
        assert_eq!(provenance.version.as_deref(), Some("v1.878"));
        assert_eq!(provenance.fingerprint.as_deref(), Some("cb68db1"));

        let silent = FakeProgram::default();
        let result = ErrhandlingEngine::with_source(silent)
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert!(
            result.metadata.engine.is_none(),
            "a silent source must not get an invented stamp"
        );
    }
}

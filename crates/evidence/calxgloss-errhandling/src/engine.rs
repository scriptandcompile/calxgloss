//! The scan over one program: read every kept function body once and
//! collect the error-handling findings (ADR-0046).
//!
//! [`ErrhandlingEngine`] follows the established evidence-engine
//! shape: it borrows any [`ScanSource`], walks the function listing in
//! order, decompiles each function once, runs the idiom detectors
//! over the kept body, and assembles an [`ErrhandlingResult`] stamped
//! with the scan metadata — the same loop the libmatch and globalstate
//! engines run, with the detector set as its only difference. All
//! findings are asserted at this seam, never inside a detector.

use crate::error::Result;
use crate::exception_api::ExceptionApiDetector;
use crate::goto_cleanup::GotoCleanupDetector;
use crate::named_handler::NamedHandlerDetector;
use crate::raise_exception::RaiseExceptionDetector;
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
/// One loop, five detectors, per the ADR-0046 family ladder: the
/// spelled SEH frame, the named personality-handler thunk, the
/// exception-API call, the direct `RaiseException` call, and the
/// goto-cleanup ladder. The SEH detectors run in rung order and
/// **the strongest family that fires takes the function's one SEH
/// claim** — a body showing a spelled block beside a thunk
/// registration lands one finding at the spelled band, never a stack
/// of duplicates for the same frame (issue #288). The `RaiseException`
/// reading is a different fact — the function *raising*, not being
/// guarded — and rides beside the SEH claim, and so does the
/// `GotoCleanup` reading — the function *cleaning up on failure*,
/// whether or not any exception mechanism is involved (issue #289).
/// One function therefore contributes at most three findings, in
/// rung order. Follow-up P15 bullets add detectors, not new control
/// flow, so the scan-order, skip and breaker behaviour — the
/// behaviour contract every evidence engine keeps — stays written in
/// exactly one place.
/// The engine is generic over its [`ScanSource`], so tests can run
/// the whole orchestration over canned bodies; [`new`](Self::new)
/// builds one over a loaded [`KunaSource`]. The SEH and raise
/// detectors carry no state, so one instance of each serves the
/// whole scan, and [`with_seh_frame`](Self::with_seh_frame),
/// [`with_named_handler`](Self::with_named_handler),
/// [`with_exception_api`](Self::with_exception_api),
/// [`with_raise_exception`](Self::with_raise_exception), and
/// [`with_goto_cleanup`](Self::with_goto_cleanup) swap one detector
/// for a configured one.
#[derive(Debug, Clone)]
pub struct ErrhandlingEngine<S = KunaSource> {
    source: S,
    seh_frame: SehFrameDetector,
    named_handler: NamedHandlerDetector,
    exception_api: ExceptionApiDetector,
    raise_exception: RaiseExceptionDetector,
    goto_cleanup: GotoCleanupDetector,
}

/// The detectors of a standard engine, spelled once so `new` and
/// `with_source` cannot drift.
fn standard_detectors() -> (
    SehFrameDetector,
    NamedHandlerDetector,
    ExceptionApiDetector,
    RaiseExceptionDetector,
    GotoCleanupDetector,
) {
    (
        SehFrameDetector,
        NamedHandlerDetector,
        ExceptionApiDetector,
        RaiseExceptionDetector,
        GotoCleanupDetector::new(),
    )
}

impl ErrhandlingEngine<KunaSource> {
    /// An engine over a loaded Kuna program, detecting the SEH frame
    /// across its three body-text families, the direct
    /// `RaiseException` call, and the goto-cleanup ladder.
    pub fn new(source: &KunaSource) -> ErrhandlingEngine<KunaSource> {
        let (seh_frame, named_handler, exception_api, raise_exception, goto_cleanup) =
            standard_detectors();
        ErrhandlingEngine {
            source: source.clone(),
            seh_frame,
            named_handler,
            exception_api,
            raise_exception,
            goto_cleanup,
        }
    }
}

impl<S> ErrhandlingEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with
    /// the detectors' standard bands and name sets.
    pub fn with_source(source: S) -> Self {
        let (seh_frame, named_handler, exception_api, raise_exception, goto_cleanup) =
            standard_detectors();
        ErrhandlingEngine {
            source,
            seh_frame,
            named_handler,
            exception_api,
            raise_exception,
            goto_cleanup,
        }
    }

    /// Read spelled SEH frames with `detector` instead of the
    /// standard one — the seam the follow-up families plug their own
    /// configured detectors into without touching the loop.
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
    /// standard one — the seam a binary's own release names plug
    /// into through [`GotoCleanupDetector::with_releases`] without
    /// touching the loop.
    pub fn with_goto_cleanup(mut self, detector: GotoCleanupDetector) -> Self {
        self.goto_cleanup = detector;
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
            // The strongest SEH family wins: the detectors run in
            // ADR-0046's rung order — spelled frame, named handler,
            // exception-API call — and the first that fires takes
            // the function's one SEH claim, so a body showing a
            // spelled block beside a thunk registration lands one
            // finding at the spelled band, never a stack of
            // duplicates for the same frame (issue #288). The
            // RaiseException reading names a different fact — the
            // function raising, not being guarded — and the
            // GotoCleanup reading names a third — the function
            // cleaning up on failure, an idiom no exception
            // mechanism is part of — and both ride beside the SEH
            // claim (issue #289).
            for mut finding in self
                .seh_frame
                .detect(&decompiled.body)
                .or_else(|| self.named_handler.detect(&decompiled.body))
                .or_else(|| self.exception_api.detect(&decompiled.body))
                .into_iter()
                .chain(self.raise_exception.detect(&decompiled.body))
                .chain(self.goto_cleanup.detect(&decompiled.body))
                .collect::<Vec<_>>()
            {
                // The detectors fill no function name (they never
                // see one); the engine owns the stamp, at the seam
                // where every finding behaviour is asserted.
                finding.set_function(&decompiled.name);
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

    /// A body naming a personality-handler thunk registration — an
    /// SEH frame the decompiler left undrawn (issue #288).
    const THUNK_BODY: &str = "  _CxxFrameHandler3(1, 0, lookup, this_ptr, frame);\n  work();\n";

    /// A body whose only exception evidence is an exception-API call.
    const API_BODY: &str = "  code = GetExceptionCode();\n  return code;\n";

    /// A body a direct `RaiseException` call with a literal code.
    const RAISE_BODY: &str = "  RaiseException(0xe06d7363, 0, 0, NULL);\n  return 0;\n";

    /// A body with the goto-cleanup ladder: two guarded forward gotos
    /// converging on one `LAB_` join block that closes the handle on
    /// the cleanup path (issue #289).
    const LADDER_BODY: &str = "  handle = CreateFileW(name);\n  \
                               if (handle == 0) {\n    goto LAB_140001350;\n  \
                               }\n  if (bad) {\n    goto LAB_140001350;\n  \
                               }\n  use(handle);\nLAB_140001350: // code ref\n  \
                               CloseHandle(handle);\n  return 0;\n";

    /// A GS stack-canary body — cookie save, cookie comparison, the
    /// guard-runtime call, and join-label noise: compiler noise the
    /// scan must never read as exception handling (issue #288's
    /// guard rail).
    const GS_BODY: &str = "  uVar = __security_cookie ^ (ulonglong)&stack0xfffffffffffffff4;\n  \
                            if (uStack_8 == __security_cookie) {\n    goto joined_r0x140001337;\n  \
                            }\n  x = __security_check_cookie(local_8);\n  thunk = \
                            _guard_check_icall_fptr;\n";

    #[tokio::test]
    async fn a_named_handler_body_lands_the_named_finding_at_its_band() {
        use crate::named_handler::NAMED_HANDLER_CONFIDENCE;
        let source = FakeProgram {
            functions: vec![summary("cpp_guarded")],
            bodies: HashMap::from([("cpp_guarded".to_string(), THUNK_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "named_handler");
        assert_eq!(result.findings[0].function(), "cpp_guarded");
        assert_eq!(
            result.findings[0].confidence().value(),
            NAMED_HANDLER_CONFIDENCE
        );
        assert!(result.findings[0].evidence().contains("_CxxFrameHandler3"));
    }

    #[tokio::test]
    async fn an_exception_api_body_lands_the_api_finding_at_its_band() {
        use crate::exception_api::EXCEPTION_API_CONFIDENCE;
        let source = FakeProgram {
            functions: vec![summary("filter_fn")],
            bodies: HashMap::from([("filter_fn".to_string(), API_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "exception_api_call");
        assert_eq!(
            result.findings[0].confidence().value(),
            EXCEPTION_API_CONFIDENCE
        );
        assert!(result.findings[0].evidence().contains("GetExceptionCode"));
    }

    #[tokio::test]
    async fn the_strongest_seh_family_wins_one_claim_per_function() {
        // A body showing a spelled block beside a thunk registration
        // beside an API call — plus a direct raise, a different fact
        // — lands exactly two findings: the SEH claim at the spelled
        // band, and the raise. Never a stack of duplicates for the
        // same frame.
        let body = format!(
            "{}{}{}{}",
            SEH_BODY,
            "  _CxxFrameHandler3(1, 0, lookup, this_ptr, frame);\n",
            "  code = GetExceptionCode();\n",
            RAISE_BODY
        );
        let source = FakeProgram {
            functions: vec![summary("everything")],
            bodies: HashMap::from([("everything".to_string(), body)]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].kind(), "seh_frame");
        assert_eq!(result.findings[1].kind(), "raise_exception");
        assert!(result.findings.iter().all(|f| f.function() == "everything"));
    }

    #[tokio::test]
    async fn a_named_handler_beside_an_api_call_takes_the_named_band() {
        // The rung order inside the union's SEH kinds: thunk
        // registration outranks the API call, one finding.
        let body = format!("{THUNK_BODY}{API_BODY}");
        let source = FakeProgram {
            functions: vec![summary("guarded_and_querying")],
            bodies: HashMap::from([("guarded_and_querying".to_string(), body)]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "named_handler");
    }

    #[tokio::test]
    async fn a_raise_beside_no_seh_shape_stands_alone() {
        // The raise needs no SEH finding beside it — a function can
        // raise into a frame it does not itself carry.
        let source = FakeProgram {
            functions: vec![summary("raiser")],
            bodies: HashMap::from([("raiser".to_string(), RAISE_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "raise_exception");
        match &result.findings[0] {
            ErrhandlingFinding::RaiseException(record) => {
                assert_eq!(record.function, "raiser");
                assert_eq!(record.code, Some(0xe06d_7363));
            }
            other => panic!("expected the raise kind, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn gs_canary_noise_claims_nothing_alone_or_beside_other_noise() {
        // The guard rail asserted at the engine seam: the canary
        // family — alone, and beside a real thunk registration it
        // must not color — yields no SEH finding. The GS body itself
        // claims nothing; the thunk function next to it keeps its
        // honest one finding.
        let alone = FakeProgram {
            functions: vec![summary("gs_only")],
            bodies: HashMap::from([("gs_only".to_string(), GS_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(alone)
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert!(result.is_empty(), "a canary check is not an SEH frame");

        let source = FakeProgram {
            functions: vec![summary("gs_only"), summary("guarded")],
            bodies: HashMap::from([
                ("gs_only".to_string(), GS_BODY.to_string()),
                ("guarded".to_string(), THUNK_BODY.to_string()),
            ]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source)
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].function(), "guarded");
    }

    #[tokio::test]
    async fn a_ladder_body_lands_the_goto_cleanup_finding_at_its_band() {
        use crate::goto_cleanup::GOTO_CLEANUP_RELEASE_CONFIDENCE;
        let source = FakeProgram {
            functions: vec![summary("cleanup_fn")],
            bodies: HashMap::from([("cleanup_fn".to_string(), LADDER_BODY.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "goto_cleanup");
        assert_eq!(result.findings[0].function(), "cleanup_fn");
        assert_eq!(
            result.findings[0].confidence().value(),
            GOTO_CLEANUP_RELEASE_CONFIDENCE
        );
        // The finding names the join block it converged on — the label
        // Ghidra printed — both in the record and through the accessor.
        match &result.findings[0] {
            ErrhandlingFinding::GotoCleanup(record) => {
                assert_eq!(record.join_label, "LAB_140001350");
            }
            other => panic!("expected the ladder kind, got {other:?}"),
        }
        assert!(result.findings[0].evidence().contains("CloseHandle"));
    }

    #[tokio::test]
    async fn a_ladder_with_only_a_constant_join_lands_quietly_low() {
        use crate::goto_cleanup::GOTO_CLEANUP_RETURN_CONFIDENCE;
        let body = "  if (a) {\n    goto LAB_1;\n  }\n  if (b) {\n    goto LAB_1;\n  \
                    }\n  work();\nLAB_1:\n  return 0;\n";
        let source = FakeProgram {
            functions: vec![summary("const_exit")],
            bodies: HashMap::from([("const_exit".to_string(), body.to_string())]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "goto_cleanup");
        assert_eq!(
            result.findings[0].confidence().value(),
            GOTO_CLEANUP_RETURN_CONFIDENCE
        );
    }

    #[tokio::test]
    async fn a_ladder_beside_a_spelled_frame_never_outranks_it() {
        // The AC ladder: one function, both readings fire — the spelled
        // frame and the cleanup ladder ride beside each other as two
        // findings, and the frame's 80 stays the strongest claim.
        let body = format!("{SEH_BODY}{LADDER_BODY}");
        let source = FakeProgram {
            functions: vec![summary("frame_and_ladder")],
            bodies: HashMap::from([("frame_and_ladder".to_string(), body)]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert_eq!(result.findings.len(), 2);
        let kinds: Vec<(&str, u8)> = result
            .findings
            .iter()
            .map(|f| (f.kind(), f.confidence().value()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("seh_frame", crate::seh_frame::SPELLED_FRAME_CONFIDENCE),
                (
                    "goto_cleanup",
                    crate::goto_cleanup::GOTO_CLEANUP_RELEASE_CONFIDENCE
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_reconfigured_ladder_detector_lands_the_custom_release_band() {
        // The extensible vocabulary at the engine seam: an engine
        // configured with a custom release name reads a ladder whose
        // join block releases through that name.
        let body = "  if (a) {\n    goto LAB_9;\n  }\n  if (b) {\n    goto LAB_9;\n  \
                    }\n  p = allocate();\nLAB_9:\n  MyPoolFree(p);\n  return 0;\n";
        let source = FakeProgram {
            functions: vec![summary("pooled")],
            bodies: HashMap::from([("pooled".to_string(), body.to_string())]),
            ..FakeProgram::default()
        };
        let plain = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        let kinds: Vec<&str> = plain.findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec!["goto_cleanup"],
            "the standard ladder sees a plain forward-goto join; the \
             builder test below shows the release-name gate changes the band"
        );
        let engine = ErrhandlingEngine::with_source(source)
            .with_goto_cleanup(crate::GotoCleanupDetector::new().with_releases(["MyPoolFree"]));
        let result = engine.scan("test.exe").await.expect("scan must succeed");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].kind(), "goto_cleanup");
    }

    #[tokio::test]
    async fn ordinary_flow_and_gs_noise_claim_no_ladder() {
        // The guard rails at the engine seam: the canary body's single
        // guarded forward goto has no join block behind it, and plain
        // straight-line flow claims nothing — the ladder stays quiet
        // where the old readings already stay quiet.
        let source = FakeProgram {
            functions: vec![summary("gs_only"), summary("plain")],
            bodies: HashMap::from([
                ("gs_only".to_string(), GS_BODY.to_string()),
                ("plain".to_string(), "  run();\n".to_string()),
            ]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source)
            .scan("test.exe")
            .await
            .expect("scan must succeed");
        assert!(result.is_empty(), "no finding without a cleanup join block");
    }

    #[tokio::test]
    async fn the_three_seh_bands_persist_ranked() {
        // One function per SEH family: the persisted confidences
        // carry the bands, and rank spelled block above named
        // handler above API call — observable through the document,
        // which is how a reviewer (and the future prompt section)
        // ranks what it is shown.
        let source = FakeProgram {
            functions: vec![summary("spelled"), summary("named"), summary("api_only")],
            bodies: HashMap::from([
                ("spelled".to_string(), SEH_BODY.to_string()),
                ("named".to_string(), THUNK_BODY.to_string()),
                ("api_only".to_string(), API_BODY.to_string()),
            ]),
            ..FakeProgram::default()
        };
        let result = ErrhandlingEngine::with_source(source.clone())
            .scan("ranked.exe")
            .await
            .expect("scan must succeed");
        let bands: Vec<(&str, u8)> = result
            .findings
            .iter()
            .map(|f| (f.kind(), f.confidence().value()))
            .collect();
        assert_eq!(
            bands,
            vec![
                ("seh_frame", crate::seh_frame::SPELLED_FRAME_CONFIDENCE),
                (
                    "named_handler",
                    crate::named_handler::NAMED_HANDLER_CONFIDENCE
                ),
                (
                    "exception_api_call",
                    crate::exception_api::EXCEPTION_API_CONFIDENCE
                ),
            ]
        );
        // Persistence observability: the scores round-trip through
        // the document unchanged.
        let json = serde_json::to_string(&result).expect("the document serializes");
        let back: crate::ErrhandlingResult =
            serde_json::from_str(&json).expect("the document loads back");
        assert_eq!(back, result);
    }

    #[tokio::test]
    async fn two_scans_of_one_program_diff_cleanly() {
        // The diffing contract, asserted over the grown finding set:
        // every family in one program, scanned twice, lands the same
        // findings in the same order.
        let source = FakeProgram {
            functions: vec![
                summary("spelled"),
                summary("named"),
                summary("raiser"),
                summary("plain"),
                summary("api_only"),
            ],
            bodies: HashMap::from([
                ("spelled".to_string(), SEH_BODY.to_string()),
                ("named".to_string(), THUNK_BODY.to_string()),
                ("raiser".to_string(), RAISE_BODY.to_string()),
                ("plain".to_string(), "  run();\n".to_string()),
                ("api_only".to_string(), API_BODY.to_string()),
            ]),
            ..FakeProgram::default()
        };
        let first = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("first scan must succeed");
        let second = ErrhandlingEngine::with_source(source.clone())
            .scan("test.exe")
            .await
            .expect("second scan must succeed");
        assert_eq!(first.findings, second.findings);
        let names: Vec<&str> = first.findings.iter().map(|f| f.function()).collect();
        assert_eq!(names, vec!["spelled", "named", "raiser", "api_only"]);
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

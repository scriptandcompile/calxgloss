// Tests for the module above, split out of the file they test.
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

// A raise carrying the C++ exception code: the raise finding
// lands, but `0xe06d7363` itself records no failure code — its
// shape is outside the code-shape bands — while the returned
// invalid-argument code below records as one.
const CODED_RAISE_BODY: &str = "  RaiseException(0xe06d7363, 0, NULL, 0);\n  return 0x80070057;\n";

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

    // The rest of the shared trait's reads: this scan never
    // makes them, so each answers with empty or not-found data.
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
    // frame comes from the kept body text, no new source reads.
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
    // function's findings land grouped in listing order,
    // whether neighbouring functions find nothing or find
    // something.
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
                "  try {\n    b();\n  }\n  catch(DWORD code){\n    hb(code);\n  }\n".to_string(),
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
    // The detector fills in no name (it never sees one); the scan
    // is what stamps it — asserted at this seam.
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
    // An empty program is not an error — it persists as an honest
    // empty record. That is the no-findings case the skip-rate
    // breaker keeps distinct from a wrong-program run.
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
    // The skip-rate breaker, asserted through the scan itself
    // like every contract here: every decompile failing is the
    // signature of the seam answering about the wrong program,
    // and an empty result would persist as a record that looks
    // clean but is not. The scan aborts with the counts rather
    // than skipping its way to a clean answer (issue #71).
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
    // A majority of failures trips the breaker; a minority is a
    // skippable gap. With four functions, three failures are a
    // majority — the third failure aborts the scan before the
    // fourth is even attempted: the breaker cuts the run off
    // rather than reporting after it.
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
    // The strongest-first order among the SEH detectors: the
    // thunk registration outranks the API call — one finding.
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
    // The guard rail asserted through the scan itself: the canary
    // family — alone, and beside a real thunk registration it
    // must not affect — yields no SEH finding. The GS body
    // itself claims nothing; the thunk function next to it keeps
    // its honest one finding.
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
    // The finding records the join block it converged on — the
    // label Ghidra printed — in both record and accessor.
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
    // One function, both readings fire — the spelled frame and
    // the cleanup ladder stand beside each other as two
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
    // Extensible release vocabulary, asserted through the scan
    // itself: a scan configured with a custom release name reads
    // a ladder whose join block releases through that name.
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
    // The guard rails, asserted through the scan itself: the
    // canary body's single guarded forward goto has no join block
    // behind it, and plain straight-line flow claims nothing — the
    // ladder stays quiet where the other readings stay quiet too.
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
    // carry the bands, ranking spelled block above named handler
    // above API call — observable through the document, which is
    // how a reviewer (and the future prompt section) ranks what
    // it is shown.
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
    // every family in one program — a propagation pair included, so
    // the inherited block is part of the equality too (#291) —
    // scanned twice, lands the same findings in the same order.
    let source = FakeProgram {
        functions: vec![
            summary("spelled"),
            summary("named"),
            summary("raiser"),
            summary("coded"),
            summary("plain"),
            summary("api_only"),
            summary("carrier"),
        ],
        bodies: HashMap::from([
            ("spelled".to_string(), SEH_BODY.to_string()),
            ("named".to_string(), THUNK_BODY.to_string()),
            ("raiser".to_string(), RAISE_BODY.to_string()),
            ("coded".to_string(), CODED_RAISE_BODY.to_string()),
            ("plain".to_string(), "  run();\n".to_string()),
            ("api_only".to_string(), API_BODY.to_string()),
            (
                "carrier".to_string(),
                "  return coded(param_1);\n".to_string(),
            ),
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
    assert_eq!(
        names,
        vec![
            "spelled", "named", "raiser", "coded", "coded", "api_only", "carrier"
        ],
        "the coded function's raise finding and its one code record both key to it, \
             and the carrier's one inherited record lands last, after every per-function finding"
    );
    assert_eq!(
        first
            .findings
            .last()
            .expect("the inherited record comes last")
            .kind(),
        "inherited_error_code",
        "the propagated record is in the compared set — two scans diff cleanly over it too"
    );
}

#[tokio::test]
async fn provenance_lands_on_the_result() {
    // Issue #208's shared rule, asserted through this scan:
    // the source's analysis-engine stamp reaches the scan
    // result. A `ScanSource` that names its analysis engine gets
    // the stamp verbatim — the real Kuna-backed source names
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

#[tokio::test]
async fn one_record_per_code_at_its_strongest_site_across_a_whole_body() {
    // The issue's one-record-per-code rule, asserted through
    // the scan itself: the same code at several sites lands once,
    // at the site that carries the evidence most strongly; a
    // second distinct code lands its own record beside it.
    let source = FakeProgram {
            functions: vec![summary("coded")],
            bodies: HashMap::from([(
                "coded".to_string(),
                "  hr = 0x80070005;\n  if (hr == 0xc0000022 || hr == 0x80070005) goto cleanup;\n  *output = 1;\n  return 0x80070005;\n".to_string(),
            )]),
            ..FakeProgram::default()
        };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    assert_eq!(result.findings.len(), 2, "two distinct codes, two records");
    let mut codes: Vec<u32> = result
        .findings
        .iter()
        .map(|f| match f {
            crate::ErrhandlingFinding::ErrorCode(c) => c.code,
            other => panic!("only code records expected, got {other:?}"),
        })
        .collect();
    codes.sort();
    assert_eq!(codes, vec![0x8007_0005, 0xc000_0022]);
    let guard = result
        .findings
        .iter()
        .find(|f| matches!(f, crate::ErrhandlingFinding::ErrorCode(c) if c.code == 0xc000_0022))
        .expect("the guard code is recorded");
    assert_eq!(guard.confidence(), crate::ERROR_CODE_GUARD_CONFIDENCE);
    let returned = result
        .findings
        .iter()
        .find(|f| matches!(f, crate::ErrhandlingFinding::ErrorCode(c) if c.code == 0x8007_0005))
        .expect("the returned code lands");
    assert_eq!(
        returned.confidence(),
        crate::ERROR_CODE_RETURN_CONFIDENCE,
        "first sighted in a guard comparison, returned from the function later — the return reading wins the one record",
    );
}

#[tokio::test]
async fn code_records_land_for_a_body_the_other_detectors_claim_nothing_about() {
    // The issue's no-idiom-shape rule, asserted through the scan
    // itself: a function that hands back a shaped failure code but
    // has no SEH frame, no raise, no ladder, and no cleanup
    // goto still gets its code record — the code reading stands
    // on its own — and nothing else. The returned expression
    // carries a comparison, so the record honestly lands at the
    // guard band: the literal is the function's failure code,
    // and the line's shape keeps the claim modest.
    let source = FakeProgram {
        functions: vec![summary("coded")],
        bodies: HashMap::from([(
            "coded".to_string(),
            "  hres = QuerySomething(&buffer);\n  return hres == S_OK ? 0 : 0x80070005;\n"
                .to_string(),
        )]),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    assert_eq!(
        result.findings.len(),
        1,
        "the code record stands with no idiom finding beside it"
    );
    let finding = &result.findings[0];
    assert!(
        matches!(finding, crate::ErrhandlingFinding::ErrorCode(_)),
        "the finding is a code record, got {finding:?}"
    );
    assert_eq!(finding.function(), "coded");
    assert_eq!(finding.confidence(), crate::ERROR_CODE_GUARD_CONFIDENCE);
}

#[tokio::test]
async fn codes_follow_the_listing_into_grouped_body_order() {
    // The issue's ordering rule, asserted through the scan itself:
    // every code-bearing function's records land keyed to the
    // function in listing order, the codes within each function
    // in body order — the property
    // `two_scans_of_one_program_diff_cleanly` relies on, for codes.
    let source = FakeProgram {
        functions: vec![summary("first"), summary("second")],
        bodies: HashMap::from([
            (
                "first".to_string(),
                "  if (a == 0xc0000022) return a;\n  return 0x80070057;\n".to_string(),
            ),
            ("second".to_string(), "  return 0x80070005;\n".to_string()),
        ]),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let shaped: Vec<(String, u32)> = result
        .findings
        .iter()
        .map(|f| match f {
            crate::ErrhandlingFinding::ErrorCode(c) => (f.function().to_string(), c.code),
            other => panic!("only code records expected, got {other:?}"),
        })
        .collect();
    assert_eq!(
        shaped,
        vec![
            ("first".to_string(), 0xc000_0022),
            ("first".to_string(), 0x8007_0057),
            ("second".to_string(), 0x8007_0005),
        ],
        "listing order across functions, body order within one"
    );
}

#[tokio::test]
async fn code_records_sit_beside_idiom_findings_in_the_same_function() {
    // The issue's grouping rule, asserted through the scan itself: a
    // function carrying an idiom finding AND its failure codes gets
    // all of them, keyed to the function, codes in body order after
    // the detector chain's own findings.
    let source = FakeProgram {
            functions: vec![summary("raiser")],
            bodies: HashMap::from([(
                "raiser".to_string(),
                "  RaiseException(0x80070057, 0, NULL, 0);\n  *output = 1;\n  if (result == 0xc0000022) return result;\n  return 0x80070057;\n"
                    .to_string(),
            )]),
            ..FakeProgram::default()
        };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    assert_eq!(
        result.findings.len(),
        3,
        "one raise finding, two code records"
    );
    let matches: Vec<&str> = result
        .findings
        .iter()
        .map(|f| match f {
            crate::ErrhandlingFinding::RaiseException(_) => "raise",
            crate::ErrhandlingFinding::ErrorCode(c) if c.code == 0x8007_0057 => "invalid_arg",
            crate::ErrhandlingFinding::ErrorCode(c) if c.code == 0xc000_0022 => "access_denied",
            other => panic!("unexpected finding shape: {other:?}"),
        })
        .collect();
    assert_eq!(matches, vec!["raise", "invalid_arg", "access_denied"]);
    assert!(
        result.findings.iter().all(|f| f.function() == "raiser"),
        "every record is keyed to the one function"
    );
}

#[tokio::test]
async fn a_guard_compare_carries_the_callees_code_onto_the_caller() {
    // Issue #291, asserted through the scan itself: the caller's
    // own guard reading stays its first-hand record, and beside
    // it sits the inherited one — same code, the penalised band,
    // the callee recorded as its partner and the call site as evidence.
    let source = FakeProgram {
            functions: vec![summary("callee"), summary("caller")],
            bodies: HashMap::from([
                (
                    "callee".to_string(),
                    "  hr = NtQuery(handle);\n  if (hr == 0xc0000022) return hr;\n  return 0x80070057;\n"
                        .to_string(),
                ),
                (
                    "caller".to_string(),
                    "  if (callee(param_1) == 0x80070057) {\n    fail();\n  }\n  return 0;\n"
                        .to_string(),
                ),
            ]),
            ..FakeProgram::default()
        };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let caller: Vec<&ErrhandlingFinding> = result
        .findings
        .iter()
        .filter(|f| f.function() == "caller")
        .collect();
    let kinds: Vec<&str> = caller.iter().map(|f| f.kind()).collect();
    assert_eq!(
        kinds,
        vec!["error_code", "inherited_error_code"],
        "the caller's own guard record first, the inherited one appended behind it"
    );
    assert_eq!(
        caller[1].confidence().value(),
        crate::INHERITED_ERROR_CODE_CONFIDENCE
    );
    let record = match caller[1] {
        ErrhandlingFinding::InheritedErrorCode(record) => record,
        other => panic!("expected an inherited record, got {other:?}"),
    };
    assert_eq!(
        record.partner, "callee",
        "the record names the callee it came from"
    );
    assert_eq!(record.code, 0x8007_0057);
    assert_eq!(
        record.evidence, "if (callee(param_1) == 0x80070057) {",
        "the call-site line the guard stands on is the evidence"
    );
    // The callee keeps its own two records under its own name.
    assert_eq!(
        result
            .findings
            .iter()
            .filter(|f| f.function() == "callee")
            .count(),
        2
    );
}

#[tokio::test]
async fn inherited_records_append_after_every_per_function_record() {
    // The listing keeps the caller ahead of its callee, and the
    // per-function block still follows the listing — but the
    // caller's inherited record lands after the late callee's own
    // findings: the propagation block is last, whatever the
    // listing order, so two scans of one program diff cleanly.
    let source = FakeProgram {
        functions: vec![summary("caller"), summary("callee")],
        bodies: HashMap::from([
            (
                "caller".to_string(),
                "  hr = callee();\n  if (hr == 0x80070057) fail();\n  return 0;\n".to_string(),
            ),
            (
                "callee".to_string(),
                "  return 0x80070057;\n  return 0xc0000022;\n".to_string(),
            ),
        ]),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let names: Vec<&str> = result.findings.iter().map(|f| f.function()).collect();
    assert_eq!(
        names,
        vec!["caller", "callee", "callee", "caller"],
        "per-function findings in listing order first, the inherited block after them"
    );
    assert_eq!(
        result.findings.last().unwrap().kind(),
        "inherited_error_code"
    );
    assert!(
        result.findings[..result.findings.len() - 1]
            .iter()
            .all(|f| f.kind() != "inherited_error_code")
    );
}

#[tokio::test]
async fn the_first_inheritance_path_claims_a_code_and_the_second_stays_quiet() {
    // Two paths would carry the same (caller, code) pair: the
    // guard comparing a's code, and the re-return handing back
    // b's whole set. One claim per code, first in scan order
    // wins: the record keeps a as partner, b's path adds nothing.
    let source = FakeProgram {
        functions: vec![summary("a"), summary("b"), summary("caller")],
        bodies: HashMap::from([
            ("a".to_string(), "  return 0x80070057;\n".to_string()),
            ("b".to_string(), "  return 0x80070057;\n".to_string()),
            (
                "caller".to_string(),
                "  if (a(param_1) == 0x80070057) { fail(); }\n  return b(param_1);\n".to_string(),
            ),
        ]),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let inherited: Vec<&str> = result
        .findings
        .iter()
        .filter(|f| f.kind() == "inherited_error_code")
        .map(|f| match f {
            ErrhandlingFinding::InheritedErrorCode(record) => record.partner.as_str(),
            _ => unreachable!("kind filter matched the wrong shape"),
        })
        .collect();
    assert_eq!(
        inherited,
        vec!["a"],
        "the guard path claimed the code first; the re-return of b claims nothing"
    );
}

#[tokio::test]
async fn an_unread_callee_contributes_nothing_to_its_caller() {
    // A callee the scan could not decompile never enters the kept
    // set: it records nothing, so it inherits nothing on. The
    // caller still keeps its own first-hand guard record, the
    // rest of the scan proceeds, and no inherited record lists
    // the unread function as its partner.
    let source = FakeProgram {
        functions: vec![summary("caller"), summary("callee"), summary("spare")],
        bodies: HashMap::from([
            (
                "caller".to_string(),
                "  if (callee(param_1) == 0x80070057) { fail(); }\n  return 0;\n".to_string(),
            ),
            ("spare".to_string(), "  run();\n".to_string()),
        ]),
        fail_decompiles: vec!["callee".to_string()],
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("one skip of three must not trip the breaker");
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.kind() != "inherited_error_code"),
        "nothing propagates from a callee the scan never read"
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.function() == "caller" && f.kind() == "error_code"),
        "the caller's own reading stands untouched"
    );
}

#[tokio::test]
async fn a_callees_idioms_never_join_the_caller() {
    // Codes travel, idioms never: a callee spelling the frame,
    // raising, and returning a code keeps all three readings
    // under its own name, and the caller re-returning its value
    // inherits only the code.
    let source = FakeProgram {
        functions: vec![summary("callee"), summary("caller")],
        bodies: HashMap::from([
            (
                "callee".to_string(),
                format!(
                    "{}  RaiseException(0xe06d7363, 0, NULL, 0);\n  return 0x80070057;\n",
                    SEH_BODY
                ),
            ),
            (
                "caller".to_string(),
                "  return callee(param_1);\n".to_string(),
            ),
        ]),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let callee_kinds: Vec<&str> = result
        .findings
        .iter()
        .filter(|f| f.function() == "callee")
        .map(|f| f.kind())
        .collect();
    assert_eq!(
        callee_kinds,
        vec!["seh_frame", "raise_exception", "error_code"]
    );
    let caller_kinds: Vec<&str> = result
        .findings
        .iter()
        .filter(|f| f.function() == "caller")
        .map(|f| f.kind())
        .collect();
    assert_eq!(
        caller_kinds,
        vec!["inherited_error_code"],
        "the caller inherits the code alone — the frame and raise stay with the body that spelled them"
    );
}

// ============================================================
// Admitted scan coverage (issue #350)
// ============================================================

/// The data-level verdict of the roster pin: empty means the record
/// names every declared facet exactly once, and each fault reports
/// one way the record has drifted from the declared roster.
fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
    coverage.roster_faults(DECLARED_FACETS)
}

#[tokio::test]
async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
    // The scan stamps its own coverage — not the registry row and
    // not the CLI: the batch scan phase and the CLI's
    // force-rescan file the same admission through this one
    // definition. Every body was read here, so the record is
    // complete and says nothing needs admitting.
    let source = FakeProgram {
        functions: vec![summary("ok")],
        bodies: HashMap::from([("ok".to_string(), SEH_BODY.to_string())]),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let coverage = result
        .metadata
        .coverage
        .expect("a fresh error-handling scan states its coverage");
    assert_eq!(coverage.status, CoverageStatus::Complete);
    assert!(
        roster_faults(&coverage).is_empty(),
        "a fresh document must name every declared facet exactly once"
    );
    let bodies = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(bodies.status, CoverageStatus::Complete);
    assert_eq!(
        bodies.limitation, None,
        "a scan that read every body admits nothing — and silence now \
             means examined-and-clean, not unchecked"
    );
}

#[tokio::test]
async fn a_decompiled_failure_is_admitted_by_name_on_the_coverage_record() {
    // The whole point of the admission: a body the scan could not
    // read is named, so it is never mistaken for an examined-and-
    // clean function that the findings simply left unmentioned.
    let source = FakeProgram {
        functions: vec![summary("ok"), summary("thunk")],
        bodies: HashMap::from([("ok".to_string(), SEH_BODY.to_string())]),
        fail_decompiles: vec!["thunk".to_string()],
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("one decompile failure must not abort the scan");
    let coverage = result
        .metadata
        .coverage
        .expect("a partial error-handling scan states its coverage too");
    assert_eq!(
        coverage.status,
        CoverageStatus::Partial,
        "the whole picture mirrors the one facet it examined"
    );
    assert!(
        roster_faults(&coverage).is_empty(),
        "a partial scan still names every declared facet exactly once"
    );
    let bodies = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(bodies.status, CoverageStatus::Partial);
    assert_eq!(
        bodies.limitation.as_deref(),
        Some("1 function body unreached: thunk"),
        "the unreached body is named, and only the unreached body"
    );
}

#[tokio::test]
async fn the_coverage_line_is_capped_at_five_names_and_counts_the_nameless() {
    // Bounded prose beside the counts: six decompile failures name
    // five inline and fold the sixth into a count, and a nameless
    // listing entry counts toward the total without stealing a name
    // slot.
    let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
    let mut functions: Vec<FunctionSummary> = names.iter().map(|name| summary(name)).collect();
    let bodies: HashMap<String, String> = names[6..]
        .iter()
        .map(|name| (name.clone(), "  return;\n".to_string()))
        .collect();
    functions.push(summary(""));
    let source = FakeProgram {
        functions,
        bodies,
        fail_decompiles: names[..6].to_vec(),
        ..FakeProgram::default()
    };
    let result = ErrhandlingEngine::with_source(source)
        .scan("test.exe")
        .await
        .expect("scan must succeed");
    let bodies = result
        .metadata
        .coverage
        .expect("a partial error-handling scan states its coverage")
        .facets
        .into_iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(bodies.status, CoverageStatus::Partial);
    assert_eq!(
        bodies.limitation.as_deref(),
        Some(
            "7 function bodies unreached: FUN_body_0000, FUN_body_0001, \
                 FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more"
        ),
        "six named failures plus one nameless entry: five names, the \
             rest counted, the count covering both"
    );
}

#[test]
fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
    let mut coverage = coverage_stamp(&[], 0);
    coverage
        .facets
        .retain(|facet| facet.id != "function-bodies");
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `function-bodies` is missing from the record"],
        "an engine quietly dropping its one facet fails loudly"
    );
}

#[test]
fn the_roster_pin_fails_when_a_facet_is_doubled() {
    let mut coverage = coverage_stamp(&["thunk".to_string()], 0);
    coverage.facets.push(coverage.facets[0].clone());
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `function-bodies` appears 2 times in the record"],
        "a facet crowded into two entries fails loudly"
    );
}

#[test]
fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
    let mut coverage = coverage_stamp(&[], 0);
    coverage.facets.push(FacetCoverage {
        id: "seh-frames".to_string(),
        status: CoverageStatus::Complete,
        limitation: None,
    });
    assert_eq!(
        roster_faults(&coverage),
        ["record names `seh-frames`, a facet the engine never declared"],
        "an entry outside the declared roster fails loudly — SEH frames \
             are findings read off the bodies, not a region the scan reads \
             on its own"
    );
}

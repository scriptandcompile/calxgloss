//! Known-library identification scan orchestration.
//!
//! [`LibmatchEngine`] runs the body-signature matcher over every function
//! of one loaded program and assembles its findings into a single
//! [`LibmatchResult`] with its scan provenance.
//!
//! The matcher is pure text analysis over one decompiled body, so the
//! engine fetches each function's pseudo-C exactly once. The scan is one
//! sequential pass over the function listing: keeping the pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order, and where two signatures claim one function the resolution
//! step ([`resolve_matches`](crate::confidence::resolve_matches)) keeps
//! only the strongest claim, standing where the function first appeared.

use std::time::Instant;

use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use tracing::{info, warn};

use crate::error::Result;
use crate::matcher::LibmatchMatcher;
use crate::types::{LibmatchFinding, LibmatchResult, ScanMetadata};

/// The decompiler reads a known-library identification scan performs.
///
/// The shared trait from the decompiler seam crate, re-exported here so
/// the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// Orchestrates the body-signature matcher into one [`LibmatchResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one
/// over a loaded [`KunaSource`]. The matcher carries no state and starts
/// with the built-in starter set —
/// [`with_matcher`](Self::with_matcher) swaps the set whole — so one
/// instance serves the whole scan.
#[derive(Debug, Clone)]
pub struct LibmatchEngine<S = KunaSource> {
    source: S,
    matcher: LibmatchMatcher,
}

impl LibmatchEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the built-in
    /// starter signature set.
    pub fn new(source: &KunaSource) -> LibmatchEngine<KunaSource> {
        LibmatchEngine {
            source: source.clone(),
            matcher: LibmatchMatcher::with_default_signatures(),
        }
    }
}

impl<S> LibmatchEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with the
    /// built-in starter signature set.
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
    /// standing where the function first appeared.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning; only a failure of the
    /// listing itself — the engine being down — aborts the run, since
    /// then nothing was scanned. But when more than half the listing
    /// fails to decompile, the skip-rate breaker aborts the run too:
    /// that is the signature of the engine answering from the wrong
    /// program, and skipping on would persist a phantom-clean record
    /// (issue #71).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<LibmatchResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings: Vec<LibmatchFinding> = Vec::new();
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
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading a program
                    // the engine cannot analyze, and an empty result
                    // would persist as a phantom-clean record. Abort
                    // with the counts instead of skipping on.
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
        }

        // Two signatures can fit one body; one function is one function,
        // so the strongest claim per function stands, in listing order
        // (ADR-0022's precedent).
        let findings = crate::confidence::resolve_matches(findings);

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
            "Identified known-library functions"
        );
        Ok(LibmatchResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::LibmatchMatcher;
    use crate::signature::LibmatchSignature;
    use crate::types::LibraryFamily;
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;

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

    /// A canned program implementing [`ScanSource`], so the whole
    /// orchestration runs without a server.
    #[derive(Clone, Default)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        fail_decompiles: Vec<String>,
        fail_listing: bool,
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
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

        // The fake source names itself, so the tests can pin that
        // scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
        }
    }

    /// The MSVC CRT byte-copy loop as Ghidra decompiles it: a countdown,
    /// a dereference assignment, and a `!= 0` loop test, with no guard
    /// branch.
    const MEMCPY_BODY: &str = "\
  puVar1 = param_1 + 1;
  lVar2 = param_2 + 1;
  do {
    param_3 = param_3 + -1;
    *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);
    lVar2 = lVar2 + 8;
    puVar1 = puVar1 + 8;
  } while (param_3 != 0);
  return param_1;
";

    /// The same copy loop as a different function's decompile: different
    /// Ghidra variable names, a register temporary, and a volatile
    /// data-address write — nothing that is part of the routine's shape.
    const MEMCPY_LOOKALIKE_BODY: &str = "\
  uVar4 = DAT_180047b10;
  puVar7 = param_1 + 1;
  lVar9 = param_2 + 1;
  in_DL = 0x180045a68;
  do {
    param_3 = param_3 + -1;
    *(undefined8 *)((long)puVar7 + -8) = *(undefined8 *)((long)lVar9 + -8);
    lVar9 = lVar9 + 8;
    puVar7 = puVar7 + 8;
  } while (param_3 != 0);
  return param_1;
";

    /// A body that is not a library routine: a plain function.
    const PLAIN_BODY: &str = "  return;\n";

    /// A copy loop with a guard branch — the overlap check that makes
    /// the shape a memmove, which the starter set does not claim.
    const GUARDED_COPY_BODY: &str = "\
  puVar1 = param_1;
  if (param_2 < param_1) {
    puVar1 = param_1 + param_3;
    param_2 = param_2 + param_3;
  }
  do {
    param_3 = param_3 + -1;
    *(undefined *)((long)puVar1 + -1) = *(undefined *)((long)param_2 + -1);
  } while (param_3 != 0);
  return param_1;
";

    /// The canned program: one function whose body is the memcpy idiom,
    /// one plain function that matches nothing, and one guarded copy
    /// the starter set vetoes.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::default();
        program.listing = vec![
            summary("FUN_18003ab00"),
            summary("FUN_18003e750"),
            summary("FUN_1800412a0"),
        ];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined8 * __fastcall FUN_18003ab00(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_BODY,
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "undefined FUN_18003e750(void)", PLAIN_BODY),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined8 * __fastcall FUN_1800412a0(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                GUARDED_COPY_BODY,
            ),
        );
        program
    }

    async fn scan(program: FakeProgram) -> LibmatchResult {
        LibmatchEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    #[tokio::test]
    async fn a_body_matching_a_builtin_signature_lands_a_finding() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&LibmatchFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1, "the memcpy idiom matches one signature");
        let finding = findings[0];
        assert_eq!(finding.kind(), "body_signature");
        assert_eq!(finding.target(), "memcpy");
        assert_eq!(finding.family(), LibraryFamily::Crt);
        // The standard body-evidence score.
        assert_eq!(
            finding.confidence().value(),
            crate::confidence::BODY_MATCH_CONFIDENCE
        );
        assert!(!finding.evidence().is_empty());
        assert!(finding.evidence().contains("= *(undefined8"));
        assert!(!finding.suggestion().is_empty());
    }

    #[tokio::test]
    async fn unmatched_bodies_land_no_findings() {
        let result = scan(program()).await;

        // The plain function and the guarded copy (a memmove shape the
        // starter set vetoes) carry nothing, and the scan changes
        // nothing else about the result.
        assert!(result.for_function("FUN_18003e750").next().is_none());
        assert!(result.for_function("FUN_1800412a0").next().is_none());
        assert_eq!(result.findings.len(), 1);
    }

    #[tokio::test]
    async fn bodies_differing_only_in_names_temporaries_and_addresses_match_the_same_signature() {
        // Two decompiles of the same routine: different Ghidra variable
        // names, a register temporary, and a volatile data address in
        // one, plain names in the other. Both must land the same
        // finding — asserted through scan findings, never through
        // normalization internals.
        let mut program = program();
        program.listing.push(summary("FUN_180098765"));
        program.bodies.insert(
            "FUN_180098765".into(),
            function(
                "FUN_180098765",
                "undefined8 * __fastcall FUN_180098765(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_LOOKALIKE_BODY,
            ),
        );
        let result = scan(program).await;

        for name in ["FUN_18003ab00", "FUN_180098765"] {
            let findings: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(findings.len(), 1, "{name} must match the memcpy signature");
            assert_eq!(findings[0].target(), "memcpy");
            assert_eq!(findings[0].family(), LibraryFamily::Crt);
        }
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry the memcpy idiom, so the persisted list
        // must group their findings by function in listing order —
        // never interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined8 * __fastcall FUN_18003e750(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_LOOKALIKE_BODY,
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
                ("FUN_18003e750", "body_signature"),
                ("FUN_18003ab00", "body_signature"),
            ]
        );
    }

    #[tokio::test]
    async fn competing_matches_for_one_function_resolve_to_the_strongest() {
        // A broad copy-loop shape and the memcpy signature both claim
        // the same function; the scan reports the stronger claim once,
        // standing where the function first appeared (ADR-0022).
        let matcher = LibmatchMatcher::with_signatures([
            LibmatchSignature::new("copy_loop", LibraryFamily::Crt, [r"while \("], "slice copy")
                .with_confidence(60),
            LibmatchSignature::new(
                "memcpy",
                LibraryFamily::Crt,
                [
                    r"VAR = VAR \+ -1",
                    r"\*\([^;]*\) = \*\(",
                    r"while \(VAR != 0\)",
                ],
                "slice copy",
            )
            .with_confidence(70),
        ]);
        let result = LibmatchEngine::with_source(program())
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<&LibmatchFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(claims.len(), 1, "one claim per function");
        assert_eq!(claims[0].target(), "memcpy");
        assert_eq!(claims[0].confidence().value(), 70);
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by detection.
        let mut program = program();
        program.fail_listing = true;
        let result = LibmatchEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::LibmatchError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::default()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // The thunk that will not decompile passes unrecorded; the
        // memcpy function beside it still lands its finding.
        let mut program = program();
        program.listing.insert(0, summary("thunk_180010000"));
        program.fail_decompiles.push("thunk_180010000".into());
        let result = scan(program).await;

        assert!(result.for_function("thunk_180010000").next().is_none());
        assert_eq!(result.for_function("FUN_18003ab00").count(), 1);
    }

    #[tokio::test]
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The skip-rate breaker: most of the listing failing to
        // decompile is the engine answering from the wrong program, and
        // an empty result would persist as a phantom-clean record.
        let mut program = program();
        program.fail_decompiles = program
            .listing
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        let result = LibmatchEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        // The breaker trips as soon as most of the listing has failed —
        // two of three — not only after all of them.
        assert!(matches!(
            result,
            Err(crate::LibmatchError::DecompileBreaker {
                failed: 2,
                total: 3
            })
        ));
    }

    #[tokio::test]
    async fn the_scan_stamps_its_provenance() {
        let result = scan(program()).await;
        let engine = result
            .metadata
            .engine
            .expect("the fake source names its engine");
        assert_eq!(engine.name, "fake-engine");
        assert_eq!(engine.version.as_deref(), Some("9.9"));
        assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
    }
}

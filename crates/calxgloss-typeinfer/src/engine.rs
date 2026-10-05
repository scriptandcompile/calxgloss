//! Type inference orchestration.
//!
//! [`TypeInferEngine`] runs the three detectors — this-pointer detection,
//! parameter-size detection, and known-type propagation — over every
//! function of one open Ghidra program and assembles their records into a
//! single [`TypeInferenceResult`] with its scan provenance.
//!
//! The detectors are pure text analysis over one decompiled body, so the
//! engine fetches each function's pseudo-C exactly once and reads it with
//! all three, rather than having each detector pull its own copy. The scan
//! is then one pass over the function listing: there are no disjoint
//! endpoint sets to overlap the way the type-database scans have, and
//! keeping the pass sequential keeps the persisted inference list in a
//! stable, diffable order.

use crate::confidence::resolve_conflicts;
use crate::error::Result;
use crate::known_type::KnownTypePropagationEngine;
use crate::param_size::ParameterSizeDetector;
use crate::this_ptr::ThisPointerDetector;
use crate::types::{InferredType, ScanMetadata, TypeInferenceResult};
use calxgloss_ghidra::{DecompiledFunction, FunctionSummary, GhidraClient};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler reads a type-inference scan performs.
///
/// [`GhidraClient`] implements it directly; tests implement it over canned
/// bodies so the orchestration runs without a server. The futures are `Send`
/// so a scan can be driven from an orchestrating task.
pub trait DecompileSource {
    /// Every function in the program, in listing order.
    fn functions(&self) -> impl std::future::Future<Output = Result<Vec<FunctionSummary>>> + Send;

    /// The pseudo-C for one function, by name.
    fn decompile(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<DecompiledFunction>> + Send;
}

impl DecompileSource for GhidraClient {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.list_functions().await?)
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        Ok(self.decompile_function_by_name(name).await?)
    }
}

/// Orchestrates the three detectors into one [`TypeInferenceResult`].
///
/// The engine is generic over its [`DecompileSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one over
/// a live [`GhidraClient`]. The detectors carry no state, so one instance of
/// each serves the whole scan.
#[derive(Debug, Clone)]
pub struct TypeInferEngine<S = GhidraClient> {
    source: S,
    this_ptr: ThisPointerDetector,
    param_size: ParameterSizeDetector,
    known: KnownTypePropagationEngine,
}

impl TypeInferEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client.
    pub fn new(client: &GhidraClient) -> TypeInferEngine<GhidraClient> {
        TypeInferEngine {
            source: client.clone(),
            this_ptr: ThisPointerDetector::new(),
            param_size: ParameterSizeDetector::new(),
            known: KnownTypePropagationEngine::new(),
        }
    }
}

impl<S> TypeInferEngine<S> {
    /// An engine whose decompiles come from `source`.
    pub fn with_source(source: S) -> Self {
        TypeInferEngine {
            source,
            this_ptr: ThisPointerDetector::new(),
            param_size: ParameterSizeDetector::new(),
            known: KnownTypePropagationEngine::new(),
        }
    }

    /// Infer parameter types across `binary`, decompiling each function
    /// exactly once and reading it with all three detectors.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The inferences
    /// follow the function listing — function by function, and within one
    /// function the this-pointer readings, then the size readings, then the
    /// known-signature readings — so two scans of the same program diff
    /// cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad entry
    /// point) is skipped with a warning; only a failure of the listing
    /// itself — the server being down — aborts the run, since then nothing
    /// was scanned. Where several detectors read one parameter differently
    /// — `strlen`'s argument stands read by the size detector and the
    /// known-signature engine at once — conflict resolution collapses the
    /// competition to the strongest record before the result is assembled,
    /// so the result carries at most one inference per parameter.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<TypeInferenceResult>
    where
        S: DecompileSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut inferences = Vec::new();
        let mut skipped = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing can
                // be inferred about it, so it passes unrecorded.
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

            let readings = self
                .this_ptr
                .detect_this_pointer(&decompiled)
                .into_iter()
                .chain(self.param_size.detect_parameter_sizes(&decompiled))
                .chain(self.known.propagate_known_types(&decompiled));
            inferences.extend(readings.map(InferredType::Param));
        }

        // The detectors read each body independently, so one parameter can
        // stand read several times over; the result carries only the
        // strongest reading per parameter.
        let collected = inferences.len();
        let inferences = resolve_conflicts(inferences);

        let mut metadata = ScanMetadata::new(binary);
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            inferences = inferences.len(),
            conflicts_resolved = collected - inferences.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Inferred parameter types"
        );
        Ok(TypeInferenceResult {
            metadata,
            inferences,
        })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, InferenceMethod, InferenceScope};
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

    /// State shared by every clone of a [`FakeProgram`], so a test can read
    /// what the scan did after the engine has consumed its source.
    #[derive(Debug, Default)]
    struct Stats {
        decompiles: Mutex<Vec<String>>,
    }

    /// A canned program implementing [`DecompileSource`], so the whole
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

    impl DecompileSource for FakeProgram {
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

    /// The canned program: one function whose body carries a vtable
    /// dispatch, a `strlen` call, and a `CloseHandle` call — one reading
    /// family per detector — and one plain function that infers nothing.
    fn program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(undefined8 param_1,undefined8 param_2,undefined8 param_3)",
                "  (**(code **)*param_1)(param_1);\n\
                 \x20 strlen(param_2);\n\
                 \x20 CloseHandle(param_3);\n",
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

    async fn scan(program: FakeProgram) -> TypeInferenceResult {
        TypeInferEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    fn finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
        method: InferenceMethod,
        param_index: usize,
    ) -> &'a InferredType {
        result
            .for_function(function)
            .find(|inference| match inference {
                InferredType::Param(record) => {
                    record.method == method && record.param_index == param_index
                }
                _ => false,
            })
            .expect("record from that detector")
    }

    fn param_count(result: &TypeInferenceResult, function: &str, param_index: usize) -> usize {
        result
            .for_function(function)
            .filter(|inference| {
                matches!(
                    inference,
                    InferredType::Param(record) if record.param_index == param_index
                )
            })
            .count()
    }

    #[tokio::test]
    async fn scan_collects_records_from_all_three_detectors() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let this_ptr = finding(&result, "FUN_18003ab00", InferenceMethod::VtableCall, 0);
        let InferredType::Param(record) = this_ptr else {
            unreachable!("the this-pointer detector emits parameter records");
        };
        assert_eq!(record.param_index, 0);
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.scope, InferenceScope::Class);
        assert!(record.is_this_pointer());

        let size = finding(&result, "FUN_18003ab00", InferenceMethod::StringFunction, 1);
        let InferredType::Param(record) = size else {
            unreachable!("the size detector emits parameter records");
        };
        assert_eq!(record.param_index, 1);
        assert_eq!(record.inferred_type, "char *");

        // `strlen` is a string-function call and a known signature at once,
        // so the same parameter stands read twice, both at 70; the readings
        // tie and conflict resolution keeps the one the scan showed first —
        // the size detector's.
        assert_eq!(param_count(&result, "FUN_18003ab00", 1), 1);

        // The vtable dispatch's first argument also carries a bare
        // dereference, so the size detector reads that parameter too; the
        // stronger this-pointer reading wins the conflict.
        assert_eq!(param_count(&result, "FUN_18003ab00", 0), 1);

        let known = finding(&result, "FUN_18003ab00", InferenceMethod::KnownSignature, 2);
        let InferredType::Param(record) = known else {
            unreachable!("the propagation engine emits parameter records");
        };
        assert_eq!(record.param_index, 2);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.scope, InferenceScope::Program);

        assert!(result.for_function("FUN_18003e750").next().is_none());
    }

    #[tokio::test]
    async fn conflicting_readings_for_one_parameter_resolve_to_the_strongest() {
        // One parameter stands read by two detectors at different
        // strengths — `strlen`'s `char *` at 70 and `CloseHandle`'s
        // `void *` at 75 — and only the stronger survives the scan.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_1800412a0")];
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(undefined8 param_1)",
                "  strlen(param_1);\n  CloseHandle(param_1);\n",
            ),
        );
        let result = scan(program).await;

        let records: Vec<&InferredType> = result.for_function("FUN_1800412a0").collect();
        assert_eq!(records.len(), 1);
        let InferredType::Param(record) = records[0] else {
            unreachable!("the detectors emit parameter records");
        };
        assert_eq!(record.method, InferenceMethod::KnownSignature);
        assert_eq!(record.inferred_type, "void *");
        assert_eq!(record.confidence, Confidence::new(75));
    }

    #[tokio::test]
    async fn scan_decompiles_each_function_exactly_once() {
        // The three detectors share one fetch per function; a scan that
        // asked each detector for its own copy would triple the wall time.
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
    async fn scan_keeps_the_listing_order() {
        // Both functions infer something, so the persisted list must group
        // their records by function in listing order, never interleaved.
        let mut program = program();
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined FUN_18003e750(char *param_1)",
                "  strlen(param_1);\n",
            ),
        );
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        let result = scan(program).await;

        let mut functions: Vec<&str> = result
            .inferences
            .iter()
            .map(|inference| inference.function())
            .collect();
        functions.dedup();
        assert_eq!(functions, vec!["FUN_18003e750", "FUN_18003ab00"]);
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // Ghidra cannot produce a body for every function; one bad entry
        // point must not cost the whole program its scan.
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
        // An empty name would send the by-name lookup into an arbitrary
        // function's body, so the entry passes without a decompile.
        let mut program = program();
        program.listing.insert(0, summary(""));
        let result = scan(program.clone()).await;

        assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by inference.
        let mut program = program();
        program.fail_listing = true;
        let result = TypeInferEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::TypeInferError::Ghidra(GhidraError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::empty()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);
    }
}

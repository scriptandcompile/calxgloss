//! Type inference orchestration.
//!
//! [`TypeInferEngine`] runs the three inline detectors — this-pointer
//! detection, parameter-size detection, and known-type propagation — over
//! every function of one open Ghidra program, then runs the
//! cross-function pass: each function's surviving parameter readings
//! type the arguments at that callee's call sites, and the caller's own
//! parameter when the argument is one. Their records are assembled into
//! a single [`TypeInferenceResult`] with its scan provenance.
//!
//! The inline detectors are pure text analysis over one decompiled body,
//! so the engine fetches each function's pseudo-C exactly once and reads
//! it with all three, rather than having each detector pull its own copy
//! — and the cross-function pass re-reads those same bodies, keeping the
//! whole scan at one decompile per function. The inline pass is then one
//! sequential pass over the function listing: there are no disjoint
//! endpoint sets to overlap the way the type-database scans have, and
//! keeping the pass sequential keeps the persisted inference list in a
//! stable, diffable order.

use std::collections::HashMap;

use crate::confidence::resolve_conflicts;
use crate::cross_function::{CalleeParams, CrossFunctionPropagator};
use crate::error::Result;
use crate::known_type::KnownTypePropagationEngine;
use crate::param_size::ParameterSizeDetector;
use crate::this_ptr::ThisPointerDetector;
use crate::types::{InferredType, ScanMetadata, TypeInferenceResult};
use calxgloss_ghidra::{DecompiledFunction, GhidraClient};
use std::time::Instant;
use tracing::{info, warn};

/// The decompiler reads a type-inference scan performs.
///
/// The shared trait from the Ghidra integration crate, re-exported here
/// so the engine's generic shape names it where it always has;
/// [`GhidraClient`] implements it over the live HTTP API, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_ghidra::ScanSource;

/// Orchestrates the inline detectors and the cross-function pass into one
/// [`TypeInferenceResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one over
/// a live [`GhidraClient`]. The detectors carry no state, so one instance of
/// each serves the whole scan.
#[derive(Debug, Clone)]
pub struct TypeInferEngine<S = GhidraClient> {
    source: S,
    this_ptr: ThisPointerDetector,
    param_size: ParameterSizeDetector,
    known: KnownTypePropagationEngine,
    cross: CrossFunctionPropagator,
}

impl TypeInferEngine<GhidraClient> {
    /// An engine over a live GhidraMCP client.
    pub fn new(client: &GhidraClient) -> TypeInferEngine<GhidraClient> {
        TypeInferEngine {
            source: client.clone(),
            this_ptr: ThisPointerDetector::new(),
            param_size: ParameterSizeDetector::new(),
            known: KnownTypePropagationEngine::new(),
            cross: CrossFunctionPropagator::new(),
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
            cross: CrossFunctionPropagator::new(),
        }
    }

    /// Infer types across `binary`, decompiling each function exactly
    /// once and reading it with all three inline detectors, then
    /// propagating the surviving readings across function boundaries.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The inferences
    /// follow the function listing — function by function, and within one
    /// function the this-pointer readings, then the size readings, then
    /// the known-signature readings — with the cross-function records
    /// appended after the inline ones, in listing order, so two scans of
    /// the same program diff cleanly.
    ///
    /// A function whose body Ghidra cannot produce (a thunk, a bad entry
    /// point) is skipped with a warning; only a failure of the listing
    /// itself — the server being down — aborts the run, since then nothing
    /// was scanned.
    /// But when more than half the listing fails to decompile, the
    /// skip-rate breaker aborts the run too: that is the signature of
    /// the bridge answering from the wrong program, and skipping on
    /// would persist a phantom-clean record (issue #71).
    /// Where several detectors read one parameter differently
    /// — `strlen`'s argument stands read by the size detector and the
    /// known-signature engine at once — conflict resolution collapses the
    /// competition to the strongest record before the result is assembled,
    /// so the result carries at most one inference per parameter, local,
    /// or call-site argument. The cross-function pass propagates only
    /// those resolved survivors, and its own records compete with the
    /// inline ones for the same targets in the final resolution.
    pub async fn scan(&self, binary: impl Into<String>) -> Result<TypeInferenceResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut inferences = Vec::new();
        // The bodies stay in hand after the inline pass so the
        // cross-function pass can re-read them without a second decompile.
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
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
                    decompile_failures += 1;
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading the
                    // wrong program (or a half-broken server), and an
                    // empty result would persist as a phantom-clean
                    // record. Abort with the counts instead of
                    // skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::TypeInferError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
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
            bodies.push(decompiled);
        }

        // The detectors read each body independently, so one parameter can
        // stand read several times over; the cross-function pass only
        // propagates the strongest reading per parameter, so the inline
        // records resolve among themselves first.
        let mut collected = inferences.len();
        let inline = resolve_conflicts(inferences);
        let callee_params = surviving_param_readings(&inline);

        // Callee to caller: each body's calls to a user-defined callee
        // take that callee's surviving readings as the arguments' types,
        // and a caller's own parameter is read when the argument names
        // one. The bodies are the ones already decompiled — the scan
        // still visits each function exactly once.
        let mut propagated: Vec<InferredType> = Vec::new();
        for body in &bodies {
            propagated.extend(self.cross.propagate(body, &callee_params));
        }

        // The propagated records compete with the inline ones — one
        // parameter can stand read by its own body and by a callee's
        // contract at once — so the assembled list resolves once more,
        // and the result carries at most one inference per target.
        collected += propagated.len();
        let inferences = resolve_conflicts(inline.into_iter().chain(propagated).collect());

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

/// The surviving parameter readings grouped by the function carrying
/// them — the contracts the cross-function pass propagates. A callee
/// absent from the map is a library routine, a thunk, or a function no
/// detector read: it carries nothing to propagate.
fn surviving_param_readings(inferences: &[InferredType]) -> CalleeParams<'_> {
    let mut by_callee: CalleeParams<'_> = HashMap::new();
    for inference in inferences {
        if let InferredType::Param(record) = inference {
            by_callee
                .entry(record.function.as_str())
                .or_default()
                .push(record);
        }
    }
    by_callee
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, InferenceMethod, InferenceScope, InferredCallType};
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

    /// State shared by every clone of a [`FakeProgram`], so a test can read
    /// what the scan did after the engine has consumed its source.
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

    /// The canned program for the cross-function pass: a helper whose
    /// body reads its own parameters — `char *` at position 0, `void *`
    /// at position 1 — and a caller that invokes it with its own
    /// parameter, a local, a literal, a cast, and a nested call.
    fn cross_program() -> FakeProgram {
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1,undefined8 param_2)",
                "  uVar1 = strlen(param_1);\n  CloseHandle(param_2);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1,undefined8 param_2)",
                "  FUN_18004b210(param_1, local_8);\n\
                 \x20 FUN_18004b210(\"name\", (char *)param_2);\n\
                 \x20 FUN_18004b210(get_name(), 0x10);\n",
            ),
        );
        program
    }

    fn call_site_finding<'a>(
        result: &'a TypeInferenceResult,
        function: &str,
        callee: &str,
        arg_index: usize,
    ) -> &'a InferredCallType {
        result
            .for_function(function)
            .find_map(|inference| match inference {
                InferredType::CallSite(record)
                    if record.callee == callee && record.arg_index == arg_index =>
                {
                    Some(record)
                }
                _ => None,
            })
            .expect("call-site record")
    }

    fn call_site_count(result: &TypeInferenceResult, function: &str) -> usize {
        result
            .for_function(function)
            .filter(|inference| matches!(inference, InferredType::CallSite(_)))
            .count()
    }

    #[tokio::test]
    async fn a_callee_s_surviving_reading_types_the_arguments_at_its_call_sites() {
        let program = cross_program();
        let result = scan(program.clone()).await;

        // The helper's own readings survive as before.
        assert_eq!(
            finding(&result, "FUN_18004b210", InferenceMethod::StringFunction, 0).inferred_type(),
            "char *"
        );

        // The call-site record: the helper's `char *` reading types the
        // first argument, with the call line as evidence.
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.arg_name.as_deref(), Some("param_1"));
        assert_eq!(site.inferred_type, "char *");
        assert_eq!(site.method, InferenceMethod::CrossFunction);
        assert_eq!(site.scope, InferenceScope::Function);
        assert_eq!(site.confidence, Confidence::new(70));
        assert_eq!(site.evidence, "FUN_18004b210(param_1, local_8);");

        // The second position takes the helper's `void *` reading; the
        // argument is a local, so no parameter record rides along.
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 1);
        assert_eq!(site.arg_name.as_deref(), Some("local_8"));
        assert_eq!(site.inferred_type, "void *");

        // The argument that is the caller's own parameter gets a
        // parameter record too — the type climbing the call chain.
        let climb = finding(&result, "FUN_180051c00", InferenceMethod::CrossFunction, 0);
        let InferredType::Param(record) = climb else {
            unreachable!("the cross-function pass emits parameter records");
        };
        assert_eq!(record.param_name.as_deref(), Some("param_1"));
        assert_eq!(record.inferred_type, "char *");
        assert_eq!(record.scope, InferenceScope::Function);
        assert_eq!(record.confidence, Confidence::new(65));
        assert_eq!(record.evidence, "FUN_18004b210(param_1, local_8);");

        // The literal, cast, and nested-call sites produced nothing:
        // two call-site records for the caller, and its second
        // parameter carries no reading at all.
        assert_eq!(call_site_count(&result, "FUN_180051c00"), 2);
        assert_eq!(param_count(&result, "FUN_180051c00", 1), 0);

        // The cross-function pass re-read the bodies it already had:
        // still one decompile per function.
        assert_eq!(
            program.decompiled(),
            vec!["FUN_18004b210", "FUN_180051c00"],
            "one decompile per function, in listing order"
        );
    }

    #[tokio::test]
    async fn conflicting_call_site_readings_for_one_target_keep_the_first_seen() {
        // Two calls to one callee at one position, both bare names: the
        // target is the same, the readings tie at 70, and conflict
        // resolution keeps the site the body showed first.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  uVar1 = strlen(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  FUN_18004b210(param_1);\n  FUN_18004b210(local_8);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(call_site_count(&result, "FUN_180051c00"), 1);
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.arg_name.as_deref(), Some("param_1"));
        assert_eq!(site.evidence, "FUN_18004b210(param_1);");
    }

    #[tokio::test]
    async fn a_cross_function_reading_loses_to_a_stronger_inline_reading_for_one_parameter() {
        // The caller's parameter stands read by its own body (`strlen`,
        // 70) and by the callee's contract (65): the direct reading wins
        // the target and the cross-function record drops — while the
        // call-site record, a different target, survives on its own.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  CloseHandle(param_1);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  uVar1 = strlen(param_1);\n  FUN_18004b210(param_1);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(param_count(&result, "FUN_180051c00", 0), 1);
        let InferredType::Param(record) =
            finding(&result, "FUN_180051c00", InferenceMethod::StringFunction, 0)
        else {
            unreachable!("the size detector emits parameter records");
        };
        assert_eq!(record.inferred_type, "char *");
        let site = call_site_finding(&result, "FUN_180051c00", "FUN_18004b210", 0);
        assert_eq!(site.inferred_type, "void *");
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
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The 2026-10-08 incident: the bridge answered the listing from
        // one program and the decompiles from another, every decompile
        // failed, and the scan nearly persisted a phantom-clean record
        // under the target's name. The skip-rate breaker aborts with
        // the counts instead, so nothing is persisted.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
        let result = TypeInferEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::TypeInferError::DecompileBreaker {
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
        let result = TypeInferEngine::with_source(program.clone())
            .scan("eqmain.dll")
            .await;

        assert!(matches!(
            result,
            Err(crate::TypeInferError::DecompileBreaker {
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

    #[tokio::test]
    async fn an_inline_reading_at_confidence_65_beats_the_cross_function_climb() {
        // Both readings sit at 65, so the first-seen rule decides — and
        // the inline chain is always resolved before the propagated one.
        let mut program = FakeProgram::empty();
        program.listing = vec![summary("FUN_18004b210"), summary("FUN_180051c00")];
        program.bodies.insert(
            "FUN_18004b210".into(),
            function(
                "FUN_18004b210",
                "undefined FUN_18004b210(undefined8 param_1)",
                "  *param_1 = 0;\n",
            ),
        );
        program.bodies.insert(
            "FUN_180051c00".into(),
            function(
                "FUN_180051c00",
                "undefined FUN_180051c00(undefined8 param_1)",
                "  *param_1 = 0;\n  FUN_18004b210(param_1);\n",
            ),
        );
        let result = scan(program).await;

        assert_eq!(param_count(&result, "FUN_180051c00", 0), 1);
        let InferredType::Param(record) =
            finding(&result, "FUN_180051c00", InferenceMethod::PointerArithmetic, 0)
        else {
            unreachable!("the pointer detector emits parameter records");
        };
        assert_eq!(record.inferred_type, "void *");
    }
}

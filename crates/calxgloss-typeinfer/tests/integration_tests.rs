//! Integration tests for the calxgloss-typeinfer crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`TypeInferEngine`] scans a canned program, the
//!   [`TypeInferPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a translation
//!   pipeline makes (the inferences made for one function) and its records
//!   render into [`TypeInfo`] for the prompts.
//! - **Cache behavior** — the `exists` check decides whether a scan runs,
//!   and a rescan replaces the cached document.
//!
//! The fake program implements [`DecompileSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_ghidra::{DecompiledFunction, FunctionSummary};
use calxgloss_prompts::TypeInfo;
use calxgloss_typeinfer::engine::{DecompileSource, TypeInferEngine};
use calxgloss_typeinfer::persist::TypeInferPersistor;
use calxgloss_typeinfer::types::{InferenceMethod, InferenceScope, InferredType};
use calxgloss_typeinfer::Result;
use tempfile::TempDir;

// ------------------------------------------------------------
// The canned program
// ------------------------------------------------------------

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

/// A canned program implementing [`DecompileSource`]: one function whose
/// body carries a vtable dispatch, a `strlen` call, and a `CloseHandle`
/// call — one reading family per detector — and one plain function that
/// infers nothing.
#[derive(Clone, Default)]
struct FakeProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
}

impl FakeProgram {
    fn empty() -> Self {
        Self::default()
    }
}

impl DecompileSource for FakeProgram {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.listing.clone())
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.bodies
            .get(name)
            .cloned()
            .ok_or_else(|| calxgloss_ghidra::GhidraError::NotFound {
                kind: "function",
                query: name.to_string(),
            }
            .into())
    }
}

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
        function("FUN_18003e750", "undefined FUN_18003e750(void)", "  return;\n"),
    );
    program
}

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = TypeInferEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = TypeInferPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/typeinfer/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_carries_at_most_one_inference_per_parameter() {
    // `strlen`'s argument stands read by the size detector and the
    // known-signature engine during the scan; what reaches disk is the
    // single surviving record, so a consumer never sees a contested
    // parameter twice.
    let workspace = TempDir::new().unwrap();
    let result = TypeInferEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = TypeInferPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let strlen_param: Vec<&InferredType> = loaded
        .for_function("FUN_18003ab00")
        .filter(|inference| {
            matches!(
                inference,
                InferredType::Param(record) if record.param_index == 1
            )
        })
        .collect();
    assert_eq!(strlen_param.len(), 1);
    let InferredType::Param(record) = strlen_param[0] else {
        unreachable!("the detectors emit parameter records");
    };
    assert_eq!(record.method, InferenceMethod::StringFunction);
    assert_eq!(record.inferred_type, "char *");
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = TypeInferEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = TypeInferPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was inferred for the function it is about to
    // translate; the plain function carries nothing.
    let inferred: Vec<&InferredType> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(inferred.len(), 3);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record renders into prompt data naming what it types and the
    // narrowed type with the evidence class behind it.
    let rendered: Vec<TypeInfo> = inferred
        .iter()
        .map(|inference| TypeInfo::from(*inference))
        .collect();
    let by_name: HashMap<&str, &str> = rendered
        .iter()
        .map(|info| (info.name.as_str(), info.description.as_str()))
        .collect();
    assert_eq!(
        by_name["param_1"],
        "void * (via vtable_call, confidence 85)"
    );
    assert_eq!(
        by_name["param_2"],
        "char * (via string_function, confidence 70)"
    );
    assert_eq!(
        by_name["param_3"],
        "void * (via known_signature, confidence 75)"
    );

    // The this-pointer reading keeps its class-wide reach through the
    // round trip.
    let this_ptr = inferred
        .iter()
        .find(|inference| {
            matches!(
                inference,
                InferredType::Param(record) if record.method == InferenceMethod::VtableCall
            )
        })
        .expect("the this-pointer reading");
    let InferredType::Param(record) = this_ptr else {
        unreachable!("the this-pointer detector emits parameter records");
    };
    assert_eq!(record.scope, InferenceScope::Class);
    assert!(record.is_this_pointer());
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = TypeInferPersistor::new(workspace.path());

    let first = TypeInferEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program whose only function infers nothing
    // replaces the document: the cache check still passes, but the
    // inferences are gone.
    let mut quiet = FakeProgram::empty();
    quiet.listing = vec![summary("FUN_18003e750")];
    quiet.bodies.insert(
        "FUN_18003e750".into(),
        function("FUN_18003e750", "undefined FUN_18003e750(void)", "  return;\n"),
    );
    let second = TypeInferEngine::with_source(quiet)
        .scan("eqmain.dll")
        .await
        .expect("second scan");
    persistor.save(&second).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, second);
    assert!(loaded.is_empty());
    assert_ne!(loaded, first);
}

#[tokio::test]
async fn results_for_two_binaries_stay_independent() {
    let workspace = TempDir::new().unwrap();
    let persistor = TypeInferPersistor::new(workspace.path());

    let eqmain = TypeInferEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&eqmain).expect("save");

    let mut other = FakeProgram::empty();
    other.listing = vec![summary("FUN_18003e750")];
    other.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(char *param_1)",
            "  strlen(param_1);\n",
        ),
    );
    let eqgame = TypeInferEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

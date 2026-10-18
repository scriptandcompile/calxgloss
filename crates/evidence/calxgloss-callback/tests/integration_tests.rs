//! Integration tests for the calxgloss-callback crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`CallbackEngine`] scans a canned program, the
//!   [`CallbackPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the
//!   function-pointer array calls, then the registrations, then the
//!   jump tables, then the plugin shapes, and after them the
//!   cross-function chain and event-system findings in listing order.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//! - **Signature enrichment** — a contract rendered from an injected
//!   [`SignatureMap`] at scan time rides the finding through the
//!   persisted document into the prompt data unchanged, and a scan
//!   without the map keeps the open `(...)` suggestion.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_callback::engine::{CallbackEngine, ScanSource};
use calxgloss_callback::persist::CallbackPersistor;
use calxgloss_callback::signatures::{CallableSignature, SignatureMap};
use calxgloss_callback::types::CallbackFinding;
use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
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

/// A canned program implementing [`ScanSource`]: one function whose
/// body carries a cast-dereference call through `handlers`, a bare
/// indexed call through `dispatch`, a `register_callback` call, a
/// bounds-checked switch-table dispatch, and a load-and-resolve plugin
/// shape with a host API table, and one plain function that finds
/// nothing.
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

impl ScanSource for FakeProgram {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        Ok(self.listing.clone())
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.bodies
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
    }

    // The rest of the shared trait's reads: these tests never make
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
}

fn program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  (*(int (**)(int))handlers[uVar1])(param_1);\n\
             \x20 dispatch[uVar2](param_2);\n\
             \x20 register_callback(my_handler);\n\
             \x20 if (uVar3 < 6) {\n\
             \x20   (*(code *)(&switchdataD_1800412a0)[uVar3])();\n\
             \x20 }\n\
             \x20 hMod = LoadLibrary(\"plugin.dll\");\n\
             \x20 init = (code *)GetProcAddress(hMod, \"Plugin_Init\");\n\
             \x20 Plugin_Init(&host_api);\n",
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

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = CallbackPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/callback/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // The detectors read disjoint shapes in one pass, so what reaches
    // disk is function by function in listing order and, within one
    // function, the call order the body carries — the order two scans
    // diff against.
    let workspace = TempDir::new().unwrap();
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "fp_array"),
            ("FUN_18003ab00", "fp_array"),
            ("FUN_18003ab00", "registration"),
            ("FUN_18003ab00", "jump_table"),
            ("FUN_18003ab00", "plugin"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function carries nothing.
    let findings: Vec<&CallbackFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 5);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the call that produced it.
    let CallbackFinding::FpArray(record) = findings[0] else {
        unreachable!("the cast-dereference call reads as an fp-array finding");
    };
    assert_eq!(record.table, "handlers");
    assert_eq!(record.suggestion, "Vec<Box<dyn Fn(...)>>");
    assert!(
        record
            .evidence
            .contains("(*(int (**)(int))handlers[uVar1])(param_1);")
    );

    let CallbackFinding::FpArray(record) = findings[1] else {
        unreachable!("the bare indexed call reads as an fp-array finding");
    };
    assert_eq!(record.table, "dispatch");
    assert_eq!(record.confidence.value(), 70);

    let CallbackFinding::Registration(record) = findings[2] else {
        unreachable!("the registration call reads as a registration finding");
    };
    assert_eq!(record.registration, "register_callback");
    assert_eq!(record.callback, "my_handler");
    assert_eq!(record.suggestion, "Box<dyn Fn(...)>");
    assert!(record.evidence.contains("register_callback(my_handler);"));

    let CallbackFinding::JumpTable(record) = findings[3] else {
        unreachable!("the switch-table dispatch reads as a jump-table finding");
    };
    assert_eq!(record.table, "switchdataD_1800412a0");
    assert_eq!(record.index, "uVar3");
    assert_eq!(record.target_count, Some(6));
    assert_eq!(record.suggestion, "match index { /* 6 arms */ }");
    assert_eq!(record.confidence.value(), 70);
    assert!(
        record
            .evidence
            .contains("(*(code *)(&switchdataD_1800412a0)[uVar3])();")
    );

    let CallbackFinding::Plugin(record) = findings[4] else {
        unreachable!("the load-and-resolve shape reads as a plugin finding");
    };
    assert_eq!(record.load.as_deref(), Some("LoadLibrary"));
    assert_eq!(record.resolve.as_deref(), Some("GetProcAddress"));
    assert_eq!(record.entry_point.as_deref(), Some("Plugin_Init"));
    assert_eq!(record.host_table.as_deref(), Some("host_api"));
    assert_eq!(record.suggestion, "Box<dyn Plugin> (loader crate)");
    assert_eq!(record.confidence.value(), 70);
    assert!(record.evidence.contains("LoadLibrary"));
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `CallbackInfo` prompt data, and the rendered escalate
    // prompt carries the CALLBACKS section with each finding's
    // suggestion, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::CallbackInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::CallbackInfo::from)
        .collect();
    assert_eq!(findings.len(), 5, "the target function's five findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* raw table indexing */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CALLBACKS"));
    assert!(prompt.contains("Vec<Box<dyn Fn(...)>>"));
    assert!(prompt.contains("fp_array pattern, confidence 70"));
    assert!(prompt.contains("Box<dyn Fn(...)>"));
    assert!(prompt.contains("registration pattern, confidence 70"));
    assert!(prompt.contains("match index { /* 6 arms */ }"));
    assert!(prompt.contains("jump_table pattern, confidence 70"));
    assert!(prompt.contains("Box<dyn Plugin> (loader crate)"));
    assert!(prompt.contains("plugin pattern, confidence 70"));
    assert!(prompt.contains("register_callback(my_handler);"));
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = CallbackPersistor::new(workspace.path());

    let first = CallbackEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program whose only function carries no shape
    // replaces the document: the cache check still passes, but the
    // findings are gone.
    let mut quiet = FakeProgram::empty();
    quiet.listing = vec![summary("FUN_18003e750")];
    quiet.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  return;\n",
        ),
    );
    let second = CallbackEngine::with_source(quiet)
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
    let persistor = CallbackPersistor::new(workspace.path());

    let eqmain = CallbackEngine::with_source(program())
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
            "undefined FUN_18003e750(void)",
            "  (*callbacks[uVar1])(param_1);\n",
        ),
    );
    let eqgame = CallbackEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

// ------------------------------------------------------------
// Cross-function chain findings
// ------------------------------------------------------------

#[tokio::test]
async fn chain_findings_survive_the_scan_persist_and_prompt_walk() {
    // The callback lifecycle across two functions: one hands
    // `my_handler` to `register_callback`, the other calls it by
    // name. The chain rides the tagged union to disk and back, and
    // renders into the escalate prompt through the usual accessors.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  register_callback(my_handler);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  my_handler(param_1);\n",
        ),
    );

    let workspace = TempDir::new().expect("workspace temp dir");
    let result = CallbackEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let chains: Vec<&CallbackFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "chain")
        .collect();
    assert_eq!(chains.len(), 1, "one chain per function pair");

    // The record keeps both functions and the callback through the
    // round trip, at the pairing's own confidence.
    let CallbackFinding::Chain(record) = chains[0] else {
        unreachable!("the register-then-call shape reads as a chain finding");
    };
    assert_eq!(record.function, "FUN_18003ab00");
    assert_eq!(record.partner, "FUN_18003e750");
    assert_eq!(record.callback, "my_handler");
    assert_eq!(record.table, None, "a direct call runs through no table");
    assert_eq!(record.confidence.value(), 70);
    assert!(record.evidence.contains("register_callback(my_handler);"));
    assert!(record.evidence.contains("my_handler(param_1);"));
    assert!(chains[0].target().contains("my_handler"));

    // The cross-function finding lands after the per-function
    // findings, so the persisted document stays diffable.
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "registration"),
            ("FUN_18003ab00", "chain"),
        ]
    );

    // The escalate prompt describes the chain with its kind and
    // confidence, like every other detector's records.
    let findings: Vec<calxgloss_prompts::CallbackInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::CallbackInfo::from)
        .collect();
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* hands the handler out */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CALLBACKS"));
    assert!(
        prompt.contains("Box<dyn Fn(...)> shared between the registering and calling functions")
    );
    assert!(prompt.contains("chain pattern, confidence 70"));
    assert!(prompt.contains("my_handler(param_1);"));
}

// ------------------------------------------------------------
// Event-system reconstruction
// ------------------------------------------------------------

#[tokio::test]
async fn event_system_findings_survive_the_scan_persist_and_prompt_walk() {
    // The event architecture across three functions: two hand
    // handlers to `register_callback`, a third dispatches through a
    // table. The reconstructed observer rides the tagged union to
    // disk and back, and renders into the escalate prompt through the
    // usual accessors.
    let mut program = FakeProgram::empty();
    program.listing = vec![
        summary("FUN_18003ab00"),
        summary("FUN_18003e750"),
        summary("FUN_1800412a0"),
    ];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  register_callback(handler_a);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  register_callback(handler_b);\n",
        ),
    );
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "  handlers[uVar1](param_1);\n",
        ),
    );

    let workspace = TempDir::new().expect("workspace temp dir");
    let result = CallbackEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let events: Vec<&CallbackFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "event_system")
        .collect();
    assert_eq!(events.len(), 1, "one event system per registration point");

    // The record keeps the point, the handlers, and the dispatchers
    // through the round trip, at the reconstruction's own confidence.
    let CallbackFinding::EventSystem(record) = events[0] else {
        unreachable!("the register-crowd-plus-dispatch shape reads as an event_system finding");
    };
    assert_eq!(record.function, "FUN_18003ab00");
    assert_eq!(record.registration, "register_callback");
    assert_eq!(record.callbacks, ["handler_a", "handler_b"]);
    assert_eq!(record.dispatchers, ["FUN_1800412a0"]);
    assert_eq!(record.confidence.value(), 60);
    assert!(record.evidence.contains("register_callback(handler_a);"));
    assert!(record.evidence.contains("handlers[uVar1](param_1);"));
    assert!(events[0].target().contains("register_callback"));

    // The cross-function finding lands after the per-function
    // findings, so the persisted document stays diffable.
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "registration"),
            ("FUN_18003e750", "registration"),
            ("FUN_1800412a0", "fp_array"),
            ("FUN_18003ab00", "event_system"),
        ]
    );

    // The escalate prompt describes the event system with its kind
    // and confidence, like every other detector's records.
    let findings: Vec<calxgloss_prompts::CallbackInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::CallbackInfo::from)
        .collect();
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* hands a handler to the event loop */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CALLBACKS"));
    assert!(prompt.contains(
        "Observer pattern: registered Box<dyn Fn(...)> handlers dispatched through a table"
    ));
    assert!(prompt.contains("event_system pattern, confidence 60"));
    assert!(prompt.contains("handlers[uVar1](param_1);"));
}

// ------------------------------------------------------------
// Signature enrichment (issue #173)
// ------------------------------------------------------------

#[tokio::test]
async fn enriched_suggestions_survive_the_scan_persist_and_prompt_walk() {
    // The enrichment is scan-time, not prompt-time: the contract an
    // injected signature map renders rides the registration and the
    // chain into the persisted document and reaches the escalate
    // prompt as the same string the CLI report prints.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  register_callback(my_handler);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  my_handler(param_1);\n",
        ),
    );

    let signatures: SignatureMap = [(
        "my_handler".to_string(),
        CallableSignature {
            param_types: vec!["i32".to_string()],
            return_type: Some("bool".to_string()),
        },
    )]
    .into_iter()
    .collect();
    let workspace = TempDir::new().expect("workspace temp dir");
    let result = CallbackEngine::with_source(program)
        .with_signatures(signatures)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = CallbackPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let suggestions: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.kind(), finding.suggestion()))
        .collect();
    assert_eq!(
        suggestions,
        vec![
            ("registration", "Box<dyn Fn(i32) -> bool>"),
            (
                "chain",
                "Box<dyn Fn(i32) -> bool> shared between the registering and calling functions"
            ),
        ],
        "the enriched contract round-trips through the persisted document"
    );

    // The prompt sees the enriched contract verbatim — the open
    // `(...)` placeholder is gone from the rendered CALLBACKS
    // section.
    let findings: Vec<calxgloss_prompts::CallbackInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::CallbackInfo::from)
        .collect();
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* hands the handler out */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CALLBACKS"));
    assert!(prompt.contains("Box<dyn Fn(i32) -> bool>"));
    assert!(!prompt.contains("Box<dyn Fn(...)>"));
}

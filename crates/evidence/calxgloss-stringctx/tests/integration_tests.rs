//! Integration tests for the calxgloss-stringctx crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`StringContextEngine`] scans a canned program,
//!   the [`StringContextPersistor`] files the result in the workspace
//!   layout, and loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the
//!   classified strings, then the format-string calls, then the
//!   localization reading, with the cross-function flows appended
//!   after the per-function walk.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_stringctx::engine::{ScanSource, StringContextEngine};
use calxgloss_stringctx::persist::StringContextPersistor;
use calxgloss_stringctx::types::StringFinding;
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

fn function(name: &str, body: &str) -> DecompiledFunction {
    DecompiledFunction {
        name: name.to_string(),
        signature: format!("undefined {name}(void)"),
        body: format!("\nundefined {name}(void)\n\n{{\n{body}}}\n"),
    }
}

/// A canned program implementing [`ScanSource`]: one function whose body
/// carries a direct literal, a `DAT_` reference, a language-name `DAT_`
/// reference, a `sprintf` call, and a call handing a literal to the
/// listing's other function — all four finding kinds — and one plain
/// function covered only through the xref fallback.
#[derive(Clone, Default)]
struct FakeProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
    literals: Vec<StringLiteral>,
    xrefs: HashMap<u64, Vec<Xref>>,
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

    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        Ok(self.literals.clone())
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
    }

    // The rest of the shared trait's reads: these tests never make
    // them, so they answer with empty or not-found data.
    async fn callers(&self, _address: u64) -> Result<Vec<String>> {
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
    let mut program = FakeProgram {
        listing: vec![summary("FUN_18003ab00"), summary("FUN_18003e750")],
        ..FakeProgram::default()
    };
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "  lFile = CreateFileA(\"Journal.txt\",0xc0000000,0,0,3,0x80,0);\n\
             \x20 FUN_18003e750(\"Journal.txt\");\n\
             \x20 puVar3 = (uint *)DAT_180128cf0;\n\
             \x20 pcVar4 = (char *)DAT_180129b00;\n\
             \x20 sprintf(local_10, \"%s: %d hits\", pcVar4, uVar3);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function("FUN_18003e750", "  return;\n"),
    );
    program.literals = vec![
        StringLiteral {
            address: 0x180128cf0,
            value: "********** Chat logging turned OFF.".to_string(),
        },
        StringLiteral {
            address: 0x180129a00,
            value: "%s: %d hits".to_string(),
        },
        StringLiteral {
            address: 0x180129b00,
            value: "English".to_string(),
        },
    ];
    program.xrefs.insert(
        0x180128cf0,
        vec![Xref {
            address: 0x180006f04,
            function: Some("FUN_18003e750".to_string()),
            kind: Some("DATA".to_string()),
        }],
    );
    program
}

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = StringContextEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = StringContextPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/stringctx/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // One pass over the listing, so what reaches disk is function by
    // function in listing order and, within one function, the
    // classified strings then the format-string calls then the
    // localization reading — with the cross-function flows appended
    // after the walk, attached to the pair's earlier end. The order
    // two scans diff against.
    let workspace = TempDir::new().unwrap();
    let result = StringContextEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = StringContextPersistor::new(workspace.path());
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
            ("FUN_18003ab00", "classified"),
            ("FUN_18003ab00", "classified"),
            ("FUN_18003ab00", "classified"),
            ("FUN_18003ab00", "format_string"),
            ("FUN_18003ab00", "localization"),
            ("FUN_18003e750", "classified"),
            ("FUN_18003ab00", "cross_function"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = StringContextEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = StringContextPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate.
    let findings: Vec<&StringFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 6);
    assert_eq!(loaded.for_function("FUN_18003e750").count(), 1);
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detail and evidence through the round trip,
    // so a prompt sees the use that produced it.
    let StringFinding::Classified(record) = findings[0] else {
        unreachable!("the literal reads as a classified finding");
    };
    assert_eq!(record.string_value, "Journal.txt");
    assert_eq!(record.classification.to_string(), "file_path");
    assert_eq!(record.purpose, "file or registry path");
    assert!(record.evidence.contains("CreateFileA"));

    let StringFinding::FormatString(record) = findings[3] else {
        unreachable!("the sprintf call reads as a format_string finding");
    };
    assert_eq!(record.format_string, "%s: %d hits");
    assert_eq!(record.arg_types.len(), 2);
    assert_eq!(record.arg_types[0].rust_type, "*const i8");
    assert_eq!(record.arg_types[1].rust_type, "i32");
    assert!(record.call_site.contains("sprintf"));

    // The localization reading survives the round trip beside the
    // classified records, which stand unchanged.
    let StringFinding::Localization(record) = findings[4] else {
        unreachable!("the language-name reference reads as a localization finding");
    };
    assert_eq!(
        record.signal_kinds,
        [calxgloss_stringctx::types::LocalizationSignalKind::LanguageName]
    );
    assert_eq!(record.signals, ["English"]);
    assert_eq!(record.confidence.value(), 60);
    assert!(record.evidence.contains("DAT_180129b00"));
    assert_eq!(findings[2].target(), "English");
    assert_eq!(findings[2].kind(), "classified");

    // The cross-function flow survives too: the literal the body hands to
    // the listing's other function, attached to the pair's earlier end —
    // this function — with the passing call's line as evidence.
    let StringFinding::CrossFunction(record) = findings[5] else {
        unreachable!("the hand-off to FUN_18003e750 reads as a cross_function finding");
    };
    assert_eq!(record.passing_function, "FUN_18003ab00");
    assert_eq!(record.receiving_function, "FUN_18003e750");
    assert_eq!(record.string_value, "Journal.txt");
    assert_eq!(record.evidence, "FUN_18003e750(\"Journal.txt\");");
    assert_eq!(record.confidence.value(), 70);
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = StringContextPersistor::new(workspace.path());

    let first = StringContextEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program with no strings at all replaces the
    // document: the cache check still passes, but the findings are gone.
    let mut quiet = FakeProgram {
        listing: vec![summary("FUN_18003e750")],
        ..FakeProgram::default()
    };
    quiet.bodies.insert(
        "FUN_18003e750".into(),
        function("FUN_18003e750", "  return;\n"),
    );
    let second = StringContextEngine::with_source(quiet)
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
    let persistor = StringContextPersistor::new(workspace.path());

    let eqmain = StringContextEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&eqmain).expect("save");

    let mut other = FakeProgram {
        listing: vec![summary("FUN_18003e750")],
        ..FakeProgram::default()
    };
    other.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "  lFile = CreateFileA(\"eqgame.ini\",0,0,0,3,0,0);\n",
        ),
    );
    let eqgame = StringContextEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

// ------------------------------------------------------------
// Prompt consumption
// ------------------------------------------------------------

#[tokio::test]
async fn the_loaded_findings_render_into_the_escalate_prompt() {
    // The pipeline's path: load the persisted document, keep the
    // target function's findings, convert them to prompt data, and
    // render the escalate prompt around them.
    let workspace = TempDir::new().unwrap();
    let result = StringContextEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = StringContextPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::StringContextInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::StringContextInfo::from)
        .collect();
    assert_eq!(findings.len(), 6, "the target function's six findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* raw literals */ }".into(),
        "Wrong result".into(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
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
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("STRINGS"));
    assert!(prompt.contains("file or registry path"));
    assert!(prompt.contains("file_path string, confidence 70"));
    assert!(prompt.contains("`*const i8`, `i32`"));
    assert!(prompt.contains("format_string string, confidence 70"));
    assert!(prompt.contains("CreateFileA"));
    assert!(prompt.contains("sprintf"));
    // The localization finding rides the union accessors into the prompt:
    // its kind tag, its below-a-classified-record confidence, its
    // language-enum suggestion, and its signal line as evidence.
    assert!(prompt.contains("localization string, confidence 60"));
    assert!(prompt.contains(
        "model the language switch as a Rust enum with the localized strings held in a table"
    ));
    assert!(prompt.contains("DAT_180129b00"));
    // The cross-function flow rides the same union accessors into the
    // prompt: its kind tag, its in-body-call-level confidence, its
    // string-type suggestion, and the passing call's line as evidence.
    assert!(prompt.contains("cross_function string, confidence 70"));
    assert!(prompt.contains(
        "the receiving parameter translates as a string type (`*const i8`/`&str`) and the \
         caller's payload is that string"
    ));
    assert!(prompt.contains("FUN_18003e750(\"Journal.txt\");"));
}

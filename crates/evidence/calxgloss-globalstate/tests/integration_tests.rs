//! End-to-end contract: scan a canned program, persist the document,
//! and read it back — the whole artifact path without a server.

use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, ScanSource, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_globalstate::{AccessKind, GlobalStateEngine, GlobalStatePersistor};
use std::collections::HashMap;

struct CannedProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
}

impl ScanSource for CannedProgram {
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

fn function(name: &str, body: &str) -> DecompiledFunction {
    DecompiledFunction {
        name: name.to_string(),
        signature: format!("undefined {name}(void)"),
        body: format!("undefined {name}(void)\n\n{{\n{body}}}\n"),
    }
}

/// A function-list entry for the canned listing.
fn summary(name: &str, address: u64) -> FunctionSummary {
    FunctionSummary {
        name: name.into(),
        address,
    }
}

#[tokio::test]
async fn a_scan_persists_and_reads_back_the_same_document() {
    let mut bodies = HashMap::new();
    bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "  DAT_180064e80 = param_1;\n  uVar1 = DAT_180064e80;\n",
        ),
    );
    bodies.insert(
        "FUN_18003e750".into(),
        function("FUN_18003e750", "  return;\n"),
    );
    let program = CannedProgram {
        listing: vec![
            summary("FUN_18003ab00", 0x1800_3ab00),
            summary("FUN_18003e750", 0x1800_3e750),
        ],
        bodies,
    };

    let workspace = tempfile::tempdir().expect("a workspace");
    let result = GlobalStateEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = GlobalStatePersistor::new(workspace.path());
    persistor.save(&result).expect("save");
    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(
        loaded, result,
        "the document reads back exactly as the scan made it"
    );

    // The reading itself, as a consumer sees it after the round trip.
    let kinds: Vec<Option<AccessKind>> = loaded
        .for_function("FUN_18003ab00")
        .map(|finding| finding.access_kind())
        .collect();
    assert_eq!(
        kinds,
        vec![Some(AccessKind::Write), Some(AccessKind::Read)],
        "the by-function lookup answers only the function's own accesses"
    );
    let entry = loaded
        .findings
        .last()
        .and_then(|finding| finding.shared_global())
        .expect("the rollup entry lands last");
    assert_eq!(entry.global, "DAT_180064e80");
    assert_eq!(entry.writers, vec!["FUN_18003ab00"]);
    assert_eq!(entry.readers, vec!["FUN_18003ab00"]);
    assert_eq!(loaded.purity.len(), 2);
    assert!(loaded.purity[1].is_pure, "the plain function reads as pure");
}

#[tokio::test]
async fn the_shared_globals_index_names_the_functions_sharing_a_global() {
    // The end-to-end rollup contract: two units touching one global
    // land one index entry naming its writer and its reader, and the
    // entry survives the document round trip.
    let mut bodies = HashMap::new();
    bodies.insert(
        "FUN_18003ab00".into(),
        function("FUN_18003ab00", "  DAT_180064e80 = param_1;\n"),
    );
    bodies.insert(
        "FUN_18003e750".into(),
        function("FUN_18003e750", "  uVar1 = DAT_180064e80;\n  return;\n"),
    );
    let program = CannedProgram {
        listing: vec![
            summary("FUN_18003ab00", 0x1800_3ab00),
            summary("FUN_18003e750", 0x1800_3e750),
        ],
        bodies,
    };

    let workspace = tempfile::tempdir().expect("a workspace");
    let result = GlobalStateEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = GlobalStatePersistor::new(workspace.path());
    persistor.save(&result).expect("save");
    let loaded = persistor.load("eqmain.dll").expect("load");

    let entry = loaded
        .findings
        .last()
        .and_then(|finding| finding.shared_global())
        .expect("the rollup entry lands last");
    assert_eq!(entry.global, "DAT_180064e80");
    assert_eq!(entry.writers, vec!["FUN_18003ab00"]);
    assert_eq!(entry.readers, vec!["FUN_18003e750"]);
    assert_eq!(
        entry.confidence.value(),
        85,
        "the exact DAT_* spellings behind the entry score the entry"
    );
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the persisted
    // document on disk answers the by-function lookup, the records render
    // into `GlobalStateInfo` prompt data, and the rendered escalate prompt
    // carries the GLOBAL STATE section with each record's suggestion, kind,
    // global, and evidence — the struct-vs-static steering included.
    let mut bodies = HashMap::new();
    bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "  DAT_180064e80 = param_1;\n  uVar1 = DAT_180064e80;\n",
        ),
    );
    let program = CannedProgram {
        listing: vec![summary("FUN_18003ab00", 0x1800_3ab00)],
        bodies,
    };

    let workspace = tempfile::tempdir().expect("a workspace");
    let result = GlobalStateEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = GlobalStatePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::GlobalStateInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::GlobalStateInfo::from)
        .collect();
    assert_eq!(findings.len(), 2, "the write and the read, not the rollup");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00(param_1: i32) { /* DAT store */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            global_state_findings: findings,
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("GLOBAL STATE"));
    assert!(
        prompt.contains("model the program global as shared struct state, not a Rust static"),
        "the write record steers the struct-vs-static choice"
    );
    assert!(prompt.contains("global_write of `DAT_180064e80`"));
    assert!(prompt.contains("global_read of `DAT_180064e80`"));
    assert!(prompt.contains("read the program global through shared state, not an invented local"));
    assert!(
        prompt.contains("rather than in a Rust `static`"),
        "the purity flag renders as the section's steering"
    );
}

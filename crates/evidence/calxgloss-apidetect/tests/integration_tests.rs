//! Integration tests for the calxgloss-apidetect crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`ApiEngine`] scans a canned program, the
//!   [`ApiPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the usages recorded for one function),
//!   and the persisted list keeps every finding in scan order: import
//!   entries in listing order, then the platform-divergence claim,
//!   then the COM claims, then usages function by function in call
//!   graph order.
//! - **Prompt rendering** — the loaded findings render into `ApiInfo`
//!   prompt data and the escalate prompt includes the LIBRARIES AND
//!   APIS section.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//! - **FFI bindings artifact** — the loaded document re-renders into a
//!   byte-identical bindings file declaring the crate-less imports, and
//!   two separate scans render the same bytes.
//! - **Dependency manifest artifact** — the loaded document re-renders
//!   into a byte-identical Cargo.toml-style manifest aggregating the
//!   identified findings' crates once, sorted, with the persisted
//!   feature flags inlined and no versions claimed.
//!
//! The fake program implements [`ScanSource`] and [`CallGraphSource`], so
//! the whole flow runs without an external server.

use calxgloss_apidetect::engine::{ApiEngine, CallGraphSource, ScanSource};
use calxgloss_apidetect::ffi_bindings::{render_dependency_manifest, render_ffi_bindings};
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_apidetect::types::ApiFinding;
use calxgloss_callgraph::{CallGraphEdge, CallType, FunctionCallGraph};
use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    StringLiteral, StructLayout, Symbol, Xref,
};
use tempfile::TempDir;

// ------------------------------------------------------------
// The canned program
// ------------------------------------------------------------

fn import(name: &str) -> Symbol {
    Symbol {
        name: name.to_string(),
        address: 0,
        imported: true,
    }
}

fn node(name: &str, address: u64, callees: Vec<(&str, u64)>) -> FunctionCallGraph {
    FunctionCallGraph {
        name: name.to_string(),
        address,
        callers: Vec::new(),
        callees: callees
            .into_iter()
            .map(|(callee_name, target)| CallGraphEdge {
                source: address,
                target,
                call_site: 0,
                call_type: CallType::Direct,
                callee_name: callee_name.to_string(),
            })
            .collect(),
        node_category: calxgloss_types::NodeCategory::Middle,
    }
}

/// A canned program implementing [`ScanSource`] and [`CallGraphSource`].
///
/// Its imports cover an identified zlib call, an identified Win32
/// call, an unidentified vendor function, and an identified POSIX
/// call — the Win32 and POSIX imports together open the
/// platform-divergence gate — plus a pair of interface-decorated names
/// opening the COM reading on a named interface. In the call graph,
/// `FUN_18003ab00` calls `inflate` directly and reaches `CreateFileA`
/// through `FUN_18003c000` — one direct and one transitive usage —
/// while `FUN_18003e750` calls nothing.
#[derive(Clone, Default)]
struct FakeProgram {
    imports: Vec<Symbol>,
    graph: Vec<FunctionCallGraph>,
}

impl ScanSource for FakeProgram {
    async fn functions(&self) -> calxgloss_decomp::Result<Vec<FunctionSummary>> {
        Ok(Vec::new())
    }

    async fn decompile(&self, name: &str) -> calxgloss_decomp::Result<DecompiledFunction> {
        Err(EngineError::NotFound {
            kind: "function",
            query: name.to_string(),
        })
    }

    async fn strings(&self) -> calxgloss_decomp::Result<Vec<StringLiteral>> {
        Ok(Vec::new())
    }

    async fn callers(&self, _address: u64) -> calxgloss_decomp::Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn xrefs_to(&self, _address: u64) -> calxgloss_decomp::Result<Vec<Xref>> {
        Ok(Vec::new())
    }

    async fn data_types(
        &self,
        _category: Option<&str>,
    ) -> calxgloss_decomp::Result<Vec<DataTypeEntry>> {
        Ok(Vec::new())
    }

    async fn struct_layout(&self, name: &str) -> calxgloss_decomp::Result<StructLayout> {
        Err(EngineError::NotFound {
            kind: "struct",
            query: name.to_string(),
        })
    }

    async fn enum_values(&self, name: &str) -> calxgloss_decomp::Result<EnumDefinition> {
        Err(EngineError::NotFound {
            kind: "enum",
            query: name.to_string(),
        })
    }

    async fn data_items(&self) -> calxgloss_decomp::Result<Vec<DataItem>> {
        Ok(Vec::new())
    }

    async fn imports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
        Ok(self.imports.clone())
    }

    async fn exports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
        Ok(Vec::new())
    }

    async fn image_base(&self) -> calxgloss_decomp::Result<u64> {
        Ok(0)
    }

    async fn read_memory(
        &self,
        _address: u64,
        _length: usize,
    ) -> calxgloss_decomp::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl CallGraphSource for FakeProgram {
    async fn call_graph(
        &self,
        _binary: &str,
    ) -> calxgloss_apidetect::Result<Vec<FunctionCallGraph>> {
        Ok(self.graph.clone())
    }
}

fn program() -> FakeProgram {
    FakeProgram {
        imports: vec![
            import("inflate"),
            import("CreateFileA"),
            import("VendorSpecialFunction"),
            import("fopen"),
            import("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
            import("?Release@IDataSource@@UEAAKXZ"),
        ],
        graph: vec![
            node(
                "FUN_18003ab00",
                0x1800_3ab00,
                vec![("inflate", 0), ("FUN_18003c000", 0x1800_3c000)],
            ),
            node("FUN_18003c000", 0x1800_3c000, vec![("CreateFileA", 0)]),
            node("FUN_18003e750", 0x1800_3e750, Vec::new()),
        ],
    }
}

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = ApiPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/apidetect/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // Imports first, in listing order — identified and unidentified
    // alike, decorated names included. Then the platform-divergence
    // claim the mixed Win32 and POSIX imports open, then the COM claim
    // the decorated names recover. Then usages function by function in
    // call graph order, direct before transitive. This is the order
    // two scans diff against.
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str, String)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.kind(), finding.function(), finding.target()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("import", "", "inflate".to_string()),
            ("import", "", "CreateFileA".to_string()),
            ("import", "", "VendorSpecialFunction".to_string()),
            ("import", "", "fopen".to_string()),
            (
                "import",
                "",
                "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z".to_string()
            ),
            ("import", "", "?Release@IDataSource@@UEAAKXZ".to_string()),
            ("platform_divergence", "", "Win32Core + POSIX".to_string()),
            ("com_interface", "", "IDataSource".to_string()),
            ("api_usage", "FUN_18003ab00", "inflate".to_string()),
            ("api_usage", "FUN_18003ab00", "CreateFileA".to_string()),
            ("api_usage", "FUN_18003c000", "CreateFileA".to_string()),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate. The plain function and the unknown function have
    // nothing, and import entries belong to the binary, not to any
    // function.
    let findings: Vec<&ApiFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 2);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the call path that produced it. The
    // category and feature enrichment survives scan → persist → load.
    let ApiFinding::ApiUsage(direct) = findings[0] else {
        unreachable!("the direct call reads as a usage finding");
    };
    assert_eq!(direct.api, "inflate");
    assert_eq!(direct.library, "zlib");
    assert_eq!(direct.rust_crate, "flate2");
    assert_eq!(direct.category.as_deref(), Some("zlib"));
    assert_eq!(direct.features, ["zlib".to_string()]);
    assert!(direct.direct);
    assert_eq!(direct.evidence, "FUN_18003ab00 → inflate");

    let ApiFinding::ApiUsage(transitive) = findings[1] else {
        unreachable!("the helper call reads as a usage finding");
    };
    assert_eq!(transitive.api, "CreateFileA");
    assert_eq!(transitive.library, "Win32");
    assert_eq!(transitive.rust_crate, "windows / std::fs");
    assert_eq!(transitive.category.as_deref(), Some("Win32Core"));
    assert!(transitive.features.is_empty());
    assert!(!transitive.direct);
    assert_eq!(
        transitive.evidence,
        "FUN_18003ab00 → FUN_18003c000 → CreateFileA"
    );
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `ApiInfo` prompt data, and the rendered escalate
    // prompt includes the LIBRARIES AND APIS section with each
    // finding's suggestion, library, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let mut findings: Vec<calxgloss_prompts::ApiInfo> = loaded
        .findings
        .iter()
        .map(calxgloss_prompts::ApiInfo::from)
        .collect();
    findings.retain(|info| info.function == "FUN_18003ab00");
    assert_eq!(findings.len(), 2, "the target function's two usages");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* raw imports */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            api_findings: findings,
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("LIBRARIES AND APIS"));
    assert!(prompt.contains("flate2[zlib]"));
    assert!(prompt.contains("`inflate`"));
    assert!(prompt.contains("zlib direct, confidence 80"));
    assert!(prompt.contains("windows / std::fs"));
    assert!(prompt.contains("Win32 transitive, confidence 60"));
    assert!(prompt.contains("FUN_18003ab00 → FUN_18003c000 → CreateFileA"));
}

#[tokio::test]
async fn the_platform_divergence_finding_survives_scan_persist_load_and_prompt() {
    // The mixed-import fixture opens the gate. The claim survives into
    // the persisted document whole — families, evidence, confidence —
    // and renders into the escalate prompt naming both families and
    // the cfg-gated shape.
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let divergences: Vec<&ApiFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "platform_divergence")
        .collect();
    assert_eq!(
        divergences.len(),
        1,
        "one claim per binary survives the round trip"
    );
    let ApiFinding::PlatformDivergence(record) = divergences[0] else {
        unreachable!("the divergence claim reads as its own record");
    };
    assert_eq!(
        record.families,
        ["Win32Core".to_string(), "POSIX".to_string()]
    );
    assert_eq!(record.evidence, "CreateFileA (Win32Core), fopen (POSIX)");
    assert_eq!(record.confidence.value(), 70);

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* raw imports */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            api_findings: loaded
                .findings
                .iter()
                .map(calxgloss_prompts::ApiInfo::from)
                .collect(),
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("LIBRARIES AND APIS"));
    assert!(
        prompt.contains("`Win32Core + POSIX`"),
        "the prompt names both platform families"
    );
    assert!(prompt.contains("platform_divergence, confidence 70"));
    assert!(
        prompt.contains("CreateFileA (Win32Core), fopen (POSIX)"),
        "the prompt carries the triggering imports as evidence"
    );
    assert!(
        prompt.contains("cfg gates"),
        "the prompt suggests the cfg-gated shape"
    );
}

#[tokio::test]
async fn the_com_interface_finding_survives_scan_persist_load_and_prompt() {
    // The decorated-name fixture recovers a named interface. The claim
    // survives into the persisted document whole — name, method
    // listing, evidence, confidence — and renders into the escalate
    // prompt naming the interface and the trait-plus-methods shape.
    let workspace = TempDir::new().unwrap();
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ApiPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let coms: Vec<&ApiFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "com_interface")
        .collect();
    assert_eq!(
        coms.len(),
        1,
        "one claim per interface survives the round trip"
    );
    let ApiFinding::ComInterface(record) = coms[0] else {
        unreachable!("the COM claim reads as its own record");
    };
    assert_eq!(record.interface.as_deref(), Some("IDataSource"));
    assert_eq!(
        record.methods,
        ["QueryInterface".to_string(), "Release".to_string()],
        "the method listing is kept in the document"
    );
    assert_eq!(
        record.evidence,
        "?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z, ?Release@IDataSource@@UEAAKXZ"
    );
    assert_eq!(record.confidence.value(), 70);

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* raw imports */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            api_findings: loaded
                .findings
                .iter()
                .map(calxgloss_prompts::ApiInfo::from)
                .collect(),
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("LIBRARIES AND APIS"));
    assert!(
        prompt.contains("`IDataSource`"),
        "the prompt names the recovered interface"
    );
    assert!(prompt.contains("com_interface, confidence 70"));
    assert!(
        prompt.contains("?QueryInterface@IDataSource@@UEAAJPEAXPEAPEAX@Z"),
        "the prompt carries the decorated names as evidence"
    );
    assert!(
        prompt.contains("trait IDataSource with QueryInterface, Release"),
        "the prompt suggests the trait shape with the method listing"
    );
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = ApiPersistor::new(workspace.path());

    let first = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program with no imports at all replaces the
    // document: the cache check still passes, but the findings are gone.
    let second = ApiEngine::with_source(FakeProgram::default())
        .scan("eqmain.dll")
        .await
        .expect("second scan");
    persistor.save(&second).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, second);
    assert!(loaded.findings.is_empty());
    assert_ne!(loaded, first);
}

#[tokio::test]
async fn results_for_two_binaries_stay_independent() {
    let workspace = TempDir::new().unwrap();
    let persistor = ApiPersistor::new(workspace.path());

    let eqmain = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&eqmain).expect("save");

    let other = FakeProgram {
        imports: vec![import("SDL_Init")],
        graph: vec![node("FUN_140012340", 0x1400_12340, vec![("SDL_Init", 0)])],
    };
    let eqgame = ApiEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

// ------------------------------------------------------------
// FFI bindings artifact
// ------------------------------------------------------------

#[tokio::test]
async fn the_ffi_bindings_artifact_regenerates_deterministically_from_a_loaded_document() {
    // The JSON stays the single source of truth: the artifact is re-rendered
    // from the loaded document, byte-identically, and nothing reads it back.
    let workspace = TempDir::new().unwrap();
    let persistor = ApiPersistor::new(workspace.path());
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let first = render_ffi_bindings(&loaded);
    let second = render_ffi_bindings(&loaded);
    assert_eq!(
        first, second,
        "two renders of the same document are byte-identical"
    );

    // The unidentified imports — the vendor function and the decorated
    // COM names — get extern declarations with sanitized identifiers;
    // the identified imports are replaced by crates and excluded.
    assert!(first.contains("fn VendorSpecialFunction();"), "{first}");
    assert!(
        first.contains("fn _QueryInterface_IDataSource_UEAAJPEAXPEAPEAX_Z();"),
        "{first}"
    );
    assert!(
        first.contains("fn _Release_IDataSource_UEAAKXZ();"),
        "{first}"
    );
    assert!(
        !first.contains("inflate"),
        "the crate-replaced imports get no declaration: {first}"
    );
    assert!(
        !first.contains("CreateFileA"),
        "the crate-replaced imports get no declaration: {first}"
    );
    assert!(
        !first.contains("fopen"),
        "the crate-replaced imports get no declaration: {first}"
    );
}

#[tokio::test]
async fn two_separate_scans_render_byte_identical_bindings() {
    // The promise a reviewer leans on: rescanning the program and
    // re-rendering changes only what the scan actually learned, never
    // the renderer's own ordering or formatting — and the header names
    // only the binary, never either scan time.
    let first = render_ffi_bindings(
        &ApiEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("first scan"),
    );
    let second = render_ffi_bindings(
        &ApiEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("second scan"),
    );

    assert_eq!(first, second);
    assert!(
        first.starts_with("// FFI bindings for eqmain.dll, rendered by `calxgloss apidetect`.\n"),
        "{first}"
    );
}

// ------------------------------------------------------------
// Dependency manifest artifact
// ------------------------------------------------------------

#[tokio::test]
async fn the_dependency_manifest_artifact_regenerates_deterministically_from_a_loaded_document_carrying_feature_flags()
 {
    // The JSON stays the single source of truth: the manifest is
    // re-rendered from the loaded document — feature flags and all —
    // byte-identically, and nothing reads it back.
    let workspace = TempDir::new().unwrap();
    let persistor = ApiPersistor::new(workspace.path());
    let result = ApiEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let first = render_dependency_manifest(&loaded);
    let second = render_dependency_manifest(&loaded);
    assert_eq!(
        first, second,
        "two renders of the same document are byte-identical"
    );

    // The whole file pinned verbatim: the zlib feature flag survived
    // persistence and renders beside its crate entry, the entries are
    // sorted, and the multi-crate suggestions render as quoted TOML
    // keys.
    let expected = "\
# Dependency manifest for eqmain.dll, rendered by `calxgloss apidetect`.
# Derived artifact: regenerated from the API detection result on
# every scan — edit the result, never this file.
# No versions are claimed: the scan never verifies crate versions.

[dependencies]
flate2 = { features = [\"zlib\"] }
\"std::fs / std::io\" = {}
\"windows / std::fs\" = {}
";
    assert_eq!(first, expected);

    // The import entry and the usage entries all name flate2 — the
    // manifest aggregates it once.
    assert_eq!(first.matches("flate2").count(), 1, "{first}");

    // The unidentified imports — the vendor function and the decorated
    // COM names — suggest no crates and contribute nothing.
    assert!(!first.contains("VendorSpecialFunction"), "{first}");
    assert!(!first.contains("QueryInterface"), "{first}");

    // No version is claimed anywhere in the dependency block.
    let body = first.split("[dependencies]").nth(1).unwrap_or_default();
    assert!(!body.contains("version"), "{first}");
    assert!(!body.contains("= \""), "no version string: {first}");
}

#[tokio::test]
async fn two_separate_scans_render_byte_identical_manifests() {
    // The promise a reviewer leans on: rescanning the program and
    // re-rendering changes only what the scan actually learned, never
    // the renderer's own ordering or formatting — and the header names
    // only the binary, never either scan time.
    let first = render_dependency_manifest(
        &ApiEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("first scan"),
    );
    let second = render_dependency_manifest(
        &ApiEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("second scan"),
    );

    assert_eq!(first, second);
    assert!(
        first.starts_with(
            "# Dependency manifest for eqmain.dll, rendered by `calxgloss apidetect`.\n"
        ),
        "{first}"
    );
}

//! Integration tests for the calxgloss-algorithm crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`AlgorithmEngine`] scans a canned program, the
//!   [`AlgorithmPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned — with
//!   competing claims resolved and the confidence floor applied before
//!   anything is persisted.
//! - **Consumption** — the loaded result answers the lookups a translation
//!   pipeline makes (the hints made for one function) and its records
//!   render into [`AlgorithmInfo`] for the prompts.
//! - **Cache behavior** — the `exists` check decides whether a scan runs,
//!   and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_algorithm::callback_db::{CallbackPattern, CallbackPatternDb};
use calxgloss_algorithm::engine::{AlgorithmEngine, ScanSource};
use calxgloss_algorithm::pattern_db::PatternDatabase;
use calxgloss_algorithm::persist::AlgorithmPersistor;
use calxgloss_algorithm::types::{AlgorithmCategory, DetectionMethod};
use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_prompts::AlgorithmInfo;
use tempfile::TempDir;

// ------------------------------------------------------------
// The canned program
// ------------------------------------------------------------

const AB00: u64 = 0x1800_3ab00;
const E750: u64 = 0x1800_3e750;
const A12A0: u64 = 0x1800_412a0;

fn summary(name: &str, address: u64) -> FunctionSummary {
    FunctionSummary {
        name: name.to_string(),
        address,
    }
}

fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
    DecompiledFunction {
        name: name.to_string(),
        signature: signature.to_string(),
        body: format!("{signature}\n\n{{\n{body}}}\n"),
    }
}

/// A canned program implementing [`ScanSource`]: a sort the control
/// flow set recognizes, a CRC loop the string set reads from its own
/// body, and a compare callback `qsort` reaches through the call graph
/// — one reading per detector — plus a program-wide listing string
/// carrying a `CRC32` marker no body spells.
#[derive(Clone, Default)]
struct FakeProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
    literals: Vec<StringLiteral>,
    callers: HashMap<u64, Vec<String>>,
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

    async fn callers(&self, address: u64) -> Result<Vec<String>> {
        Ok(self.callers.get(&address).cloned().unwrap_or_default())
    }

    // The rest of the shared trait's reads: these tests never make
    // them, so they answer with empty or not-found data.
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
    let mut bodies = HashMap::new();
    bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "void FUN_18003ab00(int *param_1,int param_2)",
            "  int iVar2;\n\
             \x20 uint uVar3;\n\
             \x20 int iVar4;\n\
             \x20 \n\
             \x20 uVar3 = 0;\n\
             \x20 while (uVar3 < (uint)param_2) {\n\
             \x20   iVar2 = 0;\n\
             \x20   while (iVar2 < param_2 - 1) {\n\
             \x20     if (param_1[iVar2] < param_1[iVar2 + 1]) {\n\
             \x20       iVar4 = param_1[iVar2];\n\
             \x20       param_1[iVar2] = param_1[iVar2 + 1];\n\
             \x20       param_1[iVar2 + 1] = iVar4;\n\
             \x20     }\n\
             \x20     iVar2 = iVar2 + 1;\n\
             \x20   }\n\
             \x20   uVar3 = uVar3 + 1;\n\
             \x20 }\n\
             \x20 return;\n",
        ),
    );
    bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined4 FUN_18003e750(char *param_1)",
            "  uint uVar1;\n\
             \x20 \n\
             \x20 uVar1 = 0;\n\
             \x20 while (*param_1 != '\\0') {\n\
             \x20   uVar1 = (uVar1 ^ (ulong)(byte)*param_1) & 0xff;\n\
             \x20   uVar1 = (uVar1 >> 8) ^ crc_table[uVar1];\n\
             \x20   param_1 = param_1 + 1;\n\
             \x20 }\n\
             \x20 return uVar1;\n",
        ),
    );
    bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "int FUN_1800412a0(int *param_1,int *param_2)",
            "  if (*param_1 < *param_2) {\n\
             \x20   return -1;\n\
             \x20 }\n\
             \x20 if (*param_2 < *param_1) {\n\
             \x20   return 1;\n\
             \x20 }\n\
             \x20 return 0;\n",
        ),
    );
    let mut callers = HashMap::new();
    callers.insert(AB00, vec!["FUN_180001900".into()]);
    callers.insert(A12A0, vec!["qsort".into()]);
    FakeProgram {
        listing: vec![
            summary("FUN_18003ab00", AB00),
            summary("FUN_18003e750", E750),
            summary("FUN_1800412a0", A12A0),
        ],
        bodies,
        literals: vec![StringLiteral {
            address: 0x1801_29350,
            value: "CRC32 verification failed".into(),
        }],
        callers,
    }
}

// ------------------------------------------------------------
// The correlated canned program
// ------------------------------------------------------------

/// A canned program whose bodies call each other: a recursive split
/// that halves its range, and a library sort that hands the host the
/// comparator beside it in the listing — the pairs the correlation
/// detector reads across function boundaries.
fn correlated_program() -> FakeProgram {
    let mut bodies = HashMap::new();
    bodies.insert(
        "FUN_180050000".into(),
        function(
            "FUN_180050000",
            "void FUN_180050000(int *param_1,int param_2)",
            "  if (param_2 < 2) {\n\
             \x20   return;\n\
             \x20 }\n\
             \x20 FUN_180050000(param_1,param_2 / 2);\n\
             \x20 FUN_180050000(param_1 + (param_2 / 2),param_2 / 2);\n\
             \x20 return;",
        ),
    );
    bodies.insert(
        "FUN_180050100".into(),
        function(
            "FUN_180050100",
            "void FUN_180050100(int *param_1,int param_2)",
            "  qsort(param_1,param_2,4,FUN_1800412a0);\n\
             \x20 return;",
        ),
    );
    bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "int FUN_1800412a0(int *param_1,int *param_2)",
            "  if (*param_1 < *param_2) {\n\
             \x20   return -1;\n\
             \x20 }\n\
             \x20 return 1;",
        ),
    );
    FakeProgram {
        listing: vec![
            summary("FUN_180050000", 0x1800_50000),
            summary("FUN_180050100", 0x1800_50100),
            summary("FUN_1800412a0", A12A0),
        ],
        bodies,
        ..Default::default()
    }
}

// ------------------------------------------------------------
// Scan to disk
// ------------------------------------------------------------

#[tokio::test]
async fn a_scan_files_its_result_in_the_workspace_and_reads_back() {
    let workspace = TempDir::new().unwrap();
    let result = AlgorithmEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = AlgorithmPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/algorithm/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_every_hint_in_scan_order() {
    // Function by function along the listing, and within one function
    // the control flow match, then the string hint, then the callback
    // match — so two scans of the same program diff cleanly.
    let workspace = TempDir::new().unwrap();
    let result = AlgorithmEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, DetectionMethod)> = loaded
        .hints
        .iter()
        .map(|hint| (hint.function.as_str(), hint.method))
        .collect();
    assert_eq!(
        order,
        [
            ("FUN_18003ab00", DetectionMethod::CfgPattern),
            ("FUN_18003ab00", DetectionMethod::StringHint),
            ("FUN_18003e750", DetectionMethod::StringHint),
            ("FUN_1800412a0", DetectionMethod::StringHint),
            ("FUN_1800412a0", DetectionMethod::CallbackPattern),
        ]
    );
}

#[tokio::test]
async fn resolved_and_floored_hints_are_what_reaches_the_disk() {
    // A callback contract naming `crc` competes with the listing-only
    // crc claim on the sort function, and a floor of 40 drops the
    // weaker claims: the persisted document carries exactly the
    // resolved survivors — the stronger crc beside the sort shape, the
    // body match on the CRC loop, and nothing on the compare callback
    // whose only claim sat below the floor.
    let workspace = TempDir::new().unwrap();
    let result = AlgorithmEngine::with_source(program())
        .with_callback_db(CallbackPatternDb::with_patterns([CallbackPattern::new(
            "crc",
            AlgorithmCategory::Checksum,
            ["FUN_180001900"],
            2,
        )]))
        .with_min_confidence(40)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str, DetectionMethod)> = loaded
        .hints
        .iter()
        .map(|hint| (hint.function.as_str(), hint.algorithm.as_str(), hint.method))
        .collect();
    assert_eq!(
        order,
        [
            (
                "FUN_18003ab00",
                "comparison_sort",
                DetectionMethod::CfgPattern
            ),
            ("FUN_18003ab00", "crc", DetectionMethod::CallbackPattern),
            ("FUN_18003e750", "crc", DetectionMethod::StringHint),
        ],
        "one resolved claim per algorithm, floor survivors only, in scan order"
    );
}

#[tokio::test]
async fn correlated_hints_reach_the_persisted_document_naming_their_partners() {
    // The fourth detector's reading survives the whole flow: the scan
    // correlates a recursive split and a qsort/comparator pair, the
    // JSON on disk spells the method as `cross_function`, and each
    // correlated hint's evidence quotes the body line naming its
    // partner function.
    let workspace = TempDir::new().unwrap();
    let result = AlgorithmEngine::with_source(correlated_program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let document =
        std::fs::read_to_string(persistor.path_for("eqmain.dll")).expect("read document");
    assert!(
        document.contains("\"method\": \"cross_function\""),
        "the persisted JSON spells the new detection method"
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
    let evidence: Vec<&str> = loaded
        .hints
        .iter()
        .filter(|hint| hint.method == DetectionMethod::CrossFunction)
        .map(|hint| hint.evidence.as_str())
        .collect();
    assert_eq!(
        evidence,
        [
            "FUN_180050000(param_1,param_2 / 2);",
            "qsort(param_1,param_2,4,FUN_1800412a0);",
        ],
        "each correlated hint quotes the body line naming its partner"
    );
}

// ------------------------------------------------------------
// Pattern database
// ------------------------------------------------------------

#[tokio::test]
async fn a_pattern_file_configures_the_scan_and_reaches_the_persisted_document() {
    // The whole teaching path in one flow: a JSON file on disk names a
    // control flow shape and a callback contract no built-in set
    // carries, each with its own confidence; the scan configured from
    // the file recognizes them, and the persisted document carries
    // exactly those claims — the built-in sets, replaced whole, are
    // absent.
    let workspace = TempDir::new().unwrap();
    let patterns = workspace.path().join("patterns.json");
    std::fs::write(
        &patterns,
        r#"{
            "control_flow": [{
                "name": "crc32_variant",
                "category": "checksum",
                "match_patterns": ["crc_table\\["],
                "min_lines": 5,
                "confidence": 85
            }],
            "callback_contracts": [{
                "name": "my_qsort_compare",
                "category": "sorting",
                "host_patterns": ["\\bqsort\\b"],
                "param_count": 2,
                "confidence": 90
            }]
        }"#,
    )
    .unwrap();

    let database = PatternDatabase::load(&patterns).expect("pattern file");
    let result = AlgorithmEngine::with_source(program())
        .with_pattern_database(database)
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");
    let loaded = persistor.load("eqmain.dll").expect("load");

    let order: Vec<(&str, &str, u8)> = loaded
        .hints
        .iter()
        .map(|hint| {
            (
                hint.function.as_str(),
                hint.algorithm.as_str(),
                hint.confidence.value(),
            )
        })
        .collect();
    assert_eq!(
        order,
        [
            ("FUN_18003e750", "crc32_variant", 85),
            ("FUN_1800412a0", "my_qsort_compare", 90),
        ],
        "only the file's entries claim, each at its own confidence, in scan order"
    );
}

#[tokio::test]
async fn a_pattern_file_correlation_section_reaches_the_persisted_document() {
    // The fourth section rides the whole teaching path: a JSON file
    // names a qsort/comparator relationship under its own name and its
    // own confidence, the scan configured from the file correlates the
    // pair through it, and the persisted document carries exactly that
    // claim — the built-in relationships the section replaced,
    // `divide_and_conquer` and `comparison_sort`, are absent.
    let workspace = TempDir::new().unwrap();
    let patterns = workspace.path().join("patterns.json");
    std::fs::write(
        &patterns,
        r#"{
            "correlation_patterns": [{
                "name": "library_sort",
                "category": "sorting",
                "body_patterns": ["\\bqsort\\s*\\("],
                "partner_patterns": ["[*&][^;]*[^-](?:[<>]|==|!=)[^;]*[*&]"],
                "min_lines": 4,
                "confidence": 80
            }]
        }"#,
    )
    .unwrap();

    let database = PatternDatabase::load(&patterns).expect("pattern file");
    let result = AlgorithmEngine::with_source(correlated_program())
        .with_pattern_database(database)
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");
    let document =
        std::fs::read_to_string(persistor.path_for("eqmain.dll")).expect("read document");
    assert!(
        document.contains("\"method\": \"cross_function\""),
        "the file-taught relationship persists under the correlation method"
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str, u8)> = loaded
        .hints
        .iter()
        .map(|hint| {
            (
                hint.function.as_str(),
                hint.algorithm.as_str(),
                hint.confidence.value(),
            )
        })
        .collect();
    assert_eq!(
        order,
        [("FUN_180050100", "library_sort", 80)],
        "only the file's relationship claims, at its own confidence"
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = AlgorithmEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was recognized in the function it is about
    // to translate; an unknown function carries nothing.
    let sort_hints: Vec<&_> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(sort_hints.len(), 2);
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record renders into prompt data naming the algorithm and
    // family, the detector and confidence behind the claim, and the
    // evidence line.
    let rendered: Vec<AlgorithmInfo> = sort_hints
        .iter()
        .map(|hint| AlgorithmInfo::from(*hint))
        .collect();
    assert_eq!(rendered[0].algorithm, "comparison_sort");
    assert_eq!(rendered[0].category, "sorting");
    assert_eq!(rendered[0].method, "cfg_pattern");
    assert_eq!(rendered[0].confidence, 60);
    assert_eq!(rendered[1].algorithm, "crc");
    assert_eq!(rendered[1].category, "checksum");
    assert_eq!(rendered[1].method, "string_hint");
    // The listing-only reading survives the round trip as the weaker
    // program-wide claim.
    assert_eq!(rendered[1].confidence, 30);
    assert_eq!(rendered[1].evidence, "CRC32 verification failed");
}

#[tokio::test]
async fn a_loaded_callback_contract_reading_carries_its_host_as_evidence() {
    // The callback half of the scan reads the call graph; the host
    // caller name that matched the contract stands as the hint's
    // evidence through the persisted round trip.
    let workspace = TempDir::new().unwrap();
    let result = AlgorithmEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = AlgorithmPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let callback = loaded
        .for_function("FUN_1800412a0")
        .find(|hint| hint.method == DetectionMethod::CallbackPattern)
        .expect("the contract match");
    assert_eq!(callback.algorithm, "qsort_compare");
    assert_eq!(callback.category, AlgorithmCategory::Sorting);
    assert_eq!(callback.confidence.value(), 75);
    assert_eq!(callback.evidence, "qsort");
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = AlgorithmPersistor::new(workspace.path());

    let first = AlgorithmEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    persistor.save(&first).expect("save");

    // A second scan of a program whose only function recognizes nothing
    // replaces the document: the cache check still passes, but the
    // hints are gone.
    let quiet = FakeProgram {
        listing: vec![summary("FUN_18003e750", E750)],
        bodies: HashMap::from([(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined4 FUN_18003e750(char *param_1)",
                "  return 0;\n",
            ),
        )]),
        ..FakeProgram::default()
    };
    let second = AlgorithmEngine::with_source(quiet)
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
    let persistor = AlgorithmPersistor::new(workspace.path());

    let eqmain = AlgorithmEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&eqmain).expect("save");

    let eqgame = AlgorithmEngine::with_source(program())
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

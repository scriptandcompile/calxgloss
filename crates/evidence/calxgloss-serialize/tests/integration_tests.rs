//! Integration tests for the calxgloss-serialize crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Scan to disk** — [`SerializeEngine`] scans a canned program, the
//!   [`SerializePersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function), and the persisted list keeps every finding in scan
//!   order: function by function, and within one function the byte
//!   swaps in call order.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_ghidra::{DecompiledFunction, FunctionSummary};
use calxgloss_serialize::Result;
use calxgloss_serialize::engine::{ScanSource, SerializeEngine};
use calxgloss_serialize::persist::SerializePersistor;
use calxgloss_serialize::types::SerializeFinding;
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
/// body carries an `ntohl` call and an `htons` call — the byte-swap
/// shape — and one plain function that finds nothing.
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
        self.bodies.get(name).cloned().ok_or_else(|| {
            calxgloss_ghidra::GhidraError::NotFound {
                kind: "function",
                query: name.to_string(),
            }
            .into()
        })
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
            "  uVar1 = ntohl(local_18);\n\
             \x20 local_14 = htons(0x1234);\n",
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
    let result = SerializeEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = SerializePersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace
            .path()
            .join("re/analysis/serialize/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_keeps_findings_in_scan_order() {
    // The detector reads one body in call order, so what reaches disk
    // is function by function in listing order and, within one
    // function, the swap calls in body order — the order two scans
    // diff against.
    let workspace = TempDir::new().unwrap();
    let result = SerializeEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![("FUN_18003ab00", "byteswap"), ("FUN_18003ab00", "byteswap"),]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_three_kind_document_survives_the_round_trip() {
    // One canned scan, three kinds: the swap call, the pack chain, and
    // the signature comparison in one body reach disk interleaved in
    // scan order and read back with their record shapes intact.
    let workspace = TempDir::new().unwrap();
    let mut mixed = FakeProgram::empty();
    mixed.listing = vec![summary("FUN_18003ab00")];
    mixed.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = ntohl(local_18);\n\
             \x20 uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;\n\
             \x20 if (uVar7 == 0x89504e47) {\n",
        ),
    );
    let result = SerializeEngine::with_source(mixed)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result);
    let kinds: Vec<&str> = loaded.findings.iter().map(|f| f.kind()).collect();
    assert_eq!(kinds, vec!["byteswap", "bitpack", "magic"]);

    let SerializeFinding::BitPack(record) = &loaded.findings[1] else {
        unreachable!("the pack chain reads as a bitpack finding");
    };
    assert_eq!(record.pattern.to_string(), "shift_or_pack");
    assert_eq!(record.widths, [8, 8, 8, 8]);

    let SerializeFinding::Magic(record) = &loaded.findings[2] else {
        unreachable!("the signature comparison reads as a magic finding");
    };
    assert_eq!(record.format, "PNG");
    assert_eq!(record.magic, 0x8950_4E47);
    assert_eq!(record.suggestion, "png::Decoder");
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no Ghidra server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `SerializationInfo` prompt data, and the rendered
    // escalate prompt carries the SERIALIZATION section with each
    // finding's suggestion, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let mut mixed = FakeProgram::empty();
    mixed.listing = vec![summary("FUN_18003ab00")];
    mixed.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = ntohl(local_18);\n\
             \x20 uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;\n\
             \x20 if (uVar7 == 0x89504e47) {\n",
        ),
    );
    let result = SerializeEngine::with_source(mixed)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::SerializationInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::SerializationInfo::from)
        .collect();
    assert_eq!(findings.len(), 3, "the target function's three findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* manual shifts and masks */ }".into(),
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
        Vec::new(),
        Vec::new(),
        findings,
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("SERIALIZATION"));
    assert!(prompt.contains("byteorder::BE::read_u32"));
    assert!(prompt.contains("byteswap pattern, confidence 70"));
    assert!(prompt.contains("bitvec or named-field masking/shifting"));
    assert!(prompt.contains("bitpack pattern, confidence 60"));
    assert!(prompt.contains("png::Decoder"));
    assert!(prompt.contains("magic pattern, confidence 80"));
    assert!(prompt.contains("uVar1 = ntohl(local_18);"));
}

#[tokio::test]
async fn the_serialization_sentinel_renders_when_there_are_no_findings() {
    // A function the scan said nothing about still gets the section —
    // with the explicit sentinel, so the LLM knows the absence is a
    // scanned absence, not a missing step.
    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003e750".into(),
        "eqmain.dll".into(),
        "fn fun_18003e750() {} ".into(),
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
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("No serialization context available."));
}

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = SerializeEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate; the plain function carries nothing.
    let findings: Vec<&SerializeFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 2);
    assert!(loaded.for_function("FUN_18003e750").next().is_none());
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps the detector's detail and evidence through the
    // round trip, so a prompt sees the call that produced it.
    let SerializeFinding::ByteSwap(record) = findings[0] else {
        unreachable!("the swap call reads as a byteswap finding");
    };
    assert_eq!(record.operation, "ntohl");
    assert_eq!(record.width, 32);
    assert_eq!(record.suggestion, "byteorder::BE::read_u32");
    assert_eq!(record.evidence, "uVar1 = ntohl(local_18);");

    let SerializeFinding::ByteSwap(record) = findings[1] else {
        unreachable!("the second swap call reads as a byteswap finding");
    };
    assert_eq!(record.operation, "htons");
    assert_eq!(record.width, 16);
    assert_eq!(record.suggestion, "byteorder::BE::read_u16");
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = SerializePersistor::new(workspace.path());

    let first = SerializeEngine::with_source(program())
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
    let second = SerializeEngine::with_source(quiet)
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
    let persistor = SerializePersistor::new(workspace.path());

    let eqmain = SerializeEngine::with_source(program())
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
            "  uVar1 = __builtin_bswap32(local_18);\n",
        ),
    );
    let eqgame = SerializeEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

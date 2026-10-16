//! Integration tests for the calxgloss-consts crate.
//!
//! These tests exercise the multi-module workflows the unit tests
//! cannot cover on their own:
//!
//! - **Scan to disk** — [`ConstEngine`] scans a canned program, the
//!   [`ConstPersistor`] files the result in the workspace layout, and
//!   loading it back yields the same result the scan returned.
//! - **Consumption** — the loaded result answers the lookups a
//!   translation pipeline makes (the findings recorded for one
//!   function, the program-level named constants and flag families
//!   included), and the persisted list keeps every finding in scan
//!   order: function by function the bitmask groups then the enum
//!   candidates, and the program-level named constants then merged
//!   flag families appended after them.
//! - **Prompt rendering** — the loaded findings render into `ConstInfo`
//!   prompt data and the escalate prompt carries the CONSTANTS section,
//!   the repeated literal's context-named `const` form included.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without a Ghidra server.

use std::collections::HashMap;

use calxgloss_consts::engine::{ConstEngine, ScanSource};
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_consts::types::ConstFinding;
use calxgloss_ghidra::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, FunctionSummary, GhidraError,
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
/// body carries a flag-bit pair, a four-case switch run, and a
/// repeated magic number — one finding family per detector — and one
/// plain function that repeats the magic number once so the frequency
/// analyzer sees it across two functions.
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
            .ok_or_else(|| GhidraError::NotFound {
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

fn program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if ((uVar1 & 0x400) != 0) {\n\
             \x20   uVar1 |= 0x100;\n\
             \x20 }\n\
             \x20 switch(local_10) {\n\
             \x20 case 0:\n\
             \x20 case 1:\n\
             \x20 case 2:\n\
             \x20 case 3:\n\
             \x20   dispatch();\n\
             \x20 }\n\
             \x20 size = 0x280;\n\
             \x20 copy(dst, 0x280);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  reserve(0x280);\n\
             \x20 return;\n",
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
    let result = ConstEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let persistor = ConstPersistor::new(workspace.path());
    assert!(!persistor.exists("eqmain.dll"), "nothing is cached yet");

    persistor.save(&result).expect("save");
    assert!(persistor.exists("eqmain.dll"));
    assert_eq!(
        persistor.path_for("eqmain.dll"),
        workspace.path().join("re/analysis/consts/eqmain.dll.json")
    );

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result, "the document round-trips exactly");
}

#[tokio::test]
async fn the_persisted_document_tags_findings_by_kind_in_scan_order() {
    // The three detectors read disjoint shapes in one pass, so what
    // reaches disk is function by function in listing order — bitmask
    // then enum — with the program-level named constants appended
    // after them, each under its serde `kind` tag.
    let workspace = TempDir::new().unwrap();
    let result = ConstEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).expect("read");
    assert!(raw.contains("\"kind\": \"bitflag_group\""));
    assert!(raw.contains("\"kind\": \"enum_candidate\""));
    assert!(raw.contains("\"kind\": \"named_constant\""));

    let loaded = persistor.load("eqmain.dll").expect("load");
    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "bitflag_group"),
            ("FUN_18003ab00", "enum_candidate"),
            ("", "named_constant"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_loaded_result_answers_the_pipeline_lookups() {
    let workspace = TempDir::new().unwrap();
    let result = ConstEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");

    // The pipeline asks what was found for the function it is about to
    // translate: the shaped function carries all three kinds, and the
    // plain function carries the named constant it uses too.
    let findings: Vec<&ConstFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 3);
    let plain: Vec<&ConstFinding> = loaded.for_function("FUN_18003e750").collect();
    assert_eq!(plain.len(), 1, "the named constant belongs to its users");
    assert!(loaded.for_function("FUN_180099999").next().is_none());

    // Each record keeps its detector's detail and evidence through the
    // round trip, so a prompt sees the shape that produced it.
    let ConstFinding::BitflagGroup(group) = findings[0] else {
        unreachable!("the flag bits read as a bitflag finding");
    };
    assert_eq!(group.bits, vec![8, 10]);
    assert_eq!(group.mask, 0x500);
    assert!(group.suggestion.contains("bitflags! struct Flags: u16"));
    assert!(group.evidence.contains("uVar1 & 0x400"));

    let ConstFinding::EnumCandidate(candidate) = findings[1] else {
        unreachable!("the case run reads as an enum finding");
    };
    assert_eq!(candidate.values, vec![0, 1, 2, 3]);
    assert_eq!(
        candidate.suggestion,
        "enum State { /* variants for 0..=3 */ }"
    );

    let ConstFinding::NamedConstant(constant) = findings[2] else {
        unreachable!("the repeated literal reads as a named-constant finding");
    };
    assert_eq!(constant.value, 0x280);
    assert_eq!(constant.count, 3);
    assert_eq!(
        constant.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );
    // The context name the body's `size = 0x280;` gave the value rides
    // the record through the persisted document.
    assert_eq!(constant.name.as_deref(), Some("SIZE_0x280"));
    assert_eq!(constant.suggestion, "const SIZE_0x280: u32 = 0x280;");
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no Ghidra server needed: the fixture
    // document on disk answers the per-function lookup, the findings
    // render into `ConstInfo` prompt data, and the rendered escalate
    // prompt carries the CONSTANTS section with each finding's
    // suggestion, kind, confidence, and evidence.
    let workspace = TempDir::new().unwrap();
    let result = ConstEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<calxgloss_prompts::ConstInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::ConstInfo::from)
        .collect();
    assert_eq!(findings.len(), 3, "the target function's three findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* bare integer literals everywhere */ }".into(),
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
        findings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONSTANTS"));
    assert!(prompt.contains("bitflags! struct Flags: u16"));
    assert!(prompt.contains("bitflag_group, confidence 70"));
    assert!(prompt.contains("enum State { /* variants for 0..=3 */ }"));
    assert!(prompt.contains("enum_candidate, confidence 70"));
    assert!(prompt.contains("const SIZE_0x280: u32 = 0x280;"));
    assert!(prompt.contains("named_constant, confidence 60"));
    assert!(prompt.contains("uVar1 & 0x400"));
}

#[tokio::test]
async fn a_decomposed_composite_group_survives_the_round_trip_and_the_prompt() {
    // The widened group — bits completed by a decomposed composite
    // mask — rides the persisted document with the existing record
    // shape (no schema change) and renders into the escalate prompt's
    // CONSTANTS section carrying the widened suggestion and the
    // composite's evidence line.
    let workspace = TempDir::new().unwrap();
    let mut composite = FakeProgram::empty();
    composite.listing = vec![summary("FUN_18003ab00")];
    composite.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n  local_10 = 0x200;\n  uVar1 &= 0x700;\n",
        ),
    );
    let result = ConstEngine::with_source(composite)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<&ConstFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 1, "the completed group is the finding");
    let ConstFinding::BitflagGroup(group) = findings[0] else {
        unreachable!("the flag bits read as a bitflag finding");
    };
    assert_eq!(group.bits, vec![8, 9, 10]);
    assert_eq!(group.mask, 0x700);
    assert_eq!(group.bit_width, 11);
    assert!(group.evidence.contains("uVar1 &= 0x700"));

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* bare integer literals everywhere */ }".into(),
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
        findings
            .iter()
            .map(|finding| calxgloss_prompts::ConstInfo::from(*finding))
            .collect(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("bitflags! struct Flags: u16 { /* bits: 0x100, 0x200, 0x400 */ }"));
    assert!(prompt.contains("uVar1 &= 0x700"));
}

#[tokio::test]
async fn a_merged_flag_family_survives_the_round_trip_and_the_prompt() {
    // Two functions reading one flag surface through a shared bit:
    // the per-function groups ride the persisted document beside the
    // merged family record, the family answers the per-function
    // lookup of each contributor, and it renders into the escalate
    // prompt's CONSTANTS section at its above-the-tier confidence.
    let workspace = TempDir::new().unwrap();
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if ((uVar1 & 0x400) != 0) {\n\
             \x20   uVar1 |= 0x100;\n\
             \x20 }\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  uVar2 &= 0x400;\n\
             \x20 uVar2 |= 0x800;\n",
        ),
    );
    let result = ConstEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).expect("read");
    assert!(raw.contains("\"kind\": \"flag_family\""));

    let loaded = persistor.load("eqmain.dll").expect("load");
    let families: Vec<&ConstFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "flag_family")
        .collect();
    assert_eq!(families.len(), 1, "one family record per merged family");
    let ConstFinding::FlagFamily(family) = families[0] else {
        unreachable!("the merged bits read as a flag-family finding");
    };
    assert_eq!(family.bits, vec![8, 10, 11]);
    assert_eq!(family.mask, 0xd00);
    assert_eq!(
        family.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );
    assert_eq!(
        family.confidence,
        calxgloss_consts::types::Confidence::new(80)
    );

    // Each contributor's per-function lookup carries its own group
    // plus the family it contributed to.
    let findings: Vec<&ConstFinding> = loaded.for_function("FUN_18003e750").collect();
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.kind())
            .collect::<Vec<_>>(),
        vec!["bitflag_group", "flag_family"]
    );

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* bare integer literals everywhere */ }".into(),
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
        loaded
            .for_function("FUN_18003ab00")
            .map(calxgloss_prompts::ConstInfo::from)
            .collect(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONSTANTS"));
    assert!(prompt.contains("bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }"));
    assert!(prompt.contains("flag_family, confidence 80"));
    assert!(
        prompt.contains("FUN_18003e750: bits 0x400, 0x800"),
        "the prompt carries the contributing groups as evidence"
    );
}

// ------------------------------------------------------------
// Cache behavior
// ------------------------------------------------------------

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let workspace = TempDir::new().unwrap();
    let persistor = ConstPersistor::new(workspace.path());

    let first = ConstEngine::with_source(program())
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
    let second = ConstEngine::with_source(quiet)
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
    let persistor = ConstPersistor::new(workspace.path());

    let eqmain = ConstEngine::with_source(program())
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
            "  if ((x & 0x1) != 0) {\n\
             \x20   x |= 0x2;\n\
             \x20 }\n",
        ),
    );
    let eqgame = ConstEngine::with_source(other)
        .scan("eqgame.dll")
        .await
        .expect("scan");
    persistor.save(&eqgame).expect("save");

    assert_eq!(persistor.load("eqmain.dll").unwrap(), eqmain);
    assert_eq!(persistor.load("eqgame.dll").unwrap(), eqgame);
    assert!(!persistor.exists("other.dll"));
}

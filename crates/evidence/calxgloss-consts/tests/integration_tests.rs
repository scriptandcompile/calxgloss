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
//!   function, the program-level named constants, flag families,
//!   protocol constants, and color palette included), and the
//!   persisted list keeps every finding in scan order: function by
//!   function the bitmask groups then the enum candidates, and the
//!   program-level named constants, merged flag families, protocol
//!   constants, and color palette appended after them.
//! - **Prompt rendering** — the loaded findings render into `ConstInfo`
//!   prompt data and the escalate prompt carries the CONSTANTS section,
//!   the repeated literal's context-named `const` form included.
//! - **Codegen artifact** — the loaded result re-renders to a
//!   byte-identical Rust source string, every finding kind included,
//!   and nothing reads the generated file back: the JSON stays the
//!   single source of truth.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_consts::codegen::render_codegen;
use calxgloss_consts::engine::{ConstEngine, ScanSource};
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_consts::types::ConstFinding;
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
    assert!(raw.contains("\"kind\": \"color_constant\""));

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
            ("", "color_constant"),
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
    // translate: the shaped function carries all four kinds, and the
    // plain function carries the named constant it uses and one of
    // the palette's colors too.
    let findings: Vec<&ConstFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 4);
    let plain: Vec<&ConstFinding> = loaded.for_function("FUN_18003e750").collect();
    assert_eq!(
        plain.len(),
        2,
        "the named constant and the palette belong to their users"
    );
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

    // The color-shaped literals the bodies carry group into one
    // palette through the round trip too.
    let ConstFinding::ColorConstant(palette) = findings[3] else {
        unreachable!("the color-shaped literals read as a palette finding");
    };
    assert_eq!(palette.values, vec![3, 0x280]);
    assert_eq!(
        palette.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the fixture
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
    assert_eq!(findings.len(), 4, "the target function's four findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* bare integer literals everywhere */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            const_findings: findings,
            ..Default::default()
        },
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
    assert!(prompt.contains("const COLOR_0x280: u32 = 0x280;"));
    assert!(prompt.contains("color_constant, confidence 60"));
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
        calxgloss_prompts::EvidenceBundle {
            const_findings: findings
                .iter()
                .map(|finding| calxgloss_prompts::ConstInfo::from(*finding))
                .collect(),
            ..Default::default()
        },
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
        calxgloss_prompts::EvidenceBundle {
            const_findings: loaded
                .for_function("FUN_18003ab00")
                .map(calxgloss_prompts::ConstInfo::from)
                .collect(),
            ..Default::default()
        },
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
// Protocol constants
// ------------------------------------------------------------

#[tokio::test]
async fn a_protocol_constant_survives_the_round_trip_and_the_prompt() {
    // A single-use magic in one body — far below the repetition
    // threshold: the protocol finding rides the persisted document
    // under its own kind tag with the table name and protocol label,
    // answers the using function's per-function lookup, and renders
    // into the escalate prompt's CONSTANTS section at its
    // above-the-tier confidence.
    let workspace = TempDir::new().unwrap();
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (signature == 0x89504e47) {\n    parse();\n  }\n",
        ),
    );
    let result = ConstEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).expect("read");
    assert!(raw.contains("\"kind\": \"protocol_constant\""));

    let loaded = persistor.load("eqmain.dll").expect("load");
    let findings: Vec<&ConstFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(
        findings.len(),
        1,
        "the protocol finding answers the using function's lookup"
    );
    let ConstFinding::ProtocolConstant(record) = findings[0] else {
        unreachable!("the matched magic reads as a protocol-constant finding");
    };
    assert_eq!(record.value, 0x89504e47);
    assert_eq!(record.name, "PNG_MAGIC");
    assert_eq!(record.protocol, "PNG image format");
    assert_eq!(record.count, 1, "a single use still reports");
    assert_eq!(record.functions, vec!["FUN_18003ab00".to_string()]);
    assert_eq!(
        record.confidence,
        calxgloss_consts::types::Confidence::new(75)
    );

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* bare integer literals everywhere */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            const_findings: loaded
                .for_function("FUN_18003ab00")
                .map(calxgloss_prompts::ConstInfo::from)
                .collect(),
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONSTANTS"));
    assert!(prompt.contains("const PNG_MAGIC: u32 = 0x89504e47;"));
    assert!(prompt.contains("protocol_constant, confidence 75"));
    assert!(
        prompt.contains("0x89504e47 used 1 times in FUN_18003ab00"),
        "the prompt carries the usage summary as evidence"
    );
}

// ------------------------------------------------------------
// Color palettes
// ------------------------------------------------------------

#[tokio::test]
async fn a_color_constant_survives_the_round_trip_and_the_prompt() {
    // Two color-shaped literals across two functions, each seen once
    // — far below the repetition bar: the palette finding rides the
    // persisted document under its own kind tag, answers each using
    // function's per-function lookup, and renders into the escalate
    // prompt's CONSTANTS section at the named-constant tier.
    let workspace = TempDir::new().unwrap();
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  fill(dst, 0x123456);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  fill(dst, 0xff00ff);\n",
        ),
    );
    let result = ConstEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).expect("read");
    assert!(raw.contains("\"kind\": \"color_constant\""));

    let loaded = persistor.load("eqmain.dll").expect("load");
    let palettes: Vec<&ConstFinding> = loaded
        .findings
        .iter()
        .filter(|finding| finding.kind() == "color_constant")
        .collect();
    assert_eq!(palettes.len(), 1, "one palette finding per binary");
    let ConstFinding::ColorConstant(record) = palettes[0] else {
        unreachable!("the color-shaped values read as a palette finding");
    };
    assert_eq!(record.values, vec![0x123456, 0xff00ff]);
    assert_eq!(
        record.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );
    assert_eq!(
        record.confidence,
        calxgloss_consts::types::Confidence::new(60)
    );

    // The palette answers the per-function lookup of every function
    // that uses one of its colors.
    for function in ["FUN_18003ab00", "FUN_18003e750"] {
        let kinds: Vec<&str> = loaded
            .for_function(function)
            .map(|finding| finding.kind())
            .collect();
        assert_eq!(
            kinds,
            ["color_constant"],
            "the palette answers {function}'s lookup"
        );
    }

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* bare integer literals everywhere */ }".into(),
        "Wrong result".into(),
        calxgloss_prompts::EvidenceBundle {
            const_findings: loaded
                .for_function("FUN_18003ab00")
                .map(calxgloss_prompts::ConstInfo::from)
                .collect(),
            ..Default::default()
        },
        Vec::new(),
    )
    .expect("the escalate prompt should render");

    assert!(prompt.contains("CONSTANTS"));
    assert!(
        prompt.contains(
            "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = 0xff00ff;"
        )
    );
    assert!(prompt.contains("color_constant, confidence 60"));
    assert!(
        prompt.contains("0x123456 used 1 times in FUN_18003ab00"),
        "the prompt carries the palette summary as evidence"
    );
}

// ------------------------------------------------------------
// Codegen artifact
// ------------------------------------------------------------

#[tokio::test]
async fn the_codegen_render_regenerates_byte_identically_from_a_loaded_document() {
    // The JSON stays the single source of truth: the artifact is
    // re-rendered from the loaded document, byte-identically, and
    // nothing reads it back.
    let workspace = TempDir::new().expect("workspace");
    let persistor = ConstPersistor::new(workspace.path());
    let result = ConstEngine::with_source(program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    let first = render_codegen(&loaded);
    let second = render_codegen(&loaded);
    assert_eq!(
        first, second,
        "two renders of the same document are byte-identical"
    );

    // The enum run and the context-named constant spell out as code;
    // the lone per-function bitflag group merged into no family, so it
    // contributes no block — the file names only what the findings
    // support.
    assert!(
        first.contains("#[repr(i64)]\npub enum FUN_18003ab00_State {\n"),
        "{first}"
    );
    assert!(first.contains("    VALUE_0 = 0,\n"), "{first}");
    assert!(first.contains("    VALUE_3 = 3,\n"), "{first}");
    assert!(
        first.contains("const SIZE_0x280: u32 = 0x280;\n"),
        "{first}"
    );
    assert!(!first.contains("bitflags!"), "no family, no block: {first}");
}

#[tokio::test]
async fn two_separate_scans_render_byte_identical_codegen() {
    // The promise a reviewer leans on: rescanning the program and
    // re-rendering changes only what the scan actually learned, never
    // the renderer's own ordering or formatting — and the header names
    // only the binary, never either scan time.
    let first = render_codegen(
        &ConstEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("first scan"),
    );
    let second = render_codegen(
        &ConstEngine::with_source(program())
            .scan("eqmain.dll")
            .await
            .expect("second scan"),
    );

    assert_eq!(first, second);
    assert!(
        first.starts_with(
            "// Constant reconstruction for eqmain.dll, rendered by `calxgloss consts`.\n"
        ),
        "{first}"
    );
}

#[tokio::test]
async fn a_loaded_document_carrying_every_kind_renders_every_section() {
    // A program yielding a merged flag family, an enum run, a
    // context-named constant, a protocol magic, and a color palette:
    // the loaded document renders the whole reconstruction — the
    // family's position-named bits, the run's value-named variants,
    // and a const per named, protocol, and color record.
    let workspace = TempDir::new().expect("workspace");
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
             \x20 copy(dst, 0x280);\n\
             \x20 if (magic == 0x89504e47) {\n\
             \x20   read_header();\n\
             \x20 }\n\
             \x20 fill(dst, 0x123456);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  uVar2 &= 0x400;\n\
             \x20 uVar2 |= 0x800;\n\
             \x20 reserve(0x280);\n\
             \x20 fill(dst, 0xff00ff);\n",
        ),
    );
    let result = ConstEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = ConstPersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let rendered = render_codegen(&persistor.load("eqmain.dll").expect("load"));

    // The merged family: one bitflags block over the union of bits,
    // each named by position, preceded by its contributing functions.
    assert!(
        rendered.contains(
            "// FUN_18003ab00, FUN_18003e750\nbitflags! {\n    struct Flags_0xd00: u16 {\n"
        ),
        "{rendered}"
    );
    assert!(
        rendered.contains("        const BIT_8 = 1 << 8;\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains("        const BIT_11 = 1 << 11;\n"),
        "{rendered}"
    );

    // The enum run, the context-named constant, the protocol magic,
    // and the palette each spell their declaration.
    assert!(
        rendered.contains("#[repr(i64)]\npub enum FUN_18003ab00_State {\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains("const SIZE_0x280: u32 = 0x280;\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains("const PNG_MAGIC: u32 = 0x89504e47;\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains("const COLOR_0x123456: u32 = 0x123456;\n"),
        "{rendered}"
    );
    assert!(
        rendered.contains("const COLOR_0xff00ff: u32 = 0xff00ff;\n"),
        "{rendered}"
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

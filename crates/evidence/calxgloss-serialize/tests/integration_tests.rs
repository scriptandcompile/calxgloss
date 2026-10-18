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
//!   swaps in call order, with the composed format layout and the
//!   protocol message identification riding at the end and the
//!   binary-level endianness map appended after them all.
//! - **Seven-kind composition** — one canned program carrying every
//!   serialization shape lands all seven finding kinds in one scan in
//!   stable order, the document persists byte-identically across two
//!   scans, every kind renders into the escalate prompt, the
//!   per-function lookup answers the binary-level map to each of its
//!   contributors, and the confidence ladder ranks every composed
//!   claim above the single signals that fed it.
//! - **Cache behavior** — the `exists` check decides whether a scan
//!   runs, and a rescan replaces the cached document.
//!
//! The fake program implements [`ScanSource`], so the whole flow runs
//! without an external server.

use std::collections::HashMap;

use calxgloss_ghidra::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
use calxgloss_serialize::engine::{ScanSource, SerializeEngine};
use calxgloss_serialize::persist::SerializePersistor;
use calxgloss_serialize::types::{
    Confidence, FormatDirection, SerializeFinding, ValidationShape, WireEndianness,
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

/// A canned program carrying every serialization shape at once: one
/// protocol handler function whose body compares a protocol magic,
/// swaps a 32-bit field through `ntohl`, packs four 8-bit fields,
/// checks a checksum, and checks a framing length — so the function
/// carries its component rows (swap, pack, magic, validation) and
/// both composed claims (the format layout and the protocol message)
/// at once — and a second function whose only shape is a 16-bit
/// network-order swap, a second contributor to the binary-level
/// endianness map.
fn seven_kind_program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 == 0x86dd) {\n\
             \x20 uVar1 = ntohl(local_18);\n\
             \x20 uVar3 = (uVar4 << 0x18) | ((uint)uVar5 << 0x10) | (uVar6 << 8) | (uint)uVar7;\n\
             \x20 if (uVar8 == uVar9 + uVar10) {\n\
             \x20 if (uVar11 == local_1c + -4) {\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  uVar2 = htons(local_14);\n",
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
        vec![
            ("FUN_18003ab00", "byteswap"),
            ("FUN_18003ab00", "byteswap"),
            ("FUN_18003ab00", "serialization_format"),
            ("", "endianness_map"),
        ]
    );
}

// ------------------------------------------------------------
// Consumption
// ------------------------------------------------------------

#[tokio::test]
async fn a_five_kind_document_survives_the_round_trip() {
    // One canned scan, five kinds: the swap call, the pack chain, the
    // signature comparison, the format the swap and pack compose, and
    // the endianness map the swap profiles reach disk in scan order
    // and read back with their record shapes intact.
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
    assert_eq!(
        kinds,
        vec![
            "byteswap",
            "bitpack",
            "magic",
            "serialization_format",
            "endianness_map"
        ]
    );

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

    let SerializeFinding::SerializationFormat(record) = &loaded.findings[3] else {
        unreachable!("the swap and pack readings compose a format finding");
    };
    assert_eq!(record.fields.len(), 5);
    assert_eq!(record.direction, Some(FormatDirection::Reader));
    assert_eq!(record.confidence, Confidence::new(75));

    let SerializeFinding::EndiannessMap(record) = &loaded.findings[4] else {
        unreachable!("the swap call profiles an endianness map");
    };
    assert_eq!(record.entries.len(), 1);
    assert_eq!(record.entries[0].width, 32);
    assert_eq!(record.entries[0].endianness, WireEndianness::BigEndian);
    assert_eq!(record.entries[0].functions, ["FUN_18003ab00"]);
    assert_eq!(record.confidence, Confidence::new(75));
}

#[tokio::test]
async fn a_validation_document_survives_the_round_trip_and_reaches_the_prompt() {
    // The cross-field validation reading end to end: a checksum and a
    // framing comparison in one body land as validation findings after
    // the swap call, ride the persisted document through the round
    // trip with their record shapes intact, and render into the
    // escalate prompt's SERIALIZATION section.
    let workspace = TempDir::new().expect("tempdir");
    let mut parser = FakeProgram::empty();
    parser.listing = vec![summary("FUN_18003ab00")];
    parser.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = ntohl(local_18);\n\
             \x20 if (uVar7 == uVar5 + uVar6) {\n\
             \x20 if (local_18 + -4 == uVar4) {\n",
        ),
    );
    let result = SerializeEngine::with_source(parser)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result);
    let kinds: Vec<&str> = loaded.findings.iter().map(|f| f.kind()).collect();
    assert_eq!(
        kinds,
        vec![
            "byteswap",
            "cross_field_validation",
            "cross_field_validation",
            "endianness_map"
        ],
        "the validation findings land after the swap call, in body order"
    );

    let SerializeFinding::CrossFieldValidation(record) = &loaded.findings[1] else {
        unreachable!("the checksum comparison reads as a validation finding");
    };
    assert_eq!(record.shape, ValidationShape::Checksum);
    assert_eq!(record.field, "uVar7");
    assert_eq!(record.computed, "uVar5 + uVar6");
    assert_eq!(record.confidence, Confidence::new(65));
    assert_eq!(record.evidence, "if (uVar7 == uVar5 + uVar6) {");

    let SerializeFinding::CrossFieldValidation(record) = &loaded.findings[2] else {
        unreachable!("the remaining-count comparison reads as a validation finding");
    };
    assert_eq!(record.shape, ValidationShape::Length);
    assert_eq!(record.field, "uVar4");
    assert_eq!(record.computed, "local_18 + -4");

    let findings: Vec<calxgloss_prompts::SerializationInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::SerializationInfo::from)
        .collect();
    assert_eq!(findings.len(), 4, "the target function's four findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* hand-rolled parse */ }".into(),
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
    assert!(prompt.contains("cross_field_validation pattern, confidence 65"));
    assert!(prompt.contains("checked parse or validate step on the Rust type"));
    assert!(prompt.contains("if (uVar7 == uVar5 + uVar6) {"));
    assert!(prompt.contains("endianness_map pattern, confidence 75"));
    assert!(prompt.contains("program-wide BE wire order at u32 (byteorder BE types)"));
}

#[tokio::test]
async fn a_protocol_message_survives_the_round_trip_and_reaches_the_prompt() {
    // The protocol identification end to end: a protocol magic
    // comparison, an `ntohl`, and a checksum comparison in one body
    // land the handler claim after its components, ride the persisted
    // document through the round trip with its record shape intact,
    // and render into the escalate prompt's SERIALIZATION section so
    // the translation can aim at protocol-aware decoding.
    let workspace = TempDir::new().expect("tempdir");
    let mut handler = FakeProgram::empty();
    handler.listing = vec![summary("FUN_18003ab00")];
    handler.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 == 0x86dd) {\n\
             \x20 uVar1 = ntohl(local_18);\n\
             \x20 if (uVar7 == uVar5 + uVar6) {\n",
        ),
    );
    let result = SerializeEngine::with_source(handler)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result);
    let kinds: Vec<&str> = loaded.findings.iter().map(|f| f.kind()).collect();
    assert_eq!(
        kinds,
        vec![
            "byteswap",
            "magic",
            "cross_field_validation",
            "protocol_message",
            "endianness_map"
        ],
        "the handler claim lands last among its function's findings"
    );

    let SerializeFinding::ProtocolMessage(record) = &loaded.findings[3] else {
        unreachable!("the corroborated sniff reads back as a protocol message finding");
    };
    assert_eq!(record.protocol, "IPv6");
    assert_eq!(record.magic, 0x86DD);
    assert_eq!(
        record.corroborations,
        ["ntohl swap", "checksum validation"],
        "the corroborating readings stay listed through the round trip"
    );
    assert_eq!(record.confidence, Confidence::new(85));
    assert_eq!(
        record.suggestion,
        "protocol-aware IPv6 message decode (byteorder BE reads)"
    );

    let findings: Vec<calxgloss_prompts::SerializationInfo> = loaded
        .for_function("FUN_18003ab00")
        .map(calxgloss_prompts::SerializationInfo::from)
        .collect();
    assert_eq!(findings.len(), 5, "the target function's five findings");

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* hand-rolled packet parse */ }".into(),
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
    assert!(prompt.contains("protocol_message pattern, confidence 85"));
    assert!(prompt.contains("protocol-aware IPv6 message decode (byteorder BE reads)"));
    assert!(prompt.contains("if (uVar2 == 0x86dd) {"));
    assert!(prompt.contains("endianness_map pattern, confidence 75"));
    assert!(prompt.contains("program-wide BE wire order at u32 (byteorder BE types)"));
}

#[tokio::test]
async fn a_loaded_result_renders_into_the_escalate_prompt() {
    // The whole escalate path, no external server needed: the fixture
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
    assert_eq!(findings.len(), 5, "the target function's five findings");

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
    assert!(prompt.contains("serialization_format pattern, confidence 75"));
    assert!(prompt.contains("byteorder reader: read_u32 then 8+8+8+8 bitfields"));
    assert!(prompt.contains("endianness_map pattern, confidence 75"));
    assert!(prompt.contains("program-wide BE wire order at u32 (byteorder BE types)"));
}

#[tokio::test]
async fn the_serialization_section_is_omitted_when_there_are_no_findings() {
    // A function the scan said nothing about gets no section at all —
    // empty context costs prompt tokens and buys the model nothing.
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

    assert!(!prompt.contains("SERIALIZATION"));
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
    // translate; the plain function carries nothing — and the map never
    // names it, so the map stays absent from its lookup too.
    let findings: Vec<&SerializeFinding> = loaded.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 4);
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

    // The two swap readings compose a layout, and the disagreeing name
    // families (a read and a write) leave its direction unnamed.
    let SerializeFinding::SerializationFormat(record) = findings[2] else {
        unreachable!("the two swap readings compose a format finding");
    };
    assert_eq!(record.fields.len(), 2);
    assert_eq!(record.fields[0].width, 32);
    assert_eq!(record.fields[0].endianness, Some(WireEndianness::BigEndian));
    assert_eq!(record.fields[1].width, 16);
    assert_eq!(record.direction, None);

    // The program-wide profile rides along with the function's own
    // findings: both swapped widths, each naming this function.
    let SerializeFinding::EndiannessMap(record) = findings[3] else {
        unreachable!("the swap calls profile an endianness map");
    };
    assert_eq!(record.entries.len(), 2);
    assert_eq!(record.entries[0].width, 16);
    assert_eq!(record.entries[0].endianness, WireEndianness::BigEndian);
    assert_eq!(record.entries[0].functions, ["FUN_18003ab00"]);
    assert_eq!(record.entries[1].width, 32);
    assert_eq!(record.entries[1].functions, ["FUN_18003ab00"]);
    assert_eq!(record.confidence, Confidence::new(75));
    assert_eq!(
        record.suggestion,
        "program-wide BE wire order at u16, u32 (byteorder BE types)"
    );
}

#[tokio::test]
async fn the_endianness_map_survives_the_round_trip_and_answers_its_contributors() {
    // The integration story for the profile: swaps in two functions
    // land one map on disk, and loading it back answers the map to
    // every contributing function — the program-level context a
    // function-level prompt reads.
    let workspace = TempDir::new().expect("tempdir");
    let mut pair = FakeProgram::empty();
    pair.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    pair.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = ntohl(local_18);\n",
        ),
    );
    pair.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  uVar2 = htons(local_14);\n",
        ),
    );
    let result = SerializeEngine::with_source(pair)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(loaded, result);

    let maps: Vec<&calxgloss_serialize::types::EndiannessMap> = loaded
        .findings
        .iter()
        .filter_map(|finding| match finding {
            SerializeFinding::EndiannessMap(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(maps.len(), 1, "one map per scan, through the round trip");
    let map = maps[0];
    assert_eq!(map.entries.len(), 2);
    assert_eq!(map.entries[0].width, 16);
    assert_eq!(map.entries[0].functions, ["FUN_18003e750"]);
    assert_eq!(map.entries[1].width, 32);
    assert_eq!(map.entries[1].functions, ["FUN_18003ab00"]);

    for contributor in ["FUN_18003ab00", "FUN_18003e750"] {
        let answered: Vec<&SerializeFinding> = loaded
            .for_function(contributor)
            .filter(|finding| finding.kind() == "endianness_map")
            .collect();
        assert_eq!(answered.len(), 1, "{contributor} reads the map");
        assert_eq!(answered[0].confidence(), Confidence::new(75));
    }
}

// ------------------------------------------------------------
// Seven-kind composition
// ------------------------------------------------------------

#[tokio::test]
async fn the_seven_kind_document_survives_scan_persist_and_load_in_scan_order() {
    // The coexistence proof: one scan of one program lands all seven
    // kinds. The handler function carries its component rows — the
    // swap, the pack chain, the magic sniff, the checksum and framing
    // validations — beside both composed claims, the format layout
    // and the protocol message, none suppressing another; the second
    // function contributes its own swap; and the binary-level map
    // rides last. The document round-trips through persist and load
    // with every record shape intact, in the scan order two scans
    // diff against.
    let workspace = TempDir::new().expect("tempdir");
    let result = SerializeEngine::with_source(seven_kind_program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let persistor = SerializePersistor::new(workspace.path());
    persistor.save(&result).expect("save");

    let loaded = persistor.load("eqmain.dll").expect("load");
    assert_eq!(
        loaded, result,
        "the seven-kind document round-trips exactly"
    );

    let order: Vec<(&str, &str)> = loaded
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003ab00", "byteswap"),
            ("FUN_18003ab00", "bitpack"),
            ("FUN_18003ab00", "magic"),
            ("FUN_18003ab00", "cross_field_validation"),
            ("FUN_18003ab00", "cross_field_validation"),
            ("FUN_18003ab00", "serialization_format"),
            ("FUN_18003ab00", "protocol_message"),
            ("FUN_18003e750", "byteswap"),
            ("", "endianness_map"),
        ],
        "components first in body-stage order, composed claims last among their function's findings, the map after them all"
    );

    // The component rows survive intact beside the composed claims —
    // the protocol sniff still lands as its own magic finding...
    let SerializeFinding::Magic(record) = &loaded.findings[2] else {
        unreachable!("the protocol comparison still reads as a magic finding");
    };
    assert_eq!(record.format, "IPv6");
    assert_eq!(record.magic, 0x86DD);

    // ...the swap and pack readings still compose their layout...
    let SerializeFinding::SerializationFormat(record) = &loaded.findings[5] else {
        unreachable!("the swap and pack readings compose the format claim");
    };
    assert_eq!(record.fields.len(), 5);
    assert_eq!(record.fields[0].width, 32);
    assert_eq!(record.fields[0].endianness, Some(WireEndianness::BigEndian));
    assert_eq!(record.direction, Some(FormatDirection::Reader));
    assert_eq!(record.confidence, Confidence::new(75));

    // ...and the corroborated sniff still composes the handler claim
    // in the same function at the same time.
    let SerializeFinding::ProtocolMessage(record) = &loaded.findings[6] else {
        unreachable!("the corroborated sniff composes the protocol message claim");
    };
    assert_eq!(record.protocol, "IPv6");
    assert_eq!(
        record.corroborations,
        ["ntohl swap", "checksum validation", "length validation"],
        "every corroborating reading is listed through the round trip"
    );
    assert_eq!(record.confidence, Confidence::new(85));

    let SerializeFinding::EndiannessMap(record) = &loaded.findings[8] else {
        unreachable!("the swap findings profile one binary-level map");
    };
    assert_eq!(record.entries.len(), 2);
    assert_eq!(record.entries[0].width, 16);
    assert_eq!(record.entries[0].functions, ["FUN_18003e750"]);
    assert_eq!(record.entries[1].width, 32);
    assert_eq!(record.entries[1].functions, ["FUN_18003ab00"]);
}

#[tokio::test]
async fn two_scans_of_the_same_program_persist_byte_identical_documents() {
    // Determinism as a contract: the scan reads the same bodies in
    // the same order and composes the same claims, so the only bytes
    // two persisted documents can differ on are the wall-clock scan
    // stamps — set those aside and the documents are byte-identical,
    // which is what lets two scans of one program diff cleanly.
    let first_dir = TempDir::new().expect("tempdir");
    let second_dir = TempDir::new().expect("tempdir");
    let first = SerializeEngine::with_source(seven_kind_program())
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    let second = SerializeEngine::with_source(seven_kind_program())
        .scan("eqmain.dll")
        .await
        .expect("second scan");
    let first_persistor = SerializePersistor::new(first_dir.path());
    let second_persistor = SerializePersistor::new(second_dir.path());
    first_persistor.save(&first).expect("first save");
    second_persistor.save(&second).expect("second save");

    assert_eq!(
        first.findings, second.findings,
        "two scans of one program make identical findings"
    );
    assert_eq!(
        persisted_document_without_scan_stamp(&first_persistor.path_for("eqmain.dll")),
        persisted_document_without_scan_stamp(&second_persistor.path_for("eqmain.dll")),
        "the persisted documents are byte-identical once the scan stamp is set aside"
    );
}

/// The persisted document with the volatile scan-stamp line removed:
/// `scanned_at` is the only field two scans of one program can differ
/// on, so setting it aside is what "byte-identical across scans"
/// means for the whole document.
fn persisted_document_without_scan_stamp(path: &std::path::Path) -> String {
    std::fs::read_to_string(path)
        .expect("the persisted document should be readable")
        .lines()
        .filter(|line| !line.contains("\"scanned_at\":"))
        .collect::<Vec<&str>>()
        .join("\n")
}

#[tokio::test]
async fn the_seven_kind_document_renders_every_kind_into_the_escalate_prompt() {
    // The consumption end of the composition: the loaded seven-kind
    // document answers the per-function lookup — the handler gets its
    // seven findings plus the binary-level map it contributes to, and
    // the second contributor gets its swap plus the same map — and
    // every kind renders into the SERIALIZATION section with its
    // kind tag, confidence, suggestion, and evidence.
    let workspace = TempDir::new().expect("tempdir");
    let result = SerializeEngine::with_source(seven_kind_program())
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
    assert_eq!(
        findings.len(),
        8,
        "the handler's seven findings plus the map it contributes to"
    );

    let prompt = calxgloss_prompts::build_escalate_prompt_with_context(
        "FUN_18003ab00".into(),
        "eqmain.dll".into(),
        "fn fun_18003ab00() { /* hand-rolled packet parse */ }".into(),
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
    assert!(prompt.contains("byteswap pattern, confidence 70"));
    assert!(prompt.contains("bitpack pattern, confidence 60"));
    assert!(prompt.contains("magic pattern, confidence 80"));
    assert!(prompt.contains("cross_field_validation pattern, confidence 65"));
    assert!(prompt.contains("serialization_format pattern, confidence 75"));
    assert!(prompt.contains("protocol_message pattern, confidence 85"));
    assert!(prompt.contains("endianness_map pattern, confidence 75"));
    assert!(prompt.contains("if (uVar2 == 0x86dd) {"));
    assert!(prompt.contains("byteorder reader: read_u32 then 8+8+8+8 bitfields"));
    assert!(prompt.contains("protocol-aware IPv6 message decode (byteorder BE reads)"));
    assert!(
        prompt.contains("program-wide BE wire order at u16, u32 (byteorder BE types)"),
        "the program-wide profile reaches the function-level prompt"
    );

    // The map answers the other contributing function from the loaded
    // document too — the program-level profile is part of what every
    // contributing function's prompt reads.
    let other: Vec<&SerializeFinding> = loaded.for_function("FUN_18003e750").collect();
    assert_eq!(other.len(), 2, "the swap and the map naming it");
    assert_eq!(other[1].kind(), "endianness_map");
}

#[tokio::test]
async fn the_confidence_ladder_ranks_every_composed_claim_above_its_parts() {
    // The P11.5 ladder as a contract, read off one scan: bit-pack
    // below validation below byte-swap below format below magic below
    // protocol message — corroboration always ranks above the single
    // signals that fed it. The binary-level map rides its own rung,
    // above the byte-swap floor it aggregates and below the
    // lone-magic floor.
    let result = SerializeEngine::with_source(seven_kind_program())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let confidence = |kind: &str| -> u8 {
        result
            .findings
            .iter()
            .find(|finding| finding.kind() == kind)
            .unwrap_or_else(|| panic!("the seven-kind scan should carry a {kind} finding"))
            .confidence()
            .value()
    };
    let ladder = [
        confidence("bitpack"),
        confidence("cross_field_validation"),
        confidence("byteswap"),
        confidence("serialization_format"),
        confidence("magic"),
        confidence("protocol_message"),
    ];
    for pair in ladder.windows(2) {
        assert!(
            pair[0] < pair[1],
            "the ladder {ladder:?} must climb strictly: bit-pack < validation < byte-swap < format < magic < protocol message"
        );
    }
    let map = confidence("endianness_map");
    assert!(
        confidence("byteswap") < map && map < confidence("magic"),
        "the binary-level map rides between the byte-swap floor and the lone-magic floor"
    );
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

// Tests for the module above, split out of the file they test.
use super::*;
use crate::byteswap::ByteSwapSignature;
use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result, StringLiteral, StructLayout, Symbol, Xref,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

/// State shared by every clone of a [`FakeProgram`], so a test can
/// read what the scan did even after the scan has consumed its
/// source.
#[derive(Debug, Default)]
struct Stats {
    decompiles: Mutex<Vec<String>>,
}

/// A canned program implementing [`ScanSource`], so the whole
/// orchestration runs without a server.
#[derive(Clone)]
struct FakeProgram {
    listing: Vec<FunctionSummary>,
    bodies: HashMap<String, DecompiledFunction>,
    fail_decompiles: Vec<String>,
    fail_listing: bool,
    stats: Arc<Stats>,
}

impl FakeProgram {
    fn empty() -> Self {
        Self {
            listing: Vec::new(),
            bodies: HashMap::new(),
            fail_decompiles: Vec::new(),
            fail_listing: false,
            stats: Arc::new(Stats::default()),
        }
    }

    fn decompiled(&self) -> Vec<String> {
        self.stats.decompiles.lock().unwrap().clone()
    }
}

impl ScanSource for FakeProgram {
    async fn functions(&self) -> Result<Vec<FunctionSummary>> {
        if self.fail_listing {
            return Err(EngineError::Reported {
                message: "the engine is busy".into(),
            });
        }
        Ok(self.listing.clone())
    }

    async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
        self.stats.decompiles.lock().unwrap().push(name.to_string());
        if self.fail_decompiles.iter().any(|f| f == name) {
            return Err(EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            });
        }
        self.bodies
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
    }

    // The rest of the shared trait's reads: this scan never makes
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
    // Story 9 (#203): the fake source names itself, so the tests can pin
    // that scan() stamps the source's provenance onto the record (#208).
    fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
        Some(calxgloss_types::EngineProvenance {
            name: "fake-engine".into(),
            version: Some("9.9".into()),
            fingerprint: Some("0123456".into()),
        })
    }
}

/// A body with two `ntohl` calls — the byte-swap shape — in
/// one function.
const SWAP_SHAPE_BODY: &str = "\
  uVar1 = ntohl(local_18);
  uVar2 = uVar1 + 1;
  uVar3 = ntohl(local_20);
";

/// The canned program: one function whose body has the swap
/// shape, and one plain function that finds nothing.
fn program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            SWAP_SHAPE_BODY,
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

async fn scan(program: FakeProgram) -> SerializeResult {
    SerializeEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan")
}

#[tokio::test]
async fn scan_collects_findings_from_the_detector() {
    let result = scan(program()).await;

    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);

    let findings: Vec<&SerializeFinding> = result.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 4);

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
    assert_eq!(record.evidence, "uVar3 = ntohl(local_20);");

    let SerializeFinding::SerializationFormat(record) = findings[2] else {
        unreachable!("the two swap readings compose a format finding");
    };
    assert_eq!(record.fields.len(), 2);
    assert_eq!(
        record.direction,
        Some(crate::types::FormatDirection::Reader)
    );
    assert_eq!(record.confidence.value(), 75);

    let SerializeFinding::EndiannessMap(record) = findings[3] else {
        unreachable!("the swap findings profile an endianness map");
    };
    assert_eq!(record.entries.len(), 1);
    assert_eq!(record.entries[0].width, 32);

    assert!(result.for_function("FUN_18003e750").next().is_none());
}

#[tokio::test]
async fn one_scan_interleaves_all_kinds_in_scan_order() {
    // A function whose body has a swap call, a pack chain, and a
    // signature comparison: the findings come back in detector
    // order — swap, pack, magic, then the composed format — and
    // the plain function stays empty.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  if (uVar6 == 0x89504e47) {
  uVar1 = ntohl(local_18);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
",
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
    let result = scan(program).await;

    let order: Vec<(&str, &str)> = result
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
            ("FUN_18003ab00", "serialization_format"),
            ("", "endianness_map"),
        ]
    );

    let findings: Vec<&SerializeFinding> = result.for_function("FUN_18003ab00").collect();
    let SerializeFinding::BitPack(record) = findings[1] else {
        unreachable!("the pack chain reads as a bitpack finding");
    };
    assert_eq!(record.widths, [8, 8, 8, 8]);
    assert_eq!(record.suggestion, "bitvec or named-field masking/shifting");

    let SerializeFinding::Magic(record) = findings[2] else {
        unreachable!("the signature comparison reads as a magic finding");
    };
    assert_eq!(record.format, "PNG");
    assert_eq!(record.suggestion, "png::Decoder");

    let SerializeFinding::SerializationFormat(record) = findings[3] else {
        unreachable!("the swap and pack readings compose a format finding");
    };
    assert_eq!(record.fields.len(), 5);
    assert_eq!(
        record.direction,
        Some(crate::types::FormatDirection::Reader)
    );
    assert_eq!(
        record.suggestion,
        "byteorder reader: read_u32 then 8+8+8+8 bitfields"
    );
}

#[tokio::test]
async fn a_checksum_comparison_lands_a_cross_field_validation_finding() {
    // A stored field compared against a value computed from other
    // fields — the checksum shape — reads through the scan as its
    // own finding naming both sides and the check.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  if (uVar7 == uVar5 + uVar6) {
    dispatch();
  }
",
        ),
    );
    let result = scan(program).await;

    let findings: Vec<&SerializeFinding> = result.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind(), "cross_field_validation");
    let SerializeFinding::CrossFieldValidation(record) = findings[0] else {
        unreachable!("the checksum comparison reads as a validation finding");
    };
    assert_eq!(record.field, "uVar7");
    assert_eq!(record.computed, "uVar5 + uVar6");
    assert_eq!(record.shape, crate::types::ValidationShape::Checksum);
    assert_eq!(record.confidence.value(), 65);
    assert_eq!(record.evidence, "if (uVar7 == uVar5 + uVar6) {");
}

#[tokio::test]
async fn scan_order_places_validation_after_the_magic_comparisons() {
    // A body with every shape: the per-function finding order is
    // byte swaps, bit packs, magic comparisons, then validation,
    // then the composed format. The order of the kinds already
    // listed does not change; the new kinds slot in after it. The
    // magic line is claimed exactly once, and the function is
    // still decompiled once.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  if (uVar6 == 0x89504e47) {
  uVar1 = ntohl(local_18);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
  if (uVar7 == uVar5 + uVar6) {
",
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
    let result = scan(program.clone()).await;

    let order: Vec<(&str, &str)> = result
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
            ("FUN_18003ab00", "serialization_format"),
            ("", "endianness_map"),
        ]
    );
    assert_eq!(
        program.decompiled(),
        vec!["FUN_18003ab00", "FUN_18003e750"],
        "one decompile per function, in listing order"
    );
}

#[tokio::test]
async fn scan_keeps_findings_in_scan_order() {
    // Both functions carry the swap shape, so the persisted list
    // must group their findings by function in listing order —
    // never interleaved.
    let mut program = program();
    program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            SWAP_SHAPE_BODY,
        ),
    );
    let result = scan(program).await;

    let order: Vec<(&str, &str)> = result
        .findings
        .iter()
        .map(|finding| (finding.function(), finding.kind()))
        .collect();
    assert_eq!(
        order,
        vec![
            ("FUN_18003e750", "byteswap"),
            ("FUN_18003e750", "byteswap"),
            ("FUN_18003e750", "serialization_format"),
            ("FUN_18003ab00", "byteswap"),
            ("FUN_18003ab00", "byteswap"),
            ("FUN_18003ab00", "serialization_format"),
            ("", "endianness_map"),
        ]
    );
}

#[tokio::test]
async fn two_network_reads_and_a_pack_chain_compose_one_format_finding() {
    // The end-to-end claim: a body with two network-order reads and
    // a pack chain lands exactly one format finding. That finding
    // has all six fields in body order, a reader direction, and the
    // sequence's own body lines as evidence.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  uVar1 = ntohl(local_18);
  uVar3 = ntohl(local_20);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
",
        ),
    );
    let result = scan(program).await;

    let kinds: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.kind())
        .collect();
    assert_eq!(
        kinds,
        vec![
            "byteswap",
            "byteswap",
            "bitpack",
            "serialization_format",
            "endianness_map"
        ],
        "the composed layout is recorded alongside its component findings"
    );

    let formats: Vec<&crate::types::SerializationFormat> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            SerializeFinding::SerializationFormat(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(formats.len(), 1, "one composed layout, not three hints");
    let format = formats[0];
    assert_eq!(format.fields.len(), 6);
    assert_eq!(format.fields[0].width, 32);
    assert_eq!(
        format.fields[0].endianness,
        Some(crate::types::WireEndianness::BigEndian)
    );
    for field in &format.fields[2..] {
        assert_eq!(field.width, 8);
        assert_eq!(field.endianness, None);
    }
    assert_eq!(
        format.direction,
        Some(crate::types::FormatDirection::Reader)
    );
    assert_eq!(format.confidence.value(), 75);
    assert_eq!(
        format.evidence,
        "uVar1 = ntohl(local_18); uVar3 = ntohl(local_20); uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;"
    );
}

#[tokio::test]
async fn a_single_reading_composes_no_format_finding() {
    // One swap call next to a magic comparison is one serialization
    // reading: no layout is claimed — honesty beats volume.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  if (uVar6 == 0x89504e47) {
  uVar1 = ntohl(local_18);
",
        ),
    );
    let result = scan(program).await;

    assert_eq!(result.findings.len(), 3);
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "serialization_format")
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.kind() != "protocol_message"),
        "a file-format magic plus a swap never promotes"
    );
}

#[tokio::test]
async fn a_protocol_magic_and_an_ntohl_lands_a_protocol_message_finding() {
    // The promotion end to end: a protocol-table magic comparison
    // and an `ntohl` in one body land the magic and byte-swap
    // findings as always, plus exactly one protocol message
    // finding. It names the protocol and its corroborating reading.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  if (uVar2 == 0x86dd) {
  uVar1 = ntohl(local_18);
",
        ),
    );
    let result = scan(program).await;

    let kinds: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.kind())
        .collect();
    assert_eq!(
        kinds,
        vec!["byteswap", "magic", "protocol_message", "endianness_map"],
        "the handler claim is recorded alongside its magic and byte-swap findings"
    );

    let SerializeFinding::Magic(record) = &result.findings[1] else {
        unreachable!("the protocol comparison still lands as a magic finding");
    };
    assert_eq!(record.format, "IPv6");
    assert_eq!(
        record.suggestion,
        "ipv6 header decode via byteorder BE reads"
    );

    let SerializeFinding::ProtocolMessage(record) = &result.findings[2] else {
        unreachable!("the corroborated sniff promotes to a protocol message finding");
    };
    assert_eq!(record.protocol, "IPv6");
    assert_eq!(record.magic, 0x86DD);
    assert_eq!(record.corroborations, vec!["ntohl swap"]);
    assert_eq!(record.confidence.value(), 85);
    assert_eq!(
        record.suggestion,
        "protocol-aware IPv6 message decode (byteorder BE reads)"
    );
    assert_eq!(
        record.evidence,
        "if (uVar2 == 0x86dd) { uVar1 = ntohl(local_18);"
    );
}

#[tokio::test]
async fn a_protocol_magic_alone_stays_a_plain_magic_finding() {
    // The honesty gate at scan level: a protocol sniff with
    // nothing corroborating it claims no handler — the magic
    // finding says all there is.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 == 0x86dd) {\n",
        ),
    );
    let result = scan(program).await;

    let kinds: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.kind())
        .collect();
    assert_eq!(kinds, vec!["magic"]);
}

#[tokio::test]
async fn scan_order_places_the_protocol_message_after_the_format_record() {
    // A body with every shape: the per-function finding order is
    // byte swaps, bit packs, magic comparisons, validation, the
    // composed format, then the protocol message. The order of the
    // kinds already listed does not change; the new kind slots in
    // last. The function is still decompiled once.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "\
  if (uVar6 == 0x86dd) {
  uVar1 = ntohl(local_18);
  uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10) | (uVar5 << 8) | (uint)uVar6;
  if (uVar7 == uVar5 + uVar6) {
",
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
    let result = scan(program.clone()).await;

    let order: Vec<(&str, &str)> = result
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
            ("FUN_18003ab00", "serialization_format"),
            ("FUN_18003ab00", "protocol_message"),
            ("", "endianness_map"),
        ]
    );
    assert_eq!(
        program.decompiled(),
        vec!["FUN_18003ab00", "FUN_18003e750"],
        "one decompile per function, in listing order"
    );
}

#[tokio::test]
async fn swaps_across_functions_land_exactly_one_map_finding_last() {
    // The program-wide claim: 32-bit and 16-bit swaps in two
    // functions land one endianness map, appended after every
    // per-function finding and owned by no function. The
    // per-function lookups answer the map to each contributor.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = ntohl(local_18);\n",
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
    let result = scan(program).await;

    let maps: Vec<&crate::types::EndiannessMap> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            SerializeFinding::EndiannessMap(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(maps.len(), 1, "one map per scan, not one per function");
    let last = result.findings.last().expect("findings");
    assert_eq!(last.kind(), "endianness_map");
    assert_eq!(
        last.function(),
        "",
        "the profile belongs to the binary, not a function"
    );

    let map = maps[0];
    assert_eq!(map.entries.len(), 2);
    assert_eq!(map.entries[0].width, 16);
    assert_eq!(
        map.entries[0].endianness,
        crate::types::WireEndianness::BigEndian
    );
    assert_eq!(map.entries[0].functions, vec!["FUN_18003e750"]);
    assert_eq!(map.entries[1].width, 32);
    assert_eq!(map.entries[1].functions, vec!["FUN_18003ab00"]);
    assert_eq!(map.confidence.value(), 75);

    for contributor in ["FUN_18003ab00", "FUN_18003e750"] {
        let answered: Vec<&SerializeFinding> = result
            .for_function(contributor)
            .filter(|finding| finding.kind() == "endianness_map")
            .collect();
        assert_eq!(answered.len(), 1, "{contributor} reads the map");
    }
}

#[tokio::test]
async fn a_builtin_only_scan_claims_a_reversal_only_entry() {
    // Honesty at the program level: a scan whose only swaps are
    // direction-neutral builtins claims byte reversal and no wire
    // order.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar1 = __builtin_bswap32(uVar2);\n",
        ),
    );
    let result = scan(program).await;

    let SerializeFinding::EndiannessMap(record) = result.findings.last().expect("map") else {
        unreachable!("the swap findings profile an endianness map");
    };
    assert_eq!(record.entries.len(), 1);
    assert_eq!(
        record.entries[0].endianness,
        crate::types::WireEndianness::ReversalOnly
    );
    assert_eq!(
        record.suggestion,
        "program-wide byte reversal at u32 — no wire order claimed"
    );
}

#[tokio::test]
async fn scan_decompiles_each_function_exactly_once() {
    // The detectors share one fetch per function; a scan that
    // asked each detector for its own copy would multiply the
    // wall time.
    let program = program();
    let result = scan(program.clone()).await;
    assert!(!result.is_empty());
    assert_eq!(
        program.decompiled(),
        vec!["FUN_18003ab00", "FUN_18003e750"],
        "one decompile per function, in listing order"
    );
}

#[tokio::test]
async fn a_function_that_will_not_decompile_is_skipped() {
    // The decompiler cannot produce a body for every function. One
    // bad entry point must not stop the whole program from being
    // scanned.
    let mut program = program();
    program.fail_decompiles = vec!["FUN_18003ab00".into()];
    let result = scan(program.clone()).await;

    assert!(
        result.is_empty(),
        "the failing function contributed nothing"
    );
    assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
}

#[tokio::test]
async fn a_scan_where_every_decompile_fails_aborts() {
    // The 2026-10-08 incident: the seam answered the listing from
    // one program and the decompiles from another, every decompile
    // failed, and the scan nearly filed a record that looks clean
    // but is not under the target's name. The skip-rate breaker
    // aborts with the counts instead, so nothing is persisted.
    let mut program = program();
    program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
    let result = SerializeEngine::with_source(program)
        .scan("eqmain.dll")
        .await;
    assert!(matches!(
        result,
        Err(crate::SerializeError::DecompileBreaker {
            failed: 2,
            total: 2
        })
    ));
}

#[tokio::test]
async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
    // The skip-rate breaker is a fuse, not a post-mortem: once more
    // than half the listing has failed to decompile, the remaining
    // decompiles would be wasted round-trips against the wrong
    // program.
    let mut program = program();
    program.listing.push(summary("FUN_1800412a0"));
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "  return;\n",
        ),
    );
    program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
    let result = SerializeEngine::with_source(program.clone())
        .scan("eqmain.dll")
        .await;

    assert!(matches!(
        result,
        Err(crate::SerializeError::DecompileBreaker {
            failed: 2,
            total: 3
        })
    ));
    assert_eq!(
        program.decompiled(),
        vec!["FUN_18003ab00", "FUN_18003e750"],
        "the scan stopped once the breaker tripped"
    );
}

#[tokio::test]
async fn a_nameless_listing_entry_is_skipped() {
    // An empty name would send the by-name lookup into an
    // arbitrary function's body, so the entry is skipped with no
    // decompile.
    let mut program = program();
    program.listing.insert(0, summary(""));
    let result = scan(program.clone()).await;

    assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
    assert!(!result.is_empty());
}

#[tokio::test]
async fn a_failing_listing_fails_the_whole_run() {
    // When the listing itself is gone, nothing was scanned, so the
    // run aborts rather than returning a result that looks empty
    // because nothing was found.
    let mut program = program();
    program.fail_listing = true;
    let result = SerializeEngine::with_source(program)
        .scan("eqmain.dll")
        .await;
    assert!(matches!(
        result,
        Err(crate::SerializeError::Engine(EngineError::Reported { .. }))
    ));
}

#[tokio::test]
async fn a_custom_detector_reaches_the_scan() {
    // Swapping the detector whole reaches the scan: the configured
    // custom spelling reads in the body, and the standard names
    // the swap removed read nothing.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "\
  uVar1 = my_swap(local_18);
  uVar2 = ntohl(local_20);",
        ),
    );

    let engine =
        SerializeEngine::with_source(program).with_byteswap(ByteSwapDetector::with_names([
            ByteSwapSignature::new("my_swap", 32),
        ]));
    let result = engine.scan("eqmain.dll").await.expect("scan");

    let findings: Vec<&SerializeFinding> = result.for_function("FUN_1800412a0").collect();
    assert_eq!(
        findings.len(),
        2,
        "the swap finding plus the map it profiles"
    );
    let SerializeFinding::ByteSwap(record) = findings[0] else {
        unreachable!("the swap call reads as a byteswap finding");
    };
    assert_eq!(record.operation, "my_swap");
    assert_eq!(record.suggestion, "byteorder::BE::read_u32");
}

#[tokio::test]
async fn a_custom_signature_table_reaches_the_scan() {
    // Swapping the signature table whole reaches the scan: the
    // configured custom magic reads in the body, and the standard
    // signatures the swap removed read nothing.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "\
  if (uVar1 == 0x43414c58) {
  if (uVar2 == 0x89504e47) {",
        ),
    );

    let engine =
        SerializeEngine::with_source(program).with_magic(MagicByteDetector::with_signatures([
            crate::magic_bytes::MagicSignature::new("CALX", 0x4341_4C58, "calx::Header"),
        ]));
    let result = engine.scan("eqmain.dll").await.expect("scan");

    let findings: Vec<&SerializeFinding> = result.for_function("FUN_1800412a0").collect();
    assert_eq!(findings.len(), 1);
    let SerializeFinding::Magic(record) = findings[0] else {
        unreachable!("the signature comparison reads as a magic finding");
    };
    assert_eq!(record.format, "CALX");
    assert_eq!(record.suggestion, "calx::Header");
}

#[tokio::test]
async fn a_custom_magic_hit_claims_no_validation_finding() {
    // The magic-hit gate runs on the findings the scan just made,
    // not the built-in table: a comparison with the configured
    // custom signature inside a computed shape lands once — as
    // magic — and claims no validation finding on top.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
        "FUN_1800412a0".into(),
        function(
            "FUN_1800412a0",
            "undefined FUN_1800412a0(void)",
            "  if (uVar1 == 0x43414c58 + uVar2) {",
        ),
    );

    let engine =
        SerializeEngine::with_source(program).with_magic(MagicByteDetector::with_signatures([
            crate::magic_bytes::MagicSignature::new("CALX", 0x4341_4C58, "calx::Header"),
        ]));
    let result = engine.scan("eqmain.dll").await.expect("scan");

    let findings: Vec<&SerializeFinding> = result.for_function("FUN_1800412a0").collect();
    assert_eq!(
        findings.len(),
        1,
        "the signature comparison lands once, as magic"
    );
    assert_eq!(findings[0].kind(), "magic");
}

#[tokio::test]
async fn scan_stamps_the_scan_provenance() {
    // The metadata names the binary, records a finish time, and
    // stamps the duration from the wall clock. A canned scan is
    // instant, so it reads as zero seconds rather than never set.
    let result = scan(program()).await;
    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);
    assert!(result.metadata.duration_secs < 60);
    // Story 9 (#203): the record also names the analysis engine that
    // produced it — scan() copies the source's provenance through (#208).
    let engine = result
        .metadata
        .engine
        .expect("scan record names its engine");
    assert_eq!(engine.name, "fake-engine");
    assert_eq!(engine.version.as_deref(), Some("9.9"));
    assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
}

#[tokio::test]
async fn an_empty_program_yields_an_empty_result() {
    let result = scan(FakeProgram::empty()).await;
    assert!(result.is_empty());
    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);
}

// ============================================================
// Admitted scan coverage (issue #351)
// ============================================================

/// What the roster pin checks at data level: an empty fault list
/// means the record names every declared facet exactly once, and
/// each fault reports one drift.
fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
    coverage.roster_faults(DECLARED_FACETS)
}

#[tokio::test]
async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
    // The coverage stamp comes from the serialization scan itself,
    // not the registry row and not the CLI — the batch scan phase
    // and the CLI's force-rescan file the same admission through
    // this one definition. Every body was read here, so the record
    // is complete and admits nothing.
    let result = scan(program()).await;
    let coverage = result
        .metadata
        .coverage
        .expect("a fresh serialization scan states its coverage");
    assert_eq!(coverage.status, CoverageStatus::Complete);
    assert!(
        roster_faults(&coverage).is_empty(),
        "a fresh document must name every declared facet exactly once"
    );
    let bodies = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(bodies.status, CoverageStatus::Complete);
    assert_eq!(
        bodies.limitation, None,
        "a scan that read every body admits nothing — and silence now \
             means examined-and-clean, not unchecked"
    );
}

#[tokio::test]
async fn a_decompiled_failure_is_admitted_by_name_on_the_coverage_record() {
    // The whole point of the admission: a body the scan could not
    // read is named, so it is never mistaken for an examined-and-
    // clean function the detectors simply found nothing in.
    let mut program = program();
    program.fail_decompiles = vec!["FUN_18003e750".into()];
    let result = scan(program).await;
    let coverage = result
        .metadata
        .coverage
        .expect("a partial serialization scan states its coverage too");
    assert_eq!(
        coverage.status,
        CoverageStatus::Partial,
        "the whole picture mirrors the one facet it examined"
    );
    assert!(
        roster_faults(&coverage).is_empty(),
        "a partial scan still names every declared facet exactly once"
    );
    let bodies = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(bodies.status, CoverageStatus::Partial);
    assert_eq!(
        bodies.limitation.as_deref(),
        Some("1 function body unreached: FUN_18003e750"),
        "the unreached body is named, and only the unreached body"
    );
}

#[tokio::test]
async fn functions_beyond_the_listing_cap_are_not_scanned_and_the_admission_says_so() {
    // Bounded prose beside the counts: six decompile failures name
    // five inline and the sixth becomes a count, and a nameless
    // listing entry counts toward the total without taking one of
    // the five name slots.
    let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
    let mut program = FakeProgram::empty();
    for (index, name) in names.iter().enumerate() {
        program.listing.push(summary(name));
        if index >= 6 {
            program.bodies.insert(
                name.clone(),
                function(name, "undefined test(void)", "  return;\n"),
            );
        }
    }
    program.fail_decompiles = names[..6].to_vec();
    program.listing.push(summary(""));
    let result = scan(program).await;
    let bodies = result
        .metadata
        .coverage
        .expect("a partial serialization scan states its coverage")
        .facets
        .into_iter()
        .find(|facet| facet.id == "function-bodies")
        .expect("function-bodies is named");
    assert_eq!(bodies.status, CoverageStatus::Partial);
    assert_eq!(
        bodies.limitation.as_deref(),
        Some(
            "7 function bodies unreached: FUN_body_0000, FUN_body_0001, \
                 FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more"
        ),
        "six named failures plus one nameless entry: five names, the \
             rest counted, the count covering both"
    );
}

#[test]
fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
    let mut coverage = coverage_stamp(&[], 0);
    coverage
        .facets
        .retain(|facet| facet.id != "function-bodies");
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `function-bodies` is missing from the record"],
        "an engine quietly dropping its one facet fails loudly"
    );
}

#[test]
fn the_roster_pin_fails_when_a_facet_is_doubled() {
    let mut coverage = coverage_stamp(&["FUN_18003e750".to_string()], 0);
    coverage.facets.push(coverage.facets[0].clone());
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `function-bodies` appears 2 times in the record"],
        "a facet crowded into two entries fails loudly"
    );
}

#[test]
fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
    let mut coverage = coverage_stamp(&[], 0);
    coverage.facets.push(FacetCoverage {
        id: "endianness-map".to_string(),
        status: CoverageStatus::Complete,
        limitation: None,
    });
    assert_eq!(
        roster_faults(&coverage),
        ["record names `endianness-map`, a facet the engine never declared"],
        "an entry outside the declared roster fails loudly — the \
             endianness profile aggregates the body findings, not a region \
             the scan reads on its own"
    );
}

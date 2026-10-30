// Tests for the module above, split out of the file they test.
use super::*;
use crate::bitmask::BitmaskDetector;
use crate::sequential::SequentialDetector;
use crate::types::Confidence;
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

/// A listing entry at a chosen address, for tests where the
/// address itself is the point: the starts a table's entries
/// resolve against.
fn summary_at(name: &str, address: u64) -> FunctionSummary {
    FunctionSummary {
        name: name.to_string(),
        address,
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
/// still read what the scan did after the scan has consumed the
/// program as its source.
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
    fail_xrefs: bool,
    stats: Arc<Stats>,
    data_items: Vec<DataItem>,
    memory: HashMap<u64, Vec<u8>>,
    xrefs: HashMap<u64, Vec<Xref>>,
}

impl FakeProgram {
    fn empty() -> Self {
        Self {
            listing: Vec::new(),
            bodies: HashMap::new(),
            fail_decompiles: Vec::new(),
            fail_listing: false,
            fail_xrefs: false,
            stats: Arc::new(Stats::default()),
            data_items: Vec::new(),
            memory: HashMap::new(),
            xrefs: HashMap::new(),
        }
    }

    fn decompiled(&self) -> Vec<String> {
        self.stats.decompiles.lock().unwrap().clone()
    }

    /// Copied from typesdb's vtable tests: a canned data object in
    /// the listing, plus the byte window `read_memory` answers with
    /// at its address; the length is read off the bytes.
    fn object_at(&mut self, label: &str, address: u64, bytes: Vec<u8>) {
        self.typed_object_at(label, address, "undefined", bytes);
    }

    /// The same object carrying the type the analysis engine's
    /// listing applied — the applied type the detector resolves its
    /// stride from (#280).
    fn typed_object_at(&mut self, label: &str, address: u64, type_name: &str, bytes: Vec<u8>) {
        self.data_items.push(DataItem {
            label: label.to_string(),
            address,
            type_name: type_name.to_string(),
            length: bytes.len() as u64,
        });
        self.memory_at(address, bytes);
    }

    /// A canned memory window at `address`.
    fn memory_at(&mut self, address: u64, bytes: Vec<u8>) {
        self.memory.insert(address, bytes);
    }

    /// The analysis engine's cross-references into `address`: one
    /// `DATA` xref from each named function's code site.
    fn xrefs_from(&mut self, address: u64, functions: &[&str]) {
        self.xrefs.insert(
            address,
            functions
                .iter()
                .map(|name| Xref {
                    address: 0x1800_3ab10,
                    function: Some((*name).to_string()),
                    kind: Some("DATA".to_string()),
                })
                .collect(),
        );
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

    // The rest of the shared trait's reads. This canned program
    // answers the data-table reading's three — the data listing,
    // canned memory windows, and canned cross-references — and
    // answers the reads this scan never makes with empty or
    // not-found data.
    async fn strings(&self) -> Result<Vec<StringLiteral>> {
        Ok(Vec::new())
    }

    async fn callers(&self, _address: u64) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn xrefs_to(&self, address: u64) -> Result<Vec<Xref>> {
        if self.fail_xrefs {
            return Err(EngineError::Reported {
                message: "cross-references unavailable".into(),
            });
        }
        Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
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
        Ok(self.data_items.clone())
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

    async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        match self.memory.get(&address) {
            Some(window) => Ok(window.iter().copied().take(length).collect()),
            None => Err(EngineError::NotFound {
                kind: "memory window",
                query: format!("{address:#x}"),
            }),
        }
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

/// A body carrying a flag-bit pair, a four-case switch run, and a
/// repeated magic number — one finding family per detector — all
/// in one function.
const EVERY_SHAPE_BODY: &str = "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n  switch(local_10) {\n  case 0:\n  case 1:\n  case 2:\n  case 3:\n    dispatch();\n  }\n  size = 0x280;\n  copy(dst, 0x280);\n";

/// The canned program: one function whose body carries every
/// shape, and one plain function that repeats the magic number so
/// the frequency analyzer sees it across two functions.
fn program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            EVERY_SHAPE_BODY,
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  reserve(0x280);\n  return;\n",
        ),
    );
    program
}

async fn scan(program: FakeProgram) -> ConstResult {
    ConstEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan")
}

fn kinds(result: &ConstResult, function: &str) -> Vec<&'static str> {
    result
        .for_function(function)
        .map(|finding| finding.kind())
        .collect()
}

/// The scan's one program-level named constant, whichever value it
/// carries.
fn named_constant(result: &ConstResult) -> &crate::types::NamedConstant {
    result
        .findings
        .iter()
        .find_map(|finding| match finding {
            ConstFinding::NamedConstant(record) => Some(record),
            _ => None,
        })
        .expect("the scan should have reported the repeated literal")
}

/// The scan's one program-level flag family, whichever bits it
/// carries.
fn flag_family(result: &ConstResult) -> &crate::types::FlagFamily {
    result
        .findings
        .iter()
        .find_map(|finding| match finding {
            ConstFinding::FlagFamily(record) => Some(record),
            _ => None,
        })
        .expect("the scan should have merged the shared-bit groups")
}

/// The scan's program-level protocol constants, whichever values
/// they carry. Named apart from the crate's `protocol_constants`
/// matcher so the test module's glob import cannot shadow it.
fn protocol_findings(result: &ConstResult) -> Vec<&crate::types::ProtocolConstant> {
    result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::ProtocolConstant(record) => Some(record),
            _ => None,
        })
        .collect()
}

/// The scan's palette findings — at most one per binary. Named
/// apart from the crate's `color_palette` matcher so the test
/// module's glob import cannot shadow it.
fn color_findings(result: &ConstResult) -> Vec<&crate::types::ColorConstant> {
    result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::ColorConstant(record) => Some(record),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_named_assignment_in_the_bodies_names_the_repeated_constant() {
    // The canned program spells `size = 0x280;` in one function and
    // repeats the value in another: the named constant carries the
    // context name, and its suggestion — the string the report and
    // the escalate prompt render — carries it too.
    let result = scan(program()).await;

    let constant = named_constant(&result);
    assert_eq!(constant.value, 0x280);
    assert_eq!(constant.name.as_deref(), Some("SIZE_0x280"));
    assert_eq!(constant.suggestion, "const SIZE_0x280: u32 = 0x280;");
}

#[tokio::test]
async fn placeholder_assignments_leave_the_constant_mechanically_named() {
    // Every sighting of the repeated value sits beside a
    // decompiler-minted name — a stack slot, an undefined variable,
    // a bare letter plus digits — so nothing names it and the
    // mechanical suggestion stands.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  local_10 = 0x280;\n  uVar1 = 0x280;\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  x1 = 0x280;\n  return;\n",
        ),
    );
    let result = scan(program).await;

    let constant = named_constant(&result);
    assert_eq!(constant.count, 3, "the value still qualifies");
    assert_eq!(constant.name, None);
    assert_eq!(constant.suggestion, "const VALUE_0x280: u32 = 0x280;");
}

#[tokio::test]
async fn the_first_named_sighting_across_the_scan_names_the_constant() {
    // Two functions name the same value differently; the sighting
    // earlier in the listing wins, and swapping the listing order
    // swaps the name — deterministic either way.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  count = 0x280;\n  copy(dst, 0x280);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  size = 0x280;\n  return;\n",
        ),
    );
    let result = scan(program.clone()).await;
    assert_eq!(
        named_constant(&result).name.as_deref(),
        Some("COUNT_0x280"),
        "the first function in listing order wins"
    );

    program.listing.reverse();
    let result = scan(program).await;
    assert_eq!(
        named_constant(&result).name.as_deref(),
        Some("SIZE_0x280"),
        "the scan names from whichever function comes first"
    );
}

#[tokio::test]
async fn a_composite_mask_beside_its_independently_seen_bits_completes_the_group() {
    // A FakeProgram body combining 0x700 in a bitwise context
    // beside bits 8, 9, and 10 each seen singly. The scan's group
    // comes back complete: widened mask, widened width, and the
    // composite line in the evidence.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n  local_10 = 0x200;\n  uVar1 &= 0x700;\n",
            ),
        );
    let result = scan(program).await;

    let group = result
        .findings
        .iter()
        .find_map(|finding| match finding {
            ConstFinding::BitflagGroup(record) => Some(record),
            _ => None,
        })
        .expect("the scan should have reported the completed flag group");
    assert_eq!(group.bits, vec![8, 9, 10]);
    assert_eq!(group.mask, 0x700);
    assert_eq!(group.bit_width, 11);
    assert!(group.evidence.contains("uVar1 &= 0x700"));
}

#[tokio::test]
async fn two_functions_sharing_a_flag_bit_yield_one_program_level_family() {
    // The same flag surface read through two bodies: FUN_a carries
    // bits 8 and 10, FUN_b bits 10 and 11. The scan keeps both
    // per-function groups beside exactly one family record carrying
    // the union of bits, the contributors ascending, and a
    // confidence above the per-function band.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  uVar2 &= 0x400;\n  uVar2 |= 0x800;\n",
        ),
    );
    let result = scan(program).await;

    let groups: Vec<&crate::types::BitflagGroup> = result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::BitflagGroup(record) => Some(record),
            _ => None,
        })
        .collect();
    assert_eq!(groups.len(), 2, "the per-function groups stay beside");

    let family = flag_family(&result);
    assert_eq!(family.bits, vec![8, 10, 11]);
    assert_eq!(family.mask, 0xd00);
    assert_eq!(family.bit_width, 12);
    assert_eq!(
        family.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );
    assert_eq!(
        family.suggestion,
        "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }"
    );
    assert_eq!(
        family.evidence,
        "FUN_18003ab00: bits 0x100, 0x400; FUN_18003e750: bits 0x400, 0x800"
    );
    assert_eq!(family.confidence, Confidence::new(80));
    assert!(
        family.confidence.value() > groups[0].confidence.value(),
        "corroboration across functions reads stronger than one body"
    );

    // The family answers the per-function lookup of each
    // contributor, beside that function's own group.
    assert_eq!(
        kinds(&result, "FUN_18003ab00"),
        ["bitflag_group", "flag_family"]
    );
    assert_eq!(
        kinds(&result, "FUN_18003e750"),
        ["bitflag_group", "flag_family"]
    );
}

#[tokio::test]
async fn groups_sharing_no_bit_merge_into_no_family() {
    // Two functions reading unrelated flag types — bits 8 and 10
    // against bits 20 and 21 — keep their per-function records
    // alone: nothing merged, so nothing joins at the program
    // level, and the lone groups claim no family of their own.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if ((uVar1 & 0x400) != 0) {\n    uVar1 |= 0x100;\n  }\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  if ((uVar2 & 0x100000) != 0) {\n    uVar2 |= 0x200000;\n  }\n",
        ),
    );
    let result = scan(program).await;

    let families = result
        .findings
        .iter()
        .filter(|finding| finding.kind() == "flag_family")
        .count();
    assert_eq!(families, 0, "disjoint groups stay separate records");
    assert_eq!(kinds(&result, "FUN_18003ab00"), ["bitflag_group"]);
    assert_eq!(kinds(&result, "FUN_18003e750"), ["bitflag_group"]);
}

#[tokio::test]
async fn a_single_use_table_magic_yields_a_protocol_constant_finding() {
    // A FakeProgram body carrying a PNG magic in a comparison,
    // seen exactly once in one function — far below the repetition
    // threshold. The protocol reading matches it off the full
    // tally anyway: the finding is named after the table entry,
    // names the protocol, and answers the using function's
    // per-function lookup.
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
    let result = scan(program).await;

    let records = protocol_findings(&result);
    assert_eq!(records.len(), 1, "the single-use magic still reports");
    let record = records[0];
    assert_eq!(record.value, 0x89504e47);
    assert_eq!(record.name, "PNG_MAGIC");
    assert_eq!(record.protocol, "PNG image format");
    assert_eq!(record.count, 1);
    assert_eq!(record.functions, vec!["FUN_18003ab00".to_string()]);
    assert_eq!(record.suggestion, "const PNG_MAGIC: u32 = 0x89504e47;");
    assert_eq!(record.confidence, Confidence::new(75));
    assert!(
        record
            .evidence
            .contains("0x89504e47 used 1 times in FUN_18003ab00")
    );
    assert!(record.evidence.contains("PNG_MAGIC (PNG image format)"));

    // The protocol claim replaces the frequency reading: the value
    // never clears the repetition bar, so it is not also a named
    // constant, and the protocol finding answers the lookup.
    assert!(
        result
            .findings
            .iter()
            .filter(|finding| finding.kind() == "named_constant")
            .count()
            == 0
    );
    assert_eq!(kinds(&result, "FUN_18003ab00"), ["protocol_constant"]);
}

#[tokio::test]
async fn a_table_value_that_clears_the_frequency_threshold_lands_once() {
    // A table value repeated enough to clear the frequency bar
    // too: 0xdeadbeef appears three times across two functions. It
    // lands once, as the protocol finding, never also as a named
    // constant, and the protocol record carries the full usage
    // data the frequency pass would have.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  marker = 0xdeadbeef;\n  fill(dst, 0xdeadbeef);\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  check(0xdeadbeef);\n  return;\n",
        ),
    );
    let result = scan(program).await;

    let records = protocol_findings(&result);
    assert_eq!(records.len(), 1, "one finding per matched value");
    let record = records[0];
    assert_eq!(record.value, 0xdeadbeef);
    assert_eq!(record.name, "DEAD_BEEF_MARKER");
    assert_eq!(record.count, 3);
    assert_eq!(
        record.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );

    let named = result
        .findings
        .iter()
        .filter(|finding| finding.kind() == "named_constant")
        .count();
    assert_eq!(
        named, 0,
        "the protocol claim is the only record for the value"
    );
    assert_eq!(kinds(&result, "FUN_18003e750"), ["protocol_constant"]);
}

#[tokio::test]
async fn values_outside_the_table_stay_ordinary_named_constants() {
    // A repeated literal the table does not name keeps the
    // frequency reading's mechanical suggestion: the protocol
    // claim never dresses an unknown value up as known.
    let result = scan(program()).await;

    assert!(
        protocol_findings(&result).is_empty(),
        "the canned program carries no table magic"
    );
    let constant = named_constant(&result);
    assert_eq!(constant.value, 0x280);
    assert_eq!(constant.suggestion, "const SIZE_0x280: u32 = 0x280;");
}

#[tokio::test]
async fn two_palette_literals_across_two_functions_yield_one_color_finding() {
    // FUN_a carries 0x123456 and FUN_b carries 0xff00ff, each in a
    // call argument, each seen once — far below the repetition
    // bar. The color reading groups the two color-shaped values off
    // the tally into exactly one program-level palette naming both
    // values and both functions, and the finding answers each using
    // function's per-function lookup.
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
    let result = scan(program).await;

    let records = color_findings(&result);
    assert_eq!(records.len(), 1, "one palette finding per binary");
    let record = records[0];
    assert_eq!(record.values, vec![0x123456, 0xff00ff]);
    assert_eq!(
        record.functions,
        vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()]
    );
    assert_eq!(
        record.suggestion,
        "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = 0xff00ff;"
    );
    assert_eq!(record.confidence, Confidence::new(60));
    assert!(
        record
            .evidence
            .contains("0x123456 used 1 times in FUN_18003ab00")
    );
    assert!(
        record
            .evidence
            .contains("0xff00ff used 1 times in FUN_18003e750")
    );

    // The palette answers the per-function lookup of every
    // function that uses one of its colors.
    assert_eq!(kinds(&result, "FUN_18003ab00"), ["color_constant"]);
    assert_eq!(kinds(&result, "FUN_18003e750"), ["color_constant"]);
}

#[tokio::test]
async fn a_table_magic_that_is_color_shape_claims_no_palette() {
    // 0xc0ffee is both a table sentinel and 24-bit-shaped: the
    // protocol claim is strictly stronger, so the matched value
    // never joins a palette — and one remaining color-shaped
    // value alone is below the floor, so no palette forms.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (marker == 0xc0ffee) {\n    log();\n  }\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  fill(dst, 0x123456);\n",
        ),
    );
    let result = scan(program).await;

    assert_eq!(protocol_findings(&result).len(), 1, "the magic reports");
    assert!(
        color_findings(&result).is_empty(),
        "the matched magic never reads as a color, and the lone \
             remaining value claims nothing"
    );
}

#[tokio::test]
async fn scan_collects_findings_from_all_three_detectors() {
    let result = scan(program()).await;

    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);

    let findings: Vec<&ConstFinding> = result.for_function("FUN_18003ab00").collect();
    assert_eq!(findings.len(), 4);

    let ConstFinding::BitflagGroup(group) = findings[0] else {
        unreachable!("the flag bits read as a bitflag finding");
    };
    assert_eq!(group.bits, vec![8, 10]);
    assert_eq!(group.mask, 0x500);
    assert_eq!(group.confidence, Confidence::new(70));

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
    assert_eq!(constant.confidence, Confidence::new(60));

    let ConstFinding::ColorConstant(palette) = findings[3] else {
        unreachable!("the color-shaped literals read as a palette finding");
    };
    assert_eq!(palette.values, vec![3, 0x280]);

    // The named constant and the palette belong to both functions
    // that use their values.
    assert_eq!(
        kinds(&result, "FUN_18003e750"),
        ["named_constant", "color_constant"]
    );
}

#[tokio::test]
async fn scan_keeps_findings_in_scan_order() {
    // Both functions carry every shape and one carries a table
    // magic, so the persisted list must group their per-function
    // findings by function in listing order — bitmask then enum —
    // and append the program-level findings after them, never
    // interleaved: the named constants, then the flag family the
    // two identical groups merge into, then the protocol constant
    // the magic matched, then the color palette the color reading
    // grouped.
    let mut program = program();
    program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            &format!("{EVERY_SHAPE_BODY}  if (magic == 0xcafebabe) {{\n    dispatch();\n  }}\n"),
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
            ("FUN_18003e750", "bitflag_group"),
            ("FUN_18003e750", "enum_candidate"),
            ("FUN_18003ab00", "bitflag_group"),
            ("FUN_18003ab00", "enum_candidate"),
            ("", "named_constant"),
            ("", "flag_family"),
            ("", "protocol_constant"),
            ("", "color_constant"),
        ]
    );
}

#[tokio::test]
async fn scan_decompiles_each_function_exactly_once() {
    // The three detectors share one fetch per function; a scan
    // that asked each detector for its own copy would triple the
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
    // The decompiler cannot produce a body for every function; one bad
    // entry point must not cost the whole program its scan.
    let mut program = program();
    program.fail_decompiles = vec!["FUN_18003ab00".into()];
    let result = scan(program.clone()).await;

    assert!(
        result.is_empty(),
        "the failing function contributed nothing and the plain one carries no shape alone"
    );
    assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
}

#[tokio::test]
async fn a_scan_where_every_decompile_fails_aborts() {
    // The 2026-10-08 incident: the seam was answering about the
    // wrong program — the listing from one program, the decompiles
    // from another — every decompile failed, and the scan nearly
    // persisted a record that looks clean but is not, filed under
    // the target's name. The skip-rate breaker aborts with the
    // counts instead, so nothing is persisted.
    let mut program = program();
    program.fail_decompiles = vec!["FUN_18003ab00".into(), "FUN_18003e750".into()];
    let result = ConstEngine::with_source(program).scan("eqmain.dll").await;
    assert!(matches!(
        result,
        Err(crate::ConstError::DecompileBreaker {
            failed: 2,
            total: 2
        })
    ));
}

#[tokio::test]
async fn the_breaker_stops_the_scan_from_decompiling_the_rest() {
    // The breaker is a fuse, not a post-mortem: once more than half
    // the listing has failed, the remaining decompiles are wasted
    // round-trips against the wrong program.
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
    let result = ConstEngine::with_source(program.clone())
        .scan("eqmain.dll")
        .await;

    assert!(matches!(
        result,
        Err(crate::ConstError::DecompileBreaker {
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
    // arbitrary function's body, so the entry passes without a
    // decompile.
    let mut program = program();
    program.listing.insert(0, summary(""));
    let result = scan(program.clone()).await;

    assert_eq!(program.decompiled(), vec!["FUN_18003ab00", "FUN_18003e750"]);
    assert!(!result.is_empty());
}

#[tokio::test]
async fn a_failing_listing_fails_the_whole_run() {
    // With the listing gone nothing was scanned, so the run aborts
    // rather than returning a result that looks like a scan that
    // found no constants.
    let mut program = program();
    program.fail_listing = true;
    let result = ConstEngine::with_source(program).scan("eqmain.dll").await;
    assert!(matches!(
        result,
        Err(crate::ConstError::Engine(EngineError::Reported { .. }))
    ));
}

#[tokio::test]
async fn custom_thresholds_reach_every_detector() {
    // Swapping a detector's thresholds whole reaches the scan: the
    // configured bars find shapes the standard ones miss, and the
    // standard bars miss these shapes.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_1800412a0")];
    program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined FUN_1800412a0(void)",
                "  x &= 0x1;\n  switch(u) {\n  case 0:\n  case 1:\n    a();\n  }\n  b(7);\n  c(7);\n  d(7);\n  e(7);\n",
            ),
        );

    let engine = ConstEngine::with_source(program.clone())
        .with_bitmask(BitmaskDetector::with_min_bits(1))
        .with_sequential(SequentialDetector::with_min_run(2))
        .with_frequency(FrequencyAnalyzer::with_thresholds(4, 1, [0, 1, 2]));
    let result = engine.scan("eqmain.dll").await.expect("scan");

    assert_eq!(
        kinds(&result, "FUN_1800412a0"),
        ["bitflag_group", "enum_candidate", "named_constant"]
    );
    // The standard configuration finds none of these shapes.
    let standard = ConstEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan");
    assert!(standard.is_empty());
}

#[tokio::test]
async fn scan_stamps_the_scan_provenance() {
    // The metadata names the binary, carries a finish time, and
    // the duration is stamped from the wall clock — a canned scan
    // is instant, so it reads as zero seconds rather than never
    // set.
    let result = scan(program()).await;
    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);
    assert!(result.metadata.duration_secs < 60);
    // Story 9 (#203): the record also names the analysis engine
    // that produced it — scan() copies the source's provenance
    // through (#208).
    let engine = result
        .metadata
        .engine
        .expect("scan record names its engine");
    assert_eq!(engine.name, "fake-engine");
    assert_eq!(engine.version.as_deref(), Some("9.9"));
    assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
}

// ---- data-table readings (issue #278) ----

/// The scan's data-table findings, in landing order.
fn table_findings(result: &ConstResult) -> Vec<&crate::types::DataTable> {
    result
        .findings
        .iter()
        .filter_map(|finding| match finding {
            ConstFinding::DataTable(record) => Some(record),
            _ => None,
        })
        .collect()
}

/// The program the disqualification-gate tests start from: one
/// kept body indexes the 24-byte `DAT_1400a1b60` under a guard
/// naming 12 entries — the tracer's one-finding shape — so the
/// only thing between this program and a table finding is what a
/// gate makes of it.
fn table_program() -> FakeProgram {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  uint uVar2 = index;\n  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
            ),
        );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    program.xrefs_from(0x1400_a1b60, &["FUN_18003ab00"]);
    program
}

/// Adds one more kept function, listing entry and body, so a test
/// can put a shape in a different body than the one that reads the
/// table.
fn add_body(program: &mut FakeProgram, name: &str, body: &str) {
    program.listing.push(summary(name));
    program.bodies.insert(
        name.to_string(),
        function(name, &format!("undefined {name}(void)"), body),
    );
}

#[tokio::test]
async fn a_bounds_guarded_indexed_read_names_one_data_table() {
    // The happy path (#278's tracer bullet): a kept body indexes
    // a defined data object under a bounds guard, the bytes
    // decode uniformly, and the guard's bound picks the stride
    // out of the three that do — one table finding, every field
    // corroborated.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  uint uVar2 = index;\n  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n    store(uVar3);\n  }\n  return;\n",
            ),
        );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    program.xrefs_from(0x1400_a1b60, &["FUN_18003ab00"]);
    let result = scan(program).await;
    assert_eq!(result.findings.len(), 1, "only the table lands");
    let finding = &result.findings[0];
    assert_eq!(finding.kind(), "data_table");
    let ConstFinding::DataTable(table) = finding else {
        panic!("the finding should be a data table: {finding:?}");
    };
    assert_eq!(table.symbol, "DAT_1400a1b60");
    assert_eq!(table.address, 0x1400_a1b60);
    assert_eq!(table.element_type, "u16");
    assert_eq!(table.count, 12);
    assert_eq!(table.values, (1..=12).collect::<Vec<u64>>());
    assert!(!table.values_truncated);
    assert_eq!(table.functions, ["FUN_18003ab00"]);
    // The bare `DAT_*` label names its table by mechanical uppercase form.
    assert_eq!(table.suggestion, "const DAT_1400A1B60: [u16; 12];");
    assert_eq!(table.confidence, Confidence::new(70));
    assert_eq!(
        table.evidence,
        "FUN_18003ab00: uVar3 = DAT_1400a1b60[uVar2];"
    );
    assert_eq!(finding.target(), "DAT_1400a1b60 [u16; 12]");
    assert_eq!(finding.function(), "");
    // The referencing function's per-function lookup surfaces the table.
    assert_eq!(kinds(&result, "FUN_18003ab00"), ["data_table"]);
    assert!(result.for_function("FUN_18003fffff").next().is_none());
}

#[tokio::test]
async fn a_meaningful_label_names_its_table_verbatim_and_a_bare_label_gets_its_uppercase_form() {
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined FUN_18003ab00(void)",
                "  if (uVar2 < 0xc) {\n    uVar3 = weapon_stats[uVar2];\n  }\n  if (uVar4 < 3) {\n    uVar5 = DAT_1400a1c00[uVar4];\n  }\n  return;\n",
            ),
        );
    program.object_at(
        "weapon_stats",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    program.object_at(
        "DAT_1400a1c00",
        0x1400_a1c00,
        [1000u32, 3000, 5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 2, "both objects were claimed as tables");
    assert_eq!(tables[0].symbol, "weapon_stats");
    assert_eq!(tables[0].suggestion, "const weapon_stats: [u16; 12];");
    assert_eq!(tables[1].suggestion, "const DAT_1400A1C00: [u32; 3];");
}

#[tokio::test]
async fn data_table_findings_follow_data_listing_order() {
    // The listing puts the higher-addressed object first; the
    // findings keep that order, not any derived sorting.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 3) {\n    uVar3 = DAT_1400a1c20[uVar2];\n  }\n  return;\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  if (uVar4 < 0xc) {\n    uVar5 = DAT_1400a1b60[uVar4];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1c20",
        0x1400_a1c20,
        [1000u32, 3000, 5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    let symbols: Vec<&str> = table_findings(&result)
        .iter()
        .map(|table| table.symbol.as_str())
        .collect();
    assert_eq!(symbols, ["DAT_1400a1c20", "DAT_1400a1b60"]);
}

#[tokio::test]
async fn a_uniform_decode_at_one_width_needs_no_guard_to_name_the_table() {
    // An indexed read corroborates; the guard only disambiguates.
    // With one uniform width surviving, the read alone claims the
    // table.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar3 = DAT_1400a1c00[uVar2];\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1c00",
        0x1400_a1c00,
        [1000u32, 3000, 5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    let result = scan(program).await;
    assert_eq!(result.findings.len(), 1);
    let ConstFinding::DataTable(table) = &result.findings[0] else {
        unreachable!()
    };
    assert_eq!(table.element_type, "u32");
    assert_eq!(table.count, 3);
    assert_eq!(table.values, [1000, 3000, 5000]);
}

#[tokio::test]
async fn a_data_object_only_the_xrefs_name_claims_its_table_at_the_referenced_tier() {
    // The middle band of the confidence scale: a clean decode the
    // cross-references name a body reader for, but whose kept-body
    // read the walk never saw — real use, no read to corroborate
    // the shape against. The reader's name is on the record and
    // the claim scores below the corroborated one.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1c00",
        0x1400_a1c00,
        [1000u32, 3000, 5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    program.xrefs_from(0x1400_a1c00, &["FUN_18003ab00"]);
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the referenced object claims its table");
    let table = tables[0];
    assert_eq!(table.confidence.value(), 50);
    assert_eq!(
        table.evidence,
        "12 bytes decode cleanly as 3 u32 entries at 0x1400a1c00; the cross-references name one function, no kept body indexes it"
    );
    assert_eq!(table.functions, ["FUN_18003ab00"]);
}

#[tokio::test]
async fn a_data_object_nothing_references_claims_its_table_at_the_raw_tier() {
    // The bottom band: bytes that decode cleanly with no body read
    // and no reference at all stay on the record at an honest low
    // score the human filters, rather than being hidden.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1c00",
        0x1400_a1c00,
        [1000u32, 3000, 5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the clean bytes claim their table");
    let table = tables[0];
    assert_eq!(table.confidence.value(), 30);
    assert_eq!(
        table.evidence,
        "12 bytes decode cleanly as 3 u32 entries at 0x1400a1c00; nothing references the object"
    );
    assert!(table.functions.is_empty());
}

#[tokio::test]
async fn bytes_incoherent_at_every_width_claim_nothing() {
    // Viability before resolution: four u32 scalars whose u32
    // decode spreads three orders of magnitude past the coherent
    // family's budget (1, 2, and two 4-billion-scale values). The
    // u16 and u8 decodes hit the zero halves between them, the
    // wide u64 decode inherits the same spread across its two
    // entries, and the float decodes read the small values as
    // denormals. No stride carries a coherent table at all, and
    // the guard-sized read resolves nothing.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 8) {\n    uVar3 = DAT_1400a1c00[uVar2];\n  }\n  return;\n",
        ),
    );
    let mut bytes = Vec::new();
    for value in [1u32, 2, 0xf000_0000, 0xe000_0000] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    program.object_at("DAT_1400a1c00", 0x1400_a1c00, bytes);
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn an_object_shorter_than_two_entries_claims_nothing() {
    // The minimum bar: one byte decodes to fewer than two elements
    // at every stride, so it is a scalar, not a table.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar3 = DAT_1400a1c00[uVar2];\n  return;\n",
        ),
    );
    program.object_at("DAT_1400a1c00", 0x1400_a1c00, vec![0x24u8]);
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn an_applied_uint_over_bytes_that_decode_at_three_widths_types_the_table() {
    // The top band of the confidence scale: the analysis engine's
    // own listing typed the object `uint` while the bytes decode
    // coherently at u16, u32 and u64 alike. The applied type
    // resolves the multi-stride decode to u32, and the claim
    // scores above every decode-only band.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar3 = DAT_1400a1c40[uVar2];\n  return;\n",
        ),
    );
    program.typed_object_at(
        "DAT_1400a1c40",
        0x1400_a1c40,
        "uint",
        (1u16..=8).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the typed object claims one table");
    let table = tables[0];
    assert_eq!(table.confidence.value(), 90);
    assert_eq!(table.element_type, "u32");
    assert_eq!(table.count, 4);
    assert_eq!(
        table.values,
        [0x0002_0001, 0x0004_0003, 0x0006_0005, 0x0008_0007]
    );
    assert_eq!(
        table.evidence,
        "data listing applies type `uint`; FUN_18003ab00: uVar3 = DAT_1400a1c40[uVar2];"
    );
    assert_eq!(table.suggestion, "const DAT_1400A1C40: [u32; 4];");
    assert!(table.functions.is_empty());
}

#[tokio::test]
async fn the_listing_applied_float_three_over_f32_bytes_claims_the_float_table() {
    // The float families landing with the listing's applied type:
    // `float [3]` over three f32 bit patterns whose u32 decode is
    // coherent as well — the applied array type picks f32, its
    // count agrees with the length, and the values carry the
    // entries' bit patterns whole for codegen to re-spell.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  fVar1 = DAT_1400a1c40[fVar2];\n  return;\n",
        ),
    );
    let mut bytes = Vec::new();
    for value in [0.5f32, 1.0, 2.0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    program.typed_object_at("DAT_1400a1c40", 0x1400_a1c40, "float [3]", bytes);
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the typed object claims one table");
    let table = tables[0];
    assert_eq!(table.confidence.value(), 90);
    assert_eq!(table.element_type, "f32");
    assert_eq!(table.count, 3);
    assert_eq!(
        table.values,
        [
            u64::from(0.5f32.to_bits()),
            u64::from(1.0f32.to_bits()),
            u64::from(2.0f32.to_bits())
        ]
    );
    assert_eq!(
        table.evidence,
        "data listing applies type `float [3]`; FUN_18003ab00: fVar1 = DAT_1400a1c40[fVar2];"
    );
    assert_eq!(table.suggestion, "const DAT_1400A1C40: [f32; 3];");
}

#[tokio::test]
async fn an_applied_array_whose_count_disagrees_with_the_length_types_nothing() {
    // `float [4]` over eight bytes: the applied count says sixteen
    // bytes, so the listing types nothing; the surviving u16 and
    // u32 decodes are two widths with no guard to pick between
    // them, and the claim stays unresolved.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar3 = DAT_1400a1c40[uVar2];\n  return;\n",
        ),
    );
    program.typed_object_at(
        "DAT_1400a1c40",
        0x1400_a1c40,
        "float [4]",
        (1u16..=4).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn an_applied_type_the_guards_contradict_claims_nothing() {
    // The listing applied `ushort`, and the guard sizes the read at
    // 4 bytes: the applied type has to name a stride the decode
    // supports and the reads agree with, and a guard contradicting
    // it leaves the object unresolved rather than overruling the
    // body that indexes it.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 4) {\n    uVar3 = DAT_1400a1c40[uVar2];\n  }\n  return;\n",
        ),
    );
    program.typed_object_at(
        "DAT_1400a1c40",
        0x1400_a1c40,
        "ushort",
        (1u16..=8).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn two_bodies_guards_that_agree_on_one_width_resolve_the_decode() {
    // Resolution from the reads themselves: the 24 bytes decode
    // coherently at u16, u32 and u64 alike, and the two bodies'
    // guards — one hex, one decimal — both name twelve entries, so
    // both imply the 2-byte stride and the u16 table lands with the
    // indexed reads as its corroboration.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003ac00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003ac00".into(),
        function(
            "FUN_18003ac00",
            "undefined FUN_18003ac00(void)",
            "  if (12 > uVar4) {\n    uVar5 = DAT_1400a1b60[uVar4];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the agreeing guards resolve one width");
    let table = tables[0];
    assert_eq!(table.element_type, "u16");
    assert_eq!(table.count, 12);
    assert_eq!(table.confidence.value(), 70);
    assert_eq!(
        table.evidence,
        "FUN_18003ab00: uVar3 = DAT_1400a1b60[uVar2]; FUN_18003ac00: uVar5 = DAT_1400a1b60[uVar4];"
    );
}

#[tokio::test]
async fn an_indexed_read_beats_function_xrefs_to_the_corroborated_tier() {
    // The two evidence paths over one clean decode: the body read
    // corroborates at 70 where the Xrefs-only path lands at 50,
    // and every reader the analysis engine names stays on the
    // record.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003ac00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar3 = DAT_1400a1c00[uVar2];\n  return;\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003ac00".into(),
        function(
            "FUN_18003ac00",
            "undefined FUN_18003ac00(void)",
            "  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1c00",
        0x1400_a1c00,
        [1000u32, 3000, 5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    program.xrefs_from(0x1400_a1c00, &["FUN_18003ab00", "FUN_18003ac00"]);
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the read corroborates one table");
    let table = tables[0];
    assert_eq!(table.confidence.value(), 70);
    assert_eq!(
        table.evidence,
        "FUN_18003ab00: uVar3 = DAT_1400a1c00[uVar2];"
    );
    assert_eq!(table.functions, ["FUN_18003ab00", "FUN_18003ac00"]);
}

#[tokio::test]
async fn a_decode_uniform_at_two_widths_with_no_guard_to_pick_claims_nothing() {
    // The resolution the stride-viability ticket (#280) needs an
    // input for: bytes coherent at u16, u32 and u64, no guard to
    // size the read and no listing type to name the stride, stay
    // unresolved — a table the scan cannot size claims nothing.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  uVar3 = DAT_1400a1b60[uVar2];\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn a_guard_that_contradicts_the_bytes_claims_nothing() {
    // A guard naming the u8 width over bytes whose u8 decode
    // carries zero-valued entries: the guard and the decode
    // disagree, and the claim stays inside what both agree on.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0x18) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn guards_naming_different_widths_claim_nothing() {
    // Two readers' guards imply different widths (12 entries of
    // u16 and 6 entries of u32 for the same object); the
    // disagreement claims nothing. The rule touches the table
    // reading only, never the program's other findings.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00"), summary("FUN_18003e750")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.bodies.insert(
        "FUN_18003e750".into(),
        function(
            "FUN_18003e750",
            "undefined FUN_18003e750(void)",
            "  if (uVar4 < 6) {\n    uVar5 = DAT_1400a1b60[uVar4];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    assert!(table_findings(&result).is_empty());
}

#[tokio::test]
async fn an_all_equal_fill_claims_nothing_even_under_a_sizing_guard() {
    // 0xCC padding guarded like a table: entries all equal at
    // every width — a fill is not a table.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0x18) {\n    uVar3 = DAT_1400a1d00[uVar2];\n  }\n  return;\n",
        ),
    );
    program.object_at("DAT_1400a1d00", 0x1400_a1d00, vec![0xcc; 48]);
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn a_body_that_assigns_to_the_symbol_claims_nothing() {
    // The mutation gate is absolute and any kept body trips it:
    // the object is mutable global state, the global-state
    // track's territory, so the read that sized it never claims a
    // constant table. This program without the store line is the
    // tracer's one-finding case.
    let mut program = table_program();
    add_body(
        &mut program,
        "FUN_18003e750",
        "  DAT_1400a1b60 = 0;\n  return;\n",
    );
    let result = scan(program).await;
    assert!(table_findings(&result).is_empty());
}

#[tokio::test]
async fn a_body_that_stores_through_an_index_into_the_symbol_claims_nothing() {
    let mut program = table_program();
    add_body(
        &mut program,
        "FUN_18003e750",
        "  if (uVar4 < 0xc) {\n    DAT_1400a1b60[uVar4] = uVar5;\n  }\n  return;\n",
    );
    let result = scan(program).await;
    assert!(table_findings(&result).is_empty());
}

#[tokio::test]
async fn a_body_that_stores_through_the_symbol_another_way_claims_nothing() {
    // The decompiler writes a store through a symbol's address
    // several ways; every one of them is the same mutable state.
    let mut program = table_program();
    add_body(
        &mut program,
        "FUN_18003e750",
        "  *(int *)(&DAT_1400a1b60)[uVar4] = 3;\n  *(int *)(DAT_1400a1b60 + 4) = 0;\n  return;\n",
    );
    let result = scan(program).await;
    assert!(table_findings(&result).is_empty());
}

#[tokio::test]
async fn an_all_function_pointer_table_claims_nothing() {
    // A table whose every entry is the address of a listed
    // function is a dispatch table: the callback crate's
    // jump-table reading owns that outright, so this one claims
    // nothing even though the bytes decode cleanly at u64 and a
    // guard picks that stride out of the widths the bytes allow.
    // The pointed-to functions carry bodies because more than half
    // a listing failing to decompile aborts the whole scan.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 3) {\n    (*(code *)DAT_1400a1b60[uVar2])();\n  }\n  return;\n",
        ),
    );
    for address in [0x1400_412a0u64, 0x1400_41300, 0x1400_41540] {
        let name = format!("FUN_{address:08x}");
        program.listing.push(summary_at(&name, address));
        program.bodies.insert(
            name.clone(),
            function(&name, &format!("undefined {name}(void)"), "  return;\n"),
        );
    }
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        [0x1400_412a0u64, 0x1400_41300, 0x1400_41540]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect(),
    );
    program.xrefs_from(0x1400_a1b60, &["FUN_18003ab00"]);
    let result = scan(program).await;
    assert!(table_findings(&result).is_empty());
}

#[tokio::test]
async fn a_mixed_pointer_and_scalar_object_claims_nothing() {
    // Some entries resolve to listed function starts and some are
    // ordinary small values: a half-decoded mix claims nothing —
    // resolving the pointers is the types track's call, never a
    // const array of numbers that are really addresses.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 4) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    for address in [0x1400_412a0u64, 0x1400_41300] {
        let name = format!("FUN_{address:08x}");
        program.listing.push(summary_at(&name, address));
        program.bodies.insert(
            name.clone(),
            function(&name, &format!("undefined {name}(void)"), "  return;\n"),
        );
    }
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        [0x1400_412a0u64, 0x1400_41300, 0x2_0000, 0x1400_41540]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect(),
    );
    program.xrefs_from(0x1400_a1b60, &["FUN_18003ab00"]);
    let result = scan(program).await;
    assert!(table_findings(&result).is_empty());
}

#[tokio::test]
async fn entries_no_function_start_names_claim_their_table_the_same() {
    // Large magnitudes are not a disqualification: these values sit
    // in the same 400-million range as the listed function's start
    // address without any of them equal to it, so they stay
    // ordinary scalars and the table lands with them. The veto is
    // resolution, not magnitude.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 4) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        [0x1400_0000u32, 0x1401_0000, 0x1800_3000, 0x1800_0000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    );
    program.xrefs_from(0x1400_a1b60, &["FUN_18003ab00"]);
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1, "the near-address values land as one table");
    assert_eq!(tables[0].element_type, "u32");
    assert_eq!(tables[0].count, 4);
    assert_eq!(tables[0].confidence.value(), 70);
    assert_eq!(
        tables[0].values,
        vec![0x1400_0000, 0x1401_0000, 0x1800_3000, 0x1800_0000]
    );
}

#[tokio::test]
async fn a_body_that_only_reads_and_compares_through_the_object_still_claims_it() {
    // Reads are not writes even when they read a lot: a
    // comparison against the symbol, a read through a cast of it,
    // and a string literal naming it all leave the object a
    // constant table.
    let mut program = table_program();
    add_body(
        &mut program,
        "FUN_18003e750",
        "  if ((int)DAT_1400a1b60 != 5) {\n    uVar4 = (uint)(&DAT_1400a1b60)[uVar5];\n  }\n  printf(\"DAT_1400a1b60 = 1\\n\");\n  return;\n",
    );
    let result = scan(program).await;
    let tables = table_findings(&result);
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].element_type, "u16");
}

#[tokio::test]
async fn a_write_in_a_body_that_never_decompiled_claims_the_table_anyway() {
    // The gate watches the bodies the scan actually keeps: a
    // function whose decompile failed contributes nothing, store
    // lines included, so the table the kept body reads still
    // lands.
    let mut program = table_program();
    program.listing.push(summary("FUN_18003e750"));
    let result = scan(program).await;
    assert_eq!(table_findings(&result).len(), 1);
}

#[tokio::test]
async fn values_past_the_inline_cap_truncate_while_the_count_stays_whole() {
    // 600 u32 entries (2400 bytes) guarded by their own count:
    // the values list caps at the inline ceiling, the truncation
    // flag says so, and the count keeps the whole 600.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0x258) {\n    uVar3 = DAT_1400a1e00[uVar2];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1e00",
        0x1400_a1e00,
        (1u32..=600).flat_map(|value| value.to_le_bytes()).collect(),
    );
    let result = scan(program).await;
    assert_eq!(result.findings.len(), 1);
    let ConstFinding::DataTable(table) = &result.findings[0] else {
        unreachable!()
    };
    assert_eq!(table.element_type, "u32");
    assert_eq!(table.count, 600);
    assert_eq!(table.values.len(), crate::types::MAX_INLINE_TABLE_VALUES);
    assert!(table.values_truncated);
    assert_eq!(&table.values[..3], &[1, 2, 3]);
}

#[tokio::test]
async fn an_object_with_no_readable_window_claims_nothing() {
    // The bytes are the decode's ground truth: an object the
    // listing defines but `read_memory` cannot answer is skipped.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.data_items.push(DataItem {
        label: "DAT_1400a1b60".to_string(),
        address: 0x1400_a1b60,
        type_name: "undefined".to_string(),
        length: 24,
    });
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

#[tokio::test]
async fn a_short_memory_window_claims_nothing() {
    // A listing length of 24 answered by a 12-byte window is not
    // enough ground truth to decode against — skip, don't guess.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.data_items.push(DataItem {
        label: "DAT_1400a1b60".to_string(),
        address: 0x1400_a1b60,
        type_name: "undefined".to_string(),
        length: 24,
    });
    program.memory_at(
        0x1400_a1b60,
        (1u16..=6).flat_map(u16::to_le_bytes).collect(),
    );
    let result = scan(program).await;
    assert!(result.findings.is_empty());
}

// -- admitted coverage (P19 admitted-semantics track, issue #348) -----

/// The data-level verdict of the roster pin: empty means the record
/// names every declared facet exactly once, and each fault names one
/// drift.
fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
    coverage.roster_faults(DECLARED_FACETS)
}

/// The facet a roster-clean record names under `id`.
fn facet<'a>(coverage: &'a ScanCoverage, id: &str) -> &'a FacetCoverage {
    coverage
        .facets
        .iter()
        .find(|facet| facet.id == id)
        .unwrap_or_else(|| panic!("`{id}` is named"))
}

#[tokio::test]
async fn scan_stamps_coverage_naming_every_declared_facet_once() {
    // Bodies read, one object's window read in full: the scan fell
    // short of nothing, so it admits nothing and a constant the
    // detectors missed reads as absent, not unchecked.
    let result = scan(table_program()).await;
    let coverage = result
        .metadata
        .coverage
        .expect("a fresh consts scan states its coverage");
    assert_eq!(coverage.status, CoverageStatus::Complete);
    assert!(
        roster_faults(&coverage).is_empty(),
        "a fresh document must name every declared facet exactly once"
    );
    for id in DECLARED_FACETS {
        let facet = facet(&coverage, id);
        assert_eq!(facet.status, CoverageStatus::Complete, "`{id}` was read");
        assert_eq!(facet.limitation, None, "complete coverage names no limit");
    }
    assert_eq!(
        coverage.admission(),
        None,
        "a fully examined scan gives the sections nothing to qualify"
    );

    // An empty listing was read end to end too: it named nothing,
    // which is complete coverage, never an unexamined scan.
    let coverage = scan(FakeProgram::empty())
        .await
        .metadata
        .coverage
        .expect("a fresh consts scan states its coverage");
    assert_eq!(coverage.status, CoverageStatus::Complete);
    assert!(roster_faults(&coverage).is_empty());
}

#[tokio::test]
async fn a_region_limited_scan_names_both_facets_partial_with_their_reasons() {
    // The two regions fall short at once: the bodies walk loses a
    // named function to a failed decompile and a nameless listing
    // entry it can name nothing about, and the data listing defines
    // an object whose memory window never arrives. The record says
    // which parts it could not read. A scan that filed almost
    // nothing under this record reads as "examined little" — what
    // an escalate retry needs — never as "this binary has no
    // constants".
    let mut program = table_program();
    program.listing.push(summary("FUN_18003e750"));
    program.fail_decompiles.push("FUN_18003e750".to_string());
    program.listing.push(summary_at("", 0x1800_40000));
    program.data_items.push(DataItem {
        label: "DAT_1400a1c00".to_string(),
        address: 0x1400_a1c00,
        type_name: "undefined".to_string(),
        length: 24,
    });
    let result = scan(program).await;
    assert_eq!(
        table_findings(&result).len(),
        1,
        "the object the scan did read still claims its table"
    );

    let coverage = result
        .metadata
        .coverage
        .expect("a fresh consts scan states its coverage");
    assert!(
        roster_faults(&coverage).is_empty(),
        "a scan that fell short still names every declared facet exactly once"
    );
    assert_eq!(
        coverage.status,
        CoverageStatus::Partial,
        "the border stands until an engine change moves it"
    );
    assert_eq!(
        facet(&coverage, "function-bodies").limitation.as_deref(),
        Some("2 function bodies unreached: FUN_18003e750, +1 more"),
        "the failed decompile names itself, the nameless entry is counted"
    );
    assert_eq!(
        facet(&coverage, "data-objects").limitation.as_deref(),
        Some("1 data-object memory window unreadable: DAT_1400a1c00"),
        "the object left unexamined names itself"
    );
    assert_eq!(
        coverage.admission().as_deref(),
        Some(
            "partial — 2 function bodies unreached: FUN_18003e750, +1 more; \
                 1 data-object memory window unreadable: DAT_1400a1c00"
        ),
        "what a reviewer reads is the shared type's own admission line"
    );
}

#[tokio::test]
async fn a_window_that_arrived_and_claimed_nothing_leaves_the_facet_complete() {
    // The disqualification gates are the object's shape, not the
    // scan's border: an object read in full whose bytes decode
    // incoherently, or a mutation-gated one, claims nothing and
    // admits nothing. Only a window that never arrived is a limit.
    let mut program = table_program();
    program.data_items.push(DataItem {
        label: "DAT_1400a1c00".to_string(),
        address: 0x1400_a1c00,
        type_name: "undefined".to_string(),
        length: 24,
    });
    program.memory_at(0x1400_a1c00, vec![0u8; 24]);
    let coverage = scan(program).await.metadata.coverage.expect("coverage");
    assert_eq!(coverage.status, CoverageStatus::Complete);
    assert_eq!(
        facet(&coverage, "data-objects").status,
        CoverageStatus::Complete
    );
}

#[tokio::test]
async fn the_bodies_limit_line_names_five_unreached_functions_and_counts_the_rest() {
    // Bounded prose beside the counts, not a dump: the same cap
    // floatsimd's admission carries (#347).
    let mut program = FakeProgram::empty();
    for index in 0..16 {
        let name = format!("FUN_{index:04}");
        if index < 7 {
            program.listing.push(summary(&name));
            program.fail_decompiles.push(name);
        } else {
            // A listing entry with no canned body fails to decompile
            // too, which would feed the failure count the skip-rate
            // breaker weighs against the whole listing.
            add_body(&mut program, &name, "  return;\n");
        }
    }
    let coverage = scan(program).await.metadata.coverage.expect("coverage");
    assert_eq!(
        facet(&coverage, "function-bodies").limitation.as_deref(),
        Some(
            "7 function bodies unreached: FUN_0000, FUN_0001, FUN_0002, FUN_0003, FUN_0004, +2 more"
        )
    );
}

#[tokio::test]
async fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
    let mut coverage = coverage_stamp(&[], 0, &[]);
    coverage.facets.retain(|facet| facet.id != "data-objects");
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `data-objects` is missing from the record"],
        "an engine quietly skipping a declared facet fails loudly"
    );
}

#[tokio::test]
async fn the_roster_pin_fails_when_a_facet_is_doubled() {
    let mut coverage = coverage_stamp(&[], 0, &[]);
    coverage.facets.push(coverage.facets[0].clone());
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `function-bodies` appears 2 times in the record"],
        "a facet crowded into two entries fails loudly"
    );
}

#[tokio::test]
async fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
    let mut coverage = coverage_stamp(&[], 0, &[]);
    coverage.facets.push(FacetCoverage {
        id: "import-table".to_string(),
        status: CoverageStatus::Unexamined,
        limitation: None,
    });
    assert_eq!(
        roster_faults(&coverage),
        ["record names `import-table`, a facet the engine never declared"],
        "an id invented outside the declared roster fails loudly"
    );
}

#[tokio::test]
async fn a_failed_xref_read_lands_the_table_with_no_referencing_functions() {
    // The claim rests on the bytes and the body read: a failing
    // `xrefs_to` degrades the record's function list to empty
    // (logged), and does not drop the table.
    let mut program = FakeProgram::empty();
    program.listing = vec![summary("FUN_18003ab00")];
    program.bodies.insert(
        "FUN_18003ab00".into(),
        function(
            "FUN_18003ab00",
            "undefined FUN_18003ab00(void)",
            "  if (uVar2 < 0xc) {\n    uVar3 = DAT_1400a1b60[uVar2];\n  }\n  return;\n",
        ),
    );
    program.object_at(
        "DAT_1400a1b60",
        0x1400_a1b60,
        (1u16..=12).flat_map(u16::to_le_bytes).collect(),
    );
    program.fail_xrefs = true;
    let result = scan(program).await;
    assert_eq!(result.findings.len(), 1);
    let ConstFinding::DataTable(table) = &result.findings[0] else {
        unreachable!()
    };
    assert_eq!(table.element_type, "u16");
    assert!(table.functions.is_empty());
}

#[tokio::test]
async fn an_empty_program_yields_an_empty_result() {
    let result = scan(FakeProgram::empty()).await;
    assert!(result.is_empty());
    assert_eq!(result.metadata.binary, "eqmain.dll");
    assert!(result.metadata.scanned_at > 0);
}

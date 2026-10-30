// Tests for the module above, split out of the file they test.
use super::*;
use crate::error::TypesDbError;
use crate::stl::StlKind;
use crate::types::{FieldType, StructField, VtableMethod};
use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    Result as EngineResult, StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::yield_now;

fn le32(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn le64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn entry(name: &str, category: &str, size: Option<u64>) -> DataTypeEntry {
    DataTypeEntry {
        name: name.to_string(),
        category: category.to_string(),
        size,
        path: format!("/{category}/{name}"),
    }
}

fn item(label: &str, address: u64, type_name: &str, length: u64) -> DataItem {
    DataItem {
        label: label.to_string(),
        address,
        type_name: type_name.to_string(),
        length,
    }
}

fn reference(function: &str) -> Xref {
    Xref {
        address: 0x1800_0100,
        function: Some(function.to_string()),
        kind: Some("DATA".to_string()),
    }
}

/// A TypeDescriptor body: the header pair plus the mangled name.
fn type_descriptor(name: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes
}

/// State shared by every clone of a [`FakeProgram`], so a test can read
/// what the scans did after the orchestration has consumed its source.
#[derive(Debug, Default)]
struct Stats {
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    tags: Mutex<Vec<(u64, String)>>,
}

/// A canned program implementing [`ScanSource`] and [`TagSink`], so the
/// whole orchestration runs without a server. Every source call yields
/// first, the way a real HTTP call pends, so the concurrency test can
/// observe the scans overlapping.
#[derive(Clone)]
struct FakeProgram {
    listing: Vec<DataTypeEntry>,
    buckets: HashMap<&'static str, Vec<DataTypeEntry>>,
    layouts: HashMap<String, StructLayout>,
    enums: HashMap<String, EnumDefinition>,
    items: Vec<DataItem>,
    functions: Vec<FunctionSummary>,
    image_base: u64,
    memory: HashMap<u64, Vec<u8>>,
    literals: Vec<StringLiteral>,
    xrefs: HashMap<u64, Vec<Xref>>,
    fail_items: bool,
    stats: Arc<Stats>,
}

impl FakeProgram {
    fn empty() -> Self {
        Self {
            listing: Vec::new(),
            buckets: HashMap::new(),
            layouts: HashMap::new(),
            enums: HashMap::new(),
            items: Vec::new(),
            functions: Vec::new(),
            image_base: 0x1800_00000,
            memory: HashMap::new(),
            literals: Vec::new(),
            xrefs: HashMap::new(),
            fail_items: false,
            stats: Arc::new(Stats::default()),
        }
    }

    fn enter(&self) {
        let now = self.stats.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.stats.max_in_flight.fetch_max(now, Ordering::SeqCst);
    }

    fn exit(&self) {
        self.stats.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    fn tagged(&self) -> Vec<(u64, String)> {
        self.stats.tags.lock().unwrap().clone()
    }
}

/// The canned program: one PE struct and one enum in the Type Manager,
/// one RTTI-confirmed vtable with two methods, and a two-literal cluster
/// that infers to a `Player` candidate.
fn program() -> FakeProgram {
    let mut program = FakeProgram::empty();

    program.listing = vec![
        entry("IMAGE_DOS_HEADER", "pe", Some(128)),
        entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
    ];
    program
        .buckets
        .insert("struct", vec![entry("IMAGE_DOS_HEADER", "pe", Some(128))]);
    program.buckets.insert(
        "enum",
        vec![entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4))],
    );
    program.layouts.insert(
        "IMAGE_DOS_HEADER".into(),
        StructLayout {
            name: "IMAGE_DOS_HEADER".into(),
            size: 128,
            alignment: 1,
            fields: vec![StructFieldLayout {
                offset: 0,
                size: 2,
                type_name: "char[2]".into(),
                field_name: "e_magic".into(),
            }],
        },
    );
    program.enums.insert(
        "_EXCEPTION_DISPOSITION".into(),
        EnumDefinition {
            name: "_EXCEPTION_DISPOSITION".into(),
            size: 4,
            members: vec![calxgloss_decomp::EnumMember {
                name: "ExceptionContinueExecution".into(),
                value: 0,
            }],
        },
    );

    // vftable @ 1801306f0 preceded by its vftable_meta_ptr, whose COL
    // names the class Widget with base Base.
    program.items = vec![
        item("vftable_meta_ptr", 0x1801_306e8, "pointer", 8),
        item("vftable", 0x1801_306f0, "pointer[2]", 16),
    ];
    program.functions = vec![
        FunctionSummary {
            name: "FUN_18003ab00".into(),
            address: 0x1800_3ab00,
        },
        FunctionSummary {
            name: "FUN_18003e750".into(),
            address: 0x1800_3e750,
        },
    ];
    program.memory.insert(
        0x1801_306f0,
        [le64(0x1800_3ab00), le64(0x1800_3e750)].concat(),
    );
    program.memory.insert(0x1801_306e8, le64(0x1801_30700));
    program.memory.insert(
        0x1801_30700,
        [le32(1), le32(0), le32(0), le32(0x13_0800), le32(0x13_0900)].concat(),
    );
    program
        .memory
        .insert(0x1801_30800, type_descriptor(".?AVWidget@@"));
    program.memory.insert(
        0x1801_30900,
        [le32(0), le32(0), le32(1), le32(0x13_0a00)].concat(),
    );
    program.memory.insert(0x1801_30a00, le32(0x13_0b00));
    let mut bcd = vec![0u8; 24];
    bcd.extend_from_slice(&le32(0x13_0c00));
    bcd.extend_from_slice(&[0u8; 4]);
    program.memory.insert(0x1801_30b00, bcd);
    program
        .memory
        .insert(0x1801_30c00, type_descriptor(".?AVBase@@"));

    program.literals = vec![
        StringLiteral {
            address: 0x1801_29350,
            value: "player.x=1".into(),
        },
        StringLiteral {
            address: 0x1801_29360,
            value: "player.y=2".into(),
        },
    ];
    program
        .xrefs
        .insert(0x1801_29350, vec![reference("Player_update")]);
    program
        .xrefs
        .insert(0x1801_29360, vec![reference("Player_update")]);
    program
}

/// The same program, but the literals are read by the vtable's methods
/// instead of `Player_update`, so the candidate should link to the table
/// and take its class name.
fn program_read_by_vtable_methods() -> FakeProgram {
    let mut program = program();
    program.xrefs.insert(
        0x1801_29350,
        vec![reference("FUN_18003ab00"), reference("FUN_18003e750")],
    );
    program
        .xrefs
        .insert(0x1801_29360, vec![reference("FUN_18003ab00")]);
    program
}

/// The same program, but the `Widget` fields are read across two
/// methods plus a hub: the hub points at 25 literals, so it cannot
/// cluster them, and the field list splits into two half-candidates
/// that the merge pass has to join back into one through the hub.
fn program_split_by_a_hub() -> FakeProgram {
    let mut program = program();
    for (address, value) in [
        (0x1801_29400, "widget.width=1"),
        (0x1801_29410, "widget.height=2"),
        (0x1801_29420, "widget.label=hello"),
        (0x1801_29430, "widget.visible=true"),
    ] {
        program.literals.push(StringLiteral {
            address,
            value: value.into(),
        });
    }
    program.xrefs.insert(
        0x1801_29400,
        vec![reference("FUN_18003ab00"), reference("FUN_widget_access")],
    );
    program.xrefs.insert(
        0x1801_29410,
        vec![reference("FUN_18003ab00"), reference("FUN_widget_access")],
    );
    program.xrefs.insert(
        0x1801_29420,
        vec![reference("FUN_18003e750"), reference("FUN_widget_access")],
    );
    program.xrefs.insert(
        0x1801_29430,
        vec![reference("FUN_18003e750"), reference("FUN_widget_access")],
    );
    // 21 more literals read only by the hub: its fan-out reaches 25,
    // past the hub threshold, so it clusters none of them.
    for i in 0..21u64 {
        let address = 0x1801_29500 + 8 * i;
        program.literals.push(StringLiteral {
            address,
            value: format!("filler_{i}"),
        });
        program
            .xrefs
            .insert(address, vec![reference("FUN_widget_access")]);
    }
    program
}

/// The same program, plus a `WIDGET` struct whose fields name other
/// recovered types: `MODES` (one enum), `MY_UNION` (one union), and
/// `SHARED` (two types share the name), so the nesting pass has a
/// unique link, a union link, and an ambiguous name to work through.
fn program_with_nested_fields() -> FakeProgram {
    let mut program = program();
    program.listing.extend(vec![
        entry("WIDGET", "pe", Some(24)),
        entry("MODES", "excpt.h", Some(4)),
        entry("MY_UNION", "sys", Some(8)),
        entry("SHARED", "a", Some(4)),
        entry("SHARED", "b", Some(4)),
    ]);
    program.buckets.insert(
        "struct",
        vec![
            entry("IMAGE_DOS_HEADER", "pe", Some(128)),
            entry("WIDGET", "pe", Some(24)),
            entry("SHARED", "a", Some(4)),
            entry("SHARED", "b", Some(4)),
        ],
    );
    program.buckets.insert(
        "enum",
        vec![
            entry("_EXCEPTION_DISPOSITION", "excpt.h", Some(4)),
            entry("MODES", "excpt.h", Some(4)),
        ],
    );
    program
        .buckets
        .insert("union", vec![entry("MY_UNION", "sys", Some(8))]);
    program.layouts.insert(
        "WIDGET".into(),
        StructLayout {
            name: "WIDGET".into(),
            size: 24,
            alignment: 4,
            fields: vec![
                StructFieldLayout {
                    offset: 0,
                    size: 4,
                    type_name: "MODES".into(),
                    field_name: "mode".into(),
                },
                StructFieldLayout {
                    offset: 4,
                    size: 8,
                    type_name: "MY_UNION".into(),
                    field_name: "payload".into(),
                },
                StructFieldLayout {
                    offset: 12,
                    size: 4,
                    type_name: "SHARED".into(),
                    field_name: "twin".into(),
                },
                StructFieldLayout {
                    offset: 16,
                    size: 4,
                    type_name: "dword".into(),
                    field_name: "raw".into(),
                },
            ],
        },
    );
    program.layouts.insert(
        "SHARED".into(),
        StructLayout {
            name: "SHARED".into(),
            size: 4,
            alignment: 4,
            fields: Vec::new(),
        },
    );
    program.enums.insert(
        "MODES".into(),
        EnumDefinition {
            name: "MODES".into(),
            size: 4,
            members: vec![calxgloss_decomp::EnumMember {
                name: "MODE_ON".into(),
                value: 1,
            }],
        },
    );
    program
}

impl ScanSource for FakeProgram {
    async fn data_types(&self, category: Option<&str>) -> EngineResult<Vec<DataTypeEntry>> {
        self.enter();
        yield_now().await;
        self.exit();
        match category {
            None => Ok(self.listing.clone()),
            Some(word) if self.buckets.contains_key(word) => Ok(self.buckets[word].clone()),
            Some(word) => Ok(self
                .listing
                .iter()
                .filter(|e| e.category.contains(word))
                .cloned()
                .collect()),
        }
    }

    async fn struct_layout(&self, name: &str) -> EngineResult<StructLayout> {
        self.enter();
        yield_now().await;
        self.exit();
        self.layouts
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "structure",
                query: name.to_string(),
            })
    }

    async fn enum_values(&self, name: &str) -> EngineResult<EnumDefinition> {
        self.enter();
        yield_now().await;
        self.exit();
        self.enums
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "enumeration",
                query: name.to_string(),
            })
    }

    async fn data_items(&self) -> EngineResult<Vec<DataItem>> {
        self.enter();
        yield_now().await;
        self.exit();
        if self.fail_items {
            return Err(EngineError::Reported {
                message: "the engine is busy".into(),
            });
        }
        Ok(self.items.clone())
    }

    async fn functions(&self) -> EngineResult<Vec<FunctionSummary>> {
        self.enter();
        yield_now().await;
        self.exit();
        Ok(self.functions.clone())
    }

    async fn image_base(&self) -> EngineResult<u64> {
        self.enter();
        yield_now().await;
        self.exit();
        Ok(self.image_base)
    }

    async fn read_memory(&self, address: u64, _length: usize) -> EngineResult<Vec<u8>> {
        self.enter();
        yield_now().await;
        self.exit();
        self.memory
            .get(&address)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "memory",
                query: format!("{address:x}"),
            })
    }

    async fn strings(&self) -> EngineResult<Vec<StringLiteral>> {
        self.enter();
        yield_now().await;
        self.exit();
        Ok(self.literals.clone())
    }

    async fn xrefs_to(&self, address: u64) -> EngineResult<Vec<Xref>> {
        self.enter();
        yield_now().await;
        self.exit();
        Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
    }

    async fn decompile(&self, name: &str) -> EngineResult<DecompiledFunction> {
        Err(EngineError::NotFound {
            kind: "function",
            query: name.to_string(),
        })
    }

    async fn callers(&self, _address: u64) -> EngineResult<Vec<String>> {
        Ok(Vec::new())
    }

    async fn imports(&self) -> EngineResult<Vec<Symbol>> {
        Ok(Vec::new())
    }

    async fn exports(&self) -> EngineResult<Vec<Symbol>> {
        Ok(Vec::new())
    }
}

impl TagSink for FakeProgram {
    async fn add_function_tag(&self, address: u64, tag: &str) -> Result<()> {
        self.enter();
        yield_now().await;
        self.exit();
        self.stats
            .tags
            .lock()
            .unwrap()
            .push((address, tag.to_string()));
        Ok(())
    }
}

#[tokio::test]
async fn scan_collects_all_three_sections() {
    let program = program();
    let db = TypesDBEngine::with_source(program.clone())
        .scan("eqmain.dll")
        .await
        .expect("scan");

    assert_eq!(db.metadata.binary, "eqmain.dll");
    assert!(db.metadata.scanned_at > 0);

    // Named types in Type Manager path order, layouts resolved.
    assert_eq!(db.named_types.len(), 2);
    assert_eq!(db.named_types[0].name, "_EXCEPTION_DISPOSITION");
    assert_eq!(
        db.named_types[0].members[0].name,
        "ExceptionContinueExecution"
    );
    assert_eq!(db.named_types[1].name, "IMAGE_DOS_HEADER");
    assert_eq!(db.named_types[1].fields[0].name, "e_magic");

    // The RTTI-confirmed vtable with its class chain and named methods.
    assert_eq!(db.vtables.len(), 1);
    let vtable = &db.vtables[0];
    assert!(vtable.is_confirmed());
    assert_eq!(vtable.class_name.as_deref(), Some("Widget"));
    assert_eq!(vtable.base_classes, vec!["Base"]);
    assert_eq!(vtable.methods.len(), 2);
    assert_eq!(vtable.methods[0].name.as_deref(), Some("FUN_18003ab00"));

    // The literal cluster as a candidate above the default threshold.
    assert_eq!(db.inferred_structs.len(), 1);
    let candidate = &db.inferred_structs[0];
    assert_eq!(candidate.name, "Player");
    assert_eq!(candidate.fields.len(), 2);
    assert!(candidate.confidence >= 40);

    // The default configuration tags confirmed vtable methods.
    let tags = program.tagged();
    assert_eq!(tags.len(), 2);
    assert!(tags.iter().all(|(_, tag)| tag == "vtable-method"));
}

#[tokio::test]
async fn scan_runs_the_three_scans_concurrently() {
    // Every source call pends like an HTTP request, so a sequential
    // orchestration could never have two scans in flight at once.
    let program = program();
    TypesDBEngine::with_source(program.clone())
        .scan("eqmain.dll")
        .await
        .expect("scan");
    assert!(
        program.stats.max_in_flight.load(Ordering::SeqCst) >= 2,
        "the three scans should overlap, not run one after another"
    );
}

#[tokio::test]
async fn a_failing_scan_fails_the_whole_run() {
    // Each scanner degrades internally for missing data, so an error
    // here is a server failure: the whole scan aborts rather than
    // returning a database with a silently missing section.
    let mut program = program();
    program.fail_items = true;
    let result = TypesDBEngine::with_source(program).scan("eqmain.dll").await;
    assert!(matches!(
        result,
        Err(TypesDbError::Engine(EngineError::Reported { .. }))
    ));
}

#[tokio::test]
async fn an_empty_program_yields_an_empty_database() {
    let db = TypesDBEngine::with_source(FakeProgram::empty())
        .scan("nothing.dll")
        .await
        .expect("scan");
    assert!(db.is_empty());
    assert_eq!(db.metadata.binary, "nothing.dll");
    assert!(db.metadata.scanned_at > 0);
}

// -- admitted coverage (P19 admitted-semantics track, issue #348) -----

/// The data-level result of the roster pin: empty means the record
/// names every declared facet exactly once; each fault names one
/// drift.
fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
    coverage.roster_faults(DECLARED_FACETS)
}

/// Runs the TypesDBEngine's own scan over `program`: every coverage
/// stamp comes from this call, the one definition the batch scan
/// phase and the CLI's force-rescan both go through.
async fn scan(program: FakeProgram) -> TypeDatabase {
    TypesDBEngine::with_source(program)
        .scan("eqmain.dll")
        .await
        .expect("scan")
}

#[tokio::test]
async fn scan_stamps_coverage_naming_every_declared_facet_once() {
    let db = scan(program()).await;
    let coverage = db
        .metadata
        .coverage
        .expect("a fresh typesdb scan states its coverage");
    assert_eq!(
        coverage.status,
        CoverageStatus::Complete,
        "a fully examined target admits nothing"
    );
    assert!(
        roster_faults(&coverage).is_empty(),
        "a fresh document must name every declared facet exactly once"
    );
    let vtables = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "vtables")
        .expect("vtables is named");
    assert_eq!(vtables.status, CoverageStatus::Complete);
    assert_eq!(vtables.limitation, None, "complete coverage names no limit");
}

#[tokio::test]
async fn a_target_yielding_no_vtable_evidence_stamps_the_facet_unavailable_with_its_reason() {
    // The data objects the RTTI walk starts from are gone, so the walk
    // finds nothing to read, while the Type Manager listing and the
    // string clusters still produce their findings. Zero recorded
    // vtables beside a database that still names types reads as the
    // target having no RTTI, never as the program having no classes.
    let mut program = program();
    program.items.clear();
    let db = scan(program).await;
    assert!(
        db.vtables.is_empty(),
        "the target yields no vtable evidence"
    );
    assert_eq!(db.named_types.len(), 2, "the other scans read normally");
    assert_eq!(db.inferred_structs.len(), 1, "and so did this one");

    let coverage = db
        .metadata
        .coverage
        .expect("a fresh typesdb scan states its coverage");
    assert!(
        roster_faults(&coverage).is_empty(),
        "a scan that comes up empty still names every declared facet exactly once"
    );
    let vtables = coverage
        .facets
        .iter()
        .find(|facet| facet.id == "vtables")
        .expect("vtables is named");
    assert_eq!(vtables.status, CoverageStatus::Unavailable);
    assert_eq!(
        vtables.limitation.as_deref(),
        Some("no vtable evidence on this target"),
        "the facet that came up empty names its reason"
    );
    assert_eq!(
        coverage.status,
        CoverageStatus::Unavailable,
        "the single facet is the whole picture"
    );
    assert_eq!(
        coverage.admission().as_deref(),
        Some("unavailable — no vtable evidence on this target"),
        "what a reviewer reads is the shared type's own admission line"
    );
}

#[tokio::test]
async fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
    let mut coverage = coverage_stamp(1);
    coverage.facets.clear();
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `vtables` is missing from the record"],
        "an engine quietly skipping a declared facet fails loudly"
    );
}

#[tokio::test]
async fn the_roster_pin_fails_when_a_facet_is_doubled() {
    let mut coverage = coverage_stamp(1);
    coverage.facets.push(coverage.facets[0].clone());
    assert_eq!(
        roster_faults(&coverage),
        ["declared facet `vtables` appears 2 times in the record"],
        "a facet crowded into two entries fails loudly"
    );
}

#[tokio::test]
async fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
    let mut coverage = coverage_stamp(1);
    coverage.facets.push(FacetCoverage {
        id: "named-types".to_string(),
        status: CoverageStatus::Unexamined,
        limitation: None,
    });
    assert_eq!(
        roster_faults(&coverage),
        ["record names `named-types`, a facet the engine never declared"],
        "an id invented outside the declared roster fails loudly"
    );
}

#[tokio::test]
async fn configuration_reaches_every_scanner() {
    let program = program();
    let db = TypesDBEngine::with_source(program.clone())
        .with_category("pe")
        .with_min_confidence(70)
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    assert_eq!(
        db.named_types.len(),
        1,
        "the category filter reaches the scanner"
    );
    assert_eq!(db.named_types[0].name, "IMAGE_DOS_HEADER");
    assert!(
        db.inferred_structs.is_empty(),
        "the threshold reaches the inference engine"
    );
    assert!(program.tagged().is_empty(), "the detector stays read-only");
    assert_eq!(db.vtables.len(), 1, "detection itself still ran");
}

#[tokio::test]
async fn a_candidate_read_by_vtable_methods_links_and_takes_the_class_name() {
    let db = TypesDBEngine::with_source(program_read_by_vtable_methods())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    assert_eq!(db.inferred_structs.len(), 1);
    let candidate = &db.inferred_structs[0];
    assert_eq!(
        candidate.name, "Widget",
        "the RTTI class name replaces the literal prefix"
    );
    assert_eq!(candidate.name_origin, NameOrigin::VtableClass);
    assert!(candidate.is_linked());
    assert_eq!(candidate.linked_vtable, Some(0x1801_306f0));
    let vtable = db
        .find_vtable(0x1801_306f0)
        .expect("the link names a recovered vtable");
    assert_eq!(
        candidate.name,
        vtable
            .class_name
            .as_deref()
            .expect("the canned RTTI resolves a class name")
    );
    // The cluster scored 16+10+25+20 = 71 as a literal-prefix name; the
    // vtable class origin pays 10 more.
    assert_eq!(candidate.confidence.value(), 81);
}

#[tokio::test]
async fn a_candidate_outside_the_vtable_stays_unlinked() {
    // The stock program's candidate is read by `Player_update`, which is
    // not one of the table's methods: nothing links, nothing renames.
    let db = TypesDBEngine::with_source(program())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let candidate = &db.inferred_structs[0];
    assert_eq!(candidate.name, "Player");
    assert_eq!(candidate.name_origin, NameOrigin::LiteralPrefix);
    assert!(!candidate.is_linked());
}

#[tokio::test]
async fn a_struct_split_across_a_hub_merges_back_into_one_candidate() {
    let db = TypesDBEngine::with_source(program_split_by_a_hub())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let widget = db
        .inferred_structs
        .iter()
        .find(|candidate| candidate.name == "Widget")
        .expect("the widget candidate");
    assert_eq!(widget.merged_from, Some(2), "two halves became one");
    assert_eq!(
        widget
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>(),
        ["width", "height", "label", "visible"],
        "the field union keeps literal-address order"
    );
    assert_eq!(
        widget.referenced_by,
        [
            "FUN_18003ab00".to_string(),
            "FUN_18003e750".to_string(),
            "FUN_widget_access".to_string()
        ]
    );
    // The linked half's vtable link and class name survive the merge.
    assert_eq!(widget.linked_vtable, Some(0x1801_306f0));
    assert_eq!(widget.name_origin, NameOrigin::VtableClass);
    // Each half scored 76 linked; the merge pays its own breadth and
    // agreement terms for what it adds: 76 + 2 fields * 8 + 1 function * 5.
    assert_eq!(widget.confidence.value(), 97);

    // The unrelated candidate, whose readers share nothing with the
    // widget's, stays separate and unmerged.
    assert_eq!(db.inferred_structs.len(), 2);
    let player = db
        .inferred_structs
        .iter()
        .find(|candidate| candidate.name == "Player")
        .expect("the player candidate");
    assert_eq!(player.merged_from, None);
    assert_eq!(player.fields.len(), 2);
}

#[tokio::test]
async fn the_confidence_threshold_still_filters_with_the_merge_in_place() {
    // The hub-split halves each score 76; a threshold above that
    // filters them before they can merge, exactly as it did before
    // the merge pass existed.
    let db = TypesDBEngine::with_source(program_split_by_a_hub())
        .with_min_confidence(80)
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");
    assert!(
        db.inferred_structs.is_empty(),
        "halves below the threshold never reach the merge"
    );
}

fn confirmed_vtable(address: u64, class_name: Option<&str>, methods: &[&str]) -> Vtable {
    Vtable {
        address,
        label: "vftable".into(),
        size: 8 * methods.len() as u64,
        meta_ptr_address: Some(address - 8),
        methods: methods
            .iter()
            .enumerate()
            .map(|(slot, name)| VtableMethod {
                slot,
                address: 0,
                name: Some((*name).into()),
            })
            .collect(),
        class_name: class_name.map(str::to_string),
        base_classes: Vec::new(),
        is_com_interface: false,
        stl_kind: None,
    }
}

fn address_named_candidate(referenced_by: &[&str]) -> InferredStruct {
    InferredStruct {
        name: "strings_at_180129350".into(),
        name_origin: NameOrigin::Address,
        fields: Vec::new(),
        confidence: Confidence::new(30),
        referenced_by: referenced_by.iter().map(|f| (*f).to_string()).collect(),
        linked_vtable: None,
        merged_from: None,
    }
}

#[test]
fn linking_names_the_candidate_and_records_the_link() {
    let mut candidates = [address_named_candidate(&["FUN_18003ab00"])];
    let vtables = [confirmed_vtable(
        0x1801_306f0,
        Some("Widget"),
        &["FUN_18003ab00"],
    )];
    link_candidates_to_vtables(&mut candidates, &vtables);
    let candidate = &candidates[0];
    assert_eq!(candidate.name, "Widget");
    assert_eq!(candidate.name_origin, NameOrigin::VtableClass);
    assert_eq!(candidate.linked_vtable, Some(0x1801_306f0));
    // The address origin paid 0; the class name pays 35.
    assert_eq!(candidate.confidence.value(), 65);
}

#[test]
fn an_unconfirmed_or_unnamed_table_links_nothing() {
    let mut unconfirmed = confirmed_vtable(0x1801_306f0, Some("Widget"), &["FUN_18003ab00"]);
    unconfirmed.meta_ptr_address = None;
    let unnamed = confirmed_vtable(0x1801_30700, None, &["FUN_18003ab00"]);
    let mut candidates = [address_named_candidate(&["FUN_18003ab00"])];
    link_candidates_to_vtables(&mut candidates, &[unconfirmed, unnamed]);
    assert!(!candidates[0].is_linked());
    assert_eq!(candidates[0].name, "strings_at_180129350");
    assert_eq!(candidates[0].confidence.value(), 30);
}

#[test]
fn a_candidate_matching_several_tables_links_to_the_most_shared_methods() {
    let weak = confirmed_vtable(0x1801_306f0, Some("Weak"), &["FUN_18003ab00"]);
    let strong = confirmed_vtable(
        0x1801_30700,
        Some("Strong"),
        &["FUN_18003ab00", "FUN_18003e750"],
    );
    let mut candidates = [address_named_candidate(&["FUN_18003ab00", "FUN_18003e750"])];
    link_candidates_to_vtables(&mut candidates, &[weak, strong]);
    assert_eq!(candidates[0].name, "Strong");
    assert_eq!(candidates[0].linked_vtable, Some(0x1801_30700));
}

#[test]
fn a_tie_between_tables_goes_to_the_lowest_address() {
    let low = confirmed_vtable(0x1801_306f0, Some("Low"), &["FUN_18003ab00"]);
    let high = confirmed_vtable(0x1801_30700, Some("High"), &["FUN_18003ab00"]);
    let mut candidates = [address_named_candidate(&["FUN_18003ab00"])];
    link_candidates_to_vtables(&mut candidates, &[high, low]);
    assert_eq!(candidates[0].linked_vtable, Some(0x1801_306f0));
    assert_eq!(candidates[0].name, "Low");
}

/// A candidate for the merge tests: fields at `addresses`, read by
/// `referenced_by`.
fn merge_candidate(
    name: &str,
    origin: NameOrigin,
    confidence: u8,
    addresses: &[u64],
    referenced_by: &[&str],
) -> InferredStruct {
    InferredStruct {
        name: name.to_string(),
        name_origin: origin,
        fields: addresses
            .iter()
            .enumerate()
            .map(|(index, &address)| InferredField {
                name: format!("field_{index}"),
                field_type: FieldType::Integer,
                size: Some(4),
                offset: Some(index as u64 * 4),
                source_value: format!("{name}.field_{index}"),
                source_address: address,
                stl_kind: None,
            })
            .collect(),
        confidence: Confidence::new(confidence),
        referenced_by: referenced_by.iter().map(|f| (*f).to_string()).collect(),
        linked_vtable: None,
        merged_from: None,
    }
}

#[test]
fn candidates_sharing_a_referencing_function_merge_into_one() {
    let mut candidates = vec![
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x100, 0x108],
            &["FUN_a", "FUN_hub"],
        ),
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x110, 0x118],
            &["FUN_b", "FUN_hub"],
        ),
    ];
    assert_eq!(merge_candidates(&mut candidates), 1);
    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(candidate.merged_from, Some(2));
    assert_eq!(
        candidate.referenced_by,
        [
            "FUN_a".to_string(),
            "FUN_b".to_string(),
            "FUN_hub".to_string()
        ]
    );
    assert_eq!(
        candidate
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field.source_address, field.offset))
            .collect::<Vec<_>>(),
        [
            ("field_0", 0x100, Some(0)),
            ("field_1", 0x108, Some(4)),
            ("field_0", 0x110, Some(8)),
            ("field_1", 0x118, Some(12)),
        ],
        "the union keeps literal-address order and re-accumulates offsets"
    );
    // 66 plus the added breadth (2 fields * 8) and agreement (1 function * 5).
    assert_eq!(candidate.confidence.value(), 87);
}

#[test]
fn a_below_threshold_overlap_keeps_candidates_separate() {
    // One shared reader out of three is not enough: a lone overlap
    // says less the more readers each half has on its own.
    let mut candidates = vec![
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x100],
            &["FUN_a", "FUN_b", "FUN_c"],
        ),
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x108],
            &["FUN_a", "FUN_d", "FUN_e"],
        ),
    ];
    assert_eq!(merge_candidates(&mut candidates), 0);
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|c| c.merged_from.is_none()));
}

#[test]
fn an_overlap_at_the_threshold_merges() {
    // Two shared readers out of three clears the half.
    let mut candidates = vec![
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x100],
            &["FUN_a", "FUN_b", "FUN_c"],
        ),
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x108],
            &["FUN_a", "FUN_b", "FUN_d"],
        ),
    ];
    assert_eq!(merge_candidates(&mut candidates), 1);
    assert_eq!(candidates[0].merged_from, Some(2));
}

#[test]
fn candidates_that_share_no_readers_stay_separate() {
    let mut candidates = vec![
        merge_candidate(
            "Widget",
            NameOrigin::LiteralPrefix,
            66,
            &[0x100],
            &["FUN_a"],
        ),
        merge_candidate(
            "Player",
            NameOrigin::LiteralPrefix,
            66,
            &[0x108],
            &["FUN_b"],
        ),
        merge_candidate("Strings", NameOrigin::Address, 30, &[0x110], &[]),
    ];
    assert_eq!(merge_candidates(&mut candidates), 0);
    assert_eq!(candidates.len(), 3);
}

#[test]
fn the_strongest_half_names_the_merge_and_keeps_its_link() {
    let mut linked = merge_candidate(
        "Widget",
        NameOrigin::VtableClass,
        97,
        &[0x100, 0x108],
        &["FUN_m1", "FUN_hub"],
    );
    linked.linked_vtable = Some(0x1801_306f0);
    let address_named = merge_candidate(
        "strings_at_180129410",
        NameOrigin::Address,
        40,
        &[0x110],
        &["FUN_b", "FUN_hub"],
    );
    let mut candidates = vec![address_named, linked];
    merge_candidates(&mut candidates);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].name, "Widget");
    assert_eq!(candidates[0].name_origin, NameOrigin::VtableClass);
    assert_eq!(candidates[0].linked_vtable, Some(0x1801_306f0));
}

#[test]
fn when_both_halves_are_linked_the_earlier_address_keeps_its_link() {
    let mut early = merge_candidate(
        "Widget",
        NameOrigin::LiteralPrefix,
        66,
        &[0x100],
        &["FUN_a", "FUN_hub"],
    );
    early.linked_vtable = Some(0x1801_306f0);
    let mut late = merge_candidate(
        "Widget",
        NameOrigin::LiteralPrefix,
        66,
        &[0x200],
        &["FUN_b", "FUN_hub"],
    );
    late.linked_vtable = Some(0x1801_30700);
    let mut candidates = vec![late.clone(), early.clone()];
    merge_candidates(&mut candidates);
    assert_eq!(candidates[0].linked_vtable, Some(0x1801_306f0));
}

#[test]
fn the_merge_does_not_depend_on_input_order() {
    let first = merge_candidate(
        "Widget",
        NameOrigin::LiteralPrefix,
        66,
        &[0x100, 0x108],
        &["FUN_a", "FUN_hub"],
    );
    let second = merge_candidate(
        "Widget",
        NameOrigin::VtableClass,
        76,
        &[0x110],
        &["FUN_b", "FUN_hub"],
    );
    let mut forwards = vec![first.clone(), second.clone()];
    let mut backwards = vec![second.clone(), first.clone()];
    merge_candidates(&mut forwards);
    merge_candidates(&mut backwards);
    assert_eq!(forwards, backwards, "two scans merge in one order");
}

// ------------------------------------------------------------
// Linking nested struct fields to their recovered types
// ------------------------------------------------------------

/// A struct named `name` in `category` with one field per
/// `(field name, type name)` pair, links not yet filled in.
fn nesting_struct(name: &str, category: &str, fields: &[(&str, &str)]) -> NamedType {
    let mut named = NamedType::from_listing(&entry(name, category, None), TypeKind::Struct);
    named.fields = fields
        .iter()
        .map(|(field_name, type_name)| StructField {
            name: (*field_name).into(),
            offset: 0,
            size: 4,
            type_name: (*type_name).into(),
            linked_type: None,
            linked_kind: None,
        })
        .collect();
    named
}

#[test]
fn a_field_naming_one_recovered_type_links_to_its_path() {
    let mut types = vec![
        nesting_struct("WIDGET", "pe", &[("mode", "MODES")]),
        NamedType::from_listing(&entry("MODES", "excpt.h", Some(4)), TypeKind::Enum),
    ];
    let linked = link_nested_fields(&mut types);

    assert_eq!(linked, 1);
    let field = &types[0].fields[0];
    assert_eq!(field.linked_type.as_deref(), Some("/excpt.h/MODES"));
    assert_eq!(field.linked_kind, Some(TypeKind::Enum));
    assert!(field.is_nested());
}

#[test]
fn a_field_naming_several_recovered_types_stays_unlinked() {
    // Paths, not names, are the unique keys: a name two recovered
    // types share names no single type, so the field gets no link.
    let mut types = vec![
        nesting_struct("WIDGET", "pe", &[("twin", "SHARED")]),
        NamedType::from_listing(&entry("SHARED", "a", Some(4)), TypeKind::Struct),
        NamedType::from_listing(&entry("SHARED", "b", Some(4)), TypeKind::Struct),
    ];
    let linked = link_nested_fields(&mut types);

    assert_eq!(linked, 0);
    assert_eq!(types[0].fields[0].linked_type, None);
    assert_eq!(types[0].fields[0].linked_kind, None);
}

#[test]
fn a_field_naming_a_recovered_union_carries_the_union_kind() {
    let mut types = vec![
        nesting_struct("WIDGET", "pe", &[("payload", "MY_UNION")]),
        NamedType::from_listing(&entry("MY_UNION", "sys", Some(8)), TypeKind::Union),
    ];
    let linked = link_nested_fields(&mut types);

    assert_eq!(linked, 1);
    assert_eq!(types[0].fields[0].linked_kind, Some(TypeKind::Union));
}

#[test]
fn a_field_naming_nothing_recovered_stays_unlinked() {
    // Primitives and types the scan never recovered name nothing to
    // link; the field keeps its bare type name.
    let mut types = vec![nesting_struct(
        "IMAGE_DOS_HEADER",
        "pe",
        &[("e_magic", "char[2]"), ("e_lfanew", "dword")],
    )];
    let linked = link_nested_fields(&mut types);

    assert_eq!(linked, 0);
    assert!(types[0].fields.iter().all(|f| !f.is_nested()));
}

#[test]
fn a_field_naming_its_own_type_stays_unlinked() {
    // A field never nests its own type — a self-link would render a
    // cycle — even when the owner is the only recovered type of
    // that name.
    let mut types = vec![nesting_struct("WIDGET", "pe", &[("twin", "WIDGET")])];
    let linked = link_nested_fields(&mut types);

    assert_eq!(linked, 0);
    assert_eq!(types[0].fields[0].linked_type, None);
}

#[tokio::test]
async fn a_scan_links_fields_that_name_recovered_types() {
    let db = TypesDBEngine::with_source(program_with_nested_fields())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let widget = db
        .find_named_type("/pe/WIDGET")
        .expect("the canned widget struct");
    let field = |name: &str| {
        widget
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("the widget should carry a `{name}` field"))
    };

    assert_eq!(field("mode").linked_type.as_deref(), Some("/excpt.h/MODES"));
    assert_eq!(field("mode").linked_kind, Some(TypeKind::Enum));
    assert_eq!(
        field("payload").linked_type.as_deref(),
        Some("/sys/MY_UNION")
    );
    assert_eq!(
        field("payload").linked_kind,
        Some(TypeKind::Union),
        "a union-typed field carries the union kind"
    );
    assert_eq!(
        field("twin").linked_type,
        None,
        "an ambiguous name stays unlinked"
    );
    assert_eq!(
        field("raw").linked_type,
        None,
        "a primitive names nothing to link"
    );
}

// ------------------------------------------------------------
// Flagging STL/MFC shapes (issue #140)
// ------------------------------------------------------------

#[test]
fn the_flag_pass_marks_types_vtables_and_inferred_fields() {
    let mut types = vec![
        NamedType::from_listing(
            &entry("std::vector<CWidget>", "pe", Some(24)),
            TypeKind::Class,
        ),
        NamedType::from_listing(&entry("CWidget", "pe", Some(8)), TypeKind::Class),
    ];
    let mut vtables = vec![
        confirmed_vtable(0x1801_306f0, Some("std::basic_string<char>"), &["FUN_1"]),
        confirmed_vtable(0x1801_30700, Some("CWidget"), &["FUN_2"]),
        confirmed_vtable(0x1801_30710, None, &["FUN_3"]),
    ];
    let mut candidates = vec![InferredStruct {
        name: "strings_at_180129350".into(),
        name_origin: NameOrigin::Address,
        fields: vec![
            InferredField {
                name: "label".into(),
                field_type: FieldType::String,
                size: Some(8),
                offset: None,
                source_value: "Player".into(),
                source_address: 0x1801_29350,
                stl_kind: None,
            },
            InferredField {
                name: "count".into(),
                field_type: FieldType::Integer,
                size: Some(4),
                offset: None,
                source_value: "42".into(),
                source_address: 0x1801_29360,
                stl_kind: None,
            },
        ],
        confidence: Confidence::new(50),
        referenced_by: vec!["FUN_18000b620".into()],
        linked_vtable: None,
        merged_from: None,
    }];

    let flagged = flag_stl_types(&mut types, &mut vtables, &mut candidates);

    assert_eq!(flagged, 3, "one type, one vtable, one field");
    assert_eq!(types[0].stl_kind, Some(StlKind::Vector));
    assert_eq!(types[1].stl_kind, None, "a plain class stays unflagged");
    assert_eq!(vtables[0].stl_kind, Some(StlKind::String));
    assert_eq!(vtables[1].stl_kind, None);
    assert_eq!(
        vtables[2].stl_kind, None,
        "a table whose class name never resolved flags nothing"
    );
    assert_eq!(
        candidates[0].fields[0].stl_kind,
        Some(StlKind::String),
        "the suggested `char *` is a string shape"
    );
    assert_eq!(candidates[0].fields[1].stl_kind, None);
}

#[test]
fn flagging_leaves_records_in_place() {
    // Flag-only (issue #140): the pass marks records, it never removes
    // or reorders them.
    let mut types = vec![
        NamedType::from_listing(&entry("CWidget", "pe", Some(8)), TypeKind::Class),
        NamedType::from_listing(&entry("std::list<int>", "pe", Some(16)), TypeKind::Class),
    ];
    let before: Vec<String> = types.iter().map(|t| t.path.clone()).collect();
    let flagged = flag_stl_types(&mut types, &mut [], &mut []);

    assert_eq!(flagged, 1);
    assert_eq!(
        types.iter().map(|t| t.path.clone()).collect::<Vec<_>>(),
        before
    );
}

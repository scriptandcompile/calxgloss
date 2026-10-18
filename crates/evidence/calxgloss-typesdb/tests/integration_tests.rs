//! Integration tests for the calxgloss-typesdb crate.
//!
//! These tests exercise the multi-module workflows the unit tests cannot
//! cover on their own:
//!
//! - **Recovery to disk** — [`TypesDBEngine`] scans a canned program, the
//!   [`TypeDatabasePersistor`] files the result in the workspace layout, and
//!   loading it back yields the same database the scan returned.
//! - **Consumption** — the loaded database answers the lookups a translation
//!   pipeline makes (named type by path, vtable by address) and its records
//!   render into [`StructuredData`] for the prompts.
//! - **Cache behavior** — the `exists` check decides whether a scan runs, and
//!   a rescan replaces the cached document.
//!
//! The fake program implements the shared `ScanSource` seam and the vtable
//! scan's `TagSink`, so the whole flow runs without an external server;
//! `tests/live.rs` covers the real bridge.

use std::collections::HashMap;

use calxgloss_decomp::{
    DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
    StringLiteral, StructFieldLayout, StructLayout, Symbol, Xref,
};
use calxgloss_prompts::StructuredData;
use calxgloss_typesdb::engine::{ScanSource, TypesDBEngine};
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use calxgloss_typesdb::rust_decls::render_rust_decls;
use calxgloss_typesdb::stl::StlKind;
use calxgloss_typesdb::types::{NameOrigin, TypeDatabase, TypeKind};
use calxgloss_typesdb::vtable::TagSink;
use tempfile::TempDir;

// ------------------------------------------------------------
// The canned program
// ------------------------------------------------------------

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

/// A canned program implementing [`ScanSource`] and [`TagSink`]: one PE
/// struct and one enum in the Type Manager, one RTTI-confirmed vtable with
/// two methods, and a two-literal cluster that infers to a `Player`
/// candidate.
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
}

impl FakeProgram {
    fn program() -> Self {
        let mut program = Self {
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
        };

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
                fields: vec![
                    StructFieldLayout {
                        offset: 0,
                        size: 2,
                        type_name: "char[2]".into(),
                        field_name: "e_magic".into(),
                    },
                    StructFieldLayout {
                        offset: 60,
                        size: 4,
                        type_name: "dword".into(),
                        field_name: "e_lfanew".into(),
                    },
                ],
            },
        );
        program.enums.insert(
            "_EXCEPTION_DISPOSITION".into(),
            EnumDefinition {
                name: "_EXCEPTION_DISPOSITION".into(),
                size: 4,
                members: vec![
                    calxgloss_decomp::EnumMember {
                        name: "ExceptionContinueExecution".into(),
                        value: 0,
                    },
                    calxgloss_decomp::EnumMember {
                        name: "ExceptionContinueSearch".into(),
                        value: 1,
                    },
                ],
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
}

impl ScanSource for FakeProgram {
    async fn data_types(
        &self,
        category: Option<&str>,
    ) -> calxgloss_decomp::Result<Vec<DataTypeEntry>> {
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

    async fn struct_layout(&self, name: &str) -> calxgloss_decomp::Result<StructLayout> {
        self.layouts
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "structure",
                query: name.to_string(),
            })
    }

    async fn enum_values(&self, name: &str) -> calxgloss_decomp::Result<EnumDefinition> {
        self.enums
            .get(name)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "enumeration",
                query: name.to_string(),
            })
    }

    async fn data_items(&self) -> calxgloss_decomp::Result<Vec<DataItem>> {
        Ok(self.items.clone())
    }

    async fn functions(&self) -> calxgloss_decomp::Result<Vec<FunctionSummary>> {
        Ok(self.functions.clone())
    }

    async fn image_base(&self) -> calxgloss_decomp::Result<u64> {
        Ok(self.image_base)
    }

    async fn read_memory(&self, address: u64, _length: usize) -> calxgloss_decomp::Result<Vec<u8>> {
        self.memory
            .get(&address)
            .cloned()
            .ok_or_else(|| EngineError::NotFound {
                kind: "memory",
                query: format!("{address:x}"),
            })
    }

    async fn strings(&self) -> calxgloss_decomp::Result<Vec<StringLiteral>> {
        Ok(self.literals.clone())
    }

    async fn xrefs_to(&self, address: u64) -> calxgloss_decomp::Result<Vec<Xref>> {
        Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
    }

    async fn decompile(&self, name: &str) -> calxgloss_decomp::Result<DecompiledFunction> {
        Err(EngineError::NotFound {
            kind: "function",
            query: name.to_string(),
        })
    }

    async fn callers(&self, _address: u64) -> calxgloss_decomp::Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn imports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
        Ok(Vec::new())
    }

    async fn exports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
        Ok(Vec::new())
    }
}

impl TagSink for FakeProgram {
    async fn add_function_tag(&self, _address: u64, _tag: &str) -> calxgloss_typesdb::Result<()> {
        Ok(())
    }
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

/// Scan the canned program read-only, so no test depends on the tagging
/// write-back the default configuration performs.
async fn scanned(binary: &str) -> TypeDatabase {
    TypesDBEngine::with_source(FakeProgram::program())
        .without_tagging()
        .scan(binary)
        .await
        .expect("scan")
}

// ------------------------------------------------------------
// Recovery to disk
// ------------------------------------------------------------

#[tokio::test]
async fn scan_save_load_round_trips_the_whole_database() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());

    let db = scanned("eqmain.dll").await;
    persistor.save(&db).unwrap();
    let loaded = persistor.load("eqmain.dll").unwrap();

    assert_eq!(loaded, db);
    assert_eq!(loaded.metadata.binary, "eqmain.dll");
    assert!(loaded.metadata.scanned_at > 0);
    assert_eq!(loaded.named_types.len(), 2);
    assert_eq!(loaded.vtables.len(), 1);
    assert_eq!(loaded.inferred_structs.len(), 1);
}

#[tokio::test]
async fn the_persistor_files_the_database_under_re_analysis_typesdb() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());

    persistor.save(&scanned("eqmain.dll").await).unwrap();

    let expected = dir
        .path()
        .join("re")
        .join("analysis")
        .join("typesdb")
        .join("eqmain.dll.json");
    assert!(expected.is_file(), "the whole chain should exist");
    let text = std::fs::read_to_string(&expected).unwrap();
    assert!(text.contains("\"named_types\""));
    assert!(text.contains("\"vtables\""));
    assert!(text.contains("\"inferred_structs\""));
}

#[tokio::test]
async fn the_cache_check_decides_whether_a_scan_runs() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());

    assert!(
        !persistor.exists("eqmain.dll"),
        "a cold cache should ask for a scan"
    );
    persistor.save(&scanned("eqmain.dll").await).unwrap();
    assert!(
        persistor.exists("eqmain.dll"),
        "the saved scan is the cache"
    );

    // The consumer's read path: no engine, just the cached document.
    let cached = persistor.load("eqmain.dll").unwrap();
    assert!(!cached.is_empty());
    assert!(
        !persistor.exists("renderer.dll"),
        "other binaries stay uncached"
    );
}

#[tokio::test]
async fn a_rescan_replaces_the_cached_document() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&scanned("eqmain.dll").await).unwrap();

    let fresh = TypesDBEngine::with_source(FakeProgram::program())
        .without_tagging()
        .with_category("pe")
        .scan("eqmain.dll")
        .await
        .expect("filtered scan");
    persistor.save(&fresh).unwrap();

    let loaded = persistor.load("eqmain.dll").unwrap();
    assert_eq!(loaded, fresh);
    assert_eq!(loaded.named_types.len(), 1);
    assert_eq!(loaded.named_types[0].name, "IMAGE_DOS_HEADER");
}

// ------------------------------------------------------------
// Consumption: lookups and prompt rendering on the loaded document
// ------------------------------------------------------------

#[tokio::test]
async fn loaded_named_types_answer_path_lookups_with_their_layouts() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&scanned("eqmain.dll").await).unwrap();
    let db = persistor.load("eqmain.dll").unwrap();

    let dos = db
        .find_named_type("/pe/IMAGE_DOS_HEADER")
        .expect("the struct should be findable by path");
    assert_eq!(dos.kind, TypeKind::Struct);
    assert_eq!(dos.size, Some(128));
    assert_eq!(dos.fields[1].name, "e_lfanew");
    assert_eq!(dos.fields[1].offset, 60);

    let disposition = db
        .find_named_type("/excpt.h/_EXCEPTION_DISPOSITION")
        .expect("the enum should be findable by path");
    assert_eq!(disposition.kind, TypeKind::Enum);
    assert_eq!(disposition.members[1].name, "ExceptionContinueSearch");
    assert_eq!(disposition.members[1].value, 1);
}

#[tokio::test]
async fn loaded_vtables_answer_address_lookups_with_methods_and_rtti() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&scanned("eqmain.dll").await).unwrap();
    let db = persistor.load("eqmain.dll").unwrap();

    let vtable = db
        .find_vtable(0x1801_306f0)
        .expect("the table should be findable by address");
    assert!(vtable.is_confirmed());
    assert_eq!(vtable.class_name.as_deref(), Some("Widget"));
    assert_eq!(vtable.base_classes, vec!["Base"]);
    assert_eq!(vtable.methods.len(), 2);
    assert_eq!(vtable.methods[0].slot, 0);
    assert_eq!(vtable.methods[0].name.as_deref(), Some("FUN_18003ab00"));
    assert_eq!(vtable.methods[1].address, 0x1800_3e750);
}

#[tokio::test]
async fn loaded_inferred_candidates_keep_their_fields_and_evidence() {
    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&scanned("eqmain.dll").await).unwrap();
    let db = persistor.load("eqmain.dll").unwrap();

    let candidate = &db.inferred_structs[0];
    assert_eq!(candidate.name, "Player");
    assert!(candidate.is_named());
    assert_eq!(candidate.fields.len(), 2);
    assert!(candidate.confidence >= 40, "the default threshold applies");
    assert!(
        candidate.referenced_by.iter().any(|f| f == "Player_update"),
        "the cluster should still name its referencing function"
    );
}

#[tokio::test]
async fn a_candidate_read_by_vtable_methods_links_names_and_persists() {
    // The same canned program, but the literals are read by the confirmed
    // vtable's two methods: the candidate should link to the table, take
    // its RTTI class name, and keep both through the JSON file.
    let mut program = FakeProgram::program();
    program.xrefs.insert(
        0x1801_29350,
        vec![reference("FUN_18003ab00"), reference("FUN_18003e750")],
    );
    program
        .xrefs
        .insert(0x1801_29360, vec![reference("FUN_18003ab00")]);
    let db = TypesDBEngine::with_source(program)
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let candidate = &db.inferred_structs[0];
    assert_eq!(candidate.name, "Widget");
    assert_eq!(candidate.name_origin, NameOrigin::VtableClass);
    assert!(candidate.is_linked());
    assert_eq!(candidate.linked_vtable, Some(0x1801_306f0));

    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&db).expect("scan should be savable");
    let text = std::fs::read_to_string(persistor.path_for("eqmain.dll"))
        .expect("the saved document should be readable");
    assert!(
        text.contains("\"linked_vtable\""),
        "the link should be in the document: {text}"
    );

    let loaded = persistor
        .load("eqmain.dll")
        .expect("the linked document should load back");
    assert_eq!(loaded, db);
    let loaded = &loaded.inferred_structs[0];
    assert_eq!(loaded.name, "Widget");
    assert_eq!(loaded.name_origin, NameOrigin::VtableClass);
    assert_eq!(loaded.linked_vtable, Some(0x1801_306f0));

    // The prompt conversion carries the class name, not the address or the
    // literal prefix.
    let rendered = StructuredData::from(loaded);
    assert_eq!(rendered.name, "Widget");
}

#[tokio::test]
async fn a_loaded_named_struct_renders_into_prompt_data() {
    let db = scanned("eqmain.dll").await;
    let dos = db.find_named_type("/pe/IMAGE_DOS_HEADER").unwrap();

    let rendered = StructuredData::from(dos);
    assert_eq!(rendered.name, "IMAGE_DOS_HEADER");
    assert_eq!(rendered.size, 128);
    assert_eq!(rendered.fields.len(), 2);
    assert_eq!(rendered.fields[0].name, "e_magic");
    assert_eq!(rendered.fields[0].type_, "char[2]");
    assert_eq!(rendered.fields[1].offset, 60);
}

#[tokio::test]
async fn a_loaded_enum_renders_members_as_value_typed_fields() {
    let db = scanned("eqmain.dll").await;
    let disposition = db
        .find_named_type("/excpt.h/_EXCEPTION_DISPOSITION")
        .unwrap();

    let rendered = StructuredData::from(disposition);
    assert_eq!(rendered.name, "_EXCEPTION_DISPOSITION");
    assert_eq!(rendered.size, 4);
    assert_eq!(rendered.fields.len(), 2);
    assert_eq!(rendered.fields[0].name, "ExceptionContinueExecution");
    assert_eq!(
        rendered.fields[1].type_, "1",
        "the member value is its type"
    );
    assert_eq!(rendered.fields[1].offset, -1, "members carry no offset");
}

#[tokio::test]
async fn a_loaded_inferred_candidate_renders_into_prompt_data() {
    let db = scanned("eqmain.dll").await;
    let candidate = &db.inferred_structs[0];

    let rendered = StructuredData::from(candidate);
    assert_eq!(rendered.name, "Player");
    assert_eq!(rendered.fields.len(), 2);
    assert_eq!(rendered.fields[0].name, "x");
    assert_eq!(rendered.fields[0].type_, "int");
    assert_eq!(rendered.fields[0].offset, 0);
    assert_eq!(rendered.fields[1].name, "y");
    assert_eq!(rendered.size, 8, "both integer fields carry a size");
}

// ------------------------------------------------------------
// Merging candidates whose cross-reference evidence overlaps
// ------------------------------------------------------------

/// The canned program, but the `Widget` fields are read across the two
/// vtable methods plus a hub function: the hub points at 25 literals, so
/// clustering splits the struct into two half-candidates that the merge
/// pass has to stitch back together.
fn program_split_by_a_hub() -> FakeProgram {
    let mut program = FakeProgram::program();
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
    // 21 more literals read only by the hub: its fan-out reaches 25, past
    // the hub threshold, so it clusters none of them.
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

#[tokio::test]
async fn a_struct_split_across_a_hub_merges_back_into_one_candidate() {
    let db = TypesDBEngine::with_source(program_split_by_a_hub())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let widgets: Vec<_> = db
        .inferred_structs
        .iter()
        .filter(|c| c.name == "Widget")
        .collect();
    assert_eq!(widgets.len(), 1, "the hub-split halves merge into one");
    let widget = &widgets[0];
    assert_eq!(widget.merged_from, Some(2));
    assert_eq!(widget.linked_vtable, Some(0x1801_306f0));
    assert_eq!(widget.name_origin, NameOrigin::VtableClass);
    assert_eq!(
        widget
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["width", "height", "label", "visible"],
        "the field union keeps its stable order"
    );
    assert!(
        db.inferred_structs.iter().any(|c| c.name == "Player"),
        "the unrelated Player candidate stays separate"
    );
}

#[tokio::test]
async fn a_merge_survives_the_save_load_round_trip() {
    let db = TypesDBEngine::with_source(program_split_by_a_hub())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&db).expect("scan should be savable");
    let text = std::fs::read_to_string(persistor.path_for("eqmain.dll"))
        .expect("the saved document should be readable");
    assert!(
        text.contains("\"merged_from\""),
        "the merge marker should be in the document: {text}"
    );

    let loaded = persistor
        .load("eqmain.dll")
        .expect("the merged document should load back");
    assert_eq!(loaded, db);
    let merged = loaded
        .inferred_structs
        .iter()
        .find(|c| c.name == "Widget")
        .expect("the merged candidate");
    assert_eq!(merged.merged_from, Some(2), "the merge marker survives");
    assert_eq!(merged.linked_vtable, Some(0x1801_306f0));
    assert_eq!(
        merged
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["width", "height", "label", "visible"],
        "the field union survives"
    );
}

#[tokio::test]
async fn two_scans_of_the_same_program_produce_byte_identical_databases() {
    // Determinism: the merge pass walks candidates in literal-address
    // order, so the same program scanned twice yields the same bytes.
    let first = TypesDBEngine::with_source(program_split_by_a_hub())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("first scan");
    let second = TypesDBEngine::with_source(program_split_by_a_hub())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("second scan");

    // Metadata carries the scan timestamp; the knowledge itself must match.
    let first_bytes =
        serde_json::to_vec(&(&first.named_types, &first.vtables, &first.inferred_structs))
            .expect("serialize first");
    let second_bytes = serde_json::to_vec(&(
        &second.named_types,
        &second.vtables,
        &second.inferred_structs,
    ))
    .expect("serialize second");
    assert_eq!(
        first_bytes, second_bytes,
        "two scans of the same program are byte-identical"
    );
}

// ------------------------------------------------------------
// Linking fields to the recovered types they name
// ------------------------------------------------------------

/// The same program, plus a `WIDGET` struct whose fields name other
/// recovered types: `MODES` (one enum), `MY_UNION` (one union), and
/// `SHARED` (two types share the name), so the flow has a unique link,
/// a union link, and an ambiguous name to work through.
fn program_with_nested_fields() -> FakeProgram {
    let mut program = FakeProgram::program();
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

#[tokio::test]
async fn a_scan_links_nested_fields_to_the_types_they_name() {
    let db = TypesDBEngine::with_source(program_with_nested_fields())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let widget = db
        .named_types
        .iter()
        .find(|t| t.name == "WIDGET")
        .expect("WIDGET recovered");
    let field = |name: &str| {
        widget
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("WIDGET should carry a `{name}` field: {:?}", widget.fields))
    };

    let mode = field("mode");
    assert_eq!(
        mode.linked_type.as_deref(),
        Some("/excpt.h/MODES"),
        "a field naming one recovered type links to its path"
    );
    assert_eq!(mode.linked_kind, Some(TypeKind::Enum));

    let payload = field("payload");
    assert_eq!(
        payload.linked_type.as_deref(),
        Some("/sys/MY_UNION"),
        "a field naming a recovered union links to it"
    );
    assert_eq!(
        payload.linked_kind,
        Some(TypeKind::Union),
        "and carries the union kind instead of being misread as a struct"
    );

    assert_eq!(
        field("twin").linked_type,
        None,
        "a name several recovered types share stays unlinked"
    );
    assert_eq!(
        field("raw").linked_type,
        None,
        "a primitive names nothing recovered"
    );
}

#[tokio::test]
async fn nested_links_survive_the_save_load_round_trip() {
    let db = TypesDBEngine::with_source(program_with_nested_fields())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let dir = TempDir::new().unwrap();
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&db).expect("scan should be savable");
    let text = std::fs::read_to_string(persistor.path_for("eqmain.dll"))
        .expect("the saved document should be readable");
    assert!(
        text.contains("\"linked_type\""),
        "the nesting links should be in the document: {text}"
    );

    let loaded = persistor
        .load("eqmain.dll")
        .expect("the nested document should load back");
    assert_eq!(loaded, db);
    let widget = loaded
        .named_types
        .iter()
        .find(|t| t.name == "WIDGET")
        .expect("the WIDGET type");
    let mode = widget
        .fields
        .iter()
        .find(|f| f.name == "mode")
        .expect("the mode field");
    assert_eq!(
        mode.linked_type.as_deref(),
        Some("/excpt.h/MODES"),
        "the link survives the file"
    );
    assert_eq!(mode.linked_kind, Some(TypeKind::Enum), "the kind survives");
}

#[tokio::test]
async fn a_nested_field_renders_its_kind_in_the_prompt() {
    let db = TypesDBEngine::with_source(program_with_nested_fields())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let widget = db
        .named_types
        .iter()
        .find(|t| t.name == "WIDGET")
        .expect("WIDGET recovered");

    let rendered = StructuredData::from(widget);
    let types: Vec<&str> = rendered.fields.iter().map(|f| f.type_.as_str()).collect();
    assert!(
        types.contains(&"enum MODES"),
        "the enum link shows in the field list: {types:?}"
    );
    assert!(
        types.contains(&"union MY_UNION"),
        "the union link shows in the field list: {types:?}"
    );
    assert!(
        types.contains(&"dword"),
        "unlinked fields stay verbatim: {types:?}"
    );
}

// ------------------------------------------------------------
// Flagging STL/MFC shapes (issue #140)
// ------------------------------------------------------------

/// The same program, plus the shapes STL flagging targets: Type Manager
/// entries named like each standard-library family, two more vtables whose
/// RTTI TypeDescriptors name `basic_string` and `vector`, and a literal
/// whose inferred field suggests `char *`. The `Widget` vtable and the
/// integer fields stay unflagged as controls.
fn program_with_stl_shapes() -> FakeProgram {
    let mut program = FakeProgram::program();
    program.listing.extend(vec![
        entry("vector<CWidget>", "pe", Some(24)),
        entry("basic_string", "pe", Some(24)),
        entry("list<CWidget>", "pe", Some(24)),
        entry("map<int,CWidget>", "pe", Some(24)),
        entry("shared_ptr<CWidget>", "pe", Some(16)),
    ]);
    program.buckets.insert(
        "struct",
        vec![
            entry("IMAGE_DOS_HEADER", "pe", Some(128)),
            entry("vector<CWidget>", "pe", Some(24)),
            entry("basic_string", "pe", Some(24)),
            entry("list<CWidget>", "pe", Some(24)),
            entry("map<int,CWidget>", "pe", Some(24)),
            entry("shared_ptr<CWidget>", "pe", Some(16)),
        ],
    );
    for name in [
        "vector<CWidget>",
        "basic_string",
        "list<CWidget>",
        "map<int,CWidget>",
        "shared_ptr<CWidget>",
    ] {
        program.layouts.insert(
            name.into(),
            StructLayout {
                name: name.into(),
                size: 24,
                alignment: 8,
                fields: Vec::new(),
            },
        );
    }

    // vftable @ 1801316f0 preceded by its vftable_meta_ptr, whose COL
    // TypeDescriptor names basic_string<char> the way MSVC RTTI spells it.
    program.items.extend(vec![
        item("vftable_meta_ptr", 0x1801_316e8, "pointer", 8),
        item("vftable", 0x1801_316f0, "pointer[1]", 8),
    ]);
    program.memory.insert(0x1801_316f0, le64(0x1800_3ab00));
    program.memory.insert(0x1801_316e8, le64(0x1801_31700));
    program.memory.insert(
        0x1801_31700,
        [le32(1), le32(0), le32(0), le32(0x13_1800), le32(0x13_1900)].concat(),
    );
    program.memory.insert(
        0x1801_31800,
        type_descriptor(".?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@"),
    );
    program
        .memory
        .insert(0x1801_31900, [le32(0), le32(0), le32(0)].concat());

    // A second RTTI-confirmed table naming std::vector<CWidget>.
    program.items.extend(vec![
        item("vftable_meta_ptr", 0x1801_326e8, "pointer", 8),
        item("vftable", 0x1801_326f0, "pointer[1]", 8),
    ]);
    program.memory.insert(0x1801_326f0, le64(0x1800_3e750));
    program.memory.insert(0x1801_326e8, le64(0x1801_32700));
    program.memory.insert(
        0x1801_32700,
        [le32(1), le32(0), le32(0), le32(0x13_2800), le32(0x13_2900)].concat(),
    );
    program
        .memory
        .insert(0x1801_32800, type_descriptor(".?AV?$vector@VWidget@@std@@"));
    program
        .memory
        .insert(0x1801_32900, [le32(0), le32(0), le32(0)].concat());

    // A literal whose inferred field suggests `char *` — a string shape.
    program.literals.push(StringLiteral {
        address: 0x1801_29370,
        value: "player.name=hello".into(),
    });
    program
        .xrefs
        .insert(0x1801_29370, vec![reference("Player_update")]);
    program
}

#[tokio::test]
async fn a_scan_flags_stl_shapes_on_types_vtables_and_fields() {
    let db = TypesDBEngine::with_source(program_with_stl_shapes())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let vector = db
        .find_named_type("/pe/vector<CWidget>")
        .expect("the container type");
    assert_eq!(
        vector.stl_kind,
        Some(StlKind::Vector),
        "a container-named type carries its family"
    );
    let string_type = db
        .find_named_type("/pe/basic_string")
        .expect("the string type");
    assert_eq!(string_type.stl_kind, Some(StlKind::String));
    assert!(vector.is_stl() && string_type.is_stl());

    let dos = db
        .find_named_type("/pe/IMAGE_DOS_HEADER")
        .expect("the program type");
    assert_eq!(
        dos.stl_kind, None,
        "a program type keeps no flag: {:?}",
        dos.name
    );

    let string_vtable = db.find_vtable(0x1801_316f0).expect("the string table");
    assert_eq!(
        string_vtable.stl_kind,
        Some(StlKind::String),
        "the RTTI-demangled class name carries the shape"
    );
    let widget = db.find_vtable(0x1801_306f0).expect("the widget table");
    assert_eq!(widget.stl_kind, None, "Widget is not an STL shape");

    let player = db
        .inferred_structs
        .iter()
        .find(|c| c.name == "Player")
        .expect("the Player candidate");
    let field = |name: &str| {
        player
            .fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("Player should carry a `{name}` field"))
    };
    assert_eq!(
        field("name").stl_kind,
        Some(StlKind::String),
        "the suggested `char *` is a string shape"
    );
    assert_eq!(field("x").stl_kind, None, "an int field stays unflagged");
}

#[tokio::test]
async fn flagged_records_still_answer_every_lookup() {
    // Flag-only (issue #140): the flag marks records, it never removes
    // them from a section or a lookup.
    let db = TypesDBEngine::with_source(program_with_stl_shapes())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    assert!(db.find_named_type("/pe/basic_string").is_some());
    assert!(db.find_named_type("/pe/vector<CWidget>").is_some());
    let string_vtable = db
        .find_vtable(0x1801_316f0)
        .expect("a flagged table stays findable");
    assert!(
        string_vtable.is_confirmed(),
        "and keeps its RTTI confirmation"
    );
    let vector_vtable = db
        .find_vtable(0x1801_326f0)
        .expect("the vector table stays findable");
    assert_eq!(vector_vtable.stl_kind, Some(StlKind::Vector));
    assert_eq!(db.named_types.len(), 7, "no named type was dropped");
    assert_eq!(db.vtables.len(), 3, "no vtable was dropped");
}

#[tokio::test]
async fn stl_flags_survive_the_save_load_round_trip() {
    let db = TypesDBEngine::with_source(program_with_stl_shapes())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let dir = TempDir::new().expect("temp dir should exist");
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&db).expect("scan should be savable");
    let text = std::fs::read_to_string(persistor.path_for("eqmain.dll"))
        .expect("the saved document should be readable");
    assert!(
        text.contains("\"stl_kind\""),
        "the flags should be in the document: {text}"
    );

    let loaded = persistor
        .load("eqmain.dll")
        .expect("the flagged document should load back");
    assert_eq!(loaded, db);
    assert_eq!(
        loaded
            .find_vtable(0x1801_316f0)
            .expect("the string table")
            .stl_kind,
        Some(StlKind::String),
        "the flag survives the file"
    );
}

#[tokio::test]
async fn a_flagged_record_names_its_stl_family_in_the_prompt() {
    let db = TypesDBEngine::with_source(program_with_stl_shapes())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let string_type = db
        .find_named_type("/pe/basic_string")
        .expect("the string type");
    let rendered = StructuredData::from(string_type);
    assert_eq!(
        rendered.name, "basic_string (STL string)",
        "the family rides in the type description"
    );

    let dos = db
        .find_named_type("/pe/IMAGE_DOS_HEADER")
        .expect("the program type");
    assert_eq!(
        StructuredData::from(dos).name,
        "IMAGE_DOS_HEADER",
        "unflagged types render verbatim"
    );

    let player = db
        .inferred_structs
        .iter()
        .find(|c| c.name == "Player")
        .expect("the Player candidate");
    let rendered = StructuredData::from(player);
    let types: Vec<&str> = rendered.fields.iter().map(|f| f.type_.as_str()).collect();
    assert!(
        types.contains(&"char * (STL string)"),
        "the flagged field's type names its family: {types:?}"
    );
    assert!(types.contains(&"int"), "unflagged fields stay verbatim");
}

// ------------------------------------------------------------
// Rendering Rust declarations from the recovered database (issue #141)
// ------------------------------------------------------------

#[tokio::test]
async fn a_round_tripped_database_renders_rust_declarations() {
    // The full flow the ticket promises: scan → save → load → render.
    let dir = TempDir::new().expect("temp dir should exist");
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&scanned("eqmain.dll").await).unwrap();
    let db = persistor
        .load("eqmain.dll")
        .expect("the document should load back");

    let rendered = render_rust_decls(&db);

    assert!(
        rendered.contains("// Rust declarations recovered from eqmain.dll"),
        "the file names its source: {rendered}"
    );
    assert!(
        rendered.contains("#[repr(C)]\npub struct IMAGE_DOS_HEADER {"),
        "{rendered}"
    );
    assert!(rendered.contains("pub e_magic: [i8; 2],"), "{rendered}");
    assert!(
        rendered.contains("_pad_2: [u8; 58],"),
        "the recovered offset gap becomes explicit padding: {rendered}"
    );
    assert!(rendered.contains("pub e_lfanew: u32,"), "{rendered}");
    assert!(
        rendered.contains("#[repr(i64)]\npub enum _EXCEPTION_DISPOSITION {"),
        "{rendered}"
    );
    assert!(
        rendered.contains("ExceptionContinueSearch = 1,"),
        "{rendered}"
    );
    assert!(
        rendered.contains("#[repr(C)]\npub struct Player {"),
        "the inferred candidate is declared too: {rendered}"
    );
    assert!(rendered.contains("pub x: i32,"), "{rendered}");
}

#[tokio::test]
async fn two_renders_of_the_round_tripped_database_are_byte_identical() {
    let dir = TempDir::new().expect("temp dir should exist");
    let persistor = TypeDatabasePersistor::new(dir.path());
    persistor.save(&scanned("eqmain.dll").await).unwrap();
    let db = persistor
        .load("eqmain.dll")
        .expect("the document should load back");

    assert_eq!(render_rust_decls(&db), render_rust_decls(&db));
}

#[tokio::test]
async fn two_separate_scans_render_byte_identical_declarations() {
    // The promise a reviewer leans on: rescanning the program and
    // re-rendering changes only what the scan actually learned, never
    // the renderer's own ordering or formatting.
    let first = scanned("eqmain.dll").await;
    let second = scanned("eqmain.dll").await;

    assert_eq!(render_rust_decls(&first), render_rust_decls(&second));
}

#[tokio::test]
async fn nested_links_and_stl_flags_shape_the_rendered_declarations() {
    // The nesting links (#139) and STL flags (#140) the renderer reads:
    // a linked field names the inner type, an STL type is a comment, and
    // the layout-less union is skipped.
    let db = TypesDBEngine::with_source(program_with_nested_fields())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");

    let rendered = render_rust_decls(&db);

    assert!(rendered.contains("pub mode: MODES,"), "{rendered}");
    assert!(
        !rendered.contains("MY_UNION {"),
        "the layout-less union gets no declaration of its own: {rendered}"
    );
    assert!(
        rendered.contains("pub twin: SHARED,"),
        "the ambiguous name stays a plain type reference: {rendered}"
    );

    let flagged = TypesDBEngine::with_source(program_with_stl_shapes())
        .without_tagging()
        .scan("eqmain.dll")
        .await
        .expect("scan");
    let rendered = render_rust_decls(&flagged);
    assert!(
        rendered.contains("// basic_string — STL string: maps to Rust String; no layout emitted."),
        "{rendered}"
    );
    assert!(
        !rendered.contains("struct vector"),
        "no hand-rolled container layouts: {rendered}"
    );
}

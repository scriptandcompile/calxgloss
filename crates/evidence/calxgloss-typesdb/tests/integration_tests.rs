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
//! The fake program implements the three source traits, so the whole flow
//! runs without a Ghidra server; `tests/live.rs` covers the real bridge.

use std::collections::HashMap;

use calxgloss_ghidra::{
    DataItem, DataTypeEntry, EnumDefinition, FunctionSummary, GhidraError, StringLiteral,
    StructFieldLayout, StructLayout, Xref,
};
use calxgloss_prompts::StructuredData;
use calxgloss_typesdb::engine::TypesDBEngine;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use calxgloss_typesdb::scanner::TypeLibrarySource;
use calxgloss_typesdb::string_infer::StringSource;
use calxgloss_typesdb::types::{TypeDatabase, TypeKind};
use calxgloss_typesdb::vtable::VtableSource;
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

/// A canned program implementing all three source traits: one PE struct and
/// one enum in the Type Manager, one RTTI-confirmed vtable with two methods,
/// and a two-literal cluster that infers to a `Player` candidate.
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
                    calxgloss_ghidra::EnumMember {
                        name: "ExceptionContinueExecution".into(),
                        value: 0,
                    },
                    calxgloss_ghidra::EnumMember {
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

impl TypeLibrarySource for FakeProgram {
    async fn list_types(
        &self,
        category: Option<&str>,
    ) -> calxgloss_typesdb::Result<Vec<DataTypeEntry>> {
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

    async fn struct_layout(&self, name: &str) -> calxgloss_typesdb::Result<StructLayout> {
        self.layouts.get(name).cloned().ok_or_else(|| {
            GhidraError::NotFound {
                kind: "structure",
                query: name.to_string(),
            }
            .into()
        })
    }

    async fn enum_values(&self, name: &str) -> calxgloss_typesdb::Result<EnumDefinition> {
        self.enums.get(name).cloned().ok_or_else(|| {
            GhidraError::NotFound {
                kind: "enumeration",
                query: name.to_string(),
            }
            .into()
        })
    }
}

impl VtableSource for FakeProgram {
    async fn data_items(&self) -> calxgloss_typesdb::Result<Vec<DataItem>> {
        Ok(self.items.clone())
    }

    async fn functions(&self) -> calxgloss_typesdb::Result<Vec<FunctionSummary>> {
        Ok(self.functions.clone())
    }

    async fn image_base(&self) -> calxgloss_typesdb::Result<u64> {
        Ok(self.image_base)
    }

    async fn read_memory(
        &self,
        address: u64,
        _length: usize,
    ) -> calxgloss_typesdb::Result<Vec<u8>> {
        self.memory.get(&address).cloned().ok_or_else(|| {
            GhidraError::NotFound {
                kind: "memory",
                query: format!("{address:x}"),
            }
            .into()
        })
    }

    async fn add_function_tag(&self, _address: u64, _tag: &str) -> calxgloss_typesdb::Result<()> {
        Ok(())
    }
}

impl StringSource for FakeProgram {
    async fn strings(
        &self,
        _filter: Option<&str>,
    ) -> calxgloss_typesdb::Result<Vec<StringLiteral>> {
        Ok(self.literals.clone())
    }

    async fn xrefs_to(&self, address: u64) -> calxgloss_typesdb::Result<Vec<Xref>> {
        Ok(self.xrefs.get(&address).cloned().unwrap_or_default())
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

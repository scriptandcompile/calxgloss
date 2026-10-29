//! JSON persistence for the recovered type database.
//!
//! The [`TypeDatabasePersistor`] saves and loads the per-binary
//! [`TypeDatabase`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/typesdb/
//!     └── {binary}.json
//! ```
//!
//! A saved database also acts as a cache. [`exists`](TypeDatabasePersistor::exists) is the
//! check a caller makes before deciding whether to run the scan again.
//! [`load`](TypeDatabasePersistor::load) reads the whole document back — the metadata and
//! all three recovered sections — for the translation pipeline to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{Result, TypesDbError};
use crate::types::TypeDatabase;

/// Saves and loads the per-binary type database as JSON.
///
/// # File Layout
///
/// Each database is saved under a cache directory, in a file named after
/// the binary the scan read:
///
/// ```text
/// cache_dir/
///     └── {binary}.json
/// ```
///
/// The default cache directory is `{workspace}/re/analysis/typesdb/`,
/// set by [`new`](Self::new). [`with_cache_dir`](Self::with_cache_dir)
/// instead points the persistor at an explicit directory.
///
/// # Example
///
/// ```no_run
/// use calxgloss_typesdb::persist::TypeDatabasePersistor;
/// use calxgloss_typesdb::types::{ScanMetadata, TypeDatabase};
///
/// # fn main() -> calxgloss_typesdb::Result<()> {
/// let persistor = TypeDatabasePersistor::new("/path/to/workspace");
/// let db = TypeDatabase::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&db)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct TypeDatabasePersistor {
    store: JsonStore<TypeDatabase>,
}

impl TypeDatabasePersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Databases are stored in `<workspace>/re/analysis/typesdb/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("typesdb")),
        }
    }

    /// Creates a new persistor with an explicit cache directory.
    ///
    /// Databases are stored directly under the provided `cache_dir` path.
    pub fn with_cache_dir(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(cache_dir),
        }
    }

    /// Returns the path where the database for `binary` is saved.
    pub fn path_for(&self, binary: &str) -> PathBuf {
        self.store.path_for(binary)
    }

    /// Whether a saved database exists for `binary`.
    ///
    /// This is the cache check. A caller that wants recovered types without
    /// re-running the scan asks here first, and only runs
    /// [`TypesDBEngine`](crate::engine::TypesDBEngine) when the answer is
    /// `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a type database to JSON, keyed on the binary name in its
    /// metadata.
    ///
    /// It creates the cache directory tree if needed, serializes the
    /// database, and writes it to disk. A rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, db: &TypeDatabase) -> Result<()> {
        let path = self.path_for(&db.metadata.binary);
        info!(
            path = %path.display(),
            named_types = db.named_types.len(),
            vtables = db.vtables.len(),
            inferred_structs = db.inferred_structs.len(),
            "Saving type database"
        );

        self.store.save(&db.metadata.binary, db)?;
        Ok(())
    }

    /// Loads the type database persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`TypesDbError::NotFound`] if no database is persisted for
    /// `binary`, or [`TypesDbError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<TypeDatabase> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Type database file not found");
            return Err(TypesDbError::NotFound { path });
        }
        info!(path = %path.display(), "Loading type database");

        Ok(self.store.load(binary)?)
    }

    /// Returns the path where the rendered Rust declarations for `binary`
    /// are saved: the JSON document's path with a `.rs` extension, so the
    /// two files always sit side by side.
    pub fn decls_path_for(&self, binary: &str) -> PathBuf {
        self.path_for(binary).with_extension("rs")
    }

    /// Whether rendered declarations are persisted for `binary`.
    pub fn decls_exists(&self, binary: &str) -> bool {
        self.decls_path_for(binary).is_file()
    }

    /// Writes the rendered Rust declarations beside the JSON document.
    ///
    /// The file is a derived artifact. Every scan rewrites it in full from
    /// the loaded database, and nothing reads it back. So a rescan that
    /// changes nothing leaves a byte-identical file.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save_decls(&self, binary: &str, content: &str) -> Result<()> {
        let path = self.decls_path_for(binary);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        info!(path = %path.display(), "Writing Rust declarations");
        std::fs::write(&path, content)?;
        Ok(())
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stl::StlKind;
    use crate::types::{
        Confidence, FieldType, InferredField, InferredStruct, NameOrigin, NamedType, ScanMetadata,
        TypeKind, Vtable,
    };
    use calxgloss_decomp::DataTypeEntry;
    use tempfile::TempDir;

    /// A database with one record in every section, so a round trip proves
    /// each section survives the file, not just the envelope.
    fn database(binary: &str) -> TypeDatabase {
        TypeDatabase {
            metadata: ScanMetadata {
                binary: binary.to_string(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
                coverage: None,
            },
            named_types: vec![NamedType::from_listing(
                &DataTypeEntry {
                    name: "IMAGE_DOS_HEADER".into(),
                    category: "pe".into(),
                    size: Some(128),
                    path: "/pe/IMAGE_DOS_HEADER".into(),
                },
                TypeKind::Struct,
            )],
            vtables: vec![Vtable {
                address: 0x1801_306f0,
                label: "vftable".into(),
                size: 40,
                meta_ptr_address: Some(0x1801_306e8),
                methods: Vec::new(),
                class_name: Some("Widget".into()),
                base_classes: vec!["Base".into()],
                is_com_interface: false,
                stl_kind: Some(StlKind::SmartPointer),
            }],
            inferred_structs: vec![InferredStruct {
                name: "Widget".into(),
                name_origin: NameOrigin::VtableClass,
                fields: vec![InferredField {
                    name: "x".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x".into(),
                    source_address: 0x1801_29350,
                    stl_kind: Some(StlKind::String),
                }],
                confidence: Confidence::new(79),
                referenced_by: vec!["FUN_18000b620".into()],
                linked_vtable: Some(0x1801_306f0),
                merged_from: None,
            }],
        }
    }

    #[test]
    fn save_then_load_round_trips_every_section() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());
        let db = database("eqmain.dll");

        persistor.save(&db).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded, db);
        assert_eq!(loaded.named_types[0].path, "/pe/IMAGE_DOS_HEADER");
        assert_eq!(loaded.vtables[0].class_name.as_deref(), Some("Widget"));
        assert_eq!(loaded.inferred_structs[0].name, "Widget");
        assert_eq!(
            loaded.inferred_structs[0].linked_vtable,
            Some(0x1801_306f0),
            "the vtable link survives the file"
        );
    }

    #[test]
    fn the_filed_document_carries_its_coverage_record_exactly() {
        // What the scan writes about its own coverage is what every later
        // reader sees — the projection seam, the report, or a `--show`
        // months later. The status, the facet id, and the limitation line
        // pass through the persistor untouched (issue #348).
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());
        let mut db = database("eqmain.dll");
        db.metadata.coverage = Some(calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Unavailable,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "vtables".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: Some("no vtable evidence on this target".to_string()),
            }],
        });

        persistor.save(&db).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.metadata.coverage, db.metadata.coverage);
        assert_eq!(
            loaded
                .metadata
                .coverage
                .as_ref()
                .and_then(|coverage| coverage.admission())
                .as_deref(),
            Some("unavailable — no vtable evidence on this target"),
            "the reader's admission line is the one the scan wrote"
        );
    }

    #[test]
    fn a_document_in_the_shipped_mvp_shape_still_loads() {
        // A database written before the linking pass has no
        // `linked_vtable` key. The field defaults, so the cache keeps
        // working across the upgrade.
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());
        let text = r#"{
            "metadata": {
                "binary": "eqmain.dll",
                "scanned_at": 1759488000,
                "duration_secs": 12
            },
            "inferred_structs": [{
                "name": "Player",
                "name_origin": "literal_prefix",
                "fields": [],
                "confidence": 79,
                "referenced_by": ["FUN_18000b620"]
            }]
        }"#;
        std::fs::write(dir.path().join("eqmain.dll.json"), text)
            .expect("mvp-shape document should be written");

        let loaded = persistor
            .load("eqmain.dll")
            .expect("the mvp-shape document should load");
        assert_eq!(loaded.inferred_structs[0].name, "Player");
        assert_eq!(loaded.inferred_structs[0].linked_vtable, None);
    }

    #[test]
    fn a_named_type_written_before_the_nesting_pass_still_loads() {
        // Documents written before the nesting pass have no `linked_type`
        // or `linked_kind` keys on their struct fields. Both fields
        // default, so the cache keeps working across the upgrade.
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());
        let text = r#"{
            "metadata": {
                "binary": "eqmain.dll",
                "scanned_at": 1759488000,
                "duration_secs": 12
            },
            "named_types": [{
                "name": "WIDGET",
                "kind": "struct",
                "category": "pe",
                "path": "/pe/WIDGET",
                "size": 8,
                "fields": [{
                    "name": "mode",
                    "offset": 0,
                    "size": 4,
                    "type_name": "MODES"
                }]
            }]
        }"#;
        std::fs::write(dir.path().join("eqmain.dll.json"), text)
            .expect("pre-nesting document should be written");

        let loaded = persistor
            .load("eqmain.dll")
            .expect("the pre-nesting document should load");
        let field = &loaded.named_types[0].fields[0];
        assert_eq!(field.linked_type, None, "no link key means no link");
        assert_eq!(field.linked_kind, None, "no kind key means no kind");
        assert!(!field.is_nested());
    }

    #[test]
    fn new_files_databases_under_re_analysis_typesdb() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::new(dir.path());

        persistor.save(&database("eqmain.dll")).unwrap();

        let expected = dir
            .path()
            .join("re")
            .join("analysis")
            .join("typesdb")
            .join("eqmain.dll.json");
        assert!(
            expected.is_file(),
            "the whole directory chain should be created"
        );
    }

    #[test]
    fn with_cache_dir_files_databases_directly_under_the_given_path() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("custom").join("cache");
        let persistor = TypeDatabasePersistor::with_cache_dir(&cache);

        persistor.save(&database("eqgame.exe")).unwrap();

        assert!(cache.join("eqgame.exe.json").is_file());
        assert!(
            !dir.path().join("re").exists(),
            "no workspace layout is built"
        );
    }

    #[test]
    fn path_for_names_the_file_after_the_binary() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::new(dir.path());

        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("typesdb")
                .join("eqmain.dll.json")
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed_json() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());

        persistor.save(&database("eqmain.dll")).unwrap();

        let text = std::fs::read_to_string(dir.path().join("eqmain.dll.json")).unwrap();
        assert!(
            text.contains("\n  \"metadata\""),
            "expected pretty JSON: {text}"
        );
    }

    #[test]
    fn exists_tracks_whether_a_database_is_persisted() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());

        assert!(!persistor.exists("eqmain.dll"));
        persistor.save(&database("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("renderer.dll"));
    }

    #[test]
    fn save_decls_files_the_declarations_beside_the_database() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::new(dir.path());

        persistor
            .save_decls("eqmain.dll", "// declarations\n")
            .unwrap();

        let expected = dir
            .path()
            .join("re")
            .join("analysis")
            .join("typesdb")
            .join("eqmain.dll.rs");
        assert_eq!(persistor.decls_path_for("eqmain.dll"), expected);
        let text = std::fs::read_to_string(&expected).unwrap();
        assert_eq!(text, "// declarations\n");
    }

    #[test]
    fn decls_exists_tracks_whether_declarations_are_persisted() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());

        assert!(!persistor.decls_exists("eqmain.dll"));
        persistor
            .save_decls("eqmain.dll", "// declarations\n")
            .unwrap();
        assert!(persistor.decls_exists("eqmain.dll"));
        assert!(
            !persistor.decls_exists("renderer.dll"),
            "other binaries keep their own declarations"
        );
    }

    #[test]
    fn loading_a_missing_database_names_the_path() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();

        assert!(
            matches!(&err, TypesDbError::NotFound { path } if path.ends_with("eqmain.dll.json")),
            "{err}"
        );
        assert!(err.to_string().contains("eqmain.dll.json"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_database() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());
        persistor.save(&database("eqmain.dll")).unwrap();

        let mut fresh = database("eqmain.dll");
        fresh.metadata.scanned_at += 60;
        fresh.named_types.clear();
        persistor.save(&fresh).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded, fresh);
    }

    #[test]
    fn databases_for_two_binaries_stay_independent() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());

        persistor.save(&database("eqmain.dll")).unwrap();
        persistor.save(&database("renderer.dll")).unwrap();

        assert_eq!(
            persistor.load("eqmain.dll").unwrap().metadata.binary,
            "eqmain.dll"
        );
        assert_eq!(
            persistor.load("renderer.dll").unwrap().metadata.binary,
            "renderer.dll"
        );
    }

    #[test]
    fn a_corrupt_document_is_refused_as_a_json_error() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::with_cache_dir(dir.path());
        std::fs::write(dir.path().join("eqmain.dll.json"), "{ not json").unwrap();

        assert!(matches!(
            persistor.load("eqmain.dll"),
            Err(TypesDbError::Json(_))
        ));
    }
}

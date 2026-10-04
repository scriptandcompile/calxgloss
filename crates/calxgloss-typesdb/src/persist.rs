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
//! A persisted database doubles as a cache: [`exists`](Self::exists) is the
//! check a caller runs before deciding whether a scan is needed, and
//! [`load`](Self::load) reads the whole document back — metadata and all
//! three recovered sections — for the translation pipeline to query.

use std::path::{Path, PathBuf};

use tracing::{info, warn};

use crate::error::{Result, TypesDbError};
use crate::types::TypeDatabase;

/// Saves and loads the per-binary type database as JSON.
///
/// # File Layout
///
/// Databases are filed under a cache directory, named after the binary the
/// scan read:
///
/// ```text
/// cache_dir/
///     └── {binary}.json
/// ```
///
/// The default cache directory is `{workspace_root}/re/analysis/typesdb/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
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
    cache_dir: PathBuf,
}

impl TypeDatabasePersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Databases are stored in `<workspace_root>/re/analysis/typesdb/`.
    pub fn new(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            cache_dir: workspace_root
                .as_ref()
                .join("re")
                .join("analysis")
                .join("typesdb"),
        }
    }

    /// Creates a new persistor with an explicit cache directory.
    ///
    /// Databases are stored directly under the provided `cache_dir` path.
    pub fn with_cache_dir(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            cache_dir: cache_dir.as_ref().to_path_buf(),
        }
    }

    /// Returns the path the database for `binary` is filed under.
    pub fn path_for(&self, binary: &str) -> PathBuf {
        self.cache_dir.join(format!("{binary}.json"))
    }

    /// Whether a persisted database exists for `binary`.
    ///
    /// This is the cache check: a caller that wants recovered types without
    /// re-running the scan asks here first and only drives
    /// [`TypesDBEngine`](crate::engine::TypesDBEngine) when the answer is
    /// `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.path_for(binary).is_file()
    }

    /// Saves a type database to JSON, keyed on its metadata's binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the database, and writes it to disk — a rescan replaces the previous
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

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(db)?;
        std::fs::write(&path, json)?;
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
        if !path.is_file() {
            warn!(path = %path.display(), "Type database file not found");
            return Err(TypesDbError::NotFound { path });
        }
        info!(path = %path.display(), "Loading type database");

        let json = std::fs::read_to_string(&path)?;
        let db: TypeDatabase = serde_json::from_str(&json)?;
        Ok(db)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        FieldType, InferredField, InferredStruct, NameOrigin, NamedType, ScanMetadata, TypeKind,
        Vtable,
    };
    use calxgloss_ghidra::DataTypeEntry;
    use tempfile::TempDir;

    /// A database with one record in every section, so a round trip proves
    /// each section survives the file, not just the envelope.
    fn database(binary: &str) -> TypeDatabase {
        TypeDatabase {
            metadata: ScanMetadata {
                binary: binary.to_string(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
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
            }],
            inferred_structs: vec![InferredStruct {
                name: "Player".into(),
                name_origin: NameOrigin::LiteralPrefix,
                fields: vec![InferredField {
                    name: "x".into(),
                    field_type: FieldType::Integer,
                    size: Some(4),
                    offset: Some(0),
                    source_value: "player.x".into(),
                    source_address: 0x1801_29350,
                }],
                confidence: 79,
                referenced_by: vec!["FUN_18000b620".into()],
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
        assert_eq!(loaded.inferred_structs[0].name, "Player");
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

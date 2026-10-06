//! JSON persistence for serialization detection results.
//!
//! The [`SerializePersistor`] saves and loads the per-binary
//! [`SerializeResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/serialize/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is the
//! check a caller runs before deciding whether a scan is needed, and
//! [`load`](Self::load) reads the whole document back — metadata and every
//! finding — for the translation pipeline to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{Result, SerializeError};
use crate::types::SerializeResult;

/// Saves and loads the per-binary serialization result as JSON.
///
/// # File Layout
///
/// Results are filed under a cache directory, named after the binary the
/// scan read:
///
/// ```text
/// cache_dir/
///     └── {binary}.json
/// ```
///
/// The default cache directory is `{workspace}/re/analysis/serialize/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_serialize::persist::SerializePersistor;
/// use calxgloss_serialize::types::{ScanMetadata, SerializeResult};
///
/// # fn main() -> calxgloss_serialize::Result<()> {
/// let persistor = SerializePersistor::new("/path/to/workspace");
/// let result = SerializeResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct SerializePersistor {
    store: JsonStore<SerializeResult>,
}

impl SerializePersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/serialize/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("serialize")),
        }
    }

    /// Creates a new persistor with an explicit cache directory.
    ///
    /// Results are stored directly under the provided `cache_dir` path.
    pub fn with_cache_dir(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(cache_dir),
        }
    }

    /// Returns the path the result for `binary` is filed under.
    pub fn path_for(&self, binary: &str) -> PathBuf {
        self.store.path_for(binary)
    }

    /// Whether a persisted result exists for `binary`.
    ///
    /// This is the cache check: a caller that wants serialization findings
    /// without re-running the scan asks here first and only drives the
    /// scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a serialization result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the result, and writes it to disk — a rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &SerializeResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving serialization result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the serialization result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`SerializeError::NotFound`] if no result is persisted for
    /// `binary`, or [`SerializeError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<SerializeResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Serialization result file not found");
            return Err(SerializeError::NotFound { path });
        }
        info!(path = %path.display(), "Loading serialization result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ByteSwapOperation, Confidence, ScanMetadata, SerializeFinding};
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> SerializeResult {
        let mut result = SerializeResult::new(ScanMetadata::new(binary));
        result
            .findings
            .push(SerializeFinding::ByteSwap(ByteSwapOperation {
                function: "ReadHeader".to_string(),
                operation: "ntohl".to_string(),
                width: 32,
                suggestion: "byteorder::BE::read_u32".to_string(),
                confidence: Confidence::new(70),
                evidence: "uVar1 = ntohl(local_18);".to_string(),
            }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        // Exhaustive while the union carries one variant; the arm list
        // grows with the bitpack and magic kinds.
        match &loaded.findings[0] {
            SerializeFinding::ByteSwap(f) => {
                assert_eq!(f.function, "ReadHeader");
                assert_eq!(f.operation, "ntohl");
                assert_eq!(f.width, 32);
            }
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_serialize_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/serialize/eqmain.dll.json");
        assert_eq!(
            SerializePersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"operation\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second
            .findings
            .push(SerializeFinding::ByteSwap(ByteSwapOperation {
                function: "WriteHeader".to_string(),
                operation: "htons".to_string(),
                width: 16,
                suggestion: "byteorder::BE::write_u16".to_string(),
                confidence: Confidence::new(70),
                evidence: "local_14 = htons(0x1234);".to_string(),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            SerializeError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SerializePersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, SerializeError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = SerializePersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn persist_errors_map_onto_serialize_errors() {
        let mapped = SerializeError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/serialize/eqmain.dll.json"),
        });
        assert!(matches!(mapped, SerializeError::NotFound { .. }));
    }
}

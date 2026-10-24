//! JSON persistence for float/SIMD usage flags.
//!
//! The [`FloatsimdPersistor`] saves and loads the per-binary
//! [`FloatsimdResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/floatsimd/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is
//! the check a caller runs before deciding whether a scan is needed,
//! and [`load`](Self::load) reads the whole document back — metadata
//! and every flag — for the translation pipeline and the downstream
//! tickets to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{FloatsimdError, Result};
use crate::types::FloatsimdResult;

/// Saves and loads the per-binary float/SIMD result as JSON.
///
/// # File Layout
///
/// Results are filed under a cache directory, named after the binary
/// the scan read:
///
/// ```text
/// cache_dir/
///     └── {binary}.json
/// ```
///
/// The default cache directory is `{workspace}/re/analysis/floatsimd/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_floatsimd::persist::FloatsimdPersistor;
/// use calxgloss_floatsimd::types::FloatsimdResult;
/// use calxgloss_types::ScanMetadata;
///
/// # fn main() -> calxgloss_floatsimd::Result<()> {
/// let persistor = FloatsimdPersistor::new("/path/to/workspace");
/// let result = FloatsimdResult::new(ScanMetadata::new("game_logic.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("game_logic.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct FloatsimdPersistor {
    store: JsonStore<FloatsimdResult>,
}

impl FloatsimdPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/floatsimd/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("floatsimd")),
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
    /// This is the cache check: a caller that wants float/SIMD flags
    /// without re-running the scan asks here first and only drives
    /// the scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a float/SIMD result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan
    /// replaces the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &FloatsimdResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving float/SIMD result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the float/SIMD result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`FloatsimdError::NotFound`] if no result is persisted
    /// for `binary`, or [`FloatsimdError::Json`] if the document is
    /// corrupt.
    pub fn load(&self, binary: &str) -> Result<FloatsimdResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Float/SIMD result file not found");
            return Err(FloatsimdError::NotFound { path });
        }
        info!(path = %path.display(), "Loading float/SIMD result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FloatsimdFinding, FloatsimdRecord};
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> FloatsimdResult {
        let mut result = FloatsimdResult::new(calxgloss_types::ScanMetadata::new(binary));
        result
            .findings
            .push(FloatsimdFinding::VectorMatrix(FloatsimdRecord {
                function: "FUN_18003ab00".to_string(),
                evidence: "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);".to_string(),
                confidence: 60.into(),
                suggestion: "translate as a small vector struct or component array, not integer \
                             or pointer arithmetic"
                    .to_string(),
            }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path());

        persistor.save(&sample_result("game_logic.dll")).unwrap();
        let loaded = persistor.load("game_logic.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "game_logic.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            FloatsimdFinding::VectorMatrix(f) => {
                assert_eq!(f.function, "FUN_18003ab00");
                assert_eq!(
                    f.evidence,
                    "local_10 = CONCAT44(uVar2 >> 4, uVar2 & 0xfffffff);"
                );
                assert_eq!(f.confidence.value(), 60);
            }
            other => panic!("expected a vector-matrix finding, got {other:?}"),
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_floatsimd_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/floatsimd/game_logic.dll.json");
        assert_eq!(
            FloatsimdPersistor::new(dir.path()).path_for("game_logic.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("game_logic.dll")).unwrap();
        assert!(persistor.path_for("game_logic.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path());
        persistor.save(&sample_result("game_logic.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("game_logic.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"vector_matrix\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path());
        assert!(!persistor.exists("game_logic.dll"));

        persistor.save(&sample_result("game_logic.dll")).unwrap();
        assert!(persistor.exists("game_logic.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path());

        persistor.save(&sample_result("game_logic.dll")).unwrap();
        let mut second = sample_result("game_logic.dll");
        second
            .findings
            .push(FloatsimdFinding::ScalarFloat(FloatsimdRecord {
                function: "FUN_18003e750".to_string(),
                evidence: "fVar1 = (float)uVar2;".to_string(),
                confidence: 90.into(),
                suggestion: "translate as f32/f64 scalar float math, not integer or pointer \
                             arithmetic"
                    .to_string(),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("game_logic.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path());

        let err = persistor.load("game_logic.dll").unwrap_err();
        match err {
            FloatsimdError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("game_logic.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = FloatsimdPersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("game_logic.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("game_logic.dll"), "{ not json").unwrap();

        let err = persistor.load("game_logic.dll").unwrap_err();
        assert!(
            matches!(err, FloatsimdError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = FloatsimdPersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("game_logic.dll")).unwrap();
        assert!(cache.join("game_logic.dll.json").exists());
    }

    #[test]
    fn persist_errors_map_onto_floatsimd_errors() {
        let mapped = FloatsimdError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/floatsimd/game_logic.dll.json"),
        });
        assert!(matches!(mapped, FloatsimdError::NotFound { .. }));
    }
}

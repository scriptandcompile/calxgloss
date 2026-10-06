//! JSON persistence for callback detection results.
//!
//! The [`CallbackPersistor`] saves and loads the per-binary [`CallbackResult`]
//! as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/callback/
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

use crate::error::{CallbackError, Result};
use crate::types::CallbackResult;

/// Saves and loads the per-binary callback result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/callback/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_callback::persist::CallbackPersistor;
/// use calxgloss_callback::types::{ScanMetadata, CallbackResult};
///
/// # fn main() -> calxgloss_callback::Result<()> {
/// let persistor = CallbackPersistor::new("/path/to/workspace");
/// let result = CallbackResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct CallbackPersistor {
    store: JsonStore<CallbackResult>,
}

impl CallbackPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/callback/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("callback")),
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
    /// This is the cache check: a caller that wants callback findings
    /// without re-running the scan asks here first and only drives the
    /// scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a callback result to JSON, keyed on its metadata's binary
    /// name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the result, and writes it to disk — a rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &CallbackResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving callback result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the callback result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`CallbackError::NotFound`] if no result is persisted for
    /// `binary`, or [`CallbackError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<CallbackResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Callback result file not found");
            return Err(CallbackError::NotFound { path });
        }
        info!(path = %path.display(), "Loading callback result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CallbackFinding, CallbackRegistration, Confidence, FpArrayCall, JumpTable, ScanMetadata,
    };
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> CallbackResult {
        let mut result = CallbackResult::new(ScanMetadata::new(binary));
        result.findings.push(CallbackFinding::FpArray(FpArrayCall {
            function: "DispatchHandlers".to_string(),
            table: "handlers".to_string(),
            suggestion: "Vec<Box<dyn Fn(...)>>".to_string(),
            confidence: Confidence::new(70),
            evidence: "(*(code *)handlers[uVar1])(param_1);".to_string(),
        }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            CallbackFinding::FpArray(f) => {
                assert_eq!(f.function, "DispatchHandlers");
                assert_eq!(f.table, "handlers");
            }
            other => panic!("expected an fp array finding, got {other:?}"),
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_callback_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/callback/eqmain.dll.json");
        assert_eq!(
            CallbackPersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"table\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second
            .findings
            .push(CallbackFinding::Registration(CallbackRegistration {
                function: "WireEvents".to_string(),
                registration: "register_callback".to_string(),
                callback: "my_handler".to_string(),
                suggestion: "Box<dyn Fn(...)>".to_string(),
                confidence: Confidence::new(70),
                evidence: "register_callback(my_handler);".to_string(),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            CallbackError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, CallbackError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = CallbackPersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn jump_table_findings_survive_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = CallbackPersistor::new(dir.path());

        let mut result = CallbackResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings.push(CallbackFinding::JumpTable(JumpTable {
            function: "ComputedDispatch".to_string(),
            table: "DAT_1400a1b60".to_string(),
            index: "uVar2".to_string(),
            target_count: Some(5),
            suggestion: "[fn(...); 5]".to_string(),
            confidence: Confidence::new(70),
            evidence: "(*DAT_1400a1b60[uVar2])();".to_string(),
        }));
        persistor.save(&result).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        match &loaded.findings[0] {
            CallbackFinding::JumpTable(t) => {
                assert_eq!(t.table, "DAT_1400a1b60");
                assert_eq!(t.target_count, Some(5));
            }
            other => panic!("expected a jump table finding, got {other:?}"),
        }
    }

    #[test]
    fn persist_errors_map_onto_callback_errors() {
        let mapped = CallbackError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/callback/eqmain.dll.json"),
        });
        assert!(matches!(mapped, CallbackError::NotFound { .. }));
    }
}

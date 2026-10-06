//! JSON persistence for control-flow detection results.
//!
//! The [`ControlFlowPersistor`] saves and loads the per-binary
//! [`ControlFlowResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/controlflow/
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

use crate::error::{ControlFlowError, Result};
use crate::types::ControlFlowResult;

/// Saves and loads the per-binary control-flow result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/controlflow/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_controlflow::persist::ControlFlowPersistor;
/// use calxgloss_controlflow::types::{ControlFlowResult, ScanMetadata};
///
/// # fn main() -> calxgloss_controlflow::Result<()> {
/// let persistor = ControlFlowPersistor::new("/path/to/workspace");
/// let result = ControlFlowResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct ControlFlowPersistor {
    store: JsonStore<ControlFlowResult>,
}

impl ControlFlowPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/controlflow/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("controlflow")),
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
    /// This is the cache check: a caller that wants control-flow findings
    /// without re-running the scan asks here first and only drives the
    /// scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a control-flow result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan replaces
    /// the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &ControlFlowResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving control-flow result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the control-flow result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`ControlFlowError::NotFound`] if no result is persisted
    /// for `binary`, or [`ControlFlowError::Json`] if the document is
    /// corrupt.
    pub fn load(&self, binary: &str) -> Result<ControlFlowResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Control-flow result file not found");
            return Err(ControlFlowError::NotFound { path });
        }
        info!(path = %path.display(), "Loading control-flow result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, ScanMetadata, SelfRecursion, SwitchChain};
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> ControlFlowResult {
        let mut result = ControlFlowResult::new(ScanMetadata::new(binary));
        result
            .findings
            .push(crate::types::ControlFlowFinding::Switch(SwitchChain {
                function: "FUN_18003ab00".to_string(),
                variable: "local_4".to_string(),
                cases: vec!["1".to_string(), "2".to_string(), "3".to_string()],
                has_default: false,
                suggestion: "match local_4 { /* 3 arms */ }".to_string(),
                confidence: Confidence::new(70),
                evidence: "if (local_4 == 1) ... else if (local_4 == 3)".to_string(),
            }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            crate::types::ControlFlowFinding::Switch(f) => {
                assert_eq!(f.function, "FUN_18003ab00");
                assert_eq!(f.variable, "local_4");
                assert_eq!(f.cases, ["1", "2", "3"]);
            }
            other => panic!("expected a switch finding, got {other:?}"),
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_controlflow_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/controlflow/eqmain.dll.json");
        assert_eq!(
            ControlFlowPersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"variable\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second
            .findings
            .push(crate::types::ControlFlowFinding::Recursion(SelfRecursion {
                function: "FUN_18003e750".to_string(),
                is_tail_call: true,
                self_calls: 1,
                suggestion: "replace with loop { ... } (tail call)".to_string(),
                confidence: Confidence::new(80),
                evidence: "FUN_18003e750() calls itself 1x (tail call)".to_string(),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            ControlFlowError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, ControlFlowError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = ControlFlowPersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn persist_errors_map_onto_control_flow_errors() {
        let mapped = ControlFlowError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/controlflow/eqmain.dll.json"),
        });
        assert!(matches!(mapped, ControlFlowError::NotFound { .. }));
    }
}

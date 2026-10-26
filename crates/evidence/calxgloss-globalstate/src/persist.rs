//! JSON persistence for global-state reference sets.
//!
//! The [`GlobalStatePersistor`] saves and loads the per-binary
//! [`GlobalStateResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/globalstate/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is
//! the check a caller runs before deciding whether a scan is needed,
//! and [`load`](Self::load) reads the whole document back — metadata,
//! every access record, and the purity summary — for the translation
//! pipeline and the downstream tickets to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{GlobalStateError, Result};
use crate::types::GlobalStateResult;

/// Saves and loads the per-binary global-state result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/globalstate/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_globalstate::persist::GlobalStatePersistor;
/// use calxgloss_globalstate::types::GlobalStateResult;
/// use calxgloss_types::ScanMetadata;
///
/// # fn main() -> calxgloss_globalstate::Result<()> {
/// let persistor = GlobalStatePersistor::new("/path/to/workspace");
/// let result = GlobalStateResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct GlobalStatePersistor {
    store: JsonStore<GlobalStateResult>,
}

impl GlobalStatePersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/globalstate/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("globalstate")),
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
    /// This is the cache check: a caller that wants global-state
    /// records without re-running the scan asks here first and only
    /// drives the scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a global-state result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan
    /// replaces the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &GlobalStateResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            purity = result.purity.len(),
            "Saving global-state result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the global-state result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalStateError::NotFound`] if no result is
    /// persisted for `binary`, or [`GlobalStateError::Json`] if the
    /// document is corrupt.
    pub fn load(&self, binary: &str) -> Result<GlobalStateResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Global-state result file not found");
            return Err(GlobalStateError::NotFound { path });
        }
        info!(path = %path.display(), "Loading global-state result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FunctionPurity, GlobalAccess, GlobalStateFinding, SharedGlobalRecord};
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> GlobalStateResult {
        let mut result = GlobalStateResult::new(calxgloss_types::ScanMetadata::new(binary));
        result
            .findings
            .push(GlobalStateFinding::GlobalWrite(GlobalAccess {
                function: "FUN_18003ab00".to_string(),
                global: "DAT_180064e80".to_string(),
                evidence: "DAT_180064e80 = param_1".to_string(),
                confidence: 85.into(),
                suggestion: "model the program global as shared struct state, not a Rust static"
                    .to_string(),
            }));
        result.purity.push(FunctionPurity {
            function: "FUN_18003ab00".to_string(),
            is_pure: false,
            reads: 0,
            writes: 1,
        });
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            GlobalStateFinding::GlobalWrite(f) => {
                assert_eq!(f.function, "FUN_18003ab00");
                assert_eq!(f.global, "DAT_180064e80");
                assert_eq!(f.confidence.value(), 85);
            }
            other => panic!("expected a global write finding, got {other:?}"),
        }
    }

    #[test]
    fn the_purity_summary_survives_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(
            loaded.purity,
            vec![FunctionPurity {
                function: "FUN_18003ab00".into(),
                is_pure: false,
                reads: 0,
                writes: 1,
            }]
        );
    }

    #[test]
    fn the_shared_globals_index_survives_the_round_trip() {
        // The rollup rides the same document as the access records:
        // one entry per global, readers and writers intact.
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());
        let mut result = sample_result("eqmain.dll");
        result
            .findings
            .push(GlobalStateFinding::SharedGlobal(SharedGlobalRecord {
                global: "DAT_180064e80".to_string(),
                readers: vec!["FUN_18003ab00".to_string(), "FUN_18003e750".to_string()],
                writers: vec!["FUN_18003ab00".to_string()],
                confidence: 85.into(),
            }));

        persistor.save(&result).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded, result, "the index reads back exactly as saved");
        let entry = loaded.findings[1]
            .shared_global()
            .expect("the rollup entry is the second record");
        assert_eq!(entry.readers, vec!["FUN_18003ab00", "FUN_18003e750"]);
        assert_eq!(entry.writers, vec!["FUN_18003ab00"]);

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(
            raw.contains("\"shared_global\""),
            "the rollup tag is spelled in the document"
        );
    }

    #[test]
    fn results_are_filed_under_re_analysis_globalstate_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/globalstate/eqmain.dll.json");
        assert_eq!(
            GlobalStatePersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"global_write\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second
            .findings
            .push(GlobalStateFinding::GlobalRead(GlobalAccess {
                function: "FUN_18003e750".to_string(),
                global: "DAT_180064e80".to_string(),
                evidence: "uVar1 = DAT_180064e80".to_string(),
                confidence: 85.into(),
                suggestion: "read the program global through shared state, not an invented local"
                    .to_string(),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            GlobalStateError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, GlobalStateError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = GlobalStatePersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn persist_errors_map_onto_global_state_errors() {
        let mapped = GlobalStateError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/globalstate/eqmain.dll.json"),
        });
        assert!(matches!(mapped, GlobalStateError::NotFound { .. }));
    }

    #[test]
    fn the_filed_document_carries_its_coverage_record_exactly() {
        // What the scan stamped rides the persistor untouched: statuses,
        // ids, order, limitation lines — exactly what a later reader
        // (the projection seam, the report, a `--show` months later)
        // sees (issue #350).
        let dir = tempfile::tempdir().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());
        let mut saved = sample_result("eqmain.dll");
        saved.metadata.coverage = Some(calxgloss_types::ScanCoverage {
            status: calxgloss_types::CoverageStatus::Partial,
            facets: vec![calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("2 function bodies unreached: FUN_180099000, +1 more".to_string()),
            }],
        });

        persistor.save(&saved).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.coverage, saved.metadata.coverage);
    }
}

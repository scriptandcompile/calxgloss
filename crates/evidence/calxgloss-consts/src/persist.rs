//! JSON persistence for constant detection results.
//!
//! The [`ConstPersistor`] saves and loads the per-binary [`ConstResult`]
//! as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/consts/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is
//! the check a caller runs before deciding whether a scan is needed,
//! and [`load`](Self::load) reads the whole document back — metadata
//! and every finding — for the translation pipeline to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{ConstError, Result};
use crate::types::ConstResult;

/// Saves and loads the per-binary constant result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/consts/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_consts::persist::ConstPersistor;
/// use calxgloss_consts::types::{ConstResult, ScanMetadata};
///
/// # fn main() -> calxgloss_consts::Result<()> {
/// let persistor = ConstPersistor::new("/path/to/workspace");
/// let result = ConstResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct ConstPersistor {
    store: JsonStore<ConstResult>,
}

impl ConstPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/consts/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("consts")),
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
    /// This is the cache check: a caller that wants constant findings
    /// without re-running the scan asks here first and only drives the
    /// scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a constant result to JSON, keyed on its metadata's binary
    /// name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan
    /// replaces the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &ConstResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving constant result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the constant result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`ConstError::NotFound`] if no result is persisted for
    /// `binary`, or [`ConstError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<ConstResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Constant result file not found");
            return Err(ConstError::NotFound { path });
        }
        info!(path = %path.display(), "Loading constant result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BitflagGroup, Confidence, NamedConstant, ScanMetadata};
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> ConstResult {
        let mut result = ConstResult::new(ScanMetadata::new(binary));
        result
            .findings
            .push(crate::types::ConstFinding::BitflagGroup(BitflagGroup {
                function: "FlagObject".to_string(),
                bits: vec![8, 10],
                mask: 0x500,
                bit_width: 11,
                suggestion: "bitflags! struct Flags: u32 { /* bits: 0x100, 0x400 */ }".to_string(),
                confidence: Confidence::new(70),
                evidence: "if ((uVar1 & 0x400) != 0) { uVar1 |= 0x100; }".to_string(),
            }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            crate::types::ConstFinding::BitflagGroup(f) => {
                assert_eq!(f.function, "FlagObject");
                assert_eq!(f.bits, vec![8, 10]);
                assert_eq!(f.mask, 0x500);
            }
            other => panic!("expected a bitflag finding, got {other:?}"),
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_consts_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/consts/eqmain.dll.json");
        assert_eq!(
            ConstPersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"bits\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second
            .findings
            .push(crate::types::ConstFinding::NamedConstant(NamedConstant {
                value: 0x280,
                count: 3,
                functions: vec!["FuncA".to_string(), "FuncB".to_string()],
                suggestion: "const VALUE_0x280: u32 = 0x280;".to_string(),
                confidence: Confidence::new(60),
                evidence: "0x280 used 3 times in FuncA, FuncB".to_string(),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            ConstError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, ConstError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = ConstPersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn named_constant_findings_survive_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ConstPersistor::new(dir.path());

        let mut result = ConstResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(crate::types::ConstFinding::NamedConstant(NamedConstant {
                value: 0x400,
                count: 5,
                functions: vec!["StartWorker".to_string(), "ReadFlags".to_string()],
                suggestion: "const VALUE_0x400: u32 = 0x400;".to_string(),
                confidence: Confidence::new(60),
                evidence: "0x400 used 5 times in ReadFlags, StartWorker".to_string(),
            }));
        persistor.save(&result).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        match &loaded.findings[0] {
            crate::types::ConstFinding::NamedConstant(c) => {
                assert_eq!(c.value, 0x400);
                assert_eq!(c.functions, vec!["StartWorker", "ReadFlags"]);
            }
            other => panic!("expected a named-constant finding, got {other:?}"),
        }
    }

    #[test]
    fn persist_errors_map_onto_const_errors() {
        let mapped = ConstError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/consts/eqmain.dll.json"),
        });
        assert!(matches!(mapped, ConstError::NotFound { .. }));
    }
}

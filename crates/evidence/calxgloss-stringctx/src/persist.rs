//! JSON persistence for string-context results.
//!
//! The [`StringContextPersistor`] saves and loads the per-binary
//! [`StringContextResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/stringctx/
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

use crate::error::{Result, StringCtxError};
use crate::types::StringContextResult;

/// Saves and loads the per-binary string-context result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/stringctx/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_stringctx::persist::StringContextPersistor;
/// use calxgloss_stringctx::types::{ScanMetadata, StringContextResult};
///
/// # fn main() -> calxgloss_stringctx::Result<()> {
/// let persistor = StringContextPersistor::new("/path/to/workspace");
/// let result = StringContextResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct StringContextPersistor {
    store: JsonStore<StringContextResult>,
}

impl StringContextPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/stringctx/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("stringctx")),
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
    /// This is the cache check: a caller that wants string context without
    /// re-running the scan asks here first and only drives the scan when
    /// the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a string-context result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan replaces
    /// the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &StringContextResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving string context result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the string-context result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`StringCtxError::NotFound`] if no result is persisted for
    /// `binary`, or [`StringCtxError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<StringContextResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "String context result file not found");
            return Err(StringCtxError::NotFound { path });
        }
        info!(path = %path.display(), "Loading string context result");

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
        ClassifiedString, Confidence, FormatHint, FormatStringUse, ScanMetadata,
        StringClassification, StringContextResult, StringFinding, StringSource,
    };
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> StringContextResult {
        let mut result = StringContextResult::new(ScanMetadata::new(binary));
        result
            .findings
            .push(StringFinding::Classified(ClassifiedString {
                function: "FUN_18003ab00".to_string(),
                string_address: 0x180127cd8,
                string_value: "Journal.txt".to_string(),
                classification: StringClassification::FilePath,
                purpose: "config file path".to_string(),
                source: StringSource::BodyParse,
                confidence: Confidence::new(70),
                evidence: "lFile = CreateFileA(\"Journal.txt\",...);".to_string(),
            }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            StringFinding::Classified(f) => {
                assert_eq!(f.function, "FUN_18003ab00");
                assert_eq!(f.string_value, "Journal.txt");
                assert_eq!(f.classification, StringClassification::FilePath);
            }
            other => panic!("expected a classified finding, got {other:?}"),
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_stringctx_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/stringctx/eqmain.dll.json");
        assert_eq!(
            StringContextPersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"string_value\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second
            .findings
            .push(StringFinding::FormatString(FormatStringUse {
                function: "FUN_18003e750".to_string(),
                format_string: "%s: %d hits".to_string(),
                string_address: 0x180127cd8,
                call_site: "sprintf(local_10, \"%s: %d hits\", name, count);".to_string(),
                arg_types: vec![
                    FormatHint {
                        specifier: "%s".to_string(),
                        position: 0,
                        rust_type: "*const i8".to_string(),
                    },
                    FormatHint {
                        specifier: "%d".to_string(),
                        position: 1,
                        rust_type: "i32".to_string(),
                    },
                ],
                confidence: Confidence::new(70),
            }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            StringCtxError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, StringCtxError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = StringContextPersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn format_string_findings_survive_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = StringContextPersistor::new(dir.path());

        let mut result = StringContextResult::new(ScanMetadata::new("eqmain.dll"));
        result
            .findings
            .push(StringFinding::FormatString(FormatStringUse {
                function: "FUN_18003e750".to_string(),
                format_string: "%s: %d hits".to_string(),
                string_address: 0x180127cd8,
                call_site: "sprintf(local_10, \"%s: %d hits\", name, count);".to_string(),
                arg_types: vec![FormatHint {
                    specifier: "%s".to_string(),
                    position: 0,
                    rust_type: "*const i8".to_string(),
                }],
                confidence: Confidence::new(70),
            }));
        persistor.save(&result).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        match &loaded.findings[0] {
            StringFinding::FormatString(f) => {
                assert_eq!(f.format_string, "%s: %d hits");
                assert_eq!(f.arg_types[0].rust_type, "*const i8");
            }
            other => panic!("expected a format_string finding, got {other:?}"),
        }
    }

    #[test]
    fn persist_errors_map_onto_string_ctx_errors() {
        let mapped = StringCtxError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/stringctx/eqmain.dll.json"),
        });
        assert!(matches!(mapped, StringCtxError::NotFound { .. }));
    }
}

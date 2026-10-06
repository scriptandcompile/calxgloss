//! JSON persistence for API-identification results.
//!
//! The [`ApiPersistor`] saves and loads the per-binary
//! [`ApiDetectionResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/apidetect/
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

use crate::error::{ApiError, Result};
use crate::types::ApiDetectionResult;

/// Saves and loads the per-binary API result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/apidetect/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_apidetect::persist::ApiPersistor;
/// use calxgloss_apidetect::types::{ApiDetectionResult, ScanMetadata};
///
/// # fn main() -> calxgloss_apidetect::Result<()> {
/// let persistor = ApiPersistor::new("/path/to/workspace");
/// let result = ApiDetectionResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct ApiPersistor {
    store: JsonStore<ApiDetectionResult>,
}

impl ApiPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/apidetect/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("apidetect")),
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
    /// This is the cache check: a caller that wants API findings without
    /// re-running the scan asks here first and only drives the scan when
    /// the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves an API result to JSON, keyed on its metadata's binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan replaces
    /// the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &ApiDetectionResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving API detection result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the API result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::NotFound`] if no result is persisted for
    /// `binary`, or [`ApiError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<ApiDetectionResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "API result file not found");
            return Err(ApiError::NotFound { path });
        }
        info!(path = %path.display(), "Loading API detection result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApiFinding, ApiSignature, ApiUsage, Confidence, ScanMetadata};
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> ApiDetectionResult {
        let mut result = ApiDetectionResult::new(ScanMetadata::new(binary));
        result.findings.push(ApiFinding::Import(ApiSignature {
            api: "inflate".to_string(),
            library: Some("zlib".to_string()),
            rust_crate: Some("flate2".to_string()),
            confidence: Confidence::new(90),
        }));
        result.findings.push(ApiFinding::ApiUsage(ApiUsage {
            function: "FUN_18003ab00".to_string(),
            api: "CreateFileA".to_string(),
            library: "Win32".to_string(),
            rust_crate: "windows / std::fs".to_string(),
            direct: false,
            confidence: Confidence::new(60),
            evidence: "FUN_18003ab00 → FUN_18003c000 → CreateFileA".to_string(),
        }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_whole_result() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::with_cache_dir(dir.path());
        let result = sample_result("eqmain.dll");

        persistor.save(&result).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded, result);
    }

    #[test]
    fn save_creates_the_cache_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(
            dir.path()
                .join("re/analysis/apidetect/eqmain.dll.json")
                .exists()
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::with_cache_dir(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"inflate\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::new(dir.path());
        let error = persistor.load("eqmain.dll").unwrap_err();
        match error {
            ApiError::NotFound { path } => assert!(path.to_string_lossy().contains("eqmain.dll")),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::with_cache_dir(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let mut smaller = ApiDetectionResult::new(ScanMetadata::new("eqmain.dll"));
        smaller.findings.pop();
        persistor.save(&smaller).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded, smaller);
    }

    #[test]
    fn a_corrupt_document_reports_a_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ApiPersistor::with_cache_dir(dir.path());
        std::fs::write(persistor.path_for("eqmain.dll"), "not json").unwrap();
        let error = persistor.load("eqmain.dll").unwrap_err();
        assert!(matches!(error, ApiError::Json(_)));
    }

    #[test]
    fn store_persist_errors_map_onto_the_crate_error() {
        let error: ApiError = PersistError::NotFound {
            path: PathBuf::from("eqmain.dll.json"),
        }
        .into();
        assert!(matches!(error, ApiError::NotFound { .. }));
    }
}

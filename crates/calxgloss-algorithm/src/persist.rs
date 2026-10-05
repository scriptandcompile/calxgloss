//! JSON persistence for algorithm recognition results.
//!
//! The [`AlgorithmPersistor`] saves and loads the per-binary
//! [`AlgorithmRecognitionResult`] as one pretty-printed JSON document per
//! binary:
//!
//! ```text
//! re/analysis/algorithm/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is the
//! check a caller runs before deciding whether a scan is needed, and
//! [`load`](Self::load) reads the whole document back — metadata and every
//! hint — for the translation pipeline to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{AlgorithmError, Result};
use crate::types::AlgorithmRecognitionResult;

/// Saves and loads the per-binary recognition result as JSON.
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
/// The default cache directory is `{workspace_root}/re/analysis/algorithm/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_algorithm::persist::AlgorithmPersistor;
/// use calxgloss_algorithm::types::{AlgorithmRecognitionResult, ScanMetadata};
///
/// # fn main() -> calxgloss_algorithm::Result<()> {
/// let persistor = AlgorithmPersistor::new("/path/to/workspace");
/// let result = AlgorithmRecognitionResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct AlgorithmPersistor {
    store: JsonStore<AlgorithmRecognitionResult>,
}

impl AlgorithmPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace_root>/re/analysis/algorithm/`.
    pub fn new(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace_root).join("algorithm")),
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
    /// This is the cache check: a caller that wants recognized algorithms
    /// without re-running the scan asks here first and only drives
    /// [`AlgorithmEngine`](crate::engine::AlgorithmEngine) when the answer
    /// is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a recognition result to JSON, keyed on its metadata's binary
    /// name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the result, and writes it to disk — a rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &AlgorithmRecognitionResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            hints = result.hints.len(),
            "Saving algorithm recognition result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the recognition result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`AlgorithmError::NotFound`] if no result is persisted for
    /// `binary`, or [`AlgorithmError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<AlgorithmRecognitionResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Algorithm recognition result file not found");
            return Err(AlgorithmError::NotFound { path });
        }
        info!(path = %path.display(), "Loading algorithm recognition result");

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
        AlgorithmCategory, AlgorithmHint, AlgorithmRecognitionResult, Confidence, DetectionMethod,
        ScanMetadata,
    };
    use tempfile::TempDir;

    /// A result carrying hints from different detectors, so a round trip
    /// proves every hint shape survives the file, not just the envelope.
    fn result(binary: &str) -> AlgorithmRecognitionResult {
        AlgorithmRecognitionResult {
            metadata: ScanMetadata {
                binary: binary.to_string(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            hints: vec![
                AlgorithmHint {
                    function: "FUN_18003ab00".into(),
                    algorithm: "comparison_sort".into(),
                    category: AlgorithmCategory::Sorting,
                    method: DetectionMethod::CfgPattern,
                    confidence: Confidence::new(60),
                    evidence: "for (local_10 = 0; local_10 < uVar2; local_10 = local_10 + 1)"
                        .into(),
                },
                AlgorithmHint {
                    function: "FUN_18003e750".into(),
                    algorithm: "crc".into(),
                    category: AlgorithmCategory::Checksum,
                    method: DetectionMethod::StringHint,
                    confidence: Confidence::new(30),
                    evidence: "crc_table".into(),
                },
            ],
        }
    }

    #[test]
    fn save_then_load_round_trips_every_hint() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());
        let saved = result("eqmain.dll");

        persistor.save(&saved).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded, saved);
        assert_eq!(loaded.hints[0].algorithm, "comparison_sort");
        assert_eq!(loaded.hints[1].confidence, Confidence::new(30));
        assert_eq!(loaded.for_function("FUN_18003e750").count(), 1);
    }

    #[test]
    fn new_files_results_under_re_analysis_algorithm() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::new(dir.path());

        persistor.save(&result("eqmain.dll")).unwrap();

        let expected = dir
            .path()
            .join("re")
            .join("analysis")
            .join("algorithm")
            .join("eqmain.dll.json");
        assert!(
            expected.is_file(),
            "the whole directory chain should be created"
        );
    }

    #[test]
    fn with_cache_dir_files_results_directly_under_the_given_path() {
        let dir = TempDir::new().unwrap();
        let cache = dir.path().join("custom").join("cache");
        let persistor = AlgorithmPersistor::with_cache_dir(&cache);

        persistor.save(&result("eqgame.exe")).unwrap();

        assert!(cache.join("eqgame.exe.json").is_file());
        assert!(
            !dir.path().join("re").exists(),
            "no workspace layout is built"
        );
    }

    #[test]
    fn path_for_names_the_file_after_the_binary() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::new(dir.path());

        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("algorithm")
                .join("eqmain.dll.json")
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed_json() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());

        persistor.save(&result("eqmain.dll")).unwrap();

        let text = std::fs::read_to_string(dir.path().join("eqmain.dll.json")).unwrap();
        assert!(
            text.contains("\n  \"metadata\""),
            "expected pretty JSON: {text}"
        );
    }

    #[test]
    fn exists_tracks_whether_a_result_is_persisted() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());

        assert!(!persistor.exists("eqmain.dll"));
        persistor.save(&result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("renderer.dll"));
    }

    #[test]
    fn loading_a_missing_result_names_the_path() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();

        assert!(
            matches!(&err, AlgorithmError::NotFound { path } if path.ends_with("eqmain.dll.json")),
            "{err}"
        );
        assert!(err.to_string().contains("eqmain.dll.json"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_result() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());
        persistor.save(&result("eqmain.dll")).unwrap();

        let mut fresh = result("eqmain.dll");
        fresh.metadata.scanned_at += 60;
        fresh.hints.clear();
        persistor.save(&fresh).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded, fresh);
    }

    #[test]
    fn results_for_two_binaries_stay_independent() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());

        persistor.save(&result("eqmain.dll")).unwrap();
        persistor.save(&result("renderer.dll")).unwrap();

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
        let persistor = AlgorithmPersistor::with_cache_dir(dir.path());
        std::fs::write(dir.path().join("eqmain.dll.json"), "{ not json").unwrap();

        assert!(matches!(
            persistor.load("eqmain.dll"),
            Err(AlgorithmError::Json(_))
        ));
    }
}

//! JSON persistence for type inference results.
//!
//! The [`TypeInferPersistor`] saves and loads the per-binary
//! [`TypeInferenceResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/typeinfer/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is the
//! check a caller runs before deciding whether a scan is needed, and
//! [`load`](Self::load) reads the whole document back — metadata and every
//! surviving inference — for the translation pipeline to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{Result, TypeInferError};
use crate::types::TypeInferenceResult;

/// Saves and loads the per-binary inference result as JSON.
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
/// The default cache directory is `{workspace_root}/re/analysis/typeinfer/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_typeinfer::persist::TypeInferPersistor;
/// use calxgloss_typeinfer::types::{ScanMetadata, TypeInferenceResult};
///
/// # fn main() -> calxgloss_typeinfer::Result<()> {
/// let persistor = TypeInferPersistor::new("/path/to/workspace");
/// let result = TypeInferenceResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct TypeInferPersistor {
    store: JsonStore<TypeInferenceResult>,
}

impl TypeInferPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace_root>/re/analysis/typeinfer/`.
    pub fn new(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace_root).join("typeinfer")),
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
    /// This is the cache check: a caller that wants inferred types without
    /// re-running the scan asks here first and only drives
    /// [`TypeInferEngine`](crate::engine::TypeInferEngine) when the answer is
    /// `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves an inference result to JSON, keyed on its metadata's binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the result, and writes it to disk — a rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &TypeInferenceResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            inferences = result.inferences.len(),
            "Saving type inference result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the inference result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`TypeInferError::NotFound`] if no result is persisted for
    /// `binary`, or [`TypeInferError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<TypeInferenceResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Type inference result file not found");
            return Err(TypeInferError::NotFound { path });
        }
        info!(path = %path.display(), "Loading type inference result");

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
        Confidence, InferenceMethod, InferenceScope, InferredCallType, InferredLocalType,
        InferredParamType, InferredType, ScanMetadata, TypeInferenceResult,
    };
    use tempfile::TempDir;

    /// A result with one record of every inference kind, so a round trip
    /// proves each kind survives the file, not just the envelope.
    fn result(binary: &str) -> TypeInferenceResult {
        TypeInferenceResult {
            metadata: ScanMetadata {
                binary: binary.to_string(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            inferences: vec![
                InferredType::Param(InferredParamType {
                    function: "FUN_18003ab00".into(),
                    param_index: 0,
                    param_name: Some("param_1".into()),
                    inferred_type: "Widget *".into(),
                    method: InferenceMethod::VtableCall,
                    scope: InferenceScope::Class,
                    confidence: Confidence::new(85),
                    evidence: "(*(code *)(**param_1))[3](param_1)".into(),
                }),
                InferredType::Local(InferredLocalType {
                    function: "FUN_18003ab00".into(),
                    variable_name: "local_8".into(),
                    inferred_type: "char *".into(),
                    method: InferenceMethod::KnownSignature,
                    scope: InferenceScope::Function,
                    confidence: Confidence::new(60),
                    evidence: "local_8 = (char *)malloc(0x10);".into(),
                }),
                InferredType::CallSite(InferredCallType {
                    function: "FUN_1800412a0".into(),
                    callee: "CloseHandle".into(),
                    arg_index: 0,
                    arg_name: Some("param_2".into()),
                    inferred_type: "void *".into(),
                    method: InferenceMethod::KnownSignature,
                    scope: InferenceScope::Program,
                    confidence: Confidence::new(75),
                    evidence: "CloseHandle(param_2);".into(),
                }),
            ],
        }
    }

    #[test]
    fn save_then_load_round_trips_every_inference_kind() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());
        let saved = result("eqmain.dll");

        persistor.save(&saved).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded, saved);
        assert_eq!(loaded.inferences[0].inferred_type(), "Widget *");
        assert_eq!(loaded.inferences[1].confidence(), Confidence::new(60));
        assert_eq!(loaded.for_function("FUN_1800412a0").count(), 1);
    }

    #[test]
    fn new_files_results_under_re_analysis_typeinfer() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::new(dir.path());

        persistor.save(&result("eqmain.dll")).unwrap();

        let expected = dir
            .path()
            .join("re")
            .join("analysis")
            .join("typeinfer")
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
        let persistor = TypeInferPersistor::with_cache_dir(&cache);

        persistor.save(&result("eqgame.exe")).unwrap();

        assert!(cache.join("eqgame.exe.json").is_file());
        assert!(!dir.path().join("re").exists(), "no workspace layout is built");
    }

    #[test]
    fn path_for_names_the_file_after_the_binary() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::new(dir.path());

        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("typeinfer")
                .join("eqmain.dll.json")
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed_json() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());

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
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());

        assert!(!persistor.exists("eqmain.dll"));
        persistor.save(&result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("renderer.dll"));
    }

    #[test]
    fn loading_a_missing_result_names_the_path() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();

        assert!(
            matches!(&err, TypeInferError::NotFound { path } if path.ends_with("eqmain.dll.json")),
            "{err}"
        );
        assert!(err.to_string().contains("eqmain.dll.json"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_result() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());
        persistor.save(&result("eqmain.dll")).unwrap();

        let mut fresh = result("eqmain.dll");
        fresh.metadata.scanned_at += 60;
        fresh.inferences.clear();
        persistor.save(&fresh).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded, fresh);
    }

    #[test]
    fn results_for_two_binaries_stay_independent() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());

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
        let persistor = TypeInferPersistor::with_cache_dir(dir.path());
        std::fs::write(dir.path().join("eqmain.dll.json"), "{ not json").unwrap();

        assert!(matches!(
            persistor.load("eqmain.dll"),
            Err(TypeInferError::Json(_))
        ));
    }
}

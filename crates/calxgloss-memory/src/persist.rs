//! JSON persistence for memory lifecycle detection results.
//!
//! The [`MemoryPersistor`] saves and loads the per-binary
//! [`MemoryResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/memory/
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

use crate::error::{MemoryError, Result};
use crate::types::MemoryResult;

/// Saves and loads the per-binary memory lifecycle result as JSON.
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
/// The default cache directory is `{workspace_root}/re/analysis/memory/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_memory::persist::MemoryPersistor;
/// use calxgloss_memory::types::{MemoryResult, ScanMetadata};
///
/// # fn main() -> calxgloss_memory::Result<()> {
/// let persistor = MemoryPersistor::new("/path/to/workspace");
/// let result = MemoryResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct MemoryPersistor {
    store: JsonStore<MemoryResult>,
}

impl MemoryPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace_root>/re/analysis/memory/`.
    pub fn new(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace_root).join("memory")),
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
    /// This is the cache check: a caller that wants memory lifecycle
    /// findings without re-running the scan asks here first and only
    /// drives the scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a memory lifecycle result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the result, and writes it to disk — a rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &MemoryResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving memory lifecycle result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the memory lifecycle result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`MemoryError::NotFound`] if no result is persisted for
    /// `binary`, or [`MemoryError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<MemoryResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Memory lifecycle result file not found");
            return Err(MemoryError::NotFound { path });
        }
        info!(path = %path.display(), "Loading memory lifecycle result");

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
        AllocationType, Confidence, CountStyle, HandleLifecycle, HandleType, MemoryFinding,
        MemoryHint, MemoryResult, ReferenceCount, ScanMetadata,
    };
    use tempfile::TempDir;

    /// A result carrying one finding of every kind, so a round trip
    /// proves every record shape survives the file, not just the
    /// envelope.
    fn result(binary: &str) -> MemoryResult {
        MemoryResult {
            metadata: ScanMetadata {
                binary: binary.to_string(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
            },
            findings: vec![
                MemoryFinding::Allocation(MemoryHint {
                    function: "FUN_18003ab00".into(),
                    allocation_type: AllocationType::Malloc,
                    suggestion: "Box<T>".into(),
                    confidence: Confidence::new(70),
                    evidence: "pvVar1 = malloc(0x20); free(pvVar1);".into(),
                }),
                MemoryFinding::Handle(HandleLifecycle {
                    function: "FUN_18003ab00".into(),
                    handle_type: HandleType::KernelObject,
                    opener: "CreateFileW".into(),
                    closer: "CloseHandle".into(),
                    suggestion: "RAII guard struct with Drop impl".into(),
                    confidence: Confidence::new(65),
                    evidence: "hFile = CreateFileW(&DAT_3801a2b0,0xc0000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,0); CloseHandle(hFile);".into(),
                }),
                MemoryFinding::RefCount(ReferenceCount {
                    function: "FUN_18003e750".into(),
                    style: CountStyle::ComMethods,
                    increment: "AddRef".into(),
                    decrement: "Release".into(),
                    suggestion: "Rc<T>".into(),
                    confidence: Confidence::new(70),
                    evidence: "AddRef((IUnknown *)param_1); Release((IUnknown *)param_1);".into(),
                }),
            ],
        }
    }

    #[test]
    fn save_then_load_round_trips_every_finding() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());
        let saved = result("eqmain.dll");

        persistor.save(&saved).expect("save should succeed");
        let loaded = persistor
            .load("eqmain.dll")
            .expect("load should succeed after a save");

        assert_eq!(loaded, saved);
        assert_eq!(loaded.findings[0].kind(), "allocation");
        assert_eq!(loaded.findings[1].confidence(), Confidence::new(65));
        assert_eq!(loaded.for_function("FUN_18003e750").count(), 1);
    }

    #[test]
    fn new_files_results_under_re_analysis_memory() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::new(dir.path());

        persistor
            .save(&result("eqmain.dll"))
            .expect("save should succeed");

        let expected = dir
            .path()
            .join("re")
            .join("analysis")
            .join("memory")
            .join("eqmain.dll.json");
        assert!(
            expected.is_file(),
            "the whole directory chain should be created"
        );
    }

    #[test]
    fn with_cache_dir_files_results_directly_under_the_given_path() {
        let dir = TempDir::new().expect("temp dir should be created");
        let cache = dir.path().join("custom").join("cache");
        let persistor = MemoryPersistor::with_cache_dir(&cache);

        persistor
            .save(&result("eqgame.exe"))
            .expect("save should succeed");

        assert!(cache.join("eqgame.exe.json").is_file());
        assert!(
            !dir.path().join("re").exists(),
            "no workspace layout is built"
        );
    }

    #[test]
    fn path_for_names_the_file_after_the_binary() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::new(dir.path());

        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("memory")
                .join("eqmain.dll.json")
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed_json() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());

        persistor
            .save(&result("eqmain.dll"))
            .expect("save should succeed");

        let text = std::fs::read_to_string(dir.path().join("eqmain.dll.json"))
            .expect("the saved document should be readable");
        assert!(
            text.contains("\n  \"metadata\""),
            "expected pretty JSON: {text}"
        );
    }

    #[test]
    fn exists_tracks_whether_a_result_is_persisted() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());

        assert!(!persistor.exists("eqmain.dll"));
        persistor
            .save(&result("eqmain.dll"))
            .expect("save should succeed");
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("renderer.dll"));
    }

    #[test]
    fn loading_a_missing_result_names_the_path() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();

        assert!(
            matches!(&err, MemoryError::NotFound { path } if path.ends_with("eqmain.dll.json")),
            "{err}"
        );
        assert!(err.to_string().contains("eqmain.dll.json"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_result() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());
        persistor
            .save(&result("eqmain.dll"))
            .expect("save should succeed");

        let mut fresh = result("eqmain.dll");
        fresh.metadata.scanned_at += 60;
        fresh.findings.clear();
        persistor
            .save(&fresh)
            .expect("a rescan should replace the document");

        let loaded = persistor
            .load("eqmain.dll")
            .expect("load should succeed after a save");
        assert_eq!(loaded, fresh);
    }

    #[test]
    fn results_for_two_binaries_stay_independent() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());

        persistor
            .save(&result("eqmain.dll"))
            .expect("save should succeed");
        persistor
            .save(&result("renderer.dll"))
            .expect("save should succeed");

        assert_eq!(
            persistor
                .load("eqmain.dll")
                .expect("load should succeed after a save")
                .metadata
                .binary,
            "eqmain.dll"
        );
        assert_eq!(
            persistor
                .load("renderer.dll")
                .expect("load should succeed after a save")
                .metadata
                .binary,
            "renderer.dll"
        );
    }

    #[test]
    fn a_corrupt_document_is_refused_as_a_json_error() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = MemoryPersistor::with_cache_dir(dir.path());
        std::fs::write(dir.path().join("eqmain.dll.json"), "{ not json")
            .expect("the corrupt document should be writable");

        assert!(matches!(
            persistor.load("eqmain.dll"),
            Err(MemoryError::Json(_))
        ));
    }
}

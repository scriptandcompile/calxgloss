//! JSON persistence for concurrency detection results.
//!
//! The [`SyncPersistor`] saves and loads the per-binary [`SyncResult`] as
//! one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/sync/
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

use crate::error::{Result, SyncError};
use crate::types::SyncResult;

/// Saves and loads the per-binary concurrency result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/sync/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir) points
/// the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_sync::persist::SyncPersistor;
/// use calxgloss_sync::types::{ScanMetadata, SyncResult};
///
/// # fn main() -> calxgloss_sync::Result<()> {
/// let persistor = SyncPersistor::new("/path/to/workspace");
/// let result = SyncResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct SyncPersistor {
    store: JsonStore<SyncResult>,
}

impl SyncPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/sync/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("sync")),
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
    /// This is the cache check: a caller that wants concurrency findings
    /// without re-running the scan asks here first and only drives the
    /// scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a concurrency result to JSON, keyed on its metadata's binary
    /// name.
    ///
    /// Creates the cache directory hierarchy if it does not exist, serializes
    /// the result, and writes it to disk — a rescan replaces the previous
    /// document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &SyncResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving concurrency result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the concurrency result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::NotFound`] if no result is persisted for
    /// `binary`, or [`SyncError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<SyncResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Concurrency result file not found");
            return Err(SyncError::NotFound { path });
        }
        info!(path = %path.display(), "Loading concurrency result");

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
        AtomicOperation, ConcurrencyHint, Confidence, ScanMetadata, SyncFinding, SyncType,
        ThreadSpawn,
    };
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> SyncResult {
        let mut result = SyncResult::new(ScanMetadata::new(binary));
        result.findings.push(SyncFinding::Mutex(ConcurrencyHint {
            function: "LockObject".to_string(),
            sync_type: SyncType::StdMutex,
            acquire: "EnterCriticalSection".to_string(),
            release: "LeaveCriticalSection".to_string(),
            suggestion: "std::sync::Mutex<T>".to_string(),
            confidence: Confidence::new(70),
            evidence: "EnterCriticalSection(&gCrit);".to_string(),
        }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded.metadata.binary, "eqmain.dll");
        assert_eq!(loaded.findings.len(), 1);
        match &loaded.findings[0] {
            SyncFinding::Mutex(f) => {
                assert_eq!(f.function, "LockObject");
                assert_eq!(f.acquire, "EnterCriticalSection");
                assert_eq!(f.release, "LeaveCriticalSection");
            }
            other => panic!("expected a mutex finding, got {other:?}"),
        }
    }

    #[test]
    fn results_are_filed_under_re_analysis_sync_in_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("re/analysis/sync/eqmain.dll.json");
        assert_eq!(
            SyncPersistor::new(dir.path()).path_for("eqmain.dll"),
            expected
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path().join("missing/nested"));
        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.path_for("eqmain.dll").exists());
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(raw.contains('\n'), "document should be pretty-printed");
        assert!(raw.contains("\"acquire\""));
    }

    #[test]
    fn exists_is_the_cache_check() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());
        assert!(!persistor.exists("eqmain.dll"));

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(persistor.exists("eqmain.dll"));
        assert!(!persistor.exists("other.dll"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let mut second = sample_result("eqmain.dll");
        second.findings.push(SyncFinding::Atomic(AtomicOperation {
            function: "BumpCounter".to_string(),
            operation: "InterlockedIncrement".to_string(),
            suggestion: "std::sync::atomic::AtomicU32".to_string(),
            confidence: Confidence::new(70),
            evidence: "InterlockedIncrement(&gCount);".to_string(),
        }));
        persistor.save(&second).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        assert_eq!(loaded.findings.len(), 2);
    }

    #[test]
    fn loading_a_missing_result_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        match err {
            SyncError::NotFound { path } => {
                assert!(path.to_string_lossy().contains("eqmain.dll.json"));
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());
        std::fs::create_dir_all(persistor.path_for("eqmain.dll").parent().unwrap()).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(
            matches!(err, SyncError::Json(_)),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("custom-cache");
        let persistor = SyncPersistor::with_cache_dir(&cache);

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        assert!(cache.join("eqmain.dll.json").exists());
    }

    #[test]
    fn thread_spawn_findings_survive_the_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = SyncPersistor::new(dir.path());

        let mut result = SyncResult::new(ScanMetadata::new("eqmain.dll"));
        result.findings.push(SyncFinding::Thread(ThreadSpawn {
            function: "StartWorker".to_string(),
            spawn: "CreateThread".to_string(),
            join: Some("WaitForSingleObject".to_string()),
            suggestion: "std::thread::spawn".to_string(),
            confidence: Confidence::new(70),
            evidence: "hThread = CreateThread(...);".to_string(),
        }));
        persistor.save(&result).unwrap();

        let loaded = persistor.load("eqmain.dll").unwrap();
        match &loaded.findings[0] {
            SyncFinding::Thread(t) => {
                assert_eq!(t.join.as_deref(), Some("WaitForSingleObject"));
                assert_eq!(t.spawn, "CreateThread");
            }
            other => panic!("expected a thread finding, got {other:?}"),
        }
    }

    #[test]
    fn persist_errors_map_onto_sync_errors() {
        let mapped = SyncError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/sync/eqmain.dll.json"),
        });
        assert!(matches!(mapped, SyncError::NotFound { .. }));
    }
}

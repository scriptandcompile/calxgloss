//! JSON persistence for known-library identification results.
//!
//! The [`LibmatchPersistor`] saves and loads the per-binary
//! [`LibmatchResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/libmatch/
//!     └── {binary}.json
//! ```
//!
//! A persisted result doubles as a cache: [`exists`](Self::exists) is
//! the check a caller runs before deciding whether a scan is needed, and
//! [`load`](Self::load) reads the whole document back — metadata and
//! every finding — for the call graph and translation pipeline to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{LibmatchError, Result};
use crate::types::LibmatchResult;

/// Saves and loads the per-binary known-library identification result
/// as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/libmatch/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_libmatch::persist::LibmatchPersistor;
/// use calxgloss_libmatch::types::{LibmatchResult, ScanMetadata};
///
/// # fn main() -> calxgloss_libmatch::Result<()> {
/// let persistor = LibmatchPersistor::new("/path/to/workspace");
/// let result = LibmatchResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct LibmatchPersistor {
    store: JsonStore<LibmatchResult>,
}

impl LibmatchPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/libmatch/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("libmatch")),
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
    /// This is the cache check: a caller that wants known-library
    /// findings without re-running the scan asks here first and only
    /// drives the scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves a known-library identification result to JSON, keyed on its
    /// metadata's binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan replaces
    /// the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &LibmatchResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving known-library identification result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the known-library identification result persisted for
    /// `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`LibmatchError::NotFound`] if no result is persisted for
    /// `binary`, or [`LibmatchError::Json`] if the document is corrupt.
    pub fn load(&self, binary: &str) -> Result<LibmatchResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Known-library identification result file not found");
            return Err(LibmatchError::NotFound { path });
        }
        info!(path = %path.display(), "Loading known-library identification result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, LibmatchFinding, LibmatchMatch, LibraryFamily, ScanMetadata};
    use tempfile::TempDir;

    /// A result carrying one finding, so a round trip proves the record
    /// shape survives the file, not just the envelope.
    fn result(binary: &str) -> LibmatchResult {
        LibmatchResult {
            metadata: ScanMetadata {
                binary: binary.to_string(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
                coverage: None,
            },
            findings: vec![LibmatchFinding::BodySignature(LibmatchMatch {
                function: "FUN_18003ab00".into(),
                symbol: "memcpy".into(),
                family: LibraryFamily::Crt,
                suggestion: "slice copy — `copy_nonoverlapping`".into(),
                confidence: Confidence::new(60),
                evidence: "*(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);"
                    .into(),
            })],
        }
    }

    #[test]
    fn save_then_load_round_trips_every_finding() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());
        let saved = result("eqmain.dll");

        persistor.save(&saved).expect("save should succeed");
        let loaded = persistor
            .load("eqmain.dll")
            .expect("load should succeed after a save");

        assert_eq!(loaded, saved);
        assert_eq!(loaded.findings[0].kind(), "body_signature");
        assert_eq!(loaded.findings[0].confidence(), Confidence::new(60));
        assert_eq!(loaded.for_function("FUN_18003ab00").count(), 1);
    }

    #[test]
    fn propagated_findings_persist_in_the_same_document_with_their_own_confidence() {
        // The cross-function findings ride the per-binary document
        // beside the direct match, each keeping its own confidence.
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());
        let mut saved = result("eqmain.dll");
        saved
            .findings
            .push(LibmatchFinding::IdenticalBody(LibmatchMatch {
                function: "thunk_FUN_180098765".into(),
                symbol: "memcpy".into(),
                family: LibraryFamily::Crt,
                suggestion: "slice copy — `copy_nonoverlapping`".into(),
                confidence: Confidence::new(60),
                evidence: "*(undefined8 *)((long)puVar7 + -8) = *(undefined8 *)((long)lVar9 + -8);"
                    .into(),
            }));
        saved
            .findings
            .push(LibmatchFinding::TailCallThunk(LibmatchMatch {
                function: "FUN_180099999".into(),
                symbol: "memcpy".into(),
                family: LibraryFamily::Crt,
                suggestion: "slice copy — `copy_nonoverlapping`".into(),
                confidence: Confidence::new(50),
                evidence: "return FUN_18003ab00(param_1, param_2, param_3);".into(),
            }));

        persistor.save(&saved).expect("save should succeed");
        let loaded = persistor
            .load("eqmain.dll")
            .expect("load should succeed after a save");

        assert_eq!(loaded, saved);
        let kinds: Vec<&str> = loaded.findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            ["body_signature", "identical_body", "tail_call_thunk"]
        );
        assert_eq!(
            loaded.findings[2].confidence(),
            Confidence::new(50),
            "the thunk keeps its penalized score through the file"
        );
    }

    #[test]
    fn new_files_results_under_re_analysis_libmatch() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = LibmatchPersistor::new(dir.path());

        persistor
            .save(&result("eqmain.dll"))
            .expect("save should succeed");

        let expected = dir
            .path()
            .join("re")
            .join("analysis")
            .join("libmatch")
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
        let persistor = LibmatchPersistor::with_cache_dir(&cache);

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
        let persistor = LibmatchPersistor::new(dir.path());

        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("libmatch")
                .join("eqmain.dll.json")
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed_json() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());

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
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());

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
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();

        assert!(
            matches!(&err, LibmatchError::NotFound { path } if path.ends_with("eqmain.dll.json")),
            "{err}"
        );
        assert!(err.to_string().contains("eqmain.dll.json"));
    }

    #[test]
    fn a_rescan_replaces_the_previous_result() {
        let dir = TempDir::new().expect("temp dir should be created");
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());
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
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());

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
        let persistor = LibmatchPersistor::with_cache_dir(dir.path());
        std::fs::write(dir.path().join("eqmain.dll.json"), "{ not json")
            .expect("the corrupt document should be writable");

        assert!(matches!(
            persistor.load("eqmain.dll"),
            Err(LibmatchError::Json(_))
        ));
    }
}

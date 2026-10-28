//! JSON persistence for error-handling evidence findings.
//!
//! The [`ErrhandlingPersistor`] saves and loads the per-binary
//! [`ErrhandlingResult`] as one pretty-printed JSON document per binary:
//!
//! ```text
//! re/analysis/errhandling/
//!     └── {binary}.json
//! ```
//!
//! A persisted result also serves as a cache:
//! [`exists`](ErrhandlingPersistor::exists) is the check a caller
//! runs before deciding whether the scan needs to run, and
//! [`load`](ErrhandlingPersistor::load) reads the whole document
//! back — metadata and every finding — for the follow-up P15 tickets
//! to query.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{ErrhandlingError, Result};
use crate::types::ErrhandlingResult;

/// Saves and loads the per-binary error-handling evidence result as JSON.
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
/// The default cache directory is `{workspace}/re/analysis/errhandling/`,
/// set by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_errhandling::{ErrhandlingPersistor, ErrhandlingResult};
/// use calxgloss_types::ScanMetadata;
///
/// # fn main() -> calxgloss_errhandling::Result<()> {
/// let persistor = ErrhandlingPersistor::new("/path/to/workspace");
/// let result = ErrhandlingResult::new(ScanMetadata::new("eqmain.dll"));
/// persistor.save(&result)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct ErrhandlingPersistor {
    store: JsonStore<ErrhandlingResult>,
}

impl ErrhandlingPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Results are stored in `<workspace>/re/analysis/errhandling/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("errhandling")),
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
    /// This is the cache check: a caller that wants error-handling
    /// findings without re-running the scan asks here first and only
    /// drives the scan when the answer is `false`.
    pub fn exists(&self, binary: &str) -> bool {
        self.store.exists(binary)
    }

    /// Saves an error-handling result to JSON, keyed on its metadata's
    /// binary name.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the result, and writes it to disk — a rescan
    /// replaces the previous document for the same binary.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, result: &ErrhandlingResult) -> Result<()> {
        let path = self.path_for(&result.metadata.binary);
        info!(
            path = %path.display(),
            findings = result.findings.len(),
            "Saving error-handling evidence result"
        );

        self.store.save(&result.metadata.binary, result)?;
        Ok(())
    }

    /// Loads the error-handling evidence result persisted for `binary`.
    ///
    /// # Errors
    ///
    /// Returns [`ErrhandlingError::NotFound`] if no result is
    /// persisted for `binary`, or [`ErrhandlingError::Json`] if the
    /// document is corrupt.
    pub fn load(&self, binary: &str) -> Result<ErrhandlingResult> {
        let path = self.path_for(binary);
        if !self.store.exists(binary) {
            warn!(path = %path.display(), "Error-handling result file not found");
            return Err(ErrhandlingError::NotFound { path });
        }
        info!(path = %path.display(), "Loading error-handling evidence result");

        Ok(self.store.load(binary)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seh_frame::{SEH_FRAME_SUGGESTION, SPELLED_FRAME_CONFIDENCE};
    use crate::types::{ErrhandlingFinding, SehFrame};
    use calxgloss_types::Confidence;
    use calxgloss_types::persist::PersistError;

    fn sample_result(binary: &str) -> ErrhandlingResult {
        let mut result = ErrhandlingResult::new(calxgloss_types::ScanMetadata::new(binary));
        result.findings.push(ErrhandlingFinding::SehFrame(SehFrame {
            function: "FUN_1800014a0".to_string(),
            confidence: Confidence::new(SPELLED_FRAME_CONFIDENCE),
            evidence: "  catch(...){".to_string(),
            suggestion: SEH_FRAME_SUGGESTION.to_string(),
        }));
        result
    }

    #[test]
    fn save_then_load_round_trips_the_document() {
        let dir = tempfile::tempdir().unwrap();
        let persistor = ErrhandlingPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();
        let loaded = persistor.load("eqmain.dll").unwrap();

        assert_eq!(loaded, sample_result("eqmain.dll"));
    }

    #[test]
    fn the_finding_lands_under_the_errhandling_analysis_directory() {
        // ADR-0043's per-binary layout, asserted at the seam so every
        // consumer of the persisted document finds it where the
        // catalog says: `re/analysis/errhandling/<binary>.json`.
        let dir = tempfile::tempdir().unwrap();
        let persistor = ErrhandlingPersistor::new(dir.path());

        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let path = dir.path().join("re/analysis/errhandling/eqmain.dll.json");
        assert!(
            path.exists(),
            "the document must land at {}",
            path.display()
        );
        assert!(persistor.exists("eqmain.dll"));
    }

    #[test]
    fn the_serde_kind_tag_names_the_finding_in_json() {
        // The tagged union spells its kind in the document, so the
        // follow-up families extend the artifact without a reader
        // having to guess which record is which.
        let dir = tempfile::tempdir().unwrap();
        let persistor = ErrhandlingPersistor::new(dir.path());
        persistor.save(&sample_result("eqmain.dll")).unwrap();

        let raw = std::fs::read_to_string(persistor.path_for("eqmain.dll")).unwrap();
        assert!(
            raw.contains("\"kind\": \"seh_frame\""),
            "the serde kind tag must name the finding kind: {raw}"
        );
    }

    #[test]
    fn loading_a_never_saved_binary_is_a_not_found_error() {
        // A missing document must not read as an empty scan — the
        // no-findings case is a claim; a never-scanned binary says
        // nothing.
        let dir = tempfile::tempdir().unwrap();
        let persistor = ErrhandlingPersistor::new(dir.path());

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(matches!(err, ErrhandlingError::NotFound { .. }));
    }

    #[test]
    fn a_corrupt_document_is_a_json_error_not_a_not_found() {
        // The two failure kinds mean different things to the CLI:
        // one says scan it, the other says the artifact is broken.
        let dir = tempfile::tempdir().unwrap();
        let persistor = ErrhandlingPersistor::new(dir.path());
        std::fs::create_dir_all(dir.path().join("re/analysis/errhandling")).unwrap();
        std::fs::write(persistor.path_for("eqmain.dll"), "{ this is not json").unwrap();

        let err = persistor.load("eqmain.dll").unwrap_err();
        assert!(matches!(err, ErrhandlingError::Json(_)), "got {err:?}");
    }

    #[test]
    fn the_store_error_maps_without_losing_its_kind() {
        // The shared store's not-found becomes this crate's
        // not-found, so the distinction the CLI reports on survives.
        let err: ErrhandlingError = PersistError::NotFound {
            path: PathBuf::from("re/analysis/errhandling/eqmain.dll.json"),
        }
        .into();
        assert!(matches!(err, ErrhandlingError::NotFound { .. }));
    }

    #[test]
    fn the_filed_document_carries_its_coverage_record_exactly() {
        // The coverage record the scan stamped passes through the
        // persistor untouched: statuses, ids, order, limitation
        // lines — exactly what a later reader (the projection seam,
        // the report, a `--show` months later) sees (issue #350).
        let dir = tempfile::tempdir().unwrap();
        let persistor = ErrhandlingPersistor::new(dir.path());
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

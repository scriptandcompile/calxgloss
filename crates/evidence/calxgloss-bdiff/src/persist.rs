//! JSON persistence for the pairing document.
//!
//! The [`BdiffPersistor`] saves and loads each [`PairingDocument`] as
//! one pretty-printed JSON document — one per (binary identity, old
//! bytes, new bytes), the exact triple the pairing pass computed for:
//!
//! ```text
//! re/analysis/bdiff/
//!     └── {binary}-{old-sha256}-{new-sha256}.json
//! ```
//!
//! The file key is the hash pair, and the document itself names both
//! hashes. A stale document — one left behind by a since-replaced
//! version — is therefore detectable twice over: it is not filed under
//! the live hash pair, and it says which pair it was computed for. A
//! persisted document doubles as a cache: [`exists`](BdiffPersistor::exists) is
//! the check a caller runs before deciding whether the pairing pass is
//! needed at all (the auto run's trigger, #298). This adds a new
//! directory under `re/analysis/`, so every previously persisted
//! artifact loads unchanged.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::error::{BdiffError, Result};
use crate::types::PairingDocument;

/// Saves and loads the per-version-pair pairing documents as JSON.
///
/// # File Layout
///
/// Documents are filed under a cache directory named for the version
/// pair they describe:
///
/// ```text
/// cache_dir/
///     └── {binary}-{old-sha256}-{new-sha256}.json
/// ```
///
/// The default cache directory is `{workspace}/re/analysis/bdiff/`, set
/// by [`new`](Self::new); [`with_cache_dir`](Self::with_cache_dir)
/// points the persistor at an explicit directory instead.
///
/// # Example
///
/// ```no_run
/// use calxgloss_bdiff::persist::BdiffPersistor;
///
/// # fn main() -> calxgloss_bdiff::Result<()> {
/// let persistor = BdiffPersistor::new("/path/to/workspace");
/// let key = BdiffPersistor::key_for("game_logic.dll", "old-hash", "new-hash");
/// if !persistor.exists(&key) {
///     // ... run the pairing pass and save its document:
///     // persistor.save(&document)?;
/// }
/// let document = persistor.load(&key)?;
/// assert_eq!(document.binary, "game_logic.dll");
/// # Ok(())
/// # }
/// ```
pub struct BdiffPersistor {
    store: JsonStore<PairingDocument>,
}

impl BdiffPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Documents are stored in `<workspace>/re/analysis/bdiff/`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(analysis_dir(workspace).join("bdiff")),
        }
    }

    /// Creates a new persistor with an explicit cache directory.
    ///
    /// Documents are stored directly under the provided `cache_dir`
    /// path.
    pub fn with_cache_dir(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::new(cache_dir),
        }
    }

    /// The document key for one (binary identity, old bytes, new bytes)
    /// triple — the key [`save`](Self::save) derives from a document
    /// and the key a caller composes to ask for a specific version
    /// pair. The hashes are full SHA-256 hex, so each key identifies
    /// exactly one version pair and a stale document can never be
    /// mistaken for a live one at the lookup.
    pub fn key_for(binary: &str, old_bytes_sha256: &str, new_bytes_sha256: &str) -> String {
        format!("{binary}-{old_bytes_sha256}-{new_bytes_sha256}")
    }

    /// Returns the path the document for `key` is filed under.
    pub fn path_for(&self, key: &str) -> PathBuf {
        self.store.path_for(key)
    }

    /// Whether a pairing document is persisted for `key`.
    ///
    /// This is the cache check: the auto run's trigger (#298) checks
    /// here before running the pairing pass at all, and reuses the
    /// persisted document when the answer is `true`.
    pub fn exists(&self, key: &str) -> bool {
        self.store.exists(key)
    }

    /// Saves a pairing document to JSON, keyed on the (binary, old
    /// hash, new hash) triple the document itself names.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the document, and writes it to disk — recomputing
    /// one version pair replaces that pair's document, and other pairs
    /// of the same binary each keep their own file.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, document: &PairingDocument) -> Result<()> {
        let key = Self::key_for(
            &document.binary,
            &document.old_bytes_sha256,
            &document.new_bytes_sha256,
        );
        let path = self.path_for(&key);
        info!(
            path = %path.display(),
            pairings = document.pairings.len(),
            "Saving binary-version pairing document"
        );

        self.store.save(&key, document)?;
        Ok(())
    }

    /// Loads the pairing document persisted for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`BdiffError::NotFound`] if no document is persisted for
    /// `key`, or [`BdiffError::Json`] if the document is corrupt.
    pub fn load(&self, key: &str) -> Result<PairingDocument> {
        let path = self.path_for(key);
        if !self.store.exists(key) {
            warn!(path = %path.display(), "Pairing document not found");
            return Err(BdiffError::NotFound { path });
        }
        info!(path = %path.display(), "Loading binary-version pairing document");

        Ok(self.store.load(key)?)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use calxgloss_types::{BinaryIdentity, Confidence};

    use super::*;
    use crate::engine::pair_versions;
    use crate::types::{FunctionEntry, MatchFamily, ScanSnapshot};

    fn function(name: &str, address: u64) -> FunctionEntry {
        FunctionEntry {
            name: name.into(),
            address,
            body: format!("// body of {name}"),
        }
    }

    fn snapshot(
        binary: &str,
        hash: &str,
        functions: Vec<FunctionEntry>,
        exports: &[&str],
    ) -> ScanSnapshot {
        ScanSnapshot {
            binary: BinaryIdentity::new(binary),
            bytes_sha256: hash.into(),
            functions,
            exports: exports.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    /// A real pairing document, produced by the pass itself, so the
    /// round-trip test pins the shipped shape rather than a
    /// hand-written copy.
    fn sample_pairing_document(binary: &str) -> PairingDocument {
        let old = snapshot(
            binary,
            "aaa",
            vec![
                function("fixture_init", 0x1000),
                function("FUN_10001200", 0x1200),
            ],
            &["fixture_init"],
        );
        let new = snapshot(
            binary,
            "bbb",
            vec![
                function("fixture_init", 0x4000),
                function("brand_new", 0x5000),
            ],
            &["fixture_init", "brand_new"],
        );
        pair_versions(&old, &new).expect("one identity")
    }

    #[test]
    fn save_then_load_round_trips_the_document_and_names_both_hashes() {
        // The pairing document goes through the shared JSON store
        // whole — records, families, confidences, evidence, listings.
        // The loaded copy still records the exact (old, new) byte pair
        // it was computed for, so staleness stays detectable after a
        // reload.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        let document = sample_pairing_document("game.dll");
        persistor.save(&document).expect("save should work");

        let key = BdiffPersistor::key_for("game.dll", "aaa", "bbb");
        let loaded = persistor.load(&key).expect("load should work");
        assert_eq!(loaded, document, "the document round-trips whole");
        assert_eq!(loaded.old_bytes_sha256, "aaa");
        assert_eq!(loaded.new_bytes_sha256, "bbb");
        assert_eq!(loaded.pairings.len(), 1);
        assert_eq!(loaded.pairings[0].confidence, Confidence::new(95));
        assert_eq!(loaded.pairings[0].family, MatchFamily::NameIdentity);
    }

    #[test]
    fn documents_are_filed_under_re_analysis_bdiff_in_the_workspace() {
        // The analysis-directory convention (ADR-0043's record
        // directories): this adds a new domain directory beside the
        // existing ones, so every previously persisted artifact loads
        // unchanged.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("save should work");

        let path = workspace
            .path()
            .join("re/analysis/bdiff/game.dll-aaa-bbb.json");
        assert!(path.is_file(), "filed under the analysis convention");
    }

    #[test]
    fn one_document_per_version_pair_stands_alone() {
        // Successive versions of one binary each keep their own
        // pairwise document: each step of a version chain is its own
        // file, and no pair overwrites another.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("first pair");

        let mut second = sample_pairing_document("game.dll");
        second.new_bytes_sha256 = "ccc".into();
        persistor.save(&second).expect("second pair");

        assert!(persistor.exists(&BdiffPersistor::key_for("game.dll", "aaa", "bbb")));
        assert!(persistor.exists(&BdiffPersistor::key_for("game.dll", "aaa", "ccc")));
        assert!(
            !persistor.exists(&BdiffPersistor::key_for("game.dll", "aaa", "gone")),
            "a hash pair the workspace no longer carries has no live document"
        );
    }

    #[test]
    fn save_creates_the_directory_hierarchy() {
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path().join("deep/nested/ws"));
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("save should create the chain");
        assert!(
            workspace
                .path()
                .join("deep/nested/ws/re/analysis/bdiff")
                .is_dir()
        );
    }

    #[test]
    fn the_saved_document_is_pretty_printed() {
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("save should work");
        let raw = std::fs::read_to_string(
            persistor.path_for(&BdiffPersistor::key_for("game.dll", "aaa", "bbb")),
        )
        .expect("the saved document should read back");
        assert!(raw.contains("\n  \"binary\": "), "pretty-printed JSON");
    }

    #[test]
    fn exists_is_the_cache_check() {
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        let key = BdiffPersistor::key_for("game.dll", "aaa", "bbb");
        assert!(!persistor.exists(&key));
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("save should work");
        assert!(persistor.exists(&key));
    }

    #[test]
    fn a_recompute_replaces_the_previous_document_for_one_pair() {
        // A recomputed pairing pass replaces the old document for the
        // same pair; the file count stays at one.
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("first save");
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("second save");

        let dir = workspace.path().join("re/analysis/bdiff");
        let entries: Vec<_> = std::fs::read_dir(&dir)
            .expect("cache dir readable")
            .collect();
        assert_eq!(entries.len(), 1, "one pair, one document");
    }

    #[test]
    fn loading_a_missing_document_reports_not_found() {
        let workspace = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(workspace.path());
        let error = persistor
            .load(&BdiffPersistor::key_for("game.dll", "aaa", "bbb"))
            .expect_err("nothing is persisted");
        assert!(matches!(error, BdiffError::NotFound { .. }));
    }

    #[test]
    fn loading_a_corrupt_document_reports_json_error() {
        let cache = tempfile::tempdir().expect("temp cache");
        let persistor = BdiffPersistor::with_cache_dir(cache.path());
        let key = BdiffPersistor::key_for("game.dll", "aaa", "bbb");
        std::fs::write(persistor.path_for(&key), "{ not json").expect("write junk");
        let error = persistor.load(&key).expect_err("junk is not a document");
        assert!(matches!(error, BdiffError::Json { .. }));
    }

    #[test]
    fn with_cache_dir_files_documents_directly_inside_it() {
        let cache = tempfile::tempdir().expect("temp cache");
        let persistor = BdiffPersistor::with_cache_dir(cache.path());
        persistor
            .save(&sample_pairing_document("game.dll"))
            .expect("save should work");
        assert!(cache.path().join("game.dll-aaa-bbb.json").is_file());
    }

    #[test]
    fn persist_errors_map_onto_bdiff_errors() {
        use calxgloss_types::persist::PersistError;
        let mapped = BdiffError::from(PersistError::NotFound {
            path: PathBuf::from("re/analysis/bdiff/game.dll-aaa-bbb.json"),
        });
        assert!(matches!(mapped, BdiffError::NotFound { .. }));
    }

    #[test]
    fn a_stale_document_is_detectable_from_its_named_hashes() {
        // The track's staleness contract (#298): a document loaded for
        // a version that has since been replaced still says which hash
        // pair it was computed for, so the consumer can refuse it.
        let document = sample_pairing_document("game.dll");
        let current_new_hash = "replaced-by-a-new-build";
        assert_ne!(
            document.new_bytes_sha256, current_new_hash,
            "the document names the pair it was computed for — a \
             mismatch against the live scan is the staleness signal"
        );
        let record = &document.pairings[0];
        assert_eq!(record.evidence, ["exported name fixture_init"]);
        let _ = record.old_function; // shape pin: records name both sides
    }
}

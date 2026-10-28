//! The P18 version-change trigger: pair one version's scan against every
//! surviving scan of the same binary (issue #298).
//!
//! The scan step writes its read cache under `re/cache/{identity}/{sha256}`
//! (ADR-0043), and when a binary's bytes change the previous version's
//! directory stays beside the new one — a surviving scan. Once the scan
//! step has written the current version's scan documents through, this
//! module pairs each surviving scan with the current one, exactly once per
//! (old, new) hash pair: it assembles both cached document sets into
//! [`ScanSnapshot`]s, [`pair_versions`] computes the pairing document, and
//! [`BdiffPersistor`] persists it keyed on that hash pair. A later run of
//! the same version finds the persisted document and reuses it instead of
//! recomputing, and a document that does not name the live (old, new) hash
//! pair is detected as stale and recomputed — never silently trusted.
//! Pairings stay pairwise (old→new); a longer version chain is covered by
//! a sequence of successive pairwise documents.
//!
//! The pass is document-level by construction: it reads only the scan
//! cache's own [`cached_functions`], [`cached_exports`], and [`cached_body`]
//! readers — no engine read anywhere (ADR-0026 untouched), no program
//! mutation (ADR-0020), and no LLM. It is deterministic and completes in
//! milliseconds. A binary that has never changed version has no sibling
//! hash directory, and this module writes nothing: the queue behaves
//! exactly as it does today.

use std::path::Path;

use calxgloss_bdiff::{BdiffPersistor, FunctionEntry, ScanSnapshot, pair_versions};
use calxgloss_decomp::{
    cache_root, cached_body, cached_exports, cached_functions, is_surviving_scan, sha256_of_file,
};
use calxgloss_types::BinaryIdentity;
use tracing::{debug, info, warn};

/// Pair the scan just warmed against every surviving scan of the same
/// binary identity, reusing pairing documents already persisted.
///
/// The pipeline's scan step calls this once per pass, after the pre-batch
/// evidence scans have written the current version's scan documents
/// through. Like the cache itself it degrades, never fails: a pairing
/// document is context a later consumer may use (the carry-over queue
/// step, #299), and nothing observed here — an unreadable binary, an
/// absent cache, an unreadable document, a failed save — ends a run whose
/// scans completed.
pub(crate) fn pair_previous_versions(workspace: &Path, binary: &str, binary_path: &Path) {
    let new_hash = match sha256_of_file(binary_path) {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            debug!(
                binary,
                path = %binary_path.display(),
                "the target binary is missing — there are no current bytes to pair"
            );
            return;
        }
        Err(err) => {
            warn!(
                binary,
                path = %binary_path.display(),
                %err,
                "could not hash the target binary — skipping version pairing"
            );
            return;
        }
    };

    let identity_dir = cache_root(workspace).join(binary);
    let Ok(entries) = std::fs::read_dir(&identity_dir) else {
        debug!(
            binary,
            "no scan cache identity directory — this binary has no surviving scan to pair"
        );
        return;
    };
    // Deterministic pairing order: directory iteration is not, and one
    // workspace's runs should compute (and log) the same documents in the
    // same order. The current version's own directory is not a sibling —
    // a scan never pairs against itself.
    let mut old_hashes: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            (entry.path().is_dir() && name != new_hash).then_some(name)
        })
        .collect();
    old_hashes.sort();

    let persistor = BdiffPersistor::new(workspace);
    let new_dir = identity_dir.join(&new_hash);
    for old_hash in old_hashes {
        let old_dir = identity_dir.join(&old_hash);
        if !is_surviving_scan(&old_dir) {
            // A cold or unusable sibling directory represents no scan:
            // nothing was read from it and nothing is written for it.
            continue;
        }
        pair_one_scan(&persistor, binary, &old_dir, &new_dir, &old_hash, &new_hash);
    }
}

/// Pair one (old, new) hash pair, reusing the persisted document when it
/// names this pair and running the pass exactly once when it does not.
fn pair_one_scan(
    persistor: &BdiffPersistor,
    binary: &str,
    old_dir: &Path,
    new_dir: &Path,
    old_hash: &str,
    new_hash: &str,
) {
    let key = BdiffPersistor::key_for(binary, old_hash, new_hash);
    if reusable_document(persistor, &key, binary, old_hash, new_hash) {
        return;
    }

    // The pairing pass reads these two cached scan document sets and
    // nothing else — no engine read (ADR-0026). A directory with no
    // readable function listing represents no scan: the sibling was
    // never warmed, or this run wrote no scan documents to disk while
    // its scans ran, and there is nothing to pair either way.
    let Some(old) = assemble_snapshot(old_dir, binary, old_hash) else {
        debug!(
            binary,
            old_hash, "the sibling scan directory holds no function listing — nothing to pair"
        );
        return;
    };
    let Some(new) = assemble_snapshot(new_dir, binary, new_hash) else {
        debug!(
            binary,
            new_hash, "this run's scan cache holds no function listing — nothing to pair against"
        );
        return;
    };

    match pair_versions(&old, &new) {
        Ok(document) => {
            if let Err(err) = persistor.save(&document) {
                warn!(binary, %err, "could not persist the pairing document");
            }
        }
        Err(err) => warn!(
            binary,
            old_hash, new_hash, %err,
            "the pairing pass failed — the queue behaves as if no pairing existed"
        ),
    }
}

/// Whether the persisted document at `key` can replace running the pass.
///
/// A document is trusted only when it names the live (old, new) hash pair
/// itself — the staleness rule of the carry-over track: documents are
/// filed under the live pair's key, and each document says which pair it
/// was computed for, so a file renamed or left behind by a since-replaced
/// version is detected here, logged, and recomputed rather than reused.
fn reusable_document(
    persistor: &BdiffPersistor,
    key: &str,
    binary: &str,
    old_hash: &str,
    new_hash: &str,
) -> bool {
    if !persistor.exists(key) {
        return false;
    }
    match persistor.load(key) {
        Ok(document)
            if document.binary == binary
                && document.old_bytes_sha256 == old_hash
                && document.new_bytes_sha256 == new_hash =>
        {
            info!(
                binary,
                old_hash,
                new_hash,
                pairings = document.pairings.len(),
                "reusing the persisted pairing document"
            );
            true
        }
        Ok(document) => {
            warn!(
                binary,
                old_hash,
                new_hash,
                documented_old = %document.old_bytes_sha256,
                documented_new = %document.new_bytes_sha256,
                "a persisted pairing document does not name the live hash pair — recomputing it"
            );
            false
        }
        Err(err) => {
            warn!(binary, %err, "the persisted pairing document is unreadable — recomputing it");
            false
        }
    }
}

/// Assemble one version's [`ScanSnapshot`] from the scan documents it kept.
///
/// The listing is kept in scan order (the order that breaks ties between
/// pairings), the names are kept verbatim (a name's spelling decides which
/// families may claim it), and each kept body is kept exactly as the scan
/// wrote it — the cache's raw engine text, before the noise filter (issue
/// #271). A function whose body document is missing simply carries a blank
/// body: it pairs through the name families it still qualifies for, exactly
/// as a blank kept body pairs nothing in the body family. `None` only when
/// the function listing itself is absent — without a listing there is no
/// scan here. A missing export listing leaves exports empty: exported-name
/// evidence then claims nothing, while demangled names still pair.
fn assemble_snapshot(dir: &Path, binary: &str, bytes_sha256: &str) -> Option<ScanSnapshot> {
    let listing = cached_functions(dir)?;
    let exports = cached_exports(dir)
        .unwrap_or_default()
        .into_iter()
        .map(|symbol| symbol.name)
        .collect();
    let functions = listing
        .into_iter()
        .map(|entry| FunctionEntry {
            body: cached_body(dir, &entry.name).unwrap_or_default(),
            name: entry.name,
            address: entry.address,
        })
        .collect();
    Some(ScanSnapshot {
        binary: BinaryIdentity::new(binary),
        bytes_sha256: bytes_sha256.to_string(),
        functions,
        exports,
    })
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use calxgloss_bdiff::{MatchFamily, PairingDocument, PairingRecord};
    use calxgloss_decomp::{
        CACHE_FORMAT_VERSION, CacheManifest, DecompiledFunction, FunctionSummary, Symbol,
        current_engine_identity,
    };
    use calxgloss_types::{Confidence, persist::save_json};

    use super::*;

    const BINARY: &str = "game.dll";
    /// A stand-in for the previous version's 64-hex byte hash: the tests'
    /// sibling directories carry this name, and their manifests name it.
    const OLD_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A workspace holding scan document directories for the named hashes.
    fn temp_workspace() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("temp workspace")
    }

    /// The scan-cache directory for one hash under the workspace's identity
    /// directory — the layout ADR-0043 defines.
    fn scan_dir(workspace: &Path, hash: &str) -> PathBuf {
        cache_root(workspace).join(BINARY).join(hash)
    }

    /// File one version's scan document set: the manifest naming its own
    /// directory and this run's engine build (the identity a warm open and
    /// the surviving-scan check both compare, #358), the function listing,
    /// the export listing, and one kept body per function unless its body
    /// is blank.
    fn file_scan_documents(
        dir: &Path,
        hash: &str,
        functions: &[(&str, u64, &str)],
        exports: &[&str],
    ) {
        std::fs::create_dir_all(dir).expect("scan directory");
        save_json(
            &dir.join("manifest.json"),
            &CacheManifest {
                binary_sha256: hash.to_string(),
                format_version: CACHE_FORMAT_VERSION,
                program: BINARY.into(),
                engine_identity: Some(current_engine_identity()),
            },
        )
        .expect("manifest filed");
        let listing: Vec<FunctionSummary> = functions
            .iter()
            .map(|(name, address, _)| FunctionSummary {
                name: (*name).to_string(),
                address: *address,
            })
            .collect();
        save_json(&dir.join("functions.json"), &listing).expect("listing filed");
        let export_listing: Vec<Symbol> = exports
            .iter()
            .map(|name| Symbol {
                name: (*name).to_string(),
                address: 0,
                imported: false,
            })
            .collect();
        save_json(&dir.join("exports.json"), &export_listing).expect("exports filed");
        for (name, _, body) in functions {
            if body.is_empty() {
                continue;
            }
            save_json(
                &dir.join("decompile").join(format!("{name}.json")),
                &DecompiledFunction {
                    name: (*name).to_string(),
                    signature: format!("undefined {name}(void)"),
                    body: (*body).to_string(),
                },
            )
            .expect("kept body filed");
        }
    }

    /// A target binary file of the named bytes, returned with the hash the
    /// trigger will read off it — the new version's live hash.
    fn target_binary(workspace: &Path, bytes: &[u8]) -> (PathBuf, String) {
        let path = workspace.join(BINARY);
        std::fs::write(&path, bytes).expect("binary written");
        let hash = sha256_of_file(&path)
            .expect("hashable")
            .expect("the binary exists");
        (path, hash)
    }

    /// A hand-authored pairing document for the live pair, one record short
    /// of anything the pass would produce.
    fn hand_document(old_hash: &str, new_hash: &str) -> PairingDocument {
        PairingDocument {
            binary: BINARY.into(),
            old_bytes_sha256: old_hash.to_string(),
            new_bytes_sha256: new_hash.to_string(),
            old_functions: vec!["fixture_init".into()],
            new_functions: vec!["fixture_init".into()],
            pairings: vec![PairingRecord {
                old_function: "fixture_init".into(),
                new_function: "fixture_init".into(),
                family: MatchFamily::NameIdentity,
                confidence: Confidence::new(1),
                evidence: vec!["hand-authored sentinel".into()],
            }],
        }
    }

    /// Two versions of one binary: `fixture_init` exported in both (name
    /// identity), one function dropped, one added.
    fn two_version_scans(workspace: &Path, new_hash: &str) {
        file_scan_documents(
            &scan_dir(workspace, OLD_HASH),
            OLD_HASH,
            &[
                ("fixture_init", 0x1000, "// old body of fixture_init"),
                ("FUN_10001200", 0x1200, "// body the update replaced"),
            ],
            &["fixture_init"],
        );
        file_scan_documents(
            &scan_dir(workspace, new_hash),
            new_hash,
            &[
                ("fixture_init", 0x4000, "// old body of fixture_init"),
                ("brand_new", 0x5000, "// body of a genuinely new function"),
            ],
            &["fixture_init", "brand_new"],
        );
    }

    #[test]
    fn a_sibling_scan_gets_one_pairing_document_naming_the_hash_pair() {
        // AC1: the scan step's trigger pairs (old, new) once and persists
        // the document under the pair's key at re/analysis/bdiff/.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"the new version's bytes");
        two_version_scans(ws.path(), &new_hash);

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let persistor = BdiffPersistor::new(ws.path());
        let key = BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash);
        assert!(
            persistor.path_for(&key).is_file(),
            "filed under the analysis-directory convention"
        );
        let document = persistor.load(&key).expect("one pairing document");
        assert_eq!(document.binary, BINARY);
        assert_eq!(document.old_bytes_sha256, OLD_HASH);
        assert_eq!(document.new_bytes_sha256, new_hash);
        assert_eq!(
            document.old_functions,
            ["fixture_init", "FUN_10001200"],
            "the listings ride in scan order"
        );
        assert_eq!(document.new_functions, ["fixture_init", "brand_new"]);
        assert_eq!(document.pairings.len(), 1);
        assert_eq!(document.pairings[0].old_function, "fixture_init");
        assert_eq!(document.pairings[0].family, MatchFamily::NameIdentity);
        assert_eq!(document.pairings[0].confidence, Confidence::new(95));
    }

    #[test]
    fn a_later_run_reuses_the_persisted_document_without_recomputing() {
        // AC2: the persisted document is the cache check — with one filed
        // under the live pair and naming it, the pass never runs again.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"the same version's bytes");
        two_version_scans(ws.path(), &new_hash);
        let persistor = BdiffPersistor::new(ws.path());
        let key = BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash);
        persistor
            .save(&hand_document(OLD_HASH, &new_hash))
            .expect("hand-authored document filed");

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let loaded = persistor.load(&key).expect("the document still stands");
        assert_eq!(
            loaded.pairings[0].evidence,
            ["hand-authored sentinel"],
            "the persisted document was reused, not recomputed"
        );
    }

    #[test]
    fn no_sibling_hash_directory_persists_nothing() {
        // AC3: no sibling means no document — the queue's inputs are
        // untouched and the trigger writes no new directory at all.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"one version, unchanged");
        file_scan_documents(
            &scan_dir(ws.path(), &new_hash),
            &new_hash,
            &[("fixture_init", 0x1000, "// a body")],
            &["fixture_init"],
        );

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        assert!(
            !ws.path().join("re").join("analysis").join("bdiff").exists(),
            "the diff pass stays invisible until a version actually changes"
        );
    }

    #[test]
    fn a_document_that_does_not_name_the_live_pair_is_recomputed_not_trusted() {
        // AC4: staleness is detected, never silently trusted. A document
        // filed at the live key but naming another (old, new) pair is
        // recomputed from the two cached scans.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"a since-replaced build");
        two_version_scans(ws.path(), &new_hash);
        let persistor = BdiffPersistor::new(ws.path());
        let key = BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash);
        let mut stale = hand_document(OLD_HASH, &new_hash);
        stale.old_bytes_sha256 = "replaced-bytes-hash".into();
        save_json(&persistor.path_for(&key), &stale).expect("stale document filed");

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let loaded = persistor
            .load(&key)
            .expect("the stale document was replaced");
        assert_eq!(loaded.old_bytes_sha256, OLD_HASH);
        assert_eq!(loaded.new_bytes_sha256, new_hash);
        assert_eq!(loaded.pairings[0].confidence, Confidence::new(95));
    }

    #[test]
    fn an_unreadable_persisted_document_is_recomputed_not_trusted() {
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"the current bytes");
        two_version_scans(ws.path(), &new_hash);
        let persistor = BdiffPersistor::new(ws.path());
        let key = BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash);
        std::fs::create_dir_all(persistor.path_for(&key).parent().expect("cache dir"))
            .expect("bdiff directory");
        std::fs::write(persistor.path_for(&key), "{ not json").expect("junk filed");

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let loaded = persistor.load(&key).expect("the junk was replaced");
        assert_eq!(loaded.pairings.len(), 1);
    }

    #[test]
    fn successive_versions_ride_successive_pairwise_documents() {
        // Pairings stay pairwise: each surviving sibling gets its own
        // (old→new) document; no chain document is ever computed.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"the third version");
        two_version_scans(ws.path(), &new_hash);
        let older_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        file_scan_documents(
            &scan_dir(ws.path(), older_hash),
            older_hash,
            &[("fixture_init", 0x0800, "// the oldest body")],
            &["fixture_init"],
        );

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let persistor = BdiffPersistor::new(ws.path());
        let newer_pair = persistor
            .load(&BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash))
            .expect("the previous version paired");
        let oldest_pair = persistor
            .load(&BdiffPersistor::key_for(BINARY, older_hash, &new_hash))
            .expect("the oldest version paired too");
        assert_eq!(newer_pair.old_bytes_sha256, OLD_HASH);
        assert_eq!(oldest_pair.old_bytes_sha256, older_hash);
        assert_eq!(
            oldest_pair.pairings[0].old_function, "fixture_init",
            "each document is its own old→new pairing"
        );
    }

    #[test]
    fn a_sibling_holding_only_a_manifest_stands_for_no_scan() {
        // The scan phase had not warmed the sibling: a manifest alone is
        // not a surviving scan, and nothing is persisted from it.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"current bytes");
        let cold = scan_dir(ws.path(), OLD_HASH);
        std::fs::create_dir_all(&cold).expect("cold directory");
        save_json(
            &cold.join("manifest.json"),
            &CacheManifest {
                binary_sha256: OLD_HASH.into(),
                format_version: CACHE_FORMAT_VERSION,
                program: BINARY.into(),
                engine_identity: Some(current_engine_identity()),
            },
        )
        .expect("manifest filed");
        file_scan_documents(
            &scan_dir(ws.path(), &new_hash),
            &new_hash,
            &[("fixture_init", 0x4000, "// old body of fixture_init")],
            &["fixture_init"],
        );

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let persistor = BdiffPersistor::new(ws.path());
        let key = BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash);
        assert!(
            !persistor.exists(&key),
            "a cold sibling directory stands for no scan"
        );
    }

    #[test]
    fn a_sibling_filed_under_another_engine_identity_is_refused() {
        // The surviving-sibling pairing contract still applies to the
        // extended manifest (#358, the #328 pairing): a warm sibling whose
        // manifest names a different engine build than the one that
        // answered it — same hash, same program, same format version, only
        // the identity is stale — is not a surviving scan, so cross-engine
        // pairing never happens. This refusal needs no version bump.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"current bytes");
        two_version_scans(ws.path(), &new_hash);
        let old_dir = scan_dir(ws.path(), OLD_HASH);
        save_json(
            &old_dir.join("manifest.json"),
            &CacheManifest {
                binary_sha256: OLD_HASH.into(),
                format_version: CACHE_FORMAT_VERSION,
                program: BINARY.into(),
                engine_identity: Some("kuna@v0.0.0@deadbee".into()),
            },
        )
        .expect("the sibling re-filed under another engine build");

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let persistor = BdiffPersistor::new(ws.path());
        assert!(
            !persistor.exists(&BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash)),
            "a sibling answered by another engine build pairs as no scan at all"
        );
    }

    #[test]
    fn a_shared_export_name_pairs_even_where_neither_version_kept_a_body() {
        // The snapshot assembles blank bodies for missing decompile
        // documents; the name-identity family still claims the shared
        // exported name, and nothing else pairs on lone signals.
        let ws = temp_workspace();
        let (binary_file, new_hash) = target_binary(ws.path(), b"stripped rebuild");
        file_scan_documents(
            &scan_dir(ws.path(), OLD_HASH),
            OLD_HASH,
            &[("open_box", 0x1000, ""), ("FUN_10001200", 0x1200, "")],
            &["open_box"],
        );
        file_scan_documents(
            &scan_dir(ws.path(), &new_hash),
            &new_hash,
            &[("open_box", 0x4000, ""), ("FUN_10009900", 0x9900, "")],
            &["open_box"],
        );

        pair_previous_versions(ws.path(), BINARY, &binary_file);

        let persistor = BdiffPersistor::new(ws.path());
        let document = persistor
            .load(&BdiffPersistor::key_for(BINARY, OLD_HASH, &new_hash))
            .expect("one pairing document");
        assert_eq!(
            document.pairings.len(),
            1,
            "the shared FUN_ spelling's successor pairs nothing on its own"
        );
        assert_eq!(document.pairings[0].old_function, "open_box");
    }

    #[test]
    fn a_missing_target_binary_pairs_nothing() {
        // Degradation, never failure: the scan step ran without a readable
        // binary (the cache's own pass-through condition); the trigger has
        // no live hash to pair against and writes nothing.
        let ws = temp_workspace();
        file_scan_documents(
            &scan_dir(ws.path(), OLD_HASH),
            OLD_HASH,
            &[("fixture_init", 0x1000, "// a body")],
            &["fixture_init"],
        );

        pair_previous_versions(ws.path(), BINARY, &ws.path().join("absent.dll"));

        assert!(
            !ws.path().join("re").join("analysis").join("bdiff").exists(),
            "no current bytes, no pairing document"
        );
    }
}

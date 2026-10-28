//! Carry-over seeding — first attempt seeded from an accepted translation (issue #299).
//!
//! When a target binary's newer version re-exports a function whose
//! previous-version twin already has an *accepted* translation (a merged
//! `re/{binary}/{function}...` branch — the review overlay's Accepted
//! classification, ADR-0003), the new function's attempt 1 seeds from
//! that accepted code instead of asking the LLM cold. The seeded unit
//! runs the normal pipeline — baseline capture and full verification
//! against the NEW target binary's bytes — so an accepted translation
//! is never trusted blindly: it must prove itself against the new bytes
//! or the fresh attempt chain takes over (P18's "binary-diff-as-similarity-heuristic" bet, `docs/adr/0016`).
//!
//! Provenance is explicit and stays visible in the record: every seeded
//! result names the old function and the attempt branch its code came
//! from, and the commit on the NEW branch says "seeded from". No seeded
//! result carries a Verified mark — carry-over is the translation
//! hypothesis, and the deterministic verification decides it.
//!
//! Seeds are collected from the pairing documents the version-pairing
//! trigger (issue #298) leaves in `{analysis}/bdiff/` during the same
//! pre-batch scan step. The accepted-code lookup goes through an
//! injected port ([`AcceptedAttemptSource`]) — the translator never
//! touches git itself (`version_pairing.rs`'s trigger ports work alike).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use calxgloss_bdiff::{CARRY_OVER_CONFIDENCE_FLOOR, PairingDocument, PairingRecord};
use tracing::warn;

/// The port to the git history: where an accepted translation's code lives.
///
/// Returns the accepted attempt's number and `rust_code` for `binary`'s
/// `function` — the highest merged `re/{binary}/{function}...` branch's
/// `translated.rs` — or `None` when the function has no accepted translation.
/// Implemented in the CLI layer over `GitManager` (the translator crate stays
/// git-free); the pipeline skips seeding entirely when no source is wired.
pub trait AcceptedAttemptSource: Send + Sync {
    /// Look up the accepted (merged) translation for one old-version function.
    fn accepted_attempt(&self, binary: &str, function: &str) -> Option<(u32, String)>;
}

/// What one new function's attempt 1 is seeded from.
#[derive(Debug, Clone)]
pub struct CarryOverSeed {
    /// The previous version's function this code came from — a different name
    /// under rename-aware pairing (the `alias` pairing evidence) and the same
    /// name when the twins paired by name.
    pub old_function: String,
    /// Which attempt branch of the old function the code was read from.
    pub old_attempt: u32,
    /// The pairing document's family label the twin was paired under
    /// (`"exact"` / `"family"` / `"alias"`), carried for provenance display.
    pub family: &'static str,
    /// The pairing record's confidence (never below
    /// [`CARRY_OVER_CONFIDENCE_FLOOR`] — only confident pairings seed).
    pub confidence: u8,
    /// The accepted translation's Rust source, verbatim.
    pub rust_code: String,
}

/// A carry-over seed's provenance, recorded on the [`FunctionResult`] so the
/// batch loop's commit message — and any reader of the record — can see
/// exactly where the code came from.
///
/// [`FunctionResult`]: crate::batch::FunctionResult
#[derive(Debug, Clone)]
pub struct CarryOverRecord {
    /// The previous version's function the code came from.
    pub old_function: String,
    /// The old function's attempt branch the code was read from.
    pub old_attempt: u32,
    /// The pairing family label (`"exact"` / `"family"` / `"alias"`).
    pub family: &'static str,
    /// The pairing record's confidence.
    pub confidence: u8,
}

impl CarryOverRecord {
    /// Provenance sentence for the commit message on the new function's
    /// branch: names the old function and the attempt branch it came from.
    pub fn commit_note(&self) -> String {
        format!(
            "seeded from {} attempt {} (paired, {}% confidence)",
            self.old_function, self.old_attempt, self.confidence
        )
    }
}

/// Collect the carry-over seeds for `functions` from the pairing documents
/// the version-pairing trigger left in `{analysis}/bdiff/`.
///
/// Gate by gate (issue #299). The **floor gate** drops records below
/// [`CARRY_OVER_CONFIDENCE_FLOOR`] — below it a function queues fresh
/// exactly as today. The **staleness gate** refuses a document unless it
/// names `binary` and the hash of `binary_path`'s current bytes — a
/// stale document describes a different version situation, and seeding
/// from it would be guesswork. The **one-branch-one-seed rule** keeps
/// two new functions from ever claiming the same accepted translation:
/// the strongest pairing wins the claim. Everything degrades to "no
/// seed": no documents, unreadable documents, and functions without an
/// accepted twin all queue fresh, unchanged from today.
///
/// One entry per function that is confidently paired *and* whose twin
/// has an accepted translation; the rest are absent.
pub fn collect_seeds(
    workspace: &Path,
    binary: &str,
    binary_path: &Path,
    functions: &[String],
    source: &Arc<dyn AcceptedAttemptSource>,
) -> HashMap<String, CarryOverSeed> {
    let bdiff_dir = calxgloss_types::persist::analysis_dir(workspace).join("bdiff");
    let entries = match std::fs::read_dir(&bdiff_dir) {
        Ok(entries) => entries,
        Err(_) => return HashMap::new(), // no pairing documents → fresh translation
    };
    // The staleness gate: a document is eligible only when it names this
    // target binary itself and its `new_bytes_sha256` is the exact bytes
    // being translated right now — the same hash the pairing trigger
    // recorded in this run's pre-batch scan.
    let new_sha = match calxgloss_decomp::sha256_of_file(binary_path) {
        Ok(Some(sha)) => sha,
        Ok(None) => return HashMap::new(), // no live bytes to compare against
        Err(err) => {
            warn!(
                path = %binary_path.display(),
                error = %err,
                "carry-over: can't hash the binary being translated — no seeds this run"
            );
            return HashMap::new();
        }
    };

    // Every eligible record for a queued function, grouped by function. The
    // floor gate is the consumer's to apply — the pairing pass persists every
    // resolved pairing regardless of it, on purpose.
    let wanted: HashSet<&str> = functions.iter().map(String::as_str).collect();
    let mut documents: Vec<PairingDocument> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let doc = match calxgloss_types::persist::load_json::<PairingDocument>(&path) {
            Ok(doc) => doc,
            Err(err) => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "carry-over: unreadable pairing document — skipped"
                );
                continue;
            }
        };
        if doc.binary == binary && doc.new_bytes_sha256 == new_sha {
            documents.push(doc);
        }
    }
    let mut by_function: HashMap<&str, Vec<&PairingRecord>> = HashMap::new();
    for doc in &documents {
        for record in &doc.pairings {
            if wanted.contains(record.new_function.as_str())
                && record.confidence.at_least(CARRY_OVER_CONFIDENCE_FLOOR)
            {
                by_function
                    .entry(record.new_function.as_str())
                    .or_default()
                    .push(record);
            }
        }
    }
    if by_function.is_empty() {
        return HashMap::new();
    }

    // Strongest pairing evidence wins per function, and an accepted
    // translation seeds at most one new function: claiming the old function
    // here (functions processed in queue order, strongest pairing first)
    // enforces the one-branch-one-seed rule across the whole batch.
    let mut order: Vec<&str> = by_function.keys().copied().collect();
    order.sort_by_key(|f| {
        // deterministic batch order: the queued order, falling back to name
        functions.iter().position(|q| q == f).unwrap_or(usize::MAX)
    });
    let mut claimed: HashSet<String> = HashSet::new();
    let mut seeds = HashMap::new();
    for function in order {
        let mut candidates = by_function[function].clone();
        // Strongest pairing evidence wins; the old function's name breaks
        // ties so document iteration order (not deterministic) never picks.
        candidates.sort_by(|a, b| {
            b.confidence
                .value()
                .cmp(&a.confidence.value())
                .then_with(|| a.old_function.cmp(&b.old_function))
        });
        for record in candidates {
            if claimed.contains(&record.old_function) {
                continue;
            }
            // The old twin lives under the same binary identity — branch
            // names keep the binary name verbatim, and the previous-
            // version scan that produced this document ran under it.
            let Some((old_attempt, rust_code)) =
                source.accepted_attempt(binary, &record.old_function)
            else {
                continue;
            };
            if rust_code.trim().is_empty() {
                continue;
            }
            claimed.insert(record.old_function.clone());
            seeds.insert(
                function.to_string(),
                CarryOverSeed {
                    old_function: record.old_function.clone(),
                    old_attempt,
                    family: record.family.as_str(),
                    confidence: record.confidence.value(),
                    rust_code,
                },
            );
            break;
        }
    }
    seeds
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use calxgloss_bdiff::{BdiffPersistor, MatchFamily};
    use calxgloss_types::Confidence;

    use super::*;

    const BINARY: &str = "game.dll";

    /// A workspace holding a target binary file of the given bytes; returns
    /// the workspace, the binary path, and the live byte hash the staleness
    /// gate compares documents against.
    fn workspace_with_binary(bytes: &[u8]) -> (tempfile::TempDir, PathBuf, String) {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let path = ws.path().join(BINARY);
        std::fs::write(&path, bytes).expect("binary written");
        let hash = calxgloss_decomp::sha256_of_file(&path)
            .expect("hashable")
            .expect("the binary exists");
        (ws, path, hash)
    }

    /// File one pairing document under the analysis-directory convention,
    /// exactly where the #298 trigger leaves it.
    fn file_document(ws: &Path, doc: PairingDocument) {
        BdiffPersistor::new(ws)
            .save(&doc)
            .expect("pairing document filed");
    }

    /// A pairing document for the (fake-old-hash, `new_sha`) pair carrying
    /// `records`, with listings that mention every named function.
    fn document(new_sha: &str, records: Vec<PairingRecord>) -> PairingDocument {
        let mut old_functions: Vec<String> =
            records.iter().map(|r| r.old_function.clone()).collect();
        let mut new_functions: Vec<String> =
            records.iter().map(|r| r.new_function.clone()).collect();
        old_functions.sort();
        new_functions.sort();
        PairingDocument {
            binary: BINARY.into(),
            old_bytes_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            new_bytes_sha256: new_sha.into(),
            old_functions,
            new_functions,
            pairings: records,
        }
    }

    /// One pairing record at the named confidence, name-identity family.
    fn record(old: &str, new: &str, confidence: u8) -> PairingRecord {
        PairingRecord {
            old_function: old.into(),
            new_function: new.into(),
            family: MatchFamily::NameIdentity,
            confidence: Confidence::new(confidence),
            evidence: vec![format!("{old} == {new}")],
        }
    }

    /// A stand-in git history: the functions with a merged attempt branch,
    /// and the code each accepted branch holds.
    #[derive(Default)]
    struct FakeSource {
        accepted: HashMap<String, (u32, String)>,
    }

    impl AcceptedAttemptSource for FakeSource {
        fn accepted_attempt(&self, binary: &str, function: &str) -> Option<(u32, String)> {
            assert_eq!(binary, BINARY, "the port is keyed on the run's binary");
            self.accepted.get(function).cloned()
        }
    }

    fn source_with(accepted: &[(&str, u32, &str)]) -> Arc<dyn AcceptedAttemptSource> {
        let mut fake = FakeSource::default();
        for (function, attempt, code) in accepted {
            fake.accepted
                .insert((*function).into(), (*attempt, (*code).into()));
        }
        Arc::new(fake)
    }

    fn collect(
        ws: &Path,
        binary_path: &Path,
        functions: &[&str],
        source: &Arc<dyn AcceptedAttemptSource>,
    ) -> HashMap<String, CarryOverSeed> {
        collect_seeds(
            ws,
            BINARY,
            binary_path,
            &functions
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<String>>(),
            source,
        )
    }

    #[test]
    fn a_paired_function_with_an_accepted_twin_seeds_from_its_code() {
        // The happy path: confident pairing + merged branch → the seed
        // carries the accepted code verbatim and names the twin.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        file_document(
            ws.path(),
            document(&new_sha, vec![record("DrawSprite", "DrawSprite", 95)]),
        );
        let src = source_with(&[("DrawSprite", 2, "fn draw_sprite() { /* accepted */ }")]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        let seed = seeds.get("DrawSprite").expect("one seed");
        assert_eq!(seed.old_function, "DrawSprite");
        assert_eq!(seed.old_attempt, 2);
        assert_eq!(seed.family, "name_identity");
        assert_eq!(seed.confidence, 95);
        assert_eq!(seed.rust_code, "fn draw_sprite() { /* accepted */ }");
    }

    #[test]
    fn a_below_floor_pairing_seeds_nothing() {
        // The floor gate: one point below 80 and the function queues fresh,
        // exactly as it does today.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        file_document(
            ws.path(),
            document(
                &new_sha,
                vec![record(
                    "DrawSprite",
                    "DrawSprite",
                    CARRY_OVER_CONFIDENCE_FLOOR - 1,
                )],
            ),
        );
        let src = source_with(&[("DrawSprite", 1, "fn draw_sprite() {}")]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        assert!(seeds.is_empty(), "below the floor, nothing seeds");
    }

    #[test]
    fn a_stale_document_seeds_nothing() {
        // The staleness gate: a document whose new_bytes_sha256 isn't the
        // bytes being translated now describes a different version
        // situation and is refused, never silently trusted.
        let (ws, binary_path, _new_sha) = workspace_with_binary(b"the current bytes");
        file_document(
            ws.path(),
            document(
                "beefstalebeefstalebeefstalebeefstalebeefstalebeefstalebeefstalebeefstal",
                vec![record("DrawSprite", "DrawSprite", 95)],
            ),
        );
        let src = source_with(&[("DrawSprite", 1, "fn draw_sprite() {}")]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        assert!(
            seeds.is_empty(),
            "a document naming other bytes claims nothing"
        );
    }

    #[test]
    fn no_pairing_documents_mean_everything_queues_fresh() {
        // A target binary that has never changed version: the #298
        // trigger wrote nothing, and the queue's inputs are untouched.
        let (ws, binary_path, _new_sha) = workspace_with_binary(b"one version unchanged");
        let src = source_with(&[]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        assert!(seeds.is_empty());
    }

    #[test]
    fn one_accepted_branch_seeds_at_most_one_new_function() {
        // Both new functions pair to the same accepted twin (a drift split
        // the pairing documents record twice). One seed, and the other
        // function queues fresh — an accepted branch never seeds two.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        file_document(
            ws.path(),
            document(
                &new_sha,
                vec![
                    record("DrawSprite", "DrawSprite", 95),
                    record("DrawSprite", "DrawSpriteScaled", 85),
                ],
            ),
        );
        let src = source_with(&[("DrawSprite", 1, "fn draw_sprite() {}")]);

        let seeds = collect(
            ws.path(),
            &binary_path,
            &["DrawSprite", "DrawSpriteScaled"],
            &src,
        );

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds["DrawSprite"].old_function, "DrawSprite");
        assert!(
            !seeds.contains_key("DrawSpriteScaled"),
            "the loser queues fresh"
        );
    }

    #[test]
    fn two_documents_for_one_function_strongest_pairing_wins() {
        // Successive versions each left a pairing document; the strongest
        // pairing confidence decides which twin the code comes from.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        file_document(
            ws.path(),
            document(&new_sha, vec![record("DrawSpriteOld", "DrawSprite", 85)]),
        );
        file_document(
            ws.path(),
            PairingDocument {
                // A different old version's document — its own key beside the first.
                old_bytes_sha256:
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                new_bytes_sha256: new_sha.clone(),
                ..document(&new_sha, vec![record("DrawSprite", "DrawSprite", 95)])
            },
        );
        let src = source_with(&[
            ("DrawSpriteOld", 3, "fn old_draw() {}"),
            ("DrawSprite", 1, "fn draw_sprite() {}"),
        ]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        let seed = seeds.get("DrawSprite").expect("one seed");
        assert_eq!(seed.old_function, "DrawSprite", "the 95-score pairing wins");
        assert_eq!(seed.confidence, 95);
    }

    #[test]
    fn a_paired_function_without_an_accepted_branch_seeds_nothing() {
        // Pairing says the twin exists; git says its work is unmerged (or
        // absent) — there is no accepted translation to carry, so the
        // function goes to the LLM fresh like today.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        file_document(
            ws.path(),
            document(&new_sha, vec![record("DrawSprite", "DrawSprite", 95)]),
        );
        let src = source_with(&[]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        assert!(seeds.is_empty());
    }

    #[test]
    fn an_unreadable_document_is_skipped_not_fatal() {
        // Junk in one document doesn't end the pass or poison the other.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        let junk = calxgloss_types::persist::analysis_dir(ws.path())
            .join("bdiff")
            .join("junk_document.json");
        std::fs::create_dir_all(junk.parent().expect("bdiff directory")).expect("bdiff directory");
        std::fs::write(&junk, "{ not json").expect("junk filed");
        file_document(
            ws.path(),
            document(&new_sha, vec![record("DrawSprite", "DrawSprite", 95)]),
        );
        let src = source_with(&[("DrawSprite", 1, "fn draw_sprite() {}")]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        assert_eq!(seeds.len(), 1, "the good document still counts");
    }

    #[test]
    fn an_accepted_branch_holding_empty_code_seeds_nothing() {
        // A merged branch whose translated.rs is blank is no evidence a
        // translation exists; seeding from nothing would only hide the
        // fresh chain that should run instead.
        let (ws, binary_path, new_sha) = workspace_with_binary(b"the new version");
        file_document(
            ws.path(),
            document(&new_sha, vec![record("DrawSprite", "DrawSprite", 95)]),
        );
        let src = source_with(&[("DrawSprite", 1, "   \n")]);

        let seeds = collect(ws.path(), &binary_path, &["DrawSprite"], &src);

        assert!(seeds.is_empty());
    }
}

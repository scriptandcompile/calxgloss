//! The `bdiff` command — review a binary version change before the run.
//!
//! Loads the pairing documents the auto run's version-pairing scan trigger
//! (issue #298) leaves in `re/analysis/bdiff/` for a binary identity and
//! lists the old↔new pairs with their confidence and match family, plus
//! the functions paired on neither side — old-only and new-only (issue
//! #300). The command is pure report: no scan runs, no engine read (the
//! documents are the whole input), and no web or dashboard surface this
//! track.
//!
//! The staleness rule is the carry-over track's (issue #299): a document
//! is live only when it self-names `binary` and its `new_bytes_sha256`
//! is the hash of the target directory's current bytes; a document naming
//! a since-replaced current version is stale and reported as such, never
//! printed as an empty success.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use calxgloss_bdiff::{CARRY_OVER_CONFIDENCE_FLOOR, MatchFamily, PairingDocument, PairingRecord};
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `bdiff` subcommand: review `binary`'s pairing documents
/// against the current bytes in the target directory, listing every
/// old↔new pair, the family and confidence that carried it, and the
/// functions paired on neither side. A missing or stale document fails
/// the run naming the gap.
pub async fn handle_bdiff(binary: &str, workspace: &Path, settings: &Settings) -> Result<()> {
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"));
    let target = target_dir.join(binary);

    // The live new hash: the same hash the scan trigger recorded when it
    // paired the version change. Without the current bytes there is no
    // live pair to review, so the run fails naming the path — the same
    // way the scan commands report a missing target.
    let live_hash = match calxgloss_decomp::sha256_of_file(&target)
        .with_context(|| format!("Failed to read the target binary: {}", target.display()))?
    {
        Some(hash) => hash,
        None => bail!(
            "No current bytes for {binary} at {} — bdiff reviews pairing documents against \
             the target directory's current version; put the new version's file in the \
             target directory (or run from the directory that holds it) and re-run.",
            target.display()
        ),
    };

    info!(
        binary,
        workspace = %workspace.display(),
        "Reviewing binary-version pairing documents"
    );

    let (live, stale) = load_pairing_documents(workspace, binary, &live_hash)?;
    for document in &live {
        let path = bdiff_document_path(workspace, document);
        print_pairing_report(document, &path, &stale);
    }
    Ok(())
}

/// What `binary`'s pairing documents say against the current bytes: the
/// live documents (self-naming `binary` and `live_hash` as the new side),
/// sorted deterministically by hash pair, beside the stale ones (naming
/// `binary` but an earlier current version). Fails with a clear report —
/// never an empty success — when no live document stands: either none
/// exists at all, or every one on disk is stale.
fn load_pairing_documents(
    workspace: &Path,
    binary: &str,
    live_hash: &str,
) -> Result<(Vec<PairingDocument>, Vec<PairingDocument>)> {
    let bdiff_dir = calxgloss_types::persist::analysis_dir(workspace).join("bdiff");
    let entries = match std::fs::read_dir(&bdiff_dir) {
        Ok(entries) => entries,
        Err(_) => bail!(
            "No pairing document for {binary}: {} holds none. The scan step pairs a \
             version change when the previous version's scan cache survives — a binary \
             that has never changed version has no document to review. Run `calxgloss \
             auto` for {binary} once a previous version is cached, then re-run this \
             command.",
            bdiff_dir.display()
        ),
    };

    let mut live: Vec<PairingDocument> = Vec::new();
    let mut stale: Vec<PairingDocument> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match calxgloss_types::persist::load_json::<PairingDocument>(&path) {
            Ok(document) if document.binary == binary => {
                if document.new_bytes_sha256 == live_hash {
                    live.push(document);
                } else {
                    stale.push(document);
                }
            }
            Ok(_) => {}
            Err(err) => {
                warn!(path = %path.display(), error = %err, "unreadable pairing document — skipped");
            }
        }
    }

    if live.is_empty() {
        match stale
            .iter()
            .map(|d| {
                (
                    short_hash(&d.old_bytes_sha256),
                    short_hash(&d.new_bytes_sha256),
                )
            })
            .max()
        {
            Some((old_short, new_short)) => bail!(
                "All pairing documents for {binary} are stale: the newest on disk \
                 describes {old_short} → {new_short}, but the current bytes hash to \
                 {}. The current version change has no pairing document — run \
                 `calxgloss auto` for {binary}; its scan step pairs the current \
                 version and writes a fresh document.",
                short_hash(live_hash)
            ),
            None => bail!(
                "No pairing document for {binary}: {} holds none. The scan step pairs \
                 a version change when the previous version's scan cache survives — a \
                 binary that has never changed version has no document to review. Run \
                 `calxgloss auto` for {binary} once a previous version is cached, then \
                 re-run this command.",
                bdiff_dir.display()
            ),
        }
    }

    // Deterministic report order: one section per surviving old version,
    // named by its hash.
    live.sort_by(|a, b| {
        (&a.old_bytes_sha256, &a.new_bytes_sha256).cmp(&(&b.old_bytes_sha256, &b.new_bytes_sha256))
    });
    stale.sort_by(|a, b| {
        (&a.old_bytes_sha256, &a.new_bytes_sha256).cmp(&(&b.old_bytes_sha256, &b.new_bytes_sha256))
    });
    Ok((live, stale))
}

/// Where the trigger filed one document — the persistor's own key rule,
/// so the report names the exact file.
fn bdiff_document_path(workspace: &Path, document: &PairingDocument) -> PathBuf {
    calxgloss_bdiff::BdiffPersistor::new(workspace).path_for(
        &calxgloss_bdiff::BdiffPersistor::key_for(
            &document.binary,
            &document.old_bytes_sha256,
            &document.new_bytes_sha256,
        ),
    )
}

/// The report's family breakdown: every match family the pairing document
/// can carry, in ladder order, each with the count of pairings the
/// document records in that family; families with no records drop out.
/// The list is the enum's full family set — a family missing from it
/// would print nothing no matter how many pairs the pass resolved
/// through it (the report-breakdown-names-every-kind precedent).
fn family_breakdown(document: &PairingDocument) -> Vec<String> {
    [
        MatchFamily::NameIdentity,
        MatchFamily::NormalizedBody,
        MatchFamily::CallTopology,
    ]
    .into_iter()
    .map(|family| {
        (
            family,
            document
                .pairings
                .iter()
                .filter(|record| record.family == family)
                .count(),
        )
    })
    .filter(|(_, count)| *count > 0)
    .map(|(family, count)| format!("{} {}", family.as_str(), count))
    .collect()
}

/// The functions paired on neither side — the document's own listings
/// minus the names its pairings claim, each side in its scan order.
fn unpaired_functions(document: &PairingDocument) -> (Vec<&str>, Vec<&str>) {
    let paired_old: HashSet<&str> = document
        .pairings
        .iter()
        .map(|record| record.old_function.as_str())
        .collect();
    let paired_new: HashSet<&str> = document
        .pairings
        .iter()
        .map(|record| record.new_function.as_str())
        .collect();
    (
        document
            .old_functions
            .iter()
            .map(String::as_str)
            .filter(|name| !paired_old.contains(name))
            .collect(),
        document
            .new_functions
            .iter()
            .map(String::as_str)
            .filter(|name| !paired_new.contains(name))
            .collect(),
    )
}

/// One pair line: the two names, the confidence that carried the pair,
/// and the family that claimed it — what an auditor reads to decide
/// whether the run's carry-over seeding can trust the pair.
fn pair_line(record: &PairingRecord) -> String {
    let score = confidence_color(record.confidence.value())(&format!(
        "{} {}",
        record.confidence.value(),
        record.family.as_str()
    ));
    format!(
        "{:<24} → {:<24}  {score}",
        record.old_function, record.new_function
    )
}

/// Color a 0–100 confidence score the way the other reports color pass rates.
fn confidence_color(confidence: u8) -> fn(&str) -> String {
    if confidence >= 70 {
        green_bold
    } else if confidence >= 50 {
        yellow_bold
    } else {
        red_bold
    }
}

/// The "…and N more" line a detail section ends with when it collapsed.
fn print_hidden_count(noun: &str, total: usize) {
    if total > DETAIL_LIMIT {
        println_content(format!(
            "  {} …and {} more {noun}",
            dim("●"),
            total - DETAIL_LIMIT
        ));
    }
}

/// The first 12 hex characters of a SHA-256 — enough to name a version
/// pair on screen without the full 64 characters.
fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// Print one version pair's report: where the document is filed, which
/// hash pair it describes, the family breakdown beside the pairing
/// count, the pairs themselves, and the functions paired on neither
/// side.
fn print_pairing_report(document: &PairingDocument, path: &Path, stale: &[PairingDocument]) {
    println!();
    hsep_bold();
    println_content(format!("  Binary Version Pairing — {}", document.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:       "),
        dim(&path.display().to_string())
    ));
    println_content(format!(
        "  {}{}",
        white_bold("Old bytes:  "),
        dim(short_hash(&document.old_bytes_sha256))
    ));
    println_content(format!(
        "  {}{}",
        white_bold("New bytes:  "),
        dim(short_hash(&document.new_bytes_sha256))
    ));
    println!();

    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Pairings:   "),
        document.pairings.len(),
        dim(&family_breakdown(document).join(", "))
    ));

    let (old_only, new_only) = unpaired_functions(document);
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Old only:   "),
        old_only.len(),
        dim("(functions the old version lost or left unpaired)")
    ));
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("New only:   "),
        new_only.len(),
        dim("(functions the new version gained or left unpaired)")
    ));
    println!();

    if !document.pairings.is_empty() {
        hsep();
        println_content("  Pairs:");
        hsep();
        for record in document.pairings.iter().take(DETAIL_LIMIT) {
            println_content(format!("  ●  {}", pair_line(record)));
        }
        print_hidden_count("pairing", document.pairings.len());
        println!();
    }

    if !old_only.is_empty() {
        hsep();
        println_content("  Old only — paired on neither side:");
        hsep();
        for name in old_only.iter().take(DETAIL_LIMIT) {
            println_content(format!("  ●  {name}"));
        }
        print_hidden_count("old-only function", old_only.len());
        println!();
    }

    if !new_only.is_empty() {
        hsep();
        println_content("  New only — paired on neither side:");
        hsep();
        for name in new_only.iter().take(DETAIL_LIMIT) {
            println_content(format!("  ●  {name}"));
        }
        print_hidden_count("new-only function", new_only.len());
        println!();
    }

    hsep_bold();
    if document.pairings.is_empty() {
        println!(
            "  {} The pairing document claims no pairs — every function on both sides \
             is unpaired, and nothing carries over.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Version change reviewed — the run's carry-over seeds only from pairings \
             at or above the carry-over floor ({CARRY_OVER_CONFIDENCE_FLOOR}).",
            green_bold("✓")
        );
    }
    if !stale.is_empty() {
        println!(
            "  {} {} stale pairing document(s) for {} name since-replaced version \
             changes; only the live documents above are shown.",
            yellow_bold("◉"),
            stale.len(),
            document.binary
        );
    }
    println!();
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_bdiff::BdiffPersistor;
    use calxgloss_types::Confidence;

    const BINARY: &str = "game.dll";
    const OLD_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn record(old: &str, new: &str, family: MatchFamily, confidence: u8) -> PairingRecord {
        PairingRecord {
            old_function: old.into(),
            new_function: new.into(),
            family,
            confidence: Confidence::new(confidence),
            evidence: vec![format!("{old} ↔ {new}")],
        }
    }

    fn document(pairings: Vec<PairingRecord>) -> PairingDocument {
        PairingDocument {
            binary: BINARY.into(),
            old_bytes_sha256: OLD_HASH.into(),
            new_bytes_sha256: NEW_HASH.into(),
            old_functions: pairings
                .iter()
                .map(|r| r.old_function.clone())
                .chain(["lost_function".into()])
                .collect(),
            new_functions: pairings
                .iter()
                .map(|r| r.new_function.clone())
                .chain(["gained_function".into()])
                .collect(),
            pairings,
        }
    }

    #[test]
    fn the_breakdown_names_every_family_the_document_carries() {
        // The breakdown line is the report's family index: every family
        // the pairing document can carry must show up with its count,
        // or a pass heavy in one family prints as though it paired
        // nothing through it.
        let document = document(vec![
            record("a", "1", MatchFamily::NameIdentity, 95),
            record("b", "2", MatchFamily::NormalizedBody, 90),
            record("c", "3", MatchFamily::CallTopology, 70),
        ]);
        let breakdown = family_breakdown(&document);
        assert_eq!(
            breakdown,
            vec!["name_identity 1", "normalized_body 1", "call_topology 1"],
            "every family the document carries is named, in ladder order"
        );
        let counted: usize = breakdown
            .iter()
            .map(|entry| entry.rsplit(' ').next().unwrap().parse::<usize>().unwrap())
            .sum();
        assert_eq!(
            counted,
            document.pairings.len(),
            "every pairing is counted — a family missing from the breakdown list fails here"
        );
    }

    #[test]
    fn a_family_with_no_records_stays_out_of_the_breakdown() {
        let document = document(vec![
            record("a", "1", MatchFamily::NameIdentity, 95),
            record("b", "2", MatchFamily::NameIdentity, 95),
        ]);
        assert_eq!(
            family_breakdown(&document),
            vec!["name_identity 2"],
            "families the pass resolved nothing through drop out of the line"
        );
    }

    #[test]
    fn each_pair_line_names_both_sides_the_confidence_and_the_family() {
        let line = pair_line(&record(
            "fixture_init",
            "brand_new",
            MatchFamily::NormalizedBody,
            88,
        ));
        assert!(line.contains("fixture_init"), "the old name is named");
        assert!(line.contains("brand_new"), "the new name is named");
        assert!(line.contains("88"), "the confidence rides along");
        assert!(
            line.contains("normalized_body"),
            "the match family is named"
        );
    }

    #[test]
    fn old_only_and_new_only_are_the_listings_minus_the_paired_names() {
        // The listings minus the paired names, each side in scan order —
        // the unpaired functions are what the run queues fresh.
        let mut document = document(vec![record(
            "kept",
            "renamed",
            MatchFamily::NameIdentity,
            95,
        )]);
        document.old_functions = ["gone".into(), "kept".into(), "moved".into()].to_vec();
        document.new_functions = ["moved_new".into(), "kept".into(), "fresh".into()].to_vec();
        document.pairings = vec![
            record("kept", "kept", MatchFamily::NameIdentity, 95),
            record("moved", "moved_new", MatchFamily::NormalizedBody, 90),
        ];
        let (old_only, new_only) = unpaired_functions(&document);
        assert_eq!(old_only, ["gone"], "the lost function stands old-only");
        assert_eq!(new_only, ["fresh"], "the gained function stands new-only");
    }

    #[test]
    fn a_missing_pairing_document_reports_clearly_instead_of_an_empty_success() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let err = load_pairing_documents(ws.path(), BINARY, NEW_HASH)
            .expect_err("no documents at all must fail the run");
        let message = err.to_string();
        assert!(message.contains(BINARY), "the report names the binary");
        assert!(
            message.contains("No pairing document"),
            "the report names the gap and how to close it: {message}"
        );
    }

    #[test]
    fn a_stale_document_is_reported_as_stale_never_as_a_success() {
        // A document naming a since-replaced current version describes a
        // different version situation: with no live document, the run
        // fails naming the stale pair and the current hash.
        let ws = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(ws.path());
        persistor.save(&document(vec![])).expect("stale doc filed");
        let current = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let err = load_pairing_documents(ws.path(), BINARY, current)
            .expect_err("a stale document must not stand in for a live one");
        let message = err.to_string();
        assert!(
            message.contains("stale"),
            "the report calls staleness by name: {message}"
        );
        assert!(
            message.contains("bbbbbbbbbbbb"),
            "the stale pair's new hash is shown"
        );
        assert!(
            message.contains("cccccccccccc"),
            "the current hash is shown for comparison"
        );
    }

    #[test]
    fn a_live_document_stands_and_stale_siblings_are_counted_beside_it() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let persistor = BdiffPersistor::new(ws.path());
        persistor
            .save(&document(vec![record(
                "a",
                "1",
                MatchFamily::NameIdentity,
                95,
            )]))
            .expect("live doc filed");
        let mut stale = document(vec![]);
        stale.new_bytes_sha256 =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        persistor.save(&stale).expect("stale doc filed");

        let (live, stale) =
            load_pairing_documents(ws.path(), BINARY, NEW_HASH).expect("the live document stands");
        assert_eq!(live.len(), 1, "exactly one live document");
        assert_eq!(
            stale.len(),
            1,
            "the since-replaced document is carried as stale"
        );
    }
}

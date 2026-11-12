//! The per-binary unknown audit ledger (issue #377): the end of a run is
//! a claim list, not a quiet queue.
//!
//! One derived join serves every reader. The pipeline's ledger documents
//! (`re/unknowns/<binary identity>.json`) and the reviewer's resolutions
//! document (`re/review/unknown_resolutions.json`) join at read time into a
//! [`BinaryUnknownLedger`] per target binary; the dashboard builder carries
//! that model into the review payload the web renders, and the run-close
//! derivation [`derive_binary_unknown_ledgers`] walks the same documents to
//! the same shape, so the two agree by construction (issue #485).
//!
//! The ledger's own absence reads as unknown, never as a clean run: a
//! binary with no filed ledger, a filed document whose `records` key is
//! absent, and an unreadable document all read as *unknown* — the
//! three-readings rule [`EffectiveLedger`](calxgloss_types::EffectiveLedger)
//! establishes, applied to the track's own artifact. Open, resolved, and
//! dismissed counts never fold into one another.

use std::path::Path;

use calxgloss_types::{
    BinaryIdentity, BinaryUnknownLedger, EffectiveLedger, UnitUnknowns, UnknownRecord,
    UnknownResolutions, read_unknown_ledger, read_unknown_resolutions,
};

/// One binary's joined ledger reading — the pure join the dashboard builder
/// and the run-close derivation both run, so the two readers cannot drift.
/// `records: None` is the unknown reading (no filed ledger, no `records`
/// key, or unreadable) and an unreadable resolutions document is unknown
/// too: settled state nobody wrote cannot be claimed either.
pub fn binary_unknown_ledger(
    binary: &str,
    records: Option<&[UnknownRecord]>,
    resolutions: Option<&UnknownResolutions>,
) -> BinaryUnknownLedger {
    let unknowns = match (records, resolutions) {
        (Some(records), Some(resolutions)) => UnitUnknowns::from_joined(&resolutions.join(records)),
        _ => UnitUnknowns::unknown(),
    };
    BinaryUnknownLedger {
        binary: binary.to_string(),
        unknowns,
    }
}

/// The named binaries with later repeats dropped — both run-close
/// derivations walk the same verbatim-unique targets in the order the
/// run handed them, so the two derivations key the same binaries by the
/// same words (issue #423).
pub(crate) fn dedupe_verbatim(binaries: &[String]) -> Vec<String> {
    let mut unique: Vec<String> = Vec::new();
    for binary in binaries {
        if unique.iter().any(|landed| landed == binary) {
            continue;
        }
        unique.push(binary.clone());
    }
    unique
}

/// Derive the audit ledgers for the named binaries straight from the
/// documents — the run-close derivation's entry point. The readings and
/// the degradation wording match the dashboard builder exactly: an
/// unreadable ledger or resolutions document degrades to *unknown* on this
/// derived surface with a named warning, never to a clean reading.
/// Binaries are named in the order handed, deduplicated on their verbatim
/// identity.
pub fn derive_binary_unknown_ledgers(
    workspace: &Path,
    binaries: &[String],
) -> Vec<BinaryUnknownLedger> {
    let resolutions = match read_unknown_resolutions(workspace) {
        Ok(resolutions) => Some(resolutions),
        Err(err) => {
            eprintln!(
                "  [unknowns] resolutions document unreadable, open-unknown state unknown: {err}"
            );
            None
        }
    };
    derive_binary_unknown_ledgers_with(workspace, binaries, resolutions.as_ref())
}

/// The same derivation against an already-read resolutions document — the
/// shape the builder reaches for so it joins with the copy it read once.
pub(crate) fn derive_binary_unknown_ledgers_with(
    workspace: &Path,
    binaries: &[String],
    resolutions: Option<&UnknownResolutions>,
) -> Vec<BinaryUnknownLedger> {
    let mut ledgers = Vec::new();
    for binary in dedupe_verbatim(binaries) {
        let records = match read_unknown_ledger(workspace, &BinaryIdentity::from(binary.as_str())) {
            Ok(EffectiveLedger::Filed(records)) => Some(records),
            Ok(EffectiveLedger::Unknown) => None,
            Err(err) => {
                eprintln!(
                    "  [unknowns] {binary}: ledger unreadable, open-unknown state unknown: {err}"
                );
                None
            }
        };
        ledgers.push(binary_unknown_ledger(
            &binary,
            records.as_deref(),
            resolutions,
        ));
    }
    ledgers
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{
        UnknownKind, UnknownOrigin, UnknownRecord, UnknownSeverity, unknown_ledger_dir,
        unknown_ledger_path, unknown_resolutions_path,
    };

    fn record(id: &str, severity: UnknownSeverity, question: &str) -> UnknownRecord {
        UnknownRecord::derive(
            "game_logic.dll",
            Some("DrawSprite".to_string()),
            UnknownKind::CoverageFacet,
            severity,
            question,
            format!("filed {id} evidence"),
            UnknownOrigin::Document {
                document: "memory lifecycle result".to_string(),
                facet: format!("facet {id}"),
            },
            1_700_000_000,
        )
    }

    #[test]
    fn the_three_ledger_documents_read_as_three_distinct_sections() {
        let dir = tempfile::tempdir().expect("temp workspace");
        let binaries = ["game_logic.dll".to_string()];

        // No document at all: unknown — nobody looked.
        let ledgers = derive_binary_unknown_ledgers(dir.path(), &binaries);
        assert_eq!(ledgers.len(), 1);
        assert_eq!(ledgers[0].unknowns.open, None);

        // A filed document with no `records` key: still unknown — an
        // absent key never means the list is empty.
        std::fs::create_dir_all(unknown_ledger_dir(dir.path())).expect("unknowns dir");
        std::fs::write(
            unknown_ledger_path(dir.path(), &BinaryIdentity::from("game_logic.dll")),
            r#"{"binary": "game_logic.dll", "filed_at": 1}"#,
        )
        .expect("file keyless ledger");
        let ledgers = derive_binary_unknown_ledgers(dir.path(), &binaries);
        assert_eq!(ledgers[0].unknowns.open, None);

        // A filed document with an explicitly empty list: the only honest
        // known-and-none.
        std::fs::write(
            unknown_ledger_path(dir.path(), &BinaryIdentity::from("game_logic.dll")),
            r#"{"binary": "game_logic.dll", "filed_at": 1, "records": []}"#,
        )
        .expect("file empty ledger");
        let ledgers = derive_binary_unknown_ledgers(dir.path(), &binaries);
        assert_eq!(
            ledgers[0].unknowns.open.as_deref(),
            Some(&[] as &[calxgloss_types::UnitUnknown])
        );
    }

    #[test]
    fn the_run_close_derivation_joins_the_reviewers_settles_separately() {
        let dir = tempfile::tempdir().expect("temp workspace");
        let open = record("open-1", UnknownSeverity::Blocking, "Never exercised?");
        let settled = record("settled-1", UnknownSeverity::Material, "Answered.");
        let dismissed = record("settled-2", UnknownSeverity::Material, "Ruled out.");
        std::fs::create_dir_all(unknown_ledger_dir(dir.path())).expect("unknowns dir");
        let records = vec![open, settled.clone(), dismissed.clone()];
        calxgloss_types::save_json(
            &unknown_ledger_path(dir.path(), &BinaryIdentity::from("game_logic.dll")),
            &calxgloss_types::UnknownLedger {
                binary: BinaryIdentity::from("game_logic.dll"),
                filed_at: 1_700_000_000,
                records: Some(records.clone()),
            },
        )
        .expect("file ledger");
        let mut resolutions = UnknownResolutions::default();
        resolutions
            .resolve(&settled, "the answer landed", 1, 1_700_000_500)
            .expect("resolve");
        resolutions
            .dismiss(&dismissed, "out of scope", 1, 1_700_000_500)
            .expect("dismiss");
        calxgloss_types::save_json(&unknown_resolutions_path(dir.path()), &resolutions)
            .expect("file resolutions");

        let ledgers = derive_binary_unknown_ledgers(dir.path(), &["game_logic.dll".to_string()]);
        let ledger = &ledgers[0];
        assert_eq!(ledger.unknowns.open.as_ref().expect("open").len(), 1);
        assert_eq!(ledger.unknowns.resolved, 1);
        assert_eq!(ledger.unknowns.dismissed, 1);
        assert_eq!(
            ledger
                .unknowns
                .open_by_severity
                .get(&UnknownSeverity::Blocking),
            Some(&1),
            "the open severity counts are the open ones"
        );
    }

    #[test]
    fn unreadable_documents_degrade_to_unknown_on_this_derived_surface() {
        let dir = tempfile::tempdir().expect("temp workspace");
        std::fs::create_dir_all(unknown_ledger_dir(dir.path())).expect("unknowns dir");
        std::fs::write(
            unknown_ledger_path(dir.path(), &BinaryIdentity::from("game_logic.dll")),
            "{ not json",
        )
        .expect("corrupt ledger");
        let ledgers = derive_binary_unknown_ledgers(dir.path(), &["game_logic.dll".to_string()]);
        assert_eq!(
            ledgers[0].unknowns.open, None,
            "unreadable is unknown, never zero"
        );
    }
}

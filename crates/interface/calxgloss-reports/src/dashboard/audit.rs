//! The per-binary unknown audit ledger (issue #377): the end of a run is
//! a claim list, not a quiet queue.
//!
//! One derived join serves every reader. The pipeline's ledger documents
//! (`re/unknowns/<binary identity>.json`) and the reviewer's resolutions
//! document (`re/review/unknown_resolutions.json`) join at read time into a
//! [`BinaryUnknownLedger`] per target binary; the terminal dashboard renders
//! the audit-ledger section from the builder's copy of that model, and the
//! live/auto run close prints the same section through
//! [`print_run_audit_ledger`], which derives the same model from the same
//! documents. The two readers print identical lines because they run the
//! same function on the same shape.
//!
//! The ledger's own absence prints as unknown, never as a clean run: a
//! binary with no filed ledger, a filed document whose `records` key is
//! absent, and an unreadable document all read as *unknown* — the
//! three-readings rule [`EffectiveLedger`](calxgloss_types::EffectiveLedger)
//! establishes, applied to the track's own artifact. Open, resolved, and
//! dismissed counts never fold into one another, and the section is bounded
//! at five named records with the remainder folded into a count — the
//! discipline the coverage fold and the prompt section already keep.

use std::path::Path;

use calxgloss_types::{
    BinaryIdentity, BinaryUnknownLedger, EffectiveLedger, UnitUnknowns, UnknownRecord,
    UnknownResolutions, read_unknown_ledger, read_unknown_resolutions,
};

use super::render::{println_content, severity_label, yellow_bold};

/// Open records the audit ledger names per binary — five names plus a
/// count, the bound the prompt section and P19's coverage fold keep
/// (issue #377). A binary with forty open gaps cannot crowd the run close
/// out of its own summary.
pub const AUDIT_LEDGER_BOUND: usize = 5;

/// The header both readers print above the per-binary ledger lines.
pub fn audit_ledger_header() -> String {
    "  Unknown audit ledger".to_string()
}

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

/// Derive the audit ledgers for the named binaries straight from the
/// documents — the run close's entry point. The readings and the
/// degradation wording match the dashboard builder exactly: an unreadable
/// ledger or resolutions document degrades to *unknown* on this derived
/// surface with a named warning, never to a clean reading. Binaries are
/// printed in the order named, deduplicated on their verbatim identity.
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
    let mut seen: Vec<String> = Vec::new();
    let mut ledgers = Vec::new();
    for binary in binaries {
        if seen.iter().any(|landed| landed == binary) {
            continue;
        }
        seen.push(binary.clone());
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
            binary,
            records.as_deref(),
            resolutions,
        ));
    }
    ledgers
}

/// The run-close audit-ledger section as lines — the header, then every
/// named binary's ledger lines, derived from the same join the dashboard
/// builder carries (issue #377). A run close with no target binaries
/// produces no lines at all — there is no claim to audit.
pub fn run_audit_ledger_lines(workspace: &Path, binaries: &[String]) -> Vec<String> {
    if binaries.is_empty() {
        return Vec::new();
    }
    let ledgers = derive_binary_unknown_ledgers(workspace, binaries);
    let mut lines = vec![audit_ledger_header(), String::new()];
    for ledger in &ledgers {
        lines.extend(audit_ledger_lines(ledger));
        lines.push(String::new());
    }
    lines
}

/// Print the run-close audit-ledger section: the same lines
/// [`run_audit_ledger_lines`] derives, content-padded like every other
/// dashboard surface (issue #377).
pub fn print_run_audit_ledger(workspace: &Path, binaries: &[String]) {
    for line in run_audit_ledger_lines(workspace, binaries) {
        println_content(line);
    }
}

/// One binary's audit-ledger lines, shared byte-for-byte by the terminal
/// dashboard section and the run close (issue #377).
///
/// Three readings, never collapsed: *unknown* — no ledger filed for this
/// binary, a filed document whose `records` key is absent, or an
/// unreadable document — prints as unknown and never as a clean run;
/// known-and-none prints the honest empty line; open records print their
/// severity counts in the head line and one bounded line each beneath it,
/// with the remainder folded into a count. Resolved and dismissed settle
/// rides visibly alongside, in its own counts, never folded into open.
pub fn audit_ledger_lines(ledger: &BinaryUnknownLedger) -> Vec<String> {
    let settled = if ledger.unknowns.resolved + ledger.unknowns.dismissed == 0 {
        None
    } else {
        Some(format!(
            "{} resolved, {} dismissed",
            ledger.unknowns.resolved, ledger.unknowns.dismissed
        ))
    };
    let mut lines = Vec::new();
    match ledger.unknowns.open.as_ref() {
        None => {
            lines.push(yellow_bold(&format!(
                "  {} — unknown: no ledger filed or unreadable — never a clean run",
                ledger.binary
            )));
        }
        Some(open) if open.is_empty() => {
            let head = format!("  {} — none open (ledger filed)", ledger.binary);
            lines.push(match &settled {
                Some(s) => format!("{head} ({s})"),
                None => head,
            });
        }
        Some(open) => {
            let severities: Vec<String> = ledger
                .unknowns
                .open_by_severity
                .iter()
                .rev()
                .filter_map(|(severity, count)| {
                    if *count == 0 {
                        None
                    } else {
                        Some(format!("{count} {}", severity_label(severity)))
                    }
                })
                .collect();
            lines.push(yellow_bold(&format!(
                "  {} — {} open ({})",
                ledger.binary,
                open.len(),
                severities.join(", ")
            )));
            for record in open.iter().take(AUDIT_LEDGER_BOUND) {
                lines.push(format!(
                    "    • [{}] {} — needs: {}",
                    severity_label(&record.severity),
                    record.question,
                    record.required_evidence
                ));
            }
            if let Some(hidden) = open.len().checked_sub(AUDIT_LEDGER_BOUND) {
                lines.push(format!("    (+{hidden} more open records not listed)"));
            }
        }
    }
    if let Some(s) = settled {
        lines.push(format!("    ({s})"));
    }
    lines
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

    fn ledger_with(
        open: &[UnknownRecord],
        resolved: &[&str],
        dismissed: &[&str],
    ) -> BinaryUnknownLedger {
        let mut resolutions = UnknownResolutions::default();
        for id in resolved {
            let landed = open
                .iter()
                .find(|r| r.id == *id)
                .cloned()
                .unwrap_or_else(|| record(id, UnknownSeverity::Notable, "settled question"));
            resolutions
                .resolve(
                    &landed,
                    "the reviewer established the fact",
                    1,
                    1_700_000_500,
                )
                .expect("first settle lands on a fresh record");
        }
        for id in dismissed {
            let landed = open
                .iter()
                .find(|r| r.id == *id)
                .cloned()
                .unwrap_or_else(|| record(id, UnknownSeverity::Notable, "dismissed question"));
            resolutions
                .dismiss(&landed, "out of scope", 1, 1_700_000_500)
                .expect("first settle lands on a fresh record");
        }
        let joined = resolutions.join(open);
        BinaryUnknownLedger {
            binary: "game_logic.dll".to_string(),
            unknowns: UnitUnknowns::from_joined(&joined),
        }
    }

    #[test]
    fn open_records_print_severity_counts_and_one_bounded_line_each() {
        let open: Vec<UnknownRecord> = (0..8)
            .map(|i| {
                record(
                    &format!("r{i}"),
                    if i < 2 {
                        UnknownSeverity::Blocking
                    } else if i < 5 {
                        UnknownSeverity::Material
                    } else {
                        UnknownSeverity::Notable
                    },
                    &format!("Open question {i}?"),
                )
            })
            .collect();
        let ledger = ledger_with(&open, &[], &[]);
        let text = audit_ledger_lines(&ledger).join("\n");

        assert!(
            text.contains("8 open (2 blocking, 3 material, 3 notable)"),
            "{text}"
        );
        for i in 0..5 {
            assert!(
                text.contains(&format!(
                    "• [{severity}] Open question {i}?",
                    severity = if i < 2 {
                        "blocking"
                    } else if i < 5 {
                        "material"
                    } else {
                        "notable"
                    }
                )),
                "record {i} missing its bounded line: {text}"
            );
            assert!(
                text.contains(&format!("needs: filed r{i} evidence")),
                "{text}"
            );
        }
        for i in 5..8 {
            assert!(
                !text.contains(&format!("Open question {i}?")),
                "question {i} sits past the bound and never renders: {text}"
            );
        }
        assert!(text.contains("(+3 more open records not listed)"), "{text}");
    }

    #[test]
    fn open_resolved_and_dismissed_counts_never_fold_into_one_another() {
        let open = vec![
            record("open-1", UnknownSeverity::Blocking, "Still open?"),
            record("open-2", UnknownSeverity::Material, "Also open?"),
        ];
        // Two settled records ride alongside the open two.
        let mut resolutions = UnknownResolutions::default();
        let resolved = record("settled-1", UnknownSeverity::Notable, "Answered.");
        let dismissed = record("settled-2", UnknownSeverity::Blocking, "Out of scope.");
        let mut all = open.clone();
        all.extend([resolved.clone(), dismissed.clone()]);
        resolutions
            .resolve(
                &resolved,
                "the answer landed in the type database",
                1,
                1_700_000_500,
            )
            .expect("first settle lands");
        resolutions
            .dismiss(
                &dismissed,
                "the reviewer ruled it out of scope",
                1,
                1_700_000_500,
            )
            .expect("first settle lands");
        let joined = resolutions.join(&all);
        let ledger = BinaryUnknownLedger {
            binary: "game_logic.dll".to_string(),
            unknowns: UnitUnknowns::from_joined(&joined),
        };
        let text = audit_ledger_lines(&ledger).join("\n");

        assert!(text.contains("2 open (1 blocking, 1 material)"), "{text}");
        assert!(text.contains("(1 resolved, 1 dismissed)"), "{text}");
        // A dismissed record still counts in the audit ledger — visibly —
        // but never as open and never as established.
        assert!(!text.contains("Out of scope?"), "{text}");
        assert!(!text.contains("Answered."), "{text}");
        assert!(
            text.contains("1 blocking"),
            "the open severity counts stay the open ones: {text}"
        );
    }

    #[test]
    fn an_unfiled_ledger_prints_unknown_never_a_clean_run() {
        let ledger = BinaryUnknownLedger {
            binary: "game_logic.dll".to_string(),
            unknowns: UnitUnknowns::unknown(),
        };
        let text = audit_ledger_lines(&ledger).join("\n");
        assert!(text.contains("unknown"), "{text}");
        assert!(!text.contains("none open"), "{text}");
        assert!(!text.contains("0 open"), "{text}");
    }

    #[test]
    fn a_filed_empty_ledger_prints_the_honest_empty_section() {
        let ledger = ledger_with(&[], &[], &[]);
        let text = audit_ledger_lines(&ledger).join("\n");
        assert_eq!(text.trim(), "game_logic.dll — none open (ledger filed)");

        // Settled state rides the honest empty line too: review settled
        // records on a binary the batch found nothing open on.
        let settled = BinaryUnknownLedger {
            binary: "game_logic.dll".to_string(),
            unknowns: UnitUnknowns {
                open: Some(Vec::new()),
                resolved: 1,
                dismissed: 2,
                ..UnitUnknowns::default()
            },
        };
        let text = audit_ledger_lines(&settled).join("\n");
        assert!(text.contains("none open (ledger filed)"), "{text}");
        assert!(text.contains("1 resolved, 2 dismissed"), "{text}");
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
        let text = audit_ledger_lines(ledger).join("\n");
        assert!(text.contains("1 open (1 blocking)"), "{text}");
        assert!(text.contains("Never exercised?"), "{text}");
        assert!(text.contains("(1 resolved, 1 dismissed)"), "{text}");
    }

    #[test]
    fn the_run_close_section_names_every_target_and_nothing_for_no_targets() {
        let dir = tempfile::tempdir().expect("temp workspace");
        let lines = run_audit_ledger_lines(
            dir.path(),
            &["game_logic.dll".to_string(), "no_ledger.dll".to_string()],
        );
        assert_eq!(lines[0], audit_ledger_header());
        let text = lines.join("\n");
        assert!(text.contains("game_logic.dll — unknown"), "{text}");
        assert!(text.contains("no_ledger.dll — unknown"), "{text}");
        assert!(!text.contains("none open"), "no target is clean: {text}");

        // No target binaries: the close prints no section at all.
        assert!(run_audit_ledger_lines(dir.path(), &[]).is_empty());
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

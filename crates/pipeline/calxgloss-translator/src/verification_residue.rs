//! Verification residue: the unknown records the verification signal itself
//! derives (issue #373, part of P21 #367).
//!
//! The review gate so far proved what the pipeline's invented inputs
//! happened to test: a unit could reach review with its verification
//! counters never moved, and an export could sit outside every filed
//! baseline document with nobody saying so. This module makes both facts
//! standing questions, so "translated" and "proven" never read the same
//! again about a subject the case set never exercised.
//!
//! Both kinds' only write sites are here, and both facts are exactly the
//! already-checkable ones the ticket names — no new evidence work happens
//! here, and nothing reads a record back into the walk:
//!
//! * a unit reaching review having run zero baseline cases files one
//!   `baseline_never_run` record against that unit, its origin the unit's
//!   own verification case set — the fact is the walk's verification
//!   counters (`tests_total` on every attempt), read after the walk, not
//!   a verdict re-judged here;
//! * an export no filed baseline document ever covered files one
//!   `export_uncovered` record against the binary, its origin a case set
//!   named for the export — the fact is the export listing already on
//!   disk beside the baseline documents already filed; an export whose
//!   document is filed asks nothing, and an export listing that never
//!   came back reads *unknown* and files nothing (ADR-0053's
//!   absent-reads-unknown rule), exactly like the seam's undeclared
//!   family.
//!
//! Both records land at [`UnknownSeverity::Blocking`] — the level whose
//! own criterion (issue #368's shared-type docs) names these two facts
//! verbatim: "zero baseline cases ever run, no filed baseline document
//! for an export". The question lines keep the track's frame — the
//! subject, then the admission — and the required evidence names the
//! input vector that would have exercised the subject, the doctrine the
//! #368 pins spell as "filed baseline cases calling F".
//!
//! Re-deriving either fact across attempts, batches, and runs folds the
//! same id: the same unit's zero-case walk, and the same export still
//! outside every baseline document, re-admit the standing question rather
//! than file a second opinion. A unit whose cases ran and a covered
//! export derive nothing, so a re-filed ledger simply stops landing
//! those entries.

use calxgloss_types::{UnknownKind, UnknownOrigin, UnknownRecord, UnknownSeverity};

/// Derive the one `baseline_never_run` record for a unit that reached
/// review having run zero baseline cases: `binary` and `function` name
/// the unit, `now` is the derivation stamp the ledger's filing merge
/// folds against what landed.
///
/// The origin is the unit's own verification case set — slot `cases-`
/// plus the unit name, the id pinning #368 established — so the same
/// unit walking again without a single case re-derives this record's id:
/// one standing question per unit, not one per zero-case walk.
pub fn zero_case_residue(binary: &str, function: &str, now: u64) -> UnknownRecord {
    UnknownRecord::derive(
        binary,
        Some(function.to_string()),
        UnknownKind::BaselineNeverRun,
        UnknownSeverity::Blocking,
        format!(
            "What is `{function}` really doing — the unit reached review having run zero \
             baseline cases: its behavior was never exercised?"
        ),
        format!("Baseline cases run against `{function}`"),
        UnknownOrigin::CaseSet {
            case_set: format!("cases-{function}"),
        },
        now,
    )
}

/// Derive the one `export_uncovered` record for an export no filed
/// baseline document ever covered: `binary` names the target binary and
/// `export` the export's own name from the listing, `now` the derivation
/// stamp the filing merge folds.
///
/// The record is filed against the binary, not a function slot — the
/// export is the subject the source slot names (issue #368's derivation:
/// `export-{name}` beside no function). The same export outside every
/// baseline document in a later batch re-derives this record's id.
pub fn uncovered_export_residue(binary: &str, export: &str, now: u64) -> UnknownRecord {
    UnknownRecord::derive(
        binary,
        None,
        UnknownKind::ExportUncovered,
        UnknownSeverity::Blocking,
        format!(
            "What is `{export}` really doing — no filed baseline document ever covered it: \
             no input vector ever called it?"
        ),
        format!("A filed baseline document calling `{export}`"),
        UnknownOrigin::CaseSet {
            case_set: format!("export-{export}"),
        },
        now,
    )
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::{DECLARED_UNKNOWN_KINDS, unknown_roster_faults};

    #[test]
    fn a_zero_case_walk_derives_the_units_standing_question_with_the_pinned_shape() {
        let record = zero_case_residue("game_logic.dll", "F", 1_700_000_000);

        assert_eq!(record.kind, UnknownKind::BaselineNeverRun);
        assert_eq!(
            record.severity,
            UnknownSeverity::Blocking,
            "zero baseline cases ever run is the Blocking level's own written criterion"
        );
        assert_eq!(record.function.as_deref(), Some("F"));
        assert_eq!(
            record.origin,
            UnknownOrigin::CaseSet {
                case_set: "cases-F".to_string(),
            },
            "the unit's verification case set is the origin"
        );
        assert_eq!(
            record.source_slot(),
            "cases-F",
            "the same unit's next zero-case walk re-derives this slot — the #368 pin"
        );
        assert_eq!(
            record.id,
            "game_logic.dll/F/baseline_never_run/cases-F",
            "the derivation is the shared one, the unit as subject, the case set as slot"
        );
        assert_eq!(
            record.question,
            "What is `F` really doing — the unit reached review having run zero baseline \
             cases: its behavior was never exercised?",
            "the question states the admitted fact on the track's own frame"
        );
        assert_eq!(
            record.required_evidence,
            "Baseline cases run against `F`",
            "the required evidence names the input vector that would have exercised the unit"
        );
        assert_eq!(record.revision, 1, "a fresh derivation starts at revision 1");
        assert_eq!(record.first_seen, 1_700_000_000);
        assert_eq!(record.last_seen, 1_700_000_000);
    }

    #[test]
    fn an_uncovered_export_files_one_record_against_the_binary_it_was_outside() {
        let record = uncovered_export_residue("game_logic.dll", "DrawSprite", 1_700_000_000);

        assert_eq!(record.kind, UnknownKind::ExportUncovered);
        assert_eq!(
            record.severity,
            UnknownSeverity::Blocking,
            "no filed baseline document for an export is the other half of the Blocking \
             criterion's own wording"
        );
        assert_eq!(
            record.function, None,
            "the export is the subject the slot names — the record rides the binary's ledger"
        );
        assert_eq!(
            record.origin,
            UnknownOrigin::CaseSet {
                case_set: "export-DrawSprite".to_string(),
            },
            "the case set that never called the export is the origin"
        );
        assert_eq!(
            record.id,
            "game_logic.dll/-/export_uncovered/export-DrawSprite",
            "the #368 derivation: no function slot, the export named in the source slot"
        );
        assert_eq!(
            record.question,
            "What is `DrawSprite` really doing — no filed baseline document ever covered it: \
             no input vector ever called it?",
            "the question states the admitted fact on the track's own frame"
        );
        assert_eq!(
            record.required_evidence,
            "A filed baseline document calling `DrawSprite`",
            "the required evidence names the input vector that would have exercised the export"
        );
    }

    #[test]
    fn re_deriving_both_facts_lands_the_same_id() {
        // The same unit's next zero-case walk, and the same export still
        // outside every baseline document in a later batch, are the same
        // standing questions — a re-run never duplicates what a reviewer
        // may already have answered.
        let unit_first = zero_case_residue("game_logic.dll", "F", 1_700_000_000);
        let unit_again = zero_case_residue("game_logic.dll", "F", 1_700_000_500);
        assert_eq!(unit_first.id, unit_again.id, "the id is the shared derivation");
        let export_first = uncovered_export_residue("game_logic.dll", "DrawSprite", 1_700_000_000);
        let export_again = uncovered_export_residue("game_logic.dll", "DrawSprite", 1_700_000_500);
        assert_eq!(export_first.id, export_again.id);
        assert!(
            unit_first.content_matches(&unit_again) && export_first.content_matches(&export_again),
            "only the stamp moves — the filing merge keeps the landed revisions and first-seens"
        );
    }

    #[test]
    fn the_shared_checker_recognizes_these_kinds_write_sites() {
        // The full pairing against every producer is the roster-sweep ticket
        // (#375); what is pinned here is that records derived at these two
        // write sites pair with the declared roster: the checker's verdict
        // has no fault naming `baseline_never_run` or `export_uncovered` —
        // not "no producer", not an undeclared kind, not a slot produced
        // twice.
        let records = [
            zero_case_residue("game_logic.dll", "F", 1_700_000_000),
            uncovered_export_residue("game_logic.dll", "DrawSprite", 1_700_000_000),
        ];
        let pairs: Vec<(String, String)> = records
            .iter()
            .map(|r| (r.kind.to_string(), r.source_slot()))
            .collect();
        let produced: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(kind, slot)| (kind.as_str(), slot.as_str()))
            .collect();
        let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
        assert!(
            faults
                .iter()
                .all(|fault| !fault.contains("baseline_never_run")
                    && !fault.contains("export_uncovered")),
            "the verification-residue write sites pair with the roster: {faults:?}"
        );
    }
}

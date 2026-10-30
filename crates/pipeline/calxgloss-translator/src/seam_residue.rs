//! Seam residue: the unknown records the batch's held capability report
//! derives (issue #371, part of P21 #367).
//!
//! P20 gave the analysis engine its live word: the held report, fetched once
//! as the batch's scan source opens, states which question families the
//! engine can answer right now and which it admits it cannot. P21 (#368)
//! landed the shared unknown-record vocabulary. This module is where the two
//! meet — every family the held report declares `unavailable` becomes one
//! `analysis_family` unknown record, filed against each unit whose retry
//! posture actually re-asks that family. This is the kind's only write site:
//! no new analysis happens here, and only families the engine itself
//! admitted it cannot answer become records.
//!
//! The mapping the shared type's own docs pin (issue #368):
//!
//! * declared `unavailable` → [`UnknownSeverity::Blocking`] — "the evidence
//!   that would establish the subject never arrived at all" is that level's
//!   honest criterion, spelled for an answer the seam says it cannot give;
//! * a declared `answerable` family derives nothing — a family the engine
//!   can answer today asks no standing question;
//! * a family the report never declared — which reads *unknown* — derives
//!   nothing, in both directions: absence never produces a gap record, and a
//!   produced record never rests on an absent declaration. P20 pinned that
//!   unknown prunes nothing in the retry ladder ([`unavailable_reask_families`]);
//!   the same rule governs what this producer files;
//! * a family the unit's posture never re-asks derives nothing against that
//!   unit — the admission bears on units that would ask the seam that
//!   question, and a ladder that never re-reads never needs the answer.
//!
//! The question line is built on the entry's own admission line, following
//! [`FamilyCapability::admission`]'s doctrine (issue #355): the engine's own
//! words stand, and the bare status word is the fallback when an entry gave
//! no reason. The record's source slot is the seam's own family id and its
//! origin names that family, so a re-derivation across attempts and runs
//! folds the same id — and the required evidence names the family that
//! could not answer.

use calxgloss_types::{
    CapabilityReport, FamilyCapability, RetryStrategy, UnknownKind, UnknownOrigin, UnknownRecord,
    UnknownSeverity,
};

use crate::retry::RetryConfig;
use crate::retry::helpers::{ESCALATE_REASK_FAMILIES, unavailable_reask_families};

/// The question families the unit's retry posture would re-ask of the seam.
///
/// Posture is the ladder the loop is configured to walk, not its outcome:
/// the escalate rung and the context-tier walk both stand behind
/// `escalate_on_failure` (the retry loop steps strategy and tier only under
/// that gate), while a first retry configured straight onto `Escalate`
/// re-asks on its own, and a ladder with one attempt never retries at all.
/// A posture that re-asks re-asks [`ESCALATE_REASK_FAMILIES`] — the one
/// roster #356 spelled for both escalate-shaped postures — and a posture
/// that never escalates re-asks nothing of the seam.
pub fn posture_reask_families(config: &RetryConfig) -> &'static [&'static str] {
    if config.max_attempts > 1
        && (config.escalate_on_failure || config.retry_strategy == RetryStrategy::Escalate)
    {
        ESCALATE_REASK_FAMILIES
    } else {
        &[]
    }
}

/// Derive one seam-residue record for each family `re_asked` that `report`
/// declares `unavailable` — in the posture list's own family order.
/// `binary` and `function` name the unit whose posture asked, and `now` is
/// the derivation stamp the ledger's filing merge folds against what landed.
///
/// The lookup is P20's own: [`unavailable_reask_families`] pairs each
/// re-asked family with a declared entry and lets an answerable or
/// undeclared family (which reads *unknown*) fall through — this producer
/// files against exactly the families the engine said it cannot answer,
/// never against what the report failed to say. Every record is derived
/// through [`UnknownRecord::derive`], so the id is the shared derivation —
/// and this function is the only site in the track naming
/// [`UnknownKind::AnalysisFamily`] as a producer.
pub fn seam_residue(
    binary: &str,
    function: &str,
    report: &CapabilityReport,
    re_asked: &[&str],
    now: u64,
) -> Vec<UnknownRecord> {
    unavailable_reask_families(report, re_asked)
        .into_iter()
        .map(|entry| derive_family_record(binary, function, entry, now))
        .collect()
}

/// Derive the one record for one unavailable re-asked family: severity from
/// the admission's criterion, the question built on the entry's own
/// admission line, and the required evidence naming the family that could
/// not answer.
fn derive_family_record(
    binary: &str,
    function: &str,
    entry: &FamilyCapability,
    now: u64,
) -> UnknownRecord {
    // The admission doctrine, per family: the entry's own admission line
    // stands, and the bare status word is the fallback when it gave no
    // reason — exactly what `FamilyCapability::admission` spells for the
    // whole entry. A `unavailable` entry always admits itself; the fallback
    // only keeps the wording honest should an entry ever arrive without it.
    let admission = entry
        .admission()
        .unwrap_or_else(|| entry.status.to_string());
    UnknownRecord::derive(
        binary,
        Some(function.to_string()),
        UnknownKind::AnalysisFamily,
        UnknownSeverity::Blocking,
        format!(
            "What is `{function}` really doing — analysis engine admitted `{admission}` for the `{}` family?",
            entry.id
        ),
        format!("Full `{}` answers from the analysis engine", entry.id),
        UnknownOrigin::Family {
            family: entry.id.clone(),
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
    use calxgloss_types::{AvailabilityStatus, DECLARED_UNKNOWN_KINDS, unknown_roster_faults};

    /// A held report in the shape the engine declares: one entry per family,
    /// with a reason line beside the admissions.
    fn report(entries: &[(&str, AvailabilityStatus, Option<&str>)]) -> CapabilityReport {
        CapabilityReport {
            families: entries
                .iter()
                .map(|(id, status, reason)| FamilyCapability {
                    id: (*id).to_string(),
                    status: *status,
                    reason: (*reason).map(str::to_string),
                })
                .collect(),
        }
    }

    fn residue(
        entries: &[(&str, AvailabilityStatus, Option<&str>)],
        re_asked: &[&str],
    ) -> Vec<UnknownRecord> {
        seam_residue(
            "game_logic.dll",
            "FUN_18003ab00",
            &report(entries),
            re_asked,
            1_700_000_000,
        )
    }

    #[test]
    fn an_unavailable_re_asked_family_derives_one_record_with_the_pinned_shape() {
        let records = residue(
            &[(
                "decompilation",
                AvailabilityStatus::Unavailable,
                Some("Zanthoxylum builds never produce a body"),
            )],
            &["function-inventory", "decompilation"],
        );
        assert_eq!(
            records.len(),
            1,
            "one unavailable re-asked family, one record"
        );
        let record = &records[0];

        assert_eq!(record.kind, UnknownKind::AnalysisFamily);
        assert_eq!(
            record.severity,
            UnknownSeverity::Blocking,
            "the seam says the answer cannot arrive at all — the Blocking level's own criterion"
        );
        assert_eq!(record.function.as_deref(), Some("FUN_18003ab00"));
        assert_eq!(
            record.origin,
            UnknownOrigin::Family {
                family: "decompilation".to_string(),
            },
            "the origin names the seam family that could not answer"
        );
        assert_eq!(
            record.source_slot(),
            "decompilation",
            "the slot is the seam's own family id"
        );
        assert_eq!(
            record.id,
            "game_logic.dll/FUN_18003ab00/analysis_family/decompilation"
        );
        assert_eq!(
            record.question,
            "What is `FUN_18003ab00` really doing — analysis engine admitted \
             `unavailable — Zanthoxylum builds never produce a body` for the \
             `decompilation` family?",
            "the question is built on the entry's own admission line, P20's \
             single-home wording — not a coverage-shaped restatement"
        );
        assert_eq!(
            record.required_evidence, "Full `decompilation` answers from the analysis engine",
            "the required evidence names the family that could not answer"
        );
        assert_eq!(
            record.revision, 1,
            "a fresh derivation starts at revision 1"
        );
        assert_eq!(record.first_seen, 1_700_000_000);
        assert_eq!(record.last_seen, 1_700_000_000);
    }

    #[test]
    fn only_a_declared_unavailable_admission_derives_a_record() {
        // Answerable derives nothing, an undeclared family (unknown) derives
        // nothing, and an empty report — a report that declared nothing —
        // derives nothing: the produces-nothing rule holds in both
        // directions, absence never produces a gap record and a produced
        // record never rests on an absent declaration.
        let records = residue(
            &[("function-inventory", AvailabilityStatus::Answerable, None)],
            &["function-inventory", "decompilation"],
        );
        assert!(
            records.is_empty(),
            "an answerable family asks no question, and the undeclared \
             `decompilation` family reads unknown, never unavailable"
        );
        assert!(
            seam_residue(
                "game_logic.dll",
                "FUN_18003ab00",
                &CapabilityReport::default(),
                &["function-inventory", "decompilation"],
                1_700_000_000,
            )
            .is_empty(),
            "a report that declared nothing says nothing"
        );
    }

    #[test]
    fn a_family_the_posture_never_re_asks_gets_no_record() {
        // The report admits `xrefs` and `strings` — neither stands in the
        // posture's re-asked roster — while `decompilation` does.
        let records = residue(
            &[
                ("xrefs", AvailabilityStatus::Unavailable, None),
                ("strings", AvailabilityStatus::Unavailable, None),
            ],
            &["function-inventory", "decompilation"],
        );
        assert!(
            records.is_empty(),
            "the admission only bears on units that would ask that family of the seam"
        );
    }

    #[test]
    fn an_unavailable_entry_with_no_reason_falls_back_to_its_bare_status_word() {
        let records = residue(
            &[("decompilation", AvailabilityStatus::Unavailable, None)],
            &["decompilation"],
        );
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].question,
            "What is `FUN_18003ab00` really doing — analysis engine admitted \
             `unavailable` for the `decompilation` family?",
            "an entry that gave no reason falls back to its bare status word, \
             the admission doctrine spelled per family"
        );
    }

    #[test]
    fn two_unavailable_re_asked_families_are_two_records_in_posture_order() {
        let records = residue(
            &[
                ("decompilation", AvailabilityStatus::Unavailable, None),
                ("function-inventory", AvailabilityStatus::Unavailable, None),
            ],
            &["function-inventory", "decompilation"],
        );
        let slots: Vec<String> = records.iter().map(|r| r.source_slot()).collect();
        assert_eq!(
            slots,
            vec!["function-inventory", "decompilation"],
            "the posture list's order leads, and each family keeps its own slot"
        );
        assert_ne!(records[0].id, records[1].id);
    }

    #[test]
    fn re_deriving_the_same_gap_across_runs_lands_the_same_id() {
        let entry = (
            "decompilation",
            AvailabilityStatus::Unavailable,
            Some("no vtable evidence on this target"),
        );
        let first = residue(&[entry], &["decompilation"]);
        let later = seam_residue(
            "game_logic.dll",
            "FUN_18003ab00",
            &report(&[entry]),
            &["decompilation"],
            1_700_000_900,
        );
        assert_eq!(first[0].id, later[0].id, "the id excludes the stamps");
        assert!(
            first[0].content_matches(&later[0]),
            "the same admission re-read lands the same persisted content — \
             the filing merge will not bump a revision for it"
        );
    }

    #[test]
    fn the_posture_helper_reads_the_configured_ladder_not_its_outcome() {
        // Default: the auto cycle walks onto Escalate and the tier walk can
        // step onto the module tiers — both escalate-shaped re-asks.
        assert_eq!(
            posture_reask_families(&RetryConfig::default()),
            ESCALATE_REASK_FAMILIES,
            "the default ladder eventually re-asks through its escalate rungs"
        );
        // A ladder that never escalates repeats its fix strategy and never
        // steps tier: it asks the seam nothing beyond the first attempt.
        let flat = RetryConfig {
            max_attempts: 3,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };
        assert_eq!(posture_reask_families(&flat), &[] as &[&str]);
        // A first retry configured straight onto Escalate re-asks on its own.
        let forced = RetryConfig {
            retry_strategy: RetryStrategy::Escalate,
            ..flat.clone()
        };
        assert_eq!(posture_reask_families(&forced), ESCALATE_REASK_FAMILIES);
        // One attempt is the first attempt only: there is no retry to prune
        // and no question a re-ask could stand behind.
        let once = RetryConfig {
            max_attempts: 1,
            ..RetryConfig::default()
        };
        assert_eq!(posture_reask_families(&once), &[] as &[&str]);
    }

    #[test]
    fn the_shared_checker_recognizes_this_kinds_write_site() {
        // The full pairing against every producer is the roster-sweep ticket
        // (#375); what is pinned here is that a record derived at this write
        // site pairs with the declared roster: the checker's verdict has no
        // fault naming `analysis_family` — not "no producer", not an
        // undeclared kind, not a slot produced twice.
        let records = residue(
            &[
                (
                    "decompilation",
                    AvailabilityStatus::Unavailable,
                    Some("Zanthoxylum builds never produce a body"),
                ),
                ("function-inventory", AvailabilityStatus::Unavailable, None),
                ("strings", AvailabilityStatus::Answerable, None),
            ],
            &["function-inventory", "decompilation"],
        );
        let produced: Vec<(String, String)> = records
            .iter()
            .map(|r| (r.kind.to_string(), r.source_slot()))
            .collect();
        let produced: Vec<(&str, &str)> = produced
            .iter()
            .map(|(kind, slot)| (kind.as_str(), slot.as_str()))
            .collect();
        let faults = unknown_roster_faults(DECLARED_UNKNOWN_KINDS, &produced);
        assert!(
            faults
                .iter()
                .all(|fault| !fault.contains("analysis_family")),
            "the seam-residue write site pairs with the roster: {faults:?}"
        );
    }
}

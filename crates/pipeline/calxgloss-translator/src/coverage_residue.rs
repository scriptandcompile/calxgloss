//! Coverage residue: the unknown records a filed evidence document's coverage
//! admission derives (issue #369, part of P21 #367).
//!
//! P19 gave every evidence engine a coverage stamp: per facet, how far its
//! scan got and a limitation line admitting what it could not reach. P21
//! (#368) landed the shared unknown-record vocabulary. This module is where
//! the two meet — while the batch's per-unit evidence fold reads each filed
//! document through the [`projection read seam`](crate::evidence_projector),
//! every facet that document stamps `partial` or `unavailable` becomes one
//! `coverage_facet` unknown record, derived from the admission already on
//! disk. This is the kind's only write site: no new analysis happens here,
//! and only gaps the engines themselves admitted become records.
//!
//! The mapping the shared type's own docs pin (issue #368):
//!
//! * `partial` → [`UnknownSeverity::Material`] — "a facet that fell short by
//!   its own admission" is that level's honest criterion, spelled;
//! * `unavailable` → [`UnknownSeverity::Blocking`] — "the evidence that would
//!   establish the subject never arrived at all", spelled;
//! * `complete` and `unexamined` derive nothing — a facet examined end to
//!   end asks no question, and a facet the engine was never built to examine
//!   is a declared unknown, not a gap this scan admits;
//! * a document with no coverage record at all (a pre-P19 document, whose
//!   absence reads as *unknown*) derives nothing — absence never produces a
//!   gap record, and a produced record never rests on an absent one.
//!
//! The question line is built on the facet's own limitation line, following
//! [`ScanCoverage::admission`]'s doctrine (issue #346): the engine's own
//! words stand, and the bare status word is the fallback when an entry gave
//! no reason. The record's source slot is `{document}#{facet}` — the same
//! facet id admitted short by two documents is two gaps — and the derived
//! record's id folds the unit's function, the kind label, and that slot.

use calxgloss_types::{
    CoverageStatus, FacetCoverage, ScanCoverage, UnknownKind, UnknownOrigin, UnknownRecord,
    UnknownSeverity,
};

/// The document kind the known-library document contributes its residue
/// under. Unlike the fourteen folded documents it has no projection row
/// (its call-graph correlation is read outside the seam, issue #310), so the
/// residue derivation names it here, beside the gather that reads it.
pub const LIBMATCH_DOCUMENT: &str = "known-library result";

/// Derive one coverage-residue record for each facet `coverage` admits fell
/// short for this unit — `partial` or `unavailable`, in the coverage
/// record's own facet order. `document` is the kind of the filed document
/// whose stamp this is (the fold's row `KIND` for a folded row,
/// [`LIBMATCH_DOCUMENT`] beside the libmatch read), `function` the unit the
/// fold is gathering for, and `now` the derivation stamp the ledger's filing
/// merge folds against what landed.
///
/// Every record is derived through [`UnknownRecord::derive`], so the id is
/// the shared derivation — and this function is the only site in the track
/// naming [`UnknownKind::CoverageFacet`] as a producer.
pub fn coverage_residue(
    binary: &str,
    document: &str,
    function: &str,
    coverage: &ScanCoverage,
    now: u64,
) -> Vec<UnknownRecord> {
    coverage
        .facets
        .iter()
        .filter(|facet| {
            matches!(
                facet.status,
                CoverageStatus::Partial | CoverageStatus::Unavailable
            )
        })
        .map(|facet| derive_facet_record(binary, document, function, facet, now))
        .collect()
}

/// Derive the one record for one admitting facet: severity from its status,
/// the question built on its own limitation line, and the required evidence
/// naming the facet and the document that fell short.
fn derive_facet_record(
    binary: &str,
    document: &str,
    function: &str,
    facet: &FacetCoverage,
    now: u64,
) -> UnknownRecord {
    let severity = match facet.status {
        CoverageStatus::Partial => UnknownSeverity::Material,
        CoverageStatus::Unavailable => UnknownSeverity::Blocking,
        // A `complete` or `unexamined` facet never reaches here — the
        // filter that admits only the two shortfall statuses is spelled
        // above — but the match stays exhaustive so a new status cannot
        // slip in silently.
        _ => UnknownSeverity::Blocking,
    };
    // The admission doctrine, per facet: the entry's own limitation line
    // stands, and the bare status word is the fallback when it gave no
    // reason — exactly what `ScanCoverage::admission` spells for the whole
    // record.
    let status_word = facet.status.to_string();
    let limitation = facet.limitation.as_deref().unwrap_or(&status_word);
    UnknownRecord::derive(
        binary,
        Some(function.to_string()),
        UnknownKind::CoverageFacet,
        severity,
        format!(
            "What is `{function}` really doing — {document} admitted `{limitation}` on `{}`?",
            facet.id
        ),
        format!("Full `{}` coverage from the {document}", facet.id),
        UnknownOrigin::Document {
            document: document.to_string(),
            facet: facet.id.clone(),
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

    /// A coverage record in the shape the engines stamp: one entry per
    /// facet id, with a limitation line beside the admissions.
    fn coverage(entries: &[(&str, CoverageStatus, Option<&str>)]) -> ScanCoverage {
        ScanCoverage {
            status: CoverageStatus::Partial,
            facets: entries
                .iter()
                .map(|(id, status, limitation)| FacetCoverage {
                    id: (*id).to_string(),
                    status: *status,
                    limitation: limitation.map(str::to_string),
                })
                .collect(),
        }
    }

    fn residue(facets: &[(&str, CoverageStatus, Option<&str>)]) -> Vec<UnknownRecord> {
        coverage_residue(
            "game_logic.dll",
            "string context result",
            "FUN_18003ab00",
            &coverage(facets),
            1_700_000_000,
        )
    }

    #[test]
    fn an_admitting_facet_derives_one_record_with_the_pinned_shape() {
        let records = residue(&[(
            "function-bodies",
            CoverageStatus::Partial,
            Some("bodies past the size cap were not read"),
        )]);
        assert_eq!(records.len(), 1, "one admitting facet, one record");
        let record = &records[0];

        assert_eq!(record.kind, UnknownKind::CoverageFacet);
        assert_eq!(
            record.severity,
            UnknownSeverity::Material,
            "a facet that fell short by its own admission is the Material level's spelled criterion"
        );
        assert_eq!(record.function.as_deref(), Some("FUN_18003ab00"));
        assert_eq!(
            record.origin,
            UnknownOrigin::Document {
                document: "string context result".to_string(),
                facet: "function-bodies".to_string(),
            },
            "the origin names the document read and the facet that fell short"
        );
        assert_eq!(
            record.source_slot(),
            "string context result#function-bodies",
            "the slot carries the document kind ahead of the facet id"
        );
        assert_eq!(
            record.id,
            "game_logic.dll/FUN_18003ab00/coverage_facet/string context result#function-bodies"
        );
        assert_eq!(
            record.question,
            "What is `FUN_18003ab00` really doing — string context result admitted \
             `bodies past the size cap were not read` on `function-bodies`?",
            "the question is built on the facet's own limitation line"
        );
        assert_eq!(
            record.required_evidence,
            "Full `function-bodies` coverage from the string context result",
            "the required evidence names the facet and the document that fell short"
        );
        assert_eq!(
            record.revision, 1,
            "a fresh derivation starts at revision 1"
        );
        assert_eq!(record.first_seen, 1_700_000_000);
        assert_eq!(record.last_seen, 1_700_000_000);
    }

    #[test]
    fn an_unavailable_facet_blocks_and_falls_back_to_its_status_word() {
        let records = residue(&[("string-xrefs", CoverageStatus::Unavailable, None)]);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(
            record.severity,
            UnknownSeverity::Blocking,
            "the evidence never arrived at all — the Blocking level's own criterion"
        );
        assert_eq!(
            record.question,
            "What is `FUN_18003ab00` really doing — string context result admitted \
             `unavailable` on `string-xrefs`?",
            "an entry that gave no reason falls back to its bare status word, \
             the admission doctrine spelled per facet"
        );
    }

    #[test]
    fn nothing_but_an_admission_derives_a_record() {
        // The four statuses at once: only the two admissions derive.
        let records = residue(&[
            ("function-bodies", CoverageStatus::Complete, None),
            (
                "program-strings",
                CoverageStatus::Partial,
                Some("half the strings decoded"),
            ),
            ("string-xrefs", CoverageStatus::Unavailable, None),
            ("delay-imports", CoverageStatus::Unexamined, None),
        ]);
        let ids: Vec<String> = records.iter().map(|r| r.source_slot()).collect();
        assert_eq!(
            ids,
            vec![
                "string context result#program-strings",
                "string context result#string-xrefs",
            ],
            "a complete facet asks no question and an unexamined facet is a \
             declared unknown, never a gap record; admitting facets keep the \
             coverage record's own order"
        );
    }

    #[test]
    fn a_complete_coverage_record_with_no_admitting_facet_derives_nothing() {
        let records = coverage_residue(
            "game_logic.dll",
            "memory lifecycle result",
            "UpdateScene",
            &coverage(&[("function-bodies", CoverageStatus::Complete, None)]),
            1_700_000_000,
        );
        assert!(
            records.is_empty(),
            "a scan that admitted nothing on disk leaves nothing for the ledger to say"
        );
    }

    #[test]
    fn two_documents_short_on_one_facet_id_are_two_records() {
        let memory = coverage_residue(
            "game_logic.dll",
            "memory lifecycle result",
            "UpdateScene",
            &coverage(&[(
                "function-bodies",
                CoverageStatus::Partial,
                Some("calls through pointers were not traced"),
            )]),
            1_700_000_000,
        );
        let strings = coverage_residue(
            "game_logic.dll",
            "string context result",
            "UpdateScene",
            &coverage(&[(
                "function-bodies",
                CoverageStatus::Partial,
                Some("wide strings were not decoded"),
            )]),
            1_700_000_000,
        );
        assert_eq!(memory.len(), 1);
        assert_eq!(strings.len(), 1);
        assert_ne!(
            memory[0].id, strings[0].id,
            "the same facet id admitted short by two documents is two gaps"
        );
    }

    #[test]
    fn the_shared_checker_recognizes_this_kinds_write_site() {
        // The full pairing against every producer is the roster-sweep ticket
        // (#375); what is pinned here is that a record derived at this write
        // site pairs with the declared roster: the checker's verdict has no
        // fault naming `coverage_facet` — not "no producer", not an
        // undeclared kind, not a slot produced twice.
        let records = residue(&[
            (
                "function-bodies",
                CoverageStatus::Partial,
                Some("bodies past the size cap were not read"),
            ),
            ("string-xrefs", CoverageStatus::Unavailable, None),
        ]);
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
            faults.iter().all(|fault| !fault.contains("coverage_facet")),
            "the coverage-residue write site pairs with the roster: {faults:?}"
        );
    }
}

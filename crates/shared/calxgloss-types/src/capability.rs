//! The answer surface the analysis engine declares about itself at the seam.
//!
//! The `ScanSource` seam answers questions about the program. It used to
//! say nothing about its own limits: an empty callers list looked exactly
//! the same whether the program had no callers or the analysis engine
//! could not answer about callers at all. This module shapes what the
//! analysis engine declares instead: one entry per query family saying
//! whether it can answer that family *right now*, with a bounded reason
//! line when it cannot (track P20, issue #354). That is the same honesty
//! doctrine ADR-0053 pinned for scans, applied one level up.
//!
//! This shape sits beside the coverage record P19 shipped, and the two
//! divide the work the same way. A scan document's admitted coverage is
//! the *persisted* half: what that filed scan examined and what it could
//! not. A capability report is live session state: it is read from the
//! open seam and discarded when the run ends. It is never filed into a
//! scan document, a cache key, or any read plumbing.

use serde::{Deserialize, Serialize};

use crate::display_serde_label;

/// Whether the analysis engine can currently answer one family of
/// questions about the program — the closed set an analysis engine stamps
/// about its own answer surface (the ADR-0053 stamping verb, one level up).
///
/// Families are the seam's own query methods grouped into question
/// families, and every capability entry states its family's state with one
/// of these two labels. There is deliberately no `unknown` here: an
/// analysis engine admits `answerable` or `unavailable` about itself. A
/// family absent from a report reads as `unknown`, and that value is
/// derived at read time ([`EffectiveAvailability::Unknown`]), never written
/// (issue #354). This is the same one-way rule P19's
/// [`CoverageStatus`](crate::CoverageStatus) keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    /// The analysis engine can answer this family right now. An empty
    /// answer from it is a fact about the program.
    Answerable,
    /// The analysis engine cannot answer this family right now: the answer
    /// would not arrive even if the program holds the thing asked about.
    /// The entry's own reason line gives the reason why.
    Unavailable,
}

display_serde_label!(AvailabilityStatus {
    Answerable => "answerable",
    Unavailable => "unavailable",
});

/// A read-side availability status: the two writable statuses plus `unknown`.
///
/// This is what every consumer of a capability report branches on. `Unknown`
/// is the derived default for a family no report declares — the report's own
/// silence admits it. This is the same graceful degradation a pre-coverage
/// document shows. Because `Unknown` lives only on this read-side enum and
/// never on [`AvailabilityStatus`], no analysis engine can write it about
/// itself. An undeclared family can never be mistaken for an answerable
/// one, and in the other direction never for an unavailable one: unknown
/// reads as unknown, never as absence (issue #354).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectiveAvailability {
    /// The report declares the engine can answer this family right now.
    Answerable,
    /// The report declares the engine cannot answer this family right now.
    Unavailable,
    /// No report declares this family. The analysis engine said nothing
    /// about it, so what it can answer there is unknown, and its silence
    /// establishes nothing either way.
    Unknown,
}

impl From<AvailabilityStatus> for EffectiveAvailability {
    fn from(status: AvailabilityStatus) -> Self {
        match status {
            AvailabilityStatus::Answerable => Self::Answerable,
            AvailabilityStatus::Unavailable => Self::Unavailable,
        }
    }
}

/// One capability entry the analysis engine declares for one family: which
/// family it is, whether the engine can answer that family right now, and —
/// when it cannot — a plain sentence saying why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCapability {
    /// The seam's own family id: a stable string that code can compare
    /// directly (e.g. `decompilation`), taken from the seam's declared
    /// family roster.
    pub id: String,
    /// Whether it can answer this family right now.
    pub status: AvailabilityStatus,
    /// A human-readable reason line, present only when there is something
    /// to admit. It is bounded to a single sentence. Free text belongs here
    /// and nowhere else: ids and statuses stay structured, exactly the
    /// limitation-line discipline P19's facet entries keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FamilyCapability {
    /// The one admission line this entry produces, or `None` when there is
    /// nothing to admit. An answerable family stays silent. An unavailable
    /// family says so, adding the engine's own reason line when it gave one
    /// (issue #355).
    ///
    /// This method is the single home of the wording, mirroring the
    /// coverage half's [`ScanCoverage::admission`]. Every consumer — a
    /// prompt section, a run report — renders this same string, so the seam
    /// admits a family in exactly one set of words end to end. An undeclared
    /// family never reaches this method: absence reads as unknown, and
    /// unknown has no admission. The seam said nothing, so nothing is said.
    pub fn admission(&self) -> Option<String> {
        match self.status {
            AvailabilityStatus::Answerable => None,
            AvailabilityStatus::Unavailable => Some(match &self.reason {
                Some(reason) => format!("unavailable — {reason}"),
                None => "unavailable".to_string(),
            }),
        }
    }
}

/// The capability report an analysis engine declares about the seam it
/// stands behind: what it can answer right now and what it cannot, in one
/// shared shape every consumer reads.
///
/// There is one report per opened scan source, held for the run beside its
/// provenance. The entries keep the engine's declared order, and statuses,
/// ids, order, and reason lines all survive write and read exactly. So a
/// prompt, a retry decision, and a run report all read the same admission.
/// Provenance says who answers the reads; this says what those answers can
/// be about. Those are the two halves of the seam's self-knowledge
/// (issue #354).
///
/// `Default` declares nothing, so every family then reads
/// [`EffectiveAvailability::Unknown`]. That is why the seam trait's default
/// report, and the report propagated by every capability-less source, is
/// honest without saying a word.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// The analysis engine's declared families, in the engine's own order,
    /// with one entry per family. A family absent from the record was not
    /// declared at all, and reads as unknown — never as answerable and
    /// never as unavailable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub families: Vec<FamilyCapability>,
}

impl CapabilityReport {
    /// The availability this report states for `family`, or
    /// [`EffectiveAvailability::Unknown`] when it states none.
    ///
    /// Every consumer branches on this read-side result. A family no
    /// analysis engine declared is unknown — the report's own absence
    /// admits it — and can never be read as an answer the seam owes or a
    /// gap the seam owns.
    pub fn availability_for(&self, family: &str) -> EffectiveAvailability {
        self.families
            .iter()
            .find(|entry| entry.id == family)
            .map_or(EffectiveAvailability::Unknown, |entry| entry.status.into())
    }

    /// The data-level verdict of the roster pin: does this report name the
    /// families `declared` — every one of them, exactly once, and no family
    /// that the seam's roster does not carry?
    ///
    /// ADR-0053's engine-stamps/roster-pins doctrine applies one level up
    /// (issue #354), and this method is the single home of its wording. The
    /// seam crate's pin calls it against the roster paired to the trait's
    /// own query methods. Each fault names one drift: a family the analysis
    /// engine stopped declaring, a family declared twice, or an id no seam
    /// method stands behind. So a drift can only ever fail loudly, naming
    /// itself in words. An empty verdict means the report pairs one-for-one
    /// with the roster.
    pub fn roster_faults(&self, declared: &[&str]) -> Vec<String> {
        let mut faults = Vec::new();
        for family_id in declared {
            let hits = self
                .families
                .iter()
                .filter(|entry| entry.id == **family_id)
                .count();
            if hits == 0 {
                faults.push(format!(
                    "declared family `{family_id}` is missing from the report"
                ));
            } else if hits > 1 {
                faults.push(format!(
                    "declared family `{family_id}` appears {hits} times in the report"
                ));
            }
        }
        for entry in &self.families {
            if !declared.contains(&entry.id.as_str()) {
                faults.push(format!(
                    "report names `{}`, a family the seam's roster never carried",
                    entry.id
                ));
            }
        }
        faults
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A report with every writable state present — one family answerable
    /// with nothing to admit, one unavailable with its reason — the shared
    /// shape every analysis engine source fills in.
    fn declared_report_fixture() -> CapabilityReport {
        CapabilityReport {
            families: vec![
                FamilyCapability {
                    id: "function-inventory".into(),
                    status: AvailabilityStatus::Answerable,
                    reason: None,
                },
                FamilyCapability {
                    id: "decompilation".into(),
                    status: AvailabilityStatus::Unavailable,
                    reason: Some("the pinned engine's lifter refuses this target".into()),
                },
            ],
        }
    }

    #[test]
    fn availability_status_serde_round_trips_the_labels() {
        // The snake_case labels are the wire format wherever a report
        // crosses a serde boundary. They are therefore a compatibility
        // contract, like every other closed set in this crate.
        let cases = [
            (AvailabilityStatus::Answerable, r#""answerable""#),
            (AvailabilityStatus::Unavailable, r#""unavailable""#),
        ];
        for (status, label) in cases {
            assert_eq!(serde_json::to_string(&status).expect("serializes"), label);
            let back: AvailabilityStatus =
                serde_json::from_str(label).expect("the label deserializes");
            assert_eq!(back, status);
        }
    }

    #[test]
    fn display_re_emits_the_serde_label() {
        // Reports and prompts print the availability word, and it must be
        // exactly the word the report stores.
        for status in [
            AvailabilityStatus::Answerable,
            AvailabilityStatus::Unavailable,
        ] {
            let label = serde_json::to_value(status).expect("serializes");
            assert_eq!(
                status.to_string(),
                label.as_str().expect("label is a string")
            );
        }
    }

    #[test]
    fn a_written_report_round_trips_its_entries_exactly() {
        // Statuses, family ids, order, and reason lines all survive
        // write→read. The admission one consumer reads is the declaration
        // the analysis engine made.
        let report = declared_report_fixture();
        let json = serde_json::to_string(&report).expect("serializes");
        let back: CapabilityReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, report);
        assert_eq!(
            back.families
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            ["function-inventory", "decompilation"],
            "the engine's own family order is preserved"
        );
        assert_eq!(back.families[0].reason, None, "nothing to admit: no line");
        assert_eq!(
            back.families[1].reason.as_deref(),
            Some("the pinned engine's lifter refuses this target")
        );
    }

    #[test]
    fn an_absent_report_loads_without_error_and_reads_fully_unknown() {
        // The serde discipline mirrors coverage: bytes with no report at
        // all load without error, and every family then reads unknown — the
        // report's own absence admits it.
        let back: CapabilityReport =
            serde_json::from_str("{}").expect("an absent report loads without error");
        assert!(
            back.families.is_empty(),
            "no entries loaded: nothing declared"
        );
        for family in ["function-inventory", "decompilation", "memory-reads"] {
            assert_eq!(
                back.availability_for(family),
                EffectiveAvailability::Unknown,
                "absent `{family}` admits itself as unknown"
            );
        }

        // The trait default and the empty report are the same honest
        // nothing: an all-`{}` document loads exactly into it.
        assert_eq!(back, CapabilityReport::default());
    }

    #[test]
    fn a_fresh_empty_report_writes_no_families_key() {
        // A source that declares nothing writes no entries. Those bytes
        // load back declaring nothing — honest in both directions.
        let json = serde_json::to_string(&CapabilityReport::default()).expect("serializes");
        assert!(
            !json.contains("families"),
            "a report declaring nothing writes no families key: {json}"
        );
        let back: CapabilityReport = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, CapabilityReport::default());
    }

    #[test]
    fn unknown_is_not_writable_at_either_level() {
        // The write-side set stays the two-valued closed set: `unknown` has
        // no variant in `AvailabilityStatus`, so neither a family entry nor
        // a whole report can ever store it. `unknown` exists only as the
        // derived read-side default.
        assert!(
            serde_json::from_str::<AvailabilityStatus>(r#""unknown""#).is_err(),
            "`unknown` is not a status an engine can stamp"
        );
        assert!(
            serde_json::from_str::<FamilyCapability>(r#"{"id":"imports","status":"unknown"}"#)
                .is_err(),
            "a family entry cannot admit `unknown` about its own engine"
        );
        assert!(
            serde_json::from_str::<CapabilityReport>(
                r#"{"families":[{"id":"imports","status":"unknown"}]}"#
            )
            .is_err(),
            "and a whole report cannot smuggle it in one entry down"
        );
    }

    #[test]
    fn availability_for_reads_declared_entries_and_silence_apart() {
        // A declared family answers with its status. An undeclared family
        // reads unknown — never answerable (an undeclared question can
        // never be treated as an answer) and never unavailable (unknown
        // must never read as absent). This pins the two-directional rule.
        let report = declared_report_fixture();
        assert_eq!(
            report.availability_for("function-inventory"),
            EffectiveAvailability::Answerable
        );
        assert_eq!(
            report.availability_for("decompilation"),
            EffectiveAvailability::Unavailable
        );
        let silence = report.availability_for("strings");
        assert_eq!(silence, EffectiveAvailability::Unknown);
        assert_ne!(silence, EffectiveAvailability::Answerable);
        assert_ne!(silence, EffectiveAvailability::Unavailable);
    }

    #[test]
    fn roster_faults_name_every_drift_direction_of_the_pinning() {
        // ADR-0053's doctrine one level up (issue #354): the report pairs
        // one-for-one with the seam's declared roster, and each drift
        // direction spells itself out as a fault — a family the analysis
        // engine stopped declaring, a family declared twice, and an id no
        // seam method stands behind. This is the shared wording the seam
        // crate's pin reads.
        let declared = ["function-inventory", "decompilation"];
        assert!(
            declared_report_fixture()
                .roster_faults(&declared)
                .is_empty(),
            "a report naming every declared family exactly once has nothing to fault"
        );

        let mut missing = declared_report_fixture();
        missing.families.retain(|entry| entry.id != "decompilation");
        assert_eq!(
            missing.roster_faults(&declared),
            ["declared family `decompilation` is missing from the report"],
            "an engine quietly dropping one of its families fails loudly"
        );

        let mut doubled = declared_report_fixture();
        doubled.families.push(doubled.families[0].clone());
        assert_eq!(
            doubled.roster_faults(&declared),
            ["declared family `function-inventory` appears 2 times in the report"],
            "a family declared twice fails loudly"
        );

        let mut orphan = declared_report_fixture();
        orphan.families.push(FamilyCapability {
            id: "masked-byte-search".into(),
            status: AvailabilityStatus::Answerable,
            reason: None,
        });
        assert_eq!(
            orphan.roster_faults(&declared),
            ["report names `masked-byte-search`, a family the seam's roster never carried"],
            "an id no seam method stands behind fails loudly"
        );
    }

    // ---- #355: the admission line's one wording home -------------------

    #[test]
    fn an_answerable_family_admits_nothing_and_an_unavailable_one_says_why() {
        // This is the home of the admission wording. An answerable entry
        // has nothing to admit. An unavailable entry says so in the one set
        // of words that every consumer — prompt section, run report — then
        // renders identically, naming the engine's own reason and inventing
        // nothing.
        let answered = FamilyCapability {
            id: "imports".to_string(),
            status: AvailabilityStatus::Answerable,
            reason: None,
        };
        assert_eq!(answered.admission(), None, "answerable admits nothing");

        let admitted = FamilyCapability {
            id: "imports".to_string(),
            status: AvailabilityStatus::Unavailable,
            reason: Some("the import table is encrypted".to_string()),
        };
        assert_eq!(
            admitted.admission().as_deref(),
            Some("unavailable — the import table is encrypted"),
            "the admission names the engine's own reason line verbatim"
        );
    }

    #[test]
    fn an_unavailable_family_with_no_reason_still_admits_itself_alone() {
        // A reason line is optional; the admission is not. An unavailable
        // family with no sentence still gets its one word, never silence.
        let admitted = FamilyCapability {
            id: "xrefs".to_string(),
            status: AvailabilityStatus::Unavailable,
            reason: None,
        };
        assert_eq!(
            admitted.admission().as_deref(),
            Some("unavailable"),
            "absence of a reason never means absence of an admission"
        );
    }

    #[test]
    fn the_report_hands_each_consumer_only_the_lines_it_declared() {
        // A family the analysis engine never declared reads unknown and has
        // no entry to admit. So filtering a report's entries for admissions
        // yields the unavailable lines, in declared order, and nothing for
        // answerable or undeclared families: unknown renders as silence,
        // and the seam's own silence is never passed off as an admission.
        let report = declared_report_fixture();
        let lines: Vec<String> = report
            .families
            .iter()
            .filter_map(|entry| entry.admission().map(|a| format!("{} — {a}", entry.id)))
            .collect();
        assert_eq!(
            lines.len(),
            report
                .families
                .iter()
                .filter(|entry| entry.status == AvailabilityStatus::Unavailable)
                .count(),
            "only unavailable entries earn a line"
        );
        assert_eq!(
            report.availability_for("never-declared-family"),
            EffectiveAvailability::Unknown,
            "an undeclared family carries no entry and no admission"
        );
        assert!(
            !report
                .families
                .iter()
                .any(|entry| entry.admission().is_some()
                    && entry.status == AvailabilityStatus::Answerable),
            "answerable entries never yield an admission line"
        );
    }
}

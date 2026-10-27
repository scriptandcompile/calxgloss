//! The answer surface the analysis engine declares about itself at the seam.
//!
//! The `ScanSource` seam answers program questions and used to say nothing
//! about its own limits: an empty callers list read byte-identically whether
//! the program had no callers or the engine could not answer about callers at
//! all. This module shapes what the engine declares instead — one entry per
//! query family saying whether it can answer that family *right now*, with a
//! bounded reason line when it cannot (track P20, issue #354; the same
//! honesty doctrine ADR-0053 pinned for scans, applied one level up).
//!
//! The shape sits beside the coverage record P19 shipped, and the two divide
//! the work the same way: a scan document's admitted coverage is the
//! *persisted* half — what that filed scan examined and could not — while a
//! capability report is live session state, read from the open seam and
//! discarded with the run. It is never filed into a scan document, a cache
//! key, or any read plumbing.

use serde::{Deserialize, Serialize};

use crate::display_serde_label;

/// Whether the engine can currently answer one family of questions about the
/// program — the closed set an engine stamps about its own answer surface.
///
/// Families are the seam's own query methods grouped into question families,
/// and every capability entry names its family's state with one of these two
/// labels. There is deliberately no `unknown` here: an engine admits
/// `answerable` or `unavailable` about itself, and the `unknown` a family
/// absent from a report reads as is derived at read time
/// ([`EffectiveAvailability::Unknown`]), never written (issue #354) — the
/// same one-way door P19's [`CoverageStatus`](crate::CoverageStatus) keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    /// The engine can answer this family right now; an empty answer from it
    /// is a fact about the program.
    Answerable,
    /// The engine cannot answer this family right now — the answer would not
    /// arrive even if the program holds the thing asked about. Why lives on
    /// the entry's own reason line.
    Unavailable,
}

display_serde_label!(AvailabilityStatus {
    Answerable => "answerable",
    Unavailable => "unavailable",
});

/// A read-side availability status: the two writable statuses plus `unknown`.
///
/// This is what every consumer of a capability report branches on. `Unknown`
/// is the derived default of a family no report declares — the report's own
/// silence admitting it — the same graceful degradation a pre-coverage
/// document practices. Because `Unknown` lives only on this read-side enum
/// and never on [`AvailabilityStatus`], no engine can stamp it about itself,
/// and an undeclared family can never be mistaken for an answerable one —
/// nor, the other direction, for an unavailable one: unknown reads as
/// unknown, never as absence (issue #354).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EffectiveAvailability {
    /// The report declares the engine can answer this family right now.
    Answerable,
    /// The report declares the engine cannot answer this family right now.
    Unavailable,
    /// No report declares this family — the engine said nothing about it, so
    /// what it can answer there is unknown, and its silence establishes
    /// nothing either way.
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

/// One engine-declared family's capability entry: which family, whether the
/// engine can answer it right now, and — when it cannot — a plain sentence
/// saying why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCapability {
    /// The seam's own family id, a stable machine-comparable string (e.g.
    /// `decompilation`) drawn from the seam's declared family roster.
    pub id: String,
    /// Whether the engine can answer this family right now.
    pub status: AvailabilityStatus,
    /// A human-readable reason line, present only when there is something
    /// to admit, bounded to a single sentence. Free text belongs here and
    /// nowhere else: ids and statuses stay structured, exactly the
    /// limitation-line discipline P19's facet entries keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FamilyCapability {
    /// The one admission line this entry earns, or `None` when there is
    /// nothing to admit: an answerable family stays silent, an unavailable
    /// one says so — with the engine's own reason line when it gave one
    /// (issue #355).
    ///
    /// The single home of the wording, mirroring the coverage half's
    /// [`ScanCoverage::admission`]: every consumer — a prompt section, a
    /// run report — renders this same string, so the seam admits a family
    /// in exactly one set of words end to end. An undeclared family never
    /// reaches this method: absence reads as unknown, and unknown has no
    /// admission — the seam said nothing, so nothing is said.
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

/// The capability report an engine declares about the seam it stands behind:
/// what it can answer right now and what it cannot, in one shared shape
/// every consumer reads.
///
/// One report per opened scan source, held for the run beside its
/// provenance. The entries keep the engine's declared order and survive
/// write and read exactly — statuses, ids, order, and reason lines — so a
/// prompt, a retry decision, and a run report all read the same admission.
/// Provenance says who answers the reads; this says what those answers can
/// be about: the two halves of the seam's self-knowledge (issue #354).
///
/// `Default` declares nothing — every family then reads
/// [`EffectiveAvailability::Unknown`] — which is why the seam trait's
/// default report and every capability-less source's propagation are honest
/// without saying a word.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// The engine's declared families, in the engine's own order, with one
    /// entry per family. A family absent from the record was not declared
    /// at all, and reads as unknown — never as answerable and never as
    /// unavailable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub families: Vec<FamilyCapability>,
}

impl CapabilityReport {
    /// The availability this report states for `family`, or
    /// [`EffectiveAvailability::Unknown`] when it states none.
    ///
    /// The read-side resolution every consumer branches on: a family no
    /// engine declared is unknown — the report's own absence admits it —
    /// and can never be read as an answer the seam owes or a gap the seam
    /// owns.
    pub fn availability_for(&self, family: &str) -> EffectiveAvailability {
        self.families
            .iter()
            .find(|entry| entry.id == family)
            .map_or(EffectiveAvailability::Unknown, |entry| entry.status.into())
    }

    /// The data-level verdict of the roster pin: does this report name the
    /// families `declared` — every one of them, exactly once, and nothing
    /// the seam's roster never carried?
    ///
    /// This is the one home of the wording ADR-0053's engine-stamps/
    /// roster-pins doctrine uses one level up (issue #354): the seam crate's
    /// pin calls it against the roster paired to the trait's own query
    /// methods, and each fault spells one drift — a family the engine
    /// stopped declaring, a family declared twice, or an id no seam method
    /// stands behind — so a drift can only ever fail loudly, naming itself
    /// in words. An empty verdict means the report pairs one-for-one with
    /// the roster.
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

    /// A report with every writable state on the books — one family
    /// answerable with nothing to admit, one unavailable with its reason —
    /// the shared shape every engine source fills in.
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
        // The snake_case labels are the wire format wherever a report is
        // handed across a serde boundary, so they are a compatibility
        // contract like every other closed set in this crate.
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
        // the exact word the report carries.
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
        // write→read — the admission one consumer reads is the declaration
        // the engine made.
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
        // The serde discipline mirrors coverage: bytes carrying no report
        // at all load without error, and every family then reads unknown —
        // the report's own absence admitting it.
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
        // A source that declares nothing writes no entries, and those
        // bytes load back declaring nothing — honest in both directions.
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
        // a whole report can ever carry it. `unknown` exists only as the
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
        // A declared family answers with its status; an undeclared family
        // reads unknown — never answerable (an undeclared question can
        // never be treated as an answer) and never unavailable (unknown
        // must never read absent). The two-directional rule, pinned.
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
        // direction spells itself as a fault — a family the engine stopped
        // declaring, a family declared twice, and an id no seam method
        // stands behind. The shared wording the seam crate's pin reads.
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
        // The admission wording's home: an answerable entry has nothing to
        // admit, and an unavailable entry says so in the one set of words
        // every consumer — prompt section, run report — then renders
        // identically, naming the engine's own reason and nothing invented.
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
        // A reason line is optional; the admission is not — an unavailable
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
        // A family the engine never declared reads unknown and has no entry
        // to admit — so filtering a report's entries for admissions yields
        // the unavailable lines, in declared order, and nothing for
        // answerable or undeclared families: unknown renders as silence,
        // and the seam's own silence is never dressed up as an admission.
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

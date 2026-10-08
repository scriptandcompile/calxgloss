//! Pipeline phase progress records — where the whole effort stands.
//!
//! The master plan runs the decompilation effort through 7 phases, with
//! Phase 2.5 (PAL Design) as its own segment. These records are the shared
//! vocabulary for reporting progress through them: the web UI's phase bar
//! renders one [`PhaseProgress`] per [`PipelinePhase`], and later tracks
//! (W2's `PipelineState`, W3's analytics) consume the same records without
//! depending on the web crate.
//!
//! Honesty is the load-bearing rule: every phase carries an explicit
//! [`PhaseState`], and phases with no backing data source (6 — Restitching,
//! 7 — Documentation) report [`PhaseState::NoDataSource`] rather than a
//! fabricated zero-progress state.

use serde::{Deserialize, Serialize};

/// One segment of the master-plan pipeline, listed in bar order
/// (Phase 1 → 7, with Phase 2.5 between 2 and 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelinePhase {
    /// Phase 1 — Project Ingestion: binary inventory and classification.
    ProjectIngestion,
    /// Phase 2 — Disassembly & Tagging: functions analyzed, APIs tagged.
    DisassemblyTagging,
    /// Phase 2.5 — Platform Abstraction Layer (PAL) Design.
    PalDesign,
    /// Phase 3 — Behavior-Driven Test Generation: baseline tests written.
    TestGeneration,
    /// Phase 4 — Rust Code Generation: functions translated by the LLM.
    RustCodeGeneration,
    /// Phase 5 — Behavior Verification: baseline/verification test results.
    BehaviorVerification,
    /// Phase 6 — Restitching. No backing data source in W0; reports
    /// [`PhaseState::NoDataSource`] until the restitch engine exists.
    Restitching,
    /// Phase 7 — Documentation & Artifacts. No backing data source in W0;
    /// reports [`PhaseState::NoDataSource`] until the function registry exists.
    Documentation,
}

impl PipelinePhase {
    /// Every phase in bar order — the order the phase bar renders segments.
    pub const ALL: [PipelinePhase; 8] = [
        PipelinePhase::ProjectIngestion,
        PipelinePhase::DisassemblyTagging,
        PipelinePhase::PalDesign,
        PipelinePhase::TestGeneration,
        PipelinePhase::RustCodeGeneration,
        PipelinePhase::BehaviorVerification,
        PipelinePhase::Restitching,
        PipelinePhase::Documentation,
    ];

    /// Whether this phase has no backing data source in the current system.
    /// Such phases must render as "no data source", never as zero progress.
    pub fn is_no_data_source(&self) -> bool {
        matches!(
            self,
            PipelinePhase::Restitching | PipelinePhase::Documentation
        )
    }
}

/// How far a pipeline phase has progressed — the honest four-state vocabulary.
///
/// `NoDataSource` is deliberately distinct from `NotStarted`: it means the
/// phase exists in the plan but nothing in the current system can report its
/// progress. Rendering it as "not started" would imply the phase is queued
/// up behind the current work, which is a fabrication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseState {
    /// No unit or binary has entered this phase yet.
    NotStarted,
    /// The phase is underway: some work entered it, not all of it is done.
    InProgress,
    /// Every unit or binary the phase covers has completed it.
    Complete,
    /// The phase has no backing data source — progress cannot be reported.
    NoDataSource,
}

/// Progress through one pipeline phase, derived from live progress data.
///
/// `completed`/`total` count units (function translations) or binaries,
/// depending on the phase, and are `None` when the phase has no countable
/// data source — a missing count is honest, a fabricated zero is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseProgress {
    /// Which phase this record reports on.
    pub phase: PipelinePhase,
    /// Honest state of the phase.
    pub state: PhaseState,
    /// Units or binaries that have completed this phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<usize>,
    /// Units or binaries the phase is expected to cover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

impl PhaseProgress {
    /// A phase with no backing data source — carries no counts, ever.
    pub fn no_data_source(phase: PipelinePhase) -> Self {
        Self {
            phase,
            state: PhaseState::NoDataSource,
            completed: None,
            total: None,
        }
    }

    /// A phase that has not started yet, with an optional known total.
    pub fn not_started(phase: PipelinePhase, total: Option<usize>) -> Self {
        Self {
            phase,
            state: PhaseState::NotStarted,
            completed: Some(0),
            total,
        }
    }
}

/// Progress for a single target binary (DLL/EXE) through the pipeline.
///
/// Every field degrades honestly: classification fields are `None` until a
/// `ClassificationComplete` event lands, `functions_total` is `None` until
/// the batch summary lands, and `tokens_used` stays `None` until the batch
/// summary reports it — an unknown total is never rendered as zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryProgress {
    /// DLL/EXE file name.
    pub dll: String,
    /// Classification category (e.g. "WindowsOs", "ProjectSpecific").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Classification strategy (e.g. "PalMapping", "CrateReplacement",
    /// "ReverseEngineer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    /// Crate recommended for replacement, when the strategy names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crate_replacement: Option<String>,
    /// Total functions in the binary — known once the batch summary lands.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions_total: Option<usize>,
    /// Functions translated successfully so far.
    pub functions_translated: usize,
    /// Functions currently being translated.
    pub functions_in_progress: usize,
    /// Functions whose translation failed.
    pub functions_failed: usize,
    /// Tokens consumed translating this binary — `None` until a batch
    /// summary reports them, so an unknown total is never shown as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<usize>,
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `PipelinePhase` serializes to its documented snake_case names, and
    /// `ALL` lists the phases in bar order (1, 2, 2.5, 3, 4, 5, 6, 7).
    #[test]
    fn pipeline_phase_serde_round_trip_covers_bar_order() {
        let expected = [
            "project_ingestion",
            "disassembly_tagging",
            "pal_design",
            "test_generation",
            "rust_code_generation",
            "behavior_verification",
            "restitching",
            "documentation",
        ];
        for (phase, name) in PipelinePhase::ALL.iter().zip(expected) {
            let json = serde_json::to_value(phase).expect("serializes");
            assert_eq!(json, name, "{phase:?} serializes to its documented name");
            let back: PipelinePhase = serde_json::from_value(json).expect("deserializes");
            assert_eq!(&back, phase);
        }
    }

    /// The state enum covers all four documented states, snake_case.
    #[test]
    fn phase_state_covers_all_four_states() {
        let states = [
            (PhaseState::NotStarted, "not_started"),
            (PhaseState::InProgress, "in_progress"),
            (PhaseState::Complete, "complete"),
            (PhaseState::NoDataSource, "no_data_source"),
        ];
        for (state, name) in states {
            let json = serde_json::to_value(state).expect("serializes");
            assert_eq!(json, name);
            let back: PhaseState = serde_json::from_value(json).expect("deserializes");
            assert_eq!(back, state);
        }
    }

    /// `PhaseProgress` round-trips, and the count fields are omitted when
    /// the phase has no countable data source.
    #[test]
    fn phase_progress_serde_round_trip_omits_missing_counts() {
        let counted = PhaseProgress {
            phase: PipelinePhase::TestGeneration,
            state: PhaseState::InProgress,
            completed: Some(3),
            total: Some(10),
        };
        let json = serde_json::to_value(&counted).expect("serializes");
        assert_eq!(json["phase"], "test_generation");
        assert_eq!(json["state"], "in_progress");
        assert_eq!(json["completed"], 3);
        assert_eq!(json["total"], 10);
        let back: PhaseProgress = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, counted);

        let no_source = PhaseProgress::no_data_source(PipelinePhase::Restitching);
        let json = serde_json::to_value(&no_source).expect("serializes");
        assert_eq!(json["state"], "no_data_source");
        assert!(
            json.get("completed").is_none() && json.get("total").is_none(),
            "no-data-source phases carry no counts: {json}"
        );
    }

    /// Phases 6–7 are the no-data-source pair; the rest are countable.
    #[test]
    fn only_restitching_and_documentation_lack_a_data_source() {
        for phase in PipelinePhase::ALL {
            assert_eq!(
                phase.is_no_data_source(),
                matches!(
                    phase,
                    PipelinePhase::Restitching | PipelinePhase::Documentation
                ),
                "{phase:?} data-source flag"
            );
        }
    }

    /// `BinaryProgress` round-trips with every field present, and the
    /// optional fields are omitted until their data lands.
    #[test]
    fn binary_progress_serde_round_trip_omits_unknown_fields() {
        let full = BinaryProgress {
            dll: "game_logic.dll".into(),
            category: Some("ProjectSpecific".into()),
            strategy: Some("ReverseEngineer".into()),
            crate_replacement: None,
            functions_total: Some(24),
            functions_translated: 10,
            functions_in_progress: 2,
            functions_failed: 1,
            tokens_used: Some(120_000),
        };
        let json = serde_json::to_value(&full).expect("serializes");
        assert_eq!(json["dll"], "game_logic.dll");
        assert_eq!(json["category"], "ProjectSpecific");
        assert_eq!(json["functions_total"], 24);
        assert_eq!(json["tokens_used"], 120_000);
        let back: BinaryProgress = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, full);

        // A binary only discovered (no classification, no batch summary yet)
        // serializes with just the honest zeros.
        let bare = BinaryProgress {
            dll: "unknown.dll".into(),
            category: None,
            strategy: None,
            crate_replacement: None,
            functions_total: None,
            functions_translated: 0,
            functions_in_progress: 0,
            functions_failed: 0,
            tokens_used: None,
        };
        let json = serde_json::to_value(&bare).expect("serializes");
        assert_eq!(
            json.as_object().expect("object").len(),
            4,
            "unknown fields are omitted, not fabricated: {json}"
        );
    }
}

//! Live translation state — what the pipeline is doing to each in-flight unit.
//!
//! The review dashboard shows what a unit *achieved*; the live view shows what
//! the pipeline is *doing* to it right now. These records are the shared shape
//! for that: `GET /api/progress/enhanced` serves them, and later tracks (W2's
//! `PipelineState`, W3's analytics) consume the same records without depending
//! on the web crate.
//!
//! Honesty is the same load-bearing rule as in [`crate::pipeline_phase`]:
//! anything the live event stream has not reported yet stays `None` or
//! [`PassState::NotRun`] rather than becoming a fabricated zero, a vacuous
//! pass, or a guessed confidence.

use serde::{Deserialize, Serialize};

use crate::progress::{PhaseRecord, TranslationPhase};

/// Honest status of one class of test evidence for an in-flight unit.
///
/// `NotRun` and `Pending` are deliberately distinct: a unit whose baseline
/// tests have been generated but not yet executed has tests *waiting*, while a
/// unit that has never reached a test run has none at all. Rendering both as
/// "0 passed" would hide the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassState {
    /// No test of this class has been observed for the unit yet.
    NotRun,
    /// Tests of this class exist for the unit but none has run yet.
    Pending,
    /// Every observed test of this class passed.
    Passed,
    /// At least one observed test of this class failed.
    Failed,
}

/// Test evidence for one class of tests — baseline or verification.
///
/// `passed`/`total` are `None` when the live stream has not reported them, so
/// an unmeasured unit never renders as "0/0".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassStatus {
    /// Honest state of this class of evidence.
    pub state: PassState,
    /// Tests that passed, once a run has reported them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<usize>,
    /// Tests in this class, once the pipeline has reported a count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
}

impl PassStatus {
    /// Nothing observed for this class yet — carries no counts, ever.
    pub fn not_run() -> Self {
        Self {
            state: PassState::NotRun,
            passed: None,
            total: None,
        }
    }

    /// `total` tests exist for the unit but none has run yet.
    pub fn pending(total: usize) -> Self {
        Self {
            state: PassState::Pending,
            passed: None,
            total: Some(total),
        }
    }

    /// A test run that reported `passed` of `total`.
    ///
    /// A run with no tests reports [`PassState::NotRun`] rather than a
    /// vacuous pass: zero tests is the absence of evidence, not evidence of
    /// correctness.
    pub fn from_counts(passed: usize, total: usize) -> Self {
        if total == 0 {
            return Self::not_run();
        }
        Self {
            state: if passed >= total {
                PassState::Passed
            } else {
                PassState::Failed
            },
            passed: Some(passed),
            total: Some(total),
        }
    }

    /// Evidence assembled from whatever the live stream has reported so far:
    /// a run when both counts arrived, [`pending`](Self::pending) when only the
    /// test count has, and [`not_run`](Self::not_run) when nothing has.
    ///
    /// A pass count without a total is not something the live event stream
    /// produces, so it reports no evidence rather than a guessed denominator.
    pub fn from_optional_counts(passed: Option<usize>, total: Option<usize>) -> Self {
        match (passed, total) {
            (Some(passed), Some(total)) => Self::from_counts(passed, total),
            (None, Some(total)) => Self::pending(total),
            _ => Self::not_run(),
        }
    }
}

/// One unit of work as the live pipeline currently sees it.
///
/// Every field degrades honestly: the retry strategy is `None` until the first
/// LLM call names one, the context tier until `ContextTierSelected` lands, the
/// test classes until their events land, and [`LiveUnitProgress::unit_confidence`]
/// until some attempt has been verified against baseline tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveUnitProgress {
    /// Target binary this unit belongs to.
    pub dll: String,
    /// Function this unit translates.
    pub function: String,
    /// The pipeline step the unit is currently in.
    pub phase: TranslationPhase,
    /// Phases entered, in event order (re-entered phases appear again, so
    /// context-tier escalations stay visible).
    pub phase_history: Vec<PhaseRecord>,
    /// Seconds since this unit's translation started.
    pub elapsed_secs: f64,
    /// Which attempt of the unit is in flight (the `v{N}` of its branch).
    pub attempt: u32,
    /// Retry strategy the current attempt is using.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_strategy: Option<String>,
    /// Context tier the current attempt runs at (e.g. `"T2"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_tier: Option<String>,
    /// Human-readable tier label (e.g. `"with_tests"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_label: Option<String>,
    /// Baseline test evidence — the tests that capture the original binary's
    /// behavior.
    pub baseline: PassStatus,
    /// Verification evidence beyond the baseline: the edge-case tests the
    /// behavior-divergence detector runs. `NotRun` until that detector reports.
    pub verification: PassStatus,
    /// Whether the latest verified attempt compiled — `None` until an attempt
    /// has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiled: Option<bool>,
    /// Reviewer-facing trust in this unit (0.0–1.0), derived from the evidence
    /// seen so far — `None` while no attempt has been verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_confidence: Option<f32>,
    /// Whether a terminal event (completed / failed / function-completed) has
    /// been observed — distinguishes finished units from in-flight ones.
    pub finished: bool,
    /// Whether the unit ultimately succeeded — `None` until a terminal event
    /// says so, so an unfinished unit never looks failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub succeeded: Option<bool>,
}

/// The live view payload: every unit the live pipeline is tracking.
///
/// Served by `GET /api/progress/enhanced`, which is registered in the live
/// router only — outside `calxgloss live` there is no live state to report, and
/// an empty payload here would be indistinguishable from an idle run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveTranslationState {
    /// One record per unit, sorted by (dll, function) so rendering is stable
    /// across refreshes.
    pub units: Vec<LiveUnitProgress>,
    /// Units tracked, including ones that have just finished.
    pub count: usize,
    /// Units still in flight — no terminal event observed yet.
    pub in_flight: usize,
}

impl LiveTranslationState {
    /// A state with no units tracked.
    pub fn empty() -> Self {
        Self {
            units: Vec::new(),
            count: 0,
            in_flight: 0,
        }
    }
}

/// Unit confidence (0.0–1.0) derived from the verification evidence seen so far.
///
/// The live stream never reports a trust score, so this is computed from what
/// it does report: the share of baseline tests the latest verified attempt
/// passed, discounted to `0.0` when that attempt did not compile. `None` while
/// no attempt has been verified or no baseline test has run — an unverified
/// unit has no evidence to score, and a made-up number would be exactly the
/// fabrication these records exist to avoid.
pub fn derive_unit_confidence(compiled: Option<bool>, baseline: &PassStatus) -> Option<f32> {
    let (passed, total) = (baseline.passed?, baseline.total?);
    if total == 0 {
        return None;
    }
    if compiled == Some(false) {
        return Some(0.0);
    }
    Some(passed as f32 / total as f32)
}

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn unit() -> LiveUnitProgress {
        LiveUnitProgress {
            dll: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            phase: TranslationPhase::LlmCall,
            phase_history: vec![PhaseRecord {
                phase: TranslationPhase::GhidraFetch,
                elapsed_secs: 0.0,
            }],
            elapsed_secs: 47.25,
            attempt: 2,
            retry_strategy: Some("decompose".into()),
            context_tier: Some("T2".into()),
            tier_label: Some("with_tests".into()),
            baseline: PassStatus::from_counts(5, 5),
            verification: PassStatus::not_run(),
            compiled: Some(true),
            unit_confidence: derive_unit_confidence(Some(true), &PassStatus::from_counts(5, 5)),
            finished: false,
            succeeded: None,
        }
    }

    #[test]
    fn live_unit_progress_serde_round_trip_covers_every_field() {
        let json = serde_json::to_value(unit()).expect("serializes");
        assert_eq!(json["dll"], "game_logic.dll");
        assert_eq!(json["phase"], "llm_call");
        assert_eq!(json["elapsed_secs"], 47.25);
        assert_eq!(json["attempt"], 2);
        assert_eq!(json["retry_strategy"], "decompose");
        assert_eq!(json["context_tier"], "T2");
        assert_eq!(json["tier_label"], "with_tests");
        assert_eq!(json["baseline"]["state"], "passed");
        assert_eq!(json["baseline"]["passed"], 5);
        assert_eq!(json["baseline"]["total"], 5);
        assert_eq!(json["verification"]["state"], "not_run");
        assert_eq!(json["compiled"], true);
        assert_eq!(json["unit_confidence"], 1.0);
        assert_eq!(json["finished"], false);

        let back: LiveUnitProgress = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, unit());
    }

    #[test]
    fn unreported_fields_are_omitted_rather_than_fabricated() {
        let fresh = LiveUnitProgress {
            dll: "game_logic.dll".into(),
            function: "Update".into(),
            phase: TranslationPhase::GhidraFetch,
            phase_history: vec![PhaseRecord {
                phase: TranslationPhase::GhidraFetch,
                elapsed_secs: 0.0,
            }],
            elapsed_secs: 1.0,
            attempt: 1,
            retry_strategy: None,
            context_tier: None,
            tier_label: None,
            baseline: PassStatus::not_run(),
            verification: PassStatus::not_run(),
            compiled: None,
            unit_confidence: None,
            finished: false,
            succeeded: None,
        };
        let json = serde_json::to_value(&fresh).expect("serializes");
        for key in [
            "retry_strategy",
            "context_tier",
            "tier_label",
            "compiled",
            "unit_confidence",
            "succeeded",
        ] {
            assert!(json.get(key).is_none(), "{key} must be absent: {json}");
        }
        // A not-run test class carries no counts either.
        assert_eq!(json["baseline"]["state"], "not_run");
        assert!(
            json["baseline"].get("passed").is_none() && json["baseline"].get("total").is_none(),
            "not-run evidence has no counts: {json}"
        );
    }

    #[test]
    fn pass_states_cover_all_four_states() {
        for (state, label) in [
            (PassState::NotRun, "not_run"),
            (PassState::Pending, "pending"),
            (PassState::Passed, "passed"),
            (PassState::Failed, "failed"),
        ] {
            assert_eq!(serde_json::to_value(state).expect("serializes"), label);
        }
    }

    #[test]
    fn a_run_with_no_tests_is_not_a_vacuous_pass() {
        let status = PassStatus::from_counts(0, 0);
        assert_eq!(status.state, PassState::NotRun);
        assert_eq!(status.passed, None);
        assert_eq!(status.total, None);
    }

    #[test]
    fn a_run_orders_its_evidence_by_its_counts() {
        assert_eq!(PassStatus::from_counts(5, 5).state, PassState::Passed);
        assert_eq!(PassStatus::from_counts(4, 5).state, PassState::Failed);
        assert_eq!(PassStatus::pending(5).state, PassState::Pending);
        assert_eq!(PassStatus::pending(5).total, Some(5));
        assert_eq!(PassStatus::pending(5).passed, None);
    }

    #[test]
    fn evidence_assembles_from_whatever_the_stream_reported() {
        // Both counts: a run. Only the total: tests waiting to run.
        // Nothing: no evidence. A pass count with no denominator: no evidence.
        assert_eq!(
            PassStatus::from_optional_counts(Some(4), Some(5)),
            PassStatus::from_counts(4, 5)
        );
        assert_eq!(
            PassStatus::from_optional_counts(None, Some(5)),
            PassStatus::pending(5)
        );
        assert_eq!(
            PassStatus::from_optional_counts(None, None),
            PassStatus::not_run()
        );
        assert_eq!(
            PassStatus::from_optional_counts(Some(3), None),
            PassStatus::not_run()
        );
    }

    #[test]
    fn confidence_is_the_baseline_pass_share_of_the_verified_attempt() {
        let all = PassStatus::from_counts(5, 5);
        let some = PassStatus::from_counts(2, 5);
        assert_eq!(derive_unit_confidence(Some(true), &all), Some(1.0));
        assert_eq!(
            derive_unit_confidence(Some(true), &some),
            Some(0.4),
            "2 of 5 baseline tests passing is 0.4"
        );
    }

    #[test]
    fn confidence_is_zero_when_the_attempt_did_not_compile() {
        let failed = PassStatus::from_counts(0, 5);
        assert_eq!(derive_unit_confidence(Some(false), &failed), Some(0.0));
    }

    #[test]
    fn confidence_is_absent_without_verified_evidence() {
        // Nothing verified yet, and a verified attempt that ran no tests:
        // neither has evidence to score.
        assert_eq!(derive_unit_confidence(None, &PassStatus::not_run()), None);
        assert_eq!(
            derive_unit_confidence(Some(true), &PassStatus::pending(5)),
            None,
            "tests that have not run prove nothing"
        );
        assert_eq!(
            derive_unit_confidence(Some(true), &PassStatus::not_run()),
            None,
            "no tests at all prove nothing"
        );
    }

    #[test]
    fn live_translation_state_round_trips_and_starts_empty() {
        let state = LiveTranslationState {
            units: vec![unit()],
            count: 1,
            in_flight: 1,
        };
        let json = serde_json::to_value(&state).expect("serializes");
        assert_eq!(json["count"], 1);
        assert_eq!(json["in_flight"], 1);
        assert_eq!(
            json["units"].as_array().expect("units is an array").len(),
            1
        );

        let back: LiveTranslationState = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, state);

        let empty = LiveTranslationState::empty();
        assert_eq!(empty.count, 0);
        assert_eq!(empty.in_flight, 0);
        assert!(empty.units.is_empty());
    }
}

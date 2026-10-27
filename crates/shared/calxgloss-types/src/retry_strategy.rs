//! The retry-strategy closed set — the shared identity of a fix attempt.
//!
//! [`RetryStrategy`] names the ways the retry loop repairs a failed
//! translation attempt. The enum lives here (not in the translator) because
//! the same closed set travels three surfaces: the translator's retry loop
//! picks one per attempt, the per-unit reviewer override stores a forced one
//! ([`FunctionOverride::retry_strategy_override`](crate::FunctionOverride)),
//! and the dashboard's Overrides tab offers the labels (issue #120).
//!
//! The serde labels are the persisted wire format — `re/analysis/
//! unit_overrides.json` stores exactly these snake_case strings, so workspaces
//! written before this type existed load unchanged. Because the record field
//! is typed, an unknown label is refused at deserialization: the web override
//! endpoint answers 422 on the failed JSON extraction (the same pattern the
//! classification override's category uses) and a typo'd force can never be
//! stored at all.
//!
//! The experiment log ([`crate::experiment_log`]) deliberately keeps a plain
//! `String` for its `retry_strategy` field: it also records the first attempt
//! under `"initial"`, which is not a retry strategy and so is not in this set
//! (issue #363 kept the set closed and named the field for it).

use serde::{Deserialize, Serialize};

use crate::display_serde_label;

/// The strategy for fixing a failed translation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryStrategy {
    /// Default — re-send the same prompt (first attempt only).
    Default,
    /// Feed compilation errors back to the LLM for a targeted fix.
    CompileFix,
    /// Compilation passed but tests failed; feed failing test cases back.
    TestFix,
    /// Add more context from disassembly and try again.
    Escalate,
    /// Compilation passed but tests failed specifically on boundary values;
    /// feed a boundary-aware fix prompt.
    EdgeCaseFix,
}

display_serde_label!(RetryStrategy {
    Default => "default",
    CompileFix => "compile_fix",
    TestFix => "test_fix",
    Escalate => "escalate",
    EdgeCaseFix => "edge_case_fix",
});

#[cfg(test)]
mod tests {
    use super::*;

    /// The persisted labels are a compatibility contract: workspaces wrote
    /// these exact strings into `re/analysis/unit_overrides.json` while the
    /// override was a plain `String`, and they must keep loading.
    #[test]
    fn serde_round_trips_the_persisted_labels() {
        let cases = [
            (RetryStrategy::Default, r#""default""#),
            (RetryStrategy::CompileFix, r#""compile_fix""#),
            (RetryStrategy::TestFix, r#""test_fix""#),
            (RetryStrategy::Escalate, r#""escalate""#),
            (RetryStrategy::EdgeCaseFix, r#""edge_case_fix""#),
        ];
        for (strategy, label) in cases {
            assert_eq!(serde_json::to_string(&strategy).expect("serializes"), label);
            let back: RetryStrategy =
                serde_json::from_str(label).expect("the persisted label deserializes");
            assert_eq!(back, strategy);
        }
    }

    /// The whole point of typing the field: a typo'd label is refused at
    /// deserialization, so it can never be stored and silently ignored.
    #[test]
    fn unknown_labels_are_refused_at_deserialization() {
        for label in [
            r#""escalatte""#,
            r#""auto""#,
            r#""Initial""#,
            r#""initial""#,
        ] {
            assert!(
                serde_json::from_str::<RetryStrategy>(label).is_err(),
                "{label} is not a strategy and must not deserialize"
            );
        }
    }

    /// `Display` says exactly what serde persists — the retry loop logs the
    /// strategy with `Display` and the experiment log stores that word.
    #[test]
    fn display_re_emits_the_serde_label() {
        for strategy in [
            RetryStrategy::Default,
            RetryStrategy::CompileFix,
            RetryStrategy::TestFix,
            RetryStrategy::Escalate,
            RetryStrategy::EdgeCaseFix,
        ] {
            let label = serde_json::to_value(strategy).expect("serializes");
            assert_eq!(
                strategy.to_string(),
                label.as_str().expect("label is a string")
            );
        }
    }
}

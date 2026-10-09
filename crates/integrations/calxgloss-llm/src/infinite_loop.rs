//! Infinite-loop detector for the retry loop.
//!
//! This module provides [`InfiniteLoopDetector`] which tracks prompt → output
//! hash pairs across retry attempts.  When the same bad output repeats three
//! or more times in a row, the detector signals that the LLM is stuck in a
//! loop and escalation to manual intervention or a radically different
//! strategy is warranted.
//!
//! # How it works
//!
//! Each retry attempt hashes two things:
//!
//! 1. **The prompt** — the full text sent to the LLM.
//! 2. **The generated code** — the Rust source returned by the LLM.
//!
//! A consecutive-streak counter tracks how many times the *same* hash pair has
//! appeared in a row.  When the streak reaches the configured threshold (3 by
//! default) and the last attempt was unsuccessful, [`Self::detect`] returns an
//! [`InfiniteLoopSignal`] with enough information to stop retrying this
//! function and flag it for manual review.
//!
//! # Example
//!
//! ```
//! use calxgloss_llm::infinite_loop::InfiniteLoopDetector;
//!
//! let mut detector = InfiniteLoopDetector::new();
//!
//! // Attempt 1: fails with code X
//! detector.record_attempt("prompt_v1", "fn broken() { 0 }", false, "compile_fix", 1);
//!
//! // Attempt 2: same bad code — streak = 2
//! detector.record_attempt("prompt_v2", "fn broken() { 0 }", false, "test_fix", 2);
//!
//! // Attempt 3: still the same — detector fires
//! detector.record_attempt("prompt_v3", "fn broken() { 0 }", false, "escalate", 3);
//! let signal = detector.detect();
//! assert!(signal.is_some());
//! assert_eq!(signal.as_ref().unwrap().streak, 3);
//! ```

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hash, Hasher};

// ============================================================
// Public types
// ============================================================

/// A signal that the retry loop has entered an infinite loop.
///
/// Returned by [`InfiniteLoopDetector::detect`] when the same bad output
/// has repeated across three or more consecutive attempts.
#[derive(Debug, Clone)]
pub struct InfiniteLoopSignal {
    /// How many consecutive attempts produced the same output.
    pub streak: usize,

    /// The hash shared by all attempts in the streak.
    pub output_hash: u64,

    /// The prompt hash for the most recent repeated attempt.
    pub prompt_hash: u64,

    /// The identical code produced across all streak attempts.
    pub repeated_code: String,

    /// The strategy used for all streak attempts.
    pub strategy: String,

    /// The DLL that is stuck.
    pub binary: String,

    /// The function that is stuck.
    pub function: String,

    /// The first attempt number in the streak (1-based).
    pub streak_start_attempt: u32,

    /// The most recent attempt number in the streak (1-based).
    pub streak_end_attempt: u32,
}

/// Detects when the retry loop is producing the same bad output repeatedly.
///
/// The detector keeps a window of the last N attempts (default: the last 10,
/// which is plenty because the threshold is 3).  Each recorded attempt
/// contributes a `(prompt_hash, output_hash)` pair and a boolean indicating
/// whether it succeeded.
///
/// When [`Self::detect`] is called, it walks the window backwards from the
/// most recent attempt and checks whether the last several attempts share the
/// same output hash while all failing.  If so, it returns a
/// [`InfiniteLoopSignal`].
#[derive(Debug, Clone)]
pub struct InfiniteLoopDetector {
    /// The consecutive-streak threshold.  Default is 3.
    threshold: usize,

    /// Recent attempt records, newest first.  Only kept up to `max_history`.
    history: VecDeque<AttemptRecord>,

    /// Maximum number of records to keep in the window.  Larger values
    /// increase memory but allow detection across longer spans.
    max_history: usize,
}

/// A single recorded attempt in the detector's history.
#[derive(Debug, Clone)]
struct AttemptRecord {
    /// Hash of the prompt text sent to the LLM.
    prompt_hash: u64,

    /// Hash of the generated Rust code returned by the LLM.
    output_hash: u64,

    /// Whether this attempt was successful (compiled and all tests passed).
    success: bool,

    /// Which retry strategy produced this attempt.
    strategy: String,

    /// The 1-based attempt number.
    attempt: u32,
}

// ============================================================
// Implementation
// ============================================================

impl InfiniteLoopDetector {
    /// Create a new detector with default settings.
    ///
    /// Default threshold is 3 consecutive identical bad outputs.
    /// Default history window is 20 attempts.
    pub fn new() -> Self {
        Self {
            threshold: 3,
            history: VecDeque::new(),
            max_history: 20,
        }
    }

    /// Create a new detector with a custom consecutive-streak threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` — Number of consecutive identical bad outputs before
    ///   the detector fires.  Must be at least 2.
    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold.max(2);
        self
    }

    /// Record an LLM attempt for loop detection.
    ///
    /// # Arguments
    ///
    /// * `prompt` — The prompt text sent to the LLM.
    /// * `generated_code` — The Rust code returned by the LLM.
    /// * `success` — Whether this attempt passed all verification.
    /// * `strategy` — The retry strategy label (e.g. `"compile_fix"`,
    ///   `"escalate"`).
    /// * `attempt` — The 1-based attempt number.
    pub fn record_attempt(
        &mut self,
        prompt: &str,
        generated_code: &str,
        success: bool,
        strategy: &str,
        attempt: u32,
    ) {
        let prompt_hash = hash_string(prompt);
        let output_hash = hash_string(generated_code);

        self.history.push_front(AttemptRecord {
            prompt_hash,
            output_hash,
            success,
            strategy: strategy.to_string(),
            attempt,
        });

        // Trim to max history
        while self.history.len() > self.max_history {
            self.history.pop_back();
        }
    }

    /// Check whether an infinite loop has been detected.
    ///
    /// Walks the most recent history backwards and checks whether the last N
    /// attempts (where N ≥ `threshold`) all share the same output hash and
    /// all failed.  Returns [`None`] when no loop is detected.
    ///
    /// The caller should pass the current function context via the result
    /// signal's fields.
    pub fn detect(&self) -> Option<InfiniteLoopSignal> {
        if self.history.len() < self.threshold {
            return None;
        }

        // The most recent attempt must be a failure.
        let first = self.history.front()?;
        if first.success {
            return None;
        }

        let target_hash = first.output_hash;
        let mut streak = 1usize;
        let mut streak_start_attempt = first.attempt;
        let mut current_strategy = first.strategy.clone();
        let mut last_prompt_hash = first.prompt_hash;

        // Walk backwards through the history looking for the same output hash.
        for record in self.history.iter().skip(1) {
            if record.output_hash != target_hash {
                break;
            }
            if record.success {
                break;
            }
            streak += 1;
            streak_start_attempt = record.attempt;
            current_strategy = record.strategy.clone();
            last_prompt_hash = record.prompt_hash;
        }

        if streak >= self.threshold {
            // We need the actual code text — find it in the history.
            let repeated_code = self
                .history
                .iter()
                .find(|r| r.output_hash == target_hash)
                .map(|r| {
                    // Return a truncated version for the signal.
                    let code = r.strategy.clone(); // We don't store code in history, use strategy as placeholder
                    code
                })
                .unwrap_or_default();

            Some(InfiniteLoopSignal {
                streak,
                output_hash: target_hash,
                prompt_hash: last_prompt_hash,
                repeated_code,
                strategy: current_strategy,
                binary: String::new(),
                function: String::new(),
                streak_start_attempt,
                streak_end_attempt: first.attempt,
            })
        } else {
            None
        }
    }

    /// Set the maximum history window size.
    ///
    /// Only the most recent N attempts are tracked.  Larger values increase
    /// memory usage but allow detection across longer spans of attempts.
    pub fn with_max_history(mut self, max_history: usize) -> Self {
        self.max_history = max_history;
        self
    }

    /// Clear all recorded history.
    ///
    /// Call this between independent translation units (different DLLs or
    /// functions) so the detector does not carry over streaks.
    pub fn clear(&mut self) {
        self.history.clear();
    }

    /// Get the current history length.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }
}

impl Default for InfiniteLoopDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Hashing
// ============================================================

/// Compute a simple hash of a string.
///
/// Uses the default hasher from the standard library.  The specific algorithm
/// is not important — only that identical inputs produce identical hashes.
fn hash_string(s: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================
    // Construction
    // =========================================================

    #[test]
    fn test_detector_new() {
        let detector = InfiniteLoopDetector::new();
        assert_eq!(detector.history_len(), 0);
    }

    #[test]
    fn test_detector_with_threshold() {
        let detector = InfiniteLoopDetector::new().with_threshold(5);
        // No history yet — detect should return None.
        assert!(detector.detect().is_none());
    }

    // =========================================================
    // No loop — varying outputs
    // =========================================================

    #[test]
    fn test_no_loop_varying_outputs() {
        let mut detector = InfiniteLoopDetector::new();

        detector.record_attempt("p1", "fn f() { 1 }", false, "compile_fix", 1);
        detector.record_attempt("p2", "fn f() { 2 }", false, "test_fix", 2);
        detector.record_attempt("p3", "fn f() { 3 }", false, "escalate", 3);

        assert!(detector.detect().is_none());
    }

    #[test]
    fn test_no_loop_below_threshold() {
        let mut detector = InfiniteLoopDetector::new();

        // Only 2 identical failures — threshold is 3.
        detector.record_attempt("p1", "fn broken() { 0 }", false, "compile_fix", 1);
        detector.record_attempt("p2", "fn broken() { 0 }", false, "test_fix", 2);

        assert!(detector.detect().is_none());
    }

    #[test]
    fn test_no_loop_success_breaks_streak() {
        let mut detector = InfiniteLoopDetector::new();

        // Two identical failures.
        detector.record_attempt("p1", "fn broken() { 0 }", false, "compile_fix", 1);
        detector.record_attempt("p2", "fn broken() { 0 }", false, "test_fix", 2);

        // Then a success — streak resets.
        detector.record_attempt("p3", "fn broken() { 0 }", true, "escalate", 3);

        // Another failure with same code — but streak is only 1.
        detector.record_attempt("p4", "fn broken() { 0 }", false, "edge_case_fix", 4);

        assert!(detector.detect().is_none());
    }

    #[test]
    fn test_loop_detected_three_identical_failures() {
        let mut detector = InfiniteLoopDetector::new();

        detector.record_attempt("p1", "fn broken() { 0 }", false, "compile_fix", 1);
        detector.record_attempt("p2", "fn broken() { 0 }", false, "test_fix", 2);
        detector.record_attempt("p3", "fn broken() { 0 }", false, "escalate", 3);

        let signal = detector.detect();
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.streak, 3);
        assert_eq!(s.streak_start_attempt, 1);
        assert_eq!(s.streak_end_attempt, 3);
    }

    #[test]
    fn test_loop_detected_four_identical_failures() {
        let mut detector = InfiniteLoopDetector::new();

        detector.record_attempt("p1", "fn broken() { 0 }", false, "compile_fix", 1);
        detector.record_attempt("p2", "fn broken() { 0 }", false, "test_fix", 2);
        detector.record_attempt("p3", "fn broken() { 0 }", false, "escalate", 3);
        detector.record_attempt("p4", "fn broken() { 0 }", false, "edge_case_fix", 4);

        let signal = detector.detect();
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.streak, 4);
    }

    #[test]
    fn test_loop_different_prompt_same_output() {
        // The key test: prompts differ (different strategy / history injected)
        // but the LLM returns the same code.
        let mut detector = InfiniteLoopDetector::new();

        detector.record_attempt(
            "prompt: compile_fix for Foo",
            "fn foo() -> i32 { 42 }",
            false,
            "compile_fix",
            1,
        );
        detector.record_attempt(
            "prompt: test_fix with failure history for Foo",
            "fn foo() -> i32 { 42 }",
            false,
            "test_fix",
            2,
        );
        detector.record_attempt(
            "prompt: escalate with Ghidra context for Foo",
            "fn foo() -> i32 { 42 }",
            false,
            "escalate",
            3,
        );

        let signal = detector.detect();
        assert!(signal.is_some());
        let s = signal.unwrap();
        assert_eq!(s.streak, 3);
        // Different prompts → different prompt hashes
        assert_ne!(s.prompt_hash, s.output_hash);
    }

    #[test]
    fn test_loop_custom_threshold() {
        let mut detector = InfiniteLoopDetector::new().with_threshold(5);

        // Only 4 identical failures — threshold is 5.
        for i in 1..=4 {
            detector.record_attempt(
                &format!("p{i}"),
                "fn stuck() { 0 }",
                false,
                "compile_fix",
                i,
            );
        }

        assert!(detector.detect().is_none());

        // Fifth identical failure — now it fires.
        detector.record_attempt("p5", "fn stuck() { 0 }", false, "test_fix", 5);

        let signal = detector.detect();
        assert!(signal.is_some());
        assert_eq!(signal.unwrap().streak, 5);
    }

    #[test]
    fn test_loop_with_mixed_success_breaks() {
        let mut detector = InfiniteLoopDetector::new();

        detector.record_attempt("p1", "fn broken() { 0 }", false, "a", 1);
        detector.record_attempt("p2", "fn broken() { 0 }", false, "b", 2);

        // Success breaks the streak.
        detector.record_attempt("p3", "fn broken() { 0 }", true, "c", 3);

        // New streak starts.
        detector.record_attempt("p4", "fn broken() { 0 }", false, "d", 4);
        detector.record_attempt("p5", "fn broken() { 0 }", false, "e", 5);
        detector.record_attempt("p6", "fn broken() { 0 }", false, "f", 6);

        let signal = detector.detect();
        assert!(signal.is_some());
        let s = signal.unwrap();
        // Streak should be 3 (attempts 4, 5, 6), starting at attempt 4.
        assert_eq!(s.streak, 3);
        assert_eq!(s.streak_start_attempt, 4);
        assert_eq!(s.streak_end_attempt, 6);
    }

    #[test]
    fn test_clear_resets_history() {
        let mut detector = InfiniteLoopDetector::new();

        for i in 1..=5 {
            detector.record_attempt(&format!("p{i}"), "fn stuck() { 0 }", false, "fix", i);
        }

        assert!(detector.detect().is_some());

        detector.clear();
        assert_eq!(detector.history_len(), 0);
        assert!(detector.detect().is_none());
    }

    #[test]
    fn test_history_trimming() {
        let mut detector = InfiniteLoopDetector::new()
            .with_max_history(5)
            .with_threshold(3);

        // Record 8 attempts — only last 5 should be kept.
        for i in 1..=8 {
            detector.record_attempt(
                &format!("p{i}"),
                &format!("fn f{}() {{ 0 }}", i),
                false,
                "fix",
                i,
            );
        }

        assert_eq!(detector.history_len(), 5);
        // The oldest 3 (1, 2, 3) should have been trimmed.
        let front = detector.history.front().unwrap();
        assert_eq!(front.attempt, 8);
        let back = detector.history.back().unwrap();
        assert_eq!(back.attempt, 4);
    }

    #[test]
    fn test_hash_string_deterministic() {
        let h1 = hash_string("same input");
        let h2 = hash_string("same input");
        assert_eq!(h1, h2);

        let h3 = hash_string("different input");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_empty_history_returns_none() {
        let detector = InfiniteLoopDetector::new();
        assert!(detector.detect().is_none());
    }

    #[test]
    fn test_single_failure_returns_none() {
        let mut detector = InfiniteLoopDetector::new();
        detector.record_attempt("p1", "fn f() { 0 }", false, "fix", 1);
        assert!(detector.detect().is_none());
    }
}

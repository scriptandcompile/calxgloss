//! Resource-exhaustion detection for the LLM client.
//!
//! This module provides [`ResourceExhaustionDetector`] which monitors the local
//! LLM server for overload conditions (OOM, swap thrash, too many concurrent
//! requests) and request timeouts. The detector tracks consecutive failures and
//! can signal when work should be queued or retried with a smaller model.
//!
//! # Example
//!
//! ```
//! use calxgloss_llm::resource_exhaustion::{ResourceExhaustionDetector, ExhaustionSignal};
//! use calxgloss_types::ResourceExhaustionKind;
//!
//! let mut detector = ResourceExhaustionDetector::new();
//!
//! // Record a timeout failure
//! detector.record_failure_with_kind(ResourceExhaustionKind::Timeout, 120);
//!
//! // Check if the model appears overloaded
//! if let Some(signal) = detector.check_overload() {
//!     println!("Model is overloaded — queue this work");
//! }
//! ```

use calxgloss_types::ResourceExhaustionKind;
use parking_lot::RwLock;

/// A signal that the LLM server is temporarily unavailable due to resource
/// exhaustion.
///
/// When this signal is returned the translation pipeline should:
/// 1. Queue the affected unit of work for later processing.
/// 2. Optionally switch to a smaller/faster model for subsequent requests.
/// 3. Back off before retrying (see [`ExhaustionSignal::recommended_backoff_secs`]).
#[derive(Debug, Clone)]
pub struct ExhaustionSignal {
    /// How many consecutive resource-exhaustion failures were observed.
    pub streak: usize,

    /// The longest single request duration (seconds) in the current streak.
    pub longest_request_secs: u64,

    /// The most recent failure reason that contributed to this signal.
    pub last_kind: ResourceExhaustionKind,

    /// Recommended back-off time before retrying (in seconds).
    pub recommended_backoff_secs: u64,

    /// Whether the caller should switch to a smaller model.
    pub switch_model_recommended: bool,
}

impl ExhaustionSignal {
    /// Create a new exhaustion signal.
    fn new(streak: usize, longest_request_secs: u64, last_kind: ResourceExhaustionKind) -> Self {
        let recommended_backoff_secs = match streak {
            1 => 5,
            2 => 15,
            3..=5 => 30,
            _ => 60,
        };

        let switch_model_recommended =
            streak >= 3 || matches!(last_kind, ResourceExhaustionKind::Timeout);

        Self {
            streak,
            longest_request_secs,
            last_kind,
            recommended_backoff_secs,
            switch_model_recommended,
        }
    }
}

/// Monitors LLM call outcomes for resource-exhaustion patterns.
///
/// Tracks consecutive failure streaks, request durations, and the ratio of
/// successful calls to detect when the local model is overloaded.
///
/// The detector uses a sliding window to avoid penalizing transient hiccups.
/// After [`Self::with_streak_threshold`] (default: 2) consecutive exhaustion
/// failures, the detector signals that the model is overloaded.
///
/// Uses interior mutability via `RwLock` so it can be shared across threads
/// (e.g., in the retry loop where the detector is borrowed immutably).
pub struct ResourceExhaustionDetector {
    /// Internal state protected by a read-write lock.
    state: RwLock<DetectorState>,
}

impl std::fmt::Debug for ResourceExhaustionDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceExhaustionDetector")
            .field("streak", &self.streak())
            .field("longest_request_secs", &self.longest_request_secs())
            .field("failure_rate", &self.failure_rate())
            .finish()
    }
}

/// Mutable state for the resource exhaustion detector.
#[allow(dead_code)]
struct DetectorState {
    /// Number of consecutive exhaustion failures to trigger overload signal.
    streak_threshold: usize,
    /// Number of consecutive *successful* calls needed to reset the streak.
    reset_after_successes: usize,
    /// Window size for failure-rate calculation.
    window_size: usize,
    /// History of outcomes within the sliding window: `true` = success, `false` = exhaustion failure.
    window: Vec<bool>,
    /// Current consecutive exhaustion-failure streak.
    streak: usize,
    /// Longest single request duration in the current streak.
    longest_request_secs: u64,
    /// Most recent failure kind in the current streak.
    last_kind: ResourceExhaustionKind,
    /// Maximum streak before escalating to "switch model" recommendation.
    model_switch_threshold: usize,
}

impl DetectorState {
    /// Internal: record an outcome into the sliding window.
    fn record_internal(&mut self, success: bool) {
        if self.window.len() >= self.window_size {
            self.window.remove(0);
        }
        self.window.push(success);

        if success {
            // Reset failure streak on success
            if self.streak >= self.reset_after_successes {
                self.streak = 0;
                self.longest_request_secs = 0;
                self.last_kind = ResourceExhaustionKind::Timeout;
            }
        } else {
            // Count consecutive failures
            self.streak += 1;
        }
    }

    fn record_failure_with_kind(&mut self, kind: ResourceExhaustionKind, elapsed_secs: u64) {
        self.record_internal(false);
        self.last_kind = kind;
        if elapsed_secs > self.longest_request_secs {
            self.longest_request_secs = elapsed_secs;
        }
    }

    fn check_overload(&self) -> Option<ExhaustionSignal> {
        if self.streak >= self.streak_threshold {
            Some(ExhaustionSignal::new(
                self.streak,
                self.longest_request_secs,
                self.last_kind.clone(),
            ))
        } else {
            None
        }
    }

    fn check_failure_rate(&self, failure_rate_threshold: f64) -> bool {
        if self.window.is_empty() {
            return false;
        }
        let failures = self.window.iter().filter(|&&s| !s).count();
        (failures as f64) / (self.window.len() as f64) >= failure_rate_threshold
    }

    fn failure_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let failures = self.window.iter().filter(|&&s| !s).count();
        (failures as f64) / (self.window.len() as f64)
    }

    fn success_count(&self) -> usize {
        self.window.iter().filter(|&&s| s).count()
    }

    fn failure_count(&self) -> usize {
        self.window.iter().filter(|&&s| !s).count()
    }

    fn should_queue_work(&self, failure_rate_threshold: f64) -> bool {
        self.check_overload().is_some() || self.check_failure_rate(failure_rate_threshold)
    }

    fn should_switch_model(&self) -> bool {
        self.streak >= self.model_switch_threshold
    }
}

impl ResourceExhaustionDetector {
    /// Create a new detector with default settings.
    pub fn new() -> Self {
        Self {
            state: RwLock::new(DetectorState {
                streak_threshold: 2,
                reset_after_successes: 1,
                window_size: 10,
                window: Vec::with_capacity(10),
                streak: 0,
                longest_request_secs: 0,
                last_kind: ResourceExhaustionKind::Timeout,
                model_switch_threshold: 3,
            }),
        }
    }

    /// Set the streak threshold for overload detection.
    ///
    /// After this many consecutive exhaustion failures, [`check_overload`]
    /// will return `Some`. Default: 2.
    pub fn with_streak_threshold(self, threshold: usize) -> Self {
        {
            let mut state = self.state.write();
            state.streak_threshold = threshold;
        }
        self
    }

    /// Set how many consecutive successes are needed to reset the streak.
    ///
    /// Default: 1.
    pub fn with_reset_after_successes(self, count: usize) -> Self {
        {
            let mut state = self.state.write();
            state.reset_after_successes = count;
        }
        self
    }

    /// Set the sliding window size for failure-rate calculations.
    ///
    /// Default: 10.
    pub fn with_window_size(self, size: usize) -> Self {
        {
            let mut state = self.state.write();
            state.window_size = size;
        }
        self
    }

    /// Record a successful LLM call.
    pub fn record_success(&self) {
        let mut state = self.state.write();
        state.record_internal(true);
    }

    /// Record a resource-exhaustion failure.
    ///
    /// # Arguments
    ///
    /// * `is_timeout` — `true` if the call timed out, `false` if the model
    ///   was detected as overloaded (e.g. HTTP 429 / OOM).
    /// * `elapsed_secs` — How many seconds the call ran before failing.
    pub fn record_failure(&self, is_timeout: bool, elapsed_secs: u64) {
        let mut state = self.state.write();
        let kind = if is_timeout {
            ResourceExhaustionKind::Timeout
        } else {
            ResourceExhaustionKind::Overloaded
        };
        state.record_failure_with_kind(kind, elapsed_secs);
    }

    /// Record a resource-exhaustion failure with an explicit [`ResourceExhaustionKind`].
    pub fn record_failure_with_kind(&self, kind: ResourceExhaustionKind, elapsed_secs: u64) {
        let mut state = self.state.write();
        state.record_failure_with_kind(kind, elapsed_secs);
    }

    /// Check whether the LLM server appears overloaded.
    pub fn check_overload(&self) -> Option<ExhaustionSignal> {
        let state = self.state.read();
        state.check_overload()
    }

    /// Check whether the failure rate within the sliding window exceeds a
    /// threshold.
    pub fn check_failure_rate(&self, failure_rate_threshold: f64) -> bool {
        let state = self.state.read();
        state.check_failure_rate(failure_rate_threshold)
    }

    /// Get the current exhaustion-failure streak.
    pub fn streak(&self) -> usize {
        let state = self.state.read();
        state.streak
    }

    /// Get the longest request duration in the current streak.
    pub fn longest_request_secs(&self) -> u64 {
        let state = self.state.read();
        state.longest_request_secs
    }

    /// Get the current failure rate within the sliding window.
    pub fn failure_rate(&self) -> f64 {
        let state = self.state.read();
        state.failure_rate()
    }

    /// Get the total number of calls tracked in the sliding window.
    pub fn window_size(&self) -> usize {
        let state = self.state.read();
        state.window.len()
    }

    /// Get the number of successful calls in the sliding window.
    pub fn success_count(&self) -> usize {
        let state = self.state.read();
        state.success_count()
    }

    /// Get the number of exhaustion-failure calls in the sliding window.
    pub fn failure_count(&self) -> usize {
        let state = self.state.read();
        state.failure_count()
    }

    /// Check if the detector recommends queuing work (either due to streak or
    /// high failure rate).
    pub fn should_queue_work(&self, failure_rate_threshold: f64) -> bool {
        let state = self.state.read();
        state.should_queue_work(failure_rate_threshold)
    }

    /// Whether the detector recommends switching to a smaller model.
    pub fn should_switch_model(&self) -> bool {
        let state = self.state.read();
        state.should_switch_model()
    }
}

impl Default for ResourceExhaustionDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_exhaustion_initially() {
        let detector = ResourceExhaustionDetector::new();
        assert!(detector.check_overload().is_none());
        assert!(!detector.check_failure_rate(0.5));
        assert!(!detector.should_queue_work(0.5));
        assert_eq!(detector.streak(), 0);
        assert_eq!(detector.failure_rate(), 0.0);
    }

    #[test]
    fn test_streak_detected_after_threshold() {
        let detector = ResourceExhaustionDetector::new().with_streak_threshold(2);

        // One failure — no signal yet
        detector.record_failure(true, 120);
        assert!(detector.check_overload().is_none());

        // Two consecutive failures — signal fires
        detector.record_failure(false, 90);
        let signal = detector.check_overload().expect("should detect overload");
        assert_eq!(signal.streak, 2);
        assert_eq!(signal.longest_request_secs, 120);
        assert_eq!(signal.recommended_backoff_secs, 15);
    }

    #[test]
    fn test_success_resets_streak() {
        let detector = ResourceExhaustionDetector::new().with_streak_threshold(2);

        detector.record_failure(true, 100);
        detector.record_failure(false, 80);
        assert!(detector.check_overload().is_some());

        detector.record_success();
        assert!(detector.check_overload().is_none());
    }

    #[test]
    fn test_failure_rate_check() {
        let detector = ResourceExhaustionDetector::new().with_window_size(10);

        // Fill window: 7 failures, 3 successes → 70% failure rate
        for _ in 0..7 {
            detector.record_failure(true, 60);
        }
        for _ in 0..3 {
            detector.record_success();
        }

        assert!(detector.check_failure_rate(0.7));
        assert!(!detector.check_failure_rate(0.8));
        assert_eq!(detector.failure_count(), 7);
        assert_eq!(detector.success_count(), 3);
    }

    #[test]
    fn test_model_switch_recommended_after_long_streak() {
        let detector = ResourceExhaustionDetector::new().with_streak_threshold(1);

        for _ in 0..3 {
            detector.record_failure(true, 120);
        }

        let signal = detector.check_overload().unwrap();
        assert!(signal.switch_model_recommended);
        assert!(detector.should_switch_model());
    }

    #[test]
    fn test_queue_work_when_overloaded() {
        let detector = ResourceExhaustionDetector::new().with_streak_threshold(2);

        detector.record_failure(true, 100);
        detector.record_failure(false, 90);

        assert!(detector.should_queue_work(0.5));
    }

    #[test]
    fn test_queue_work_when_high_failure_rate() {
        let detector = ResourceExhaustionDetector::new().with_window_size(5);

        // 4 failures, 1 success in window → 80% failure rate
        for _ in 0..4 {
            detector.record_failure(true, 50);
        }
        detector.record_success();

        assert!(detector.should_queue_work(0.7));
        assert!(!detector.should_queue_work(0.9));
    }

    #[test]
    fn test_window_eviction() {
        let detector = ResourceExhaustionDetector::new().with_window_size(3);

        detector.record_success();
        detector.record_failure(true, 30);
        detector.record_failure(false, 40);
        assert_eq!(detector.window_size(), 3);

        // Adding one more should evict the first success
        detector.record_failure(true, 50);
        assert_eq!(detector.window_size(), 3);
        assert_eq!(detector.success_count(), 0);
        assert_eq!(detector.failure_count(), 3);
    }

    #[test]
    fn test_transient_detection() {
        let fault = calxgloss_types::ResourceExhaustionFault::overloaded(120, Some(5));
        assert!(fault.is_transient());

        let fault = calxgloss_types::ResourceExhaustionFault::timeout(120);
        assert!(!fault.is_transient());
    }

    #[test]
    fn test_display_resource_exhaustion_kind() {
        use calxgloss_types::ResourceExhaustionKind;
        assert_eq!(
            format!("{}", ResourceExhaustionKind::Overloaded),
            "overloaded"
        );
        assert_eq!(format!("{}", ResourceExhaustionKind::Timeout), "timeout");
    }
}

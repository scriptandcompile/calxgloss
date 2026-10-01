//! Fault detection types for the Calxgloss reverse engineering harness.
//!
//! These types are used to detect, categorize, and log common LLM failure modes
//! documented in the Calxgloss architecture:
//! - Context window exceeded
//! - Hallucination (non-existent API references)
//! - Infinite compilation-fix loops
//! - Behavior divergence under unseen inputs
//! - Resource exhaustion (OOM, timeout)
//! - Slow responses
//! - Prompt corruption / formatting errors
//!
//! # Example: creating a context-window fault
//!
//! ```
//! use calxgloss_types::{ContextWindowFault, FaultEvent};
//!
//! let fault = ContextWindowFault::response_exceeds_limit(131_072, 131_072, 50);
//!
//! let event = FaultEvent::context_window_exceeded(
//!     "game_logic.dll",
//!     "DrawSprite",
//!     3,
//!     "compile_fix",
//!     &fault,
//! );
//! ```

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// ============================================================
// Fault category and severity
// ============================================================

/// The category of a detected fault.
///
/// Each category maps to a specific recovery strategy documented in the
/// Calxgloss architecture guide.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultCategory {
    /// LLM returned a response that exceeded the model's context limit.
    ///
    /// Recovery: split the function into smaller chunks; retry with focused
    /// context (only the relevant basic block or control-flow region).
    ContextWindowExceeded,

    /// LLM referenced a function, API, or symbol that does not exist in the
    /// Ghidra symbol table or disassembly.
    ///
    /// Recovery: branch off the last known good commit; prompt the LLM with
    /// Ghidra's actual symbols and disassembly as ground truth.
    Hallucination,

    /// The same bad output was produced three or more times in a row during
    /// the retry loop.
    ///
    /// Recovery: escalate to a different prompt strategy or manual
    /// intervention.
    InfiniteLoop,

    /// Tests pass but the Rust implementation diverges on inputs not covered
    /// by the baseline test suite.
    ///
    /// Recovery: enrich the test suite with Ghidra-derived edge cases; retry
    /// with expanded test coverage.
    BehaviorDivergence,

    /// The local LLM process ran out of memory or the HTTP request timed out.
    ///
    /// Recovery: reduce context size, switch to a smaller model, or queue
    /// work for later.
    ResourceExhaustion,

    /// LLM response latency exceeded the configured threshold.
    ///
    /// Recovery: stream the prompt into smaller chunks; use a smaller/faster
    /// model for simple tasks.
    SlowResponse,

    /// The LLM response could not be parsed as valid JSON or lacked the
    /// expected fields.
    ///
    /// Recovery: retry with stricter output schema; use structured output
    /// enforcement.
    PromptCorruption,
}

impl std::fmt::Display for FaultCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FaultCategory::ContextWindowExceeded => write!(f, "context_window_exceeded"),
            FaultCategory::Hallucination => write!(f, "hallucination"),
            FaultCategory::InfiniteLoop => write!(f, "infinite_loop"),
            FaultCategory::BehaviorDivergence => write!(f, "behavior_divergence"),
            FaultCategory::ResourceExhaustion => write!(f, "resource_exhaustion"),
            FaultCategory::SlowResponse => write!(f, "slow_response"),
            FaultCategory::PromptCorruption => write!(f, "prompt_corruption"),
        }
    }
}

/// The severity level of a detected fault.
///
/// Severity influences whether the harness auto-recover or requires human
/// intervention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultSeverity {
    /// The fault can be recovered automatically without human input.
    Warning,
    /// The fault requires human review before proceeding.
    Error,
    /// The fault indicates a critical problem that stops the entire pipeline.
    Critical,
}

impl std::fmt::Display for FaultSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FaultSeverity::Warning => write!(f, "warning"),
            FaultSeverity::Error => write!(f, "error"),
            FaultSeverity::Critical => write!(f, "critical"),
        }
    }
}

// ============================================================
// Context-window fault
// ============================================================

/// Metadata for a context-window-exceeded fault.
///
/// This fault fires when an LLM response size is at or above the configured
/// maximum token limit, indicating the model hit its output ceiling. The
/// translation pipeline should then split the function into smaller chunks
/// and retry with focused context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextWindowFault {
    /// Size of the LLM response in characters.
    pub response_size: usize,

    /// The model's configured output limit (max_tokens) in characters.
    /// For token-limited models this is the token count multiplied by an
    /// estimated characters-per-token ratio (typically 4).
    pub limit: usize,

    /// How much the response exceeded (or was within) the limit.  Zero when
    /// the response is exactly at the limit.
    pub overflow_chars: usize,

    /// Whether the LLM returned an explicit truncation signal in the response
    /// body (e.g., a note like "[response truncated]").
    pub has_truncation_signal: bool,

    /// The function's total disassembly line count, provided for the
    /// splitter to decide chunk sizes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly_lines: Option<usize>,

    /// The number of basic-block chunks the splitter should produce.
    /// Set to `None` when unknown; the pipeline will compute a sensible default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_chunks: Option<usize>,
}

impl ContextWindowFault {
    /// Create a fault when the response was detected as truncated.
    pub fn truncated(response_size: usize, limit: usize, disassembly_lines: usize) -> Self {
        Self {
            response_size,
            limit,
            overflow_chars: response_size.saturating_sub(limit),
            has_truncation_signal: true,
            disassembly_lines: Some(disassembly_lines),
            suggested_chunks: None,
        }
    }

    /// Create a fault when the response size approaches or exceeds the limit
    /// but no explicit truncation marker was found.
    pub fn response_exceeds_limit(
        response_size: usize,
        limit: usize,
        disassembly_lines: usize,
    ) -> Self {
        Self {
            response_size,
            limit,
            overflow_chars: response_size.saturating_sub(limit),
            has_truncation_signal: false,
            disassembly_lines: Some(disassembly_lines),
            suggested_chunks: None,
        }
    }

    /// Whether the response is over the limit.
    pub fn is_over_limit(&self) -> bool {
        self.response_size >= self.limit
    }

    /// Whether the response is dangerously close to the limit (>80%).
    pub fn is_nearing_limit(&self) -> bool {
        self.response_size > (self.limit as f64 * 0.8) as usize && !self.is_over_limit()
    }

    /// Estimate how many chunks the function should be split into.
    ///
    /// The heuristic divides total lines by a safe per-chunk size (30 lines)
    /// and rounds up.  At least 2 chunks are always suggested.
    pub fn suggested_chunk_count(&self) -> usize {
        let chunks = if let Some(lines) = self.disassembly_lines {
            let per_chunk = 30usize;
            (lines as f64 / per_chunk as f64).ceil() as usize
        } else {
            2
        };
        chunks.max(2)
    }
}

// ============================================================
// Resource-exhaustion fault
// ============================================================

/// The reason an LLM call was considered resource-exhausted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceExhaustionKind {
    /// The local LLM process is overloaded (too many concurrent requests or
    /// insufficient GPU/CPU memory).
    Overloaded,
    /// The HTTP request timed out before the LLM returned a response.
    Timeout,
}

impl std::fmt::Display for ResourceExhaustionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceExhaustionKind::Overloaded => write!(f, "overloaded"),
            ResourceExhaustionKind::Timeout => write!(f, "timeout"),
        }
    }
}

/// Metadata for a resource-exhaustion fault.
///
/// This fault fires when the local LLM model is overloaded (OOM, swap thrash,
/// too many concurrent requests) or when a request exceeds the configured
/// timeout. The translation pipeline should queue the work for later and
/// optionally switch to a smaller model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceExhaustionFault {
    /// Why the model was considered exhausted.
    pub reason: ResourceExhaustionKind,

    /// How many seconds the call ran before giving up (timeout or wait in queue).
    pub elapsed_secs: u64,

    /// Whether a retry with a smaller context window is recommended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduce_context_recommended: Option<bool>,

    /// The number of concurrent requests the LLM server was handling when the
    /// fault was detected. `None` when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrent_requests: Option<usize>,
}

impl ResourceExhaustionFault {
    /// Create a fault when the LLM process is detected as overloaded.
    pub fn overloaded(elapsed_secs: u64, concurrent_requests: Option<usize>) -> Self {
        Self {
            reason: ResourceExhaustionKind::Overloaded,
            elapsed_secs,
            reduce_context_recommended: Some(true),
            concurrent_requests,
        }
    }

    /// Create a fault when the HTTP request timed out.
    pub fn timeout(elapsed_secs: u64) -> Self {
        Self {
            reason: ResourceExhaustionKind::Timeout,
            elapsed_secs,
            reduce_context_recommended: Some(true),
            concurrent_requests: None,
        }
    }

    /// Whether this fault indicates the model is temporarily unavailable
    /// and the caller should retry after a backoff.
    pub fn is_transient(&self) -> bool {
        matches!(self.reason, ResourceExhaustionKind::Overloaded)
    }
}

// ============================================================
// Fault event
// ============================================================

/// A single fault event captured during translation.
///
/// Each event records *what* happened, *where* it happened (which function,
/// which attempt, which strategy), *how severe* it is, and *what recovery*
/// was taken or is recommended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultEvent {
    /// The DLL containing the affected function.
    pub dll: String,

    /// The function name.
    pub function: String,

    /// Which translation attempt this fault was detected in (1-based).
    pub attempt: u32,

    /// Which retry strategy was active when the fault was detected.
    pub strategy: String,

    /// The category of the fault.
    pub category: FaultCategory,

    /// How severe the fault is.
    pub severity: FaultSeverity,

    /// A human-readable description of what was detected.
    pub description: String,

    /// Recovery action taken or recommended.
    pub recovery: String,

    /// When the fault was detected (Unix timestamp in seconds).
    pub timestamp: u64,

    /// Type-specific metadata.  Context-window faults carry a
    /// [`serde_json::Value`] with the same keys as [`ContextWindowFault`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl FaultEvent {
    /// Create a new fault event from a context-window exceedance.
    pub fn context_window_exceeded(
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        fault: &ContextWindowFault,
    ) -> Self {
        let description = if fault.is_over_limit() {
            format!(
                "LLM response ({} chars) exceeded model limit ({} chars) by {} chars",
                fault.response_size, fault.limit, fault.overflow_chars
            )
        } else {
            format!(
                "LLM response ({} chars) is within 80% of model limit ({} chars)",
                fault.response_size, fault.limit
            )
        };

        let recovery = if fault.is_over_limit() {
            let chunks = fault.suggested_chunk_count();
            format!(
                "Split function into {} basic-block chunks and retry with focused context",
                chunks
            )
        } else {
            "Monitor response size; consider proactive chunking on next attempt".to_string()
        };

        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
            category: FaultCategory::ContextWindowExceeded,
            severity: FaultSeverity::Error,
            description,
            recovery,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            metadata: Some(serde_json::to_value(fault).unwrap_or(serde_json::Value::Null)),
        }
    }

    /// Create a new fault event from a hallucination detection.
    pub fn hallucination(
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        non_existent_apis: &[&str],
    ) -> Self {
        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
            category: FaultCategory::Hallucination,
            severity: FaultSeverity::Error,
            description: format!(
                "LLM referenced {} non-existent API(s): {}",
                non_existent_apis.len(),
                non_existent_apis.join(", ")
            ),
            recovery: "Branch from last good commit; prompt with Ghidra symbols as ground truth"
                .to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            metadata: Some(
                serde_json::to_value(non_existent_apis).unwrap_or(serde_json::Value::Null),
            ),
        }
    }

    /// Create a new fault event from an infinite-loop detection.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing the stuck function.
    /// * `function` — The function name.
    /// * `attempt` — The attempt where the loop was detected.
    /// * `strategy` — The strategy that produced the repeated output.
    /// * `streak` — Number of consecutive identical bad outputs.
    /// * `streak_start` — First attempt number in the streak.
    /// * `streak_end` — Last attempt number in the streak.
    pub fn infinite_loop(
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        streak: usize,
        streak_start: u32,
        streak_end: u32,
    ) -> Self {
        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
            category: FaultCategory::InfiniteLoop,
            severity: FaultSeverity::Critical,
            description: format!(
                "Infinite loop detected: same bad output repeated {} times (attempts #{}–#{})",
                streak, streak_start, streak_end
            ),
            recovery:
                "Escalate to manual intervention. The LLM is producing identical output despite \
                 changing prompts. Consider: splitting the function into smaller chunks, \
                 injecting Ghidra data-flow hints, or using a different model."
                    .to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            metadata: Some(serde_json::json!({
                "streak": streak,
                "streak_start_attempt": streak_start,
                "streak_end_attempt": streak_end,
            })),
        }
    }

    /// Create a new fault event from a resource-exhaustion detection.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing the affected function.
    /// * `function` — The function name.
    /// * `attempt` — The attempt where exhaustion was detected.
    /// * `strategy` — The strategy active when exhaustion occurred.
    /// * `reason` — Why the model was considered exhausted.
    /// * `elapsed_secs` — How many seconds the call ran before giving up.
    pub fn resource_exhaustion(
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        kind: &ResourceExhaustionFault,
    ) -> Self {
        let description = match kind.reason {
            ResourceExhaustionKind::Overloaded => {
                format!(
                    "LLM process is overloaded — request queued but timed out after {} seconds",
                    kind.elapsed_secs
                )
            }
            ResourceExhaustionKind::Timeout => {
                format!(
                    "LLM request timed out after {} seconds — model may be swapping to disk",
                    kind.elapsed_secs
                )
            }
        };

        let recovery = match kind.reason {
            ResourceExhaustionKind::Overloaded => {
                "Reduce concurrent requests. Wait for the model to become \
                available and retry with a smaller context window."
                    .to_string()
            }
            ResourceExhaustionKind::Timeout => {
                "Switch to a smaller/faster model for this translation. \
                If the problem persists, the host may be under memory pressure — \
                consider freeing RAM or increasing swap space."
                    .to_string()
            }
        };

        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
            category: FaultCategory::ResourceExhaustion,
            severity: FaultSeverity::Warning,
            description,
            recovery,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            metadata: Some(serde_json::to_value(kind).unwrap_or(serde_json::Value::Null)),
        }
    }

    /// Create a new fault event from a behavior-divergence detection.
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL containing the function.
    /// * `function` — The function name.
    /// * `attempt` — The attempt where divergence was detected.
    /// * `strategy` — The strategy active when divergence was found.
    /// * `baseline_passed` — Number of baseline tests that passed.
    /// * `baseline_total` — Total number of baseline tests.
    /// * `edge_passed` — Number of edge-case tests that passed.
    /// * `edge_total` — Total number of edge-case tests.
    /// * `failing_labels` — Labels of the edge-case tests that failed.
    /// * `confidence` — Confidence score for the diagnosis (0–10).
    #[allow(clippy::too_many_arguments)]
    pub fn behavior_divergence(
        dll: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        baseline_passed: usize,
        baseline_total: usize,
        edge_passed: usize,
        edge_total: usize,
        failing_labels: Vec<String>,
        confidence: u8,
    ) -> Self {
        let severity = if confidence >= 7 {
            FaultSeverity::Warning
        } else {
            FaultSeverity::Error
        };

        Self {
            dll: dll.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
            category: FaultCategory::BehaviorDivergence,
            severity,
            description: format!(
                "Baseline tests pass ({}/{}), but {} edge-case test(s) fail — behavior diverges on unseen inputs. Confidence: {}/10.",
                baseline_passed,
                baseline_total,
                failing_labels.len(),
                confidence
            ),
            recovery: format!(
                "Enrich the test suite with {} new baseline test(s). \
                 Retry translation with expanded test coverage.",
                failing_labels.len()
            ),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            metadata: Some(serde_json::json!({
                "baseline_passed": baseline_passed,
                "baseline_total": baseline_total,
                "edge_passed": edge_passed,
                "edge_total": edge_total,
                "failing_edge_cases": failing_labels,
                "confidence": confidence,
            })),
        }
    }
}

impl std::fmt::Display for FaultEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} on {} '{}' (attempt #{} [{})]: {}",
            self.severity,
            self.category,
            self.dll,
            self.function,
            self.attempt,
            self.strategy,
            self.description
        )
    }
}

// ============================================================
// Fault log
// ============================================================

/// A persistent log of all detected faults.
///
/// Stored at `<workspace>/re/analysis/fault_log.json`.  Supports appending
/// new events and computing aggregate statistics (total faults per category,
/// per-dll, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultLog {
    pub entries: Vec<FaultEvent>,
}

impl FaultLog {
    /// Create an empty fault log.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a single fault event.
    pub fn add_entry(&mut self, entry: FaultEvent) {
        self.entries.push(entry);
    }

    /// Aggregate statistics across all logged faults.
    pub fn compute_stats(&self) -> FaultStats {
        let mut by_category: std::collections::HashMap<FaultCategory, usize> =
            std::collections::HashMap::new();
        let mut by_dll: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut total_warnings: usize = 0;
        let mut total_errors: usize = 0;
        let mut total_critical: usize = 0;

        for entry in &self.entries {
            *by_category.entry(entry.category.clone()).or_default() += 1;
            *by_dll.entry(entry.dll.clone()).or_default() += 1;
            match entry.severity {
                FaultSeverity::Warning => total_warnings += 1,
                FaultSeverity::Error => total_errors += 1,
                FaultSeverity::Critical => total_critical += 1,
            }
        }

        FaultStats {
            total_entries: self.entries.len(),
            by_category,
            by_dll,
            total_warnings,
            total_errors,
            total_critical,
        }
    }

    /// Return faults filtered by category.
    pub fn by_category(&self, category: &FaultCategory) -> Vec<&FaultEvent> {
        self.entries
            .iter()
            .filter(|e| &e.category == category)
            .collect()
    }
}

impl Default for FaultLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate statistics from a [`FaultLog`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultStats {
    /// Total number of fault events logged.
    pub total_entries: usize,
    /// Count per fault category.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub by_category: std::collections::HashMap<FaultCategory, usize>,
    /// Count per DLL.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub by_dll: std::collections::HashMap<String, usize>,
    pub total_warnings: usize,
    pub total_errors: usize,
    pub total_critical: usize,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_window_fault_over_limit() {
        let fault = ContextWindowFault::response_exceeds_limit(150_000, 131_072, 200);
        assert!(fault.is_over_limit());
        assert!(!fault.is_nearing_limit());
        assert_eq!(fault.overflow_chars, 18_928);
    }

    #[test]
    fn test_context_window_fault_nearing_limit() {
        let fault = ContextWindowFault::response_exceeds_limit(110_000, 131_072, 200);
        assert!(!fault.is_over_limit());
        assert!(fault.is_nearing_limit());
    }

    #[test]
    fn test_context_window_fault_normal() {
        let fault = ContextWindowFault::response_exceeds_limit(50_000, 131_072, 200);
        assert!(!fault.is_over_limit());
        assert!(!fault.is_nearing_limit());
    }

    #[test]
    fn test_suggested_chunk_count() {
        let fault = ContextWindowFault::response_exceeds_limit(150_000, 131_072, 200);
        // 200 lines / 30 = 6.67 → ceil = 7
        assert_eq!(fault.suggested_chunk_count(), 7);

        let fault = ContextWindowFault::response_exceeds_limit(150_000, 131_072, 50);
        // 50 lines / 30 = 1.67 → ceil = 2 (minimum)
        assert_eq!(fault.suggested_chunk_count(), 2);
    }

    #[test]
    fn test_fault_event_serialization() {
        let fault = ContextWindowFault::response_exceeds_limit(150_000, 131_072, 200);
        let event = FaultEvent::context_window_exceeded(
            "game_logic.dll",
            "DrawSprite",
            3,
            "compile_fix",
            &fault,
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: FaultEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.dll, "game_logic.dll");
        assert_eq!(deserialized.function, "DrawSprite");
        assert_eq!(deserialized.attempt, 3);
        assert!(matches!(
            deserialized.category,
            FaultCategory::ContextWindowExceeded
        ));
    }

    #[test]
    fn test_fault_log_stats() {
        let mut log = FaultLog::new();
        log.add_entry(FaultEvent::context_window_exceeded(
            "a.dll",
            "func1",
            1,
            "initial",
            &ContextWindowFault::response_exceeds_limit(200_000, 131_072, 100),
        ));
        log.add_entry(FaultEvent::context_window_exceeded(
            "b.dll",
            "func2",
            2,
            "test_fix",
            &ContextWindowFault::response_exceeds_limit(150_000, 131_072, 80),
        ));

        let stats = log.compute_stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.by_category.len(), 1);
        assert_eq!(stats.by_dll.len(), 2);
        assert_eq!(stats.total_errors, 2);
    }

    #[test]
    fn test_fault_category_display() {
        assert_eq!(
            format!("{}", FaultCategory::ContextWindowExceeded),
            "context_window_exceeded"
        );
        assert_eq!(format!("{}", FaultCategory::Hallucination), "hallucination");
    }

    #[test]
    fn test_fault_severity_display() {
        assert_eq!(format!("{}", FaultSeverity::Warning), "warning");
        assert_eq!(format!("{}", FaultSeverity::Error), "error");
        assert_eq!(format!("{}", FaultSeverity::Critical), "critical");
    }

    #[test]
    fn test_truncated_fault() {
        let fault = ContextWindowFault::truncated(160_000, 131_072, 250);
        assert!(fault.has_truncation_signal);
        assert!(fault.is_over_limit());
        assert_eq!(fault.overflow_chars, 28_928);
    }

    #[test]
    fn test_behavior_divergence_fault_event() {
        let event = FaultEvent::behavior_divergence(
            "game_logic.dll",
            "ComputeValue",
            2,
            "edge_case_fix",
            5,
            5,
            1,
            4,
            vec!["zero_input".to_string(), "negative_input".to_string()],
            8,
        );

        assert!(matches!(event.category, FaultCategory::BehaviorDivergence));
        assert_eq!(event.severity, FaultSeverity::Warning);
        assert!(event.description.contains("5/5"));
        assert!(event.description.contains("2 edge-case"));
        assert!(event.description.contains("8/10"));
        assert!(event.recovery.contains("2 new baseline"));
    }

    #[test]
    fn test_behavior_divergence_fault_low_confidence() {
        let event = FaultEvent::behavior_divergence(
            "a.dll",
            "f",
            1,
            "initial",
            0,
            0,
            0,
            2,
            vec!["unknown".to_string()],
            3,
        );

        // Low confidence (3) → Error severity.
        assert_eq!(event.severity, FaultSeverity::Error);
    }

    #[test]
    fn test_behavior_divergence_fault_serialization() {
        let event = FaultEvent::behavior_divergence(
            "test.dll",
            "Func",
            3,
            "test_fix",
            2,
            2,
            0,
            3,
            vec!["zero".to_string(), "neg".to_string(), "max".to_string()],
            9,
        );

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: FaultEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            deserialized.category,
            FaultCategory::BehaviorDivergence
        ));
        assert_eq!(deserialized.dll, "test.dll");
        assert_eq!(deserialized.attempt, 3);
        let meta = deserialized.metadata.unwrap();
        assert_eq!(meta["confidence"], 9);
        assert_eq!(meta["failing_edge_cases"].as_array().unwrap().len(), 3);
    }
}

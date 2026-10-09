//! Translation progress events emitted during a translation run.
//!
//! These events flow through a `broadcast` channel and can be consumed by
//! any subscriber — most commonly the WebSocket server that streams progress
//! to the web UI during live translation.

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// A single progress event emitted by the translation pipeline.
///
/// Events are emitted at key milestones:
/// - Pipeline start / completion / failure
/// - Ghidra data fetch (function metadata, imports)
/// - Baseline test generation
/// - Each translation attempt (compile, test, LLM call)
///
/// # Example: consuming events
///
/// ```no_run
/// use calxgloss_types::{ProgressEvent, TranslationEvents};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let events = TranslationEvents::new(128);
/// let mut rx = events.subscribe();
///
/// while let Ok(event) = rx.recv().await {
///     match event {
///         ProgressEvent::TranslationAttemptCompleted {
///             attempt,
///             success,
///             tests_passed,
///             tests_total,
///             ..
///         } => {
///             println!("Attempt {attempt}: {}/{} tests", tests_passed, tests_total);
///         }
///         _ => println!("[{event}]"),
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProgressEvent {
    /// Pipeline started translating the given DLL and function.
    TranslationStarted { dll: String, function: String },
    /// GhidraMCP returned function metadata (disassembly, decompiler output).
    GhidraFetchComplete {
        dll: String,
        function: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<u64>,
        disassembly_lines: usize,
    },
    /// Windows API tagging completed.
    ApiTaggingComplete {
        dll: String,
        function: String,
        tagged_apis: usize,
    },
    /// Baseline test inputs were generated.
    TestsGenerated {
        dll: String,
        function: String,
        test_count: usize,
    },
    /// The context tier for this function was selected.
    ///
    /// Emitted after complexity analysis and before the first LLM call.
    /// The tier determines how much context the LLM receives. On retry
    /// failures the tier is escalated and this event is re-emitted with
    /// the new tier.
    ContextTierSelected {
        dll: String,
        function: String,
        tier: String,
        tier_label: String,
        /// Complexity classification that influenced the selection.
        complexity: String,
        /// Number of distinct Windows API calls.
        api_call_count: usize,
    },
    /// LLM call was sent to generate / fix code.
    LlmCallStart {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
    },
    /// LLM call completed with generated code.
    LlmCallComplete {
        dll: String,
        function: String,
        attempt: u32,
        code_length: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        tokens_used: Option<usize>,
    },
    /// The full prompt sent to the LLM (raw request body).
    LlmRequest {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// The prompt text that will be sent to the LLM.
        prompt: String,
    },
    /// The full response received from the LLM.
    LlmResponse {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// The raw text content returned by the LLM.
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tokens_used: Option<usize>,
    },
    /// A translation attempt was verified (compile + test results).
    TranslationAttemptCompleted {
        dll: String,
        function: String,
        attempt: u32,
        /// `true` if this attempt passed all tests.
        success: bool,
        /// Compilation succeeded?
        compiled: bool,
        tests_passed: usize,
        tests_total: usize,
        /// Compilation error messages (if compilation failed).
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        compilation_errors: Vec<String>,
        /// Failing test summaries (if tests failed).
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        failed_tests: Vec<String>,
        /// Which strategy produced this attempt.
        strategy: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tokens_used: Option<usize>,
    },
    /// All retry attempts exhausted without success.
    TranslationFailed {
        dll: String,
        function: String,
        total_attempts: usize,
    },
    /// Translation completed successfully after retry loop.
    TranslationCompleted {
        dll: String,
        function: String,
        total_attempts: usize,
        /// Which strategy ultimately succeeded.
        #[serde(skip_serializing_if = "Option::is_none")]
        success_strategy: Option<String>,
    },
    /// LLM call is still in progress (keepalive heartbeat).
    /// Emitted periodically to indicate the request has not hung.
    LlmCallInProgress {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// How many seconds the call has been running.
        elapsed_secs: u64,
    },
    /// LLM call failed with an error (HTTP/network failure, timeout, etc.).
    LlmCallFailed {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// The error message from the LLM client.
        error: String,
    },
    /// A DLL classification has completed.
    ClassificationComplete {
        dll: String,
        /// The assigned category.
        category: String,
        /// The strategy used.
        strategy: String,
        /// Crate replacement target (if any).
        #[serde(skip_serializing_if = "Option::is_none")]
        crate_replacement: Option<String>,
        /// Number of exported symbols.
        exported_symbols: usize,
        /// Number of imported symbols.
        imported_symbols: usize,
    },
    /// A function in a batch translation has completed (succeeded or failed).
    ///
    /// Emitted **immediately after each function completes** during batch
    /// translation, before moving on to the next function. This enables
    /// incremental git commits and real-time progress tracking per-function.
    FunctionCompleted {
        dll: String,
        function: String,
        /// Whether this function's translation ultimately succeeded.
        success: bool,
        /// Total attempts used for this function (including retries).
        attempts: usize,
        /// Git branch name assigned to this function (if git is enabled),
        /// populated by the caller after the event is emitted.
        #[serde(skip_serializing_if = "Option::is_none")]
        branch: Option<String>,
    },
    /// Batch work for a DLL has begun — the whole per-binary pass: function
    /// enumeration, analysis recovery, test generation, and translation.
    ///
    /// Batch-level (no unit key): it marks the binary as being worked on
    /// before any unit event exists, and `BatchSummary` marks the pass done.
    BatchStarted { dll: String },
    /// The live loop's ordered plan for this run — the binaries it will
    /// process, in the exact order it will process them. Emitted once
    /// before the first pass starts so the pipeline table can show the
    /// queue, not just the current binary.
    QueuePlanned { dlls: Vec<String> },
    /// A batch-level analysis pass is walking its work list — the heartbeat
    /// of the pre-translation passes (call-graph extraction, the evidence
    /// scans) that grind function-by-function before any unit event exists.
    ///
    /// `pass` names the work ("type inference", "call graph", …) — a free
    /// string, so a new evidence pass needs no new event variant. `index`
    /// and `total` are the pass's own work list; `total` 0 means the pass
    /// has no per-item granularity, and `function`/`index` stay empty.
    BatchProgress {
        dll: String,
        pass: String,
        #[serde(default)]
        function: String,
        index: usize,
        total: usize,
    },
    /// Batch translation for a DLL has completed (summary across all functions).
    BatchSummary {
        dll: String,
        /// Total functions attempted.
        total_functions: usize,
        /// Functions that succeeded.
        success_count: usize,
        /// Functions that failed.
        failure_count: usize,
        /// Total translation attempts across all functions.
        total_attempts: usize,
        /// Total tokens consumed.
        total_tokens: usize,
    },
    /// Hallucination detector found non-existent API/function references.
    ///
    /// Emitted after the LLM response is scanned and one or more hallucinated
    /// calls are detected.  The `hallucinated_apis` field lists the names of
    /// the non-existent references found.
    HallucinationDetected {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// The names of the hallucinated API/function references.
        hallucinated_apis: Vec<String>,
    },
    /// The retry loop is stuck — the same bad output repeated ≥3 times.
    ///
    /// Emitted when the infinite-loop detector fires.  The `streak` field
    /// indicates how many consecutive attempts produced the same output.
    InfiniteLoopDetected {
        dll: String,
        function: String,
        streak: usize,
        streak_start_attempt: u32,
        streak_end_attempt: u32,
        strategy: String,
    },
    /// Behavior divergence detected — baseline tests pass but edge-case
    /// tests fail.
    ///
    /// Emitted by the behavior-divergence detector when the Rust
    /// implementation passes all baseline tests but one or more
    /// edge-case tests fail. This indicates insufficient test coverage.
    BehaviorDivergenceDetected {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// Baseline tests that passed.
        baseline_passed: usize,
        baseline_total: usize,
        /// Edge-case tests that passed / total.
        edge_tests_passed: usize,
        edge_tests_total: usize,
        /// Labels of the failing edge-case tests.
        failing_edge_cases: Vec<String>,
        /// Confidence score for the divergence diagnosis (0–10).
        fault_confidence: u8,
    },
    /// The local LLM model is overloaded or has timed out.
    ///
    /// Emitted by the resource-exhaustion detector when the LLM client
    /// detects that the model process is out of memory, swapping to disk,
    /// or too many requests are queued.  The caller should queue the current
    /// work for later and optionally switch to a smaller model.
    ResourceExhaustionDetected {
        dll: String,
        function: String,
        attempt: u32,
        strategy: String,
        /// Why the model was considered exhausted.
        reason: String,
        /// How many seconds the call ran before the detector gave up.
        elapsed_secs: u64,
        /// Recommended back-off time before retrying (in seconds).
        recommended_backoff_secs: u64,
    },
}

impl ProgressEvent {
    /// The `(dll, function)` unit this event refers to, or `None` for
    /// batch-level events (`ClassificationComplete`, `BatchSummary`) that
    /// are not scoped to a single unit of work.
    pub fn unit_key(&self) -> Option<(&str, &str)> {
        match self {
            ProgressEvent::TranslationStarted { dll, function }
            | ProgressEvent::GhidraFetchComplete { dll, function, .. }
            | ProgressEvent::ApiTaggingComplete { dll, function, .. }
            | ProgressEvent::TestsGenerated { dll, function, .. }
            | ProgressEvent::ContextTierSelected { dll, function, .. }
            | ProgressEvent::LlmCallStart { dll, function, .. }
            | ProgressEvent::LlmCallComplete { dll, function, .. }
            | ProgressEvent::LlmRequest { dll, function, .. }
            | ProgressEvent::LlmResponse { dll, function, .. }
            | ProgressEvent::TranslationAttemptCompleted { dll, function, .. }
            | ProgressEvent::TranslationFailed { dll, function, .. }
            | ProgressEvent::TranslationCompleted { dll, function, .. }
            | ProgressEvent::LlmCallInProgress { dll, function, .. }
            | ProgressEvent::LlmCallFailed { dll, function, .. }
            | ProgressEvent::FunctionCompleted { dll, function, .. }
            | ProgressEvent::HallucinationDetected { dll, function, .. }
            | ProgressEvent::InfiniteLoopDetected { dll, function, .. }
            | ProgressEvent::BehaviorDivergenceDetected { dll, function, .. }
            | ProgressEvent::ResourceExhaustionDetected { dll, function, .. } => {
                Some((dll.as_str(), function.as_str()))
            }
            ProgressEvent::ClassificationComplete { .. }
            | ProgressEvent::BatchStarted { .. }
            | ProgressEvent::QueuePlanned { .. }
            | ProgressEvent::BatchProgress { .. }
            | ProgressEvent::BatchSummary { .. } => None,
        }
    }
}

impl std::fmt::Display for ProgressEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgressEvent::TranslationStarted { dll, function } => {
                write!(f, "Starting translation of {function} ({dll})")
            }
            ProgressEvent::GhidraFetchComplete { dll, function, .. } => {
                write!(f, "Fetched Ghidra data for {function} ({dll})")
            }
            ProgressEvent::ApiTaggingComplete {
                dll,
                function,
                tagged_apis,
            } => {
                write!(
                    f,
                    "Tagged {tagged_apis} Windows APIs for {function} ({dll})"
                )
            }
            ProgressEvent::TestsGenerated {
                dll,
                function,
                test_count,
            } => {
                write!(
                    f,
                    "Generated {test_count} baseline tests for {function} ({dll})"
                )
            }
            ProgressEvent::ContextTierSelected {
                dll,
                function,
                tier,
                tier_label,
                complexity,
                ..
            } => {
                write!(
                    f,
                    "Context tier selected for {function} ({dll}): {tier} ({tier_label}) — complexity={complexity}"
                )
            }
            ProgressEvent::LlmCallStart {
                dll,
                function,
                attempt,
                strategy,
            } => {
                write!(f, "LLM call #{attempt} ({strategy}) for {function} ({dll})")
            }
            ProgressEvent::LlmCallComplete {
                dll,
                function,
                attempt,
                code_length,
                ..
            } => {
                write!(
                    f,
                    "LLM returned {code_length} bytes for {function} ({dll}) attempt #{attempt}"
                )
            }
            ProgressEvent::LlmRequest {
                dll,
                function,
                attempt,
                strategy,
                ..
            } => {
                write!(
                    f,
                    "LLM prompt sent: {function} ({dll}) attempt #{attempt} [{strategy}]"
                )
            }
            ProgressEvent::LlmResponse {
                dll,
                function,
                attempt,
                strategy,
                content,
                ..
            } => {
                write!(
                    f,
                    "LLM response received: {function} ({dll}) attempt #{attempt} [{strategy}] — {} chars",
                    content.len()
                )
            }
            ProgressEvent::TranslationAttemptCompleted {
                dll,
                function,
                attempt,
                success,
                tests_passed,
                tests_total,
                compiled,
                ..
            } => {
                let status = if *success { "✓" } else { "✗" };
                let msg = format!(
                    "Attempt {attempt} {status} for {function} ({dll}) — compiled={compiled}, tests={tests_passed}/{tests_total}"
                );
                write!(f, "{msg}")
            }
            ProgressEvent::TranslationFailed {
                dll,
                function,
                total_attempts,
            } => {
                write!(
                    f,
                    "Translation failed for {function} ({dll}) after {total_attempts} attempts"
                )
            }
            ProgressEvent::TranslationCompleted {
                dll,
                function,
                total_attempts,
                ..
            } => {
                write!(
                    f,
                    "Translation completed for {function} ({dll}) in {total_attempts} attempts"
                )
            }
            ProgressEvent::LlmCallFailed {
                dll,
                function,
                attempt,
                strategy,
                error,
            } => {
                write!(
                    f,
                    "LLM call failed for {function} ({dll}) attempt #{attempt} [{strategy}]: {error}"
                )
            }
            ProgressEvent::LlmCallInProgress {
                dll,
                function,
                attempt,
                strategy,
                elapsed_secs,
            } => {
                write!(
                    f,
                    "LLM call still in progress — {function} ({dll}) attempt #{attempt} [{strategy}] ({elapsed_secs}s elapsed)"
                )
            }
            ProgressEvent::ClassificationComplete { dll, category, .. } => {
                write!(f, "Classified {dll} as {category}")
            }
            ProgressEvent::FunctionCompleted {
                dll,
                function,
                success,
                attempts,
                branch,
            } => {
                let status = if *success { "✓" } else { "✗" };
                let branch_info = branch
                    .as_deref()
                    .map(|b| format!(" [{b}]"))
                    .unwrap_or_default();
                write!(
                    f,
                    "Batch {status} for {function} ({dll}) in {attempts} attempt(s){branch_info}"
                )
            }
            ProgressEvent::BatchStarted { dll } => {
                write!(f, "Batch started for {dll}")
            }
            ProgressEvent::QueuePlanned { dlls } => {
                let noun = if dlls.len() == 1 {
                    "binary"
                } else {
                    "binaries"
                };
                write!(f, "Translation queue planned: {} {noun}", dlls.len())
            }
            ProgressEvent::BatchProgress {
                dll,
                pass,
                function,
                index,
                total,
            } => {
                if *total > 0 {
                    let item = if function.is_empty() {
                        format!("{index} of {total}")
                    } else {
                        format!("{function} ({index} of {total})")
                    };
                    write!(f, "{pass} — {item} ({dll})")
                } else {
                    write!(f, "{pass} ({dll})")
                }
            }
            ProgressEvent::BatchSummary {
                dll,
                total_functions,
                success_count,
                failure_count,
                total_attempts,
                total_tokens,
            } => {
                write!(
                    f,
                    "Batch summary for {dll}: {success_count}/{total_functions} succeeded, {failure_count} failed after {total_attempts} attempts ({total_tokens} tokens)"
                )
            }
            ProgressEvent::HallucinationDetected {
                dll,
                function,
                attempt,
                strategy,
                hallucinated_apis,
            } => {
                write!(
                    f,
                    "Hallucination detected for {function} ({dll}) attempt #{attempt} [{strategy}]: {} non-existent API(s) found",
                    hallucinated_apis.len()
                )
            }
            ProgressEvent::InfiniteLoopDetected {
                dll,
                function,
                streak,
                streak_start_attempt,
                streak_end_attempt,
                strategy,
            } => {
                write!(
                    f,
                    "Infinite loop detected for {function} ({dll}): same bad output repeated {} times (attempts #{streak_start_attempt}–#{streak_end_attempt}) [{strategy}]",
                    streak
                )
            }
            ProgressEvent::BehaviorDivergenceDetected {
                dll,
                function,
                attempt,
                strategy,
                baseline_passed,
                baseline_total,
                edge_tests_passed,
                edge_tests_total,
                failing_edge_cases,
                fault_confidence,
            } => {
                write!(
                    f,
                    "Behavior divergence detected for {function} ({dll}) attempt #{attempt} [{strategy}]: {baseline_passed}/{baseline_total} baseline tests pass, {edge_tests_passed}/{edge_tests_total} edge-case tests pass ({} failing, fault confidence {}/10)",
                    failing_edge_cases.len(),
                    fault_confidence
                )
            }
            ProgressEvent::ResourceExhaustionDetected {
                dll,
                function,
                attempt,
                strategy,
                reason,
                elapsed_secs,
                recommended_backoff_secs,
            } => {
                write!(
                    f,
                    "Resource exhaustion for {function} ({dll}) attempt #{attempt} [{strategy}]: {reason} ({elapsed_secs}s elapsed, backoff {recommended_backoff_secs}s)"
                )
            }
        }
    }
}

/// The pipeline step a unit of work is currently in.
///
/// This is the shared vocabulary for in-flight status: the web UI labels
/// each in-flight unit with its current phase, and later tracks (W2's
/// `PipelineState`, W3's analytics) consume the same records. The phase is
/// **derived from [`ProgressEvent`] variants** via
/// [`TranslationPhase::from_event`] — there is no separate phase event
/// vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranslationPhase {
    /// Fetching function metadata (disassembly, decompiler output) from Ghidra.
    GhidraFetch,
    /// Tagging Windows API calls referenced by the function.
    ApiTagging,
    /// Generating baseline tests from observed behavior.
    TestGen,
    /// Selecting (or re-selecting on escalation) the context tier.
    ContextTier,
    /// Calling the LLM to generate or fix code.
    LlmCall,
    /// Compiling the generated code.
    Compiling,
    /// Running baseline/verification tests against the compiled code.
    Testing,
    /// Awaiting human review.
    Review,
}

impl TranslationPhase {
    /// Derive the phase a unit enters when `event` is emitted.
    ///
    /// Returns `None` for events that don't move a unit into a new phase —
    /// lifecycle events (`TranslationFailed`, `FunctionCompleted`),
    /// informational events (fault detectors, `LlmCallFailed`), and
    /// batch/classification events.
    ///
    /// `ContextTierSelected` is re-emitted when the retry loop escalates the
    /// tier; it derives `ContextTier` again so the escalation is visible in
    /// the phase history.
    pub fn from_event(event: &ProgressEvent) -> Option<Self> {
        match event {
            ProgressEvent::TranslationStarted { .. } => Some(TranslationPhase::GhidraFetch),
            ProgressEvent::GhidraFetchComplete { .. } => Some(TranslationPhase::ApiTagging),
            ProgressEvent::ApiTaggingComplete { .. } => Some(TranslationPhase::TestGen),
            ProgressEvent::TestsGenerated { .. } => Some(TranslationPhase::ContextTier),
            ProgressEvent::ContextTierSelected { .. } => Some(TranslationPhase::ContextTier),
            ProgressEvent::LlmCallStart { .. }
            | ProgressEvent::LlmRequest { .. }
            | ProgressEvent::LlmCallInProgress { .. }
            | ProgressEvent::LlmResponse { .. } => Some(TranslationPhase::LlmCall),
            ProgressEvent::LlmCallComplete { .. } => Some(TranslationPhase::Compiling),
            ProgressEvent::TranslationAttemptCompleted { .. } => Some(TranslationPhase::Testing),
            ProgressEvent::TranslationCompleted { .. } => Some(TranslationPhase::Review),
            _ => None,
        }
    }
}

/// One entry in a unit's phase history: the phase entered and how many
/// seconds after the unit's translation started it was entered.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PhaseRecord {
    /// The phase the unit entered.
    pub phase: TranslationPhase,
    /// Seconds since the unit's translation started when the phase was entered.
    pub elapsed_secs: f64,
}

/// A broadcast channel for translation progress events.
///
/// Create one per translation session. Call [`Self::emit`] to publish events,
/// and [`Self::subscribe`] to create a receiver that can be passed to the
/// WebSocket server.
///
/// `TranslationEvents` is cloneable — each clone shares the same underlying
/// broadcast channel, so you can pass it to multiple pipeline instances.
#[derive(Debug, Clone)]
pub struct TranslationEvents {
    sender: broadcast::Sender<ProgressEvent>,
}

impl TranslationEvents {
    /// Create a new event emitter with the given channel capacity.
    ///
    /// The capacity determines how many events can be buffered when subscribers
    /// are slow. When the buffer fills, the oldest events are dropped.
    pub fn new(capacity: usize) -> Self {
        let (sender, _receiver) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Emit a progress event.
    ///
    /// Returns the number of subscribers that received the event. Errors
    /// (e.g. no subscribers) are silently ignored — the pipeline should
    /// keep running even when no one is listening for progress events.
    pub fn emit(&self, event: ProgressEvent) -> usize {
        self.sender.send(event).unwrap_or_default()
    }

    /// Create a new subscriber (receiver) for this event stream.
    ///
    /// Pass the receiver to the WebSocket server's broadcast task.
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressEvent> {
        self.sender.subscribe()
    }
}

/// A shared stop signal for graceful shutdown of a live run.
///
/// Set by the web server's shutdown/restart endpoints and observed by the
/// translation pipeline **at unit boundaries** — the unit in flight is
/// allowed to complete (and persist its result) before the run stops.
///
/// `StopSignal` is cloneable — each clone shares the same underlying flag,
/// so the web server and the pipeline can hold separate clones of one
/// signal.
#[derive(Debug, Clone, Default)]
pub struct StopSignal {
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl StopSignal {
    /// Create a new, not-yet-stopped signal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request the stop. Idempotent — repeated calls are harmless.
    pub fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether a stop has been requested.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phase_of(event: ProgressEvent) -> Option<TranslationPhase> {
        TranslationPhase::from_event(&event)
    }

    #[test]
    fn unit_key_scopes_unit_events_and_skips_batch_events() {
        let unit_event = ProgressEvent::LlmCallStart {
            dll: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
        };
        assert_eq!(
            unit_event.unit_key(),
            Some(("game_logic.dll", "DrawPrimitive"))
        );
        let batch_event = ProgressEvent::BatchSummary {
            dll: "game_logic.dll".into(),
            total_functions: 4,
            success_count: 3,
            failure_count: 1,
            total_attempts: 6,
            total_tokens: 1000,
        };
        assert_eq!(batch_event.unit_key(), None);
    }

    #[test]
    fn batch_started_is_batch_scoped_phaseless_and_tagged() {
        let event = ProgressEvent::BatchStarted {
            dll: "LaunchPad.exe".into(),
        };
        assert_eq!(event.unit_key(), None, "batch-level, not unit-scoped");
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a batch pass names no unit phase"
        );
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "batch_started");
        assert_eq!(json["dll"], "LaunchPad.exe");
    }

    #[test]
    fn queue_planned_is_batch_scoped_tagged_and_phaseless() {
        let event = ProgressEvent::QueuePlanned {
            dlls: vec!["LaunchPad.exe".into(), "eqmain.dll".into()],
        };
        assert_eq!(event.unit_key(), None, "batch-level, not unit-scoped");
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a queue plan names no unit phase"
        );
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "queue_planned");
        assert_eq!(json["dlls"].as_array().expect("dlls array").len(), 2);
        assert!(
            event.to_string().contains("2"),
            "display counts the queue: {event}"
        );
    }

    #[test]
    fn batch_progress_is_batch_scoped_tagged_and_phaseless() {
        let event = ProgressEvent::BatchProgress {
            dll: "LaunchPad.exe".into(),
            pass: "type inference".into(),
            function: "FUN_1929282".into(),
            index: 1,
            total: 22143,
        };
        assert_eq!(event.unit_key(), None, "batch-level, not unit-scoped");
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a batch pass names no unit phase"
        );
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "batch_progress");
        assert_eq!(json["pass"], "type inference");
        assert_eq!(json["index"], 1);
        assert_eq!(json["total"], 22143);
        let shown = event.to_string();
        assert!(
            shown.contains("type inference")
                && shown.contains("FUN_1929282")
                && shown.contains("22143"),
            "display names the pass, the item, and the position: {shown}"
        );
    }

    #[test]
    fn translation_phase_serde_round_trip() {
        let phases = [
            TranslationPhase::GhidraFetch,
            TranslationPhase::ApiTagging,
            TranslationPhase::TestGen,
            TranslationPhase::ContextTier,
            TranslationPhase::LlmCall,
            TranslationPhase::Compiling,
            TranslationPhase::Testing,
            TranslationPhase::Review,
        ];
        for phase in phases {
            let json = serde_json::to_string(&phase).expect("phase should serialize");
            let back: TranslationPhase =
                serde_json::from_str(&json).expect("phase should deserialize");
            assert_eq!(back, phase, "round trip of {phase:?}");
        }
        assert_eq!(
            serde_json::to_string(&TranslationPhase::LlmCall).expect("serialize"),
            "\"llm_call\""
        );
        assert_eq!(
            serde_json::to_string(&TranslationPhase::GhidraFetch).expect("serialize"),
            "\"ghidra_fetch\""
        );
    }

    #[test]
    fn phase_record_serde_round_trip() {
        let record = PhaseRecord {
            phase: TranslationPhase::Compiling,
            elapsed_secs: 12.5,
        };
        let json = serde_json::to_string(&record).expect("record should serialize");
        let back: PhaseRecord = serde_json::from_str(&json).expect("record should deserialize");
        assert_eq!(back, record);
    }

    #[test]
    fn translation_phase_derived_from_full_event_flow() {
        // The canonical single-unit event flow, in the order the pipeline
        // emits it (pipeline.rs: started → fetch → tagging → tests → tier →
        // llm → compile → test → completed).
        let flow = vec![
            ProgressEvent::TranslationStarted {
                dll: "d".into(),
                function: "f".into(),
            },
            ProgressEvent::GhidraFetchComplete {
                dll: "d".into(),
                function: "f".into(),
                address: None,
                disassembly_lines: 10,
            },
            ProgressEvent::ApiTaggingComplete {
                dll: "d".into(),
                function: "f".into(),
                tagged_apis: 3,
            },
            ProgressEvent::TestsGenerated {
                dll: "d".into(),
                function: "f".into(),
                test_count: 5,
            },
            ProgressEvent::ContextTierSelected {
                dll: "d".into(),
                function: "f".into(),
                tier: "T1".into(),
                tier_label: "Signature + imports".into(),
                complexity: "Medium".into(),
                api_call_count: 3,
            },
            ProgressEvent::LlmCallStart {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
            },
            ProgressEvent::LlmRequest {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                prompt: "…".into(),
            },
            ProgressEvent::LlmCallInProgress {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                elapsed_secs: 5,
            },
            ProgressEvent::LlmResponse {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                content: "fn f() {}".into(),
                tokens_used: None,
            },
            ProgressEvent::LlmCallComplete {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                code_length: 12,
                tokens_used: None,
            },
            ProgressEvent::TranslationAttemptCompleted {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                success: true,
                compiled: true,
                tests_passed: 5,
                tests_total: 5,
                compilation_errors: vec![],
                failed_tests: vec![],
                strategy: "direct".into(),
                tokens_used: None,
            },
            ProgressEvent::TranslationCompleted {
                dll: "d".into(),
                function: "f".into(),
                total_attempts: 1,
                success_strategy: Some("direct".into()),
            },
        ];
        let derived: Vec<Option<TranslationPhase>> =
            flow.iter().map(TranslationPhase::from_event).collect();
        assert_eq!(
            derived,
            vec![
                Some(TranslationPhase::GhidraFetch),
                Some(TranslationPhase::ApiTagging),
                Some(TranslationPhase::TestGen),
                Some(TranslationPhase::ContextTier),
                Some(TranslationPhase::ContextTier),
                Some(TranslationPhase::LlmCall),
                Some(TranslationPhase::LlmCall),
                Some(TranslationPhase::LlmCall),
                Some(TranslationPhase::LlmCall),
                Some(TranslationPhase::Compiling),
                Some(TranslationPhase::Testing),
                Some(TranslationPhase::Review),
            ]
        );
    }

    #[test]
    fn context_tier_selected_reemitted_on_tier_escalation() {
        // On retry failure the retry loop escalates the tier and re-emits
        // ContextTierSelected — it must derive ContextTier again so the
        // escalation is visible in the phase history.
        let first = phase_of(ProgressEvent::ContextTierSelected {
            dll: "d".into(),
            function: "f".into(),
            tier: "T1".into(),
            tier_label: "Signature + imports".into(),
            complexity: "Medium".into(),
            api_call_count: 3,
        });
        let failed = phase_of(ProgressEvent::LlmCallFailed {
            dll: "d".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "direct".into(),
            error: "context window exceeded".into(),
        });
        let escalated = phase_of(ProgressEvent::ContextTierSelected {
            dll: "d".into(),
            function: "f".into(),
            tier: "T2".into(),
            tier_label: "Signature + callees".into(),
            complexity: "Medium".into(),
            api_call_count: 3,
        });
        assert_eq!(first, Some(TranslationPhase::ContextTier));
        assert_eq!(failed, None);
        assert_eq!(escalated, Some(TranslationPhase::ContextTier));
    }

    #[test]
    fn lifecycle_and_informational_events_derive_no_phase() {
        let events = vec![
            ProgressEvent::LlmCallFailed {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                error: "timeout".into(),
            },
            ProgressEvent::TranslationFailed {
                dll: "d".into(),
                function: "f".into(),
                total_attempts: 3,
            },
            ProgressEvent::FunctionCompleted {
                dll: "d".into(),
                function: "f".into(),
                success: true,
                attempts: 1,
                branch: None,
            },
            ProgressEvent::HallucinationDetected {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                hallucinated_apis: vec!["FakeApi".into()],
            },
            ProgressEvent::InfiniteLoopDetected {
                dll: "d".into(),
                function: "f".into(),
                streak: 3,
                streak_start_attempt: 1,
                streak_end_attempt: 3,
                strategy: "direct".into(),
            },
            ProgressEvent::BehaviorDivergenceDetected {
                dll: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                baseline_passed: 5,
                baseline_total: 5,
                edge_tests_passed: 1,
                edge_tests_total: 2,
                failing_edge_cases: vec!["edge_1".into()],
                fault_confidence: 8,
            },
            ProgressEvent::ClassificationComplete {
                dll: "d".into(),
                category: "MicrosoftSdk".into(),
                strategy: "crate_replacement".into(),
                crate_replacement: None,
                exported_symbols: 1,
                imported_symbols: 2,
            },
            ProgressEvent::BatchSummary {
                dll: "d".into(),
                total_functions: 4,
                success_count: 3,
                failure_count: 1,
                total_attempts: 6,
                total_tokens: 1000,
            },
        ];
        for event in events {
            assert_eq!(
                TranslationPhase::from_event(&event),
                None,
                "{event:?} must not derive a phase"
            );
        }
    }

    /// A fresh signal is not stopped; `stop` flips it for every clone, and
    /// repeated stops are harmless.
    #[test]
    fn stop_signal_is_shared_across_clones_and_idempotent() {
        let signal = StopSignal::new();
        let clone = signal.clone();
        assert!(!signal.is_stopped());

        clone.stop();
        assert!(signal.is_stopped(), "clones share the same flag");

        signal.stop();
        assert!(signal.is_stopped(), "stop is idempotent");
    }
}

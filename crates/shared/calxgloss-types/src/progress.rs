//! Translation progress events emitted during a translation run.
//!
//! These events flow through a `broadcast` channel and can be consumed by
//! any subscriber — most commonly the WebSocket server that streams progress
//! to the web UI during live translation.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;

use crate::identity::{BinaryIdentity, UnitKey};

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
    TranslationStarted {
        binary: BinaryIdentity,
        function: String,
    },
    /// GhidraMCP returned function metadata (disassembly, decompiler output).
    GhidraFetchComplete {
        binary: BinaryIdentity,
        function: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<u64>,
        disassembly_lines: usize,
    },
    /// Windows API tagging completed.
    ApiTaggingComplete {
        binary: BinaryIdentity,
        function: String,
        tagged_apis: usize,
    },
    /// Baseline test inputs were generated.
    TestsGenerated {
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
        function: String,
        attempt: u32,
        strategy: String,
    },
    /// LLM call completed with generated code.
    LlmCallComplete {
        binary: BinaryIdentity,
        function: String,
        attempt: u32,
        code_length: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        tokens_used: Option<usize>,
    },
    /// The full prompt sent to the LLM (raw request body).
    LlmRequest {
        binary: BinaryIdentity,
        function: String,
        attempt: u32,
        strategy: String,
        /// The prompt text that will be sent to the LLM.
        prompt: String,
    },
    /// The full response received from the LLM.
    LlmResponse {
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
        function: String,
        total_attempts: usize,
    },
    /// Translation completed successfully after retry loop.
    TranslationCompleted {
        binary: BinaryIdentity,
        function: String,
        total_attempts: usize,
        /// Which strategy ultimately succeeded.
        #[serde(skip_serializing_if = "Option::is_none")]
        success_strategy: Option<String>,
    },
    /// LLM call is still in progress (keepalive heartbeat).
    /// Emitted periodically to indicate the request has not hung.
    LlmCallInProgress {
        binary: BinaryIdentity,
        function: String,
        attempt: u32,
        strategy: String,
        /// How many seconds the call has been running.
        elapsed_secs: u64,
    },
    /// LLM call failed with an error (HTTP/network failure, timeout, etc.).
    LlmCallFailed {
        binary: BinaryIdentity,
        function: String,
        attempt: u32,
        strategy: String,
        /// The error message from the LLM client.
        error: String,
    },
    /// A DLL classification has completed.
    ClassificationComplete {
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
    BatchStarted { binary: BinaryIdentity },
    /// The live loop's ordered plan for this run — the binaries it will
    /// process, in the exact order it will process them. Emitted once
    /// before the first pass starts so the pipeline table can show the
    /// queue, not just the current binary.
    QueuePlanned { binaries: Vec<String> },
    /// A batch-level analysis pass is walking its work list — the heartbeat
    /// of the pre-translation passes (call-graph extraction, the evidence
    /// scans) that grind function-by-function before any unit event exists.
    ///
    /// `pass` names the work ("type inference", "call graph", …) — a free
    /// string, so a new evidence pass needs no new event variant. `index`
    /// and `total` are the pass's own work list; `total` 0 means the pass
    /// has no per-item granularity, and `function`/`index` stay empty.
    BatchProgress {
        binary: BinaryIdentity,
        pass: String,
        #[serde(default)]
        function: String,
        index: usize,
        total: usize,
    },
    /// Batch translation for a DLL has completed (summary across all functions).
    BatchSummary {
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
        binary: BinaryIdentity,
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
    /// The pipeline's lifecycle state changed (issue #90, W2.1).
    ///
    /// Emitted by every successful [`PipelineControl`] transition — start,
    /// pause, resume, stop, complete, fail — so the WebSocket broadcast and
    /// any dashboard mirror the state machine in real time instead of
    /// inferring it from unit traffic. Batch-level: it names no unit.
    PipelineStateChanged {
        /// The state the pipeline left.
        previous: PipelineState,
        /// The state the pipeline entered.
        state: PipelineState,
    },
    /// The unit in flight was cancelled by the operator (issue #91, W2.2).
    ///
    /// Emitted by [`UnitCancellation::cancel_current`] the moment the
    /// cancellation lands, so the WebSocket broadcast and progress state
    /// reflect it immediately — the pipeline then aborts the unit at the
    /// earliest safe point and continues with the next one. The cancelled
    /// attempt is kept as a failed record; nothing is discarded.
    UnitCancelled {
        binary: BinaryIdentity,
        function: String,
    },
}

impl ProgressEvent {
    /// The [`UnitKey`] of the unit this event refers to, or `None` for
    /// batch-level events (`ClassificationComplete`, `BatchSummary`) that
    /// are not scoped to a single unit of work.
    pub fn unit_key(&self) -> Option<UnitKey> {
        match self {
            ProgressEvent::TranslationStarted { binary, function }
            | ProgressEvent::GhidraFetchComplete {
                binary, function, ..
            }
            | ProgressEvent::ApiTaggingComplete {
                binary, function, ..
            }
            | ProgressEvent::TestsGenerated {
                binary, function, ..
            }
            | ProgressEvent::ContextTierSelected {
                binary, function, ..
            }
            | ProgressEvent::LlmCallStart {
                binary, function, ..
            }
            | ProgressEvent::LlmCallComplete {
                binary, function, ..
            }
            | ProgressEvent::LlmRequest {
                binary, function, ..
            }
            | ProgressEvent::LlmResponse {
                binary, function, ..
            }
            | ProgressEvent::TranslationAttemptCompleted {
                binary, function, ..
            }
            | ProgressEvent::TranslationFailed {
                binary, function, ..
            }
            | ProgressEvent::TranslationCompleted {
                binary, function, ..
            }
            | ProgressEvent::LlmCallInProgress {
                binary, function, ..
            }
            | ProgressEvent::LlmCallFailed {
                binary, function, ..
            }
            | ProgressEvent::FunctionCompleted {
                binary, function, ..
            }
            | ProgressEvent::HallucinationDetected {
                binary, function, ..
            }
            | ProgressEvent::InfiniteLoopDetected {
                binary, function, ..
            }
            | ProgressEvent::BehaviorDivergenceDetected {
                binary, function, ..
            }
            | ProgressEvent::ResourceExhaustionDetected {
                binary, function, ..
            }
            | ProgressEvent::UnitCancelled { binary, function } => {
                Some(UnitKey::new(binary, function.as_str()))
            }
            ProgressEvent::ClassificationComplete { .. }
            | ProgressEvent::BatchStarted { .. }
            | ProgressEvent::QueuePlanned { .. }
            | ProgressEvent::BatchProgress { .. }
            | ProgressEvent::BatchSummary { .. }
            | ProgressEvent::PipelineStateChanged { .. } => None,
        }
    }
}

impl std::fmt::Display for ProgressEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProgressEvent::TranslationStarted { binary, function } => {
                write!(f, "Starting translation of {function} ({binary})")
            }
            ProgressEvent::GhidraFetchComplete {
                binary, function, ..
            } => {
                write!(f, "Fetched Ghidra data for {function} ({binary})")
            }
            ProgressEvent::ApiTaggingComplete {
                binary,
                function,
                tagged_apis,
            } => {
                write!(
                    f,
                    "Tagged {tagged_apis} Windows APIs for {function} ({binary})"
                )
            }
            ProgressEvent::TestsGenerated {
                binary,
                function,
                test_count,
            } => {
                write!(
                    f,
                    "Generated {test_count} baseline tests for {function} ({binary})"
                )
            }
            ProgressEvent::ContextTierSelected {
                binary,
                function,
                tier,
                tier_label,
                complexity,
                ..
            } => {
                write!(
                    f,
                    "Context tier selected for {function} ({binary}): {tier} ({tier_label}) — complexity={complexity}"
                )
            }
            ProgressEvent::LlmCallStart {
                binary,
                function,
                attempt,
                strategy,
            } => {
                write!(
                    f,
                    "LLM call #{attempt} ({strategy}) for {function} ({binary})"
                )
            }
            ProgressEvent::LlmCallComplete {
                binary,
                function,
                attempt,
                code_length,
                ..
            } => {
                write!(
                    f,
                    "LLM returned {code_length} bytes for {function} ({binary}) attempt #{attempt}"
                )
            }
            ProgressEvent::LlmRequest {
                binary,
                function,
                attempt,
                strategy,
                ..
            } => {
                write!(
                    f,
                    "LLM prompt sent: {function} ({binary}) attempt #{attempt} [{strategy}]"
                )
            }
            ProgressEvent::LlmResponse {
                binary,
                function,
                attempt,
                strategy,
                content,
                ..
            } => {
                write!(
                    f,
                    "LLM response received: {function} ({binary}) attempt #{attempt} [{strategy}] — {} chars",
                    content.len()
                )
            }
            ProgressEvent::TranslationAttemptCompleted {
                binary,
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
                    "Attempt {attempt} {status} for {function} ({binary}) — compiled={compiled}, tests={tests_passed}/{tests_total}"
                );
                write!(f, "{msg}")
            }
            ProgressEvent::TranslationFailed {
                binary,
                function,
                total_attempts,
            } => {
                write!(
                    f,
                    "Translation failed for {function} ({binary}) after {total_attempts} attempts"
                )
            }
            ProgressEvent::TranslationCompleted {
                binary,
                function,
                total_attempts,
                ..
            } => {
                write!(
                    f,
                    "Translation completed for {function} ({binary}) in {total_attempts} attempts"
                )
            }
            ProgressEvent::LlmCallFailed {
                binary,
                function,
                attempt,
                strategy,
                error,
            } => {
                write!(
                    f,
                    "LLM call failed for {function} ({binary}) attempt #{attempt} [{strategy}]: {error}"
                )
            }
            ProgressEvent::LlmCallInProgress {
                binary,
                function,
                attempt,
                strategy,
                elapsed_secs,
            } => {
                write!(
                    f,
                    "LLM call still in progress — {function} ({binary}) attempt #{attempt} [{strategy}] ({elapsed_secs}s elapsed)"
                )
            }
            ProgressEvent::ClassificationComplete {
                binary, category, ..
            } => {
                write!(f, "Classified {binary} as {category}")
            }
            ProgressEvent::FunctionCompleted {
                binary,
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
                    "Batch {status} for {function} ({binary}) in {attempts} attempt(s){branch_info}"
                )
            }
            ProgressEvent::BatchStarted { binary } => {
                write!(f, "Batch started for {binary}")
            }
            ProgressEvent::QueuePlanned { binaries } => {
                let noun = if binaries.len() == 1 {
                    "binary"
                } else {
                    "binaries"
                };
                write!(f, "Translation queue planned: {} {noun}", binaries.len())
            }
            ProgressEvent::BatchProgress {
                binary,
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
                    write!(f, "{pass} — {item} ({binary})")
                } else {
                    write!(f, "{pass} ({binary})")
                }
            }
            ProgressEvent::BatchSummary {
                binary,
                total_functions,
                success_count,
                failure_count,
                total_attempts,
                total_tokens,
            } => {
                write!(
                    f,
                    "Batch summary for {binary}: {success_count}/{total_functions} succeeded, {failure_count} failed after {total_attempts} attempts ({total_tokens} tokens)"
                )
            }
            ProgressEvent::HallucinationDetected {
                binary,
                function,
                attempt,
                strategy,
                hallucinated_apis,
            } => {
                write!(
                    f,
                    "Hallucination detected for {function} ({binary}) attempt #{attempt} [{strategy}]: {} non-existent API(s) found",
                    hallucinated_apis.len()
                )
            }
            ProgressEvent::InfiniteLoopDetected {
                binary,
                function,
                streak,
                streak_start_attempt,
                streak_end_attempt,
                strategy,
            } => {
                write!(
                    f,
                    "Infinite loop detected for {function} ({binary}): same bad output repeated {} times (attempts #{streak_start_attempt}–#{streak_end_attempt}) [{strategy}]",
                    streak
                )
            }
            ProgressEvent::BehaviorDivergenceDetected {
                binary,
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
                    "Behavior divergence detected for {function} ({binary}) attempt #{attempt} [{strategy}]: {baseline_passed}/{baseline_total} baseline tests pass, {edge_tests_passed}/{edge_tests_total} edge-case tests pass ({} failing, fault confidence {}/10)",
                    failing_edge_cases.len(),
                    fault_confidence
                )
            }
            ProgressEvent::ResourceExhaustionDetected {
                binary,
                function,
                attempt,
                strategy,
                reason,
                elapsed_secs,
                recommended_backoff_secs,
            } => {
                write!(
                    f,
                    "Resource exhaustion for {function} ({binary}) attempt #{attempt} [{strategy}]: {reason} ({elapsed_secs}s elapsed, backoff {recommended_backoff_secs}s)"
                )
            }
            ProgressEvent::PipelineStateChanged { previous, state } => {
                write!(f, "Pipeline state: {previous} → {state}")
            }
            ProgressEvent::UnitCancelled { binary, function } => {
                write!(f, "Cancelled in-flight unit {function} ({binary})")
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

/// The lifecycle state of a live translation run (issue #90, W2.1).
///
/// The state machine (driven only through [`PipelineControl`]):
///
/// ```text
/// Idle ──start()──> Running ──pause()──> Paused ──resume()──> Running
///                 │                      │
///                 │ stop()               │ stop()
///                 ▼                      ▼
///               Stopping ──complete()──> Complete
///                 │
///                 └───(error)──> Error
/// ```
///
/// `complete()` is also legal directly from `Running` (the run ended
/// naturally), and `fail()` from any live state. `Complete` and `Error`
/// are terminal for the *run* — `restart()` (issue #92, W2.3) begins a
/// fresh run from either, moving the machine back to `Running` inside
/// the same live process. The web server's server-status endpoint
/// mirrors this enum, so the dashboard header and the pipeline always
/// agree on what the run is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineState {
    /// No translation run has started yet.
    Idle,
    /// A run is translating (or between units of it).
    Running,
    /// A pause was requested; the run halts at the next unit boundary and
    /// waits there until resumed or stopped.
    Paused,
    /// A stop was requested; the current unit finishes, then the run halts.
    Stopping,
    /// The run finished — naturally or after a stop. Terminal.
    Complete,
    /// The run failed. Terminal.
    Error,
}

impl PipelineState {
    /// Whether the run must not start another unit at its next boundary —
    /// a stop was requested (`Stopping`) or the run has ended (`Complete`).
    /// `Paused` is deliberately *not* halted: the run parks at the
    /// boundary, waiting to resume.
    pub fn is_halted(self) -> bool {
        matches!(self, PipelineState::Stopping | PipelineState::Complete)
    }

    /// Stable numeric encoding for the control handle's atomic cell.
    fn as_code(self) -> u8 {
        match self {
            PipelineState::Idle => 0,
            PipelineState::Running => 1,
            PipelineState::Paused => 2,
            PipelineState::Stopping => 3,
            PipelineState::Complete => 4,
            PipelineState::Error => 5,
        }
    }

    /// Decode a code written by [`Self::as_code`]. Unknown codes decode to
    /// `Idle` — the cell is only ever written by `as_code`, so an unknown
    /// code can only come from memory corruption, and `Idle` fails safe
    /// (nothing in flight to disturb).
    fn from_code(code: u8) -> Self {
        match code {
            1 => PipelineState::Running,
            2 => PipelineState::Paused,
            3 => PipelineState::Stopping,
            4 => PipelineState::Complete,
            5 => PipelineState::Error,
            _ => PipelineState::Idle,
        }
    }
}

impl std::fmt::Display for PipelineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            PipelineState::Idle => "idle",
            PipelineState::Running => "running",
            PipelineState::Paused => "paused",
            PipelineState::Stopping => "stopping",
            PipelineState::Complete => "complete",
            PipelineState::Error => "error",
        };
        f.write_str(name)
    }
}

/// A lifecycle operation rejected because the pipeline's current state does
/// not allow it (e.g. pausing an already-paused pipeline). The web layer
/// turns this into a 409 rather than silently ignoring the request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("cannot {operation} a pipeline that is {current}")]
pub struct PipelineTransitionError {
    /// The lifecycle operation that was refused.
    pub operation: &'static str,
    /// The state the pipeline was in when the operation arrived.
    pub current: PipelineState,
}

/// A shared handle on the live pipeline's [`PipelineState`] (issue #90, W2.1).
///
/// Modeled on [`StopSignal`]: `Arc`-backed and cheaply cloneable, so the
/// web server and the translation pipeline hold separate clones of one
/// state machine. Transitions are atomic compare-and-set against the state
/// machine's legality table — an operation that the current state forbids
/// fails with a typed [`PipelineTransitionError`] instead of silently
/// doing nothing, so a stale dashboard button can never corrupt the run's
/// state.
///
/// When built `with_events`, every successful transition emits a
/// [`ProgressEvent::PipelineStateChanged`] on the shared event channel, so
/// the WebSocket broadcast and progress state stay the single source of
/// dashboard truth.
///
/// # Example
///
/// ```
/// use calxgloss_types::{PipelineControl, PipelineState};
///
/// let control = PipelineControl::new();
/// control.start().expect("idle -> running");
/// control.pause().expect("running -> paused");
///
/// // Pausing again is rejected, not silently ignored.
/// assert!(control.pause().is_err());
/// control.resume().expect("paused -> running");
/// assert_eq!(control.state(), PipelineState::Running);
/// ```
#[derive(Debug, Clone, Default)]
pub struct PipelineControl {
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    events: Option<TranslationEvents>,
}

impl PipelineControl {
    /// Create a new control sitting in [`PipelineState::Idle`], emitting no
    /// lifecycle events.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a [`ProgressEvent::PipelineStateChanged`] on `events` for every
    /// successful transition.
    pub fn with_events(mut self, events: TranslationEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// The state the pipeline is in right now.
    pub fn state(&self) -> PipelineState {
        PipelineState::from_code(self.state.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Idle → Running: begin the translation phase of a live session.
    pub fn start(&self) -> Result<(), PipelineTransitionError> {
        self.transition("start", &[PipelineState::Idle], PipelineState::Running)
    }

    /// Running → Paused: the pipeline observes this at the next **unit
    /// boundary** — the unit in flight is never interrupted mid-LLM-call.
    pub fn pause(&self) -> Result<(), PipelineTransitionError> {
        self.transition("pause", &[PipelineState::Running], PipelineState::Paused)
    }

    /// Paused → Running: continue exactly where the pause stopped the run.
    pub fn resume(&self) -> Result<(), PipelineTransitionError> {
        self.transition("resume", &[PipelineState::Paused], PipelineState::Running)
    }

    /// Running | Paused → Stopping: finish the current unit, clean up, then
    /// halt. The pipeline marks the halt with [`Self::complete`].
    pub fn stop(&self) -> Result<(), PipelineTransitionError> {
        self.transition(
            "stop",
            &[PipelineState::Running, PipelineState::Paused],
            PipelineState::Stopping,
        )
    }

    /// Running | Stopping → Complete: the run halted in a consistent state
    /// — naturally at the end of the queue, or after a stop.
    pub fn complete(&self) -> Result<(), PipelineTransitionError> {
        self.transition(
            "complete",
            &[PipelineState::Running, PipelineState::Stopping],
            PipelineState::Complete,
        )
    }

    /// Running | Paused | Stopping → Error: the run failed.
    pub fn fail(&self) -> Result<(), PipelineTransitionError> {
        self.transition(
            "fail",
            &[
                PipelineState::Running,
                PipelineState::Paused,
                PipelineState::Stopping,
            ],
            PipelineState::Error,
        )
    }

    /// Complete | Error → Running: begin a fresh run inside the same live
    /// process (issue #92, W2.3). The restart endpoint drives this after
    /// the previous run halted; what the fresh run covers travels on a
    /// [`RunRequestSignal`]. A run that is still live (Running, Paused,
    /// Stopping) or never started (Idle) refuses the restart — the
    /// operator stops it first, or uses `start` for a session that has
    /// not translated yet.
    pub fn restart(&self) -> Result<(), PipelineTransitionError> {
        self.transition(
            "restart",
            &[PipelineState::Complete, PipelineState::Error],
            PipelineState::Running,
        )
    }

    /// Atomically move the state machine if `current` is in `allowed`,
    /// emitting the lifecycle event on success. A racing transition makes
    /// this retry with the fresh state, so two operators clicking at once
    /// produce exactly one winner and one typed rejection.
    fn transition(
        &self,
        operation: &'static str,
        allowed: &[PipelineState],
        target: PipelineState,
    ) -> Result<(), PipelineTransitionError> {
        loop {
            let current_code = self.state.load(std::sync::atomic::Ordering::SeqCst);
            let current = PipelineState::from_code(current_code);
            if !allowed.contains(&current) {
                return Err(PipelineTransitionError { operation, current });
            }
            match self.state.compare_exchange(
                current_code,
                target.as_code(),
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => {
                    if let Some(events) = &self.events {
                        events.emit(ProgressEvent::PipelineStateChanged {
                            previous: current,
                            state: target,
                        });
                    }
                    return Ok(());
                }
                // Another transition won the race — re-read and re-decide.
                Err(_) => continue,
            }
        }
    }
}

// ============================================================
// Start & restart run requests (issue #92, W2.3)
// ============================================================

/// Which pipeline phase a start/restart request wants the run to begin
/// from (issue #92, W2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunPhase {
    /// Re-classify the selected target binaries before translating —
    /// the route when the operator wants fresh classification.
    Classify,
    /// Go straight to translation, honoring the classification records
    /// already on disk. The default: a restart re-runs the work, not the
    /// classification.
    #[default]
    Translate,
}

impl std::fmt::Display for RunPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            RunPhase::Classify => "classify",
            RunPhase::Translate => "translate",
        };
        f.write_str(name)
    }
}

/// Which target binaries a start/restart request covers (issue #92, W2.3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTarget {
    /// Every target binary the run discovers.
    #[default]
    All,
    /// Exactly one target binary, named by its identity.
    Binary(BinaryIdentity),
}

impl std::fmt::Display for RunTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunTarget::All => f.write_str("all binaries"),
            RunTarget::Binary(id) => write!(f, "{id}"),
        }
    }
}

/// Which functions of the selected binaries re-enter the queue plan
/// (issue #92, W2.3). The split is read from the workspace's own attempt
/// record (`re/analysis/token_usage.json`), so it holds across process
/// restarts — exactly what a restart needs to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunScope {
    /// Every function the enumeration finds.
    #[default]
    AllFunctions,
    /// Only functions never attempted — no token-usage entry names them.
    OnlyQueued,
    /// Only functions attempted but never translated — a token-usage
    /// entry names them and none of their attempts succeeded.
    OnlyFailed,
}

impl std::fmt::Display for RunScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            RunScope::AllFunctions => "all functions",
            RunScope::OnlyQueued => "only queued functions",
            RunScope::OnlyFailed => "only failed functions",
        };
        f.write_str(name)
    }
}

/// What the next run should cover, carried from the web server's
/// start/restart endpoints to the live loop (issue #92, W2.3). Every
/// field defaults to the plain "run everything" request the Start
/// endpoint sends, so an empty JSON body means exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PipelineRunRequest {
    /// The phase to begin the run from.
    #[serde(default)]
    pub phase: RunPhase,
    /// The target binaries the run covers.
    #[serde(default)]
    pub target: RunTarget,
    /// The function scope selector.
    #[serde(default)]
    pub scope: RunScope,
}

/// A shared request slot between the web server and the live loop
/// (issue #92, W2.3): the start/restart endpoints store the request the
/// next run should honor, and the live loop waits on it to re-run the
/// pipeline inside the same process.
///
/// Modeled on [`StopSignal`]: `Arc`-backed and cheaply cloneable, so the
/// router handlers and the pipeline loop hold separate clones of one
/// channel. The state-machine transition is driven at the endpoint
/// **before** the request is stored, so a rejected operation never
/// leaves a stale request for the loop to pick up. Each stored request
/// wakes the waiting loop exactly once; the loop takes it with its
/// [`Self::subscribe`]d receiver.
#[derive(Debug, Clone)]
pub struct RunRequestSignal {
    sender: std::sync::Arc<tokio::sync::watch::Sender<Option<PipelineRunRequest>>>,
}

impl RunRequestSignal {
    /// Create an empty signal — no run has been requested.
    pub fn new() -> Self {
        Self {
            sender: std::sync::Arc::new(tokio::sync::watch::Sender::new(None)),
        }
    }

    /// The live loop's subscription: `changed()` resolves on each stored
    /// request, and `borrow_and_update` takes it.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<PipelineRunRequest>> {
        self.sender.subscribe()
    }

    /// Store `request` as the next run's scope and wake the waiting loop.
    pub fn request(&self, request: PipelineRunRequest) {
        self.sender.send_replace(Some(request));
    }
}

impl Default for RunRequestSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// The unit a [`UnitCancellation`] currently holds in flight, and whether
/// a cancellation has landed on it.
#[derive(Debug, Clone)]
struct InFlightUnit {
    unit: UnitKey,
    cancelled: bool,
}

/// A shared handle for cancelling the unit currently in flight (issue #91,
/// W2.2).
///
/// Modeled on [`StopSignal`] and [`PipelineControl`]: `Arc`-backed and
/// cheaply cloneable, so the live pipeline and the web server hold separate
/// clones of one handle. The pipeline registers each unit it starts
/// ([`Self::begin_unit`]) and clears it at the boundary
/// ([`Self::end_unit_was_cancelled`]); the web server's cancel-current endpoint fires
/// [`Self::cancel_current`] at whatever unit is in flight. The pipeline
/// observes the cancellation with [`Self::is_cancelled_for`] and aborts the
/// unit at the earliest safe point — the run then continues with the next
/// unit, and the cancelled attempt stays recorded as a failure.
///
/// Cancelling with no unit in flight is rejected with [`NoUnitInFlight`]
/// rather than silently doing nothing, so a stale dashboard button can
/// never drive the run inconsistent. When built `with_events`, the first
/// cancellation of a unit emits [`ProgressEvent::UnitCancelled`] on the
/// shared channel the moment it lands, so the WebSocket broadcast and
/// progress state reflect it like every other lifecycle operation.
///
/// # Example
///
/// ```
/// use calxgloss_types::UnitCancellation;
///
/// let cancellation = UnitCancellation::new();
///
/// // No unit in flight yet — the request is rejected, not ignored.
/// assert!(cancellation.cancel_current().is_err());
///
/// cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
/// let cancelled = cancellation.cancel_current().expect("a unit is in flight");
/// assert_eq!(cancelled.function(), "DrawPrimitive");
/// assert!(cancellation.is_cancelled_for("game_logic.dll", "DrawPrimitive"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct UnitCancellation {
    in_flight: std::sync::Arc<std::sync::Mutex<Option<InFlightUnit>>>,
    events: Option<TranslationEvents>,
}

impl UnitCancellation {
    /// Create a new handle with no unit in flight, emitting no events.
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a [`ProgressEvent::UnitCancelled`] on `events` when a
    /// cancellation lands (once per unit — repeat cancels are idempotent).
    pub fn with_events(mut self, events: TranslationEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// Register the unit the pipeline is about to start as in flight,
    /// clearing any previous unit's cancellation.
    pub fn begin_unit(&self, binary: impl Into<BinaryIdentity>, function: impl Into<String>) {
        let unit = UnitKey::new(&binary.into(), function);
        *self.lock() = Some(InFlightUnit {
            unit,
            cancelled: false,
        });
    }

    /// Clear the in-flight registration at the unit boundary, reporting
    /// whether the unit was cancelled. This is the pipeline's race-free
    /// check when its unit finished on its own: a cancellation landing
    /// between the unit's work completing and this call still counts, so
    /// the operator's cancel is never silently lost.
    pub fn end_unit_was_cancelled(&self) -> bool {
        self.lock().take().is_some_and(|flight| flight.cancelled)
    }

    /// The unit in flight right now, if any.
    pub fn current_unit(&self) -> Option<UnitKey> {
        self.lock().as_ref().map(|flight| flight.unit.clone())
    }

    /// Whether a cancellation has landed on the named unit while it is in
    /// flight — the check the pipeline makes at its safe points.
    pub fn is_cancelled_for(
        &self,
        binary: impl Into<BinaryIdentity>,
        function: impl Into<String>,
    ) -> bool {
        let target = UnitKey::new(&binary.into(), function);
        self.lock()
            .as_ref()
            .is_some_and(|flight| flight.cancelled && flight.unit == target)
    }

    /// Cancel the unit in flight and return it. While the same unit stays
    /// in flight, repeat calls are idempotent — the lifecycle event is
    /// emitted once, by the cancellation that first lands.
    pub fn cancel_current(&self) -> Result<UnitKey, NoUnitInFlight> {
        let unit = {
            let mut slot = self.lock();
            let Some(flight) = slot.as_mut() else {
                return Err(NoUnitInFlight);
            };
            let first_cancellation = !flight.cancelled;
            flight.cancelled = true;
            let unit = flight.unit.clone();
            drop(slot);
            if first_cancellation && let Some(events) = &self.events {
                events.emit(ProgressEvent::UnitCancelled {
                    binary: unit.binary().clone(),
                    function: unit.function().to_string(),
                });
            }
            unit
        };
        Ok(unit)
    }

    /// Lock the shared slot, treating poisoning as recoverable — nothing a
    /// holder does while locked can leave the slot inconsistent.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<InFlightUnit>> {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A cancel-current request rejected because no unit is in flight (issue
/// #91, W2.2) — the run is idle, paused, or between units. The web layer
/// turns this into a 409 rather than silently ignoring the request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("no unit is in flight to cancel")]
pub struct NoUnitInFlight;

#[cfg(test)]
mod tests {
    use super::*;

    fn phase_of(event: ProgressEvent) -> Option<TranslationPhase> {
        TranslationPhase::from_event(&event)
    }

    #[test]
    fn unit_key_scopes_unit_events_and_skips_batch_events() {
        let unit_event = ProgressEvent::LlmCallStart {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
        };
        assert_eq!(
            unit_event.unit_key(),
            Some(UnitKey::new(
                &BinaryIdentity::new("game_logic.dll"),
                "DrawPrimitive"
            ))
        );
        let batch_event = ProgressEvent::BatchSummary {
            binary: "game_logic.dll".into(),
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
            binary: "LaunchPad.exe".into(),
        };
        assert_eq!(event.unit_key(), None, "batch-level, not unit-scoped");
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a batch pass names no unit phase"
        );
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "batch_started");
        assert_eq!(json["binary"], "LaunchPad.exe");
    }

    #[test]
    fn queue_planned_is_batch_scoped_tagged_and_phaseless() {
        let event = ProgressEvent::QueuePlanned {
            binaries: vec!["LaunchPad.exe".into(), "eqmain.dll".into()],
        };
        assert_eq!(event.unit_key(), None, "batch-level, not unit-scoped");
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a queue plan names no unit phase"
        );
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "queue_planned");
        assert_eq!(
            json["binaries"].as_array().expect("binaries array").len(),
            2
        );
        assert!(
            event.to_string().contains("2"),
            "display counts the queue: {event}"
        );
    }

    #[test]
    fn batch_progress_is_batch_scoped_tagged_and_phaseless() {
        let event = ProgressEvent::BatchProgress {
            binary: "LaunchPad.exe".into(),
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
                binary: "d".into(),
                function: "f".into(),
            },
            ProgressEvent::GhidraFetchComplete {
                binary: "d".into(),
                function: "f".into(),
                address: None,
                disassembly_lines: 10,
            },
            ProgressEvent::ApiTaggingComplete {
                binary: "d".into(),
                function: "f".into(),
                tagged_apis: 3,
            },
            ProgressEvent::TestsGenerated {
                binary: "d".into(),
                function: "f".into(),
                test_count: 5,
            },
            ProgressEvent::ContextTierSelected {
                binary: "d".into(),
                function: "f".into(),
                tier: "T1".into(),
                tier_label: "Signature + imports".into(),
                complexity: "Medium".into(),
                api_call_count: 3,
            },
            ProgressEvent::LlmCallStart {
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
            },
            ProgressEvent::LlmRequest {
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                prompt: "…".into(),
            },
            ProgressEvent::LlmCallInProgress {
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                elapsed_secs: 5,
            },
            ProgressEvent::LlmResponse {
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                content: "fn f() {}".into(),
                tokens_used: None,
            },
            ProgressEvent::LlmCallComplete {
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                code_length: 12,
                tokens_used: None,
            },
            ProgressEvent::TranslationAttemptCompleted {
                binary: "d".into(),
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
                binary: "d".into(),
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
            binary: "d".into(),
            function: "f".into(),
            tier: "T1".into(),
            tier_label: "Signature + imports".into(),
            complexity: "Medium".into(),
            api_call_count: 3,
        });
        let failed = phase_of(ProgressEvent::LlmCallFailed {
            binary: "d".into(),
            function: "f".into(),
            attempt: 1,
            strategy: "direct".into(),
            error: "context window exceeded".into(),
        });
        let escalated = phase_of(ProgressEvent::ContextTierSelected {
            binary: "d".into(),
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
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                error: "timeout".into(),
            },
            ProgressEvent::TranslationFailed {
                binary: "d".into(),
                function: "f".into(),
                total_attempts: 3,
            },
            ProgressEvent::FunctionCompleted {
                binary: "d".into(),
                function: "f".into(),
                success: true,
                attempts: 1,
                branch: None,
            },
            ProgressEvent::HallucinationDetected {
                binary: "d".into(),
                function: "f".into(),
                attempt: 1,
                strategy: "direct".into(),
                hallucinated_apis: vec!["FakeApi".into()],
            },
            ProgressEvent::InfiniteLoopDetected {
                binary: "d".into(),
                function: "f".into(),
                streak: 3,
                streak_start_attempt: 1,
                streak_end_attempt: 3,
                strategy: "direct".into(),
            },
            ProgressEvent::BehaviorDivergenceDetected {
                binary: "d".into(),
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
                binary: "d".into(),
                category: "MicrosoftSdk".into(),
                strategy: "crate_replacement".into(),
                crate_replacement: None,
                exported_symbols: 1,
                imported_symbols: 2,
            },
            ProgressEvent::BatchSummary {
                binary: "d".into(),
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

    // ── Pipeline lifecycle state machine (issue #90, W2.1) ──────────────

    #[test]
    fn pipeline_state_serde_round_trip() {
        for state in [
            PipelineState::Idle,
            PipelineState::Running,
            PipelineState::Paused,
            PipelineState::Stopping,
            PipelineState::Complete,
            PipelineState::Error,
        ] {
            let json = serde_json::to_value(state).expect("serializes");
            let back: PipelineState = serde_json::from_value(json.clone()).expect("deserializes");
            assert_eq!(back, state, "round trip preserves {state}");
        }
        assert_eq!(
            serde_json::to_value(PipelineState::Paused).expect("serializes"),
            "paused"
        );
    }

    #[test]
    fn pipeline_state_changed_event_serde_round_trip() {
        let event = ProgressEvent::PipelineStateChanged {
            previous: PipelineState::Running,
            state: PipelineState::Paused,
        };
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "pipeline_state_changed");
        assert_eq!(json["previous"], "running");
        assert_eq!(json["state"], "paused");
        assert!(event.unit_key().is_none(), "lifecycle events name no unit");
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a lifecycle transition derives no unit phase"
        );
        assert!(
            event.to_string().contains("paused"),
            "display shows the transition: {event}"
        );
    }

    #[test]
    fn pipeline_control_valid_transitions_succeed() {
        let control = PipelineControl::new();
        assert_eq!(control.state(), PipelineState::Idle);

        control.start().expect("idle -> running");
        control.pause().expect("running -> paused");
        control.resume().expect("paused -> running");
        control.pause().expect("running -> paused (again)");
        control.stop().expect("paused -> stopping");
        control.complete().expect("stopping -> complete");
        assert_eq!(control.state(), PipelineState::Complete);

        // A run may also complete naturally, or fail from any live state.
        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        control
            .complete()
            .expect("running -> complete (natural end)");

        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        control.stop().expect("running -> stopping");
        control.fail().expect("stopping -> error");
        assert_eq!(control.state(), PipelineState::Error);
    }

    #[test]
    fn pipeline_control_invalid_transitions_error() {
        let control = PipelineControl::new();
        // Nothing can be driven before start, and start is not re-entrant.
        assert!(control.pause().is_err(), "idle cannot be paused");
        assert!(control.resume().is_err(), "idle cannot be resumed");
        assert!(control.stop().is_err(), "idle cannot be stopped");
        control.start().expect("idle -> running");
        assert!(control.start().is_err(), "running cannot start again");
        control.pause().expect("running -> paused");
        assert!(
            control.pause().is_err(),
            "pausing an already-paused pipeline is rejected"
        );
        control.stop().expect("paused -> stopping");
        assert!(control.pause().is_err(), "stopping cannot be paused");
        assert!(control.resume().is_err(), "stopping cannot be resumed");
        control.complete().expect("stopping -> complete");
        assert!(control.start().is_err(), "complete is terminal");
        assert!(control.fail().is_err(), "complete is terminal");
    }

    #[test]
    fn pipeline_control_error_names_the_operation_and_state() {
        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        control.pause().expect("running -> paused");
        let err = control.pause().expect_err("already paused must error");
        assert_eq!(err.operation, "pause");
        assert_eq!(err.current, PipelineState::Paused);
        assert_eq!(err.to_string(), "cannot pause a pipeline that is paused");
    }

    #[test]
    fn pipeline_control_is_shared_across_clones() {
        let control = PipelineControl::new();
        let clone = control.clone();
        assert_eq!(clone.state(), PipelineState::Idle);

        clone.start().expect("idle -> running");
        assert_eq!(
            control.state(),
            PipelineState::Running,
            "clones share the state"
        );

        control.pause().expect("running -> paused");
        assert_eq!(clone.state(), PipelineState::Paused);

        assert!(
            clone.start().is_err(),
            "the clone sees the pause and rejects the start"
        );
    }

    #[test]
    fn pipeline_control_emits_state_changed_events_on_transition() {
        let events = TranslationEvents::new(16);
        let mut rx = events.subscribe();
        let control = PipelineControl::new().with_events(events);

        control.start().expect("idle -> running");
        control.pause().expect("running -> paused");

        let first = rx.try_recv().expect("start emitted");
        assert!(
            matches!(
                first,
                ProgressEvent::PipelineStateChanged {
                    previous: PipelineState::Idle,
                    state: PipelineState::Running,
                }
            ),
            "start emits idle -> running, got: {first}"
        );
        let second = rx.try_recv().expect("pause emitted");
        assert!(
            matches!(
                second,
                ProgressEvent::PipelineStateChanged {
                    previous: PipelineState::Running,
                    state: PipelineState::Paused,
                }
            ),
            "pause emits running -> paused, got: {second}"
        );

        // A rejected transition emits nothing — the stream only carries truth.
        assert!(control.pause().is_err());
        assert!(
            rx.try_recv().is_err(),
            "a rejected transition emits no event"
        );
    }

    // ── Start & restart (issue #92, W2.3) ─────────────────────────────

    #[test]
    fn pipeline_control_restart_from_terminal_states_succeeds() {
        // A stopped run restarts into a fresh one inside the same process.
        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        control.stop().expect("running -> stopping");
        control.complete().expect("stopping -> complete");
        control.restart().expect("complete -> running");
        assert_eq!(control.state(), PipelineState::Running);

        // A failed run restarts too.
        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        control.fail().expect("running -> error");
        control.restart().expect("error -> running");
        assert_eq!(control.state(), PipelineState::Running);
    }

    #[test]
    fn pipeline_control_restart_refuses_live_and_idle_states() {
        // Idle has no run to restart — that is what start is for.
        let control = PipelineControl::new();
        let err = control.restart().expect_err("idle cannot restart");
        assert_eq!(err.operation, "restart");
        assert_eq!(err.current, PipelineState::Idle);

        // A live run must be stopped before it can be restarted.
        control.start().expect("idle -> running");
        let err = control.restart().expect_err("running cannot restart");
        assert_eq!(err.current, PipelineState::Running);
        control.pause().expect("running -> paused");
        let err = control.restart().expect_err("paused cannot restart");
        assert_eq!(err.current, PipelineState::Paused);
        control.stop().expect("paused -> stopping");
        let err = control.restart().expect_err("stopping cannot restart");
        assert_eq!(err.current, PipelineState::Stopping);
    }

    #[test]
    fn run_request_serde_defaults_and_wire_shape() {
        // An empty body is the plain "run everything" request.
        let request: PipelineRunRequest = serde_json::from_str("{}").expect("empty body parses");
        assert_eq!(request, PipelineRunRequest::default());
        assert_eq!(request.phase, RunPhase::Translate);
        assert_eq!(request.target, RunTarget::All);
        assert_eq!(request.scope, RunScope::AllFunctions);

        // The full selector set round-trips in its snake_case wire shape.
        let json = serde_json::json!({
            "phase": "classify",
            "target": {"binary": "game_logic.dll"},
            "scope": "only_failed",
        });
        let request: PipelineRunRequest = serde_json::from_value(json.clone()).expect("parses");
        assert_eq!(request.phase, RunPhase::Classify);
        assert_eq!(
            request.target,
            RunTarget::Binary(BinaryIdentity::new("game_logic.dll"))
        );
        assert_eq!(request.scope, RunScope::OnlyFailed);
        assert_eq!(serde_json::to_value(&request).expect("serializes"), json);
    }

    #[test]
    fn run_request_signal_is_shared_across_clones() {
        let signal = RunRequestSignal::new();
        let mut rx = signal.subscribe();
        assert!(rx.borrow().is_none(), "a fresh signal carries no request");

        let sender = signal.clone();
        sender.request(PipelineRunRequest {
            phase: RunPhase::Translate,
            target: RunTarget::Binary(BinaryIdentity::new("game_logic.dll")),
            scope: RunScope::OnlyQueued,
        });

        assert!(
            rx.has_changed().expect("signal alive"),
            "the clone's request wakes the loop"
        );
        let taken = rx
            .borrow_and_update()
            .clone()
            .expect("the request is taken");
        assert_eq!(taken.scope, RunScope::OnlyQueued);
        assert!(
            !rx.has_changed().expect("signal alive"),
            "the taken request is consumed"
        );

        // The next request wakes it again.
        signal.request(PipelineRunRequest::default());
        assert!(
            rx.has_changed().expect("signal alive"),
            "the second request wakes the loop"
        );
        assert_eq!(
            rx.borrow_and_update().clone().expect("taken again"),
            PipelineRunRequest::default()
        );
    }

    // ── UnitCancellation (issue #91, W2.2) ────────────────────────────

    #[test]
    fn unit_cancellation_without_in_flight_unit_is_rejected() {
        let cancellation = UnitCancellation::new();
        assert_eq!(
            cancellation.cancel_current().err(),
            Some(NoUnitInFlight),
            "cancelling with nothing in flight is rejected, not ignored"
        );
        cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
        assert!(
            !cancellation.end_unit_was_cancelled(),
            "an untouched unit ends uncancelled"
        );
        assert!(
            cancellation.cancel_current().is_err(),
            "the boundary clears the registration — nothing left to cancel"
        );
        assert!(cancellation.current_unit().is_none());
    }

    #[test]
    fn unit_cancellation_end_unit_reports_a_cancelled_unit() {
        let cancellation = UnitCancellation::new();
        cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
        cancellation
            .cancel_current()
            .expect("the unit is in flight to cancel");
        assert!(
            cancellation.end_unit_was_cancelled(),
            "a cancellation that landed just as the unit finished still counts"
        );
        assert!(
            !cancellation.end_unit_was_cancelled(),
            "the boundary is cleared — a second release sees nothing"
        );
    }

    #[test]
    fn unit_cancellation_is_shared_across_clones() {
        let cancellation = UnitCancellation::new();
        let pipeline_side = cancellation.clone();

        cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
        let cancelled = pipeline_side
            .cancel_current()
            .expect("the clone sees the in-flight unit");
        assert_eq!(cancelled.to_string(), "game_logic.dll/DrawPrimitive");
        assert!(
            cancellation.is_cancelled_for("game_logic.dll", "DrawPrimitive"),
            "the pipeline side observes the cancellation the clone made"
        );
        assert!(
            !cancellation.is_cancelled_for("game_logic.dll", "UpdateScene"),
            "the cancellation is scoped to the unit that was in flight"
        );

        // Repeat cancels while the same unit is in flight are idempotent.
        pipeline_side
            .cancel_current()
            .expect("the unit is still in flight");

        // A new unit starts clean — the previous cancellation does not leak.
        cancellation.begin_unit("game_logic.dll", "UpdateScene");
        assert!(
            !cancellation.is_cancelled_for("game_logic.dll", "UpdateScene"),
            "begin_unit clears the previous unit's cancellation"
        );
    }

    #[test]
    fn unit_cancellation_emits_event_once_when_it_lands() {
        let events = TranslationEvents::new(16);
        let mut rx = events.subscribe();
        let cancellation = UnitCancellation::new().with_events(events);

        // Rejected requests emit nothing.
        assert!(cancellation.cancel_current().is_err());
        assert!(rx.try_recv().is_err(), "a rejected cancel emits no event");

        cancellation.begin_unit("game_logic.dll", "DrawPrimitive");
        cancellation.cancel_current().expect("unit in flight");
        let event = rx.try_recv().expect("the landing emits");
        assert!(
            matches!(event, ProgressEvent::UnitCancelled { .. }),
            "the cancellation emits UnitCancelled, got: {event}"
        );
        assert_eq!(
            event.unit_key().unwrap().to_string(),
            "game_logic.dll/DrawPrimitive"
        );
        assert!(
            TranslationPhase::from_event(&event).is_none(),
            "a cancellation derives no new unit phase"
        );

        // The idempotent repeat does not emit a second event.
        cancellation.cancel_current().expect("still in flight");
        assert!(
            rx.try_recv().is_err(),
            "the event is emitted once, by the cancellation that lands"
        );
    }

    #[test]
    fn unit_cancelled_event_serde_round_trip() {
        let event = ProgressEvent::UnitCancelled {
            binary: "game_logic.dll".into(),
            function: "DrawPrimitive".into(),
        };
        let json = serde_json::to_value(&event).expect("serializes");
        assert_eq!(json["event"], "unit_cancelled");
        assert_eq!(json["binary"], "game_logic.dll");
        assert_eq!(json["function"], "DrawPrimitive");
        assert!(
            event.to_string().contains("DrawPrimitive"),
            "display names the cancelled unit: {event}"
        );
    }
}

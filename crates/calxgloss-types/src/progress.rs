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
        }
    }
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

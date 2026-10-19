//! Translation pipeline — full end-to-end workflow.
//!
//! This module provides the [`TranslationPipeline`] struct, which wires together
//! all the pieces needed to translate a disassembled function to Rust:
//!
//! 1. Pull function data through the analysis seam (Kuna decompiler output)
//! 2. Tag Windows API calls with their PAL mappings
//! 3. Generate baseline test inputs from function signature and disassembly
//! 4. Build a structured prompt bundling all context
//! 5. Send the prompt to the LLM for Rust code generation
//! 6. Return the translated code along with metadata
//!
//! # Example
//!
//! ```no_run
//! use calxgloss_translator::TranslationPipeline;
//! use calxgloss_kuna::KunaSource;
//! use calxgloss_llm::LlmClient;
//! use calxgloss_pal::ApiMappings;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let kuna = KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
//! let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//! let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());
//!
//! let translation = pipeline.translate("game_logic.dll", "DrawSprite").await?;
//! println!("Translated code:\n{}", translation.rust_code);
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use calxgloss_analysis::Analyzer;
use calxgloss_analysis::FaultLogger;
use calxgloss_callback::signatures::{CallableSignature, SignatureMap};
use calxgloss_callgraph::{ContextEnricher, FunctionContext, NodeCategory};
use calxgloss_decomp::{CachedScanSource, PipelineSource, ScanSource};
use calxgloss_kuna::KunaSource;
use calxgloss_llm::{
    LlmClient, LlmMessage, context::ContextWindowDetector, hallucination::HallucinationDetector,
};
use calxgloss_pal::ApiMappings;
use calxgloss_prompts::build_translate_prompt;
use calxgloss_testgen::TestGenerator;
use calxgloss_typeinfer::error::TypeInferError;
use calxgloss_typeinfer::persist::TypeInferPersistor;
use calxgloss_typeinfer::types::{InferredType, TypeInferenceResult};
use calxgloss_types::{
    BinaryIdentity, ContextTier, Export, FunctionInfo, PipelineControl, PipelineState,
    ProgressEvent, ScopeControl, StopSignal, TestCase, TranslationEvents, TranslationRequest,
    UnitCancellation,
};
use calxgloss_verify::Verifier;
use tokio::task::JoinSet;
use tracing::{debug, info, instrument, warn};

use crate::Translation;
use crate::batch;
use crate::error::{Result, TranslatorError};
use crate::retry;
use crate::scan_job::{ScanJob, TypeInferenceLatch};

/// The pass name the scan phase's heartbeat carries: one honest
/// "n of m functions consumed" row for the whole group of eleven
/// pre-batch evidence scans, instead of one row per scan that restarts
/// with each scan (issue #239).
const SCAN_PHASE: &str = "evidence scans";

/// The scan phase's fan-out window: at most four evidence scans run at a
/// time (issue #240).
///
/// The window is not there to protect the Kuna engine — the engine stays
/// the serial resource either way, the read cache's per-key cell already
/// collapsing concurrent misses of one body into one engine request. The
/// cap exists to bound peak memory, since each running scan keeps its own
/// bodies while the shared memo holds every body only once, and to keep
/// the scan phase's single dashboard row meaningful. Four is one named
/// decision, measured (issue #241): on eqmain.dll (4,076 functions)
/// widening the window from four to eleven bought the scan phase nothing
/// (parse-only wall 56.6 s → 57.3 s) and cost it on the cold path
/// (113.9 s → 153.8 s — the extra in-flight jobs pile waiting bodies onto
/// the same listing region the engine is already chewing through), all
/// while adding a seventh of the kept decompilation copies, so four
/// stands. Widening it further stays a one-line change with the phase's
/// tests behind it —
/// `the_scan_phase_window_never_runs_more_than_the_named_cap_at_a_time`
/// pins that the phase never exceeds this constant and never degenerates
/// to one scan at a time.
const MAX_CONCURRENT_EVIDENCE_SCANS: usize = 4;

/// One evidence scan as the fan-out's unit of work: takes its owned
/// [`ScanJob`] and hands back the boxed scan future. The eleven scans'
/// futures are eleven distinct types, so the window boxes them to move
/// them onto tasks (issue #240).
type EvidenceScanTask = fn(ScanJob) -> Pin<Box<dyn Future<Output = ()> + Send>>;

// The eleven scans as task-ready async fns. Their futures are boxed at
// spawn time rather than in closure position — the compiler cannot prove
// a boxed `async` block inside a closure is `'static` (rust#100013),
// while a named async fn's future is `'static` by signature.
async fn scan_type_database(job: ScanJob) {
    job.type_database().await;
}
async fn scan_type_inference(job: ScanJob) {
    job.type_inference().await;
}
async fn scan_algorithm_recognition(job: ScanJob) {
    job.algorithm_recognition().await;
}
async fn scan_memory_detection(job: ScanJob) {
    job.memory_detection().await;
}
async fn scan_sync_detection(job: ScanJob) {
    job.sync_detection().await;
}
async fn scan_callback_detection(job: ScanJob) {
    job.callback_detection().await;
}
async fn scan_controlflow_detection(job: ScanJob) {
    job.controlflow_detection().await;
}
async fn scan_string_context(job: ScanJob) {
    job.string_context().await;
}
async fn scan_api_detection(job: ScanJob) {
    job.api_detection().await;
}
async fn scan_const_detection(job: ScanJob) {
    job.const_detection().await;
}
async fn scan_serialize_detection(job: ScanJob) {
    job.serialize_detection().await;
}

/// One evidence scan as it crosses the fan-out window: it announces itself
/// to the phase's in-flight tracker, runs, and leaves. The phase keeps the
/// high-water mark of that tracker, so the window's cap is a tested
/// contract rather than only a comment (issue #241). A named async fn
/// again, so the spawned future is `'static` (issue #240).
async fn run_scan_in_window(
    scan: EvidenceScanTask,
    job: ScanJob,
    in_flight: Arc<AtomicUsize>,
    high_water: Arc<AtomicUsize>,
) {
    let entered = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    high_water.fetch_max(entered, Ordering::SeqCst);
    scan(job).await;
    in_flight.fetch_sub(1, Ordering::SeqCst);
}

/// The eleven evidence scans in today's spawn order — type database, type
/// inference, algorithm recognition, memory, sync, callback, control
/// flow, string context, api, const, serialize. The order is only the
/// order they enter the window: the scans no longer run in a fixed order,
/// and the one real ordering edge — callback detection awaiting type
/// inference's completion latch — rides the latch itself, not this list
/// (issue #238, fan-out issue #240).
fn evidence_scan_tasks() -> Vec<EvidenceScanTask> {
    vec![
        |job| Box::pin(scan_type_database(job)),
        |job| Box::pin(scan_type_inference(job)),
        |job| Box::pin(scan_algorithm_recognition(job)),
        |job| Box::pin(scan_memory_detection(job)),
        |job| Box::pin(scan_sync_detection(job)),
        |job| Box::pin(scan_callback_detection(job)),
        |job| Box::pin(scan_controlflow_detection(job)),
        |job| Box::pin(scan_string_context(job)),
        |job| Box::pin(scan_api_detection(job)),
        |job| Box::pin(scan_const_detection(job)),
        |job| Box::pin(scan_serialize_detection(job)),
    ]
}

// ============================================================
// TranslationPipeline — full end-to-end pipeline
// ============================================================

/// Full translation pipeline: seam reads → Analysis → Tests → LLM → Rust code.
///
/// This is the main entry point for the translation workflow. It orchestrates
/// all the steps needed to translate a function from disassembly to working Rust:
///
/// 1. Fetch function metadata through the analysis seam (decompiler output)
/// 2. Tag Windows API calls with PAL mappings using the analyzer
/// 3. Generate baseline test inputs from function signature and disassembly
/// 4. Build a structured prompt bundling all context
/// 5. Send the prompt to the LLM for Rust code generation
/// 6. Return a [`Translation`] with the code and all metadata
///
/// # Construction
///
/// ```no_run
/// use calxgloss_translator::TranslationPipeline;
/// use calxgloss_kuna::KunaSource;
/// use calxgloss_llm::LlmClient;
/// use calxgloss_pal::ApiMappings;
///
/// let kuna = KunaSource::load(std::path::Path::new("target/game_logic.dll")).unwrap();
/// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").unwrap();
/// let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());
/// ```
pub struct TranslationPipeline {
    /// The loaded Kuna program every seam read goes through.
    kuna: KunaSource,

    /// Client for sending prompts to the LLM.
    llm: LlmClient,

    /// Windows API → Rust mapping table.
    api_mappings: ApiMappings,

    /// Analyzer for DLL classification and API tagging.
    analyzer: Analyzer,

    /// Built-in root-symbol patterns backing the translate-path guard: a
    /// function named explicitly that the call-graph batch path would skip
    /// (entry point, import thunk) is refused before any scan fetch or
    /// LLM spend, instead of being translated from a body that owns no
    /// logic of its own.
    root_detector: calxgloss_callgraph::RootDetector,

    /// Optional test generator for baseline test input creation.
    testgen: Option<TestGenerator>,

    /// Optional exports for signature extraction during test generation.
    exports: Vec<Export>,

    /// Optional binary name override for test generation context.
    target_binary: Option<BinaryIdentity>,

    /// Optional workspace root path for experiment logging.
    workspace: Option<std::path::PathBuf>,

    /// Optional broadcast channel for progress events.
    /// When present, events are emitted at key pipeline milestones
    /// and can be consumed by a WebSocket server for live progress.
    #[allow(dead_code)]
    events: Option<TranslationEvents>,

    /// Context-window detector for fault detection.
    /// Created once with the LLM client's `context_window` setting.
    context_detector: ContextWindowDetector,

    /// Hallucination detector for validating LLM-generated code.
    /// Created from engine symbols and PAL API catalogue; `None` when
    /// no engine source is available.
    hallucination_detector: Option<HallucinationDetector>,

    /// Persistent fault event logger.  When present, every detected fault
    /// (context-window exceeded, hallucination, infinite loop, behavior
    /// divergence, resource exhaustion) is persisted to
    /// `<workspace>/re/analysis/fault_log.json` for post-hoc analysis.
    #[allow(dead_code)]
    fault_logger: Option<FaultLogger>,

    /// When `true`, skip call-graph extraction in `fetch_function`.
    ///
    /// The call graph (caller/callee names) is used by higher context tiers
    /// (ModuleContext, FullModule) to inject neighbor information into
    /// prompts.  Setting this flag means those tiers fall back to less
    /// context rather than call-graph-derived context.
    no_callgraph: AtomicBool,

    /// When `true`, print call graph statistics after the graph is built.
    ///
    /// Useful for debugging and understanding the call graph structure before
    /// translation begins.  The summary includes function count, root/middle/leaf
    /// distribution, call-type breakdown, and external API count.
    callgraph_verbose: bool,

    /// Optional pre-built call graph.
    ///
    /// When set, [`translate`](Self::translate) reuses this graph for
    /// all enrichment and neighbor extraction instead of rebuilding it
    /// from the engine for every function.
    call_graph: Option<calxgloss_callgraph::CallGraph>,

    /// Explicit cache directory for call graph JSON files.
    ///
    /// When set, call graphs are saved to and loaded from this directory
    /// instead of the default `{workspace}/re/analysis/` path. This allows
    /// users to customize the cache location via the `--callgraph-cache` CLI flag.
    callgraph_cache_dir: Option<std::path::PathBuf>,

    /// Path to the target binary file on disk, used to build the batch's
    /// shared [`CachedScanSource`] (issue #105).
    ///
    /// The cache's validity key includes the binary's file bytes, so the
    /// pipeline needs the file itself — not just its name — to open the
    /// cache at the top of a batch. Without it (or without a workspace to
    /// file the cache under), batches read live, exactly as before the
    /// cache existed.
    binary_path: Option<std::path::PathBuf>,

    /// The batch's shared cached scan source, armed by
    /// [`begin_cached_source`](Self::begin_cached_source) at the top of a
    /// batch and read by every scan, the call-graph build, and the
    /// retry/escalation helpers through [`scan_source`](Self::scan_source).
    ///
    /// A second batch over the same workspace and unchanged binary replays
    /// from the disk tier with zero live reads.
    cached_source: Mutex<Option<CachedScanSource>>,

    /// The scan phase's type-inference completion latch, armed by
    /// [`run_prebatch_scans`](Self::run_prebatch_scans) and carried by
    /// the [`ScanJob`]s [`scan_job`](Self::scan_job) builds (issue #238).
    ///
    /// The type-inference scan publishes it whether the scan succeeds
    /// or fails; callback detection awaits it before composing its
    /// closure contracts from the type-inference document, so the one
    /// real ordering edge between the scans survives the fan-out
    /// (#240). `None` outside a scan phase — a scan asked for directly
    /// has no phase to order within.
    type_inference_latch: Mutex<Option<TypeInferenceLatch>>,

    /// The scan phase's fan-out window high-water mark: the most evidence
    /// scans that ran at once during the latest
    /// [`run_prebatch_scans`](Self::run_prebatch_scans), recorded as each
    /// scan enters the window (issue #241).
    ///
    /// The window is one named decision ([`MAX_CONCURRENT_EVIDENCE_SCANS`])
    /// and this is the test behind it: the phase reports its own high-water
    /// mark, so a test can pin that the scans never exceed the cap and never
    /// degenerate to one at a time. Reset at the start of every phase.
    scan_window_high_water: Arc<AtomicUsize>,

    /// Force the batch's scan read cache cold (issue #106).
    ///
    /// Set by the CLI's `--refresh-cache` flag. When true,
    /// [`begin_cached_source`](Self::begin_cached_source) opens the cache
    /// through [`CachedScanSource::new_refresh`]: the disk tier for the
    /// binary's current bytes is wiped before the run, every read goes
    /// live, and the cache is rewritten. The manifest keys on the
    /// binary's bytes, so a hand-edited cache is the one staleness it
    /// cannot detect — this is the escape hatch for that case.
    refresh_cache: bool,

    /// Shared stop signal for graceful shutdown of a live run.
    ///
    /// When set and stopped, the batch loops break at the next **unit
    /// boundary** — the unit in flight completes and persists before the
    /// run stops. Set by the web server's shutdown/restart endpoints.
    stop: Option<StopSignal>,

    /// Shared pipeline lifecycle control handle (issue #90, W2.1).
    ///
    /// When set, the batch loops observe it at each **unit boundary**:
    /// `Paused` parks the loop until the run is resumed, and
    /// `Stopping`/`Complete` end the batch after the unit in flight has
    /// completed and been reported to the caller (which persists it and
    /// cleans up its branch). Driven by the web control endpoints.
    pipeline_control: Option<PipelineControl>,

    /// Shared unit-cancellation handle (issue #91, W2.2).
    ///
    /// When set, each unit is registered in-flight while the batch loop
    /// works on it; the web server's cancel-current endpoint cancels
    /// whatever unit is in flight, and the loop aborts it at the earliest
    /// safe point — mid-LLM-call included — records the attempt as a
    /// failure, and continues with the next unit.
    unit_cancellation: Option<UnitCancellation>,

    /// Shared translation-scope handle (issue #93, W2.5).
    ///
    /// When set, the batch loops apply it at **queue selection**: skipped
    /// functions never enter the plan at all, and priority functions sort
    /// ahead of the rest of the queue. Its constraints bound consumption —
    /// max attempts caps the retry config, max context tier caps automatic
    /// escalation, and the token budget stops the batch at the next unit
    /// boundary once spend reaches it. Driven by the web scope endpoints.
    scope: Option<ScopeControl>,

    /// Shared per-unit reviewer-override handle (issue #96, W2.7).
    ///
    /// When set, the context builder honors it per unit: a forced tier
    /// replaces the automatic selection, a forced retry strategy replaces
    /// the configured one, and custom hints reach the unit's prompts. The
    /// batch loops also drop override-skipped units at queue selection, so
    /// one hopeless function never blocks the rest of its binary's pass.
    /// Driven by the web override endpoints.
    overrides: Option<calxgloss_types::OverrideControl>,
}

impl TranslationPipeline {
    /// Create a new translation pipeline over a loaded Kuna program and an
    /// LLM client.
    ///
    /// This sets up the full pipeline with default analyzer and empty exports/tests.
    /// A context-window detector is initialized with the LLM client's `context_window`
    /// setting for automatic fault detection.
    pub fn new(kuna: KunaSource, llm: LlmClient, api_mappings: ApiMappings) -> Self {
        let analyzer = Analyzer::new(PipelineSource::Kuna(kuna.clone()), api_mappings.clone());
        let context_detector = ContextWindowDetector::new(llm.context_window());
        Self {
            kuna,
            llm,
            api_mappings,
            analyzer,
            root_detector: calxgloss_callgraph::RootDetector::new(),
            testgen: None,
            exports: Vec::new(),
            target_binary: None,
            workspace: None,
            events: None,
            context_detector,
            hallucination_detector: None,
            fault_logger: None,
            no_callgraph: AtomicBool::new(false),
            callgraph_verbose: false,
            call_graph: None,
            callgraph_cache_dir: None,
            binary_path: None,
            cached_source: Mutex::new(None),
            type_inference_latch: Mutex::new(None),
            scan_window_high_water: Arc::new(AtomicUsize::new(0)),
            refresh_cache: false,
            stop: None,
            pipeline_control: None,
            unit_cancellation: None,
            scope: None,
            overrides: None,
        }
    }

    /// Disable call-graph extraction.
    ///
    /// When set, `fetch_function` returns an empty call graph (no caller or
    /// callee names).  This speeds up translation when call-graph-derived
    /// context is not needed.
    pub fn with_no_callgraph(self) -> Self {
        self.no_callgraph.store(true, Ordering::Relaxed);
        self
    }

    /// Enable call-graph statistics output.
    ///
    /// When set, [`translate`](Self::translate) prints a summary of call graph
    /// statistics (function count, root/middle/leaf breakdown, call-type
    /// distribution, external API count) after the graph is built.
    pub fn with_callgraph_verbose(mut self) -> Self {
        self.callgraph_verbose = true;
        self
    }

    /// Set the workspace root path for experiment logging.
    ///
    /// When set, every translation attempt is recorded to
    /// `<workspace>/re/analysis/prompt_strategy_log.json`.
    pub fn with_workspace(mut self, workspace: impl Into<std::path::PathBuf>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    /// Attach a progress event emitter for live WebSocket streaming.
    ///
    /// When set, the pipeline emits [`ProgressEvent`] instances at every
    /// major milestone. Subscribers to the channel (typically a WebSocket
    /// server) can relay these events to connected clients in real time.
    pub fn with_events(mut self, events: TranslationEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// Attach a shared stop signal for graceful shutdown of a live run.
    ///
    /// When the signal is stopped (e.g. by the web server's shutdown
    /// endpoint), the batch loops break at the next **unit boundary**: the
    /// unit in flight completes and its result is persisted before the run
    /// stops.
    pub fn with_stop_signal(mut self, stop: StopSignal) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Attach the shared [`PipelineControl`] lifecycle handle (issue #90,
    /// W2.1).
    ///
    /// The web server's pause/resume/stop endpoints drive it; the batch
    /// loops observe it at each **unit boundary** — a pause parks the loop
    /// (no unit is interrupted mid-LLM-call), a stop lets the unit in
    /// flight finish and then halts the batch.
    pub fn with_pipeline_control(mut self, control: PipelineControl) -> Self {
        self.pipeline_control = Some(control);
        self
    }

    /// Attach the shared [`UnitCancellation`] handle (issue #91, W2.2).
    ///
    /// The web server's cancel-current endpoint drives it; the batch loop
    /// registers each unit in-flight while it works on it and aborts the
    /// unit as soon as a cancellation lands — the earliest safe point is
    /// mid-LLM-call, since nothing an aborted attempt produced is
    /// persisted. The cancelled unit is recorded as a failure and the run
    /// continues with the next unit.
    pub fn with_unit_cancellation(mut self, cancellation: UnitCancellation) -> Self {
        self.unit_cancellation = Some(cancellation);
        self
    }

    /// Attach the shared [`ScopeControl`] handle (issue #93, W2.5).
    ///
    /// The web server's scope endpoints drive it; the batch loops consult
    /// it at **queue selection** — a skipped function never enters the plan,
    /// a priority function sorts ahead of the rest of the queue — and at each
    /// **unit boundary** for the per-binary pause (issue #219, part of #217):
    /// a binary the operator has paused ends its batch there rather than
    /// parking it. Its constraints bound the retry config, tier escalation,
    /// and the run's token budget.
    pub fn with_scope(mut self, scope: ScopeControl) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Attach the shared [`OverrideControl`] handle (issue #96, W2.7).
    ///
    /// The web server's override endpoints drive it; the translation context
    /// builder consults it per unit — a forced tier replaces the automatic
    /// selection, a forced retry strategy replaces the configured one, and
    /// custom hints reach the unit's prompts — while the batch loops drop
    /// override-skipped units at queue selection.
    pub fn with_overrides(mut self, overrides: calxgloss_types::OverrideControl) -> Self {
        self.overrides = Some(overrides);
        self
    }

    /// Whether an attached stop signal has been requested.
    fn stop_requested(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| s.is_stopped())
    }

    /// Observe the lifecycle control at a unit boundary (issue #90, W2.1).
    ///
    /// Returns `false` when the batch must end: `Stopping` (a stop was
    /// requested) or `Complete` (stop-current ended the run) halt after the
    /// unit in flight, and a stop signal arriving while the loop is parked
    /// in a pause releases the park the same way — shutdown must never hang
    /// on a paused run. Returns `true` when the next unit may start.
    async fn control_allows_next_unit(&self) -> bool {
        let Some(control) = self.pipeline_control.as_ref() else {
            return true;
        };
        loop {
            match control.state() {
                PipelineState::Paused => {
                    if self.stop_requested() {
                        return false;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                state if state.is_halted() => return false,
                _ => return true,
            }
        }
    }

    /// Whether the operator has paused the batch's target binary (issue #219,
    /// part of #217).
    ///
    /// Unlike a run-level pause, which parks the loop at a unit boundary until
    /// the operator resumes, a paused binary **ends** the batch at the next
    /// boundary — the batch returns rather than waits, so the run can move on
    /// to another binary. The batch loops consult this just before
    /// [`control_allows_next_unit`](Self::control_allows_next_unit), so the
    /// pause is honored at the boundary even while the run itself is parked.
    /// With no scope handle attached, no binary is ever paused.
    fn binary_paused(&self, binary: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|scope| scope.is_paused(binary))
    }

    /// Resolves once a cancellation has landed on the named unit (issue #91,
    /// W2.2). With no cancellation handle attached it never resolves, so the
    /// `select!` in the batch loop simply never takes the abort branch.
    ///
    /// The poll interval is short (50 ms) because the point of cancel-current
    /// is to stop a runaway unit burning tokens *now* — unlike pause, which
    /// only matters at unit boundaries.
    async fn wait_for_unit_cancel(&self, binary: &str, function: &str) {
        match self.unit_cancellation.as_ref() {
            None => std::future::pending::<()>().await,
            Some(cancellation) => loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if cancellation.is_cancelled_for(binary, function) {
                    break;
                }
            },
        }
    }

    /// Apply the operator's function scope and the reviewer's per-unit
    /// overrides at queue selection (issues #93, W2.5 and #96, W2.7).
    ///
    /// Skipped functions leave the plan before the first unit starts — they
    /// are never attempted — and priority functions sort ahead of the rest
    /// of the queue: the prioritized group keeps its relative order, and
    /// everything after it keeps its original order (a stable partition).
    /// A reviewer override's skip flag removes its single unit the same way,
    /// so one hopeless function never blocks the rest of its binary's pass.
    /// With neither handle attached the list passes through untouched.
    ///
    /// `name_of` extracts the function name from a queue item, so the same
    /// filtering serves plain name lists and call-graph plan entries alike.
    fn apply_function_scope<T>(
        &self,
        binary: &str,
        items: Vec<T>,
        name_of: impl Fn(&T) -> &str,
    ) -> Vec<T> {
        // W2.7: reviewer-skipped units leave the plan at the same selection
        // point as operator-skipped functions.
        let items = match self.overrides.as_ref() {
            None => items,
            Some(overrides) => {
                let total = items.len();
                let kept: Vec<T> = items
                    .into_iter()
                    .filter(|item| !overrides.is_skipped(binary, name_of(item)))
                    .collect();
                let skipped = total - kept.len();
                if skipped > 0 {
                    info!(
                        binary,
                        skipped, "Override filter — reviewer-skipped units leave the queue plan"
                    );
                }
                kept
            }
        };
        let Some(scope) = self.scope.as_ref() else {
            return items;
        };
        let plan = scope.scope();
        if plan.skipped_functions.is_empty() && plan.priority_functions.is_empty() {
            return items;
        }
        let total = items.len();
        let kept: Vec<T> = items
            .into_iter()
            .filter(|item| !plan.is_skipped(binary, name_of(item)))
            .collect();
        let skipped = total - kept.len();
        if skipped > 0 {
            info!(
                binary,
                skipped, "Scope filter — skipped functions leave the queue plan"
            );
        }
        let (mut front, rest): (Vec<T>, Vec<T>) = kept
            .into_iter()
            .partition(|item| plan.is_priority(binary, name_of(item)));
        if !front.is_empty() {
            info!(
                binary,
                prioritized = front.len(),
                "Scope filter — priority functions sort ahead of the queue"
            );
        }
        front.extend(rest);
        front
    }

    /// Bound the retry config with the operator's constraints (issue #93,
    /// W2.5).
    ///
    /// `max_attempts` can only lower the configured attempt count (a
    /// constraint caps consumption, never raises the ceiling), and
    /// `max_context_tier` rides into [`RetryLoopCtx`](retry::RetryLoopCtx)
    /// where it caps automatic tier escalation. With no scope handle
    /// attached the config passes through untouched.
    fn constrained_retry_config(&self, config: &retry::RetryConfig) -> retry::RetryConfig {
        let Some(scope) = self.scope.as_ref() else {
            return config.clone();
        };
        let constraints = scope.constraints();
        let mut capped = config.clone();
        if let Some(max) = constraints.max_attempts {
            capped.max_attempts = capped.max_attempts.min(max);
        }
        capped.max_context_tier = match (capped.max_context_tier, constraints.max_context_tier) {
            (Some(existing), Some(cap)) => Some(if existing.number() <= cap.number() {
                existing
            } else {
                cap
            }),
            (existing, cap) => existing.or(cap),
        };
        capped
    }

    /// Whether the attached scope's token budget has been reached (issue
    /// #93). No handle or no budget means never exhausted — the batch runs
    /// on. Checked at unit boundaries, like the stop signal and pause.
    fn budget_exhausted(&self) -> bool {
        self.scope.as_ref().is_some_and(|s| s.budget_exhausted())
    }

    /// Charge a completed unit's attempt tokens against the run's token
    /// budget (issue #93). Attempts that never reported a token count
    /// charge nothing.
    fn record_unit_tokens(&self, result: &batch::FunctionResult) {
        let Some(scope) = self.scope.as_ref() else {
            return;
        };
        let spent: u64 = result
            .retry_result
            .attempts
            .iter()
            .filter_map(|a| a.tokens_used)
            .map(|t| t as u64)
            .sum();
        if spent > 0 {
            scope.record_tokens(spent);
        }
    }

    /// Emit a progress event if an event emitter was attached.
    fn emit(&self, event: ProgressEvent) {
        if let Some(ref emitter) = self.events {
            let _ = emitter.emit(event);
        }
    }

    /// Set the test generator for baseline test creation.
    pub fn with_testgen(mut self, testgen: TestGenerator) -> Self {
        self.testgen = Some(testgen);
        self
    }

    /// Set exports to use for function signature extraction.
    pub fn with_exports(mut self, exports: Vec<Export>) -> Self {
        self.exports = exports;
        self
    }

    /// Set the target binary name for test generation context.
    pub fn with_target_binary(mut self, binary: impl Into<BinaryIdentity>) -> Self {
        self.target_binary = Some(binary.into());
        self
    }

    /// Attach a pre-built hallucination detector for validating LLM
    /// responses.  Call this after `new()` when a runtime context is
    /// available; skip it in unit tests that don't need detection.
    pub fn with_hallucination_detector(mut self, detector: HallucinationDetector) -> Self {
        self.hallucination_detector = Some(detector);
        self
    }

    /// Attach a fault event logger for persisting detected faults to disk.
    ///
    /// When set, every detected fault (context-window exceeded, hallucination,
    /// infinite loop, behavior divergence, resource exhaustion) is recorded to
    /// `<workspace>/re/analysis/fault_log.json`.
    pub fn with_fault_logger(mut self, logger: FaultLogger) -> Self {
        self.fault_logger = Some(logger);
        self
    }

    /// Attach a pre-built call graph for reuse across multiple translations.
    ///
    /// When set, [`translate`](Self::translate) reuses this graph instead of
    /// building one from the engine for every function call. This avoids
    /// redundant analysis and guarantees that all prompt enrichment data
    /// comes from the same graph snapshot.
    ///
    /// The graph is also used by
    /// [`batch_translate_from_callgraph`](Self::batch_translate_from_callgraph)
    /// to derive priority ordering and per-function context.
    pub fn with_call_graph(mut self, graph: calxgloss_callgraph::CallGraph) -> Self {
        self.call_graph = Some(graph);
        self
    }

    /// Set an explicit cache directory for call graph JSON files.
    ///
    /// When set, call graphs are saved to and loaded from this directory
    /// instead of the default `{workspace}/re/analysis/` path.
    pub fn with_callgraph_cache_dir(mut self, cache_dir: impl Into<std::path::PathBuf>) -> Self {
        self.callgraph_cache_dir = Some(cache_dir.into());
        self
    }

    /// Set the path to the target binary file on disk (issue #105).
    ///
    /// With a workspace also set, a batch arms a shared
    /// [`CachedScanSource`] for this binary at its top, and every scan,
    /// the call-graph build, and the retry/escalation helpers read through
    /// it — a second batch over the same workspace and unchanged binary
    /// costs no live engine reads. Without it, batches read live.
    pub fn with_binary_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Force the batch's scan read cache cold for this pipeline's batches
    /// (issue #106).
    ///
    /// The CLI's `--refresh-cache` flag sets it. Each batch then wipes the
    /// disk tier for the binary's current bytes before reading: every
    /// engine read goes live once and is written back. The manifest keys
    /// on the binary's bytes, so a hand-edited cache is the one staleness
    /// it cannot detect — this is the escape hatch for that case.
    /// Without this, warm batches replay from the cache unchanged.
    pub fn with_refresh_cache(mut self) -> Self {
        self.refresh_cache = true;
        self
    }

    /// Translate a function from the loaded program.
    ///
    /// This is the main pipeline entry point. It fetches all data from the
    /// engine, analyzes the function, generates tests, builds a prompt, and
    /// sends it to the LLM.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing the function. Recorded on the result; the
    ///   lookup is against the loaded program, which must be this DLL.
    /// * `function` — The function name to translate.
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata, or an error
    /// if any step in the pipeline fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_kuna::KunaSource;
    /// use calxgloss_llm::LlmClient;
    /// use calxgloss_pal::ApiMappings;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kuna = KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());
    ///
    /// let translation = pipeline.translate("game_logic.dll", "DrawSprite").await?;
    /// println!("Generated {} lines of Rust code", translation.rust_code.lines().count());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(binary, function))]
    pub async fn translate(&self, binary: &str, function: &str) -> Result<Translation> {
        debug!(binary, function, "Starting translation pipeline");

        // Root symbols — entry points and import thunks — own no logic to
        // translate. The call-graph batch path already skips or stubs them,
        // but an explicitly named function reaches here unchecked, and a
        // `DelayLoad_` thunk is the classic trap: its resolved-import jump
        // decompiles to an unrecovered jumptable plus a bare `return`, and
        // the LLM faithfully translates the wreckage. Refuse before the
        // scan fetch, before any token is spent.
        self.refuse_root_function(binary, function)?;

        // Emit: translation started
        self.emit(ProgressEvent::TranslationStarted {
            binary: binary.to_string().into(),
            function: function.to_string(),
        });

        // Step 1: Fetch function metadata from the engine
        let function_info = self.fetch_function(binary, function).await?;
        info!(binary, function, "Fetched function metadata");

        // Triage: Ghidra's analysis failures ride inside the pseudo-C as
        // WARNING comments. Name them before the LLM sees the body — an
        // unrecovered jump table otherwise becomes a plausible, hollow
        // `return` in the generated Rust, with nothing marking the address
        // that needs human recovery.
        self.triage_decompiler_warnings(binary, function, &function_info.decompiler_output);

        // Emit: scan fetch complete
        self.emit(ProgressEvent::ScanFetchComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            address: Some(function_info.address),
            disassembly_lines: function_info.disassembly.lines().count(),
        });

        // Step 2: Fetch imports and tag Windows APIs
        let imports = self.fetch_imports(binary).await?;
        let tagged_apis = self.tag_windows_apis(&function_info.disassembly, &imports)?;
        info!(
            binary,
            function,
            tagged_apis = tagged_apis.len(),
            "Tagged Windows APIs"
        );

        // Emit: API tagging complete
        self.emit(ProgressEvent::ApiTaggingComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            tagged_apis: tagged_apis.len(),
        });

        // Step 3: Generate baseline test inputs
        let baseline_tests = self
            .generate_baseline_tests(&function_info, &imports)
            .await?;
        info!(
            binary,
            function,
            tests = baseline_tests.len(),
            "Generated baseline tests"
        );

        // Emit: tests generated
        self.emit(ProgressEvent::TestsGenerated {
            binary: binary.to_string().into(),
            function: function.to_string(),
            test_count: baseline_tests.len(),
        });

        // Step 4: Detect function complexity and build translation request
        let complexity = self
            .analyzer
            .detect_complexity(&function_info.disassembly, &function_info.windows_apis);
        info!(
            binary,
            function,
            complexity = %complexity,
            "Detected function complexity"
        );

        // Select the context tier based on complexity and API call count.
        // Historical success rate tracking is reserved for a later integration.
        let api_call_count = tagged_apis.len();
        let auto_tier = calxgloss_types::select_context_tier(
            &complexity,
            api_call_count,
            calxgloss_types::SuccessRate::default(),
        );
        // W2.7: a reviewer override forces the tier — the automatic selector
        // is bypassed for this unit (issue #96).
        let tier = match self.forced_context_tier(binary, function) {
            Some(forced) => {
                info!(
                    binary,
                    function,
                    tier = %forced,
                    automatic = %auto_tier,
                    "Reviewer override forces the context tier"
                );
                forced
            }
            None => auto_tier,
        };
        let complexity_label = complexity.to_string();
        info!(
            binary,
            function,
            tier = %tier,
            "Selected context tier"
        );
        self.emit(ProgressEvent::ContextTierSelected {
            binary: binary.to_string().into(),
            function: function.to_string(),
            tier: tier.to_string(),
            tier_label: tier.label().to_string(),
            complexity: complexity_label,
            api_call_count,
        });

        let request = self.build_translation_request(
            binary,
            function,
            &function_info,
            tagged_apis.clone(),
            baseline_tests.clone(),
        );

        // Enrich the prompt data with call graph context when available.
        //
        // If a pre-built graph was attached via `with_call_graph`, reuse it.
        // Otherwise, build and enrich from the engine.
        let enriched_context: Vec<FunctionContext> = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
        } else if let Some(ref graph) = self.call_graph {
            if self.callgraph_verbose {
                calxgloss_analysis::print_call_graph_stats(graph);
            }
            let enricher = ContextEnricher::new();
            enricher.enrich(graph)
        } else {
            let workspace = self
                .workspace
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("."));
            let cache_dir = self.callgraph_cache_dir.as_deref();
            self.begin_scan_pass(&function_info.binary, "call graph");
            let built = calxgloss_analysis::build_enriched_call_graph(
                &self.scan_source(),
                &function_info.binary,
                workspace,
                cache_dir,
            )
            .await;
            self.end_scan_pass();
            match built {
                Ok(call_graph) => {
                    if self.callgraph_verbose {
                        calxgloss_analysis::print_call_graph_stats(&call_graph);
                    }
                    let enricher = ContextEnricher::new();
                    enricher.enrich(&call_graph)
                }
                Err(e) => {
                    warn!(
                        binary,
                        function,
                        error = %e,
                        "Failed to build call graph for context enrichment; continuing without it"
                    );
                    Vec::new()
                }
            }
        };

        // Step 5: Build a complexity-aware prompt and send to LLM
        self.emit(ProgressEvent::LlmCallStart {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
        });

        let prompt = match tier {
            ContextTier::Signature => {
                let stub_data =
                    calxgloss_prompts::SignaturePromptData::from_function_info(&function_info);
                calxgloss_prompts::build_signature_prompt(&stub_data)?
            }
            ContextTier::Disassembly => {
                let data =
                    calxgloss_prompts::DisassemblyPromptData::from_function_info(&function_info);
                calxgloss_prompts::build_disassembly_prompt(&data)?
            }
            ContextTier::WithTests => {
                let mut data = calxgloss_prompts::WithTestsPromptData::from_request(&request);
                data.call_graph_context = enriched_context.clone();
                calxgloss_prompts::build_with_tests_prompt(&data)?
            }
            ContextTier::ModuleContext => {
                let call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                let neighboring_functions = crate::retry::helpers::extract_neighboring_context(
                    &self.scan_source(),
                    &function_info.call_graph,
                )
                .await;
                let data_structures = crate::retry::helpers::extract_data_structures(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                );
                let control_flow_findings = crate::retry::helpers::extract_control_flow_hints(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                );
                let convention_findings = crate::retry::helpers::extract_convention_hints(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                );
                let data = calxgloss_prompts::ModuleContextPromptData::from_request_with_context(
                    &request,
                    call_graph_neighbors,
                    neighboring_functions,
                    data_structures,
                    enriched_context.clone(),
                    control_flow_findings,
                    convention_findings,
                );
                calxgloss_prompts::build_module_context_prompt(&data)?
            }
            ContextTier::FullModule => {
                // Tier 4: Full module context + shim layer code + PAL trait definitions
                let call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                let neighboring_functions = crate::retry::helpers::extract_neighboring_context(
                    &self.scan_source(),
                    &function_info.call_graph,
                )
                .await;
                let data_structures = crate::retry::helpers::extract_data_structures(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                );

                // Extract shim layer code from the workspace
                let shim_layers = crate::retry::helpers::extract_shim_layers(
                    self.workspace.as_deref(),
                    &function_info.binary,
                );

                // Extract PAL trait definitions from the function's Windows API categories
                let pal_traits =
                    crate::retry::helpers::extract_pal_traits(&function_info.windows_apis);

                let control_flow_findings = crate::retry::helpers::extract_control_flow_hints(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                );
                let data = calxgloss_prompts::FullModulePromptData::from_request_with_full_context(
                    &request,
                    call_graph_neighbors,
                    neighboring_functions,
                    data_structures,
                    shim_layers,
                    pal_traits,
                    enriched_context.clone(),
                    control_flow_findings,
                );
                calxgloss_prompts::build_full_module_prompt(&data)?
            }
        };

        // W2.7: the reviewer's custom hints ride into the prompt, so what
        // the reviewer knows about this function reaches the LLM (issue #96).
        let reviewer_hints = self.reviewer_hints_for(binary, function);
        let prompt = if reviewer_hints.is_empty() {
            prompt
        } else {
            info!(
                binary,
                function,
                hints = reviewer_hints.len(),
                "Reviewer override appends custom hints to the prompt"
            );
            Self::append_reviewer_hints(prompt, &reviewer_hints)
        };

        // Emit: LLM request (full prompt)
        self.emit(ProgressEvent::LlmRequest {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
            prompt: prompt.clone(),
        });

        let response = self
            .send_to_llm(
                &prompt,
                self.events.as_ref(),
                binary,
                function,
                1,
                "initial",
                function_info.disassembly.lines().count(),
            )
            .await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        // Emit: LLM response (full content)
        self.emit(ProgressEvent::LlmResponse {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            strategy: "initial".to_string(),
            content: response.content.clone(),
            tokens_used: response.tokens_used,
        });

        // Emit: LLM call complete
        self.emit(ProgressEvent::LlmCallComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            code_length: response.content.len(),
            tokens_used: response.tokens_used,
        });

        info!(
            binary,
            function,
            code_len = response.content.len(),
            model = %response.model,
            "Translation complete"
        );

        Ok(Translation {
            binary: binary.to_string().into(),
            function: function.to_string(),
            function_address: Some(function_info.address),
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests,
            call_graph: function_info.call_graph.clone(),
            call_graph_context: enriched_context,
            disassembly_hints: function_info.disassembly_hints.clone(),
            context_tier: tier,
        })
    }

    /// Translate using a pre-built [`TranslationRequest`].
    ///
    /// Skips the scan fetch and analysis steps, going straight to prompt
    /// building and LLM invocation. Useful when the request data comes from
    /// a cache or manual source.
    ///
    /// # Arguments
    ///
    /// * `request` — A pre-built [`TranslationRequest`] with all context.
    pub async fn translate_from_request(&self, request: TranslationRequest) -> Result<Translation> {
        debug!(binary = %request.binary, function = %request.function, "Translating from request");

        // Same root-symbol guard as [`translate`](Self::translate): a
        // pre-built request is not a reason to spend LLM tokens on a thunk.
        self.refuse_root_function(&request.binary, &request.function)?;

        if request.disassembly.is_empty() && request.decompiler_output.is_empty() {
            return Err(TranslatorError::MissingContext(
                "Both disassembly and decompiler output are empty".to_string(),
            ));
        }

        self.triage_decompiler_warnings(
            &request.binary,
            &request.function,
            &request.decompiler_output,
        );

        let prompt = build_translate_prompt(&request)?;
        let response = self
            .send_to_llm(
                &prompt,
                self.events.as_ref(),
                &request.binary,
                &request.function,
                1,
                "initial",
                request.disassembly.lines().count(),
            )
            .await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        info!(
            binary = %request.binary,
            function = %request.function,
            code_len = response.content.len(),
            "Translation from request complete"
        );

        Ok(Translation {
            binary: request.binary,
            function: request.function,
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
            call_graph: Vec::new(),
            call_graph_context: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: ContextTier::WithTests,
        })
    }

    /// Translate with automatic retry on verification failure.
    ///
    /// This is the main entry point for production use. It performs the full
    /// translation pipeline, verifies the result, and if verification fails
    /// it retries with escalating strategies:
    ///
    /// 1. **Initial attempt** — full pipeline, then verify
    /// 2. **Compile fix** — if compilation fails, feed errors back to LLM
    /// 3. **Test fix** — if tests fail, feed failing cases back to LLM
    /// 4. **Escalate** — add more context and retry
    ///
    /// The retry loop continues until success or `max_attempts` is reached.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing the function.
    /// * `function` — The function name to translate.
    /// * `config` — Retry configuration (default: 3 attempts, compile_fix strategy).
    /// * `verifier` — The verification engine to use for checking translations.
    ///
    /// # Returns
    ///
    /// A [`RetryResult`] containing all attempts and the final outcome.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::{TranslationPipeline, RetryConfig, RetryStrategy};
    /// use calxgloss_verify::Verifier;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kuna = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(kuna, llm, calxgloss_pal::ApiMappings::default());
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    /// let config = RetryConfig::default();
    ///
    /// let result = pipeline.try_translate_with_retry(
    ///     "game_logic.dll",
    ///     "DrawSprite",
    ///     &config,
    ///     &verifier,
    /// ).await?;
    ///
    /// if result.success {
    ///     println!("Success after {} attempts", result.attempts.len());
    ///     println!("{}", result.rust_code.as_ref().unwrap());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn try_translate_with_retry(
        &self,
        binary: &str,
        function: &str,
        config: &retry::RetryConfig,
        verifier: &Verifier,
    ) -> Result<retry::RetryResult> {
        debug!(
            binary,
            function, "Starting translation with retry (max {} attempts)", config.max_attempts
        );

        // Step 1: Initial translation via the full pipeline.
        // The futures below are boxed so that downstream crates' `Send` checks
        // stop at this boundary instead of recursively descending through the
        // whole pipeline (which overflows the compiler's trait evaluation
        // recursion limit — see rust-lang/rust#159228).
        let initial_translation: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Translation>> + Send + '_>,
        > = Box::pin(self.translate(binary, function));
        let initial = initial_translation.await?;

        info!(
            binary,
            function,
            code_len = initial.rust_code.len(),
            "Initial translation complete, beginning verification loop"
        );

        // Step 2: Run the retry loop
        let source = self.scan_source();
        // W2.5: operator constraints (max attempts, max context tier) cap the
        // retry policy before the loop runs.
        let mut bounded_config = self.constrained_retry_config(config);
        // W2.7: a reviewer override forces the retry strategy and carries its
        // custom hints into the loop's failure-informed prompts (issue #96).
        if let Some(strategy) = self.forced_retry_strategy(binary, function) {
            info!(
                binary,
                function,
                strategy = %strategy,
                configured = %config.strategy,
                "Reviewer override forces the retry strategy"
            );
            bounded_config.strategy = strategy;
        }
        let reviewer_hints = self.reviewer_hints_for(binary, function);
        let ctx = retry::RetryLoopCtx {
            verifier,
            llm: &self.llm,
            source: &source,
            config: &bounded_config,
            workspace: self.workspace.as_deref(),
            events: self.events.as_ref(),
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &reviewer_hints,
        };
        // Boxed for the same reason as above.
        let retry_loop: std::pin::Pin<
            Box<dyn std::future::Future<Output = retry::RetryResult> + Send + '_>,
        > = Box::pin(retry::try_translate_with_retry(initial, &ctx));
        let result = retry_loop.await;

        if result.success {
            self.emit(ProgressEvent::TranslationCompleted {
                binary: binary.to_string().into(),
                function: function.to_string(),
                total_attempts: result.attempts.len(),
                success_strategy: result.success_strategy.clone(),
            });
            info!(
                binary,
                function,
                attempts = result.attempts.len(),
                strategy = %result.success_strategy.as_deref().unwrap_or("unknown"),
                "Translation succeeded via retry loop"
            );
        } else {
            self.emit(ProgressEvent::TranslationFailed {
                binary: binary.to_string().into(),
                function: function.to_string(),
                total_attempts: result.attempts.len(),
            });
            warn!(
                binary,
                function,
                attempts = result.attempts.len(),
                "All retry attempts exhausted without success"
            );
        }

        // Record the final result for future tier selection tracking.
        // (Success rate tracking infrastructure will be added in a follow-up.)

        Ok(result)
    }

    /// Refuse a translate request for a function the built-in root patterns
    /// mark as skip — entry points and import thunks (`DelayLoad_*`,
    /// `_imp_*`, `thunk_*`).
    ///
    /// The matched pattern's description becomes the error's reason, so the
    /// operator learns *why* the function was refused: the thunk owns no
    /// logic, and the caller's translation reaches the real API through the
    /// PAL mappings instead. Only the `Skip` action is refused here —
    /// `GenerateStub` is a batch-path policy and a single explicit request
    /// still gets a real translation attempt.
    fn refuse_root_function(&self, binary: &str, function: &str) -> Result<()> {
        if let Some(pattern) = self.root_detector.matched_pattern(function)
            && matches!(pattern.action, calxgloss_callgraph::RootAction::Skip)
        {
            warn!(
                binary,
                function,
                pattern = pattern.description,
                "Refusing to translate a root symbol named explicitly — it owns no logic to translate"
            );
            return Err(TranslatorError::SkippedRoot {
                binary: binary.to_string(),
                function: function.to_string(),
                reason: pattern.description.to_string(),
            });
        }
        Ok(())
    }

    /// Log the decompiler warnings that change what a translation can mean.
    ///
    /// A warning is not a failure — the translation still runs — but an
    /// unrecovered jump table means the body's dispatch is missing, and the
    /// generated Rust will be hollow exactly there. Logging the address
    /// turns "the Rust is just a `return`" into a pointer at the jump to
    /// recover in the decompiler (or reconstruct from the disassembly's table).
    /// Kuna's inline slug comment names no address, so the jump is logged
    /// as an unknown site.
    fn triage_decompiler_warnings(&self, binary: &str, function: &str, decompiler_output: &str) {
        for table in crate::triage::scan_unrecovered_jump_tables(decompiler_output) {
            let address = table.address.map_or_else(
                || "unknown".to_string(),
                |address| format!("{address:#010x}"),
            );
            warn!(
                binary,
                function,
                address = %address,
                reason = %table.reason,
                "the decompiler could not recover this jump table — the indirect jump decompiles as a call; the dispatch needs human recovery before the translation can be trusted"
            );
        }
    }

    /// Fetch function metadata through the batch's scan source.
    ///
    /// The name is resolved to an address through the function listing
    /// first, and only an exact match is accepted: a substring match would
    /// silently translate a different function.
    async fn fetch_function(&self, binary: &str, function: &str) -> Result<FunctionInfo> {
        let context = |source| TranslatorError::ScanFetch {
            binary: binary.to_string(),
            function: function.to_string(),
            source: Box::new(source),
        };

        let source = self.scan_source();
        let functions = ScanSource::functions(&source).await.map_err(context)?;
        let found = functions
            .iter()
            .find(|f| f.name == function)
            .ok_or_else(|| TranslatorError::ScanFetch {
                binary: binary.to_string(),
                function: function.to_string(),
                source: Box::new(calxgloss_decomp::EngineError::NotFound {
                    kind: "function",
                    query: function.to_string(),
                }),
            })?;

        let decompiled = ScanSource::decompile(&source, function)
            .await
            .map_err(context)?;

        let call_graph = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
        } else {
            // Callers come from the cross-references to the entry; callees
            // are read out of the decompiled body and so cannot include
            // calls through a function pointer.
            let callers = ScanSource::callers(&source, found.address)
                .await
                .map_err(context)?;
            callers
                .into_iter()
                .chain(calxgloss_decomp::parse::callees_from_decompiled(
                    &decompiled.body,
                ))
                .collect()
        };

        Ok(FunctionInfo {
            name: found.name.clone(),
            address: found.address,
            binary: binary.to_string().into(),
            // Kuna's answer is the decompiler's; there is no separate
            // disassembly listing to carry.
            disassembly: String::new(),
            decompiler_output: decompiled.body,
            windows_apis: Vec::new(),
            call_graph,
            disassembly_hints: Vec::new(),
        })
    }

    /// Fetch the names of the target binary's imports.
    ///
    /// Returned as names rather than [`calxgloss_decomp::Import`] values: the
    /// engine reports an import as a name and an external slot with no module
    /// attached, so there is no module name to put in an `Import`.
    async fn fetch_imports(&self, binary: &str) -> Result<Vec<String>> {
        ScanSource::imports(&self.scan_source())
            .await
            .map(|symbols| symbols.into_iter().map(|s| s.name).collect())
            .map_err(|e| TranslatorError::ScanFetch {
                binary: binary.to_string(),
                function: "<imports>".to_string(),
                source: Box::new(e),
            })
    }

    /// Tag Windows API calls in the function's disassembly and imports.
    fn tag_windows_apis(
        &self,
        disassembly: &str,
        imports: &[String],
    ) -> Result<Vec<calxgloss_types::WindowsApiCall>> {
        // Use the analyzer's tagging logic via the analyzer we constructed
        let tagged = self
            .analyzer
            .tag_windows_apis(disassembly, imports)
            .map_err(|e| TranslatorError::TestGen(anyhow::anyhow!("API tagging failed: {e}")))?;

        // The analyzer already tags into the shared `WindowsApiCall`, so the
        // tagged list is the prompt's list — no conversion needed.
        Ok(tagged)
    }

    /// Generate baseline test inputs for a function.
    async fn generate_baseline_tests(
        &self,
        function_info: &FunctionInfo,
        _imports: &[String],
    ) -> Result<Vec<TestCase>> {
        // The signature the decompiler inferred, used to derive the
        // parameters the test cases feed in.
        let signature = self.signature_for(function_info);

        // Generate test inputs from signature and disassembly
        let tests = calxgloss_testgen::generate_test_inputs(&signature, &function_info.disassembly)
            .map_err(TranslatorError::TestGen)?;

        Ok(tests)
    }

    /// The function's C signature, as the decompiler inferred it.
    ///
    /// The reviewer's override record for a unit, if any (issue #96, W2.7).
    fn unit_override(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_types::FunctionOverride> {
        self.overrides
            .as_ref()
            .and_then(|o| o.get(binary, function))
    }

    /// The context tier a reviewer forced for this unit, if any — the
    /// context builder swaps it in for the automatic selection.
    fn forced_context_tier(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_types::ContextTier> {
        self.unit_override(binary, function)
            .and_then(|o| o.tier_override)
    }

    /// The retry strategy a reviewer forced for this unit, if any. The
    /// record's field is the shared [`calxgloss_types::RetryStrategy`]
    /// enum, so a stored value is always a real strategy — an unknown
    /// label was refused at the override boundary (issue #120) and never
    /// reached the record.
    fn forced_retry_strategy(&self, binary: &str, function: &str) -> Option<retry::RetryStrategy> {
        self.unit_override(binary, function)
            .and_then(|o| o.retry_strategy_override)
    }

    /// The reviewer's custom hints for this unit — appended to its prompts.
    fn reviewer_hints_for(&self, binary: &str, function: &str) -> Vec<String> {
        self.unit_override(binary, function)
            .map(|o| o.custom_hints)
            .unwrap_or_default()
    }

    /// Append the reviewer's custom hints to a built prompt (issue #96, W2.7).
    ///
    /// The hints ride as a clearly-marked section at the end of the prompt —
    /// the reviewer's knowledge of the function (what it really does, known
    /// quirks) that the automatic context extraction cannot produce.
    fn append_reviewer_hints(prompt: String, hints: &[String]) -> String {
        let mut out = prompt;
        out.push_str("\n\n## Reviewer hints\n\n");
        out.push_str("Additional context supplied by the human reviewer steering this run:\n");
        for hint in hints {
            out.push_str(&format!("- {hint}\n"));
        }
        out
    }

    /// The decompiler's first line is a real signature carrying real parameter
    /// types, so it is preferred. Only when that line is unusable — the
    /// decompilation failed, or the text is not pseudo-C — does this fall back
    /// to a placeholder, which yields boundary-value tests for the wrong
    /// parameter count rather than no tests at all.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn signature_for(&self, function_info: &FunctionInfo) -> String {
        if let Some(parsed) =
            calxgloss_decomp::parse::parse_decompiled(&function_info.decompiler_output)
        {
            return parsed.signature;
        }

        warn!(
            function = %function_info.name,
            "No signature in the decompiled output; falling back to a parameter-less one"
        );
        format!("int __stdcall {}()", function_info.name)
    }

    /// Build a [`TranslationRequest`] with all gathered context.
    pub(crate) fn build_translation_request(
        &self,
        binary: &str,
        function: &str,
        function_info: &FunctionInfo,
        tagged_apis: Vec<calxgloss_types::WindowsApiCall>,
        baseline_tests: Vec<TestCase>,
    ) -> TranslationRequest {
        TranslationRequest {
            binary: binary.to_string().into(),
            function: function.to_string(),
            disassembly: function_info.disassembly.trim().to_string(),
            decompiler_output: function_info.decompiler_output.trim().to_string(),
            windows_apis: tagged_apis,
            baseline_tests,
        }
    }

    /// Generate a stub implementation for a root function.
    ///
    /// Root functions include entry points (e.g., `main`, `WinMain`,
    /// `DllMain`) and runtime library initializers. These are not
    /// translated via the LLM; instead, a minimal stub is generated
    /// from the function's name and signature to serve as a placeholder
    /// that can be compiled and linked.
    ///
    /// # Arguments
    ///
    /// * `name` — The function name (e.g., `mainCRTStartup`, `WinMain`).
    /// * `signature` — The inferred C signature from the decompiler.
    ///
    /// # Returns
    ///
    /// A string containing a minimal stub implementation. For well-known
    /// entry points, a meaningful stub is generated. For unknown root
    /// functions, a generic placeholder is returned.
    pub fn generate_stub(&self, name: &str, signature: &str) -> String {
        // Handle common entry point patterns
        let stub = match name {
            // C/C++ entry points — return 0
            "main" | "wmain" | "_main" | "WinMain" | "WinMain@16" | "WinMain@20" | "wWinMain"
            | "wWinMain@16" | "wWinMain@20" | "mainCRTStartup" | "__mainCRTStartup"
            | "_mainCRTStartup" => {
                format!(
                    "/// Entry point stub for `{name}`.\npub fn {name}() {{\n    std::process::exit(0);\n}}"
                )
            }
            // DLL entry points
            "DllMain" | "DllMain@16" | "DllMainCRTStartup" | "__DllMainCRTStartup" => {
                format!(
                    "/// DLL entry point stub for `{name}`.\npub fn {name}() {{\n    // DLL initialization\n}}"
                )
            }
            // Ghidra auto-generated entry
            "entry" => {
                "/// Entry point stub.\npub fn entry() {\n    std::process::exit(0);\n}".to_string()
            }
            // VB6 initialization
            name if name.starts_with("__vba") => {
                format!(
                    "/// VB6 runtime initialization stub for `{name}`.\npub fn {name}() {{\n    // VB6 runtime init\n}}"
                )
            }
            // .NET CLR entry
            "__managed_main" | "_CorExeMain" | "_CorDllMain" => {
                format!(
                    "/// .NET CLR entry stub for `{name}`.\npub fn {name}() {{\n    // CLR host initialization\n}}"
                )
            }
            // MinGW entry
            "_start" | "__libc_start_main" => {
                format!(
                    "/// MinGW entry stub for `{name}`.\npub fn {name}() {{\n    std::process::exit(0);\n}}"
                )
            }
            // MSVC debug runtime
            name if name.starts_with("_RTC_") => {
                format!(
                    "/// MSVC runtime check stub for `{name}`.\npub fn {name}() {{\n    // Runtime check\n}}"
                )
            }
            // Generic entry point — use the signature to infer a stub
            _ => {
                // Try to extract a return type and parameters from the signature
                let safe_name = if name.starts_with("FUN_") {
                    // Ghidra auto-generated name — keep as-is
                    name.to_string()
                } else {
                    name.to_string()
                };
                format!(
                    "/// Auto-generated stub for `{safe_name}`.\npub fn {safe_name}() {{\n    // TODO: Translate\n}}"
                )
            }
        };

        // Include the signature as a comment for reference
        format!("{stub}\n// Signature: {signature}")
    }

    /// Send a prompt to the LLM and extract the Rust code response.
    ///
    /// If `events` is provided, emits `LlmCallInProgress` keepalive events
    /// every 30 seconds while the request is in flight.
    ///
    /// After receiving a response, the context-window detector checks whether
    /// the output exceeds (or nears) the model's configured limit.  If a fault
    /// is detected it is logged via `tracing::warn!` so the caller can act
    /// on it (e.g., by splitting the function and retrying).
    ///
    /// # Arguments
    ///
    /// * `disassembly_lines` — The number of lines in the function's
    ///   disassembly, used to compute a suggested chunk count for the retry
    ///   splitter when a context-window fault is detected.
    #[allow(clippy::too_many_arguments)]
    async fn send_to_llm(
        &self,
        prompt: &str,
        events: Option<&TranslationEvents>,
        binary: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        disassembly_lines: usize,
    ) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];

        // Pre-check: is the prompt itself too large for the model's context?
        if let Some(fault) = self.context_detector.detect_prompt_too_large(&messages) {
            warn!(
                binary,
                function,
                attempt,
                strategy,
                prompt_size = fault.response_size,
                limit = fault.limit,
                "Prompt exceeds model context limit — splitting function",
            );
            // We still proceed with the call; the LLM server will handle
            // truncation. The post-response check catches the actual output.
        }

        let response = if let Some(em) = events {
            let em = em.clone();
            let em_err = em.clone();
            let dll_s = binary.to_string();
            let function_s = function.to_string();
            let strategy_s = strategy.to_string();

            // Clone values before moving into the keepalive closure
            let dll_kp = dll_s.clone();
            let function_kp = function_s.clone();
            let strategy_kp = strategy_s.clone();

            // Spawn a keepalive task that emits progress events every 30s
            let keepalive_handle = tokio::task::spawn(async move {
                let interval = std::time::Duration::from_secs(30);
                let mut elapsed = interval;
                loop {
                    tokio::time::sleep(interval).await;
                    let secs = elapsed.as_secs();
                    let _ = em.emit(ProgressEvent::LlmCallInProgress {
                        binary: dll_kp.clone().into(),
                        function: function_kp.clone(),
                        attempt,
                        strategy: strategy_kp.clone(),
                        elapsed_secs: secs,
                    });
                    elapsed += interval;
                }
            });

            let result = self.llm.complete(&messages).await;
            keepalive_handle.abort();

            match &result {
                Ok(_) => {}
                Err(e) => {
                    let _ = em_err.emit(ProgressEvent::LlmCallFailed {
                        binary: dll_s.clone().into(),
                        function: function_s.clone(),
                        attempt,
                        strategy: strategy_s.clone(),
                        error: e.to_string(),
                    });
                }
            }

            result
        } else {
            self.llm.complete(&messages).await
        }?;

        // Post-check: detect context-window exceeded faults.
        if let Some(fault) = self
            .context_detector
            .detect_response(&response, disassembly_lines)
        {
            warn!(
                binary,
                function,
                attempt,
                strategy,
                response_size = fault.response_size,
                limit = fault.limit,
                overflow = fault.overflow_chars,
                "Context window exceeded — function should be split into {} chunks",
                fault.suggested_chunk_count(),
            );
            if let Some(logger) = &self.fault_logger {
                let event = calxgloss_types::FaultEvent::context_window_exceeded(
                    binary, function, attempt, strategy, &fault,
                );
                logger.record(event);
            }
        }

        // Hallucination detection: scan the generated code for non-existent
        // API/function references.  When hallucinations are found, log a
        // warning and emit a progress event so the caller can react.  Also
        // persist a fault event for post-hoc analysis.
        let hallucinations = self
            .hallucination_detector
            .as_ref()
            .map(|d| d.detect(&response.content))
            .unwrap_or_default();
        if !hallucinations.is_empty() {
            let names: Vec<String> = hallucinations.iter().map(|h| h.name.clone()).collect();
            warn!(
                binary,
                function,
                attempt,
                strategy,
                count = names.len(),
                apis = ?names,
                "Hallucinated API/function references detected",
            );
            if let Some(em) = events {
                let _ = em.emit(ProgressEvent::HallucinationDetected {
                    binary: binary.to_string().into(),
                    function: function.to_string(),
                    attempt,
                    strategy: strategy.to_string(),
                    hallucinated_apis: names.clone(),
                });
            }
            if let Some(logger) = &self.fault_logger {
                let names_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
                let event = calxgloss_types::FaultEvent::hallucination(
                    binary,
                    function,
                    attempt,
                    strategy,
                    &names_refs,
                );
                logger.record(event);
            }
        }

        debug!(
            code_len = response.content.len(),
            model = %self.llm.model(),
            "Received LLM response"
        );

        Ok(response)
    }

    /// Get a reference to the loaded Kuna program behind the seam.
    pub fn kuna(&self) -> &KunaSource {
        &self.kuna
    }

    /// Get a reference to the underlying LLM client.
    pub fn llm(&self) -> &LlmClient {
        &self.llm
    }

    /// Get a reference to the API mappings.
    pub fn api_mappings(&self) -> &ApiMappings {
        &self.api_mappings
    }

    // =========================================================
    // Batch translation
    // =========================================================

    /// Arm the batch's shared read cache over Kuna for `binary` (issue #105).
    ///
    /// Called at the top of both batch entry points. With a workspace and a
    /// `binary_path` set, this builds one [`CachedScanSource`] for the
    /// target binary — the binary's file bytes are hashed once — and every
    /// later read made through [`scan_source`](Self::scan_source) resolves
    /// memo → disk → engine, writing through as it goes.
    ///
    /// Degrades rather than fails: without a workspace or binary path the
    /// batch simply reads straight from the engine (the pre-cache
    /// behaviour), and an unreadable binary file leaves the cache in
    /// pass-through mode too.
    async fn begin_cached_source(&self, binary: &str) {
        let (Some(workspace), Some(binary_path)) =
            (self.workspace.as_deref(), self.binary_path.as_deref())
        else {
            return;
        };

        let opened = if self.refresh_cache {
            CachedScanSource::new_refresh(self.kuna.clone(), workspace, binary, binary_path)
        } else {
            CachedScanSource::new(self.kuna.clone(), workspace, binary, binary_path)
        };
        match opened {
            Ok(source) => {
                debug!(
                    binary,
                    refresh = self.refresh_cache,
                    cache_dir = source
                        .cache_dir()
                        .map_or_else(|| "(memo only)".to_string(), |d| d.display().to_string()),
                    "Batch engine reads will go through the shared cache"
                );
                *self
                    .cached_source
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(source);
            }
            Err(e) => {
                warn!(
                    binary,
                    error = %e,
                    "Could not open the batch read cache — reads will pass through to the engine"
                );
            }
        }
    }

    /// The read source every batch consumer — the [`ScanJob`]s the eleven
    /// `ensure_*` scans build, the call-graph build, and the
    /// retry/escalation helpers — pulls program facts through: the batch's
    /// [`CachedScanSource`] once armed by
    /// [`begin_cached_source`](Self::begin_cached_source), the loaded
    /// Kuna program otherwise.
    fn scan_source(&self) -> PipelineSource {
        let guard = self
            .cached_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match guard.as_ref() {
            Some(cache) => PipelineSource::Cached(cache.clone()),
            None => PipelineSource::Kuna(self.kuna.clone()),
        }
    }

    /// Arm the engine's heartbeat for one analysis pass so the
    /// dashboard can show which function the pass is on. Without an event
    /// channel there is nothing to beat to — the scan runs unchanged.
    fn begin_scan_pass(&self, binary: &str, pass: &str) {
        if let Some(ref ev) = self.events {
            self.kuna.begin_pass(binary, pass, ev);
        }
    }

    /// Disarm the heartbeat — the pass is done.
    fn end_scan_pass(&self) {
        self.kuna.end_pass();
    }

    /// Build the owned handle one evidence scan runs as (issue #237):
    /// clones of everything the scan reads — the workspace, the batch's
    /// shared read source as currently armed, and the scan phase's
    /// type-inference completion latch when one is armed (issue
    /// #238) — so the scan borrows nothing from the batch and a caller
    /// can move the job onto a task. `None` when no workspace is
    /// configured, which is every scan's skip condition. The pass
    /// heartbeat is the phase's, not the job's (issue #239).
    fn scan_job(&self, binary: &str) -> Option<ScanJob> {
        let workspace = self.workspace.as_deref()?;
        let type_inference = self
            .type_inference_latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Some(ScanJob::new(
            binary,
            workspace,
            self.scan_source(),
            type_inference,
        ))
    }

    /// Arm a fresh type-inference completion latch for one scan phase
    /// (issue #238). The type-inference scan publishes it on every
    /// exit, success or failure; callback detection awaits it before
    /// composing its closure contracts. A new phase replaces a stale
    /// latch, exactly as [`begin_cached_source`](Self::begin_cached_source)
    /// re-arms the read cache per batch.
    fn arm_type_inference_latch(&self) {
        *self
            .type_inference_latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(TypeInferenceLatch::new());
    }

    /// Run the eleven pre-batch evidence scans, the shared scan-phase
    /// preamble both batch entry points drive — the function-list path
    /// ([`batch_translate`](Self::batch_translate)) and the call-graph path
    /// ([`batch_translate_from_callgraph`](Self::batch_translate_from_callgraph))
    /// — so neither keeps its own copy of the sequence and the CLI and web
    /// paths cannot drift apart (issue #234).
    ///
    /// The scans run concurrently on a [`JoinSet`] with a window of
    /// [`MAX_CONCURRENT_EVIDENCE_SCANS`] at a time, each on its own owned
    /// [`ScanJob`] (issues #237, #240): the engine thread is handed the
    /// next body the moment it frees the last, so parse work overlaps
    /// engine work and a cold scan phase costs roughly the engine's own
    /// decompile time rather than that plus every scan's parse time. The
    /// spawn order is today's order — [`evidence_scan_tasks`] — but that
    /// order is only the order the scans enter the window. Exactly-once
    /// decompilation is preserved by construction, not by new locking:
    /// the read cache's per-key cell collapses concurrent misses of one
    /// body into one engine request, so the engine stays the serial
    /// resource the racing scans share safely.
    ///
    /// Each scan keeps its own shape: a cached document short-circuits it
    /// before any engine read, and a failed scan or save only warns and
    /// continues — one detector's failure never takes down the batch. The
    /// group joins all eleven and never cancels its siblings.
    ///
    /// The phase arms a fresh type-inference completion latch first:
    /// the inference scan publishes it on every exit and callback
    /// detection awaits it before composing its closure contracts, so
    /// the one real ordering edge between the scans is explicit data
    /// rather than any call order (issue #238).
    ///
    /// The phase also arms the engine heartbeat once around the whole
    /// group, under the phase name, and disarms it when the group ends:
    /// the dashboard shows one honest "n of m functions consumed" row
    /// for the scan phase instead of eleven that restart with each
    /// scan. Beats count unique functions consumed — a body pulled cold
    /// from the engine and replayed warm by the read cache counts once —
    /// so a warm run still shows life and the row stays honest while the
    /// scans interleave (issue #239, preserving #121).
    async fn run_prebatch_scans(&self, binary: &str) {
        self.begin_scan_pass(binary, SCAN_PHASE);
        self.arm_type_inference_latch();
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping the pre-batch evidence scans"
            );
            self.end_scan_pass();
            return;
        };
        let mut scans = evidence_scan_tasks().into_iter();
        let mut set = JoinSet::new();
        self.scan_window_high_water.store(0, Ordering::SeqCst);
        let in_flight = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::clone(&self.scan_window_high_water);
        for scan in scans.by_ref().take(MAX_CONCURRENT_EVIDENCE_SCANS) {
            set.spawn(run_scan_in_window(
                scan,
                job.clone(),
                Arc::clone(&in_flight),
                Arc::clone(&high_water),
            ));
        }
        // Sliding window: every completion frees a permit for the next
        // scan, and the group joins all eleven — a failing or panicking
        // scan never cancels its siblings (issue #240).
        while let Some(outcome) = set.join_next().await {
            if let Err(e) = outcome {
                warn!(
                    binary,
                    error = %e,
                    "An evidence scan task did not complete; continuing without its context"
                );
            }
            if let Some(scan) = scans.next() {
                set.spawn(run_scan_in_window(
                    scan,
                    job.clone(),
                    Arc::clone(&in_flight),
                    Arc::clone(&high_water),
                ));
            }
        }
        self.end_scan_pass();
    }

    /// The most evidence scans that ran at once during the latest scan
    /// phase (issue #241) — the fan-out window's high-water mark, recorded
    /// by [`run_scan_in_window`] as each scan enters the window. Zero when
    /// no phase has run, or when the phase skipped for want of a workspace.
    pub fn scan_window_high_water(&self) -> usize {
        self.scan_window_high_water.load(Ordering::SeqCst)
    }

    /// Recover the per-binary type database before a batch starts, unless one
    /// is already cached.
    ///
    /// Tier 3/4 prompts and escalated retries read recovered data structures
    /// from `re/analysis/typesdb/{binary}.json` (see
    /// [`extract_data_structures`](crate::retry::helpers::extract_data_structures));
    /// running the recovery scan once up front means every function in the
    /// batch can see type context instead of none. The persisted file is the
    /// cache: when a database is already saved for `binary`, the scan is skipped
    /// entirely.
    ///
    /// Returns whether a database is available afterwards. A missing
    /// workspace, a failed scan, or a failed save only log a
    /// warning and return `false` — prompts without data structure context
    /// are degraded, not fatal, and the batch proceeds either way.
    ///
    /// The scan itself — cached-document short-circuit, engine call,
    /// persist, and warn-and-continue degradation —
    /// runs on the owned [`ScanJob`] this builds, so the same scan can be
    /// handed to a task (issue #237). The pass heartbeat belongs to the
    /// scan phase, not to this scan (issue #239).
    pub async fn ensure_type_database(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping type database recovery"
            );
            return false;
        };
        job.type_database().await
    }

    /// Infer parameter types across the binary before a batch starts, unless
    /// an inference result is already cached.
    ///
    /// Prompts and escalated retries read inferred parameter types from
    /// `re/analysis/typeinfer/{binary}.json` (see
    /// [`extract_type_info`](crate::retry::helpers::extract_type_info));
    /// running the inference scan once up front means every function in the
    /// batch can see type context instead of none. The persisted file is the
    /// cache: when a result is already saved for `binary`, the scan is skipped
    /// entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without type context are degraded, not
    /// fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237),
    /// which publishes the scan phase's completion latch on every exit —
    /// cached hit, success, or failure — so callback detection waiting on
    /// it is released either way (issue #238).
    pub async fn ensure_type_inference(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(binary, "No workspace configured; skipping type inference");
            return false;
        };
        job.type_inference().await
    }

    /// Recognize algorithms across the binary before a batch starts, unless a
    /// recognition result is already cached.
    ///
    /// Escalated retries read recognized algorithm hints from
    /// `re/analysis/algorithm/{binary}.json` (see
    /// [`extract_algorithm_hints`](crate::retry::helpers::extract_algorithm_hints));
    /// running the recognition scan once up front means every function in the
    /// batch can see algorithm context instead of none. The persisted file is
    /// the cache: when a result is already saved for `binary`, the scan is
    /// skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without algorithm context are degraded, not
    /// fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_algorithm_recognition(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping algorithm recognition"
            );
            return false;
        };
        job.algorithm_recognition().await
    }

    /// Detect memory lifecycles across the binary before a batch starts,
    /// unless a detection result is already cached.
    ///
    /// The scan's findings — allocation pairs, handle lifetimes, and
    /// reference counts — are filed at `re/analysis/memory/{binary}.json` for
    /// the prompt path to read (see
    /// [`extract_memory_hints`](crate::retry::helpers::extract_memory_hints));
    /// running the detection scan once up front
    /// means every function in the batch can see memory context instead of
    /// none. The persisted file is the cache: when a result is already
    /// saved for `binary`, the scan is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without memory context are degraded, not
    /// fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_memory_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping memory lifecycle detection"
            );
            return false;
        };
        job.memory_detection().await
    }

    /// Detect concurrency constructs across the binary before a batch
    /// starts, unless a detection result is already cached.
    ///
    /// The scan's findings — mutex pairings, atomic calls, and thread
    /// spawns — are filed at `re/analysis/sync/{binary}.json` for the prompt
    /// path to read (see
    /// [`extract_concurrency_hints`](crate::retry::helpers::extract_concurrency_hints));
    /// running the detection scan once up front means every function in
    /// the batch can see concurrency context instead of none. The
    /// persisted file is the cache: when a result is already saved for
    /// `binary`, the scan is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without concurrency context are degraded,
    /// not fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_sync_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping concurrency detection"
            );
            return false;
        };
        job.sync_detection().await
    }

    /// Detect constant structures across the binary before a batch
    /// starts, unless a detection result is already cached.
    ///
    /// The scan's findings — bitflag groups, enum candidates, and
    /// repeated magic numbers — are filed at
    /// `re/analysis/consts/{binary}.json` for the prompt path to read (see
    /// [`extract_constant_hints`](crate::retry::helpers::extract_constant_hints));
    /// running the detection scan once up front means every function in
    /// the batch can see constant context instead of none. The
    /// persisted file is the cache: when a result is already saved for
    /// `binary`, the scan is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without constant context are degraded, not
    /// fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_const_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping constant detection"
            );
            return false;
        };
        job.const_detection().await
    }

    /// Detect callback and function-pointer tables across the binary
    /// before a batch starts, unless a detection result is already cached.
    ///
    /// The scan's findings — function-pointer array calls, callback
    /// registrations, and jump-table dispatches — are filed at
    /// `re/analysis/callback/{binary}.json` for the prompt path to read (see
    /// [`extract_callback_hints`](crate::retry::helpers::extract_callback_hints));
    /// running the detection scan once up front means every function in
    /// the batch can see callback context instead of none. The persisted
    /// file is the cache: when a result is already saved for `binary`, the
    /// scan is skipped entirely. When a type-inference result is cached
    /// too — inside a scan phase the job waits on inference's completion
    /// latch before reading — its records are composed
    /// into a signature map and injected, so the persisted suggestions
    /// carry real closure contracts (see [`callback_signature_map`]).
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without callback context are degraded, not
    /// fatal, and the batch proceeds either way.
    ///
    /// The scan itself — including the type-inference enrichment — runs on
    /// the owned [`ScanJob`] this builds (issue #237). Inside an armed scan
    /// phase the job first awaits the type-inference completion latch, so
    /// the enrichment rides the explicit edge, not the preamble's call
    /// order (issue #238).
    pub async fn ensure_callback_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping callback detection"
            );
            return false;
        };
        job.callback_detection().await
    }

    /// Detect control-flow patterns across the binary before a batch
    /// starts, unless a detection result is already cached.
    ///
    /// The scan's findings — switch-shaped if-else chains, self-recursion,
    /// and state-machine patterns — are filed at
    /// `re/analysis/controlflow/{binary}.json` for the prompt path to read (see
    /// [`extract_control_flow_hints`](crate::retry::helpers::extract_control_flow_hints));
    /// running the detection scan once up front means every function in
    /// the batch can see control-flow context instead of none. The persisted
    /// file is the cache: when a result is already saved for `binary`, the scan
    /// is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without control-flow context are degraded,
    /// not fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_controlflow_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping control-flow detection"
            );
            return false;
        };
        job.controlflow_detection().await
    }

    /// Map the binary's strings to its functions before a batch starts,
    /// unless a string-context result is already cached.
    ///
    /// The scan's findings — classified strings, their functions, and
    /// format-string calls with the argument types they imply — are filed
    /// at `re/analysis/stringctx/{binary}.json` for the prompt path to read
    /// (see
    /// [`extract_string_context`](crate::retry::helpers::extract_string_context));
    /// running the scan once up front means every function in the batch
    /// can see string context instead of none. The persisted file is the
    /// cache: when a result is already saved for `binary`, the scan is
    /// skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without string context are degraded, not
    /// fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_string_context(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping string context scan"
            );
            return false;
        };
        job.string_context().await
    }

    /// Identify the libraries and APIs of the binary before a batch
    /// starts, unless a detection result is already cached.
    ///
    /// The scan's findings — identified import-table entries and the
    /// APIs each function reaches through the call graph — are filed at
    /// `re/analysis/apidetect/{binary}.json` for the prompt path to read
    /// (see [`extract_api_hints`](crate::retry::helpers::extract_api_hints));
    /// running the scan once up front means every function in the batch
    /// can see library/API context instead of none. The persisted file
    /// is the cache: when a result is already saved for `binary`, the scan
    /// is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without API context are degraded, not fatal,
    /// and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_api_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(binary, "No workspace configured; skipping API detection");
            return false;
        };
        job.api_detection().await
    }

    /// Detect endianness and serialization patterns across the binary
    /// before a batch starts, unless a detection result is already cached.
    ///
    /// The scan's findings — byte-swap calls, bit-packing chains, and
    /// file-format signature comparisons — are filed at
    /// `re/analysis/serialize/{binary}.json` for the prompt path to read
    /// (see
    /// [`extract_serialization_hints`](crate::retry::helpers::extract_serialization_hints));
    /// running the detection scan once up front means every function in
    /// the batch can see serialization context instead of none. The
    /// persisted file is the cache: when a result is already saved for
    /// `binary`, the scan is skipped entirely.
    ///
    /// Returns whether a result is available afterwards. A missing workspace,
    /// a failed scan, or a failed save only log a warning and
    /// return `false` — prompts without serialization context are degraded,
    /// not fatal, and the batch proceeds either way.
    ///
    /// The scan itself runs on the owned [`ScanJob`] this builds (issue #237).
    pub async fn ensure_serialize_detection(&self, binary: &str) -> bool {
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping serialization detection"
            );
            return false;
        };
        job.serialize_detection().await
    }

    /// Translate multiple functions from a single DLL, one at a time.
    ///
    /// For each function, this runs the full translation pipeline with retry
    /// logic (same as the single-function
    /// [`try_translate_with_retry`](Self::try_translate_with_retry) path).
    /// Functions are processed sequentially in the order provided.
    ///
    /// Before the first function, the per-binary type database, type inference
    /// result, algorithm recognition result, memory lifecycle result, and
    /// concurrency result are recovered (or loaded from their caches) so
    /// higher context tiers have data structure, parameter type, algorithm,
    /// memory, and concurrency context — the eleven evidence scans run through
    /// one shared preamble, [`run_prebatch_scans`](Self::run_prebatch_scans).
    ///
    /// The caller can provide a callback (`on_function_completed`) that is
    /// invoked **immediately after each function completes** (before moving on
    /// to the next). This enables incremental git commits and per-function
    /// post-processing without blocking subsequent translations.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing all functions to translate.
    /// * `functions` — Function names to translate.
    /// * `config` — Retry configuration applied to every function.
    /// * `verifier` — Verification engine used for checking translations.
    /// * `on_function_completed` — Optional closure called after each function
    ///   completes. Receives the DLL name, function name, a mutable reference to
    ///   the [`batch::FunctionResult`], and a boolean indicating whether the
    ///   caller should continue processing the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`] with per-function outcomes.  A function
    /// counts as a failure when all retry attempts are exhausted without
    /// producing passing tests.
    ///
    /// # Notes
    ///
    /// - If the LLM is unreachable, the batch continues with the remaining
    ///   functions (each failure is recorded individually).
    /// - The retry strategy (compile_fix → test_fix → escalate) is applied
    ///   independently to each function.
    /// - The callback is called on the **same task** that is running the batch;
    ///   it should return `true` quickly to avoid delaying the next function.
    ///   If the callback returns `false`, the batch stops early.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_verify::Verifier;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kuna = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(kuna, llm, calxgloss_pal::ApiMappings::default());
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    /// let config = calxgloss_translator::RetryConfig::default();
    ///
    /// let functions = vec!["DrawSprite".to_string(), "UpdatePosition".to_string()];
    /// let results = pipeline.batch_translate(
    ///     "game_logic.dll",
    ///     &functions,
    ///     &config,
    ///     &verifier,
    ///     Some(&mut |_dll, _function, _result| true), // keep going
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed", results.success_count(), results.failure_count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Produces a priority-ordered translation plan from a call graph.
    ///
    /// This method is the bridge between call-graph analysis and the
    /// batch translation pipeline.  It uses [`TranslationOrderer`] to
    /// transform a [`CallGraph`] into an ordered list of
    /// [`FunctionTranslationPlan`] instances, each annotated with its
    /// priority tier (root / middle / leaf) and topological position.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph to plan from.
    /// * `max_functions` — Optional limit on the number of functions in the plan.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_callgraph::CallGraph;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kuna = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let pipeline = TranslationPipeline::new(kuna, llm, calxgloss_pal::ApiMappings::default());
    ///
    /// // Build or load the call graph first (e.g. via Analyzer::build_call_graph)
    /// let call_graph = /* CallGraph */ todo!();
    ///
    /// // Get a priority-ordered plan (max 100 functions)
    /// let plan = pipeline.plan_from_callgraph(&call_graph, Some(100))?;
    ///
    /// for function in plan {
    ///     println!("{:?} {} ({} callers, {} callees)",
    ///         function.priority, function.name,
    ///         function.caller_count, function.callee_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn plan_from_callgraph(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
        max_functions: Option<usize>,
    ) -> crate::error::Result<Vec<calxgloss_callgraph::FunctionTranslationPlan>> {
        let mut orderer = calxgloss_callgraph::TranslationOrderer::new();
        if let Some(max) = max_functions {
            orderer = orderer.with_max_functions(max);
        }
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;
        Ok(plan.into_iter().collect())
    }

    #[allow(clippy::type_complexity)]
    pub async fn batch_translate(
        &self,
        binary: &str,
        functions: &[String],
        config: &retry::RetryConfig,
        verifier: &Verifier,
        mut on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(
            binary,
            count = functions.len(),
            "Starting batch translation"
        );

        self.begin_cached_source(binary).await;

        self.run_prebatch_scans(binary).await;

        // W2.5: operator scope — skipped functions never enter the queue,
        // priority functions sort to the front.
        let functions = self.apply_function_scope(binary, functions.to_vec(), |f| f.as_str());

        let mut batch_result = batch::BatchTranslationResult::new(binary.to_string());

        for (idx, function) in functions.iter().enumerate() {
            if self.stop_requested() {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Stop signal received — ending batch at unit boundary"
                );
                break;
            }

            if self.budget_exhausted() {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Token budget exhausted — ending batch at unit boundary"
                );
                break;
            }

            // A paused binary ends this batch — unlike a run-level pause it
            // never parks the loop (issue #219, part of #217).
            if self.binary_paused(binary) {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Binary paused — ending batch at unit boundary"
                );
                break;
            }

            if !self.control_allows_next_unit().await {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Pipeline control halt — ending batch at unit boundary"
                );
                break;
            }

            info!(
                binary,
                function,
                index = idx + 1,
                total = functions.len(),
                "Translating function in batch"
            );

            // Register the unit in-flight so the web server's cancel-current
            // endpoint has something to name (issue #91, W2.2).
            if let Some(cancellation) = self.unit_cancellation.as_ref() {
                cancellation.begin_unit(binary, function);
            }

            // The unit races the cancellation watch: a cancellation that
            // lands mid-unit drops the in-flight future — the earliest safe
            // point, since nothing an attempt produced is persisted until
            // the unit completes — and the unit is recorded as a failed
            // attempt while the batch continues with the next unit.
            // A refused root is recorded skipped, not failed; the flag keeps
            // it out of the completion callback (see below).
            let mut unit_refused = false;
            let (mut result, mut aborted) = tokio::select! {
                outcome = self.try_translate_with_retry(binary, function, config, verifier) => {
                    let result = match outcome {
                        Ok(retry_result) => {
                            if retry_result.success {
                                info!(
                                    binary,
                                    function,
                                    attempts = retry_result.attempts.len(),
                                    "Batch function succeeded"
                                );
                                let rust_code = retry_result.rust_code.clone().unwrap_or_default();
                                batch::FunctionResult::success(
                                    binary.to_string(),
                                    function.clone(),
                                    rust_code,
                                    retry_result,
                                    None, // git handled by caller via callback
                                )
                            } else {
                                warn!(
                                    binary,
                                    function,
                                    attempts = retry_result.attempts.len(),
                                    "Batch function exhausted all retries"
                                );
                                batch::FunctionResult::failure(
                                    binary.to_string(),
                                    function.clone(),
                                    retry_result,
                                )
                            }
                        }
                        Err(e) => {
                            // A root symbol named explicitly on the CLI is a
                            // request the pipeline refuses, not a unit that
                            // failed: record it skipped, the way the
                            // call-graph path records its Skip nodes.
                            if matches!(e, TranslatorError::SkippedRoot { .. }) {
                                info!(
                                    binary,
                                    function,
                                    error = %e,
                                    "Batch function is a root symbol — recorded skipped, not failed"
                                );
                                unit_refused = true;
                                batch::FunctionResult::skipped(binary.to_string(), function.clone())
                            } else {
                                warn!(
                                    binary,
                                    function,
                                    error = %e,
                                    "Batch function translation failed (pipeline error)"
                                );
                                // Create a minimal failed result so the caller sees it
                                let empty_result = retry::RetryResult::new();
                                batch::FunctionResult::failure(
                                    binary.to_string(),
                                    function.clone(),
                                    empty_result,
                                )
                            }
                        }
                    };
                    (result, false)
                }
                _ = self.wait_for_unit_cancel(binary, function) => {
                    warn!(
                        binary,
                        function,
                        "Operator cancelled the in-flight unit — aborting at earliest safe point"
                    );
                    let empty_result = retry::RetryResult::new();
                    (
                        batch::FunctionResult::failure(
                            binary.to_string(),
                            function.clone(),
                            empty_result,
                        ),
                        true,
                    )
                }
            };

            // The unit is no longer in flight — a cancel-current arriving
            // from here to the next unit's start is rejected, not absorbed.
            // The release is also the race-free check for a cancellation
            // that landed while the unit's own work was finishing: the
            // operator's cancel still wins over the completion it raced,
            // so the unit is recorded cancelled, not completed.
            if let Some(cancellation) = self.unit_cancellation.as_ref()
                && cancellation.end_unit_was_cancelled()
            {
                if result.success {
                    warn!(
                        binary,
                        function,
                        "Operator cancelled as the unit completed — recording it cancelled"
                    );
                    let empty_result = retry::RetryResult::new();
                    result = batch::FunctionResult::failure(
                        binary.to_string(),
                        function.clone(),
                        empty_result,
                    );
                }
                aborted = true;
            }

            let success = result.success;
            // W2.5: charge the unit's token spend against the run budget.
            self.record_unit_tokens(&result);
            batch_result.add(result.clone());

            // Emit progress event for real-time tracking. A cancelled unit
            // already got its terminal `UnitCancelled` event from the
            // cancellation handle the moment it landed — no completion on
            // top of it.
            if !aborted {
                self.emit(ProgressEvent::FunctionCompleted {
                    binary: binary.to_string().into(),
                    function: function.clone(),
                    success,
                    attempts: 0,  // filled by caller after git branch creation
                    branch: None, // filled by caller after git branch creation
                });
            }

            // Invoke the caller's callback (e.g., for incremental git
            // commits). Cancelled units go through it too — the caller owns
            // git cleanup, and per the Archive rule a cancelled unit's
            // branch is archived under the archive refs, never deleted.
            // A refused root never reaches it: it was never attempted, so
            // it has no translated code to write and no branch to clean up,
            // and a caller that assumes a success carries code would panic.
            let continue_batch = if let Some(ref mut cb) = on_function_completed
                && !unit_refused
            {
                cb(binary, function, &mut result)
            } else {
                true
            };

            if !continue_batch {
                info!(binary, function, "Batch stopped early by callback");
                break;
            }
        }

        info!(
            binary,
            total = batch_result.total_count(),
            success = batch_result.success_count(),
            failure = batch_result.failure_count(),
            "Batch translation complete"
        );

        Ok(batch_result)
    }

    /// Translate multiple functions from a single DLL, prioritized by
    /// call-graph topology.
    ///
    /// This method uses a [call graph] to determine translation order:
    ///
    /// 1. [Leaf] functions (call external APIs) — translated first
    /// 2. [Middle] functions — translated second
    /// 3. [Root] functions — translated last
    ///
    /// Within each tier, functions are sorted topologically so that a
    /// function is only translated after all of its callees have been
    /// processed. This ordering lets the LLM reference already-translated
    /// callee code when generating shim layers or caller wrappers.
    ///
    /// Before the first function, the per-binary type database, type inference
    /// result, algorithm recognition result, memory lifecycle result, and
    /// concurrency result are recovered (or loaded from their caches) so
    /// higher context tiers have data structure, parameter type, algorithm,
    /// memory, and concurrency context — the eleven evidence scans run through
    /// one shared preamble, [`run_prebatch_scans`](Self::run_prebatch_scans).
    ///
    /// The caller can provide a callback (`on_function_completed`) that is
    /// invoked **immediately after each function completes** (before moving on
    /// to the next). This enables incremental git commits and per-function
    /// post-processing without blocking subsequent translations.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph containing all functions to translate.
    ///   Root functions are automatically stubbed with minimal placeholders
    ///   (they have no translation work). Runtime library functions
    ///   (`NodeCategory::Skip`) are not stubbed.
    /// * `config` — Retry configuration applied to every function.
    /// * `verifier` — Verification engine used for checking translations.
    /// * `on_function_completed` — Optional closure called after each function
    ///   completes. Receives the DLL name, function name, a mutable reference to
    ///   the [`batch::FunctionResult`], and a boolean indicating whether the
    ///   caller should continue processing the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`] with per-function outcomes.  A function
    /// counts as a failure when all retry attempts are exhausted without
    /// producing passing tests.
    ///
    /// Root functions from the call graph are stubbed automatically and
    /// appear in the result with [`batch::FunctionResult::stubbed`].
    /// Functions classified as [`NodeCategory::Skip`] (runtime library functions)
    /// are not stubbed and appear as [`batch::FunctionResult::skipped`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_translator::TranslationPipeline;
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_analysis::build_enriched_call_graph;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kuna = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let config = calxgloss_translator::RetryConfig::default();
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// // Build or load the enriched call graph first (reads through the seam)
    /// let call_graph = build_enriched_call_graph(
    ///     &calxgloss_decomp::PipelineSource::from(kuna.clone()),
    ///     "game_logic.dll",
    ///     Path::new("/tmp/calxgloss-work"),
    ///     None,
    /// ).await?;
    ///
    /// let pipeline = TranslationPipeline::new(kuna.clone(), llm, calxgloss_pal::ApiMappings::default());
    ///
    /// let results = pipeline.batch_translate_from_callgraph(
    ///     &call_graph,
    ///     &config,
    ///     &verifier,
    ///     Some(&mut |_dll, _function, _result| true), // keep going
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed, {} skipped",
    ///     results.success_count(), results.failure_count(), results.skipped_count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [call graph]: calxgloss_callgraph::CallGraph
    /// [Leaf]: calxgloss_types::NodeCategory::Leaf
    /// [Middle]: calxgloss_types::NodeCategory::Middle
    /// [Root]: calxgloss_types::NodeCategory::Root
    #[allow(clippy::type_complexity)]
    pub async fn batch_translate_from_callgraph(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
        config: &retry::RetryConfig,
        verifier: &Verifier,
        mut on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(binary = %graph.binary, count = graph.functions.len(), "Starting call-graph batch translation");

        self.begin_cached_source(&graph.binary).await;

        self.run_prebatch_scans(&graph.binary).await;

        // Build a priority-ordered plan
        let orderer = calxgloss_callgraph::TranslationOrderer::new();
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;

        let plan: Vec<_> = plan.into_iter().collect();
        let binary = &graph.binary;

        // W2.5: operator scope — skipped functions leave the plan before the
        // first unit starts, priority functions sort to the front.
        let plan = self.apply_function_scope(binary, plan, |p| p.name.as_str());

        let mut batch_result = batch::BatchTranslationResult::new(binary.clone());

        for (idx, plan_func) in plan.iter().enumerate() {
            use calxgloss_callgraph::TranslationPriority;

            if self.stop_requested() {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Stop signal received — ending call-graph batch at unit boundary"
                );
                break;
            }

            if self.budget_exhausted() {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Token budget exhausted — ending call-graph batch at unit boundary"
                );
                break;
            }

            // A paused binary ends this batch — unlike a run-level pause it
            // never parks the loop (issue #219, part of #217).
            if self.binary_paused(binary) {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Binary paused — ending call-graph batch at unit boundary"
                );
                break;
            }

            if !self.control_allows_next_unit().await {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Pipeline control halt — ending call-graph batch at unit boundary"
                );
                break;
            }

            // Handle root functions (entry points) — generate stubs instead of translating
            if matches!(plan_func.priority, TranslationPriority::Root) {
                // Skip functions are truly skipped (runtime library functions)
                if matches!(plan_func.category, NodeCategory::Skip) {
                    info!(
                        binary,
                        name = %plan_func.name,
                        address = plan_func.address,
                        "Skipping runtime library function"
                    );
                    let skipped =
                        batch::FunctionResult::skipped(binary.clone(), plan_func.name.clone());
                    batch_result.add(skipped);

                    self.emit(ProgressEvent::FunctionCompleted {
                        binary: binary.clone().into(),
                        function: plan_func.name.clone(),
                        success: true,
                        attempts: 0,
                        branch: None,
                    });

                    // A skipped plan node never reaches the caller's
                    // callback: it was never attempted, so it has no
                    // translated code to write and no branch to clean up,
                    // and a caller that assumes a success carries code
                    // would panic.

                    continue;
                }

                // Generate stub for entry point functions
                info!(
                    binary,
                    name = %plan_func.name,
                    address = plan_func.address,
                    "Generating stub for root function"
                );
                let stub_code = self.generate_stub(&plan_func.name, "");
                let stubbed = batch::FunctionResult::stubbed(
                    binary.clone(),
                    plan_func.name.clone(),
                    stub_code,
                );
                batch_result.add(stubbed.clone());

                self.emit(ProgressEvent::FunctionCompleted {
                    binary: binary.clone().into(),
                    function: plan_func.name.clone(),
                    success: true,
                    attempts: 0,
                    branch: None,
                });

                // Invoke the caller's callback even for stubbed functions
                if let Some(ref mut cb) = on_function_completed
                    && !cb(binary, &plan_func.name, &mut stubbed.clone())
                {
                    info!(binary, function = %plan_func.name, "Batch stopped early by callback");
                    break;
                }

                continue;
            }

            info!(
                binary,
                name = %plan_func.name,
                address = plan_func.address,
                priority = ?plan_func.priority,
                index = idx + 1,
                total = plan.len(),
                "Translating function in batch"
            );

            let mut result = match self
                .try_translate_with_retry(binary, &plan_func.name, config, verifier)
                .await
            {
                Ok(retry_result) => {
                    if retry_result.success {
                        info!(
                            binary,
                            name = %plan_func.name,
                            attempts = retry_result.attempts.len(),
                            "Batch function succeeded"
                        );
                        let rust_code = retry_result.rust_code.clone().unwrap_or_default();
                        batch::FunctionResult::success(
                            binary.clone(),
                            plan_func.name.clone(),
                            rust_code,
                            retry_result,
                            None,
                        )
                    } else {
                        warn!(
                            binary,
                            name = %plan_func.name,
                            attempts = retry_result.attempts.len(),
                            "Batch function exhausted all retries"
                        );
                        let empty_result = retry::RetryResult::new();
                        batch::FunctionResult::failure(
                            binary.clone(),
                            plan_func.name.clone(),
                            empty_result,
                        )
                    }
                }
                Err(e) => {
                    warn!(
                        binary,
                        name = %plan_func.name,
                        error = %e,
                        "Batch function translation failed (pipeline error)"
                    );
                    let empty_result = retry::RetryResult::new();
                    batch::FunctionResult::failure(
                        binary.clone(),
                        plan_func.name.clone(),
                        empty_result,
                    )
                }
            };

            let success = result.success;
            // W2.5: charge the unit's token spend against the run budget.
            self.record_unit_tokens(&result);
            batch_result.add(result.clone());

            // Emit progress event for real-time tracking
            self.emit(ProgressEvent::FunctionCompleted {
                binary: binary.clone().into(),
                function: plan_func.name.clone(),
                success,
                attempts: 0,  // filled by caller after git branch creation
                branch: None, // filled by caller after git branch creation
            });

            // Invoke the caller's callback
            let continue_batch = if let Some(ref mut cb) = on_function_completed {
                cb(binary, &plan_func.name, &mut result)
            } else {
                true
            };

            if !continue_batch {
                info!(binary, function = %plan_func.name, "Batch stopped early by callback");
                break;
            }
        }

        info!(
            binary,
            total = batch_result.total_count(),
            success = batch_result.success_count(),
            failure = batch_result.failure_count(),
            "Call-graph batch translation complete"
        );

        Ok(batch_result)
    }
}

// ============================================================
// Hallucination detector helpers
// ============================================================

/// Build a [`HallucinationDetector`] from the program's symbols and the
/// PAL API catalogue.
///
/// The detector's known-good symbol set is the union of:
/// 1. All engine functions (exports and user-defined functions)
/// 2. All engine imports (DLL imports)
/// 3. Every Windows API name from the PAL mapping table
pub async fn build_hallucination_detector(
    source: &KunaSource,
    api_mappings: &ApiMappings,
) -> HallucinationDetector {
    // Engine functions
    let engine_functions: Vec<String> = ScanSource::functions(source)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|f| f.name)
        .collect();

    // Engine imports
    let engine_imports: Vec<String> = ScanSource::imports(source)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|s| s.name)
        .collect();

    // Collect Windows API names from the PAL mapping table
    let _windows_apis: Vec<String> = api_mappings
        .iter()
        .map(|m| m.windows_api.to_string())
        .collect();

    HallucinationDetector::new(engine_functions, engine_imports)
}

/// Compose the callback scan's signature map from the type-inference
/// document cached for `binary` under `workspace`.
///
/// The callback engine takes callable contracts by injection (see
/// [`calxgloss_callback::signatures`]); this is the one place that
/// reads the type-inference scan's persisted per-binary document and
/// composes those contracts, so the CLI `callback` command and the
/// batch pre-analysis wire the enrichment identically (issue #173,
/// ADR-0036). A missing or corrupt document — the type-inference scan
/// never ran, or its artifact is broken — yields an empty map and the
/// callback scan degrades silently to its un-enriched suggestions: a
/// bad neighbor artifact never fails the scan.
///
/// The composition is honest about what the records prove. A function
/// joins the map only when its parameter records cover positions
/// `0..n` **contiguously** and a return record stands: a gap proves a
/// middle parameter the records never typed, and a contract that
/// skipped it would misplace every type after it; no parameter
/// records at all cannot tell a zero-parameter callback from one
/// whose parameters were never read; and with no return reading the
/// contract would assert a unit return nobody read.
pub fn callback_signature_map(workspace: &Path, binary: &str) -> SignatureMap {
    let persistor = TypeInferPersistor::new(workspace);
    match persistor.load(binary) {
        Ok(result) => compose_signature_map(&result),
        Err(TypeInferError::NotFound { path }) => {
            debug!(
                binary,
                path = %path.display(),
                "No type-inference document cached; the callback scan runs without signature enrichment"
            );
            SignatureMap::new()
        }
        Err(error) => {
            warn!(
                binary,
                error = %error,
                "Type-inference document unreadable; the callback scan runs without signature enrichment"
            );
            SignatureMap::new()
        }
    }
}

/// Group one type-inference document's per-function records into the
/// callable contracts the callback engine consumes: the parameter
/// records by position, and the function's return record.
fn compose_signature_map(result: &TypeInferenceResult) -> SignatureMap {
    // First-seen wins per slot, mirroring the inference scan's own
    // conflict-resolution tie: a well-formed document carries one
    // record per slot anyway.
    let mut params: HashMap<&str, Vec<(usize, &str)>> = HashMap::new();
    let mut returns: HashMap<&str, &str> = HashMap::new();
    for inference in &result.inferences {
        match inference {
            InferredType::Param(record) => params
                .entry(record.function.as_str())
                .or_default()
                .push((record.param_index, record.inferred_type.as_str())),
            InferredType::Return(record) => {
                returns
                    .entry(record.function.as_str())
                    .or_insert(record.inferred_type.as_str());
            }
            // Locals and call-site readings type storage, not the
            // callable's contract.
            _ => {}
        }
    }

    let mut signatures = SignatureMap::new();
    for (function, mut slots) in params {
        // A stable sort keeps first-seen in front among equal
        // positions, and the dedup then folds a repeated position to
        // its first reading.
        slots.sort_by_key(|(index, _)| *index);
        slots.dedup_by_key(|(index, _)| *index);
        if slots
            .iter()
            .enumerate()
            .any(|(position, (index, _))| position != *index)
        {
            continue;
        }
        let Some(return_type) = returns.get(function) else {
            continue;
        };
        signatures.insert(
            function.to_string(),
            CallableSignature {
                param_types: slots
                    .into_iter()
                    .map(|(_, inferred_type)| inferred_type.to_string())
                    .collect(),
                return_type: Some(return_type.to_string()),
            },
        );
    }
    signatures
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_algorithm::persist::AlgorithmPersistor;
    use calxgloss_algorithm::types::AlgorithmRecognitionResult;
    use calxgloss_apidetect::persist::ApiPersistor;
    use calxgloss_apidetect::types::ApiDetectionResult;
    use calxgloss_callback::persist::CallbackPersistor;
    use calxgloss_callback::types::CallbackResult;
    use calxgloss_consts::persist::ConstPersistor;
    use calxgloss_consts::types::ConstResult;
    use calxgloss_controlflow::persist::ControlFlowPersistor;
    use calxgloss_controlflow::types::ControlFlowResult;
    use calxgloss_memory::persist::MemoryPersistor;
    use calxgloss_memory::types::MemoryResult;
    use calxgloss_serialize::persist::SerializePersistor;
    use calxgloss_serialize::types::SerializeResult;
    use calxgloss_stringctx::persist::StringContextPersistor;
    use calxgloss_stringctx::types::StringContextResult;
    use calxgloss_sync::persist::SyncPersistor;
    use calxgloss_sync::types::SyncResult;
    use calxgloss_typeinfer::persist::TypeInferPersistor;
    use calxgloss_typeinfer::types::{
        InferenceMethod, InferenceScope, InferredLocalType, InferredParamType, InferredReturnType,
        TypeInferenceResult,
    };
    use calxgloss_types::Confidence;
    use calxgloss_types::TranslationConstraints;
    use calxgloss_typesdb::persist::TypeDatabasePersistor;
    use calxgloss_typesdb::types::{ScanMetadata, TypeDatabase};
    use tempfile::TempDir;

    /// The fixture target loaded under the Kuna engine — the only engine
    /// (issue #214). One source per test: the heartbeat pass state is
    /// shared by clones, so tests that scan concurrently need their own
    /// engine.
    fn fixture_kuna() -> calxgloss_kuna::KunaSource {
        let target = calxgloss_testfixtures::load_target()
            .expect("fixture target should build and validate");
        calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna")
    }

    /// A pipeline over the fixture engine, workspace included when there is
    /// one. Functions the fixture does not list fail by name at the engine,
    /// which is how the batch tests get their per-unit failures.
    fn pipeline_over(workspace: Option<&std::path::Path>) -> TranslationPipeline {
        pipeline_with(fixture_kuna(), workspace)
    }

    /// A stopped `StopSignal` ends `batch_translate` at the next unit
    /// boundary: the unit in flight completes (its callback runs, so the
    /// result is persisted by the caller) and no further unit starts.
    #[tokio::test]
    async fn batch_translate_breaks_at_unit_boundary_when_stop_is_requested() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let stop = StopSignal::new();
        let stop_cb = stop.clone();
        let pipeline = pipeline_over(Some(dir.path())).with_stop_signal(stop);

        let mut completed = 0;
        let result = pipeline
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, _function, _func_result| {
                    completed += 1;
                    // Stop requested right after the first unit completes.
                    stop_cb.stop();
                    true
                }),
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        assert_eq!(completed, 1, "only the first unit should have run");
        assert_eq!(
            result.results.len(),
            1,
            "the second unit must not start after the stop signal"
        );
    }

    // ─── Operator translation scope (issue #93, W2.5) ─────────────────

    /// A function the operator skipped never enters the queue plan: it is
    /// not attempted at all, so it never appears in the batch results.
    #[tokio::test]
    async fn batch_translate_never_queues_operator_skipped_functions() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let scope = ScopeControl::new();
        scope
            .skip_function("game_logic.dll", "UpdateScene")
            .expect("skip should persist");

        let result = pipeline_over(Some(dir.path()))
            .with_scope(scope)
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        let names: Vec<&str> = result.results.iter().map(|r| r.function.as_str()).collect();
        assert_eq!(
            names,
            vec!["DrawPrimitive"],
            "the skipped function must never enter the queue"
        );
    }

    /// A prioritized function sorts ahead of the rest of the queue, keeping
    /// the remaining functions in their original order.
    #[tokio::test]
    async fn batch_translate_runs_priority_functions_first() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let scope = ScopeControl::new();
        scope
            .prioritize_function("game_logic.dll", "UpdateScene")
            .expect("priority should persist");

        let result = pipeline_over(Some(dir.path()))
            .with_scope(scope)
            .batch_translate(
                "game_logic.dll",
                &[
                    "DrawPrimitive".to_string(),
                    "UpdateScene".to_string(),
                    "LoadAssets".to_string(),
                ],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        let names: Vec<&str> = result.results.iter().map(|r| r.function.as_str()).collect();
        assert_eq!(
            names,
            vec!["UpdateScene", "DrawPrimitive", "LoadAssets"],
            "the prioritized function must run first, the rest keep their order"
        );
    }

    // ─── Per-unit reviewer overrides (issue #96, W2.7) ─────────────────

    /// A unit the reviewer skipped never enters the queue plan — and the
    /// rest of its binary's pass keeps running, so one hopeless function
    /// does not block the batch.
    #[tokio::test]
    async fn batch_translate_never_queues_reviewer_skipped_units() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let overrides = calxgloss_types::OverrideControl::new();
        overrides
            .set(
                "game_logic.dll",
                "UpdateScene",
                calxgloss_types::FunctionOverride {
                    skip: true,
                    ..Default::default()
                },
            )
            .expect("in-memory skip");

        let result = pipeline_over(Some(dir.path()))
            .with_overrides(overrides)
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        let names: Vec<&str> = result.results.iter().map(|r| r.function.as_str()).collect();
        assert_eq!(
            names,
            vec!["DrawPrimitive"],
            "the reviewer-skipped unit must never enter the queue, the rest keep running"
        );
    }

    // ─── Root-symbol guard & decompiler-warning triage ─────────────────

    /// An import thunk named explicitly is refused before the engine fetch:
    /// the pipeline never spends a read (let alone an LLM call) on a
    /// function that owns no logic, and the refusal names the matched
    /// pattern so the operator learns why.
    #[tokio::test]
    async fn translate_refuses_an_import_thunk_before_touching_the_engine() {
        let result = pipeline_over(None)
            .translate(PROGRAM, "DelayLoad_cef_string_utf16_clear")
            .await;
        let Err(TranslatorError::SkippedRoot {
            function, reason, ..
        }) = result
        else {
            panic!("a delay-load thunk must be refused, got {result:?}");
        };
        assert_eq!(function, "DelayLoad_cef_string_utf16_clear");
        assert!(
            reason.contains("import thunk"),
            "the refusal should name the matched pattern, got: {reason}"
        );
    }

    /// A thunk named explicitly in a batch list is recorded skipped, not
    /// failed — the same honest record the call-graph path gives its Skip
    /// nodes — and the batch itself completes.
    #[tokio::test]
    async fn batch_translate_records_a_requested_thunk_as_skipped() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let result = pipeline_over(Some(dir.path()))
            .batch_translate(
                PROGRAM,
                &["DelayLoad_ShellExecuteW".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("the batch completes even when every unit is refused");

        assert_eq!(result.total_count(), 1);
        assert_eq!(result.skipped_count(), 1, "the thunk is recorded skipped");
        assert_eq!(result.failure_count(), 0, "a refusal is not a failure");
    }

    /// The callback contract the CLI git-commit path relies on: a result
    /// delivered with `success` set carries its translated code. A refused
    /// root arriving as a success without code makes the caller's
    /// `rust_code` unwrap panic mid-batch (the `auto` crash on a
    /// delay-load thunk named explicitly).
    #[tokio::test]
    async fn batch_translate_callback_never_sees_a_success_without_code() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let mut codeless_successes: Vec<String> = Vec::new();
        let result = pipeline_over(Some(dir.path()))
            .batch_translate(
                PROGRAM,
                &["DelayLoad_ShellExecuteW".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, _function, func_result| {
                    if func_result.success && func_result.rust_code.is_none() {
                        codeless_successes.push(func_result.function.clone());
                    }
                    true
                }),
            )
            .await
            .expect("the batch completes even when every unit is refused");

        assert!(
            codeless_successes.is_empty(),
            "every success delivered to the callback must carry rust_code; \
             codeless: {codeless_successes:?}"
        );
        assert_eq!(
            result.skipped_count(),
            1,
            "the refusal is still recorded skipped"
        );
    }

    /// A forced tier replaces the automatic selection for that unit only;
    /// other units keep the automatic tier.
    #[test]
    fn reviewer_override_forces_the_context_tier() {
        let overrides = calxgloss_types::OverrideControl::new();
        overrides
            .set(
                "game_logic.dll",
                "DrawPrimitive",
                calxgloss_types::FunctionOverride {
                    tier_override: Some(calxgloss_types::ContextTier::FullModule),
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        let pipeline = pipeline_over(None).with_overrides(overrides);

        assert_eq!(
            pipeline.forced_context_tier("game_logic.dll", "DrawPrimitive"),
            Some(calxgloss_types::ContextTier::FullModule)
        );
        assert_eq!(
            pipeline.forced_context_tier("game_logic.dll", "UpdateScene"),
            None,
            "units without an override keep the automatic tier"
        );
    }

    /// A forced strategy reaches the retry loop as the translator's own
    /// strategy. Unknown labels no longer need a pipeline-side guard: the
    /// override record's typed field refuses them at deserialization
    /// (issue #120), so a stored force is always a real strategy.
    #[test]
    fn reviewer_override_forces_the_retry_strategy() {
        let overrides = calxgloss_types::OverrideControl::new();
        overrides
            .set(
                "game_logic.dll",
                "DrawPrimitive",
                calxgloss_types::FunctionOverride {
                    retry_strategy_override: Some(calxgloss_types::RetryStrategy::Escalate),
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        let pipeline = pipeline_over(None).with_overrides(overrides);

        assert_eq!(
            pipeline.forced_retry_strategy("game_logic.dll", "DrawPrimitive"),
            Some(retry::RetryStrategy::Escalate)
        );
        assert_eq!(
            pipeline.forced_retry_strategy("game_logic.dll", "UpdateScene"),
            None,
            "units without an override keep the configured strategy"
        );
    }

    /// The reviewer's custom hints reach the unit's prompt as a marked
    /// section; units without hints keep the prompt untouched.
    #[test]
    fn reviewer_hints_ride_into_the_prompt() {
        let overrides = calxgloss_types::OverrideControl::new();
        overrides
            .set(
                "game_logic.dll",
                "DrawPrimitive",
                calxgloss_types::FunctionOverride {
                    custom_hints: vec!["reads the palette table".into()],
                    ..Default::default()
                },
            )
            .expect("in-memory set");
        let pipeline = pipeline_over(None).with_overrides(overrides);

        assert_eq!(
            pipeline.reviewer_hints_for("game_logic.dll", "DrawPrimitive"),
            vec!["reads the palette table".to_string()]
        );
        assert!(
            pipeline
                .reviewer_hints_for("game_logic.dll", "UpdateScene")
                .is_empty()
        );

        let with_hints = TranslationPipeline::append_reviewer_hints(
            "BASE PROMPT".to_string(),
            &["reads the palette table".to_string()],
        );
        assert!(with_hints.starts_with("BASE PROMPT"));
        assert!(with_hints.contains("## Reviewer hints"));
        assert!(with_hints.contains("- reads the palette table"));
    }

    /// With the run's token budget already spent, the batch ends at the very
    /// first unit boundary — no unit starts.
    #[tokio::test]
    async fn batch_translate_ends_before_any_unit_when_token_budget_is_spent() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let scope = ScopeControl::new();
        scope
            .set_constraints(TranslationConstraints {
                max_attempts: None,
                max_context_tier: None,
                token_budget: Some(100),
            })
            .expect("constraints should persist");
        scope.record_tokens(100);

        let result = pipeline_over(Some(dir.path()))
            .with_scope(scope)
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        assert!(
            result.results.is_empty(),
            "no unit may start once the token budget is spent"
        );
    }

    /// `max_attempts` only ever lowers the attempt ceiling and the context
    /// tier cap rides into the retry config (issue #93).
    #[test]
    fn constraints_cap_retry_config_without_raising_it() {
        let scope = ScopeControl::new();
        scope
            .set_constraints(TranslationConstraints {
                max_attempts: Some(2),
                max_context_tier: Some(calxgloss_types::ContextTier::Disassembly),
                token_budget: None,
            })
            .expect("constraints should persist");

        let pipeline = pipeline_over(None).with_scope(scope);

        let default = retry::RetryConfig::default();
        let capped = pipeline.constrained_retry_config(&default);
        assert_eq!(capped.max_attempts, 2, "attempt ceiling must come down");
        assert_eq!(
            capped.max_context_tier,
            Some(calxgloss_types::ContextTier::Disassembly)
        );

        // A stricter pipeline config is never raised by a looser constraint.
        let strict = retry::RetryConfig {
            max_attempts: 1,
            max_context_tier: Some(calxgloss_types::ContextTier::Signature),
            ..retry::RetryConfig::default()
        };
        let capped = pipeline.constrained_retry_config(&strict);
        assert_eq!(capped.max_attempts, 1, "the tighter ceiling wins");
        assert_eq!(
            capped.max_context_tier,
            Some(calxgloss_types::ContextTier::Signature),
            "the tighter tier cap wins"
        );
    }

    /// A paused `PipelineControl` parks `batch_translate` at the next unit
    /// boundary — the unit in flight is never interrupted — and the resume
    /// continues exactly where it stopped (issue #90, W2.1).
    #[tokio::test]
    async fn batch_translate_pauses_at_unit_boundary_and_resumes_where_it_stopped() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let control = PipelineControl::new();
        control.start().expect("idle -> running");

        // The "operator" side: watch for the pause to land, record it, then
        // resume — mirroring the pause/resume endpoints driving the handle.
        let watched = control.clone();
        let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let order_watch = order.clone();
        let resume_task = tokio::spawn(async move {
            while watched.state() != PipelineState::Paused {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            order_watch
                .lock()
                .expect("order lock")
                .push("paused".to_string());
            watched.resume().expect("paused -> running");
        });

        let pipeline = pipeline_over(Some(dir.path())).with_pipeline_control(control.clone());
        let order_cb = order.clone();
        let result = pipeline
            .batch_translate(
                "game_logic.dll",
                &[
                    "DrawPrimitive".to_string(),
                    "UpdateScene".to_string(),
                    "SpawnEntity".to_string(),
                ],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, function, _func_result| {
                    order_cb
                        .lock()
                        .expect("order lock")
                        .push(function.to_string());
                    // Pause requested right after the first unit completes.
                    if function == "DrawPrimitive" {
                        control.pause().expect("running -> paused");
                    }
                    true
                }),
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");
        resume_task.await.expect("the resume task ran");

        assert_eq!(
            control.state(),
            PipelineState::Running,
            "the run resumed and finished running"
        );
        assert_eq!(result.results.len(), 3, "a pause never drops a queued unit");
        assert_eq!(
            *order.lock().expect("order lock"),
            ["DrawPrimitive", "paused", "UpdateScene", "SpawnEntity"],
            "the pause took effect at the boundary after unit 1, before unit 2 started"
        );
    }

    /// A stopped `PipelineControl` ends `batch_translate` at the next unit
    /// boundary: the unit in flight completes (its callback runs, so the
    /// caller persists it and cleans up its branch), then the run halts in
    /// `Stopping` (issue #90, W2.1).
    #[tokio::test]
    async fn batch_translate_halts_at_unit_boundary_when_control_is_stopped() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        let control_cb = control.clone();
        let pipeline = pipeline_over(Some(dir.path())).with_pipeline_control(control.clone());

        let mut completed = 0;
        let result = pipeline
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, _function, _func_result| {
                    completed += 1;
                    // Stop requested right after the first unit completes.
                    control_cb.stop().expect("running -> stopping");
                    true
                }),
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        assert_eq!(completed, 1, "the in-flight unit completed first");
        assert_eq!(
            result.results.len(),
            1,
            "the second unit must not start after the stop"
        );
        assert_eq!(
            control.state(),
            PipelineState::Stopping,
            "the batch halts in the stopping state"
        );
    }

    /// A stop signal arriving while the loop is parked at a pause boundary
    /// releases the park and ends the batch — server shutdown must never
    /// hang on a paused run (issue #90, W2.1).
    #[tokio::test]
    async fn batch_translate_stop_during_pause_releases_the_park() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let control = PipelineControl::new();
        control.start().expect("idle -> running");
        let stop = StopSignal::new();

        // The "operator" side: once the run is parked in Paused, fire the
        // stop signal (what the shutdown endpoint does).
        let watched = control.clone();
        let stop_signal = stop.clone();
        let stop_task = tokio::spawn(async move {
            while watched.state() != PipelineState::Paused {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            stop_signal.stop();
        });

        let pipeline = pipeline_over(Some(dir.path()))
            .with_pipeline_control(control.clone())
            .with_stop_signal(stop.clone());
        let control_cb = control.clone();
        let result = pipeline
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, function, _func_result| {
                    if function == "DrawPrimitive" {
                        control_cb.pause().expect("running -> paused");
                    }
                    true
                }),
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");
        stop_task.await.expect("the stop task ran");

        assert_eq!(
            result.results.len(),
            1,
            "the parked loop ended at the boundary on the stop signal"
        );
    }

    /// A paused target binary ends `batch_translate` at the next unit
    /// boundary, mirroring the run-level stop test: the unit in flight
    /// completes and is counted, the remaining units never start — and,
    /// unlike a run-level pause, the batch **returns** rather than parking
    /// for a resume (issue #219, part of #217). The scope handle is the
    /// in-memory one with no server, the same handle the web endpoints drive.
    #[tokio::test]
    async fn batch_translate_ends_at_unit_boundary_when_its_binary_is_paused() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let scope = ScopeControl::new();
        let scope_cb = scope.clone();
        let pipeline = pipeline_over(Some(dir.path())).with_scope(scope);

        let mut completed = 0;
        // The timeout is the "never parks" assertion: a run-level pause
        // would hold here until a resume that never arrives, while a binary
        // pause ends the batch on its own. The bound is generous because the
        // twelve pre-analysis scans over the fixture run inside it.
        let batch = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            pipeline.batch_translate(
                "game_logic.dll",
                &[
                    "DrawPrimitive".to_string(),
                    "UpdateScene".to_string(),
                    "SpawnEntity".to_string(),
                ],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, _function, _func_result| {
                    completed += 1;
                    // Pause requested right after the first unit completes.
                    scope_cb
                        .pause_binary("game_logic.dll")
                        .expect("pause persists");
                    true
                }),
            ),
        )
        .await
        .expect("a paused binary ends the batch — it never parks waiting for a resume");

        let result = batch
            .expect("batch over functions the fixture lacks still reports per-function failures");
        assert_eq!(completed, 1, "the in-flight unit completed first");
        assert_eq!(
            result.results.len(),
            1,
            "the second unit must not start after the binary pause"
        );
    }

    /// A binary paused before its batch starts attempts zero units: the
    /// boundary check fires before the first unit and the batch returns an
    /// empty result — and the differently-cased pause still matches, the one
    /// match rule from #107 (issue #219, part of #217).
    #[tokio::test]
    async fn batch_translate_attempts_no_units_when_its_binary_is_paused_before_start() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let scope = ScopeControl::new();
        scope
            .pause_binary("GAME_LOGIC.DLL")
            .expect("pause persists before the batch starts");

        let result = pipeline_over(Some(dir.path()))
            .with_scope(scope)
            .batch_translate(
                "game_logic.dll",
                &["DrawPrimitive".to_string(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, function, _func_result| {
                    panic!("no unit may start for a binary paused before its batch: {function}");
                }),
            )
            .await
            .expect("batch over functions the fixture lacks still reports per-function failures");

        assert!(
            result.results.is_empty(),
            "a binary paused before its batch starts attempts zero units"
        );
    }

    /// A stand-in LLM server that accepts connections and never answers —
    /// a unit that reaches it stays in flight until something ends it.
    /// Returns the base URL to point a client at.
    async fn hanging_llm() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake server should bind");
        let addr = listener.local_addr().expect("fake server address");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // Hold the connection open without ever responding.
                    let _stream = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        format!("http://{addr}/v1")
    }

    /// Cancel-current on the unit in flight (issue #91, W2.2): the unit is
    /// aborted at the earliest safe point — mid-LLM-call, against an LLM
    /// that never answers, so without the abort the batch would sit until
    /// the client timeout — the cancelled attempt is recorded as a failure,
    /// its callback still runs so the caller can archive its branch, and
    /// Cancel-current on the unit in flight (issue #91, W2.2): the unit is
    /// aborted at the earliest safe point — mid-LLM-call, against an LLM
    /// that never answers, so without the abort the batch would sit until
    /// the client timeout — the cancelled attempt is recorded as a failure,
    /// its callback still runs so the caller can archive its branch, and
    /// the run continues with the next unit.
    #[tokio::test]
    async fn batch_translate_cancel_current_aborts_in_flight_unit_and_continues() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        // The fixture engine resolves the first unit's fetch — its tick
        // entry point, listed with MinGW's leading underscore — so that
        // unit reaches the hanging LLM and stays in flight; the second
        // unit fails fast at the fetch.
        let kuna = fixture_kuna();
        let listed = calxgloss_decomp::ScanSource::functions(&kuna)
            .await
            .expect("fixture function listing");
        let tick = listed
            .iter()
            .find(|f| f.name.trim_start_matches('_') == "fixture_tick")
            .expect("the fixture lists its tick entry point")
            .name
            .clone();
        let llm = LlmClient::from_url(&hanging_llm().await, "qwen3").expect("llm config");
        let cancellation = UnitCancellation::new();
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default())
            .with_workspace(dir.path().to_path_buf())
            .with_unit_cancellation(cancellation.clone());

        // The "operator" side: as soon as a unit is registered in flight,
        // cancel it — what the cancel-current endpoint does.
        let watched = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            while watched.current_unit().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            watched
                .cancel_current()
                .expect("the in-flight unit can be cancelled")
        });

        let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>> = std::sync::Arc::default();
        let seen_cb = seen.clone();
        let result = pipeline
            .batch_translate(
                "game_logic.dll",
                &[tick.clone(), "UpdateScene".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_dll, function, func_result| {
                    seen_cb
                        .lock()
                        .expect("callback lock is never poisoned")
                        .push((function.to_string(), func_result.success));
                    true
                }),
            )
            .await
            .expect("a cancelled unit never fails the batch itself");
        let cancelled_unit = cancel_task.await.expect("the cancel task ran");

        assert_eq!(
            cancelled_unit.function(),
            tick,
            "the cancellation lands on the unit that was in flight"
        );
        assert_eq!(
            result.results.len(),
            2,
            "the cancelled unit is recorded and the run continued to the next unit"
        );
        let cancelled = &result.results[0];
        assert_eq!(cancelled.function, tick);
        assert!(
            !cancelled.success,
            "the cancelled attempt is recorded as failed"
        );
        assert!(
            cancelled.retry_result.attempts.is_empty(),
            "the aborted attempt left no completed attempt behind — nothing half-written"
        );
        assert_eq!(
            *seen.lock().expect("callback lock is never poisoned"),
            vec![(tick.clone(), false), ("UpdateScene".to_string(), false),],
            "the caller's callback ran for the cancelled unit (nothing is \
             discarded) and the next unit was attempted"
        );
    }

    #[tokio::test]
    async fn a_cached_database_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeDatabasePersistor::new(dir.path());
        persistor
            .save(&TypeDatabase::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_type_database("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn no_workspace_skips_the_recovery() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_type_database("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_inference_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = TypeInferPersistor::new(dir.path());
        persistor
            .save(&TypeInferenceResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_type_inference("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn no_workspace_skips_the_inference() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_type_inference("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_algorithm_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = AlgorithmPersistor::new(dir.path());
        persistor
            .save(&AlgorithmRecognitionResult::new(ScanMetadata::new(
                "eqmain.dll",
            )))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_algorithm_recognition("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn no_workspace_skips_the_algorithm_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_algorithm_recognition("eqmain.dll").await);
    }

    /// A pipeline over a caller-supplied engine source, workspace included
    /// when there is one.
    fn pipeline_with(
        kuna: calxgloss_kuna::KunaSource,
        workspace: Option<&std::path::Path>,
    ) -> TranslationPipeline {
        let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3").expect("llm config");
        let pipeline = TranslationPipeline::new(kuna, llm, ApiMappings::default());
        match workspace {
            Some(dir) => pipeline.with_workspace(dir.to_path_buf()),
            None => pipeline,
        }
    }

    #[tokio::test]
    async fn a_cached_memory_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = MemoryPersistor::new(dir.path());
        persistor
            .save(&MemoryResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_memory_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_memory_detection("eqmain.dll").await);

        let persistor = MemoryPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("memory")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/memory"
        );
    }

    #[tokio::test]
    async fn a_failed_memory_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_memory_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_memory_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_memory_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_concurrency_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = SyncPersistor::new(dir.path());
        persistor
            .save(&SyncResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_sync_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_concurrency_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_sync_detection("eqmain.dll").await);

        let persistor = SyncPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("sync")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/sync"
        );
    }

    #[tokio::test]
    async fn a_failed_concurrency_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_sync_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_concurrency_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_sync_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_serialization_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = SerializePersistor::new(dir.path());
        persistor
            .save(&SerializeResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_serialize_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_serialization_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_serialize_detection("eqmain.dll").await);

        let persistor = SerializePersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("serialize")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/serialize"
        );
    }

    #[tokio::test]
    async fn a_failed_serialization_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_serialize_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_serialization_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_serialize_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_constant_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = ConstPersistor::new(dir.path());
        persistor
            .save(&ConstResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_const_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_constant_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_const_detection("eqmain.dll").await);

        let persistor = ConstPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("consts")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/consts"
        );
    }

    #[tokio::test]
    async fn a_failed_constant_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_const_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_constant_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_const_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_callback_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = CallbackPersistor::new(dir.path());
        persistor
            .save(&CallbackResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_callback_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_callback_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_callback_detection("eqmain.dll").await);

        let persistor = CallbackPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("callback")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/callback"
        );
    }

    #[tokio::test]
    async fn a_failed_callback_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_callback_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_callback_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_callback_detection("eqmain.dll").await);
    }

    // ─── Type-inference completion latch (issue #238) ────────────────

    /// The latch is a shared one-shot: a waiter that arrived before the
    /// publish is released by it, a waiter that arrives after answers
    /// immediately, and publishing again changes nothing.
    #[tokio::test]
    async fn the_type_inference_latch_is_a_shared_one_shot() {
        let latch = TypeInferenceLatch::new();
        assert!(!latch.is_set(), "a fresh latch has not completed");

        let early = latch.clone();
        let waiting = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(10), early.wait()).await
        });
        // Park the spawned waiter on the unset latch before publishing.
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "an unpublished latch holds the waiter that arrived first"
        );

        let late = latch.clone();
        latch.publish();
        assert!(latch.is_set(), "the publish is the completion");
        latch.publish();

        waiting
            .await
            .expect("the waiting task runs")
            .expect("the publish releases the waiter that arrived first");
        tokio::time::timeout(std::time::Duration::from_secs(1), late.wait())
            .await
            .expect("a waiter that arrives after the publish never blocks");
    }

    /// The edge survives a reversed call order — the shape the fan-out
    /// (#240) gives it: callback detection starts first and waits on
    /// the latch, the inference scan then runs and publishes, and the
    /// callback job composes its contracts from the document inference
    /// just filed. Without the wait the callback scan would have read
    /// an empty workspace and its findings would have lost the
    /// enrichment (issue #173).
    #[tokio::test]
    async fn callback_detection_waits_for_inference_across_a_reversed_call_order() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));
        pipeline.arm_type_inference_latch();

        let job = pipeline
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");
        let callback = tokio::spawn(async move { job.callback_detection().await });
        tokio::task::yield_now().await;
        assert!(
            !callback.is_finished(),
            "the callback job waits on the unpublished latch"
        );

        assert!(
            pipeline.ensure_type_inference("eqmain.dll").await,
            "the inference scan succeeds over the fixture"
        );

        let scanned = tokio::time::timeout(std::time::Duration::from_secs(120), callback)
            .await
            .expect("the published latch releases the callback job — inference never strands it")
            .expect("the callback task runs");
        assert!(scanned, "the callback scan succeeds over the fixture");

        // The enrichment the wait protects: inference's document is in
        // place when the callback job reads it, and it composes real
        // contracts — the fixture's inference records yield fully-read
        // callables.
        assert!(
            TypeInferPersistor::new(dir.path()).exists("eqmain.dll"),
            "the inference document is filed before the callback job reads it"
        );
        assert!(
            !callback_signature_map(dir.path(), "eqmain.dll").is_empty(),
            "the callback scan's closure contracts compose from the inference document"
        );
    }

    /// The wait is real, not incidental: a callback job holding an
    /// unpublished latch is still parked well past the time the same
    /// scan takes over the fixture when it does not wait — and the
    /// publish releases it to a normal successful scan (issue #238).
    #[tokio::test]
    async fn callback_detection_holds_until_the_latch_publishes() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));
        pipeline.arm_type_inference_latch();

        let job = pipeline
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");
        let callback = tokio::spawn(async move { job.callback_detection().await });

        // The fixture callback scan finishes in seconds; a job that
        // skipped the latch would have answered inside this window.
        // The generous margin is what turns a missing wait into a
        // failure rather than a race.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert!(
            !callback.is_finished(),
            "an unpublished latch holds the callback job past the scan's own runtime"
        );

        // The latch lives on the pipeline for the phase; publish through
        // the armed handle, the way the inference scan would.
        pipeline
            .type_inference_latch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("the phase armed a latch")
            .publish();

        let scanned = tokio::time::timeout(std::time::Duration::from_secs(120), callback)
            .await
            .expect("the publish releases the held job")
            .expect("the callback task runs");
        assert!(
            scanned,
            "the released job scans the fixture normally and files its document"
        );
        assert!(
            CallbackPersistor::new(dir.path()).exists("eqmain.dll"),
            "the released scan persists like any other"
        );
    }

    /// A failing type-inference scan leaves callback detection degraded
    /// — no document, no enrichment — never blocked: the latch is
    /// published on the failure path too, exactly as on success
    /// (issue #238).
    #[tokio::test]
    async fn a_failing_type_inference_scan_degrades_callback_detection_never_blocks_it() {
        let dir = TempDir::new().unwrap();
        // `re/analysis/typeinfer` as a plain file makes the inference
        // save fail even though the scan itself succeeds — the same
        // warn-and-continue failure any scan can hit.
        std::fs::create_dir_all(dir.path().join("re").join("analysis")).unwrap();
        std::fs::write(
            dir.path().join("re").join("analysis").join("typeinfer"),
            "not a directory",
        )
        .unwrap();

        let pipeline = pipeline_over(Some(dir.path()));
        pipeline.arm_type_inference_latch();

        let inference = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            pipeline.ensure_type_inference("eqmain.dll"),
        )
        .await
        .expect("a failing inference scan still returns");
        assert!(!inference, "the failed save degrades the inference scan");

        // The failure path published the latch, so the callback job's
        // wait releases even though no document was ever filed.
        let callback = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            pipeline.ensure_callback_detection("eqmain.dll"),
        )
        .await
        .expect("a failed inference scan never blocks callback detection");
        assert!(callback, "the callback scan itself still succeeds");

        assert!(
            !TypeInferPersistor::new(dir.path()).exists("eqmain.dll"),
            "the failed save filed no document"
        );
        assert!(
            callback_signature_map(dir.path(), "eqmain.dll").is_empty(),
            "no document, no enrichment — degraded exactly as today"
        );
        assert!(
            CallbackPersistor::new(dir.path()).exists("eqmain.dll"),
            "callback detection still files its own document, degraded"
        );
    }

    #[tokio::test]
    async fn a_cached_controlflow_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = ControlFlowPersistor::new(dir.path());
        persistor
            .save(&ControlFlowResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_controlflow_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_controlflow_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_controlflow_detection("eqmain.dll").await);

        let persistor = ControlFlowPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("controlflow")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/controlflow"
        );
    }

    #[tokio::test]
    async fn a_failed_controlflow_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_controlflow_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_controlflow_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_controlflow_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_string_context_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = StringContextPersistor::new(dir.path());
        persistor
            .save(&StringContextResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_string_context("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn a_string_context_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_string_context("eqmain.dll").await);

        let persistor = StringContextPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("stringctx")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/stringctx"
        );
        let saved = persistor.load("eqmain.dll").expect("saved document");
        assert!(
            !saved.findings.is_empty(),
            "the fixture's referenced literals should tie to their functions"
        );
    }

    #[tokio::test]
    async fn a_failed_string_context_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_string_context("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_string_context_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_string_context("eqmain.dll").await);
    }

    #[tokio::test]
    async fn a_cached_api_result_is_reused_without_rescanning() {
        let dir = TempDir::new().unwrap();
        let persistor = ApiPersistor::new(dir.path());
        persistor
            .save(&ApiDetectionResult::new(ScanMetadata::new("eqmain.dll")))
            .unwrap();
        let saved = std::fs::read(persistor.path_for("eqmain.dll")).expect("saved document");

        // The fixture engine would rescan successfully, so `true` alone
        // proves nothing: the reuse is proven by the saved document's
        // bytes surviving untouched - a rescan would rewrite them.
        let pipeline = pipeline_over(Some(dir.path()));
        assert!(pipeline.ensure_api_detection("eqmain.dll").await);
        assert_eq!(
            std::fs::read(persistor.path_for("eqmain.dll")).expect("document after recovery"),
            saved,
            "a cached document must not be rewritten by a rescan"
        );
    }

    #[tokio::test]
    async fn an_api_cache_miss_scans_and_saves_the_result() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));

        assert!(pipeline.ensure_api_detection("eqmain.dll").await);

        let persistor = ApiPersistor::new(dir.path());
        assert!(
            persistor.exists("eqmain.dll"),
            "a cache miss should leave a saved document behind"
        );
        assert_eq!(
            persistor.path_for("eqmain.dll"),
            dir.path()
                .join("re")
                .join("analysis")
                .join("apidetect")
                .join("eqmain.dll.json"),
            "the document should be filed under re/analysis/apidetect"
        );
        let saved = persistor.load("eqmain.dll").expect("saved document");
        // The fixture's import table is identified through the seam; the
        // fixture-named callees the call graph extracts map to no PAL
        // library, so the usage path stays quiet here — it is covered by
        // the apidetect crate's own tests.
        assert!(
            saved
                .findings
                .iter()
                .any(|f| f.kind() == "import" && f.target().contains("puts")),
            "the fixture's `puts` import should be identified, got {:?}",
            saved
                .findings
                .iter()
                .map(|f| (f.kind(), f.target()))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_failed_api_save_degrades_instead_of_failing() {
        let dir = TempDir::new().unwrap();
        // `re/analysis` as a plain file makes the save's directory
        // creation fail even though the scan itself succeeds.
        std::fs::create_dir_all(dir.path().join("re")).unwrap();
        std::fs::write(dir.path().join("re").join("analysis"), "not a directory").unwrap();

        let pipeline = pipeline_over(Some(dir.path()));

        assert!(!pipeline.ensure_api_detection("eqmain.dll").await);
    }

    #[tokio::test]
    async fn no_workspace_skips_the_api_scan() {
        let pipeline = pipeline_over(None);
        assert!(!pipeline.ensure_api_detection("eqmain.dll").await);
    }

    // ============================================================
    // The scan cache through the batch pipeline (issue #105)
    // ============================================================

    const PROGRAM: &str = "LaunchPad.exe";

    /// A pipeline over the fixture engine with a workspace holding a copy
    /// of the fixture binary — the bytes both batches hash identically,
    /// the cache's validity key. Returns the pipeline and the copy's path.
    fn cached_pipeline(dir: &std::path::Path) -> (TranslationPipeline, std::path::PathBuf) {
        let fixture = calxgloss_testfixtures::load_target().expect("fixture target");
        let binary_file = dir.join(calxgloss_testfixtures::TARGET_FILE_NAME);
        std::fs::copy(fixture.path(), &binary_file).expect("fixture copied into the workspace");
        let pipeline = pipeline_with(fixture_kuna(), Some(dir)).with_binary_path(&binary_file);
        (pipeline, binary_file)
    }

    /// The one scan-cache document directory the batch built under
    /// `re/cache/{identity}/{sha256}/`.
    fn scan_cache_dir(workspace: &std::path::Path) -> std::path::PathBuf {
        let root = workspace.join("re").join("cache");
        let mut found = Vec::new();
        for identity in std::fs::read_dir(&root).expect("cache root").flatten() {
            for hash in std::fs::read_dir(identity.path())
                .expect("identity dir")
                .flatten()
            {
                let dir = hash.path();
                if dir.join("imports.json").is_file() {
                    found.push(dir);
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "one cache directory for one binary's bytes: {found:?}"
        );
        found.pop().expect("one cache directory")
    }

    /// An import listing the engine could never answer, filed where the
    /// real one was: if a batch's API findings carry it, that read came
    /// off disk — the only possible replay source.
    fn sentinel_imports() -> Vec<calxgloss_decomp::Symbol> {
        vec![calxgloss_decomp::Symbol {
            name: "sentinel_import_xyz".into(),
            address: 1,
            imported: true,
        }]
    }

    /// The marquee: a first batch reads live and writes the scan cache
    /// through, and a second batch over the same workspace with unchanged
    /// binary bytes replays from the cache. With no server to count calls
    /// at, the instrumentation is the documents themselves — the pattern
    /// proven in the seam's cache tests: the import listing is tampered,
    /// and the API scan's persisted findings prove which tier answered.
    /// The engine-result documents are wiped between batches so the scans
    /// genuinely re-run.
    #[tokio::test]
    async fn a_second_batch_over_unchanged_bytes_replays_from_the_cache() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        // Batch 1, cold: the eleven scans read live through the engine and
        // write every answer through to the scan cache.
        pipeline
            .batch_translate(
                calxgloss_testfixtures::TARGET_FILE_NAME,
                &[],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("cold batch over the fixture engine");
        let cache = scan_cache_dir(dir.path());

        // The cold batch also files the rule that keeps the cache out of
        // the workspace repo's commits.
        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore"))
            .expect("the batch run ensures a workspace .gitignore");
        assert!(
            gitignore.lines().any(|line| line.trim() == "re/cache/"),
            "the run leaves re/cache/ ignored in the workspace: {gitignore}"
        );

        // Wipe the engine-result documents so the second batch re-runs all
        // eleven scans — only the scan cache may answer them.
        std::fs::remove_dir_all(dir.path().join("re").join("analysis"))
            .expect("clear engine-result documents");

        // Tamper the import listing; the warm batch's API findings must
        // carry the sentinel if they replayed from disk.
        calxgloss_types::save_json(&cache.join("imports.json"), &sentinel_imports())
            .expect("imports tampered");

        pipeline
            .batch_translate(
                calxgloss_testfixtures::TARGET_FILE_NAME,
                &[],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("warm batch replays from the cache");
        let saved = ApiPersistor::new(dir.path())
            .load(calxgloss_testfixtures::TARGET_FILE_NAME)
            .expect("warm batch's API document");
        assert!(
            saved
                .findings
                .iter()
                .any(|f| f.target() == "sentinel_import_xyz"),
            "the warm batch must replay the tampered document, proving a disk \
             read with no engine round trip: {:?}",
            saved
                .findings
                .iter()
                .map(|f| f.target())
                .collect::<Vec<_>>()
        );
    }

    /// The refresh escape hatch (issue #106): a batch with the flag set
    /// ignores even a warm disk tier — the scans read live again — and
    /// rewrites the cache, so the next batch replays the engine's own
    /// values rather than what the tampering left behind.
    #[tokio::test]
    async fn the_refresh_flag_forces_a_warm_batch_back_to_live_reads() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, binary_file) = cached_pipeline(dir.path());
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        // Batch 1, cold: reads live and writes the cache through.
        pipeline
            .batch_translate(
                calxgloss_testfixtures::TARGET_FILE_NAME,
                &[],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("cold batch over the fixture engine");

        // Wipe the engine-result documents so each later batch re-runs the
        // API scan — only the scan cache may answer it.
        std::fs::remove_dir_all(dir.path().join("re").join("analysis"))
            .expect("clear engine-result documents");

        // Tamper the import listing, then take the refresh escape hatch:
        // same workspace, same bytes, warm disk tier — a refreshing batch
        // ignores it and refetches from the engine.
        let cache = scan_cache_dir(dir.path());
        calxgloss_types::save_json(&cache.join("imports.json"), &sentinel_imports())
            .expect("imports tampered");

        let refreshed = pipeline_with(fixture_kuna(), Some(dir.path()))
            .with_binary_path(binary_file.clone())
            .with_refresh_cache();
        refreshed
            .batch_translate(
                calxgloss_testfixtures::TARGET_FILE_NAME,
                &[],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("a refreshed batch reads live over a warm cache");
        let saved = ApiPersistor::new(dir.path())
            .load(calxgloss_testfixtures::TARGET_FILE_NAME)
            .expect("refreshed document");
        assert!(
            !saved
                .findings
                .iter()
                .any(|f| f.target() == "sentinel_import_xyz"),
            "a refresh refetches live instead of replaying the tampered document"
        );
        assert!(
            saved
                .findings
                .iter()
                .any(|f| f.kind() == "import" && f.target().contains("puts")),
            "the refreshed scan should carry the fixture's own imports"
        );

        // And the refresh rewrote the cache rather than just bypassing it:
        // the import document on disk now carries the engine's listing.
        let on_disk: Vec<calxgloss_decomp::Symbol> =
            calxgloss_types::load_json(&cache.join("imports.json")).expect("rewritten document");
        assert!(
            on_disk.iter().any(|i| i.name.contains("puts"))
                && !on_disk.iter().any(|i| i.name == "sentinel_import_xyz"),
            "the refresh must rewrite the cache, not just bypass it"
        );
    }

    /// Drain every `BatchProgress` beat seen since the last drain.
    fn drain_beats(rx: &mut tokio::sync::broadcast::Receiver<ProgressEvent>) -> Vec<ProgressEvent> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .filter(|ev| matches!(ev, ProgressEvent::BatchProgress { .. }))
            .collect()
    }

    /// Every beat must name the scan phase, not the scan that happened
    /// to be running, and its index must sit inside the listing the
    /// phase is consuming (issue #239).
    fn assert_phase_beats(beats: &[ProgressEvent]) {
        for beat in beats {
            match beat {
                ProgressEvent::BatchProgress {
                    pass, index, total, ..
                } => {
                    assert_eq!(
                        pass, "evidence scans",
                        "the beat names the scan phase, not the scan: {beat}"
                    );
                    assert!(
                        *total > 0 && index <= total,
                        "the index never exceeds the listing size: {beat}"
                    );
                }
                other => unreachable!("drain_beats keeps only beats, got {other:?}"),
            }
        }
    }

    /// The scan phase arms one heartbeat once around the whole group
    /// under the phase name (issue #239): a cold batch's beats name
    /// "evidence scans" and count unique functions consumed — later
    /// scans replaying a body warm from the read cache never push the
    /// index past the listing — and a warm batch replaying every body
    /// from the cache still beats, so a cached binary shows life
    /// (issue #121 preserved).
    #[tokio::test]
    async fn the_scan_phase_beats_under_the_phase_name_cold_and_warm() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let pipeline = pipeline.with_events(events);
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        // Cold batch: the first scan pays the engine and the rest replay
        // warm through the cached source — one phase row either way.
        pipeline
            .batch_translate(
                calxgloss_testfixtures::TARGET_FILE_NAME,
                &[],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("cold batch over the fixture engine");
        let cold = drain_beats(&mut rx);
        assert!(
            !cold.is_empty(),
            "the cold scan phase must beat under the phase name"
        );
        assert_phase_beats(&cold);

        // Wipe the engine-result documents so the second batch re-runs
        // all eleven scans — every body now arrives warm from the read
        // cache, and a warm replay of an already-counted function counts
        // once in the fresh phase's count.
        std::fs::remove_dir_all(dir.path().join("re").join("analysis"))
            .expect("clear engine-result documents");
        pipeline
            .batch_translate(
                calxgloss_testfixtures::TARGET_FILE_NAME,
                &[],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("warm batch replays from the cache");
        let warm = drain_beats(&mut rx);
        assert!(
            !warm.is_empty(),
            "a warm replay must still beat the phase heartbeat (issue #121)"
        );
        assert_phase_beats(&warm);
    }

    /// Cache trouble degrades to plain live reads: with the binary file
    /// missing, the disk tier is dropped entirely and every read passes
    /// straight through to the engine — the batch behaves exactly as an
    /// uncached one, failing the named unit at the engine.
    #[tokio::test]
    async fn a_failed_cache_build_degrades_to_live_reads() {
        let dir = TempDir::new().expect("temp workspace");
        let pipeline =
            pipeline_over(Some(dir.path())).with_binary_path(dir.path().join("absent-binary.dll"));
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let result = pipeline
            .batch_translate(
                PROGRAM,
                &["DrawPrimitive".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("a dropped disk tier degrades — the batch still reports per-function failures");
        assert_eq!(
            result.results.len(),
            1,
            "the unit ran live against the engine, as without the cache"
        );
    }

    // ============================================================
    // The scan-phase fan-out (issue #240)
    // ============================================================

    /// Zero the run-varying scan stamps wherever they sit in a
    /// document's JSON form, so two runs of one scan compare over what
    /// the scan actually recovered (the #237 precedent, generalized to
    /// whole documents).
    fn zero_scan_stamps(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(entries) => {
                for (key, inner) in entries {
                    if key == "scanned_at" || key == "duration_secs" {
                        *inner = serde_json::Value::from(0);
                    } else {
                        zero_scan_stamps(inner);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    zero_scan_stamps(item);
                }
            }
            _ => {}
        }
    }

    /// A persisted document as JSON with the stamps zeroed — the
    /// comparison form for one scan run twice.
    fn stamped_document(document: serde_json::Value) -> serde_json::Value {
        let mut document = document;
        zero_scan_stamps(&mut document);
        document
    }

    /// The fan-out keeps the engine the serial resource it has always
    /// been: across a cold phase's eleven concurrent scans the engine
    /// call log shows every function of the listing exactly once — the
    /// read cache's per-key cell collapses concurrent misses of one
    /// body into a single round trip (issue #240).
    #[tokio::test]
    async fn the_fanned_scan_phase_decompiles_each_function_exactly_once() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;
        pipeline.run_prebatch_scans(PROGRAM).await;

        let calls = pipeline.kuna().decompile_calls();
        assert!(
            !calls.is_empty(),
            "a cold scan phase must take the engine through the listing"
        );
        let mut sorted = calls.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            calls.len(),
            "no function reached the engine twice across the eleven scans: {calls:?}"
        );
    }

    /// The fan-out's marquee: given the same cached reads, the
    /// concurrent phase and the sequential preamble persist the same
    /// eleven documents — findings, order, and callback enrichment
    /// alike (issue #240).
    ///
    /// Both compared runs replay one read cache, warmed by a cold
    /// phase first: the Kuna engine folds each decompile's recovered
    /// types into its program listing, so two cold runs over the same
    /// bytes legitimately see different listings depending on what
    /// decompiled when. With every read pinned by the cache, the only
    /// thing that differs between the compared runs is the schedule —
    /// exactly what the fan-out must not let matter.
    #[tokio::test]
    async fn the_fanned_scan_phase_persists_what_the_sequential_preamble_persisted() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;

        // Warm the read cache with one cold phase, then clear its
        // documents: the compared runs must re-run their scans,
        // replaying the cache rather than short-circuiting on them.
        pipeline.run_prebatch_scans(PROGRAM).await;
        std::fs::remove_dir_all(dir.path().join("re").join("analysis"))
            .expect("cold phase documents cleared");

        // The fanned run: the same phase, warm.
        pipeline.run_prebatch_scans(PROGRAM).await;
        macro_rules! filed {
            ($persistor:ty) => {{
                let loaded = <$persistor>::new(dir.path())
                    .load(PROGRAM)
                    .expect("the scan filed its document");
                serde_json::to_value(loaded).expect("the document serializes for comparison")
            }};
        }
        let fanned = [
            filed!(TypeDatabasePersistor),
            filed!(TypeInferPersistor),
            filed!(AlgorithmPersistor),
            filed!(MemoryPersistor),
            filed!(SyncPersistor),
            filed!(CallbackPersistor),
            filed!(ControlFlowPersistor),
            filed!(StringContextPersistor),
            filed!(ApiPersistor),
            filed!(ConstPersistor),
            filed!(SerializePersistor),
        ];

        // The sequential preamble: the same eleven scans one after the
        // other, in the order they used to run — the inference scan
        // before callback detection, so the enrichment rides in on the
        // workspace document exactly as it did when the scans shared a
        // call order.
        std::fs::remove_dir_all(dir.path().join("re").join("analysis"))
            .expect("fanned documents cleared");
        assert!(pipeline.ensure_type_database(PROGRAM).await);
        assert!(pipeline.ensure_type_inference(PROGRAM).await);
        assert!(pipeline.ensure_algorithm_recognition(PROGRAM).await);
        assert!(pipeline.ensure_memory_detection(PROGRAM).await);
        assert!(pipeline.ensure_sync_detection(PROGRAM).await);
        assert!(pipeline.ensure_callback_detection(PROGRAM).await);
        assert!(pipeline.ensure_controlflow_detection(PROGRAM).await);
        assert!(pipeline.ensure_string_context(PROGRAM).await);
        assert!(pipeline.ensure_api_detection(PROGRAM).await);
        assert!(pipeline.ensure_const_detection(PROGRAM).await);
        assert!(pipeline.ensure_serialize_detection(PROGRAM).await);
        let in_sequence = [
            filed!(TypeDatabasePersistor),
            filed!(TypeInferPersistor),
            filed!(AlgorithmPersistor),
            filed!(MemoryPersistor),
            filed!(SyncPersistor),
            filed!(CallbackPersistor),
            filed!(ControlFlowPersistor),
            filed!(StringContextPersistor),
            filed!(ApiPersistor),
            filed!(ConstPersistor),
            filed!(SerializePersistor),
        ];

        let names = [
            "type database",
            "type inference",
            "algorithm recognition",
            "memory lifecycle",
            "sync detection",
            "callback detection",
            "control flow",
            "string context",
            "api detection",
            "const detection",
            "serialize detection",
        ];
        for ((name, fanned), in_sequence) in names.into_iter().zip(fanned).zip(in_sequence) {
            assert_eq!(
                stamped_document(fanned),
                stamped_document(in_sequence),
                "the fanned {name} document must equal the sequential preamble's"
            );
        }

        // The equality above only means something if the callback scan
        // was enriched on both sides: the fixture's inference records
        // compose real contracts (the #238 precedent), so the callback
        // documents match as enriched documents, not as two degraded ones.
        assert!(
            !callback_signature_map(dir.path(), PROGRAM).is_empty(),
            "the inference document composes real contracts — the callback scan \
             had the enrichment to read, fanned and in sequence alike"
        );
    }

    /// One scan's failure stays its own: with the memory document's
    /// directory sabotaged, the memory scan degrades at its save while
    /// the other ten documents are still filed and the phase still
    /// ends — the group joins all eleven and never cancels a sibling
    /// (issue #240).
    #[tokio::test]
    async fn one_failing_scan_leaves_the_other_ten_persisted() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        // `re/analysis/memory` as a plain file makes the memory
        // persistor's directory creation fail even though its scan
        // succeeds — the existing save-sabotage pattern.
        std::fs::create_dir_all(dir.path().join("re").join("analysis")).expect("analysis dir");
        std::fs::write(
            dir.path().join("re").join("analysis").join("memory"),
            "not a directory",
        )
        .expect("sabotage filed");

        pipeline.begin_cached_source(PROGRAM).await;
        pipeline.run_prebatch_scans(PROGRAM).await;

        let workspace = dir.path();
        assert!(
            !MemoryPersistor::new(workspace).exists(PROGRAM),
            "the sabotaged save left no memory document"
        );
        for (name, filed) in [
            (
                "type database",
                TypeDatabasePersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "type inference",
                TypeInferPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "algorithm recognition",
                AlgorithmPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "sync detection",
                SyncPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "callback detection",
                CallbackPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "control flow",
                ControlFlowPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "string context",
                StringContextPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "api detection",
                ApiPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "const detection",
                ConstPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "serialize detection",
                SerializePersistor::new(workspace).exists(PROGRAM),
            ),
        ] {
            assert!(
                filed,
                "the {name} scan persisted its document despite the memory failure"
            );
        }
    }

    /// The test behind the one named window: the scan phase never runs more
    /// than [`MAX_CONCURRENT_EVIDENCE_SCANS`] scans at a time, and it
    /// genuinely overlaps them — never degenerating to one at a time
    /// (issue #241). Widen the constant and the ceiling assertion follows
    /// the one-line change; break the window in either direction and one of
    /// the two assertions fires.
    #[tokio::test]
    async fn the_scan_phase_window_never_runs_more_than_the_named_cap_at_a_time() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;
        pipeline.run_prebatch_scans(PROGRAM).await;

        let high_water = pipeline.scan_window_high_water();
        assert!(
            high_water >= 2,
            "{high_water} scan(s) at a time means the fan-out degenerated to \
             one at a time — the window must overlap scans"
        );
        assert!(
            high_water <= MAX_CONCURRENT_EVIDENCE_SCANS,
            "at most {MAX_CONCURRENT_EVIDENCE_SCANS} scans may hold a window \
             permit at once; the phase peaked at {high_water}"
        );
    }

    // ============================================================
    // The scan-phase measurement rig (issue #241)
    // ============================================================

    /// The process's peak resident set in MiB — `VmHWM` from
    /// `/proc/self/status`, the same number `/usr/bin/time -v` reports, so
    /// an operator can cross-check the rig's memory figures from outside.
    fn peak_rss_mib() -> u64 {
        let status =
            std::fs::read_to_string("/proc/self/status").expect("/proc/self/status is readable");
        status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb / 1024)
            .expect("VmHWM in /proc/self/status")
    }

    /// Issue #241's measurement rig: time the scan phase over a real target
    /// binary and print the numbers the spec thread records — wall time, the
    /// engine round trips the phase paid (the source's ledger), the window's
    /// high-water mark, the documents filed, and the process's peak resident
    /// set across the phase. The engine is the real one and the binary is a
    /// real one; only the workspace is a scratch directory.
    ///
    /// Cold run: point the workspace at an empty directory — every body
    /// crosses the engine exactly once, which the printed ledger proves.
    /// Parse-only run: keep the workspace's `re/cache` and delete
    /// `re/analysis` — every scan re-runs, every read replays off disk, and
    /// the ledger prints zero engine round trips, so the wall time is the
    /// scans' parse time alone. The sequential baseline (the pre-#240 build)
    /// runs the same rig with the same environment, so the only difference
    /// between the two numbers is the schedule.
    ///
    /// ```text
    /// CALXGLOSS_SCAN_BENCH_BINARY=/path/to/eqmain.dll \
    /// CALXGLOSS_SCAN_BENCH_WORKSPACE=/tmp/scanbench \
    ///   cargo test -p calxgloss-translator --release --lib -- \
    ///   --ignored measure_the_scan_phase -- --nocapture
    /// ```
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "measures the scan phase over a real target binary; needs CALXGLOSS_SCAN_BENCH_BINARY"]
    async fn measure_the_scan_phase_wall_time_on_a_real_target_binary() {
        let binary_path = std::path::PathBuf::from(
            std::env::var("CALXGLOSS_SCAN_BENCH_BINARY")
                .expect("CALXGLOSS_SCAN_BENCH_BINARY: the real target binary to scan"),
        );
        let workspace = std::path::PathBuf::from(
            std::env::var("CALXGLOSS_SCAN_BENCH_WORKSPACE")
                .expect("CALXGLOSS_SCAN_BENCH_WORKSPACE: the workspace to run the phase in"),
        );
        std::fs::create_dir_all(&workspace).expect("bench workspace");
        let binary = binary_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("the binary path has a file name")
            .to_string();

        let kuna = KunaSource::load(&binary_path).expect("the real target must load");
        let listing = kuna
            .list_functions()
            .await
            .expect("the real target must list");
        let pipeline = pipeline_with(kuna.clone(), Some(&workspace)).with_binary_path(&binary_path);
        pipeline.begin_cached_source(&binary).await;

        let rss_before = peak_rss_mib();
        let started = std::time::Instant::now();
        pipeline.run_prebatch_scans(&binary).await;
        let wall = started.elapsed();
        let rss_after = peak_rss_mib();

        let filed = [
            TypeDatabasePersistor::new(&workspace).exists(&binary),
            TypeInferPersistor::new(&workspace).exists(&binary),
            AlgorithmPersistor::new(&workspace).exists(&binary),
            MemoryPersistor::new(&workspace).exists(&binary),
            SyncPersistor::new(&workspace).exists(&binary),
            CallbackPersistor::new(&workspace).exists(&binary),
            ControlFlowPersistor::new(&workspace).exists(&binary),
            StringContextPersistor::new(&workspace).exists(&binary),
            ApiPersistor::new(&workspace).exists(&binary),
            ConstPersistor::new(&workspace).exists(&binary),
            SerializePersistor::new(&workspace).exists(&binary),
        ]
        .into_iter()
        .filter(|exists| *exists)
        .count();

        println!(
            "scan phase over {binary} ({} listed functions, window cap {MAX_CONCURRENT_EVIDENCE_SCANS}):",
            listing.len()
        );
        println!("  wall time:          {wall:?}");
        println!("  engine round trips: {}", kuna.decompile_calls().len());
        println!("  documents filed:    {filed} of 11");
        println!(
            "  window high water:  {}",
            pipeline.scan_window_high_water()
        );
        println!("  peak RSS before:    {rss_before} MiB");
        println!("  peak RSS across:    {rss_after} MiB");
    }

    // ============================================================
    // The owned scan job (issue #237)
    // ============================================================

    /// The fan-out's unit of work: the handle owns every read a scan makes,
    /// is cheap to clone, and is safe to move onto a task (issue #237).
    #[test]
    fn a_scan_job_is_cheap_to_clone_and_safe_to_share_across_tasks() {
        fn assert_handle<T: Send + Sync + Clone>() {}
        assert_handle::<ScanJob>();
    }

    /// The prefactor the fan-out needs: a scan handed to a spawned task
    /// answers exactly like the inline call — same verdict, and the same
    /// persisted document once the wall-clock scan stamp is set aside
    /// (issue #237).
    #[tokio::test]
    async fn a_scan_job_handed_to_a_spawned_task_matches_the_inline_call() {
        let inline_dir = TempDir::new().expect("temp workspace");
        let inline = pipeline_over(Some(inline_dir.path()))
            .ensure_type_database("eqmain.dll")
            .await;
        assert!(inline, "the inline scan succeeds over the fixture");

        let job_dir = TempDir::new().expect("temp workspace");
        let job = pipeline_over(Some(job_dir.path()))
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");
        let spawned = tokio::spawn(async move { job.type_database().await })
            .await
            .expect("the scan task runs to completion");
        assert_eq!(
            spawned, inline,
            "the job on a task answers like the inline call"
        );

        let mut from_task = TypeDatabasePersistor::new(job_dir.path())
            .load("eqmain.dll")
            .expect("the task's document");
        let mut from_inline = TypeDatabasePersistor::new(inline_dir.path())
            .load("eqmain.dll")
            .expect("the inline call's document");
        // The scan stamp is wall-clock, not a finding: zero it so the
        // comparison is over what the scan actually recovered.
        for doc in [&mut from_task, &mut from_inline] {
            doc.metadata.scanned_at = 0;
            doc.metadata.duration_secs = 0;
        }
        assert_eq!(
            from_task, from_inline,
            "the task's persisted document must match the inline call's"
        );
    }

    // ------------------------------------------------------------
    // Callback signature map composition (issue #173)
    // ------------------------------------------------------------

    fn param_reading(function: &str, index: usize, inferred_type: &str) -> InferredType {
        InferredType::Param(InferredParamType {
            function: function.to_string(),
            param_index: index,
            param_name: Some(format!("param_{}", index + 1)),
            inferred_type: inferred_type.to_string(),
            method: InferenceMethod::IntegerBitPattern,
            scope: InferenceScope::Function,
            confidence: Confidence::new(65),
            evidence: format!("{function} masks param_{}", index + 1),
        })
    }

    fn return_reading(function: &str, inferred_type: &str) -> InferredType {
        InferredType::Return(InferredReturnType {
            function: function.to_string(),
            inferred_type: inferred_type.to_string(),
            method: InferenceMethod::ReturnUsage,
            scope: InferenceScope::Function,
            confidence: Confidence::new(65),
            evidence: format!("FUN_caller uses {function}'s return"),
        })
    }

    fn local_reading(function: &str, variable: &str, inferred_type: &str) -> InferredType {
        InferredType::Local(InferredLocalType {
            function: function.to_string(),
            variable_name: variable.to_string(),
            inferred_type: inferred_type.to_string(),
            method: InferenceMethod::AssignmentChain,
            scope: InferenceScope::Function,
            confidence: Confidence::new(60),
            evidence: format!("{function} assigns {variable}"),
        })
    }

    fn typeinfer_document(inferences: Vec<InferredType>) -> TypeInferenceResult {
        let mut result = TypeInferenceResult::new(ScanMetadata::new("eqmain.dll"));
        result.inferences = inferences;
        result
    }

    #[test]
    fn the_signature_map_composes_contracts_from_param_and_return_readings() {
        // `my_handler`'s contract was read on both sides: two
        // parameters its body uses, a return its callers consume.
        // A local record types storage, not the callable; a function
        // with no return reading and one with no parameter readings
        // both stay out — neither contract is fully known.
        let map = compose_signature_map(&typeinfer_document(vec![
            param_reading("my_handler", 0, "i32"),
            param_reading("my_handler", 1, "char *"),
            return_reading("my_handler", "bool"),
            local_reading("my_handler", "local_8", "u32"),
            param_reading("no_return", 0, "u32"),
            return_reading("no_params", "bool"),
        ]));
        assert_eq!(map.len(), 1, "only the fully-read contract joins the map");
        assert_eq!(
            map["my_handler"],
            CallableSignature {
                param_types: vec!["i32".to_string(), "char *".to_string()],
                return_type: Some("bool".to_string()),
            }
        );
    }

    #[test]
    fn record_order_never_matters_and_a_void_return_rides_the_map() {
        // Records arrive in whatever order the scan persisted them;
        // the positions sort out. A `void` return rides as read —
        // dropping the clause is the contract renderer's call, not
        // the composition's.
        let map = compose_signature_map(&typeinfer_document(vec![
            return_reading("notify", "void"),
            param_reading("notify", 1, "u32"),
            param_reading("notify", 0, "char *"),
        ]));
        assert_eq!(
            map["notify"].contract(),
            "Fn(char *, u32)",
            "a void return drops its clause at render time"
        );
    }

    #[test]
    fn a_param_gap_composes_no_entry() {
        // The hole at position 1 proves a middle parameter the
        // records never typed: a contract that skipped it would
        // misplace every type after it, so the function stays out
        // and its suggestion stays open.
        let map = compose_signature_map(&typeinfer_document(vec![
            param_reading("gapped", 0, "i32"),
            param_reading("gapped", 2, "bool"),
            return_reading("gapped", "bool"),
        ]));
        assert!(
            map.is_empty(),
            "a hole in the parameter positions claims nothing"
        );
    }

    #[test]
    fn a_missing_or_corrupt_document_yields_an_empty_map() {
        // The scan degrades silently either way: no document, and a
        // document that will not parse, both compose to nothing.
        let workspace = TempDir::new().expect("temp workspace");
        assert!(
            callback_signature_map(workspace.path(), "eqmain.dll").is_empty(),
            "no cached document, no enrichment"
        );

        let persistor = TypeInferPersistor::new(workspace.path());
        persistor
            .save(&typeinfer_document(vec![
                param_reading("my_handler", 0, "i32"),
                return_reading("my_handler", "bool"),
            ]))
            .expect("save");
        assert_eq!(
            callback_signature_map(workspace.path(), "eqmain.dll").len(),
            1,
            "a cached document feeds the enrichment"
        );

        std::fs::write(persistor.path_for("eqmain.dll"), "{ not json").expect("corrupt write");
        assert!(
            callback_signature_map(workspace.path(), "eqmain.dll").is_empty(),
            "a corrupt document degrades the scan, never fails it"
        );
    }
}

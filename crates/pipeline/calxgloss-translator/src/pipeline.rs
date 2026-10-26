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
//! A pass is described by [`PipelineSpec`](assembly::PipelineSpec) and wired
//! by [`assemble`](assembly::assemble) — the pipeline's constructor is
//! assembly-internal, so a hand-built pipeline does not compile outside the
//! seam (issue #328).
//!
//! ```no_run
//! use calxgloss_kuna::KunaSource;
//! use calxgloss_llm::LlmClient;
//! use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
//! let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
//! let spec = PipelineSpec {
//!     llm: Some(LlmSelection::Client(llm)),
//!     workspace: std::env::current_dir()?,
//!     ..PipelineSpec::default()
//! };
//! let pass = assemble(&spec, &engine).await?;
//!
//! let translation = pass.pipeline.translate("game_logic.dll", "DrawSprite").await?;
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
    BinaryIdentity, ContextTier, FunctionInfo, PipelineControl, PipelineState, ProgressEvent,
    ScopeControl, StopSignal, TestCase, TranslationEvents, TranslationRequest, UnitCancellation,
};
use calxgloss_verify::Verifier;
use tokio::task::JoinSet;
use tracing::{debug, info, instrument, warn};

use crate::Translation;
use crate::batch;
use crate::error::{Result, TranslatorError};
use crate::retry;
use crate::scan_job::ScanJob;
use crate::scan_registry::{ScanDescriptor, ScanLatches, arm_completion_latches, scan_rows};

/// The pass name the scan phase's heartbeat carries: one honest
/// "n of m functions consumed" row for the whole group of fifteen
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
/// [`ScanJob`] and hands back the boxed scan future. The scans' futures
/// are distinct types, so the window boxes them to move them onto tasks
/// (issue #240). Registered rows enter as capturing thunks, hence the
/// boxed `FnOnce` rather than the plain `fn` pointer this was (issue #302).
type EvidenceScanTask =
    Box<dyn FnOnce(ScanJob) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

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

/// One registered row as the phase runs it: the row reads the batch
/// through the job's owned context, carries the completion latches the
/// phase armed for its declared dependency edge, and reports its own
/// outcome; the phase's window, heartbeat, and joins wrap it from
/// outside (issues #302, #305).
async fn run_registered_scan(row: ScanDescriptor, job: ScanJob, latches: ScanLatches) {
    let mut ctx = job.scan_context();
    ctx.latches = latches;
    row.run(ctx).await;
}

/// The registered rows as task-ready thunks: each row moves into its own
/// thunk, boxed so the window can move it onto a task (issue #240).
/// The phase's completion latches are wired onto each row's context from
/// the table's own declarations — the latch armed for this row's name is
/// the one its run publishes on every exit, and the latch named by its
/// `waits_for` is the one its pre-scan hook waits on (issue #305). No
/// row names a latch field of its own; the edge is table data, and this
/// is the only way a scan enters the phase (issue #308).
fn registered_scan_tasks() -> Vec<EvidenceScanTask> {
    let rows = scan_rows();
    let armed = arm_completion_latches(&rows);
    rows.into_iter()
        .map(|row| -> EvidenceScanTask {
            let publish = armed
                .iter()
                .find(|(name, _)| *name == row.name())
                .map(|(_, latch)| latch.clone());
            let wait = row.waits_for().and_then(|producer| {
                armed
                    .iter()
                    .find(|(name, _)| *name == producer)
                    .map(|(_, latch)| latch.clone())
            });
            Box::new(move |job: ScanJob| {
                Box::pin(run_registered_scan(row, job, ScanLatches { publish, wait }))
            })
        })
        .collect()
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
/// The constructor is assembly-internal: the only way to bring a pipeline
/// into existence is to describe the pass — a
/// [`PipelineSpec`](crate::assembly::PipelineSpec) — and assemble it with
/// [`assemble`](crate::assembly::assemble) (or
/// [`assemble_patch`](crate::assembly::assemble_patch) for a pass that
/// loads its own engine). Hand-building one outside the pipeline
/// context's assembly does not compile (issue #328).
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

    /// Port to the git history's accepted (merged) translations, for
    /// carry-over seeding (issue #299).
    ///
    /// Set by the CLI when git is enabled; `None` everywhere else, which
    /// keeps the queue exactly as it is today. The translator never touches
    /// git itself — this trait object is the only window onto it, the same
    /// port pattern the version-pairing trigger uses.
    accepted_attempt_source: Option<Arc<dyn crate::carry_over::AcceptedAttemptSource>>,

    /// The current batch's carry-over seeds, keyed by new-function name.
    ///
    /// Collected once per batch by
    /// [`refresh_carry_over_seeds`](Self::refresh_carry_over_seeds) — right
    /// after the pre-batch scans, when the pairing documents for this run's
    /// bytes exist — and read by [`translate`](Self::translate) per unit.
    /// Empty outside a seeded batch; one batch covers one binary, so the
    /// keys cannot collide.
    carry_over_seeds: Mutex<HashMap<String, crate::carry_over::CarryOverSeed>>,

    /// The batch's shared cached scan source, armed by
    /// [`begin_cached_source`](Self::begin_cached_source) at the top of a
    /// batch and read by every scan, the call-graph build, and the
    /// retry/escalation helpers through [`scan_source`](Self::scan_source).
    ///
    /// A second batch over the same workspace and unchanged binary replays
    /// from the disk tier with zero live reads.
    cached_source: Mutex<Option<CachedScanSource>>,

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
    /// Create a new translation pipeline over a loaded Kuna program, an LLM
    /// client, and a PAL mapping table.
    ///
    /// This sets up the full pipeline with the default analyzer.
    /// A context-window detector is initialized with the LLM client's
    /// `context_window` setting for automatic fault detection.
    ///
    /// **Assembly-internal** (issue #328): this constructor and every
    /// `with_*` setter below it form the wiring surface of the
    /// [`assembly`](crate::assembly) module — [`wire_pass`](crate::assembly)
    /// is the only production caller across the workspace, pinned at source
    /// level by the seam's own test suite. Outside this crate the compiler
    /// refuses a hand-built pipeline; in-crate tests may wire one directly
    /// to pin behavior around the seam.
    pub(crate) fn new(kuna: KunaSource, llm: LlmClient, api_mappings: ApiMappings) -> Self {
        let analyzer = Analyzer::new(PipelineSource::Kuna(kuna.clone()), api_mappings.clone());
        let context_detector = ContextWindowDetector::new(llm.context_window());
        Self {
            kuna,
            llm,
            api_mappings,
            analyzer,
            root_detector: calxgloss_callgraph::RootDetector::new(),
            testgen: None,
            target_binary: None,
            workspace: None,
            events: None,
            context_detector,
            hallucination_detector: None,
            no_callgraph: AtomicBool::new(false),
            callgraph_verbose: false,
            callgraph_cache_dir: None,
            binary_path: None,
            accepted_attempt_source: None,
            carry_over_seeds: Mutex::new(HashMap::new()),
            cached_source: Mutex::new(None),
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
    pub(crate) fn with_no_callgraph(self) -> Self {
        self.no_callgraph.store(true, Ordering::Relaxed);
        self
    }

    /// Enable call-graph statistics output.
    ///
    /// When set, [`translate`](Self::translate) prints a summary of call graph
    /// statistics (function count, root/middle/leaf breakdown, call-type
    /// distribution, external API count) after the graph is built.
    pub(crate) fn with_callgraph_verbose(mut self) -> Self {
        self.callgraph_verbose = true;
        self
    }

    /// Set the workspace root path for experiment logging.
    ///
    /// When set, every translation attempt is recorded to
    /// `<workspace>/re/analysis/prompt_strategy_log.json`.
    pub(crate) fn with_workspace(mut self, workspace: impl Into<std::path::PathBuf>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    /// Attach a progress event emitter for live WebSocket streaming.
    ///
    /// When set, the pipeline emits [`ProgressEvent`] instances at every
    /// major milestone. Subscribers to the channel (typically a WebSocket
    /// server) can relay these events to connected clients in real time.
    pub(crate) fn with_events(mut self, events: TranslationEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// Attach a shared stop signal for graceful shutdown of a live run.
    ///
    /// When the signal is stopped (e.g. by the web server's shutdown
    /// endpoint), the batch loops break at the next **unit boundary**: the
    /// unit in flight completes and its result is persisted before the run
    /// stops.
    pub(crate) fn with_stop_signal(mut self, stop: StopSignal) -> Self {
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
    pub(crate) fn with_pipeline_control(mut self, control: PipelineControl) -> Self {
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
    pub(crate) fn with_unit_cancellation(mut self, cancellation: UnitCancellation) -> Self {
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
    pub(crate) fn with_scope(mut self, scope: ScopeControl) -> Self {
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
    pub(crate) fn with_overrides(mut self, overrides: calxgloss_types::OverrideControl) -> Self {
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
    pub(crate) fn with_testgen(mut self, testgen: TestGenerator) -> Self {
        self.testgen = Some(testgen);
        self
    }

    /// Set the target binary name for test generation context.
    pub(crate) fn with_target_binary(mut self, binary: impl Into<BinaryIdentity>) -> Self {
        self.target_binary = Some(binary.into());
        self
    }

    /// Attach a pre-built hallucination detector for validating LLM
    /// responses.  Call this after `new()` when a runtime context is
    /// available; skip it in unit tests that don't need detection.
    pub(crate) fn with_hallucination_detector(mut self, detector: HallucinationDetector) -> Self {
        self.hallucination_detector = Some(detector);
        self
    }

    /// Set an explicit cache directory for call graph JSON files.
    ///
    /// When set, call graphs are saved to and loaded from this directory
    /// instead of the default `{workspace}/re/analysis/` path.
    pub(crate) fn with_callgraph_cache_dir(
        mut self,
        cache_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
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
    pub(crate) fn with_binary_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Wire the port to the git history's accepted translations, enabling
    /// carry-over seeding for this pipeline's batches (issue #299).
    ///
    /// A batch then seeds attempt 1 of every function that is confidently
    /// paired (per the pairing documents the scan step leaves behind) with a
    /// previous-version twin whose translation is accepted — the code rides
    /// in verbatim and faces the same baseline capture and full
    /// verification against the new bytes. Without this, or without a
    /// workspace and binary path also set, batches translate fresh exactly
    /// as today.
    pub(crate) fn with_accepted_attempt_source(
        mut self,
        source: Arc<dyn crate::carry_over::AcceptedAttemptSource>,
    ) -> Self {
        self.accepted_attempt_source = Some(source);
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
    pub(crate) fn with_refresh_cache(mut self) -> Self {
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
    /// use calxgloss_kuna::KunaSource;
    /// use calxgloss_llm::LlmClient;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    ///
    /// let translation = pass.pipeline.translate("game_logic.dll", "DrawSprite").await?;
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

        // Body-shape guard (issue #269): an import thunk the symbol table
        // named after its import — `SetCursor` carrying only
        // `SetCursor(); return;` — matches no name-based root pattern, but
        // its body is one unconditional call to its own name. Refuse it
        // here, before the prompt is built and any token is spent: the LLM
        // would faithfully translate the apparent recursion into a Rust
        // function that calls itself.
        self.refuse_self_call_thunk(binary, function, &function_info.decompiler_output)?;

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

        // Step 3: Generate baseline test inputs. The control-flow
        // document loads once here and serves both consumers: its
        // branch-site records target the baseline suite, and its
        // findings ride into the prompt's CONTROL FLOW section below —
        // one source of truth for the LLM's context and its test
        // oracle (issue #261). A missing or corrupt document loads as
        // nothing, leaving generation at exactly today's suite.
        let control_flow =
            crate::retry::helpers::load_control_flow_result(self.workspace.as_deref(), binary);
        let branch_inventory =
            crate::retry::helpers::branch_inventory_of(control_flow.as_ref(), function);
        let baseline_tests = self
            .generate_baseline_tests(&function_info, &imports, &branch_inventory)
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
        // Build and enrich from the engine — the auto/translate/batch passes
        // that own a pre-built graph route it through
        // `batch_translate_from_callgraph`, which takes the graph as an
        // argument; the pipeline never carried one (issue #328 retired the
        // never-called `with_call_graph`).
        let enriched_context: Vec<FunctionContext> = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
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

        // Carry-over seeding (issue #299): when a pairing document pairs
        // this function confidently with a previous-version twin whose
        // translation was *accepted* (a merged review branch), attempt 1
        // carries that code — no prompt built, no LLM called, no tokens
        // spent. Everything deterministic still runs: the scan fetch and
        // root refusals above, the baseline tests and tier selection just
        // above, and the full verification against the NEW binary's bytes
        // in the retry loop ahead — the accepted translation is a
        // hypothesis the new bytes get to reject, and a rejection hands the
        // unit to the fresh attempt chain like any other failed attempt.
        // Nothing here marks the unit verified; the review overlay's model
        // (ADR-0003) is untouched — the new branch starts unmerged.
        if let Some(seed) = self
            .carry_over_seeds
            .lock()
            .expect("carry-over seeds lock")
            .get(function)
            .cloned()
        {
            info!(
                binary,
                function,
                old_function = %seed.old_function,
                old_attempt = seed.old_attempt,
                family = seed.family,
                confidence = seed.confidence,
                "Seeding attempt 1 from the accepted translation of the paired previous-version function"
            );
            return Ok(Translation {
                binary: binary.to_string().into(),
                function: function.to_string(),
                function_address: Some(function_info.address),
                rust_code: seed.rust_code,
                // No prompt was sent; the record says what rode in instead.
                prompt_used: format!(
                    "carry-over seed: {} attempt {} (paired, {} family, {}% confidence) — no prompt sent, no LLM call",
                    seed.old_function, seed.old_attempt, seed.family, seed.confidence
                ),
                model: "carry-over".to_string(),
                tokens_used: None,
                baseline_tests,
                call_graph: function_info.call_graph.clone(),
                call_graph_context: enriched_context,
                disassembly_hints: function_info.disassembly_hints.clone(),
                context_tier: tier,
            });
        }

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
                // One gather over the analyzer caches (issue #268); the
                // call-graph lists and the in-memory control-flow result
                // ride in on top of it.
                let mut evidence = crate::retry::helpers::gather_function_evidence(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                    &function_info.call_graph,
                );
                evidence.call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                evidence.neighboring_functions =
                    crate::retry::helpers::extract_neighboring_context(
                        &self.scan_source(),
                        &function_info.call_graph,
                    )
                    .await;
                evidence.call_graph_context = enriched_context.clone();
                evidence.control_flow_findings =
                    crate::retry::helpers::control_flow_hints_from(control_flow.as_ref(), function);
                calxgloss_prompts::build_module_context_prompt(&request, evidence)?
            }
            ContextTier::FullModule => {
                // Tier 4: Full module context + shim layer code + PAL trait definitions
                let mut evidence = crate::retry::helpers::gather_function_evidence(
                    self.workspace.as_deref(),
                    &function_info.binary,
                    function,
                    &function_info.call_graph,
                );
                evidence.call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                evidence.neighboring_functions =
                    crate::retry::helpers::extract_neighboring_context(
                        &self.scan_source(),
                        &function_info.call_graph,
                    )
                    .await;
                evidence.call_graph_context = enriched_context.clone();
                evidence.control_flow_findings =
                    crate::retry::helpers::control_flow_hints_from(control_flow.as_ref(), function);

                // Extract shim layer code from the workspace
                let shim_layers = crate::retry::helpers::extract_shim_layers(
                    self.workspace.as_deref(),
                    &function_info.binary,
                );

                // Extract PAL trait definitions from the function's Windows API categories
                let pal_traits =
                    crate::retry::helpers::extract_pal_traits(&function_info.windows_apis);

                calxgloss_prompts::build_full_module_prompt(
                    &request,
                    evidence,
                    shim_layers,
                    pal_traits,
                )?
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

        // Same body-shape guard as [`translate`](Self::translate): a
        // pre-built request carrying a thunk's self-call body is no reason
        // to spend LLM tokens on a veneer that owns no logic.
        self.refuse_self_call_thunk(
            &request.binary,
            &request.function,
            &request.decompiler_output,
        )?;

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
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     workspace: Path::new("/tmp/calxgloss-work").to_path_buf(),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// let result = pass.pipeline.try_translate_with_retry(
    ///     "game_logic.dll",
    ///     "DrawSprite",
    ///     &pass.retry,
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

    /// Refuse a translate request for a function whose whole decompiled
    /// body is one unconditional call to its own name — an import thunk the
    /// decompiler renders as a self-call (issue #269).
    ///
    /// The name-based root patterns cannot see these: the symbol table names
    /// the veneer after the import it tail-jumps to, so `SetCursor` carries
    /// no `thunk_` marker and matches no pattern. The body shape is the
    /// tell, and unlike the name guard this one can only run once the body
    /// is in hand — but still before the prompt is built and any LLM token
    /// is spent. The reason names the shape so the operator learns the same
    /// *why* the root patterns give: the veneer owns no logic, and the
    /// caller's translation reaches the real API through the PAL mappings.
    /// A genuinely recursive function — a self-call inside real logic, with
    /// a base case — is not this shape and is never refused here.
    fn refuse_self_call_thunk(
        &self,
        binary: &str,
        function: &str,
        decompiler_output: &str,
    ) -> Result<()> {
        if crate::triage::is_self_call_thunk(function, decompiler_output) {
            warn!(
                binary,
                function,
                "Refusing to translate a function whose whole body is a call to its own name — an import thunk the decompiler renders as a self-call"
            );
            return Err(TranslatorError::SkippedRoot {
                binary: binary.to_string(),
                function: function.to_string(),
                reason: "import thunk decompiled as a self-call (the body is only a call to its own name)".to_string(),
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

    /// Generate baseline test inputs for a function, targeted at the
    /// branch sites the loaded control-flow findings inventoried for it
    /// (issue #261). An empty inventory — no records, or no usable
    /// document — is today's suite exactly.
    async fn generate_baseline_tests(
        &self,
        function_info: &FunctionInfo,
        _imports: &[String],
        branch_inventory: &[calxgloss_controlflow::types::BranchSite],
    ) -> Result<Vec<TestCase>> {
        // The signature the decompiler inferred, used to derive the
        // parameters the test cases feed in.
        let signature = self.signature_for(function_info);

        // Generate test inputs from signature, disassembly, and the
        // branch inventory: one case per branch target, deduplicated
        // against the boundary cases and capped per function.
        let mut tests = calxgloss_testgen::generate_test_inputs(
            &signature,
            &function_info.disassembly,
            branch_inventory,
        )
        .map_err(TranslatorError::TestGen)?;

        // The global-state artifact supplies the typed side-effect
        // expectations: when a persisted global-state document names
        // globals for this function, every test case carries them as
        // GlobalRead/GlobalWrite expectations naming each global — a
        // global side effect is a named kind, never an Other string.
        // No document (the scan has not run) or a corrupt one leaves
        // the expectations empty, exactly as before.
        if let Some(workspace) = self.workspace.as_deref() {
            let expectations = calxgloss_testgen::global_state_expectations(
                workspace,
                &function_info.binary,
                &function_info.name,
            );
            if !expectations.is_empty() {
                for test in &mut tests {
                    test.expected_side_effects.clone_from(&expectations);
                }
            }
        }

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
    ///
    /// A signature that names no calling convention — a usable line without a
    /// convention word, or the placeholder — gets the convention the scan
    /// detected for this function spelled in, so the FFI binding built from
    /// the same string calls the original with the right convention instead
    /// of the blanket `__stdcall` (issue #251, part of #226). A decompiler
    /// line that names one still wins: the line is the better witness of the
    /// function itself. Microsoft x64 has no C word to spell — the default
    /// ABI already is the x64 convention — so it leaves the convention slot
    /// empty rather than inventing a spelling. With no convention record, or
    /// no artifact to hold one, today's default spelling stands untouched.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn signature_for(&self, function_info: &FunctionInfo) -> String {
        let detected = self.detected_convention(&function_info.binary, &function_info.name);

        if let Some(parsed) =
            calxgloss_decomp::parse::parse_decompiled(&function_info.decompiler_output)
        {
            // Spell the detected convention only where the line named none,
            // and only when the convention has a C spelling at all.
            if let Some(spelling) = detected
                .and_then(|convention| convention.c_spelling())
                .filter(|_| !names_convention(&parsed.signature))
                && let Some(refined) = spell_convention(&parsed.signature, spelling)
            {
                return refined;
            }
            return parsed.signature;
        }

        warn!(
            function = %function_info.name,
            "No signature in the decompiled output; falling back to a parameter-less one"
        );
        // The default `__stdcall` stands only when no record read a
        // convention; a record that did spells its own word, and the x64
        // record spells none because the parser's default already fits.
        let convention = match detected {
            Some(convention) => convention.c_spelling().unwrap_or_default(),
            None => "__stdcall",
        };
        if convention.is_empty() {
            format!("int {}()", function_info.name)
        } else {
            format!("int {convention} {}()", function_info.name)
        }
    }

    /// The convention the persisted type-inference record detected for this
    /// function (issue #251, part of #226). Only the function's own record
    /// spells its signature: a call-site view of a callee's convention keys
    /// beside the caller's records and must never be mistaken for the
    /// caller's own. A missing workspace, a missing or corrupt artifact, or
    /// no convention record yields none, leaving the existing default
    /// spelling in force.
    fn detected_convention(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_typeinfer::types::CallingConvention> {
        let workspace = self.workspace.as_deref()?;
        let result = match TypeInferPersistor::new(workspace).load(binary) {
            Ok(result) => result,
            Err(error) => {
                debug!(
                    binary,
                    error = %error,
                    "No usable type inference result; synthesizing the signature without a detected convention"
                );
                return None;
            }
        };
        result.for_function(function).find_map(|inference| {
            match inference {
                // The engine resolves to one convention per function, so the
                // first own-convention record is the whole answer; call-site
                // views (callee spelled) stay out.
                InferredType::Convention(record) if record.callee.is_none() => {
                    Some(record.convention)
                }
                _ => None,
            }
        })
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
        }

        // Hallucination detection: scan the generated code for non-existent
        // API/function references.  When hallucinations are found, log a
        // warning and emit a progress event so the caller can react.
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

    /// The read source every batch consumer — the [`ScanJob`]s the fifteen
    /// registered scans build, the call-graph build, and the
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
    /// shared read source as currently armed — so the scan borrows
    /// nothing from the batch and a caller can move the job onto a task.
    /// `None` when no workspace is configured, which is every scan's skip
    /// condition. The pass heartbeat is the phase's, not the job's (issue
    /// #239), and the scan-phase ordering lives on the registry's rows,
    /// not on the job (issue #305).
    fn scan_job(&self, binary: &str) -> Option<ScanJob> {
        let workspace = self.workspace.as_deref()?;
        Some(ScanJob::new(binary, workspace, self.scan_source()))
    }

    /// Run the fifteen pre-batch evidence scans, the shared scan-phase
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
    /// spawn order is the rows' order — [`scan_rows`] — but that
    /// order is only the order the scans enter the window. Exactly-once
    /// decompilation is preserved by construction, not by new locking:
    /// the read cache's per-key cell collapses concurrent misses of one
    /// body into one engine request, so the engine stays the serial
    /// resource the racing scans share safely.
    ///
    /// Each scan keeps its own shape: a cached document short-circuits it
    /// before any engine read, and a failed scan or save only warns and
    /// continues — one detector's failure never takes down the batch. The
    /// The group joins all fifteen and never cancels its siblings.
    ///
    /// The one real ordering edge between the scans — callback detection
    /// composing its closure contracts from the type-inference
    /// document — is a declared row dependency: the phase arms a fresh
    /// completion latch per declared producer ([`arm_completion_latches`])
    /// and the inference row publishes its latch on every exit while the
    /// callback row waits on it, so the edge is explicit table data
    /// rather than any call order (issues #238, #305).
    ///
    /// The phase also arms the engine heartbeat once around the whole
    /// group, under the phase name, and disarms it when the group ends:
    /// the dashboard shows one honest "n of m functions consumed" row
    /// for the scan phase instead of fifteen that restart with each
    /// scan. Beats count unique functions consumed — a body pulled cold
    /// from the engine and replayed warm by the read cache counts once —
    /// so a warm run still shows life and the row stays honest while the
    /// scans interleave (issue #239, preserving #121).
    async fn run_prebatch_scans(&self, binary: &str) {
        self.begin_scan_pass(binary, SCAN_PHASE);
        let Some(job) = self.scan_job(binary) else {
            debug!(
                binary,
                "No workspace configured; skipping the pre-batch evidence scans"
            );
            self.end_scan_pass();
            return;
        };
        let mut scans = registered_scan_tasks().into_iter();
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
        // scan, and the group joins all fifteen — a failing or panicking
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

        // P18's version-change trigger (issue #298): the scan step has
        // just written the current version's scan documents through. Pair
        // this scan against any surviving scan of the same identity — the
        // sibling hash directories under `re/cache/{identity}/` — exactly
        // once per (old, new) hash pair; a later pass reuses the persisted
        // document. Document-level only: no engine reads (ADR-0026), no
        // LLM, milliseconds — and with no sibling directory it writes
        // nothing, leaving the queue's behavior exactly as today.
        if let (Some(workspace), Some(binary_path)) =
            (self.workspace.as_deref(), self.binary_path.as_deref())
        {
            crate::version_pairing::pair_previous_versions(workspace, binary, binary_path);
        }
    }

    /// Collect this batch's carry-over seeds (issue #299), immediately after
    /// [`run_prebatch_scans`] wrote the pairing documents for the bytes being
    /// translated now.
    ///
    /// One directory pass, one hash, and one accepted-code lookup per paired
    /// candidate — milliseconds against an LLM batch. With no port wired, no
    /// workspace or binary path, no eligible documents, or no accepted twin
    /// for a function, the map stays empty and every unit translates fresh,
    /// byte for byte like today. Never fails the batch: the documents are
    /// context a consumer may use, not an input it requires.
    fn refresh_carry_over_seeds(&self, binary: &str, functions: &[String]) {
        let mut seeds = self.carry_over_seeds.lock().expect("carry-over seeds lock");
        seeds.clear();
        let (Some(source), Some(workspace), Some(binary_path)) = (
            self.accepted_attempt_source.as_ref(),
            self.workspace.as_deref(),
            self.binary_path.as_deref(),
        ) else {
            return;
        };
        if functions.is_empty() {
            return;
        }
        let collected =
            crate::carry_over::collect_seeds(workspace, binary, binary_path, functions, source);
        if !collected.is_empty() {
            info!(
                binary,
                seeds = collected.len(),
                "Carry-over: attempt 1 will seed from accepted translations of paired functions"
            );
        }
        *seeds = collected;
    }

    /// Attach the carry-over provenance to a completed unit's result
    /// (issue #299): the record names the old function and attempt branch
    /// the winning code rode in on, so the batch callback's commit message
    /// and any reader of the record can see where attempt 1's code came
    /// from.
    ///
    /// Attached only when the unit succeeded **with the seed's code** — if
    /// the fresh chain won, the code is the LLM's, and claiming a carry-over
    /// would be false provenance.
    fn attach_carry_over_provenance(&self, result: &mut batch::FunctionResult) {
        if !result.success {
            return;
        }
        let seed = self
            .carry_over_seeds
            .lock()
            .expect("carry-over seeds lock")
            .get(&result.function)
            .cloned();
        let (Some(seed), Some(code)) = (seed, result.rust_code.as_deref()) else {
            return;
        };
        if code == seed.rust_code {
            result.carry_over = Some(crate::carry_over::CarryOverRecord {
                old_function: seed.old_function,
                old_attempt: seed.old_attempt,
                family: seed.family,
                confidence: seed.confidence,
            });
        }
    }

    /// The most evidence scans that ran at once during the latest scan
    /// phase (issue #241) — the fan-out window's high-water mark, recorded
    /// by [`run_scan_in_window`] as each scan enters the window. Zero when
    /// no phase has run, or when the phase skipped for want of a workspace.
    pub fn scan_window_high_water(&self) -> usize {
        self.scan_window_high_water.load(Ordering::SeqCst)
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
    /// memory, and concurrency context — the fifteen evidence scans run through
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
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     workspace: Path::new("/tmp/calxgloss-work").to_path_buf(),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// let functions = vec!["DrawSprite".to_string(), "UpdatePosition".to_string()];
    /// let results = pass.pipeline.batch_translate(
    ///     "game_logic.dll",
    ///     &functions,
    ///     &pass.retry,
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
    /// When the workspace holds a persisted global-state document for the
    /// graph's binary, the ordering is further extended by state-sharing
    /// edges: within a tier, a global's first definer precedes the units
    /// that reuse it (issue #256). No document leaves today's order intact.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph to plan from.
    /// * `max_functions` — Optional limit on the number of functions in the plan.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_callgraph::CallGraph;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    ///
    /// // Build or load the call graph first (e.g. via Analyzer::build_call_graph)
    /// let call_graph = /* CallGraph */ todo!();
    ///
    /// // Get a priority-ordered plan (max 100 functions)
    /// let plan = pass.pipeline.plan_from_callgraph(&call_graph, Some(100))?;
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
        // State-sharing edges from the persisted shared-globals index
        // extend the ordering when the global-state scan has run for this
        // binary (issue #256); the plan reads the artifact, it never runs
        // the scan.
        orderer = orderer.with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;
        Ok(plan.into_iter().collect())
    }

    /// The state-sharing edges the persisted shared-globals index names for
    /// this binary (issue #256, part of #225). The orderer consumes the
    /// artifact the global-state scan wrote; it never runs the scan itself.
    /// A missing workspace, a missing or corrupt document yields an empty
    /// set, leaving today's dependency order exactly in force.
    fn state_sharing_edges(&self, binary: &str) -> calxgloss_callgraph::StateSharingEdges {
        let Some(workspace) = self.workspace.as_deref() else {
            return calxgloss_callgraph::StateSharingEdges::default();
        };
        let persistor = calxgloss_globalstate::persist::GlobalStatePersistor::new(workspace);
        match persistor.load(binary) {
            Ok(result) => calxgloss_callgraph::StateSharingEdges::from_pairs(
                calxgloss_globalstate::rollup::state_sharing_pairs(
                    result.findings.iter().filter_map(
                        calxgloss_globalstate::types::GlobalStateFinding::shared_global,
                    ),
                ),
            ),
            Err(error) => {
                debug!(
                    binary,
                    error = %error,
                    "No usable global-state result; ordering without state-sharing edges"
                );
                calxgloss_callgraph::StateSharingEdges::default()
            }
        }
    }

    /// Performs batch translation of the specified functions within a binary.
    ///
    /// Returns a `BatchTranslationResult` containing the translation outcomes for each function.
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

        // Carry-over seeding (issue #299): the scan step just persisted the
        // pairing documents for these exact bytes; collect the seeds for
        // this queue now, so the batch's inputs are fixed before its first
        // unit starts.
        self.refresh_carry_over_seeds(binary, &functions);

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

            // Carry-over provenance (issue #299): when attempt 1 rode in on
            // an accepted translation and that code is what succeeded, say
            // so on the record — the git callback's commit message reads it.
            self.attach_carry_over_provenance(&mut result);

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
    /// memory, and concurrency context — the fifteen evidence scans run through
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
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_analysis::build_enriched_call_graph;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// // Build or load the enriched call graph first (reads through the seam)
    /// let call_graph = build_enriched_call_graph(
    ///     &calxgloss_decomp::PipelineSource::from(engine.clone()),
    ///     "game_logic.dll",
    ///     Path::new("/tmp/calxgloss-work"),
    ///     None,
    /// ).await?;
    ///
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    ///
    /// let results = pass.pipeline.batch_translate_from_callgraph(
    ///     &call_graph,
    ///     &pass.retry,
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

        // Build a priority-ordered plan, extended by the persisted
        // shared-globals index when the global-state scan has run for
        // this binary (issue #256) — a read of the artifact, never a scan.
        let orderer = calxgloss_callgraph::TranslationOrderer::new()
            .with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;

        let plan: Vec<_> = plan.into_iter().collect();
        let binary = &graph.binary;

        // W2.5: operator scope — skipped functions leave the plan before the
        // first unit starts, priority functions sort to the front.
        let plan = self.apply_function_scope(binary, plan, |p| p.name.as_str());

        // Carry-over seeding (issue #299): pairing documents for these exact
        // bytes were persisted by the scan step; collect the seeds for this
        // plan before its first unit starts.
        let queue_names: Vec<String> = plan.iter().map(|p| p.name.clone()).collect();
        self.refresh_carry_over_seeds(binary, &queue_names);

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

            // A refused root — a name-pattern root that reached the unit
            // anyway, or a self-call thunk the name patterns cannot see
            // (issue #269) — is a request the pipeline refuses, not a unit
            // that failed: record it skipped, the way the explicit-list
            // path does, and the flag keeps it out of the completion
            // callback below (a refused unit has no code to write).
            let mut unit_refused = false;
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
                    // A root refusal is a refusal, not a failure: record
                    // it skipped, exactly as the explicit-list path does.
                    if matches!(e, TranslatorError::SkippedRoot { .. }) {
                        info!(
                            binary,
                            name = %plan_func.name,
                            error = %e,
                            "Plan function is a root symbol — recorded skipped, not failed"
                        );
                        unit_refused = true;
                        batch::FunctionResult::skipped(binary.clone(), plan_func.name.clone())
                    } else {
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
                }
            };

            // Carry-over provenance (issue #299): when attempt 1 rode in on
            // an accepted translation and that code is what succeeded, say
            // so on the record — the git callback's commit message reads it.
            self.attach_carry_over_provenance(&mut result);

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

            // Invoke the caller's callback. A refused root never reaches
            // it: it was never attempted, so it has no translated code to
            // write and no branch to clean up, and a caller that assumes a
            // success carries code would panic.
            let continue_batch = if let Some(ref mut cb) = on_function_completed
                && !unit_refused
            {
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
// Signature synthesis helpers
// ============================================================

/// The calling-convention words the testgen signature parser extracts from a
/// signature — the same closed set, so a decompiler line the parser would
/// read as convention-bearing is never re-spelled over (issue #251, part of
/// #226).
const CONVENTION_SPELLINGS: [&str; 6] = [
    "__stdcall",
    "__cdecl",
    "__fastcall",
    "__thiscall",
    "__naked",
    "__retpoline",
];

/// Whether `signature` already names a calling convention in the slot the
/// parser reads — between the return type and the parameter list. A
/// parameter list cannot carry these words, so only the part before the
/// opening parenthesis is checked.
fn names_convention(signature: &str) -> bool {
    let before_paren = signature.split('(').next().unwrap_or(signature);
    CONVENTION_SPELLINGS
        .iter()
        .any(|spelling| before_paren.contains(spelling))
}

/// Spell `convention` into `signature` between the return type and the
/// declarator's name — the slot the parser reads — leaving the parameter
/// list untouched. None when there is no name slot to spell before (no
/// whitespace separating a return type from the name), which leaves the
/// signature exactly as the decompiler wrote it.
fn spell_convention(signature: &str, convention: &str) -> Option<String> {
    let open = signature.find('(')?;
    let before = signature[..open].trim_end();
    let name_start = before.rfind(|c: char| c.is_whitespace())? + 1;
    if name_start == 0 {
        return None;
    }
    let mut refined = signature[..name_start].to_string();
    refined.push_str(convention);
    refined.push(' ');
    refined.push_str(&signature[name_start..]);
    Some(refined)
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
    use crate::scan_registry::{CompletionLatch, ScanRunOptions};
    use calxgloss_algorithm::persist::AlgorithmPersistor;
    use calxgloss_apidetect::persist::ApiPersistor;
    use calxgloss_callback::persist::CallbackPersistor;
    use calxgloss_consts::persist::ConstPersistor;
    use calxgloss_controlflow::persist::ControlFlowPersistor;
    use calxgloss_controlflow::types::ControlFlowResult;
    use calxgloss_errhandling::persist::ErrhandlingPersistor;
    use calxgloss_floatsimd::persist::FloatsimdPersistor;
    use calxgloss_globalstate::persist::GlobalStatePersistor;
    use calxgloss_globalstate::types::{GlobalAccess, GlobalStateFinding, GlobalStateResult};
    use calxgloss_memory::persist::MemoryPersistor;
    use calxgloss_serialize::persist::SerializePersistor;
    use calxgloss_stringctx::persist::StringContextPersistor;
    use calxgloss_sync::persist::SyncPersistor;
    use calxgloss_typeinfer::persist::TypeInferPersistor;
    use calxgloss_typeinfer::types::{
        InferenceMethod, InferenceScope, InferredLocalType, InferredParamType, InferredReturnType,
        TypeInferenceResult,
    };
    use calxgloss_types::Confidence;
    use calxgloss_types::TranslationConstraints;
    use calxgloss_typesdb::persist::TypeDatabasePersistor;
    use calxgloss_typesdb::types::ScanMetadata;
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

    /// An import thunk the symbol table named after its import — the
    /// fixture's MinGW `puts` veneer, whose whole body is `return puts(a0);`
    /// — matches no name-based root pattern, so the body-shape guard reads
    /// the fetched body and refuses it before any LLM token is spent
    /// (issue #269).
    #[tokio::test]
    async fn translate_refuses_a_thunk_named_after_its_own_import() {
        let result = pipeline_over(None).translate(PROGRAM, "puts").await;
        let Err(TranslatorError::SkippedRoot {
            function, reason, ..
        }) = result
        else {
            panic!("the puts veneer must be refused, got {result:?}");
        };
        assert_eq!(function, "puts");
        assert!(
            reason.contains("self-call"),
            "the refusal should name the body shape, got: {reason}"
        );
    }

    /// The same veneer named explicitly in a batch list is recorded
    /// skipped, not failed — the batch completes over it exactly as it does
    /// for a name-pattern thunk.
    #[tokio::test]
    async fn batch_translate_records_a_self_call_thunk_as_skipped() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let result = pipeline_over(Some(dir.path()))
            .batch_translate(
                PROGRAM,
                &["free".to_string()],
                &retry::RetryConfig::default(),
                &verifier,
                None,
            )
            .await
            .expect("the batch completes even when every unit is refused");

        assert_eq!(result.total_count(), 1);
        assert_eq!(result.skipped_count(), 1, "the veneer is recorded skipped");
        assert_eq!(result.failure_count(), 0, "a refusal is not a failure");
    }

    /// A two-node call graph over the fixture's `puts` and `free` veneers,
    /// carried as ordinary Middle nodes — the name-based root patterns
    /// cannot see a veneer named after its import, so the call-graph
    /// classification leaves them in the plan (issue #269).
    fn veneer_graph() -> calxgloss_callgraph::CallGraph {
        calxgloss_callgraph::CallGraph {
            binary: PROGRAM.to_string(),
            functions: vec![
                calxgloss_callgraph::FunctionCallGraph {
                    name: "puts".to_string(),
                    address: 0x1000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_callgraph::NodeCategory::Middle,
                },
                calxgloss_callgraph::FunctionCallGraph {
                    name: "free".to_string(),
                    address: 0x2000,
                    callers: vec![],
                    callees: vec![],
                    node_category: calxgloss_callgraph::NodeCategory::Middle,
                },
            ],
        }
    }

    /// The call-graph plan path queues both veneers as units, and the
    /// body-shape guard refuses each one in the unit loop. The plan path
    /// must record them skipped rather than failed — the way the
    /// explicit-list path does — and keep them out of the completion
    /// callback, where a success carrying no code would panic a
    /// code-writing caller.
    #[tokio::test]
    async fn callgraph_batch_records_a_self_call_thunk_as_skipped() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

        let pipeline = pipeline_over(Some(dir.path()));
        let graph = veneer_graph();

        let mut seen: Vec<String> = Vec::new();
        let results = pipeline
            .batch_translate_from_callgraph(
                &graph,
                &retry::RetryConfig::default(),
                &verifier,
                Some(&mut |_binary, function, _result| {
                    seen.push(function.to_string());
                    true
                }),
            )
            .await
            .expect("the plan batch completes even when every unit is refused");

        assert_eq!(
            results.skipped_count(),
            2,
            "both veneers are recorded skipped"
        );
        assert_eq!(results.failure_count(), 0, "a refusal is not a failure");
        for veneer in ["puts", "free"] {
            let found = results
                .results
                .iter()
                .find(|r| r.function == veneer)
                .unwrap_or_else(|| panic!("the {veneer} veneer should appear in the plan results"));
            assert!(
                found.success && found.rust_code.is_none() && found.stub_code.is_none(),
                "{veneer} must be recorded skipped — a success carrying no code"
            );
            assert!(
                !seen.iter().any(|f| f == veneer),
                "the {veneer} veneer must never reach the completion callback"
            );
        }
    }

    /// A pre-built request carrying a thunk's self-call body is refused
    /// too: the guard reads the body the request brings, before the prompt
    /// is built.
    #[tokio::test]
    async fn translate_from_request_refuses_a_self_call_body() {
        let request = calxgloss_types::TranslationRequest {
            binary: PROGRAM.into(),
            function: "SetCursor".to_string(),
            disassembly: String::new(),
            decompiler_output: "\
void SetCursor(void)
{
  SetCursor();
  return;
}"
            .to_string(),
            windows_apis: Vec::new(),
            baseline_tests: Vec::new(),
        };

        let result = pipeline_over(None).translate_from_request(request).await;
        assert!(
            matches!(&result, Err(TranslatorError::SkippedRoot { reason, .. })
                if reason.contains("self-call")),
            "the self-call body must be refused, got {result:?}"
        );
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
        // fifteen pre-analysis scans over the fixture run inside it.
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
    async fn baseline_test_expectations_name_globals_with_the_typed_kinds() {
        // The global-state artifact supplies the side-effect
        // expectations (issue #257): a function with persisted access
        // records gets its generated test cases carrying
        // GlobalRead/GlobalWrite expectations naming each global in
        // the detail — never an Other(...) string — while a function
        // the document says nothing about keeps empty expectations.
        let dir = TempDir::new().unwrap();
        let persistor = GlobalStatePersistor::new(dir.path());
        let mut result = GlobalStateResult::new(ScanMetadata::new("game_logic.dll"));
        result
            .findings
            .push(GlobalStateFinding::GlobalWrite(GlobalAccess {
                function: "DrawPrimitive".to_string(),
                global: "DAT_180064e80".to_string(),
                evidence: "DAT_180064e80 = uVar2;".to_string(),
                confidence: 85.into(),
                suggestion: "hold the global in shared state".to_string(),
            }));
        result
            .findings
            .push(GlobalStateFinding::GlobalRead(GlobalAccess {
                function: "DrawPrimitive".to_string(),
                global: "g_frame_count".to_string(),
                evidence: "uVar1 = g_frame_count;".to_string(),
                confidence: 60.into(),
                suggestion: "read the program global through shared state".to_string(),
            }));
        // Another function's record must not leak into this unit's
        // expectations.
        result
            .findings
            .push(GlobalStateFinding::GlobalRead(GlobalAccess {
                function: "UpdateScene".to_string(),
                global: "DAT_other".to_string(),
                evidence: "uVar3 = DAT_other;".to_string(),
                confidence: 85.into(),
                suggestion: "read the program global through shared state".to_string(),
            }));
        persistor.save(&result).unwrap();

        let pipeline = pipeline_over(Some(dir.path()));
        let function_info = FunctionInfo {
            name: "DrawPrimitive".to_string(),
            address: 0x1000,
            binary: "game_logic.dll".to_string().into(),
            disassembly: "cmp eax, 0\nje 0x1010".to_string(),
            decompiler_output: "void DrawPrimitive(void) { DAT_180064e80 = 2; }".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };

        let tests = pipeline
            .generate_baseline_tests(&function_info, &[], &[])
            .await
            .expect("test inputs generate");
        assert!(!tests.is_empty(), "test cases are still generated");
        for test in &tests {
            assert_eq!(
                test.expected_side_effects,
                vec![
                    calxgloss_types::SideEffect {
                        kind: calxgloss_types::SideEffectKind::GlobalWrite,
                        detail: "DAT_180064e80".to_string(),
                    },
                    calxgloss_types::SideEffect {
                        kind: calxgloss_types::SideEffectKind::GlobalRead,
                        detail: "g_frame_count".to_string(),
                    },
                ],
                "expectations name the function's globals with the typed kinds"
            );
        }

        // A binary the document was never written for degrades to
        // today's behavior: generated cases with no expectations.
        let other = FunctionInfo {
            name: "NeverScanned".to_string(),
            address: 0x2000,
            binary: "other.dll".to_string().into(),
            disassembly: String::new(),
            decompiler_output: "int NeverScanned(void) { return 0; }".to_string(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };
        let tests = pipeline
            .generate_baseline_tests(&other, &[], &[])
            .await
            .expect("test inputs generate");
        assert!(
            tests.iter().all(|t| t.expected_side_effects.is_empty()),
            "no document, no expectations"
        );
    }

    /// Run `translate` far enough to watch the suite it generates and
    /// report the count the `TestsGenerated` event carries. The LLM step
    /// is unreachable offline, so each run ends in failure at the call —
    /// the proof is the event the unit emits before it. The LLM URL
    /// points at a closed port so the run fails fast however the dev
    /// box is configured.
    async fn tests_generated_through_translate(
        workspace: Option<&std::path::Path>,
        binary: &str,
        function: &str,
    ) -> usize {
        let llm = LlmClient::from_url("http://127.0.0.1:1/v1", "qwen3").expect("llm config");
        let pipeline = TranslationPipeline::new(fixture_kuna(), llm, ApiMappings::default());
        let pipeline = match workspace {
            Some(dir) => pipeline.with_workspace(dir.to_path_buf()),
            None => pipeline,
        };
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let pipeline = pipeline.with_events(events);

        let _ = pipeline.translate(binary, function).await;

        while let Ok(event) = rx.try_recv() {
            if let ProgressEvent::TestsGenerated { test_count, .. } = event {
                return test_count;
            }
        }
        panic!("translate emitted no TestsGenerated event before failing");
    }

    /// A branch-site finding for the unit under translation, keyed to
    /// the name the engine listing reports.
    fn branch_site_finding_for(
        function: &str,
        condition: &str,
        immediate: &str,
    ) -> calxgloss_controlflow::types::ControlFlowFinding {
        calxgloss_controlflow::types::ControlFlowFinding::BranchSite(
            calxgloss_controlflow::types::BranchSite {
                function: function.to_string(),
                condition: condition.to_string(),
                params: vec!["code".to_string()],
                operator: Some("==".to_string()),
                immediate: Some(immediate.to_string()),
                guards: calxgloss_controlflow::types::GuardedTarget::SwitchArm,
                suggestion: format!("cover the {condition} arm"),
                confidence: Confidence::new(80),
                evidence: condition.to_string(),
            },
        )
    }

    /// A switch finding for the unit — a finding the load keeps, but no
    /// branch inventory record.
    fn switch_finding_for(function: &str) -> calxgloss_controlflow::types::ControlFlowFinding {
        calxgloss_controlflow::types::ControlFlowFinding::Switch(
            calxgloss_controlflow::types::SwitchChain {
                function: function.to_string(),
                variable: "code".to_string(),
                cases: vec!["0".to_string(), "1".to_string()],
                has_default: true,
                suggestion: "match code { /* 2 arms */ } + _".to_string(),
                confidence: Confidence::new(70),
                evidence: "switch (code)".to_string(),
            },
        )
    }

    /// The marquee for issue #261: the control-flow document the
    /// translator already loads for prompt context is the one source
    /// that feeds baseline test generation. Over the fixture harness,
    /// a persisted document carrying branch_site records for the unit
    /// grows the suite the `TestsGenerated` event reports — and the
    /// added cases probe the records' immediates — while no document, a
    /// document with findings but no records, and a corrupt document
    /// each keep exactly the plain suite.
    #[tokio::test]
    async fn persisted_branch_inventory_reaches_baseline_generation_through_translate() {
        let binary = calxgloss_testfixtures::TARGET_FILE_NAME;
        // Kuna lists MinGW exports with the leading underscore; the
        // document's records must key to the name translate resolves.
        let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
            .await
            .expect("fixture function listing");
        let status = listed
            .iter()
            .find(|f| f.name.trim_start_matches('_') == "fixture_status")
            .expect("the fixture lists its status entry point")
            .name
            .clone();

        // The plain suite: no workspace, so no document to load.
        let plain = tests_generated_through_translate(None, binary, &status).await;

        let dir = TempDir::new().expect("temp workspace");
        let persistor = ControlFlowPersistor::new(dir.path());

        // Findings but no branch_site records: exactly today's suite.
        let mut result = ControlFlowResult::new(ScanMetadata::new(binary));
        result.findings.push(switch_finding_for(&status));
        persistor.save(&result).expect("document saved");
        let no_records = tests_generated_through_translate(Some(dir.path()), binary, &status).await;
        assert_eq!(
            no_records, plain,
            "a document with no branch_site records keeps today's suite"
        );

        // A corrupt document: also exactly today's suite.
        std::fs::write(persistor.path_for(binary), "{ not json").expect("corrupt document written");
        let corrupt = tests_generated_through_translate(Some(dir.path()), binary, &status).await;
        assert_eq!(corrupt, plain, "a corrupt document keeps today's suite");

        // Records for the unit: the branch-targeted cases reach the
        // suite through the same load the prompt reads.
        let mut result = ControlFlowResult::new(ScanMetadata::new(binary));
        result
            .findings
            .push(branch_site_finding_for(&status, "code == 3", "3"));
        result
            .findings
            .push(branch_site_finding_for(&status, "code == 12", "12"));
        persistor.save(&result).expect("document saved");
        let targeted = tests_generated_through_translate(Some(dir.path()), binary, &status).await;
        assert!(
            targeted > plain,
            "the loaded inventory reaches generation: {plain} -> {targeted} cases"
        );

        // And the cases the growth adds are the branch-targeted ones:
        // the records read back through the same load make generation
        // probe the recorded immediates on the unit's parameter.
        let loaded = crate::retry::helpers::load_control_flow_result(Some(dir.path()), binary)
            .expect("the persisted document loads");
        let inventory = crate::retry::helpers::branch_inventory_of(Some(&loaded), &status);
        assert_eq!(inventory.len(), 2, "the document's records for the unit");
        let function_info = FunctionInfo {
            name: status.clone(),
            address: 0x1000,
            binary: binary.to_string().into(),
            disassembly: String::new(),
            decompiler_output: format!("int {status}(int code) {{ return code; }}"),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };
        let tests = pipeline_over(Some(dir.path()))
            .generate_baseline_tests(&function_info, &[], &inventory)
            .await
            .expect("test inputs generate");
        let probes = |value: i64| {
            tests.iter().any(|t| {
                t.inputs
                    .as_object()
                    .is_some_and(|values| values.values().any(|v| *v == serde_json::json!(value)))
            })
        };
        assert!(
            probes(3) && probes(12),
            "the suite probes the recorded immediates: {:?}",
            tests.iter().map(|t| &t.inputs).collect::<Vec<_>>()
        );
    }

    // ─── Type-inference completion latch (issue #238) ────────────────

    /// A named row out of a fresh table — descriptors are not `Clone`,
    /// so each test takes its row out of its own `scan_rows()`.
    fn find_row(name: &str) -> ScanDescriptor {
        scan_rows()
            .into_iter()
            .find(|row| row.name() == name)
            .expect("the roster carries the named row")
    }

    /// The completion latch is a shared one-shot: a waiter that arrived
    /// before the publish is released by it, a waiter that arrives after
    /// answers immediately, and publishing again changes nothing.
    #[tokio::test]
    async fn the_completion_latch_is_a_shared_one_shot() {
        let latch = CompletionLatch::new();
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

    /// The declared edge survives a reversed call order — the shape the
    /// fan-out (#240) gives it: the callback row starts first and its
    /// pre-scan hook waits on the armed latch, the inference row then
    /// runs and publishes its latch on the way out, and the callback
    /// scan composes its contracts from the document inference just
    /// filed. Without the wait the callback scan would have read an
    /// empty workspace and its findings would have lost the enrichment
    /// (issues #173, #238, #305).
    #[tokio::test]
    async fn callback_detection_waits_for_inference_across_a_reversed_call_order() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));
        let job = pipeline
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");

        // The latch the phase arms for the declared edge, wired onto the
        // two rows exactly the way `registered_scan_tasks` wires it: the
        // inference row's run publishes it on every exit, the callback
        // row's pre-scan hook waits on it.
        let edge = CompletionLatch::new();
        let inference = find_row("type-inference");
        let callback = find_row("callback-detection");
        let mut inference_ctx = job.scan_context();
        inference_ctx.latches.publish = Some(edge.clone());
        let mut callback_ctx = job.scan_context();
        callback_ctx.latches.wait = Some(edge.clone());

        let running = tokio::spawn(async move { callback.run(callback_ctx).await });
        tokio::task::yield_now().await;
        assert!(
            !running.is_finished(),
            "the callback row waits on the unpublished latch"
        );

        assert!(
            inference.run(inference_ctx).await,
            "the inference scan succeeds over the fixture"
        );
        assert!(
            edge.is_set(),
            "the inference row publishes its latch on the way out"
        );

        let scanned = tokio::time::timeout(std::time::Duration::from_secs(120), running)
            .await
            .expect("the published latch releases the callback row — inference never strands it")
            .expect("the callback task runs");
        assert!(scanned, "the callback scan succeeds over the fixture");

        // The enrichment the wait protects: inference's document is in
        // place when the callback row composes its contracts, and it
        // composes real ones — the fixture's inference records yield
        // fully-read callables.
        assert!(
            TypeInferPersistor::new(dir.path()).exists("eqmain.dll"),
            "the inference document is filed before the callback row reads it"
        );
        assert!(
            !callback_signature_map(dir.path(), "eqmain.dll").is_empty(),
            "the callback scan's closure contracts compose from the inference document"
        );
    }

    /// The wait is real, not incidental: a callback row holding an
    /// unpublished latch is still parked well past the time the same
    /// scan takes over the fixture when it does not wait — and the
    /// publish releases it to a normal successful scan (issues #238,
    /// #305).
    #[tokio::test]
    async fn callback_detection_holds_until_the_latch_publishes() {
        let dir = TempDir::new().unwrap();
        let pipeline = pipeline_over(Some(dir.path()));
        let job = pipeline
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");

        let edge = CompletionLatch::new();
        let callback = find_row("callback-detection");
        let mut ctx = job.scan_context();
        ctx.latches.wait = Some(edge.clone());
        let running = tokio::spawn(async move { callback.run(ctx).await });

        // The fixture callback scan finishes in seconds; a row that
        // skipped the wait would have answered inside this window.
        // The margin — comfortably above the scan's own runtime, even
        // on a slow CI box — is what turns a missing wait into a
        // failure rather than a race.
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        assert!(
            !running.is_finished(),
            "an unpublished latch holds the callback row past the scan's own runtime"
        );

        // Publish the way the inference row's run does — the latch is
        // the phase's, set on its way out.
        edge.publish();

        let scanned = tokio::time::timeout(std::time::Duration::from_secs(120), running)
            .await
            .expect("the publish releases the held row")
            .expect("the callback task runs");
        assert!(
            scanned,
            "the released row scans the fixture normally and files its document"
        );
        assert!(
            CallbackPersistor::new(dir.path()).exists("eqmain.dll"),
            "the released scan persists like any other"
        );
    }

    /// A failing type-inference scan leaves callback detection degraded
    /// — no document, no enrichment — never blocked: the inference row
    /// publishes its latch on the failure path too, exactly as on
    /// success (issues #238, #305).
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
        let job = pipeline
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");

        let edge = CompletionLatch::new();
        let inference = find_row("type-inference");
        let mut inference_ctx = job.scan_context();
        inference_ctx.latches.publish = Some(edge.clone());
        let inferred = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            inference.run(inference_ctx),
        )
        .await
        .expect("a failing inference scan still returns");
        assert!(!inferred, "the failed save degrades the inference row");
        assert!(
            edge.is_set(),
            "the failing run still published its latch on the way out"
        );

        // The failure path published the latch, so the callback row's
        // wait releases even though no document was ever filed.
        let callback = find_row("callback-detection");
        let mut callback_ctx = job.scan_context();
        callback_ctx.latches.wait = Some(edge);
        let scanned = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            callback.run(callback_ctx),
        )
        .await
        .expect("a failed inference row never blocks the callback row");
        assert!(scanned, "the callback scan itself still succeeds");

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

    // The control-flow seam quads (cached hit, cache miss, failed save,
    // no workspace) left with the `ensure_*` entry points they drove:
    // the registry's generic four-shape pass now runs every registered
    // row — control-flow included — through the same shapes at the
    // phase seam (issues #302–#305, retargeted by #307).

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

    /// Recursive directory copy — turning one version's warm scan cache
    /// into a plausible surviving sibling of another version's (#298).
    fn copy_dir_tree(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).expect("copy destination");
        for entry in std::fs::read_dir(from).expect("source directory readable") {
            let entry = entry.expect("directory entry");
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_dir_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("document copied");
            }
        }
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

        // Batch 1, cold: the fifteen scans read live through the engine and
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
        // fifteen scans — only the scan cache may answer them.
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
        // all fifteen scans — every body now arrives warm from the read
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
    /// been: across a cold phase's fifteen concurrent scans the engine
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
            "no function reached the engine twice across the fifteen scans: {calls:?}"
        );
    }

    /// P18's version-change trigger (issue #298): once the scan step has
    /// warmed this version's cache directory, a sibling hash directory — a
    /// surviving scan of the previous version — pairs with it exactly once,
    /// and the pairing document persists under the analysis-directory
    /// convention, keyed on the (old, new) hash pair. A later pass reuses
    /// the persisted document instead of recomputing.
    #[tokio::test]
    async fn a_surviving_sibling_scan_is_paired_once_after_the_scan_step() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;

        // A scan of one version's bytes: no sibling, no pairing document.
        pipeline.run_prebatch_scans(PROGRAM).await;
        assert!(
            !dir.path().join("re/analysis/bdiff").exists(),
            "no sibling hash directory — the diff pass stays invisible"
        );

        // The version change, simulated honestly: this scan's document set
        // is itself a well-formed surviving scan — copy it under another
        // hash name and let its manifest name the directory it stands in,
        // the way every kept scan's manifest does.
        let live = scan_cache_dir(dir.path());
        let new_hash = live
            .file_name()
            .expect("hash directory")
            .to_string_lossy()
            .into_owned();
        let old_hash = "a".repeat(64);
        let sibling = live.with_file_name(&old_hash);
        copy_dir_tree(&live, &sibling);
        calxgloss_types::persist::save_json(
            &sibling.join("manifest.json"),
            &calxgloss_decomp::CacheManifest {
                binary_sha256: old_hash.clone(),
                format_version: calxgloss_decomp::CACHE_FORMAT_VERSION,
                program: PROGRAM.into(),
            },
        )
        .expect("the sibling manifest names its own directory");

        // The new version's scan step pairs the two scans and persists one
        // document for the (old, new) hash pair — reading only the two
        // cached document sets.
        pipeline.run_prebatch_scans(PROGRAM).await;

        let persistor = calxgloss_bdiff::BdiffPersistor::new(dir.path());
        let key = calxgloss_bdiff::BdiffPersistor::key_for(PROGRAM, &old_hash, &new_hash);
        let document = persistor
            .load(&key)
            .expect("the scan step paired the version change");
        assert_eq!(document.binary, PROGRAM);
        assert_eq!(document.old_bytes_sha256, old_hash);
        assert_eq!(document.new_bytes_sha256, new_hash);
        assert_eq!(
            document.old_functions, document.new_functions,
            "both scans read the same bytes, so the two listings match"
        );
        assert!(
            !document.pairings.is_empty(),
            "kept bodies ride the snapshot, and equal bodies pair through the body family"
        );

        // A later run of the same version reuses the persisted document:
        // mark it with a score no family can produce, and see the mark
        // survive another scan step.
        let mut marked = document;
        marked.pairings[0].confidence = calxgloss_types::Confidence::new(1);
        persistor
            .save(&marked)
            .expect("the marked document is filed");
        pipeline.run_prebatch_scans(PROGRAM).await;
        let reused = persistor.load(&key).expect("the document still stands");
        assert_eq!(
            reused.pairings[0].confidence,
            calxgloss_types::Confidence::new(1),
            "the persisted document was reused, not recomputed"
        );
    }

    // ─── Carry-over seeding (issue #299) ───────────────────────────────

    /// The pipeline's carry-over track: a hand-filed pairing document for
    /// the live bytes, plus a port answering which twins have accepted
    /// (merged) translations. Mirrors the CLI's real wiring without git.
    fn seeded_pipeline(
        dir: &std::path::Path,
        accepted: Vec<(String, u32, String)>,
    ) -> (TranslationPipeline, std::path::PathBuf) {
        struct Port {
            accepted: std::collections::HashMap<String, (u32, String)>,
        }
        impl crate::carry_over::AcceptedAttemptSource for Port {
            fn accepted_attempt(&self, binary: &str, function: &str) -> Option<(u32, String)> {
                assert_eq!(binary, PROGRAM, "the port is keyed on the run's binary");
                self.accepted.get(function).cloned()
            }
        }
        let fixture = calxgloss_testfixtures::load_target().expect("fixture target");
        let binary_file = dir.join(calxgloss_testfixtures::TARGET_FILE_NAME);
        std::fs::copy(fixture.path(), &binary_file).expect("fixture copied into the workspace");
        // An LLM port nothing answers: a unit that reaches it proves the
        // fresh chain ran, and only a seeded unit never reaches it.
        let llm = LlmClient::from_url("http://127.0.0.1:1/v1", "qwen3").expect("llm config");
        let accepted: std::collections::HashMap<String, (u32, String)> = accepted
            .into_iter()
            .map(|(function, attempt, code)| (function, (attempt, code)))
            .collect();
        let pipeline = TranslationPipeline::new(fixture_kuna(), llm, ApiMappings::default())
            .with_workspace(dir.to_path_buf())
            .with_binary_path(&binary_file)
            .with_accepted_attempt_source(Arc::new(Port { accepted }));
        (pipeline, binary_file)
    }

    /// File a pairing document for the live bytes under the analysis
    /// convention — exactly where the #298 trigger leaves its documents,
    /// so the carry-over step reads the real layout.
    async fn file_pairing_document(
        dir: &std::path::Path,
        binary_file: &std::path::Path,
        records: Vec<calxgloss_bdiff::PairingRecord>,
    ) {
        let new_hash = calxgloss_decomp::sha256_of_file(binary_file)
            .expect("hashable")
            .expect("the binary exists");
        let listing = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
            .await
            .expect("fixture function listing");
        let document = calxgloss_bdiff::PairingDocument {
            binary: PROGRAM.into(),
            old_bytes_sha256: "a".repeat(64),
            new_bytes_sha256: new_hash,
            old_functions: records.iter().map(|r| r.old_function.clone()).collect(),
            new_functions: listing.iter().map(|f| f.name.clone()).collect(),
            pairings: records,
        };
        calxgloss_bdiff::BdiffPersistor::new(dir)
            .save(&document)
            .expect("pairing document filed");
    }

    fn pairing(old: &str, new: &str, confidence: u8) -> calxgloss_bdiff::PairingRecord {
        calxgloss_bdiff::PairingRecord {
            old_function: old.into(),
            new_function: new.into(),
            family: calxgloss_bdiff::MatchFamily::NameIdentity,
            confidence: calxgloss_types::Confidence::new(confidence),
            evidence: vec![format!("{old} ↔ {new}")],
        }
    }

    /// The marquee for issue #299: with a confident pairing document naming
    /// the live bytes and a paired twin whose translation was accepted, the
    /// unit's attempt 1 carries the accepted code verbatim — the LLM port
    /// stays untouched — and the unit still runs through the retry loop's
    /// full verification. A below-floor pairing queues fresh exactly as
    /// today: it reaches the (closed) LLM port and fails like any unit the
    /// engine cannot answer for.
    #[tokio::test]
    async fn a_batch_seeds_attempt_1_from_the_accepted_translation_of_a_paired_twin() {
        let dir = TempDir::new().expect("temp workspace");
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");
        let seeded_code = "fn seeded_from_the_previous_version() {}".to_string();

        // Kuna lists MinGW exports with the leading underscore; resolve the
        // names the queue will use, as every fixture test does.
        let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
            .await
            .expect("fixture function listing");
        let name_for = |plain: &str| {
            listed
                .iter()
                .find(|f| f.name.trim_start_matches('_') == plain)
                .unwrap_or_else(|| panic!("the fixture lists {plain}"))
                .name
                .clone()
        };
        let status = name_for("fixture_status");
        let describe = name_for("fixture_describe");

        let (pipeline, binary_file) = seeded_pipeline(
            dir.path(),
            vec![("legacy_status".to_string(), 3, seeded_code.clone())],
        );
        file_pairing_document(
            dir.path(),
            &binary_file,
            vec![
                // A rename-aware pairing: the twin goes by another name.
                pairing("legacy_status", &status, 95),
                // One point under the floor — today's fresh queue, exactly.
                pairing(
                    "old_describe",
                    &describe,
                    calxgloss_bdiff::CARRY_OVER_CONFIDENCE_FLOOR - 1,
                ),
            ],
        )
        .await;

        let result = pipeline
            .batch_translate(
                PROGRAM,
                &[status.clone(), describe.clone()],
                &retry::RetryConfig {
                    max_attempts: 1,
                    strategy: retry::RetryStrategy::CompileFix,
                    escalate_on_failure: false,
                    max_context_tier: None,
                },
                &verifier,
                None,
            )
            .await
            .expect("a unit that fails verification never fails the batch itself");

        assert_eq!(result.results.len(), 2);
        let seeded = result
            .results
            .iter()
            .find(|r| r.function == status)
            .expect("status unit");
        assert_eq!(
            seeded.retry_result.attempts.len(),
            1,
            "the seeded code was verified as attempt 1, and max_attempts caps the chain"
        );
        let attempt = &seeded.retry_result.attempts[0];
        assert_eq!(
            attempt.rust_code, seeded_code,
            "attempt 1 carries the accepted translation verbatim — the fresh \
             chain never reached the closed LLM port"
        );
        assert_eq!(attempt.strategy, "initial", "the seed rides as attempt 1");
        assert!(
            attempt.tokens_used.is_none(),
            "a seeded attempt spends no LLM tokens"
        );
        // The seed is a hypothesis the new bytes get to reject — and from
        // #334 on the rejection is honest: attempt 1 now consults the
        // freshly captured baseline suite, and the attempt-1 record
        // carries its real size. The verdict lands as tests-failed here
        // for two toolchain-side reasons outside this issue's scope — the
        // scratch suite runner cannot build on this machine (a verify-
        // crate defect), and a stub seed like this one could never answer
        // a behavioral suite anyway. What is pinned is the contract: the
        // suite was consulted, the counts are real, and success remains
        // the verifier's verdict, never a carry-over stamp — the review
        // overlay model (ADR-0003) is untouched, and the pairing never
        // marks a unit Verified.
        assert!(attempt.compiled, "the seed compiles against the new bytes");
        assert!(
            attempt.tests_total > 0,
            "attempt 1 now consults the captured baseline suite — the \
             compile-only success hole is closed (#334)"
        );
        assert!(
            !attempt.is_successful(),
            "verification — not the pairing — decided the outcome"
        );
        assert!(
            seeded.carry_over.is_none(),
            "provenance rides only an honest done: with verification saying \
             not-done, nothing marks the carried code as a win (ADR-0003)"
        );

        let fresh = result
            .results
            .iter()
            .find(|r| r.function == describe)
            .expect("describe unit");
        assert!(
            fresh.retry_result.attempts.is_empty(),
            "the below-floor pairing queued fresh: the unit went to the LLM \
             like today and failed there, never reaching verification"
        );
        assert!(!fresh.success);
    }

    /// The seeded attempt's own record names its source — the old function
    /// and the attempt branch the code rode in on — and spends no tokens.
    /// A known-library root's Skip classification also stands
    /// independently of pairing: a seed for a delay-load thunk never gets
    /// to translate it, refusal first.
    #[tokio::test]
    async fn a_seeded_attempt_names_its_source_and_never_overrides_a_root_refusal() {
        let dir = TempDir::new().expect("temp workspace");
        let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
            .await
            .expect("fixture function listing");
        let status = listed
            .iter()
            .find(|f| f.name.trim_start_matches('_') == "fixture_status")
            .expect("the fixture lists its status entry point")
            .name
            .clone();

        let (pipeline, _) = seeded_pipeline(
            dir.path(),
            vec![(
                "legacy_status".to_string(),
                3,
                "fn carried_over() {}".to_string(),
            )],
        );
        pipeline
            .carry_over_seeds
            .lock()
            .expect("seeds lock")
            .insert(
                status.clone(),
                crate::carry_over::CarryOverSeed {
                    old_function: "legacy_status".into(),
                    old_attempt: 3,
                    family: "name_identity",
                    confidence: 95,
                    rust_code: "fn carried_over() {}".to_string(),
                },
            );
        // A seed cannot smuggle a Skip-classified root past the refusal —
        // the known-library guard runs before any carry-over lookup.
        pipeline
            .carry_over_seeds
            .lock()
            .expect("seeds lock")
            .insert(
                "DelayLoad_ShellExecuteW".to_string(),
                crate::carry_over::CarryOverSeed {
                    old_function: "old_thunk".into(),
                    old_attempt: 1,
                    family: "name_identity",
                    confidence: 95,
                    rust_code: "fn carried_over() {}".to_string(),
                },
            );

        let translation = pipeline
            .translate(PROGRAM, &status)
            .await
            .expect("the seeded unit needs no LLM to produce attempt 1");
        assert_eq!(translation.rust_code, "fn carried_over() {}");
        assert_eq!(
            translation.model, "carry-over",
            "the record says where the code came from"
        );
        assert!(translation.tokens_used.is_none(), "no tokens were spent");
        assert!(
            translation.prompt_used.contains("legacy_status")
                && translation.prompt_used.contains("attempt 3"),
            "the record names the source branch: {}",
            translation.prompt_used
        );

        let refused = pipeline.translate(PROGRAM, "DelayLoad_ShellExecuteW").await;
        assert!(
            matches!(refused, Err(TranslatorError::SkippedRoot { .. })),
            "pairing never overrides the known-library Skip classification: {refused:?}"
        );
    }

    /// The commit-message provenance rule: a carry-over record rides only
    /// when the winning code **is** the seeded code — when the fresh chain
    /// took over, the code is the LLM's and claiming a carry-over would be
    /// false provenance.
    #[test]
    fn carry_over_provenance_rides_only_when_the_seed_code_won() {
        let dir = TempDir::new().expect("temp workspace");
        let pipeline = pipeline_over(Some(dir.path()));
        pipeline
            .carry_over_seeds
            .lock()
            .expect("seeds lock")
            .insert(
                "DrawSprite".to_string(),
                crate::carry_over::CarryOverSeed {
                    old_function: "legacy_draw".into(),
                    old_attempt: 2,
                    family: "name_identity",
                    confidence: 95,
                    rust_code: "fn carried() {}".to_string(),
                },
            );

        let mut seeded_win = batch::FunctionResult::success(
            PROGRAM,
            "DrawSprite".to_string(),
            "fn carried() {}".to_string(),
            retry::RetryResult::new(),
            None,
        );
        pipeline.attach_carry_over_provenance(&mut seeded_win);
        let record = seeded_win
            .carry_over
            .expect("the seed won: provenance rides");
        assert_eq!(record.old_function, "legacy_draw");
        assert_eq!(record.old_attempt, 2);
        assert_eq!(
            record.commit_note(),
            "seeded from legacy_draw attempt 2 (paired, 95% confidence)"
        );

        let mut fresh_win = batch::FunctionResult::success(
            PROGRAM,
            "DrawSprite".to_string(),
            "fn the_llms_own_work() {}".to_string(),
            retry::RetryResult::new(),
            None,
        );
        pipeline.attach_carry_over_provenance(&mut fresh_win);
        assert!(
            fresh_win.carry_over.is_none(),
            "the fresh chain won: no carry-over claim"
        );

        let mut failed = batch::FunctionResult::failure(
            PROGRAM,
            "DrawSprite".to_string(),
            retry::RetryResult::new(),
        );
        failed.rust_code = Some("fn carried() {}".to_string());
        failed.success = true;
        pipeline.attach_carry_over_provenance(&mut failed);
        assert!(
            failed.carry_over.is_some(),
            "the check rides the final code, however it got there"
        );
    }

    /// Every registered row's filed document, read from the location
    /// its descriptor names, as parsed JSON keyed by the row's name —
    /// the registry-driven form the equivalence legs compare, so a row
    /// added to the table later is compared with no test edit
    /// (issue #307).
    fn registered_documents(workspace: &std::path::Path) -> Vec<(&'static str, serde_json::Value)> {
        scan_rows()
            .iter()
            .map(|row| {
                let path = row.document_path(workspace, PROGRAM);
                let bytes = std::fs::read(&path).unwrap_or_else(|e| {
                    panic!(
                        "the {} row's document at {}: {e}",
                        row.name(),
                        path.display()
                    )
                });
                (
                    row.name(),
                    serde_json::from_slice(&bytes).expect("the filed document is JSON"),
                )
            })
            .collect()
    }

    /// The fan-out's marquee: given the same cached reads, the
    /// concurrent phase and the same registry run one scan at a time
    /// persist the same documents — findings, order, and callback
    /// enrichment alike — for every registered row, the comparison
    /// driven by the table rather than a hand-written list of engines
    /// (issue #240, retargeted onto the registry by issue #307).
    ///
    /// Both compared runs replay one read cache, warmed by a cold
    /// phase first: the Kuna engine folds each decompile's recovered
    /// types into its program listing, so two cold runs over the same
    /// bytes legitimately see different listings depending on what
    /// decompiled when. With every read pinned by the cache, the only
    /// thing that differs between the compared runs is the schedule —
    /// exactly what the fan-out must not let matter.
    #[tokio::test]
    async fn the_fanned_scan_phase_persists_what_the_sequential_registry_run_persists() {
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
        let fanned = registered_documents(dir.path());

        // The sequential leg: the same registry run one scan at a time,
        // in table order, over the read cache the cold phase warmed —
        // the guarantee the old sequential preamble pinned, now driven
        // by the table instead of a hand-written list of entry points,
        // so every registered row is compared and a row added later is
        // compared with no test edit. The completion latches are armed
        // and wired onto each row's context exactly as
        // `registered_scan_tasks` wires the phase's, so the declared
        // edge holds here too: the inference row sits directly before
        // the callback row in the table, publishes its latch on the way
        // out, and the callback row composes its closure contracts from
        // the inference document the sequential leg just filed
        // (issue #307).
        std::fs::remove_dir_all(dir.path().join("re").join("analysis"))
            .expect("fanned documents cleared");
        let job = pipeline
            .scan_job(PROGRAM)
            .expect("the workspace is configured, so the job exists");
        let rows = scan_rows();
        let armed = arm_completion_latches(&rows);
        for row in &rows {
            let publish = armed
                .iter()
                .find(|(name, _)| *name == row.name())
                .map(|(_, latch)| latch.clone());
            let wait = row.waits_for().and_then(|producer| {
                armed
                    .iter()
                    .find(|(name, _)| *name == producer)
                    .map(|(_, latch)| latch.clone())
            });
            let mut ctx = job.scan_context();
            ctx.latches = ScanLatches { publish, wait };
            assert!(
                row.run(ctx).await,
                "the sequential {} row must file its document over the fixture",
                row.name()
            );
        }
        let in_sequence = registered_documents(dir.path());

        for ((name, fanned), (same_name, in_sequence)) in fanned.into_iter().zip(in_sequence) {
            assert_eq!(name, same_name, "both legs read the same registry table");
            assert_eq!(
                stamped_document(fanned),
                stamped_document(in_sequence),
                "the fanned {name} document must equal the sequential registry run's"
            );
        }

        // The equality above only means something if the callback scan
        // was enriched on both sides: the fixture's inference records
        // compose real contracts (the #238 precedent), so the callback
        // documents match as enriched documents, not as two degraded
        // ones — and in the sequential leg it is the declared edge, not
        // a call-order accident, that put the enrichment there.
        assert!(
            !callback_signature_map(dir.path(), PROGRAM).is_empty(),
            "the inference document composes real contracts — the callback scan \
             had the enrichment to read, fanned and in sequence alike"
        );
    }

    /// One scan's failure stays its own: with the memory document's
    /// directory sabotaged, the memory scan degrades at its save while
    /// the other fourteen documents are still filed and the phase still
    /// ends — the group joins all fifteen and never cancels a sibling
    /// (issue #240, roster grown by errhandling in #292, float/SIMD in
    /// #229, and known-library identification in #306).
    #[tokio::test]
    async fn one_failing_scan_leaves_the_other_fourteen_persisted() {
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
                "global state",
                GlobalStatePersistor::new(workspace).exists(PROGRAM),
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
            (
                "error handling",
                ErrhandlingPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "float/SIMD",
                FloatsimdPersistor::new(workspace).exists(PROGRAM),
            ),
            (
                "known libraries",
                calxgloss_libmatch::persist::LibmatchPersistor::new(workspace).exists(PROGRAM),
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
    // The scan-descriptor registry (issues #302–#305)
    // ============================================================

    /// Registry-completeness is a test, not a comment: every row the
    /// phase runs from a descriptor is named here, so adding or dropping
    /// a row fails this test until the roster is edited on purpose. That
    /// is what keeps the `libmatch` drift — an engine the phase silently
    /// never ran — from returning (spec #301).
    ///
    /// The pair's twin sits at the CLI: the pairing test
    /// `the_cli_contribution_table_pairs_one_for_one_with_the_registry_roster`
    /// and its two fault-direction siblings in
    /// `crates/interface/calxgloss-cli/src/commands/scan_command.rs` read
    /// this roster's own `scan_rows()` data against the CLI contribution
    /// table, so a row that joins this roster without a reviewed CLI
    /// contribution fails there too (issue #342).
    #[test]
    fn the_registered_rows_are_exactly_the_named_roster() {
        let names: Vec<&str> = scan_rows().iter().map(ScanDescriptor::name).collect();
        assert_eq!(
            names,
            [
                "control-flow",
                "memory-lifecycle",
                "concurrency",
                "global-state",
                "constants",
                "error-handling",
                "float-simd",
                "type-database",
                "algorithm-recognition",
                "string-context",
                "library-api",
                "serialization",
                "type-inference",
                "callback-detection",
                "known-library",
            ],
            "the registry roster changed — a scan joins the phase by adding \
             its row to the table, and never by being forgotten"
        );
    }

    /// Every registered row, through one generic pass: a cold phase files
    /// each row's document at the location its descriptor names, under the
    /// `re/analysis/<domain>/` convention.
    #[tokio::test]
    async fn every_registered_row_files_its_document_on_a_cold_phase() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;
        pipeline.run_prebatch_scans(PROGRAM).await;

        let rows = scan_rows();
        assert!(!rows.is_empty(), "the registry must drive the phase");
        for row in &rows {
            let path = row.document_path(dir.path(), PROGRAM);
            assert_eq!(
                path.parent()
                    .and_then(|domain| domain.parent())
                    .expect("the document rides re/analysis/<domain>/<binary>.json"),
                dir.path().join("re").join("analysis"),
                "the {} row's document rides the analysis-document convention: {}",
                row.name(),
                path.display()
            );
            assert_eq!(
                path.file_name().and_then(|name| name.to_str()),
                Some(format!("{PROGRAM}.json").as_str()),
                "the {} row's document is named after its binary: {}",
                row.name(),
                path.display()
            );
            assert!(
                path.is_file(),
                "the registered {} row filed its document on a cold phase",
                row.name()
            );
        }
        // The table is the whole phase: all fifteen scans' documents
        // are filed by one cold phase, every one of them from a row.
    }

    /// Every registered row, second shape: a pre-filed document is left
    /// byte-identical. The row's short-circuit sits ahead of any engine
    /// read, and a rescan would rewrite the wall-clock stamps — so
    /// unchanged bytes, not a returned flag, are the proof.
    #[tokio::test]
    async fn a_pre_filed_registered_document_is_left_byte_identical() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;
        pipeline.run_prebatch_scans(PROGRAM).await;

        let filed: Vec<(&str, std::path::PathBuf, Vec<u8>)> = scan_rows()
            .iter()
            .map(|row| {
                let path = row.document_path(dir.path(), PROGRAM);
                (
                    row.name(),
                    path.clone(),
                    std::fs::read(&path).expect("the row's filed document"),
                )
            })
            .collect();

        pipeline.run_prebatch_scans(PROGRAM).await;
        for (name, path, bytes) in filed {
            assert_eq!(
                std::fs::read(&path).expect("the document is still in place"),
                bytes,
                "the second phase must leave the pre-filed {name} document untouched"
            );
        }
    }

    /// Every registered row, third shape: with its document directory
    /// sabotaged the row warns and files nothing — and every other
    /// registered row still files its own. One detector's trouble
    /// never takes down the group.
    #[tokio::test]
    async fn a_sabotaged_registered_row_degrades_without_taking_the_group_down() {
        for row in scan_rows() {
            let dir = TempDir::new().expect("temp workspace");
            // A plain file where the persistor needs its domain
            // directory: the scan succeeds and only the save fails.
            let document = row.document_path(dir.path(), PROGRAM);
            let domain_dir = document
                .parent()
                .expect("the document path names its domain directory");
            std::fs::create_dir_all(dir.path().join("re").join("analysis")).expect("analysis dir");
            std::fs::write(domain_dir, "not a directory").expect("sabotage filed");

            let (pipeline, _) = cached_pipeline(dir.path());
            pipeline.begin_cached_source(PROGRAM).await;
            pipeline.run_prebatch_scans(PROGRAM).await;

            assert!(
                !document.exists(),
                "the sabotaged {} row left no document behind",
                row.name()
            );
            for other in scan_rows() {
                if other.name() != row.name() {
                    assert!(
                        other.document_path(dir.path(), PROGRAM).is_file(),
                        "the sabotaged {} row never took down the {} row",
                        row.name(),
                        other.name()
                    );
                }
            }
        }
    }

    /// Every registered row, fourth shape: with no workspace configured
    /// the whole phase is skipped — no scan enters the window, nothing is
    /// filed, and nothing panics.
    #[tokio::test]
    async fn no_workspace_skips_the_phase_without_panic_or_documents() {
        let pipeline = pipeline_over(None);
        pipeline.run_prebatch_scans(PROGRAM).await;
        assert_eq!(
            pipeline.scan_window_high_water(),
            0,
            "the phase skipped before any window permit was taken"
        );
    }

    // ============================================================
    // Per-run options on the registry run (issue #338, spec #337)
    // ============================================================

    /// A pattern database carrying one control-flow entry: the built-in
    /// linear-search shape the fixture's bodies really wear, renamed to a
    /// custom algorithm the built-in set can never emit. A section the
    /// document omits reads as an empty set, so the file's set replaces
    /// the standard sets whole.
    fn custom_pattern_database_document() -> &'static str {
        r#"{
            "control_flow": [
                {
                    "name": "custom_fixture_scan_shape",
                    "category": "searching",
                    "match_patterns": ["\\b(for|while) \\(", "==", "\\b(return|break)\\b"],
                    "exclude_patterns": ["(?:/ 2\\b|>> 1)", "% "],
                    "min_lines": 10
                }
            ]
        }"#
    }

    /// A signature database carrying one signature: the starter set's
    /// strlen scan shape (which the fixture's statically linked `strnlen`
    /// matches, pinned by issue #306's tests) renamed to a custom symbol
    /// the built-in set can never name.
    fn custom_signature_database_document() -> &'static str {
        r#"{
            "signatures": [
                {
                    "symbol": "custom_fixture_strlen",
                    "family": "crt",
                    "match_patterns": [
                        "while \\(\\*VAR( != '\\\\0')?\\)",
                        "VAR = (?:VAR \\+ 1|&VAR\\[1\\])"
                    ],
                    "exclude_patterns": ["\\bmalloc\\b", "\\bfree\\b"],
                    "min_lines": 6,
                    "suggestion": "count bytes to the NUL — the fixture's scan loop"
                }
            ]
        }"#
    }

    /// The set-override option drives engine construction inside the
    /// rows that can take one — no engine-named vocabulary crossed the
    /// shared shape to get there. Over the fixture target: the algorithm
    /// row's filed document carries only the file's renamed shape (the
    /// built-in claims are gone — the file's set replaces the standard
    /// sets whole), and the known-library row's document identifies the
    /// fixture's scan loop through the file's renamed symbol instead of
    /// the starter set's `strlen`. The defaults keep both rows on their
    /// built-in sets — that is the shipped phase, pinned by the roster,
    /// persistence, and cold-batch tests above.
    #[tokio::test]
    async fn a_set_override_file_replaces_the_built_in_set_inside_the_row_build() {
        let dir = TempDir::new().expect("temp workspace");
        let patterns = dir.path().join("custom-patterns.json");
        std::fs::write(&patterns, custom_pattern_database_document())
            .expect("custom pattern database written");
        let signatures = dir.path().join("custom-signatures.json");
        std::fs::write(&signatures, custom_signature_database_document())
            .expect("custom signature database written");
        let job = pipeline_over(Some(dir.path()))
            .scan_job(PROGRAM)
            .expect("the workspace is configured, so the job exists");

        let algorithm = find_row("algorithm-recognition");
        assert!(
            algorithm
                .run_with_options(
                    job.scan_context(),
                    ScanRunOptions {
                        set_override_file: Some(patterns),
                        ..ScanRunOptions::default()
                    },
                )
                .await,
            "the algorithm row scans the fixture from the override file's set"
        );
        let document = AlgorithmPersistor::new(dir.path())
            .load(PROGRAM)
            .expect("the overridden run filed an algorithm document");
        assert!(
            document
                .hints
                .iter()
                .all(|hint| hint.algorithm == "custom_fixture_scan_shape")
                && !document.hints.is_empty(),
            "the document carries the file's claims and no built-in ones: {:?}",
            document
                .hints
                .iter()
                .map(|hint| &hint.algorithm)
                .collect::<Vec<_>>()
        );

        let known_library = find_row("known-library");
        assert!(
            known_library
                .run_with_options(
                    job.scan_context(),
                    ScanRunOptions {
                        set_override_file: Some(signatures),
                        ..ScanRunOptions::default()
                    },
                )
                .await,
            "the known-library row scans the fixture from the override file's set"
        );
        let document = calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path())
            .load(PROGRAM)
            .expect("the overridden run filed a known-library document");
        assert!(
            document
                .findings
                .iter()
                .any(|finding| finding.function() == "strnlen"
                    && finding.target() == "custom_fixture_strlen")
                && document
                    .findings
                    .iter()
                    .all(|finding| finding.target() == "custom_fixture_strlen"),
            "the document identifies the fixture's scan loop only through the file's \
             renamed symbol — the starter set never named it: {:?}",
            document
                .findings
                .iter()
                .map(|finding| finding.target())
                .collect::<Vec<_>>()
        );
    }

    /// A malformed set-override file fails the row's own scan loudly,
    /// naming the file's path in the warning, and the row files nothing
    /// — for both override-capable rows. The row degrades exactly as its
    /// descriptor spells a failed scan; the shared shape never parsed
    /// the file itself.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn a_malformed_set_override_file_fails_the_override_capable_rows_naming_the_path() {
        for (row_name, database_wording) in [
            ("algorithm-recognition", "could not read pattern database"),
            ("known-library", "could not read signature database"),
        ] {
            let dir = TempDir::new().expect("temp workspace");
            let malformed = dir.path().join("broken-database.json");
            std::fs::write(&malformed, "{ this is not a database document")
                .expect("malformed override file written");
            let job = pipeline_over(Some(dir.path()))
                .scan_job(PROGRAM)
                .expect("the workspace is configured, so the job exists");

            let row = find_row(row_name);
            assert!(
                !row.run_with_options(
                    job.scan_context(),
                    ScanRunOptions {
                        set_override_file: Some(malformed.clone()),
                        ..ScanRunOptions::default()
                    },
                )
                .await,
                "the {row_name} row's scan fails on its malformed override file"
            );
            assert!(
                logs_contain(database_wording) && logs_contain(&malformed.display().to_string()),
                "the {row_name} row's scan-failure warning names the bad file: \
                 {malformed:?}"
            );
            assert!(
                !row.document_path(dir.path(), PROGRAM).is_file(),
                "the failed {row_name} scan left no document behind"
            );
        }
    }

    /// The write-suppression signal reaches the type-database row's own
    /// engine construction: with the option set, the row scans the
    /// fixture green, files its document, and writes nothing back — the
    /// tag path never runs, so the tag-write refusal warning never fires.
    /// The defaults change nothing: the option run's document is the
    /// default run's document, stamps aside.
    ///
    /// One limitation is recorded rather than hidden: the fixture target
    /// is pure C with no MSVC-RTTI vtables (its scan recovers zero
    /// vtables), and the Kuna seam refuses every tag write by name, so
    /// the registry seam cannot exhibit a tag write this option
    /// prevented — the engine-level pin for the write itself stays
    /// `without_tagging_writes_nothing_back` in the type-database crate.
    /// What this test pins is the seam the option travels: the signal
    /// reaches the row's build, the run stays green, the filed record is
    /// byte-familiar, and the run writes no function tag back.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn the_write_suppression_option_holds_the_type_database_row_to_its_reads() {
        let row = find_row("type-database");
        let document_of = |workspace: &std::path::Path| {
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(TypeDatabasePersistor::new(workspace).path_for(PROGRAM))
                    .expect("the row filed its document"),
            )
            .expect("the document is JSON")
        };

        let default_dir = TempDir::new().expect("temp workspace");
        let default_job = pipeline_over(Some(default_dir.path()))
            .scan_job(PROGRAM)
            .expect("the workspace is configured, so the job exists");
        assert!(
            row.run(default_job.scan_context()).await,
            "the type-database row scans the fixture with the defaults"
        );

        let suppressed_dir = TempDir::new().expect("temp workspace");
        let suppressed_job = pipeline_over(Some(suppressed_dir.path()))
            .scan_job(PROGRAM)
            .expect("the workspace is configured, so the job exists");
        assert!(
            row.run_with_options(
                suppressed_job.scan_context(),
                ScanRunOptions {
                    suppress_write_back: true,
                    ..ScanRunOptions::default()
                },
            )
            .await,
            "the type-database row scans the fixture with the write suppression set"
        );
        assert_eq!(
            stamped_document(document_of(suppressed_dir.path())),
            stamped_document(document_of(default_dir.path())),
            "the suppressed run's document is exactly the default run's — \
             suppressing the write-back changes no part of the scan's record"
        );
        assert!(
            !logs_contain("Could not tag vtable method"),
            "the suppressed run wrote no vtable-method tag back — the tag path never ran"
        );
    }

    /// The overwrite policy, pinned at the registry level: the defaults
    /// never re-run a scan whose document is filed — even an override
    /// option riding the same run short-circuits ahead of any engine
    /// read — while the overwrite policy bypasses the short-circuit and
    /// replaces the document with the fresh scan's result. Failure
    /// semantics survive the bypass: a forced re-scan that fails (here
    /// on a malformed override file, failing before any engine read)
    /// answers `false` and leaves the previously filed document exactly
    /// as it was — a save only ever follows a successful scan.
    #[tokio::test]
    async fn the_overwrite_policy_bypasses_the_short_circuit_without_losing_a_failed_rescan() {
        let dir = TempDir::new().expect("temp workspace");
        let patterns = dir.path().join("custom-patterns.json");
        std::fs::write(&patterns, custom_pattern_database_document())
            .expect("custom pattern database written");
        let broken = dir.path().join("broken-patterns.json");
        std::fs::write(&broken, "{ this is not a database document")
            .expect("malformed override file written");
        let job = pipeline_over(Some(dir.path()))
            .scan_job(PROGRAM)
            .expect("the workspace is configured, so the job exists");
        let row = find_row("algorithm-recognition");
        let persistor = AlgorithmPersistor::new(dir.path());

        assert!(
            row.run(job.scan_context()).await,
            "the cold run files the built-in set's document"
        );
        let built_in = persistor
            .load(PROGRAM)
            .expect("the cold run filed an algorithm document");
        assert!(
            built_in
                .hints
                .iter()
                .any(|hint| hint.algorithm == "linear_search"),
            "the built-in set claims the fixture's scan loops — the baseline \
             the overwrite replaces: {:?}",
            built_in
                .hints
                .iter()
                .map(|hint| &hint.algorithm)
                .collect::<Vec<_>>()
        );

        assert!(
            row.run_with_options(
                job.scan_context(),
                ScanRunOptions {
                    set_override_file: Some(patterns.clone()),
                    ..ScanRunOptions::default()
                },
            )
            .await,
            "the default policy answers a filed document from the short-circuit"
        );
        let short_circuited = persistor.load(PROGRAM).expect("document still filed");
        assert_eq!(
            short_circuited.hints, built_in.hints,
            "the default policy never re-ran the scan — the override option alone \
             does not bypass the short-circuit"
        );

        assert!(
            row.run_with_options(
                job.scan_context(),
                ScanRunOptions {
                    set_override_file: Some(patterns),
                    overwrite_filed_document: true,
                    ..ScanRunOptions::default()
                },
            )
            .await,
            "the overwrite policy re-runs a row whose document is already filed"
        );
        let replaced = persistor.load(PROGRAM).expect("the forced re-scan saved");
        assert!(
            !replaced.hints.is_empty()
                && replaced
                    .hints
                    .iter()
                    .all(|hint| hint.algorithm == "custom_fixture_scan_shape"),
            "the forced re-scan replaced the filed document with the override \
             file's result: {:?}",
            replaced
                .hints
                .iter()
                .map(|hint| &hint.algorithm)
                .collect::<Vec<_>>()
        );

        assert!(
            !row.run_with_options(
                job.scan_context(),
                ScanRunOptions {
                    set_override_file: Some(broken),
                    overwrite_filed_document: true,
                    ..ScanRunOptions::default()
                },
            )
            .await,
            "a forced re-scan on a malformed override file answers false"
        );
        let survived = persistor
            .load(PROGRAM)
            .expect("the previous document survived");
        assert_eq!(
            survived.hints, replaced.hints,
            "the failed forced re-scan left the previously filed document in place"
        );
    }

    /// The drift spec #301 records, closed: a batch that has never had
    /// `calxgloss libmatch` run still leaves a known-library document
    /// behind — the fifteenth row runs the scan from the batch preamble,
    /// on the batch's shared read source with the built-in starter
    /// signature set, and files it exactly where the two readers — the
    /// retry/escalation prompt path and the call-graph Skip
    /// classification — already look (issue #306).
    #[tokio::test]
    async fn a_cold_batch_that_never_ran_the_command_files_a_known_library_document() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

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

        let persistor = calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path());
        let document = persistor.path_for(calxgloss_testfixtures::TARGET_FILE_NAME);
        assert!(
            document.starts_with(dir.path().join("re").join("analysis").join("libmatch")),
            "the known-library document rides the analysis-document convention: {}",
            document.display()
        );
        assert!(
            document.is_file(),
            "a cold batch that never ran the command still leaves a known-library document"
        );

        let result = persistor
            .load(calxgloss_testfixtures::TARGET_FILE_NAME)
            .expect("the batch filed a loadable known-library document");
        assert_eq!(
            result.metadata.binary,
            calxgloss_testfixtures::TARGET_FILE_NAME,
            "the document is keyed to the batch's binary"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.function() == "strnlen" && finding.target() == "strlen"),
            "the document says something, not just metadata: the Kuna-dialect starter set \
             identifies the fixture's statically linked scan loops ({})",
            result.findings.len()
        );
    }

    /// The payoff the escalation prompt path waited for: after that cold
    /// batch, the per-attempt known-library read over the batch's binary
    /// finds a document — the scan's real record, not the absence of one
    /// (issue #306). What the record carries is now identifications: the
    /// starter set learned to speak Kuna's dialect (#309 closed the gap
    /// #306 recorded), so the canary this test used to be has strengthened
    /// to pinning a real finding for one of the scan order's callees, and
    /// must never loosen back to an empty document.
    #[tokio::test]
    async fn the_escalation_prompt_reads_the_known_library_document_the_batch_filed() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

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

        let document = crate::retry::helpers::load_libmatch_result(
            Some(dir.path()),
            calxgloss_testfixtures::TARGET_FILE_NAME,
        )
        .expect("the escalation read finds the document the batch filed, not nothing");
        assert_eq!(
            document.metadata.binary,
            calxgloss_testfixtures::TARGET_FILE_NAME,
            "the reader lands on the pipeline's own document for this binary"
        );
        assert!(
            document
                .findings
                .iter()
                .any(|finding| finding.function() == "strnlen" && finding.target() == "strlen"),
            "the pipeline's own document carries real identifications — the \
             starter set speaks Kuna now (#309), and this test strengthens, \
             never loosens: {:?}",
            document.findings
        );
    }

    /// The other reader's seam: a call graph built after the phase finds
    /// the known-library document where the phase filed it, under the
    /// same binary key. The floor behavior itself stays pinned in the
    /// analysis crate's classification tests (issue #265); what is pinned
    /// here is the join — the batch preamble files the very document
    /// `build_enriched_call_graph` loads for that binary (issue #306).
    /// Two limits travel with the join, recorded rather than hidden: the
    /// built-in set's body match scores 60 below the Skip floor of 80,
    /// so end-to-end `Skip` never fires on pipeline findings — cold runs
    /// carry real identifications now (#309), but none at the floor —
    /// and the call-graph batch path receives a pre-built graph, so that
    /// path still only benefits when a document already existed (spec
    /// #301).
    #[tokio::test]
    async fn a_call_graph_built_after_the_phase_finds_the_known_library_document() {
        let dir = TempDir::new().expect("temp workspace");
        let (pipeline, _) = cached_pipeline(dir.path());
        pipeline.begin_cached_source(PROGRAM).await;
        pipeline.run_prebatch_scans(PROGRAM).await;

        assert!(
            calxgloss_libmatch::persist::LibmatchPersistor::new(dir.path()).exists(PROGRAM),
            "the phase filed the document under the batch's binary key"
        );

        let kuna = fixture_kuna();
        let graph = calxgloss_analysis::build_enriched_call_graph(&kuna, PROGRAM, dir.path(), None)
            .await
            .expect("the graph build runs over the workspace the phase produced");
        assert!(
            !graph.functions.is_empty(),
            "the graph build classifies the fixture's listing"
        );
        assert!(
            graph.functions.iter().all(|function| !matches!(
                function.node_category,
                calxgloss_types::NodeCategory::Skip
            )),
            "nothing in the pipeline's document meets the Skip floor of 80, so the \
             structural cascade alone decides — the floor gate holds"
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

    /// The prefactor the fan-out needs: a registered row's scan handed
    /// to a spawned task answers exactly like the inline run — same
    /// verdict, and the same persisted document once the wall-clock
    /// scan stamp is set aside (issue #237, held at the registry seam
    /// since issue #307).
    #[tokio::test]
    async fn a_scan_job_handed_to_a_spawned_task_matches_the_inline_call() {
        let row_location = |workspace: &std::path::Path| {
            find_row("type-database").document_path(workspace, "eqmain.dll")
        };
        let inline_dir = TempDir::new().expect("temp workspace");
        let inline_job = pipeline_over(Some(inline_dir.path()))
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");
        let inline = find_row("type-database")
            .run(inline_job.scan_context())
            .await;
        assert!(inline, "the inline scan succeeds over the fixture");

        let job_dir = TempDir::new().expect("temp workspace");
        let job = pipeline_over(Some(job_dir.path()))
            .scan_job("eqmain.dll")
            .expect("the workspace is configured, so the job exists");
        let spawned =
            tokio::spawn(async move { find_row("type-database").run(job.scan_context()).await })
                .await
                .expect("the scan task runs to completion");
        assert_eq!(
            spawned, inline,
            "the job on a task answers like the inline call"
        );

        // The scan stamp is wall-clock, not a finding: zero it so the
        // comparison is over what the scan actually recovered.
        let document = |workspace: &std::path::Path| {
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(row_location(workspace)).expect("the scan's document"),
            )
            .expect("the document is JSON")
        };
        assert_eq!(
            stamped_document(document(job_dir.path())),
            stamped_document(document(inline_dir.path())),
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

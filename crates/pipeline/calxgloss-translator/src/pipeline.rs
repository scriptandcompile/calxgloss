//! Translation pipeline — the full end-to-end translation workflow.
//!
//! This module holds the [`TranslationPipeline`] struct, which combines every
//! piece needed to turn one disassembled function into Rust:
//!
//! 1. Read the function's data from the analysis engine (Kuna decompiler output)
//! 2. Tag Windows API calls with their PAL mappings
//! 3. Generate the baseline test's inputs from the signature and disassembly
//! 4. Build the evidence bundle that carries all this context into one prompt
//! 5. Send that prompt to the LLM, which writes the Rust code
//! 6. Return the translated code together with its metadata
//!
//! # Example
//!
//! A pass is described by [`PipelineSpec`](assembly::PipelineSpec) and built by
//! [`assemble`](assembly::assemble): the pipeline's constructor is
//! assembly-internal, so a pipeline built by hand does not compile outside
//! assembly (issue #328).
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

/// The scan phase's name in progress reporting: one row carrying
/// "n of m functions consumed" for the whole group of fifteen pre-batch
/// evidence scans, instead of a separate row per scan that restarts with
/// each scan (issue #239).
const SCAN_PHASE: &str = "evidence scans";

/// At most four evidence scans run at a time — the scan phase's fan-out
/// window (issue #240).
///
/// The cap does not protect the analysis engine. The engine handles one
/// request at a time either way, and the scan read cache already turns
/// simultaneous requests for one function body into a single engine request.
///
/// The cap exists to limit peak memory (each running scan keeps its own
/// copies of function bodies, while the shared cache stores each body
/// once) and to keep the scan phase's single dashboard row readable.
///
/// Four was chosen by measurement (issue #241). On eqmain.dll (4,076
/// functions), raising the cap from four to eleven changed warm-cache
/// speed almost nothing (56.6 s → 57.3 s), was slower on cold reads
/// (113.9 s → 153.8 s, because more scans in flight stack up waiting work
/// on the same listing data the engine is processing), and added about a
/// seventh more kept decompilation copies. So four stands. Raising it
/// later is a one-line change, guarded by
/// `the_scan_phase_window_never_runs_more_than_the_named_cap_at_a_time`,
/// which pins the phase at or under this constant and never at one scan.
const MAX_CONCURRENT_EVIDENCE_SCANS: usize = 4;

/// One evidence scan as the fan-out's unit of work: takes its owned
/// [`ScanJob`] and hands back the scan's boxed future. Each scan's future
/// is a distinct type, so the window boxes them to move them onto tasks
/// (issue #240). Registered rows arrive as closures that capture their row,
/// hence the boxed `FnOnce` rather than the plain `fn` pointer (issue #302).
type EvidenceScanTask =
    Box<dyn FnOnce(ScanJob) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static>;

/// One evidence scan as it passes through the fan-out window: it counts
/// itself in, runs, and counts itself out. The phase records the highest
/// count it ever reached, so the window's cap is a tested contract rather
/// than only a comment (issue #241). A named async fn again, so that the
/// spawned future is `'static` (issue #240).
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
/// outcome; the phase's window, progress reporting, and joins wrap it
/// from outside (issues #302, #305).
async fn run_registered_scan(row: ScanDescriptor, job: ScanJob, latches: ScanLatches) {
    let mut ctx = job.scan_context();
    ctx.latches = latches;
    row.run(ctx).await;
}

/// The registered rows as ready-to-run tasks: each row moves into its own
/// closure, boxed so the window can move it onto a task (issue #240). The
/// completion latches are attached to each row's context from the table's
/// own declarations — the latch armed for this row's name is the one its
/// run publishes on every exit, and the latch named by its `waits_for` is
/// the one its pre-scan hook waits on (issue #305). No row carries its own
/// latch field; the ordering edge is table data, and this is the only way
/// a scan enters the phase (issue #308).
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

/// Full translation pipeline: analysis reads → Analysis → tests → LLM → Rust code.
///
/// This is the main entry point of the translation workflow. It runs every
/// step needed to turn one function's disassembly into working Rust:
///
/// 1. Read the function's data from the analysis engine (decompiler output)
/// 2. Tag Windows API calls with their PAL mappings using the analyzer
/// 3. Generate the baseline test's inputs from the signature and disassembly
/// 4. Build the evidence bundle that carries all this context into one prompt
/// 5. Send that prompt to the LLM, which writes the Rust code
/// 6. Return a [`Translation`] with the code and all its metadata
///
/// # Construction
///
/// The constructor is assembly-internal: the only way to create a pipeline is
/// to describe the pass — a
/// [`PipelineSpec`](crate::assembly::PipelineSpec) — and assemble it with
/// [`assemble`](crate::assembly::assemble) (or
/// [`assemble_patch`](crate::assembly::assemble_patch) for a pass that
/// loads its own analysis engine). Building a pipeline by hand, outside
/// assembly, does not compile (issue #328).
pub struct TranslationPipeline {
    /// The loaded Kuna program that every analysis read goes through.
    kuna: KunaSource,

    /// Client that sends prompts to the LLM.
    llm: LlmClient,

    /// Windows API → Rust mapping table.
    api_mappings: ApiMappings,

    /// Analyzer used for DLL classification and API tagging.
    analyzer: Analyzer,

    /// The built-in root-symbol patterns behind the single-function path's
    /// guard: when a root symbol (entry point, import thunk) is named
    /// directly, the pipeline stops before any scan fetch or LLM spend,
    /// instead of translating a body that holds no logic of its own — the
    /// call-graph batch path would have skipped this function anyway.
    root_detector: calxgloss_callgraph::RootDetector,

    /// Test generator for the baseline test's inputs, when one is configured.
    testgen: Option<TestGenerator>,

    /// Binary name override used as context when generating tests.
    target_binary: Option<BinaryIdentity>,

    /// Workspace root path for experiment logging, when one is set.
    workspace: Option<std::path::PathBuf>,

    /// Broadcast channel for progress events, when one is attached. Events
    /// go out at the pipeline's main steps, so a WebSocket server can
    /// subscribe and show live progress.
    #[allow(dead_code)]
    events: Option<TranslationEvents>,

    /// Detects context-window faults. Built once, from the LLM client's
    /// `context_window` setting.
    context_detector: ContextWindowDetector,

    /// Checks LLM-written code for invented symbols. Built from the
    /// analysis engine's symbols and the PAL API catalogue; `None` when no
    /// analysis engine source is available.
    hallucination_detector: Option<HallucinationDetector>,

    /// When `true`, skip call-graph extraction in `fetch_function`.
    ///
    /// The call graph (caller and callee names) is what the higher context
    /// tiers (ModuleContext, FullModule) use to add neighbor information to
    /// prompts. With this flag set, those context tiers fall back to less
    /// context instead of context taken from the call graph.
    no_callgraph: AtomicBool,

    /// When `true`, print call-graph statistics after the graph is built.
    ///
    /// Useful for debugging: it shows the call graph's shape before
    /// translation starts — how many functions there are, how they split
    /// between root, middle, and leaf, the call types, and the external API count.
    callgraph_verbose: bool,

    /// Explicit cache directory for call-graph JSON files.
    ///
    /// When set, call graphs are saved to and loaded from this directory
    /// instead of the default `{workspace}/re/analysis/` path, so the
    /// `--callgraph-cache` CLI flag can point the cache somewhere else.
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

    /// Port to the git history's accepted (merged) translations, used for
    /// carry-over seeding (issue #299).
    ///
    /// The CLI sets it when git is enabled; everywhere else it is `None`,
    /// which leaves the queue exactly as it is today. The translator never
    /// runs git itself — this trait object is its only way to reach git,
    /// the same port shape the version-pairing trigger uses.
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

    /// The batch's shared cached scan source, set up by
    /// [`begin_cached_source`](Self::begin_cached_source) at the top of a
    /// batch and read by every scan, the call-graph build, and the
    /// retry/escalation helpers through [`scan_source`](Self::scan_source).
    ///
    /// A second batch over the same workspace and an unchanged binary
    /// replays from the disk tier with no live reads at all.
    cached_source: Mutex<Option<CachedScanSource>>,

    /// What the analysis seam can and cannot report, fetched exactly once
    /// when the batch's cached scan source opens, and held for the whole
    /// batch (issue #355).
    ///
    /// The fetch goes out beside
    /// [`begin_cached_source`](Self::begin_cached_source): the report travels
    /// with the source it describes, so reading it costs no extra engine
    /// read. A batch whose cache never opened holds the live engine's own
    /// declaration instead — the same words, read from the source its reads
    /// really go through. Prompts never ask again; they read this stored copy.
    seam_report: Mutex<calxgloss_types::CapabilityReport>,

    /// The batch's unknown residue: the records its producers have admitted
    /// so far — the units' evidence folds (issue #369) and each unit's
    /// seam-residue derivation from the held capability report (issue #371).
    ///
    /// `None` says no unit's fold has read a document and no seam admission
    /// has filed yet this batch — the ledger writer files nothing, because
    /// nothing has been looked at; the absence of a ledger document reads as
    /// *unknown* by ADR-0053's absent-field rule, and a writer that filed an
    /// empty set nobody derived would fake a known-and-none. `Some` holds
    /// the records in first-seen order, deduplicated by id: re-running a
    /// unit's fold or a unit's posture re-derives the same ids, never a
    /// second question for one gap. Reset at the start of every batch; the
    /// per-binary ledger merge ([`file_unknown_ledger`](Self::file_unknown_ledger))
    /// folds this set against the landed document at every unit
    /// boundary, so the document is always the current derived set —
    /// never an append log.
    unknown_residue: Mutex<Option<Vec<calxgloss_types::UnknownRecord>>>,

    /// The scan phase's fan-out high-water mark: the most evidence scans
    /// that ran at the same time during the latest
    /// [`run_prebatch_scans`](Self::run_prebatch_scans), recorded as each
    /// scan enters the window (issue #241).
    ///
    /// The window is one named decision ([`MAX_CONCURRENT_EVIDENCE_SCANS`]),
    /// and this is the test behind it: the phase reports its own high-water
    /// mark, so a test can pin that the scans never exceed the cap and never
    /// fall back to one at a time. Reset at the start of every phase.
    scan_window_high_water: Arc<AtomicUsize>,

    /// Force the batch's scan read cache cold (issue #106).
    ///
    /// The CLI's `--refresh-cache` flag sets this. When true,
    /// [`begin_cached_source`](Self::begin_cached_source) opens the cache
    /// through [`CachedScanSource::new_refresh`]: the disk tier holding the
    /// binary's current bytes is wiped before the run, every read goes
    /// live, and the cache is rewritten afterwards. The manifest keys on the
    /// binary's bytes, so a hand-edited cache is the one kind of staleness
    /// it cannot notice — this is the way out of that case.
    refresh_cache: bool,

    /// Shared stop signal, for shutting a live run down cleanly.
    ///
    /// When it is set and stopped, the batch loops break at the next
    /// **unit boundary**: the unit in flight finishes and is saved before
    /// the run stops. The web server's shutdown and restart endpoints set it.
    stop: Option<StopSignal>,

    /// Shared handle for the pipeline's lifecycle (issue #90, W2.1).
    ///
    /// When set, the batch loops check it at each **unit boundary**:
    /// `Paused` holds the loop until the run resumes, and
    /// `Stopping`/`Complete` end the batch after the unit in flight has
    /// finished and been reported to the caller (which saves it and cleans
    /// up its branch). The web control endpoints drive this.
    pipeline_control: Option<PipelineControl>,

    /// Shared handle for cancelling the unit in flight (issue #91, W2.2).
    ///
    /// When set, each unit is registered as in-flight while the batch loop
    /// works on it; the web server's cancel-current endpoint cancels the
    /// unit in flight, and the loop stops it at the first safe point —
    /// including in the middle of an LLM call — records that attempt as a
    /// failure, and moves on to the next unit.
    unit_cancellation: Option<UnitCancellation>,

    /// Shared handle for the translation scope (issue #93, W2.5).
    ///
    /// When set, the batch loops apply it when they pick from the queue:
    /// skipped functions never enter the plan at all, and priority
    /// functions sort ahead of the rest. Its limits bound spending — max
    /// attempts caps the retry config, max context tier caps automatic
    /// escalation, and the token budget stops the batch at the next unit
    /// boundary once spending reaches it. The web scope endpoints drive it.
    scope: Option<ScopeControl>,

    /// Shared handle for per-unit reviewer overrides (issue #96, W2.7).
    ///
    /// When set, the context builder honors it for that unit: a forced
    /// context tier replaces the automatic choice, a forced retry strategy
    /// replaces the configured one, and custom hints reach the unit's
    /// prompts. The batch loops also drop override-skipped units when they
    /// pick from the queue, so one hopeless function never blocks the rest
    /// of its binary's pass. The web override endpoints drive it.
    overrides: Option<calxgloss_types::OverrideControl>,
}

impl TranslationPipeline {
    /// Create a new translation pipeline over a loaded Kuna program, an LLM
    /// client, and a PAL mapping table.
    ///
    /// This sets up the full pipeline with the default analyzer and builds the
    /// context-window detector from the LLM client's `context_window` setting,
    /// so context-window faults are detected automatically.
    ///
    /// **Assembly-internal** (issue #328): this constructor and every `with_*`
    /// setter below it exist to build a pass in the
    /// [`assembly`](crate::assembly) module — [`wire_pass`](crate::assembly)
    /// is the only production caller in the workspace, pinned at source level
    /// by assembly's own tests. Outside this crate the compiler refuses a
    /// hand-built pipeline; tests inside the crate may still build one
    /// directly to pin behavior around the pipeline.
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
            seam_report: Mutex::new(calxgloss_types::CapabilityReport::default()),
            unknown_residue: Mutex::new(None),
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
    /// callee names). This speeds up translation when call-graph context is
    /// not needed.
    pub(crate) fn with_no_callgraph(self) -> Self {
        self.no_callgraph.store(true, Ordering::Relaxed);
        self
    }

    /// Turn on call-graph statistics output.
    ///
    /// When set, [`translate`](Self::translate) prints a summary of the call
    /// graph after it is built: function count, root/middle/leaf split,
    /// call-type breakdown, and the external API count.
    pub(crate) fn with_callgraph_verbose(mut self) -> Self {
        self.callgraph_verbose = true;
        self
    }

    /// Set the workspace root path for experiment logging.
    ///
    /// When set, every translation attempt is recorded in
    /// `<workspace>/re/analysis/prompt_strategy_log.json`.
    pub(crate) fn with_workspace(mut self, workspace: impl Into<std::path::PathBuf>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    /// Attach a progress-event emitter for live WebSocket streaming.
    ///
    /// When set, the pipeline sends a [`ProgressEvent`] at each major step.
    /// A subscriber to the channel (usually a WebSocket server) can pass
    /// those events on to connected clients as they happen.
    pub(crate) fn with_events(mut self, events: TranslationEvents) -> Self {
        self.events = Some(events);
        self
    }

    /// Attach a shared stop signal, for shutting a live run down cleanly.
    ///
    /// When the signal is stopped (for example by the web server's shutdown
    /// endpoint), the batch loops break at the next **unit boundary**: the
    /// unit in flight finishes, and its result is saved before the run
    /// stops.
    pub(crate) fn with_stop_signal(mut self, stop: StopSignal) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Attach the shared [`PipelineControl`] lifecycle handle (issue #90,
    /// W2.1).
    ///
    /// The web server's pause/resume/stop endpoints drive it. The batch
    /// loops check it at each **unit boundary**: a pause holds the loop
    /// (no unit is interrupted mid-LLM-call), and a stop lets the unit in
    /// flight finish before the batch ends.
    pub(crate) fn with_pipeline_control(mut self, control: PipelineControl) -> Self {
        self.pipeline_control = Some(control);
        self
    }

    /// Attach the shared [`UnitCancellation`] handle (issue #91, W2.2).
    ///
    /// The web server's cancel-current endpoint drives it. The batch loop
    /// marks each unit in-flight while it works on it and stops that unit
    /// as soon as a cancellation arrives — the first safe point is in the
    /// middle of an LLM call, because an aborted attempt has saved nothing.
    /// The cancelled unit is recorded as a failure and the run moves on to
    /// the next unit.
    pub(crate) fn with_unit_cancellation(mut self, cancellation: UnitCancellation) -> Self {
        self.unit_cancellation = Some(cancellation);
        self
    }

    /// Attach the shared [`ScopeControl`] handle (issue #93, W2.5).
    ///
    /// The web server's scope endpoints drive it. The batch loops consult
    /// it at **queue selection** — a skipped function never enters the
    /// plan, and a priority function sorts ahead of the rest of the
    /// queue — and at each **unit boundary** for the per-binary pause
    /// (issue #219, part of #217): a binary the operator has paused ends
    /// its batch there instead of being held open. Its constraints cap the
    /// retry config, context tier escalation, and the run's token budget.
    pub(crate) fn with_scope(mut self, scope: ScopeControl) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Attach the shared [`OverrideControl`] handle (issue #96, W2.7).
    ///
    /// The web server's override endpoints drive it. The translation
    /// context builder consults it per unit — a forced context tier
    /// replaces the automatic choice, a forced retry strategy replaces the
    /// configured one, and custom hints reach the unit's prompts — while
    /// the batch loops drop override-skipped units at queue selection.
    pub(crate) fn with_overrides(mut self, overrides: calxgloss_types::OverrideControl) -> Self {
        self.overrides = Some(overrides);
        self
    }

    /// Whether the attached stop signal, if any, has been requested.
    fn stop_requested(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| s.is_stopped())
    }

    /// Check the lifecycle control at a unit boundary (issue #90, W2.1).
    ///
    /// Returns `false` when the batch must end: `Stopping` (a stop was
    /// requested) or `Complete` (stop-current ended the run) halt after the
    /// unit in flight. A stop signal that arrives while the loop is held in
    /// a pause releases the hold the same way — shutting down must never
    /// wait on a paused run. Returns `true` when the next unit may start.
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
    /// A run-level pause holds the loop at a unit boundary until the operator
    /// resumes it; a paused binary, by contrast, **ends** the batch at the
    /// next boundary — the batch returns instead of waiting, so the run can
    /// move on to another binary. The batch loops check this just before
    /// [`control_allows_next_unit`](Self::control_allows_next_unit), so the
    /// pause is honored at the boundary even while the run itself is on
    /// hold. With no scope handle attached, no binary is ever paused.
    fn binary_paused(&self, binary: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|scope| scope.is_paused(binary))
    }

    /// Resolves once a cancellation has arrived for the named unit (issue
    /// #91, W2.2). With no cancellation handle attached it never resolves,
    /// so the `select!` in the batch loop simply never takes the abort branch.
    ///
    /// The poll interval is short (50 ms) because cancel-current exists to
    /// stop a runaway unit from spending tokens *now* — unlike a pause,
    /// which only matters at unit boundaries.
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
    /// overrides when the queue is selected (issues #93, W2.5 and #96, W2.7).
    ///
    /// Skipped functions leave the plan before the first unit starts — they
    /// are never attempted — and priority functions sort ahead of the rest
    /// of the queue: the priority group keeps its relative order, and
    /// everything after it keeps its original order (a stable split). A
    /// reviewer override's skip flag removes its one unit the same way, so
    /// one hopeless function never blocks the rest of its binary's pass.
    /// With neither handle attached, the list passes through untouched.
    ///
    /// `name_of` reads the function name out of a queue item, so the same
    /// filtering works for plain name lists and call-graph plan entries.
    fn apply_function_scope<T>(
        &self,
        binary: &str,
        items: Vec<T>,
        name_of: impl Fn(&T) -> &str,
    ) -> Vec<T> {
        // W2.7: reviewer-skipped units leave the plan at the same point in
        // the selection as operator-skipped functions.
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
    /// constraint caps spending, it never raises the limit), and
    /// `max_context_tier` goes into [`RetryLoopCtx`](retry::RetryLoopCtx),
    /// where it caps automatic context tier escalation. With no scope
    /// handle attached the config passes through untouched.
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
    /// #93). No handle, or no budget, means never reached — the batch runs
    /// on. Checked at unit boundaries, like the stop signal and the pause.
    fn budget_exhausted(&self) -> bool {
        self.scope.as_ref().is_some_and(|s| s.budget_exhausted())
    }

    /// Add a completed unit's attempt tokens to the run's token budget
    /// (issue #93). An attempt that never reported a token count adds
    /// nothing.
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

    /// Send a progress event, if an event emitter is attached.
    fn emit(&self, event: ProgressEvent) {
        if let Some(ref emitter) = self.events {
            let _ = emitter.emit(event);
        }
    }

    /// Set the test generator used to create the baseline test's inputs.
    pub(crate) fn with_testgen(mut self, testgen: TestGenerator) -> Self {
        self.testgen = Some(testgen);
        self
    }

    /// Set the binary name used as context when generating tests.
    pub(crate) fn with_target_binary(mut self, binary: impl Into<BinaryIdentity>) -> Self {
        self.target_binary = Some(binary.into());
        self
    }

    /// Attach a hallucination detector that was built elsewhere, for
    /// checking LLM responses. Call this after `new()` once the runtime
    /// context is available; skip it in unit tests that do not need checking.
    pub(crate) fn with_hallucination_detector(mut self, detector: HallucinationDetector) -> Self {
        self.hallucination_detector = Some(detector);
        self
    }

    /// Set an explicit cache directory for call-graph JSON files.
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
    /// With a workspace also set, a batch opens a shared
    /// [`CachedScanSource`] for this binary at its start; every scan, the
    /// call-graph build, and the retry/escalation helpers read through it,
    /// so a second batch over the same workspace and an unchanged binary
    /// needs no live engine reads. Without it, batches read live.
    pub(crate) fn with_binary_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    /// Attach the port to the git history's accepted translations, so this
    /// pipeline's batches can use carry-over seeding (issue #299).
    ///
    /// A batch then starts attempt 1 for every confidently paired function
    /// (per the pairing documents the scan step leaves behind) from its twin
    /// in the previous version, when that twin's translation was accepted:
    /// that code is copied in verbatim and goes through the same baseline
    /// capture and full verification against the new bytes. Without this, or
    /// without a workspace and binary path also set, batches translate from
    /// scratch, exactly as they do today.
    pub(crate) fn with_accepted_attempt_source(
        mut self,
        source: Arc<dyn crate::carry_over::AcceptedAttemptSource>,
    ) -> Self {
        self.accepted_attempt_source = Some(source);
        self
    }

    /// Force the scan read cache cold for this pipeline's batches (issue
    /// #106).
    ///
    /// The CLI's `--refresh-cache` flag sets it. Each batch then wipes the
    /// disk tier for the binary's current bytes before reading: every
    /// engine read goes live once and is written back. The manifest keys on
    /// the binary's bytes, so a hand-edited cache is the one kind of
    /// staleness it cannot notice — this is the way out of that case.
    /// Without it, warm batches replay from the cache unchanged.
    pub(crate) fn with_refresh_cache(mut self) -> Self {
        self.refresh_cache = true;
        self
    }

    /// Translate one function from the loaded program.
    ///
    /// This is the main entry point of the pipeline. It reads all the data
    /// from the analysis engine, analyzes the function, generates the
    /// baseline test's inputs, builds the prompt, and sends it to the LLM.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing the function. Recorded on the result;
    ///   the lookup runs against the loaded program, which must be this DLL.
    /// * `function` — The name of the function to translate.
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata, or an
    /// error if any step of the pipeline fails.
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

        // Root symbols — entry points and import thunks — hold no logic to
        // translate. The call-graph batch path already skips or stubs them,
        // but an explicitly named function gets here unchecked, and a
        // `DelayLoad_` thunk is the classic trap: its resolved-import jump
        // decompiles to an unrecovered jump table plus a bare `return`, and
        // the LLM translates that broken result as if it were real. Stop
        // before the scan fetch, before any token is spent.
        self.refuse_root_function(binary, function)?;

        // Report: translation started
        self.emit(ProgressEvent::TranslationStarted {
            binary: binary.to_string().into(),
            function: function.to_string(),
        });

        // Step 1: read the function's metadata from the analysis engine
        let function_info = self.fetch_function(binary, function).await?;
        info!(binary, function, "Fetched function metadata");

        // Body-shape guard (issue #269): an import thunk the symbol table
        // named after its import — `SetCursor` carrying only
        // `SetCursor(); return;` — matches no name-based root pattern, but
        // its body is one unconditional call to its own name. Stop it here,
        // before the prompt is built and any token is spent: the LLM would
        // translate that apparent recursion into a Rust function that calls
        // itself.
        self.refuse_self_call_thunk(binary, function, &function_info.decompiler_output)?;

        // Triage: Ghidra's analysis failures arrive inside the pseudo-C as
        // WARNING comments. Name them before the LLM sees the body — an
        // unrecovered jump table otherwise becomes a plausible, empty
        // `return` in the generated Rust, with nothing marking the address
        // that still needs a human.
        self.triage_decompiler_warnings(binary, function, &function_info.decompiler_output);

        // Report: scan fetch complete
        self.emit(ProgressEvent::ScanFetchComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            address: Some(function_info.address),
            disassembly_lines: function_info.disassembly.lines().count(),
        });

        // Step 2: read the imports and tag the Windows APIs
        let imports = self.fetch_imports(binary).await?;
        let tagged_apis = self.tag_windows_apis(&function_info.disassembly, &imports)?;
        info!(
            binary,
            function,
            tagged_apis = tagged_apis.len(),
            "Tagged Windows APIs"
        );

        // Report: API tagging complete
        self.emit(ProgressEvent::ApiTaggingComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            tagged_apis: tagged_apis.len(),
        });

        // Step 3: generate the baseline test's inputs. The control-flow
        // document loads once here and serves both users: its branch-site
        // records target the baseline suite, and its findings go into the
        // prompt's CONTROL FLOW section below — one source of truth for the
        // LLM's context and for the test oracle (issue #261). A missing or
        // corrupt document loads as nothing, leaving generation on exactly
        // today's suite.
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

        // Report: tests generated
        self.emit(ProgressEvent::TestsGenerated {
            binary: binary.to_string().into(),
            function: function.to_string(),
            test_count: baseline_tests.len(),
        });

        // Step 4: judge the function's complexity and build the request
        let complexity = self
            .analyzer
            .detect_complexity(&function_info.disassembly, &function_info.windows_apis);
        info!(
            binary,
            function,
            complexity = %complexity,
            "Detected function complexity"
        );

        // Pick the context tier from the complexity and the API call count.
        // Tracking historical success rates is left to a later integration.
        let api_call_count = tagged_apis.len();
        let auto_tier = calxgloss_types::select_context_tier(
            &complexity,
            api_call_count,
            calxgloss_types::SuccessRate::default(),
        );
        // W2.7: a reviewer override forces the context tier — the automatic
        // choice is skipped for this unit (issue #96).
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

        // Add call-graph context to the prompt data when it is available.
        //
        // Build and enrich it from the engine — the auto/translate/batch
        // passes that already have a graph send it through
        // `batch_translate_from_callgraph`, which takes the graph as an
        // argument; the pipeline never kept one (issue #328 removed the
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
        // root stops above, the baseline tests and context tier selection
        // just above, and the full verification against the NEW binary's
        // bytes in the retry loop ahead — the accepted code is a guess the
        // new bytes may still fail, and that failure sends the unit into
        // the fresh-attempt chain like any other failed attempt. Nothing
        // here marks the unit verified; the review overlay's model
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
                // No prompt was sent; the record says what arrived instead.
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

        // Step 5: build a prompt sized to the complexity and send it to the LLM
        self.emit(ProgressEvent::LlmCallStart {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            retry_strategy: "initial".to_string(),
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
                // One pass over the analyzer caches (issue #268); the
                // call-graph lists and the in-memory control-flow result are
                // added on top of it.
                // The fold reads the filed documents through the projection
                // seam and derives their coverage residue beside the bundle:
                // what the engines already admitted on disk for this unit,
                // accumulated for the batch's ledger writer (issue #369).
                let (mut evidence, residue) =
                    crate::retry::helpers::gather_function_evidence_residue(
                        self.workspace.as_deref(),
                        &function_info.binary,
                        function,
                        &function_info.call_graph,
                    );
                self.record_unknown_residue(residue);
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
                // FullModule context tier: whole-module context + shim layer code + PAL traits
                // The fold reads the filed documents through the projection
                // seam and derives their coverage residue beside the bundle:
                // what the engines already admitted on disk for this unit,
                // accumulated for the batch's ledger writer (issue #369).
                let (mut evidence, residue) =
                    crate::retry::helpers::gather_function_evidence_residue(
                        self.workspace.as_deref(),
                        &function_info.binary,
                        function,
                        &function_info.call_graph,
                    );
                self.record_unknown_residue(residue);
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

                // Pull the shim layer's code out of the workspace
                let shim_layers = crate::retry::helpers::extract_shim_layers(
                    self.workspace.as_deref(),
                    &function_info.binary,
                );

                // Pull PAL trait definitions for the function's Windows API categories
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

        // W2.7: the reviewer's custom hints go into the prompt, so what the
        // reviewer knows about this function reaches the LLM (issue #96).
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

        // Report: LLM request (full prompt)
        self.emit(ProgressEvent::LlmRequest {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            retry_strategy: "initial".to_string(),
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

        // Report: LLM response (full content)
        self.emit(ProgressEvent::LlmResponse {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            retry_strategy: "initial".to_string(),
            content: response.content.clone(),
            tokens_used: response.tokens_used,
        });

        // Report: LLM call complete
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
    /// Skips the scan fetch and analysis steps and goes straight to building
    /// the prompt and calling the LLM. Useful when the request's data comes
    /// from a cache or from hand-written input.
    ///
    /// # Arguments
    ///
    /// * `request` — A pre-built [`TranslationRequest`] carrying all context.
    pub async fn translate_from_request(&self, request: TranslationRequest) -> Result<Translation> {
        debug!(binary = %request.binary, function = %request.function, "Translating from request");

        // The same root-symbol guard as in [`translate`](Self::translate): a
        // pre-built request is no reason to spend LLM tokens on a thunk.
        self.refuse_root_function(&request.binary, &request.function)?;

        if request.disassembly.is_empty() && request.decompiler_output.is_empty() {
            return Err(TranslatorError::MissingContext(
                "Both disassembly and decompiler output are empty".to_string(),
            ));
        }

        // The same body-shape guard as in [`translate`](Self::translate): a
        // pre-built request carrying a thunk's self-call body is no reason to
        // spend LLM tokens on a wrapper that holds no logic.
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

    /// Translate with automatic retry when Verification fails.
    ///
    /// This is the main entry point for production use. It runs the full
    /// pipeline, verifies the result, and when Verification fails it retries
    /// with escalating retry strategies:
    ///
    /// 1. **Initial attempt** — the full pipeline, then Verification
    /// 2. **Compile fix** — if compilation fails, send the errors back to the LLM
    /// 3. **Test fix** — if tests fail, send the failing cases back to the LLM
    /// 4. **Escalate** — add more context and try again
    ///
    /// The retry loop continues until it succeeds or reaches `max_attempts`.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL that contains the function.
    /// * `function` — The name of the function to translate.
    /// * `config` — The retry config (default: 3 attempts, compile_fix strategy).
    /// * `verifier` — The Verifier used to check the translation.
    ///
    /// # Returns
    ///
    /// A [`RetryResult`](crate::RetryResult) with every attempt and the final result.
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

        // The ladder's posture, settled before the unit's first attempt:
        // W2.5's operator constraints (max attempts, max context tier) cap
        // the retry policy, and W2.7 a reviewer override can force the retry
        // strategy and add its custom hints to the loop's prompts that follow
        // a failure (issue #96). Steering lands at unit boundaries, so the
        // reads below belong ahead of Step 1 — the seam-residue filing and
        // the loop itself walk one and the same settled posture.
        let source = self.scan_source();
        let mut bounded_config = self.constrained_retry_config(config);
        if let Some(strategy) = self.forced_retry_strategy(binary, function) {
            info!(
                binary,
                function,
                strategy = %strategy,
                configured = %config.retry_strategy,
                "Reviewer override forces the retry strategy"
            );
            bounded_config.retry_strategy = strategy;
        }
        let reviewer_hints = self.reviewer_hints_for(binary, function);
        // The batch's stored capability declaration, taken from the stored
        // copy for this prompt — the seam is never asked again (issue #355).
        let seam_report = self.seam_report();

        // Seam residue (issue #371): every family the held report declares
        // `unavailable`, and this unit's ladder posture would re-ask, files
        // its standing question against the unit — the P20 admission that
        // pruned the re-ask (issue #356) is now a record a reviewer can
        // resolve. Filed at the unit's entry into the retry wrapper: the
        // posture, not the unit's outcome, is what the admission bears on.
        // A family the report never declared — which reads unknown — files
        // nothing, and so does a posture that never re-asks.
        let residue = crate::seam_residue::seam_residue(
            binary,
            function,
            &seam_report,
            crate::seam_residue::posture_reask_families(&bounded_config),
            calxgloss_types::scan::now_unix_secs(),
        );
        if !residue.is_empty() {
            // A seam that admitted nothing opens nothing: the fold stays
            // the only writer that files an empty ledger (issue #369).
            self.record_unknown_residue(residue);
        }

        // Step 1: the first translation attempt, through the full pipeline.
        // The futures below are boxed so that downstream crates' `Send` checks
        // stop at this boundary instead of walking down the whole pipeline,
        // which overflows the compiler's trait evaluation recursion limit (see
        // rust-lang/rust#159228).
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

        // Step 2: run the retry loop
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
            seam_report: &seam_report,
        };
        // Boxed for the same reason as in step 1.
        let retry_loop: std::pin::Pin<
            Box<dyn std::future::Future<Output = retry::RetryResult> + Send + '_>,
        > = Box::pin(retry::try_translate_with_retry(initial, &ctx));
        let result = retry_loop.await;

        // Ladder residue (issue #372): every escalate rung the walk pruned
        // and every context-tier step it refused on a declared unavailable
        // filed its record at the decision — the loop hands them up, and
        // the pipeline folds them into the same per-binary accumulator
        // every other record lands in, deduplicated by id. The walk has
        // already run: a filed record feeds nothing back into which rung
        // or tier comes next (that door is P27's). A ladder that pruned
        // nothing opens nothing.
        if !result.unknown_residue.is_empty() {
            self.record_unknown_residue(result.unknown_residue.clone());
        }

        // Verification residue (issue #373): a unit that reached review
        // having run zero baseline cases files its standing question
        // against the unit — the walk's own verification counters (no
        // attempt ever moved `tests_total`) say this unit's behavior was
        // never exercised, and "translated" must not read as "proven"
        // about it. The counters are read after the walk, never back into
        // which rung comes next, and a walk whose cases ran opens nothing.
        if !result
            .attempts
            .iter()
            .any(|attempt| attempt.tests_total > 0)
        {
            self.record_unknown_residue(vec![crate::verification_residue::zero_case_residue(
                binary,
                function,
                calxgloss_types::scan::now_unix_secs(),
            )]);
        }

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

        // Record the final result for later context tier selection tracking.
        // (The success-rate tracking itself comes in a follow-up.)

        Ok(result)
    }

    /// Stop a translate request for a function that the built-in root
    /// patterns mark as skip — entry points and import thunks (`DelayLoad_*`,
    /// `_imp_*`, `thunk_*`).
    ///
    /// The matched pattern's description becomes the error's reason, so the
    /// operator learns *why* this function was stopped: the thunk holds no
    /// logic, and the caller's translation reaches the real API through the
    /// PAL mappings instead. Only the `Skip` action stops here —
    /// `GenerateStub` is a batch-path policy, and a single explicit request
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

    /// Stop a translate request when the function's whole decompiled body
    /// is one unconditional call to its own name — an import thunk that the
    /// decompiler renders as a self-call (issue #269).
    ///
    /// The name-based root patterns cannot see these: the symbol table names
    /// the wrapper after the import it tail-jumps to, so `SetCursor` carries
    /// no `thunk_` marker and matches no pattern. The body's shape is the
    /// sign, and unlike the name guard this one can only run once the body
    /// is in hand — still, that is before the prompt is built and any LLM
    /// token is spent. The reason describes the shape, so the operator
    /// learns the same *why* the root patterns give: the wrapper holds no
    /// logic, and the caller's translation reaches the real API through the
    /// PAL mappings. A genuinely recursive function — a self-call inside
    /// real logic, with a base case — is not this shape and is never stopped.
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
    /// generated Rust will be empty exactly there. Logging the address turns
    /// "the Rust is just a `return`" into a pointer at the jump to recover
    /// in the decompiler (or rebuild from the disassembly's table). Kuna's
    /// inline slug comment gives no address, so the jump is logged as an
    /// unknown site.
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

    /// Read the function's metadata through the batch's scan source.
    ///
    /// The name is turned into an address using the function listing first,
    /// and only an exact match counts: a substring match would quietly
    /// translate a different function.
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
            // are read out of the decompiled body, so they cannot include
            // calls made through a function pointer.
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

    /// Get the names of the target binary's imports.
    ///
    /// These come back as names rather than [`calxgloss_decomp::Import`]
    /// values: the engine reports an import as a name plus an external slot
    /// with no module attached, so there is no module name to put in an `Import`.
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
        // Use the analyzer that was built with the pipeline, so its tagging runs
        let tagged = self
            .analyzer
            .tag_windows_apis(disassembly, imports)
            .map_err(|e| TranslatorError::TestGen(anyhow::anyhow!("API tagging failed: {e}")))?;

        // The analyzer already writes the shared `WindowsApiCall` values, so
        // its tagged list is the prompt's list — no conversion needed.
        Ok(tagged)
    }

    /// Generate the baseline test's inputs for a function, aimed at the
    /// branch sites that the loaded control-flow findings listed for it
    /// (issue #261). An empty list — no records, or no usable document —
    /// gives exactly today's suite.
    async fn generate_baseline_tests(
        &self,
        function_info: &FunctionInfo,
        _imports: &[String],
        branch_inventory: &[calxgloss_controlflow::types::BranchSite],
    ) -> Result<Vec<TestCase>> {
        // The signature the decompiler worked out, which gives the
        // parameters that the test cases pass in.
        let signature = self.signature_for(function_info);

        // Generate the test inputs from the signature, the disassembly, and
        // the branch list: one case per branch target, de-duplicated
        // against the boundary cases, with a cap per function.
        let mut tests = calxgloss_testgen::generate_test_inputs(
            &signature,
            &function_info.disassembly,
            branch_inventory,
        )
        .map_err(TranslatorError::TestGen)?;

        // The saved global-state artifact provides the typed side-effect
        // expectations: when a stored global-state document names globals
        // for this function, every test case carries them as
        // GlobalRead/GlobalWrite expectations that name each global — a
        // global side effect is always a named kind, never an Other string.
        // No document (the scan has not run) or a corrupt one leaves the
        // expectations empty, exactly as before.
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

    /// The function's C signature, as the decompiler worked it out.
    ///
    /// The reviewer's override record for a unit, when there is one (issue #96, W2.7).
    fn unit_override(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_types::FunctionOverride> {
        self.overrides
            .as_ref()
            .and_then(|o| o.get(binary, function))
    }

    /// The context tier a reviewer forced for this unit, when there is one —
    /// the context builder uses it instead of the automatic choice.
    fn forced_context_tier(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_types::ContextTier> {
        self.unit_override(binary, function)
            .and_then(|o| o.tier_override)
    }

    /// The retry strategy a reviewer forced for this unit, when there is
    /// one. The record's field is the shared
    /// [`calxgloss_types::RetryStrategy`] enum, so a stored value is always
    /// a real strategy — an unknown label was stopped at the override
    /// boundary (issue #120) and never reached the record.
    fn forced_retry_strategy(&self, binary: &str, function: &str) -> Option<retry::RetryStrategy> {
        self.unit_override(binary, function)
            .and_then(|o| o.retry_strategy_override)
    }

    /// The reviewer's custom hints for this unit, added to its prompts.
    fn reviewer_hints_for(&self, binary: &str, function: &str) -> Vec<String> {
        self.unit_override(binary, function)
            .map(|o| o.custom_hints)
            .unwrap_or_default()
    }

    /// Add the reviewer's custom hints to a prompt that is already built.
    ///
    /// The hints go into a clearly-marked section at the end of the prompt —
    /// what the reviewer knows about the function (what it really does, its
    /// known quirks) that the automatic context gathering cannot produce.
    fn append_reviewer_hints(prompt: String, hints: &[String]) -> String {
        let mut out = prompt;
        out.push_str("\n\n## Reviewer hints\n\n");
        out.push_str("Additional context supplied by the human reviewer steering this run:\n");
        for hint in hints {
            out.push_str(&format!("- {hint}\n"));
        }
        out
    }

    /// The decompiler's first line is a real signature with real parameter
    /// types, so it is preferred. Only when that line is unusable — the
    /// decompilation failed, or the text is not pseudo-C — does this fall back
    /// to a placeholder, which gives boundary-value tests for the wrong
    /// parameter count rather than no tests at all.
    ///
    /// A signature that names no calling convention — a usable line without a
    /// convention word, or the placeholder — has the convention the scan
    /// detected for this function written into it, so the FFI binding built
    /// from the same string calls the original with the right convention
    /// instead of the blanket `__stdcall` (issue #251, part of #226). A
    /// decompiler line that does name a convention still wins: that line
    /// describes the function itself better. Microsoft x64 has no C keyword
    /// for it — the default ABI already is the x64 convention — so the
    /// convention slot is left empty rather than inventing a keyword. With no
    /// convention record, or no artifact, today's default stands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn signature_for(&self, function_info: &FunctionInfo) -> String {
        let detected = self.detected_convention(&function_info.binary, &function_info.name);

        if let Some(parsed) =
            calxgloss_decomp::parse::parse_decompiled(&function_info.decompiler_output)
        {
            // Write in the detected convention only where the line named none,
            // and only when the convention has a C keyword at all.
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
        // The default `__stdcall` is kept only when no record named a
        // convention; a record that did writes its own keyword, and the x64
        // record writes none because the parser's default already fits.
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

    /// The calling convention that the saved type-inference record detected
    /// for this function (issue #251, part of #226). Only the function's own
    /// record describes its signature: a call-site view of a callee's
    /// convention is stored beside the caller's records and must never be
    /// mistaken for the caller's own. A missing workspace, a missing or
    /// corrupt artifact, or no convention record gives nothing, so the
    /// existing default convention stays in force.
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
                // The records resolve to one convention per function, so the
                // first record naming its own convention is the whole answer;
                // call-site views (callee named) stay out.
                InferredType::Convention(record) if record.callee.is_none() => {
                    Some(record.convention)
                }
                _ => None,
            }
        })
    }

    /// Build a [`TranslationRequest`] from all the gathered context.
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

    /// Generate a Stub implementation for a root function.
    ///
    /// Root functions include entry points (`main`, `WinMain`, `DllMain`) and
    /// runtime library initializers. These do not go through the LLM;
    /// instead, a minimal Stub is generated from the function's name and
    /// signature, as a placeholder that can be compiled and linked.
    ///
    /// # Arguments
    ///
    /// * `name` — The function name (for example `mainCRTStartup`, `WinMain`).
    /// * `signature` — The C signature the decompiler worked out.
    ///
    /// # Returns
    ///
    /// A string holding a minimal Stub implementation. For a well-known entry
    /// point, the Stub says something meaningful. For an unknown root
    /// function, the Stub is a general placeholder that still compiles
    /// and links.
    pub fn generate_stub(&self, name: &str, signature: &str) -> String {
        // Match the common entry-point patterns
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
            // Generic entry point — use the signature to work out a Stub
            _ => {
                // Pull the return type and parameters out of the signature
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

        // Keep the signature in the output, as a comment for reference
        format!("{stub}\n// Signature: {signature}")
    }

    /// Send a prompt to the LLM and take the Rust code out of the response.
    ///
    /// When `events` is present, a `LlmCallInProgress` keepalive event goes
    /// out every 30 seconds while the request is running.
    ///
    /// After the response arrives, the context-window detector checks whether
    /// the output reaches or passes the model's configured limit. A detected
    /// fault is logged with `tracing::warn!` so the caller can act on it —
    /// for example by splitting the function and trying again.
    ///
    /// # Arguments
    ///
    /// * `disassembly_lines` — How many lines the function's disassembly has,
    ///   used to suggest a chunk count for the retry splitter when a
    ///   context-window fault is detected.
    #[allow(clippy::too_many_arguments)]
    async fn send_to_llm(
        &self,
        prompt: &str,
        events: Option<&TranslationEvents>,
        binary: &str,
        function: &str,
        attempt: u32,
        retry_strategy: &str,
        disassembly_lines: usize,
    ) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];

        // Pre-check: is the prompt itself already too large for the context?
        if let Some(fault) = self.context_detector.detect_prompt_too_large(&messages) {
            warn!(
                binary,
                function,
                attempt,
                retry_strategy,
                prompt_size = fault.response_size,
                limit = fault.limit,
                "Prompt exceeds model context limit — splitting function",
            );
            // The call still goes ahead; the LLM server handles the
            // truncation, and the check after the response sees the real output.
        }

        let response = if let Some(em) = events {
            let em = em.clone();
            let em_err = em.clone();
            let dll_s = binary.to_string();
            let function_s = function.to_string();
            let strategy_s = retry_strategy.to_string();

            // Copy the values before moving them into the keepalive closure
            let dll_kp = dll_s.clone();
            let function_kp = function_s.clone();
            let strategy_kp = strategy_s.clone();

            // Start a keepalive task that sends a progress event every 30 seconds
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
                        retry_strategy: strategy_kp.clone(),
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
                        retry_strategy: strategy_s.clone(),
                        error: e.to_string(),
                    });
                }
            }

            result
        } else {
            self.llm.complete(&messages).await
        }?;

        // Post-check: look for a context-window-exceeded fault.
        if let Some(fault) = self
            .context_detector
            .detect_response(&response, disassembly_lines)
        {
            warn!(
                binary,
                function,
                attempt,
                retry_strategy,
                response_size = fault.response_size,
                limit = fault.limit,
                overflow = fault.overflow_chars,
                "Context window exceeded — function should be split into {} chunks",
                fault.suggested_chunk_count(),
            );
        }

        // Hallucination check: look through the generated code for API or
        // function references that do not exist. When invented references
        // turn up, log a warning and send a progress event so the caller can act.
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
                retry_strategy,
                count = names.len(),
                apis = ?names,
                "Hallucinated API/function references detected",
            );
            if let Some(em) = events {
                let _ = em.emit(ProgressEvent::HallucinationDetected {
                    binary: binary.to_string().into(),
                    function: function.to_string(),
                    attempt,
                    retry_strategy: retry_strategy.to_string(),
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

    /// The loaded Kuna program behind the analysis seam.
    pub fn kuna(&self) -> &KunaSource {
        &self.kuna
    }

    /// The LLM client this pipeline uses.
    pub fn llm(&self) -> &LlmClient {
        &self.llm
    }

    /// The API mappings table this pipeline uses.
    pub fn api_mappings(&self) -> &ApiMappings {
        &self.api_mappings
    }

    // =========================================================
    // Batch translation
    // =========================================================

    /// Open the batch's shared read cache over Kuna for `binary` (issue #105).
    ///
    /// Both batch entry points call this at their start. With a workspace and a
    /// `binary_path` set, it builds one [`CachedScanSource`] for the target
    /// binary — the binary's file bytes are hashed once — and every later read
    /// made through [`scan_source`](Self::scan_source) then tries the memo, then
    /// the disk tier, then the engine, saving what it reads as it goes.
    ///
    /// It degrades instead of failing: with no workspace or binary path the batch
    /// reads straight from the engine, exactly as before the cache existed, and an
    /// unreadable binary file also leaves the cache in pass-through mode, so the
    /// batch runs on either way.
    async fn begin_cached_source(&self, binary: &str) {
        let (Some(workspace), Some(binary_path)) =
            (self.workspace.as_deref(), self.binary_path.as_deref())
        else {
            // No cache to open: the batch's reads go to the live engine, so
            // its declaration is the one the prompts hold (issue #355) —
            // fetched once, right here, beside this decision.
            *self
                .seam_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = self.kuna.capability_report();
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
                // The declaration travels with the source it describes: it is
                // fetched right here, as the source opens, and reading a
                // capability costs no extra engine read (issue #355). Every
                // later prompt reads this stored copy.
                *self
                    .seam_report
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    source.capability_report();
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
                // Same rule on the fallback path: the declaration belongs to
                // whichever source the batch's reads go through.
                *self
                    .seam_report
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    self.kuna.capability_report();
            }
        }
    }

    /// The stored capability declaration (issue #355): fetched once by
    /// [`begin_cached_source`](Self::begin_cached_source), and read by the
    /// escalate step of the retry loop for every fix prompt in the batch.
    pub(crate) fn seam_report(&self) -> calxgloss_types::CapabilityReport {
        self.seam_report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Record one unit's admitted residue into the batch accumulator —
    /// the coverage fold's facet admissions (issue #369) and the seam
    /// report's unavailable families (issue #371): they arrive in the
    /// unit's own derivation order, and an id already admitted is never
    /// recorded twice — the same gap re-derived is one question, not a
    /// second opinion. The accumulator opening to `Some` is also the
    /// writer's signal that a producer actually looked this batch over.
    fn record_unknown_residue(&self, residue: Vec<calxgloss_types::UnknownRecord>) {
        let mut accumulator = self.unknown_residue.lock().expect("unknown residue lock");
        let admitted = accumulator.get_or_insert_with(Vec::new);
        for record in residue {
            if !admitted.iter().any(|landed| landed.id == record.id) {
                admitted.push(record);
            }
        }
    }

    /// File the batch's export-coverage residue (issue #373): one
    /// `export_uncovered` record for every export in the listing that no
    /// filed baseline document covers — the document testgen's own
    /// `re/baseline/<binary>/<export>/baseline.json` layout names. The
    /// check is the already-checkable fact, no new evidence work: a
    /// covered export asks nothing, and an export listing that never came
    /// back (a target that is not a PE, a target whose bytes went away)
    /// reads *unknown* and files nothing — the ledger's absence keeps
    /// the honest reading, exactly like the seam's undeclared family. No
    /// workspace means nowhere to look for documents and nowhere to
    /// file, so the check does not run at all.
    async fn record_export_residue(&self, binary: &str) {
        let Some(workspace) = self.workspace.as_deref() else {
            return;
        };
        let generator = TestGenerator::new(workspace);
        let exports = match self.scan_source().exports().await {
            Ok(exports) => exports,
            Err(source) => {
                warn!(
                    binary,
                    error = %source,
                    "The export listing never came back — the export-coverage check \
                     reads unknown and files nothing"
                );
                return;
            }
        };
        let now = calxgloss_types::scan::now_unix_secs();
        let residue: Vec<calxgloss_types::UnknownRecord> = exports
            .iter()
            .filter(|export| !export.name.is_empty())
            .filter(|export| !generator.baseline_path(binary, &export.name).is_file())
            .map(|export| {
                crate::verification_residue::uncovered_export_residue(binary, &export.name, now)
            })
            .collect();
        if !residue.is_empty() {
            self.record_unknown_residue(residue);
        }
    }

    /// File (or re-file) the batch's per-binary unknown ledger,
    /// `re/unknowns/<binary identity>.json` (issue #369).
    ///
    /// The current derived set — every record the batch's producers have
    /// admitted so far, the folds' facet admissions and the seam report's
    /// unavailable families — merges through the shared
    /// [`UnknownLedger::file`](calxgloss_types::UnknownLedger::file)
    /// revision doctrine against the landed document: a re-run lands the
    /// same ids, a revision bumps only when a persisted field actually
    /// changed, and a reviewer's reopen mark fires exactly once. The
    /// document is replaced outright, so it is always the current derived
    /// set, never an append log — a source slot that stops deriving
    /// simply stops landing.
    ///
    /// The reviewer's resolutions document feeds the merge and is never
    /// touched: it is read here, and a corrupt or absent one reads as no
    /// reopen marks — the reviewer's own artifact, whose trouble never
    /// stops a batch. The pipeline's own landed ledger is different: an
    /// unreadable one fails the write loudly rather than guess past the
    /// document this write replaces. A batch whose folds never read a
    /// document files nothing — the ledger's absence reads as *unknown*
    /// (ADR-0053's absent-field rule), and filing a nothing nobody looked
    /// at would be the dishonest known-and-none.
    fn file_unknown_ledger(&self, binary: &str) -> Result<()> {
        let Some(workspace) = self.workspace.as_ref() else {
            // No workspace configured: nowhere to file, nothing read.
            return Ok(());
        };
        let derived = self
            .unknown_residue
            .lock()
            .expect("unknown residue lock")
            .clone();
        let Some(derived) = derived else {
            return Ok(());
        };
        let identity = calxgloss_types::BinaryIdentity::new(binary);
        let landed = match calxgloss_types::load_json::<calxgloss_types::UnknownLedger>(
            &calxgloss_types::unknown_ledger_path(workspace, &identity),
        ) {
            Ok(ledger) => Some(ledger),
            Err(calxgloss_types::PersistError::NotFound { .. }) => None,
            Err(source) => {
                return Err(TranslatorError::UnknownLedger {
                    binary: binary.to_string(),
                    source,
                });
            }
        };
        let reopened = match calxgloss_types::load_json::<calxgloss_types::UnknownResolutions>(
            &calxgloss_types::unknown_resolutions_path(workspace),
        ) {
            Ok(resolutions) => resolutions.reopened,
            Err(calxgloss_types::PersistError::NotFound { .. }) => Default::default(),
            Err(e) => {
                debug!(
                    binary,
                    error = %e,
                    "The reviewer's unknown resolutions are unreadable; \
                     filing the ledger without reopen marks"
                );
                Default::default()
            }
        };
        let ledger = calxgloss_types::UnknownLedger::file(
            identity.clone(),
            landed.as_ref(),
            &derived,
            &reopened,
            calxgloss_types::scan::now_unix_secs(),
        );
        calxgloss_types::save_json(
            &calxgloss_types::unknown_ledger_path(workspace, &identity),
            &ledger,
        )
        .map_err(|source| TranslatorError::UnknownLedger {
            binary: binary.to_string(),
            source,
        })
    }

    /// The source that every batch user — the [`ScanJob`]s the fifteen
    /// registered scans build, the call-graph build, and the
    /// retry/escalation helpers — reads program facts from: the batch's
    /// [`CachedScanSource`] once
    /// [`begin_cached_source`](Self::begin_cached_source) has opened it, and
    /// the loaded Kuna program otherwise.
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

    /// Start the analysis engine's progress reporting for one pass, so the
    /// dashboard can show which function the pass is on. Without an event
    /// channel there is nothing to report to — the scan runs unchanged.
    fn begin_scan_pass(&self, binary: &str, pass: &str) {
        if let Some(ref ev) = self.events {
            self.kuna.begin_pass(binary, pass, ev);
        }
    }

    /// Stop the engine's progress reporting — the pass is finished.
    fn end_scan_pass(&self) {
        self.kuna.end_pass();
    }

    /// Build the owned handle that one evidence scan runs as (issue #237):
    /// copies of everything the scan reads — the workspace, the batch's
    /// shared read source as it stands now — so the scan borrows nothing
    /// from the batch and a caller can move the job onto a task. `None`
    /// when no workspace is configured, which is every scan's skip
    /// condition. The pass's progress reporting belongs to the phase, not
    /// to the job (issue #239), and the scan phase's ordering lives on the
    /// registry's rows, not on the job (issue #305).
    fn scan_job(&self, binary: &str) -> Option<ScanJob> {
        let workspace = self.workspace.as_deref()?;
        Some(ScanJob::new(binary, workspace, self.scan_source()))
    }

    /// Run the fifteen pre-batch evidence scans: the shared scan phase that
    /// both batch entry points call — the function-list path
    /// ([`batch_translate`](Self::batch_translate)) and the call-graph path
    /// ([`batch_translate_from_callgraph`](Self::batch_translate_from_callgraph))
    /// — so neither keeps its own copy of the sequence and the CLI and web
    /// paths cannot drift apart (issue #234).
    ///
    /// The scans run concurrently on a [`JoinSet`], at most
    /// [`MAX_CONCURRENT_EVIDENCE_SCANS`] at a time, each on its own owned
    /// [`ScanJob`] (issues #237, #240): the engine thread is handed the next
    /// body as soon as it frees the last one, so parse work overlaps engine
    /// work, and a cold scan phase costs about the engine's own decompile
    /// time rather than that plus every scan's parse time. Scans enter the
    /// window in [`scan_rows`] order, but that is the order they enter, not
    /// the order they finish. Each body is decompiled exactly once by
    /// construction, with no new locking: the read cache's per-key cell turns
    /// concurrent requests for one body into a single engine request, so the
    /// engine stays the serial resource that the scans share safely.
    ///
    /// Each scan keeps its own shape: a cached-hit short-circuit ends it
    /// before any engine read, and a failed scan or save only warns and
    /// continues, so one detector's failure never takes down the batch. The
    /// group joins all fifteen and never cancels its siblings.
    ///
    /// The one real ordering edge between the scans — callback detection
    /// building its closure contracts from the type-inference document — is
    /// a declared row dependency: the phase arms a fresh completion latch for
    /// each declared producer ([`arm_completion_latches`]), the inference row
    /// publishes its latch on every exit, and the callback row waits on it,
    /// so the edge is explicit table data rather than a call order (issues
    /// #238, #305).
    ///
    /// The phase also starts the engine's progress reporting once for the
    /// whole group, under the phase name, and stops it when the group ends:
    /// the dashboard shows one honest "n of m functions consumed" row for the
    /// scan phase instead of fifteen rows that restart with each scan. The
    /// counts are of unique functions consumed — a body pulled cold from the
    /// engine and replayed warm by the read cache counts once — so a warm run
    /// still shows life, and the row stays honest while the scans interleave
    /// (issue #239, preserving #121). The phase skips itself when there is no
    /// workspace to file its documents under.
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
        // Sliding window: every completion frees a slot for the next scan,
        // and the group joins all fifteen — a failing or panicking scan
        // never cancels its siblings (issue #240).
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

        // P18's version-change trigger (issue #298): the scan step has just
        // written this version's scan documents. Compare this scan against
        // any surviving scan of the same identity — the sibling hash
        // directories under `re/cache/{identity}/` — exactly once per
        // (old, new) hash pair; a later run reuses the saved document.
        // Documents only: no engine reads (ADR-0026), no LLM, milliseconds.
        // With no sibling directory it writes nothing, leaving the queue's
        // behavior exactly as it is today.
        if let (Some(workspace), Some(binary_path)) =
            (self.workspace.as_deref(), self.binary_path.as_deref())
        {
            crate::version_pairing::pair_previous_versions(workspace, binary, binary_path);
        }
    }

    /// Collect this batch's carry-over seeds (issue #299), right after
    /// [`run_prebatch_scans`] wrote the pairing documents for the bytes being
    /// translated now.
    ///
    /// One directory pass, one hash, and one accepted-code lookup per paired
    /// candidate — milliseconds next to an LLM batch. With no port wired, no
    /// workspace or binary path, no eligible documents, or no accepted twin for
    /// a function, the map stays empty and every unit translates fresh, byte
    /// for byte as it does today. The batch never fails over this: the
    /// documents are context a user may want, not an input it needs.
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

    /// Attach the carry-over history to a completed unit's result (issue
    /// #299): the record names the old function and the attempt branch that
    /// the winning code arrived on, so the batch callback's commit message,
    /// and anyone reading the record, can see where attempt 1's code came
    /// from.
    ///
    /// Attached only when the unit succeeded **with the seed's code** — if the
    /// fresh attempt chain won instead, the code is the LLM's own, and claiming
    /// a carry-over for it would be false provenance.
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

    /// The most evidence scans that ran at the same time during the latest
    /// scan phase (issue #241) — the fan-out window's high-water mark,
    /// recorded by `run_scan_in_window` as each scan enters the window. Zero
    /// when no phase has run, or when it skipped for want of a workspace.
    pub fn scan_window_high_water(&self) -> usize {
        self.scan_window_high_water.load(Ordering::SeqCst)
    }

    /// Translate several functions from one DLL, one at a time.
    ///
    /// Each function goes through the full pipeline with retry logic, the
    /// same path as the single-function
    /// [`try_translate_with_retry`](Self::try_translate_with_retry). The
    /// functions are processed in the order they are given.
    ///
    /// Before the first function, the per-binary type database, the type
    /// inference result, the algorithm recognition result, the memory
    /// lifecycle result, and the concurrency result are collected, or loaded
    /// from their caches, so the higher context tiers have data structure,
    /// parameter type, algorithm, and concurrency context. The fifteen
    /// evidence scans run through one shared scan phase, `run_prebatch_scans`.
    ///
    /// The caller may pass a callback (`on_function_completed`) that runs
    /// **immediately after each function completes**, before the next one
    /// starts. That allows git commits as the batch goes and per-function
    /// follow-up work without delaying the later translations.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL that holds all the functions to translate.
    /// * `functions` — The names of the functions to translate.
    /// * `config` — The retry config used for every function.
    /// * `verifier` — The Verifier that checks each translation.
    /// * `on_function_completed` — Optional closure that runs after each
    ///   function completes. It gets the DLL name, the function name, a
    ///   mutable reference to the [`batch::FunctionResult`], and a boolean
    ///   telling the caller whether to continue with the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`](crate::BatchTranslationResult) with each
    /// function's outcome. A function counts as a failure when its retry
    /// attempts run out without producing tests that pass.
    ///
    /// # Notes
    ///
    /// - If the LLM cannot be reached, the batch carries on with the rest of
    ///   the functions, recording each failure on its own.
    /// - The retry strategy (compile_fix → test_fix → escalate) applies to
    ///   each function separately.
    /// - The callback runs on the **same task** that is running the batch, so
    ///   it should return `true` quickly and not delay the next function. If
    ///   it returns `false`, the batch stops early.
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
    /// Produce a translation plan ordered by priority from a call graph.
    ///
    /// This method connects call-graph analysis to the batch translation path.
    /// Through [`TranslationOrderer`](calxgloss_callgraph::TranslationOrderer)
    /// it turns a [`CallGraph`](calxgloss_callgraph::CallGraph) into a list of
    /// [`FunctionTranslationPlan`](calxgloss_callgraph::FunctionTranslationPlan) records,
    /// each with its priority group (root / middle / leaf) and topological
    /// position. A saved global-state document for the graph's binary adds
    /// state-sharing edges to that order: within a group, a global's first
    /// definer comes before the units that reuse it (issue #256). With no
    /// document, today's order is unchanged.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph to plan from.
    /// * `max_functions` — An optional cap on how many functions the plan holds.
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
        // State-sharing edges from the saved shared-globals index extend
        // the order when the global-state scan has run for this binary
        // (issue #256); the plan reads the saved file, it never runs the
        // scan itself.
        orderer = orderer.with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;
        Ok(plan.into_iter().collect())
    }

    /// The state-sharing edges that the saved shared-globals index names for
    /// this binary (issue #256, part of #225). The orderer uses the file the
    /// global-state scan wrote; it never runs the scan itself. A missing
    /// workspace, a missing document, or a corrupt one gives an empty set,
    /// so today's dependency order stays exactly as it is.
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

    /// Translate the given functions in one binary as a batch.
    ///
    /// Returns a `BatchTranslationResult` holding each function's translation outcome.
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

        // W2.5: operator scope — skipped functions never enter the queue and
        // priority functions move to the front.
        let functions = self.apply_function_scope(binary, functions.to_vec(), |f| f.as_str());

        // Carry-over seeding (issue #299): the scan step just saved the
        // pairing documents for these exact bytes, so collect the seeds for
        // this queue now and the batch's inputs are settled before its first
        // unit starts.
        self.refresh_carry_over_seeds(binary, &functions);

        // Unknown residue (issues #369, #371): the batch's ledger write
        // files the current derived set, so the previous batch's
        // accumulated set starts out gone — what this batch's producers
        // admit replaces it.
        *self.unknown_residue.lock().expect("unknown residue lock") = None;

        // Verification residue (issue #373): every export no filed
        // baseline document covers files its standing question ahead of
        // the queue, so the binary-level facts lead the ledger's derived
        // order and re-file a batch after covering an export simply stops
        // landing that entry.
        self.record_export_residue(binary).await;

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
            // never holds the loop open (issue #219, part of #217).
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

            // Mark the unit in-flight so the web server's cancel-current
            // endpoint has something to name (issue #91, W2.2).
            if let Some(cancellation) = self.unit_cancellation.as_ref() {
                cancellation.begin_unit(binary, function);
            }

            // The unit races the cancellation watch: a cancellation that
            // arrives mid-unit drops the in-flight future — the first safe
            // point, because an attempt has saved nothing until the unit
            // completes — and the unit is recorded as a failed attempt while
            // the batch carries on with the next unit. A stopped root symbol
            // is recorded skipped rather than failed, and the flag keeps it
            // out of the completion callback (see below).
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
                            // A root symbol named directly on the CLI is a
                            // request the pipeline stops, not a unit that
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
            // between here and the next unit's start is refused, not taken.
            // Releasing the registration is also the race-free check for a
            // cancellation that arrived while the unit's own work was
            // finishing: the operator's cancel still outranks the completion
            // it raced with, so the unit is recorded cancelled, not completed.
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

            // Carry-over history (issue #299): when attempt 1 arrived with
            // an accepted translation and that code is what succeeded, the
            // record says so — the git callback's commit message reads it.
            self.attach_carry_over_provenance(&mut result);

            let success = result.success;
            // W2.5: add the unit's token spend to the run's budget.
            self.record_unit_tokens(&result);
            batch_result.add(result.clone());

            // Send the progress event for live tracking. A cancelled unit
            // already got its final `UnitCancelled` event from the
            // cancellation handle the moment the cancel arrived — no
            // completion event on top of that.
            if !aborted {
                self.emit(ProgressEvent::FunctionCompleted {
                    binary: binary.to_string().into(),
                    function: function.clone(),
                    success,
                    attempts: 0,  // filled by caller after git branch creation
                    branch: None, // filled by caller after git branch creation
                });
            }

            // Run the caller's callback (for example, for git commits as the
            // batch goes). Cancelled units go through it too — the caller
            // owns git cleanup, and per the Archive rule a cancelled unit's
            // branch is archived under the archive refs, never deleted. A
            // stopped root symbol never reaches this: it was never attempted,
            // so it has no translated code to write and no branch to clean
            // up, and a caller that assumed success means code would panic.
            let continue_batch = if let Some(ref mut cb) = on_function_completed
                && !unit_refused
            {
                cb(binary, function, &mut result)
            } else {
                true
            };

            // The unit is complete — file this binary's unknown ledger so
            // the gaps the batch's folds admitted stand on disk even if
            // the batch stops before its last unit (issue #369).
            self.file_unknown_ledger(binary)?;

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

    /// Translate several functions from one DLL, in an order the call
    /// graph sets.
    ///
    /// This method uses a [call graph] to pick the translation order:
    ///
    /// 1. [Leaf] functions (they call external APIs) — translated first
    /// 2. [Middle] functions — translated second
    /// 3. [Root] functions — translated last
    ///
    /// Within each group, functions are sorted so that a function is only
    /// translated after every function it calls. That lets the LLM use
    /// already-translated callee code when it writes shim layers or caller
    /// wrappers.
    ///
    /// Before the first function, the per-binary type database, the type
    /// inference result, the algorithm recognition result, the memory
    /// lifecycle result, and the concurrency result are collected, or loaded
    /// from their caches, so the higher context tiers have data structure,
    /// parameter type, algorithm, memory, and concurrency context. The fifteen
    /// evidence scans run through one shared scan phase, `run_prebatch_scans`.
    ///
    /// The caller can provide a callback (`on_function_completed`) that runs
    /// **immediately after each function finishes** (before the next one
    /// starts). That allows incremental git commits and per-function
    /// follow-up work without delaying the rest of the batch.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph holding all the functions to translate.
    ///   Root functions get a minimal Stub automatically (they have no
    ///   translation work). Runtime library functions
    ///   (`NodeCategory::Skip`) are not stubbed.
    /// * `config` — The retry config applied to every function.
    /// * `verifier` — The Verifier used to check the translations.
    /// * `on_function_completed` — Optional closure called after each function
    ///   finishes. It receives the DLL name, the function name, a mutable
    ///   reference to the [`batch::FunctionResult`], and a boolean saying
    ///   whether to keep going with the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`](crate::BatchTranslationResult) with each
    /// function's outcome. A function counts as a failure when its retry
    /// attempts run out without producing passing tests.
    ///
    /// Root functions from the call graph get a Stub automatically and
    /// appear in the result with `batch::FunctionResult::stubbed`. Functions
    /// classified as [`NodeCategory::Skip`] (runtime library functions) are
    /// not stubbed and appear as `batch::FunctionResult::skipped`.
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

        // Build the plan in priority order, extended by the saved
        // shared-globals index when the global-state scan has run for
        // this binary (issue #256) — it reads the artifact, never scans.
        let orderer = calxgloss_callgraph::TranslationOrderer::new()
            .with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;

        let plan: Vec<_> = plan.into_iter().collect();
        let binary = &graph.binary;

        // W2.5: operator scope — skipped functions are taken out of the plan
        // before the first unit starts, and priority functions sort first.
        let plan = self.apply_function_scope(binary, plan, |p| p.name.as_str());

        // Carry-over seeding (issue #299): the scan step saved the pairing
        // documents for these exact bytes; collect the seeds for this plan
        // before its first unit starts.
        let queue_names: Vec<String> = plan.iter().map(|p| p.name.clone()).collect();
        self.refresh_carry_over_seeds(binary, &queue_names);

        // Unknown residue (issues #369, #371): the batch's ledger write
        // files the current derived set, so the previous batch's
        // accumulated set starts out gone — what this batch's producers
        // admit replaces it.
        *self.unknown_residue.lock().expect("unknown residue lock") = None;

        // Verification residue (issue #373): the export-coverage check
        // runs ahead of the queue here too — every export no filed
        // baseline document covers files its standing question into the
        // same accumulator the ladder and seam residues land in.
        self.record_export_residue(binary).await;

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
            // never holds the loop open (issue #219, part of #217).
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

            // Handle root functions (entry points) — generate Stubs, not translations
            if matches!(plan_func.priority, TranslationPriority::Root) {
                // Skip functions are recorded as skipped (runtime library functions)
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
                    // and a caller that assumes a success always carries
                    // code would panic.

                    continue;
                }

                // Generate a Stub for entry-point functions
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

                // Run the caller's callback even for functions that got a Stub
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

            // A stopped root — a name-pattern root that reached the unit
            // anyway, or a self-call thunk the name patterns cannot see
            // (issue #269) — is a request the pipeline stops, not a unit
            // that failed: record it as skipped, the way the explicit-list
            // path does, and the flag keeps it out of the completion
            // callback below (a stopped unit has no code to write).
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
                    // A stopped root is a stop, not a failure: record it
                    // as skipped, exactly as the explicit-list path does.
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

            // Carry-over history (issue #299): when attempt 1 arrived on an
            // accepted translation and that code is what succeeded, say so on
            // the record — the git callback's commit message reads it.
            self.attach_carry_over_provenance(&mut result);

            let success = result.success;
            // W2.5: charge the unit's token spend against the run budget.
            self.record_unit_tokens(&result);
            batch_result.add(result.clone());

            // Send the progress event used for real-time tracking
            self.emit(ProgressEvent::FunctionCompleted {
                binary: binary.clone().into(),
                function: plan_func.name.clone(),
                success,
                attempts: 0,  // filled by caller after git branch creation
                branch: None, // filled by caller after git branch creation
            });

            // Run the caller's callback. A stopped root never reaches
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

            // The unit is complete — file this binary's unknown ledger so
            // the gaps the batch's folds admitted stand on disk even if
            // the batch stops before its last unit (issue #369).
            self.file_unknown_ledger(binary)?;

            if !continue_batch {
                info!(
                    binary,
                    function = %plan_func.name,
                    "Batch stopped early by callback"
                );
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

/// The calling-convention keywords that the testgen signature parser picks
/// out of a signature — the same closed set, so a decompiler line the
/// parser reads as carrying a convention never gets a keyword written
/// over it (issue #251, part of #226).
const CONVENTION_SPELLINGS: [&str; 6] = [
    "__stdcall",
    "__cdecl",
    "__fastcall",
    "__thiscall",
    "__naked",
    "__retpoline",
];

/// Whether `signature` already names a calling convention in the slot
/// the parser reads — between the return type and the parameter list. A
/// parameter list cannot hold these keywords, so only the part before the
/// opening parenthesis is checked.
fn names_convention(signature: &str) -> bool {
    let before_paren = signature.split('(').next().unwrap_or(signature);
    CONVENTION_SPELLINGS
        .iter()
        .any(|spelling| before_paren.contains(spelling))
}

/// Write `convention` into `signature` between the return type and the
/// declarator's name — the slot the parser reads — leaving the parameter
/// list as it is. Returns None when there is no name to write before (no
/// whitespace between the return type and the name), which leaves the
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
/// The detector's set of known-good symbols is the union of:
/// 1. every analysis engine function (exports and user-defined functions)
/// 2. every analysis engine import (DLL imports)
/// 3. every Windows API name in the PAL mapping table
pub async fn build_hallucination_detector(
    source: &KunaSource,
    api_mappings: &ApiMappings,
) -> HallucinationDetector {
    // Analysis engine functions
    let engine_functions: Vec<String> = ScanSource::functions(source)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|f| f.name)
        .collect();

    // Analysis engine imports
    let engine_imports: Vec<String> = ScanSource::imports(source)
        .await
        .ok()
        .into_iter()
        .flatten()
        .map(|s| s.name)
        .collect();

    // Gather the Windows API names from the PAL mapping table
    let _windows_apis: Vec<String> = api_mappings
        .iter()
        .map(|m| m.windows_api.to_string())
        .collect();

    HallucinationDetector::new(engine_functions, engine_imports)
}

/// Build the callback scan's signature map from the type-inference
/// document cached for `binary` under `workspace`.
///
/// The callback engine takes its callable contracts by injection (see
/// [`calxgloss_callback::signatures`]); this is the only place that
/// reads the type-inference scan's saved per-binary document and
/// builds those contracts, so the CLI `callback` command and the
/// batch pre-analysis get the same enrichment (issue #173,
/// ADR-0036). A missing or corrupt document — the type-inference scan
/// never ran, or its artifact is broken — gives an empty map and the
/// callback scan quietly falls back to its plain suggestions: a
/// broken artifact next door never fails the scan.
///
/// The map is honest about what the records prove. A function joins
/// it only when its parameter records cover positions `0..n`
/// **contiguously** and a return record is there: a gap means a
/// middle parameter the records never typed, and a contract that
/// skipped it would put every type after it in the wrong place; no
/// parameter records at all cannot tell a zero-parameter callback
/// from one whose parameters were never read; and with no return
/// reading, the contract would claim a unit return that nobody read.
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
/// callable contracts that the callback engine uses: the parameter
/// records by position, and the function's return record.
fn compose_signature_map(result: &TypeInferenceResult) -> SignatureMap {
    // First-seen wins per slot, matching the tie-break that the
    // inference scan itself uses for conflicts: a well-formed document
    // holds one record per slot anyway.
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
            // Locals and call-site readings describe storage, not the
            // callable's contract.
            _ => {}
        }
    }

    let mut signatures = SignatureMap::new();
    for (function, mut slots) in params {
        // A stable sort keeps the first-seen record in front among equal
        // positions, and the dedup step then reduces a repeated position
        // to its first reading.
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
mod tests;

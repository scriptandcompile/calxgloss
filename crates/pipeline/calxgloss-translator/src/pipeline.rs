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

#![allow(unused_imports)] // header imports feed the submodules and the test module through `use super::*;`
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

// The pipeline's own seams. Each names the part of the pipeline it owns;
// they see this module through `use super::*;`, and the tests below see
// them back through the globs here.
mod batch_run;
mod builder;
mod callgraph_plan;
mod control;
mod residue;
mod scan_phase;
mod signatures;
mod translate_unit;
mod unit_reads;

pub use signatures::{build_hallucination_detector, callback_signature_map};

// Every seam below defines methods on this module's struct and free items
// this module's own methods call; the globs bring them back into scope here,
// and the submodules' and test module's `use super::*;` resolve through them.
use batch_run::*;
use builder::*;
use callgraph_plan::*;
use control::*;
use residue::*;
use scan_phase::*;
use signatures::*;
use translate_unit::*;
use unit_reads::*;

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
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests;

//! Pipeline assembly — the seam that turns a pass description into a wired pipeline.
//!
//! This is the expand step of epic #322 (issue #323): the vocabulary
//! ([`PipelineSpec`]), the single assembly function ([`assemble`]), and the
//! assembled-pass outcome ([`AssembledPass`]). `auto` runs through the seam
//! (issue #325), and so do `translate` and `batch-translate` (issue #326):
//! the CLI folds its resolved settings into the vocabulary, layers each
//! command's run options on, and calls assembly once per pass. The one
//! remaining hand-built construction — web's patch-retry — still uses
//! [`TranslationPipeline::new`] and the `with_*` setters until the epic's
//! closing slice moves that call site through.
//!
//! Reachability follows the epic's rule: the module is public on the crate
//! path (`calxgloss_translator::assembly`) but the seam types are *not*
//! re-exported at the crate root, so the root surface stays unchanged while
//! facades wire through the module path — and no new hand-rolled construction
//! appears by reaching through the root.
//!
//! # Scope of the vocabulary (real knobs only)
//!
//! Every field here corresponds to a knob that exists in the codebase today —
//! the reference is the hand-built dance `interface/calxgloss-cli/src/
//! commands/auto.rs` carried until issue #325 moved it through `assemble`,
//! with the same dance its `commands/translate.rs` and
//! `commands/batch_translate.rs` twins carried until issue #326 moved them
//! through too. The epic's prose names spec fields with no implementation
//! counterpart anywhere (a target dialect, an LLM-call budget, context-
//! trimming limits beyond the LLM context window, toolchain paths, a testgen
//! timeout, a `no_tests` toggle, git policy and author); those are
//! intentionally absent. A spec field that only round-trips through assembly
//! would be a hidden test of a behavior that does not exist, so each belongs
//! to the ticket that builds the behavior, not to this seam.
//!
//! # What `assemble` guarantees
//!
//! - The LLM is **mandatory**: a spec carrying neither a prebuilt client nor a
//!   description that can build one fails assembly with
//!   [`TranslatorError::MissingLlm`] — no pass runs quietly without an LLM. A
//!   description whose endpoint cannot produce a client folds the
//!   [`calxgloss_llm::LlmError`] into the crate's existing
//!   [`TranslatorError::Llm`] — no new error enum.
//! - Patch mode honors the configured Kuna budget *for the engine load it
//!   makes*: the CLI loads every pass's engine through
//!   `KunaSource::load_with_budget(…, settings.kuna_budget())`, and a
//!   patch-retry pass assembles that load itself from the spec's binary path
//!   under the spec's budget. Normal passes receive the engine their facade
//!   loaded (per-binary budget selection stays a facade concern until the
//!   epic folds the call sites).
//! - The retry config the pass carries matches what the hand-built ladder
//!   produces today: the spec's policy with escalation always on and no
//!   context-tier cap (the pipeline's scope constraints cap it downstream —
//!   assembly never raises it).

use std::path::PathBuf;
use std::sync::Arc;

use calxgloss_kuna::{KunaBudget, KunaSource};
use calxgloss_llm::{LlmClient, LlmConfig};
use calxgloss_pal::ApiMappings;
use calxgloss_testgen::TestGenerator;
use calxgloss_types::{
    OverrideControl, PipelineControl, RetryStrategy, ScopeControl, StopSignal, TranslationEvents,
    UnitCancellation,
};
use calxgloss_verify::Verifier;

use crate::carry_over::AcceptedAttemptSource;
use crate::error::{Result, TranslatorError};
use crate::pipeline::{TranslationPipeline, build_hallucination_detector};
use crate::retry::RetryConfig;

/// What an agent wants an LLM pass to talk to: the endpoint and model, plus
/// the optional settings the client supports.
///
/// Mirrors the settings vocabulary (`Settings::llm_client`'s callers build a
/// client from exactly these fields); a spec carrying a description has its
/// client built during assembly, and a client that cannot be built is an
/// assembly error, not a pass that quietly has no LLM.
#[derive(Debug, Clone)]
pub struct LlmDescription {
    /// OpenAI-compatible endpoint, e.g. `http://127.0.0.1:8081/v1/chat/completions`.
    pub endpoint: String,
    /// Model name the endpoint expects.
    pub model: String,
    /// API key sent as a bearer token (no default applied here — a local
    /// endpoint needs none, a hosted one supplies its own).
    pub api_key: Option<String>,
    /// Context window in tokens for prompt trimming (`LlmConfig`'s default applies when unset).
    pub context_window: Option<usize>,
    /// Sampling temperature (`LlmConfig`'s default applies when unset).
    pub temperature: Option<f32>,
    /// Per-request timeout in seconds (`LlmConfig`'s default applies when unset).
    pub timeout_secs: Option<u64>,
}

/// How a spec asks for the pass's LLM: reuse a prebuilt client, or build one
/// from a description during assembly.
#[derive(Debug, Clone)]
pub enum LlmSelection {
    /// A client the facade already built (e.g. from its settings).
    Client(LlmClient),
    /// Endpoint and model to build a client from — assembly builds it, and a
    /// description with an invalid endpoint fails the assembly (the
    /// [`calxgloss_llm::LlmError`] folds into [`TranslatorError::Llm`]).
    Description(LlmDescription),
}

/// The name and location of the binary a pass targets: the seam's one binary
/// notion, so a caller never carries a display name and a path separately.
///
/// `name` is the bare file name (`fixture_target.dll`) shown in reports and
/// carried as the pipeline's binary identity; `path` locates the bytes on
/// disk for patch loads and the batch's read cache key.
#[derive(Debug, Clone)]
pub struct BinaryTarget {
    /// Bare file name used in reports and the pipeline's binary identity.
    pub name: String,
    /// Where the binary lives on disk.
    pub path: PathBuf,
}

/// A complete description of one translation pass: everything that separates
/// one pass from another, as plain data a facade builds from its options.
///
/// Plain struct fields carry the vocabulary; every field defaults to unset.
/// Options with no pipeline behavior behind them are absent from the spec
/// rather than present-and-ignored (see the module docs). Fields the spec
/// leaves unset keep pipeline defaults.
#[derive(Default, Clone)]
pub struct PipelineSpec {
    /// The LLM this pass talks to. Mandatory in effect: an assembly with no
    /// LLM (neither client nor description) fails with
    /// [`TranslatorError::MissingLlm`].
    pub llm: Option<LlmSelection>,
    /// The workspace the pass operates in (reports, caches, and the verifier's
    /// build root live under it).
    pub workspace: PathBuf,
    /// This pass is a patch-retry pass: `assemble` loads the engine for the
    /// pass itself, under the spec's Kuna budget, from the spec's binary path.
    pub patch_mode: bool,
    /// The binary this pass targets, when the pass names one (the CLI
    /// commands and patch retries do; a bare spec may not).
    pub target_binary: Option<BinaryTarget>,
    /// Kuna budget for the engine loads this assembly performs (patch mode).
    /// The facade chooses per-binary budgets and passes the one this pass
    /// wants.
    pub kuna_budget: KunaBudget,
    /// The PAL mapping table this pass answers to (a caller's custom table);
    /// `None` uses the built-in default table.
    pub api_mappings: Option<ApiMappings>,
    /// Retry: attempts per unit before escalating to full-patch context.
    pub retry_max_attempts: Option<u32>,
    /// Retry: per-unit strategy (compile-fix, test-fix, …).
    pub retry_strategy: Option<RetryStrategy>,

    // ---- Call-graph and cache flags ----
    /// Skip the call-graph pre-pass.
    pub no_callgraph: bool,
    /// Print the call graph to stdout before translating.
    pub callgraph_verbose: bool,
    /// Directory for the call-graph JSON cache (default: the workspace's
    /// `re/analysis/` path).
    pub callgraph_cache_dir: Option<PathBuf>,
    /// Recompute the call graph even when the JSON cache is fresh.
    pub refresh_cache: bool,

    // ---- Injected collaborators (object args, never option strings) ----
    // The same handles the `with_*` setters carry today; a facade that owns
    // long-lived handles (a web server's events, a CLI run's control) hands
    // them through the spec and `assemble` wires them.
    /// The accepted-attempt port that makes carry-over seeding live
    /// (the CLI wires the git journal here when git is enabled).
    pub accepted_attempt_source: Option<Arc<dyn AcceptedAttemptSource>>,
    /// Translation progress events.
    pub events: Option<TranslationEvents>,
    /// Cooperative cancellation control.
    pub stop: Option<StopSignal>,
    /// The caller's lifecycle control handle.
    pub pipeline_control: Option<PipelineControl>,
    /// Per-unit cancellation control.
    pub unit_cancellation: Option<UnitCancellation>,
    /// The translation scope for a pass that carries one.
    pub scope: Option<ScopeControl>,
    /// Per-function reviewer overrides for a pass that carries them.
    pub overrides: Option<OverrideControl>,
}

/// Field view: one injected port (`AcceptedAttemptSource`) is a trait object
/// without `Debug`, so it prints as set-or-unset rather than inline; the
/// mapping table prints the same way because the table itself is noise next
/// to the question "did the caller supply one?" (precedent: the manual
/// `Debug` on [`AssembledPass`]). Enumerates every field: add new fields to
/// this impl when adding them to the struct.
impl std::fmt::Debug for PipelineSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineSpec")
            .field("llm", &self.llm)
            .field("workspace", &self.workspace)
            .field("patch_mode", &self.patch_mode)
            .field("target_binary", &self.target_binary)
            .field("kuna_budget", &self.kuna_budget)
            .field(
                "api_mappings",
                &self.api_mappings.as_ref().map(|_| "custom"),
            )
            .field("retry_max_attempts", &self.retry_max_attempts)
            .field("retry_strategy", &self.retry_strategy)
            .field("no_callgraph", &self.no_callgraph)
            .field("callgraph_verbose", &self.callgraph_verbose)
            .field("callgraph_cache_dir", &self.callgraph_cache_dir)
            .field("refresh_cache", &self.refresh_cache)
            .field(
                "accepted_attempt_source",
                &self.accepted_attempt_source.as_ref().map(|_| "port"),
            )
            .field("events", &self.events)
            .field("stop", &self.stop)
            .field("pipeline_control", &self.pipeline_control)
            .field("unit_cancellation", &self.unit_cancellation)
            .field("scope", &self.scope)
            .field("overrides", &self.overrides)
            .finish()
    }
}

/// A pass ready to run: the wired pipeline, its verifier, and its retry
/// configuration — what a facade's command body reaches for once assembly is
/// done, and what the retry loop consumes.
pub struct AssembledPass {
    /// The pipeline, wired from the spec: LLM, engine, mappings, workspace,
    /// detector, and the injected handles all set.
    pub pipeline: TranslationPipeline,
    /// The verifier that compiles generated tests (the spec's workspace is
    /// its working directory).
    pub verifier: Verifier,
    /// Retry configuration assembled from the spec (defaults filled in).
    pub retry: RetryConfig,
}

/// Field names only: the pipeline and the verifier own state (engine threads,
/// caches) with no meaningful `Debug` view, and a test that fails to print a
/// pass only needs to know which fields it cared about.
impl std::fmt::Debug for AssembledPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssembledPass")
            .field("pipeline", &"..")
            .field("verifier", &"..")
            .field("retry", &self.retry)
            .finish()
    }
}

/// Assembles `spec` into a ready-to-run pass over `engine`.
///
/// The engine is passed in because normal passes load it in their facade
/// (the CLI loads with `settings.kuna_budget()`, the web server plain-loads
/// for patch retries — each owns its own budget policy). The exception is
/// patch mode with a named binary: there `assemble` performs the load itself,
/// under the spec's Kuna budget, so an assembled patch pass provably honors
/// the configured budget for its engine; the passed engine is used only when
/// no binary path is on the spec.
///
/// The wiring mirrors the reference dance `commands/auto.rs` carried until
/// issue #325: detector built from the engine and the mapping table before
/// the pipeline consumes them, testgen and detector wired first, then the
/// call-graph flags, the injected handles, workspace, and the binary
/// identity/path.
pub async fn assemble(spec: &PipelineSpec, engine: &KunaSource) -> Result<AssembledPass> {
    let llm = match spec.llm.as_ref() {
        None => {
            return Err(TranslatorError::MissingLlm {
                reason: "the spec carries neither a prebuilt client nor an endpoint and model to build one from".to_string(),
            });
        }
        Some(LlmSelection::Client(client)) => client.clone(),
        Some(LlmSelection::Description(desc)) => {
            let mut config = LlmConfig::new(&desc.endpoint, &desc.model)?;
            if let Some(key) = &desc.api_key {
                config = config.with_api_key(key.clone());
            }
            if let Some(window) = desc.context_window {
                config = config.with_context_window(window);
            }
            if let Some(temperature) = desc.temperature {
                config = config.with_temperature(temperature);
            }
            if let Some(secs) = desc.timeout_secs {
                config = config.with_timeout_secs(secs);
            }
            LlmClient::new(config)?
        }
    };

    // Patch passes assemble their own load so the configured budget binds
    // the engine this pass reads through (issue #211's budgets arm at load).
    let engine = if spec.patch_mode {
        match spec.target_binary.as_ref() {
            Some(target) => KunaSource::load_with_budget(&target.path, None, spec.kuna_budget)?,
            None => engine.clone(),
        }
    } else {
        engine.clone()
    };

    // The detector reads the engine and the mapping table; the pipeline then
    // consumes both, so build it first — exactly as the hand-built paths do.
    let api_mappings = spec.api_mappings.clone().unwrap_or_default();
    let detector = build_hallucination_detector(&engine, &api_mappings).await;

    let mut pipeline = TranslationPipeline::new(engine, llm, api_mappings)
        .with_testgen(TestGenerator::new(&spec.workspace))
        .with_hallucination_detector(detector);

    if spec.no_callgraph {
        pipeline = pipeline.with_no_callgraph();
    }
    if let Some(cache_dir) = &spec.callgraph_cache_dir {
        pipeline = pipeline.with_callgraph_cache_dir(cache_dir.clone());
    }
    if spec.callgraph_verbose {
        pipeline = pipeline.with_callgraph_verbose();
    }
    if let Some(events) = &spec.events {
        pipeline = pipeline.with_events(events.clone());
    }
    if let Some(stop) = &spec.stop {
        pipeline = pipeline.with_stop_signal(stop.clone());
    }
    if let Some(control) = &spec.pipeline_control {
        pipeline = pipeline.with_pipeline_control(control.clone());
    }
    if let Some(cancellation) = &spec.unit_cancellation {
        pipeline = pipeline.with_unit_cancellation(cancellation.clone());
    }
    if let Some(scope) = &spec.scope {
        pipeline = pipeline.with_scope(scope.clone());
    }
    if let Some(overrides) = &spec.overrides {
        pipeline = pipeline.with_overrides(overrides.clone());
    }
    pipeline = pipeline.with_workspace(spec.workspace.clone());
    if let Some(source) = &spec.accepted_attempt_source {
        pipeline = pipeline.with_accepted_attempt_source(source.clone());
    }
    if let Some(target) = &spec.target_binary {
        pipeline = pipeline.with_target_binary(target.name.clone());
        // The batch's shared read cache keys on the target's file bytes
        // (issue #105) — the path rides with the name.
        pipeline = pipeline.with_binary_path(target.path.clone());
    }
    if spec.refresh_cache {
        pipeline = pipeline.with_refresh_cache();
    }

    let retry = RetryConfig {
        max_attempts: spec.retry_max_attempts.unwrap_or(3),
        strategy: spec.retry_strategy.unwrap_or(RetryStrategy::CompileFix),
        escalate_on_failure: true,
        max_context_tier: None,
    };

    let verifier = Verifier::new(&spec.workspace).map_err(TranslatorError::VerifierSetup)?;

    Ok(AssembledPass {
        pipeline,
        verifier,
        retry,
    })
}

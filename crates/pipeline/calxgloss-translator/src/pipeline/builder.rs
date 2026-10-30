//! Builder setters of [`TranslationPipeline`]: one `with_*` per optional input
//! the assembly seam can hand it. The struct itself and its `new` door stay in
//! the pipeline module.

use super::*;

impl TranslationPipeline {
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
}

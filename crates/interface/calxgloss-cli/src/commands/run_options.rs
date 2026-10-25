//! The bundles that carry the run-wide options of the `auto` and `live`
//! entry points.
//!
//! Both commands accept the same flag surface, and both end up in the same
//! run plumbing — `handle_auto`, `handle_live`, and `run_translation_for_dll`
//! each used to take 14–20 positional parameters (issue #268). These structs
//! group them by what they are:
//!
//! - [`AutoRunOptions`] — the `auto` command's flags plus the settings and
//!   workspace every phase needs.
//! - [`LiveRunOptions`] — the `live` command's flags plus the log controls.
//! - [`RunControls`] — the optional live run state (events, control,
//!   cancellation, scope and override handles) that the web server drives;
//!   `RunControls::default()` is a plain batch run with none of it, and
//!   [`RunControls::apply`] layers whichever handles exist onto a pass
//!   description for assembly to wire.
//! - [`PassPlumbing`] — one binary's translation pass: workspace, settings,
//!   git flag, the [`PipelineSpec`] description assembly consumes, and the
//!   [`RunControls`] it observes.

use std::path::PathBuf;

use calxgloss::{
    ClassificationOverrideControl, OverrideControl, PipelineControl, ScopeControl, StopSignal,
    TranslationEvents, UnitCancellation,
};
use calxgloss_translator::assembly::PipelineSpec;
use calxgloss_web::LogLevelControl;

use crate::Settings;

/// The `auto` command's flags, settings, and resolved workspace — everything
/// the classify/translate phases read that isn't live run state.
#[derive(Clone)]
pub struct AutoRunOptions<'a> {
    /// `--target-dir` override; falls back to settings, then errors.
    pub target: Option<PathBuf>,
    /// `--binaries` list, comma-separated; otherwise the target dir is scanned.
    pub binaries_arg: Option<String>,
    /// `--all-functions` flag (kept for the flag surface; the queue plan
    /// itself is chosen by the run request's scope).
    pub all_functions: bool,
    /// `--classify-only`: classify, report, and stop before translating.
    pub classify_only: bool,
    /// Translate after classifying instead of stopping (always true for
    /// `live`, which re-runs the loop on every Start request).
    pub continue_mode: bool,
    /// Skip git operations.
    pub skip_git: bool,
    /// Resolved settings (config + env + flags).
    pub settings: &'a Settings,
    /// The resolved workspace the run writes into.
    pub workspace: PathBuf,
    /// Skip call-graph analysis for this run.
    pub no_callgraph: bool,
    /// Directory holding the cached call graph.
    pub callgraph_cache: Option<PathBuf>,
    /// Log call-graph diagnostics.
    pub callgraph_verbose: bool,
    /// Force the batch's shared scan read cache cold (issue #106).
    pub refresh_cache: bool,
}

/// The `live` command's flags and log controls. The workspace, port, and
/// settings stay separate — the live workspace is always CWD and the port
/// is bound before the run loop starts.
#[derive(Clone)]
pub struct LiveRunOptions {
    /// `--target-dir` override.
    pub target: Option<PathBuf>,
    /// `--binaries` list, comma-separated.
    pub binaries: Option<String>,
    /// `--all-functions` flag.
    pub all_functions: bool,
    /// `--classify-only`: launch into classification and wait for Start.
    pub classify_only: bool,
    /// Skip git operations.
    pub skip_git: bool,
    /// Skip call-graph analysis.
    pub no_callgraph: bool,
    /// Directory holding the cached call graph.
    pub callgraph_cache: Option<PathBuf>,
    /// Log call-graph diagnostics.
    pub callgraph_verbose: bool,
    /// Force the batch's shared scan read cache cold.
    pub refresh_cache: bool,
    /// The logging level the run loop and the serve task share.
    pub log_level: &'static str,
    /// The live log filter shared with the web UI.
    pub log_filter: LogLevelControl,
}

/// The live run state the web server drives and the pipeline observes —
/// all optional: a plain batch (`RunControls::default()`) has none of it.
#[derive(Clone, Copy, Default)]
pub struct RunControls<'a> {
    /// Progress events for live progress streaming.
    pub events: Option<&'a TranslationEvents>,
    /// The shutdown/restart endpoints flip it; the pipeline pauses at unit
    /// boundaries.
    pub stop: Option<&'a StopSignal>,
    /// The pause/resume/stop endpoints drive it.
    pub control: Option<&'a PipelineControl>,
    /// The cancel-current endpoint aborts the in-flight unit.
    pub cancellation: Option<&'a UnitCancellation>,
    /// The scope endpoints steer this run through it.
    pub scope_control: Option<&'a ScopeControl>,
    /// The override endpoints steer this run through it.
    pub override_control: Option<&'a OverrideControl>,
    /// The classification endpoints steer this run through it.
    pub classification_overrides: Option<&'a ClassificationOverrideControl>,
}

impl RunControls<'_> {
    /// Layer the live run state onto a pass description (issue #325): the
    /// handles the `with_*` setters used to carry ride the description as
    /// plain data now, and `assemble` wires them onto the pipeline. The
    /// description ends up mirroring exactly what this bundle holds —
    /// handles set, handles absent cleared (the fold leaves the injection
    /// fields unset, so in practice this only ever sets).
    ///
    /// The classification handle is deliberately not layered: the pipeline
    /// never sees it — the classification phase reads it directly.
    pub fn apply(&self, spec: &mut PipelineSpec) {
        let RunControls {
            events,
            stop,
            control,
            cancellation,
            scope_control,
            override_control,
            classification_overrides: _,
        } = *self;
        spec.events = events.cloned();
        spec.stop = stop.cloned();
        spec.pipeline_control = control.cloned();
        spec.unit_cancellation = cancellation.cloned();
        spec.scope = scope_control.cloned();
        spec.overrides = override_control.cloned();
    }
}

/// One binary's translation pass: the workspace and settings it runs against,
/// the git flag, the [`PipelineSpec`] description its assembly consumes, and
/// the live run state it observes.
///
/// The call-graph flags it used to carry (issue #268) are knob-set data the
/// description now carries: `handle_auto` folds them into the spec once per
/// run, and each pass clones the spec rather than re-deciding per knob
/// (issue #325).
#[derive(Clone)]
pub struct PassPlumbing<'a> {
    /// Settings the engine load is made from (its budgets); the pass
    /// description carries what assembly needs beyond the binary the pass
    /// names.
    pub settings: &'a Settings,
    /// The workspace — git, src/, scratch all live here.
    pub workspace: &'a std::path::Path,
    /// Skip git operations.
    pub skip_git: bool,
    /// The pass description assembled once per pass: resolved settings
    /// folded, run flags and live control handles layered on.
    pub spec: PipelineSpec,
    /// The live run state this pass observes, if any.
    pub run: &'a RunControls<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_control_handles_layer_onto_the_pass_description() {
        // Issue #325: bundle to description is a pure data move — every
        // pipeline-facing handle in the bundle lands on the spec for
        // assembly to wire, and the classification handle stays off it
        // (the pipeline never sees it).
        let events = TranslationEvents::new(16);
        let stop = StopSignal::new();
        let control = PipelineControl::new();
        let cancellation = UnitCancellation::new();
        let scope = ScopeControl::new();
        let overrides = OverrideControl::new();
        let classification = ClassificationOverrideControl::new();
        let controls = RunControls {
            events: Some(&events),
            stop: Some(&stop),
            control: Some(&control),
            cancellation: Some(&cancellation),
            scope_control: Some(&scope),
            override_control: Some(&overrides),
            classification_overrides: Some(&classification),
        };
        let mut spec = PipelineSpec::default();
        controls.apply(&mut spec);
        assert!(spec.events.is_some(), "events reach the description");
        assert!(
            spec.stop.is_some(),
            "the stop signal reaches the description"
        );
        assert!(
            spec.pipeline_control.is_some(),
            "the lifecycle control reaches the description"
        );
        assert!(
            spec.unit_cancellation.is_some(),
            "per-unit cancellation reaches the description"
        );
        assert!(
            spec.scope.is_some(),
            "the scope handle reaches the description"
        );
        assert!(
            spec.overrides.is_some(),
            "the reviewer overrides reach the description"
        );
    }

    #[test]
    fn a_plain_batch_layers_nothing_onto_the_description() {
        // `RunControls::default()` is a plain batch run: after apply every
        // injection field stays unset, so the pass assembles with pipeline
        // defaults — no quietly attached live state.
        let mut spec = PipelineSpec::default();
        RunControls::default().apply(&mut spec);
        assert!(spec.events.is_none());
        assert!(spec.stop.is_none());
        assert!(spec.pipeline_control.is_none());
        assert!(spec.unit_cancellation.is_none());
        assert!(spec.scope.is_none());
        assert!(spec.overrides.is_none());
    }
}

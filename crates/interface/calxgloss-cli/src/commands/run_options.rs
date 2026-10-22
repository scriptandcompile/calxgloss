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
//!   `RunControls::default()` is a plain batch run with none of it.
//! - [`PassPlumbing`] — one binary's translation pass: workspace, settings,
//!   git flag, call-graph flags, and the [`RunControls`] it observes.

use std::path::PathBuf;

use calxgloss::{
    ClassificationOverrideControl, OverrideControl, PipelineControl, ScopeControl, StopSignal,
    TranslationEvents, UnitCancellation,
};
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

/// One binary's translation pass: the workspace and settings it runs against,
/// the flags that configure its pipeline, and the live run state it observes.
#[derive(Clone)]
pub struct PassPlumbing<'a> {
    /// Settings the engine and LLM client are built from.
    pub settings: &'a Settings,
    /// The workspace — git, src/, scratch all live here.
    pub workspace: &'a std::path::Path,
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
    /// The live run state this pass observes, if any.
    pub run: &'a RunControls<'a>,
}

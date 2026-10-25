//! The bundles that carry the run-wide options of the translation entry
//! points.
//!
//! `auto` and `live` accept the same flag surface, and both end up in the
//! same run plumbing — `handle_auto`, `handle_live`, and
//! `run_translation_for_dll` each used to take 14–20 positional parameters
//! (issue #268). These structs group them by what they are:
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
//! - [`command_pass_spec`] — the one-target commands' pass description:
//!   settings folded once, the command's [`PassFlags`] and named target
//!   layered on (issue #326).

use std::path::PathBuf;

use anyhow::Result;

use calxgloss::{
    ClassificationOverrideControl, OverrideControl, PipelineControl, ScopeControl, StopSignal,
    TranslationEvents, UnitCancellation,
};
use calxgloss_translator::assembly::BinaryTarget;
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

/// The call-graph and read-cache flags a single-target translation command
/// layers onto its pass description — the same four fields `AutoRunOptions`
/// carries per run (issue #268's bundle convention), as one group (issue
/// #326).
#[derive(Clone, Default)]
pub struct PassFlags {
    /// Skip call-graph analysis for this run.
    pub no_callgraph: bool,
    /// Directory holding the cached call graph.
    pub callgraph_cache: Option<PathBuf>,
    /// Log call-graph diagnostics.
    pub callgraph_verbose: bool,
    /// Force the batch's shared scan read cache cold (issue #106).
    pub refresh_cache: bool,
}

/// Build the pass description one single-target command run assembles (issue
/// #326): the resolved settings folded once (issue #324), then this command's
/// run options layered on — the resolved workspace, its call-graph and cache
/// flags, and the binary it names.
///
/// This is the same data move `handle_auto` performs inline on its base
/// description (issue #325), minus the live control handles only `auto` and
/// `live` carry: the three commands end up with descriptions folded from the
/// one fold, so an assembled pass honors the settings knobs identically
/// whichever command typed the run.
///
/// A record with no endpoint pair is refused here with the settings layer's
/// "not configured" guidance — naming every layer that can supply one —
/// rather than the assembly seam's internal `MissingLlm` wording, exactly as
/// `handle_auto` refuses.
pub fn command_pass_spec(
    settings: &Settings,
    workspace: &std::path::Path,
    binary: &str,
    target: &std::path::Path,
    flags: PassFlags,
) -> Result<PipelineSpec> {
    let mut spec = crate::settings::pipeline_spec(settings)?;
    if spec.llm.is_none() {
        settings.require_llm_url()?;
        settings.require_llm_model()?;
    }
    // The resolved workspace (--workspace > settings > CWD) wins over the
    // record's own value: the flag layer is what the command was handed.
    spec.workspace = workspace.to_path_buf();
    spec.no_callgraph = flags.no_callgraph;
    spec.callgraph_cache_dir = flags.callgraph_cache;
    spec.callgraph_verbose = flags.callgraph_verbose;
    spec.refresh_cache = flags.refresh_cache;
    spec.target_binary = Some(BinaryTarget {
        name: binary.to_string(),
        path: target.to_path_buf(),
    });
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_config::{AnalysisSection, LlmSection};
    use calxgloss_translator::assembly::LlmSelection;

    /// Resolve a record from the file and flag layers, bypassing env and the
    /// real config search (the settings module's fold tests are the prior
    /// art for this helper).
    fn settings_from(
        flags: calxgloss_config::FileConfig,
        file: calxgloss_config::FileConfig,
    ) -> Settings {
        let layers = calxgloss_config::Layers {
            file,
            ..Default::default()
        };
        let loaded = calxgloss_config::LoadedConfig {
            file: layers.file.clone(),
            path: None,
            searched: vec![PathBuf::from("calxgloss.toml")],
        };
        Settings::resolve(&layers, flags, &loaded)
    }

    #[test]
    fn the_command_description_carries_the_settings_knobs_and_the_command_flags() {
        // Issue #326: `translate` and `batch-translate` build their pass from the
        // same fold `auto` reads — every knob the record resolved rides the
        // description verbatim, and the command's own flags layer on top. The
        // pass assembled from this description honors those knobs whichever
        // command typed the run.
        let file = calxgloss_config::FileConfig {
            workspace: Some("/home/dev/from-settings".into()),
            llm: LlmSection {
                url: Some("http://127.0.0.1:1919/v1".into()),
                model: Some("Qwen".into()),
                api_key: Some("sk-secret".into()),
                max_retries: Some(9),
                strategy: Some("test_fix".into()),
                ..Default::default()
            },
            analysis: AnalysisSection {
                max_fn_instructions: Some(5000),
                max_fn_seconds: Some(30),
                max_fn_memory_mib: Some(512),
            },
            ..Default::default()
        };
        let s = settings_from(Default::default(), file);
        let spec = command_pass_spec(
            &s,
            std::path::Path::new("/run/workspace"),
            "fixture_target.dll",
            std::path::Path::new("/targets/fixture_target.dll"),
            PassFlags {
                no_callgraph: true,
                callgraph_cache: Some(PathBuf::from("/tmp/cg-cache")),
                callgraph_verbose: true,
                refresh_cache: true,
            },
        )
        .expect("a resolved record folds without complaint");
        let Some(LlmSelection::Description(desc)) = spec.llm.as_ref() else {
            panic!("the fold hands over the endpoint description the record resolved");
        };
        assert_eq!(desc.endpoint, "http://127.0.0.1:1919/v1");
        assert_eq!(desc.model, "Qwen");
        assert_eq!(desc.api_key.as_deref(), Some("sk-secret"));
        assert_eq!(spec.retry_max_attempts, Some(9));
        assert_eq!(
            spec.retry_strategy,
            Some(calxgloss_types::RetryStrategy::TestFix)
        );
        assert_eq!(spec.kuna_budget.max_instructions, Some(5000));
        // The workspace the command resolved wins over the record's own value.
        assert_eq!(spec.workspace, PathBuf::from("/run/workspace"));
        // Command-specific flags layer on top of the record's description.
        assert!(spec.no_callgraph, "--no-callgraph reaches the description");
        assert_eq!(
            spec.callgraph_cache_dir.as_deref(),
            Some(std::path::Path::new("/tmp/cg-cache")),
            "--callgraph-cache reaches the description"
        );
        assert!(
            spec.callgraph_verbose,
            "--callgraph-verbose reaches the description"
        );
        assert!(
            spec.refresh_cache,
            "--refresh-cache reaches the description"
        );
        // The binary the command names rides as one target: report identity
        // and read-cache key together.
        let target = spec.target_binary.expect("the command names its target");
        assert_eq!(target.name, "fixture_target.dll");
        assert_eq!(target.path, PathBuf::from("/targets/fixture_target.dll"));
    }

    #[test]
    fn a_record_without_an_endpoint_pair_is_refused_with_settings_guidance() {
        // A translation pass always needs an LLM. The command's description
        // build refuses with the settings layer's guidance wording — naming
        // the flag, the env var, and the config table — before any engine
        // load, exactly like `auto` and the old inline `require_*` ladders.
        let s = settings_from(Default::default(), Default::default());
        let err = match command_pass_spec(
            &s,
            std::path::Path::new("/run/workspace"),
            "fixture_target.dll",
            std::path::Path::new("/targets/fixture_target.dll"),
            PassFlags::default(),
        ) {
            Ok(_) => panic!("no LLM must not fold into a runnable pass description"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("--llm-url"), "{err}");
        assert!(err.contains("CALXGLOSS_LLM_URL"), "{err}");
    }

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

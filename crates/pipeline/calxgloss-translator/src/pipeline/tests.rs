// Tests for the module above, split out of the file they test.
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
use calxgloss_libmatch::persist::LibmatchPersistor;
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
use calxgloss_types::EffectiveCoverage;
use calxgloss_types::TranslationConstraints;
use calxgloss_typesdb::persist::TypeDatabasePersistor;
use calxgloss_typesdb::types::ScanMetadata;
use tempfile::TempDir;

/// The fixture target loaded under the Kuna engine — the only engine
/// (issue #214). One source per test: the heartbeat pass state is
/// shared by clones, so tests that scan concurrently need their own
/// engine.
fn fixture_kuna() -> calxgloss_kuna::KunaSource {
    let target =
        calxgloss_testfixtures::load_target().expect("fixture target should build and validate");
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

/// A prioritized function runs ahead of the rest of the queue; the
/// remaining functions keep their original order.
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
fn reviewer_hints_reach_the_prompt() {
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
/// tier cap moves into the retry config (issue #93).
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

/// A paused `PipelineControl` holds `batch_translate` open at the next
/// unit boundary — the unit in flight is never interrupted — and the
/// resume continues exactly where it stopped (issue #90, W2.1).
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

/// A stop signal arriving while the loop is waiting at a pause boundary
/// releases the wait and ends the batch — server shutdown must never
/// hang on a paused run (issue #90, W2.1).
#[tokio::test]
async fn batch_translate_stop_during_pause_releases_the_wait() {
    let dir = TempDir::new().expect("temp workspace");
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

    let control = PipelineControl::new();
    control.start().expect("idle -> running");
    let stop = StopSignal::new();

    // The "operator" side: once the run is waiting in Paused, fire the
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
        "the paused loop ended at the boundary on the stop signal"
    );
}

/// A paused target binary ends `batch_translate` at the next unit
/// boundary, mirroring the run-level stop test: the unit in flight
/// completes and is counted, the remaining units never start — and,
/// unlike a run-level pause, the batch **returns** rather than waiting
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
    // The timeout is the "never waits forever" assertion: a run-level
    // pause would hold here until a resume that never arrives, while a
    // binary pause ends the batch on its own. The bound is generous
    // because the fifteen pre-analysis scans over the fixture run inside it.
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
    .expect("a paused binary ends the batch — it never waits for a resume");

    let result =
        batch.expect("batch over functions the fixture lacks still reports per-function failures");
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

/// Cancel-current on the unit in flight (issue #91, W2.2): the test
/// aborts mid-LLM-call, at the earliest safe point, against an LLM
/// server that never answers — without the abort the batch would hang
/// until the client timeout. The abort is what keeps this test fast,
/// and what proves the pipeline can stop an attempt that is already
/// under way rather than only one that has not started. The
/// cancelled attempt is recorded as a failure, and its callback
/// still runs so the caller can archive that unit's branch even
/// though the attempt failed. Once the cancellation is recorded the
/// run moves on: the remaining queued units translate normally,
/// and the returned results show the cancelled unit as failed.
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

// ─── API scope roster and captured-trace fold (issue #386, P22) ────

/// File an apidetect document for `game_logic.dll` holding these
/// per-function API usage findings (function, API, directness).
fn file_api_usages(dir: &std::path::Path, usages: &[(&str, &str, bool)]) {
    let mut result =
        calxgloss_apidetect::types::ApiDetectionResult::new(ScanMetadata::new("game_logic.dll"));
    result.findings = usages
        .iter()
        .map(|(function, api, direct)| {
            calxgloss_apidetect::types::ApiFinding::ApiUsage(calxgloss_apidetect::types::ApiUsage {
                function: (*function).to_string(),
                api: (*api).to_string(),
                library: "gdi32.dll".to_string(),
                rust_crate: "windows".to_string(),
                category: None,
                features: Vec::new(),
                direct: *direct,
                confidence: calxgloss_types::Confidence::new(if *direct { 80 } else { 60 }),
                evidence: format!("{function} → {api}"),
            })
        })
        .collect();
    calxgloss_apidetect::persist::ApiPersistor::new(dir)
        .save(&result)
        .expect("apidetect document should file");
}

/// File a baseline document for `game_logic.dll`'s `DrawPrimitive` holding
/// one captured case per (inputs, captured trace) pair — the shape
/// `collect_results` saves, where the trace rides both the case's
/// expectations and the result's actuals.
fn file_baseline_captures(dir: &std::path::Path, captures: &[(serde_json::Value, &[&str])]) {
    let results: Vec<calxgloss_types::TestResult> = captures
        .iter()
        .map(|(inputs, trace)| {
            let trace: Vec<String> = trace.iter().map(|name| name.to_string()).collect();
            calxgloss_types::TestResult {
                test_case: TestCase {
                    inputs: inputs.clone(),
                    expected_return: serde_json::Value::Null,
                    expected_side_effects: Vec::new(),
                    expected_api_calls: trace.clone(),
                },
                actual_return: serde_json::Value::Null,
                actual_side_effects: Vec::new(),
                actual_api_calls: trace,
                passed: true,
                error: None,
            }
        })
        .collect();
    calxgloss_testgen::TestGenerator::new(dir)
        .save_baseline("game_logic.dll", "DrawPrimitive", &results)
        .expect("baseline document should file");
}

/// A unit's `DrawPrimitive` fixture info, the same one the global-state
/// fold tests drive.
fn roster_fixture_function() -> FunctionInfo {
    FunctionInfo {
        name: "DrawPrimitive".to_string(),
        address: 0x1000,
        binary: "game_logic.dll".to_string().into(),
        disassembly: "cmp eax, 0\nje 0x1010".to_string(),
        decompiler_output:
            "void DrawPrimitive(void) { BitBlt(hdc, 0, 0, 1, 1, hdc2, 0, 0, SRCCOPY); }".to_string(),
        windows_apis: Vec::new(),
        call_graph: Vec::new(),
        disassembly_hints: Vec::new(),
    }
}

/// #386 (P22): the trace a saved baseline captured for a case becomes that
/// case's expectation — scoped to the in-scope API roster the apidetect
/// document records for the function (direct uses and through callees)
/// and spelled onto the verify PAL surface. Out-of-roster names and names
/// the surface stands in for nothing drop out of the expectation: the
/// fold never manufactures an expectation the gate can never satisfy.
#[tokio::test]
async fn baseline_tests_fold_captured_traces_scoped_to_the_api_roster() {
    let dir = TempDir::new().unwrap();
    let pipeline = pipeline_over(Some(dir.path()));
    let function_info = roster_fixture_function();

    // The unit's roster: BitBlt used directly, CreateFileA through a
    // callee (transitive findings join the roster too), and GetLastError
    // in the roster but spelled for nothing on the verify surface. Sleep
    // belongs to another function, so it is out of this unit's scope —
    // even though it has a surface spelling.
    file_api_usages(
        dir.path(),
        &[
            ("DrawPrimitive", "BitBlt", true),
            ("DrawPrimitive", "CreateFileA", false),
            ("DrawPrimitive", "GetLastError", true),
            ("UpdateScene", "Sleep", true),
        ],
    );

    // Take the generated suite's own inputs for the baseline document,
    // so the first capture matches the first generated case exactly.
    let first_pass = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("test inputs generate");
    assert!(
        !first_pass.is_empty(),
        "the fixture generates cases to fold onto"
    );

    // The captured trace, in recorded order: roster names with a surface
    // spelling, an out-of-roster name, an unspellable roster name, and a
    // repeated call — repetitions and order ride through.
    file_baseline_captures(
        dir.path(),
        &[(
            first_pass[0].inputs.clone(),
            &["BitBlt", "Sleep", "CreateFileA", "GetLastError", "BitBlt"],
        )],
    );

    let tests = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("test inputs generate");
    assert_eq!(
        tests[0].expected_api_calls,
        vec!["blit", "open", "blit"],
        "the captured trace folds onto the matching case spelled onto the verify PAL surface, in recorded order, out-of-roster and unspellable names dropped"
    );
    for test in &tests[1..] {
        assert!(
            test.expected_api_calls.is_empty(),
            "a case the baseline document has no capture for stays trace-unassessed"
        );
    }
}

/// #386's honest-degradation half: the fold needs both artifacts. A saved
/// baseline with no apidetect roster (the scan never ran) files no
/// expectations, and a roster with no saved baseline folds nothing — the
/// same shape the global-state expectations take (#276).
#[tokio::test]
async fn the_trace_fold_degrades_to_unassessed_without_one_of_its_documents() {
    let function_info = roster_fixture_function();

    // A captured trace with no roster: the baseline document exists,
    // apidetect never ran.
    let dir = TempDir::new().unwrap();
    let pipeline = pipeline_over(Some(dir.path()));
    let first_pass = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("test inputs generate");
    assert!(!first_pass.is_empty());
    file_baseline_captures(
        dir.path(),
        &[(first_pass[0].inputs.clone(), &["BitBlt", "BitBlt"])],
    );
    let tests = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("test inputs generate");
    assert!(
        tests.iter().all(|t| t.expected_api_calls.is_empty()),
        "without the apidetect roster the captured trace is no expectation"
    );

    // A roster with no saved baseline: apidetect ran, the baseline was
    // never recorded.
    let dir = TempDir::new().unwrap();
    file_api_usages(dir.path(), &[("DrawPrimitive", "BitBlt", true)]);
    let pipeline = pipeline_over(Some(dir.path()));
    let tests = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("test inputs generate");
    assert!(
        tests.iter().all(|t| t.expected_api_calls.is_empty()),
        "without a saved capture there is no trace to fold"
    );
}

/// A corrupt apidetect document leaves the trace dimension unassessed
/// rather than failing the unit — the degradation the global-state fold
/// already takes (#276).
#[tokio::test]
async fn a_corrupt_apidetect_document_leaves_the_trace_dimension_unassessed() {
    let dir = TempDir::new().unwrap();
    let doc_dir = dir.path().join("re").join("analysis").join("apidetect");
    std::fs::create_dir_all(&doc_dir).expect("apidetect dir");
    std::fs::write(doc_dir.join("game_logic.dll.json"), "not json at all")
        .expect("corrupt document filed");

    let pipeline = pipeline_over(Some(dir.path()));
    let function_info = roster_fixture_function();
    let first_pass = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("test inputs generate");
    file_baseline_captures(dir.path(), &[(first_pass[0].inputs.clone(), &["BitBlt"])]);

    let tests = pipeline
        .generate_baseline_tests(&function_info, &[], &[])
        .await
        .expect("a corrupt apidetect document must not sink suite generation");
    assert!(
        tests.iter().all(|t| t.expected_api_calls.is_empty()),
        "a corrupt roster leaves the trace dimension unassessed"
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

/// The headline test for issue #261: the control-flow document the
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

// ─── Per-function analysis artifact (issue #379) ─────────────────

/// `translate` files the unit's tagged Windows APIs as the per-function
/// analysis artifact — `re/analysis/{binary}/{function}.json`, the
/// document the web review UI's Windows API mappings panel reads — and
/// the tagging is body-scoped. The fixture binary's `fixture_tick`
/// body names `puts` and `GetTickCount`; `OutputDebugStringA` is an
/// import of the same binary that this body never names. With both
/// `GetTickCount` and `OutputDebugStringA` in the run's mapping table,
/// the artifact must carry exactly the API the body references: the
/// mapped-but-unnamed import stays out.
#[tokio::test]
async fn translate_files_the_body_scoped_analysis_artifact() {
    let dir = TempDir::new().expect("temp workspace");
    let mappings = calxgloss_pal::ApiMappings::from_custom(vec![
        calxgloss_pal::ApiMapping::new(
            "GetTickCount",
            calxgloss_types::ApiCategory::Win32Core,
            "std::time::Instant",
            "test-only mapping",
        ),
        calxgloss_pal::ApiMapping::new(
            "OutputDebugStringA",
            calxgloss_types::ApiCategory::Win32Gui,
            "log::info!",
            "test-only mapping",
        ),
    ]);
    // The LLM URL points at a closed port: the run fails at the LLM
    // call, but the artifact is filed at step 2, before any prompt is
    // built, so it is on disk either way.
    let llm = LlmClient::from_url("http://127.0.0.1:1/v1", "qwen3").expect("llm config");
    let pipeline = TranslationPipeline::new(fixture_kuna(), llm, mappings)
        .with_workspace(dir.path().to_path_buf());

    let _ = pipeline
        .translate(calxgloss_testfixtures::TARGET_FILE_NAME, "fixture_tick")
        .await;

    let artifact = calxgloss_types::analysis_dir(dir.path())
        .join(calxgloss_testfixtures::TARGET_FILE_NAME)
        .join("fixture_tick.json");
    let document: serde_json::Value =
        calxgloss_types::load_json(&artifact).expect("the artifact is filed");

    // The shape the web reader deserializes: a `windows_apis` array
    // whose entries carry name, category, and pal_mapping.
    let apis = document["windows_apis"]
        .as_array()
        .expect("the artifact carries a windows_apis array");
    assert_eq!(
        apis.iter()
            .map(|api| api["name"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("GetTickCount")],
        "the artifact names exactly the APIs the function's body references"
    );
    assert_eq!(
        apis[0]["category"], "Win32Core",
        "the category round-trips as its plain name, the way the web reader reads it"
    );
    assert_eq!(
        apis[0]["pal_mapping"], "std::time::Instant",
        "the mapping table's PAL target rides through with no conversion"
    );
}

/// A failed artifact write must not stop the translation: the artifact
/// is panel context, never pipeline input. Making `re` a plain file in
/// the workspace leaves the artifact's parent directory chain
/// unconstructable; `translate` must still run to the LLM call like any
/// other offline run, and the write failure must not surface as the
/// run's error.
#[tokio::test]
async fn a_failed_analysis_artifact_write_does_not_stop_translation() {
    let dir = TempDir::new().expect("temp workspace");
    std::fs::write(dir.path().join("re"), "not a directory").expect("blocking file for `re`");

    let llm = LlmClient::from_url("http://127.0.0.1:1/v1", "qwen3").expect("llm config");
    let pipeline = TranslationPipeline::new(fixture_kuna(), llm, ApiMappings::default())
        .with_workspace(dir.path().to_path_buf());

    let error = pipeline
        .translate(calxgloss_testfixtures::TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect_err("the run still reaches the closed-port LLM");
    assert!(
        matches!(error, TranslatorError::Llm(_)),
        "the failure should be the unreachable LLM, not the artifact write: {error}"
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
    // Keep the spawned waiter waiting on the unset latch before publishing.
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

    // The latch the phase arms for the declared edge, attached to the
    // two rows exactly the way `registered_scan_tasks` attaches it: the
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
/// unpublished latch is still waiting well past the time the same
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

// The four control-flow seam tests (cached hit, cache miss, failed save,
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

/// The headline test: a first batch reads live and writes the scan cache
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

// ============================================================
// The batch's unknown ledger from coverage residue (issue #369)
// ============================================================

/// The ticket's demoable run: the fixture is scanned once, and the
/// filed string-context document is then re-stamped so two of its
/// declared facets admit falling short. A one-unit batch at the
/// forced ModuleContext tier reads that document through the fold
/// and files `re/unknowns/<binary>.json`: one record per admitting
/// facet, kind, severity, wording, origin and function all derived
/// from the admission on disk. The complete facet and the unexamined
/// gap stay silent; a re-run lands the same ids at the same
/// revisions; re-wording the admission bumps exactly that record; and
/// the reviewer's resolutions document is never touched.
#[tokio::test]
async fn a_batch_files_the_coverage_residue_of_the_documents_it_reads() {
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _binary_file) = cached_pipeline(dir.path());
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

    // Scan the fixture once, cold: every seam document is filed with
    // its engine's own coverage stamp.
    pipeline.begin_cached_source(PROGRAM).await;
    pipeline.run_prebatch_scans(PROGRAM).await;
    let stringctx = StringContextPersistor::new(dir.path()).path_for(PROGRAM);
    assert!(
        stringctx.is_file(),
        "the string-context scan files its document over the fixture"
    );

    // The admission, written onto the filed document itself: one body
    // facet partial with its reason spelled, one xref facet that never
    // arrived, and the strings facet left complete.
    let mut doc: calxgloss_stringctx::types::StringContextResult =
        calxgloss_types::load_json(&stringctx).expect("the filed string-context document");
    doc.metadata.coverage = Some(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("the bodies past the size cap were not read".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "program-strings".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
            calxgloss_types::FacetCoverage {
                id: "string-xrefs".to_string(),
                status: calxgloss_types::CoverageStatus::Unavailable,
                limitation: None,
            },
        ],
    });
    calxgloss_types::save_json(&stringctx, &doc).expect("the admission is written back");

    // Kuna lists MinGW exports with the leading underscore; the unit
    // name is the one the queue itself would use.
    let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
        .await
        .expect("fixture function listing");
    let unit = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_status")
        .expect("the fixture lists fixture_status")
        .name
        .clone();

    // A reviewer's settle for the record this batch is about to file,
    // pre-filed so the byte-unchanged rule has something to hold.
    let bodies_id =
        format!("{PROGRAM}/{unit}/coverage_facet/string context result#function-bodies");
    let resolutions_path = calxgloss_types::unknown_resolutions_path(dir.path());
    std::fs::create_dir_all(resolutions_path.parent().expect("re/review")).expect("review dir");
    calxgloss_types::save_json(
        &resolutions_path,
        &calxgloss_types::UnknownResolutions {
            resolutions: [(
                bodies_id.clone(),
                calxgloss_types::UnknownResolution {
                    disposition: calxgloss_types::UnknownDisposition::Dismissed,
                    reason: "the cap is a scanner limit, not a question".to_string(),
                    expected_revision: 1,
                    at: 1_700_000_000,
                },
            )]
            .into_iter()
            .collect(),
            reopened: Default::default(),
        },
    )
    .expect("the reviewer's settle is filed");
    let resolutions_before = std::fs::read(&resolutions_path).expect("filed reviewer bytes");

    // Force the unit's tier: only the tiers that read the evidence
    // documents run the fold, and forcing pins that this one does.
    let overrides = calxgloss_types::OverrideControl::new();
    overrides
        .set(
            PROGRAM,
            &unit,
            calxgloss_types::FunctionOverride {
                tier_override: Some(calxgloss_types::ContextTier::ModuleContext),
                ..Default::default()
            },
        )
        .expect("in-memory tier override");
    let pipeline = pipeline.with_overrides(overrides);

    // The unit's own translation outcome does not matter to the
    // ledger: the fold runs while its prompt is built, and the unit's
    // end flushes what the batch has admitted either way.
    pipeline
        .batch_translate(
            PROGRAM,
            std::slice::from_ref(&unit),
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("a batch over one fixture function");

    let ledger_path = calxgloss_types::unknown_ledger_path(
        dir.path(),
        &calxgloss_types::BinaryIdentity::new(PROGRAM),
    );
    let ledger: calxgloss_types::UnknownLedger = calxgloss_types::load_json(&ledger_path)
        .expect("the batch files its unknown ledger beside the scans");
    assert_eq!(
        ledger.binary,
        calxgloss_types::BinaryIdentity::new(PROGRAM),
        "the ledger envelope names the binary it was filed for"
    );
    let records = ledger
        .records
        .expect("a batch whose fold read documents files a current set, never an absent key");
    let admitted: Vec<&calxgloss_types::UnknownRecord> = records
        .iter()
        .filter(|r| {
            matches!(&r.origin, calxgloss_types::UnknownOrigin::Document { document, .. }
                    if document.as_str() == "string context result")
        })
        .collect();
    assert_eq!(
        admitted
            .iter()
            .map(|r| r.source_slot())
            .collect::<Vec<String>>(),
        vec![
            "string context result#function-bodies",
            "string context result#string-xrefs",
        ],
        "the two admitting facets file in the document's own facet order; \
             the complete facet asks nothing"
    );
    let bodies = admitted[0];
    assert_eq!(bodies.id, bodies_id, "the derivation is the shared one");
    assert_eq!(bodies.kind, calxgloss_types::UnknownKind::CoverageFacet);
    assert_eq!(bodies.function.as_deref(), Some(unit.as_str()));
    assert_eq!(
        bodies.severity,
        calxgloss_types::UnknownSeverity::Material,
        "partial by its own admission"
    );
    assert_eq!(
        bodies.question,
        format!(
            "What is `{unit}` really doing — string context result admitted \
                 `the bodies past the size cap were not read` on `function-bodies`?"
        ),
        "the question is built on the facet's own limitation line"
    );
    assert_eq!(
        bodies.required_evidence,
        "Full `function-bodies` coverage from the string context result"
    );
    assert_eq!(bodies.revision, 1, "a first landing starts at revision 1");
    let first_seen = bodies.first_seen;
    assert_eq!(
        admitted[1].severity,
        calxgloss_types::UnknownSeverity::Blocking,
        "unavailable: the evidence never arrived at all"
    );
    assert_eq!(
        admitted[1].question,
        format!(
            "What is `{unit}` really doing — string context result admitted \
                 `unavailable` on `string-xrefs`?"
        ),
        "an entry that gave no reason falls back to its bare status word"
    );

    // A second batch over the same documents: same ids, same order,
    // same revisions — a re-run never re-numbers a diff.
    pipeline
        .batch_translate(
            PROGRAM,
            std::slice::from_ref(&unit),
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("the ledger re-run");
    let refiled: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the re-filed ledger");
    let again = refiled
        .records
        .expect("a current set every re-file")
        .into_iter()
        .map(|r| (r.id, r.revision, r.first_seen))
        .collect::<Vec<_>>();
    let landed = records
        .into_iter()
        .map(|r| (r.id, r.revision, r.first_seen))
        .collect::<Vec<_>>();
    assert_eq!(
        again, landed,
        "re-runs land the same ids at the same revisions and first-seens"
    );

    // Re-wording the admission on disk is a real change: exactly that
    // record bumps, and only above the landed revision.
    let mut doc: calxgloss_stringctx::types::StringContextResult =
        calxgloss_types::load_json(&stringctx).expect("the filed string-context document");
    doc.metadata
        .coverage
        .as_mut()
        .expect("the stamped coverage")
        .facets[0]
        .limitation = Some("the size cap stopped half the bodies short".to_string());
    calxgloss_types::save_json(&stringctx, &doc).expect("the re-worded admission is filed");
    pipeline
        .batch_translate(
            PROGRAM,
            std::slice::from_ref(&unit),
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("the batch after the re-worded admission");
    let bumped: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the ledger after the bump");
    let bumped = bumped.records.expect("a current set");
    let bodies = bumped
        .iter()
        .find(|r| r.id == bodies_id)
        .expect("the same record, one revision up");
    assert_eq!(
        bodies.revision, 2,
        "a persisted field changed — exactly one bump"
    );
    assert_eq!(
        bodies.first_seen, first_seen,
        "the bump keeps the original first-seen"
    );
    assert!(
        bodies
            .question
            .contains("the size cap stopped half the bodies short"),
        "the landed question carries the re-worded admission"
    );

    // The reviewer's own document stands untouched through every one
    // of these writes.
    assert_eq!(
        std::fs::read(&resolutions_path).expect("the reviewer document after the writes"),
        resolutions_before,
        "the ledger write never touches the reviewer's resolutions document"
    );
}

// ============================================================
// The batch's unknown ledger from seam residue (issue #371)
// ============================================================

/// The ticket's demoable run: the batch's held capability report is
/// re-stamped to degrade the `decompilation` family with its reason
/// spelled, to declare `strings` answerable and `xrefs` unavailable,
/// and to declare `function-inventory` not at all. One fixture unit
/// enters the retry wrapper twice under two postures — a second pass
/// whose ladder never escalates asks the seam nothing, so it files
/// nothing; a pass at the default posture walks onto the escalate
/// rungs, and every family its re-asked roster meets an `unavailable`
/// declaration files one record: kind, severity, wording, origin,
/// slot and id all derived from the admission. The answerable family,
/// the undeclared family the posture also re-asks, and the admitted
/// family the posture never re-asks all stay silent; a re-run lands
/// the same id at the same revision.
#[tokio::test]
async fn a_unit_filing_the_seams_unavailable_families_lands_one_record_per_re_asked_gap() {
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _binary_file) = cached_pipeline(dir.path());
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

    // Open the cached source, then re-stamp the declaration it holds.
    // Kuna admits nothing itself, so the degraded report is written
    // onto the batch's held copy — the same document the escalate
    // rung reads, only hand-degraded the way a failing engine would
    // (the #355 fake-for-a-degraded-engine precedent).
    pipeline.begin_cached_source(PROGRAM).await;
    let degraded = calxgloss_types::CapabilityReport {
        families: vec![
            calxgloss_types::FamilyCapability {
                id: "decompilation".to_string(),
                status: calxgloss_types::AvailabilityStatus::Unavailable,
                reason: Some("the engine never produced a body".to_string()),
            },
            calxgloss_types::FamilyCapability {
                id: "strings".to_string(),
                status: calxgloss_types::AvailabilityStatus::Answerable,
                reason: None,
            },
            calxgloss_types::FamilyCapability {
                id: "xrefs".to_string(),
                status: calxgloss_types::AvailabilityStatus::Unavailable,
                reason: None,
            },
            // `function-inventory` is deliberately undeclared: the
            // posture re-asks it, the report never says anything
            // about it, and absence files nothing.
        ],
    };
    *pipeline
        .seam_report
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = degraded.clone();

    // Kuna lists MinGW exports with the leading underscore; the unit
    // name is the one the queue itself would use.
    let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
        .await
        .expect("fixture function listing");
    let unit = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_status")
        .expect("the fixture lists fixture_status")
        .name
        .clone();

    // A ladder that never escalates repeats its fix strategy and
    // never steps tier: it asks the seam nothing beyond the first
    // attempt, so the held admission bears on no retry it would make.
    let flat = retry::RetryConfig {
        max_attempts: 3,
        retry_strategy: retry::RetryStrategy::CompileFix,
        escalate_on_failure: false,
        max_context_tier: None,
    };
    let _ = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &flat, &verifier)
        .await;
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the filing call");
    let ledger_path = calxgloss_types::unknown_ledger_path(
        dir.path(),
        &calxgloss_types::BinaryIdentity::new(PROGRAM),
    );
    assert!(
        !ledger_path.exists(),
        "a unit whose posture never re-asks files no seam record — and a \
             seam residue admitted by nobody opens no ledger at all"
    );

    // The same unit at the default posture: its ladder walks onto the
    // escalate rungs, whose re-asked roster meets the report's
    // `decompilation` admission. The unit's own translation outcome —
    // offline here, so the attempts fail — never bears on the filing:
    // it is the posture, taken at the unit's entry, that asked.
    let _ = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &retry::RetryConfig::default(), &verifier)
        .await;
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("a re-asking posture opened the accumulator");
    let ledger: calxgloss_types::UnknownLedger = calxgloss_types::load_json(&ledger_path)
        .expect("the re-asking posture files its unknown ledger");
    assert_eq!(
        ledger.binary,
        calxgloss_types::BinaryIdentity::new(PROGRAM),
        "the ledger envelope names the binary it was filed for"
    );
    let records = ledger
        .records
        .expect("a posture that re-asked files a current set, never an absent key");
    let family_id = format!("{PROGRAM}/{unit}/analysis_family/decompilation");
    let seams: Vec<&calxgloss_types::UnknownRecord> = records
        .iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::AnalysisFamily)
        .collect();
    assert_eq!(
        seams
            .iter()
            .map(|r| r.source_slot())
            .collect::<Vec<String>>(),
        vec!["decompilation"],
        "one record for the one re-asked family the report admits — the \
             answerable `strings` family asks nothing, the undeclared \
             `function-inventory` reads unknown and files nothing, and the \
             admitted `xrefs` family stands outside this posture's roster"
    );
    assert_eq!(
        records.len(),
        1,
        "the fixture's complete scans admit no facet residue either — \
             the seam record is the ledger's only entry"
    );

    // The record's shape, derived from the admission itself.
    let seam = seams[0];
    assert_eq!(seam.id, family_id, "the derivation is the shared one");
    assert_eq!(
        seam.severity,
        calxgloss_types::UnknownSeverity::Blocking,
        "the seam says the answer cannot arrive at all — the Blocking level's own criterion"
    );
    assert_eq!(seam.function.as_deref(), Some(unit.as_str()));
    assert_eq!(
        seam.origin,
        calxgloss_types::UnknownOrigin::Family {
            family: "decompilation".to_string(),
        },
        "the origin names the seam family that could not answer"
    );
    assert_eq!(
        seam.question,
        format!(
            "What is `{unit}` really doing — analysis engine admitted \
                 `unavailable — the engine never produced a body` for the \
                 `decompilation` family?"
        ),
        "the question is built on the entry's own admission line"
    );
    assert_eq!(
        seam.required_evidence, "Full `decompilation` answers from the analysis engine",
        "the required evidence names the family that could not answer"
    );
    assert_eq!(seam.revision, 1, "a first landing starts at revision 1");

    // The flat posture re-walks after the record landed and still
    // contributes nothing of its own; the default posture re-walks
    // once more, and the re-derivation lands the same id at the same
    // revision — a re-run never re-numbers a diff.
    let _ = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &flat, &verifier)
        .await;
    let _ = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &retry::RetryConfig::default(), &verifier)
        .await;
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the ledger re-file");
    let refiled: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the re-filed ledger");
    let again = refiled
        .records
        .expect("a current set every re-file")
        .into_iter()
        .map(|r| (r.id, r.revision, r.first_seen))
        .collect::<Vec<_>>();
    let landed = records
        .into_iter()
        .map(|r| (r.id, r.revision, r.first_seen))
        .collect::<Vec<_>>();
    assert_eq!(
        again, landed,
        "re-runs land the same ids at the same revisions and first-seens"
    );
}

/// A canned LLM that always answers with broken code — alternating
/// two spellings so the loop detector never streaks a repeated
/// (prompt, output) pair to a fire. Every attempt verification-fails,
/// so a pipeline-driven ladder really walks its strategy cycle and
/// its tier climb (the #356 harness pattern, retargeted at the real
/// wrapper). Returns the base URL to point a client at.
async fn broken_alternating_llm() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("canned LLM should bind");
    let addr = listener.local_addr().expect("canned LLM address");
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls_server = calls;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let n = calls_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let content = if n % 2 == 0 {
                    "fn draw_sprite(x: i32) -> i32 { let y: = ; x }"
                } else {
                    "fn draw_sprite(x: i32) -> i32 { let z: = ; x }"
                };
                let body = format!(
                    "{{\"choices\":[{{\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}}}}],\"usage\":{{\"completion_tokens\":123,\"total_tokens\":123}}}}"
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// The ticket's demoable run (issue #372): a canned-report run whose
/// report makes the escalate re-ask `unavailable`, driving a whole
/// pipeline ladder. The walk prunes its escalate rung and holds its
/// module-tier step exactly as #356 pinned — the attempt walk, the
/// tier steps, and the prune hints stay byte-unchanged — while each
/// pruned decision files its own record in the same binary's ledger
/// as every other record, with the retry decision as origin and the
/// shared derived id. A second, differently capped run re-derives the
/// same standing questions at the same revisions and first-seens:
/// the ladder keeps owning which prompt runs, and nothing here feeds
/// unknowns back into strategy.
#[tokio::test]
async fn a_pruned_ladder_walk_files_its_residue_in_the_binaries_ledger() {
    let dir = TempDir::new().expect("temp workspace");
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

    // The pipeline the batch would run, pointed at the canned LLM.
    let llm = LlmClient::from_url(&broken_alternating_llm().await, "qwen3").expect("llm config");
    let fixture = calxgloss_testfixtures::load_target().expect("fixture target");
    let binary_file = dir.path().join(calxgloss_testfixtures::TARGET_FILE_NAME);
    std::fs::copy(fixture.path(), &binary_file).expect("fixture copied into the workspace");
    let pipeline = TranslationPipeline::new(fixture_kuna(), llm, ApiMappings::default())
        .with_workspace(dir.path().to_path_buf())
        .with_binary_path(&binary_file);

    // The held report, hand-degraded onto the batch's copy exactly as
    // the #371 filing test stamps it: `decompilation` unavailable with
    // its own reason, every other family answerable-or-undeclared.
    pipeline.begin_cached_source(PROGRAM).await;
    let degraded = calxgloss_types::CapabilityReport {
        families: vec![calxgloss_types::FamilyCapability {
            id: "decompilation".to_string(),
            status: calxgloss_types::AvailabilityStatus::Unavailable,
            reason: Some("the engine never produced a body".to_string()),
        }],
    };
    *pipeline
        .seam_report
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = degraded;

    let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
        .await
        .expect("fixture function listing");
    let unit = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_status")
        .expect("the fixture lists fixture_status")
        .name
        .clone();

    // Run one: the cap pins the tier at Signature, so the walk takes
    // the tier gate never and prunes exactly one escalate rung.
    let capped = retry::RetryConfig {
        max_attempts: 6,
        retry_strategy: retry::RetryStrategy::CompileFix,
        escalate_on_failure: true,
        max_context_tier: Some(calxgloss_types::ContextTier::Signature),
    };
    let result = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &capped, &verifier)
        .await
        .expect("the canned LLM answers every attempt");
    assert_eq!(
        result.attempts[1]
            .context_tier
            .as_deref()
            .expect("the attempt records its tier"),
        "signature",
        "the fixture unit's ladder starts at the signature tier — the walk \
             shapes below are pinned against that"
    );
    assert_eq!(
        result
            .attempts
            .iter()
            .map(|a| a.retry_strategy.as_str())
            .collect::<Vec<_>>(),
        vec![
            "initial",
            "compile_fix",
            "test_fix",
            "pruned_escalate",
            "edge_case_fix",
            "compile_fix"
        ],
        "the walk is exactly the #356 prune walk — the residue records change no rung"
    );
    assert_eq!(
        result.attempts[3].compilation_errors,
        vec![
            "Pruned: escalate would re-ask decompilation — unavailable — the engine never produced a body"
        ],
        "the existing prune hint stays byte-unchanged"
    );
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the filing call");
    let ledger_path = calxgloss_types::unknown_ledger_path(
        dir.path(),
        &calxgloss_types::BinaryIdentity::new(PROGRAM),
    );
    let ledger: calxgloss_types::UnknownLedger = calxgloss_types::load_json(&ledger_path)
        .expect("a pruned walk files its unknown ledger beside every other record");
    let records = ledger
        .records
        .expect("a pruned walk files a current set, never an absent key");

    // The pruned rung's record, in the same ledger as the seam's own
    // posture record (#371), naming family, reason, and decision.
    let pruned = records
        .iter()
        .find(|r| r.kind == calxgloss_types::UnknownKind::RetryPruned)
        .expect("the pruned escalate rung filed its own record");
    assert_eq!(
        pruned.id,
        format!("{PROGRAM}/{unit}/retry_pruned/decompilation"),
        "the shared derivation, the ladder-residue kind, the family as slot"
    );
    assert_eq!(
        pruned.origin,
        calxgloss_types::UnknownOrigin::RetryDecision {
            decision: "decompilation".to_string(),
        },
        "the retry decision is the origin"
    );
    assert_eq!(pruned.function.as_deref(), Some(unit.as_str()));
    assert_eq!(pruned.severity, calxgloss_types::UnknownSeverity::Blocking);
    assert!(
        pruned.question.contains("the engine never produced a body"),
        "the record names the unavailable reason beside the family: {}",
        pruned.question
    );
    let landed: Vec<(String, u32, u64)> = records
        .iter()
        .map(|r| (r.id.clone(), r.revision, r.first_seen))
        .collect();

    // Run two: the uncapped nine-attempt climb — the #356 hold walk,
    // byte-identical walk and tier holds — whose second escalate
    // prune and second tier hold re-admit standing questions the
    // first prune and first hold already filed.
    let climbing = retry::RetryConfig {
        max_attempts: 9,
        ..retry::RetryConfig::default()
    };
    let result = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &climbing, &verifier)
        .await
        .expect("the canned LLM answers every attempt");
    assert_eq!(
        result
            .attempts
            .iter()
            .map(|a| a.retry_strategy.as_str())
            .collect::<Vec<_>>(),
        vec![
            "initial",
            "compile_fix",
            "escalated(disassembly)",
            "pruned_escalate",
            "edge_case_fix",
            "escalated(with_tests)",
            "test_fix",
            "pruned_escalate",
            "edge_case_fix"
        ],
        "the climb is exactly the #356 hold walk — records change no rung and no tier step"
    );
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the second filing call");
    let refiled: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the re-filed ledger");
    let records = refiled.records.expect("a current set every re-file");

    // The refused step's matching record: one for the step, naming
    // the held tier and the family's admission.
    let refused: Vec<&calxgloss_types::UnknownRecord> = records
        .iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::TierRefused)
        .collect();
    assert_eq!(
        refused.len(),
        1,
        "two tier holds land one standing question at one id"
    );
    assert_eq!(
        refused[0].id,
        format!("{PROGRAM}/{unit}/tier_refused/module_context"),
        "the refused step names the tier the ladder refused to step onto"
    );
    assert_eq!(
        refused[0].origin,
        calxgloss_types::UnknownOrigin::RetryDecision {
            decision: "module_context".to_string(),
        }
    );
    assert!(
        refused[0]
            .question
            .contains("decompilation — unavailable — the engine never produced a body"),
        "the refused step's record names the family and its reason: {}",
        refused[0].question
    );

    // The re-run re-derives, never re-numbers: every record run one
    // landed keeps its id, revision, and first-seen; the only new
    // entry is the refused step's own question. And the walk filed
    // ladder, seam, and verification records — the fixture's
    // complete scans still admit no facet residue, while the canned
    // code never compiled, so the unit reached review having run
    // zero baseline cases (#373) and files that standing question
    // too, re-derived whole in run two.
    let again: Vec<(String, u32, u64)> = records
        .iter()
        .map(|r| (r.id.clone(), r.revision, r.first_seen))
        .collect();
    let new_ids: Vec<&String> = again
        .iter()
        .filter(|entry| !landed.contains(entry))
        .map(|(id, _, _)| id)
        .collect();
    assert_eq!(
        new_ids,
        vec![&format!("{PROGRAM}/{unit}/tier_refused/module_context")],
        "a re-run adds only the refused step's own question, at revision 1"
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == calxgloss_types::UnknownKind::RetryPruned)
            .count(),
        1,
        "two escalate prunes, one standing question"
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == calxgloss_types::UnknownKind::AnalysisFamily)
            .count(),
        1,
        "the seam's posture record (#371) rides the same ledger, untouched"
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.kind == calxgloss_types::UnknownKind::BaselineNeverRun)
            .count(),
        1,
        "the canned code never compiled, so no case ever ran: the unit's zero-case \
             question (#373) rides the same ledger, one standing question at one id"
    );
}

/// The ticket's demoable run for the zero-cases fact (issue #373): the
/// canned LLM's broken code never compiles, so the fixture unit's walk
/// never runs a baseline case — and the unit files a `baseline_never_run`
/// record against itself, origin its own verification case set, at the
/// Blocking level the shared severity docs name for exactly this fact.
/// A second walk re-derives the same standing question whole: same id,
/// same revision, same first-seen.
#[tokio::test]
async fn a_unit_that_never_ran_a_baseline_case_files_its_zero_case_record() {
    let dir = TempDir::new().expect("temp workspace");
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");
    let llm = LlmClient::from_url(&broken_alternating_llm().await, "qwen3").expect("llm config");
    let fixture = calxgloss_testfixtures::load_target().expect("fixture target");
    let binary_file = dir.path().join(calxgloss_testfixtures::TARGET_FILE_NAME);
    std::fs::copy(fixture.path(), &binary_file).expect("fixture copied into the workspace");
    let pipeline = TranslationPipeline::new(fixture_kuna(), llm, ApiMappings::default())
        .with_workspace(dir.path().to_path_buf())
        .with_binary_path(&binary_file);

    // Kuna lists MinGW exports with the leading underscore; the unit
    // name is the one the queue itself would use.
    let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
        .await
        .expect("fixture function listing");
    let unit = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_status")
        .expect("the fixture lists fixture_status")
        .name
        .clone();

    let capped = retry::RetryConfig {
        max_attempts: 6,
        retry_strategy: retry::RetryStrategy::CompileFix,
        escalate_on_failure: true,
        max_context_tier: Some(calxgloss_types::ContextTier::Signature),
    };
    let result = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &capped, &verifier)
        .await
        .expect("the canned LLM answers every attempt");
    assert!(
        result
            .attempts
            .iter()
            .all(|attempt| attempt.tests_total == 0),
        "nothing ever compiled, so nothing ever verified: zero baseline cases ran"
    );
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the filing call");
    let ledger_path = calxgloss_types::unknown_ledger_path(
        dir.path(),
        &calxgloss_types::BinaryIdentity::new(PROGRAM),
    );
    let ledger: calxgloss_types::UnknownLedger = calxgloss_types::load_json(&ledger_path)
        .expect("a zero-case walk files its unknown ledger like every other residue");
    let records = ledger
        .records
        .expect("a walk whose case set never ran files a current set, never an absent key");
    let zero: Vec<&calxgloss_types::UnknownRecord> = records
        .iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::BaselineNeverRun)
        .collect();
    assert_eq!(zero.len(), 1, "one unit, one zero-case standing question");
    let zero = zero[0];
    assert_eq!(
        zero.id,
        format!("{PROGRAM}/{unit}/baseline_never_run/cases-{unit}"),
        "the shared derivation, the unit as subject, the unit's own case set as slot"
    );
    assert_eq!(
        zero.origin,
        calxgloss_types::UnknownOrigin::CaseSet {
            case_set: format!("cases-{unit}"),
        },
        "the verification case set is the origin"
    );
    assert_eq!(
        zero.severity,
        calxgloss_types::UnknownSeverity::Blocking,
        "zero baseline cases ever run is the Blocking level's own written criterion"
    );
    assert_eq!(zero.function.as_deref(), Some(unit.as_str()));
    assert!(
        zero.question.contains("zero baseline cases"),
        "the question states the admitted fact: {}",
        zero.question
    );
    assert!(
        zero.required_evidence.contains(&unit),
        "the required evidence names the input vector that would have exercised the unit: {}",
        zero.required_evidence
    );
    assert_eq!(zero.revision, 1);

    // Run two: the same unit walks again, again without a single case
    // — the same standing question, re-derived whole, never a second
    // opinion and never a re-numbered diff.
    let first_seen = zero.first_seen;
    let _ = pipeline
        .try_translate_with_retry(PROGRAM, &unit, &capped, &verifier)
        .await
        .expect("the canned LLM answers every attempt");
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the second filing call");
    let refiled: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the re-filed ledger");
    let again = refiled
        .records
        .expect("a current set every re-file")
        .into_iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::BaselineNeverRun)
        .collect::<Vec<_>>();
    assert_eq!(again.len(), 1, "the re-walk re-derives, never duplicates");
    assert_eq!(again[0].id, zero.id, "the same id every re-derivation");
    assert_eq!(
        again[0].revision, 1,
        "the unchanged record keeps its revision"
    );
    assert_eq!(again[0].first_seen, first_seen, "and its first-seen");
}

/// The ticket's demoable run for the uncovered-exports fact (issue #373):
/// a batch over the fixture with no baseline document filed anywhere
/// files one `export_uncovered` record per export in the binary's
/// ledger — no function slot, the export named in the source slot. A
/// re-run lands the same ids at the same revisions, and filing a real
/// baseline document for one export makes exactly that export's record
/// stop landing: "translated" and "proven" never read the same again,
/// and a covered export asks nothing.
#[tokio::test]
async fn a_batch_files_a_record_for_every_export_no_baseline_document_covered() {
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _binary_file) = cached_pipeline(dir.path());
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

    let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
        .await
        .expect("fixture function listing");
    let unit = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_status")
        .expect("the fixture lists fixture_status")
        .name
        .clone();

    // The export listing the check itself reads — the fixture's four
    // named exports — so the pinned slots are the listing's own names.
    let exports = calxgloss_decomp::ScanSource::exports(&fixture_kuna())
        .await
        .expect("fixture export listing");
    assert!(!exports.is_empty(), "the fixture serves its named exports");

    pipeline
        .batch_translate(
            PROGRAM,
            std::slice::from_ref(&unit),
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("a batch over one fixture function");
    let ledger_path = calxgloss_types::unknown_ledger_path(
        dir.path(),
        &calxgloss_types::BinaryIdentity::new(PROGRAM),
    );
    let ledger: calxgloss_types::UnknownLedger = calxgloss_types::load_json(&ledger_path)
        .expect("a batch files its unknown ledger beside the scans");
    let records = ledger
        .records
        .expect("a current derived set, never an absent key");
    let uncovered: Vec<&calxgloss_types::UnknownRecord> = records
        .iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::ExportUncovered)
        .collect();
    assert_eq!(
        uncovered
            .iter()
            .map(|r| r.source_slot())
            .collect::<Vec<String>>(),
        exports
            .iter()
            .filter(|export| !export.name.is_empty())
            .map(|export| format!("export-{}", export.name))
            .collect::<Vec<String>>(),
        "one record per export, in the listing's own order — no baseline document \
             was filed for any of them"
    );
    for record in &uncovered {
        assert_eq!(
            record.function, None,
            "the export is the subject the slot names, not a function"
        );
        assert_eq!(
            record.severity,
            calxgloss_types::UnknownSeverity::Blocking,
            "no filed baseline document for an export is the Blocking criterion's \
                 own written wording"
        );
        assert_eq!(
            record.id,
            format!("{PROGRAM}/-/export_uncovered/{}", record.source_slot()),
            "the #368 derivation: no function slot, the export named in the slot"
        );
        assert!(
            matches!(&record.origin,
                    calxgloss_types::UnknownOrigin::CaseSet { case_set }
                        if case_set == &record.source_slot()),
            "the case set that never called the export is the origin"
        );
    }
    let landed: Vec<(String, u32, u64)> = uncovered
        .iter()
        .map(|r| (r.id.clone(), r.revision, r.first_seen))
        .collect();

    // Run two, still nothing filed: the same ids at the same revisions
    // and first-seens — a re-run never re-numbers a diff.
    pipeline
        .batch_translate(
            PROGRAM,
            std::slice::from_ref(&unit),
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("the ledger re-run");
    let refiled: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the re-filed ledger");
    let again: Vec<(String, u32, u64)> = refiled
        .records
        .expect("a current set every re-file")
        .iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::ExportUncovered)
        .map(|r| (r.id.clone(), r.revision, r.first_seen))
        .collect();
    assert_eq!(
        again, landed,
        "re-runs land the same ids at the same revisions and first-seens"
    );

    // Cover one export the way the testgen writer itself files a
    // baseline document, and re-batch: exactly that export's record
    // stops landing — the ledger stays the current derived set.
    let covered = exports
        .iter()
        .last()
        .expect("the fixture lists at least one export");
    calxgloss_testgen::TestGenerator::new(dir.path())
        .save_baseline(PROGRAM, &covered.name, &[])
        .expect("a baseline document filed through the real writer");
    pipeline
        .batch_translate(
            PROGRAM,
            std::slice::from_ref(&unit),
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("the batch after the baseline document is filed");
    let covered_now: calxgloss_types::UnknownLedger =
        calxgloss_types::load_json(&ledger_path).expect("the ledger after the covering");
    let slots: Vec<String> = covered_now
        .records
        .expect("a current set")
        .iter()
        .filter(|r| r.kind == calxgloss_types::UnknownKind::ExportUncovered)
        .map(|r| r.source_slot())
        .collect();
    assert_eq!(
        slots,
        exports
            .iter()
            .filter(|export| export.name != covered.name)
            .map(|export| format!("export-{}", export.name))
            .collect::<Vec<String>>(),
        "the covered export asks nothing; its record stops landing, the others stand"
    );
}

// ---- #375: the track sweep pinning the unknown-kind roster ------------
//
// ADR-0053's engine-stamps/roster-pins doctrine, one level up: one
// sweep over the real batch path pairs `DECLARED_UNKNOWN_KINDS`
// against what the four producers — the coverage fold, the seam
// residue, the verification signal, and the ladder — actually file,
// in one failure report naming every offender (the #352 and #359
// sweeps' pattern, aimed at kinds). A fifth producer (the future
// masked-byte search, P28) adds one kind string and one write site:
// forgetting either half fails here, at once.

/// The sweep's run: one real batch over the fixture target, staged
/// exactly as each producer's own filing test (#369, #371, #372, #373)
/// stages its fact, so every producer writes on the batch path —
///
/// * the filed string-context document admits one body facet fell
///   short, and the unit's tier is forced onto the fold that reads
///   it → one `coverage_facet` record (the complete facet asks nothing);
/// * the held seam report declares `decompilation` unavailable, so the
///   re-asking posture files `analysis_family`, and the nine-attempt
///   climb prunes its escalate rungs and holds its next module-tier
///   step → `retry_pruned` and `tier_refused`;
/// * the canned code never compiles, so the walk never ran a baseline
///   case → `baseline_never_run`, and no filed baseline document
///   covers any fixture export → one `export_uncovered` per export.
///
/// Offline throughout: Kuna loads in-process, the LLM side is the
/// canned broken-alternating server. Exactly one unit walks: the swept
/// pairing keys on (kind, source slot), and a second unit reading the
/// same admitted facet would fold to one pair produced twice — the
/// field must read clean to be honest. Returns the records the batch
/// really filed, read back off the ledger document it filed.
async fn unknown_sweep_batch_records(dir: &std::path::Path) -> Vec<calxgloss_types::UnknownRecord> {
    let verifier = calxgloss_verify::Verifier::new(dir).expect("verifier over temp dir");
    let llm = LlmClient::from_url(&broken_alternating_llm().await, "qwen3").expect("llm config");
    let fixture = calxgloss_testfixtures::load_target().expect("fixture target");
    let binary_file = dir.join(calxgloss_testfixtures::TARGET_FILE_NAME);
    std::fs::copy(fixture.path(), &binary_file).expect("fixture copied into the workspace");
    let pipeline = TranslationPipeline::new(fixture_kuna(), llm, ApiMappings::default())
        .with_workspace(dir.to_path_buf())
        .with_binary_path(&binary_file);

    // Kuna lists MinGW exports with the leading underscore; the unit
    // name is the one the queue itself would use.
    let listed = calxgloss_decomp::ScanSource::functions(&fixture_kuna())
        .await
        .expect("fixture function listing");
    let unit = listed
        .iter()
        .find(|f| f.name.trim_start_matches('_') == "fixture_status")
        .expect("the fixture lists fixture_status")
        .name
        .clone();

    // Force the unit's tier: only the tiers that read the evidence
    // documents run the fold, and forcing pins that this one does.
    let overrides = calxgloss_types::OverrideControl::new();
    overrides
        .set(
            PROGRAM,
            &unit,
            calxgloss_types::FunctionOverride {
                tier_override: Some(calxgloss_types::ContextTier::ModuleContext),
                ..Default::default()
            },
        )
        .expect("in-memory tier override");
    let pipeline = pipeline.with_overrides(overrides);

    // An empty batch queues nothing but opens the batch path: the cold
    // scans file every seam document with its engine's own coverage
    // stamp, and the batch's export check lands `export_uncovered`
    // against the binary's ledger before the queue even starts.
    pipeline
        .batch_translate(
            PROGRAM,
            &[],
            &retry::RetryConfig::default(),
            &verifier,
            None,
        )
        .await
        .expect("the batch that opens the path and runs the scans");

    // The coverage admission, written onto the filed document itself
    // exactly as #369 stamps it: one body facet partial with its
    // reason spelled, one facet left complete.
    let stringctx = StringContextPersistor::new(dir).path_for(PROGRAM);
    let mut doc: calxgloss_stringctx::types::StringContextResult =
        calxgloss_types::load_json(&stringctx).expect("the filed string-context document");
    doc.metadata.coverage = Some(calxgloss_types::ScanCoverage {
        status: calxgloss_types::CoverageStatus::Partial,
        facets: vec![
            calxgloss_types::FacetCoverage {
                id: "function-bodies".to_string(),
                status: calxgloss_types::CoverageStatus::Partial,
                limitation: Some("the bodies past the size cap were not read".to_string()),
            },
            calxgloss_types::FacetCoverage {
                id: "program-strings".to_string(),
                status: calxgloss_types::CoverageStatus::Complete,
                limitation: None,
            },
        ],
    });
    calxgloss_types::save_json(&stringctx, &doc).expect("the admission is written back");

    // The seam admission, on the batch's held copy exactly as #371
    // stamps it — stamped after the batch's source opened, since
    // opening the source is what fetches the declaration. The ladder's
    // own residue follows from walking against the same report.
    let degraded = calxgloss_types::CapabilityReport {
        families: vec![calxgloss_types::FamilyCapability {
            id: "decompilation".to_string(),
            status: calxgloss_types::AvailabilityStatus::Unavailable,
            reason: Some("the engine never produced a body".to_string()),
        }],
    };
    *pipeline
        .seam_report
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = degraded;

    // The unit walks the batch's own unit path — the retry wrapper the
    // queue puts every queued function through. The nine-attempt
    // climb is #372's walk, whose escalate prunes and
    // tier holds file the ladder's standing questions, and whose
    // zero-case fact the verification signal files beside them.
    let climbing = retry::RetryConfig {
        max_attempts: 9,
        ..retry::RetryConfig::default()
    };
    pipeline
        .try_translate_with_retry(PROGRAM, &unit, &climbing, &verifier)
        .await
        .expect("the canned LLM answers every attempt");
    pipeline
        .file_unknown_ledger(PROGRAM)
        .expect("the batch's ledger filing call");

    let ledger_path =
        calxgloss_types::unknown_ledger_path(dir, &calxgloss_types::BinaryIdentity::new(PROGRAM));
    let ledger: calxgloss_types::UnknownLedger = calxgloss_types::load_json(&ledger_path)
        .expect("the sweep's batch files its unknown ledger through the real path");
    ledger
        .records
        .expect("a batch whose producers wrote files a current set, never an absent key")
}

/// The field the sweep pairs: what the producers filed, as the shared
/// checker takes it — one `(kind label, source slot)` pair per record
/// the batch actually landed. Nothing re-spells the roster: the labels
/// are the records' own serde wording and the slots their own origins,
/// so the sweep cannot drift from what was filed (#352's rule).
fn swept_pairs(records: &[calxgloss_types::UnknownRecord]) -> Vec<(String, String)> {
    records
        .iter()
        .map(|record| (record.kind.to_string(), record.source_slot()))
        .collect()
}

/// The sweep's verdict: the declared roster read against the field
/// through the shared checker — one pass, one report naming every
/// offender, exactly as the seam sweep's `seam_sweep_faults` reports.
fn unknown_sweep_faults(pairs: &[(String, String)]) -> Vec<String> {
    let field: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(kind, slot)| (kind.as_str(), slot.as_str()))
        .collect();
    calxgloss_types::unknown_roster_faults(calxgloss_types::DECLARED_UNKNOWN_KINDS, &field)
}

/// The sweep itself (issue #375): the real batch path's producers pair
/// one-for-one against the declared unknown kinds — every declared
/// kind has exactly one producer standing behind it on the batch path,
/// every producer names a declared kind, and the shared checker's
/// verdict is empty. The per-kind counts pin the shape underneath:
/// an empty field can never pass for a pairing, because each of the
/// four producers really writes.
#[tokio::test]
async fn the_unknown_sweep_pairs_the_roster_against_the_real_producers_one_for_one() {
    let dir = TempDir::new().expect("temp workspace");
    let records = unknown_sweep_batch_records(dir.path()).await;
    let faults = unknown_sweep_faults(&swept_pairs(&records));
    assert!(
        faults.is_empty(),
        "the real batch path's producers must pair one-for-one against the \
             declared unknown kinds, and these drifted:\n{}",
        faults.join("\n")
    );
    let filed = |kind: calxgloss_types::UnknownKind| {
        records.iter().filter(|record| record.kind == kind).count()
    };
    assert!(
        filed(calxgloss_types::UnknownKind::CoverageFacet) >= 1,
        "the coverage fold files one question per admitting facet, at every \
             `{{document}}#{{facet}}` slot the engines admitted short"
    );
    assert_eq!(
        filed(calxgloss_types::UnknownKind::AnalysisFamily),
        1,
        "the held seam report files the one unavailable family the posture re-asks"
    );
    assert_eq!(
        filed(calxgloss_types::UnknownKind::BaselineNeverRun),
        1,
        "the zero-case walk files one standing question against the unit"
    );
    assert!(
        filed(calxgloss_types::UnknownKind::ExportUncovered) >= 1,
        "the batch's export check files every export no baseline document covered"
    );
    assert_eq!(
        filed(calxgloss_types::UnknownKind::RetryPruned),
        1,
        "two escalate prunes file one standing question, as #372 pinned"
    );
    assert_eq!(
        filed(calxgloss_types::UnknownKind::TierRefused),
        1,
        "the held tier step files its own standing question"
    );
    assert!(
        swept_pairs(&records).contains(&(
            "coverage_facet".to_string(),
            "string context result#function-bodies".to_string(),
        )),
        "the bodies facet the helper stamped partial on the filed document is \
             among the gaps the fold read off disk"
    );
}

/// A declared kind with no producer behind it (issue #375): drop the
/// ladder's refused-step record from the swept field and the sweep
/// fails, naming the kind. This is the P28 half — a future masked-byte
/// search that adds its kind string to the roster but no write site
/// fails here, at once.
#[tokio::test]
async fn the_sweep_fails_a_declared_kind_that_no_producer_files() {
    let dir = TempDir::new().expect("temp workspace");
    let records = unknown_sweep_batch_records(dir.path()).await;
    let mut pairs = swept_pairs(&records);
    pairs.retain(|(kind, _)| kind != "tier_refused");
    assert_eq!(
        unknown_sweep_faults(&pairs),
        ["declared kind `tier_refused` has no producer"],
        "a roster entry whose write site went missing fails loudly, naming itself"
    );
}

/// A producer naming an undeclared kind (issue #375): the masked-byte
/// pair below stands for P28's future write site arriving with its
/// half-second omission — the write site without a roster string. It
/// fails the same sweep at once, naming the kind it invented.
#[tokio::test]
async fn the_sweep_fails_a_producer_naming_an_undeclared_kind() {
    let dir = TempDir::new().expect("temp workspace");
    let records = unknown_sweep_batch_records(dir.path()).await;
    let mut pairs = swept_pairs(&records);
    pairs.push((
        "masked_byte_search".to_string(),
        "masked-byte result#pattern-bodies".to_string(),
    ));
    assert_eq!(
        unknown_sweep_faults(&pairs),
        ["producer files `masked_byte_search`, a kind the roster never declared"],
        "a producer admitting a gap the roster never named fails loudly, naming itself"
    );
}

/// One kind produced twice from one source slot (issue #375): a second
/// write site claiming the seam's own family slot — the same standing
/// question filed from two places, never a second opinion. The sweep
/// names the kind and the slot it doubled on.
#[tokio::test]
async fn the_sweep_fails_a_kind_produced_twice_from_one_source_slot() {
    let dir = TempDir::new().expect("temp workspace");
    let records = unknown_sweep_batch_records(dir.path()).await;
    let mut pairs = swept_pairs(&records);
    let seam = pairs
        .iter()
        .find(|(kind, slot)| kind == "analysis_family" && slot == "decompilation")
        .expect("the seam's own pair stands in the swept field")
        .clone();
    pairs.push(seam);
    assert_eq!(
        unknown_sweep_faults(&pairs),
        ["kind `analysis_family` is produced twice from source slot `decompilation`"],
        "one slot claimed by two write sites fails loudly, naming kind and slot"
    );
}

/// Missing, orphaned, and doubled in one field (issue #375): the
/// sweep's single verdict carries all three offenders in one pass,
/// naming each — the #359 one-report doctrine, one level up. A
/// contributor fixing the drift sees the whole damage at once.
#[tokio::test]
async fn one_unknown_sweep_report_names_every_offender_at_once() {
    let dir = TempDir::new().expect("temp workspace");
    let records = unknown_sweep_batch_records(dir.path()).await;
    let mut pairs = swept_pairs(&records);
    pairs.retain(|(kind, _)| kind != "tier_refused");
    pairs.push((
        "masked_byte_search".to_string(),
        "masked-byte result#pattern-bodies".to_string(),
    ));
    let seam = pairs
        .iter()
        .find(|(kind, slot)| kind == "analysis_family" && slot == "decompilation")
        .expect("the seam's own pair stands in the swept field")
        .clone();
    pairs.push(seam);
    let faults = unknown_sweep_faults(&pairs);
    assert_eq!(
        faults.len(),
        3,
        "missing, orphaned, and doubled offenders name themselves at once:\n{}",
        faults.join("\n")
    );
    assert!(
        faults.iter().any(|fault| fault.contains("tier_refused")),
        "the kind whose producer went missing is named:\n{}",
        faults.join("\n")
    );
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("masked_byte_search")),
        "the kind no roster declared is named:\n{}",
        faults.join("\n")
    );
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("analysis_family") && fault.contains("twice")),
        "the slot claimed twice is named:\n{}",
        faults.join("\n")
    );
}

/// Drain every `BatchProgress` beat seen since the last drain.
fn drain_beats(rx: &mut tokio::sync::broadcast::Receiver<ProgressEvent>) -> Vec<ProgressEvent> {
    std::iter::from_fn(|| rx.try_recv().ok())
        .filter(|ev| matches!(ev, ProgressEvent::BatchProgress { .. }))
        .collect()
}

/// Every heartbeat must name the scan phase, not the scan that happened
/// to be running, and its index must sit inside the listing the phase is
/// consuming (issue #239).
fn assert_phase_beats(beats: &[ProgressEvent]) {
    for beat in beats {
        match beat {
            ProgressEvent::BatchProgress {
                pass, index, total, ..
            } => {
                assert_eq!(
                    pass, "evidence scans",
                    "the heartbeat names the scan phase, not the scan: {beat}"
                );
                assert!(
                    *total > 0 && index <= total,
                    "the index never exceeds the listing size: {beat}"
                );
            }
            other => unreachable!("drain_beats keeps only heartbeats, got {other:?}"),
        }
    }
}

/// The scan phase arms one progress heartbeat for the whole group,
/// named for the phase (issue #239): a cold batch's heartbeats say
/// "evidence scans" and count unique functions consumed — later scans
/// replaying a body warm from the read cache never push the index past
/// the listing — and a warm batch replaying every body from the cache
/// still beats, so a cached binary shows life (issue #121 preserved).
#[tokio::test]
async fn scan_phase_heartbeats_name_the_phase_cold_and_warm() {
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _) = cached_pipeline(dir.path());
    let events = TranslationEvents::new(64);
    let mut rx = events.subscribe();
    let pipeline = pipeline.with_events(events);
    let verifier = calxgloss_verify::Verifier::new(dir.path()).expect("verifier over temp dir");

    // Cold batch: the first scan reads the engine live and the rest replay
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
/// read cache's per-key cell merges concurrent misses of one
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
            engine_identity: Some(calxgloss_decomp::current_engine_identity()),
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
        "kept bodies are recorded in the snapshot, and equal bodies pair through the body family"
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
/// the live bytes, plus a source answering which paired binaries have
/// been accepted (merged). Mirrors the CLI's real setup without git.
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

/// The headline test for issue #299: with a confident pairing document naming
/// the live bytes and a paired binary whose translation was accepted, the
/// unit's attempt 1 carries the accepted code verbatim — the LLM
/// endpoint stays untouched — and the unit still runs through the retry
/// loop's full verification. A below-floor pairing queues fresh exactly
/// as today: it reaches the (closed) LLM endpoint and fails like any
/// unit the engine cannot answer for.
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
            // A rename-aware pairing: the paired binary goes by another name.
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
                retry_strategy: retry::RetryStrategy::CompileFix,
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
    assert_eq!(
        attempt.retry_strategy, "initial",
        "the seed is kept as attempt 1"
    );
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
        "provenance is recorded only beside an honest done: with verification \
             saying not-done, nothing marks the carried code as a win (ADR-0003)"
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
/// and the attempt branch the code arrived on — and spends no tokens.
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
    // A seed cannot slip a Skip-classified root past the refusal —
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

/// The commit-message provenance rule: a carry-over record counts only
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
        .expect("the seed won: provenance is recorded");
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
        "the check looks at the final code, however it got there"
    );
}

/// Every registered row's filed document, read from the location
/// its descriptor names, as parsed JSON keyed by the row's name —
/// the registry-driven form the equivalence checks compare, so a row
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

/// The headline fan-out test: given the same cached reads, the
/// concurrent phase and the same registry run one scan at a time
/// persist the same documents — findings, order, and callback
/// enrichment alike — for every registered row, the comparison
/// driven by the table rather than a hand-written list of engines
/// (issue #240, retargeted onto the registry by issue #307).
///
/// Both compared runs replay one read cache, warmed by a cold
/// phase first: the Kuna engine merges each decompile's recovered
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

    // The sequential part: the same registry run one scan at a time,
    // in table order, over the read cache the cold phase warmed —
    // the guarantee the old sequential preamble pinned, now driven
    // by the table instead of a hand-written list of entry points,
    // so every registered row is compared and a row added later is
    // compared with no test edit. The completion latches are armed
    // and attached to each row's context exactly as
    // `registered_scan_tasks` attaches the phase's, so the declared
    // edge holds here too: the inference row sits directly before
    // the callback row in the table, publishes its latch on the way
    // out, and the callback row composes its closure contracts from
    // the inference document the sequential part just filed
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
    // ones — and in the sequential part it is the declared edge, not
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
/// The pair's counterpart sits at the CLI: the pairing test
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

/// The track roster (issue #352): every registered scan row keyed to
/// the engine's **own** declared-facets table — each engine crate
/// lifts its `DECLARED_FACETS` to module scope precisely so this
/// sweep reads the tables' own data, the same pairing doctrine the
/// CLI contribution table pins (#342). A row that joins the registry
/// without a pairing row here, or whose engine renames a facet this
/// table never had, fails the sweep below loudly; no roster is ever
/// re-spelled for the sweep, so the sweep cannot drift from the
/// engine it checks.
const TRACK_DECLARED_FACETS: &[(&str, &[&str])] = &[
    (
        "control-flow",
        calxgloss_controlflow::engine::DECLARED_FACETS,
    ),
    (
        "memory-lifecycle",
        calxgloss_memory::engine::DECLARED_FACETS,
    ),
    ("concurrency", calxgloss_sync::engine::DECLARED_FACETS),
    (
        "global-state",
        calxgloss_globalstate::engine::DECLARED_FACETS,
    ),
    ("constants", calxgloss_consts::engine::DECLARED_FACETS),
    (
        "error-handling",
        calxgloss_errhandling::engine::DECLARED_FACETS,
    ),
    ("float-simd", calxgloss_floatsimd::engine::DECLARED_FACETS),
    ("type-database", calxgloss_typesdb::engine::DECLARED_FACETS),
    (
        "algorithm-recognition",
        calxgloss_algorithm::engine::DECLARED_FACETS,
    ),
    (
        "string-context",
        calxgloss_stringctx::engine::DECLARED_FACETS,
    ),
    ("library-api", calxgloss_apidetect::engine::DECLARED_FACETS),
    (
        "serialization",
        calxgloss_serialize::engine::DECLARED_FACETS,
    ),
    (
        "type-inference",
        calxgloss_typeinfer::engine::DECLARED_FACETS,
    ),
    (
        "callback-detection",
        calxgloss_callback::engine::DECLARED_FACETS,
    ),
    ("known-library", calxgloss_libmatch::engine::DECLARED_FACETS),
];

/// The track sweep's fixture: a cold phase over the fixture target,
/// then every registered row's filed document as parsed JSON — the
/// documents the sweep reads are the ones the phase actually wrote,
/// not re-serialized copies.
async fn track_sweep_documents(
    workspace: &std::path::Path,
) -> Vec<(&'static str, serde_json::Value)> {
    let (pipeline, _) = cached_pipeline(workspace);
    pipeline.begin_cached_source(PROGRAM).await;
    pipeline.run_prebatch_scans(PROGRAM).await;
    registered_documents(workspace)
}

/// One document's metadata as the shared type carries it, for the
/// sweep: absent or unreadable metadata is itself a sweep fault,
/// never a silent skip.
fn swept_metadata(doc: &serde_json::Value) -> std::result::Result<ScanMetadata, serde_json::Error> {
    serde_json::from_value(doc["metadata"].clone())
}

/// The all-fifteen sweep (issue #352): walk every registered scan
/// row's produced document, read the coverage entry its engine
/// stamped, and pin it against the engine's own declared-facets
/// table — every declared facet named exactly once, nothing else
/// named. Every fault names its engine; one failure report carries
/// them all, so a single run of this test states the whole track's
/// pinning health.
#[tokio::test]
async fn every_registered_rows_document_pins_its_engines_own_roster() {
    let dir = TempDir::new().expect("temp workspace");
    let documents = track_sweep_documents(dir.path()).await;
    let mut report: Vec<String> = Vec::new();
    for (row, declared) in TRACK_DECLARED_FACETS {
        let Some((_, doc)) = documents.iter().find(|(name, _)| name == row) else {
            report.push(format!("{row}: the phase filed no document to sweep"));
            continue;
        };
        match swept_metadata(doc) {
            Ok(metadata) => match &metadata.coverage {
                Some(coverage) => {
                    for fault in coverage.roster_faults(declared) {
                        report.push(format!("{row}: {fault}"));
                    }
                }
                None => report.push(format!(
                    "{row}: the filed document carries no coverage entry — the \
                         engine stamped nothing"
                )),
            },
            Err(error) => report.push(format!(
                "{row}: the filed document's metadata will not load: {error}"
            )),
        }
    }
    for (name, _) in &documents {
        if !TRACK_DECLARED_FACETS.iter().any(|(row, _)| row == name) {
            report.push(format!(
                "{name}: a filed document no track roster entry pairs with"
            ));
        }
    }
    assert!(
        report.is_empty(),
        "the all-fifteen sweep pins every filed coverage entry against its \
             engine's own DECLARED_FACETS table, and these engines broke it:\n{}",
        report.join("\n")
    );
}

/// The orphan check (issue #352): a coverage entry in any written
/// document that names a facet its engine never declared is an
/// invented qualification — the reader would be shown a gap in a
/// facet the scan never promised to read. This sweep states that
/// direction alone: every facet id in every filed document is in
/// the engine's own table, one failure report naming every orphan.
#[tokio::test]
async fn no_filed_document_names_a_facet_its_engine_never_declared() {
    let dir = TempDir::new().expect("temp workspace");
    let documents = track_sweep_documents(dir.path()).await;
    let mut orphans: Vec<String> = Vec::new();
    for (row, declared) in TRACK_DECLARED_FACETS {
        let Some((_, doc)) = documents.iter().find(|(name, _)| name == row) else {
            continue; // the roster sweep above reports the absence
        };
        if let Ok(Some(coverage)) = swept_metadata(doc).map(|m| m.coverage) {
            for facet in &coverage.facets {
                if !declared.contains(&facet.id.as_str()) {
                    orphans.push(format!("{row}: `{}`", facet.id));
                }
            }
        }
    }
    assert!(
        orphans.is_empty(),
        "no written coverage entry names a facet its engine never \
             declared, and these orphans broke it: {}",
        orphans.join(", ")
    );
}

/// The pre-P19 fixtures load across all fifteen engines (issue
/// #352): a document written before the coverage key shipped —
/// `ScanMetadata::new` stamps nothing, and the engine's own
/// persistor saves those bytes — carries no coverage key at all,
/// loads through that persistor without an error, reads coverage
/// absent, and resolves to `EffectiveCoverage::Unknown`, never
/// `Complete`. The absent-reads-as-unknown rule (ADR-0053) is the
/// whole contract, and each engine's loader holds it.
#[test]
fn every_engine_loads_a_pre_p19_document_as_unknown_coverage() {
    type FixtureDoc = fn(&std::path::Path) -> (String, ScanMetadata);
    let fixtures: [(&str, FixtureDoc); 15] = [
        ("library-api", |dir| {
            let p = ApiPersistor::new(dir);
            p.save(&calxgloss_apidetect::types::ApiDetectionResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 api-detection document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 api-detection document loads")
                    .metadata,
            )
        }),
        ("known-library", |dir| {
            let p = LibmatchPersistor::new(dir);
            p.save(&calxgloss_libmatch::types::LibmatchResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 libmatch document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 libmatch document loads")
                    .metadata,
            )
        }),
        ("float-simd", |dir| {
            let p = FloatsimdPersistor::new(dir);
            p.save(&calxgloss_floatsimd::types::FloatsimdResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 floatsimd document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 floatsimd document loads")
                    .metadata,
            )
        }),
        ("type-database", |dir| {
            let p = TypeDatabasePersistor::new(dir);
            p.save(&calxgloss_typesdb::types::TypeDatabase::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 type-database document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 type-database document loads")
                    .metadata,
            )
        }),
        ("constants", |dir| {
            let p = ConstPersistor::new(dir);
            p.save(&calxgloss_consts::types::ConstResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 constants document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 constants document loads")
                    .metadata,
            )
        }),
        ("control-flow", |dir| {
            let p = ControlFlowPersistor::new(dir);
            p.save(&ControlFlowResult::new(ScanMetadata::new(PROGRAM)))
                .expect("a pre-P19 control-flow document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 control-flow document loads")
                    .metadata,
            )
        }),
        ("memory-lifecycle", |dir| {
            let p = MemoryPersistor::new(dir);
            p.save(&calxgloss_memory::types::MemoryResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 memory document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 memory document loads")
                    .metadata,
            )
        }),
        ("concurrency", |dir| {
            let p = SyncPersistor::new(dir);
            p.save(&calxgloss_sync::types::SyncResult::new(ScanMetadata::new(
                PROGRAM,
            )))
            .expect("a pre-P19 concurrency document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 concurrency document loads")
                    .metadata,
            )
        }),
        ("global-state", |dir| {
            let p = GlobalStatePersistor::new(dir);
            p.save(&GlobalStateResult::new(ScanMetadata::new(PROGRAM)))
                .expect("a pre-P19 global-state document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 global-state document loads")
                    .metadata,
            )
        }),
        ("error-handling", |dir| {
            let p = ErrhandlingPersistor::new(dir);
            p.save(&calxgloss_errhandling::types::ErrhandlingResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 error-handling document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 error-handling document loads")
                    .metadata,
            )
        }),
        ("algorithm-recognition", |dir| {
            let p = AlgorithmPersistor::new(dir);
            p.save(
                &calxgloss_algorithm::types::AlgorithmRecognitionResult::new(ScanMetadata::new(
                    PROGRAM,
                )),
            )
            .expect("a pre-P19 algorithm document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 algorithm document loads")
                    .metadata,
            )
        }),
        ("string-context", |dir| {
            let p = StringContextPersistor::new(dir);
            p.save(&calxgloss_stringctx::types::StringContextResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 string-context document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 string-context document loads")
                    .metadata,
            )
        }),
        ("serialization", |dir| {
            let p = SerializePersistor::new(dir);
            p.save(&calxgloss_serialize::types::SerializeResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 serialization document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 serialization document loads")
                    .metadata,
            )
        }),
        ("type-inference", |dir| {
            let p = TypeInferPersistor::new(dir);
            p.save(&TypeInferenceResult::new(ScanMetadata::new(PROGRAM)))
                .expect("a pre-P19 type-inference document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 type-inference document loads")
                    .metadata,
            )
        }),
        ("callback-detection", |dir| {
            let p = CallbackPersistor::new(dir);
            p.save(&calxgloss_callback::types::CallbackResult::new(
                ScanMetadata::new(PROGRAM),
            ))
            .expect("a pre-P19 callback document saves");
            (
                std::fs::read_to_string(p.path_for(PROGRAM)).expect("the saved document's bytes"),
                p.load(PROGRAM)
                    .expect("a pre-P19 callback document loads")
                    .metadata,
            )
        }),
    ];
    for (engine, fixture) in fixtures {
        let dir = TempDir::new().expect("temp workspace");
        let (raw, metadata) = fixture(dir.path());
        assert!(
            !raw.contains("\"coverage\""),
            "{engine}: a pre-P19 document carries no coverage key at all — \
                 its metadata was stamped by `ScanMetadata::new`"
        );
        assert!(
            metadata.coverage.is_none(),
            "{engine}: the loaded document names no coverage entry"
        );
        assert_eq!(
            metadata.coverage_status(),
            EffectiveCoverage::Unknown,
            "{engine}: an absent coverage entry reads as unknown — never \
                 as complete"
        );
    }
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
                .expect("the document sits under re/analysis/<domain>/<binary>.json"),
            dir.path().join("re").join("analysis"),
            "the {} row's document follows the analysis-document convention: {}",
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

/// One registered row's third shape: with its document directory
/// sabotaged the row warns and files nothing — and every other
/// registered row still files its own. One detector's trouble never
/// takes down the group.
async fn a_sabotaged_row_degrades(row: &ScanDescriptor) {
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

/// The sabotage walk's row roster, as one macro listing: the fifteen
/// tests below and the completeness guard both expand from it, so a
/// row joining the registry gets its own walk or the guard fails.
macro_rules! for_each_registered_row {
    ($f:ident) => {
        $f!(sabotages_control_flow, "control-flow");
        $f!(sabotages_memory_lifecycle, "memory-lifecycle");
        $f!(sabotages_concurrency, "concurrency");
        $f!(sabotages_global_state, "global-state");
        $f!(sabotages_constants, "constants");
        $f!(sabotages_error_handling, "error-handling");
        $f!(sabotages_float_simd, "float-simd");
        $f!(sabotages_type_database, "type-database");
        $f!(sabotages_algorithm_recognition, "algorithm-recognition");
        $f!(sabotages_string_context, "string-context");
        $f!(sabotages_library_api, "library-api");
        $f!(sabotages_serialization, "serialization");
        $f!(sabotages_type_inference, "type-inference");
        $f!(sabotages_callback_detection, "callback-detection");
        $f!(sabotages_known_library, "known-library");
    };
}

// The third shape over the whole registry: every row `scan_rows()`
// holds goes through the sabotage walk, so the fifteen rows here are the
// whole table. One test per row rather than one loop over the table:
// each walk runs the entire scan phase, so the loop serialized
// fifteen scan phases — most of this binary's wall clock — where the
// fifteen tests overlap across test threads instead.
macro_rules! define_sabotage_test {
    ($name:ident, $row:literal) => {
        #[tokio::test]
        async fn $name() {
            let row = find_row($row);
            a_sabotaged_row_degrades(&row).await;
        }
    };
}
for_each_registered_row!(define_sabotage_test);

#[test]
fn every_registered_row_gets_its_own_sabotage_test() {
    // Splitting the walk must not quietly drop a row out of the
    // suite: a registry row the macro listing does not name faults.
    let mut walked = Vec::new();
    macro_rules! collect_row {
        ($name:ident, $row:literal) => {
            walked.push($row);
        };
    }
    for_each_registered_row!(collect_row);

    let table: Vec<&str> = scan_rows().iter().map(ScanDescriptor::name).collect();
    assert_eq!(
        walked, table,
        "each registry row must get exactly one sabotage test, in table order"
    );
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
/// descriptor defines it for a failed scan; the shared shape never parsed
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
/// option attached to the same run short-circuits ahead of any engine
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
        "the known-library document follows the analysis-document convention: {}",
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
/// #306 recorded), so what this test watched for at first has hardened
/// into pinning a real finding for one of the scan order's callees, and
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
        graph
            .functions
            .iter()
            .all(|function| !matches!(function.node_category, calxgloss_types::NodeCategory::Skip)),
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
/// engine round trips the phase paid (the engine call log), the window's
/// high-water mark, the documents filed, and the process's peak resident
/// set across the phase. The engine is the real one and the binary is a
/// real one; only the workspace is a scratch directory.
///
/// Cold run: point the workspace at an empty directory — every body
/// crosses the engine exactly once, which the printed call log proves.
/// Parse-only run: keep the workspace's `re/cache` and delete
/// `re/analysis` — every scan re-runs, every read replays off disk, and
/// the call log prints zero engine round trips, so the wall time is the
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

/// The prerequisite the fan-out needs: a registered row's scan handed
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
fn record_order_never_matters_and_a_void_return_is_kept_in_the_map() {
    // Records arrive in whatever order the scan persisted them;
    // the positions sort out. A `void` return is kept as read —
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

// ---- #355: the seam declaration is pulled once and held -------------

#[tokio::test]
async fn the_batch_holds_the_seam_declaration_pulled_beside_the_source_open() {
    // The fetch goes through begin_cached_source and nothing else: the held
    // report pairs one-for-one with the seam's own roster, equals the
    // engine's live declaration byte-for-byte, and took no engine
    // read — the call log is exactly what the source's opening left.
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _) = cached_pipeline(dir.path());
    pipeline.begin_cached_source(PROGRAM).await;
    let held = pipeline.seam_report();
    assert_eq!(
        held,
        pipeline.kuna().capability_report(),
        "the held copy equals the opened source's declaration exactly"
    );
    let ids: Vec<&str> = calxgloss_decomp::QUERY_FAMILIES
        .iter()
        .map(|(family, _methods)| *family)
        .collect();
    assert_eq!(
        held.roster_faults(&ids),
        Vec::<String>::new(),
        "the held report pairs one-for-one with the seam's own roster"
    );
    assert!(
        held.families.iter().all(|entry| {
            entry.status == calxgloss_types::AvailabilityStatus::Answerable
                && entry.admission().is_none()
        }),
        "Kuna declares its full roster answerable today — nothing admitted"
    );
}

#[tokio::test]
async fn the_capability_hold_costs_no_additional_engine_read_beyond_the_opening() {
    // The pin the acceptance names: pulling the report beside opening
    // the cached source adds zero engine reads. The engine call log
    // over `begin_cached_source` — source opening plus capability
    // fetch — stays empty: opening the cache never touched the
    // engine either, and after the batch begins the log is still
    // exactly as silent as before it began.
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _) = cached_pipeline(dir.path());
    let reads_before = pipeline.kuna().decompile_calls().len();
    pipeline.begin_cached_source(PROGRAM).await;
    let _held = pipeline.seam_report();
    assert_eq!(
        pipeline.kuna().decompile_calls().len(),
        reads_before,
        "opening the cached source and holding its capability report \
             took no decompile read from the engine"
    );
}

#[tokio::test]
async fn a_batch_with_no_cache_to_open_holds_the_live_engines_declaration() {
    // The fallback branch beside the same fetch point: with no workspace
    // there is no cache to open and the batch's reads go through the
    // live engine — so the live engine's own declaration is the one
    // held, pulled at the same one point, still with no engine read.
    let pipeline = pipeline_with(fixture_kuna(), None);
    let reads_before = pipeline.kuna().decompile_calls().len();
    pipeline.begin_cached_source(PROGRAM).await;
    let held = pipeline.seam_report();
    assert_eq!(
        held,
        pipeline.kuna().capability_report(),
        "the fallback holds the live source's declaration, not an emptier one"
    );
    assert_eq!(
        pipeline.kuna().decompile_calls().len(),
        reads_before,
        "the fallback fetch read nothing from the engine"
    );
}

// ---- #359: the track sweep over the real pipeline's seam read -------

/// The track sweep's data-level verdict (issue #359): does the capability
/// report the real pipeline reads from its opened seam pair one-for-one
/// against the seam's own query methods — every method the seam exposes
/// on the engine side claimed by exactly one declared family, every
/// declared family carried by the read exactly once, and no declared
/// family naming nothing the seam can answer?
///
/// Every fault states its drift in its own words and they all arrive in
/// one pass, so a single failure of the sweep below names every offender
/// at once — the one-report doctrine the registry pairing (#342) and the
/// P19 track sweep (#352) established, now guarding the seam itself. The
/// family-id pairing wording is the shared `CapabilityReport::roster_faults`
/// #354 established; the method pairing and the family-side orphan check
/// are this sweep's own additions.
fn seam_sweep_faults(
    report: &calxgloss_types::CapabilityReport,
    roster: &[(&str, &[&str])],
) -> Vec<String> {
    let ids: Vec<&str> = roster.iter().map(|(family, _methods)| *family).collect();
    // A family the read omits, a family it names twice, and a family it
    // names that no seam roster carries — the orphan direction on the
    // read's own side.
    let mut faults = report.roster_faults(&ids);
    // Every query method the seam exposes on the engine side pairs with
    // exactly one declared family.
    let mut methods: Vec<&str> = Vec::new();
    for (_family, family_methods) in roster {
        for method in *family_methods {
            if !methods.contains(method) {
                methods.push(method);
                let claims = roster
                    .iter()
                    .filter(|(_, claimed)| claimed.contains(method))
                    .count();
                if claims > 1 {
                    faults.push(format!(
                        "seam method `{method}` is claimed by {claims} declared families — \
                             a query method pairs with exactly one family"
                    ));
                }
            }
        }
    }
    // The orphan check on the family side: a declared family that names
    // no seam query method stands for nothing the seam can answer.
    for (family, family_methods) in roster {
        if family_methods.is_empty() {
            faults.push(format!(
                "declared family `{family}` names no seam query method — \
                     the sweep rejects a family that stands for nothing"
            ));
        }
    }
    faults
}

/// A report pairing the named families with one `answerable` entry each —
/// the shape a full declaration answers with, for the hand-built fixtures.
fn sweep_report(families: &[&str]) -> calxgloss_types::CapabilityReport {
    calxgloss_types::CapabilityReport {
        families: families
            .iter()
            .map(|id| calxgloss_types::FamilyCapability {
                id: (*id).to_string(),
                status: calxgloss_types::AvailabilityStatus::Answerable,
                reason: None,
            })
            .collect(),
    }
}

/// The all-twelve sweep over the real pipeline's seam read (issue #359):
/// the report `begin_cached_source` holds is the one the cached source
/// opened over the fixture hands up, forwarded unchanged through the
/// cache wrapper — a cache never changes capabilities, it only caches
/// answers — and it pairs one-for-one against the seam's own query
/// methods. This is the seam crate's trait-to-roster pairing (#354)
/// walked from the consumer's end: a P28 or P29 that grows the trait,
/// the roster, or the declaration without growing the other two fails
/// here, naming itself.
#[tokio::test]
async fn the_seam_sweep_pairs_the_real_pipelines_read_one_for_one() {
    let dir = TempDir::new().expect("temp workspace");
    let (pipeline, _) = cached_pipeline(dir.path());
    pipeline.begin_cached_source(PROGRAM).await;
    let read = pipeline.seam_report();
    let roster = calxgloss_decomp::QUERY_FAMILIES;
    let faults = seam_sweep_faults(&read, roster);
    assert!(
        faults.is_empty(),
        "the real pipeline's seam read must pair one-for-one against \
             the seam's query methods, and these drifted:\n{}",
        faults.join("\n")
    );
    // The shape the sweep stands on, pinned so a roster that grows
    // without the read growing — or the reverse — names itself in a
    // count before it can hide inside a pairing.
    let methods: usize = roster.iter().map(|(_, m)| m.len()).sum();
    assert_eq!(
        roster.len(),
        12,
        "twelve declared families pair the seam today"
    );
    assert_eq!(
        methods, 14,
        "fourteen program-query methods sit behind those families today"
    );
    assert_eq!(
        read.families.len(),
        roster.len(),
        "the live read declares exactly the families the roster carries"
    );
}

/// Missing, doubled, and orphaned in one read: the sweep's verdict
/// carries all three offenders in a single pass, naming each (issue
/// #359) — a contributor fixing the seam sees the whole damage at once,
/// instead of discovering one offender per run.
#[test]
fn one_sweep_report_names_every_offender_at_once() {
    let families: Vec<&str> = calxgloss_decomp::QUERY_FAMILIES
        .iter()
        .map(|(family, _methods)| *family)
        .filter(|family| *family != "decompilation")
        .chain(std::iter::once("strings"))
        .chain(std::iter::once("sardine"))
        .collect();
    let read = sweep_report(&families);
    let faults = seam_sweep_faults(&read, calxgloss_decomp::QUERY_FAMILIES);
    assert_eq!(
        faults.len(),
        3,
        "missing, doubled, and orphaned offenders name themselves at once:\n{}",
        faults.join("\n")
    );
    assert!(
        faults.iter().any(|fault| fault.contains("decompilation")),
        "the family the read stopped declaring is named:\n{}",
        faults.join("\n")
    );
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("strings") && fault.contains("times")),
        "the family declared twice is named:\n{}",
        faults.join("\n")
    );
    assert!(
        faults.iter().any(|fault| fault.contains("sardine")),
        "the entry naming a family no seam roster carries is named:\n{}",
        faults.join("\n")
    );
}

/// The orphan check, family side (issue #359): a family the engine
/// declares and the read faithfully carries, but which names no seam
/// query method at all, stands for nothing the seam can answer — the
/// sweep rejects it, and it names itself.
#[test]
fn the_sweep_orphan_check_rejects_a_declared_family_that_names_no_query_method() {
    let roster: Vec<(&str, &[&str])> = calxgloss_decomp::QUERY_FAMILIES
        .iter()
        .copied()
        .chain(std::iter::once(("smokewood", [].as_slice())))
        .collect();
    let ids: Vec<&str> = roster.iter().map(|(family, _methods)| *family).collect();
    let read = sweep_report(&ids);
    assert_eq!(
        seam_sweep_faults(&read, &roster),
        ["declared family `smokewood` names no seam query method — \
             the sweep rejects a family that stands for nothing"],
        "a declared family naming nothing fails the orphan check, naming itself"
    );
}

/// The method side of the pairing (issue #359): one seam query feeding
/// two declared families means one family answers a question it does not
/// own — the pairing is exactly one-to-one in both directions, and the
/// sweep says so in words.
#[test]
fn the_sweep_fails_a_query_method_claimed_by_two_families() {
    let roster: Vec<(&str, &[&str])> = calxgloss_decomp::QUERY_FAMILIES
        .iter()
        .map(|(family, methods)| {
            if *family == "image-base" {
                (*family, &["image_base", "read_memory"][..])
            } else {
                (*family, *methods)
            }
        })
        .collect();
    let ids: Vec<&str> = roster.iter().map(|(family, _methods)| *family).collect();
    let read = sweep_report(&ids);
    assert_eq!(
        seam_sweep_faults(&read, &roster),
        [
            "seam method `read_memory` is claimed by 2 declared families — \
             a query method pairs with exactly one family"
        ],
        "a query method claimed twice fails the pairing, naming itself"
    );
}

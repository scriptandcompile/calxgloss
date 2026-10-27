//! The retry loop — orchestrates translation, verification, and LLM fixes.

use crate::Translation;
use crate::retry::attempt::{
    AttemptOutcome, AttemptPath, AttemptReport, AttemptRunCtx, AttemptUnit, emit_attempt,
    run_attempt, verify_and_record,
};
use crate::retry::helpers::{
    ESCALATE_REASK_FAMILIES, build_escalated_prompt, reask_admission_lines, tier_re_asks_seam,
    unavailable_reask_families,
};
use crate::retry::{
    FixPromptRequest, RetryConfig, RetryResult, RetryStrategy, TranslationAttempt, UnitVerdict,
    build_fix_prompt,
};
use calxgloss_analysis::FaultLogger;
use calxgloss_llm::{
    LlmClient, LlmError, LlmMessage, infinite_loop::InfiniteLoopDetector,
    resource_exhaustion::ResourceExhaustionDetector,
};
use calxgloss_types::{FailureHint, ProgressEvent, TranslationEvents};
use calxgloss_verify::Verifier;
use tracing::{info, warn};

/// Context for the retry loop.
///
/// Groups the parameters that `try_translate_with_retry` needs so callers
/// can build a single struct instead of passing 7 separate arguments.
/// Reduces the public function signature to 2 parameters.
pub struct RetryLoopCtx<'a> {
    /// Verification engine for checking translations.
    pub verifier: &'a Verifier,
    /// LLM client for sending fix prompts.
    pub llm: &'a LlmClient,
    /// Scan source, used for context extraction during escalation — the
    /// batch's shared source (live client or read cache).
    pub source: &'a calxgloss_decomp::PipelineSource,
    /// Retry configuration.
    pub config: &'a RetryConfig,
    /// Optional workspace path for experiment logging.
    pub workspace: Option<&'a std::path::Path>,
    /// Optional progress event emitter for live WebSocket streaming.
    pub events: Option<&'a calxgloss_types::TranslationEvents>,
    /// Optional resource-exhaustion detector for tracking LLM server health.
    pub resource_detector: Option<&'a ResourceExhaustionDetector>,
    /// Optional fault logger for persisting detected faults to disk.
    pub fault_logger: Option<&'a FaultLogger>,
    /// Reviewer's custom hints for this unit (issue #96, W2.7). When
    /// non-empty they seed the failure history, so the reviewer's knowledge
    /// reaches every failure-informed fix prompt from the first retry on.
    pub reviewer_hints: &'a [String],
    /// The seam capability report the pipeline holds from the moment it
    /// opened the batch's scan source (issue #355). The escalate arm folds
    /// one family from this held copy, and the ladder consults it before
    /// dispatching an escalate-shaped strategy or tier step (issue #356)
    /// — no prompt path and no retry decision ever re-asks the seam.
    pub seam_report: &'a calxgloss_types::CapabilityReport,
}

/// Execute a translation with retry logic.
///
/// This is the main retry entry point. It:
/// 1. Takes the initial translation result
/// 2. Verifies it against baseline tests
/// 3. On failure, builds a fix prompt and sends it to the LLM
/// 4. Re-verifies each fix attempt
/// 5. Escalates strategy after each failure
/// 6. Returns a [`RetryResult`] with all attempt details
/// 7. Logs experiment data per attempt
/// 8. Emits [`ProgressEvent`] instances via the optional events channel
///
/// # Arguments
///
/// * `initial_translation` — The initial [`Translation`] to verify and retry.
/// * `ctx` — A [`RetryLoopCtx`] holding the verifier, LLM, scan source,
///   configuration, and optional extras.
pub async fn try_translate_with_retry(
    initial_translation: Translation,
    ctx: &RetryLoopCtx<'_>,
) -> RetryResult {
    let mut result = RetryResult::new();
    let max = ctx.config.max_attempts;
    let mut current_strategy = ctx.config.retry_strategy;
    let mut current_tier = initial_translation.context_tier;
    // W2.5: an operator `max_context_tier` constraint also caps the starting
    // tier — retries rebuild their prompts no higher than the cap.
    if let Some(cap) = ctx.config.max_context_tier
        && current_tier.number() > cap.number()
    {
        current_tier = cap;
    }

    // Failure history for failure-informed prompting. W2.7: the reviewer's
    // custom hints seed it (attempt 0, "reviewer" strategy), so a steered
    // unit's fix prompts carry the reviewer's knowledge from the first retry.
    let mut failure_history: Vec<FailureHint> = ctx
        .reviewer_hints
        .iter()
        .map(|hint| FailureHint::new(0, "reviewer", hint.clone()))
        .collect();

    // Infinite-loop detector — tracks (prompt_hash, output_hash) pairs.
    // If the same bad output repeats 3+ times, the detector fires and the
    // loop breaks to avoid wasting tokens on a dead-end path.
    let mut loop_detector = InfiniteLoopDetector::new();

    let binary = initial_translation.binary.clone();
    let function = initial_translation.function.clone();

    // The attempt seam's run context (issue #331): everything every attempt
    // of this unit needs from the loop, gathered once.
    let run = &mut AttemptRunCtx {
        verifier: ctx.verifier,
        llm: ctx.llm,
        events: ctx.events,
        workspace: ctx.workspace,
        resource_detector: ctx.resource_detector,
        fault_logger: ctx.fault_logger,
        loop_detector: &mut loop_detector,
        binary: binary.clone(),
        function: function.clone(),
    };

    // First attempt: verify the initial translation, riding the attempt
    // seam (issue #331). Compile-only mode — today's hole, closed in #334.
    let initial_unit = AttemptUnit {
        binary: &initial_translation.binary,
        function: &initial_translation.function,
        code_under_fix: &initial_translation.rust_code,
        baseline_tests: &initial_translation.baseline_tests,
        tier: initial_translation.context_tier,
        function_address: initial_translation.function_address,
        call_graph: &initial_translation.call_graph,
        call_graph_context: &initial_translation.call_graph_context,
    };
    let initial_prompt = format!("{function} ({binary}) initial translation");
    let initial_report = verify_and_record(
        run,
        &mut result,
        &initial_unit,
        1,
        "initial",
        &initial_prompt,
        initial_translation.tokens_used,
    )
    .await;

    // If the first attempt succeeded, we're done
    if result.success {
        return result;
    }

    // Loop detector fired — do not retry
    if initial_report.loop_fired {
        return result;
    }

    // The verdict evidence the fix prompts quote — always about **the code
    // being fixed** (#334): seeded from the initial attempt's own record
    // and seam outcome, and routed forward after every failed verification
    // to that attempt's own record and seam outcome. The verifier stays
    // asked exactly once per candidate code; the loop re-gathers nothing.
    let mut verdict = UnitVerdict::from_failure(&result, &initial_report.outcome);
    // The code the next fix prompt repairs — the latest failed attempt's
    // own code from #334 on, seeded with the initial translation's output.
    let mut fix_code = initial_translation.rust_code.clone();

    // Retry loop
    let mut tier_escalated = false;
    for attempt_num in 2..=max {
        info!(
            attempt = attempt_num,
            max = max,
            current_strategy = %current_strategy,
            current_tier = %current_tier,
            "Retry attempt"
        );

        // Wall-clock start of this attempt — recorded on its token-usage
        // entry so the dashboard can estimate remaining time (issue #64).
        // Handed through the seam so the recorded duration still spans
        // prompt building plus the call.
        let attempt_start = std::time::Instant::now();

        // The unit under repair, routed through the attempt seam (issue
        // #331): the code the fix would replace — the latest failed
        // candidate's own since #334 — the suite it must pass, and the
        // tier this attempt's prompt is built at.
        let unit = AttemptUnit {
            binary: &initial_translation.binary,
            function: &initial_translation.function,
            code_under_fix: &fix_code,
            baseline_tests: &initial_translation.baseline_tests,
            tier: current_tier,
            function_address: initial_translation.function_address,
            call_graph: &initial_translation.call_graph,
            call_graph_context: &initial_translation.call_graph_context,
        };

        // If the tier was escalated in the previous iteration, build an
        // escalated prompt with additional decompiler/workspace context for
        // the next attempt.  Otherwise fall through to the strategy-based
        // prompt below.
        if tier_escalated {
            tier_escalated = false;

            // Try to build the escalated prompt.  If it fails, fall back to
            // the strategy-based prompt below (the match arms that follow).
            let escalated_prompt = match build_escalated_prompt(
                &initial_translation,
                current_tier,
                ctx.source,
                ctx.workspace,
            )
            .await
            {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        binary = %binary,
                        function,
                        error = %e,
                        tier = %current_tier,
                        "Failed to build escalated prompt — falling back to strategy prompt"
                    );
                    // Signal that tier escalation failed; the match below
                    // will handle the normal strategy-based prompt.
                    // We handle this by setting a flag.
                    result.add_attempt(TranslationAttempt {
                        attempt: attempt_num,
                        rust_code: initial_translation.rust_code.clone(),
                        compiled: false,
                        compilation_errors: vec![format!("Tier escalation failed: {e}")],
                        tests_passed: 0,
                        tests_total: 0,
                        failed_tests: Vec::new(),
                        retry_strategy: format!("tier_escalation_failed({})", current_tier.label()),
                        tokens_used: None,
                        context_tier: Some(current_tier.label().to_string()),
                    });
                    emit_attempt(
                        ctx.events,
                        &binary,
                        &function,
                        &result,
                        attempt_num,
                        &format!("tier_escalation_failed({})", current_tier.label()),
                    );
                    continue;
                }
            };
            let tier_label = current_tier.label().to_string();

            let report = run_attempt(
                run,
                &mut result,
                &mut failure_history,
                &unit,
                AttemptPath::TierEscalated,
                &format!("escalated({tier_label})"),
                attempt_num,
                &escalated_prompt,
                attempt_start,
            )
            .await;

            // The failed candidate's own verdict and code ride into the
            // next prompt (#334), and a fired detector ends the chain
            // wherever it lands — its fault record and event are already
            // written by the seam.
            route_latest_failure(&result, &report, &mut verdict, &mut fix_code);
            if report.loop_fired {
                break;
            }

            match report.outcome {
                AttemptOutcome::Passed => break,
                AttemptOutcome::LlmEmpty
                | AttemptOutcome::LlmExhausted { .. }
                | AttemptOutcome::LlmCallError => continue,
                AttemptOutcome::VerificationFailed { .. } => {}
            }

            // Escalate strategy AND tier after failed tier-escalated attempt
            if ctx.config.escalate_on_failure {
                current_strategy = ctx.config.next_strategy(current_strategy);
            }
            continue; // Tier-escalated prompt was already sent above
        }

        // The strategy prompt junction — normal path, no tier escalation —
        // is one dispatch call now (issue #333): the loop stopped matching
        // over the variants to pick a builder and simply asks the retry
        // context's door. The Default arm stays loop-side — its skip is
        // selection, not a prompt — and the door never sees that variant.
        if matches!(current_strategy, RetryStrategy::Default) {
            // Re-send original prompt — skip (would be identical to initial)
            warn!("Default retry strategy — skipping (would be identical to initial)");
            result.add_attempt(TranslationAttempt {
                attempt: attempt_num,
                rust_code: initial_translation.rust_code.clone(),
                compiled: false,
                compilation_errors: vec![
                    "Skipped: default strategy would re-send identical prompt".to_string(),
                ],
                tests_passed: 0,
                tests_total: 0,
                failed_tests: Vec::new(),
                retry_strategy: "skip_default".to_string(),
                tokens_used: None,
                context_tier: Some(current_tier.label().to_string()),
            });
            emit_attempt(
                ctx.events,
                &binary,
                &function,
                &result,
                attempt_num,
                "skip_default",
            );
            continue;
        }
        // The escalate posture consults the held report before it burns
        // an attempt (issue #356): an escalate retry that would re-ask
        // the seam for a family the engine itself declares it cannot
        // answer right now can only re-produce today's empty context,
        // so the ladder prunes the strategy and rotates to one that can
        // actually close the unit. The pruning survives as reviewable
        // evidence — an attempt record carrying the ladder's own
        // `pruned_escalate` label and a failure hint naming the family
        // beside the seam's own admission line, riding every following
        // fix prompt's history beside the unit's other failure hints,
        // never a silent skip. Unknown prunes nothing: only a declared
        // `unavailable` blocks this arm, exactly P19's two-directional
        // rule — absence reads unknown, unknown never reads absent.
        if matches!(current_strategy, RetryStrategy::Escalate) {
            let blocked = unavailable_reask_families(ctx.seam_report, ESCALATE_REASK_FAMILIES);
            if !blocked.is_empty() {
                let admission = reask_admission_lines(&blocked);
                warn!(
                    binary = %binary,
                    function,
                    pruned_strategy = %current_strategy,
                    families = %admission,
                    "Escalate retry pruned — the held report says the engine cannot answer a family it would re-ask"
                );
                let evidence = format!("Pruned: escalate would re-ask {admission}");
                failure_history.push(FailureHint::new(attempt_num, "escalate", evidence.clone()));
                result.add_attempt(TranslationAttempt {
                    attempt: attempt_num,
                    rust_code: initial_translation.rust_code.clone(),
                    compiled: false,
                    compilation_errors: vec![evidence],
                    tests_passed: 0,
                    tests_total: 0,
                    failed_tests: Vec::new(),
                    retry_strategy: "pruned_escalate".to_string(),
                    tokens_used: None,
                    context_tier: Some(current_tier.label().to_string()),
                });
                emit_attempt(
                    ctx.events,
                    &binary,
                    &function,
                    &result,
                    attempt_num,
                    "pruned_escalate",
                );
                if ctx.config.escalate_on_failure {
                    current_strategy = ctx.config.next_strategy(current_strategy);
                }
                continue;
            }
        }
        // The wire strategy label is the Display spelling — byte-identical
        // to the literals the old inline arms paired with their prompts.
        let strategy_name = current_strategy.to_string();
        let prompt_req = FixPromptRequest {
            unit: &unit,
            verdict: &verdict,
            history: &failure_history,
            workspace: ctx.workspace,
            source: ctx.source,
            seam_report: ctx.seam_report,
        };
        let prompt = build_fix_prompt(current_strategy, &prompt_req).await;

        let report = run_attempt(
            run,
            &mut result,
            &mut failure_history,
            &unit,
            AttemptPath::StrategyPrompt,
            &strategy_name,
            attempt_num,
            &prompt,
            attempt_start,
        )
        .await;
        route_latest_failure(&result, &report, &mut verdict, &mut fix_code);
        if report.loop_fired {
            // A fired detector ends the chain wherever it lands (#334) —
            // matching the fault record, event and history entry the seam
            // already wrote for the firing attempt.
            break;
        }
        match report.outcome {
            // Today's shape, moved whole: a passing attempt stops the loop
            // right here, and the LLM-failure tails continue without
            // stepping strategy or tier.
            AttemptOutcome::Passed => break,
            AttemptOutcome::LlmEmpty
            | AttemptOutcome::LlmExhausted { .. }
            | AttemptOutcome::LlmCallError => continue,
            AttemptOutcome::VerificationFailed { .. } => {}
        }

        // Escalate strategy and context tier for next attempt. The ladder
        // step has one owner (#334); the gate, the starting strategy and
        // the tier walk stay loop-side policy.
        if ctx.config.escalate_on_failure {
            current_strategy = ctx.config.next_strategy(current_strategy);

            // Escalate context tier to include more decompiler/workspace context.
            // On the next loop iteration the tier-escalated prompt path will
            // be taken (tier_escalated stays false here; it's set when the
            // prompt is actually rebuilt at the top of the next iteration).
            // W2.5: an operator `max_context_tier` constraint caps the walk —
            // escalation stops at the cap instead of going past it.
            // Issue #356: a step onto a tier whose escalated prompt re-asks
            // the seam is escalate-shaped the same way the strategy arm is —
            // if the held report says a re-asked family is answerably
            // unavailable, the step is pruned and its reason survives as a
            // failure hint, while steps that re-ask nothing walk on.
            if let Some(next_tier) = ctx.config.next_tier_within_cap(current_tier) {
                let blocked = if tier_re_asks_seam(next_tier) {
                    unavailable_reask_families(ctx.seam_report, ESCALATE_REASK_FAMILIES)
                } else {
                    Vec::new()
                };
                if !blocked.is_empty() {
                    let admission = reask_admission_lines(&blocked);
                    warn!(
                        binary = %binary,
                        function,
                        old_tier = %current_tier,
                        new_tier = %next_tier,
                        families = %admission,
                        "Context tier escalation pruned — the escalated prompt would re-ask a family the engine cannot answer"
                    );
                    failure_history.push(FailureHint::new(
                        attempt_num,
                        "tier_escalation",
                        format!(
                            "Pruned: tier escalation to {} would re-ask {admission}",
                            next_tier.label()
                        ),
                    ));
                } else {
                    warn!(
                        binary = %binary,
                        function,
                        old_tier = %current_tier,
                        new_tier = %next_tier,
                        "Context tier escalated"
                    );
                    if let Some(em) = ctx.events {
                        let _ = em.emit(ProgressEvent::ContextTierSelected {
                            binary: binary.clone(),
                            function: function.clone(),
                            tier: next_tier.to_string(),
                            tier_label: next_tier.label().to_string(),
                            complexity: current_tier.label().to_string(),
                            api_call_count: 0,
                        });
                    }
                    current_tier = next_tier;
                    tier_escalated = true;
                }
            }
        }
    }

    result
}

/// Route the latest failed candidate into the next prompt (#334): its
/// record's evidence and the seam outcome's structured cases become the
/// verdict, and its own code becomes the unit the next fix repairs. Only
/// attempts that reached verification produce a candidate and a verdict —
/// the LLM-tail outcomes (empty, exhausted, call error) leave both
/// untouched, since there is nothing new to fix.
fn route_latest_failure(
    result: &RetryResult,
    report: &AttemptReport,
    verdict: &mut UnitVerdict,
    fix_code: &mut String,
) {
    if matches!(report.outcome, AttemptOutcome::VerificationFailed { .. }) {
        *verdict = UnitVerdict::from_failure(result, &report.outcome);
        *fix_code = result
            .attempts
            .last()
            .expect("the seam records every verified attempt")
            .rust_code
            .clone();
    }
}

/// Call the LLM with periodic progress keepalive events.
///
/// While the HTTP request is in flight, emits `LlmCallInProgress` events every
/// 30 seconds so the caller (and the web UI) know the request hasn't hung.
pub(crate) fn llm_call_with_keepalive<'a>(
    llm: &'a LlmClient,
    messages: &'a [LlmMessage],
    binary: &'a calxgloss_types::BinaryIdentity,
    function: &'a str,
    attempt_num: u32,
    retry_strategy: &str,
    events: Option<&'a TranslationEvents>,
) -> impl std::future::Future<Output = Result<calxgloss_llm::LlmResponse, LlmError>> + 'a {
    let binary = binary.clone();
    let function = function.to_string();
    let messages = messages.to_vec();
    let events = events.cloned();
    let attempt = attempt_num;
    let strategy = retry_strategy.to_string();

    async move {
        let keepalive_interval = std::time::Duration::from_secs(30);

        // Spawn a keepalive task that emits progress events every 30s
        let events_clone = events.clone();
        let dll_kp = binary.clone();
        let function_kp = function.clone();
        let strategy_kp = strategy.clone();
        let attempt_kp = attempt;
        let keepalive_handle = tokio::task::spawn(async move {
            let mut elapsed = keepalive_interval;
            if let Some(em) = events_clone {
                loop {
                    tokio::time::sleep(keepalive_interval).await;
                    let secs = elapsed.as_secs();
                    let _ = em.emit(ProgressEvent::LlmCallInProgress {
                        binary: dll_kp.clone(),
                        function: function_kp.clone(),
                        attempt: attempt_kp,
                        retry_strategy: strategy_kp.clone(),
                        elapsed_secs: secs,
                    });
                    elapsed += keepalive_interval;
                }
            }
        });

        // Race the HTTP request against the keepalive handle (which runs forever)
        let result = llm.complete(&messages).await;

        // Cancel the keepalive task — drop the handle to stop the loop
        keepalive_handle.abort();

        match &result {
            Ok(_) => {}
            Err(e) => {
                if let Some(em) = events {
                    let _ = em.emit(ProgressEvent::LlmCallFailed {
                        binary: binary.clone(),
                        function: function.clone(),
                        attempt,
                        retry_strategy: strategy.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        result
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retry::is_edge_case_failure;
    use crate::retry::{
        EscalatePromptCtx, FixPromptCtx, build_compile_fix_prompt,
        build_failure_informed_compile_fix_prompt, build_failure_informed_edge_case_fix_prompt,
        build_failure_informed_escalate_prompt, build_failure_informed_test_fix_prompt,
        build_test_fix_prompt,
    };

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.retry_strategy, RetryStrategy::CompileFix);
        assert!(config.escalate_on_failure);
    }

    #[test]
    fn test_translation_attempt_is_successful() {
        let mut attempt = TranslationAttempt {
            attempt: 1,
            rust_code: "fn foo() {}".to_string(),
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 5,
            tests_total: 5,
            failed_tests: Vec::new(),
            retry_strategy: "initial".to_string(),
            tokens_used: Some(1024),
            context_tier: None,
        };
        assert!(attempt.is_successful());

        attempt.tests_passed = 4;
        assert!(!attempt.is_successful());

        // No tests = successful by definition
        attempt.tests_passed = 0;
        attempt.tests_total = 0;
        assert!(attempt.is_successful());

        // But code that doesn't compile is never successful, even with no tests.
        attempt.compiled = false;
        assert!(!attempt.is_successful());
    }

    #[test]
    fn test_retry_result_new() {
        let result = RetryResult::new();
        assert!(!result.success);
        assert!(result.rust_code.is_none());
        assert!(result.attempts.is_empty());
    }

    #[test]
    fn test_retry_result_add_successful_attempt() {
        let mut result = RetryResult::new();
        result.add_attempt(TranslationAttempt {
            attempt: 1,
            rust_code: "fn foo() -> i32 { 42 }".to_string(),
            compiled: true,
            compilation_errors: Vec::new(),
            tests_passed: 3,
            tests_total: 3,
            failed_tests: Vec::new(),
            retry_strategy: "initial".to_string(),
            tokens_used: Some(512),
            context_tier: None,
        });
        assert!(result.success);
        assert!(result.rust_code.is_some());
        assert_eq!(
            result.rust_code.as_deref().unwrap(),
            "fn foo() -> i32 { 42 }"
        );
        assert_eq!(result.success_strategy.as_deref().unwrap(), "initial");
    }

    #[test]
    fn test_build_compile_fix_prompt() {
        let prompt = build_compile_fix_prompt(&FixPromptCtx {
            function_name: "entry".to_string(),
            dll_name: "eqmain.dll".to_string(),
            original_rust_code: "fn entry() { __security_init_cookie(); }".to_string(),
            compilation_errors: vec![
                "error[E0425]: not found: `__security_init_cookie`".to_string(),
            ],
            failed_tests: Vec::new(),
            history: Vec::new(),
        });
        assert!(prompt.contains("entry"));
        assert!(prompt.contains("eqmain.dll"));
        assert!(prompt.contains("__security_init_cookie"));
        assert!(prompt.contains("E0425"));
    }

    #[test]
    fn test_build_test_fix_prompt() {
        let prompt = build_test_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            compilation_errors: Vec::new(),
            failed_tests: vec![
                "Test 0: expected 42, got 10 — input was 10".to_string(),
                "Test 1: expected 0, got 5 — input was 5".to_string(),
            ],
            history: Vec::new(),
        });
        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("expected 42"));
        assert!(prompt.contains("expected 0"));
    }

    #[test]
    fn test_is_edge_case_failure_boundary() {
        let failed = vec![
            "Test 0: expected 0, got 1 — input was 0 (zero check)".to_string(),
            "Test 1: expected 2147483647, got 0 — input was max (overflow)".to_string(),
        ];
        assert!(is_edge_case_failure(&failed, 0, 2));
    }

    #[test]
    fn test_is_edge_case_failure_normal_failure() {
        let failed = vec![
            "Test 0: expected 100, got 50 — wrong multiplication".to_string(),
            "Test 1: expected 200, got 100 — wrong addition".to_string(),
        ];
        assert!(!is_edge_case_failure(&failed, 0, 2));
    }

    #[test]
    fn test_is_edge_case_failure_mixed() {
        // Mixed: 2 boundary + 1 normal — should be edge case (majority)
        let failed = vec![
            "Test 0: expected 0, got 1 — zero input".to_string(),
            "Test 1: expected 0, got -1 — negative input".to_string(),
            "Test 2: expected 100, got 50 — wrong value".to_string(),
        ];
        assert!(is_edge_case_failure(&failed, 0, 3));
    }

    #[test]
    fn test_is_edge_case_failure_all_passed() {
        let failed: Vec<String> = vec![];
        assert!(!is_edge_case_failure(&failed, 5, 5));
    }

    // ============================================================
    // Failure-informed prompt builder tests
    // ============================================================

    #[test]
    fn test_failure_informed_compile_fix_includes_history() {
        let hints = vec![
            FailureHint::new(
                1,
                "compile_fix",
                "Compilation failed: E0425 — `__security_init_cookie` not found",
            ),
            FailureHint::new(2, "test_fix", "Wrong result on boundary input"),
        ];

        let prompt = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
            function_name: "entry".to_string(),
            dll_name: "eqmain.dll".to_string(),
            original_rust_code: "fn entry() { __security_init_cookie(); }".to_string(),
            compilation_errors: vec![
                "error[E0425]: not found: `__security_init_cookie`".to_string(),
            ],
            failed_tests: Vec::new(),
            history: hints,
        });

        assert!(prompt.contains("entry"));
        assert!(prompt.contains("eqmain.dll"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Attempt #1"));
        assert!(prompt.contains("compile_fix"));
        assert!(prompt.contains("Attempt #2"));
        assert!(prompt.contains("test_fix"));
    }

    #[test]
    fn test_failure_informed_compile_fix_empty_history() {
        let prompt = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
            function_name: "entry".to_string(),
            dll_name: "eqmain.dll".to_string(),
            original_rust_code: "fn entry() { }".to_string(),
            compilation_errors: vec!["error[E0425]: not found: `foo`".to_string()],
            failed_tests: Vec::new(),
            history: Vec::new(), // empty history — should not include history section
        });

        assert!(prompt.contains("entry"));
        assert!(!prompt.contains("PREVIOUS ATTEMPT HISTORY"));
    }

    #[test]
    fn test_failure_informed_test_fix_includes_history() {
        let hints = vec![FailureHint::new(
            1,
            "compile_fix",
            "Compilation failed: E0412",
        )];

        let prompt = build_failure_informed_test_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: "fn draw_sprite(x: i32) -> i32 { x }".to_string(),
            compilation_errors: Vec::new(),
            failed_tests: vec!["Test 0: expected 42, got 10 — input was 10".to_string()],
            history: hints,
        });

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("game_logic.dll"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("compile_fix"));
        assert!(prompt.contains("Compilation failed: E0412"));
    }

    #[test]
    fn test_failure_informed_edge_case_fix_includes_history() {
        let hints = vec![
            FailureHint::new(1, "test_fix", "Wrong result on zero input"),
            FailureHint::new(2, "escalate", "Still wrong on zero after adding context"),
        ];

        let failed_tests = vec![calxgloss_prompts::EdgeCaseTest {
            index: 1,
            inputs: serde_json::json!({"x": 0}),
            expected: serde_json::json!(0),
            actual: serde_json::json!(1),
            error: "Expected 0, got 1".to_string(),
            disassembly_hints: "cmp eax, 0\nje .zero_branch".to_string(),
        }];

        let prompt = build_failure_informed_edge_case_fix_prompt(
            &FixPromptCtx {
                function_name: "DrawSprite".to_string(),
                dll_name: "game_logic.dll".to_string(),
                original_rust_code: "fn draw_sprite(x: i32) -> i32 { x + 1 }".to_string(),
                compilation_errors: Vec::new(),
                failed_tests: Vec::new(),
                history: hints,
            },
            &failed_tests,
        );

        assert!(prompt.contains("DrawSprite"));
        assert!(prompt.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt.contains("Learn from past failures"));
    }

    // ─── Attempt-duration recording (issue #64) ──────────────────────

    /// A fake LLM server that sleeps ~1.1s before answering with empty code
    /// and a token count, so the retry loop's wall-clock measurement for the
    /// attempt is guaranteed to be at least one second. Returns the base URL
    /// to point an [`LlmClient`] at.
    async fn fake_llm() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake LLM should bind");
        let addr = listener.local_addr().expect("fake LLM address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    // Make the attempt measurably slow so the recorded
                    // duration is >= 1s rather than rounding to 0.
                    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                    let body = r#"{"choices":[{"message":{"role":"assistant","content":""}}],"usage":{"completion_tokens":123,"total_tokens":123}}"#;
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

    #[tokio::test]
    async fn retry_loop_records_attempt_duration_in_token_usage_log() {
        let ws = tempfile::TempDir::new().expect("temp workspace");

        // Broken initial code → attempt 1 fails compile → retry loop runs.
        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };

        let llm_base = fake_llm().await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let config = RetryConfig {
            max_attempts: 2,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };

        let seam_report = calxgloss_types::CapabilityReport::default();
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: None,
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &[],
            seam_report: &seam_report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;
        assert!(
            !result.success,
            "the canned LLM returns empty code; attempts={:?}",
            result.attempts
        );

        let log = calxgloss_analysis::TokenUsageLogger::new(ws.path())
            .load()
            .expect("token usage log should exist");

        let entry = log
            .entries
            .iter()
            .find(|e| e.attempt == 2)
            .expect("attempt 2 should be logged");
        assert_eq!(entry.strategy, "compile_fix");
        assert_eq!(entry.tokens_used, 123);
        assert!(
            entry.duration_secs.is_some_and(|d| d >= 1),
            "attempt duration should be recorded and >= 1s, got {:?}",
            entry.duration_secs
        );
    }

    // ─── The loop rides the seam: today's event stream, zero divergence ──
    // (issue #332 — the deleted probe's absence is pinned here too)

    /// A canned LLM server answering the first call with broken code and
    /// every later call with code that compiles — the canned failing-then-
    /// succeeding run the event stream is captured over.
    async fn flaky_llm() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("flaky LLM should bind");
        let addr = listener.local_addr().expect("flaky LLM address");
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_server = calls;
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let calls = calls_server.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let content = if n == 0 {
                        "fn draw_sprite(x: i32) -> i32 { let y: = ; x }"
                    } else {
                        "fn draw_sprite(x: i32) -> i32 { x }"
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

    #[tokio::test]
    async fn retry_loop_streams_todays_event_order_and_records_no_divergence() {
        let ws = tempfile::TempDir::new().expect("temp workspace");

        // Broken initial code → attempt 1 fails compile; attempt 2 gets the
        // canned broken fix (verification fails, ladder stays put because
        // escalation is off); attempt 3 gets the canned compiling fix and
        // the run stops passed.
        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };

        let llm_base = flaky_llm().await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let fault_logger = calxgloss_analysis::FaultLogger::new(ws.path());
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let config = RetryConfig {
            max_attempts: 3,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };

        let seam_report = calxgloss_types::CapabilityReport::default();
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: Some(&events),
            resource_detector: None,
            fault_logger: Some(&fault_logger),
            reviewer_hints: &[],
            seam_report: &seam_report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;
        assert!(
            result.success,
            "the canned fix should pass on attempt 3, attempts={:?}",
            result.attempts
        );
        assert_eq!(result.attempts.len(), 3);

        // The run is over — everything published is queued; drain the stream.
        let mut captured: Vec<calxgloss_types::ProgressEvent> = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }

        // Today's per-attempt ordering on both retry attempts: every LLM
        // attempt streams request → call-start → response → completed.
        let streamed: Vec<(u32, &'static str)> = captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest { attempt, .. } => Some((*attempt, "request")),
                ProgressEvent::LlmCallStart { attempt, .. } => Some((*attempt, "call-start")),
                ProgressEvent::LlmResponse { attempt, .. } => Some((*attempt, "response")),
                ProgressEvent::TranslationAttemptCompleted { attempt, .. } => {
                    Some((*attempt, "completed"))
                }
                _ => None,
            })
            .collect();
        for num in [2u32, 3] {
            let per_attempt: Vec<&str> = streamed
                .iter()
                .filter(|(a, _)| *a == num)
                .map(|(_, name)| *name)
                .collect();
            assert_eq!(
                per_attempt,
                vec!["request", "call-start", "response", "completed"],
                "attempt {num} should stream request → call-start → response → completed, full stream: {streamed:?}"
            );
        }

        // Today's payloads on the completion events: strategy names and the
        // verdicts, attempt 1 riding verify_and_record untouched.
        let completions: Vec<(u32, String, bool)> = captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::TranslationAttemptCompleted {
                    attempt,
                    retry_strategy,
                    success,
                    ..
                } => Some((*attempt, retry_strategy.clone(), *success)),
                _ => None,
            })
            .collect();
        assert_eq!(
            completions,
            vec![
                (1, "initial".to_string(), false),
                (2, "compile_fix".to_string(), false),
                (3, "compile_fix".to_string(), true),
            ]
        );

        // #333: the dispatched compile_fix prompt equals the pre-adapter
        // inline arm's result byte for byte — same recipe, same inputs,
        // demanded identical.
        let sent: std::collections::BTreeMap<u32, String> = captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => Some((*attempt, prompt.clone())),
                _ => None,
            })
            .collect();
        let expected2 = build_compile_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
            compilation_errors: result.attempts[0].compilation_errors.clone(),
            failed_tests: Vec::new(),
            history: Vec::new(),
        });
        assert_eq!(
            sent[&2], expected2,
            "the dispatched compile_fix prompt must be byte-identical to the pre-adapter arm's"
        );
        // By attempt 3 the seam's push from attempt 2's failed verification
        // seeds the history, and the verdict is attempt 2's own record
        // (#334's routing — the canned code matches the initial one here,
        // bytes and all), so the informed variant is the plain variant's
        // only difference — rebuild it the same way and demand equality.
        let expected3 = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: result.attempts[1].rust_code.clone(),
            compilation_errors: result.attempts[1].compilation_errors.clone(),
            failed_tests: Vec::new(),
            history: vec![FailureHint::new(
                2,
                "compile_fix",
                format!(
                    "Compilation failed: {}",
                    result.attempts[1].compilation_errors.join("; ")
                ),
            )],
        });
        assert_eq!(
            sent[&3], expected3,
            "attempt 3's dispatched informed-variant prompt must match the pre-adapter recipe bytes"
        );

        // The deleted probes fabricated all-true edge results against a
        // detector that reports only failing edges — they could never fire.
        // A passing verified run pins their absence: zero divergence events
        // on the stream and zero divergence faults in the log.
        assert!(
            !captured
                .iter()
                .any(|ev| matches!(ev, ProgressEvent::BehaviorDivergenceDetected { .. })),
            "no divergence event may appear on a passing verified run"
        );
        let faults = calxgloss_analysis::FaultLogger::new(ws.path())
            .load()
            .map(|l| l.entries)
            .unwrap_or_default();
        assert!(
            !faults.iter().any(|f| matches!(
                f.category,
                calxgloss_types::FaultCategory::BehaviorDivergence
            )),
            "no divergence fault may be recorded, faults={faults:?}"
        );
    }

    /// A canned LLM server alternating between the initial broken code and
    /// a broken variant one identifier apart on every call — every attempt
    /// still fails verification, so the strategy ladder walks its full
    /// cycle, but consecutive attempts never produce the same output three
    /// times running and the infinite-loop detector — which now stops the
    /// chain wherever it fires (#334) — stays quiet through the run.
    async fn alternating_broken_llm() -> String {
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

    #[tokio::test]
    async fn strategy_ladder_walks_the_full_cycle_quoting_each_attempts_own_verdict() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let broken = "fn draw_sprite(x: i32) -> i32 { let y: = ; x }";

        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: broken.to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };

        let llm_base = alternating_broken_llm().await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();

        // The cap pins the tier at Signature — Signature's next tier would
        // breach it — so no attempt ever rides the tier-escalated path and
        // the ladder's compile_fix → test_fix → escalate walk is what
        // dispatches all three retry prompts.
        let config = RetryConfig {
            max_attempts: 6,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: true,
            max_context_tier: Some(calxgloss_types::ContextTier::Signature),
        };

        let seam_report = calxgloss_types::CapabilityReport::default();
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: Some(&events),
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &[],
            seam_report: &seam_report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;
        assert!(
            !result.success,
            "the canned code is broken on every attempt"
        );
        assert_eq!(result.attempts.len(), 6);
        assert_eq!(result.attempts[1].retry_strategy, "compile_fix");
        assert_eq!(result.attempts[2].retry_strategy, "test_fix");
        assert_eq!(result.attempts[3].retry_strategy, "escalate");
        assert_eq!(result.attempts[4].retry_strategy, "edge_case_fix");
        assert_eq!(result.attempts[5].retry_strategy, "compile_fix");

        let mut captured: Vec<calxgloss_types::ProgressEvent> = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }
        assert!(
            !captured
                .iter()
                .any(|ev| matches!(ev, ProgressEvent::InfiniteLoopDetected { .. })),
            "alternating outputs must not streak the detector to a fire — one would stop the chain (#334)"
        );
        let sent: std::collections::BTreeMap<u32, String> = captured
            .iter()
            .filter_map(|ev| match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => Some((*attempt, prompt.clone())),
                _ => None,
            })
            .collect();

        // #334: each fix prompt is built from the verdict of the code it
        // repairs — the previous attempt's recorded evidence, routed — and
        // replaces that attempt's own code. Rebuild every prompt through
        // the builders from the recorded routed inputs and demand byte
        // equality; the recipe reads the loop's own records, so it pins
        // the routing exactly.

        // Attempt 2, compile_fix — history still empty, plain variant;
        // the verdict is the initial attempt's own record.
        let initial_errors = result.attempts[0].compilation_errors.clone();
        assert!(
            !initial_errors.is_empty(),
            "the broken start must not compile"
        );
        let expected = build_compile_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: broken.to_string(),
            compilation_errors: initial_errors.clone(),
            failed_tests: Vec::new(),
            history: Vec::new(),
        });
        assert_eq!(sent[&2], expected, "attempt 2 compile_fix prompt");

        // Attempt 3, test_fix — attempt 2's candidate (the canned code,
        // identical to the initial) failed, so this prompt quotes THAT
        // record's evidence and repairs that code; the seam's push after
        // attempt 2 seeds the history. No re-verification feeds this
        // prompt anymore — the record is the payload.
        let history3 = vec![FailureHint::new(
            2,
            "compile_fix",
            format!(
                "Compilation failed: {}",
                result.attempts[1].compilation_errors.join("; ")
            ),
        )];
        let expected = build_failure_informed_test_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: result.attempts[1].rust_code.clone(),
            compilation_errors: Vec::new(),
            failed_tests: result.attempts[1].failed_tests.clone(),
            history: history3.clone(),
        });
        assert_eq!(sent[&3], expected, "attempt 3 test_fix prompt");

        // Attempt 4, escalate — attempt 3's candidate was the *other*
        // broken variant, so this prompt quotes the variant's own compile
        // errors and repairs the variant's code, and the history carries
        // both pushes.
        let history4: Vec<FailureHint> = history3
            .into_iter()
            .chain(std::iter::once(FailureHint::new(
                3,
                "test_fix",
                format!(
                    "Compilation failed: {}",
                    result.attempts[2].compilation_errors.join("; ")
                ),
            )))
            .collect();
        let variant_errors = result.attempts[2].compilation_errors.clone();
        let failure_description = format!(
            "Compilation failed with {} error(s):\n\n{}",
            variant_errors.len(),
            variant_errors.join("\n\n")
        );
        let expected = build_failure_informed_escalate_prompt(EscalatePromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: result.attempts[2].rust_code.clone(),
            failure_description,
            source: source.clone(),
            address: 0,
            call_graph: Vec::new(),
            history: history4.clone(),
            call_graph_context: Vec::new(),
            workspace: Some(ws.path().to_path_buf()),
            seam_report: calxgloss_types::CapabilityReport::default(),
        })
        .await;
        assert_eq!(sent[&4], expected, "attempt 4 escalate prompt");

        // Attempt 5, edge_case_fix — attempt 4's candidate was the initial
        // variant again and did not compile, so there are no structured
        // failing cases to carry: nothing fabricates a placeholder from a
        // re-run anymore, the payload is simply the verdict's empty slice.
        let history5: Vec<FailureHint> = history4
            .into_iter()
            .chain(std::iter::once(FailureHint::new(
                4,
                "escalate",
                format!(
                    "Compilation failed: {}",
                    result.attempts[3].compilation_errors.join("; ")
                ),
            )))
            .collect();
        let expected = build_failure_informed_edge_case_fix_prompt(
            &FixPromptCtx {
                function_name: "DrawSprite".to_string(),
                dll_name: "game_logic.dll".to_string(),
                original_rust_code: result.attempts[3].rust_code.clone(),
                compilation_errors: Vec::new(),
                failed_tests: Vec::new(),
                history: history5.clone(),
            },
            &[],
        );
        assert_eq!(sent[&5], expected, "attempt 5 edge_case_fix prompt");

        // Attempt 6, the cycle back to compile_fix — attempt 5's variant
        // verdict and code, with the full history.
        let history6: Vec<FailureHint> = history5
            .into_iter()
            .chain(std::iter::once(FailureHint::new(
                5,
                "edge_case_fix",
                format!(
                    "Compilation failed: {}",
                    result.attempts[4].compilation_errors.join("; ")
                ),
            )))
            .collect();
        let expected = build_failure_informed_compile_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: result.attempts[4].rust_code.clone(),
            compilation_errors: result.attempts[4].compilation_errors.clone(),
            failed_tests: Vec::new(),
            history: history6,
        });
        assert_eq!(sent[&6], expected, "attempt 6 compile_fix prompt");

        // #334's routing, visible in the wire bytes: attempt 4's fix slot
        // names attempt 3's own variant — the initial code it replaces is
        // gone from that section.
        let section4 = original_section(&sent[&4]);
        assert!(
            section4.contains("let z: = ; x"),
            "the escalate prompt must repair attempt 3's own code, not the initial one:\n{section4}"
        );
        assert!(
            !section4.contains("let y: = ; x"),
            "the replaced initial code must not sit in attempt 4's repair slot:\n{section4}"
        );
    }

    /// The "ORIGINAL TRANSLATION (FAILED)" section of a fix prompt — the
    /// code the prompt tells the LLM to replace.
    fn original_section(prompt: &str) -> &str {
        const HEADER: &str = "## ORIGINAL TRANSLATION (FAILED)";
        let start = prompt
            .find(HEADER)
            .expect("fix prompts carry the failing code section");
        let rest = &prompt[start + HEADER.len()..];
        let end = rest.find("\n## ").unwrap_or(rest.len());
        &rest[..end]
    }

    /// A canned LLM server answering every call with the same code — the
    /// same-output run that streaks the infinite-loop detector, or the
    /// compiling-but-failing run a suite pins over.
    async fn same_code_llm(content: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("canned LLM should bind");
        let addr = listener.local_addr().expect("canned LLM address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
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

    /// A canned LLM server naming each reply with its own marker — every
    /// attempt fails to compile for its OWN reason (an unresolved name),
    /// so each attempt's recorded errors quote its own source and the
    /// routing can be told apart from the initial translation's evidence.
    async fn marker_rotating_llm() -> String {
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
                    let content = if n == 0 {
                        "fn draw_sprite(x: i32) -> i32 { marker_alpha(x) }"
                    } else {
                        "fn draw_sprite(x: i32) -> i32 { marker_beta(x) }"
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

    /// #334 criterion 1, end to end: the initial translation rides the
    /// seam with its baseline suite — a merely-compiling unit with a
    /// non-empty suite is NOT done. The attempt-1 record carries the
    /// suite's real counts, the run reports failure, and the retry prompt
    /// is the test-fix one built from that verdict's payload. (The scratch
    /// toolchain's suite runner currently fails to build — a verify-crate
    /// defect out of this ticket's scope — so the honest verdict lands as
    /// 0-of-1 with no per-case lines; what is pinned is that the suite was
    /// consulted at all and the record tells the truth about it, which is
    /// what closes the compile-only success hole.)
    #[tokio::test]
    async fn a_compiling_unit_with_a_failing_suite_is_not_reported_success() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let good = "fn draw_sprite(x: i32) -> i32 { x + 1 }";

        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: good.to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: vec![calxgloss_types::TestCase {
                inputs: serde_json::json!([5]),
                expected_return: serde_json::json!(4),
                expected_side_effects: Vec::new(),
            }],
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };

        // The canned fix compiles too — with the runner defect nothing can
        // pass, and max_attempts 2 keeps the run inside the detector's
        // streak threshold whatever the code.
        let llm_base = same_code_llm(good).await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();

        let config = RetryConfig {
            max_attempts: 2,
            retry_strategy: RetryStrategy::TestFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };
        let seam_report = calxgloss_types::CapabilityReport::default();
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: Some(&events),
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &[],
            seam_report: &seam_report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;

        assert!(
            !result.success,
            "a compiling unit whose baseline suite failed is not done — the compile-only hole is closed"
        );
        assert_eq!(
            result.attempts.len(),
            2,
            "the failing suite rides into a retry"
        );
        let first = &result.attempts[0];
        assert_eq!(first.retry_strategy, "initial");
        assert!(first.compiled, "the code does compile");
        assert_eq!(
            first.tests_total, 1,
            "the attempt-1 record carries the suite's real size"
        );
        assert_eq!(
            first.tests_passed, 0,
            "and honestly reports the suite as failed"
        );
        assert_eq!(result.attempts[1].retry_strategy, "test_fix");

        // The retry prompt is the test-fix one, byte-built from the
        // attempt-1 verdict's payload — the record's failed-test lines are
        // the payload, empty under the runner defect and named as such by
        // the builder's fallback.
        let sent: std::collections::BTreeMap<u32, String> = {
            let mut captured = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                captured.push(ev);
            }
            captured
                .iter()
                .filter_map(|ev| match ev {
                    ProgressEvent::LlmRequest {
                        attempt, prompt, ..
                    } => Some((*attempt, prompt.clone())),
                    _ => None,
                })
                .collect()
        };
        let expected = build_test_fix_prompt(&FixPromptCtx {
            function_name: "DrawSprite".to_string(),
            dll_name: "game_logic.dll".to_string(),
            original_rust_code: first.rust_code.clone(),
            compilation_errors: Vec::new(),
            failed_tests: first.failed_tests.clone(),
            history: Vec::new(),
        });
        assert_eq!(
            sent[&2], expected,
            "the retry prompt is built from the initial verdict's payload"
        );
    }

    /// #334 criterion 2, pinned through the captured request bodies: once
    /// attempt N has failed, attempt N+1's prompt names N's OWN code and
    /// quotes N's OWN failure evidence — the initial translation is no
    /// longer the repair target or the evidence source. (The structured
    /// failing cases of a tests-failed verdict ride the same routing;
    /// they are pinned at seam and adapter level because this toolchain's
    /// suite runner cannot produce real case lines — defect note above.)
    #[tokio::test]
    async fn fix_prompts_quote_the_latest_failed_attempts_code_and_evidence() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let start = "fn draw_sprite(x: i32) -> i32 { let q: = ; x }";

        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: start.to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };

        let llm_base = marker_rotating_llm().await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();

        let config = RetryConfig {
            max_attempts: 3,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };
        let seam_report = calxgloss_types::CapabilityReport::default();
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: Some(&events),
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &[],
            seam_report: &seam_report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;
        assert!(!result.success, "every canned variant is broken");
        assert_eq!(result.attempts.len(), 3);

        let sent: std::collections::BTreeMap<u32, String> = {
            let mut captured = Vec::new();
            while let Ok(ev) = rx.try_recv() {
                captured.push(ev);
            }
            captured
                .iter()
                .filter_map(|ev| match ev {
                    ProgressEvent::LlmRequest {
                        attempt, prompt, ..
                    } => Some((*attempt, prompt.clone())),
                    _ => None,
                })
                .collect()
        };

        // Attempt 2 repairs the initial code — nothing has replaced it yet.
        let section2 = original_section(&sent[&2]);
        assert!(
            section2.contains("let q: = ; x"),
            "attempt 2 repairs the initial translation:\n{section2}"
        );

        // Attempt 3 repairs attempt 2's code — the alpha variant — and
        // quotes attempt 2's own errors: the marker names both the repair
        // slot and the error text, so it occurs at least twice.
        let section3 = original_section(&sent[&3]);
        assert!(
            section3.contains("marker_alpha"),
            "attempt 3 must repair attempt 2's own code:\n{section3}"
        );
        assert!(
            !section3.contains("let q: = ; x"),
            "the initial code is gone from attempt 3's repair slot:\n{section3}"
        );
        assert!(
            sent[&3].matches("marker_alpha").count() >= 2,
            "attempt 3's prompt must also quote attempt 2's own compile errors:\n{}",
            sent[&3]
        );
    }

    /// #334's "the verifier is asked exactly once per candidate code",
    /// held at the source level: the retry loop module's own body never
    /// asks the verifier anything — every verification belongs to the
    /// attempt seam, and the re-verification arms are gone for good.
    #[test]
    fn retry_loop_never_reverifies_a_previous_attempts_code() {
        let src = include_str!("retry_loop.rs");
        let body = src
            .split("#[cfg(test)]")
            .next()
            .expect("a module body ahead of the test module");
        let needle = concat!(".", "verify", "(");
        assert!(
            !body.contains(needle),
            "the retry loop body must not call the verifier itself (#334): the seam owns every verification"
        );
    }

    /// #334: a fired infinite-loop detector ends the chain wherever it
    /// lands. Same canned code as the initial translation on every call —
    /// the initial attempt rides the detector too, so the third straight
    /// identical failing output fires at attempt 3. Today's loop merely
    /// observed the mid-chain fire; this one stops on it, leaving its one
    /// event and one fault record as the whole story past attempt 3.
    #[tokio::test]
    async fn a_fired_loop_detector_ends_the_chain_where_it_lands() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let broken = "fn draw_sprite(x: i32) -> i32 { let y: = ; x }";

        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: broken.to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };

        let llm_base = same_code_llm(broken).await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna);
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let events = calxgloss_types::TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let fault_logger = calxgloss_analysis::FaultLogger::new(ws.path());

        let config = RetryConfig {
            max_attempts: 6,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: false,
            max_context_tier: None,
        };
        let seam_report = calxgloss_types::CapabilityReport::default();
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: Some(&events),
            resource_detector: None,
            fault_logger: Some(&fault_logger),
            reviewer_hints: &[],
            seam_report: &seam_report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;

        assert!(!result.success, "every output is the same broken code");
        assert_eq!(
            result.attempts.len(),
            3,
            "the chain stops at the firing attempt — no attempt 4"
        );

        let mut loop_events = 0;
        let mut requests = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, ProgressEvent::InfiniteLoopDetected { .. }) {
                loop_events += 1;
            }
            if let ProgressEvent::LlmRequest { attempt, .. } = ev {
                requests.push(attempt);
            }
        }
        assert_eq!(loop_events, 1, "exactly one InfiniteLoopDetected event");
        assert_eq!(
            requests,
            vec![2, 3],
            "no fix request is built past the fire"
        );

        let faults = fault_logger.load().expect("fault log").entries;
        assert_eq!(faults.len(), 1, "one fault record for the fired detector");
        assert!(
            matches!(
                faults[0].category,
                calxgloss_types::FaultCategory::InfiniteLoop
            ),
            "the one fault is the loop fire, faults={faults:?}"
        );
    }

    // ---- #356: the capability-aware ladder — an escalate-shaped retry that
    // would re-ask a family the report calls unavailable prunes/rotates, with
    // the decision itself surviving as reviewable evidence ----

    /// A hand-declared report stating `id` is unanswerable right now, with the
    /// engine's own reason. The engine never declares this family, so a ladder
    /// that walks differently is demonstrably deciding off the held report, not
    /// the live seam.
    fn unavailable_report(id: &str, reason: &str) -> calxgloss_types::CapabilityReport {
        calxgloss_types::CapabilityReport {
            families: vec![calxgloss_types::FamilyCapability {
                id: id.to_string(),
                status: calxgloss_types::AvailabilityStatus::Unavailable,
                reason: Some(reason.to_string()),
            }],
        }
    }

    /// One whole report-driven ladder run: what the walk recorded, what it
    /// asked of the LLM and the seam, and what the stream said it chose.
    struct CapLadderRun {
        result: RetryResult,
        kuna: calxgloss_kuna::KunaSource,
        prompts: std::collections::BTreeMap<u32, String>,
        completions: Vec<(u32, String)>,
        tier_steps: Vec<String>,
    }

    async fn run_ladder_with_report(
        report: calxgloss_types::CapabilityReport,
        max_attempts: u32,
        max_context_tier: Option<calxgloss_types::ContextTier>,
    ) -> CapLadderRun {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        // Today's ladder-pin unit, with a real fixture function in the call
        // graph so a rung that does re-ask the seam leaves its mark in the
        // engine-call log.
        let translation = Translation {
            binary: "game_logic.dll".to_string().into(),
            function: "DrawSprite".to_string(),
            function_address: None,
            rust_code: "fn draw_sprite(x: i32) -> i32 { let y: = ; x }".to_string(),
            prompt_used: "prompt".to_string(),
            model: "test-model".to_string(),
            tokens_used: Some(10),
            baseline_tests: Vec::new(),
            call_graph: vec!["UpdateScene".to_string()],
            disassembly_hints: Vec::new(),
            context_tier: calxgloss_types::ContextTier::Signature,
            call_graph_context: Vec::new(),
        };
        let llm_base = alternating_broken_llm().await;
        let llm = LlmClient::from_url(&llm_base, "test-model").expect("llm client");
        let target = calxgloss_testfixtures::load_target().expect("fixture target");
        let kuna = calxgloss_kuna::KunaSource::load(target.path())
            .expect("the fixture must load for scanning with Kuna");
        // The clone shares the engine-call log — this handle reads what the
        // batch's source wrote.
        let source = calxgloss_decomp::PipelineSource::Kuna(kuna.clone());
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let events = calxgloss_types::TranslationEvents::new(256);
        let mut rx = events.subscribe();
        let config = RetryConfig {
            max_attempts,
            max_context_tier,
            ..RetryConfig::default()
        };
        let ctx = RetryLoopCtx {
            verifier: &verifier,
            llm: &llm,
            source: &source,
            config: &config,
            workspace: Some(ws.path()),
            events: Some(&events),
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &[],
            seam_report: &report,
        };

        let result = try_translate_with_retry(translation, &ctx).await;
        let mut prompts = std::collections::BTreeMap::new();
        let mut completions = Vec::new();
        let mut tier_steps = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            match ev {
                ProgressEvent::LlmRequest {
                    attempt, prompt, ..
                } => {
                    prompts.insert(attempt, prompt);
                }
                ProgressEvent::TranslationAttemptCompleted {
                    attempt,
                    retry_strategy,
                    ..
                } => completions.push((attempt, retry_strategy)),
                ProgressEvent::ContextTierSelected { tier_label, .. } => {
                    tier_steps.push(tier_label)
                }
                _ => {}
            }
        }
        CapLadderRun {
            result,
            kuna,
            prompts,
            completions,
            tier_steps,
        }
    }

    /// The strategy walk's labels, in order — the shape of the ladder on the wire.
    fn walk(result: &RetryResult) -> Vec<&str> {
        result
            .attempts
            .iter()
            .map(|a| a.retry_strategy.as_str())
            .collect()
    }

    /// A declared `Unavailable` on a family the escalate rung re-asks is the
    /// one answer that prunes it: the rung rotates instead, and the prune
    /// reads as reviewable evidence in the fault/hint channel — never a
    /// silent skip, and never by asking the seam again.
    #[tokio::test]
    async fn a_report_calling_the_re_asked_family_unavailable_prunes_the_escalate_rung() {
        let run = run_ladder_with_report(
            unavailable_report("decompilation", "Zanthoxylum builds never produce a body"),
            6,
            Some(calxgloss_types::ContextTier::Signature),
        )
        .await;
        assert!(
            !run.result.success,
            "the canned code is broken on every attempt"
        );

        // the escalate rung is swapped out of the walk — exactly the shape of
        // today's skip_default precedent swapping the default off
        assert_eq!(
            walk(&run.result),
            vec![
                "initial",
                "compile_fix",
                "test_fix",
                "pruned_escalate",
                "edge_case_fix",
                "compile_fix"
            ]
        );

        // the prune is recorded — family and reason named beside the other
        // failure evidence, on an attempt carrying the ladder's own label
        assert_eq!(
            run.result.attempts[3].compilation_errors,
            vec![
                "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
            ]
        );
        assert_eq!(
            run.completions,
            vec![
                (1, "initial".to_string()),
                (2, "compile_fix".to_string()),
                (3, "test_fix".to_string()),
                (4, "pruned_escalate".to_string()),
                (5, "edge_case_fix".to_string()),
                (6, "compile_fix".to_string()),
            ]
        );

        // the decision read the held report, not the engine: the pruned rung
        // never re-asked the seam, and nothing else in this walk asks it —
        // the round-trip log stays empty
        assert!(run.kuna.decompile_calls().is_empty());

        // the pruned rung built no prompt, and the rung it rotated to carries
        // the prune in its fix prompt's history, named exactly once
        assert_eq!(
            run.prompts.keys().copied().collect::<Vec<_>>(),
            vec![2, 3, 5, 6],
            "the pruned rung asked no LLM question"
        );
        let prompt5 = run
            .prompts
            .get(&5)
            .expect("the rotated-to rung re-asks the LLM");
        assert!(prompt5.contains("PREVIOUS ATTEMPT HISTORY"));
        assert!(prompt5.contains(
            "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
        ));
        assert_eq!(prompt5.matches("Zanthoxylum").count(), 1);
    }

    /// Pruning is only ever about the family a rung re-asks: a report naming
    /// a different family unavailable leaves the walk byte-identically today's,
    /// and the re-ask still reaches the seam.
    #[tokio::test]
    async fn a_report_unavailable_about_another_family_leaves_the_ladder_today() {
        let run = run_ladder_with_report(
            unavailable_report("strings", "Ginkgo builds keep no string table"),
            6,
            Some(calxgloss_types::ContextTier::Signature),
        )
        .await;

        assert_eq!(
            walk(&run.result),
            vec![
                "initial",
                "compile_fix",
                "test_fix",
                "escalate",
                "edge_case_fix",
                "compile_fix"
            ]
        );
        // the unblocked escalate rung still re-asks the seam exactly as today
        assert!(
            run.kuna
                .decompile_calls()
                .contains(&"UpdateScene".to_string()),
            "an unblocked escalate rung must still re-ask the seam"
        );
        // and the unrelated family's reason never quotes itself into a prompt
        for (attempt, prompt) in &run.prompts {
            assert!(
                !prompt.contains("Ginkgo"),
                "attempt {attempt}'s prompt quotes an unrelated family's reason"
            );
        }
    }

    /// Today's Kuna declares every family on the seam roster answerable, so
    /// the production ladder must walk exactly as it walked before the report
    /// entered it — the all-answerable report admits nothing to prune on.
    #[tokio::test]
    async fn a_report_calling_every_family_answerable_walks_todays_ladder() {
        let report = calxgloss_types::CapabilityReport {
            families: calxgloss_decomp::QUERY_FAMILIES
                .iter()
                .map(|(id, _)| calxgloss_types::FamilyCapability {
                    id: (*id).to_string(),
                    status: calxgloss_types::AvailabilityStatus::Answerable,
                    reason: None,
                })
                .collect(),
        };
        let run =
            run_ladder_with_report(report, 6, Some(calxgloss_types::ContextTier::Signature)).await;

        assert_eq!(
            walk(&run.result),
            vec![
                "initial",
                "compile_fix",
                "test_fix",
                "escalate",
                "edge_case_fix",
                "compile_fix"
            ]
        );
        assert!(
            run.kuna
                .decompile_calls()
                .contains(&"UpdateScene".to_string()),
            "an answerable re-ask still reaches the seam"
        );
    }

    /// A step ONTO ModuleContext re-asks the seam the same families the
    /// escalate strategy arm does, so the same declared `Unavailable` holds
    /// the tier walk at the last tier that asks nothing — recorded in the
    /// same channel, the held step never silent.
    #[tokio::test]
    async fn a_blocked_seam_holds_the_tier_rung_from_stepping_onto_a_module_tier() {
        let run = run_ladder_with_report(
            unavailable_report("decompilation", "Zanthoxylum builds never produce a body"),
            9,
            None,
        )
        .await;

        // the escalate rungs swap out (as before), and the climb walks to the
        // last tier that re-asks nothing — and no further
        assert_eq!(
            walk(&run.result),
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
            ]
        );
        assert_eq!(run.tier_steps, vec!["disassembly", "with_tests"]);

        // no rung ever re-asked the seam — the held report decided every step
        assert!(run.kuna.decompile_calls().is_empty());

        // every hold is reviewable: the final fix prompt's failure history
        // carries both escalate prunes and the tier hold, each named by the
        // seam's own admission wording
        let last_prompt = run
            .prompts
            .get(&9)
            .expect("the rung after the holds re-asks the LLM");
        assert_eq!(
            last_prompt
                .matches(
                    "Pruned: escalate would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
                )
                .count(),
            2,
            "both escalate prunes survive as hints"
        );
        assert!(last_prompt.contains(
            "Pruned: tier escalation to module_context would re-ask decompilation — unavailable — Zanthoxylum builds never produce a body"
        ));
        assert_eq!(last_prompt.matches("Zanthoxylum").count(), 3);
    }

    /// The matching control: with nothing declared unavailable, the identical
    /// config walks today's full climb — escalate rungs included, every tier
    /// stepped, the re-asks reaching the seam.
    #[tokio::test]
    async fn an_answerable_seam_walks_todays_full_tier_climb() {
        let run =
            run_ladder_with_report(calxgloss_types::CapabilityReport::default(), 9, None).await;

        assert_eq!(
            walk(&run.result),
            vec![
                "initial",
                "compile_fix",
                "escalated(disassembly)",
                "escalate",
                "escalated(with_tests)",
                "compile_fix",
                "escalated(module_context)",
                "escalate",
                "escalated(full_module)"
            ]
        );
        assert_eq!(
            run.tier_steps,
            vec!["disassembly", "with_tests", "module_context", "full_module"]
        );
        assert!(
            run.kuna
                .decompile_calls()
                .contains(&"UpdateScene".to_string()),
            "the unblocked ladder re-asks the seam along the climb"
        );
    }
}

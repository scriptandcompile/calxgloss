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
                ctx.seam_report,
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

            // The failed candidate's own verdict and code go into the next
            // prompt (#334), and a fired detector ends the chain wherever it
            // lands — its fault record and event are already written by the
            // seam.
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
                crate::ladder_residue::file_escalate_prune(
                    &mut result.unknown_residue,
                    binary.as_str(),
                    &function,
                    &blocked,
                );
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
                    crate::ladder_residue::file_tier_refusal(
                        &mut result.unknown_residue,
                        binary.as_str(),
                        &function,
                        next_tier,
                        &blocked,
                    );
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

    // Ladder residue: each arm above filed its decision's own record (#372).
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
mod tests;

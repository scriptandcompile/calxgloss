//! One attempt — prompt → LLM → verification → record (issue #330, P38).
//!
//! This is the hidden module the retry loop used to interleave with its own
//! selection policy, spelled once. The loop routes a unit of work through
//! here: `run_attempt` takes the unit under repair plus a built prompt, sends
//! it to the LLM with today's keepalive and resource-exhaustion recording,
//! verifies the returned code against the scratch project, records the
//! attempt (progress events, token-usage and experiment logs, the
//! infinite-loop detector), and returns the attempt's **verdict** — passed,
//! verification-failed (with structured failing cases riding for the next
//! prompt), or an LLM-level failure. `verify_and_record` is the same
//! verification+recording tail for the initial translation, with no prompt
//! and no LLM call.
//!
//! The vacuous behavior-divergence probe the loop carried on both branches
//! (edge results fabricated all-true — the detector reports only on a failing
//! edge, so it could never fire) does not come along; the detector, event
//! and fault types stay for the day edge tests get real results (P22/P25).

use crate::retry::retry_loop::llm_call_with_keepalive;
use crate::retry::{
    RetryResult, TranslationAttempt, log_prompt_variant_experiment, log_token_usage,
};
use calxgloss_analysis::FaultLogger;
use calxgloss_llm::{
    LlmClient, LlmError, LlmMessage, infinite_loop::InfiniteLoopDetector,
    resource_exhaustion::ResourceExhaustionDetector,
};
use calxgloss_types::{
    BinaryIdentity, ContextTier, FailureHint, FaultEvent, ProgressEvent, ResourceExhaustionFault,
    TestCase, TranslationEvents,
};
use calxgloss_verify::{CompileResult, Verifier};
use tracing::warn;

/// Approximate elapsed time recorded for resource-exhaustion events when the
/// call never completed. Spelled once for the whole retry crate (the loop
/// carried this constant twice before the seam).
const DEFAULT_ELAPSED_SECS: u64 = 300;

/// Which prompt path produced this attempt. Today's two loop branches
/// spelled the exhausted-attempt note differently; the seam keeps both
/// spellings byte-identical across the move (#332).
#[derive(Debug)]
pub(crate) enum AttemptPath {
    /// A strategy-built fix prompt (compile fix, test fix, escalate, …).
    StrategyPrompt,
    /// A tier-escalated prompt rebuilt with decompiler/workspace context.
    TierEscalated,
}

/// The unit under repair, routed through the seam instead of the loop
/// reaching into the translation's fields (issue #330). The escalate
/// adapter's wider reads (address, call graph) joined it with the strategy
/// adapters (#333).
pub(crate) struct AttemptUnit<'a> {
    /// The DLL hosting the function under repair.
    pub binary: &'a BinaryIdentity,
    /// The function under repair.
    pub function: &'a str,
    /// The code this attempt's fix would replace — today the initial
    /// translation's output; from #334 on, the last failed attempt's.
    pub code_under_fix: &'a str,
    /// The baseline suite the unit must pass.
    pub baseline_tests: &'a [TestCase],
    /// The context tier this attempt's prompt was built at.
    pub tier: ContextTier,
    /// The function's entry-point address, if known — the escalate adapter
    /// pulls its neighbor context at this address.
    pub function_address: Option<u64>,
    /// Call-graph neighbors (callers and callees) from the scan — context
    /// the escalate adapter pulls prompts around.
    pub call_graph: &'a [String],
    /// Enriched call-graph context (caller/callee details, matched APIs) —
    /// the escalate adapter's richest context source.
    pub call_graph_context: &'a [calxgloss_callgraph::FunctionContext],
}

/// Everything one attempt needs from the run, gathered once per unit.
pub(crate) struct AttemptRunCtx<'a> {
    /// Verification engine for checking translations.
    pub verifier: &'a Verifier,
    /// LLM client for sending fix prompts.
    pub llm: &'a LlmClient,
    /// Optional progress event emitter for live WebSocket streaming.
    pub events: Option<&'a TranslationEvents>,
    /// Optional workspace path for experiment logging.
    pub workspace: Option<&'a std::path::Path>,
    /// Optional resource-exhaustion detector for tracking LLM server health.
    pub resource_detector: Option<&'a ResourceExhaustionDetector>,
    /// Optional fault logger for persisting detected faults to disk.
    pub fault_logger: Option<&'a FaultLogger>,
    /// The unit's infinite-loop detector, streaked across attempts.
    pub loop_detector: &'a mut InfiniteLoopDetector,
    /// Binary identity for event payloads and logs.
    pub binary: BinaryIdentity,
    /// Function name for event payloads and logs.
    pub function: String,
}

/// How an attempt ended — the closed set the loop's policy branches on.
#[derive(Debug)]
pub(crate) enum AttemptOutcome {
    /// Compiled and its suite passed (or there was no suite). Done.
    Passed,
    /// Ran and failed verification. The structured failing cases go out to
    /// the next prompt — the loop routes them, together with this attempt's
    /// recorded evidence, into the next fix prompt instead of re-verifying to
    /// re-gather them (#334).
    VerificationFailed {
        structured_failed_cases: Vec<calxgloss_prompts::EdgeCaseTest>,
    },
    /// The LLM answered with empty code. Recorded; no policy step follows.
    LlmEmpty,
    /// The LLM was overloaded or timed out. Detector, fault and history
    /// recorded; no policy step follows.
    LlmExhausted {
        // Read from #334 on. The seam already recorded the kind with the
        // resource detector and the fault log.
        #[allow(dead_code)]
        kind: String,
    },
    /// The LLM call errored. Recorded; no policy step follows.
    LlmCallError,
}

/// The seam's report: the verdict plus whether the infinite-loop detector
/// fired on this attempt's (prompt, output) streak. A fired detector ends
/// the chain wherever it lands — the loop stops on `loop_fired`, matching
/// the fault record and event the seam already wrote (#334).
#[derive(Debug)]
pub(crate) struct AttemptReport {
    pub outcome: AttemptOutcome,
    pub loop_fired: bool,
}

/// Emit a TranslationAttemptCompleted event for the attempt just appended to
/// `result`, exactly as the loop's closure did.
pub(crate) fn emit_attempt(
    events: Option<&TranslationEvents>,
    binary: &BinaryIdentity,
    function: &str,
    result: &RetryResult,
    attempt_num: u32,
    retry_strategy: &str,
) {
    if let (Some(em), Some(attempt)) = (events, result.attempts.last()) {
        let _ = em.emit(ProgressEvent::TranslationAttemptCompleted {
            binary: binary.clone(),
            function: function.to_string(),
            attempt: attempt_num,
            success: attempt.is_successful(),
            compiled: attempt.compiled,
            tests_passed: attempt.tests_passed,
            tests_total: attempt.tests_total,
            compilation_errors: attempt.compilation_errors.clone(),
            failed_tests: attempt.failed_tests.clone(),
            retry_strategy: retry_strategy.to_string(),
            tokens_used: attempt.tokens_used,
        });
    }
}

/// Record an attempt in the loop detector so streaks are tracked, and
/// persist a fault event when a loop is detected — the loop's closure,
/// moved to the seam whole.
fn record_in_detector(
    run: &mut AttemptRunCtx<'_>,
    prompt: &str,
    code: &str,
    success: bool,
    retry_strategy: &str,
    attempt: u32,
) -> bool {
    run.loop_detector
        .record_attempt(prompt, code, success, retry_strategy, attempt);

    // Check for infinite loop
    if let Some(signal) = run.loop_detector.detect() {
        // Emit progress event
        if let Some(em) = run.events {
            let _ = em.emit(ProgressEvent::InfiniteLoopDetected {
                binary: run.binary.clone(),
                function: run.function.clone(),
                streak: signal.streak,
                streak_start_attempt: signal.streak_start_attempt,
                streak_end_attempt: signal.streak_end_attempt,
                retry_strategy: signal.strategy.clone(),
            });
        }
        // Persist fault event for post-hoc analysis
        if let Some(logger) = run.fault_logger {
            let event = FaultEvent::infinite_loop(
                &run.binary,
                &run.function,
                attempt,
                retry_strategy,
                signal.streak,
                signal.streak_start_attempt,
                signal.streak_end_attempt,
            );
            logger.record(event);
        }
        warn!(
            binary = %run.binary,
            function = %run.function,
            streak = signal.streak,
            strategy = signal.strategy,
            streak_range = ?format!("{}–{}", signal.streak_start_attempt, signal.streak_end_attempt),
            "Infinite loop detected — stopping retry"
        );
        return true; // loop detected
    }
    false
}

/// One attempt: send the built prompt to the LLM, verify the returned code,
/// record everything, and return the verdict.
///
/// The recording tail — request/call-start/keepalive/response progress
/// events, exhaustion handling, empty-code handling, the attempt record and
/// its completion event, the token-usage log, the failure-history push and
/// the prompt-variant experiment log — lives here once, spelled in today's
/// order. The verification-failed tail steps neither strategy nor tier; the
/// loop owns that policy (#330).
// Parameters mirror one attempt's full input set, passed positionally by
// the loop — same shape as log_token_usage.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_attempt(
    run: &mut AttemptRunCtx<'_>,
    result: &mut RetryResult,
    failure_history: &mut Vec<FailureHint>,
    unit: &AttemptUnit<'_>,
    path: AttemptPath,
    retry_strategy: &str,
    attempt_num: u32,
    prompt: &str,
    attempt_start: std::time::Instant,
) -> AttemptReport {
    // Emit: LLM request (full prompt) for this retry attempt
    if let Some(em) = run.events {
        let _ = em.emit(ProgressEvent::LlmRequest {
            binary: run.binary.clone(),
            function: run.function.clone(),
            attempt: attempt_num,
            retry_strategy: retry_strategy.to_string(),
            prompt: prompt.to_string(),
        });
    }

    // Emit: LLM call started
    if let Some(em) = run.events {
        let _ = em.emit(ProgressEvent::LlmCallStart {
            binary: run.binary.clone(),
            function: run.function.clone(),
            attempt: attempt_num,
            retry_strategy: retry_strategy.to_string(),
        });
    }

    // Send fix prompt to LLM with keepalive progress updates
    let response = match llm_call_with_keepalive(
        run.llm,
        &[LlmMessage::user(prompt)],
        &run.binary,
        &run.function,
        attempt_num,
        retry_strategy,
        run.events,
    )
    .await
    {
        Ok(r) => {
            // Record success in the resource exhaustion detector
            if let Some(detector) = run.resource_detector {
                detector.record_success();
            }
            r
        }
        Err(LlmError::ResourceExhausted { kind }) => {
            // Record in the resource exhaustion detector
            if let Some(detector) = run.resource_detector {
                detector.record_failure_with_kind(kind.clone(), DEFAULT_ELAPSED_SECS);
                if let Some(signal) = detector.check_overload() {
                    // Emit progress event
                    if let Some(em) = run.events {
                        let _ = em.emit(ProgressEvent::ResourceExhaustionDetected {
                            binary: run.binary.clone(),
                            function: run.function.clone(),
                            attempt: attempt_num,
                            retry_strategy: retry_strategy.to_string(),
                            reason: kind.to_string(),
                            elapsed_secs: signal.longest_request_secs,
                            recommended_backoff_secs: signal.recommended_backoff_secs,
                        });
                    }
                    warn!(
                        binary = %run.binary,
                        function = %run.function,
                        streak = signal.streak,
                        kind = %kind,
                        backoff = signal.recommended_backoff_secs,
                        "LLM model overloaded — work queued"
                    );
                }
            }
            // Persist fault event to disk
            if let Some(logger) = run.fault_logger {
                let fault = ResourceExhaustionFault::timeout(DEFAULT_ELAPSED_SECS);
                logger.record_resource_exhaustion(
                    &run.binary,
                    &run.function,
                    attempt_num,
                    retry_strategy,
                    &fault,
                );
            }
            warn!(
                attempt = attempt_num,
                kind = %kind,
                "LLM resource exhausted during retry"
            );
            // Today's two branches spelled the note differently; the seam
            // keeps both across the move (#332).
            let note = match path {
                AttemptPath::StrategyPrompt => {
                    format!("LLM resource exhausted ({kind}) — model is overloaded or timed out")
                }
                AttemptPath::TierEscalated => {
                    format!("LLM resource exhausted ({kind}) during tier escalation")
                }
            };
            result.add_attempt(TranslationAttempt {
                attempt: attempt_num,
                rust_code: unit.code_under_fix.to_string(),
                compiled: false,
                compilation_errors: vec![note],
                tests_passed: 0,
                tests_total: 0,
                failed_tests: Vec::new(),
                retry_strategy: retry_strategy.to_string(),
                tokens_used: None,
                context_tier: Some(unit.tier.label().to_string()),
            });
            emit_attempt(
                run.events,
                &run.binary,
                &run.function,
                result,
                attempt_num,
                retry_strategy,
            );
            // Record failure history for informed prompting
            failure_history.push(FailureHint::new(
                attempt_num,
                retry_strategy,
                format!("LLM resource exhausted: {kind}"),
            ));
            return AttemptReport {
                outcome: AttemptOutcome::LlmExhausted {
                    kind: kind.to_string(),
                },
                loop_fired: false,
            };
        }
        Err(e) => {
            warn!(
                attempt = attempt_num,
                error = %e,
                "LLM call failed during retry"
            );
            result.add_attempt(TranslationAttempt {
                attempt: attempt_num,
                rust_code: unit.code_under_fix.to_string(),
                compiled: false,
                compilation_errors: vec![format!("LLM call failed: {e}")],
                tests_passed: 0,
                tests_total: 0,
                failed_tests: Vec::new(),
                retry_strategy: retry_strategy.to_string(),
                tokens_used: None,
                context_tier: Some(unit.tier.label().to_string()),
            });
            emit_attempt(
                run.events,
                &run.binary,
                &run.function,
                result,
                attempt_num,
                retry_strategy,
            );
            return AttemptReport {
                outcome: AttemptOutcome::LlmCallError,
                loop_fired: false,
            };
        }
    };

    // Emit: LLM response (full content) for this retry attempt
    if let Some(em) = run.events {
        let _ = em.emit(ProgressEvent::LlmResponse {
            binary: run.binary.clone(),
            function: run.function.clone(),
            attempt: attempt_num,
            retry_strategy: retry_strategy.to_string(),
            content: response.content.clone(),
            tokens_used: response.tokens_used,
        });
    }

    let new_rust_code = response.content.trim().to_string();
    let tokens_used = response.tokens_used;

    if new_rust_code.is_empty() {
        warn!(
            attempt = attempt_num,
            "LLM returned empty code during retry"
        );
        result.add_attempt(TranslationAttempt {
            attempt: attempt_num,
            rust_code: String::new(),
            compiled: false,
            compilation_errors: vec!["LLM returned empty code".to_string()],
            tests_passed: 0,
            tests_total: 0,
            failed_tests: Vec::new(),
            retry_strategy: retry_strategy.to_string(),
            tokens_used,
            context_tier: Some(unit.tier.label().to_string()),
        });
        emit_attempt(
            run.events,
            &run.binary,
            &run.function,
            result,
            attempt_num,
            retry_strategy,
        );

        // Log token usage (even with empty code, the LLM consumed tokens)
        log_token_usage(
            &run.binary,
            &run.function,
            attempt_num,
            retry_strategy,
            tokens_used,
            false,
            run.workspace,
            unit.tier.label(),
            Some(attempt_start.elapsed().as_secs()),
        );
        return AttemptReport {
            outcome: AttemptOutcome::LlmEmpty,
            loop_fired: false,
        };
    }

    // Verify the fix attempt
    let compile_result = match run
        .verifier
        .compile(&run.binary, &run.function, &new_rust_code)
        .await
    {
        Ok(cr) => cr,
        Err(e) => CompileResult {
            success: false,
            errors: vec![e.to_string()],
            warnings: Vec::new(),
            output: e.to_string(),
        },
    };

    // Get test results
    let (tests_passed, tests_total, failed_tests, structured_failed_cases) =
        if compile_result.success {
            match run
                .verifier
                .verify(
                    &run.binary,
                    &run.function,
                    &new_rust_code,
                    unit.baseline_tests,
                )
                .await
            {
                Ok(vr) => (
                    vr.tests_passed,
                    vr.tests_total,
                    vr.failed_tests
                        .iter()
                        .map(|ft| {
                            format!(
                                "Test {}: expected {}, got {} — {}",
                                ft.test_index, ft.expected, ft.actual, ft.error
                            )
                        })
                        .collect::<Vec<_>>(),
                    vr.failed_tests
                        .iter()
                        .map(|ft| calxgloss_prompts::EdgeCaseTest {
                            index: ft.test_index,
                            inputs: ft.inputs.clone(),
                            expected: ft.expected.clone(),
                            actual: ft.actual.clone(),
                            error: ft.error.clone(),
                            disassembly_hints: String::new(),
                        })
                        .collect::<Vec<_>>(),
                ),
                Err(_) => (
                    0,
                    0,
                    vec!["Verification failed".to_string()],
                    vec![calxgloss_prompts::EdgeCaseTest {
                        index: 0,
                        inputs: serde_json::Value::Null,
                        expected: serde_json::Value::Null,
                        actual: serde_json::Value::Null,
                        error: "Verification failed".to_string(),
                        disassembly_hints: String::new(),
                    }],
                ),
            }
        } else {
            (0, 0, Vec::new(), Vec::new())
        };

    // Record this attempt in the infinite-loop detector so we catch
    // cases where the LLM keeps returning identical code despite
    // changing prompts/strategies.
    let attempt_success = compile_result.success && tests_passed == tests_total;
    let loop_fired = record_in_detector(
        run,
        prompt,
        &new_rust_code,
        attempt_success,
        retry_strategy,
        attempt_num,
    );

    let attempt = TranslationAttempt {
        attempt: attempt_num,
        rust_code: new_rust_code,
        compiled: compile_result.success,
        compilation_errors: compile_result.errors.clone(),
        tests_passed,
        tests_total,
        failed_tests: failed_tests.clone(),
        retry_strategy: retry_strategy.to_string(),
        tokens_used,
        context_tier: Some(unit.tier.label().to_string()),
    };
    result.add_attempt(attempt);
    emit_attempt(
        run.events,
        &run.binary,
        &run.function,
        result,
        attempt_num,
        retry_strategy,
    );

    // Log token usage to file
    log_token_usage(
        &run.binary,
        &run.function,
        attempt_num,
        retry_strategy,
        tokens_used,
        result
            .attempts
            .last()
            .map(|a| a.is_successful())
            .unwrap_or(false),
        run.workspace,
        unit.tier.label(),
        Some(attempt_start.elapsed().as_secs()),
    );

    // Track failure history for informed prompting. Only failed attempts
    // push (not successful retries) — one spelling where today's two
    // branches differed only in an unreachable arm (#332).
    if attempt_num >= 1 && !result.success {
        let tp = result.attempts.last().map(|a| a.tests_passed).unwrap_or(0);
        let tt = result.attempts.last().map(|a| a.tests_total).unwrap_or(0);
        let comp_errors = result
            .attempts
            .last()
            .map(|a| a.compilation_errors.clone())
            .unwrap_or_default();
        let failure_desc = if !comp_errors.is_empty() {
            format!("Compilation failed: {}", comp_errors.join("; "))
        } else if tp < tt {
            format!("{tp} of {tt} tests passed")
        } else {
            "Unknown failure".to_string()
        };
        failure_history.push(FailureHint::new(attempt_num, retry_strategy, failure_desc));
    }

    let outcome = if result.success {
        AttemptOutcome::Passed
    } else {
        // Log experiment data for prompt variant tracking (failed attempts
        // only — today's loop breaks before this line on success).
        log_prompt_variant_experiment(
            &run.binary,
            retry_strategy,
            result.success,
            attempt_num,
            run.workspace,
        );
        AttemptOutcome::VerificationFailed {
            structured_failed_cases,
        }
    };
    AttemptReport {
        outcome,
        loop_fired,
    }
}

/// The verification+recording tail without a prompt or an LLM call — for
/// the initial translation `translate()` hands to the loop. It consults
/// the baseline suite honestly: compiled *and* the suite passed, never
/// "compiled and nobody asked" (the hole #334 closed).
// Parameters mirror the verification+recording tail's inputs, passed
// positionally by the loop — same shape as log_token_usage.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn verify_and_record(
    run: &mut AttemptRunCtx<'_>,
    result: &mut RetryResult,
    unit: &AttemptUnit<'_>,
    attempt_num: u32,
    retry_strategy: &str,
    detector_prompt: &str,
    tokens_used: Option<usize>,
) -> AttemptReport {
    let compile_result = match run
        .verifier
        .compile(&run.binary, &run.function, unit.code_under_fix)
        .await
    {
        Ok(cr) => cr,
        Err(e) => {
            warn!(error = %e, "Compilation check failed during retry");
            CompileResult {
                success: false,
                errors: vec![e.to_string()],
                warnings: Vec::new(),
                output: e.to_string(),
            }
        }
    };

    let (tests_passed, tests_total, failed_tests, structured_failed_cases) =
        if compile_result.success {
            match run
                .verifier
                .verify(
                    &run.binary,
                    &run.function,
                    unit.code_under_fix,
                    unit.baseline_tests,
                )
                .await
            {
                Ok(vr) => (
                    vr.tests_passed,
                    vr.tests_total,
                    vr.failed_tests
                        .iter()
                        .map(|ft| {
                            format!(
                                "Test {}: expected {}, got {} — {}",
                                ft.test_index, ft.expected, ft.actual, ft.error
                            )
                        })
                        .collect::<Vec<_>>(),
                    vr.failed_tests
                        .iter()
                        .map(|ft| calxgloss_prompts::EdgeCaseTest {
                            index: ft.test_index,
                            inputs: ft.inputs.clone(),
                            expected: ft.expected.clone(),
                            actual: ft.actual.clone(),
                            error: ft.error.clone(),
                            disassembly_hints: String::new(),
                        })
                        .collect::<Vec<_>>(),
                ),
                Err(_) => (
                    0,
                    0,
                    vec!["Verification failed".to_string()],
                    vec![calxgloss_prompts::EdgeCaseTest {
                        index: 0,
                        inputs: serde_json::Value::Null,
                        expected: serde_json::Value::Null,
                        actual: serde_json::Value::Null,
                        error: "Verification failed".to_string(),
                        disassembly_hints: String::new(),
                    }],
                ),
            }
        } else {
            (0, 0, Vec::new(), Vec::new())
        };

    let attempt = TranslationAttempt {
        attempt: attempt_num,
        rust_code: unit.code_under_fix.to_string(),
        compiled: compile_result.success,
        compilation_errors: compile_result.errors.clone(),
        tests_passed,
        tests_total,
        failed_tests,
        retry_strategy: retry_strategy.to_string(),
        tokens_used,
        context_tier: Some(unit.tier.label().to_string()),
    };
    result.add_attempt(attempt);
    emit_attempt(
        run.events,
        &run.binary,
        &run.function,
        result,
        attempt_num,
        retry_strategy,
    );

    // Record in the infinite-loop detector (initial translation).
    let loop_fired = record_in_detector(
        run,
        detector_prompt,
        unit.code_under_fix,
        result.success,
        retry_strategy,
        attempt_num,
    );

    let outcome = if result.success {
        AttemptOutcome::Passed
    } else {
        AttemptOutcome::VerificationFailed {
            structured_failed_cases,
        }
    };
    AttemptReport {
        outcome,
        loop_fired,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_analysis::{FaultLogger, PromptStrategyLogger, TokenUsageLogger};
    use calxgloss_types::ContextTier;

    const GOOD_CODE: &str = "fn draw_sprite(x: i32) -> i32 { x }";
    const BROKEN_CODE: &str = "fn draw_sprite(x: i32) -> i32 { let y: = ; x }";

    /// A canned LLM server answering every request with `status` and, for
    /// 200, `content` plus a token count. `status == 0` hangs up without
    /// answering, producing an LLM call error. No sleep — unlike the loop's
    /// duration fake, the seam tests do not pin wall-clock.
    async fn canned_llm(status: u16, content: &str) -> String {
        let content = content.to_string();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("canned LLM should bind");
        let addr = listener.local_addr().expect("canned LLM address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let content = content.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    if status == 0 {
                        let _ = stream.shutdown().await;
                        return;
                    }
                    let (status_line, body) = if status == 200 {
                        (
                            "200 OK",
                            format!(
                                "{{\"choices\":[{{\"message\":{{\"role\":\"assistant\",\"content\":\"{}\"}}}}],\"usage\":{{\"completion_tokens\":123,\"total_tokens\":123}}}}",
                                content
                            ),
                        )
                    } else {
                        (
                            "429 Too Many Requests",
                            "{\"error\":{\"message\":\"overloaded\"}}".to_string(),
                        )
                    };
                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// A 'static identity the fixture units can borrow.
    fn unit_identity() -> &'static BinaryIdentity {
        use std::sync::OnceLock;
        static ID: OnceLock<BinaryIdentity> = OnceLock::new();
        ID.get_or_init(|| "game_logic.dll".to_string().into())
    }

    fn fixture_unit<'a>(code_under_fix: &'a str, suite: &'a [TestCase]) -> AttemptUnit<'a> {
        AttemptUnit {
            binary: unit_identity(),
            function: "draw_sprite",
            code_under_fix,
            baseline_tests: suite,
            tier: ContextTier::Signature,
            function_address: None,
            call_graph: &[],
            call_graph_context: &[],
        }
    }

    fn token_entries(ws: &std::path::Path) -> Vec<calxgloss_types::TokenUsageEntry> {
        TokenUsageLogger::new(ws)
            .load()
            .map(|l| l.entries)
            .unwrap_or_default()
    }

    fn experiment_entries(ws: &std::path::Path) -> Vec<calxgloss_types::PromptStrategyEntry> {
        PromptStrategyLogger::new(ws)
            .load()
            .map(|l| l.entries)
            .unwrap_or_default()
    }

    fn fault_entries(ws: &std::path::Path) -> Vec<calxgloss_types::FaultEvent> {
        FaultLogger::new(ws)
            .load()
            .map(|l| l.entries)
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn run_attempt_passed_records_once_and_emits_in_order() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let base = canned_llm(200, GOOD_CODE).await;
        let llm = LlmClient::from_url(&base, "test-model").expect("llm client");
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &llm,
            events: Some(&events),
            workspace: Some(ws.path()),
            resource_detector: None,
            fault_logger: None,
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite: Vec<TestCase> = Vec::new();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x }", &suite);
        let mut result = RetryResult::new();
        let mut history: Vec<FailureHint> = Vec::new();

        let report = run_attempt(
            &mut run,
            &mut result,
            &mut history,
            &unit,
            AttemptPath::StrategyPrompt,
            "compile_fix",
            1,
            "fix it",
            std::time::Instant::now(),
        )
        .await;

        assert!(
            matches!(report.outcome, AttemptOutcome::Passed),
            "outcome: {:?}",
            report
        );
        assert!(!report.loop_fired);
        assert!(result.success);
        let attempt = result.attempts.last().expect("one attempt recorded");
        assert!(attempt.compiled);
        assert_eq!(attempt.tokens_used, Some(123));

        // Exactly one token-usage entry; no experiment entry — today's loop
        // breaks before that line on success.
        let entries = token_entries(ws.path());
        assert_eq!(entries.len(), 1, "entries: {:?}", entries);
        assert_eq!(entries[0].attempt, 1);
        assert_eq!(entries[0].strategy, "compile_fix");
        assert_eq!(entries[0].tokens_used, 123);
        assert!(entries[0].duration_secs.is_some());
        assert!(
            experiment_entries(ws.path()).is_empty(),
            "no experiment entry for a passing attempt"
        );

        // Today's per-attempt progress ordering, with today's payloads.
        let mut seen: Vec<&str> = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            match ev {
                ProgressEvent::LlmRequest {
                    attempt,
                    retry_strategy,
                    prompt,
                    ..
                } => {
                    assert_eq!(attempt, 1);
                    assert_eq!(retry_strategy, "compile_fix");
                    assert_eq!(prompt, "fix it");
                    seen.push("request");
                }
                ProgressEvent::LlmCallStart { .. } => seen.push("call-start"),
                ProgressEvent::LlmResponse { tokens_used, .. } => {
                    assert_eq!(tokens_used, Some(123));
                    seen.push("response");
                }
                ProgressEvent::TranslationAttemptCompleted { success, .. } => {
                    assert!(success);
                    seen.push("attempt");
                }
                ProgressEvent::InfiniteLoopDetected { .. } => seen.push("loop"),
                _ => {}
            }
        }
        assert_eq!(seen, ["request", "call-start", "response", "attempt"]);
    }

    #[tokio::test]
    async fn run_attempt_compile_failure_routes_verdict_and_records_history_and_experiment() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let base = canned_llm(200, BROKEN_CODE).await;
        let llm = LlmClient::from_url(&base, "test-model").expect("llm client");
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &llm,
            events: None,
            workspace: Some(ws.path()),
            resource_detector: None,
            fault_logger: None,
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite: Vec<TestCase> = Vec::new();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x }", &suite);
        let mut result = RetryResult::new();
        let mut history: Vec<FailureHint> = Vec::new();

        let report = run_attempt(
            &mut run,
            &mut result,
            &mut history,
            &unit,
            AttemptPath::StrategyPrompt,
            "compile_fix",
            1,
            "fix it",
            std::time::Instant::now(),
        )
        .await;

        assert!(
            matches!(report.outcome, AttemptOutcome::VerificationFailed { .. }),
            "outcome: {:?}",
            report
        );
        let attempt = result.attempts.last().expect("one attempt recorded");
        assert!(!attempt.compiled);
        assert!(!attempt.compilation_errors.is_empty());

        assert_eq!(history.len(), 1);
        assert!(
            history[0]
                .failure_description
                .starts_with("Compilation failed:")
        );

        // Verified failure records both logs exactly once each (today's tail).
        assert_eq!(token_entries(ws.path()).len(), 1);
        let experiments = experiment_entries(ws.path());
        assert_eq!(experiments.len(), 1);
        assert!(!experiments[0].success);
        assert_eq!(experiments[0].retry_strategy, "compile_fix");
    }

    #[tokio::test]
    async fn run_attempt_empty_code_logs_tokens_once_without_experiment_or_history() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let base = canned_llm(200, "").await;
        let llm = LlmClient::from_url(&base, "test-model").expect("llm client");
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &llm,
            events: None,
            workspace: Some(ws.path()),
            resource_detector: None,
            fault_logger: None,
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite: Vec<TestCase> = Vec::new();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x }", &suite);
        let mut result = RetryResult::new();
        let mut history: Vec<FailureHint> = Vec::new();

        let report = run_attempt(
            &mut run,
            &mut result,
            &mut history,
            &unit,
            AttemptPath::StrategyPrompt,
            "compile_fix",
            1,
            "fix it",
            std::time::Instant::now(),
        )
        .await;

        assert!(
            matches!(report.outcome, AttemptOutcome::LlmEmpty),
            "outcome: {:?}",
            report
        );
        let attempt = result.attempts.last().expect("one attempt recorded");
        assert!(attempt.rust_code.is_empty());
        assert_eq!(attempt.tokens_used, Some(123));

        // Today's empty-code path logs tokens (the LLM burned them) but
        // neither pushes history nor writes an experiment entry.
        assert_eq!(token_entries(ws.path()).len(), 1);
        assert!(history.is_empty());
        assert!(experiment_entries(ws.path()).is_empty());
    }

    #[tokio::test]
    async fn run_attempt_resource_exhaustion_records_detector_fault_and_history_once() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let base = canned_llm(429, "").await;
        let llm = LlmClient::from_url(&base, "test-model").expect("llm client");
        let resource_detector = ResourceExhaustionDetector::new();
        let fault_logger = FaultLogger::new(ws.path());
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &llm,
            events: None,
            workspace: Some(ws.path()),
            resource_detector: Some(&resource_detector),
            fault_logger: Some(&fault_logger),
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite: Vec<TestCase> = Vec::new();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x }", &suite);
        let mut result = RetryResult::new();
        let mut history: Vec<FailureHint> = Vec::new();

        let report = run_attempt(
            &mut run,
            &mut result,
            &mut history,
            &unit,
            AttemptPath::StrategyPrompt,
            "compile_fix",
            1,
            "fix it",
            std::time::Instant::now(),
        )
        .await;

        assert!(
            matches!(&report.outcome, AttemptOutcome::LlmExhausted { kind } if !kind.is_empty()),
            "outcome: {:?}",
            report
        );
        let attempt = result.attempts.last().expect("one attempt recorded");
        assert!(attempt.compilation_errors[0].contains("LLM resource exhausted"));

        assert_eq!(history.len(), 1);
        assert!(
            history[0]
                .failure_description
                .contains("LLM resource exhausted:")
        );
        assert_eq!(fault_entries(ws.path()).len(), 1, "one fault record");
        assert!(token_entries(ws.path()).is_empty());
        assert!(experiment_entries(ws.path()).is_empty());
    }

    #[tokio::test]
    async fn run_attempt_call_error_records_attempt_without_history_or_logs() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let base = canned_llm(0, "").await;
        let llm = LlmClient::from_url(&base, "test-model").expect("llm client");
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &llm,
            events: None,
            workspace: Some(ws.path()),
            resource_detector: None,
            fault_logger: None,
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite: Vec<TestCase> = Vec::new();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x }", &suite);
        let mut result = RetryResult::new();
        let mut history: Vec<FailureHint> = Vec::new();

        let report = run_attempt(
            &mut run,
            &mut result,
            &mut history,
            &unit,
            AttemptPath::StrategyPrompt,
            "compile_fix",
            1,
            "fix it",
            std::time::Instant::now(),
        )
        .await;

        assert!(
            matches!(report.outcome, AttemptOutcome::LlmCallError),
            "outcome: {:?}",
            report
        );
        let attempt = result.attempts.last().expect("one attempt recorded");
        assert!(attempt.compilation_errors[0].starts_with("LLM call failed:"));
        assert!(history.is_empty());
        assert!(token_entries(ws.path()).is_empty());
        assert!(experiment_entries(ws.path()).is_empty());
    }

    #[tokio::test]
    async fn run_attempt_detector_fire_surfaces_in_report_and_records_fault_once() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let base = canned_llm(200, BROKEN_CODE).await;
        let llm = LlmClient::from_url(&base, "test-model").expect("llm client");
        let fault_logger = FaultLogger::new(ws.path());
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &llm,
            events: Some(&events),
            workspace: None,
            resource_detector: None,
            fault_logger: Some(&fault_logger),
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite: Vec<TestCase> = Vec::new();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x }", &suite);
        let mut result = RetryResult::new();
        let mut history: Vec<FailureHint> = Vec::new();

        // Three identical bad outputs at the same prompt: the third trips
        // the detector's default streak of 3.
        let mut fired = Vec::new();
        for attempt in 1..=3 {
            let report = run_attempt(
                &mut run,
                &mut result,
                &mut history,
                &unit,
                AttemptPath::StrategyPrompt,
                "compile_fix",
                attempt,
                "fix it",
                std::time::Instant::now(),
            )
            .await;
            fired.push(report.loop_fired);
        }
        assert_eq!(fired, vec![false, false, true]);
        assert_eq!(result.attempts.len(), 3);

        let mut loop_events = 0;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, ProgressEvent::InfiniteLoopDetected { .. }) {
                loop_events += 1;
            }
        }
        assert_eq!(loop_events, 1, "one InfiniteLoopDetected event");
        assert_eq!(fault_entries(ws.path()).len(), 1, "one fault record");
    }

    /// One failing baseline case: `draw_sprite(5)` returns 6, expected 4.
    fn failing_suite() -> Vec<TestCase> {
        vec![TestCase {
            inputs: serde_json::json!(5),
            expected_return: serde_json::json!(4),
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
        }]
    }

    #[tokio::test]
    async fn verify_and_record_honestly_consults_the_baseline_suite() {
        let ws = tempfile::TempDir::new().expect("temp workspace");
        let verifier = Verifier::new(&ws.path().join("verify")).expect("verifier");
        let mut loop_detector = InfiniteLoopDetector::new();
        let mut run = AttemptRunCtx {
            verifier: &verifier,
            llm: &LlmClient::from_url("http://127.0.0.1:1", "test-model").expect("llm client"),
            events: None,
            workspace: Some(ws.path()),
            resource_detector: None,
            fault_logger: None,
            loop_detector: &mut loop_detector,
            binary: "game_logic.dll".to_string().into(),
            function: "draw_sprite".to_string(),
        };
        let suite = failing_suite();
        let unit = fixture_unit("fn draw_sprite(x: i32) -> i32 { x + 1 }", &suite);
        let mut result = RetryResult::new();

        let report = verify_and_record(
            &mut run,
            &mut result,
            &unit,
            1,
            "initial",
            "draw_sprite (game_logic.dll) initial translation",
            Some(10),
        )
        .await;

        // The initial attempt's verdict is honest now (#334): a
        // merely-compiling unit with a non-empty suite is not done — the
        // record carries the suite's real counts and the outcome routes to
        // a retry. (The scratch toolchain's suite runner currently fails
        // to build — a verify-crate defect out of this ticket's scope —
        // so every failing suite verdict lands as 0-of-N here; the honest
        // part is that the suite was consulted and recorded at all.)
        assert!(
            matches!(report.outcome, AttemptOutcome::VerificationFailed { .. }),
            "outcome: {:?}",
            report
        );
        assert!(!result.success);
        let attempt = result.attempts.last().expect("one attempt recorded");
        assert!(attempt.compiled);
        assert_eq!(attempt.tests_total, 1, "the suite was consulted");
        assert_eq!(attempt.tests_passed, 0);
        assert_eq!(attempt.tokens_used, Some(10));
        // The initial attempt still writes neither log (no LLM call ran).
        assert!(token_entries(ws.path()).is_empty());
        assert!(experiment_entries(ws.path()).is_empty());
    }
}

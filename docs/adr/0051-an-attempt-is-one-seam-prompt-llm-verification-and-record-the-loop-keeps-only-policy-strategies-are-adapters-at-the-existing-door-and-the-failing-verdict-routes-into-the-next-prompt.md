# ADR-0051: An attempt is one seam — prompt, LLM, verification, record; the loop keeps only policy, strategies are adapters at the existing door, and the failing verdict routes into the next prompt

- **Status:** Accepted
- **Date:** 2026-10-25 (P38 shipped, issues #331–#336, spec #330)
- **Deciders:** Arthur (solo project)

## Context

ADR-0050 handed the run loop a complete assembled pass. Inside that pass sat
the retry loop: one 1,272-line async fn carrying two ~450-line near-duplicate
bodies — the tier-escalated branch and the strategy branch — each re-spelling
the same attempt sequence copy-for-copy: emit request and call-start, keepalive
LLM call, resource-exhaustion handling, empty-code handling, compile, test run,
divergence probe, loop-detector record, token-usage log, failure-history push,
strategy ladder. A fix to "how one attempt fails and gets re-prompted" had to
be written twice or silently lived in one (spec #330, architecture review
2026-10-24, candidate 5).

Four contract defects hid in that duplication:

- **The compile-only success hole.** The initial attempt verified compilation
  only. A unit whose code merely compiled was reported success, never retried,
  and carried to review as a translation with a baseline suite nobody ran.
- **Wrong code in the prompt.** Every fix prompt carried the *initial*
  translation as "ORIGINAL TRANSLATION (FAILED)" and its first-attempt errors,
  whatever had failed since. Once attempt N failed, attempt N+1 was asked to
  repair the wrong code while quoting evidence about a different one.
- **The detector fire never stopped.** Three consecutive identical failing
  outputs fired the infinite-loop detector mid-chain — event emitted, fault
  logged — and the loop carried on sending attempts anyway, burning the
  remaining budget at the operator's expense.
- **The vacuous divergence probe.** Both branches generated an edge-case probe
  with fabricated all-true results against a detector that reports only on a
  failing edge; it could never fire, and its event and fault types never had a
  production emitter. ~90 lines per branch of dead arithmetic over pretend
  inputs.

The shape decisions worth fixing: where one attempt lives, what the loop keeps,
how strategies reach their prompts, whether a prompt's evidence is re-gathered
or routed, and what "verified" means for the first attempt.

## Decision

One attempt, one seam; the loop is policy; strategies are adapters; verdicts
route.

- **An attempt is one seam.** `crates/pipeline/calxgloss-translator/src/retry/attempt.rs`
  spells the hidden module once: `run_attempt(unit, prompt, …)` runs
  **prompt → LLM call → verification → record** and returns the attempt's
  verdict — `AttemptOutcome::Passed`, `VerificationFailed { structured_failed_cases }`,
  or an LLM-level failure (`LlmEmpty`, `LlmExhausted`, `LlmCallError`). Every
  recording tail belongs to the seam: attempt and completion events, the
  token-usage log, the prompt-variant experiment log, the infinite-loop
  detector record, the failure-history push. `verify_and_record` is the same
  verification-plus-recording tail for the initial translation — no prompt, no
  LLM call. `attempt_start: Instant` is loop-owned and handed through, so
  token durations still span prompt-build plus call byte-identically.
- **The loop keeps only policy.** Selection (strategy ladder, context-tier walk
  with operator cap, the `Default` skip arm), gates, and stop routing on the
  verdict — nothing else. The compiler cannot pin the shape inside the crate,
  so source pins do (`tests/source_pins.rs`): exactly one production module
  rides the seam; the per-attempt log sinks are called from nowhere but the
  seam; attempts are constructed only at the seam and the loop's two
  bookkeeping arms for attempts that never reached an LLM (the `Default`-skip
  entry, the tier-escalation-build-failure entry); no production module outside
  the retry tree drives a prompt builder; and the loop's production region
  stays within a 600-line budget (measured 493 — the two bodies it replaced
  spanned ~900 lines alone).
- **Strategies are adapters at the existing door.** Each strategy module —
  `compile_fix.rs`, `prompts.rs`, `escalate.rs` — contributes one adapter over
  its builder, all taking one `FixPromptRequest` (unit, verdict, history,
  workspace, scan source); `retry.rs` holds the closed dispatch keyed by
  `RetryStrategy` as the loop's single door to the builders. `Default` is
  unreachable through the door — re-sending the original prompt is selection,
  and the loop's skip arm owns it. The adapters preserve today's exact prompt
  shape — payload split, plain-versus-failure-informed rule, template
  rendering — pinned byte-identically through captured LLM request bodies.
- **Verdicts route; evidence is not re-gathered.** The prompt's evidence groups
  into one `UnitVerdict` — `compilation_errors`, `failed_test_quotes`,
  `structured_failed_cases` — built by `UnitVerdict::from_failure` from the
  **newest** recorded attempt's payload plus that attempt's seam outcome,
  seeded from the initial record and re-routed after every `VerificationFailed`
  at both loop sites; the routing also moves the repair target to that
  attempt's own returned code, so every fix prompt names and quotes the code
  being fixed. LLM-tail outcomes leave verdict and target untouched — there is
  nothing new to fix. The verifier is asked exactly once per candidate code:
  the three hoisted re-verification arms are deleted, and a source pin keeps
  any verifier call out of the loop body.
- **The initial attempt verifies honestly.** `VerificationMode` is retired;
  both seam functions compile **and** run the baseline suite. Success stays
  exactly the old rule — compiled and the suite passed, or there was no suite
  — closing the hole where a merely-compiling unit was done.
- **A detector fire ends the chain where it lands.** One event, one fault
  record, no next request — at both seam sites.
- **The vacuous divergence probe leaves with its fabricated inputs.** The
  detector type, the progress event, and the fault record stay — web analytics
  parses fault logs, and P22/P25's gate work is where edge results get real
  evidence — and the deletion is pinned by absence: a verified passing run
  records zero divergence events and zero divergence faults.
- **The public surface does not move.** The `retry::` re-export set, the
  loop's entry `(Translation, &RetryLoopCtx)`, `RetryConfig`, `RetryResult`,
  `TranslationAttempt`, and every builder stay public exactly as before — an
  integration test compiles them from outside the crate — while the seam
  itself (`run_attempt`, `verify_and_record`, `AttemptOutcome`, `AttemptUnit`)
  is `pub(crate)`: outside the crate, driving an attempt around the loop does
  not compile. Event, log, and token wire shapes are byte-identical, pinned by
  the captured-stream suites.

## Consequences

- Three user-visible defects close with the deepening: units are verified, not
  merely compiled; fix prompts quote the code that actually failed; and a
  detected loop stops the token spend instead of annotating it. The loop's
  event stream, per-attempt experiment records and token logs land with
  today's fields, so nothing downstream — review UI, web analytics, fault
  logs — had to change.
- P27's hypothesis ledger lands on verdict records, not log lines: the seam
  returns structured per-attempt outcomes a ledger can consume directly.
- Contributor contract: a new attempt path (new strategy, new escalation)
  rides `run_attempt` and contributes an adapter at the door — it cannot
  record events, write logs, or construct attempts by hand without failing a
  pin; the loop body that folds an attempt back in fails its line budget.
- One honest toolchain limit stays recorded rather than hidden: the scratch
  suite runner does not build on this machine (the verify crate's runner
  references an undefined `TestCaseInput`), so a non-empty suite currently
  reports 0/N with no per-case lines — the honest-consulted-but-failing
  verdict. The suite-run defect is its own ticket; the attempt-1 honesty pin
  holds in the failing direction until then, and the structured-case routing
  is pinned at seam, `from_failure`, and adapter level meanwhile.

# ADR-0051: An attempt is one seam — prompt, LLM, verification, record; the loop keeps only policy, strategies are adapters at the existing door, and the failing verdict routes into the next prompt

- **Status:** Accepted
- **Date:** 2026-10-25 (P38 shipped, issues #331–#336, spec #330)
- **Deciders:** Arthur (solo project)

## Context

ADR-0050 handed the run loop a complete assembled pass. Inside that pass
sat the retry loop: one 1,272-line async fn holding two ~450-line bodies
that nearly duplicated each other — the tier-escalated branch and the
strategy branch — each writing the same attempt sequence again copy for
copy: emit request and call-start, keepalive LLM call, resource-exhaustion
handling, empty-code handling, compile, test run, divergence probe,
loop-detector record, token-usage log, failure-history push, strategy
ladder. A fix to "how one attempt fails and gets re-prompted" had to be
written twice or silently lived in one branch (spec #330, architecture
review 2026-10-24, candidate 5).

Four contract defects hid in that duplication:

- **The compile-only success hole.** The initial attempt checked
  compilation only. A unit whose code merely compiled was reported as a
  success, never retried, and sent to review as a translation with a
  baseline suite nobody had run.
- **Wrong code in the prompt.** Every fix prompt included the *initial*
  translation labeled "ORIGINAL TRANSLATION (FAILED)" plus its
  first-attempt errors, no matter what had failed since. Once attempt N
  failed, attempt N+1 was asked to repair the wrong code while quoting
  evidence about a different one.
- **The detector fire never stopped.** Three consecutive identical failing
  outputs fired the infinite-loop detector mid-chain — event emitted,
  fault logged — and the loop kept sending attempts anyway, spending the
  remaining token budget at the operator's expense.
- **The vacuous divergence probe.** Both branches generated an edge-case
  probe with fabricated all-true results against a detector that reports
  only on a failing edge; it could never fire, and its event and fault
  types never had a production emitter. ~90 lines per branch of dead
  arithmetic over invented inputs.

The shape decisions worth fixing: where one attempt lives, what the loop
keeps, how strategies reach their prompts, whether a prompt's evidence is
re-gathered or routed, and what "verified" means for the first attempt.

## Decision

One attempt, one seam; the loop is policy; strategies are adapters;
verdicts route.

- **An attempt is one seam.**
  `crates/pipeline/calxgloss-translator/src/retry/attempt.rs` holds the
  hidden module in one place: `run_attempt(unit, prompt, …)` runs
  **prompt → LLM call → verification → record** and returns the attempt's
  verdict — `AttemptOutcome::Passed`, `VerificationFailed { structured_failed_cases }`,
  or an LLM-level failure (`LlmEmpty`, `LlmExhausted`, `LlmCallError`).
  Everything the attempt records belongs to the seam: attempt and
  completion events, the token-usage log, the prompt-variant experiment
  log, the infinite-loop detector record, the failure-history push.
  `verify_and_record` is the same verification-plus-recording tail for the
  initial translation — no prompt, no LLM call. `attempt_start: Instant`
  belongs to the loop and is passed through, so token durations still span
  prompt-build plus call byte-identically.
- **The loop keeps only policy.** Selection (the strategy ladder, the
  context-tier walk with the operator cap, the `Default` skip arm), gates,
  and stop routing on the verdict — nothing else. The compiler cannot
  enforce this shape inside the crate, so source-check tests do
  (`tests/source_pins.rs`): exactly one production module calls the seam;
  the per-attempt log sinks are called from nowhere but the seam; attempts
  are constructed only at the seam and at the loop's two bookkeeping points
  for attempts that never reached an LLM (the `Default`-skip entry, the
  tier-escalation-build-failure entry); no production module outside the
  retry tree calls a prompt builder; and the loop's production region stays
  within a 600-line budget (measured 493 — the two bodies it replaced
  spanned ~900 lines alone).
- **Strategies are adapters at the existing door.** Each strategy module —
  `compile_fix.rs`, `prompts.rs`, `escalate.rs` — contributes one adapter
  over its builder, all taking one `FixPromptRequest` (unit, verdict,
  history, workspace, scan source); `retry.rs` holds the closed dispatch
  keyed by `RetryStrategy` — the one place, the "door", where the loop can
  reach the prompt builders. `Default` is unreachable through the door —
  re-sending the original prompt is selection, and the loop's skip arm owns
  it. The adapters keep today's exact prompt shape — payload split,
  plain-versus-failure-informed rule, template rendering — fixed
  byte-identically by captured LLM request bodies.
- **Verdicts route; evidence is not re-gathered.** The prompt's evidence
  is grouped into one `UnitVerdict` — `compilation_errors`,
  `failed_test_quotes`, `structured_failed_cases` — built by
  `UnitVerdict::from_failure` from the **newest** recorded attempt's
  payload plus that attempt's seam outcome, seeded from the initial record
  and re-read after every `VerificationFailed` at both loop sites. The
  routing also moves the repair target to that attempt's own returned code,
  so every fix prompt names and quotes the code being fixed. LLM-tail
  outcomes leave verdict and target untouched — there is nothing new to
  fix. The verifier runs exactly once per candidate code: the three
  re-verification branches that had been lifted out of the builders are
  deleted, and a source-check test keeps any verifier call out of the loop
  body.
- **The initial attempt verifies honestly.** `VerificationMode` is
  retired; both seam functions compile **and** run the baseline suite.
  Success stays exactly the old rule — compiled and the suite passed, or
  there was no suite — closing the hole where a merely-compiling unit
  counted as done.
- **A detector fire ends the chain where it lands.** One event, one fault
  record, no next request — at both seam sites.
- **The vacuous divergence probe leaves with its fabricated inputs.** The
  detector type, the progress event, and the fault record stay — web
  analytics parses fault logs, and P22/P25's gate work is where edge
  results get real evidence — and the deletion is enforced by absence: a
  verified passing run records zero divergence events and zero divergence
  faults.
- **The public surface does not move.** The `retry::` re-export set, the
  loop's entry `(Translation, &RetryLoopCtx)`, `RetryConfig`,
  `RetryResult`, `TranslationAttempt`, and every builder stay public
  exactly as before — an integration test compiles them from outside the
  crate — while the seam itself (`run_attempt`, `verify_and_record`,
  `AttemptOutcome`, `AttemptUnit`) is `pub(crate)`: outside the crate,
  driving an attempt around the loop does not compile. Event, log, and
  token wire shapes are byte-identical, proved by the captured-stream
  suites.

## Consequences

- Three user-visible defects close with the deepening: units are verified,
  not merely compiled; fix prompts quote the code that actually failed; and
  a detected loop stops the token spend instead of only annotating it. The
  loop's event stream, per-attempt experiment records and token logs land
  with today's fields, so nothing downstream — review UI, web analytics,
  fault logs — had to change.
- P27's hypothesis ledger lands on verdict records, not log lines: the seam
  returns structured per-attempt outcomes a ledger can consume directly.
- Contributor contract: a new attempt path (new strategy, new escalation)
  goes through `run_attempt` and contributes an adapter at the door — it
  cannot record events, write logs, or construct attempts by hand without
  failing a source-check test; and if the loop body started absorbing
  attempt logic again, it would fail its line budget.
- One honest toolchain limit stays recorded rather than hidden: the scratch
  project's suite runner does not build on this machine (the verify crate's
  runner references an undefined `TestCaseInput`), so a non-empty suite
  currently reports 0/N with no per-case lines — the honest
  "consulted-but-failing" verdict. The suite-run defect is its own ticket;
  the attempt-1 honesty test pin holds in the failing direction until then,
  and the structured-case routing is tested at seam, `from_failure`, and
  adapter level meanwhile.

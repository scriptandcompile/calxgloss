# ADR-0047: Failure codes travel the call map one hop, codes only, and an inherited code rides a confidence penalty onto the caller

- **Status:** Accepted
- **Date:** 2026-10-23 (P15 propagation shipped, issue #291)
- **Deciders:** Arthur (solo project)

## Context

ADR-0046's failure-code reading stops at a body's closing brace: a code
record names only the literals the function itself spelled at a return,
raise, or guard site. But failure contracts compose through calls. A caller
that checks `FUN_140006b40(param_1)` against `0xc0000001`, or hands its
result straight back, takes part in that callee's contract without ever
spelling the literal, and today it reads clean. A translator given the
per-binary errhandling document (spec #230) therefore sees the callee's
codes but not the callers that must actually pass them along.

Two established patterns shape the fix. The callback cross-function pass
(ADR-0035) showed how to relate bodies the scan already holds: derive the
call map from the kept text, fetch nothing new, and let ADR-0024's
exactly-once decompile hold untouched. And ADR-0028's renumbering pass
established the claim gate for whole-program passes: one claim per pair,
first in scan order wins, every later path quiet, so the pass stays
deterministic and diff-clean. The open questions were what may be passed
along, what caller shape earns an inheritance, where second-hand evidence
ranks on the confidence ladder, and how far a chain may be taken before it
stops being evidence and starts being inference.

## Decision

The `calxgloss-errhandling` scan gains one cross-function pass
(`cross_function`) after the per-function loop, over the
`DecompiledFunction` entries the scan already kept, appending
`inherited_error_code` findings after every per-function record.

- **Codes travel; idioms never.** A callee's spelled frame, named
  handler, exception-API call, `RaiseException` claim, and cleanup ladder
  describe how the *callee* handles failure; none of them says anything
  about the caller's own body. Only failure-code records — the callee's
  contract — cross a call edge.
- **Two caller shapes inherit.** A guard comparing a callee's return
  against a shaped code literal — the call straight inside the comparison,
  or a plain local the call just assigned standing under an `if`, `else`,
  or `while` head — inherits each compared code the callee itself records,
  evidenced at the call-site line. A `return` handing a call's value whole
  back — spelled casts seen through, or a just-assigned local — inherits
  the callee's *whole* recorded set, because re-returning makes the
  callee's return codes the caller's return codes too. A returned
  comparison hands back a flag, not a code, and inherits nothing.
- **Only codes the callee records.** The callee's set is its own
  configured `ErrorCodeDetector` reading re-run on text the scan holds —
  never a looser re-parse — so a code can only inherit if the first-hand
  reading already claimed it, and a compared literal outside the callee's
  set states no contract to inherit.
- **One hop, then stop.** The pass runs once per scan: a caller
  inherits its callee's records, never its grandcallee's. A chain is still
  readable — the inherited record states its partner callee beside the
  code — but stacking hops would assert a contract no body actually shows
  (ADR-0021's evidence-before-inference line).
- **The inherited band: 54.** The guard reading's 64, minus the
  confidence penalty for propagation: the tie from the caller's value to
  the callee's contract is read, not seen. 54 sits below the
  exception-API band's 60 and the cleanup-ladder band's 55 as well, so an
  inherited code never outranks *any* reading that saw the literal in the
  body it claims. A caller's own first-hand records, at their own bands,
  coexist beside the inherited ones.
- **One claim per (function, code).** Across every inheritance path
  the first claim in scan order wins and every later path stays quiet —
  ADR-0028's gate, adopted verbatim — and findings append in a fixed order
  (callers in listing order, call sites in body order) after the
  per-function block, so two scans of one program still diff cleanly.
- **Nothing to inherit, nothing said.** A callee the scan never read (a
  skipped decompile) or one that records no codes contributes nothing; the
  skip and breaker behaviour of the per-function pass (issue #71) governs
  which callees exist for the pass. Recursion claims nothing.
- **A new kind, no new reads.** The finding is a new tagged arm of
  ADR-0046's union stating its partner callee beside the code and the
  shared accessors; call edges come from the same kept bodies through the
  shared `call_sites` scan, run over lines with comments and strings
  blanked out, so the pass adds zero analysis engine round-trips
  (ADR-0024) and zero annotation write-back (ADR-0020).

## Consequences

- Scan results gain a trailing inherited block: consumers of the
  persisted document see, per caller, the second-hand codes it enforces
  and *which callee* said so — the failure graph the translation prompts
  will walk in #292–#293 without re-deriving it.
- The confidence ladder is fixed by a const assertion: 54 under 55/60
  under the first-hand code bands, so a future band move cannot silently
  promote second-hand evidence above first-hand.
- Old documents load unchanged — a new tag only; the CLI's
  kind-breakdown line gains `inherited_error_code`.
- Chains of two or more hops need a reader (human or the #292 batch
  wiring) to walk one edge at a time; that is deliberate, and a future
  transitive rule would need its own ADR and its own, lower band.
- Batch scan wiring and the prompt sections follow in #292–#293; nothing
  in this change feeds a prompt or writes back yet.

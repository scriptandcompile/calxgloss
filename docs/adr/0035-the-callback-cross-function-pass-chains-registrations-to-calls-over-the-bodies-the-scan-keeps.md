# ADR-0035: The callback cross-function pass chains registrations to calls over the bodies the scan keeps

- **Status:** Accepted
- **Date:** 2026-10-15
- **Deciders:** Arthur (solo project)

## Context

Phase 5 of the callback scan (issue #171, spec #169) asks the scan to
see the callback lifecycle across function boundaries. A handler
registered in one function and invoked in another — the actual shape
of a callback — is invisible to every per-body detector: each detector
stops at its body's closing brace. The reading must use the same
tagged-union finding list, persistence, CLI kind breakdown, and
escalate prompt path as every other detector. And it must not disturb
the scan's two provable contracts: each function is decompiled exactly
once, and the skip-rate breaker aborts the run when too many functions
fail to decompile. The memory crate solved the same problem for
allocation lifecycles in ADR-0027, and the sync crate solved it for
lock orders in ADR-0033, by running their cross-function passes over
the bodies the scan had already fetched.

## Decision

Mirror ADR-0027 and ADR-0033 in the callback crate:

- A new `cross_function` module holds a stateless `CrossFunctionAnalyzer`.
  The evidence engine runs it **after the per-function walk**, over the
  `DecompiledFunction` values the walk kept. The chain map is built
  from those bodies, using the same call-site scan the registration
  and plugin detectors use — **no new `ScanSource` reads** — so the
  exactly-once-decompile guarantee and the skip-rate breaker survive
  untouched, proven by their existing tests staying green.
- Per body, the pass records the registrations the registration
  detector binds, through the detector's own `detect_sites` (made
  `pub(crate)`). That function also reports **every plain identifier
  spelled in the call's arguments**, so a table passed in beside the
  handler (`register_callback(on_message, &handler_table)`) can be
  matched against a partner body's table calls without a second walk
  or a second argument parse. The pass also collects the direct-call
  targets of the shared call-site scan, and the tables being called
  that the fp-array and jump-table detectors read. Everything matches
  against the **detectors' configured name
  sets**: custom spellings reach the pass through `with_registration`
  and `with_fp_array`, not a private default set, and the two readings
  cannot disagree about what a registration or a table identifies.
- A chain exists when a registration's bound callback stands as a
  direct call target in another kept body, or when the registration
  names a table that a partner body dispatches through. Each chain
  reports one `CallbackFinding::Chain` **per (registering function,
  calling function) pair** — first match in body order winning, both
  directions of a pair checked separately. The finding is attached to
  the earlier function in listing order, and records the later one as
  `partner`, the bound callback, and the table the callback runs
  through (`table` skipped from the JSON when the chain is a direct
  name), at confidence **70** — both ends are explicit body evidence,
  level with an in-body registration. The evidence is both ends' call
  lines, registration first, joined with ` | ` because the decompiled
  lines already end in semicolons.
- Cross-function findings **are appended after the per-function
  findings**, both groups in listing order, keeping the persisted
  document diffable. A function whose decompile failed is absent from
  the kept bodies: it binds no registration, calls nothing, and
  produces no chain.

## Consequences

- The scan's cost and safety model is untouched: one decompile per
  function, the breaker still aborting a run on decompile failures,
  and the finding order still stable across scans. The contract tests,
  unmodified, still pin all of this.
- The callback in a chain is the registration detector's bound
  argument — its first plain identifier. So a site spelling the table
  first (`register_callback(&handler_table, on_message)`) binds the
  table as the callback, and the chain reports the same name as both
  callback and table. That is the registration reading's existing
  choice, inherited unchanged rather than made worse.
- Chains depend on names the decompiler kept: a callback registered
  through a decompiler-minted local, or called through a computed
  expression, reads as no chain. Same limitation as every other
  reading.
- The event-system reading (issue #172) and the signature enrichment
  (issue #173) build next on these kept bodies. The chain suggestion
  keeps its `(...)` open so the signature pass can fill it.
- The evidence engine now holds every decompiled body for the scan's
  duration, so peak memory grows with the size of the program's
  decompiled text. Accepted: the bodies are the same text the scan
  already read once, and the alternative — re-fetching them for the
  pass — would break the exactly-once contract.

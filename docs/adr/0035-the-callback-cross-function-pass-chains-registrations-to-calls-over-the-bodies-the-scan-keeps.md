# ADR-0035: The callback cross-function pass chains registrations to calls over the bodies the scan keeps

- **Status:** Accepted
- **Date:** 2026-10-15
- **Deciders:** Arthur (solo project)

## Context

Phase 5 of the callback scan (issue #171, spec #169) asks the scan to
see the callback lifecycle across function boundaries: a handler
registered in one function and invoked in another — the actual shape
of a callback — is invisible to every per-body detector, each of which
stops at its body's closing brace. The reading has to land on the same
tagged-union finding list, persistence, CLI kind breakdown, and
escalate prompt plumbing as every other detector, and it must not
disturb the scan's two provable contracts: each function is
decompiled exactly once, and the skip-rate breaker gates the run on
decompile failures. The memory crate solved the same shape for
allocation lifecycles in ADR-0027, and the sync crate for lock orders
in ADR-0033, by running their cross-function passes over the bodies
the scan already fetched.

## Decision

Mirror ADR-0027 and ADR-0033 in the callback crate:

- A new `cross_function` module holds a stateless `CrossFunctionAnalyzer`
  that the engine runs **after the per-function walk**, over the
  `DecompiledFunction` values the walk kept. The chain map is derived
  from those bodies with the same call-site scan the registration and
  plugin detectors use — **no new `ScanSource` reads** — so the
  exactly-once-decompile guarantee and the skip-rate breaker survive
  untouched, proven by their existing tests staying green.
- Per body, the pass records the registrations the registration
  detector binds — through its own `detect_sites` (made `pub(crate)`),
  which also reports **every plain identifier the call's arguments
  spell**, so a table handed over beside the handler
  (`register_callback(on_message, &handler_table)`) is matched against
  a partner body's table calls without a second walk or a second
  argument parse — the direct-call targets of the shared call-site
  scan, and the tables the fp-array and jump-table detectors read
  being called. Everything keys on the **detectors' configured name
  sets**: custom spellings reach the pass through `with_registration`
  and `with_fp_array`, not a private default set, and the two readings
  cannot disagree about what a registration or a table names.
- A registration whose bound callback stands as a direct call target
  in another kept body, or whose site names a table the partner body
  dispatches through, lands one `CallbackFinding::Chain` **per
  (registering function, calling function) pair** — first match in
  body order winning, both directions of a pair checked separately —
  on the earlier function in listing order, naming the later one as
  `partner`, the bound callback, and the table it runs through
  (`table` skipped from the JSON when the chain is a direct name), at
  confidence **70** — both ends are explicit body evidence, level with
  an in-body registration. The evidence is both ends' call lines,
  registration first, joined with ` | ` because the decompiled lines
  already end in semicolons.
- Cross-function findings **append after the per-function findings**,
  both groups in listing order, keeping the persisted document
  diffable. A function whose decompile failed is absent from the kept
  bodies, binds no registration, calls nothing, and fabricates no
  chain.

## Consequences

- The scan's cost and safety model is untouched: one decompile per
  function, the breaker gating as before, and the finding order
  staying stable across scans — all still pinned by the contract
  tests, unmodified.
- The chain's callback name is the registration detector's bound
  argument — its first plain identifier — so a site spelling the
  table first (`register_callback(&handler_table, on_message)`) binds
  the table as the callback and the chain names it as both callback
  and table. That is the registration reading's existing choice,
  inherited whole rather than made worse.
- Chains key on names the decompiler kept: a callback registered
  through a minted local or called through a computed expression reads
  as no chain. Same limitation as every other reading.
- The kept bodies are the substrate the event-system reading (issue
  #172) and the signature enrichment (issue #173) build on next; the
  chain suggestion keeps its `(...)` open for the signature pass to
  fill.
- The engine now holds every decompiled body for the scan's duration,
  so peak memory grows with the program's decompiled text. Accepted:
  the bodies are the same text the scan already read once, and the
  alternative — re-fetching for the pass — would break the
  exactly-once contract.

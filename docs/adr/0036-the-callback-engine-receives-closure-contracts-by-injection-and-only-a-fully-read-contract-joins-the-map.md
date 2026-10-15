# ADR-0036: The callback engine receives closure contracts by injection, and only a fully-read contract joins the map

- **Status:** Accepted
- **Date:** 2026-10-15
- **Deciders:** Arthur (solo project)

## Context

Phase 5 of the callback scan (issue #173, spec #169) asks the scan to
fill in what it has always left open: a registration or chain finding
names the callback it binds but suggests `Box<dyn Fn(...)>`, because
no single decompiled body spells the callback's contract. The
type-inference scan (P2.5, shipped) already reads that contract
piecemeal across the binary — parameter records from the bodies that
use the parameters, a return record from the callers that consume the
value — and persists it per binary at
`re/analysis/typeinfer/<binary>.json`. The obvious wiring, the
callback crate loading that document itself, is ruled out by the
spec: **the callback crate gains no new dependency on the
type-inference crate** — the integration is injection only. Two
callers must feed the same enrichment — the CLI `callback` command
and the batch pre-analysis — and the composition of the map from the
type-inference records must not be duplicated between them. The
enrichment must also be honest: the suggestion is advice to the
translator LLM, and a contract that misstates the callback's arity or
return is worse than the open `(...)`.

## Decision

Split the work along the dependency boundary the spec drew:

- The **callback crate** owns the injected map's shape and the
  rendering, in a new `signatures` module: `CallableSignature`
  (parameter types in order, optional return type, all as C text) and
  `SignatureMap` (callback spelling → contract). The engine gains a
  `with_signatures` builder beside the existing detector builders, and
  a hit replaces the `Fn(...)` placeholder inside the registration
  and chain suggestion templates — one substitution point, so the
  templates stay the source of truth for the prose around the
  contract. The crate reads no type-inference artifact and names no
  type-inference type.
- **Only registrations and chains are enriched.** The fp-array and
  jump-table callees are unnamed — there is no name to look up — and
  an event-system finding names a crowd of handlers whose contracts
  can differ, so no single one of them stands for the crowd; all
  three keep `(...)`.
- The **composition lives in the translator pipeline crate** — the
  wiring crate both callers already pass through — as
  `callback_signature_map(workspace, binary)`: it loads the
  type-inference document through the type-inference persistor and
  groups its records per function. The callback crate and the
  type-inference crate stay untouched by each other; the translator
  already depends on both.
- The composition is **honest about what the records prove**. A
  function joins the map only when its parameter records cover
  positions `0..n` contiguously **and** a return record stands: a gap
  proves a middle parameter the records never typed and a contract
  that skipped it would misplace every type after it; no parameter
  records at all cannot tell a zero-parameter callback from one whose
  parameters were never read; and with no return reading the contract
  would assert a unit return nobody read. A `void` return rides the
  map as read and drops its clause at render time — the C-semantics
  call belongs to the renderer, so a hand-built map gets the same
  contract as a composed one.
- A **missing, corrupt, or partial document yields an empty map** and
  the scan degrades silently to today's suggestions: a bad neighbor
  artifact never fails the callback scan. Missing logs at `debug`
  (the standalone scan is first-class), unreadable at `warn`.
- The enrichment is **scan-time, not prompt-time**: the engine
  deepens the finding's `suggestion` string before the result is
  assembled, so the persisted JSON, the CLI report, and the escalate
  prompt all carry the same enriched string through plumbing that
  does not change.

## Consequences

- The callback crate gains no dependency, and the type-inference
  crate gains no knowledge of callbacks: the seam is one builder
  method and one plain map type. This is the first evidence engine to
  take caller-supplied cross-scan context, and it shows the pattern
  costs nothing at the dependency boundary — but a third caller that
  wants the enrichment must reach through the translator helper (or
  recompose), so the composition's single home is the thing to
  preserve.
- The residual risk is arity: records for positions `0..n` cannot
  prove the callback has *exactly* n+1 parameters — a trailing
  parameter nobody typed is invisible. Accepted: the contract is a
  hypothesis, level with every other inference record the document
  already carries, and the suggestion is advice the LLM checks
  against the body in front of it. The open `(...)` remains the
  answer wherever the reading is not complete.
- Enriched suggestions are ordinary strings on the existing records:
  persistence, the CLI kind breakdown, and the prompt conversion ride
  the union accessors with no shape change, and older documents and
  un-enriched scans read back exactly as before.
- Batch order already works: the pre-analysis runs type inference
  before callback detection, so the cached document is usually in
  place; when it is not, the scan simply degrades.

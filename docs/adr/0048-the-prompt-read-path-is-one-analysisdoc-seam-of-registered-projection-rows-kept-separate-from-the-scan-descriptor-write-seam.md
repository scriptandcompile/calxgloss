# ADR-0048: The prompt read path is one AnalysisDoc seam of registered projection rows, kept separate from the scan-descriptor write seam

- **Status:** Accepted
- **Date:** 2026-10-25 (P35 shipped, issues #311–#315, spec #310)
- **Deciders:** Arthur (solo project)

## Context

P34 proved the descriptor-table shape on the scan **write** side: one
evidence engine contributes one row, and the registry owns the whole scan
phase (spec #301, shipped through #302–#308). The **read** side had never
received the same treatment. `gather_function_evidence` assembled the
per-function prompt bundle from nineteen near-identical
`extract_*`/`load_*` copies. Each copy spelled the same three steps — load
the evidence engine's persisted analysis document for the binary, keep the
records naming the target function, convert through the prompts crate's
`From` impls — differing only in crate name, persistor name, and miss-log
string. Each copy came with its own trio of degradation tests (no-workspace /
missing cache / corrupt cache), forty-nine in all, and nothing caught an
evidence engine drifting to a harsher or laxer failure mode than its
neighbors. A new evidence engine cost the whole hand-written spelling plus
its trio of tests (spec #310).

Because both sides name the same evidence engines and the same persisted
documents, the unification question was right there: why not let one
descriptor own both writing and reading a document? P34's rows already
hold each evidence engine's persistor and document location; an
`AnalysisDoc` adapter repeats that persistor load. The open questions were
what the read-side seam exposes, where it lives, whether the two tables
merge, and what projection stays bespoke.

## Decision

A second, separate seam — the **evidence-bundle projector** — lives in
the translator pipeline crate (`evidence_projector`, adapters in
`evidence_projector::adapters`), and the two tables deliberately stay
two:

- **The seam exposes exactly the three shared steps** and nothing else:
  an `AnalysisDoc` adapter loads its evidence engine's persisted document
  for one binary (`load`), yields the records one function holds
  (`for_function`, delegated to the engine result's own selection), and
  converts one record into the bundle field(s) (`fill`, over the prompts
  crate's existing `From` impls). Fourteen adapters make the seam real —
  one per per-function document that feeds the bundle.
- **The degradation contract is written once, in the seam, never in an
  adapter:** no workspace configured → the field stays empty, nothing
  logged; document missing or unparseable → one `debug` line naming the
  document kind, binary, and error, then empty, the two failure kinds
  logging distinctly (`DocLoadError::Missing` vs `Corrupt`); document
  present → exactly that function's records, in scan order. Absent context
  degrades the prompt and never fails it — the existing rule, now spelled
  in one place where it cannot repeat or drift.
- **Bundle assembly is one pass over a static table of rows.**
  `ProjectionRow` pairs an adapter with what it fills; `gather_function_evidence`
  keeps its exact signature and combines the `PROJECTION_ROWS` table.
  Documents feeding two bundle fields — consts (const findings + data-table
  findings) and type-inference (type info + parameter directions) — are
  single multi-field rows loaded exactly once per gather, so two fields can
  never disagree about what the workspace holds. A roster test locks the
  registered set, and the parametrized test suite in the helpers' test
  module runs every registered row through the gather at the existing
  external seam, so a new evidence engine lands already covered and a
  forgotten row fails CI.
- **The seam stays separate from the scan-descriptor table.** A P34 row
  schedules a scan: evidence engine construction, scan execution,
  persistence, warn-and-continue phase degradation, batch cadence. An
  `AnalysisDoc` row reads a persisted artifact during prompt assembly, per
  function, potentially many times per run, and may run against a workspace
  whose scans ran days earlier. The two tables coincide only on the
  document location — which neither hardcodes: both take it from the
  evidence engine's own persistor, the single owner of that location.
  Merging the tables would couple scan-phase scheduling to prompt assembly
  so that a change to one forces a change to the other; keeping them apart
  lets P36 render the bundle while knowing nothing of scan machinery, and
  lets the read side cover documents that are not per-binary scan outputs
  at all. Any future unification needs its own ADR (spec #310 recorded it
  as a later question; this ADR closes the question for now).
- **Projection that is genuinely specific to one evidence engine stays
  explicit bespoke code outside the seam:** libmatch's call-graph-
  correlated extraction (consumes the call graph, not just the function
  name), the async call-graph-neighbor and neighboring-context extractions
  (reads over the scan seam, not a persisted per-binary document), and the
  shim layer and PAL-trait extractions (whole-DLL reads, not per-function).
  Squeezing them into the seam would distort it; they keep their own
  tests.

## Consequences

- Adding an evidence engine to the prompt bundle is now one adapter plus
  one row — the three steps never have to be hand-spelled a nineteenth
  time, and the degradation trio comes free with registration (the
  parametrized suite plus the roster test, replacing forty-nine per-engine
  copies).
- Helper-module surface shrank accordingly: the nineteen hand-copied
  functions are gone except the five bespoke extractions, and
  `retry/helpers` lost roughly 1,500 lines while the projector module
  grew ~1,400 — the shared contract now has one home, documented at its
  definition.
- Evidence engine crates, persistor APIs, on-disk paths and formats,
  prompts-crate info types, and the P34 registry are untouched — existing
  workspaces and caches need no change, and gathered bundles are identical
  before and after (the whole-bundle behavior test passed unmodified across
  the whole migration).
- Two tables now list every evidence engine, and each keeps its own roster
  test; accepting that duplication is the price of the seam split. A
  document moving on disk needs no table edited — its persistor owns the
  path — but a scan losing its registry row, or a read losing its
  projection row, fails loudly in its own suite, not silently.
- P36 (bundle through the templates) uses exactly this seam: rendering
  will take the filled `EvidenceBundle` without knowing the seventeen
  evidence engine identities behind it, because the row table already
  hides them.

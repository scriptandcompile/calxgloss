# ADR-0048: The prompt read path is one AnalysisDoc seam of registered projection rows, kept separate from the scan-descriptor write seam

- **Status:** Accepted
- **Date:** 2026-10-25 (P35 shipped, issues #311–#315, spec #310)
- **Deciders:** Arthur (solo project)

## Context

P34 proved the descriptor-table shape on the scan **write** side: an
evidence engine contributes one row and the registry owns the whole scan
phase (spec #301, shipped through #302–#308). The **read** side had never
received the same treatment. `gather_function_evidence` assembled the
per-function prompt bundle from nineteen near-identical
`extract_*`/`load_*` copies, each spelling the same three steps — load
the engine's persisted analysis document for the binary, keep the records
naming the target function, convert through the prompts crate's `From`
impls — differing only in crate name, persistor name, and miss-log
string. Each copy carried its own trio of degradation tests
(no-workspace / missing cache / corrupt cache), forty-nine in all, and
nothing caught an engine drifting to a harsher or laxer failure mode than
its neighbors. A new engine's price was the whole spelling plus its trio
(spec #310).

Because both sides name the same engines and the same persisted
documents, the unification question sat right there: why not let one
descriptor own both writing and reading a document? P34's rows already
carry each engine's persistor and document location; an `AnalysisDoc`
adapter repeats that persistor load. The open questions were what the
read-side seam exposes, where it lives, whether the two tables merge,
and what projection stays bespoke.

## Decision

A second, separate seam — the **evidence-bundle projector** — lives in
the translator pipeline crate (`evidence_projector`, adapters in
`evidence_projector::adapters`), and the two tables deliberately stay
two:

- **The seam exposes exactly the three shared steps** and nothing else:
  an `AnalysisDoc` adapter loads its engine's persisted document for one
  binary (`load`), yields the records one function holds (`for_function`,
  delegated to the engine result's own selection), and converts one
  record into the bundle field(s) (`fill`, over the prompts crate's
  existing `From` impls). Fourteen adapters make the seam real — one per
  per-function document that feeds the bundle.
- **The degradation contract is spelled once, in the seam, never in an
  adapter:** no workspace configured → the field stays empty, nothing
  logged; document missing or unparseable → one `debug` line naming the
  document kind, binary, and error, then empty, the two failure kinds
  logging distinctly (`DocLoadError::Missing` vs `Corrupt`); document
  present → exactly that function's records, in scan order. Absent
  context degrades the prompt and never fails it — the existing rule,
  now un-repeating and undriftable.
- **Bundle assembly is a fold over a static row table.** `ProjectionRow`
  pairs an adapter with what it fills; `gather_function_evidence` keeps
  its exact signature and folds `PROJECTION_ROWS`. Documents feeding two
  bundle fields — consts (const findings + data-table findings) and
  type-inference (type info + parameter directions) — are single
  multi-field rows loaded exactly once per gather, so two fields can
  never disagree about what the workspace holds. A roster test pins the
  registered set, and the parametrized suite in the helpers' test module
  drives every registered row through the gather at the existing
  external seam, so a new engine lands covered automatically and a
  forgotten row fails CI.
- **The seam stays separate from the scan-descriptor table.** A P34 row
  schedules a scan: engine construction, scan execution, persistence,
  warn-and-continue phase degradation, batch cadence. An
  `AnalysisDoc` row reads a persisted artifact during prompt assembly,
  per function, potentially many times per run, and may run against a
  workspace whose scans ran days earlier. They coincide only on the
  document location — which neither table hardcodes: both borrow it from
  the engine's own persistor, the single owner. Merging the tables would
  couple scan-phase scheduling to prompt assembly so that a change to
  one forces a change to the other; keeping them apart lets P36 render
  the bundle while knowing nothing of scan machinery, and lets the read
  side cover documents that are not per-binary scan outputs at all. Any
  future unification needs its own ADR (spec #310 recorded it as a
  later question; this ADR closes the question for now).
- **Genuinely engine-specific projection stays explicit bespoke code
  outside the seam:** libmatch's call-graph-correlated extraction
  (consumes the call graph, not just the function name), the async
  call-graph-neighbor and neighboring-context extractions (reads over
  the scan seam, not a persisted per-binary document), and the shim
  layer and PAL-trait extractions (whole-DLL reads, not per-function).
  Squeezing them into the seam would distort it; they keep their own
  tests.

## Consequences

- Adding an evidence engine to the prompt bundle is now one adapter plus
  one row — the nineteenth copy of the spelling is never re-spelled, and
  the degradation trio comes free with registration (the parametrized
  suite plus the roster test, replacing forty-nine per-engine copies).
- Helper-module surface shrank accordingly: the nineteen hand-copied
  functions are gone except the five bespoke extractions, and
  `retry/helpers` lost roughly 1,500 lines while the projector module
  grew ~1,400 — the shared contract now has one home, documented at its
  definition.
- Engine crates, persistor APIs, on-disk paths and formats, prompts-crate
  info types, and the P34 registry are untouched — existing workspaces
  and caches need no change, and gathered bundles are identical before
  and after (the whole-bundle behavior test passed unmodified across the
  whole migration).
- Two tables now name every engine, and each keeps its own roster test;
  that duplication is the accepted price of the seam split. A document
  moving on disk needs no table edited — its persistor owns the path —
  but a scan losing its registry row or a read losing its projection row
  each fails loudly in its own suite, not silently.
- P36 (bundle through the templates) consumes exactly this seam:
  rendering will take the filled `EvidenceBundle` without knowing
  seventeen engine identities, because the fold already hides them.

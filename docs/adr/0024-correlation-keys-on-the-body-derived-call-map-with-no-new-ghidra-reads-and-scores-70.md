# ADR-0024: Correlation keys on the body-derived call map with no new Ghidra reads, and scores above a single-body match

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-3 shipped, issue #154)
- **Deciders:** Arthur (solo project)

## Context

Every algorithm detector so far read exactly one function at a time: a
control flow signature, a string signature, or a callback contract. Each
was decided from one body, plus at most the listing. Algorithms that
live in the *call relationship between* two functions the scan already
decompiles were invisible. Two examples: a recursive routine that halves
its problem, and a sort that drives a comparator callback. Each half
reads as an ordinary function on its own.

Spec #151 asked for a multi-function correlation detector that emits
`cross_function` hints. Four questions had to be settled. Where does the
call map come from? (The typeinfer precedent, P2.5-2, fetched caller
bodies through the graph.) What is the detector's confidence relative to
the ADR-0022 ladder? Which relationships does it ship knowing? And how
do its hints enter resolution and the confidence floor?

## Decision

- **The call map is derived from the bodies the scan already holds —
  no new Ghidra round trips.** The correlation pass runs after the
  per-function pass, over the `DecompiledFunction` bodies the scan
  collected anyway. It reads each body for the program's own function
  names, appearing as whole identifier tokens. These token matches
  cover both call shapes that matter: a direct call (`FUN_x(...);`) and
  a callback handed to a host (`qsort(a, n, 4, FUN_y)`); the graph xref
  route would have had to reconstruct the second shape. The scan's
  fetch counts — decompiles, string reads, caller reads — are identical
  with the detector present and absent. A test pins this at the evidence
  engine's seam. The typeinfer crate's caller-fetching pass had a
  different contract: it types *callers*, which the algorithm scan never
  fetches. Here every function in the listing is already in hand, so the
  graph adds nothing.
- **The detector scores 70 — above a single-body match (60), below a
  call-graph-confirmed callback contract (75).** A correlation is
  stronger evidence than one body's shape, because two functions'
  bodies agree on the relationship. It is weaker than a contract the
  call graph itself confirms: there, the graph states the host's demand
  directly instead of inferring it. The score lives in the shared
  confidence module beside the others, so ADR-0022's resolution and
  floor apply to correlated hints with no new plumbing. A correlated
  claim for the same algorithm wins against a 60 body match, and a floor
  above 70 drops correlated hints like any other.
- **Relationships are data, shaped like the other detectors' patterns.**
  A `CorrelationRelationship` names an algorithm and a category. It
  carries `body_patterns` that every host body must match, with the
  `{name}` placeholder for self-reference. It carries optional
  `partner_patterns` that the callee's body must match, a line-count
  floor, and an optional per-entry `confidence`. This is the ADR-0023
  field convention, so #155's pattern-database section for this detector
  will be pure wiring, not a format change. A relationship with no
  partner patterns is proven by the host body alone: recursion beside a
  halving needs no second function.
- **The built-in set is deliberately small: `divide_and_conquer` and
  `comparison_sort`.** Both are shapes that existing bodies already
  show in real programs, and neither collides with the built-in cfg
  set. The cfg `comparison_sort` signature deliberately excludes
  `\bqsort\b`. So a qsort-driven sort is claimed *only* by the
  correlation detector, and a hand-rolled bubble sort only by the cfg
  matcher. The set is a seed, not the full corpus — the pattern
  database is where an operator extends it.
- **Partner selection is first fit in listing order, and the evidence
  is the body line naming the partner.** Where several mentioned
  functions fit the partner shapes, the first one in listing order
  gives the hint. This keeps two scans of one program byte-identical.
  The evidence is the first body line naming the partner after the
  opening brace. The signature line is skipped, because a function's
  own name there is never call-shaped evidence. So the hint quotes the
  call or callback that made the correlation.

## Consequences

- The scan gained a fourth detector and a fourth `DetectionMethod`
  (`cross_function`), visible in the hint, the persisted JSON, and the
  `algorithm --show` breakdown. `DetectionMethod`'s serde label is
  `cross_function`, and documents persisted before the change load
  unchanged.
- Correlated hints append after the per-function hints, in listing
  order. The persisted document's scan-order contract still holds,
  and two scans of one program still diff cleanly.
- The correlation pass needs the whole listing in hand. So it runs
  once per scan after the per-function pass, not per function. #156's
  parallelization must keep this shape: the pass is not per-function
  work, and its output order is listing order.
- The fetch counts prove the zero-extra-reads claim. An evidence-engine
  test pins this by comparing a scan with the detector against one with
  an empty detector: identical decompiles, string reads, and caller
  reads.
- ADR-0023's whole-replacement contract extends to the fourth detector:
  `with_pattern_database` also empties the correlation detector, since
  the database has no correlation section yet. A file that removes the
  built-in `qsort` shape never keeps a built-in correlation. #155's
  section fills the gap.

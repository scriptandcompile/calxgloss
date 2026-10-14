# ADR-0024: Correlation keys on the body-derived call map with no new Ghidra reads, and scores above a single-body match

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-3 shipped, issue #154)
- **Deciders:** Arthur (solo project)

## Context

Every algorithm detector so far read exactly one function at a time: a
control flow signature, a string signature, a callback contract — each
decided from one body plus at most the listing. Algorithms that live in
the *call relationship between* two functions the scan already
decompiles — a recursive routine that halves its problem, a sort that
drives a comparator callback — were invisible: each half reads as an
ordinary function on its own.

Spec #151 asked for a multi-function correlation detector emitting
`cross_function` hints. The questions this had to settle: where the
call map comes from (the typeinfer precedent, P2.5-2, fetched caller
bodies through the graph); what the detector's confidence is relative
to the ADR-0022 ladder; what relationships it ships knowing; and how
its hints enter resolution and the confidence floor.

## Decision

- **The call map is derived from the bodies the scan already holds —
  no new Ghidra round trips.** The correlation pass runs after the
  per-function loop, over the `DecompiledFunction` bodies the scan
  collected anyway, and reads each body for the program's own function
  names appearing as whole identifier tokens. That token reading covers
  both call shapes that matter: a direct call (`FUN_x(...);`) and a
  callback handed to a host (`qsort(a, n, 4, FUN_y)`), which the graph
  xref route would have had to reconstruct. The scan's fetch counts —
  decompiles, string reads, caller reads — are identical with the
  detector present and absent; a test pins this at the engine seam.
  The typeinfer crate's caller-fetching pass had a different contract
  (it types *callers*, which the algorithm scan never fetches); here
  every function in the listing is already in hand, so the graph buys
  nothing.
- **The detector scores 70 — above a single-body match (60), below a
  call-graph-confirmed callback contract (75).** A correlation is
  stronger evidence than one body's shape, because two functions'
  bodies agree on the relationship; it is weaker than a contract the
  call graph itself confirms, which names the host's demand rather
  than inferring it. The score lives in the shared confidence module
  beside the others, so ADR-0022's resolution and floor apply to
  correlated hints with no new plumbing: a correlated claim for the
  same algorithm beats a 60 body match, and a floor above 70 drops
  correlated hints like any other.
- **Relationships are data, shaped like the other detectors' patterns.**
  A `CorrelationRelationship` names an algorithm and category, carries
  `body_patterns` every host body must match (with the `{name}`
  placeholder for self-reference), optional `partner_patterns` the
  callee's body must match, a line-count floor, and an optional
  per-entry `confidence` — the ADR-0023 field convention, so #155's
  pattern-database section for this detector is pure wiring, not a
  format change. A relationship with no partner patterns is
  self-carried: the host body alone proves it (recursion beside a
  halving needs no second function).
- **The built-in set is deliberately small: `divide_and_conquer` and
  `comparison_sort`.** Both are shapes the existing bodies already
  show in real programs, and neither collides with the built-in cfg
  set: the cfg `comparison_sort` signature deliberately excludes
  `\bqsort\b`, so a qsort-driven sort is claimed *only* by the
  correlation detector, and a hand-rolled bubble sort only by the cfg
  matcher. The set is the seed, not the corpus — the pattern database
  is where an operator grows it.
- **Partner selection is first fit in listing order, and evidence is
  the body line naming the partner.** Where several mentioned
  functions fit the partner shapes, the listing's first one carries
  the hint, keeping two scans of one program byte-identical. The
  evidence is the first body line naming the partner after the
  opening brace — the signature line is skipped, since a function's
  own name there is never call-shaped evidence — so the hint quotes
  the call or callback that made the correlation.

## Consequences

- The scan gained a fourth detector and a fourth `DetectionMethod`
  (`cross_function`), visible in the hint, the persisted JSON, and the
  `algorithm --show` breakdown; `DetectionMethod`'s serde label is
  `cross_function`, and documents persisted before the change load
  unchanged.
- Correlated hints append after the per-function hints, in listing
  order: the persisted document's scan-order contract still holds,
  and two scans of one program still diff cleanly.
- The correlation pass needs the whole listing in hand, so it runs
  once per scan after the loop rather than per function — the shape
  #156's parallelization must keep (the pass is not per-function
  work, and its output order is listing order).
- Fetch counts are the proof of the zero-extra-reads claim, pinned by
  an engine test comparing a scan with the detector against one with
  an empty detector: identical decompiles, string reads, and caller
  reads.
- ADR-0023's whole-swap contract extends to the fourth detector:
  `with_pattern_database` also empties the correlation detector, since
  the database carries no correlation section yet — a file that
  retires the built-in `qsort` shape never keeps a built-in
  correlation. #155's section fills the gap.

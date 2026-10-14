# ADR-0025: The correlation section completes the pattern database, replacing the built-in relationships whole

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-4 shipped, issue #155)
- **Deciders:** Arthur (solo project)

## Context

ADR-0023 made the scan's three per-function signature sets data: one
JSON document, one section per detector, entries exactly the pattern
types' serde shapes. ADR-0024 then made the fourth detector's
relationships data-shaped records — `CorrelationRelationship` already
carried the body shapes, partner shapes, line floor, and per-entry
confidence — and explicitly deferred the document's fourth section,
calling it "pure wiring". Until now the whole-swap contract carried a
stated gap: a supplied database emptied the correlation detector,
because the document had nothing to carry its set.

Spec #151's story 7 asks for one database file covering all four
detectors, so an operator's file describes everything the scan knows.
The questions this had to settle: whether the fourth section joins the
same document or rides a separate one; whether a supplied section
merges with the built-in relationship set or replaces it; whether an
omitted section keeps the built-in set (the fourth section behaving
differently from the other three) or empties the detector like they
do; and where the built-in set lives once relationships are data.

## Decision

- **The fourth section joins the same document, keyed
  `correlation_patterns`, and its entries are exactly the
  `CorrelationRelationship` serde shape.** No new wire format, holding
  ADR-0023's precedent: what a scan persists and what a database
  carries stay the same thing, and the relationship type's existing
  round-trip and `deny_unknown_fields` tests already pin half the
  section's format. Because ADR-0024 put the per-entry confidence on
  the type up front, the section adds no field and no scoring change —
  a file relationship claims at the standard 70 or its own confidence,
  and joins resolution and the floor exactly like a built-in one.
- **A supplied section replaces the built-in relationship set whole;
  an omitted section is an empty set.** The fourth section means
  exactly what the other three mean: the file is what the scan knows,
  and a file that names only its own relationships retires
  `divide_and_conquer` and `comparison_sort` with it. The alternative
  — an absent section keeping the built-in set, say an
  `Option<Vec<...>>` — was rejected: it would make one section behave
  backwards from the other three, split "a section the document omits
  is an empty set" into two rules, and break the silence contract the
  engine test pinned before the section even existed. The built-in
  set remains the default in exactly one place: a scan supplied no
  database file at all.
- **The built-in set stays in Rust as the seed, not the corpus.**
  `default_relationships` keeps the two honest built-in relationships
  for the no-file default; the file replaces it rather than growing
  it, so retiring a built-in relationship that misfires on one binary
  works the same way retiring a built-in signature always has.

## Consequences

- The pattern document now describes everything the scan knows — all
  four detectors read their sets from it — and the `--patterns` flag
  and the CLI wiring are untouched: the section rides the existing
  load, the existing whole swap, and the existing loud failure on a
  malformed document, including a misspelled relationship field.
- The engine's silence test stays green: a supplied document without
  the section still leaves the fourth detector with nothing to read.
  The whole-swap contract was pinned before the section landed, and
  the section filled ADR-0023's gap without bending the contract.
- The four section keys are pinned by one serde test, so a future
  fifth detector's section is the same additive move: a field on the
  document, a swap in `with_pattern_database`, a key in the pin.
- File-taught relationships are ordinary correlations: the evidence
  names the partner, hints land under `cross_function`, and two scans
  of one program still diff cleanly — the file's entry order is scan
  order, the way every detector's configuration order has been.

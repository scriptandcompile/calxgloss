# ADR-0025: The correlation section completes the pattern database, replacing the built-in relationships whole

- **Status:** Accepted
- **Date:** 2026-10-14 (P3.5-4 shipped, issue #155)
- **Deciders:** Arthur (solo project)

## Context

ADR-0023 made the scan's three per-function signature sets into data:
one JSON document, one section per detector, entries exactly the pattern
types' serde shapes. ADR-0024 then made the fourth detector's
relationships into data-shaped records. `CorrelationRelationship`
already held the body shapes, partner shapes, line floor, and per-entry
confidence. ADR-0024 explicitly deferred the document's fourth section,
calling it "pure wiring". Until now, the whole-replacement contract
carried a stated gap: a supplied database emptied the correlation
detector, because the document had nothing to hold the correlation set.

Spec #151's story 7 asks for one database file covering all four
detectors, so an operator's file describes everything the scan knows.
Four questions had to be settled. Does the fourth section join the same
document or a separate one? Does a supplied section merge with the
built-in relationship set, or replace it? If the section is omitted,
does it keep the built-in set — making the fourth section behave
differently from the other three — or empty the detector like they do?
And where does the built-in set live once relationships are data?

## Decision

- **The fourth section joins the same document, keyed
  `correlation_patterns`, and its entries are exactly the
  `CorrelationRelationship` serde shape.** There is no new wire format.
  This keeps ADR-0023's precedent: what a scan persists and what a
  database holds stay the same thing. The relationship type's existing
  round-trip and `deny_unknown_fields` tests already pin half of the
  section's format. Because ADR-0024 put the per-entry confidence on
  the type from the start, the section adds no field and no scoring
  change. A relationship from a file claims at the standard 70 or at its
  own confidence, and joins resolution and the floor exactly like a
  built-in one.
- **A supplied section replaces the built-in relationship set whole;
  an omitted section is an empty set.** The fourth section means
  exactly what the other three mean: the file is what the scan knows. A
  file that names only its own relationships also removes
  `divide_and_conquer` and `comparison_sort` with them. The
  alternative — an absent section keeping the built-in set, say an
  `Option<Vec<...>>` — was rejected. It would make one section behave
  backwards from the other three. It would split "a section the document
  omits is an empty set" into two rules. And it would break the silence
  contract that the evidence-engine test pinned before the section even
  existed. The built-in set remains the default in exactly one place: a
  scan that supplied no database file at all.
- **The built-in set stays in Rust as the seed, not the corpus.**
  `default_relationships` keeps the two honest built-in relationships
  for the no-file default. A file replaces this set rather than
  extending it. So removing a built-in relationship that misfires on one
  binary works the same way removing a built-in signature always has.

## Consequences

- The pattern document now describes everything the scan knows — all
  four detectors read their sets from it. The `--patterns` flag
  and the CLI wiring are untouched. The section uses the existing load,
  the existing whole swap, and the existing loud failure on a
  malformed document, including a misspelled relationship field.
- The evidence engine's silence test stays green: a supplied document
  without the section still leaves the fourth detector with nothing to
  read. The whole-swap contract was pinned before the section landed,
  and the section filled ADR-0023's gap without changing the contract.
- The four section keys are pinned by one serde test. So a future
  fifth detector's section is the same additive move: a field on the
  document, a swap in `with_pattern_database`, a key in the pin.
- Relationships taught by a file are ordinary correlations: the evidence
  names the partner, and hints land under `cross_function`. Two scans
  of one program still diff cleanly. The file's entry order is scan
  order, the way every detector's configuration order has been.

# ADR-0010: Struct candidates merge when their cross-reference evidence overlaps by half the smaller reader set

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-2 shipped, issue #138)
- **Deciders:** Arthur (solo project)

## Context

String-guided struct inference clusters string literals by the functions
that reference them. A struct whose fields are read through a *hub*
function gets split. A hub reads more literals than `MAX_HUB_FANOUT` (24),
which is too many for the hub to be a meaningful clustering key. The
fields each real method reads form one candidate, and the hub's shared
readers cannot pull the halves together. The same `Widget` then appears in
the database as two half-candidates. Each has half the fields, half the
evidence, and a weaker confidence, and the translator's prompts see two
hypotheses where the program has one class.

The merge rule needed deliberate choices: what overlap counts as "the same
struct"; the order the pass runs in, so a vtable link survives; and how a
merged candidate is named, scored, and kept deterministic.

## Decision

`TypesDBEngine::scan` runs a pure candidate-level merge pass
(`merge_candidates` in `engine.rs`) **after** the vtable-linking pass of
ADR-0009. A half that already has a `linked_vtable` and an RTTI class name
keeps both through the merge:

- **Overlap is measured on referencing functions, and only hubs can make
  it happen.** Two candidates merge when their `referenced_by` sets share
  at least one function and the shared set reaches half of the *smaller*
  set (`shared * 2 >= smaller`). No name-identity guard is needed. The
  literal-level union-find already merges any two clusters sharing a
  non-hub function, so overlap between distinct candidates can only come
  from hub readers — exactly the split this pass repairs. Candidates with
  disjoint readers (two genuinely different structs read by different
  functions) stay separate.
- **`referenced_by` now includes hub functions too.** The clustering keys
  still exclude hubs. Inference-time naming (`function_stem`) and scoring
  still run on the key functions only, so existing names and scores do not
  shift. But the persisted evidence list includes every reader, and that
  is what lets the overlap rule see the hub at all.
- **Deterministic order.** Candidates are sorted by (first field's
  `source_address`, name) before a union-find groups them, so the merge
  result never depends on scan order. The final list is re-sorted by
  confidence descending and name ascending — the database's existing
  order. Two scans of one program produce byte-identical knowledge: named
  types, vtables, and candidates serialize to the same bytes. Only the
  scan timestamp differs.
- **The strongest half names the merge.** The merged candidate takes its
  name, `name_origin`, and `linked_vtable` from the member with the
  strongest name origin (`NameOrigin::confidence_bonus`). A tie goes to
  the earlier literal address. One link survives: if both halves linked to
  different tables, the dominant half's table wins.
- **The field union keeps a stable order.** Fields are concatenated and
  sorted by (source address, name). Offsets are re-accumulated under the
  same 4-byte cursor rule `infer_candidate` uses, so a merged layout reads
  like one inferred from scratch.
- **Confidence re-scores on merged evidence, monotonically.** The merged
  score starts from the strongest member's confidence. It adds a breadth
  gain for fields the merge adds past the widest member, and an agreement
  gain for readers it adds past the widest reader set. These are the same
  per-field and per-reader payouts `score()` pays; the merge's gains count
  the persisted reader list, hubs included. The result is clamped at 100.
  A merge can never score below either half it came from, so the
  min-confidence threshold, which filters before the pass, still filters
  only genuinely weak hypotheses.
- **The merge is recorded, serde-optionally.** `merged_from: Option<usize>`
  on `InferredStruct` is `Some(n)` when n ≥ 2 halves merged and absent
  otherwise. Databases written before the pass load unchanged, and the
  `calxgloss typesdb` report marks merged rows and counts them.

## Consequences

A struct read through a hub now reaches the persisted document, the
translator prompts, and the report as one candidate with the full field
list, the union of its readers, and one name — instead of two halves that
each looked too thin to trust. The cost is a new false-merge risk. Two
*different* structs whose readers happen to overlap only through a hub
will merge when the overlap reaches the half-of-smaller bar. Because
grouping is a union-find, merging is transitive: A with B and B with C
makes one candidate even where A and C alone would not clear the bar. That
bet is accepted because candidates stay confidence-scored hypotheses, the
bar requires the overlap to be a real fraction of one candidate's whole
reader set, and the `merged_from` marker keeps the provenance visible to
reviewers. The threshold constants
(`MERGE_OVERLAP_NUMERATOR`/`_DENOMINATOR`) sit in one place, in case real
binaries demand tuning.

# ADR-0009: Inferred candidates link to RTTI-confirmed vtables on one shared method, and take the class name

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-1 shipped, issue #137)
- **Deciders:** Arthur (solo project)

## Context

String-guided struct inference recovers *inferred candidates* — struct
hypotheses clustered from string literals — but many fall back to an
address-derived name (`strings_at_…`), which is nearly worthless as prompt
evidence. Meanwhile the vtable scan already recovers *RTTI-confirmed vtables*
with demangled class names. When the functions referencing a candidate's
literals are that vtable's methods, the string evidence and the RTTI evidence
describe one class, and the candidate can carry the program's own name for it.

The linking rule needed a deliberate choice: the ticket wording ("whose
referencing functions are the methods of an RTTI-confirmed vtable") could
mean *all* or merely *some* of the referencing functions.

## Decision

`TypesDBEngine::scan` runs a pure candidate-level pass after the three
concurrent scans (no new Ghidra endpoints):

- **One shared method is enough to link.** A candidate links to a confirmed
  vtable when its referencing functions *include* at least one of the
  table's named methods — not when all of them are methods. Requiring all
  would drop true links wherever a free function or global accessor also
  reads the member literals; the false-link risk of *any* is accepted
  because a candidate stays a confidence-scored hypothesis, never a fact.
- **Deterministic winner.** A candidate matching several tables links to the
  one sharing the most methods; ties go to the lowest vtable address, so two
  scans of one program diff cleanly.
- **The link is keyed by vtable address** (`linked_vtable: Option<u64>`,
  serde-optional so databases written before the pass still load). Vtables
  are keyed by address everywhere in the database — Ghidra labels them all
  `vftable` — and the named-type merge of P1.5-2 builds on this link.
- **A confirmed table whose RTTI class name never resolved links nothing.**
  The link exists to carry a real class name; without one there is nothing
  to take, and a link with no name would be a dangling address.
- **The class name tops the name-origin ladder.** `vtable_class` ranks above
  literal-prefix and function-stem names, address stays last; the ladder's
  payouts live in one place (`NameOrigin::confidence_bonus`) and a linked
  candidate is re-scored by swapping its old origin's payout for the new
  one's, so the confidence score and the ladder can never drift apart.

## Consequences

Candidates that previously shipped `DAT_…`-style names now arrive — in the
persisted document, the translator prompts, and the `calxgloss typesdb`
report — with a real class name and higher confidence. A linked candidate's
weaker literal- or stem-derived name is replaced, not kept alongside; the
`name_origin` field records the promotion. Matching is by Ghidra function
name on both sides, so a method slot pointing outside any function body
carries no name and can never contribute a match.

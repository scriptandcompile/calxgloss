# ADR-0009: Inferred candidates link to RTTI-confirmed vtables on one shared method, and take the class name

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-1 shipped, issue #137)
- **Deciders:** Arthur (solo project)

## Context

String-guided struct inference recovers *inferred candidates*: struct
hypotheses clustered from string literals. Many candidates fall back to an
address-derived name (`strings_at_…`), which is nearly worthless as prompt
evidence. Meanwhile the vtable scan already recovers *RTTI-confirmed
vtables* with demangled class names. Sometimes the functions referencing a
candidate's literals are that vtable's methods. When they are, the string
evidence and the RTTI evidence describe one class, and the candidate can
take the program's own name for it.

The linking rule needed a deliberate choice. The ticket wording ("whose
referencing functions are the methods of an RTTI-confirmed vtable") could
mean *all* of the referencing functions or merely *some* of them.

## Decision

`TypesDBEngine::scan` runs a pure candidate-level pass after the three
concurrent scans. It adds no new Ghidra endpoints:

- **One shared method is enough to link.** A candidate links to a confirmed
  vtable when its referencing functions *include* at least one of the
  table's named methods. They do not all have to be methods. Requiring all
  of them would drop true links wherever a free function or global
  accessor also reads the member literals. We accept the false-link risk
  of *any*, because a candidate stays a confidence-scored hypothesis,
  never a fact.
- **Deterministic winner.** A candidate that matches several tables links
  to the table it shares the most methods with. A tie goes to the lowest
  vtable address, so two scans of one program diff cleanly.
- **The link is keyed by vtable address** (`linked_vtable: Option<u64>`,
  serde-optional so databases written before the pass still load). Every
  part of the database keys vtables by address, because Ghidra labels them
  all `vftable`. The named-type merge of P1.5-2 builds on this link.
- **A confirmed table whose RTTI class name never resolved links nothing.**
  The link exists to hand over a real class name. Without a name there is
  nothing to take, and a link with no name would be a dangling address.
- **The class name tops the name-origin ladder.** `vtable_class` ranks
  above the literal-prefix and function-stem names, and address stays last.
  The bonus for each name origin lives in one place
  (`NameOrigin::confidence_bonus`). A linked candidate is re-scored by
  swapping the bonus of its old origin for the bonus of the new one, so
  the confidence score and the ladder can never drift apart.

## Consequences

Candidates that previously had `DAT_…`-style names now have a real class
name and higher confidence — in the persisted document, the translator
prompts, and the `calxgloss typesdb` report. A linked candidate's weaker
literal- or stem-derived name is replaced, not kept alongside. The
`name_origin` field records the promotion. Both sides match by Ghidra
function name, so a method slot pointing outside any function body has no
name and can never contribute a match.

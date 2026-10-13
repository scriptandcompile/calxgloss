# ADR-0011: Recover type nesting by linking fields to named types by exact name, in a post-assembly pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-3 shipped, issue #139)
- **Deciders:** Arthur (solo project)

## Context

The type database recovers each named type as a flat field list, but real
programs nest: a struct field typed `MODES` is a field typed as the enum
the scan also recovered, and the prompt — which renders each type as a
flat list — loses that. The field record already carries the type's *name*
(`type_name`), and the scan already knows every recovered type's *path*
and *kind*; what is missing is a link between them. Ghidra's own field
type is a pointer into the Type Manager, but our recovered records are
built from memory-access evidence, not from Ghidra's field decomposition,
so no existing endpoint hands us the nesting.

## Decision

Nesting is a **pure post-assembly pass** in the engine — after vtable
linking and split/merge, over the final named-type list — that links each
field whose type name matches a recovered named type **by exact name**,
keyed on the Type Manager path.

- **Exact name, keyed on the path.** The link stores the matched type's
  Type Manager path, not its name: paths are unique, names are not, and
  the path is what a consumer resolves.
- **Ambiguity stays unlinked.** When several recovered types share a name
  — which happens exactly when Ghidra applied the same typedef in several
  categories — the field names them all equally and nothing in the field
  record carries a category to pick one. A wrong link would render a
  wrong subtree into the prompt, so the field stays unlinked.
- **The kind rides the link.** The field also records the linked type's
  kind, so a field typed as a recovered union renders as `union MY_UNION`
  in the prompt instead of being misread as a struct.
- **Named-type fields only.** An inferred field is a raw memory access
  with no type name at all — there is nothing to match — so the pass
  touches only `StructField`s.
- **The links are serde-optional.** A document written before this pass
  still loads, keeping the wire format additive.

## Consequences

- Positive:
  - The prompt shows the type tree within each type's existing field
    list — no new prompt sections, no new template.
  - A field typed as a union or enum is no longer misread as a struct.
  - The pass is pure and deterministic: no new endpoint, no new LLM
    call, no new state — it composes with the vtable-link and split/merge
    passes already in `scan`.
  - The `typesdb` report names the nested-field count, making nesting
    visible on real binaries.
- Negative:
  - A same-named type that *is* the right match (one category's typedef
    applied over another) stays unlinked — the field record carries no
    category to disambiguate, and guessing would corrupt the rendered
    subtree. Accepted: an unlinked field still names its type.
  - The link is a record-and-render enhancement, not a re-parse: the
    nested type's own fields are not inlined into the outer type's list.
    A consumer that wants the subtree resolves the path.

# ADR-0011: Recover type nesting by linking fields to named types by exact name, in a post-assembly pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-3 shipped, issue #139)
- **Deciders:** Arthur (solo project)

## Context

The type database recovers each named type as a flat field list, but real
programs nest. A struct field typed `MODES` is a field typed as the enum
the scan also recovered, and the prompt — which renders each type as a
flat list — loses that. The field record already has the type's *name*
(`type_name`), and the scan already knows every recovered type's *path*
and *kind*. What is missing is a link between them. Ghidra's own field
type is a pointer into the Type Manager, but our recovered records are
built from memory-access evidence, not from Ghidra's field decomposition,
so no existing endpoint gives us the nesting.

## Decision

Nesting is a **pure post-assembly pass** in the evidence engine. It runs
after vtable linking and split/merge, over the final named-type list. It
links each field whose type name matches a recovered named type **by exact
name**, keyed on the Type Manager path.

- **Exact name, keyed on the path.** The link stores the matched type's
  Type Manager path, not its name. Paths are unique; names are not. The
  path is what a consumer resolves.
- **Ambiguity stays unlinked.** Several recovered types can share a name,
  and that happens exactly when Ghidra applied the same typedef in several
  categories. Then the field names them all equally, and nothing in the
  field record has a category to pick one. A wrong link would render a
  wrong subtree into the prompt, so the field stays unlinked.
- **The link also records the kind.** The field records the linked type's
  kind, so a field typed as a recovered union renders as `union MY_UNION`
  in the prompt instead of being misread as a struct.
- **Named-type fields only.** An inferred field is a raw memory access
  with no type name at all, so there is nothing to match. The pass touches
  only `StructField`s.
- **The links are serde-optional.** A document written before this pass
  still loads. The wire format stays additive.

## Consequences

- Positive:
  - The prompt shows the type tree within each type's existing field
    list — no new prompt sections, no new template.
  - A field typed as a union or enum is no longer misread as a struct.
  - The pass is pure and deterministic: no new endpoint, no new LLM
    call, no new state. It composes with the vtable-link and split/merge
    passes already in `scan`.
  - The `typesdb` report shows the nested-field count, which makes
    nesting visible on real binaries.
- Negative:
  - A same-named type that *is* the right match (one category's typedef
    applied over another) stays unlinked. The field record has no
    category to disambiguate with, and guessing would corrupt the
    rendered subtree. Accepted: an unlinked field still names its type.
  - The link adds recording and rendering; it is not a re-parse. The
    nested type's own fields are not inlined into the outer type's list.
    A consumer that wants the subtree resolves the path.

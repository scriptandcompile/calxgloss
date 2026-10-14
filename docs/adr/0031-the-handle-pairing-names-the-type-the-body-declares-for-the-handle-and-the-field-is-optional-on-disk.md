# ADR-0031: The handle pairing names the type the body itself declares for the handle, the scoped narrowing still outranks it, and the field is optional on disk

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-5 shipped, issue #162)
- **Deciders:** Arthur (solo project)

## Context

The handle pairing detector suggested a generic "RAII guard struct with
Drop impl" for every closed pair. But the decompiled body often spells a
real type for the handle variable — `HANDLE hFile = CreateFileW(...)`, a
hoisted `FILE *local_10;` — and a Rust translation reading the finding
has to invent that wrapper name itself. Naming it in the suggestion
(`impl Drop for HANDLE`) says which type the `Drop` impl belongs to.

The questions: where the type may come from (the declaration, a cast, a
guess?), what counts as nameable versus the decompiler's untyped
vocabulary, how the upgrade interacts with the existing scoped
(read-after-close) narrowing, and what happens to documents persisted
before the field existed.

## Decision

- **The type comes only from the body's own declaration.** A binding
  the decompiler spelled `<Type> <variable>;` or `<Type> <variable> =
  ...;` — the name followed by `;` or a plain `=`, preceded, past any
  `*`, by a spelled type word. A bare assignment (`hFile =
  CreateFileW(...)`) declares nothing, and the reading never invents a
  type from casts, opener names, or convention.
- **A nameable type is a spelled identifier outside the primitive
  family.** All words plain identifiers, none a statement keyword, and
  at least one outside the primitive and `undefined` family the
  decompiler writes on untyped slots: `undefined8`, `void *`, `int`
  name nothing worth a `Drop` impl; `HANDLE` and `FILE` do. The
  primitive family is the allocator detector's (`allocator::is_type_word`),
  deliberately not the handle detector's wider cast-stripping list,
  which counts `HANDLE` itself as a type word for a different question.
- **The reading is blind where prose is not code.** Inside string
  literals a declaration-shaped fragment is text, and a longer name
  that merely ends where the variable's does (`hFile2`) is not the
  variable's declaration.
- **The scoped narrowing outranks the name.** A handle read after its
  close can only take a scoped guard whatever its type is called, so
  that reading keeps its wording and its 65; the named-type upgrade
  rides the plain pair at its own 70 — the name refines *what to call
  the guard*, not how strongly the lifecycle was read.
- **`HandleLifecycle` gains `type_name: Option<String>`, optional on
  disk.** Documents persisted by earlier builds carry no such field and
  read back untyped, exactly as the other optional fields before it.

## Consequences

- No new finding kind: the upgrade rewrites the existing pair record's
  `suggestion` string, so persistence, the CLI kind breakdown, and the
  prompt conversion carry it with no shape change.
- Ghidra's applied typedefs become visible in suggestions: a scan of a
  program whose handle slots are typed reads `impl Drop for HANDLE`,
  while an unworked program whose slots read `undefined8` keeps the
  generic guard — the suggestion strength now tracks how typed the
  program is, which is honest: the name is only as good as the
  program's own type information.
- Two `is_type_word` vocabularies now coexist in the handle detector:
  the local one for cast stripping (includes the win32 typedefs) and
  the allocator's primitive family for naming. They answer different
  questions and are deliberately not merged.

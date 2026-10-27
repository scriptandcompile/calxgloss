# ADR-0031: The handle pairing names the type the body itself declares for the handle, the scoped narrowing still outranks it, and the field is optional on disk

- **Status:** Accepted
- **Date:** 2026-10-14 (P4.5-5 shipped, issue #162)
- **Deciders:** Arthur (solo project)

## Context

The handle pairing detector suggested a generic "RAII guard struct with
Drop impl" for every closed pair. But the decompiled body often states
a real type for the handle variable — `HANDLE hFile = CreateFileW(...)`,
or a hoisted `FILE *local_10;` — and a Rust translation reading the
finding has to invent that wrapper name itself. Giving the type in the
suggestion (`impl Drop for HANDLE`) says which type the `Drop` impl
belongs to.

The questions: where may the type come from — the declaration, a cast,
or a guess? What counts as nameable, as opposed to the decompiler's
untyped vocabulary? How does the upgrade interact with the existing
scoped (read-after-close) narrowing? And what happens to documents
persisted before the field existed?

## Decision

- **The type comes only from the body's own declaration.** The
  decompiler must have spelled a binding as `<Type> <variable>;` or as
  `<Type> <variable> =
  ...;` — the name followed by `;` or a plain `=`, and preceded, past
  any `*`, by a spelled type word. A bare assignment (`hFile =
  CreateFileW(...)`)) declares nothing. The reading never invents a
  type from casts, opener names, or convention.
- **A nameable type is a spelled identifier outside the primitive
  family.** Every word must be a plain identifier, none may be a
  statement keyword, and at least one word must fall outside the
  primitive and `undefined` family the decompiler writes on untyped
  slots. `undefined8`, `void *`, and `int` identify nothing worth a
  `Drop` impl; `HANDLE` and `FILE` do. The primitive family is the
  allocator detector's (`allocator::is_type_word`), deliberately not
  the handle detector's wider cast-stripping list, which counts
  `HANDLE` itself as a type word because it answers a different
  question.
- **The reading ignores text that is not code.** Inside a string
  literal, a fragment shaped like a declaration is only text. And a
  longer name that merely ends where the variable's name ends
  (`hFile2`) is not that variable's declaration.
- **The scoped narrowing outranks the name.** A handle read after its
  close can only take a scoped guard, whatever its type is called, so
  that reading keeps its wording and its 65. The named-type upgrade
  applies to the plain pair, at its own 70 — the name refines *what to
  call the guard*, not how strongly the lifecycle was read.
- **`HandleLifecycle` gains `type_name: Option<String>`, optional on
  disk.** Documents persisted by earlier builds have no such field and
  read back untyped, exactly like the other optional fields before it.

## Consequences

- No new finding kind: the upgrade rewrites the existing pair record's
  `suggestion` string, so persistence, the CLI kind breakdown, and the
  prompt conversion show it with no shape change.
- Ghidra's applied typedefs become visible in suggestions: a scan of a
  program whose handle slots are typed reads `impl Drop for HANDLE`,
  while an unworked program whose slots read `undefined8` keeps the
  generic guard. The suggestion is now as strong as the program's own
  type information, which is honest: the name is only as good as that
  information.
- Two `is_type_word` vocabularies now coexist in the handle detector:
  the local one for cast stripping (it includes the win32 typedefs)
  and the allocator's primitive family for naming. They answer
  different questions and are deliberately not merged.

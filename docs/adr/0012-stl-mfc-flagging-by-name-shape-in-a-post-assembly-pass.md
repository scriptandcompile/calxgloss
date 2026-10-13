# ADR-0012: Flag STL/MFC types by name shape, flag-only, in a post-assembly pass

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-4 shipped, issue #140)
- **Deciders:** Arthur (solo project)

## Context

The type database recovers standard-library and MFC types exactly like the
program's own classes: `basic_string<…>` and `vector<…>` show up as Type
Manager names, RTTI-demangled vtable class names arrive spelled the MSVC
way (`std::VWidget::$vector`), and an inferred field's suggested type can
be a bare `char *`. The translator does not know they are standard types,
so it spends LLM effort inventing raw layouts for containers that map
directly onto Rust's `String`/`Vec<T>`/`BTreeMap<K,V>`.

Recognizing them by *layout* is not viable: the recovered field lists come
from memory-access evidence, not from the compiler, and a container's
recovered shape is just pointers and counts — indistinguishable from any
hand-rolled linked list. What *is* reliable is the name: the demangler and
the Type Manager both spell these families in recognizable shapes.

## Decision

STL/MFC recognition is a **pure post-assembly pass** in the engine — after
vtable linking, split/merge, and nesting — that matches each recovered
name against per-family token lists and records the matched family as an
optional `stl_kind` on the record.

- **Name shape, not layout.** `stl::detect` scans the *head* of a name —
  the part before the first `<` — for whole-word family tokens
  (`basic_string`, `vector`, `map`/`set` family, `list`, `shared_ptr`…,
  plus the C spellings `char *`/`wchar_t *`). A token matches only at
  non-identifier boundaries, so `offset` is not a `set`, `listing` is not
  a `list`, and `my_set` is not a `set`, while `std::vector<…>`,
  `$vector`, and `char *` all match. Template arguments never name a
  family: `std::less<std::string>` is a comparator, not a string.
- **Case-sensitive lowercase tokens.** A program's own `Set`, `List`, or
  `String` class is not mistaken for the standard one; `CString` is the
  one mixed-case token because that is how MFC spells it.
- **Three record kinds.** `NamedType` matches on its name, `Vtable` on
  its RTTI-demangled class name, and `InferredField` on the C type its
  inference suggested — the string the prompt actually shows. Struct
  fields of named types are not flagged: their `type_name` is a Ghidra
  type reference, and the type it names is flagged (or not) in its own
  record.
- **Flag-only.** A flagged record stays in every section and answers
  every lookup — the same principle ADR-0009 applies to weak candidates.
  A name is evidence, not proof: the program may define its own `MySet`,
  and dropping records on a name match would hide real types from the
  translator.
- **The flag is serde-optional.** A document written before this pass
  still loads, keeping the wire format additive.
- **The kind rides into the prompt.** A flagged named type renders as
  `basic_string (STL string)` and a flagged inferred field as
  `char * (STL string)`, so the translator maps them to Rust equivalents
  instead of inventing raw layouts — no new prompt sections.

## Consequences

- Positive:
  - The translator stops hand-rolling layouts for the program's
    `std::string`/`std::vector` members; the family names itself in the
    prompt.
  - The pass is pure and deterministic: no new endpoint, no new LLM
    call, no new state — it composes with the passes already in `scan`,
    and runs last so each record is flagged once, after duplicates fold
    away.
  - The `typesdb` report counts flagged types, vtables, and fields, and
    each flagged vtable row names its family, making detection visible
    on real binaries.
- Negative:
  - False negatives: an STL type hidden behind a typedef alias or a
    Ghidra-renamed class carries no shape to match. Accepted — the name
    is the only evidence available, and a missed flag costs only the
    translation effort the pre-flagging scan already spent.
  - False positives: a program class genuinely named `map` is flagged.
    Accepted — flag-only means the record is never dropped, and the
    prompt suffix is a hint the LLM can see through. Ghidra's builtin
    `string` typedef matches the `string` token the same way; accepted,
    since it genuinely is a C string and the family label is honest.
  - MFC coverage is thin (`CString` only): the rest of the MFC class
    family is program-specific naming with no stable shape, and
    guessing at it would flag the program's own classes.

# ADR-0013: Render the recovered type database as a derived Rust declarations file

- **Status:** Accepted
- **Date:** 2026-10-13 (P1.5-5 shipped, issue #141)
- **Deciders:** Arthur (solo project)

## Context

The type database already feeds the translator's prompts. But a reviewer
who wants to *read* the recovered types has only the JSON document. They
want to check a struct's layout, spot a wrong link, or diff what a rescan
learned. JSON shows offsets as numbers and hides what the recovered layout
means in Rust terms. The P1.5 spec's last ticket asks for a Rust codegen
output: `#[repr(C)]` declarations beside the database that a human can
review and a rescan can diff.

The recovered records are evidence, not source. Names come from Ghidra's
Type Manager and may be shared across categories. Field names may be
`(unnamed)` or C keywords. Offsets leave gaps. Some types are STL shapes
(ADR-0012) that should never get a hand-rolled layout. Many records have
no layout at all. A naive dump would change on every rescan and would
misrepresent all of that.

## Decision

The declarations file is a **derived artifact rendered by a pure function
from the loaded database**. It is written beside the JSON and never read
back.

- **One renderer, no state.** `rust_decls::render_rust_decls(&TypeDatabase)
  -> String` is data in, string out: no Ghidra call, no LLM, no clock.
  The `typesdb` command writes the file to
  `re/analysis/typesdb/{binary}.rs` after every save, and `--show` prints
  the path when the file exists. Nothing in the pipeline ever parses the
  file back. The JSON stays the single source of truth, and that mirrors
  ADR-0003's split between derived artifacts and authoritative records.
- **Deterministic, timestamp-free output.** Declarations appear in the
  database's own stored order: named types by Type Manager path, then
  inferred candidates. The file header includes only the binary's name,
  never the scan time. Two renders of the same database are
  byte-identical, so re-scanning the same program produces a reviewable
  diff, not a stream of pointless changes.
- **Sanitized identifiers, collision suffixes in render order.** Type
  names become valid Rust identifiers: non-identifier characters collapse
  to `_`. Field names become snake_case, and a Rust keyword gets a
  trailing `_`. A name that is already taken gets `_2`, `_3`, … in render
  order, so two `SHARED` types in different categories still get
  distinct, stable declarations. All names are assigned before any body
  renders, so a nested field always references the exact name its inner
  type was declared under.
- **Explicit padding.** Wherever the next field's offset leaves a gap,
  and between the last field and the declared size, the renderer emits
  `_pad_{offset}: [u8; n]`. The declaration then matches the recovered
  layout byte for byte, instead of silently re-packing it.
- **Enums are `#[repr(i64)]`.** Recovered member values are signed i64,
  because Ghidra enums may hold negative values. The repr matches the
  record, rather than guessing the narrowest integer that fits.
- **STL-flagged types render as comments, not layouts.** Following
  ADR-0012, a flagged type becomes
  `// basic_string — STL string: maps to Rust String; no layout emitted.`,
  and a field linked to a flagged type shows the Rust equivalent with a
  trailing comment. The renderer never hand-rolls a container layout that
  the flagging pass already told us to map onto
  `String`/`Vec`/`BTreeMap`.
- **Layout-less types are skipped entirely.** A record that only tells us
  the type exists has nothing to declare. Emitting an empty struct would
  invent a shape the evidence does not support.
- **Inferred candidates render too**, marked as hypotheses with their
  confidence in a comment. Padding is only emitted when every field was
  placed. Candidate offsets are estimates, and padding built on unknown
  offsets would make a guess look like a layout.

## Consequences

- Positive:
  - Reviewers see the recovered type tree in the language the project
    targets. The `typesdb` report prints the file's path after every scan
    and under `--show`.
  - The render is pure and deterministic. It composes with every earlier
    pass (linking, merging, nesting, flagging) for free, because the
    renderer only reads the records those passes left behind.
  - Rescans diff cleanly: only real knowledge changes move the file.
- Negative:
  - The file is a review artifact, not a compile target. Sanitized names
    (`vector_CWidget`), `*mut c_void` for every bare pointer, and
    `#[repr(i64)]` for enums narrower than that keep the render honest to
    the records rather than idiomatic to Rust. Accepted — the translator,
    not this file, produces the code that compiles.
  - Ghidra-renamed or typedef-hidden STL types have no flag, so they
    render as plain structs. The flagging pass's false negatives
    (ADR-0012) are also the renderer's false negatives.
  - A field linked to a layout-less inner type references a name that has
    no declaration in the file. The reference stays, because it records
    real evidence, and the reviewer sees the gap.

## Addendum (2026-10-15, P9.5-4/-5)

The `apidetect` crate's FFI bindings and dependency manifest artifacts
(issues #187–#188) follow the same pattern: pure renderers over the
loaded document, written beside the JSON, never read back. They are
recorded here as a one-line sibling under this pattern rather than as a
fresh decision, per epic #183.

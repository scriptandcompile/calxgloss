# ADR-0021: Apply write-back in program order, narrowing only undefined slots

- **Status:** Accepted
- **Date:** 2026-10-14 (P2.5-8 shipped, issue #150)
- **Deciders:** Arthur (solo project)

## Context

ADR-0020 gave the inferred types a named path back into the type
manager — the `TypeWriteSource` trait — but nothing used it. Ticket
#150 makes the pass: it takes a persisted `TypeInferenceResult`, applies
its surviving records into the open Ghidra program, and reports what
landed.

The pass must answer these questions. In what order do the writes go, so
that no write names a type Ghidra cannot resolve? What does a *missing*
named type become when the scan inferred `Widget *` but the Type
Manager holds no `Widget`? When may a write touch a slot at all? How
does the record's Rust-flavored type text (`u32`) meet Ghidra's C
parser? And how does one refused write affect the rest of the run?

The tension: an aggressive pass types everything the scan inferred; a
conservative pass risks doing little. The scan's records are
hypotheses — the whole crate says so. So write-back must not let a
hypothesis destroy a fact already in the program.

## Decision

- **The driver is generic over both seams.** `WriteBack<S: ScanSource,
  W: TypeWriteSource>::new(source, writer, floor).apply(result)` lives
  in `write_back.rs`. The CLI passes the same raw `GhidraClient` to
  both positions; ADR-0020's rule that the read cache never implements
  the write trait means there is nothing else to pass. Tests pass a
  canned program and a recording writer, so the whole pass is tested
  without a Ghidra server.
- **Fixed phase order: create named types → prototypes → locals.** A
  prototype that names `Widget *` fails to parse unless `Widget`
  resolves. So every named type a surviving record references is created
  before any record applies. Each function's decompiled body is fetched
  at most once per run and reused by both write phases.
- **A missing named type becomes a placeholder typedef, never a
  fabricated layout.** The pass calls `create_typedef(name, "undefined")`
  — the bridge's smallest concrete type. It does this
  because the bridge *refuses* a fieldless `create_struct` ("No valid
  fields parsed") and the scan records hold no field evidence to build a
  layout from. A 1-byte placeholder is exactly what the bridge's
  `replace_placeholder` flow lets later layout work swap out. An
  existing name is **never** recreated: `create_typedef` uses Ghidra's
  `REPLACE_HANDLER` and would silently overwrite a real struct. So
  existence is checked against `data_types(None)` first. Qualified
  spellings (`Namespace::Type`) name no creatable single type through
  this seam, so they get no creation. Their write may then fail, and the
  failure is collected like any other.
- **Only the undefined family is narrowed.** A slot Ghidra already
  types concretely — anything but `undefined`, `undefined1`..`undefined8`
  and their pointer spellings (`undefined *`) — is skipped, with the
  reason reported. `void` is a decision, not a placeholder, so a `void`
  return survives a return reading. A hand-typed slot always wins over a
  scan hypothesis.
- **Param and return readings merge into one prototype write per
  function.** The pass parses the current signature line and replaces
  only undefined slots. Everything else — name, convention spelling,
  untouched slots, return type when untouched — goes back out verbatim
  through `set_function_prototype`. Locals go through
  `set_local_variable_type`, keyed by the decompiled name and guarded by
  the name actually appearing as a plain declaration in the body.
  Call-site records are **skipped** (`CallSiteArgument`): they type an
  argument at a site, not a slot the program can hold a type in.
- **Type text is normalized only at the write seam.** The detectors
  persist `u8`/`u16`/`u32`/`u64` for the prompts.
  `set_function_prototype` applies its text through Ghidra's C parser,
  which cannot resolve those spellings, so the write carries
  `uchar`/`ushort`/`uint`/`ulonglong` instead. The persisted record text
  is untouched — the normalization is a property of the seam, not of the
  vocabulary.
- **A confidence floor gates which records apply, default 70.** The
  floor is checked before anything else. Records below the floor are
  skipped, and the reason states their confidence and the floor. The CLI
  flag `--confidence-floor` sets it. `--write-back` works after a scan
  and with `--show`, applying the cached result.
- **Setup reads can fail the run; per-record failures never do.** The
  function listing (name → address) and the Type Manager listing are the
  pass's foundation. A failure there ends the run. A function that will
  not decompile, and every refused write, is collected into the report
  and the pass continues. It ends with applied / skipped / failed counts
  and reasons.

## Consequences

- The program only ever *gains* types. An undefined slot narrows, a
  concrete slot never moves, and a placeholder type is a seed that later
  layout work can replace. So an operator can run write-back on a
  hand-worked program without fear.
- The report is the audit trail. Every record the pass did not apply
  says why, and every refused write carries the bridge's error — which
  the #149 classifier already turns from prose into a named error.
- Struct *layout* reconstruction stays out of scope: write-back creates
  the name as a placeholder, and the typesdb track's recovered layouts
  remain where field evidence lives.
- The pass reads the current prototype from the decompiler's signature
  line — the only place the read seam exposes current parameter types.
  So a function whose body will not decompile cannot have its prototype
  merged; its records are collected as failures saying exactly that.

# ADR-0021: Apply write-back in program order, narrowing only undefined slots

- **Status:** Accepted
- **Date:** 2026-10-14 (P2.5-8 shipped, issue #150)
- **Deciders:** Arthur (solo project)

## Context

ADR-0020 gave the inferred types a named path back into the type
manager — the `TypeWriteSource` trait — but nothing drives it. Ticket
#150 makes the pass: take a persisted `TypeInferenceResult`, apply its
surviving records into the open Ghidra program, and report what landed.

The questions the pass must answer: in what order the writes go so no
write names a type Ghidra cannot resolve; what a *missing* named type
becomes when the scan inferred `Widget *` but the Type Manager holds no
`Widget`; when a write may touch a slot at all; how the record's Rust-
flavored type text (`u32`) meets Ghidra's C parser; and how one refused
write affects the rest of the run.

The tension: an aggressive pass types everything the scan inferred; a
conservative pass risks doing little. The scan's records are
hypotheses — the whole crate says so — so write-back must not let a
hypothesis destroy a fact already in the program.

## Decision

- **The driver is generic over both seams.** `WriteBack<S: ScanSource,
  W: TypeWriteSource>::new(source, writer, floor).apply(result)` lives
  in `write_back.rs`. The CLI hands both positions the same raw
  `GhidraClient` — ADR-0020's rule that the read cache never implements
  the write trait means there is nothing else to hand — and tests hand
  a canned program and a recording writer, so the whole pass is tested
  without a Ghidra server.
- **Fixed phase order: create named types → prototypes → locals.** A
  prototype naming `Widget *` fails to parse unless `Widget` resolves,
  so every named type a surviving record references is created before
  any record applies. Each function's decompiled body is fetched at
  most once per run and reused by both write phases.
- **A missing named type becomes a placeholder typedef, never a
  fabricated layout.** `create_typedef(name, "undefined")` — the
  bridge's smallest concrete type — because the bridge *refuses* a
  fieldless `create_struct` ("No valid fields parsed") and the scan
  records carry no field evidence to build a layout from. A 1-byte
  placeholder is exactly what the bridge's `replace_placeholder` flow
  lets later layout work swap out. An existing name is **never**
  recreated: `create_typedef` uses Ghidra's `REPLACE_HANDLER` and would
  silently clobber a real struct, so existence is checked against
  `data_types(None)` first. Qualified spellings (`Namespace::Type`)
  name no creatable single type through this seam and get no creation;
  their write may then fail and is collected like any other.
- **Only the undefined family is narrowed.** A slot Ghidra already
  types concretely — anything but `undefined`, `undefined1`..`undefined8`
  and their pointer spellings (`undefined *`) — is skipped with the
  reason reported. `void` is a decision, not a placeholder, so a
  `void` return survives a return reading. Hand-typed slots always win
  over scan hypotheses.
- **Param and return readings merge into one prototype write per
  function.** The current signature line is parsed, only undefined
  slots are replaced, and everything else — name, convention spelling,
  untouched slots, return type when untouched — rides back out verbatim
  through `set_function_prototype`. Locals go through
  `set_local_variable_type` keyed by the decompiled name, guarded by
  the name actually appearing as a plain declaration in the body.
  Call-site records are **skipped** (`CallSiteArgument`): they type an
  argument at a site, not a slot the program can hold a type in.
- **Type text is normalized only at the write seam.** The detectors
  persist `u8`/`u16`/`u32`/`u64` for the prompts; `set_function_prototype`
  applies its text through Ghidra's C parser, which cannot resolve
  those spellings, so the write carries `uchar`/`ushort`/`uint`/
  `ulonglong` instead. The persisted record text is untouched — the
  normalization is a property of the seam, not of the vocabulary.
- **A confidence floor gates which records apply, default 70.** The
  floor is checked before anything else; below-floor records are
  skipped with their confidence and the floor in the reason. The CLI
  flag `--confidence-floor` sets it; `--write-back` works after a scan
  and with `--show`, applying the cached result.
- **Setup reads can fail the run; per-record failures never do.** The
  function listing (name → address) and the Type Manager listing are
  the pass's foundation — a failure there ends the run. A function
  that will not decompile, and every refused write, is collected into
  the report and the pass continues, ending with applied / skipped /
  failed counts and reasons.

## Consequences

- The program only ever *gains* types: an undefined slot narrows, a
  concrete slot never moves, and a placeholder type is a seed later
  layout work can replace — so an operator can run write-back on a
  hand-worked program without fear.
- The report is the audit trail: every record the pass did not apply
  says why, and every refused write carries the bridge's error, which
  the #149 classifier already turns from prose into a named error.
- Struct *layout* reconstruction stays out of scope: write-back seeds
  the name, and the typesdb track's recovered layouts remain the place
  field evidence lives.
- The pass reads the current prototype from the decompiler's signature
  line — the only place the read seam exposes current parameter types —
  so a function whose body will not decompile cannot have its
  prototype merged; its records are collected as failures naming that.

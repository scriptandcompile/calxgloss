# ADR-0044: A managed PE is detected from the COM descriptor at classification and parked as Do Not Translate

- **Status:** Accepted
- **Date:** 2026-10-19
- **Deciders:** Arthur (solo project)

## Context

Every translation path in calxgloss reads x86/x64 machine code: the disassembly
RE path, the decompiler engines, and the shim suggestion flow all assume the
binary's exports carry native code. A .NET assembly is a PE container around
CIL, and its exports are managed thunks. Feeding one through the native paths
produces confident nonsense: the decompiler reads JIT stubs, the LLM invents
semantics for them, and the reviewer inherits a translation that looks real and
is not.

The name tables cannot tell the two apart. `EQUIMOS~1.DLL` — the file that
started this — looks like any third-party DLL until something opens the PE and
reads data directory 14, the COM descriptor: a managed assembly always carries
one, a native PE never does. That is a fact about the file, not a guess, and it
is already one field read away from the PE parse classification performs today.

## Decision

A binary whose PE carries a non-empty COM descriptor is classified
`DllCategory::DotNetManaged` and routed to a new `Strategy::DoNotTranslate`.

- **Detection rides the existing PE parse.** `classify_dll_with_target` already
  parses the PE for the import table; the managed check is one accessor on the
  optional header's data directories (`get_clr_runtime_header`). No second file
  read, no new parse pass.
- **Precedence is override > PE > names.** The operator's classification
  override still wins — parking is a policy, and the override is how an
  operator overrules policy. The PE check outranks every name-table heuristic:
  a managed binary is not a category the name tables can guess.
- **The binary is parked, not deleted.** Its dashboard units carry a new
  `ReviewStatus::DoNotTranslate`: visible in the full queue, excluded from
  active counts and next-work, sorted after skipped units, and exempt from the
  auto-blocking cascade so a parked dependency never blocks a translatable one.
  The classification record's `reason` rides into the unit's `known_gaps` so
  the reviewer sees why it is parked.
- **The CLI refuses before spending anything.** `translate`, `batch-translate`,
  and `auto` check the in-force category before loading the engine or the LLM
  and name the gap ("we do not yet decompile .NET programs"), the signal, and
  the escape hatch.
- **`known_runtime` stays false.** The flag is reserved for runtime libraries;
  a managed binary is a translation candidate that happens to be untranslatable
  today, not a library to link against.

## Consequences

- Managed binaries stop producing fake native translations; the gap is stated
  instead of papered over.
- When a managed decompiler exists, releasing a parked binary is a
  classification-override entry pointing its category away from
  `DotNetManaged` — the override already releases it end to end, and a test
  pins that behavior.
- The dashboard gains a sixth review status and the CLI one more refusal path;
  both are additive and old records keep parsing (`#[serde(default)]`).
- Framework version, single-file bundles, and native images are explicitly out
  of scope: the COM descriptor answers only "is this managed", which is the
  only question the routing decision needs.

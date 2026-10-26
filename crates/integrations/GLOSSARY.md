# Integrations

The engine-and-tooling side of the reverse-engineering effort: the analysis engine that loads the program and answers decompile questions, the local LLM that does the translating, the prompt templates that instruct it, and the Windows-API mappings that make translated code run anywhere. This context owns the language of the seam, the engine, the dialect, the cache, load budgets, and prompt templates.

## Language

### The seam and the engine

**Analysis engine**:
The component that loads the target binary and answers the decompile questions — always Kuna, in-process, since ADR-0041.
_Avoid_: bare "engine" (banned repo-wide); Ghidra as a live component — it is a retired engine, never the current one

**Seam**:
The fixed boundary between analysis engine and every consumer: reads flow through the *scan source*, writes through the *write-back source*. The seam outlives any engine that stands behind it.
_Avoid_: bridge — that was the deleted HTTP mechanism; provider

**Scan source**:
The read side of the seam — the one place decompiled answers (bodies, listings, names) reach any consumer.
_Avoid_: client (there is no connection any more)

**Write-back source**:
The write side of the seam — the only way scan records enter the loaded program; the scan read cache never implements it, by construction.

**Kuna**:
The in-process analysis engine; it reads the target binary inside the harness process — nothing to attach to, spawn, install, or connect to.
_Avoid_: server, headless, JVM

**Loaded program**:
The target binary as the engine holds it during a run — one engine thread holds it and answers one call at a time. Evidence engines and the pipeline read through it; it is what "the program" names.

**Engine fault**:
The single failure vocabulary for everything the engine refuses: a failed load, a missing answer, a malformed one.
_Avoid_: GhidraError (retired name)

### Dialect and format names

**Decompile dialect**:
The pseudo-C text flavor the engine serves — what bodies, listings, and the pipeline's text handling are written in, and what the engine faithfully reproduces.

**Ghidra names formats, never the engine**:
Dialect spellings keep their historical names — `FUN_…`, `DAT_…`, `param_N`/`local_N`, `vftable`, the WARNING preamble — because they name a *format*; no live component is ever called Ghidra.

**Decompile noise filter**:
The seam's curation of engine text: shapes that would fake a structure (stack-guard patterns) are stripped so they never read as real; shapes that are evidence (spelled try/catch frames) pass through byte for byte.

### Cache and budgets

**Scan read cache**:
The seam-owned, two-tier on-disk store of decompiled answers that survives restarts and makes warm reruns cheap. The name is the noun — it caches scans, and nothing else does.
_Avoid_: Ghidra cache (the retired path name for it)

**Load**:
Bringing a target binary into the engine — the first act of every scan, and what doctor proves by doing.
_Avoid_: attach, spawn (retired lifecycle words)

**Per-function budget**:
The ceiling on what one function's analysis may consume — instructions, seconds, memory — refused loudly when exceeded rather than left to hang. Settings carry the budgets.

### The LLM and its templates

**Local LLM**:
The locally hosted model that does the translating; because it is local, failed output is cheap and asking again is the normal path.

**Fault monitor**:
A run's watchdog over LLM responses, ending an attempt when the response shows a characteristic failure — invented APIs, an unproductive loop, divergence, exhaustion.

**Context window**:
The single token budget — prompt plus output together — that the local LLM offers; the pressure it creates is what context tiers escalate against.

**Prompt template**:
The assembled ask that one LLM call sends; every template must be reachable from the pipeline — an unreachable one is deleted, never kept "for later".
_Avoid_: bare "prompt" (prompt tier and the LLM I/O log use the word differently)

**Section include**:
The shared per-evidence-engine snippet that prompt templates call; which evidence sections a prompt shows is a property of which includes that template calls.

### Windows-API mappings

**PAL**:
The cross-platform traits layer that Windows API calls map onto, so translated code compiles and runs on any platform.

**PAL mapping**:
One Windows API's route to its PAL counterpart — trait, crate suggestion, and feature flags. The evidence scan's mapping database borrows PAL's category names without depending on PAL.

**API category**:
The kind an imported API belongs to, shared as the display vocabulary between the evidence side's API detection and PAL's mappings.

**Shim**:
The generated forwarding layer that routes Windows API calls to their PAL mappings so translated units link against a real surface.

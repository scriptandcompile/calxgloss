# ADR-0042: The deferred renames are taken up — the seam crate is `calxgloss-decomp`, the cache files under `re/decomp-cache/`, and the web surface follows

- **Status:** Accepted
- **Date:** 2026-10-18
- **Deciders:** Arthur (solo project)
- **Completes:** ADR-0041's recorded deferrals (ADR-0041 is left as written)

## Context

ADR-0041 deleted the Ghidra path but deliberately left three names
behind, recording the name-vs-thing gap as intentional: the seam crate
stayed `calxgloss-ghidra` (the seam predates the analysis engine), the
on-disk scan read cache stayed `re/ghidra-cache/` (existing workspaces
keep their caches), and the web UI's "Ghidra Context" tab and
`/api/units/{id}/ghidra` route stayed (they serve decompile-dialect
content).

With the retirement settled, the remnants stopped earning their keep:
every `calxgloss-ghidra` import, every `re/ghidra-cache` path, and the
dashboard tab now refer to a system that no longer exists, and the
confusion costs every reader and every agent working through the repo.

## Decision

Take up all three deferrals (issue #214 follow-up):

- **The seam crate renames.** `crates/integrations/calxgloss-ghidra`
  becomes `calxgloss-decomp`; every dependency path and import in the
  workspace follows.
- **The cache directory renames.** The two-tier scan read cache files
  go under `re/decomp-cache/` instead of `re/ghidra-cache/`. The
  rename is a silent cache reset for existing workspaces — accepted
  because the `CACHE_FORMAT_VERSION` marker inside the directory
  already invalidates bridge-era documents, so the reset was one bump
  away regardless.
- **The web surface renames.** The tab is "Decompiler Context", the
  route is `/api/units/{id}/decomp`, and the handler file,
  `GhidraContext*` types, `ghidra-*` CSS/JS ids, and `unitGhidra`/
  `loadGhidraView` JS spellings become their `decomp` equivalents. The
  route's wire JSON has no `ghidra` keys, so the type renames are
  wire-safe.
- **Comments and docs stop calling Ghidra the live analysis engine** —
  they refer to the decompiler, the analysis engine, or the seam.

What deliberately stays: every spelling that names the *dialect* the
decompiler output is written in — `FUN_…`, `LAB_…`, `sub_…`, `uVar1`,
`local_18`, `thunk_…`, `EXTERNAL:<ordinal>`, `vftable`, the `WARNING`
banners, `size + -4`, `entry` — because Kuna reproduces that dialect
(ADR-0041). Also kept: the config's refusal of stale `[ghidra]` keys
and `CALXGLOSS_GHIDRA_*` variables, which literally test those names,
and the `Ghidra/Processors/x86` paths in the Kuna build, which are
real spec-tree paths. Historical records — CHANGELOG entries, ADRs,
and archived docs — are left as written. The two bridge-era notes that
sat loose in `docs/`, `ghidra_endpoint_map.md` and
`ghidra_integration.md`, are deleted with this uptake; their surviving
history is the ADRs and the changelog.

## Consequences

- The crate name, the cache path, and the UI tab finally refer to the
  thing that does the work; no import or path in the live tree names a
  retired system.
- Existing workspaces lose their scan caches once. Rebuilding is just
  a rerun; the format-version machinery treats the old directory as
  gone anyway.
- The web route change breaks anything bookmarked against
  `/api/units/{id}/ghidra`; the dashboard is the only consumer.
- ADR-0041's deferral note reads as history now. This ADR is the
  record of uptake, and no further Ghidra-named surface remains to
  rename.

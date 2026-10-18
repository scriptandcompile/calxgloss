# ADR-0043: The scan read cache files under `re/cache/`

- **Status:** Accepted
- **Date:** 2026-10-18
- **Deciders:** Arthur (solo project)
- **Amends:** ADR-0042's cache-directory clause (ADR-0042 is left as written)

## Context

ADR-0042 renamed the scan read cache from `re/ghidra-cache/` to
`re/decomp-cache/` because the old name pointed at a retired system. The new
name fixed that but kept a qualifier that carries no information: the
directory holds the scan read cache and nothing else lives under it, the
crate that owns it is already `calxgloss-decomp`, and every consumer calls
it the scan read cache. `decomp-` repeats the owner rather than naming the
thing, and the record of effort around it (`re/analysis/`, `re/classify/`,
`re/shims/`, `re/review/`) spells its directories as plain nouns.

Workspaces also carry the cost of the previous rename: the EverQuest
workspace still holds a 22 MB `re/ghidra-cache/` that no code reads, because
a rename is a silent reset with no cleanup step.

## Decision

`cache_root()` is `{workspace}/re/cache`.

- **No migration and no compatibility.** The `CACHE_FORMAT_VERSION` marker
  inside a directory (3 as of the IAT-slot listing fix) already makes every
  existing directory cold, so the rename costs nothing beyond the one reset
  ADR-0042 accepted. A directory under an old name is simply never opened
  again.
- **Old directories are the workspace owner's to delete.** Nothing in the
  tool removes `re/ghidra-cache/` or `re/decomp-cache/`: silently deleting a
  directory under the workspace root is not worth the blast radius of a
  recursive remove in the cache's constructor, and the content is regenerable
  either way.
- **The name is the noun, not the owner.** A future second cache gets its own
  named directory beside it rather than a qualifier inside this one.

## Consequences

- The path an operator reads in `--help`, the README, and the layout tree
  matches the path on disk, and it is short enough to type.
- Existing workspaces gain a third orphan directory unless the owner deletes
  the superseded ones; the README's delete-by-hand route already covers it.
- ADR-0042's title names the superseded path and reads as history, the way
  ADR-0041's deferral note already did.

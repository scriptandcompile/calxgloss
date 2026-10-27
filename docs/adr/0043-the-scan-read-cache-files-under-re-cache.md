# ADR-0043: The scan read cache files under `re/cache/`

- **Status:** Accepted
- **Date:** 2026-10-18
- **Deciders:** Arthur (solo project)
- **Amends:** ADR-0042's cache-directory clause (ADR-0042 is left as written)

## Context

ADR-0042 renamed the scan read cache from `re/ghidra-cache/` to
`re/decomp-cache/` because the old name pointed at a retired system. The new
name fixed that, but it kept a qualifier that says nothing extra: the
directory holds the scan read cache and nothing else lives under it, the
crate that owns it is already `calxgloss-decomp`, and every consumer calls
it the scan read cache. `decomp-` repeats the owner instead of naming the
thing. The effort's other record directories around it (`re/analysis/`,
`re/classify/`, `re/shims/`, `re/review/`) use plain nouns as directory
names.

Workspaces also still pay for the previous rename: the EverQuest
workspace still holds a 22 MB `re/ghidra-cache/` that no code reads, because
the tool's rename is a silent reset with no cleanup step.

## Decision

`cache_root()` is `{workspace}/re/cache`.

- **No migration and no compatibility.** The `CACHE_FORMAT_VERSION` marker
  inside a directory (3 as of the IAT-slot listing fix) already makes every
  existing directory cold, so the rename costs nothing beyond the one reset
  ADR-0042 accepted. A directory under an old name is simply never opened
  again.
- **Old directories are the workspace owner's to delete.** Nothing in the
  tool removes `re/ghidra-cache/` or `re/decomp-cache/`: silently deleting a
  directory under the workspace root is not worth the risk that a recursive
  remove inside the cache's constructor could go wrong, and the content is
  regenerable either way.
- **The name names the thing, not the owner.** A future second cache gets
  its own named directory beside this one, rather than a qualifier inside
  it.

## Consequences

- The path an operator reads in `--help`, the README, and the layout tree
  matches the path on disk, and it is short enough to type.
- Existing workspaces gain a third leftover, unused directory unless the
  owner deletes the superseded ones; the README already tells the owner to
  delete by hand, and that covers it.
- ADR-0042's title names the superseded path and reads as history, the way
  ADR-0041's deferral note already did.

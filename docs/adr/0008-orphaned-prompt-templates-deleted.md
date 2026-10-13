# ADR-0008: Orphaned prompt templates are deleted, not wired up

- **Status:** Accepted
- **Date:** 2026-10-10 (X2 closed, issue #87; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

`fix.j2` and `disassembly_translate.j2` sat in the prompts crate's
`templates/` directory unreferenced by `templates.rs` — one of them a
near-namesake of the real failure-fix template, inviting the next reader to
"fix" the apparent gap. The roadmap item asked for a decision: remove them or
wire them up.

## Decision

**Remove.** The audit verdict (ponytail-audit finding 7, 2026-10-09) is
delete, not wire-up: the renderer already covers both jobs with other
templates. Both files were deleted, and every shipped template now has a
live reference in the renderer. If a future track wants a standalone "fix" or
disassembly-translation prompt, it writes the template fresh against its own
spec — the dead files are not a starting point.

## Consequences

The prompts crate ships only templates that are actually rendered; an
unreferenced template file is now a smell to delete, not backlog to keep.

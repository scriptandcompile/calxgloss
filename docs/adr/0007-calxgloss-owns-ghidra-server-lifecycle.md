# ADR-0007: calxgloss owns the Ghidra server lifecycle — attach-or-spawn, never touch what it didn't start

- **Status:** Accepted
- **Date:** 2026-10-12 (G1 shipped, epic #110; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

Every Ghidra-dependent command assumed a human had prepared the whole stack
by hand: Ghidra installed, the GhidraMCP extension built for exactly that
Ghidra build (ADR-0001's strict pairing), a server on exactly the configured
port, the right program open. Missing links produced cryptic HTTP errors — or
worse, the 2026-10-08 incident: several GUI CodeBrowser windows open, the
bridge answering listings and name searches from *different programs*, scans
skipping their whole (wrong-program) listing and nearly persisting a
phantom-clean record.

## Decision

All of it becomes calxgloss-side orchestration. Every Ghidra command starts
with a **preflight** (`GhidraSession::ensure`) that:

1. **probes identity first** — parses both bridge answer forms into server
   kind, plugin version, and current program; a port answering as something
   other than GhidraMCP fails with a named error, not a malformed-response
   puzzle;
2. **discovers running servers via the bridge's UDS registration directory**
   (`$XDG_RUNTIME_DIR/ghidra-mcp`) and **attaches** to one, auto-correcting a
   stale configured port;
3. **spawns a supervised headless server** (the bridge's own launch recipe)
   only when nothing answers and the configured port is free — never binding
   over someone else's server — and shuts it down cleanly when the command
   ends;
4. **tracks ownership explicitly** (`Owned` vs `Attached`): **a Ghidra calxgloss
   did not start is never killed or replaced**, and a crashed run's orphan is
   reclaimed only when its pid+port verify as ours;
5. **creates/opens the workspace project** (`<workspace>/ghidra/<target>.gpr`)
   and loads + analyzes every binary the run needs, with an analysis cache
   (`re/ghidra/analysis_cache.json`, keyed by path + SHA-256) so re-runs skip
   the minutes-long auto-analysis;
6. **guards the program** — the incident fix: program selectors required on
   the spawned server (`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`) plus a
   current-program check before every scan target.

Lifecycle answers to config (`auto_start`, `headless = auto|always|never`,
`project`, `min_version`, `start_timeout_secs`), and setup splits into two
commands: **`doctor` is read-only** (every failure carries a remediation hint,
non-zero exit for CI), while **`doctor --fix` bootstraps a bare machine behind
explicit consent** — a **plugin-first** selection (the newest GhidraMCP
release's `extension.properties` names the Ghidra build to fetch; "latest of
each" produces a broken pair), sha256-verified downloads, a user-writable
managed prefix with an install manifest, and never sudo.

## Consequences

Commands run on a bare or half-prepared machine without hand-setup, and the
wrong-program failure mode is closed at both ends (selectors + preflight).
The launch plan is built as pure data, so the recipe is unit-testable without
a JVM. Costs: a Linux-only discovery path (UDS/XDG), and calxgloss now
supervises JVM processes — pid files, boot budgets, and orphan handling are
its problem. GUI lifecycle (launching/managing GUI instances) stays out of
scope: calxgloss only attaches.

# ADR-0007: calxgloss owns the Ghidra server lifecycle — attach-or-spawn, never touch what it didn't start

- **Status:** Superseded by ADR-0041 (2026-10-18, issue #214 — the lifecycle module is deleted; the engine loads in-process)
- **Date:** 2026-10-12 (G1 shipped, epic #110; recorded 2026-10-13)
- **Deciders:** Arthur (solo project)

## Context

Every Ghidra-dependent command assumed a human had prepared the whole
stack by hand: Ghidra installed, the GhidraMCP extension built for exactly
that Ghidra build (ADR-0001's strict pairing), a server on exactly the
configured port, and the right program open. A missing piece produced a
cryptic HTTP error — or worse, the 2026-10-08 incident: several GUI
CodeBrowser windows were open, and the bridge answered listings and name
searches from *different programs*. Scans skipped their whole (wrong-program)
listing and nearly persisted a phantom-clean record.

## Decision

calxgloss now orchestrates all of this itself. Every Ghidra command starts
with a **preflight** (`GhidraSession::ensure`) that:

1. **probes identity first** — it parses both bridge answer forms and reads
   the server kind, the plugin version, and the current program. A port
   that answers as something other than GhidraMCP fails with an error that
   names the problem, not a malformed-response puzzle;
2. **discovers running servers through the bridge's UDS registration
   directory** (`$XDG_RUNTIME_DIR/ghidra-mcp`) and **attaches** to one,
   correcting a stale configured port automatically;
3. **spawns a supervised headless server** using the bridge's own launch
   recipe, but only when nothing answers and the configured port is free.
   It never binds over someone else's server, and it shuts the spawned
   server down cleanly when the command ends;
4. **tracks ownership explicitly** (`Owned` vs `Attached`): **calxgloss
   never kills or replaces a Ghidra it did not start**. It reclaims an
   orphan from a crashed run only when that process's pid+port verify as
   ours;
5. **creates/opens the workspace project**
   (`<workspace>/ghidra/<target>.gpr`) and loads and analyzes every binary
   the run needs. An analysis cache (`re/ghidra/analysis_cache.json`, keyed
   by path + SHA-256) lets re-runs skip the auto-analysis, which takes
   minutes;
6. **guards the program** — this is the incident fix. The spawned server
   requires program selectors
   (`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`), and a current-program check
   runs before every scan target.

The lifecycle follows the config (`auto_start`, `headless = auto|always|never`,
`project`, `min_version`, `start_timeout_secs`), and setup splits into two
commands: **`doctor` is read-only** — every failure includes a remediation
hint, and it exits non-zero for CI — while **`doctor --fix` sets up a bare
machine behind explicit consent**. It picks the plugin first: the newest
GhidraMCP release's `extension.properties` records which Ghidra build to
fetch, because fetching "latest of each" produces a broken pair. Downloads
are sha256-verified. Install goes into a user-writable managed prefix with
an install manifest. It never uses sudo.

## Consequences

Commands run on a bare or half-prepared machine without hand-setup, and the
wrong-program failure mode is closed at both ends (selectors + preflight).
The launch plan is built as pure data, so the recipe is unit-testable without
a JVM. Costs: a Linux-only discovery path (UDS/XDG), and calxgloss now
supervises JVM processes — pid files, boot budgets, and orphan handling are
its problem. GUI lifecycle (launching/managing GUI instances) stays out of
scope: calxgloss only attaches.

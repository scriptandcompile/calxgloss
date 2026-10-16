# ADR-0039: The analysis engine is a seam choice — Kuna loads the target in-process, Ghidra stays the default, and one run uses exactly one engine

- **Status:** Accepted
- **Date:** 2026-10-16 (X5-#205 shipped, epic #203)
- **Deciders:** Arthur (solo project)

## Context

Every Ghidra-dependent command needs the whole Ghidra stack live: the
bethington/ghidra-mcp bridge extension strictly paired to one Ghidra build
(ADR-0001), and calxgloss-side server orchestration — probe, attach-or-spawn,
pid files, orphan reaping, boot budgets, the wrong-program guard (ADR-0007).
Those mechanisms answer operational failures that have nothing to do with the
target binary: version mismatches, busy ports, phantom programs.

Kuna (Noelo-Lab/kuna, Apache-2.0) is a Rust port of Ghidra's decompiler that
embeds as a library: it loads ELF/PE/Mach-O directly in-process, with its own
loader/analyzer tier. Epic #203's spec puts it behind the existing
`ScanSource`/`TypeWriteSource` seams so nothing above Integrations learns
which engine produced a record. This ADR records the first slice (#205): the
engine skeleton and the selection mechanism the later tickets ride.

## Decision

**Engine selection is a run-wide setting, not a per-command wiring.** A
`[analysis] engine = "ghidra" | "kuna"` config key (env
`CALXGLOSS_ANALYSIS_ENGINE`, global `--engine` CLI flag) resolves through the
normal layered precedence, defaulting to **`ghidra`** — existing workflows and
write-back-to-Ghidra behavior are undisturbed until opted in. **A run uses
exactly one engine**: the dispatch gate rejects every Ghidra-dependent command
under `kuna` with a named error pointing at `--engine ghidra`, rather than
letting one command quietly reach the other engine. An invalid configured
value fails at resolution, naming the layer it came from.

**`calxgloss-kuna` (Integrations context) loads targets in-process.** The
crate wraps Kuna's console engine (`kuna_console::engine::bootstrap_from_object`)
behind one deep entry — `load(path) -> KunaProgram` — answering program
identity (SLEIGH id like `x86:LE:64:default`, entry point, symbol count).
Every failure is a named `KunaError` whose message spells out the
`--engine ghidra` fallback; no stack traces.

**The Kuna dependency is pinned to a release tag via a git dependency** —
`v1.878` (commit `cb68db1`) — because the Kuna workspace is `publish = false`
and moves fast; upgrades are deliberate, and the pinned release is reported
(`KUNA_RELEASE`) so records can name their engine. Only the three crates the
skeleton needs are pinned (`kuna-base`, `kuna-console`, plus `kuna-slacomp`
build-side), not the whole workspace.

**SLEIGH specs are compiled at build time and embedded.** Kuna's own
embed-specs feature lives on its bin-only CLI crate, which cargo cannot reach
through library dependencies, so calxgloss builds its own: `build.rs` locates
the pinned checkout's `specs/` tree, compiles the x86 tree with Kuna's
`slacomp` driven as a library, and embeds the output via `include_bytes!`; at
runtime the specs unpack once into `$XDG_CACHE_HOME/calxgloss/kuna/specs-<id>`
behind a lockfile and a completion marker — mirroring Kuna's own embedded-specs
pattern — and the engine loads them from there. Only x86/x86-64 is embedded,
matching calxgloss's PE-target scope.

**`doctor` under `kuna` is load-and-report.** `doctor --engine kuna --binary
<FILE>` loads the target and prints its identity; the probe/attach/spawn,
install, and port checks of the Ghidra path simply do not run. The binary is
required because there is no server to ask for its current program.

**ADR-0001 and ADR-0007 stay Accepted and untouched.** They govern the
`ghidra` engine; the Ghidra lifecycle code is not modified by this work. The
two engines coexist until (and unless) the parity comparison in #203 decides
whether `kuna` ever becomes the default.

## Consequences

**Gains:**
- A bare machine can load and identify a target binary with only the
  calxgloss binary — no Ghidra install, no JVM, no bridge, no ports. The
  wrong-program failure mode is structurally impossible under `kuna`: one run
  loads exactly one target.
- The selection mechanism is one resolver (`Settings::engine_choice`) and one
  dispatch gate, so the later scan-path tickets (#206–#213) inherit the
  one-engine rule instead of re-deciding it per command.
- Embedding the specs keeps the "one binary, no external data tree" property
  Kuna's own distribution has; the build-time compile is deterministic and
  rev-matched to the pin.

**Caveats:**
- In-process embedding means an engine panic lands inside calxgloss. The
  spec's isolate-at-the-seam-boundary rule (catch-unwind per source call) is
  later-ticket work; the skeleton itself does not yet install it.
- Only x86/x86-64 specs are embedded; other architectures fail with the named
  load error and the `--engine ghidra` pointer.
- The web scan path does not yet honour `kuna`: `serve` and `live` are
  gated to the ghidra engine like every other engine-dependent command, and
  engine selection reaches the web scan path itself with #212's e2e work.
- First `kuna` use unpacks the specs into the user cache (~a few MB);
  subsequent runs reuse them. Deleting the cache directory is always safe.
- The pinned Kuna release is young and moves fast; the pin plus the reported
  `KUNA_RELEASE` make any upgrade a deliberate, reviewable change.

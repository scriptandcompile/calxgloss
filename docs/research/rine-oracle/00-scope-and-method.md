# rine ↔ calxgloss — scope and method

> Part of the [rine-oracle overview](README.md). Read this first for what is
> being compared and how.

## What rine is

**rine** ([scriptandcompile/rine](https://github.com/scriptandcompile/rine),
website [scriptandcompile.github.io/rine](https://scriptandcompile.github.io/rine/))
is a **Windows PE executable loader for Linux, written from scratch in Rust** —
a modern-Wine project in the same functional space, and a sibling repo sharing
calxgloss's owner (`scriptandcompile`). Its model, per its own README: parse
the PE (goblin), `mmap` sections at the preferred base, apply relocations,
resolve imports against a plugin registry of reimplemented DLLs (ntdll,
kernel32, user32, msvcrt, gdi32, advapi32, shell32, ws2_32…), and let guest
code run **natively in the loader process** — no interpreter, no CPU
emulation, no wineserver. 32-bit guests are delegated to a separate `rine32`
binary. Status v0.1.4: console apps with basic I/O, threading, and
synchronization; GUI in progress; no networking beyond stubs.

## Why this comparison exists

calxgloss executes Windows code in three lanes — **baseline capture**,
**reference-app capture**, and **scenario capture** — all by launching Wine
([10](10-calxgloss-baseline.md)). Wine is a black box: the *verify* lane never
touches it, and the capture lanes only get process-level service from it.
The question this corpus answers:

> Assuming rine keeps growing its API conformance list, **what else would it
> need to become a better test harness than Wine** — direct API hooking,
> mocking, deep introspection — and what should rine's focus be to make that
> happen?

This is deliberately **not** a "can rine run Windows 95 notepad" comparison and
not an API-count comparison. Coverage is a prerequisite, not the subject; the
subject is the *harness surface* — the things around the API list that
determine whether captures are observable, interceptable, reproducible, and
attributable.

## Review method

- **calxgloss side**: read from the working tree —
  `crates/pipeline/calxgloss-testgen/src/wine*` (runner, harness, proxy,
  capture, scenario lane, owned-process, sampler),
  `crates/pipeline/calxgloss-verify/src/` (consumer side), plus
  `docs/roadmap.md` P43/P44/P48, the CHANGELOG Wine incident entries, and the
  ADRs the lanes cite.
- **rine side**: read from a checkout at **`da46c32` (v0.1.4, 634 commits,
  2026-11-08)** — `crates/rine-runtime-core` (loader, resolver, entry),
  `crates/rine-dlls` (registry, dynamic providers), `crates/rine-dll-build`
  (codegen), `crates/platform/win-common/*` (implementations),
  `crates/rine-types` (config, dev hooks, handles), `crates/rine-channel` +
  `crates/rine-dev-bridge` + `crates/rine-dev` (telemetry), `crates/rine/tests`
  + `tests/fixtures` (test story), `docs/data/dll-support.json` (coverage),
  and the unmerged `golden-harness` branch.
- All rine file:line citations were re-verified against that HEAD.

## Two stale-document traps found during review

1. **rine docs claims not at HEAD.** A root `docs/ARCHITECTURE.md`, a
   `dll.builtin` config key, and `--dll-report` / `--memory-snapshot` CLI
   flags appear in some mid-investigation citations but do **not** exist at
   `da46c32` (only a static-site `docs/` exists: `index.html`,
   `dll-support.html`, `data/dll-support.json`). Treat only the citations in
   [20](20-rine-inventory.md) as current.
2. **The `golden-harness` branch is unmerged.** It carries
   `docs/plans/golden-harness-plan.md` and a `rine-test-utils` crate (pixel
   PNG goldens + canonical-environment knobs). It is a *theming regression*
   harness, not an API oracle, and none of it is on `main`. [20 §3](20-rine-inventory.md)
   marks its items explicitly.

Also note `docs/data/dll-support.json`'s `generatedAt` is `2026-05-29`, so the
published coverage numbers *understate* the code at HEAD; the repo-wide
attribute counts in [20 §2](20-rine-inventory.md) are the fresher measure.

## Comparison scope

**In scope:** the harness interface (what calxgloss calls and reads at the
emulator seam), observation and tracing surfaces, hooking/mocking mechanisms,
determinism and provenance controls, state introspection, embedding, fault
handling, and the test-suite strategy on both sides.

**Out of scope:** API-by-API conformance auditing of rine; Wine internals
beyond what calxgloss's lanes touch; GUI/visual fidelity except where it
blocks headless CI; the GameFrame research corpus's live-analysis tooling
(cited only for the privileged-instruction lesson in
[10 §3](10-calxgloss-baseline.md)).

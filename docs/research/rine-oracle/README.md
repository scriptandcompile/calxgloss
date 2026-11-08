# rine (scriptandcompile/rine) — as a calxgloss test oracle, replacing Wine

> **rine** ([scriptandcompile/rine](https://github.com/scriptandcompile/rine)) is a
> from-scratch Rust reimplementation of the Windows-user-space execution layer:
> a PE loader plus reimplemented DLLs (kernel32, user32, ntdll, …) that run
> Windows x86-64 binaries natively on Linux. It is the sibling repo to
> calxgloss and shares its owner. calxgloss today runs its baseline,
> reference-capture and scenario lanes under **Wine**; rine is the candidate
> replacement oracle.
> This directory asks one question: **beyond adding more API coverage, what
> would make rine a better test harness than Wine — and what should rine focus
> on to get there?** rine reviewed at `da46c32` (v0.1.4, 2026-11-08); see
> [scope and method](00-scope-and-method.md).

## Executive summary

**Wine gives calxgloss a process, not an instrument.** Everything calxgloss's
three Wine lanes get from the emulator is process-level — launch, stdio, exit
code — and everything beyond that (the recording proxy DLL, guest-process
sampling through `/proc`, per-case crash retries, pairing stamps against
nondeterminism) is scaffolding calxgloss builds *around* Wine, because Wine's
API boundary is a real PE DLL boundary implemented in C and nothing inside it
is cheap to observe, intercept, or control. ([10 §2, §3](10-calxgloss-baseline.md))

**rine's structure is the inverse: one codegen seam serves tracing, hooking,
mocking, and provenance simultaneously.** Every API is a typed Rust function
registered in `DllRegistry`; a build script already generates wrapper code
from `#[implemented]`/`#[partial]`/`#[stubbed]` attributes; coverage state is
already machine-readable JSON. Recording wrappers, per-export mocks, and
provenance stamps all attach at that one seam — which is why *API coverage is
not the binding constraint on oracle quality*. ([20 §2](20-rine-inventory.md),
[30 §1](30-oracle-gap-analysis.md))

**The gap is that rine today exposes none of this as a harness surface.** No
per-API-call hook exists anywhere in the tree (`DevHook` is lifecycle-only);
guest calls bypass interception entirely after load-time IAT patching;
`LoadLibrary`/`GetProcAddress` are stubs returning 0; runs leak state to
`$HOME`; the crates are binary-only with no embedding API. The six priority
areas that close the gap — ordered so each one compounds the next — are in
[30 §3](30-oracle-gap-analysis.md) and scheduled as tracks R1–R10 in the rine
repo's [`roadmap.md`](https://github.com/scriptandcompile/rine/blob/main/roadmap.md)
(`rine/roadmap.md`). ([20 §5-6](20-rine-inventory.md))

## Capability matrix (condensed)

Winner in **bold**; "—" = absent. Reasoning per row in
[30 §2](30-oracle-gap-analysis.md).

| Harness capability | Wine (as calxgloss uses it) | rine today | rine potential | Verdict today |
|---|---|---|---|---|
| API coverage | ~6,000+ exports, decades of conformance | 308 declared (107 implemented) across 8 DLLs | grows with conformance work | **Wine**, unconditionally |
| Call-time observation | relay tracing (C, noisy, unmaintained) | — (IAT patched, no call seam) | codegen wrapper on every API, typed, JSON | **Wine** barely; rine wins by construction |
| Hooking / mocking | builtin/native DLL overrides, WINEDEBUG | provider `.so` per DLL, load-time only | per-export override + call-through spy + `force_stub` | **Wine**; rine's mechanism is better-shaped but narrower |
| Determinism control | none (prefix state, GUI boot, version skew) | worse (state in `$HOME` keyed by abs path) | hermetic mode, virtual clock, load-base pin | **Wine** by default; rine can pass P44 by construction |
| White-box introspection | — (winedbg only) | memory snapshot (dev-only) | handle/GDI/window/region state queries over socket | rine only |
| Embedding as a library | — | — (binary-only) | `lib.rs` session API | rine only |
| Faults as data | winedbg pop-ups, hang wedges batch | `abort()` on stub; SIGSEGV → exit 128+n | named fault events, hang budget at exec seam | both weak; rine fixable at one seam |
| Process-tree visibility | wineserver teardown; `/proc` preloader sniffing | real host threads, no session identity | session-scoped thread/process enumeration | rine can retire the sampler hack |

## Read next

- [00 — scope and method](00-scope-and-method.md): what was reviewed, how,
  and the two stale-document traps found during review.
- [10 — calxgloss baseline](10-calxgloss-baseline.md): exactly what the
  three Wine lanes need from an oracle (the wire contract), and every
  documented Wine pain point.
- [20 — rine inventory](20-rine-inventory.md): rine's execution model, the
  dispatch seam, testing story, observability, and hooking — exists vs missing.
- [30 — oracle gap analysis](30-oracle-gap-analysis.md): the six areas beyond
  conformance, their order, and what each one lets calxgloss delete.

## Steal list → where it landed

The gap analysis's priorities were transplanted into the rine repo as
`roadmap.md` (sibling checkout: `../../../../rine/roadmap.md`) — tracks
**R1–R10**, status matrix,
dependency order, and the calxgloss cutover definition-of-done). calxgloss-side
follow-ups (e.g. relaxing the Wine-specific workarounds once rine lands) are
noted in [30 §4](30-oracle-gap-analysis.md); P44 in
[`docs/roadmap.md`](../../roadmap.md) is the calxgloss track that consumes
rine's provenance record.

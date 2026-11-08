# Oracle gap analysis — what makes rine a better harness than Wine, beyond conformance

> Part of the [rine-oracle overview](README.md). Adjudicates
> [10](10-calxgloss-baseline.md)'s Wine contract and pain list against
> [20](20-rine-inventory.md)'s rine inventory, and states the focus areas in
> the order that compounds them. These became tracks **R1–R10** in
> `rine/roadmap.md`.

## 1. Difference of kind

Wine's API boundary is a **real PE DLL boundary implemented in C**. Nothing
inside it is cheap to observe, intercept, or control — which is exactly why
calxgloss had to invent the proxy-DLL lane, the `/proc` sampler, the
pairing-stamp nondeterminism defense, and the crash-retry dance
([10 §2-3](10-calxgloss-baseline.md)). Wine's own instrumentation (relay
tracing, winedbg) is process-wide C debug spew, not machine-consumable
records.

rine's API boundary is a **typed Rust function registry with a build-time
codegen pass** ([20 §2](20-rine-inventory.md)): every export crosses
`generate_metadata_code()` once; every implementation carries an
`implemented`/`partial`/`stubbed` maturity tag; coverage is already JSON.
That means one seam can serve **tracing, hooking, mocking, maturity tagging,
and provenance simultaneously** — cross-cutting harness features that cost
Wine a separate diverging effort each. This, not API count, is rine's
strategic case as an oracle.

The corollary is the risk: with 308 declared APIs and no call-time seam used
for observation yet ([20 §2, §4](20-rine-inventory.md)), rine today is a
*narrower* black box than Wine. The gap is architectural, and it is cheap to
close early — before the API list grows into the thousands and retrofitting
wrappers gets expensive.

## 2. The adjudicated matrix, per harness capability

| Capability | Why Wine can't | Why rine can | What to build (rine track) |
|---|---|---|---|
| Call-time observation + maturity tagging | C DLL boundary; relay traces unmaintained | codegen wraps every registered export once | recording wrapper → `ApiCall` event on the dev socket + `trace.json`; carries name, scalar args, return, `implemented`/`partial` tag. **R4** |
| Hooking / mocking per export | builtin/native overrides are per-DLL and coarse | provider `.so` ABI exists (`dynamic_provider.rs:12-13`) | per-export override, call-through spy, wire up dead `force_stub` (`config.rs:181`), post-load IAT re-patch. **R6** |
| Faults as data, not death | winedbg pop-ups; hangs wedge the batch | exception dispatch + `VIRTUAL_REGIONS` are Rust data | exact SEH→`SetUnhandledExceptionFilter`→`TerminateProcess(exit code)` path; privileged instructions as named fault records; `stub_function` abort (`registry.rs:490`) → configurable disposition; per-case hang budget at the exec seam. **R3** |
| Determinism + provenance | prefix state, `wineboot` GUI, version skew | loader already pins preferred base (`memory.rs:175`) | parseable `--version`; per-run `provenance.json` (rine build hash, guest sha256, load base, config hash); hermetic mode (in-memory registry, scratch root, wire the dead `PathTranslator`); virtual clock + RNG seed; canonical-env knobs ported from `golden-harness`. **R1, R5** |
| White-box state queries | — (winedbg only) | the state is already in `HANDLE_TABLE`, `VIRTUAL_REGIONS`, window/GDI registries | snapshot/query API over the dev socket: handles, regions, windows, GDI, TEB/PEB; generalize `rine-memory-snapshot-v1`. **R8** |
| Session-scoped process view | wineserver teardown + `/proc` preloader sniffing | guest threads are host threads rine itself created | enumerate threads/processes belonging to run N — deletes the racy sampler. **R8** |
| Embedding | — | same workspace, Rust | `src/lib.rs` session API (typed driver; keep one-guest-per-process isolation). **R7** |
| Conformance truth source | Wine's suite is the de-facto oracle but Wine is the thing being compared | differential runner can pair Wine+Windows | port Wine's LGPL conformance tests; run under Wine and rine; diff captures — fixtures assert Windows behavior, not rine's own. **R9** |
| Multi-guest / replay / snapshot-restore | impossible structurally | eventually: globals behind a session context | `GuestContext` refactor of `HANDLE_TABLE`/`TLS_BITMAP`/… **R10** (long horizon) |

## 3. The six focus areas, in compounding order

**A. Prioritize the loader family — it is harness infrastructure, not ordinary
conformance.** calxgloss's harness pattern ("map a DLL, read exports, call
from RWX trampolines, probe memory, catch the exception filter",
[10 §2](10-calxgloss-baseline.md)) fails entirely on rine today:
`LoadLibraryExW`/`GetProcAddress`/`GetModuleHandleExW` are stubs returning 0,
ordinals are never emitted, delay imports warn-only. These specific APIs buy
the *harness*, not just coverage — and fixing
`GetModuleHandleExW(FROM_ADDRESS)` deletes a workaround calxgloss carries for
Wine's own error-126 bug (`proxy.rs:388-398`). → R2 (+R3 for
`VirtualQuery`/`PAGE_GUARD`/exception dispatch).

**B. Make the API boundary observable at call time — the keystone.** Since
codegen already wraps every attribute, emit an optional recording wrapper:
name, scalar args, return, and the maturity tag, streamed as `ApiCall` events
on the existing socket or written as `trace.json` beside the run. Every future
conformance drop then produces a captured trace *for free* — with Wine,
tracing and conformance are separate, diverging efforts. Prereqs: add
`EnvFilter` to the subscriber (`rine/src/main.rs:18` — `RUST_LOG` is inert
today) and keep stderr clean for the `module base = 0x…` line. → R4.

**C. Hermeticity and provenance before any baseline is trusted.** An oracle
is only as good as its reproducibility. rine is currently *worse* than Wine
here: `$HOME` state keyed by absolute path, hardcoded drive mapping
(`file.rs:632`), dead `PathTranslator`. Publish a per-run provenance record so
calxgloss's P44 stamping is a read; add a per-case hang budget at the exec
seam (calxgloss's baseline lane has none — `wine.rs:40-45`). → R1, R5.

**D. Turn the provider ABI into a hook/mock framework.** The out-of-tree
`.so` seam is already better-shaped than Wine's DLL overrides; finish it:
per-export override, typed call-through spy, `force_stub` from config (the
"guest copes when API X is missing" lever Wine has no equivalent of),
post-load re-patch for tests that hook after bind. A `stub_function` that
records instead of `abort()` is what turns "unimplemented" from a lost batch
into a named verdict — calxgloss's per-case retry dance exists because a
Wine-side fault destroys the batch. → R3, R6.

**E. White-box introspection — the part Wine can never give.** The state a
harness wants is already Rust data: handle tables, the virtual-region map
(the same store `VirtualQuery` answers from), window/GDI registries, TEB/PEB.
Generalize the dev memory snapshot into a query format; make `PeLoaded`/thread
events session-scoped so calxgloss replaces the racy `/proc` preloader
sampler with one API call. Add a `lib.rs` session API so harness drivers are
typed Rust instead of a stdin/stdout wire protocol — while keeping
process-per-guest as the isolation boundary (that is what makes crash
isolation cheap). → R7, R8.

**F. Make the conformance suite itself the instrument.** Port Wine's LGPL
conformance tests into a differential runner: same cases on Wine and (where
reachable) Windows and rine; diff the captures. Divergences become
conformance bugs *and* baseline records, and with (B) each divergence arrives
with the exact API call, args, and maturity tag that produced it — which
today's self-asserting fixtures (`rine_test.h` avoiding `printf` to dodge
rine's gaps) cannot. → R9, with R10 (per-session context) as the long-horizon
enabler for replay and multi-guest.

## 4. What calxgloss deletes if this lands

| If rine ships… | calxgloss can delete / simplify |
|---|---|
| R4 trace + maturity tags | part of the proxy-DLL recording lane; P22 trace normalization gains a per-call maturity tag for free |
| R8 session-scoped process view | `scenario_run/sampler.rs` (`/proc` preloader sniffing) |
| R2 `GetModuleHandleExW(FROM_ADDRESS)` | the error-126 workaround in `harness.rs`/`proxy.rs` |
| R3 dispositions + hang budget | per-case batch-retry compensation in the baseline lane; unbounded-hang risk |
| R1/R5 provenance + hermetic mode | P44 becomes a read, not an inference; `wineboot`/GUI and `Z:`-non-ASCII workarounds (`wine.rs:47-61`, `engine.rs:913-919`) |
| R7 embedding API | the stdin/stdout wire protocol for new lanes (keep it as a compatibility surface for existing ones) |

Calxgloss-side work is deliberately *not* scheduled here: the lanes stay
Wine-first until rine passes the wire-contract gate (R1's acceptance list and
R2's loader family); the one calxgloss track that pairs with this is **P44**
(`docs/roadmap.md:93`), whose provenance stamp design should read rine's
`provenance.json` format.

## 5. Verdict

Wine-as-oracle is a process; rine-as-oracle can be an instrument. The
architectural preconditions — one codegen seam, typed registry, maturity
metadata, socket telemetry plumbing, a working interposition ABI — **all
already exist in rine at v0.1.4**; none is a coverage dependency. What's
missing is assembly: the recording wrapper, the loader family, hermetic runs,
the mock framework's last three features, and the state queries. That is the
focus. The tracks, in dependency order, are scheduled in `rine/roadmap.md`
(R1–R10, with the calxgloss cutover as R9/R10's definition-of-done).

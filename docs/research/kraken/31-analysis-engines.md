# KRAKEN analysis engines — the seam, the native engine, Ghidra, .NET, and the fake

> Part of the [KRAKEN overview](README.md). The engine layer end to end:
> the capability-trait seam (`kraken-engine`), the JVM-free native engine,
> the Ghidra sidecar, the .NET engine, the recorded-fixture fake, the
> `analyze` job, and how engine state is keyed to the binary — then the
> direct comparison against calxgloss's single-Kuna seam
> (ADR-0039/0040/0041, 0042/0043/0055, 0054/0055). KRAKEN claims cite the
> clone at `68718c6`, paths relative to the clone root.

## What KRAKEN does

### 1. The seam: thirteen capability facets, not one god-trait

`kraken-engine` (2,155 LOC) defines the whole engine contract. There is no
single `Engine` super-trait an implementor must satisfy; instead an engine
presents up to **thirteen capability traits** and *declares which it has*:

| Facet | Trait | What it answers |
|---|---|---|
| `loader` | `Loader` (traits.rs:33) | `open_binary` + optional stage reporting (traits.rs:44) |
| `analyzer` | `Analyzer` (traits.rs:58) | staged job: `load` / `core` / `expensive`, cancellable |
| `decompiler` | `Decompiler` (traits.rs:70) | one function at a time, token spans validated (traits.rs:71-77) |
| `type_store` | `TypeStore` (traits.rs:82) | get/define/list named types |
| `function_lister` | `FunctionLister` (traits.rs:97) | paginated functions, `get_function` |
| `mutator` | `Mutator` (traits.rs:115) | apply one edit-log op, `save` → `Watermark`, `current_checkpoint` for staleness detection |
| `memory` | `MemoryReader` (traits.rs:139) | memory map + raw bytes (uninitialized bytes reported) |
| `disassembler` | `Disassembler` (traits.rs:156) | paginated rows, function scope |
| `xrefs` | `XrefProvider` (traits.rs:185) | to/from, by kind, whole-function scope |
| `cfg` | `FlowGraph` (traits.rs:198) | blocks + edges of the containing function |
| `strings` | `StringLister` (traits.rs:206) | min length, filter, paginated |
| `symbols` | `SymbolLister` (traits.rs:218) | imports and exports |
| `assembler` | `Assembler` (traits.rs:175) | one instruction → encodings |

The bundle trait `Engine` (caps.rs:127) exposes `capabilities()` plus one
`Option<&dyn …>` accessor per facet — absent facets return `None` and
callers map that to `unsupported` (caps.rs:125-126, traits.rs:24).
`EngineCaps` (caps.rs:88) carries the protocol **handshake** — protocol
version, a free-form *build id*, and the capability names — so "what does
this engine support" is a wire-level fact, not a compile-time one
(caps.rs:97-117). `Engine::process_id()` (caps.rs:184) exists purely so a
UI can show activity (CPU) of the sidecar/worker while a long step reports
nothing. Every call takes a `CancellationToken` and returns
`EngineResult<T> = Result<T, ProtoError>` (traits.rs:21); refusals to
mutate carry code + reason (`EngineRejected`, types.rs:119-142). Long work
is a uniform job protocol: `AnalysisJob` = progress stream + completion
future + cancel token (job.rs:24-76), with stages (types.rs:46-67) and
within-stage `Step`s named by the engine (types.rs:71-94).

Discovery of an engine's support happens at three layers. Engines reach the
registry only through an `EngineFactory` (`session.rs:38`) — "the registry
never depends on a concrete engine crate: the CLI passes a factory building
`GhidraEngine`, tests pass one building `FakeEngine`" (`session.rs:34-35`).
Each registry command declares `needs(&[Cap])` (`command.rs:107`); dispatch
refuses a command whose needs the open project's engine lacks, with an
explicit `unsupported` naming the command (`command.rs:186-194, 216-224`).
And `project_info` lists the engine's capabilities, build, engine kind, the
choice and *why it was chosen* (`project.rs:64-82`), which the MCP resources
render for agents (`kraken-mcp/src/resources.rs:409`). Sidecars add a
wire-level handshake: the Ghidra client refuses a JVM whose advertised
capabilities miss any of `REQUIRED_SIDECAR_CAPABILITIES` — `open_binary`,
`analyze.staged`, `decompile.tokens`, `apply_op.v1`, `types.roundtrip`, …
(supervisor.rs:18-33, 433).

### 2. Engines run as confined child processes

Design 0004 sets the process model: 0.1a spawns a sidecar per client;
0.1b moves to `krakend` as sole parent, bounded sidecar restarts with log
replay, one ordered write queue (docs/design/0004-process-model.md:12-22).
Design 0007 sets the confinement: scrubbed environment, Landlock read-only
JDK/Ghidra/binary/system-libs and RW only throwaway home + project, TCP
denial via Landlock ABI v4 plus user/net namespaces for what Landlock misses
(UDP), socketpair-as-stdin with 4-byte big-endian length-prefixed JSON-RPC
2.0 (docs/design/0007-sidecar-confinement.md:14-25). The implemented
confinement stack in `kraken-sidecar/src/sandbox.rs:3-15` goes further than
the ADR: Landlock ABI v4/v6/v9 (`ResolveUnix`), a seccomp filter refusing
`socket(2)` and every non-`AF_UNIX` `socketpair(2)`,
`unshare(CLONE_NEWUSER|CLONE_NEWNET)`, `PR_SET_PDEATHSIG` from a spawner
thread — and **spawning fails unless the confinement is available**
(`ConfinementOptions::allow_unconfined` defaults false, sandbox.rs:24-35).
`kraken-procguard` covers the platforms' parent-death gap: Windows job
object with `KILL_ON_JOB_CLOSE`, macOS parent-pid watch (lib.rs:1-7). The
RPC client multiplexes request ids and dispatches `ready`/`progress`
notifications (rpc.rs:1-7).

### 3. The native engine: Ghidra's decompiler without the JVM

`engine-native` (22.2k) + `engine-native-sys` (1.5k Rust + 1.1k C++ shim)
replace the whole Java half of Ghidra (ADR 0014). What stays is Ghidra's
**C++ decompiler and Sleigh lifter**, compiled from the pinned
`Ghidra_12.1.4_build` source — `build.rs` compiles the Makefile's CORE,
DECCORE and SLEIGH sets as C++17, and with no cached sources builds a stub
whose `available()` is false so workspace builds never need a C++ toolchain
(build.rs:1-10; engine-native-sys/src/lib.rs:14-15, 535). A ~1k-line GPL
`cxx` shim provides the `SleighArchitecture` subclass, a Rust-backed
`LoadImage`, Ghidra core type names, and a `PrintC` that records token
spans directly — no markup parsing (docs/design/0014-native-engine.md:19-27).
The library holds global state, so one process-wide RwLock guards every
call; `Session::fork` creates equal sessions from an edit journal so
analysis can run on several at once (engine-native-sys/src/lib.rs:3-8,
369-381). Runtime inputs are only compiled `.sla` files — `cargo xtask
native-sla` compiles 24 Sleigh specs, byte-identical to Ghidra's
(0014:29).

Everything the Java side used to do is Rust in `engine-native`: ELF loader
at Ghidra's bases so anchors match Ghidra projects (elf.rs:1-4); PE32/32+
x86/x86-64 with ordinal imports, `EXTERNAL`-style stand-ins, TLS callbacks
and `.pdata` discovery (pe.rs:1-8); ELF/COFF objects, static libraries and
import libraries laid out like Ghidra links them, relocations applied by
type (objfile.rs:1-7); function discovery seeded by symbols, entry, PLT
stubs, init/fini arrays, `.eh_frame` FDE starts and `.pdata`, then
recursive descent over Sleigh flow with noreturn propagation to a fixpoint
(discover.rs:1-11, `NORETURN` list :20-39); DWARF types + locked
prototypes through `gimli` (dwarf.rs:1-12); Ghidra-style Itanium *and*
MSVC demangling with the mangled name kept (demangle.rs:1-9); constant
propagation over raw p-code for RISC address-building (constprop.rs:1-10);
Thumb mode detection via mapping symbols or a branch-only recursive walk
(arm.rs:1-7); references, CFGs in Ghidra's `SimpleBlockModel` shape,
strings, imports/exports, type store mirrored into the decompiler's C
grammar, ~240 libc + ~130 Win32 prototype tables (refs.rs:1-4, cfg.rs:1-3,
strings.rs:1-4, typestore.rs:1-10, libc.rs:1-6, win32.rs:1-7).

The native engine declares 12 of the 13 facets — everything **except
`assembler`** (engine.rs:1424-1438). It runs by default in a confined
`kraken-native-worker` child process with a hard watchdog: per-request
deadlines, idle-gap limits on opens/analysis, kill-and-structured-`timeout`
on overrun, `internal` + `worker: "crashed"` on death, automatic worker
restart that re-opens the binary and replays saved state plus the ops the
parent kept (native.rs:41-46; worker/mod.rs:10-11, 49, 65-106;
0014:89-98). `Isolation::InProcess` remains for tests; non-Unix is always
in-process (0014:98).

Coverage and quality are measured, not claimed. Against real-Ghidra
fixtures (ADR 0014:138-143): PE x86-64 100% functions / 98.9% bodies /
94.5% names; PE x86 100/99.0/98.7; 32-bit ELF 98.1/93.6/99.5; x86-64 ELF
98.3% functions, 94.4% bodies (:70). Truth recall is 100% on every corpus
binary (22 native-set binaries :134; 452/452 across 68 ARM/AArch64/RISC-V
binaries :167). What it does *not* do (docs/native-engine.md:304-316):
Mach-O, big-endian ELF, any processor beyond x86/ARM/AArch64/RISC-V, PDB
for PE, delay-load imports, PE resources, DWARF variables, non-Linux hosts
— with `auto` routing those to Ghidra. Performance is documented to the
table: a small program opens in well under a second; the 7 MB
`libQt6Widgets` first-opens in ~1191 s but reopens in 7.0 s from the saved
engine state; decompile p50 through the worker is ~6 ms (re-decompile
~2 ms) (docs/performance.md:120-165).

### 4. The Ghidra engine: the full JVM sidecar

`engine-ghidra` (4.0k Rust) + `java/kraken-ghidra` (5.1k Java, 11 files)
embed a real Ghidra: the extension's `KrakenSidecar.main` starts a
dispatcher, `Engine.java` (1,058 lines) wraps `Loader`/`AutoAnalysisManager`/
`DataTypeManager` behind the RPC methods, `TypeConv.java` maps Ghidra's type
system to the neutral model, `Assemble.java` provides the SLEIGH assembler —
so the Ghidra engine is the only one declaring all 13 caps (engine.rs:898-906).
Nothing starts until the first `open_binary` (because heap and Landlock rules
depend on the binary), and the JVM heap is sized from the binary's size,
floored at 1 GiB, capped by config and physical RAM (lib.rs:15-16;
config.rs:10, 99). A `Supervisor` does the handshake check, death detection,
bounded restarts and `SidecarEvent`s to the registry (supervisor.rs:38, 157).
Install discovery is strict: `TESTED_GHIDRA_VERSIONS = ["12.1.4"]`, with
`KRAKEN_GHIDRA_HOME`/`KRAKEN_JAVA_HOME`/`KRAKEN_GHIDRA_EXT_JAR` env lookup
(install.rs:11-17). Provisioning (`kraken setup`) downloads the pinned
Ghidra 12.1.4 archive and Temurin JDK 21.0.12.1+1 with SHA-256 verified
*before* unpacking, refuses zip-slip and >16 GiB extractions, and compiles
the extension with the downloaded JDK's `javac` — no Gradle — or installs a
prebuilt jar (provision.rs:1-14, 30-45); that is the ~3 GB download
(docs/native-engine.md:31). What Ghidra still offers over native: every
Sleigh processor, Mach-O, PDB, richer analysis-fed typing, references kept
up to date across structural edits (native-engine.md:41-43), and the
assembler. Analysis is Ghidra's own `AutoAnalysisManager`, split into two
stages by toggling analyzer options — everything except "Decompiler Switch
Analysis" and "Decompiler Parameter ID" in `core`, those two in `expensive`
(decision 90; Engine.java:80-83) — each stage saved to the Ghidra project
after it completes, stage completion persisted in the program info
(`stages_done`, Engine.java:192, 368-373), and a cancel-aware monitor that
reads the running analyzer *by reflection* to name each `Step` (Engine.java:214-320).

### 5. The .NET engine: proof the seam generalizes

`engine-dotnet` (2.5k) + `dotnet/kraken-dotnet` (980 lines C#) run ILSpy's
`ICSharpCode.Decompiler` in a confined .NET sidecar: methods listed as
`Locator::Managed`, decompiled to C# with token-linked references, types
read-only (lib.rs:1-10). It declares only **five** facets — loader,
decompiler, type_store, function_lister, mutator (engine.rs:309-317): no
disassembly, xrefs, CFG, strings, symbols, memory, assembler. ILSpy has no
database to write to, so edits live in KRAKEN's log and are *replayed at
render time* — renamed tokens substituted in the C# text, comments added as
`//` lines (annotate.rs:1-6). Setup downloads a pinned .NET 10 runtime
(SHA-256 checked); managed assemblies always use this engine, whatever the
project's choice (docs/dotnet.md:16-22; docs/native-engine.md:60). Status:
first release, deliberately small, with the gaps listed so there are no
surprises (dotnet.md:3-5).

### 6. engine-fake: everything tested without an engine

`engine-fake` (2.7k) serves every facet from one JSON fixture **recorded
from real Ghidra** by `kraken-record` (lib.rs:8-36). Where a fixture omits
program data it synthesizes plausible stand-ins — fake `.text/.rodata/.bss`
blocks, synthetic disassembly rows, xrefs derived from decompiled calls
(lib.rs:44-56). Mutations behave like the real thing: a rename rewrites the
decompiled text and token spans; a stale `old_name` returns
`conflict_stale_read`; `Perturb` models drift between recording and replay
(lib.rs:38-48; engine.rs:125-127). The same `run_contract_suite` — sections
capabilities / loader / analyzer / listing / decompile / types /
cancellation / mutation (kraken-engine/src/testing.rs:117, 129-140) — runs
against the fake (engine-fake/src/tests.rs:31), against a real Ghidra in
`#[ignore]` tests the `real-ghidra` CI job runs (engine-ghidra/tests/real_ghidra.rs:213),
against native on corpus binaries (engine-native/tests/native.rs:430,
windows.rs:422, arch.rs:461, libraries.rs:517), and against the committed
fixtures themselves (kraken-record/tests/fixtures.rs:169). The whole Rust
workspace, and even the Python e2e suite, run against FakeEngine-backed
projects with a scripted `krakend` — no Ghidra, no JVM, no native library
(ci.yml:152-154; session.rs:34-35). `drift.yml` nightly re-records each
fixture from real Ghidra and fails on drift (kraken-record/src/lib.rs:1-11;
drift.yml:8, 68). This is how KRAKEN keeps a multi-engine seam honest
without multiplying real-engine CI.

### 7. What one `kraken analyze` actually does

`analyze` is a job-kind, mutating command (jobs.rs:40): it requires
`Cap::Analyzer` (jobs.rs:63), returns a `job_id` — *or the existing id if
one is already running* (jobs.rs:84-92) — and its docs say to run it once
after opening; other tools give partial results until it finishes
(jobs.rs:53-56). The registry's pump (jobs.rs:148-210) forwards engine
progress events into a `JobReporter`, adds `elapsed_ms` and — sampling the
engine's `process_id` — a CPU-activity readout with a `quiet_secs` field so
a stalled job is visible. `job_status` / `job_await` (default 30 s, capped
by session config) / `job_cancel` drive it from any surface
(jobs.rs:278, 323, 363). Edits made during analysis are logged but held,
then flushed to the engine when the job ends; the result reports
`flushed_entries` / `rejected_entries` (jobs.rs:57-61, 113-124).

What the job *means* differs per engine, and that is the point of the
staged `load`/`core`/`expensive` protocol (types.rs:46-53): for the Ghidra
engine it is Ghidra's full auto-analysis, staged and resumable via
`resume_from` (engine-ghidra/src/engine.rs:431-451; Engine.java:329-396).
For the native engine most of it already happened **at open**: discovery,
landing pads, noreturn propagation, the reference index and symbol lists
are loader work; `load` and `core` mostly *report* it (plus the string
scan), and `expensive` decompiles every function **once** to fill in
signatures, on up to 6 forked decompiler sessions, while the program's own
session stays free for interactive decompiles (analyze.rs:1-19;
docs/performance.md:102). Interactive reads are always live against the
engine — `decompile` hits the decompiler per call, no registry-level cache
of pseudocode (query.rs:265-300) — with engine-internal caches underneath
(next section). Native's whole-program pass is the slower route:
libzstd's analyze is 805 s native vs 199 s Ghidra, because Ghidra's
switch-analysis analyzers share work differently (performance.md:269-272);
but native's *open* is far faster for small binaries — seconds vs about a
minute of Ghidra analysis (docs/native-engine.md:32).

### 8. Caching and identity: the log is truth, the engine is cache

A project directory holds `project.kraken.sqlite` (the append-only edit
log: operation, anchor, author, run id, provenance, read-set, status —
session.rs:26; kraken-model/src/lib.rs:1-3; store schema store.rs:21-39),
`meta.json`, and an engine directory (named `ghidra` whatever the engine,
session.rs:30). The engine's entire state is a cache with a three-part
validity key — the **epoch** `{engine_build, options_hash, binary_hash}`
written at create (session.rs:1117-1121; `OPTIONS_DESCRIPTOR` versioned
"loader=default;analysis=staged-v1", session.rs:32). On open, each field is
compared and the *mismatching field names* are reported (`epoch_mismatch`,
session.rs:1226-1232, 446-449); `project_info` says `epoch_stale: true,
stale_fields: [...]` and points at `rebuild` (project.rs:70-73).
`rebuild` recreates the engine project from nothing: fresh engine
directory, full replay of the log, then a diff against the old engine's
views reporting `name_changed` / `signature_changed` / `missing_after` /
extra functions (rebuild.rs:1, 30-45) — the exit criterion that milestone
0.1a was gated on (ADR 0012). Engine-level staleness has its own channel:
`Mutator::current_checkpoint` vs the stored push watermark detects an
engine whose saved state is behind the log, and the session re-pushes the
pushed entries to resync (session.rs:604-614, 639-705).

The native engine's cache is concrete and keyed: `save` returns
`native:<count>:<hash>` watermarks; with a state directory it writes
`native-state.json` (journal + analysed signatures, keyed by binary
SHA-256) so reopening restores state without re-analysis (0014:83), and
`discovery-cache.json` stores recovered jump tables keyed by binary hash ×
use-symbols × library version, best-effort both ways (jumpcache.rs:1-8).
Ghidra's cache is its own project directory, which the sidecar may write.
Re-analysis after an engine swap or option change is not incremental — it
is `rebuild` against a fresh engine — but re-opening a warm engine directory
is nearly free (Qt Widgets: 1191 s first open → 7.0 s reopen,
performance.md:152-165).

## Comparison with calxgloss

### The seam: multi-process facet engines vs one in-process seam

KRAKEN's seam and calxgloss's are the same shape — a narrow set of query
facets with engine-neutral wire types above them (KRAKEN's
`kraken-registry` never links an engine crate, `session.rs:34-35`;
calxgloss's consumers never see Kuna types, ADR-0039/0040) — and both
declare capability per query family and refuse honestly
(`needs(&[Cap])` → `unsupported`, command.rs:216-224; `ScanSource::capability_report`
`answerable`/`unavailable` with admission lines, ADR-0054/0055). The
differences are load-bearing:

- **Process stance.** KRAKEN puts every real engine across a process
  boundary and confines it, because it executes JVMs, C++ and C# parsers
  over untrusted bytes — and measured consequences forced it back even
  after choosing an in-process native library: "a crash or hang in the C++
  code takes the whole process with it" (engine-native-sys/src/lib.rs:9-10)
  is why phase 3 re-confined it behind a watchdog (0014:89-98). calxgloss
  deleted exactly this lifecycle (JVM bridge and Ghidra HTTP removed,
  ADR-0041) and pays nothing for it at runtime: one engine thread, no
  sidecar, no restart path. That works *because Kuna is in-repo Rust under
  calxgloss's own tests* — the trust assumption is the whole difference.
  If calxgloss ever pulls Kuna from upstream binaries, KRAKEN's watchdog +
  restart + replay is the design it will wish it had.
- **Contract testing.** KRAKEN runs one suite against every engine
  (fake/ghidra/native) and checks the handshake agrees with the accessors
  (testing.rs:1-6). calxgloss has engine harnesses over one fixture DLL
  and a fixture-replay gap it records as roadmap P33. KRAKEN's
  recorded-from-the-real-engine fixture + nightly drift check
  (`kraken-record`, drift.yml:68) is the single most directly stealable
  engine-layer idea in this whole comparison: `kraken-record`-style
  *recorded Kuna output* + a drift job would give calxgloss's 15 scans a
  Ghidra-bridge-free, Kuna-upgrade-safe test ground, and the fixture
  format is just JSON of the wire types calxgloss already has.
- **Type-safety direction.** calxgloss's split read/write traits with the
  compile-time tripwire (`CachedScanSource` can never implement the write
  trait, `type_write_source.rs:222-227`) is stricter than KRAKEN's runtime
  `Option<&dyn Mutator>`: KRAKEN's cache-like layers (worker client) can in
  principle mis-declare `Cap::Mutator`; only the contract suite catches it.

**Verdict:** KRAKEN's facet seam is the better *multi-engine* seam and its
contract-suite + drift-check discipline is better than anything calxgloss
has. calxgloss's single-engine in-process seam is the better *pipeline*
seam — fewer moving parts, stronger compile-time guarantees, and ADR-0041
already spent the choice and banked the simplicity. Neither should change
sides; calxgloss should copy the *tests*, not the processes.

### Analysis model: one job + live queries vs batch scans + read cache

KRAKEN: one staged `analyze` job per binary (progress, cancel, resume,
CPU-activity honesty), then everything answers live against the engine;
pseudocode is re-decompiled per call and costs engine latency (~6 ms p50
native through the worker). calxgloss: 15 whole-binary evidence scans fan
out *before* any translation, through the scan registry with latches and a
skip-rate fuse (ADR-0052), each stamping its own coverage record
(ADR-0053), results filed as documents under `re/analysis/` and served
through a three-tier read cache. KRAKEN has **no evidence layer at all** —
its engine does function discovery, references, strings, types and
signatures, but nothing like type-inference propagation, memory-lifecycle,
callback or known-library analysis; those live in `kraken-infer`/the AI
layer or in the analyst. calxgloss-only, decisively.

Cache identity, side by side:

| | calxgloss scan read cache | KRAKEN engine cache |
|---|---|---|
| Key | binary identity + `sha256` of bytes, `CACHE_FORMAT_VERSION` 4, **engine build identity** (ADR-0042/0043/0055; `cache.rs:16-23,140`) | epoch `{engine_build, options_hash, binary_hash}` (`session.rs:1117-1121`) + native per-file keys (binary SHA-256 × symbols × library version, `jumpcache.rs:1-8`) |
| Miss behaviour | cold replay through the engine, read-through | `epoch_stale` + named stale fields → explicit `rebuild` command, then drift report (`project.rs:70-73`; `rebuild.rs:1`) |
| Granularity | per-read JSON documents (decompile/callers/memory) | whole engine state (`native-state.json`) + jump-table cache |

The designs converge on the same principle (engine identity belongs in the
validity key — exactly the lesson calxgloss adopted in ADR-0055), but
KRAKEN makes invalidation a *user-visible job with a drift report*, while
calxgloss makes it invisible (cold reads) and pairs it with `bdiff`
version-pairing of *accepted work*, which KRAKEN has no equivalent of at
the engine layer. KRAKEN's per-facet caching (jump tables, signatures,
journal) is more incremental than calxgloss's whole-scan documents;
calxgloss's cache is more *replayable* (a scan command re-runs from cache
without the engine, `--show` reads the filed document).

**Verdict:** for unattended whole-binary translation, calxgloss's batch +
filed-documents model is the right one — KRAKEN's live-query model would
make the translator pay engine latency thousands of times and gives the
prompt nothing KRAKEN computes anyway. KRAKEN confirms calxgloss's ADR-0055
key choice and adds one stealable nuance: **naming which identity field
went stale** (`stale_fields`) and offering a single named repair command —
calxgloss's cache just goes cold silently.

### Write-back: edit log pushed to the engine vs scan records typed into the program

KRAKEN's write path is designed around the inverse of calxgloss's premise.
Because humans and agents rename/type/comment at addresses, the **SQLite
edit log is the truth** and the engine program is a cache: `Mutator::apply`
is idempotent, compare-and-set on a read-set (`conflict_stale_read` for
stale `old_name`/function hash, 0014:82), undo writes compensating entries,
`save`/`current_checkpoint` keep the engine and log watermarks aligned
(traits.rs:115-135; session.rs:604-705), and `rebuild` proves the cache can
be thrown away. Every engine replays the log on open (native from its
journal; .NET at render time, annotate.rs:1-6). calxgloss has no per-change
history because nothing per-change exists to log: its write-back commits
**scan-discovered types** into the loaded program — narrow-only, program
order, never over a hand-typed slot (ADR-0020/0021) — and the loaded
program is itself disposable: re-loadable from binary + engine + records.
Both systems agree on the deep rule (derived state lives outside the
engine; the engine is rebuildable) and disagree on the unit: KRAKEN's
atomic unit is one human/agent edit with author, run id and undo;
calxgloss's is one engine scan's typed reading with confidence and
coverage. calxgloss's compile-time write/read split has no KRAKEN
counterpart, and KRAKEN's CAS-on-read-set prevents lost updates between
concurrent writers — a problem calxgloss sidesteps only because its
pipeline is single-writer.

**Verdict:** KRAKEN's machinery is the right shape for its interactive
domain and is over-built for calxgloss's (no authors, no undo, no
concurrent writers). calxgloss's narrow-only, never-overrule rule is the
better guard for machine-written program state. Neither should import the
other's write-back; the transferable piece is the **checkpoint/watermark
staleness probe** — KRAKEN's `current_checkpoint` vs watermark comparison
(session.rs:668-693) is a clean way for calxgloss to detect a loaded
program that has drifted from its filed records.

### Engine choice: per-file native/Ghidra/.NET vs fixed Kuna

KRAKEN chooses per project, recorded with the reason: `auto` is a pure
function over a machine/build probe and a file fit, and its chosen answer
carries the sentence that justified it (`choose`, host/native.rs:276-310;
`engine_reason` shown by `project_info`, project.rs:47/117); archives are
forced native because Ghidra cannot load them (`choose_native_only`,
native.rs:246-271); .NET always routes to the .NET engine
(native-engine.md:60). calxgloss fixed on Kuna (ADR-0041: "no engine
choice remains") and parks managed PEs unread (ADR-0044). For calxgloss's
exact niche — Windows PE32+ x86/x64 — KRAKEN's native engine is the one
other system doing the same job with public numbers (PE agreement vs
Ghidra: 100% functions / 98.9% bodies / 94.5% names, 0014:140), and its
Ghidra fallback is what calxgloss deliberately abandoned to keep
in-process determinism and its cache-identity story simple. One engine
means calxgloss's capability report describes one live session rather than
a selection; multi-engine would double the surface the queue, cache and
review UI must be honest about.

**Verdict:** KRAKEN's `auto` + recorded `engine_reason` is genuinely good
engineering (the decision is testable and explainable), but for calxgloss's
mandate fixed-Kuna is the right call and KRAKEN's existence proves nothing
against it — the two tools are choosing different things. The stealable
piece is again rhetorical: calxgloss's capability admission lines already
say *what* is unavailable; KRAKEN demonstrates always also saying *why
this* — worth applying when a scan row or tier is skipped.

### Overlap / calxgloss-only / KRAKEN-only

- **Overlap:** capability-declaring narrow seam over neutral wire types;
  honest `unsupported` refusals; engine identity inside cache validity
  keys; engine state treated as rebuildable cache over a durable record
  store (log vs `re/`); pinned downloaded toolchains with SHA-256
  (provision.rs:30-45 vs calxgloss's vendored Kuna crate); staged
  whole-binary analysis with progress and cancellation.
- **calxgloss-only:** 15 batch evidence scans with coverage stamps and a
  skip-rate fuse; type write-back with narrow-only rules and a
  compile-time read/write trait split; read-through per-read JSON cache +
  `bdiff` version pairing; scan output as prompt evidence (ADR-0048/0049);
  one engine with zero lifecycle.
- **KRAKEN-only:** the native JVM-free engine (22k LOC over Ghidra's C++)
  with measured Ghidra agreement; confined/watchdogged engine processes;
  the three-engine fleet (native/Ghidra/.NET) behind one seam; per-file
  engine choice with recorded reasons; `engine-fake` + contract suite +
  nightly fixture drift; job protocol with CPU-activity reporting;
  epoch-staleness that names its mismatched fields and repairs itself via
  `rebuild` with a drift report.

### Verdict

KRAKEN's engine layer is the strongest third-party evidence that
calxgloss's engine decisions were right for calxgloss's job: it *tried*
Ghidra-as-sidecar, *built* a JVM-free native path, and still had to confine
the C++ behind a watchdog — while calxgloss's in-process Kuna sidesteps the
whole lifecycle at the cost of a narrower engine. Where KRAKEN is plainly
better is engine *assurance*: the contract suite every engine passes,
fixtures recorded from the real engine, and the nightly drift check —
precisely calxgloss's P33 gap. Concrete steals, in priority order:
(1) **recorded-output fixtures + drift job** for Kuna (record scan outputs
from the fixture DLL, replay them in workspace tests, re-record nightly);
(2) **contract-test the seam** the way `run_contract_suite` does, so
Kuna-upgrade regressions fail at the seam, not in a pipeline run;
(3) **named stale-identity fields + one named repair command** instead of
silent cold cache; (4) **checkpoint-vs-watermark staleness probe** for the
loaded program; (5) **always state why** — a `reason:` string beside every
engine/capability decision. What calxgloss should *not* copy: multi-process
engines, engine choice, and KRAKEN's absence of an evidence layer.

## Sources

- `docs/design/0004-process-model.md`, `0007-sidecar-confinement.md`,
  `0014-native-engine.md` (phases, agreement tables, worker, mutation)
- `docs/native-engine.md` (engine matrix :29-43, choice :52-58, big
  programs :118-145, not-yet list :304-316), `docs/dotnet.md`,
  `docs/performance.md` (stage semantics :102, tables :120-176, native-vs-
  Ghidra :269-272)
- `crates/kraken-engine/src/{traits,caps,job,types,testing}.rs`
- `crates/kraken-sidecar/src/{sandbox,rpc}.rs`, `kraken-confine/src/lib.rs`,
  `kraken-procguard/src/lib.rs`
- `crates/engine-native/src/*` (module docs), `engine-native-sys/{build.rs,src/lib.rs,shim/}`,
  `crates/engine-native/src/{native,engine,analyze,discover,jumpcache,worker/*}.rs`
- `crates/engine-ghidra/src/{lib,launch,install,config,supervisor,engine}.rs`,
  `java/kraken-ghidra/src/main/java/kraken/ghidra/{Engine,KrakenSidecar,Dispatcher,TypeConv,Assemble}.java`
- `crates/engine-dotnet/src/{lib,engine,annotate}.rs`
- `crates/engine-fake/src/{lib,engine}.rs`, `crates/kraken-record/src/lib.rs`,
  `.github/workflows/{ci,drift}.yml`
- `crates/kraken-registry/src/{command,session}.rs`,
  `src/commands/{jobs,project,rebuild,query}.rs`,
  `crates/kraken-model/src/{lib,store}.rs`,
  `crates/kraken-host/src/{native,provision}.rs`
- calxgloss: `docs/research/kraken/10-calxgloss-baseline.md` §The
  analysis engine's seam; ADR-0001/0007/0020/0021/0039–0044/0048/0049/
  0052–0055; `crates/integrations/calxgloss-decomp/`
  (`scan_source.rs`, `type_write_source.rs`, `cache.rs`); roadmap P33

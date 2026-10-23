# REA deep native analysis — engines, providers, and the Kuna overlap

> Part of the [REA overview](README.md). REA's deep native-binary analysis surface and its engine providers, compared against calxgloss's embedded-Kuna pipeline.

## What REA does

REA is an agent-facing harness whose core is a *binary session* bound to one
*deep analysis provider*. Everything below — sessions, queries, annotations,
caching — is organized around that pair.

### The session model

`open_binary` admits one target by absolute path and selects the provider
(`provider_id`; CLI `--provider`; standing preference `REA_ANALYSIS_PROVIDER`)
(cli.md:226–254). `binary_session` reports the open target, selected provider,
and a complete per-tool availability inventory with reasons and remediation
inline (native-and-artifacts.md:254–267). `close_binary` releases provider
resources and optionally saves a snapshot (cli.md:306–310). The provider stays
bound until an explicit switch or close — runtime failure **never**
auto-falls back to another engine (ghidra-provider.md:21–23;
native-investigation.md:719). Unavailability and unsupported metadata are
*unknown, not false* (native-and-artifacts.md:228–229).

Navigation state is provider-side: `goto_address`, `current_address`,
`next/prev_address`, `get_navigation_context` move a provider cursor
(20-rea-inventory.md §2) — and only for engines that have one ("Kuna has no
cursor", kuna-provider.md:89). Hopper snapping and unmapped-input rejection
are specified per-provider (native-investigation.md:184–185).

Annotation state is mutated *in the engine's database*, not on disk:
Ghidra edits are "ephemeral database" with read-only bytes on Windows P0
(ghidra-provider.md:3–5). `annotate_native_function` atomically edits a
function name and entry comments and returns a refreshed dossier; edits are
session-scoped and invalidate immutable snapshots (native-investigation.md:713–718,
native-and-artifacts.md:483–485). `set_address_name`(s) name entries or data
labels with per-address booleans, preserving Ghidra namespaces
(native-investigation.md:720–731). Bookmarks, comments, and inline comments
round-trip through the provider; Hopper enforces a 1024-UTF-16-unit symbol
limit and exact readback on renames (native-investigation.md:187–193).

### The query surface

Text/structure queries, all session-scoped MCP tools (20-rea-inventory.md §2):
pseudocode (`decompile` / `procedure_pseudo_code`, `batch_decompile`),
assembly (`procedure_assembly`), instruction windows
(`read_function_instructions`), procedure inventory/search, edges
(`procedure_callers/callees/references`, `find_xrefs_to_name`), graph
(`get_call_graph`, `build_call_path`, `trace_call_path`, `trace`), strings,
memory (`read_bytes`, `inspect_address_context`,
`inspect_native_load_image`, `address_to_file_offset`), and dossiers
(`analyze_function`) whose facets are paged later via `inspect_analysis_view`
without re-analysis (native-and-artifacts.md:231–238). Deeper primitives on
Ghidra: per-instruction inspection with incoming references
(native-investigation.md:119–131), call-target resolution
(native-investigation.md:153–156), database type inspection up to 20k fields
(native-investigation.md:169–179), p-code def-use tracing across calls
(`trace_native_values`, native-investigation.md:293–302), jump-table recovery
with AArch64 verification (native-investigation.md:315–334). Ghidra selectors
accept names, canonical lowercase hex addresses, address-space coordinates,
and — for decompile only — source file offsets
(`procedure: "file-offset:0x..."`), with symbol-before-address precedence and
ambiguity failing closed (native-investigation.md:47–61;
ghidra-provider.md:84–107).

### The provider matrix

| Provider | What it answers | Selection / notes |
|---|---|---|
| Hopper | Full session surface; default; auto-install offered; string/dossier evidence, regex with deadline+worker-heap budgets | `--provider hopper` (native-investigation.md:182–250) |
| Ghidra | Full read-only surface + ephemeral edits; masked byte search; instruction/call/type primitives; P-code flow; PDB coverage handshake | BYO Ghidra 12.1.x + declared JDK (ghidra-provider.md:1–15) |
| IDA | Adapter over upstream ida-pro-mcp (attached GUI or headless idalib supervisor) or the native ida-free-mcp plugin: inventory, pseudocode, assembly, callees, xrefs, dossiers; direct callers only on the legacy profile; no CFG/typed refs/comments | `REA_IDA_MCP_CONFIG`, profile checked against live `tools/list` (ida-provider.md:1–19, 149–157) |
| Kuna | Inventory, pseudocode, assembly listing, callers/callees, strings, exact-address xrefs; **no** typed references, CFG, raw memory, annotations, type recovery | BYO `kuna` executable via `REA_KUNA_COMMAND` (kuna-provider.md:39–50) |
| Cutter bridge / Rizin | Arbitrary Cutter commands via authenticated loopback plugin; one-shot `execute_rizin_command` against an artifact; Rizin debug sessions (Linux) | retirement rule below (reverse-engineering-tools.md:48–130) |
| objdump | One-shot artifact views: headers, sections, symbols, relocations, DWARF, `-d`/`-D`, optional `--symbol` selector; raw text authoritative, 16 MiB capture cap | `REA_OBJDUMP_COMMAND` (reverse-engineering-tools.md:15–31) |
| GDB | Persistent GDB/MI console sessions + Linux-only debugger with detach proof via /proc | `start_gdb_session`, `gdb_console` (reverse-engineering-tools.md:34–38) |

`rea providers`/`rea capabilities` advertise operations up front (cli.md:228–237).
`auto` picks the single supporting provider; several supporting → explicit
selection required; Kuna plus another configured → `ambiguous` with
`details.candidate_ids` (cli.md:239–258; kuna-provider.md:14). Routing rules
from the skill: prefer literal search, names, decompilation, callers, xrefs;
use `binary_overview` only when inventory context helps; unrestricted
Rizin/Cutter/GDB commands retire any active analysis session so a fresh
provider can't be rebound mid-write — reopen explicitly afterwards
(native-and-artifacts.md:222–229; reverse-engineering-tools.md:5–13).
Architecture breadth: DOS 16-bit MZ/COM, generic MIPS o32 32r2, big-endian
PPC ELF32, RISC-V double-float ELF, PSP Allegrex MIPS ELFs, and .NET 8
NativeAOT x64 PE metadata all ride the Ghidra lane as narrowly-admitted
profiles; Windows Ghidra P0 is a read-only experimental boundary for
x86/x64/ARMNT/ARM64 PEs plus raw 6502 (ghidra-dos.md:1–8, ghidra-mips.md:13–24,
ghidra-ppc.md:11–20, ghidra-riscv.md:14–20, ghidra-psp.md:10–18,
ghidra-nativeaot.md:3–15, windows-ghidra-p0.md:12–20). Headerless images open
with `format: raw-binary` + `architecture` ∈ {x86, x86_64, arm, arm64, 6502,
m68k} + caller `entry_point`; only Ghidra admits them (raw-binary.md:28–52, 77–80).

### The Kuna provider in depth

REA treats Kuna as a **bring-your-own external executable** — one `kuna`
binary, static, never executes the target; verified against Kuna 1.833, other
releases marked unverified (kuna-provider.md:3–5). Targets: ELF and thin
Mach-O for x86-64/AArch64/ARM; **PE and universal Mach-O are rejected**;
Windows unsupported (kuna-provider.md:35).

Process model per session (kuna-provider.md:52–67): the first text/assembly
request starts a background `kuna decompile-project` on a private copy of the
target; meanwhile pseudocode comes from single `kuna decompile --addr` runs,
inventory from `kuna functions --json`, strings from one
`kuna strings --json ... --no-xrefs` scan (kuna-provider.md:77), calls from a
lazy `kuna decompile-graph` with no bodies, xrefs from `xrefs --to ADDRESS`
(kuna-provider.md:85–91). Runs are shared per function with per-waiter
cancellation; completed single-function text is cached to 16 MiB LRU.
Deadlines: `REA_KUNA_TIMEOUT_MS` 120 s per function,
`REA_KUNA_PROJECT_TIMEOUT_MS` 30 min whole-program (kuna-provider.md:29–33).
`REA_KUNA_JOBS` defaults to 1 because more jobs "lose callee-first prototypes,
and change about 40–60% of function bodies on the measured binaries"
(kuna-provider.md:31).

**Cache ownership** is explicit (kuna-provider.md:54, 119–128): exports are
keyed by target SHA-256 × Kuna executable SHA-256 × version × `--jobs`,
published under REA-owned `REA_KUNA_CACHE_DIR` by one atomic rename into
immutable `projects/<key>/`, with `staging/`/`trash/` gated on *proven process
stop* and LRU eviction under a 4 GiB cap. Every answer records provenance in
`raw_result.source` (`single-function` vs `project-export` with file, byte
span, digest) (kuna-provider.md:65).

Provenance limits (kuna-provider.md:113–117): extents are upper bounds clipped
at the next entry and Kuna can split one function at an inferred entry;
pseudocode is reconstruction; answers are re-read, not replayed from REA
snapshots, because a cold answer can differ from the export's. Memory scale is
measured: streaming JSON, no fixed buffers — a 20 MB binary yields 31 MB of
string rows; a 53 MB binary yields a 157 MB call graph retained in ~93 MB
after a ~1 min walk (kuna-provider.md:77, 91).

The internal case study (kuna-case-study.md) is the performance record: exact
string-address lookups moved to binary search over the validated inventory's
address order — 28 warm reads 495.2 → 90.8 ms (~5.5×) on a 602,544-row
inventory — while cold read, whole-task time, and memory showed **no** stable
improvement, and ~846k tokens of catalog transport dominated the task with *no
token reduction established* (kuna-case-study.md:46–66). The skill's lesson:
"reuse before adding machinery," measure the whole task, and don't generalize
a narrow win (kuna-case-study.md:77–90).

### Verification boundaries

Three honesty contracts stand out. (1) **Pseudocode honesty**: assembly and
pseudocode are the provider's listing/decompiler output, "neither is original
source," and cross-provider text is never treated as equal or unequal semantic
fact (ghidra-provider.md:168; mirrored for Kuna at kuna-provider.md:116).
Function extents report where an inferred no-return call truncated a body,
with a named-list no-return repair pass on non-Windows hosts
(ghidra-provider.md:175–198). (2) **Masked byte search** (`search_bytes`):
hex pairs with `??` wildcards plus an equal-length bit `mask` (`pattern "a0"`,
`mask "f0"` matches a0–af); searches initialized analyzed memory in address
order, never crosses block boundaries, lists `skipped_not_loaded` /
`skipped_uninitialized` coverage, and "a missing match does not establish
absence from uninitialized memory" (ghidra-provider.md:232–259;
native-investigation.md:853–863). (3) **Admitted inventory semantics**
(ghidra-provider.md:26–44): complete collections in one response (no caller
offsets/limits), string search covers only Ghidra-defined string `Data` (an
empty result proves nothing), memory ends are exclusive, thunks stay distinct
from targets, ambiguity fails closed, and the socket opens only after
auto-analysis completes. Snapshots replay exactly on
bytes+operation+provider+settings match, exclude mutations and
cursor-dependent calls, and are invalidated by any dispatched metadata write
(cli.md:280–317); analysis-profile versioning stops old snapshots replaying
superseded semantics (native-investigation.md:70–71).

## Comparison with calxgloss

### Overlap: the same engine at the core

Both harnesses put the **Kuna decompiler** (Noelo-Lab/kuna, Apache-2.0) at the
center — with opposite integration. REA shells out to a caller-supplied
`kuna` **executable**, one subprocess per whole-image run, results arriving as
JSON the adapter streams and validates (kuna-provider.md:52–91). calxgloss
embeds Kuna as a **Rust library in-process** (crate `calxgloss-kuna`):
`KunaSource` holds a `!Send` `ConsoleProgram` on an engine thread, loads the
target PE directly, and implements the `ScanSource`/`TypeWriteSource` seam so
nothing above the seam knows which engine answered (ADR-0039/0040); ADR-0041
then deleted the Ghidra bridge entirely, leaving Kuna as the only engine
while keeping the seam. A sharp irony: REA's Kuna provider *rejects PE
targets* (kuna-provider.md:35) — calxgloss runs embedded Kuna on exactly that
format, and reaches PE pseudocode-in-REA via the Ghidra provider instead.

Provider choice vs single engine: REA keeps five deep providers behind one
tool surface and negotiates per-tool availability at session level; calxgloss
collapsed to one engine (ADR-0041's "no engine choice remains"). REA's session
reports what each tool can currently answer, reasons included
(native-and-artifacts.md:254–267) — calxgloss has no equivalent surface.

### Cache comparison

Both built sha256-keyed read caches, with different invalidation philosophy:

- **REA, Kuna export cache**: key = target SHA-256 × *engine executable*
  SHA-256 × version × `--jobs` — external-engine identity is part of the key
  because the engine changes outside the harness (kuna-provider.md:54). LRU
  eviction, rename-publish, staging/trash lifecycle gated on *proven process
  stop* (kuna-provider.md:119–128). Separate from that, REA's snapshot files
  cache exact query results keyed on bytes+operation+provider+settings and
  exclude mutations (cli.md:280–317).
- **calxgloss scan read cache** (`re/cache/<binary>/<sha256>/`, ADR-0042/0043):
  keyed on binary bytes + program name + `CACHE_FORMAT_VERSION` — engine
  identity rides the harness build (the engine is compiled in), so a format
  version marker, not an engine digest, forces cold reads; renames are silent
  resets with no migration.

REA's key is stronger against engine drift; calxgloss's cache is simpler
because engine and cache ship together — and calxgloss has no REA-style query
snapshot storing replayable agent questions.

### calxgloss-only

- **Batch whole-binary evidence engines**: 11+ scans (types, callgraph,
  memory, sync, callbacks, serialization…) run before any function is
  translated; REA has no batch evidence layer — its queries are per-question.
- **Type write-back into the program state**: `TypeWriteSource` commits
  discovered types into the engine program (ADR-0020/0021), so later reads see
  better state. REA's engine edits (names/comments) are ephemeral, session-
  scoped, and never persisted — and Kuna annotations are unavailable at all
  (kuna-provider.md:50).
- **Automatic pipeline + verification loop**: prompts → LLM translate →
  compile/test the generated Rust against FFI baselines captured from the
  real DLL, with retries and review-UI adjudication. REA offers
  `verify_reconstruction`/compare tools but no closed compile-and-test loop.

### REA-only

- **Multi-provider choice** with discovery, doctor, and capability
  advertising (cli.md:226–272); calxgloss has one engine and no seam alternate.
- **Interactive navigation and annotations**: cursor state, bookmarks,
  comments, renames mutated in the live database (see session model above) —
  absent in calxgloss.
- **Arbitrary-address queries**: instruction-level inspection, `read_bytes`,
  load-image mapping, file-offset selectors, masked byte search — calxgloss's
  baseline explicitly has "no arbitrary per-address queries."
- **Call-path primitives on demand**: `get_call_graph`, `build_call_path`,
  `trace_call_path`, `trace_native_values` def-use across calls; calxgloss
  computes call graphs batch-wide but can't trace an ad-hoc path.
- **Architecture and format breadth**: ELF/Mach-O/PE/COFF, DOS, raw 6502/m68k,
  MIPS/PPC/RISC-V/PSP, NativeAOT, plus debugger/artifact lanes.

### Verdict

For calxgloss's job — deterministic, unattended, whole-binary PE→Rust
translation with evidence, write-back, and equivalence testing — calxgloss is
far stronger; REA would never produce its output automatically. For an
analyst's or agent's *question-driven* work on any native format, and for the
engine-agnostic surface itself, REA is the better harness: it answers
arbitrary questions, keeps honest boundaries about what each answer means,
and can swap engines. Things calxgloss could steal, concretely: (1)
**masked byte search** at the seam — a `search_bytes(pattern, mask)`
primitive would feed `calxgloss-consts`/`serialize` magic-number scans with
real matches instead of guesses; (2) **provider-seam revival as capability
advertising** — ADR-0041 kept the seam; adding a session-style capability
report would let prompts and fault monitors know which facts the engine can
actually answer (unknown ≠ false); (3) **engine-identity cache keys** —
include the Kuna crate version (or build hash) in the cache key à la
kuna-provider.md:54 instead of relying on a hand-bumped format version;
(4) **a call-path/def-use primitive** over the kept bodies for retry
strategies (`escalate`) to ask "how does this value reach this call" without
re-scanning; (5) the case study's measurement discipline — benchmark the
whole pipeline task, not the warm-path micro-op, and beware that transport
volume (tokens) can dominate everything else.

## Sources

- `docs/native-investigation.md` (core chapter, incl. §Locate a byte signature)
- `docs/kuna-provider.md`
- `docs/ghidra-provider.md`
- `docs/ida-provider.md`
- `docs/reverse-engineering-tools.md`
- `docs/cli.md` (Choose a provider; Save and reuse analysis snapshots; Output and exit status)
- `docs/raw-binary.md`
- `docs/ghidra-dos.md`, `ghidra-mips.md`, `ghidra-ppc.md`, `ghidra-riscv.md`, `ghidra-psp.md`, `ghidra-nativeaot.md` (skimmed)
- `docs/windows-ghidra-p0.md` (skimmed)
- `.agents/skills/reverse-engineer-anything/references/native-and-artifacts.md` (tool-routing sections)
- `.agents/skills/rea-analysis-optimization/references/kuna-case-study.md`
- calxgloss: `docs/adr/0039–0043`, `docs/rea/10-calxgloss-baseline.md`, `docs/rea/20-rea-inventory.md`

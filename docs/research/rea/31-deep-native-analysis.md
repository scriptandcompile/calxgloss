# REA deep native analysis — engines, providers, and the Kuna overlap

> Part of the [REA overview](README.md). REA's deep native-binary analysis surface and its engine providers, compared against calxgloss's embedded-Kuna pipeline.

## What REA does

REA is a harness for coding agents. Its core is a pair: a *binary session*
(the open analysis of one file) bound to one *deep analysis provider*
("provider" is REA's word for the disassembly/decompilation engine that
answers questions — Hopper, Ghidra, IDA, Kuna, and the rest). Everything
below — sessions, queries, annotations, caching — is organized around that
pair.

### The session model

`open_binary` opens one target by absolute path and selects the provider
(`provider_id`; CLI `--provider`; standing preference `REA_ANALYSIS_PROVIDER`)
(cli.md:226–254). `binary_session` reports the open target, the selected
provider, and a full inventory of which tools are currently available, with
reasons and remediation written inline (native-and-artifacts.md:254–267).
`close_binary` releases provider resources and optionally saves a snapshot
(cli.md:306–310). One provider stays bound until an explicit switch or close.
A runtime failure **never** falls back to another engine automatically
(ghidra-provider.md:21–23; native-investigation.md:719). REA reports
unavailability and unsupported metadata as *unknown, not false*
(native-and-artifacts.md:228–229).

Navigation state is kept by the provider: `goto_address`, `current_address`,
`next/prev_address`, `get_navigation_context` move a cursor inside the
provider (20-rea-inventory.md §2). Only engines that have a cursor support
this ("Kuna has no cursor", kuna-provider.md:89). Hopper's snapping rule and
its rejection of unmapped input are specified per provider
(native-investigation.md:184–185).

Annotations are written *into the engine's database*, not to disk: Ghidra's
edits go to its "ephemeral database", with the bytes kept read-only on
Windows P0 (ghidra-provider.md:3–5). `annotate_native_function` edits a
function name and its entry comments in one atomic step and returns a fresh
dossier (REA's per-function collection of findings); the edits apply only to
the current session and invalidate its immutable snapshots
(native-investigation.md:713–718, native-and-artifacts.md:483–485).
`set_address_name`(s) sets an entry name or a data label, one boolean per
address, and keeps Ghidra namespaces intact (native-investigation.md:720–731).
Bookmarks, comments, and inline comments are read and written through the
provider; on renames, Hopper enforces a 1024-UTF-16-unit symbol limit and
confirms the stored name exactly (native-investigation.md:187–193).

### The query surface

Text and structure queries, all session-scoped MCP tools
(20-rea-inventory.md §2):
pseudocode (`decompile` / `procedure_pseudo_code`, `batch_decompile`),
assembly (`procedure_assembly`), instruction windows
(`read_function_instructions`), procedure inventory/search, edges
(`procedure_callers/callees/references`, `find_xrefs_to_name`), graph
(`get_call_graph`, `build_call_path`, `trace_call_path`, `trace`), strings,
memory (`read_bytes`, `inspect_address_context`,
`inspect_native_load_image`, `address_to_file_offset`), and dossiers
(`analyze_function`); a dossier's parts are fetched later through
`inspect_analysis_view`, without re-running the analysis
(native-and-artifacts.md:231–238). Deeper primitives on Ghidra: per-instruction inspection with incoming references
(native-investigation.md:119–131), call-target resolution
(native-investigation.md:153–156), database type inspection up to 20k fields
(native-investigation.md:169–179), p-code def-use tracing across calls
(`trace_native_values`, native-investigation.md:293–302), jump-table recovery
with AArch64 verification (native-investigation.md:315–334). Ghidra selectors
accept names, canonical lowercase hex addresses, address-space coordinates,
and — for decompile only — source file offsets
(`procedure: "file-offset:0x..."`). A symbol wins over an address when both
are given. An ambiguous selector is refused, not guessed — it fails closed
(native-investigation.md:47–61;
ghidra-provider.md:84–107).

### The provider matrix

| Provider | What it answers | Selection / notes |
|---|---|---|
| Hopper | Full session surface; default; auto-install offered; string and dossier evidence, regex with deadline and worker-heap budgets | `--provider hopper` (native-investigation.md:182–250) |
| Ghidra | Full read-only surface + ephemeral edits; masked byte search; instruction/call/type primitives; P-code flow; PDB coverage handshake | Bring your own Ghidra 12.1.x + declared JDK (ghidra-provider.md:1–15) |
| IDA | Adapter over upstream ida-pro-mcp (attached GUI or headless idalib supervisor) or the native ida-free-mcp plugin: inventory, pseudocode, assembly, callees, xrefs, dossiers; direct callers only on the legacy profile; no CFG/typed refs/comments | `REA_IDA_MCP_CONFIG`, profile checked against live `tools/list` (ida-provider.md:1–19, 149–157) |
| Kuna | Inventory, pseudocode, assembly listing, callers/callees, strings, exact-address xrefs; **no** typed references, CFG, raw memory, annotations, type recovery | Bring your own `kuna` executable via `REA_KUNA_COMMAND` (kuna-provider.md:39–50) |
| Cutter bridge / Rizin | Arbitrary Cutter commands via authenticated loopback plugin; one-shot `execute_rizin_command` against an artifact; Rizin debug sessions (Linux) | retirement rule below (reverse-engineering-tools.md:48–130) |
| objdump | One-shot artifact views: headers, sections, symbols, relocations, DWARF, `-d`/`-D`, optional `--symbol` selector; raw text authoritative, 16 MiB capture cap | `REA_OBJDUMP_COMMAND` (reverse-engineering-tools.md:15–31) |
| GDB | Persistent GDB/MI console sessions + Linux-only debugger with detach proof via /proc | `start_gdb_session`, `gdb_console` (reverse-engineering-tools.md:34–38) |

`rea providers`/`rea capabilities` advertise operations up front (cli.md:228–237).
`auto` picks the single provider that supports the operation; if several
support it, an explicit selection is required; if Kuna and another provider
are both configured, the result is `ambiguous` with `details.candidate_ids`
(cli.md:239–258; kuna-provider.md:14). The skill's routing rules: prefer
literal search, names, decompilation, callers, xrefs; use `binary_overview`
only when inventory context helps. An unrestricted Rizin/Cutter/GDB command
closes any active analysis session, so a new provider cannot be attached
while that command's writes are half-finished; reopen the session explicitly
afterwards (native-and-artifacts.md:222–229; reverse-engineering-tools.md:5–13).
Architecture breadth: DOS 16-bit MZ/COM, generic MIPS o32 32r2, big-endian
PPC ELF32, RISC-V double-float ELF, PSP Allegrex MIPS ELFs, and .NET 8
NativeAOT x64 PE metadata are all handled through the Ghidra provider, each
as a narrowly admitted profile — REA documents exactly where support holds.
Windows Ghidra P0 is a read-only experimental boundary for
x86/x64/ARMNT/ARM64 PEs plus raw 6502 (ghidra-dos.md:1–8, ghidra-mips.md:13–24,
ghidra-ppc.md:11–20, ghidra-riscv.md:14–20, ghidra-psp.md:10–18,
ghidra-nativeaot.md:3–15, windows-ghidra-p0.md:12–20). Headerless images open
with `format: raw-binary` + `architecture` ∈ {x86, x86_64, arm, arm64, 6502,
m68k} plus a caller-supplied `entry_point`; only Ghidra supports them
(raw-binary.md:28–52, 77–80).

### The Kuna provider in depth

REA treats Kuna as a **bring-your-own external executable** — one `kuna`
binary, a static build, that never runs the target. REA verified it against
Kuna 1.833; other releases are marked unverified (kuna-provider.md:3–5). Targets: ELF and thin
Mach-O for x86-64/AArch64/ARM; **PE and universal Mach-O are rejected**;
Windows unsupported (kuna-provider.md:35).

Process model per session (kuna-provider.md:52–67): the first text/assembly
request starts a background `kuna decompile-project` over a private copy of
the target. Until that finishes, pseudocode comes from single
`kuna decompile --addr` runs, the inventory from `kuna functions --json`,
strings from one `kuna strings --json ... --no-xrefs` scan
(kuna-provider.md:77), calls from a lazily started `kuna decompile-graph`
with no bodies, and xrefs from `xrefs --to ADDRESS` (kuna-provider.md:85–91).
One run serves all waiters for the same function, and each waiter can cancel
its own wait. Finished single-function text is kept in a 16 MiB LRU cache.
Deadlines: `REA_KUNA_TIMEOUT_MS` 120 s per function,
`REA_KUNA_PROJECT_TIMEOUT_MS` 30 min whole-program (kuna-provider.md:29–33).
`REA_KUNA_JOBS` defaults to 1 because more jobs "lose callee-first prototypes,
and change about 40–60% of function bodies on the measured binaries"
(kuna-provider.md:31).

**Cache ownership** is explicit (kuna-provider.md:54, 119–128). Exports are
stored under REA's own `REA_KUNA_CACHE_DIR`. The cache key is target
SHA-256 × Kuna executable SHA-256 × version × `--jobs`. An export becomes an
immutable `projects/<key>/` directory through one atomic rename. `staging/`
and `trash/` are touched only once the producing process is *proven stopped*,
and LRU eviction keeps the store under a 4 GiB cap. Every answer records its
provenance in `raw_result.source` (`single-function` vs `project-export`,
with file, byte span, and digest) (kuna-provider.md:65).

Provenance limits (kuna-provider.md:113–117): a function extent is an upper
bound, clipped at the next entry, and Kuna can split one function at an
inferred entry. Pseudocode is a reconstruction, not original source. Answers
are re-read rather than replayed from REA snapshots, because a cold answer
can differ from the export's. Memory scale is measured: REA streams JSON and
uses no fixed buffers — a 20 MB binary yields 31 MB of string rows; a 53 MB
binary yields a 157 MB call graph, retained in ~93 MB after a ~1 min walk
(kuna-provider.md:77, 91).

The internal case study (kuna-case-study.md) is the performance record. Exact
string-address lookups were switched to binary search over the validated
inventory's address order: 28 warm reads went from 495.2 ms to 90.8 ms
(~5.5×) on a 602,544-row inventory. Cold reads, whole-task time, and memory
showed **no** stable improvement. Transporting ~846k tokens of tool catalog
dominated the whole task, and *no token reduction was established*
(kuna-case-study.md:46–66). The skill's lesson:
"reuse before adding machinery," measure the whole task, and don't generalize
a narrow win (kuna-case-study.md:77–90).

### Verification boundaries

Three honesty contracts stand out. (1) **Pseudocode honesty**: assembly and
pseudocode are the provider's listing and decompiler output. "Neither is
original source." Text from two providers is never treated as equal or unequal
as a semantic fact (ghidra-provider.md:168; the rule is mirrored for Kuna at
kuna-provider.md:116). Where an inferred no-return call cut a body short, the
function extent says so; a named-list no-return repair pass runs on
non-Windows hosts (ghidra-provider.md:175–198). (2) **Masked byte search**
(`search_bytes`): hex pairs with `??` wildcards plus an equal-length bit
`mask` (`pattern "a0"` with `mask "f0"` matches a0–af). It searches
initialized, analyzed memory in address order and never crosses a block
boundary. It lists `skipped_not_loaded` / `skipped_uninitialized` coverage,
and states that "a missing match does not establish absence from
uninitialized memory" (ghidra-provider.md:232–259;
native-investigation.md:853–863). (3) **Admitted inventory semantics** — the
provider documents exactly what each result covers (ghidra-provider.md:26–44):
collections are complete in one response (callers get no offsets/limits),
string search covers only Ghidra-defined string `Data`, so an empty result
proves nothing, memory ends are exclusive, thunks stay distinct from their
targets, an ambiguous selector fails closed, and the socket opens only after
auto-analysis completes. Snapshots replay exactly when bytes, operation,
provider, and settings all match. They exclude mutations and cursor-dependent
calls, and any dispatched metadata write invalidates them (cli.md:280–317).
Analysis-profile versioning stops old snapshots replaying superseded
semantics (native-investigation.md:70–71).

## Comparison with calxgloss

### Overlap: the same engine at the core

Both harnesses put the **Kuna decompiler** (Noelo-Lab/kuna, Apache-2.0) at the
center, but integrate it the opposite way. REA starts a caller-supplied
`kuna` **executable** as a subprocess, one per whole-image run; the results
arrive as JSON that REA's adapter streams and validates
(kuna-provider.md:52–91). calxgloss embeds Kuna as a **Rust library
in-process** (crate `calxgloss-kuna`): `KunaSource` holds a `!Send`
`ConsoleProgram` on the analysis engine's thread, loads the target PE
directly, and implements the `ScanSource`/`TypeWriteSource` seam, so nothing
above the seam knows which analysis engine answered (ADR-0039/0040).
ADR-0041 then deleted the Ghidra bridge entirely, leaving Kuna as the only
analysis engine and keeping the seam. The irony: REA's Kuna provider *rejects
PE targets* (kuna-provider.md:35). calxgloss runs embedded Kuna on exactly
that format; inside REA, PE pseudocode has to go through the Ghidra provider.

Provider choice vs one analysis engine: REA keeps five deep providers behind
one tool surface and reports per-tool availability at session level.
calxgloss collapsed to one analysis engine (ADR-0041's "no engine choice
remains"). REA's session reports what each tool can answer right now,
reasons included (native-and-artifacts.md:254–267) — calxgloss has no
equivalent surface.

### Cache comparison

Both projects built a read cache keyed on sha256, with different
invalidation philosophies:

- **REA, Kuna export cache**: key = target SHA-256 × *engine executable*
  SHA-256 × version × `--jobs`. REA puts the external engine's identity in
  the key because that engine changes outside REA (kuna-provider.md:54). LRU
  eviction, rename-publish, and a staging/trash lifecycle gated on *proven
  process stop* (kuna-provider.md:119–128). Separate from that, REA's
  snapshot files cache exact query results keyed on
  bytes+operation+provider+settings and exclude mutations (cli.md:280–317).
- **calxgloss scan read cache** (`re/cache/<binary>/<sha256>/`, ADR-0042/0043):
  keyed on binary bytes + program name + `CACHE_FORMAT_VERSION`. The analysis
  engine's identity comes along with the harness build, because the analysis
  engine is compiled into the harness. So a format version marker, not an
  analysis engine digest, forces cold reads; a cache-format rename silently
  resets the cache, with no migration.

REA's key is stronger against engine drift. calxgloss's cache is simpler
because its analysis engine and cache are shipped together — and calxgloss
has no REA-style query snapshot that stores an agent's question for replay.

### calxgloss-only

- **Batch whole-binary evidence engines**: 11+ scans (types, callgraph,
  memory, sync, callbacks, serialization…) run over the whole program before
  any function is translated. REA has no batch evidence layer — its queries
  answer one question at a time.
- **Type write-back into the loaded program**: `TypeWriteSource` commits
  discovered types into the loaded program through the seam (ADR-0020/0021),
  so later reads see better state. REA's engine edits (names/comments) are
  ephemeral, limited to the session, and never persisted — and Kuna offers no
  annotations at all (kuna-provider.md:50).
- **Automatic pipeline + verification loop**: a prompt → the LLM translates →
  the generated Rust is compiled and tested against FFI baselines captured
  from the real DLL, with retries and review-UI decisions. REA offers
  `verify_reconstruction`/compare tools but no closed compile-and-test loop.

### REA-only

- **Multi-provider choice** with discovery, doctor, and capability
  advertising (cli.md:226–272); calxgloss has one analysis engine and no
  alternative behind its seam.
- **Interactive navigation and annotations**: cursor state, bookmarks,
  comments, and renames written into the live database (see the session model
  above) — absent in calxgloss.
- **Arbitrary-address queries**: instruction-level inspection, `read_bytes`,
  load-image mapping, file-offset selectors, masked byte search — calxgloss's
  baseline explicitly has "no arbitrary per-address queries."
- **Call-path primitives on demand**: `get_call_graph`, `build_call_path`,
  `trace_call_path`, `trace_native_values` def-use across calls; calxgloss
  builds call graphs with its batch scans but can't trace one path on demand.
- **Architecture and format breadth**: ELF/Mach-O/PE/COFF, DOS, raw 6502/m68k,
  MIPS/PPC/RISC-V/PSP, NativeAOT, plus debugger/artifact lanes.

### Verdict

For calxgloss's job — deterministic, unattended, whole-binary PE→Rust
translation with evidence, write-back, and equivalence testing — calxgloss is
far stronger; REA would never produce its output automatically. For an
analyst's or agent's *question-driven* work on any native format, and for the
engine-agnostic surface itself, REA is the better harness: it answers
arbitrary questions, keeps honest boundaries about what each answer means,
and can swap engines. What calxgloss could steal, concretely: (1)
**masked byte search** at the seam — a `search_bytes(pattern, mask)`
primitive would give the `calxgloss-consts`/`serialize` magic-number scans
real byte matches to work with, instead of guesses; (2) **provider-seam
revival as capability advertising** — ADR-0041 kept the seam; a
session-style capability report would tell prompts and fault monitors which
facts the analysis engine can actually answer (unknown ≠ false);
(3) **analysis-engine identity in the cache key** — include the Kuna crate
version (or build hash) in the scan read cache key à la kuna-provider.md:54,
instead of relying on a hand-bumped format version; (4) **a call-path and
def-use primitive** over the kept bodies, so retry strategies (`escalate`)
can ask "how does this value reach this call" without running a new scan;
(5) the case study's measurement discipline — benchmark the whole pipeline
task, not the warm-path micro-operation, and beware that transport volume
(tokens) can dominate everything else.

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

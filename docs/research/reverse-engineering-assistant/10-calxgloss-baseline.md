# calxgloss Capability Baseline

**What calxgloss is.** calxgloss is a standalone, offline, deterministic PE
(x86-32 / x86-64) semantic translator. It builds a whole-program semantic graph
— functions, globals, call graph, verified signatures, enums, structs,
field-level dataflow — out of a Windows binary, renders it as a human-readable,
hyperlinked HTML report, and commits that report to a git-managed wiki. The
unit of output is a *verified claim*, not text: every function ends with a
`VerificationResult` (compiled y/n, baseline tests passed/total, API-call-trace
assessed/total, failed-test details —
`crates/shared/calxgloss-types/src/verification.rs:76-108`), confidence,
deterministic evidence, and a machine-readable record tree that later passes
read instead of re-deriving; the human review queue then tracks each unit via
`ReviewStatus` (Queued → PendingReview → Accepted/SendBack/… —
`crates/shared/calxgloss-types/src/dashboard/types.rs:135-152`).
There is no chat, no agent loop, no interactive
session — the user runs commands, reads reports, and the program decides its
own retry policy.

## Core principles (README.md:11-19)
Deterministic (same binary + version + seed ⇒ byte-identical artifact),
verifiable (evidence for every claim), honest (explicit unknowns, degradations,
corrections), offline (no network), correct-by-construction (strict types,
schemas, validation at trust boundaries). It is **not** an IDE, MCP server, or
assistant.

## Architecture (docs/Calxgloss.md:24-39)
Rust workspace (edition 2024, `Cargo.toml:5`), **34 member crates** under `crates/`
in five layers (`pipeline` → `evidence` → `integrations` → `interface` →
`shared`; the read-side analysis crates live under `crates/evidence/`, not
top-level, and `crates/calxgloss` is the binary meta-crate), **475 `.rs`
files, ~279k LOC**, plus **29 `.j2` prompt templates** — 11 top-level and 18
`sections/*.j2`, all under `crates/integrations/calxgloss-prompts/templates/`
(no root `templates/`). Pipeline stages:
entry points → type inference (call graph, signatures, enums, structs,
field-level flow) → semantic enrichment → verify → render → commit.
`calxgloss-verify` is a hard gate: unconfirmed functions are still rendered,
but clearly marked and excluded from the summary (README.md:58-63).
Web layer is axum, HTTP/REST-first; the shipped UI is static HTML/JS/CSS
under `crates/interface/calxgloss-web/static/` (the "React SPA" in
README.md:30 and docs/Calxgloss.md:31 is stale — no `package.json` or JS
toolchain in the repo).

## What it does (verified against the tree, 2026-10-31)

### Pipeline & verification
- **15 registered evidence scans** in
  `crates/pipeline/calxgloss-translator/src/scan_registry.rs` (rows
  `:82-565`, 15 rows in `scan_rows()` at `:606`), parallelized
  with a **fan-out cap of 4** (`src/pipeline/scan_phase.rs:33`); README.md:38's
  "13" is stale. Three more reader crates — `calxgloss-analysis`,
  `calxgloss-callgraph`, `calxgloss-bdiff` — run their own SLEIGH scans outside
  the scan-record registry.
- **5 context tiers** (`crates/shared/calxgloss-types/src/context_tier.rs:59-84`);
  **`RetryStrategy{Default, CompileFix, TestFix, Escalate, EdgeCaseFix}`**
  (`crates/shared/calxgloss-types/src/retry_strategy.rs:31-42`) — the auto
  cycle `CompileFix→TestFix→Escalate→EdgeCaseFix`
  (`src/retry/config.rs:43-46`, `max_attempts: 3` default), escalating
  with an attempt seam (`src/retry/attempt.rs:63-145`) that snapshots the
  scratch model before enrichment and skips enrichment on a confident baseline
  (ADR-0055).
- **Deterministic evidence** — content hashes, not LLM traces; **6 unknown
  kinds** (`crates/shared/calxgloss-types/src/unknowns.rs:25-67`); corrections
  are versioned and auditable (v3 format, `src/corrections_store.rs:58`).
- **Record tree**: `pipeline-record.json`, `scan-records.json`,
  `attempt-records.json` written as scratch finalizes
  (`crates/pipeline/calxgloss-model/src/json_store.rs:408-417`), archived on
  publish to `output/<exe_stem>/.calxgloss/pipeline-history/`
  (`crates/interface/calxgloss-cli/src/commands/publish.rs:153-157`).

### Decompile & evidence sources
- Disasm/decomp via Kuna pinned at git **`v1.984`**
  (`crates/integrations/calxgloss-kuna/build.rs:9`), vendored at commit,
  SLEIGH specs `sleigh/processors/x86/data/` — **x86 family only**
  (32/64 confirmed by tests).
- The translator's read-only view of Ghidra-family sources (`decomp`,
  `decomp-xml`, `ghidra`, `ida`, `binexport`, `json`) is **modeled but not
  wired**: `crates/integrations/calxgloss-decomp/src/scan_source.rs:7-14`
  (16 read families, 5 source groups); **18 evidence crates** in
  `crates/evidence/` ship without an external engine.
- Decomp cache: `output/<exe_stem>/.calxgloss/decompile-cache/`, content- and
  config-keyed, **format v4** (`crates/integrations/calxgloss-decomp/src/cache.rs:48`).

### Windows specifics
- `calxgloss-testgen` builds Wine PE baselines — native x86-64 harness with
  12-arg trampolines (`calxgloss-testgen/src/wine/harness.rs`) or WOW64 mode
  (ADR-0018); ADR-0053 captures return values (scalar + float/SIMD) into
  caller-visible scratch. `calxgloss-verify` runs the target's `DllMain`
  first; unresolved imports get **IAT interposer stubs**
  (`calxgloss-verify/src/stubs.rs:20-144`), **x86-64 only**.
- ADR-0057 parked P22 (dynamic-trace enrichment, API-trace gate): interposer
  logging works; the capture gate fails for a real DLL at `DllMain` reentry —
  the trace path is not used in any pipeline run.
- Managed PE: recognized, **classified and parked** — "Managed PE
  unsupported" unknown, **never routed to native verify**
  (`crates/pipeline/calxgloss-analysis/src/classify.rs:366-406`).

### Wiki, output, CLI
- `calxgloss-git` clones a wiki repo (branch `calxgloss/<exe-stem>`),
  materializes records, renders templates into `wiki/<exe-stem>/`, commits and
  pushes; `dependency.rs` renders the **Dependency Health Dashboard** (ADR-0019).
- Two axum routers: primary at `127.0.0.1:865`, static+SPA-fallback+WS at
  `1060` (`calxgloss-web/src/server/mod.rs:14,17,101-125`); `/api` surface
  covers wiki, pipeline, testgen, decomp, types, DLL, corrections, chat
  history (no LLM chat). **29 CLI subcommands**
  (`crates/interface/calxgloss-cli/src/cli_types.rs:197-519`), no `--json` mode.

### Gaps & open tracks (docs/roadmap.md)
Open: P23, P24, P26-P33, P40-P52 (P41 in progress — the `testgen` split).
Parked: P22, ADR-0044 managed PE. Tests: ~4.7k test fns (3,712 `#[test]`,
980 `#[tokio::test]`), 51 integration-test files under
`tests/integration_tests/`. **No `.github/` anywhere — no CI**; `just test`
is the harness. **57 ADRs** (`docs/adr/`, 0001-0057), none crate-scoped.

## Hard boundaries (what calxgloss never does)
- **No interactive reverse-engineering session** — no debugger, breakpoint,
  live inspection, or rename write-back (static `crates/` has no
  frida/gdb/ptrace code; `ida-pro-mcp` only in user-local scratch outside the
  tree). The P22 dynamic line is parked (ADR-0057).
- **No MCP server, no JSON-RPC tool surface, no agent tool-use loop** — zero
  MCP code/deps anywhere.
- **No generic binary format support** — PE only; ELF/Mach-O would be new
  top-level tracks.
- **No cross-architecture decompilation** — Kuna SLEIGH ships x86 only; the
  Wine verify harness is x86-64-native/WOW64 with x86-64 interposers.
- **No interactive UI editing of program state** — web actions trigger
  pipeline runs or serve data; the decompiler is never steered.

## How to compare ReVa against this
Hold the axes the folder's `00-scope-and-method.md` fixes — interactivity,
verification authority, determinism — and ask, for each ReVa capability:
*session-attached or artifact-producing?* (calxgloss is the latter);
*what makes a claim true here — a verdict or a human answer?* (calxgloss
requires evidence-bound verdicts; anything ReVa calls "ground truth" from a
live Ghidra query is a different authority kind);
*what is the format/ISA floor?* (PE + x86 vs ReVa's broader loader surface).
Record as gap: any capability needing a live session, user-chosen address, or
immediate UI mutation has no calxgloss equivalent without a new input surface
(batch scripts / structured specs) plus deterministic replay — and note ReVa's
own unverified LLM layer (its `decompilation_analyzer.py`) has no calxgloss
analogue: nothing here emits prose it cannot re-derive.

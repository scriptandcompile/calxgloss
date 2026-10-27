# calxgloss capability baseline — the comparison anchor

> Part of the [REA overview](README.md). This is the fixed baseline every domain
> file compares REA against. Facts come from `README.md`, `docs/Calxgloss.md`
> (design doc, 1390 lines), `docs/data_flow.md` (856 lines, `live` workflow),
> ADR titles in `docs/adr/`, and the crate inventory in `crates/`.

## What calxgloss is

A **Rust workspace** (414 indexed files) that reverse engineers a *directory of
Windows binaries* (`target_dir`: EXEs and DLLs, read-only) into a **cross-platform
Rust workspace** with identical observable behavior. It is a fully automated
**pipeline + review harness**, not an interactive tool: an LLM does the
decompilation work, evidence engines supply the structured evidence,
verification proves equivalence, and a human reviews each unit of work in a web
UI.

Core principles (README "Core Principles"):

1. **Functional equivalence over binary precision** — behavior, not instruction sequences.
2. **Cross-platform by default** — Windows APIs map to Rust equivalents via a PAL.
3. **Test-driven decompilation** — baseline tests capture original behavior; Rust must pass them.
4. **Incremental restitching** — swap in Rust implementations one function at a time.
5. **LLM-first, discard-when-wrong** — the local LLM does the primary translation
   work; discarding bad output is cheap.
6. **Source-control backed reversibility** — every unit of work is a commit on that function's attempt branch.
7. **Human-in-the-loop review** — web UI reviews every unit, its justification, and its dependencies.

## The pipeline (`calxgloss-translator`)

`live` = the foreground classify + translate loop, with the review UI running
alongside it. Per-function pipeline (README architecture block,
`docs/data_flow.md` §3.2.2):

```
read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit
```

- **Batch warmup** runs the 11 evidence scans over the whole binary before any
  translation starts; its results go into every function's prompt.
- **5 context tiers** (`calxgloss-prompts`, askama templates) — when a function
  fails at a lower tier, the pipeline sends the next attempt a larger context
  tier.
- **Retries driven by the failure**, with named retry strategies
  (`docs/data_flow.md` §8): `compile_fix`, `test_fix`, `escalate`,
  `edge_case_fix`, `auto` (cycles through the others).
- **Fault monitors** (`calxgloss-llm`) watch the local LLM servers
  (Ollama/vLLM) for hallucination, infinite loops, divergence, and exhaustion.

### Evidence engines (the "11 scans" + per-function passes)

One crate per analysis methodology. All of them read the loaded program
through the seam (`crates/evidence/`):

| Crate | Extracts |
|-------|----------|
| `calxgloss-analysis` | DLL classification (UI/rendering/game-logic/etc.), call graphs, API tagging; managed PE parked as do-not-translate (ADR-0044) |
| `calxgloss-callgraph` | root/leaf detection, translation ordering, context enrichment |
| `calxgloss-typesdb` | Type Manager scans, vtable detection, struct inference; RTTI linking (ADR-0009/0010) |
| `calxgloss-typeinfer` | this-pointer detection, parameter-size detection, type propagation callee→caller and caller→callee (ADR-0014/0015) |
| `calxgloss-algorithm` | control-flow signature matching, string-guided hints, callback patterns; claims resolved by strongest evidence (ADR-0022) |
| `calxgloss-memory` | alloc/free pairing, handle lifecycle, refcount detection, leak readings (ADR-0027–0031) |
| `calxgloss-sync` | mutex/lock pairs, atomics, lock-order graphs, data-race readings (ADR-0033/0034) |
| `calxgloss-consts` | bitflag groups, enum candidates, magic-number frequency |
| `calxgloss-callback` | function-pointer arrays, callback registration→call chains (ADR-0035/0036) |
| `calxgloss-controlflow` | switch-shaped if-else chains, self-recursion, state-variable chains |
| `calxgloss-stringctx` | nine-category string classification, per-function string maps, format-string inference |
| `calxgloss-apidetect` | import tables, library→crate mapping, per-function API summaries, divergence readings (ADR-0037) |
| `calxgloss-serialize` | byte-swap matching, bit-packing, magic-byte format sniffing (ADR-0038) |
| `calxgloss-libmatch` | known-library identification by body-signature matching of statically linked CRT/STL |

The evidence engines also **write their discovered types back** into the
loaded program, through the write side of the seam (ADR-0020/0021), so later
reads see the improved program state.

## The analysis engine's seam

- `calxgloss-decomp` defines the `ScanSource` (read) and `TypeWriteSource`
  (write-back) traits plus a **scan read cache**
  (`re/cache/<binary>/<sha256>/`, keyed on binary bytes + program name + cache
  format; ADR-0042/0043).
- `calxgloss-kuna` embeds the **Kuna analysis engine** in-process, loading the
  target PE directly (ADR-0039/0040/0041). Kuna is the only analysis engine.
  The old Ghidra MCP bridge was deleted (ADR-0041); ADR-0001 originally built
  that bridge, and the ADRs keep that history visible.

## Verification & restitching

- `calxgloss-testgen` generates FFI bindings + test inputs and runs the
  **original DLL** to capture baseline behavior.
- `calxgloss-verify` compiles the generated Rust crate and runs those tests.
- `calxgloss-pal` maps Windows APIs (Win32, GDI, DirectX) to cross-platform
  Rust (`tiny-skia`, `wgpu`, std) so output builds on Windows/macOS/Linux.
- `calxgloss-git`: one attempt branch per function; each commit records its
  justification; branches merge in dependency order; nothing is ever deleted
  (ADRs/`docs/Calxgloss.md` "Source-Control Backed Reversibility").

## Review UI (`calxgloss-web`)

An Axum + React SPA. Per unit of work it offers accept / send back / patch /
skip / override, enforces justification requirements, and shows dependency
visualization, the review queue, a dashboard, and live progress events. It also
carries pipeline controls: pause/resume/stop/start/cancel-current
(`docs/data_flow.md` §5, §7).

## CLI surface (`calxgloss-cli`)

`init · doctor · classify · translate · auto · batch-translate · serve ·
dashboard · verify · gc · typesdb · typeinfer · algorithm · memory · sync ·
consts · callback · controlflow · stringctx · apidetect · serialize · config ·
auto-shim` — every evidence engine has its own standalone command, so each
engine's evidence can be inspected by itself. Configuration resolves in order:
flags → env → TOML → defaults.

## What calxgloss is *not*

- Not interactive; no MCP surface; no arbitrary per-address queries.
- Not multi-format: PE32/PE32+ Windows targets only; managed PEs are detected
  and parked, not translated (ADR-0044).
- No runtime instrumentation: nothing attaches to a running program with Frida
  or a debugger. Baseline behavior comes from calling the original DLL through
  FFI in `testgen`.
- Output is *reconstructed Rust source*, an end product — not findings,
  pseudocode excerpts, or evidence reports.
- No version-comparison, capture, browser, or app-packaging workflows.

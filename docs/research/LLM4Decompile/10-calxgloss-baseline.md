# calxgloss capability baseline — the comparison anchor

> Part of the [LLM4Decompile overview](README.md). This is the fixed baseline
> every domain file compares LLM4Decompile against. Facts come from `README.md`,
> `docs/Calxgloss.md` (design doc, 1,387 lines), `docs/data_flow.md` (973
> lines, `live` workflow), `docs/roadmap.md` (507 lines), `CHANGELOG.md`, the
> 57 ADRs in `docs/adr/` (no crate-scoped ADRs exist), the per-context
> `GLOSSARY.md` files, and code spans verified in `crates/`. Verified against
> git HEAD `40fbf91f1815c1eb0207d05c3c2d7a58cb3bc7f0` (2026-10-31, "retire P22
> from the roadmap and record the trace-gate decisions as ADR-0057"). Where
> this differs from the [KRAKEN baseline](../kraken/10-calxgloss-baseline.md)
> (same repo, reviewed 2026-10-30), changes are marked *updated*.

## What calxgloss is

A **Rust workspace** — 34 member crates in six groups under `crates/` (root,
`shared/`, `integrations/`, `evidence/`, `pipeline/`, `interface/`), 475 `.rs`
files, ≈279k lines of Rust including in-crate tests — that reverse engineers a
*directory of Windows binaries* (`target_dir`: EXEs and DLLs, read-only) into
a **cross-platform Rust workspace** with identical observable behavior. Fully
automated **pipeline + review harness**, not an interactive tool: an LLM does
the decompilation work, 15 evidence engines supply structured evidence,
verification proves equivalence, a human reviews every unit in a web UI.
LLM4Decompile is the strongest published counter-ontology to calxgloss's core
bet: it teaches decompilation **into model weights** (fine-tuned 1.3B–22B code
LLMs, 15B-token and 2M-pair corpora, RL afterwards) and scores decompilation
**offline on benchmarks** (re-executability of standalone functions), where
calxgloss **refuses to train** and instead surrounds off-the-shelf local LLMs
with 15 evidence scans, compile + behavioral + trace gates, and per-unit human
review of whole binaries. The comparison is model-ontology vs
harness-ontology; the two meet at the same oracle — can it compile and run?

Core principles (`README.md:11-19`, quoted): 1. **"Functional equivalence over
binary precision — reproduce observable behavior, not instruction sequences"**;
2. **"Cross-platform by default — Windows APIs and libraries map to their
closest cross-platform Rust equivalents"**; 3. **"Test-driven decompilation —
tests capture original behavior; Rust code must pass those tests"**;
4. **"Incremental restitching — swap in Rust implementations one at a time, and
verify each swap"**; 5. **"LLM-first, discard-when-wrong … Throwing away
incorrect LLM output is cheap when the LLM is hosted locally."**;
6. **"Reversible through source control — every unit of work becomes a commit
on its function's attempt branch."**; 7. **"Human-in-the-loop review — a web UI
provides structured review of every unit of work, its justification, and its
dependency relationships"**

## Pipeline anatomy

A **unit of work** is one function or struct keyed `{binary}/{function}`, the
binary-side identity **verbatim** (`game_logic/DrawSprite`,
`game_logic/FUN_18003ab00`). **`live`** is the one foreground process running
pipeline + review server together. Per-function loop (`docs/data_flow.md`
§3.2.2, `README.md:37`):
`read cache ▸ evidence warmup ▸ fetch ▸ prompt ▸ translate ▸ verify ▸ retry ▸ commit`.

- **Queue order = call-graph topological dependency order, callees before
  callers (bottom-up).** `build_dependency_graph_from_call_graph →
  topological_order` is pinned C≺B≺A for A→B→C
  (`calxgloss-analysis/src/callgraph.rs:964-1032`); the queue never puts a
  dependent first (`calxgloss-web/.../handlers/queue.rs:450-491`); merges pass
  a callee-first gate (`calxgloss-git/src/dependency.rs:80-87`). The reviewer
  overlay edits same-depth ties only (ADR-0003).
- **Pre-batch scans**: `run_prebatch_scans`
  (`calxgloss-translator/src/pipeline/scan_phase.rs:273`) runs **15 scan rows**
  from the evidence-scan registry (`scan_registry.rs:606`; names at
  `crates/evidence/GLOSSARY.md:10`: type-database, type-inference,
  algorithm-recognition, memory-lifecycle, known-library, concurrency,
  global-state, constants, callback-detection, control-flow, string-context,
  library-api, serialization, error-handling, float-simd — 15 pinned by the
  CLI pairing test, `calxgloss-cli/src/commands/scan_command.rs:1407-1424`;
  `README.md:38`'s "13" is stale). Fan window capped at 4 (`scan_phase.rs:33`),
  `waits_for` latches, skip-rate breaker (ADR-0052); each scan stamps a
  **coverage record** (ADR-0053). Three engines have no scan row:
  classification, call graph, version pairing (`calxgloss-bdiff`).
- **Attempt seam** (ADR-0051): one attempt = prompt → LLM call → verification
  → record, in `run_attempt` (`retry/attempt.rs:229`). The loop keeps policy
  only; strategies `compile_fix · test_fix · escalate · edge_case_fix · auto`
  (`docs/data_flow.md` §8) are adapters at one door; the failing verdict routes
  into the next prompt; evidence is never re-gathered mid-retry.
- **5 context tiers** — `Signature → Disassembly → WithTests → ModuleContext →
  FullModule` (`calxgloss-types/src/context_tier.rs:59-84`); a seam-declared
  `unavailable` family prunes the ladder (ADR-0055), and each pruned/refused
  step now **files a named unknown record** (*updated*, ADR-0056;
  `translator/src/ladder_residue.rs`).
- **Fault monitors** (`calxgloss-llm`) end attempts on context overflow,
  hallucination, loops, divergence, exhaustion (`hallucination.rs` etc.),
  logged to `re/analysis/fault_log.json`.
- **Restitching** (principle 4) is a *design-phase* engine
  (`docs/Calxgloss.md:604-625`): today accepted merges land on `main` at
  `src/modules/{function}/translated.rs` (`git_manager.rs:955-957`); a
  fail-closed whole-binary verdict is open roadmap P26.

## Naming & typing

calxgloss **has no function-renaming feature, by doctrine**. What exists is a
layered stack producing *named, confidence-scored evidence* that feeds one
translate-and-verify loop:

1. **Identity is never rewritten.** The binary-side name (export name or
   Ghidra-dialect `FUN_xxx`) is verbatim in branch
   `re/{binary}/{function}v{N}` (`calxgloss-git/src/lib.rs:4-5`), the output
   path, the log join key `(dll, function, attempt)`, and the Wine locator,
   which parses `FUN_` names as RVAs and otherwise hits the export table
   (`calxgloss-testgen/src/wine/types.rs:335-347`). Rust identifiers are only
   *mechanically sanitized* (`calxgloss-verify/src/helpers.rs:9-26`).
2. **The seam's write side writes types, never names.** `TypeWriteSource` =
   "setting prototypes and variable types, creating the named types an inferred
   type refers to" (`calxgloss-decomp/src/lib.rs:13-14`); write-back narrows
   undefined slots in program order (ADR-0020/0021) and the read cache
   compile-time cannot call it. No rename write-back exists in any crate.
3. **Import names come free and typed.** PE import tables give real API names;
   `calxgloss-apidetect` extracts them with library→crate mapping
   (`lib_mapping.rs:212`); prompts render "WINDOWS API CALLS IDENTIFIED" and
   full PAL table rows as "API MAPPING REFERENCE" (`translate.j2:15-41`).
   `calxgloss-pal` is a **mapping database** — per-API trait, suggested crate,
   "[PAL placeholder]" notes (`data.rs:75-111`) — not a compiled dependency. A
   mini import-signature DB: `calxgloss-typeinfer/src/known_type.rs:195`
   (`memcpy` → byte-buffer/byte-count contracts).
4. **Static-library naming is evidence, never application.**
   `calxgloss-libmatch` matches *bodies* against a built-in CRT/STL symbol set
   (`memcpy`, `operator new`, `std::_Tree` idioms — pinned at
   `signature.rs:376-417`; symbol + family + regexes + suggestion each). A
   finding carries `BODY_MATCH_CONFIDENCE`
   (`calxgloss-libmatch/src/engine/tests.rs:507-527`) and
   rides into prompts as `LibmatchInfo` with a version-admission line
   ("match, version unknown", `calxgloss-prompts/src/templates.rs:315-336`,
   `sections/libmatch.j2`). It has no write-back path.
5. **Algorithm claims name behavior, not symbols.** A JSON pattern DB
   (control-flow signatures, string markers, callback contracts, correlations
   on the body-derived call map, ADR-0023/0024) files claims like "`FUN_x` is
   `crc` (checksum) at 90" with strongest-evidence resolution
   (`calxgloss-algorithm/src/engine.rs:365-371`,
   `calxgloss-algorithm/src/engine/tests.rs:1102-1138`); the prompt gains a
   "recognized algorithms" section.
6. **Mangling/RTTI/consts name the program's types and values.** MSVC symbols
   type a function "from its own name" (ADR-0018;
   `calxgloss-typeinfer/src/engine/tests.rs:1326-1362`); RTTI confirms vtables
   with class + method names (ADR-0009/0010); STL/MFC flagging by name shape
   (ADR-0012); type names render to sanitized Rust decls (`typesdb/
   src/rust_decls.rs:651-680`); constants get context names or mechanical
   `VALUE_0x…` forms (`consts/src/naming.rs`,
   `calxgloss-consts/src/types.rs:127-152,1243-1256`).
7. **The prompt is told to *keep* names, not invent them.** Every tier template
   demands "**Preserve the function signature** with FFI-compatible types"
   (`translate.j2:108`, `signature_translate.j2:27`); unknown callees become
   `extern "C"` stubs (`translate.j2:53-114`); inter-unit linking waits for
   the design-phase restitch engine. The minimal tier asks the model to *infer
   purpose* from name/params/return/neighbors (`signature_translate.j2:29-31`).

Bottom line: naming is embedded in the translate-and-verify loop, spread over
import tables, body-signature DBs, RTTI/mangling decoders, pattern DBs, and
the PAL DB — each confidence-scored with admission lines — and human rename
authority is deliberately excluded. The design doc's illustrative review
header `sub_00401234 (renamed: DrawSprite)` (`docs/Calxgloss.md:1216`) assumes
renaming *upstream in the analysis tool*, never implemented in the harness.
Roadmap **P51** (*new*) would score name/type suggestions by counting
independent agreeing evidence kinds, "model self-assessment ignored"
(`docs/roadmap.md:74`) — naming quality as an evidence-counting problem.

## Verification & evidence

- **Baseline capture** (`calxgloss-testgen`): PE tables → signatures, FFI
  bindings, inputs from signatures + type evidence + one branch-targeted case
  per branch in the control-flow scan's inventory; then **the original binary
  executes under Wine** — `WineRunner` builds a per-function harness,
  cross-compiles for the DLL's architecture, captures return values
  (`calxgloss-testgen/src/lib.rs:13-24`).
- *Updated* — **the API-call trace gate (P22) shipped** (ADR-0057; the HEAD
  commit retires the track). The Wine harness records, per case, the **ordered
  API-call sequence the original made** via import-address-table recording
  shims; the verify-side PAL **records what the restitched body executed**;
  the verdict judges **ordered containment, not sequence equality** —
  permuted/substituted routes fail, extra surface entries never fail
  (`CHANGELOG.md`; `calxgloss-verify/tests/api_trace_verdict.rs`). A
  value-matching, trace-divergent test **fails**, with both ordered traces +
  `trace_divergence_index` as typed data (`calxgloss-types/verification.rs`).
  Missing traces read **unassessed, never passing** (`trace_assessed_tests`).
- **What counts as proof**: sandboxed scratch Cargo project (`scratch/`,
  shared PAL stubs), `cargo check`, behavioral tests vs
  `re/baseline/*/baseline.json`, plus the trace dimension — all in a data-only
  `VerificationResult` traveling one shape to CLI, web, and records.
- **Honesty vocabulary**: absent coverage = *unknown, never absent* (ADR-0053);
  capability is live session state (ADR-0054/0055); admitted gaps are **named
  `UnknownRecord`s from a closed six-kind roster** — `coverage_facet`,
  `analysis_family`, `baseline_never_run`, `export_uncovered`, `retry_pruned`,
  `tier_refused` (`calxgloss-types/src/unknowns.rs:70-110`, ADR-0056, *new*) —
  surfaced as chips/`Unk` columns; resolve/dismiss/reopen are **API-only**
  routes (`/api/units/{id}/unknowns/{id}/…`).
- **Ground truth is one fixture**: a checked-in source-built x86-64 PE DLL
  (`calxgloss-testfixtures`) asserted by the engine harnesses. No corpus, no
  scored eval (P33 open), **no CI at all** — verified: no `.github/` anywhere
  (*new* P42 names the gap). No "binary done" conformance verdict (P26 open).

## Model layer

- **LLM seam**: `calxgloss-llm`'s `LlmClient` speaks OpenAI-compatible HTTP to
  locally hosted models — the crate doc names **Ollama, vLLM, llama.cpp**
  (`calxgloss-llm/src/lib.rs:1-4`; LLM4Decompile instead ships *its own*
  fine-tuned weights, loaded via HF `transformers` in demos and served by
  vLLM/TGI in its eval runners). Endpoint/model are pure config
  with **no defaults**; unset values fail loudly listing three ways to set
  them (`README.md:130-134`).
- **Prompts**: askama 0.16.1 templates as `.j2` files
  (`calxgloss-prompts/Cargo.toml:16`) — 11 top-level variants + 18 shared
  evidence `sections/*.j2`; the **evidence bundle** is the single render input,
  one include per engine (ADR-0048/0049); missing evidence drops sections — a
  prompt never fails — admission lines render beside what they qualify;
  `open_unknowns.j2` feeds open unknowns into retries.
- **Economics logged, not budgeted**: per-attempt tokens →
  `re/analysis/token_usage.json`, strategy → `prompt_strategy_log.json`
  (`translator/src/retry.rs:43,64`), raw I/O → `re/analysis/llm_io/log.jsonl`
  (web `/api/llm-io`, `/api/token-usage/*` by tier/strategy/binary); every
  attempt commit's justification block carries **LLM model + context size**
  (`calxgloss-git/src/lib.rs:17-30`). Cost metering/budgets are open P50.
- **Trust posture**: the local model does the primary translation work, bad
  output discarded (principle 5), trusted only after compile + behavioral +
  trace verification and human review. No semantic critique, self-consistency
  sampling, or second-model review exists. P45 (typed untrusted prompt data)
  and P43 (fail-closed sandbox) record those gaps honestly.

## Surface & state

- **CLI**: **29 subcommands** (`calxgloss-cli/src/cli_types.rs:197`):
  `init · doctor · classify · translate · batch-translate · typesdb ·
  typeinfer · algorithm · memory · libmatch · bdiff · sync · globalstate ·
  consts · callback · controlflow · stringctx · apidetect · serialize ·
  errhandling · floatsimd · config · verify · dashboard · auto · serve · live ·
  auto-shim · gc`; each scan command rides a registry row (ADR-0052).
  *Updated*: `dashboard` carries review-action subcommands `view · accept ·
  send-back · accept-all` (`cli_types.rs:1052-1142`) — CLI-side accept beside
  the web UI. Config resolves flag → env → TOML → default with per-value
  *Source*; `doctor` loads the target through Kuna in-process, exits non-zero
  for CI gating.
- **Web review UI** (`calxgloss-web`, Axum + React): two routers by design
  (ADR-0002) — `shared_routes()` (`server/mod.rs:865`) over persisted
  artifacts (unit detail/diff/attempts/decomp, accept · send-back · patch ·
  skip/unskip · override, batch actions, queue overlay, unknowns
  resolve/dismiss/reopen, LLM-I/O + fault/token/strategy analytics) and
  `live_only_routes()` (`server/mod.rs:1060`) for in-flight state (progress,
  WebSocket server→client only, pipeline pause/resume/stop/start/restart/
  cancel-current as a REST state machine, ADR-0004); views read-only over
  artifacts/overlays (ADR-0006).
- **Git attempt branches**: one per attempt, `re/{binary}/{function}v{N}`
  (`calxgloss-git/src/lib.rs:4-5`); success merges to `main` after the
  callee-first dependency gate; failure branches kept forever; unmerged ones
  renamed into an Archive by `gc`, never deleted (principle 6). **No edit
  log** — undo is discard/retry-a-branch.
- **Absent (re-verified 2026-10-31)**: no daemon (`live`/`serve` foreground);
  no MCP surface (zero `MCP` word matches in `crates/` outside the deleted
  GhidraMCP note, `calxgloss-decomp/src/lib.rs:5`); no plugin/ACP API, no
  embedded chat; **no OS sandbox** around verify/Wine — scratch-dir convention
  only (open P43); no eval harness (P33), no CI (P42); no `--json` CLI mode
  (P31/P52); no ad-hoc per-address queries — the seam answers only declared
  query families (ADR-0054/0055; ad-hoc call-path/def-use is open P29).
  PE32/PE32+ Windows only; managed PEs parked do-not-translate (ADR-0044);
  Kuna is the only analysis engine, fully in-process (ADR-0039/0040/0041).

## Current state & open gaps

Works end-to-end today: classify → 15-scan warmup → tiered prompt → attempt
loop with failure-informed retries → Wine-captured baselines + compile +
behavioral + API-trace verification → attempt branches + web/CLI review →
merged Rust on `main`, with token/strategy/fault/unknown telemetry. *Updated*
vs 2026-10-30: **P21 unknown records shipped** (ADR-0056) and **P22 trace
gate shipped** (ADR-0057) within the day before HEAD `40fbf91f`. Open roadmap
(`docs/roadmap.md:28-95`): **P23–P33** (mined inputs, EXE scenario capture,
verification receipts, fail-closed restitch conformance, hypothesis ledger,
masked byte search, ad-hoc call-path/def-use, PE artifact intelligence, deep
`doctor`, contributor skill, whole-task measurement); **P40** open
(`api_aware` never reaches a prompt, #365); **P41** in progress (translate-path
artifact landed #379, full `FunctionInfo` open); and the new **P42–P52**
KRAKEN block (CI substrate, fail-closed sandbox, baseline provenance +
live-oracle, typed untrusted prompt data, seam drift checks, per-function
staleness hashes, mechanical pre-refusal, counterexample ordering, cost as a
first-class number, **evidence-computed name/type confidence (P51)**,
discipline bundle with `--json`).

## Anchors for the LLM4Decompile comparison

- **Where decompilation knowledge lives**: LLM4Decompile bakes it into
  fine-tuned weights (up to 15B tokens, 2M curated pairs from 100M raw, RL on
  execution rewards); calxgloss keeps it in *readable, auditable artifacts* —
  15 scan rows, PAL DB, pattern DB, libmatch signatures, ADRs — with the model
  untouched. Compare *what you can inspect, correct, and version* when a
  translation is wrong: retrain vs re-scan/re-prompt/retry.
- **Verification**: both land on the same oracle — decompiled code must
  **compile and pass behavior tests** — and both reject n-gram/edit-similarity
  as primary signal (their `legacy-test/README.md` argues it explicitly). But
  LLM4Decompile runs the oracle only *offline, per benchmark function, on the
  authors' machine*; calxgloss runs it *in-product, per unit, every attempt*
  (Wine-captured baselines + compile + ordered API-trace containment,
  ADR-0057) and files honest unknowns when it can't. Same gate, opposite
  placement.
- **Evaluation substrate is their gift to calxgloss**: HumanEval-Decompile
  (164×4), ExeBench (2,621 real functions), DecompBench-Eval (70K),
  BringUpBench (505 whole-program functions) plus `cal_execute_rate.py` /
  `cal_edit_sim.py` harnesses are exactly the scored-eval substrate calxgloss
  *lacks entirely* (open P33/P42; one fixture DLL today). The steal direction
  here inverts every previous dossier.
- **Function-level vs whole-binary**: their unit is a standalone function
  recompiled with stubs/assertions against O0–O3 x86-64 GCC ELFs; calxgloss's
  unit is `{binary}/{function}` inside a call-graph-ordered queue for
  whole-binary restitch (Windows PE32/PE32+ under Wine). Benchmarks measure
  per-function re-executability; neither project today ships a whole-binary
  equivalence verdict — calxgloss roadmaps it (P26).
- **Naming doctrine collides head-on**: SK²Decompile's Phase 2 ("skin") is
  pure *identifier recovery* — the LLM invents names and they land verbatim
  in the output source. calxgloss deliberately never applies names (see
  *Naming & typing*; types-only write-back, ADR-0020/0021); named knowledge
  is scored, admission-stamped evidence fed to prompts, with P51 scoring
  suggestions by evidence counts. Same task, opposite trust model.
- **Ordering & context**: both agree structure recovery comes first —
  SK²'s skeleton→skin two-phase mirrors calxgloss's tier ladder and
  callees-first queue; V2's "refine Ghidra pseudo-code" is calxgloss's own
  Kuna-prompt path with a fine-tuner bolted on. Their context is a *single
  text blob* per function; calxgloss's is 15 whole-binary scans rendered as
  a tiered evidence bundle.
- **Retry loop, two homes**: LLM4Decompile trains the retry loop *into the
  weights* (VERL GRPO with exec+similarity rewards); calxgloss runs it at
  inference time (failure-informed retries over typed verdicts, fault
  monitors). GRPO's reward is compiled execution — the same signal calxgloss
  already records per attempt (`token_usage`, verdicts).
- **Model economics**: their "under $20 / 3.5 h on one A100" replication
  script (decompile-ghidra-100k) is the *training* counterpart of calxgloss's
  discard-when-wrong *inference* economics (principle 5); both claim cheap
  repetition, neither budgets (P50 open on our side).
- **State, review, honesty records**: LLM4Decompile is a stateless batch —
  no per-unit review UI, no attempt history, no unknown ledger; a benchmark
  score is the whole verdict. calxgloss has attempt branches, accept /
  send-back / patch, named `UnknownRecord`s, and refuses to call a binary
  done without a verdict (P26). Their absence is methodology (offline eval
  doesn't need it); it says nothing about in-the-loop safety.
- **Claims hygiene**: their README numbers (e.g. ">100% improvement", "40.1%
  more", IDA-Pro comparisons) are model-card scores on benchmarks they partly
  own; audit them in [32](32-evaluation-and-effectiveness.md) before citing.
  calxgloss publishes no scores at all — the honest-null alternative; P33
  would put us in the same measurable game.

## Sources

`README.md` (principles :11-19; stale "13 scans" :38; config :116-137) ·
`docs/Calxgloss.md` (:604-625 restitch, :1195-1240 review-doc example) ·
`docs/data_flow.md` (§3.2.2, §6 :675-777, §8 :853-886) · `docs/roadmap.md`
(status matrix :28-95) · `CHANGELOG.md` (P21/P22/P41 entries) · `docs/adr/`
0001-0057, esp. 0020/0021, 0039-41, 0048-49, 0051-57 · crate spans cited
inline across `translator`, `types`, `git`, `decomp`, `testgen`, `verify`,
`prompts`, `llm`, `libmatch`, `algorithm`, `typeinfer`, `typesdb`, `consts`,
`apidetect`, `pal`, `analysis`, `cli`, `web` · scale counts (34 crates / 475
`.rs` / ≈279k LOC) and every absence verified at HEAD `40fbf91f`.

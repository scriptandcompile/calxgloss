# OGhidra — Benchmark Package, Test Suite, and Effect

> Part of the [OGhidra overview](README.md)

This chapter covers in-scope item 5 of [00 — Scope and Method](00-scope-and-method.md):
"Is there a benchmark or corpus, and any published results? What is the test and CI
posture? Any evidence of real use?" It answers five questions: what the `benchmark/`
package actually measures, how its ground truth is built, which metrics it computes,
whether the runner still runs against the product at HEAD — and whether *anyone* has
ever published a score from it. It also folds in the test/CI survey, the model-size
posture, and the DSPy branch, because all four bear on the same question: **does this
project have any way of knowing whether its AI features work?**

## What OGhidra does

LLNL ships a package called "Benchmark & Evaluation Framework"
(`benchmark/README.md:1-7`): "Compare OGhidra AI-generated summaries and naming
decisions against ground truth from source code", with subcommands `extract`, `run`,
`evaluate`, `report`. The package is real code with real third-party metric
libraries — and three structural facts that decide how much it is worth:

1. The reference text it scores against is itself **LLM-generated** from the
   original source. There is no human-curated corpus anywhere.
2. **No run of it has ever been published** — by the maintainers or anyone else.
3. At HEAD the package **does not import**, and its LLM-judge metric could not have
   loaded even when it did: a renamed attribute sits behind a swallowed
   `AttributeError`.

Everything below is from the clone at `6224d26` unless stated otherwise; API facts
carry a "GitHub API, 2026-11-01" tag.

### 1. What the benchmark measures

The core comparison is one axis: **the AI summary built from decompiled code vs a
"ground truth" summary of the original source code**
(`benchmark/runners/benchmark_runner.py:1-13`: "Measure semantic similarity between
OGhidra output and ground truth").

**The entry point.** `benchmark/cli.py` wires four subcommands. `run` constructs a
real product `Bridge` — `Bridge(config, include_capabilities=True, enable_cag=False)`
at `benchmark/cli.py:96-99`, "Disable CAG for clean benchmark" — so the benchmark
drives the same client stack the GUI drives, minus the context layer. Addresses are
mapped from Ghidra if missing (`cli.py:108-111`), and `--llm-judge` is plumbed as a
flag (`cli.py:117`).

**The runner does not drive the agent.** `runners/oghidra_runner.py:1-10` says
"bypasses OGhidra MCP tools, directly uses Bridge's GhidraClient"; the header notes:
"OGhidra's 'agentic' behavior comes from **prompts** in interactive mode rather than
complex code logic. By using the same prompt format, we achieve identical
functionality with simpler code." Concretely, per function it:

- decompiles directly: `bridge.ghidra.decompile_function_by_address` (`:84`);
- pulls xrefs and decompiles the **first 3 callers and 3 callees**, each truncated
  to 1000 chars (`:139-141`, `:155-157`), whole-context cap 6000 chars (`:47`);
- builds one prompt (`_build_analysis_prompt`, `:182-214`: "Analyze the function
  ... provide a detailed summary", output schema `Function Analysis / Behavior
  Summary / **Suggested Name:** [descriptiveFunctionName] / Rationale`) and sends it
  as a **single-shot** `bridge.ollama.generate(prompt=...)` (`:104`).

That single shot is not the product path. In the product, rename/analysis work goes
through the plan→execute→review loop with LLM-chosen tools (ch. 32 §2–§6) and CAG
retrieval serving context (ch. 33 §1); this benchmark prompt was hand-built to
*mimic* the bulk enumeration prompts' output format ("matches OGhidra's
enumerate-binary format", `oghidra_runner.py:96`; the product's enumeration
machinery is ch. 34 §4). What is being scored is therefore "an offline one-shot
prompt that copies the shape of a product prompt" — the harness does not exercise
the loop that ch. 32 showed the product actually runs.

**What the combined score covers — the 00-chapter claim, nuance-corrected.**
[00 §2](00-scope-and-method.md) recorded the framework's self-description as scoring
"renames and summaries". Half true, in the direction that matters:

- The **combined score is summaries only**. `combined_score` in
  `metrics/evaluator.py:39-46` weights four text metrics; the name axis is excluded
  by design (`runners/benchmark_runner.py:321-325` computes `name_accuracy`
  separately; the stats block comment "Combined score stats" at `:308` covers text
  metrics only).
- The rename axis is **pure exact string equality**:
  `sum(1 for r in results if r.suggested_name == r.function_name)` at `:321`. One
  character of disagreement counts as a miss; `FUN_00400f80` renamed to
  `FUN_00400F80` scores zero. A "renames benchmark" built on string equality is the
  exact-match style calxgloss explicitly abandoned in favor of ordered trace
  containment ([10, "Verification & correctness"](10-calxgloss-baseline.md)) —
  OGhidra kept string equality *and* never ran it.

**Filters.** Functions without a `binary_address` are skipped, and `run` defaults to
requiring `llm_source_summary` (`benchmark_runner.py:156-165`) — with no reference
text, there is nothing to compare, which shows how central the LLM-generated
reference is (below).

### 2. Ground-truth machinery: the corpus is made of LLM prose

This is the chapter's load-bearing finding. The package's README presents "source
code ground truth" (`benchmark/README.md:1-7`); the code reveals a two-layer trick.

**Layer 1 — regex source harvesting.** `ground_truth/source_parser.py:8` states the
implementation choice plainly: "regex-based parsing for portability (no external
dependencies like libclang)". The regexes (`:31-56`) match function definitions at
line starts; keyword lists (`:59-85`) drive a heuristic complexity score (`:231-256`:
control-flow keywords ×5 each, capped at 100) and free-text tags (`:258-286`:
`file_io`, `memory_management`, `network`, `crypto`...). So "ground truth from
source code" means structural facts — signature, params, return type, source text,
docstring if any — extracted by regex from checked-out C/C++ trees (`**/*.c,*.cpp,
*.cc,*.h,*.hpp`; `ground_truth/extractor.py:165,179`).

**Layer 2 — the reference summary is generated.** The text the metrics actually
compare against is produced by `SummaryGenerator.generate_summary`
(`ground_truth/summary_generator.py:82-127`, called from `extractor.py:206`): hand-written
`SOURCE_SUMMARY_PROMPT` (`:19-48`) — "You are analyzing source code to create a
**ground truth summary for benchmarking**", temperature 0.3, source capped at
4000 chars (`__init__`, `:59-81`) — sent to
the configured local model. The dataclass field is honestly named
`llm_source_summary` (`extractor.py:43`), but the metrics' own field
`reference_summary` (`metrics/evaluator.py:34`) elides that those
"reference summaries" are a model's paraphrase of source. The measured quantity is
**agreement between two LLM outputs** — one summarizing the C source, one
summarizing the decompiled pseudocode — with nothing human in the loop. (ch. 34 §6
showed the product's security report is seven LLM calls over harvested prose, "a
self-report with invented timestamps"; the benchmark launders LLM text the same way,
now on the measuring side.)

**Address mapping.** `extractor.py:231-267` calls `list_functions()` and splits each
line on `" at "`, matching the **exact** name. The Java plugin formats
`"%s at %s"` (`GhidraMCPPlugin.java:931-943`) with a default limit of 100
(`:262-266`) — the extractor never paginates, so at most the first 100 functions map.
The docstring warns binaries must "contain debug symbols (not stripped)"
(`:238-240`). Exact-name matching against a 100-function page: the pipeline assumes
small targets and unmangled names, and fails silently otherwise.

**No corpus exists.** There are no sample binaries, no checked-in datasets, no JSON
fixtures anywhere in the repo (`find` over the clone: the only JSONs are
`src/cag/knowledge/*.json`); the CLI requires the user to supply `--source` and
`--binary`. Worse, `benchmark/__init__.py:19-22` documents a usage example against
"benchmark/corpora/test_corpus", **a directory that does not exist**, and its
docstring names a `SemanticBenchmark` class that does not exist either (the real
classes are `BenchmarkRunner` and `SemanticEvaluator`). The package documents
itself running against a fictional fixture.

### 3. Metrics and scoring

The metric layer is the most substantial part of the package — real libraries,
sensibly implemented, lazy-imported (`metrics/evaluator.py:130-153`).

| Metric | Library | Note |
|---|---|---|
| ROUGE-L F | `rouge-score` | lexical; the only legacy-style one |
| BERTScore F1 | `bert-score` | `roberta-large` |
| SBERT cosine | `sentence-transformers` | `all-MiniLM-L6-v2` |
| LLM-as-Judge | Ollama | 1-5 rubric, JSON out |

Dependencies are **not declared**: `pyproject.toml` and the root requirements carry
none of them; `benchmark/README.md:12` tells users to `pip install bert-score
sentence-transformers rouge-score matplotlib`. Run `report` without them and the
matplotlib `ImportError` is swallowed with a print (`cli.py:247-250`) — the report
subcommand can quietly do nothing.

**Combined score weights** (`evaluator.py:41-46`): BERTScore 0.35, SBERT 0.35,
ROUGE-L 0.15, LLM-judge 0.15, with weights renormalized over whichever metrics
actually loaded (`:48-58`). Text similarity therefore dominates (0.85 of the weight)
even when a judge is configured.

**The judge rubric** (`metrics/llm_judge.py:21-68`) is the best-written artifact in
the package: "You are an expert evaluator assessing the quality of a function
summary generated from **decompiled binary code**", four criteria
(`semantic_accuracy`, `completeness`, `technical_precision`, `clarity`) plus overall,
each 1-5 with explicit anchors, strict JSON out. Two honest flaws: missing keys
default to 3 (`:165-171`), and total parse failure returns all-3s
(`:186-196`) — a failed judgment fabricates a fake 0.6, the same fabricated-
completion disease as the report chapter's invented timestamps (ch. 34 §6).

**The verified bug: the judge can never load.** `SemanticEvaluator.__init__` stores
the client as `self._llm_embedding_client` (`evaluator.py:120`); the lazy init gates
on that attribute (`:155`) but then constructs
`LLMJudgeMetric(ollama_client=self._ollama_client)` (`:159`) — an attribute that
**does not exist**. The `AttributeError` is swallowed by the `except Exception`
defensive handler (`:162`) and logged as "LLM-as-Judge not available". The runner
does pass a real client — `llm_client=bridge.ollama` (`benchmark_runner.py:142-145`)
— so this never worked through `SemanticEvaluator`. `git blame` puts the rename in
`79d118d` (the cherry-pick of PR #18, June 2026, "add embedding client param and
fallback"). So whenever the benchmark could run at all, the judge was silently
absent and the combined score was the three text metrics reweighted.

**Reports** exist (`reports/generator.py`, `visualizer.py`): JSON statistics (means,
stds — `benchmark_runner.py:87`), Markdown tables, matplotlib PNGs, a sample-analysis
section. All machinery; zero outputs (below). (This `reports/` is a separate thing
from the GUI's LLM-written security report — ch. 34 §6 — same word, different code.)

### 4. Harness decay: the runner cannot run against main at HEAD

Two independent breakages, both verified in this session — first-hand observation
marked as such.

**The package no longer imports.** On this machine's Python 3.12.3 (the project
requires ≥3.12, `pyproject.toml:6`), `import benchmark` crashes:
`TypeError: unsupported operand type(s) for |: 'builtin_function_or_method' and
'NoneType'` — three annotation sites annotate with the **lowercase builtin**
`callable`, which is not a type and cannot take `| None`:
`ground_truth/summary_generator.py:149`, `runners/benchmark_runner.py:153`,
`runners/oghidra_runner.py:238`. `git log -S` puts the regression in `9078cd9`
("Fix/precommit followup (#61)", 2026-10-22), which mangled a working
`Optional[callable]` into `callable | None`. `python -m py_compile` still passes —
the syntax is legal; the evaluation is not — which is exactly what no-import-smoke-test
CI lets through.

**After fixing it, the product APIs still line up** — for now. `cli.py` calls
`select_ghidra_client_class` (`src/bridge.py:65`), the Bridge stores
`self.ghidra_client` (`:128`) and exposes a `@property def ghidra` alias
(`:5366-5368`); `decompile_function[_by_address]` and `list_functions` exist on both
client classes (`src/ghidra_client.py:762` HTTP, `:1322` PyGhidra); `bridge.ollama`
is real. So the breakage is self-inflicted annotation rot, not product drift — but
with no tests and no CI (§6), each such regression is caught by nobody, and the
benchmark has now sat broken for longer than it ever demonstrably worked.

**Verdict on viability:** decaying, not live. One `sed` fixes the three annotations
for today's HEAD; nothing guarantees the next `9078cd9`-style commit doesn't break it
again tomorrow.

### 5. Results: none, anywhere

The strongest negative finding of the chapter, established by exhaustive search:

- **No checked-in reports.** `git log --all --diff-filter=A` filtered for benchmark
  artifacts (results/reports/ground-truth JSON, scores, CSV/PNG under benchmark or
  reports paths): **empty**. Nothing has ever been committed.
- **No claims anywhere visible.** grep of main's README for "benchmark / eval /
  score" hits **zero mentions** — the README never even mentions the benchmark
  exists. No scores in the README, no benchmark run results in any issue, no
  published run by anyone found by GitHub search.
- **Maintenance history is itself the evidence.** The benchmark was contributed by
  an external contributor (PRs #4/#3, merged 2026-01-21 as `8150f0d`); the first
  fix to it was an import-error fix in PR #17, **three and a half months later**;
  and issue #16 (open, Eriken79) *requests a benchmark* — "How does analysis with
  OGhidra compare to analysis without?" — **unanswered by the maintainers as of
  2026-11-01** (GitHub API: `search/issues?q=repo:LLNL/OGhidra+benchmark` hits
  #16, #17, #4, #3, #22). A project whose users have to ask for a benchmark, whose
  benchmark sits broken, and whose docs never mention it, is a project that does not
  measure its effect.
- **Effect evidence, to the extent it exists:** the YouTube walkthrough
  (`README.md:13`, `:79`) is the only end-to-end demonstration; three screenshots
  exist (`images/design.png` 1298×916, `images/function-summaries.png` 1920×1026,
  `images/renaming-ui.png` 1920×1028, all PNG RGBA — described from `file` output,
  not from seeing them; added in `87dfa21`, 2025-12-22, ezrealenoch) and they are
  **referenced by no markdown file in the repo**. Popularity proxies: 465 stars,
  50 forks, 3 subscribers, `has_discussions: false` (GitHub API, 2026-11-01).

So the honest summary of §5: **no quantitative result — a score, a percentage, a
before/after count — exists in this repository or on its GitHub footprint, for the
benchmark, for the model choices, or for the analysis claims.**

### 6. Test suite: substantial volume, none of it guarding the benchmark or CI

The repo carries 22 test files, 4,023 lines (`tests/`) — but the composition
matters:

- **Style:** unittest-style, 134 `def test_` definitions, zero pytest imports — and
  **no pytest configuration on main**. The suite as committed is not runnable by
  `pytest tests/` out of the box.
- **Split:** mocked unit tests (`test_bridge.py`, `test_api_health.py`,
  `test_session_compactor.py`, `test_coverage_tracker.py`, `test_execution_gate.py`,
  `test_security_hardening_regressions.py`, `verify_prompts*`) **and** scripts that
  require a live Ghidra with an open binary — `test_tool_calls.py` *generates*
  `tool_capabilities.md`, and `test_scan_function_pointer_tables.py` states "This
  script must be run with the GhidraMCP plugin loaded... function tables are expected
  to exist in the open binary." `tests/README.md:3-7` is explicit: "No Mock Support
  for Ghidra: all calls directed to live Ghidra server."
- **Coverage gaps:** zero tests for `benchmark/`, and the CAG layer has none either —
  the two AI-facing subsystems whose behavior ch. 33 and this chapter probe are
  exactly the untested ones.
- **CI: none for tests.** The only workflow is `release.yml` (build + PyPI + GitHub
  Release). PR #50's test-workflow was closed unmerged (ch. 21 §6; GitHub API,
  2026-11-01). The 134 tests protect nothing automatically.

One-line summary of this section: the test suite is **substantial but largely
Ghidra-coupled and CI-less, with zero coverage of benchmark and CAG**.

### 7. Model posture: RAM figures, no measured quality

The README recommends models by RAM, not by measured quality
(`README.md:157-163`): `gemma3:27b` — "Good balance (20GB RAM)";
`nomic-embed-text` for RAG; `gpt-oss:120b` and `devstral-2:123b` — "High quality
(80GB RAM)". Troubleshooting advice is to go *smaller* under load
(`:500-506`: "Use smaller models: Switch to `gemma3:9b`"). Budgets default via
`.env.example`: `CONTEXT_BUDGET=100000` (`:130`, chars, chars≈tokens×4 per `:114`),
`MAX_EXECUTION_STEPS=5` (`:103`), `MAX_AGENTIC_CYCLES=2` (`:105`),
`COMPACTION_THRESHOLD=0.75`. The `model_map` per-phase override (ch. 32 §2) lets
users assign different models to planning/execution/analysis
(`src/config.py:244-255`, `:1175`/`:1231`/`:1307`, resolution `:1585-1588`).

None of these choices is backed by a published number. "Good balance" and "High
quality" are assertions; the benchmark that could have tested them is the one that
doesn't import. (Inferred, not verified: that README model advice looks like
developer experience — the phrasing is RAM-first throughout.)

### 8. The DSPy branch: deletes the benchmark, ships the real eval idea elsewhere

[21 — history and releases](21-history-and-releases.md) sketches this branch in its
branch map (§6); the benchmark-relevant facts, verified directly on the branch: it
**deletes `benchmark/` entirely** (tip
`9b466f3`; merge-base diff 149 files, +2,439/−49,432; 128 D) and replaces it with
`src/oghidra_workflows/` — an MCP-stdio rename pipeline with DSPy signatures
(`GatherEvidence`, ReAct over tools; `AnalyzeFunction` emitting a structured
`Proposal`) and a five-stage state machine "capture, investigate, propose, apply,
verify" where **verify** is a read-back of the renamed function in the GUI
(`verification_failed` status). Note what is *not* on the branch: no
`dspy.Evaluate`, no metric, no optimizer (grep empty) — "DSPy" here means
typed signatures, not evaluation.

What the branch *does* add is the thing main never had: a hermetic pytest suite
against a fake Ghidra server (`tests/fake_ghidra.py`, 82 LOC), a
`[project.optional-dependencies] test = [pytest, pytest-asyncio]` group, and
`[tool.pytest.ini_options] testpaths` — PR #63 (open **against the branch**, 9
commits, +1,897/−468, "Improve DSPy workflow setup, diagnostics, and
documentation"; GitHub API, 2026-11-01) carries that work. The branch that throws
away the benchmark is the branch that finally grows runnable tests. (The
orchestrator-branch delta is the not-yet-written
[36 — orchestrator branch](36-orchestrator-branch.md)'s subject; this chapter only
points.)

## Comparison with calxgloss

### Overlap — what both projects have

- **Deterministic, non-model gates bounding the pipeline.** Both projects grew
  above-the-loop control: calxgloss gates patches on the compile/trace verdict
  (ADR-0057); OGhidra has an execution gate and loop brakes (ch. 32 §9 — "triggers
  that fire, brakes that don't"). Same instinct, very different closure.
- **A rename-acceptance concept.** OGhidra's benchmark has a suggested-name axis;
  calxgloss has `re/accepts|rejections|patches` review decisions
  ([10, "Data model & persistence"](10-calxgloss-baseline.md)).
- **LLM-summarized context of the target.** Both summarize before deciding:
  OGhidra's cached function summaries — harvested panel prose into a vector store
  with `RESULT_CACHE_ENABLED` skip logic (ch. 33 §4–§5); calxgloss's digest/claims
  substrate (ADR-0001/0005 family).
- **A single-fixture view of evaluation.** Neither ships a multi-binary corpus;
  calxgloss has one fixture DLL, OGhidra tells users to bring their own.

### What calxgloss has that OGhidra does not — the verification chain

calxgloss's answer to "did the fix work" is an **ordered containment verdict**:
compile, then replay Wine sessions against recorded baselines, then compare ordered
emission traces, with the data-only `VerificationResult` and `re/verdict.clj`
deciding by trace containment — never by model judgment (ADR-0057, [10,
"Verification & correctness"](10-calxgloss-baseline.md)).
OGhidra has no equivalent for its own output: the *product* never verifies an AI
rename or summary against the binary, and the *benchmark* verifies it only against
other LLM prose. Nowhere in OGhidra is there a check that touches execution or the
binary itself as the oracle.

A second difference is sharper: calxgloss has **no model-graded judgment anywhere in
its decision path** — no LLM-as-judge, no rubric — whereas OGhidra's benchmark
design gives 15% of its combined score to an LLM judge. calxgloss's judgment (the
human reviewer, and the trace comparator) sits outside the scored loop by
construction.

### What OGhidra has that calxgloss does not

- **A scored text-metric stack over embeddings.** BERTScore (roberta-large), SBERT
  cosine (all-MiniLM-L6-v2), ROUGE-L, with weighted combination and renormalization
  (`evaluator.py:41-58`) — exactly the kind of model-free-scoring-over-text machinery
  calxgloss lacks for rename/summary outputs (`re/accepts` counts are raw events).
- **LLM-as-judge rubric design.** The four-criteria 1-5 rubric
  (`llm_judge.py:21-68`) is the most careful evaluation prompt either project has
  written — as a *document*.
- **A user-facing benchmark CLI.** Four subcommands, report generators, matplotlib
  charts — an opinion that *evaluation belongs in the repo, runnable by users*. The
  intent is right even where the execution failed.
- **Live-state confirmation, at least in design (branch only).** The DSPy
  workflow's verify stage reads the applied rename back out of the running Ghidra
  program and can emit `verification_failed` — a receipt against *live session
  state*. calxgloss confirms against recorded baselines and its own ledger, never
  against a live human workspace; the concept, though unrun, is the one honest
  verification idea on the branch.

### OGhidra artifacts calxgloss should explicitly not copy

1. **Checked-in LLM-generated ground-truth text.** `llm_source_summary` bakes model
   output into the corpus, so scores measure two models' agreement, and model drift
   silently redefines ground truth. calxgloss truth must be *behavioral* (captured
   baselines) or *human-facts* (the known original name); never a model's prose.
   (kraken/37 §3: corpus truth is hand-extracted JSONs; ch. 34 §6: the product
   already launders LLM text — doing it on the measuring side is worse.)
2. **Judge fallbacks that fabricate scores.** The all-3s default
   (`llm_judge.py:165-196`) turns a failed judgment into a fake 0.6 — the same
   invented-timestamp disease ch. 34 §6 found in the security report, now on the
   evaluation side. A failed measurement must stay a failure.
3. **Docstrings describing fictional fixtures.** `benchmark/__init__.py:19-22`
   (`corpora/test_corpus`, `SemanticBenchmark`) — calxgloss's standard is the
   opposite: tests run against real seams (ADR-0059).
4. **Annotations no CI evaluates.** The `callable | None` crash (§4) is what
   un-executed code looks like at HEAD — calxgloss's CI-mode honesty line
   (kraken/37 §2, "CI mode") exists precisely because *anything not run rots*.

### Verdict

**Both projects built the right shape — a scored harness separate from the product
that makes a claim about its own output — and OGhidra is a case study in everything
that happens when the harness is never run: the runner imports nothing, the judge
never loads, the corpus is fictional-by-example and LLM-made by design, and not one
score has ever been published.** For calxgloss the lesson is not to copy anything big
— it is the negative result, which calxgloss's own roadmap (P33 whole-task eval,
P42 CI) is pointed at, and which KRAKEN already solved well (kraken/37: 27 scored
tasks, model-free F1, cassettes, honest CI-mode line). The benchmark's *intent* is
the strongest hint that even an LLNL-adjacent project needs the discipline calxgloss
already codifies: truth comes from execution or from humans, failures are recorded as
failures, and the CI line says what a score does and does not mean.

Prioritized steal list:

1. **A scored harness over the fixture DLL, ahead of anything else** — the P33
   oracle done OGhidra-shaped: capture truth from the existing Wine baselines plus
   known-original-name facts (rejections in `re/`), score model-free with token-set
   or embedding comparison (KRAKEN's token-set F1, kraken/37 §2, not OGhidra's
   judge-heavy mix),
   fold in the P51 evidence-computed confidence idea, and expose it as `make eval`.
   OGhidra proves only that the *shape* is right — its own package is the cautionary
   tale of the same shape never run.
2. **CI first** (kraken/37 §2: the CI-mode honesty note and the test CI *are* the
   honesty mechanism). A single
   smoke job — `python -c "import benchmark"`-style — would have caught the exact
   bug class that killed OGhidra's benchmark at HEAD (§4). Any calxgloss eval
   harness must arrive with the job that runs it, or it will rot the same way.
3. **The judge rubric as a prompt template only** (`llm_judge.py:21-68`) — and only
   for naming/text triage questions, never on the verdict path. calxgloss has no
   model-graded judgment anywhere in its decision path today (ADR-0057); this
   chapter's evidence for why that restraint is correct is the combination of §2
   (the judge scored other LLM's prose) and §3 (its failures became fake 3/5s).

## Sources

Primary (clone `6224d26`, cited inline):

- `benchmark/README.md`, `benchmark/cli.py`, `benchmark/__init__.py`.
- `benchmark/runners/benchmark_runner.py` (:33, :142-145, :156-165, :308, :321-325),
  `benchmark/runners/oghidra_runner.py` (:47, :84, :96-104, :139-141, :155-157,
  :182-214, :238).
- `benchmark/metrics/evaluator.py` (:39-58, :120, :130-161),
  `benchmark/metrics/llm_judge.py` (:21-68, :165-196),
  `benchmark/ground_truth/source_parser.py` (:8, :31-56, :59-85, :231-286),
  `benchmark/ground_truth/extractor.py` (:27-57, :165,179, :206, :231-267),
  `benchmark/ground_truth/summary_generator.py` (:19-48, :59-81, :82-127, :149).
- `benchmark/reports/generator.py`, `benchmark/reports/visualizer.py`.
- `tests/` directory (22 files / 4,023 LOC), `tests/README.md`,
  `tests/test_tool_calls.py`, `tests/test_scan_function_pointer_tables.py`.
- `src/bridge.py` (:65, :128, :5366-5368), `src/ghidra_client.py` (:762, :1322),
  `src/config.py` (:244-255, :1175, :1231, :1307, :1585-1588),
  `OGhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java` (:262-266,
  :931-943), `README.md` (:157-163, :500-506), `.env.example` (:103, :105, :114,
  :130), `pyproject.toml` (:6).
- `git log` / `git blame` / `git log -S` / `git show` for `8150f0d`, `79d118d`,
  `9078cd9`, `87dfa21`, `63674d7`, `9b466f3`; `git log --all --diff-filter=A` for
  benchmark artifacts (empty).
- Live probes (first-hand observation): `import benchmark` `TypeError` on Python
  3.12.3 (three annotation sites); `py_compile` passes; post-fix API-resolution
  probe against `src/bridge.py` / `src/ghidra_client.py`.
- `file images/*` output (dimensions/format only; images not seen).

GitHub API (2026-11-01): repo stats (465 stars, 50 forks, 3 subscribers,
`has_discussions: false`); issue #16 open/unanswered; PRs #4/#3 (merged 2026-01-21,
external contributor), #17, #50 (closed unmerged), #63 (open against
`origin/dspy-plugin-vibes`, 9 commits, +1,897/−468);
`search/issues?q=repo:LLNL/OGhidra+benchmark`.

Prior chapters: [00 — Scope and Method](00-scope-and-method.md) (in-scope item 5; the
"renames and summaries" claim this chapter corrects with nuance),
[10 — calxgloss baseline](10-calxgloss-baseline.md) (verification chain, ADR-0057,
roadmap P33/P42), [20 — OGhidra inventory](20-oghidra-inventory.md) (module map,
CI/packaging posture), [21 — history and releases](21-history-and-releases.md)
(§6 branch map: `dspy-plugin-vibes`, PR #50 closed unmerged, PR #63),
[31 — Ghidra bridge & backends](31-ghidra-bridge-and-backends.md) (the Java plugin's
`listFunctions`, the two client classes),
[32 — agentic core & context](32-agentic-core-and-context.md) (the loop the benchmark
bypasses; execution gate §9; `model_map` §2; context engine §10),
[33 — knowledge, RAG & sessions](33-knowledge-rag-and-sessions.md) (CAG per
`cli.py:99`; summary caches §4–§5),
[34 — UI, CLI, bulk & reports](34-ui-cli-bulk-and-reports.md) (the enumeration modes
the benchmark prompt mimics, §4; the LLM-written security report, §6);
[36 — orchestrator branch](36-orchestrator-branch.md) (indexed, not yet written);
[KRAKEN 37 — Inference, corpus, evaluation](../kraken/37-inference-corpus-eval.md)
(§2 scored harness / §3 corpus — the template OGhidra never built)
and [KRAKEN 31](../kraken/31-analysis-engines.md) (chapter-structure model).

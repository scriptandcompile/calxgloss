# OGhidra ↔ calxgloss comparison — scope and method

> Part of the [OGhidra overview](README.md). Read this first for what is
> being compared and how.

## What OGhidra is

**OGhidra** ([LLNL/OGhidra](https://github.com/LLNL/OGhidra), BSD-3-Clause +
commercial-license alternative, LLNL-CODE-2013290) is an open-source
**Python bridge between LLMs and Ghidra**, built by Enoch Wang at Lawrence
Livermore National Laboratory. It lets a user analyze a binary *conversationally*
through Ghidra: an agentic loop (plan → execute tools → review → replan) drives
Ghidra over a **GhidraMCP plugin (HTTP)** or a **headless PyGhidra** backend,
against local models via **Ollama** or external APIs (OpenAI, Gemini,
Anthropic, any OpenAI-compatible endpoint).

Key structural facts (as of the revision below):

- **~36k lines of Python in `src/`** on `main` (~53k including tests, benchmark,
  and the Java GhidraMCP extension), Python 3.12+, single flat module tree
  (`src/bridge.py` alone is 7,845 lines);
- an **agentic core** in `src/bridge.py`: planning phase → tool-call execution
  (capped `MAX_EXECUTION_STEPS`) → review phase → replan, up to
  `MAX_AGENTIC_CYCLES`, with a tiered context budget (`CONTEXT_BUDGET`,
  compaction thresholds);
- two **Ghidra backends**: the *http* backend (an HTTP server inside a Ghidra
  extension, `OGhidraMCP/`, derived from LaurieWired/GhidraMCP and
  starsong/GhydraMCP) and the *pyghidra* backend (headless Ghidra via PyGhidra,
  no Ghidra GUI); multi-instance analysis of several binaries;
- a **CAG knowledge system** (`src/cag/` + `src/models/memory.py`): vector
  store for semantic search over function summaries (RAG with an embedding
  model), a metadata extractor, malware-pattern detection (14 techniques with
  MITRE ATT&CK mapping; the README's "12+" is a floor), session store/cache so
  analysis survives restarts;
- **task modes** (`malware`, `vuln`, `general`) and **bulk operations**
  (Rename-Only / Smart / Full enumeration of all functions);
- a **Tkinter GUI and interactive CLI** with one-click smart tool buttons and
  a generated security report (`src/report_template.py`);
- a **benchmark harness** (`benchmark/`): ground truth extracted from the
  *source* of compiled binaries, then scored with ROUGE, BERTScore,
  Sentence-BERT and an LLM-judge over renames/summaries;
- a separate **`orchestrator` branch** — a Claude-inspired orchestrator /
  worker-agent rewrite (blackboard, recipes, lead tracker) that is the
  README's headline alternate version;
- history: created 2025-11-20, 147 commits on `main` (last 2026-10-28), 465
  stars, 50 forks, ~9 named contributors, PyPI packaging + Docker + GitHub
  Actions release job.

**Premise correction.** OGhidra was described for this study as "a tool
designed to reverse engineer a binary into source code". That is not what
OGhidra does: its deliverable is *analysis inside a Ghidra project* — renamed
and documented functions, findings, knowledge-graph summaries, and a security
report — not reconstructed source code. Its benchmark scores only the *text*
of the work: the combined score measures the similarity of AI-written function
summaries to LLM-generated reference summaries, with renames as a separate
exact-string stat ([35](35-benchmark-and-effect.md)). The comparison below
therefore
treats OGhidra as a **conversational analysis assistant over Ghidra** and
calxgloss as an **automated binary → verified Rust pipeline**; where OGhidra
gets closer to "back to source" (the orchestrator branch's rewrite-adjacent
workflows) the relevant chapter says so. Verify-in-detail flag: each `3x-*`
chapter must state explicitly what "output" OGhidra produces for its domain.

## Comparison scope

calxgloss works only on **native Windows PE/DLL targets**, decompiled by
Kuna in-process to **cross-platform Rust**, verified by compile + baseline
tests + API-call trace. OGhidra inherits Ghidra's format support (PE, ELF,
…) and its mission is different in kind. Following the pattern of the
[KRAKEN](../kraken/00-scope-and-method.md) and
[REA](../rea/00-scope-and-method.md) comparisons, **everything in OGhidra is
in scope** — every part bears on the shared "understand a binary with an LLM"
problem:

1. **Ghidra bridge & backends** — the `OGhidraMCP` Java extension (what it
   added over upstream GhidraMCP), the HTTP client, the PyGhidra backend,
   multi-instance handling, and the full Ghidra **tool surface** the LLM may
   call (`tool_capabilities.md`, `docs/enabled_tools.md`) → [31](31-ghidra-bridge-and-backends.md).
2. **Agentic core & context management** — `bridge.py`'s plan/execute/review
   loop, command parser, execution gate, context budgeting/compression/
   compaction, task modes, intelligent context builder → [32](32-agentic-core-and-context.md).
3. **Knowledge system** — CAG manager, vector store + RAG document builder,
   function metadata extractor, function graph, malware patterns, sessions/
   caches, memory panels/health, coverage tracker → [33](33-knowledge-rag-and-sessions.md).
4. **Human surface** — GUI (Tkinter, split panels), smart tool buttons,
   interactive CLI commands, bulk rename/enumeration, report generation,
   analysis dumps → [34](34-ui-cli-bulk-and-reports.md).
5. **Benchmark & effect** — `benchmark/` ground-truth extraction, metrics
   (ROUGE/BERTScore/Sentence-BERT/LLM-judge), runners, what is actually
   measured, reported results → [35](35-benchmark-and-effect.md).
6. **Orchestrator branch** — the Claude-inspired orchestrator/worker rewrite:
   agents, blackboard, recipes, correlation hooks, and what it changes about
   the whole design → [36](36-orchestrator-branch.md).
7. **Repo ops & history** — packaging (pyproject/PyPI), Docker, CI, config
   system, tests, branches and their research directions, release/versioning
   history → [20](20-oghidra-inventory.md), [21](21-history-and-releases.md).
8. **Whole-project comparison** — feature matrix, philosophy contrast,
   effectiveness evidence, and steal-ideas → [40](40-comparison.md).

**Out of scope:** Ghidra itself (NSA's platform is only described as far as
OGhidra touches it); Ollama and the external providers; upstream
LaurieWired/GhidraMCP and starsong/GhydraMCP except for what OGhidra's fork
adds or changes; other branches not named in the README except as a map
([21](21-history-and-releases.md)).

## Method

- **Primary sources only.** The repo was cloned at `6224d26` (branch `main`,
  last commit 2026-10-28) with a second worktree at `origin/orchestrator`
  (`aa03aa8`, 2026-05-08). Every claim in a `3x-*` file cites `file:line` in
  that clone, the repo's own docs/README, or the GitHub API (stars,
  contributors, languages — recorded 2026-11-01). Ranked secondhand blog
  coverage is not used.
- **The calxgloss side is fixed** at the [10-calxgloss-baseline](10-calxgloss-baseline.md)
  (re-verified 2026-11-01 against this repo's docs, ADRs, and crates). Every
  comparison section anchors to it rather than re-deriving calxgloss facts.
- **Chapter shape** follows the sibling studies (see [KRAKEN 31](../kraken/31-analysis-engines.md)
  as the model): what OGhidra does (numbered sections with code evidence) →
  comparison with calxgloss (overlap / calxgloss-only / OGhidra-only) →
  verdict → concrete steal ideas in priority order → Sources.
- **Vocabulary** follows calxgloss glossaries (`crates/<context>/GLOSSARY.md`):
  *unit of work*, *attempt*, *run*, *scan*, *seam*, *analysis engine* vs
  *evidence engine*, *PAL*. OGhidra's own words (*agentic loop*, *CAG*,
  *smart enumeration*, *task mode*, *workplan*) are introduced as OGhidra's,
  not mapped onto calxgloss words where they don't fit.
- **Partial work is committed as each file lands**; `README.md` is the index
  and gets its executive summary + capability matrix last, once the `3x-*`
  files and [40-comparison](40-comparison.md) are done.

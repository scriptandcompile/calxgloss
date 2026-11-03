# llm-reverse-engineering ↔ calxgloss comparison — scope and method

> Part of the [llm-reverse-engineering overview](README.md). Read this first
> for what is being compared and how.

## What llm-reverse-engineering is

**llm-reverse-engineering** ([mjurzak/llm-reverse-engineering](https://github.com/mjurzak/llm-reverse-engineering),
MIT) is a small Python tool that lets a user decompile a compiled C/C++
binary *conversationally*: a LangChain ReAct-style agent with OpenAI-tool
calling is given eight `radare2` tools and a system prompt demanding a
compilable C listing plus a semantic analysis, and a Streamlit chat UI wraps
the whole thing — with session save/load, one-click extract-compile-metrics,
AI compile-error fixing, tool-call-flow graphs, and auto-generated READMEs.
It was built by Michał Jurzak (AGH University, `michaljurzak@student.agh.edu.pl`)
as the project "LLM – code translation and reverse engineering" — a student
design project ("studio projektowe" per paths in the committed logs).

Key structural facts (as of the revision below):

- **~1,700 lines of Python in 5 modules** (`app.py` 670, `radare2_tools.py`
  363, `code_generator.py` 271, `main.py` 252, `reverse_engineering_agent.py`
  140); single branch `main`, 13 commits total, 2025-04-24 → 2025-06-13,
  one contributor, 0 stars / 1 fork / 0 releases / 0 issues (GitHub API,
  recorded 2026-11-01);
- the agent is stock **LangChain `AgentExecutor`** (`OpenAIToolsAgentOutputParser`)
  over `ChatOpenAI(model="o4-mini")` or `ChatOllama` (default
  `qwen2.5-coder:7b`) — no custom loop, no planning/review phases, no context
  budgeting beyond raw history replay;
- **8–10 LLM-callable radare2 tools** via `r2pipe`
  (`analyze`/`list_functions`/`decompile`/`search_strings`/`get_imports`/
  `get_exports`/`read_memory`/`close`, plus two project-directory tools);
  "decompilation" is radare2's `pdc` microcode pseudo-C, not a real
  decompiler (no r2ghidra/r2dec anywhere in the repo);
- a **Streamlit UI** with chat sessions persisted as JSON, a
  *Extract and Compile* button that gcc-compiles the LLM's code block, emits
  a metrics blob (size / MD5 / string-set comparison), retries AI fixes up
  to 3 attempts, and can generate a README per successful compile;
- a **CLI** (`main.py`, Typer) with a second, older path: CSmith-generated
  random programs → compile → agent decompile → compare via **Code Property
  Graphs (Joern)** and binary metrics (`code_generator.py`);
- an **evaluation corpus**: 20 hand-written C/C++ examples (incl. UB/vuln
  programs), 3 multi-file projects, and the author's own analysis spreadsheet
  `testing/results/project_analysis.xlsx`, summarized qualitatively in the
  README's Strengths/Weaknesses section;
- no tests, no CI, `config/` and `utils/` are empty packages (dead
  scaffolding), committed `__pycache__`/logs/workspace junk, Docker image on
  Docker Hub (`michaljurzak/llm-reverse-engineering`).

## Premise

The study was framed as "a tool designed to reverse engineer a binary into
source code". Unlike the OGhidra premise problem, **that description is
broadly accurate here**: the deliverable *is* reconstructed C source (the
prompt mandates a complete, compilable C program), and the tool recompiles
it. Two corrections matter, though, and are argued in the deep-dive chapters:

1. The reconstruction target is **readable, compilable, semantically-plausible
   C**, not behavior-equivalent code with any proof of equivalence — the
   "verification" is (a) does it compile, (b) do crude binary metrics look
   similar, (c) does the author eyeball it in a spreadsheet ([33](33-cli-csmith-cpg-and-metrics.md),
   [34](34-evaluation-corpus-and-effect.md)).
2. Its decompiler engine is radare2 `pdc`, a microcode pseudocutter — the
   README's "High-quality decompilation" claim is not supported by the tool
   code ([31](31-agent-loop-and-radare2-tool-surface.md)).

## Comparison scope

calxgloss works on native Windows PE/DLL targets, decompiles with the Kuna
engine in-process behind the decompiler seam, and emits **cross-platform
Rust** verified by compile + baseline tests + API-call trace, one attempt
branch per unit of work. llm-reverse-engineering (short name **LRE** in the
tables) works on Linux ELF binaries (gcc-compiled C/C++ samples), emits C,
and keeps a human in a chat loop. Following the sibling studies
([OGhidra](../OGhidra/00-scope-and-method.md),
[LLM4Decompile](../LLM4Decompile/00-scope-and-method.md)), **everything in
LRE is in scope** — the repo is small enough that every file bears on the
comparison:

1. **Agent loop & radare2 tool surface** — system prompt, LangChain wiring,
   history replay, the tool table with exact r2 commands, analysis modes,
   project-directory mode → [31](31-agent-loop-and-radare2-tool-surface.md).
2. **Streamlit UI, recompile loop, XAI & sessions** — chat/session JSON
   store, extract→compile→metrics→AI-fix loop, README generation, tool-call
   flow graphs, "Explain in Detail" table →
   [32](32-streamlit-ui-recompile-metrics-and-sessions.md).
3. **CLI, CSmith, CPG metrics** — the `generate` / `generate_and_analyze`
   commands, CSmith generation, Joern CPG comparison (graph edit distance,
   SimRank, node/edge diff), binary comparison metrics and why MD5-match is
   the wrong oracle → [33](33-cli-csmith-cpg-and-metrics.md).
4. **Evaluation corpus & effect** — the 20-example + 3-project corpus, the
   committed `project_analysis.xlsx` results, `demo_code/` artifacts, and
   the author's own published Strengths/Weaknesses — the *only* effectiveness
   evidence that exists → [34](34-evaluation-corpus-and-effect.md).
5. **Repo inventory & history** — layout, LOC, dependencies, Docker,
   config surface, dead code, committed artifacts, commit timeline,
   authorship, README claims vs code ledger →
   [20](20-llm-reverse-engineering-inventory.md),
   [21](21-history-and-releases.md).
6. **Whole-project comparison** — feature matrix, philosophy contrast,
   effect evidence, and steal-ideas → [40](40-comparison.md).

**Out of scope:** radare2 itself (described only as far as LRE touches it);
LangChain internals; Ollama/OpenAI providers; CSmith and Joern as standalone
tools; the author's university context beyond provenance.

## Method

- **Primary sources only.** The repo was cloned at `aa74f48` (branch `main`,
  last commit 2025-06-13) into `/tmp/opencode/llm-reverse-engineering`.
  Every code claim cites `file:line` in that clone; the whole 1,696-line
  Python surface was read end-to-end by the lead agent (not delegated), so
  the `3x-*` chapters are written from direct reading. GitHub API facts
  (stars/forks/contributors/branches/releases/issues) recorded 2026-11-01.
  Sub-agents were used only for the evaluation corpus and `xlsx` artifact
  extraction ([34](34-evaluation-corpus-and-effect.md) Notes), with claims
  spot-checked against the clone.
- **The calxgloss side is fixed** at the [10-calxgloss-baseline](10-calxgloss-baseline.md)
  (compiled 2026-11-01 against this repo's docs, ADRs and crates; consistent
  with the [OGhidra baseline](../OGhidra/10-calxgloss-baseline.md) verified
  the same day). Every comparison section anchors to it.
- **Chapter shape** follows the sibling studies: what LRE does (numbered
  sections with code evidence) → comparison with calxgloss (overlap /
  calxgloss-only / LRE-only) → verdict → concrete steal ideas in priority
  order → Sources.
- **Vocabulary** follows calxgloss glossaries (`crates/<context>/GLOSSARY.md`):
  *unit of work*, *attempt*, *run*, *scan*, *seam*, *evidence engine*,
  *oracle*, *PAL*. LRE's own words (*chat session*, *analysis mode*,
  *tool call*, *metrics*) are kept as LRE's, not mapped onto calxgloss
  words where they don't fit.
- **Partial work is saved as each file lands**; `README.md` is the index and
  gets its executive summary + capability matrix last.

## Pinned revisions

| Item | Value |
|---|---|
| Repo | `mjurzak/llm-reverse-engineering` (README's clone URL `michaljurzak1/...` is a stale account name — it 404-redirects to `mjurzak`) |
| Clone HEAD | `aa74f48` "Create LICENSE", 2025-06-13 |
| First commit | `bff1e18` "First program", 2025-04-24 |
| Branches | `main` only (GitHub API) |
| License | MIT (`aa74f48`, added last, 2025-06-13) |
| GitHub stats | 0★, 1 fork, 1 watcher, 0 issues, 0 releases; language stats report "C" (the test corpus outweighs the Python) — recorded 2026-11-01 |
| calxgloss anchor | this repo at working date 2026-11-01, see [10](10-calxgloss-baseline.md) |

# 20 — llm-reverse-engineering: repo inventory

> Part of the [overview](README.md). All paths and `file:line` cite the clone
> at `aa74f48` (`/tmp/opencode/llm-reverse-engineering`), recorded 2026-11-01.

## 1. Shape of the repo

Total clone size 2.6 MB; **1,696 lines of Python across 5 modules** — the
entire engine of the tool. The rest is corpus, artifacts and packaging:

```
app.py                                670 L  Streamlit UI: chat, sessions, compile/metrics/AI-fix loop, XAI, visualizations
tools/radare2_tools.py                363 L  r2pipe wrapper: tool factory + project-dir scan
tools/code_generator.py               271 L  CSmith generation, gcc compile, binary + Joern-CPG comparison metrics
main.py                               252 L  Typer CLI: `generate`, `generate_and_analyze`
agents/reverse_engineering_agent.py   140 L  LangChain agent construction + system prompt + history update
testing/code_examples/                 20 files  hand-written C/C++ corpus, 48–255 LOC each (see 34)
testing/code_examples_compiled/        21 ELF binaries + 3 data files
testing/code_projects/                  3 multi-file projects: simple_calc, utils_lib, json_parser (see 34)
testing/results/project_analysis.xlsx  the author's manual evaluation, 3 Polish sheets (see 34)
testing/src/compile_examples.sh        builds the corpus with -Wall -Wextra (default -O0)
demo_code/                              7 C sources/LLM outputs + 7 ELF binaries + 2 generated READMEs + chat_output.md (see 34)
images/                                 5 UI screenshots
Dockerfile, .dockerignore              two-stage image; Docker Hub michaljurzak/llm-reverse-engineering
.env.example, requirements.txt         config surface (17 unpinned deps)
LICENSE (MIT)                          added in the very last commit, 2025-06-13
__init__.py, config/, utils/           empty root package + two empty packages (dead scaffolding — __init__.py is 0 bytes in each)
```

No package metadata (no `pyproject.toml`/`setup.py`): this is a script-style
app, not an installable tool. **No tests, no CI, no linter config, no issue
tracker activity.** Single branch `main`.

## 2. Runtime composition

Two entry points share three components (`Radare2Tools`,
`ReverseEngineeringAgent`, and markdown-C extraction):

- **`app.py`** (`streamlit run app.py`) — the shipped product: Docker
  entrypoint, README's whole framing.
- **`main.py`** (Typer CLI) — the *original* project form: `generate`
  (one-shot agent run) and `generate_and_analyze` (CSmith → compile →
  decompile → CPG/binary compare). Details in [33](33-cli-csmith-cpg-and-metrics.md).

`tools/code_generator.py` is only reachable from the CLI; the UI never
imports it (`app.py:17` has the import commented out).

### Dependencies (requirements.txt, all `>=`, no lockfile)

LangChain quartet (`langchain`, `langchain-community/-core/-openai`),
`r2pipe`, `openai`, `ollama`, `streamlit`, `typer`+`click`, `rich`, `loguru`,
`python-dotenv`, `pydantic`, `networkx`, `matplotlib`, `graphviz`.

**Dependency gap:** `app.py:12` and `code_generator.py:179` use
`networkx.drawing.nx_agraph` (`graphviz_layout`, `read_dot`), which needs
**pygraphviz** — not in requirements. `app.py:186-187` catches the failure
and falls back to `spring_layout`; the CPG path in `code_generator.py` has a
bare `except` at `code_generator.py:187-189` that collapses to an *empty*
graph, silently producing 0% CPG similarity results.

External system tools assumed at runtime: `r2` (radare2), `gcc`, `strings`,
`file`, and for the CLI path `csmith`, `joern-parse`, `joern-export`
(`code_generator.py:17-19` — none of these are installed by the Dockerfile;
the CLI's evaluation path is not usable in the published image).

## 3. Configuration surface

`.env.example` sets: `OLLAMA_BASE_URL`, `OLLAMA_MODEL` (default
`qwen2.5-coder:7b`), `OPENAI_REV_ENG_API_KEY` (commented), 
`DEFAULT_ANALYSIS_MODE`, `LOG_LEVEL`, `LOG_FILE`, `R2_CACHE`,
`R2_RELOCS_APPLY`.

- **The OpenAI model is hardcoded** to `o4-mini`
  (`agents/reverse_engineering_agent.py:29`) — no env override, despite the
  README's "Model Flexibility: easily switch between OpenAI models (like
  GPT-4)".
- `R2_CACHE` and `R2_RELOCS_APPLY` have **zero readers in the codebase**
  (grep over `*.py`: no matches) — dead config keys.
- `DEFAULT_ANALYSIS_MODE` is honored only by the CLI default
  (`main.py:55`); the UI hardcodes `"standard"` at `app.py:371` and `:374`.

## 4. Docker packaging

Two-stage build (`Dockerfile`): builder clones and builds radare2 from
source (`sys/install.sh`), final image is `python:3.13.2-slim` + graphviz +
copied radare2 binaries/libs; entrypoint is the Streamlit app on 8501.
Published as `michaljurzak/llm-reverse-engineering:latest` — Docker Hub API
(recorded 2026-11-01): registered 2025-06-13, **233 pulls**, status active,
~348 MB.

Weaknesses visible from the Dockerfile alone:

- final stage installs **no `file` utility**, yet project-directory mode
  shells out to `file` per candidate file (`radare2_tools.py:39`) inside a
  `try/except` that `continue`s on failure — in the image, *every* file
  detection fails and the mode raises "No binary files found" (not
  runtime-verified; static reading). The same applies to `strings`
  (binutils) used by the metrics panel (`app.py:91`) — `app.py:96-98` at
  least logs and degrades to empty sets.
- README itself notes Ollama is unreachable from the container
  (README.md:88) — Docker mode is OpenAI-API-only.

## 5. Dead scaffolding and committed artifacts

Consistently present across the repo: machinery that exists but is not
wired, and artifacts that should not be tracked.

- Empty packages `config/`, `utils/` + root `__init__.py` (0 bytes each).
- `Radare2Tools.get_call_graph` (`radare2_tools.py:95`) and
  `get_binary_info` (`:116`) are defined but never called and never exposed
  as agent tools (the tool factory at `:177-195` omits them) — a call-graph
  *capability* the LLM never gets, despite the prompt's dependency steps.
- `ReverseEngineeringAgent.update_history` (`:131-141`) is used only by the
  CLI (`main.py:105`); the UI keeps its own parallel history
  (`st.session_state.llm_history`).
- Tracked despite being gitignored (added before the ignore rules and never
  untracked): 5 `__pycache__/*.pyc` (CPython **3.12** — the author's
  runtime), `logs/analysis.log`, `workspace/output.json/{project.json,
  cpg.bin.tmp}`, and the `demo_code/decompiled_*` outputs. The log and
  workspace files leak the author's machine paths
  (`/home/mjurzak/studio_projektowe/`, `/mnt/d/University/Studio
  Projektowe/` — the AGH "studio projektowe" provenance, see [21](21-history-and-releases.md)).

## 6. README-claims vs code ledger

The claims most relevant to a fair comparison (claim → reality, evidence):

| README claim | Reality at `aa74f48` |
|---|---|
| "Full program analysis (`aaa`)" | mode-dependent: `quick`→`aaa`, `standard`→`aaaa`, `deep`→`aaaaa` (`radare2_tools.py:133-138`); UI hardcodes `standard` (`app.py:371`) |
| "High-quality decompilation" | `pdc` only — radare2's microcode pseudo-C (`radare2_tools.py:291`); no r2ghidra/r2dec anywhere in repo or Dockerfile |
| "Model Flexibility: switch between OpenAI models (like GPT-4)" | `ChatOpenAI(model="o4-mini")` hardcoded (`reverse_engineering_agent.py:29`); only local/OpenAI switch is real |
| "recompile it, and view comparison metrics against the original binary" | true but crude: size %, MD5 equality, string-set stats, first-10k-byte sequence ratio (`app.py:82-136`) — see [32](32-streamlit-ui-recompile-metrics-and-sessions.md) |
| "Automated Documentation … README.md upon successful compilation" | true (`app.py:506-530`) — and `demo_code/README_simple_c_program.md` shows how badly it can go, see [34](34-evaluation-corpus-and-effect.md) |
| "Save, load, and delete entire analysis sessions" | true (JSON files in `chat_history/`, `app.py:236-306`); README lists "loading a conversation does not correctly re-initialize the file analysis context" as a *future* fix, yet the load path does re-init r2 (`app.py:427-434`) — partially addressed already |
| Clone URL `michaljurzak1/llm-reverse-engineering.git` | stale account name; redirects to `mjurzak/` (GitHub API) |

## 7. Comparison to calxgloss

- **Scale ratio is real but not the whole story.** calxgloss is a Rust
  workspace (decomp seam, 15 evidence engines, prompts crate, verify, git,
  web review UI, 57 ADRs); LRE is 1.7k lines of glue over LangChain + r2pipe.
  What LRE actually reuses, it reuses well: radare2 for analysis, gcc for
  rebuild, Joern CPG for similarity — it never reimplements an analyzer.
  calxgloss likewise treats Kuna as an external engine behind a seam
  (ADR-0041/0042). The difference is *what is built around the engine*:
  LRE wraps it in a chat; calxgloss wraps it in a pipeline + oracles.
- **Tool-surface honesty.** LRE's prompt advertises an analysis recipe
  ("use `analyze()`, `list_functions()`, `decompile()`…"
  `reverse_engineering_agent.py:53-58`) that matches the registered tools —
  a small but genuine prompt/tool coherence. calxgloss's capability report
  doctrine (declared query families, admission lines) is the formalized
  version of the same instinct.
- **Dead-config and dead-code pattern.** LRE has the *mild* version of
  OGhidra's pathology: `R2_CACHE`/`R2_RELOCS_APPLY` keys nothing reads, two
  unused analysis methods, a missing pygraphviz dep that silently zeroes
  CPG scores. None of it is claimed as a feature, so the harm is
  maintenance-illusion rather than false marketing — but the pygraphviz
  case shows a *metric path that silently reports emptiness*, exactly the
  failure class calxgloss's coverage-honesty doctrine (ADR-0053) targets.
- **Artifact hygiene.** committed `__pycache__`, logs, workspace state and
  machine paths would not survive calxgloss's git hygiene (per-attempt
  branches, generated dirs gitignored). Minor, but it signals no review
  gate of any kind on the repo itself.

**Verdict:** LRE's engineering is thin — 5 modules, no tests, dead
scaffolding, one unpinnable dependency chain — but its *composition*
choices (external analyzer + external compiler + external CPG differ +
human loop) are the same architectural family calxgloss uses, at student
scale. The interesting content is in how far that composition gets without
an oracle, which is what [32](32-streamlit-ui-recompile-metrics-and-sessions.md)/[33](33-cli-csmith-cpg-and-metrics.md)/[34](34-evaluation-corpus-and-effect.md) quantify.

## Sources

Clone `aa74f48` files as cited; Docker Hub API record 2026-11-01;
`git ls-files`, `grep` sweeps and `.gitignore` read directly. Corpus detail:
[34](34-evaluation-corpus-and-effect.md). CLI internals:
[33](33-cli-csmith-cpg-and-metrics.md).

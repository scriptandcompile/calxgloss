# OGhidra complete inventory — scale, module map, dependencies, packaging, config surface

> Part of the [OGhidra overview](README.md). This is the fixed surface map the
> `3x-*` domain chapters work from. Sources: the clone at
> `/tmp/opencode/OGhidra` @ `6224d26` (branch `main`, 2026-10-28), measured
> directly — every LOC figure is `wc -l` over `git ls-files` / `find` run in
> the clone today; GitHub facts are `gh api` recorded 2026-11-01. OGhidra
> claims cite clone-relative `path:line`. The grouping of `src/` follows the
> repo's own docstrings and the README architecture diagram (`README.md:513-550`),
> not an invention. The *deeper* subsystems (bridge loop, CAG, benchmark,
> orchestrator) each get their own chapter here — this file inventories them,
> it does not analyse them.

**Chapter legend** (where each subsystem is analysed in depth): **31** Ghidra
bridge/backends · **32** agentic core & context · **33** knowledge/RAG/sessions ·
**34** UI/CLI/bulk/reports · **35** benchmark · **36** orchestrator branch ·
**21** history & branches.

## 1. Repo shape and scale

- Single Python package `src/` (flat tree, `pyproject.toml:42-43` wheel
  packages `["src"]`), entry point `main.py` at the root, a Java Ghidra
  extension in `OGhidraMCP/`, a benchmark package `benchmark/`, and a test
  directory `tests/`. Python ≥ 3.12 (`pyproject.toml:6`).
- **Measured scale**: **139 tracked files** (verified: `git ls-files | wc -l`
  = 139), **52,761 lines** total by `wc -l` including the 3 PNG screenshots
  (2,520 binary "lines") — this is where the [scope file](00-scope-and-method.md)
  "~53k" comes from. By area: `src/` **63 files / 36,020 lines** (35,209 of it
  Python, 811 JSON/markdown knowledge data), `tests/` 22 / 4,023,
  `benchmark/` 18 / 3,260, `OGhidraMCP/` 13 / 2,261, `docs/` 2 / 345,
  root 17 / 4,283 (incl. `main.py` 1,426), `.github/` 1 / 49, `images/` 3.
- Python is **43,726 lines** (src 35,209 + tests 3,959 + benchmark 3,132 +
  main 1,426, measured `find … -name '*.py' | xargs wc -l`); Java
  **2,066** (one real class, 2,028); markdown 3,153; shell 72 + batch 75
  (the two plugin-build scripts).
- GitHub language bytes (GitHub API, 2026-11-01): Python 1,842,709, Java
  82,619, Batchfile 2,202, Shell 2,087, Dockerfile 1,051. Repo `size` 3,832 KB,
  `license.spdx_id` **NOASSERTION** (the LICENSE is not stock BSD-3, §10),
  wiki on / discussions off (`has_wiki: true`, `has_discussions: false`).
- No CI test/build pipeline: `.github/workflows/` contains exactly one
  workflow, `release.yml` (49 lines) — see §8. "Set up CI tests" (#10) and
  "Add some security checks to CI" (#36) sit open (GitHub API, 2026-11-01).
- The five biggest source files: `src/bridge.py` 7,845, `src/ghidra_client.py`
  2,822, `src/gui/tool_buttons_panel.py` 2,579, the Java plugin 2,028,
  `src/config.py` 2,000.

## 2. `src/` module map (every file)

LOC as measured §1. Groups follow the README architecture diagram's layers
(UI / bridge / Ghidra client / LLM clients / CAG) plus the repo's own docstring
camps ("Enhanced Knowledge System", dated 2026-02-19, and the OpenCode-inspired
modules that cite OpenCode by name).

### 2.1 Core & bridge (ch. 32)

| File | LOC | For |
|---|---:|---|
| `src/bridge.py` | 7,845 | The whole agentic core: *agentic loop* (plan → execute tool calls → review → replan), Ghidra/LLM/CAG tool routing, prompt assembly, bulk enumeration entry points. `src/bridge.py:1-6` calls itself "Ollama-GhidraMCP Bridge" |
| `src/config.py` | 2,000 | Pydantic/`pydantic-settings` config: every `.env` knob as a `Field(env=…)` (91 distinct `env=` names, measured `grep -o 'env="[A-Z_]*"'`), provider/model/tool-parameter models, env-override merge (`config.py:1546-1556`) |
| `src/command_parser.py` | 606 | Extracts `EXECUTE: tool(args)` blocks from LLM responses, validates params, dispatches to the Ghidra client (`tests/README.md:28-40`) |
| `src/bridge_mcp_ghidra.py` | 387 | Standalone PEP-723 script (`mcp>=1.2.0,<2`) wrapping the GhidraMCP HTTP server as a **FastMCP tool server** — OGhidra's own MCP surface, separate from the Java extension (ch. 31) |
| `src/execution_gate.py` | 353 | *Execution gate*: pause the loop on artifacts, repetition (doom-loop), risky tools; "Inspired by OpenCode's PermissionNext.ask()/reply() system" (`execution_gate.py:1-9`) |
| `src/api_health.py` | 57 | One-shot generation probe for OpenAI-compatible endpoints (used by GUI server config) |
| `src/_execution_agent_rank_method.py` | 100 | One extracted helper: asks the execution-phase agent to rank/filter large tool results |

### 2.2 Ghidra backend seam (ch. 31)

| File | LOC | For |
|---|---:|---|
| `src/ghidra_client.py` | 2,822 | The backend seam: `AbstractGhidraClient` ABC (`:21`), `GhidraMCPClient` over HTTP (`:762`), `PyGhidraClient` headless (`:1322`); 147 methods total (measured `grep -c '    def '`) |
| `src/ghidra_mcp_client.py` | 509 | Older direct GhidraMCP HTTP client implementing `src/cag/knowledge/function_signatures.json`; targeted for deletion by branch `delete-ghidra_mcp_client` ([21 §6](21-history-and-releases.md)) |

### 2.3 LLM clients

| File | LOC | For |
|---|---:|---|
| `src/ollama_client.py` | 698 | Ollama chat + embeddings client, retries, per-phase model maps (`OLLAMA_MODEL_PLANNING`/`EXECUTION`/`REVIEW`/…, `config.py:1587-1588`) |
| `src/custom_api_client.py` | 762 | OpenAI-compatible client: tenacity retries, throttling/concurrency knobs from `.env`, 429 `Retry-After` respect |
| `src/external_client.py` | 450 | Vendor-API client ("Currently implements Google Gemini v1beta interface", `external_client.py:1-6`) |

`LLM_PROVIDER=ollama|external|custom_api` selects between them
(`.env.example:9-11`); a fourth "mcp" surface exists as §2.1's
`bridge_mcp_ghidra.py` script.

### 2.4 Context, budgeting & compaction (ch. 32)

| File | LOC | For |
|---|---:|---|
| `src/context_manager.py` | 1,119 | *Context budget*: result caching with `get_cached_result()` refs, LLM summarization of big results, tiered recent/older detail, budget enforcement |
| `src/session_compactor.py` | 280 | *Session compaction*: deterministic prune + LLM-driven compact between cycles; "Inspired by OpenCode's SessionCompaction system" (`session_compactor.py:1-10`) |
| `src/result_compactor.py` | 181 | Deterministic per-tool-result compaction before prompt injection (rate-limit/504 relief) |
| `src/intelligent_context_builder.py` | 381 | Query-intent-driven context assembly instead of fixed truncation ("Enhanced Knowledge System", 2026-02-19) |

### 2.5 Knowledge & investigation agents (ch. 33)

Top-level siblings of the CAG package (all part of the *smart enumeration*
knowledge build):

| File | LOC | For |
|---|---:|---|
| `src/rag_document_builder.py` | 619 | Builds dense hierarchical docs per function for embedding/retrieval |
| `src/function_metadata_extractor.py` | 555 | Structured metadata (LOC, complexity, operations) from decompiled C |
| `src/function_graph.py` | 406 | Lightweight call graph over function metadata; graph-aware RAG expansion, domain clustering |
| `src/vector_store.py` | 204 | Session-level numpy vector store (RAG over session records) — **separate** from `src/cag/vector_store.py` |
| `src/coverage_tracker.py` | 225 | *Coverage tracker*: investigation-area checklist injected into the prompt; born from a named post-mortem ("WiseBootAssistant", `coverage_tracker.py:8-10`) |
| `src/lead_tracker.py` | 122 | *Lead tracker*: prioritized follow-up queue against "breadth-over-depth" |
| `src/user_question.py` | 153 | `ASK_USER:` / `OPTIONS:` directive — AI-initiated questions mid-run ("Inspired by OpenCode's Question.ask()/reply()", `user_question.py:1-8`) |

### 2.6 Memory & sessions (ch. 33)

Eight files, two overlapping stacks — pydantic-model-backed memory
(`memory_models`/`memory_manager`/`active_session`/`session_store`) and the
enhanced JSON session system (`enhanced_session_manager` + `cag/session_cache`):

| File | LOC | For |
|---|---:|---|
| `src/enhanced_session_manager.py` | 669 | Save/load whole analysis sessions: analyzed functions, RAG vectors, UI state (README "Session Management" §5) |
| `src/memory_health.py` | 334 | Health checks over the memory/vector system |
| `src/memory_manager.py` | 264 | Glue: session storage + active session + vector DB for RAG |
| `src/session_utils.py` | 211 | Embeddings/summary generation for session records |
| `src/active_session.py` | 135 | In-flight session record + tool-call log |
| `src/memory_models.py` | 83 | Pydantic `SessionRecord`/`ToolCallRecord` |
| `src/session_store.py` | 52 | JSON session history persistence |
| `src/user_prefs_store.py` | 33 | Sticky user prefs across restarts |

### 2.7 `src/models/`

| File | LOC | For |
|---|---:|---|
| `src/models/memory.py` | 556 | The type-safe backbone: `ConversationMessage`, `MessageRole`, `AnalysisState`, *CAGContext*, `PromptSection`, tool-execution results (`models/memory.py:1-9`) |
| `src/models/__init__.py` | 25 | Re-exports |

### 2.8 `src/gui/` — Tkinter workbench (ch. 34)

Split out of a 6,622-line `src/ui.py` on 2026-06-26 (PR #27; branch evidence in
[21 §6](21-history-and-releases.md)). Total 11 files / **6,801 lines**:

| File | LOC | For |
|---|---:|---|
| `src/gui/tool_buttons_panel.py` | 2,579 | The *smart tool buttons*: one-click analyze/rename/bulk-enumerate/report tasks (largest GUI file) |
| `src/gui/ui.py` | 1,228 | Main window assembly, panels, menu, task-mode dropdown |
| `src/gui/renamed_functions_panel.py` | 1,173 | Renamed-functions table (summaries, async refresh) |
| `src/gui/server_config_dialog.py` | 544 | LLM/Ghidra server config + health checks |
| `src/gui/memory_info_panel.py` | 391 | Memory/vector-store status panel |
| `src/gui/query_input_panel.py` | 350 | Query input + workflow diagram host |
| `src/gui/ai_response_panel.py` | 184 | Chat response view |
| `src/gui/workflow_diagram.py` | 133 | Visual stages of the agentic workflow (includes the RAG-vector stage) |
| `src/gui/session_load_dialog.py` | 107 | Session picker |
| `src/gui/ui_thread.py` | 74 | The one Tk thread-safety primitive: `@ui_safe` decorator + single queue/pump (`ui_thread.py:1-11`) |
| `src/gui/daemon_thread_pool_executor.py` | 38 | Daemon-worker pool so bulk jobs don't block exit |

### 2.9 `src/cag/` — Cache-Augmented Generation (ch. 33)

*CAG* is OGhidra's house knowledge system — persistent cache-augmented
generation instead of real-time retrieval (`cag/__init__.py:1-6`). 7 Python
files 3,423 lines + 811 lines of baked-in data:

| File | LOC | For |
|---|---:|---|
| `src/cag/manager.py` | 1,067 | *CAG manager* wired into `Bridge`: assembles cached knowledge into prompts |
| `src/cag/malware_patterns.py` | 934 | 12+ malware techniques (PEB walking, dynamic API resolution, anti-debug/VM, injection, persistence, API hashing, token/UAC abuse) with MITRE ATT&CK mapping (23 `mitre` mentions, measured `grep -c`) |
| `src/cag/session_cache.py` | 551 | Per-session conversation + results cache |
| `src/cag/knowledge_cache.py` | 410 | Domain-knowledge cache: `AnalysisRule`, `BinaryPattern`, `FunctionSignature`, `GhidraKnowledgeCache` |
| `src/cag/vector_store.py` | 393 | Function-summary vector store; optional FAISS index behind try-import (`cag/vector_store.py:10-14`) — **FAISS is declared nowhere** (measured: absent from `pyproject.toml` + `requirements.txt`) |
| `src/cag/init_dirs.py` | 51 | Bootstraps the CAG directory tree |
| `src/cag/__init__.py` | 17 | Re-exports |
| `src/cag/knowledge/function_signatures.json` | 171 | GhidraMCP API signatures the client implements |
| `src/cag/knowledge/common_workflows.json` | 12 | Recipe text for common Ghidra workflows |
| `src/cag/templates/interactive_prompt.md` | 52 | Interactive-prompt template |
| `src/cag/workplans/*.md` (6) | 576 | *Workplans*: playbook markdown — progressive_analysis (218), knowledge_capture (148), ghidra_tasks (87), malware_analysis_triage (60), windows_service_security (32), executable_loading_security (31) |

### 2.10 Misc top-level

| File | LOC | For |
|---|---:|---|
| `src/report_template.py` | 1,490 | HTML/CSS security-report generator ("Based on the WiseDiskCleaner report template", `report_template.py:1-6`) |
| `src/analysis_dump.py` | 292 | Pre-truncation dump of raw tool outputs + chain-of-thought for manual review |
| `src/__init__.py` | 7 | Package docstring; `__version__ = "0.1.0"` (`:7`) — stale under VCS versioning, §8 |

## 3. Entry point `main.py` (1,426 lines)

CLI + launcher (ch. 34 owns the interactive REPL). `load_dotenv(override=True)`
before any import (`main.py:8-11`); argparse surface: `--interactive/-i`,
`--query/-q`, `--ui` (GUI is the default when no mode flag is passed,
`main.py:1302-1310`), `--ghidra-backend={http,pyghidra}`,
`--pyghidra-project/-program/-binary`, `--no-capabilities`, `--disable-cag`
(`main.py:1300-1361`). Its ASCII banner cites `README-ARCHITECTURE.md`, which
does not exist in the repo (`main.py:28`; stale pointer).

## 4. `tests/` — what is tested, how

- 22 files / 4,023 lines; **134 test functions** (measured
  `grep -c 'def test_'`), all `unittest` style (`import unittest` in 10
  files; **0** pytest imports; no conftest.py anywhere — measured `find`).
  They still run under pytest, but there is no pytest config, no markers, no
  CI job running them (§8).
- Real unit coverage targets: execution gate (25 tests), coverage tracker (31),
  session compactor (12), user-question tool (13), security-hardening
  regressions from the "Slasher" audit (10), summary extraction (8), api_health
  (7), lead tracker (6), command normalization (4), context manager (4),
  read_bytes (4), bridge (3, mocked), verify_prompts (4).
- Live-server scripts, not tests: `test_tool_calls.py` (446) and
  `test_extended_api.py` hit a running GhidraMCP plugin and *generate*
  `tool_capabilities.md` (tests/README "Generated Documentation");
  `test_scan_function_pointer_tables.py` + `debug_scan.py` probe the
  `scan_function_pointer_tables` tool; `analyze_logs.py`/`read_log.py`
  summarise `logs/llm_interactions.log`; `embedding_similarity_sweep.py` (533)
  is an embedding-model bake-off against a saved session.
- Fixtures are synthetic, per the file's own disclaimer: example malware
  patterns, RFC1918 addresses, generic addresses (`tests/README.md:8-16`).
  **No test binaries** anywhere in the clone (no `.exe`/`.dll`/`.elf` in
  `git ls-files`).

## 5. `benchmark/` (inventory only — ch. 35 goes deep)

18 files / 3,260 lines (17 Python, 3,132 + README 128). A semantic-similarity
harness answering "Can an agentic AI, iteratively exploring a binary through
Ghidra, achieve semantic understanding comparable to having the source code?"
(`benchmark/README.md:120-126`). Ground truth comes from the *source code* of
compiled binaries: `ground_truth/source_parser.py` parses C/C++ sources,
`summary_generator.py` has an LLM write reference summaries from source,
`extractor.py` maps functions to binary addresses via a live Ghidra.
`metrics/` = BERTScore, Sentence-BERT cosine, ROUGE-L, LLM-as-Judge;
`runners/oghidra_runner.py` drives the real Bridge; `reports/` emit md/html/csv/json.
Scores renames + summaries, never program behaviour. Its heavy deps
(bert-score, sentence-transformers, rouge-score, matplotlib) are **not declared
in pyproject/requirements** (measured `grep -c`, 0 hits) — the README says
`pip install` them by hand (`benchmark/README.md:9-15`).

## 6. `OGhidraMCP/` — the Java Ghidra extension (inventory only — ch. 31 goes deep)

13 files / 2,261 lines; one class `com.lauriewired.GhidraMCPPlugin.java`
(2,028) plus a stock 38-line `AppTest.java`. Header declares it a modified
LaurieWired/GhidraMCP with multi-instance design "inspired by GhydraMCP
(starsong)" and the added `read_bytes` endpoint
(`GhidraMCPPlugin.java:1-12`) — the package name is still LaurieWired's. It is
an embedded **HTTP** server plugin (not MCP): `@PluginInfo … RELEASED`
(`:77`), serves `http://localhost:8080/methods` (`README.md:149`). Build:
Ghidra's own `buildExtension.gradle` applied from `$GHIDRA_INSTALL_DIR`
(`build.gradle:25`), `version = "1.0"`, `ext.ghidraVersion = "12.0.3"`, Java 21
(`build.gradle:28-34`); `extension.properties` says `version=12.0.3`,
`createdOn=2025-03-22`, author "LaurieWired (Original), Modified by
ezrealenoch", while `META-INF/MANIFEST.MF` claims `Plugin-Version: 1.1.0` —
three different version fields. `gradle_version.txt` is a UTF-16 capture of a
`gradlew --version` run (Gradle 8.12.1 via Ghidra, Adoptium 17). Prebuilt
extension zips were committed until 2026-05-08 (ee15cfd "Remove OGhidraMCP
build artifacts"); builds now go through root scripts
`build_ghidra_plugin.sh` (72 lines, falls back to Ghidra's `lastrun` file for
`GHIDRA_INSTALL_DIR`) and `.bat` (75).

## 7. Dependencies, linting, build

- `pyproject.toml` (49 lines) and `requirements.txt` (14) carry the **same 14
  runtime deps** (diffed): flask ≥3.0.3,<3.1 · httpx ≥0.24 · ijson ≥3.2 ·
  matplotlib-stubs ≥0.3.11 · numpy ≥1.24 · psutil ≥5.9 · pydantic-settings
  ≥2.2.1 · pydantic ≥2.7.1 · python-dotenv ≥1.0 · requests ≥2.26 · rich ≥13.7.1
  · tenacity ≥9 · ttkbootstrap ≥1.10 · **pyghidra ≥3.0.2** (`pyproject.toml:13-27`).
  No optional-dependencies section, no benchmark deps (§5), no dev/test extras.
  The GUI is Tkinter + ttkbootstrap; RAG is numpy-only with FAISS optional and
  undeclared (§2.9).
- Lint/format: **ruff** — `[tool.ruff] line-length = 128`, lint ignores
  `DTZ003/DTZ005/DTZ006` (`pyproject.toml:45-49`); enforced by
  `.pre-commit-config.yaml` (28 lines): ruff-pre-commit **v0.17.2** (`ruff
  --fix` + `ruff-format`), pre-commit-hooks v6.0.0 (mixed-line-ending,
  end-of-file-fixer, trailing-whitespace, check-case-conflict,
  check-merge-conflict, check-toml, check-json, pretty-format-json --autofix),
  shellcheck-py v0.11.0.1-1 `-x`; excludes only `.gitignore`. pre-commit.ci
  runs it in the cloud (bot commits/PRs — that is the only CI traffic besides
  releases).
- Java side: Gradle through Ghidra's bundled wrapper (§6); no wrapper checked
  in, no Maven, no CI job for it.

## 8. Packaging & ops

- **Packaging**: `name = "oghidra"`, `dynamic = ["version"]`
  (`pyproject.toml:2-3`); build backend hatchling + **hatch-vcs**, version
  `source = "vcs"` (`pyproject.toml:36-40`) — versions come from git tags
  matching `v[0-9]*` (`describe-name`, `.git_archival.txt`, `export-subst` via
  `.gitattributes`, so source archives keep the tag too).
- **CI/release** (`.github/workflows/release.yml`, the *only* workflow): on
  `workflow_dispatch` or `v*` tag push → `build-wheel` (setup-python 3.12,
  `python -m build`, `twine check`, upload artifact) → `pypi-publish` gated on
  tag pushes, GitHub `environment: pypi`, `pypa/gh-action-pypi-publish@release/v1`
  (`release.yml:36-48`). **No GHCR/docker job on main** — that lives on the
  open branch `add-ghcr-docker-release-job` (+44 lines, [21 §6](21-history-and-releases.md)).
  PyPI actually received **one** release: `oghidra==0.0.0` (wheel + sdist,
  2026-08-14T22:59Z, PyPI JSON API 2026-11-01) — see
  [21 §5](21-history-and-releases.md) for why the version is 0.0.0.
- **Dockerfile** (35 lines, header says "Containerfile"): base
  `docker.io/eclipse-temurin:26.0.1_8-jdk-ubi10-minimal`; microdnf installs
  git/vim/python3/pip/wget/unzip, later `python3-tkinter` + X libs; downloads
  **Ghidra 12.1** (`ghidra_12.1_PUBLIC_20260513`, SHA-256-pinned,
  `Dockerfile:9-16`) — contradicting the README's Ghidra 12.0.3 target
  (`README.md:54-57`); clones the repo **`-b pyghidra`** (`Dockerfile:20`) — a
  branch that **no longer exists** on the remote (measured
  `git ls-remote --heads origin`, no `pyghidra`), so the build fails today;
  `uv sync --extra headless` (`Dockerfile:27`) references an extras group that
  pyproject doesn't define; `ADD .env` (`:29`) requires a local `.env` at
  build time; `ENTRYPOINT ["bash"]` — the intent is an interactive container
  you edit `.env` inside (stated in the commit that added it, d836031).
- `.gitignore` (313 lines) is a gitignore.io/Toptal bundle (python, vscode,
  java, gradle, macos, windows) + hand additions (`110de6b`); `git commit`
  hygiene otherwise unassisted (no CI gates).

## 9. Configuration surface — `.env.example` (170 lines, 72 variables)

Measured: `grep -E '^[A-Z_]+=' .env.example | wc -l` = 72; the code consumes
**96** distinct env names (91 via `env=` in `config.py` + `os.getenv` hits) —
**25 consumed but undocumented**, including the per-phase model overrides
`OLLAMA_MODEL_PLANNING/EXECUTION/REVIEW/EVALUATION/ANALYSIS`, `GHIDRA_BACKEND`,
`PYGHIDRA_PROJECT_PATH/PROGRAM/BINARY`, `EXECUTION_LOOP_ENABLED`,
`OLLAMA_SHOW_REASONING`, `OLLAMA_MAX_RETRIES`, the `GOOGLE_*` family,
`EXTERNAL_BASE_URL/TOP_P/TOP_K/MAX_RETRIES/REQUEST_DELAY`,
`CUSTOM_API_LOG_FILE`, `GHIDRA_API_PATH` (comm battery in-clone).
One `.env.example` key (`ENABLE_CYCLE_CONCLUSIONS`) is not read anywhere by
that name. Groups:

| Group | Vars | Role |
|---|---|---|
| Provider switch | `LLM_PROVIDER` | `ollama` / `external` / `custom_api` |
| External API | 7 (`EXTERNAL_PROVIDER/API_KEY/MODEL/EMBEDDING_MODEL/TIMEOUT/TEMPERATURE/MAX_TOKENS`) | Gemini-first generic vendor path |
| Ollama | 7 (`OLLAMA_BASE_URL/MODEL/EMBEDDING_MODEL/TIMEOUT/USERNAME/PASSWORD` + `OLLAMA_REQUEST_DELAY:107`) | local models + auth + pacing |
| Custom OpenAI-compatible | 21 | URL/model/embeddings + timeout/temp/max_tokens + SSL verify + retries + global concurrency/min-interval + `Retry-After` respect + adaptive throttle (factor/jitter/streak) — the most-instrumented provider |
| Review agent | `REVIEW_THOROUGHNESS` | basic/standard/thorough approval strictness (`.env.example:73-75`) |
| LLM logging | 7 (`LLM_LOGGING_ENABLED/LOG_FILE/PROMPTS/RESPONSES/TOKENS/TIMING/FORMAT`) | full prompt/response/token/timing log, json or text (docs/llm-logging.md) |
| Ghidra | 3 (`GHIDRA_BASE_URL/TIMEOUT/MOCK_MODE`) | http backend target; README still mentions `GHIDRA_MOCK_MODE` but tests/README:30 says mock mode was removed |
| Agent loop | 3 (`MAX_EXECUTION_STEPS:103`, `MAX_AGENTIC_CYCLES:105`, `AGENTIC_LOOP_ENABLED`) | steps per cycle, cycle cap, replanning toggle (defaults 5/2 here; config.py defaults 10/3, `config.py:1266-1268`) |
| Context budget | 13 (`CONTEXT_BUDGET:130` + `CONTEXT_BUDGET_EXECUTION`, summarization/cache/tiered toggles, `CURRENT/PREV/OLDER_LOOP_MAX_CHARS`, `MAX_DETAILED_STEPS`, `TOP_N_PER_CATEGORY`, correlation-hint toggles) | the ASCII scaling table at `.env.example:113-127` maps 25K–1M-token budgets |
| Execution gate | 6 (`EXECUTION_GATE_ENABLED`, `GATE_ON_ARTIFACT/REPETITION/…THRESHOLD/HIGH_RISK_TOOL/AUTO_RESUME_TIMEOUT`) | pause-the-loop policy incl. doom-loop detection |
| Session compaction | 3 (`COMPACTION_ENABLED/THRESHOLD:168-170/AUTO`) | prune/compact at 75% context |

## 10. Top-level oddities & docs surface

- **`tool_capabilities.md`** (1,334 lines, repo root): machine-generated API
  reference for the Ghidra client — every tool, params, return type, "✅
  Success" test status — produced by running `tests/test_tool_calls.py`
  against a live GhidraMCP server (`tests/README.md:44-50`). Maintenance:
  content last updated by 4841c4c "Leads and Convergence" (2026-02-09); since
  then only pre-commit auto-fixes (measured `git log -- tool_capabilities.md`,
  2 commits). It is ~8 months behind the code (root placement itself is an
  accident of that generator's path).
- **`ai_ghidra_capabilities.txt`** (45 lines): hand-written prompt-adjacent
  capability list — 34 tool bullets (measured `grep -c '^- '`) grouped
  Information-Gathering / Context-Management / discovery helpers /
  Modification / Instance-Management, with the `EXECUTE:` usage hints. It is a
  *prompt asset* (fed into LLM context, changed with feature commits —
  `git log`: 8 touching commits) rather than documentation.
- **`docs/`** is two files only: `enabled_tools.md` (143 lines, human-written
  tour of enabled Ghidra tools, added in the 2025-11-20 initial import, last
  touched by pre-commit autofix 2026-05-23) and `llm-logging.md` (202 lines,
  logging guide mirroring §9's log vars). The 608-line README does the rest
  (quick start, plugin build/install, model pulls, backends, PyGhidra flags,
  workflows, troubleshooting, architecture ASCII, citation, acknowledgments).
- **Licensing structure**: `LICENSE` (48 lines) is titled "*BSD 3‑Clause with
  Commercial License alternative*", © 2025 LLNS: conditions 1–3 are standard
  BSD-3 *plus an explicit non-commercial restriction* ("permitted for any
  non‑commercial purpose", `LICENSE:6-8`) and condition 4 requires a separate
  written commercial license from LLNS (`softwarelicensing@llnl.gov`) for any
  commercial advantage/monetary compensation, with monetized consulting
  named (`LICENSE:22-33`). `NOTICE.md` is the standard DOE/LLNL disclaimer
  (Contract DE-AC52-07NA27344); the release number **LLNL-CODE-2013290**
  appears only at `README.md:600`. GitHub reports the license as
  NOASSERTION (GitHub API, 2026-11-01) while `pyproject.toml:7` claims plain
  "BSD-3-Clause" and the README badge says the same (`README.md:6`) — the
  strict text is a source-available non-commercial license, not OSI BSD-3.
- **`CODE_OF_CONDUCT.md`** (46): hand-written mini code of conduct (not the
  Contributor Covenant template).
- `images/`: 3 PNGs (design.png, function-summaries.png, renaming-ui.png).
- Stale pointers: README's Support section links GitHub **Discussions**, which
  is switched off (`README.md:607` vs API `has_discussions: false`); README
  never mentions the PyPI package it publishes, nor the Docker image
  (measured `grep -in "pypi|docker" README.md` → only `pip install -r`);
  contact is a personal Gmail (`README.md:608`, `pyproject.toml:9`).

## Sources

- Read-only clone `/tmp/opencode/OGhidra` @ `6224d26` (branch `main`,
  last commit 2026-10-28), clean tree, all remote branches fetched. Batteries
  run in-clone: `git ls-files | wc -l` (139), `git ls-files -z | xargs -0
  wc -l` (52,761 total), per-area `find … | xargs wc -l` (src 35,209 py + 811
  data, tests 3,959, benchmark 3,132, java 2,066), module heads (first ~12
  lines of all 63 src files), `grep -o 'env="[A-Z_]*"' src/config.py` (91) vs
  `.env.example` keys (72) vs `os.getenv` census (comm battery at
  `/tmp/{cfgenv,envkeys,getenv,allcfg}.txt`), `grep -c 'def test_' tests/*.py`
  (134), unittest/pytest import census, FAISS and benchmark-dep greps,
  `git ls-remote --heads origin` (12 branches, no `pyghidra`), `git log --`
  per file for doc-maintenance (tool_capabilities, ai_ghidra_capabilities,
  docs/*), LICENSE/NOTICE/pyproject/Dockerfile/release.yml/pre-commit/gradle
  full reads, `git show` of `5fa72ea`'s initial tree (54 files, bridge.py at
  4,761) and of `71da7d7` (C++ placeholder).
- GitHub REST API via `gh api` (2026-11-01): `/languages`, `/contributors`,
  `/releases` (0), `/tags` (v0.0.0), repo metadata (`license.spdx_id
  NOASSERTION`, `has_discussions false`, `has_wiki true`, `size 3832`).
- PyPI JSON API `https://pypi.org/pypi/oghidra/json` (2026-11-01): single
  release 0.0.0, 2026-08-14.
- Cross-chapter: [21-history-and-releases](21-history-and-releases.md)
  (branches, PRs, release forensics); [00-scope-and-method](00-scope-and-method.md)
  pins the revisions; [10-calxgloss-baseline](10-calxgloss-baseline.md) is the
  comparison anchor.

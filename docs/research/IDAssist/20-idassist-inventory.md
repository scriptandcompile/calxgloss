# 20 — IDAssist repository inventory

> Part of the [overview](README.md). All facts below were verified against a read-only clone of `IDAssist` at HEAD `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302` (commit date 2026-09-20 14:44:17 -0400; 76 commits; version 2.4.0), working tree clean (`git status --porcelain` → 0 lines), verified 2026-11-01. All paths are clone-relative; line numbers were confirmed with `grep -n`.

## 1. Repository layout at a glance

Tracked files: `git ls-tree -r HEAD --name-only | wc -l` → **154**. Top level (`ls -a`):

```
docs/  src/  tests/  .git  .gitignore  ida-plugin.json  idassist_plugin.py
LICENSE  README.md  requirements.txt
```

Python LOC (`find … -name '*.py' | xargs wc -l`) → **55,326 lines total** across **128** Python files (`git ls-tree -r HEAD --name-only | grep -c '\.py$'` → 128; 154 tracked = 128 py + 12 docs `.md` + 9 screenshots + README/LICENSE/ida-plugin.json/requirements.txt/.gitignore). *Corrected 2026-11-02 during the full fact-check: an earlier draft said 99 Python files, which contradicted both this command and the per-directory table below (it sums to 128).*

Per-directory Python totals (`find <dir> -maxdepth 1 -name '*.py' -exec cat {} + | wc -l`):

| Directory | .py files | LOC | Role |
|---|---:|---:|---|
| `src/` (root) | 3 + `__init__` | 389 | compat shims + worker: `ida_compat.py` (137, "IDA Compatibility Layer — logging, main-thread execution", `src/ida_compat.py:3-4`), `qt_compat.py` (130, "PySide6 … tried first; falls back to PyQt5", `src/qt_compat.py:2-3`), `daemon_worker.py` (117, async threading bridge) |
| `idassist_plugin.py` (top level) | 1 | 313 | IDA entry point: plugin classes with `activate`/`update` (`idassist_plugin.py:49-123`), IDA event hooks (`renamed`, `func_added`, `finish_populating_widget_popup`, `idassist_plugin.py:134-164`) |
| `src/controllers/` | 11 | 13,421 | one controller per tab + threads (`react_thread.py`, `actions_llm_thread.py`) + `chat_edit_manager.py` |
| `src/views/` | 10 | 5,861 | one tab view per tab + `idassist_form.py` (shell) + `streaming_markdown_browser.py` |
| `src/views/semantic_graph/` | 2 | 234 | `manual_analysis_panel.py` (229) |
| `src/services/` (direct) | 25 | 13,483 | core services: settings, llm, rag, symgraph, analysis DB, MCP, transcripts, streaming-adjacent |
| `src/services/graphrag/` | 15 | 5,919 | semantic knowledge-graph extraction & query |
| `src/services/llm_providers/` | 17 | 9,858 | 10 provider implementations + OAuth utilities + factory |
| `src/services/migrations/` | 10 | 645 | small settings-DB migrations (one file per migration) |
| `src/services/models/` | 12 | 1,971 | Pydantic/dataclass models (`llm_models.py`, `symgraph_models.py` 656 LOC largest) |
| `src/services/react/` | 5 | 1,375 | ReAct agent: orchestrator (797), prompts, findings cache, todo list |
| `src/services/streaming/` | 5 | 457 | streaming render: block boundary, reasoning filter, render update, renderer (239) |
| `tests/` | 10 | 1,400 | 10 test modules (incl. one `__init__.py` row in §3's table; §1's per-dir count excludes that 1-LOC marker) |

Biggest files and what they hold (all `wc -l`):

| File | LOC | Content |
|---|---:|---|
| `src/controllers/query_controller.py` | 4,190 | Query-tab chat/agent logic (largest file in repo) |
| `src/controllers/explain_controller.py` | 2,155 | Explain-tab logic |
| `src/controllers/settings_controller.py` | 2,109 | Settings-tab logic |
| `src/controllers/symgraph_controller.py` | 2,051 | SymGraph collaboration-tab logic |
| `src/services/analysis_db_service.py` | 1,931 | SQLite analysis store |
| `src/views/symgraph_tab_view.py` | 1,422 | SymGraph tab UI |
| `src/views/semantic_graph_tab_view.py` | 1,409 | Semantic Graph tab UI |
| `src/services/symgraph_service.py` | 1,215 | SymGraph sync service |
| `src/services/graphrag/graph_store.py` | 1,147 | graph persistence |
| `src/services/llm_providers/openai_oauth_provider.py` | 1,128 | ChatGPT OAuth provider |

*(inference)* the file-role descriptions in this table follow the tab names documented in `docs/tabs/`; I did not read these files end-to-end.

## 2. Packaging & install surface

### `ida-plugin.json` (35 lines, IDA Plugin Manager manifest)

Every field, with verified line (`grep -n` output):

| Field | Value | Line |
|---|---|---|
| `IDAMetadataDescriptorVersion` | `1` | :2 |
| `plugin.name` | `"IDAssist"` | :4 |
| `plugin.entryPoint` | `"idassist_plugin.py"` | :5 |
| `plugin.version` | `"2.4.0"` | :6 |
| `plugin.description` | "AI-powered reverse engineering plugin with LLM analysis, semantic knowledge graphs, RAG search, and SymGraph collaboration" | :7 |
| `plugin.license` | `"MIT"` | :8 |
| `plugin.urls.repository` | `https://github.com/symgraph/IDAssist` | :10 |
| `plugin.authors` | Jason Tang `<jason.tang@badc0ded.net>` | :12-17 |
| `plugin.categories` | `integration-with-third-parties-interoperability`, `api-scripting-and-automation` | :18 |
| `plugin.idaVersions` | `9.1`, `9.2`, `9.3`, `9.4` | :19 |
| `plugin.logoPath` | `docs/screenshots/icon.png` | :20 |
| `plugin.keywords` | llm, ai, reverse-engineering, analysis, knowledge-graph, symgraph | :21 |
| `plugin.pythonDependencies` | openai, anthropic, pysqlite3, markdown, httpx, anyio>=4.6, mcp==1.23.3, whoosh, aiohttp, pywin32 (Windows only) | :22-33 |

Note: the manifest repo URL is `symgraph/IDAssist` (`ida-plugin.json:10`) while the README links releases at `jtang613/IDAssist` (`README.md:89`) — org fork/rename discrepancy, worth flagging.

### `requirements.txt` (11 lines)

Identical to `pythonDependencies` **plus `boto3`** (requirements.txt:1; absent from the manifest — needed only by the Bedrock provider, `src/services/llm_providers/bedrock_provider.py`, 706 LOC). Purposes: openai (OpenAI-compatible APIs), anthropic (Claude API), pysqlite3 (bundled SQLite), markdown (chat rendering), httpx + anyio>=4.6 + aiohttp (HTTP/async transports), mcp==1.23.3 pinned exactly (Model Context Protocol client, `src/services/mcp_client.py`), whoosh (search index, used by RAG — inference), pywin32 gated to Windows (named pipes on Windows — inference). All purposes are *(inference)* except the pin/version literals, which are verbatim.

### Install flows

- **IDA Plugin Manager (recommended):** `README.md:79` "Install the plugin (recommended — IDA Plugin Manager)", command `hcli plugin install idassist` at `README.md:82`; "This automatically installs the plugin and its Python dependencies into IDA's environment." (`README.md:85`). Same flow in `docs/getting-started.md:19`.
- **Release tarball:** `README.md:87-89` "Or install manually (from release tarball)" — download the latest release zip from GitHub Releases and extract into the IDA plugins directory; then install dependencies with **IDA's bundled Python**, not system Python: `<IDA_INSTALL_DIR>/python3/bin/pip3 install -r ~/.idapro/plugins/IDAssist/requirements.txt` (`README.md:103`) and the Windows variant `"<IDA_INSTALL_DIR>\python3\python.exe" -m pip install -r "%APPDATA%\Hex-Rays\IDA Pro\plugins\IDAssist\requirements.txt"` (`README.md:108`).
- **IDAUSR:** "You can also set the `IDAUSR` environment variable to a custom directory containing a `plugins/` subdirectory." (`README.md:113`, repeated `docs/getting-started.md:50`).

## 3. Test suite

All tests are stdlib `unittest`, run via `sys.path.insert` (`tests/test_bedrock_provider.py:9`), heavily `unittest.mock`-based. **No IDA imports anywhere in tests**: `grep -rn 'import ida\|idaapi\|ida_ida' tests/ | wc -l` → 0. No network: providers are patched out (e.g. `patch("…OpenAI")`, `tests/test_openwebui_provider.py:34-35`). No test needs IDA. **No pytest/unittest run instructions exist in README or docs**: `grep -rn -i 'pytest\|unittest' README.md docs/` → no output.

| Test file | LOC | What it tests | Needs IDA / network? |
|---|---:|---|---|
| `tests/test_bedrock_provider.py` | 462 | BedrockProvider chat via "mocked boto3" / "mocked Converse API" (docstrings :1, :33; the "Converse API" docstring specifically is :30) | no / no |
| `tests/test_litellm_provider.py` | 175 | "LiteLLM/Bedrock compatibility handling" (:1) | no / no |
| `tests/test_bedrock_migration.py` | 150 | Bedrock DB migration, idempotent, real `sqlite3` + `tempfile` (:5, :7) | no / no |
| `tests/test_settings_service.py` | 159 | settings service on real sqlite3/tempfile (:5-6) | no / no |
| `tests/test_openwebui_provider.py` | 129 | "OpenWebUI provider URL and transport handling" (:1), `AsyncMock`/`patch` (:7) | no / no |
| `tests/test_bedrock_factory.py` | 102 | "Bedrock provider factory registration" (:1), `patch` (:6) | no / no |
| `tests/test_provider_types.py` | 76 | "ProviderType enum — verifies BEDROCK and existing providers" (:1) | no / no |
| `tests/test_qt_compat.py` | 49 | static AST check that every symbol consumers import from `qt_compat` exists (:3, :30-31) | no / no |
| `tests/test_bedrock_message_format.py` | 51 | "Bedrock Query-tab message formatting support" (:1) | no / no |
| `tests/test_settings_workers.py` | 46 | `src.daemon_worker.DaemonWorker` threading (:11) | no / no |
| `tests/__init__.py` | 1 | package marker | — |

**Untested subsystems** (no file in `tests/` imports them; verified by cross-checking the test imports above against the file list in §1): all 11 controllers, all 10 views, the entire `graphrag/` package, `rag_service.py`, `react/`, all 5 `mcp_*` modules, `symgraph_service.py`, `analysis_db_service.py`, `context_window_manager.py`, `streaming/`, `transcript_*`, `binary_context_service.py`, `function_summary_service.py`, OAuth files, `ida_compat.py`, `idassist_plugin.py`, and 8 of 10 provider implementations (Anthropic, OpenAI platform, OpenAI OAuth, Gemini OAuth, Ollama, LiteLLM itself, Claude CLI, base provider — only Bedrock/OpenWebUI/LiteLLM-compat paths are touched). Test coverage is essentially "Bedrock provider + settings plumbing + qt_compat guard".

## 4. CI & tooling — verified absences

- **No CI config, no build files, no linter/type-checker config, no pre-commit.** Proof commands (run in clone root):
  - `ls -a` → only the 10 entries listed in §1 (no `.github`, no hidden tooling).
  - `find . -path ./.git -prune -o \( -name pyproject.toml -o -name setup.py -o -name setup.cfg -o -name tox.ini -o -name Makefile -o -name Dockerfile -o -name .pre-commit-config.yaml -o -name '*.cfg' -o -name .github -o -name .gitlab-ci.yml \) -print` → **no output**.
  - Consequently no pinned dev tooling, no venv guidance, no test runner config; tests are bare stdlib.
- **License:** MIT — `LICENSE` is the 7-line short MIT text, `Copyright (c) 2026 Jason Tang`, standard permission/condition paragraphs; also declared `"license": "MIT"` (`ida-plugin.json:8`).
- `.gitignore` is a single line.

## 5. Docs tree

12 markdown files + 9 screenshots (`docs/screenshots/`: `main_interface.png` 840 KB, `query_tab.png` 756 KB, `semantic_graph_tab.png` 723 KB, `explain_tab.png` 700 KB, `settings_tab.png` 653 KB, `actions_tab.png` 623 KB, `rag_tab.png` 588 KB, `icon.png` 118 KB, `slideshow.gif` 2.29 MB — sizes from `ls -la`).

| File | LOC | One-line content |
|---|---:|---|
| `docs/index.md` | 128 | Hub: "What is IDAssist?", Tabs Overview, Key Features (MCP tools, ReAct agent, extended thinking, semantic graph), Supported LLM Providers + Recommended Models, Architecture Overview (TOC lines 8-118) |
| `docs/getting-started.md` | 220 | Install (hcli line 19, IDAUSR tip line 50), provider setup, first use |
| `docs/tabs/query-tab.md` | 138 | Query Tab Reference |
| `docs/tabs/settings-tab.md` | 154 | Settings Tab Reference |
| `docs/tabs/semantic-graph-tab.md` | 169 | Semantic Graph Tab Reference (results-table columns line 128) |
| `docs/tabs/symgraph-tab.md` | 147 | SymGraph Tab Reference |
| `docs/tabs/actions-tab.md` | 99 | Actions Tab Reference (confidence column line 28) |
| `docs/tabs/explain-tab.md` | 92 | Explain Tab Reference |
| `docs/tabs/rag-tab.md` | 75 | RAG Tab Reference |
| `docs/workflows/explain-workflow.md` | 113 | "Workflow: Analyzing Functions with the Explain Tab" |
| `docs/workflows/query-workflow.md` | 165 | "Workflow: Querying with the Query Tab" |
| `docs/workflows/semantic-graph-workflow.md` | 140 | "Workflow: Building a Knowledge Graph…" |

Structure: an `index.md` hub linking **7 tab references** (mirroring the 7 UI tabs) and **3 task-oriented workflows**; `README.md:144` links into `docs/index.md#recommended-models`. Plain markdown (no mkdocs/Sphinx config — same `find` as §4). Screenshots per tab plus a slideshow GIF. Docs total 1,640 md LOC plus 187-line README.

## 6. Architecture at a glance (file level)

- **Views (10 + 2):** `actions_tab_view.py`, `explain_tab_view.py`, `query_tab_view.py`, `rag_tab_view.py`, `semantic_graph_tab_view.py`, `settings_tab_view.py`, `symgraph_tab_view.py`, `idassist_form.py`, `streaming_markdown_browser.py`.
- **Controllers (11):** `actions_controller.py`, `explain_controller.py`, `query_controller.py`, `rag_controller.py`, `semantic_graph_controller.py`, `settings_controller.py`, `symgraph_controller.py`, plus thread helpers `react_thread.py`, `actions_llm_thread.py`, and `chat_edit_manager.py`.
- **Services:** 25 at `src/services/` top level (actions, analysis_db, binary_context, context_window_manager, db_migrations, function_summary, internal_tools, llm, 5× mcp_*, message_format, rag, rlhf, service_registry, settings, symgraph, tool_approval, 2× transcript, action-tools) + 6 subpackages: `graphrag/` (15 files), `llm_providers/` (17), `migrations/` (10), `models/` (12), `react/` (5), `streaming/` (5).
- **No `src/models/`** — data models live at `src/services/models/` (`ls`-verified from the §1 tree).
- **Naming convention:** `X_tab_view.py` ↔ `X_controller.py` ↔ `X_service.py`, one file per class per layer.
- **Wiring convention:** the shell `src/views/idassist_form.py` lazily imports each controller and constructs it over its view, then `addTab`s it — e.g. `from src.controllers.explain_controller import ExplainController` / `ExplainController(self.explain_view)` / `addTab(..., "Explain")` at `src/views/idassist_form.py:176-180`; same pattern at :164-168 (Settings), :198-202 (Query), :220-224 (Actions), :240-244 (Semantic Graph), :261-265 (RAG), :273-280 (SymGraph). Services are reached through a DI container: `ServiceRegistry` — "Dependency injection container for services" (`src/services/service_registry.py:3-5`), initializing in dependency order starting with settings (`:31-40`).

## 7. Effectiveness claims, eval, benchmarks — verified negative

- `grep -rn -i -E '\beval\b|\bevals\b|evaluation' --exclude-dir=.git .` → **no output**: no eval harness, no eval docs, no eval vocabulary anywhere.
- `grep -rn -i -E 'benchmark|accuracy' --exclude-dir=.git .` → **no output** (the 22 hits for `corpus` are all TF-IDF document-corpus internals in `src/services/rag_service.py:75-922`).
- `grep -rn -i -E '\bscore\b'` hits are UI relevance/confidence values (e.g. `src/services/models/rag_models.py:20 score: float`; results-table column `src/views/semantic_graph_tab_view.py:1167`) plus internal sort keys in the graph query engine (`graphrag/query_engine.py:112`) — nothing in the shape of scored evaluation artifacts.

**Conclusion:** IDAssist v2.4.0 makes no quantitative effectiveness or accuracy claims and ships no benchmarks or eval corpora; its README/docs describe features, not measured performance.

## Limitations

- Largest files (query/symgraph/settings/explain controllers, analysis_db_service) were classified by name, docstring, and grep only — not read end-to-end (~10.3k LOC unread in detail).
- Dependency-purpose statements in §2 are labeled inferences; pin literals are verbatim.
- `git log` history beyond HEAD count (76 commits) and HEAD date was not analyzed (out of scope for inventory).

## Sources

- Read-only clone `/tmp/opencode/IDAssist` at HEAD `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302` (2026-09-20), verified 2026-11-01.
- Commands used for proofs: `git rev-parse HEAD`, `git status --porcelain`, `git ls-tree -r HEAD`, `find`, `wc -l`, `ls -a`, `ls -la docs/screenshots/`, `grep -n`/`grep -rn` invocations quoted inline in each section, `sed -n` for module docstrings.
- Cited files: `ida-plugin.json`, `requirements.txt`, `README.md`, `LICENSE`, `docs/index.md`, `docs/getting-started.md`, `docs/tabs/*`, `docs/workflows/*`, `tests/*`, `src/views/idassist_form.py`, `src/services/service_registry.py`, `src/ida_compat.py`, `src/qt_compat.py`, `idassist_plugin.py`, plus targeted greps across `src/`.

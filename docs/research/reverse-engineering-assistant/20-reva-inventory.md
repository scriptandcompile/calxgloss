# ReVa complete inventory + calxgloss-relevance triage

> Part of the [ReVa overview](README.md). The complete surface of ReVa: every
> package, MCP tool, skill, doc and test suite, with `path:line` citations
> relative to the clone root `/tmp/opencode/cyberkaida-rea` @ `a2fcd94`
> (2026-10-27). Later chapters can cite this file instead of re-deriving the map.
>
> **Size**: 27,773 LOC Java in `src/main` (87 files); 44,934 Java LOC incl. tests;
> `src/reva_cli` 879 LOC Python; `tests/` ~8,400 LOC Python.
> **Counts**: **88 MCP tools** across **19 tool providers** in **6 tool groups**;
> **1 MCP resource**; **6 skills**; **2 subagents**; Ghidra 12.0+ (12.2 needs Java 25, `README.md:53`).

## 1. Repo anatomy

| Path | What it holds |
|------|----------------|
| `src/main/java/reva/` | Java extension: `plugin/` (entry points + config), `server/` (MCP over Jetty), `tools/` (19 tool providers, 19 sub-packages), `services/` (background job managers), `resources/` (MCP resources), `headless/`, `ui/`, `debug/`, `util/` |
| `src/main/help/help/topics/ReVa/` | Ghidra help HTML: `ReVa_overview.html`, `ReVa_installation.html`, `ReVa_skills.html` |
| `src/test/java/reva/` | 36 fast Java unit tests (no Ghidra runtime) |
| `src/test.slow/java/reva/` | 50 Java integration tests (real Ghidra TestEnv; gradle `integrationTest` sourceSet, `build.gradle:67-73,169`) |
| `src/reva_cli/` + `src/CLAUDE.md` | Python `mcp-reva` CLI (`__main__.py`, `launcher.py`, `project_manager.py`, `stdio_bridge.py`); source-dir guide with test/address-format rules |
| `tests/` | Pytest headless/e2e suite + `tests/fixtures/` (ELF, x86_64/ARM64, Mach-O fat binary, C/C++ sources) |
| `ReVa/` | Claude Code plugin package: `.claude-plugin/plugin.json`, `.mcp.json`, `skills/` (6), LICENSE |
| `.claude/`, `.claude-plugin/`, `.continue/` | Dev-workspace config: agents, hooks, `marketplace.json`; two Continue docs-registry yamls (MCP Java SDK site, placeholder) |
| `.github/workflows/` | 6 workflows (§9); plus `copilot-instructions.md`, `CI_WORKFLOWS.md`, `WORKFLOW_SETUP.md`, `dependabot.yml` |
| `config/reva-headless-example.properties` | Every headless setting documented as properties |
| `lib/` | Drop-in jars (populated by build from `implementation` deps, `build.gradle:109`) |
| Root files | `build.gradle`, `pyproject.toml` (+`uv.lock`), `extension.properties`, `Module.manifest` (dep: `Ghidra/Features/VersionTracking`), `DEVELOPER.md`, `CLAUDE.md`, `AGENTS.md` (condensed), `README.md` (design thesis: small tools, context-rot reduction) |

## 2. MCP tool surface — 88 tools

Registration: each `ToolProvider` builds `McpSchema.Tool.builder().name(...)` and
calls `registerTool()` (`src/main/java/reva/tools/AbstractToolProvider.java:53`;
interface `tools/ToolProvider.java:15-48` incl. `unregisterTools()` for runtime
group toggling). Providers are constructed per-group in
`src/main/java/reva/server/McpServerManager.java:227-258`. Citations below are
the `.name("...")` line in each provider file.

**CORE_ANALYSIS — 39 tools**
| Provider (`src/main/java/reva/tools/…`) | Tools |
|---|---|
| `symbols/SymbolToolProvider.java`, `strings/StringToolProvider.java` | `get-symbols-count:60`, `get-symbols:111`, `get-strings-count:89`, `get-strings:131` — count-first pagination is a house pattern |
| `functions/FunctionToolProvider.java` | `get-function-count:355`, `get-functions:444`, `get-functions-by-similarity:582`, `set-function-prototype:966`, `get-undefined-function-candidates:1169`, `create-function:1371`, `function-tags:1506` |
| `decompiler/DecompilerToolProvider.java` | `get-decompilation:697` (xref/namespace reinforcement), `search-decompilation:1011`, `rename-variables:1080`, `change-variable-datatypes:1221`, `set-decompilation-comment:1841`, `get-callers-decompiled:2001`, `get-referencers-decompiled:2167` |
| `memory/MemoryToolProvider.java`, `xrefs/CrossReferencesToolProvider.java` | `get-memory-blocks:66`, `read-memory:121`, `find-cross-references:113` |
| `constants/ConstantSearchToolProvider.java`, `imports/ImportExportToolProvider.java` | `find-constant-uses:62`, `find-constants-in-range:96`, `list-common-constants:136`, `list-imports:66`, `list-exports:111`, `find-import-references:144`, `resolve-thunk:196` |
| `project/ProjectToolProvider.java` | `get-current-program:126`, `list-project-files:176`, `list-open-programs:246`, `checkin-program:304`, `analyze-program:701`, `analysis-status:914`, `analysis-cancel:1041`, `list-analyzers:1169`, `change-processor:1318`, `import-file:1467`, `capture-reva-debug-info:1966` |

**DATA_AND_TYPES — 13 tools**
| Provider | Tools |
|---|---|
| `data/DataToolProvider.java`, `datatypes/DataTypeToolProvider.java` | `get-data:69`, `apply-data-type:97`, `create-label:190`, `get-data-type-archives:64`, `get-data-types:171`, `get-data-type-by-string:265` |
| `structures/StructureToolProvider.java` | `parse-c-structure:68`, `validate-c-structure:192`, `get-structure-info:251`, `list-structures:290`, `apply-structure:373`, `delete-structure:450`, `parse-c-header:571` |

**ADVANCED_ANALYSIS — 9 tools**
| Provider | Tools |
|---|---|
| `callgraph/CallGraphToolProvider.java` | `get-call-graph:57`, `get-call-tree:117`, `find-common-callers:166` |
| `dataflow/DataFlowToolProvider.java` | `trace-data-flow-backward:68`, `trace-data-flow-forward:99`, `find-variable-accesses:130` |
| `vtable/VtableToolProvider.java` | `analyze-vtable:87`, `find-vtable-callers:115`, `find-vtables-containing-function:156` |

**DIFF — 13 tools** (`tools/diff/DiffToolProvider.java`, backed by Ghidra VersionTracking):
`diff-list-sessions:56`, `diff-delete-session:78`, `diff-summary:314`, `diff-list-functions:376`,
`diff-function:542`, `diff-strings:680`, `diff-data:701`, `diff-transfer-markup:821`,
`diff-apply-match:876`, `diff-status:959`, `diff-cancel:1065`, `diff-create-session:1146` (async),
`diff-add-correlator:1232`.

**ANNOTATIONS — 9 tools** — `comments/CommentToolProvider.java`: `set-comment:73`,
`get-comments:151`, `remove-comment:233`, `search-comments:300`;
`bookmarks/BookmarkToolProvider.java`: `set-bookmark:64`, `get-bookmarks:146`,
`remove-bookmark:242`, `search-bookmarks:327`, `list-bookmark-categories:405`.

**SCRIPTING — 5 tools** (`tools/scripts/ScriptToolProvider.java`; requires Ghidra
launched under PyGhidra, `:62`): `run-script:166`, `list-scripts:312`, `read-script:381`,
`write-script:452`, `edit-script:528`. Support classes in the same dir:
`PythonScriptExecutor`, `ScriptFileEditor`, `ScriptDirectoryManager`, `CappedWriter`,
`GhidraScriptRunner`.

**Non-tool surface**: 1 MCP resource `ghidra://programs` / "open-programs"
(`resources/impl/ProgramListResource.java:41-42`, registered `McpServerManager.java:207`);
capabilities advertise prompts but **no prompt is ever registered** (`McpServerManager.java:161-165`).

## 3. Tool groups / enable-disable mechanism

- Enum `plugin/ToolGroup.java:26-32`: `CORE_ANALYSIS`, `DATA_AND_TYPES`,
  `ADVANCED_ANALYSIS`, `DIFF`, `ANNOTATIONS`, `SCRIPTING`; kebab-case `canonicalId()`
  and flexible `fromId()` parsing (`:51-77`).
- One boolean per group in config, default **all enabled** (`ConfigManager.java:75`,
  registration `:225-228`, getter/setter `:674-684`).
- Startup registers only enabled groups (`McpServerManager.java:218-224`); **runtime
  toggle**: config-change listener maps the option display name back to a group and
  adds/removes tools live (`McpServerManager.java:691` +
  `AbstractToolProvider.unregisterTools():82-87`).
- CLI flags `--disable-tool-group GROUP` / allowlist `--tool-group GROUP`
  (`src/reva_cli/__main__.py:140-154`) pushed to the Java launcher via
  `setDisabledToolGroups/setEnabledToolGroups` (`launcher.py:45-54`).
- Tests: `src/test/.../plugin/{ConfigManagerToolGroupTest,ToolGroupTest}.java`,
  `tools/AbstractToolProviderUnregisterTest.java`,
  `src/test.slow/.../server/ToolGroupRegistrationIntegrationTest.java` +
  `headless/HeadlessLauncherToolGroupIntegrationTest.java`, python
  `tests/test_tool_group_cli{,_e2e}.py` + `test_tool_group_toggle_integration.py`.

## 4. Java package map

| Class | Role |
|---|---|
| `plugin/RevaPlugin.java:46` | `ProgramPlugin` (per-tool, per-program lifecycle) |
| `plugin/RevaApplicationPlugin.java:50` | `ApplicationLevelOnlyPlugin` + `ProjectListener` — owns the app-level MCP server so it works from the project window |
| `server/McpServerManager.java` | Builds `McpSyncServer` (SDK mcp-bom 2.1.0, `build.gradle:111`), Jetty 12 ee10 servlet on `/mcp/message` (streamable HTTP; endpoint const `:85`, handler `:335-351`), group lifecycle |
| `server/ResilientStreamableServerTransportProvider.java:21-30` | Fork of the SDK transport: keeps the MCP session alive across failed GET-stream writes (Last-Event-ID replay) |
| `server/ApiKeyAuthFilter.java:42` | `X-API-Key` header auth when enabled |
| `server/RequestLoggingFilter`, `server/PublicBindingConsentDialog` | opt-in `reva-tools.log`; GUI consent / headless refusal for `0.0.0.0` bind without API key |
| `plugin/ConfigManager.java` + `plugin/config/*` | settings backend over Ghidra ToolOptions (GUI), properties file, or in-memory (headless) |
| `plugin/RevaProgramManager.java:41`, `FollowMeService.java:44` | program open/close registry; "follow-me" navigates the GUI to what a tool read/wrote |
| `services/AnalysisJobManager.java:25`, `DiffJobManager.java:18` + Runners/JobLog/JobStatus | async job machinery behind `analyze-program` and the diff tools |
| `headless/RevaHeadlessLauncher.java:61,474` | Java headless server entry point, callable from PyGhidra (`:41-46`) |
| `debug/DebugCaptureService.java:39`, `DebugInfoCollector` | support bundle behind `capture-reva-debug-info` |
| `ui/RevaProvider.java:34`, `FollowMeAction`, `CaptureDebugAction` | GUI component provider + toolbar actions |
| `util/` | `AddressUtil`, `SchemaUtil`, `ToolResultBuilder`, `SimilarityComparator`, `RevaInternalServiceRegistry`, `DecompilationDiffUtil`, `VersionTrackingUtil`… |

**Settings** (keys `ConfigManager.java:44-66`, defaults `:69-88`; properties form in
`config/reva-headless-example.properties`): server port (default **8080**) / host
(127.0.0.1) / enabled; API-key auth off + auto-generated key; debug mode; request
logging; max-decompiler-search-functions 1000; decompiler timeout 10s; import timeout
120s; import-analysis timeout 600s; wait-for-analysis-on-import **false** (LLM clients
call `analyze-program` explicitly); import max archive depth 10; analysis timeout 600s;
follow-reads/follow-writes true; script timeout 60s; script output char limit 65536;
allow-public-binding-without-key false; + 6 tool-group booleans.

## 5. Python side (`src/reva_cli`, console script `mcp-reva`)

- `pyproject.toml`: package `reverse-engineering-assistant`,
  `mcp-reva = "reva_cli.__main__:main"`, deps `pyghidra>=3.1.0`, `mcp>=2.3,<3`,
  `httpx2`; version from git tags via setuptools_scm.
- `__main__.py:118-154`: flags `--config`, `--verbose`, `--version` (3.0.0), the two
  tool-group flags. Boot (`main():157-196`): `pyghidra.start()` → lazy
  `ProjectManager` → random API key `ReVa-<uuid4>` unless `--config` →
  `ReVaLauncher(use_random_port=True)` → stdio bridge.
- `launcher.py:12` `ReVaLauncher`: imports the **Java**
  `reva.headless.RevaHeadlessLauncher` in-process via PyGhidra's JVM (`:68,97`) and
  pushes tool-group lists before start.
- `project_manager.py:14` `ProjectManager`: temp Ghidra project per session,
  `import_binary():122`, cleanup.
- `stdio_bridge.py`: `ReconnectingBackend:80` + `ReVaStdioBridge:145` — presents stdio
  MCP to the agent while proxying to the private authenticated HTTP backend,
  auto-reconnecting (client-side mirror of the Java transport's resilience).

## 6. Claude Code marketplace & skills

- Marketplace: `.claude-plugin/marketplace.json` (plugin source `./ReVa`); plugin
  manifest `ReVa/.claude-plugin/plugin.json` (v0.1.0); MCP wiring `ReVa/.mcp.json`:
  `uv run mcp-reva`.
- **6 skills** (`ReVa/skills/*/SKILL.md`, SKILL.md lines): `binary-triage` (155 —
  survey memory layout/strings/imports/functions), `deep-analysis` (607 + `patterns.md`
  + `examples.md` — depth-first question answering with a rename/retype/comment
  improvement loop, evidence-based answers), `ctf-rev` (548 + patterns), `ctf-pwn`
  (532 + patterns), `ctf-crypto` (323 + patterns), `pyghidra-scripting` (240 + 5
  references: `flat-api`, `decompiler-pcode`, `jpype-interop`, `persistent-scripts`,
  `recipes` — when to drop into `run-script`).
- Dev-side agents `.claude/agents/`: `ghidra-api-expert.md` (Ghidra API
  investigator), `reva-setup-installer.md` (build-env fixer). Hooks:
  `.claude/settings.json` SessionStart → `hooks/setup-remote-env.sh` (installs
  JDK/Gradle/Ghidra in Claude Code web envs); `hooks/gradle-proxy.py`; `launch.json`.

## 7. Docs

- `DEVELOPER.md` (20.9 KB): architecture; why an app-plugin **and** a tool-plugin
  (`:89-124`); adding resources (`:185`) and tools (`:245`); best practices; test
  categories; debugging.
- `CLAUDE.md` (15.3 KB): build/test commands, structure, core components; `AGENTS.md`
  is its 3.5 KB condensation. `src/CLAUDE.md`: test placement, address-format rules,
  decompiler-tool implementation patterns, utility usage. **33** `CLAUDE.md`
  files repo-wide — 29 under `src/main/java/reva/` (roughly one per package),
  plus root, `src/`, and test-tree copies; `src/test.slow/CLAUDE.md` documents the
  shared-TestEnv integration pattern (fork-per-test, headed).
- `.continue/docs/new-doc.yaml` registers the MCP Java SDK docs site for Continue
  (`new-doc-1.yaml` placeholder). `.github/copilot-instructions.md` for Copilot.
  Ghidra in-product help: `src/main/help/help/topics/ReVa/` (overview/installation/skills).

## 8. Test suites

| Suite | Coverage |
|---|---|
| `src/test/java/reva/` (36 files, `gradle test`) | No-Ghidra units: ConfigManager (change/port/script-options/tool-group), FollowMeService, transport resilience, PublicBindingConsentDialog, AnalysisJob/DiffJob managers + JobLog, provider unregister, PythonScriptExecutor/ScriptFileEditor units, util tests (Address, Schema, Symbol, ToolResult, VersionTracking, DecompilationDiff) |
| `src/test.slow/java/reva/` (50 files, `gradle integrationTest`) | Real Ghidra + MCP client, one integration test set per tool provider; diff session persistence / staged correlators / cancel / async transfer-markup; analysis job cancel-on-close; headless launcher API-key + tool-group; public-binding guard/revert; server restart initialize; random-port regression |
| `tests/` (17 pytest files, markers unit/integration/e2e/cli/slow) | PyGhidra smoke, launcher lifecycle, MCP tool connectivity, config parsing, CLI e2e + project-manager units, API-key injection, e2e workflow, diff / import / run-script e2e, tool-group CLI + live-toggle, VS Code MCP-client compat, tool-result "workflow correctness"; fixtures: ELF x86_64/ARM64, C++ variants, Mach-O fat, dataflow C |

## 9. Build / release

- `build.gradle`: delegates to Ghidra's `support/buildExtension.gradle`
  (`distributeExtension:45`, `install:53` into `Ghidra/Extensions`); deps: MCP SDK
  2.1.0, Jetty 12.1.14, jakarta servlet 6.1, Jackson; `test` + `integrationTest`
  tasks; `check` depends on both (`:203`). No gradle wrapper — system `gradle` 9.1+
  (`DEVELOPER.md:141`). `extension.properties` `version=@extversion@` — injected from
  the git tag at release time.
- Workflows: `test-ghidra.yml` (Ghidra-version matrix, Java 25, unit + integration),
  `test-headless.yml` (python headless matrix), `publish-ghidra.yml` (GitHub release →
  extension zip per Ghidra version), `publish-pypi.yml` (release → PyPI), `claude.yml`,
  `copilot-setup-steps.yml`; `dependabot.yml`.
- Four independent version schemes: PyPI (setuptools_scm tags), Ghidra extension
  `@extversion@`, MCP `serverInfo("ReVa","1.0.0")` (`McpServerManager.java:86-87`),
  `mcp-reva --version` 3.0.0 + plugin.json 0.1.0.

## 10. Triage — ReVa capability areas vs. calxgloss (Windows PE → Rust harness)

Legend: ● high — directly informs/feeds the harness; ◐ medium — one chapter or
pattern; ○ low — inventory-only.

| ReVa area | Relevance | Why for calxgloss |
|---|---|---|
| Decompiler + search/rename/retype tools (7) | ● | Core PE→pseudo-C loop; the reinforcement-with-xrefs output shape is the model for our decompile payloads |
| Function tools incl. `get-undefined-function-candidates`, `create-function`, prototypes | ● | PE auto-analysis gaps; prototype setting feeds Rust signature recovery |
| Data/Types/Structures (13, `parse-c-header`, `apply-structure`) | ● | Type import is how a Rust reconstruction gets layouts |
| Diff tools (13, async sessions, markup transfer) | ● | Version-to-version PE diffing; correlator pipeline maps to match-then-retranslate |
| Analysis job machinery (`analyze-program` async + status/cancel) | ● | A headless harness needs exactly this job model |
| `import-file` + archive depth + import timeouts | ● | PE drop-in automation |
| Headless PyGhidra + Java launcher + stdio bridge + random port + auto API key | ● | The no-GUI deployment pattern the harness copies |
| Tool groups (6 groups, runtime toggle, CLI allowlist) | ● | Context-budget control for an agent harness |
| Scripting tools (run/read/write/edit-script, PyGhidra in-process) | ● | Escape hatch for non-decompiler queries |
| Pagination & count-first tool design (`get-*-count` before listings) | ● | Design standard for all our list endpoints |
| xrefs, constants, strings, memory, imports/exports (12) | ● | Query surface the harness wraps around Ghidra |
| Call graph / data-flow / vtable (9) | ● (vtable ◐) | Data-flow drives variable→Rust typing; vtable only for C++ PEs |
| Annotations (comments + bookmarks, 9) | ◐ | Write-back into the Ghidra DB as harness state |
| Follow-Me UI, `RevaProvider`, GUI actions | ○ | GUI-only |
| Marketplace + triage/CTF skills | ◐ | Workflow prompts worth adapting; CTF skills ○ |
| `pyghidra-scripting` skill + 5 reference docs | ● | Distilled PyGhidra usage our agents can reuse verbatim |
| 1 MCP resource; prompts capability never implemented | ○ | A surface gap we should not copy |
| Debug capture (`capture-reva-debug-info`) | ◐ | Supportability pattern for a CI harness |
| Server security (API key, public-binding guard, consent dialog) | ◐ | Only if we expose MCP beyond localhost |
| Unit vs slow-integration test split + Ghidra-version CI matrix | ◐ | Test-architecture model |
| Ghidra help HTML, `.continue/`, `.claude` web hooks, copilot files | ○ | Plumbing noise |

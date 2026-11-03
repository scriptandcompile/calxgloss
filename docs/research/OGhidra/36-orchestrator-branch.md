# 36 — The orchestrator branch: a multi-agent harness frozen inside main's own history

> Part of the [OGhidra overview](README.md). The *orchestrator*/*worker* agent stack end to end: why the
> branch exists, how a query reaches it, the cycle loop and its exit reasons, the single generic *worker*
> loop, the *blackboard* of shared working memory, *recipes*, *correlation hooks*, *coverage* and *lead*
> machinery, tool execution and tool health, the *gate* and ask-the-human plumbing, what "multi-agent"
> means at runtime, the diffstat against main, the branch's own run posture, and the comparison against
> calxgloss's fixed pipeline (ADR-0051), record tree and unknown records (ADR-0056), evidence-bundle tiers
> (ADR-0048/0049) and scan registry (ADR-0052/0053). **Citations.** A bare `path:line` is the
> **orchestrator tree** — the branch checkout at `aa03aa8` (2026-05-08). A `main:` prefix is the **main
> tree** at `6224d26` (2026-10-28), already covered by ch. 31–35 and cited here only for contrast.
> *Verified* = read or measured here; *inferred* = my reading. Inspection only: the sandbox has no
> `pytest`, `flask` or `pydantic`, so the branch's own suite could not be executed (§16). Git history is
> not re-derived — see [21 — history and releases](21-history-and-releases.md) §4, §6.

## What OGhidra (orchestrator branch) does

### 1. Why the branch exists: a bookmark, not a development line

`origin/orchestrator` has **no commits of its own** (verified): `git merge-base --is-ancestor
origin/orchestrator origin/main` → true, the merge-base *is* the tip `aa03aa8`, and that tip appears
exactly once on main's first-parent chain; **0 commits ahead of main, main 39 ahead.** The whole stack
arrived *on main* in `d5dec8a` "Harnesses and Helpers" (2026-04-02, 38 files +16,969/−4,640) and was
reverted there by `c62ec6e` (2026-05-15, exact mirror) four minutes before `44ee11d` pointed the README
at this branch (ch. 21 §4). Between the stack and the tip sit 30 chore commits: ruff line-128
formatting, import sorting ("…files that don't change as a result of the orchestrator being added"),
README tidy-ups, pydantic `field_validator` fixes, Ghidra 12.0.3 plugin-build fixes.

So the branch is main's history **pinned at the moment the harness was still in the tree**, kept
cloneable. Hence a three-dot `git diff --stat origin/main...origin/orchestrator` returns *empty* — a
trap that makes a careless reviewer conclude the branch "adds nothing"; the real measurement is two-dot,
branch→main (§15). *Inferred*: the purpose is distribution and demonstration, not continued development
— nothing postdates 2026-05-13, nothing cites an issue or PR, and it carries none of main's release
machinery.

### 2. Entry point: every query goes to the orchestrator; the old loop stays, unreachable

`Bridge.process_query` (`src/bridge.py:1432`) does one thing: it hands the query to
`_process_query_with_orchestrator` (`:1448`, defined `:1455`), which builds the `Orchestrator` around
the shared trackers — the same `CoverageTracker`, `LeadTracker` (`:288`, `:1475`), session memory and
context manager the pre-revert loop used. `src/lazy_ghidra.py` (93) is a proxy that defers the GhidraMCP
health-check/API-detection until first attribute access, so the bridge starts while Ghidra is not yet
running (`LazyGhidraClient`, used from `bridge.py`).

The pre-revert machinery is **still present and now unreachable** (caller grep over `src/` and
`tests/`):

| Dead method | Span | Callers on this tree |
|---|---|---|
| `_execution_loop` | `bridge.py:2060-2517` (458 lines) | none (own body + a docstring mention at `execution_gate.py:9`) |
| `_execution_agent_rank` / `_build_execution_loop_prompt` | `:2518` / `:2546` | one each, inside `_execution_loop` |
| `_analyze_execution_results` | `:2651` | **zero** |
| `_consolidate_findings_hybrid` / `_format_results_with_context` | `:2750` / `:2894` | one each, inside `_execution_loop` |

≈900 lines of plan→execute→review machinery (`:2060-2969`, with the report-synthesis helpers continuing
at `:2970-3173`) sit behind a call graph nothing enters; on main that loop *is* the live path (ch. 32).
So the branch does not merely add an agent, it **subtracts the deterministic path while keeping its
source**.

### 3. Two modes, one router, three strategies

`Orchestrator.run` (`src/orchestrator.py:444`) makes one LLM call (`_route_query` `:477`,
`phase="planning"` `:534`) and picks **conversational** (`_run_conversational` `:559`: one worker,
`max_steps=20` hard-coded `:590`, no triage/strategy/synthesis overhead, then one synthesis call over
gathered data `:645`) or **investigation** (`:669`: recon + hooks + multi-*cycle* loop, §4). The
docstring is explicit: "The worker's LLM loop IS the conversation."

The strategy labels (`vuln_hunting`, `malware_hunting`, `binary_understanding`) come from the same
routing call and steer later behaviour: which notebook entries are rejected (§7) and which closing
question the report answers — `_VERDICT_QUESTIONS` (`:1752`) demands "VULNERABLE (with specifics) or NO
CONFIRMED VULNERABILITIES (with what was checked)", "MALICIOUS … or NO MALICIOUS BEHAVIOR CONFIRMED", or
"what does this binary do". *Verified* the answer comes from an LLM call (`:1917`); *inferred* this is
the project's nearest thing to a calxgloss *verdict*, and it is prose, not a computed gate. Ceilings are
config-driven (`:421-437`; this tree's own `src/config.py:53-122,1363-1366`): `orchestrator_max_cycles`
15, `worker_default_max_steps` 20, `coverage_stall_threshold` 3, `orchestrator_doom_loop_threshold` 2 —
and `README.md:224-233` labels them honestly: "the LLM decides when to stop; these are hard limits".

### 4. The cycle loop: recon, batch-fired hooks, six ways out

A *recon* pass maps imports/exports/strings into the discovery cache (`_run_recon_phase` `:1053`, one
`planning` call `:1001`), then **all** matching hooks fire at once (`:708-751`; the comment records the
fix: "prevents hooks from consuming 4-5 orchestrator cycles"), then `while True` (`:761`). Exit reasons
verbatim:

| Line | `exit_reason` | Trigger |
|---|---|---|
| `:769` | `hard_ceiling` | `cycle > max_cycles` (default 15) |
| `:798` | `coverage_stall` | coverage ratio flat for `coverage_stall_threshold` cycles (`_is_coverage_stalled` `:2340`) |
| `:808` | `diminishing_returns` | no new notebook entry for 3 cycles (`_is_diminishing_returns` `:2377`) |
| `:820` | `llm_complete` | task call returns no task: "Investigation complete (LLM decision)" |
| `:843` | `doom_loop` | near-identical worker goals (`recent_goals`, threshold 2) |
| `:758` | `unknown` | initial value, i.e. an exception path |

Four brakes are counters over the tracker's own arithmetic; the fifth is the model's say-so. Nothing
measures whether the binary was actually covered (§10).

### 5. Task creation: the model writes the plan, the code keeps the ceiling

`_create_next_task` (`:1147`) asks for a JSON task spec; `_parse_task_from_response` (`:1268`) reads the
requested budget (`:1284`) and discards it for the config ceiling twice (`:1291`, `:1318`, both `#
Safety ceiling`). `WorkerTask` (`src/agents/base.py:19`, in a 250-line module with `AgentResult`,
`SubAgentState`, `OrchestratorState`, `SubAgentRegistry`) has **no `soft_limit` field**, yet every event
and log record carries a `soft_limit` always set to the hard ceiling (`:600`, `:679`, `:692-693`,
`:728`, `:831`; the hook factory passes `worker_max_steps` for *both* `worker_max_steps` and
`worker_soft_limit` at `:432-433`). *Inferred*: graduated-budget vocabulary, decorative plumbing.

Duplicate-work memory is real: `WorkerResultSummary` (`:77`) accumulates one-line summaries of what each
worker already did and feeds them into the next task prompt, and `_is_duplicate_entry` (`:1706`) rejects
findings by exact title, by shared address + same category, or by >60% title-word overlap.

### 6. The worker: one class, one loop, done when it says so

There is exactly one agent class, `WorkerAgent` (`src/agents/worker_agent.py:58`, 1,385 lines): `grep
"^class "` over `src/agents/` returns only the data types plus `WorkerAgent` — **no specialised
workers**. The README bullet "Multi-Agent Orchestration — Complex investigations use specialized workers
for deep analysis" (`README.md:92`) is wrong as written: specialization is task text plus a recipe name,
not types.

The loop (`:204`, `while True`) is main's loop with tighter rails: completion by marker word —
`COMPLETION_MARKERS = ("INVESTIGATION COMPLETE", "TASK COMPLETE", "GOAL ACHIEVED")` (`:78`, stripped
`:478`); `MAX_COMMANDS_PER_RESPONSE = 3`, truncated not rejected (`:279-285`); a per-worker dedup cache
returning the cached result for identical `(tool, params)`, errors included (`:196-198`, `:306-309`,
`:343-344`); `CONSECUTIVE_ERROR_THRESHOLD = 3` (`:84`) retires a tool, `DOOM_LOOP_THRESHOLD = 3` (`:81`)
ends the worker with `exit_reason="doom_loop"` (`:436`), `hard_ceiling` (`:212`) and `llm_complete`
(`:254`) the others; tool failures become **data**, not exceptions — `result_str = f"ERROR:
{str(e)[:500]}"` (`:335`) plus `blackboard.tool_health.record_failure` (`:338`); and after each call it
auto-marks coverage, updates the function registry and discovery cache, and scans for artifacts
(`:355-411`, `:418-424`). Static prompt context reuses main's own `SystemContextBuilder`
(`src/models/memory.py:293`, used at `:568-578` with `task.include_sections`) — the worker did not
reinvent prompt assembly — and a second mechanism sits on top (§11). Beware the import at `:44`:
`ExecutionGate` there is a `models/memory.py` pydantic model, *not* the
`execution_gate.ExecutionGatekeeper` module.

### 7. The blackboard: shared working memory, and one genuinely useful cache

`BlackboardAccess` (`src/blackboard.py:36`, 395 lines) is one read/write facade over `SessionMemory`,
`CoverageTracker`, `LeadTracker`, `ContextManager`, `FunctionRegistry`, `InvestigationNotebook`,
`DiscoveryCache`, `ToolHealthTracker` (`:20-35`), built once per investigation and shared by reference.
All of it is in-process: the blackboard is never persisted, and main's durable session layer (ch. 33) is
touched only via `SessionMemory`.

The piece with real engineering value is `_code_cache` (`:79`, `:284-315`): address → decompiled C,
written by workers and read by later workers, the orchestrator and the final report — one decompilation
per address per run instead of one per worker.

The **notebook** has a programmatic admission test, the most transferable object on the branch
(`_validate_notebook_entry` `:1632`, rules `:1643-1655` and `:1681-1701`): reject titles < 10 chars or
detail < 20; reject ten noise phrases ("uses the api", "general observation", …) under the two hunting
strategies; cap at `MAX_NOTEBOOK_ENTRIES = 25` (`:1613`) then admit only `critical`/`high`; reject
`info`/`low` for `vuln_hunting`; **reject a `vuln_hunting` entry with no address evidence**
(`:1681-1685` — no `entry.addresses` and no hex-looking string in `entry.evidence`); reject "binary uses
X" observations unless an exploit path is described. Rejections are logged and counted;
`_update_notebook` (`:1344`) parses entries from the worker's answer first (`:1414`, one `analysis`
call) and drops malformed JSON silently (`:1602`).

### 8. Recipes: deterministic gather, one LLM call, bounded follow-up

*Recipes* are the branch's own admission that its loop is expensive. Four built-ins (`AVAILABLE_RECIPES`
`src/recipes.py:43`: `trace_import_callers`, `trace_string_refs`, `deep_function_analysis`,
`surface_recon`), caps of `DEFAULT_MAX_FUNCTIONS = 15` (`:36`) and `MAX_CODE_LINES_PER_FUNCTION = 250`
(`:51`) enforced at nine call sites, plus a plugin loader (`src/recipe_registry.py:175`,
`custom_recipes_dir`). A recipe is picked by the task-creation LLM (a `recipe` field in its JSON) or by
a hook, and run by `_run_recipe_mode` (`worker_agent.py:1024`) whose docstring is the clearest statement
of intent in the tree:

> 1. **Gather**: `RecipeExecutor` deterministically gathers all relevant code (no LLM involvement). 2.
> **Analyze**: A single LLM call receives ALL gathered code and produces: summary + JSON notebook entries
> + optional follow-up. 3. **Follow-up** (optional): ≤3 additional decompilations … then a re-analysis. …
> **This replaces the LLM-driven tool-selection loop for recipe-enabled tasks.** (`:1026-1038`)

Gathered bodies go into the blackboard code cache (`:1063-1065`); a recipe that gathers nothing exits at
once with `exit_reason="recipe_complete"` and a finding saying so (`:1084-1101`). Two LLM calls total
(`:1116`, and `:1157` if follow-ups ran). That is calxgloss's shape — deterministic evidence assembly,
one model call over a complete bundle, bounded second pass — built *inside* the agent as an escape hatch
from the agent, and left without identity, coverage stamp or provenance (§18).

### 9. Correlation hooks: five vulnerability predicates written in Python

`src/correlation_hooks.py` (206) gives a `CorrelationHook` ABC (`name`, `description`, `check(all_apis,
coverage, function_registry, discovery_cache) -> Optional[WorkerTask]`) plus a registry loading drop-in
hooks from `custom_hooks_dir`. Five built-ins (`correlation_hooks_builtin.py:395`, factory `:384`),
extracted "verbatim from the original hardcoded `_build_default_correlation_rules()`" per the module
docstring (`:1-6`): `unquoted_service_path` (`:29`), `dll_hijacking` (`:114`), `command_injection`
(`:180`), `token_privilege_escalation` (`:256`), `network_file_traversal` (`:322`); README:268 lists the
same five. Each is a cheap predicate — `CreateProcessW`/`CreateProcessA` present **and**
`service_management` at depth ≥ `encountered` or a service API present (`:38-60`) — whose body is an
enumerated procedure handed to a worker as a goal: "(a) Is lpApplicationName NULL? (b) Is lpCommandLine
constructed from a path containing spaces? (c) Is the path quoted…" (`:62-71`). CVE-2019-18915 is cited
by name in the source comment (`:24`). The legacy single-fire path survives in the orchestrator
(`_check_correlation_rules` `:2264`: "Only one hook fires per check (first match wins)").

### 10. Coverage and leads: the branch deepens main's checklist, and its flaw

Both trees carry the *coverage tracker* and *lead tracker*; the branch grew them (verified two-tree
diff: 349 insertions across `coverage_tracker.py`/`lead_tracker.py`/ `context_manager.py`; 397 lines
here vs `main:` 225, ch. 33 §11). The branch adds a **depth ladder** `none` → `encountered` → `analyzed`
(`:37-47`) where only `analyzed` counts toward `coverage_ratio()` (`:306-317`) — the quantity the loop
stalls on (§4). Depth is chosen **by tool class, not by evidence** (`:238-247`): analysis tools
(`:54-59`) → `analyzed`, surface tools (`:64-69`) → `encountered`, **unknown tools → `analyzed`
("conservative")**. Matching is still substring over `f"{tool_name} {str(tool_params)}
{result}".lower()` (`:236`) — main's echo flaw: asking for `CreateServiceW` and getting nothing still
marks — and the checklist grew from eight areas to nine with `input_handling` (`:154`). *Inferred*
consequence: `coverage_ratio()` can reach 1.0 with zero analysis performed, so `coverage_stall` measures
arithmetic, not the binary.

The *lead tracker* (120 here vs 122 on main) is unchanged in kind: leads are harvested by regex from the
model's own prose (`lead_tracker.py:69-94`) and re-injected as "You MUST address all HIGH priority
leads". `BlackboardAccess` exposes `add_lead`/`get_leads_prompt` (`:139-147`), but the only production
`parse_analysis_dump` call site is inside the dead legacy loop (`bridge.py:2568-2569`). On the live
agent path leads reach the prompt but are not harvested from the notebook (verified) — the orchestrator
writes structured `NotebookEntry` objects instead (`orchestrator.py:1364`, `:1448`, `:1473`, `:1540`).

### 11. Tools, health, artifacts, compaction, config: the small honest modules

- **`src/tool_executor.py` (478)** — one shared executor for every worker: command normalisation, a cache
  with a `NO_CACHE_COMMANDS` denylist (`:39`, enforced `:357`, `:371`), errors raised as `ValueError` with
  an enhanced message (`:152`, `:162`, `:225`) that the worker converts to data. `:134` records that the
  `get_cached_result` command was removed in orchestrator mode because it depended on
  `context_manager.result_cache`. **No permission or approval machinery anywhere in it** (verified by
  grep).
- **`src/tool_health.py` (100)** — `RLock`-guarded global failure counter (`:28`, `:46-49`) that
  **blacklists a tool after 5 global failures** (`DEFAULT_FAILURE_THRESHOLD = 5`, `:15`) and injects
  warnings so the model stops asking for it.
- **`src/artifact_scanner.py` (74)** — 16 regex signatures over tool output (privilege tokens,
  credentials, private keys, IP-literal URLs…); the worker auto-promotes hits to the notebook
  (`worker_agent.py:418-424`). Two facts: the count is **16, not the 19 the README promises**
  (`README.md:26`, measured by loading the list), and the docstring says it came from "the former
  ExecutionGatekeeper to remove the over-engineered PAUSE/feedback/doom-loop wrapper" (`:7-10`) — the
  stack simplifying itself in public.
- **`src/worker_compactor.py` (141)** — past `DEFAULT_THRESHOLD = 6` (`:29`) older tool results collapse
  into a digest grouped by semantic category (discovery / decompilation / xrefs, `_CATEGORY_MAP`
  `:14-26`), keeping `DEFAULT_PRESERVE_RECENT = 4` (`:30`); threshold is config
  (`worker_compaction_threshold`, `src/config.py:100`).
- **`src/config_loader.py` (129)** — layered user→project config files merged *under* env-var overrides,
  called from `src/config.py:2027-2033` inside `except Exception: pass`.
- **`src/orchestrator_logger.py` (237)** — a per-run markdown log under `logs/`, flushed after each cycle:
  strategy decision, per-cycle task, worker results, notebook entries **accepted and rejected**, coverage
  progression, hook firings, final report, timings and token estimates (`:1-16`), so a crashed run still
  leaves a post-mortem.

### 12. Events and the Tk tree: a UI built around the agent

`src/event_emitter.py` (130) offers three callbacks — chain-of-thought (`:41`), question (`:49`), agent
lifecycle (`:53`). Exactly two are set on this tree: the Tk UI wires CoT at `src/ui.py:5234` and agent
events at `:5272`, and the monolithic `src/ui.py` (6,391 lines; main has since split the GUI into
`src/gui/`, ch. 34) grows an **orchestrator/worker tree sidebar** polling a `SubAgentRegistry` at 200 ms
during a run (`:758`, `:764`, `:5239-5267`). The branch's GUI is built *around* the agent — the reverse
of main, where the workbench surface dominates.

### 13. The gate and the question: complete plumbing, no pump

The branch keeps main's *execution gate* (`src/execution_gate.py`, 371 lines vs `main:` 353) and
*question* handler (`src/user_question.py`, 158) and constructs both in `Bridge.__init__`
(`bridge.py:276`). None of it is reachable on the live path (caller grep across `src/`, `tests/`,
`main.py`):

- every `execution_gate` call site — `reset()` `:2083-2084`, `consume_feedback()` `:2087`,
  `check_before_execution()` `:2170`, and the `ASK_USER:` handler `:2124-2138` — is inside the dead
  `_execution_loop`;
- `set_gate_check_callback` / `set_gate_question_callback` have **zero callers**; `_ui_gate_callback` is
  never assigned (`bridge.py:270` comments it out as removed);
- `QuestionHandler.set_answer` (`user_question.py:122`) has no production caller and
  `exec_results.pending_question` is written (`bridge.py:2137`), never read;
- `set_question_callback` (`event_emitter.py:49`) likewise has no caller, so question events fall through
  to nothing;
- `Orchestrator.__init__` takes **no gate parameter**, despite a docstring example showing one
  (`orchestrator.py:372` is prose).

So on this branch **no tool is gated and no human is ever asked**, while `tests/test_execution_gate.py`
and `tests/test_user_question.py` (13 tests) keep the unwired chain green. Ch. 32 §9 found main's gate
"fires but never stops"; the branch drops a step further: the trigger never fires. *Inferred*: this is
what callbacks-first interactivity becomes — the hook exists, nothing in the shipped path calls it, and
the README keeps selling the capability.

### 14. Concurrency: "multi-agent", one worker at a time, one Ghidra

Every thread start in `src/` is in `src/ui.py` (`:397`, `:1696`, `:2693`, `:2713`, `:2936`, `:2965`,
`:3153`, `:3396`, `:4479` — UI worker and stage-monitor threads) plus the legacy bulk-rename
`ThreadPoolExecutor` at `:4218-4228`. The orchestrator spawns **one worker per cycle, sequentially**;
all workers share the single `ToolExecutor`, hence one `GhidraMCP` HTTP server, hence Ghidra mutations
are serialized. The locks in `coverage_tracker`, `tool_health` and `SubAgentRegistry` exist because the
UI polls them, not because workers race. So there is no concurrent-mutation hazard in the agent stack —
and no parallelism: "multi-agent" here means *N sequential LLM loops over one shared scratchpad*.

### 15. The two trees, sized

Direction matters, so state the command: `git diff --stat origin/orchestrator..origin/main` (two-dot;
three-dot is empty, §1) → **151 files, +22,255/−34,101**. Read branch→main, the deletions are the
harness plus what main later reorganised.

| Measure | orchestrator tree | main tree |
|---|---|---|
| `src/**.py` | 62 files / 42,999 lines | 54 files / 35,209 lines |
| `src/bridge.py` | 4,445 | 7,845 |
| `tests/**.py` | 26 files / 7,865 (16 `test_*.py`) | 22 files / 3,959 (15) |
| `.github/` | **absent entirely** | one publish-only workflow (ch. 20) |
| `Dockerfile`, `.pre-commit-config.yaml`, `.gitattributes`, `.git_archival.txt` | absent | present |
| Ghidra backends | GhidraMCP HTTP only — 0 `pyghidra` hits in `src/**.py`, `requirements.txt`, README | GhidraMCP + headless PyGhidra (ch. 21 PR #23, ch. 31) |
| GUI | monolithic `src/ui.py` 6,391 | `src/gui/` split, 11 files / 6,801 |

**27 paths are branch-only (22,966 lines)**: `src/ui.py` 6,391 (main moved it), `orchestrator.py` 2,764,
`report_generator.py` 2,520, `interactive_mode.py` 2,037, `tests/test_orchestrator.py` 1,790,
`agents/worker_agent.py` 1,385, then the test trio (1,004 + 958), `recipes.py` 754, `tool_executor.py`
478, `correlation_hooks_builtin.py` 395, `blackboard.py` 395, `benchmark/reports/visualizations.py` 300,
`agents/base.py` 250, `orchestrator_logger.py` 237, `correlation_hooks.py` 206, `recipe_registry.py`
175, `worker_compactor.py` 141, `event_emitter.py` 130, `config_loader.py` 129, `tool_health.py` 100,
`lazy_ghidra.py` 93, `artifact_scanner.py` 74, `agents/__init__.py` 17, plus three embedding-eval
artifacts (ch. 33's topic). **19 paths are main-only (7,308 lines)**: the `src/gui/` split (6,801),
`api_health.py` 57 + its test 100, `test_security_hardening_regressions.py` 234, `release.yml` 49,
`Dockerfile` 35, `.pre-commit-config.yaml` 28, `.gitattributes` + `.git_archival.txt` 4.
Shared-and-different leaders: `bridge.py` +5,236/−1,836, `ghidra_client.py` +2,359/−892, `config.py`
+1,091/−1,128, `main.py` +210/−90.

### 16. Effect and run posture: 3,752 lines of tests nobody gates, and a file that no longer parses

- **Tests**: the agent trio is 3,752 lines and **197 `def test_`** (94 orchestrator + 50 worker + 53
  recipes); `test_coverage_tracker.py` adds 637/69. Those three suites are the only files in the tree that
  `import pytest` with bare `def test_` — a pytest-style suite main never had (main's is unittest-style,
  ch. 35 §5). **But** `requirements.txt` names no pytest, `pyproject.toml` ends at line 39 with **no
  `[project.optional-dependencies]` or `[tool.pytest.ini_options]`**, there is no `conftest.py` and no
  `.github`, and this sandbox lacks pytest/flask/pydantic — the suite cannot run as committed without an
  unnamed dependency (the dspy branch grew exactly that packaging, ch. 35 PR #63).
- **Bit-rot**: `python3 -m py_compile` over the ten central modules under Python 3.12 fails on exactly one
  — `src/interactive_mode.py`, `IndentationError: … on line 2037 (…line 2038)`. **926 of its 2,037 lines**
  are junk stubs named `show_run_tool_file_file_file_…` with `pass` bodies, ending mid-comment. Nothing
  imports it (`main.py:45` defines its own `run_interactive_mode`), and the corruption arrived in the
  first commit `5fa72ea` "OGhidra-Open-Source" (2025-11-20) — ~2k lines of dead, unparseable filler
  predate the harness.
- **The agent is unmeasured**: `benchmark/` here is main's rename/summary package ("Can an agentic AI,
  iteratively exploring a binary through Ghidra, achieve semantic understanding comparable to having the
  source code?", `benchmark/README.md:129`) with **no orchestrator scenario** (`benchmark/ground_truth/` =
  extractor, source_parser, summary_generator only) and no `benchmark/agent/` (ch. 35 §3). No run
  artifacts, no committed `logs/` (verified: `git ls-tree -r origin/orchestrator | grep logs/` → empty),
  and `docs/` holds two files, neither mentioning the orchestrator. *Inferred*: reviewed by humans, never
  scored; the only evidence that it works is its own pytest suite, which nothing runs.
- **Health**: tip-region author dates interleave 2026-05-08 and 2026-05-13 (measured); no CI, no
  pre-commit, no packaging workflow, and six months of main's work — pyghidra, the GUI split,
  `api_health.py`, security-hardening regressions — do not exist here.

### 17. Provenance: "Claude-inspired" is main's label, not this tree's

`main:README.md:3` — "For the version using a Claude-inspired Orchestrator, see …/tree/orchestrator".
The branch README never uses the phrase (verified by grep) and its own comments name other ancestors:
"Two modes (inspired by claw-code's single-loop + OGhidra's …)" (`orchestrator.py:447`), "Dynamic loop
model (inspired by opencode sub-agents)" (`worker_agent.py:25`). *Inferred*: the Claude framing is
retrospective marketing added after the revert; the tree claims single-loop and sub-agent lineage.

### 18. The design-study question: an agent that grew a pipeline, or a pipeline wearing an agent?

Three of the branch's mechanisms are **anti-agentic by construction**: *recipes* replace tool selection
with deterministic gather + one call (`worker_agent.py:1036`); *correlation hooks* replace "should I
look for this?" with five hardcoded predicates that fire with no model call
(`correlation_hooks_builtin.py:38-70`); the *notebook* admits findings only through ~70 lines of
deterministic rules (`orchestrator.py:1632-1701`). Meanwhile everything that is pure agent — the router,
the cycle loop, the marker word, the model-authored next task — is where the weaknesses sit: stops
computed over the tracker's own arithmetic (§10), "done" as a string the model emits
(`worker_agent.py:78`), and a *blackboard*/*lead* discipline that leaves **no durable record of what was
established**. Honest reading: the *working-memory discipline* (blackboard/leads/notebook/coverage) is
the load-bearing idea, and the model-driven control flow is what this project threw away. calxgloss made
the same split in advance, in the opposite direction: evidence assembly deterministic, model calls
wrapped in one seam with verdict-routed retries (ADR-0051).

## Comparison with calxgloss

### Control flow: an agent loop with brakes vs the attempt seam (ADR-0051)

calxgloss's loop "keeps only policy — strategy ladder, tier walk with an operator cap, stop routing on
the verdict" (ADR-0051; ch. 10 §attempt seam); the model never chooses what to look at next. Here the
policy *is* inside the model's context: the next task is JSON the model writes (`orchestrator.py:1147`)
and stops are four counters over self-bookkeeping plus a marker word. Both bound the loop with hard
ceilings (15 cycles / 20 steps here, operator cap there); what differs is authority — calxgloss routes
on a **computed verdict** (compile + baseline tests + ordered API-call trace, ADR-0057), this branch on
the model's say-so.

### Working memory: blackboard/leads/notebook vs the record tree and unknown records (ADR-0056/0053)

The blackboard is a session scratchpad: in-process, wiped with the run, keyed by nothing a reader can
cite. calxgloss's answer is a durable record tree where "absent coverage reads as **unknown, never
absent**" and admitted gaps are **named records with deterministic ids, one document per owner joined at
read time** (P21 shipped, ADR-0056; stamped at scan time, ADR-0053). Ahead of *main*'s equivalent, the
branch at least deepens coverage into a three-step ladder (`coverage_tracker.py:37-47`). Behind
calxgloss: depth is assigned by **which tool class ran** (`:238-247`, unknown → "analyzed") over
substring matching that includes the tool's own parameters (`:236`) — a `coverage_ratio()` of 1.0 is
compatible with nothing having been analyzed, exactly the collapse calxgloss forbids ("empty findings
under complete coverage and under an admission line must never render alike"). The notebook's
evidence-equality rule — no address, no entry (`orchestrator.py:1681-1685`) — is the closest thing in
this repo to calxgloss's "no record without a readable address".

### Context discipline: category digest vs the evidence bundle (ADR-0048/0049)

`WorkerContextCompactor` folds older tool output into a per-category digest past 6 steps, keeping the
last 4 whole (`worker_compactor.py:14-30`) — recency plus three categories. calxgloss assembles a bundle
from engines' filed documents through registered projection rows, one shared section include per engine,
so missing evidence drops sections and coverage/admission lines render beside what they qualify
(ADR-0048/0049). The branch reuses main's `SystemContextBuilder` for static sections
(`worker_agent.py:568-578`) *and* layers its compactor on top — two context engines on one path. What a
digest can never express is *why* something is absent: collapsed is indistinguishable from never-ran.
calxgloss's tiers are provenance-first and non-lossy by construction; these are token-first and lossy by
design.

### Human-in-the-loop vs the web *verdict* surface: neither side has an oracle

The branch ships a complete escalation chain — gate → `ASK_USER:` → question handler → UI callback →
`set_answer` — and wires none of it into the live path (§13) while the README sells the capability (as
main's does; ch. 32 §9). calxgloss has no escalation prompt and no need for one at the loop level:
accept/reject is a human action on the web *verdict* surface and the mechanical gate is the verify seam
(ADR-0057). Neither project has a truth oracle over *the binary*, but calxgloss has a mechanical
pass/fail and a durable place for the human's answer. Lesson from the losing side: **an unwired
escalation feature is worse than none, because it makes the README able to lie.**

### Recipes and hooks vs the scan registry and strategy ladder (ADR-0052/0053)

Same object class, seen twice. calxgloss: one `ScanDescriptor` row per engine in a registry, fanned out
under a sliding window, each scan stamping its own coverage record, with a skip-rate breaker and
join-everything/cancel-nothing (ADR-0052/0053). Here: four recipes with caps and five hooks that are
pure predicates over API sets and coverage depth, both extensible by drop-in directories
(`custom_recipes_dir`, `custom_hooks_dir`) — the same plugin instinct. But the recipe/hook layer has
**no identity, no coverage stamp, no provenance, no skip-rate fuse**: running `trace_import_callers`
leaves gathered text and a count, not a record. The *vocabulary* is worth more than the machinery — see
the steals.

### Run visibility: narrative cycle log vs prompt/token logs (P27)

calxgloss already logs every strategy, token count and raw prompt/response (`prompt_strategy_log.json`,
`token_usage.json`, `llm_io/log.jsonl`), so OGhidra's token estimates add nothing. What it has that
calxgloss lacks is a **cycle-shaped narrative that includes what was rejected**:
`orchestrator_logger.py:1-16` logs the strategy decision, each cycle's task, notebook entries accepted
*and* rejected with reasons, coverage progression and hook firings, flushed per cycle. That is exactly
the shape roadmap **P27 (hypothesis ledger for stuck retries)** wants — what was tried, what was
rejected, why — except that calxgloss wants those as queryable records, not markdown.

### Overlap / calxgloss-only / OGhidra(orchestrator)-only

- **Overlap:** deterministic non-model gates above the model (recipes, hooks, notebook validator, tool
  blacklist vs skip-rate fuse and verify seam); a shared tiered context builder; hard ceilings;
  errors-as-data; plugin directories for recognition routines; a prompt carrying a coverage checklist and
  a prioritized lead list (main too, ch. 33 §11); no oracle over the binary on either side.
- **calxgloss-only:** durable records with deterministic ids and named unknowns (P21/ADR-0056); coverage
  stamps naming shortfalls with an admission line (ADR-0053); the evidence bundle as *only* render input
  with coverage rendered beside what it qualifies (ADR-0048/0049); a mechanical verdict (ADR-0057);
  attempt branches kept forever (`re/{binary}/{function}v{N}`) so failures are reversible and auditable;
  scan identity + binary-version pairing (ADR-0052); a fixture DLL and engine harnesses (ch. 10 §P33/P42);
  versioned prompt templates with orphan deletion (ADR-0008).
- **OGhidra(orchestrator)-only:** the blackboard facade with a cross-worker **address → decompiled C
  cache**; recipes as zero-LLM gather-then-one-call units with a bounded 3-call follow-up; five
  correlation hooks as named vulnerability predicates carrying their own check list in the goal; a
  **programmatic notebook admission test** with severity floors, noise-phrase rejection, a 25-entry cap
  and an address-evidence requirement; a coverage **depth ladder** that at least tries to separate "saw
  it" from "read it"; a per-run markdown cycle log recording rejections; a live orchestrator/worker tree
  UI panel; 3,752 lines of pytest-style agent tests; a lazy Ghidra proxy so the bridge starts without
  Ghidra.

### Verdict

Read as a system, the branch is unmeasured and half-unwired: no CI, no pytest packaging, no benchmark
scenario, no run artifacts, ~2k lines of unparseable filler, gate and ask-the-user chains orphaned
inside dead code, "specialized workers" that are one class, coverage that measures the tracker,
completion that is a magic word. Read as design evidence it is calxgloss's strongest external
confirmation that agent-freedom-over-Ghidra does not survive contact with a maintained binary-analysis
tool — the same authors reverted it — while *inside* that loop they built three deterministic escapes
(recipes, hooks, notebook validation) that agree with calxgloss's conclusions. The *working-memory
discipline* is what to mine; the control flow is what to refuse.

Steals, in priority order:

1. **Address-evidence admission rule** (`orchestrator.py:1681-1685`): no finding recorded without an
   address the engine can re-read. Make it a structural requirement of P27's *hypothesis ledger* — every
   hypothesis entry names the offsets it is about — instead of prose-only retry context.
2. **Rejection-inclusive run narrative** (`orchestrator_logger.py:1-16`): log rejected attempts with
   reasons beside accepted ones, flushed as you go — calxgloss logs attempts but keeps rejection reasons
   unqueryable; same shape serves P27 and the P26 *obligation ledger*.
3. **Algorithm-recognition vocabulary as scan names** (`correlation_hooks_builtin.py:24-322`, plus the 9
   coverage areas incl. `input_handling`): unquoted service path, DLL hijacking, command injection, token
   privilege escalation, network/directory traversal — named dimensions a deterministic engine scan files
   records under (candidate content for **P30**), with calxgloss's `ScanDescriptor` + coverage stamp bolted
   on, exactly what the hooks lack.
4. **Depth ladder, corrected**: adopt `encountered` vs `analyzed` (calxgloss's coverage records flatten it,
   ADR-0053); never adopt the assignment rule — depth must follow what produced an evidence row, not which
   tool class ran (`coverage_tracker.py:238-247`).
5. **Cross-call decompilation cache keyed by address** (`blackboard.py:79,284-315`): the branch states in
   the plainest terms why decompilation is fetched once per address per run and shared by every consumer.

What calxgloss should **not** copy: the agentic control flow — model-authored next tasks, marker-word
completion, counters over self-bookkeeping as stops — which ADR-0051 excludes by design (loop keeps
policy, strategies at the door, verdicts routing); an in-memory scratchpad instead of durable records;
noise-phrase blocklists as quality control (brittle prose policing is what the compile/trace verdict
replaces); a second compaction layer on top of an existing tiered builder; callbacks-only human
escalation that ships unwired; and the multi-agent *UI* tree, which renders sequential loops as parallel
agents.

## Sources

- **Orchestrator tree** (`aa03aa8`): `src/orchestrator.py` (421-437, 444-534, 559-669, 708-843, 1001-1053,
  1147-1318, 1344-1473, 1602-1701, 1752-1919, 2264, 2340-2377); `src/agents/worker_agent.py` (25, 58,
  78-84, 196-254, 279-344, 355-436, 478, 568-578, 1024-1157); `src/agents/base.py`; `src/blackboard.py`
  (20-36, 79, 139-147, 284-315); `src/recipes.py` (36-51); `src/recipe_registry.py`;
  `src/correlation_hooks*.py` (1-6, 24-71, 114-322, 384); `src/tool_executor.py` (39, 134, 152-225,
  355-371); `src/tool_health.py` (15-58); `src/artifact_scanner.py` (7-10, 48); `src/worker_compactor.py`
  (14-30); `src/lazy_ghidra.py`; `src/config_loader.py`; `src/orchestrator_logger.py` (1-16);
  `src/event_emitter.py` (38-53); `src/user_question.py` (122); `src/execution_gate.py` (9);
  `src/coverage_tracker.py` (37-47, 54-69, 99-154, 216-287, 306-337); `src/lead_tracker.py`;
  `src/models/memory.py` (293-330); `src/bridge.py` (40-46, 270-288, 1432-1475, 2060-2181, 2518-2894,
  2970-3173, 4177-4195); `src/ui.py` (758-764, 4218-4228, 5234, 5239-5272); `src/interactive_mode.py`;
  `src/config.py` (53-122, 1363-1366); `pyproject.toml`; `requirements.txt`; `README.md` (26, 92, 224-233,
  266-272); `benchmark/README.md:129`; `benchmark/`; `docs/`; `tests/`.
- **Main tree** (`6224d26`), contrast only: `README.md:3`, `.github/workflows/release.yml`,
  `src/api_health.py`, `src/gui/*` (11 files / 6,801), `tests/test_api_health.py`,
  `tests/test_security_hardening_regressions.py`, `Dockerfile`, `.pre-commit-config.yaml`.
- **Measurements** (read-only, this session): `git merge-base --is-ancestor`; `git rev-list --count` (0 /
  39); `git rev-list --first-parent … | grep -c` on the tip (1); `git diff --stat
  origin/orchestrator..origin/main` (151 files, +22,255/−34,101) and the empty three-dot; `git ls-tree`
  set differences for the 27 / 19 path lists with per-file `wc -l`; per-tree `src` / `tests` LOC sums;
  caller greps for every dead-loop method and every gate/question callback; `python3 -m py_compile` over
  ten central modules (one failure); `CRITICAL_ARTIFACT_PATTERNS` length by direct module load (16); `def
  test_` counts (94 / 50 / 53 / 69 / 13); `pyghidra` grep (0); `git log` for `d5dec8a`, `c62ec6e`,
  `44ee11d`, `5fa72ea` and the `.github` add date.
- **Cross-check**: dates, ADR/P-numbers and citation format here were compared against the other chapters in
  this volume (verified 2026-11-01: 34 numbered chapters present, ch. 36 listed in the README table with
  status ⏳, none contradicting these numbers).
- **Prior chapters**: [21](21-history-and-releases.md) §4/§6 (the incident and branch map — the dates this
  chapter deliberately does not re-derive), [32](32-agentic-core-and-context.md) §9/§10 (main's live loop,
  the gate that fires but never stops, the context engine), [33](33-knowledge-rag-and-sessions.md) §11
  (main's coverage/lead trackers), [34](34-ui-cli-bulk-and-reports.md) (the `src/gui/` split, the
  bulk-rename thread pool), [35](35-benchmark-and-effect.md) (main's test/CI posture, the dspy branch's
  pytest packaging), [20](20-oghidra-inventory.md) (main's publish-only workflow), and [10 — calxgloss
  baseline](10-calxgloss-baseline.md) for ADR-0008/0048/0049/0051/0052/0053/0056/0057 and roadmap
  P21/P26/P27/P30/P33/P42.

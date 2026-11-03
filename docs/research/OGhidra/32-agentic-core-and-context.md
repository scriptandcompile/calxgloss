# 32 — The agentic core and context engine: a loop the LLM steers, a budget that counts characters, and a gate that never closes

> Part of the [OGhidra overview](README.md). The whole *agentic loop* end
> to end — entry routing, the Planning→Execution→Analysis→Evaluation cycles
> in `bridge.py`, the `EXECUTE:` protocol in `command_parser.py`, the
> *execution gate*, the *context budget* / *tiered history* / *session
> compaction* machinery, *task modes*, and transport-level retry — then the
> comparison against calxgloss's fixed pipeline, *attempt* seam, and
> *verdict*-driven *strategy ladder* ([ch. 10](10-calxgloss-baseline.md);
> ADR-0051/0055). All `:line` cites are to the clone at `6224d26` (branch
> `main`); LOC re-measured with `wc -l`; quoted prompt text is verbatim.

## What OGhidra does

### 1. The cast of modules, and the loop constants that bound everything

The agentic core is one giant orchestrator plus six supporting modules
(LOC self-measured): `src/bridge.py` (7,845), `src/config.py` (2,000),
`src/context_manager.py` (1,119), `src/command_parser.py` (606),
`src/execution_gate.py` (353), `src/session_compactor.py` (280),
`src/result_compactor.py` (181), plus
`src/intelligent_context_builder.py` (381 — imported by nothing; §11);
the *workplan* text injected as methodology is markdown (218 lines).

Every bound the loop respects is a config field, and the defaults disagree
with the shipped `.env.example` — which matters, because the README tells
users to copy that file. Verified against `src/config.py` at `6224d26`:

| Constant | Code default | `.env.example` | config.py |
|---|---|---|---|
| `max_execution_steps` (inner loop, tools per execution phase) | 10 | **5** | :48-49 |
| `max_agentic_cycles` (outer cycles) | 3 | **2** | :59-65 |
| `agentic_loop_enabled` | True | true | :67-71 |
| `execution_loop_enabled` | True | — | :52-56 |
| `context_budget` (tokens, nominal) | 80,000 | **100,000** | :98-104 |
| `context_budget_execution` (fraction of budget for tool results) | 0.5 | **0.4** | :106-112 |
| `max_detailed_steps` (sliding window) | 10 | 10 | :128-134 |
| tiered caps current / prev / older loop | 4,000 / 800 / 200 chars | **2,000 / 400 / 100** | :136-154 |
| gate: enabled / artifact / repetition / threshold | True / True / True / 3 | same | :170-190 |
| gate: high-risk-tool / auto-resume timeout | **False** / **0** (forever) | same | :192-201 |
| compaction: enabled / threshold / auto | True / 0.75 / True | same | :204-218 |
| result summarization / result cache / tiered history | True / True / True | same | :114-124 |
| `review_thoroughness` | "standard" | standard | :224-226 |
| `max_steps` (legacy goal/review loop cap) | 5 (no env var) | — | :1470 |
| transport: `timeout` / `max_retries` / `request_delay` | 120 s / 3 / 0 s | **300 s** / — / **2.0 s** | :43, :88-95 |
| LLM logging: enabled / format | True / json | same | :74-80 |

(`.env.example:25,74,80-86,103-106,130-164`.) Bold rows are the drift:
shipped config halves the tier caps, bumps the budget, lowers the
execution fraction, cuts both loop counters, multiplies the timeout — and
the MAX_EXECUTION_STEPS line comments "Increased from 10 to 20" while
shipping `5` (`.env.example:103`), a fossil of the drift pattern
[ch. 20 §9](20-oghidra-inventory.md) documents.

### 2. Entry routing and the outer cycle

`Bridge.process_query` (`src/bridge.py:2340-2360`) is the single entry: with
`agentic_loop_enabled` it runs `process_query_with_agentic_loop`
(`:2002-2246`), otherwise the legacy `process_query_single_pass`
(`:2248-2338`). The agentic method is one
`for cycle in range(1, max_agentic_cycles + 1)` over five phases:
**plan** (`_generate_plan`, def `:2362`) → **execute**
(`_execution_loop`, called `:2122`) → **compact** (§10) → **analyze**
(`_analyze_execution_results`, def `:3586`) → **evaluate**
(`_evaluate_goal_achievement`, def `:4373`). "GOAL ACHIEVED" ends the run;
"GOAL NOT ACHIEVED: <reason>" triggers a replan with the prior cycle's
evidence (§7). The entire method is wrapped in one defensive `try`; any
escape hatch returns the string `f"Error in query processing: {e!s}"` to
the caller (`:2235-2246`) — the same errors-as-data move §4 will meet at
tool level, one story higher. Phases carry their own model routing:
`model_map` maps `planning`/`execution`/`analysis` to model names (empty =
default; `config.py:244-261`); every call goes through
`generate_with_phase(..., phase=...)`.

### 3. Planning phase and the workplans

`_generate_plan` (`:2362-2398`) sends the user goal with a system prompt
whose exact text is `config.py:643-660`: *"You are an expert Reverse
Engineering Planning Agent… Explicitly state which tool(s) will be used
for each step… Always batch discovery tools (list_imports, list_exports)
in the first step."* A vuln-mode variant adds a "Deployment Vulnerability
Awareness" checklist (`config.py:663-708`); selection is task-mode-gated
(`bridge.py:844-852`). Planning output is free-form text: the *plan* is
only ever echoed into the execution prompt, never parsed into a structure.

The methodology layer above it is the *workplan*: the CAG manager loads
four markdown playbooks — `knowledge_capture`, `progressive_analysis`,
`ghidra_tasks`, `malware_analysis_triage` (`src/cag/manager.py:485-497`) —
and retrieval-augmented excerpts arrive as `CAGContext(workplans=[...])`
(`bridge.py:988-993`). `progressive_analysis.md` is six named workplans
(Entry Point :5, Import-Based :41, String-Based :78, Recursive Call Tree
:116, Data Flow :157, Vulnerability/Safety Verification :194), each a
numbered procedure with literal few-shot tool calls (`EXECUTE:
decompile_function(name="ENTRY_POINT")`, :17), and hard verification rules
("Check 1: Are security attributes (lpSecurityAttributes) NULL?", :207).
It is the closest thing OGhidra has to a calxgloss strategy — pre-written
playbooks for recurring investigation shapes — but they enter as *prompt
prose*, not code-level dispatch.

### 4. The execution loop: ten steps, LLM-chosen tools, everything fed back as text

`_execution_loop(plan, max_steps=10)` (`:2960`, called at `:2122`) runs
the inner cycle (`for step in range(1, max_steps + 1)`, `:2997`). Each
step: build prompt (`_build_execution_loop_prompt`, `:3462`), one
`generate_with_phase(phase="execution")` call (`:3006`), regex-scrape
`REASONING:` (`:3012`) + `EXECUTE:` commands (§5), then act. The step
body is a wall of guardrails, all *within*-LLM, none outside it:

- **Completion signal**: `"INVESTIGATION COMPLETE"` or `"GOAL ACHIEVED"`
  anywhere in the response ends the loop (`:3019-3021`); EXECUTEs in the
  same response void it and a scolding message is injected (`:3024-3041`).
- **No tool call**: one free retry — `continue` gives the model an extra
  step, then `break` (`:3071-3077`).
- **Duplicate suppression**: `executed_tools` (canonical `name(params)`
  signatures, `:234`) skips repeats, replying with the original step id +
  150-char excerpt + `get_cached_result(result_id=…)` pointer
  (`:3108-3134`); `get_cached_result` itself is never skipped (`:3110`).
  The separate `tool_repetition_limit` is parked at 999 — "TEMPORARILY
  DISABLED - was causing cache misses (original: 2)" (`:235`).
- **Auto-continuation**: a truncated decompile (`[Total Lines: X]
  [Showing Lines: 1-Y]`) silently fires the follow-up fetch for the rest
  (`:3148-3181`) — the loop repairs Ghidra's pagination for the model.
- **Ranking before injection**: results of the four list tools over 100
  items are replaced by an LLM-ranked top-20 (`LARGE_RESULT_TOOLS`,
  `RANKING_THRESHOLD = 100`, `:3183-3222`).
- **Compaction before injection**: `ResultCompactor.compact` rewrites
  list/dict/text results to `max_chars=2000`, `max_list_items=25`,
  head-40/tail-10 lines plus keyword-priority lines
  (`src/result_compactor.py:15-63`), always appending `"... [content
  omitted; use get_cached_result(...) for full output]"` (`:132`, `:169`);
  wiring measured in ch. 31 (`bridge.py:3236-3238`).
- **Truncation with a retrieval pointer**: whatever is left is cut to
  `_get_max_result_chars()` — 10% of the remaining execution budget,
  floor 5,000 chars (`bridge.py:550-579`) — naming its step id:
  `f'... Use get_cached_result(result_id="step_L{loop}_{step}") for full
  content'` (`:3252-3280`); full results go to the *result cache* under
  that id (`:3307-3309`).
- **ASK_USER**: an `ASK_USER:` directive (`src/user_question.py:53`) sets
  `pending_question` and `break`s the loop (`:3048-3063`) — the outer
  loop then logs *"[PAUSED] Question pending - Phase 1: Log and
  continue"*, nulls the question, and proceeds (`:2134-2140`); nobody
  ever answers — `_ui_question_callback = None` (`:285`), never assigned.

Errors stay data: any step exception becomes
`ToolExecution(success=False, error=f"ERROR: {e}")` and the loop
continues (`:3404-3420`); Ghidra-side failures arrive as error strings
through the ch. 31 surface. The step prompt (`:3479-3522`) is re-rendered
whole each step from the structured `ExecutionPhaseResults` — goal, plan,
progress, previous loops' step ids + 100-char excerpts (max 5),
current-loop results at 500 chars each — not a message-list replay.

### 5. The `EXECUTE:` protocol — and one correction to the brief

`command_parser.py` (606 lines) is a **response parser for the LLM's
pseudo-tool-call format**, not a CLI command layer; the interactive CLI
slash-style commands (`health`, `cag`, `run-tool`, `enumerate-binary`,
`review-session`, `clear_log`) live in `main.py:105-1290`, ch. 34's. The
primary grammar is one regex —
`EXECUTE:\s*([\w_]+)\((.*?)\)` (`command_parser.py:19`) — and five
fallback formats (markdown-fenced EXECUTEs, JSON calls, etc., `:22-28`)
are tried only when the primary regex finds nothing (`:211-242`). Below
the grammar sits a repair shop: a `REQUIRED_PARAMETERS` table (`:31-44`),
alias mapping (`string_search` → `list_strings`, dynamic `xref_lookup`
for any `find_references_to_*`, `:266-287`), parameter-name corrections
(`:294-310`), numeric coercion and `FUN_`/`0x` prefix stripping
(`:319-356`), and a `generate_format_feedback` that explains the syntax
error back to the model verbatim (`:549-606`) so the next step
self-corrects; the system prompt pre-teaches the common mistakes as
comments (`FUNCTION_CALL_BEST_PRACTICES`, `config.py:982-989`: "DO NOT
use the '0x' prefix… Use get_cached_result(result_id=...) if a result is
already available"). This is a protocol with no schema: validation by
regex, repair by dict-lookup, enforcement by scolding prose — the polar
opposite of calxgloss's declared query families and compile-time seam
(ch. 10 :129-160).

### 6. Analysis phase, consolidation, and the legacy review loop

The analysis phase (`:3586-3688`) pre-digests mechanically before the
LLM sees anything: the cycle's results pass through `RelevanceRanker`
(top-10 per category, `config.py:157-159`) and `CorrelationHintBuilder`
(addresses mentioned by ≥2 tools become hints, `config.py:161-167`, both
wired at `bridge.py:3607-3636`); `_consolidate_findings_hybrid`
(`:3769`) merges per-step findings, `_synthesize_report_with_conclusions`
(`:4298`) renders the report, and consolidation applies §10's tiered
truncation to old-loop results (`:3949-3970`). The *review* story proper
is the legacy path: `_generate_analysis` (`:2806-2958`), capped at
`max_goal_steps` — 5 (`bridge.py:90`, `config.py:1470`, no env override)
— where the reviewer model may itself emit EXECUTE calls and a "FINAL
RESPONSE" that merely *describes* actions
(`\b(should|must|need to|will|let's)\s+(call|execute|rename|...)`,
`:2876-2881`) is rejected and the loop continues; only a FINAL RESPONSE
over 100 chars of results ends it (`:2901-2905`). The review prompt
(`bridge.py:892-935`) offers the three thoroughness dialects
(`config.py:228-235`) and a fixed contract ("**Status**: APPROVED or
NEEDS_IMPROVEMENT"). Model grading model, regex gatekeeping for
honesty-of-form only.

### 7. Evaluation, replan, and the custom-mode notepad

`_evaluate_goal_achievement` (`:4373-4494`) truncates the execution
digest to 4,000 chars (keep 2,000 head + 1,500 tail, `:4395-4397`) and
asks the evaluator (system prompt `config.py:991-1004`: *"respond ONLY
with 'GOAL ACHIEVED'… or 'GOAL NOT ACHIEVED'"*), retrying **once** on an
empty reply (`:4464-4471`); parsing is strict — anything not starting
with the two magic strings yields `goal_achieved=False`, reason
"unknown" (`:4475-4486`). On failure the next cycle replans with
`cycle_context` appended: the evaluation's reason, then *"## Already
Executed Tools (DO NOT repeat these exact calls)"* listing every prior
step id + excerpt, plus the
`get_cached_result(result_id="step_L{loop}_{N}")` pointer
(`:2086-2100`). `DEPTH_INSTRUCTIONS` — a canned five-cycle escalation
script ("1: RECONNAISSANCE… 5: GAP FILL", `:2039-2048`) — is injected
**only in task mode** (`:2049-2052`); custom mode keeps a 12-bullet
markdown notepad per binary, LLM-updated after the final response
(`_maybe_update_custom_workplan`, def `:428-476`, called `:2231`/`:2324`).

### 8. Task modes: real in the GUI, drifted in the README

The four *task modes* are `purpose_id`, `malware`, `vuln`, `custom`
(`src/gui/query_input_panel.py:53,62`; `task_mode_enabled` defaults False,
ch. 20 §9). What mode actually changes, verified in code: the system
prompts swap to the 185-line task-mode execution prompt
(`config.py:711-895`) with mandatory methodology — *"1️⃣ DISCOVER
→ Search with targeted filters (limit ≤20)… 3️⃣ TRACE → Decompile the
calling function (MANDATORY)… NEVER use limit>20 for bulk operations"*
(`:775-799`) — plus `DEPTH_INSTRUCTIONS` (§7), the coverage/lead tracker
sections in the step prompt (`bridge.py:3509-3522`), malware-mode CAG
pattern detection firing on decompile/list_strings results (`:3321-3376`,
ch. 33's machinery), and the vuln planning prompt (§3). The README's CLI
recipe (`README.md:251-261`: "`# In CLI: set task_mode <mode>`",
`task_mode general`) is **doc drift**: no `task_mode` string exists in
`main.py`, and `general` is not a mode anywhere in the code.

### 9. The execution gate: triggers that fire, brakes that don't

`execution_gate.py` (353 lines) classifies and pauses. It names
`HIGH_RISK_TOOLS = {"rename_function", "rename_function_by_address"}` —
exactly 2 of the 8 mutating tools ch. 31 counted (`:37-40`, confirming
ch. 31's `:444`) — and that check is also **off by default**
(`GATE_ON_HIGH_RISK_TOOL=False`, `config.py:192-194`). Artifact triggers
scan results through ~20 regexes for "critical artifacts" (service
paths, unquoted-path patterns, credential APIs, `:61-84`); repetition
triggers on 3 identical signatures unless the tool is in
`INVESTIGATION_TOOLS` (`:45-57`). Defaults: gate enabled, artifact on,
repetition on, threshold 3 (`config.py:170-190`). The load-bearing
fact: **a triggered gate never stops anything.** Pre- and post-execution
PAUSEs are met with `self.logger.warning(...)` and the comment *"Phase 1:
Log and continue (Phase 2 will truly block)"* (`bridge.py:3090-3093`,
`:3400-3402`) — the tool executes anyway; `_ui_gate_callback`
(`execution_gate.py:11`) is initialized `None` (`bridge.py:281`), read
once (`:674-675`), assigned nowhere. The one real effect is bookkeeping:
artifact context auto-saved into session knowledge
(`execution_gate.py:222-231,252-319`) and logged gate hits
(`bridge.py:2127-2132`). `inject_feedback` (`execution_gate.py:325`) is
consumed at `bridge.py:2984-2988` but called only from tests, and
`GATE_AUTO_RESUME_TIMEOUT` (0 = wait forever, `config.py:196-201`) is
dead config. The gate is a *detector* wired end-to-end and an
*interactor* wired nowhere: the "OpenCode-inspired" interactive pause
(`config.py:169` comment) exists in the enum and the tests, not in the
shipped runtime.

### 10. Context engine: character arithmetic, tiered history, two compactors

`context_manager.py` (1,119) is the budget ledger. **All token math is
`len(text) // 4`** (`:96-97`, `estimate_tokens` `:212-214`,
`chars_per_token=4.0`) — grep confirms no `tiktoken` anywhere in the
repo, requirements included. `ContextBudget` splits the nominal budget:
system 25% / execution `context_budget_execution` (0.5) / history 15% /
response 20% (`:200-207`). The *result cache* (`ResultCache`, max 100
entries, evicting "bottom 20% by priority then timestamp", `:175-183`)
holds full tool outputs; prompts carry ids like
`r{counter}_{tool}_{param_hash}` (`:94`) and the LLM pulls full text
back via `get_cached_result` → `get_full_result` (`bridge.py:1302-1322`,
dispatch `:1697-1699`); a distinct, older *tool-level* memo keyed by
canonical params sits under `_get_cached_result`, its `NO_CACHE_COMMANDS`
list excluding the volatile list tools (`:1898-1935`; caching skips
`ERROR:` strings, `:1939-1960` — the no-invalidation cache ch. 31
flagged). *Tiered history* (`:614-654`): current-cycle results keep
4,000 chars, previous-cycle results become 800-char bullet summaries,
older cycles one 200-char line with a `get_cached_result` reference —
code defaults; `.env.example:141-145` ships 2,000/400/100 — the display
policy §4's step prompt and §6's consolidation both call
(`get_tiered_display_content`, `bridge.py:3970`). Oversized results can
be *LLM-summarized* rather than cut: input capped at 12,000 chars, "2-4
sentences… Preserve: function names, addresses, key patterns, errors",
`_smart_truncate` on failure (`:465-488`).

The *session compactor* is a separate, cycle-boundary mechanism
(wired `bridge.py:2143-2161`): when usage (chars ÷ budget, `:86`) crosses
0.75, first *prune* — oldest tool outputs beyond a protect-count of 10
and a 20,000-char floor replaced by `[PRUNED]` previews
(`session_compactor.py:21-23,109-164`) — then, still over, *compact*:
the LLM writes a continuation summary under a fixed prompt (`:166-224`)
with a non-LLM `_fallback_summary` if that fails (`:253-276`). Nothing
is undone or journaled: compaction destructively rewrites what the next
cycle reads.

### 11. Seams designed, seams never wired

A grep-complete census of orphaned machinery in the agentic core
(verified: whole-tree `grep -rn`, 2026-11-01):

| Orphan | Size | State |
|---|---|---|
| `IntelligentContextBuilder` (`intelligent_context_builder.py`) | 381 LOC | keyword-scored intent classifier (data_flow/security/implementation/call_flow, `:28-83`, `:132-154`) rendering CAG function metadata into briefs — **zero importers tree-wide** |
| `_should_analyze_findings` / `_create_analysis_checkpoint` (`bridge.py:478-549`) | 72 LOC | "force reflection every 3 tool executions" ("lesson from the ninja trojan investigation failure", `:483-485`) — **never called anywhere, not even by tests** |
| `_check_implied_actions_without_commands` (`bridge.py:5280-5333`) | 54 LOC | prompts the LLM when prose implies a rename it never executed — tests only (`tests/test_bridge.py:35`) |
| `inject_feedback` (`execution_gate.py:325`) | — | consumed in `bridge.py:2984-2988`, called from tests only |
| `tool_repetition_limit` (`bridge.py:235`) | — | "TEMPORARILY DISABLED", parked at 999 |
| `GATE_AUTO_RESUME_TIMEOUT` (`config.py:196-201`) | — | no code reads it into a wait |

The pattern is consistent: *forced reflection* — the only design note
naming a concrete past failure — was built unwired, like the gate's
blocking half: Phase 1 shipped, Phase 2 never arrived in 147 commits (ch. 21).

### 12. Transport, retries, and the JSONL telemetry

Beneath the loop, the LLM clients do the real fault handling. Both
`ollama_client.py` and `custom_api_client.py` wrap HTTP in tenacity
`Retrying(stop=stop_after_attempt(max_retries+1),
wait=wait_exponential(multiplier=1, min=2, max=10),
retry=retry_if_exception(is_retryable_exception), reraise=True)` with
retryable = 429/5xx/conn/timeout (`ollama_client.py:329-336`, `:130-138`;
3 retries default — `config.py:93-95`, ollama
`getattr(config, "max_retries", 3)` `ollama_client.py:186`),
timeouts 120 s ollama (`:164`) / 300 s custom (`custom_api_client.py:57`),
generation capped by `num_predict` 2000 (`:325`). The custom-API client
adds adaptive throttling: Retry-After respect capped at 60 s, interval
grow/shrink with jitter, and a `throttle_state` record logged per change
(`custom_api_client.py:74-135`, `:206-276`). Telemetry:
`LLM_LOGGING_ENABLED` writes one JSON line per interaction to
`logs/llm_interactions.log` — full prompts, responses, Ollama's real
`prompt_eval_count`/`eval_count` token counts, and timing
(`ollama_client.py:364-382`, toggles `config.py:74-80`) — on by default
for Ollama (`:74`) and custom-API (`:1310`), **off** for Google (`:1195`)
and external (`:1257`). Fault *semantics* never rise above transport: an
empty response is an execution-loop `continue` (`bridge.py:3071-3077`) or
one evaluation-phase re-ask (`:4464-4471`); overflow is pre-empted by
§10's char arithmetic, never observed as a provider error; a dead server
re-raises into `process_query`'s catch-all string (`:2235-2246`).

## Comparison with calxgloss

### Posture: the LLM drives the loop vs the loop is the program

calxgloss's per-function loop — read cache ▸ evidence warmup ▸ fetch ▸
prompt ▸ translate ▸ verify ▸ retry ▸ commit (ch. 10 :50-55) — has zero
degrees of freedom at run time: the *unit of work* is one function, the
sequence is code, and the LLM speaks only inside an *attempt* (ADR-0051).
OGhidra inverts this: the LLM picks which tools run, in what order, for
how many steps, and whether it is done — its only determinism is
*counters* (steps, cycles, char caps) plus prose playbooks. Neither the
queue nor the ladder has an OGhidra analogue: its "escalation ladder" is
DEPTH_INSTRUCTIONS — prompt-level, never verdict-driven.

### Work records: a session transcript vs the attempt ledger

OGhidra's persistent residue of a run is a session store, CAG knowledge,
`analysis_state` dicts, and renames made directly in the live Ghidra
program — no per-unit verdict record, no branch-per-attempt, no undo of
a bad *attempt* (the gate's bookkeeping only writes notes). calxgloss's
git-backed attempt branches and durable verification records (ch. 10
:197-203) mean every failure is re-playable and every success
bisectable. OGhidra can *iterate* freely because its canvas (the
Ghidra program) is meant to be edited in place; calxgloss can *audit*
rigorously because each *attempt* is a branch and a verdict.

### Fault story: retries at the socket vs fault monitors above it

OGhidra's fault ladder has four rungs — transport retry (tenacity, 3,
429/5xx only), empty-response handling (one re-ask at evaluation,
`continue` at execution), replan on "GOAL NOT ACHIEVED", and
compaction-before-overflow — plus errors-as-data feeding every failure
back as text (§4, ch. 31 §errors). No rung recognizes a *class* of
failure: no context-overflow monitor (prevented by §10's arithmetic,
never detected), no hallucination or divergence detector (the
FINAL-RESPONSE regex, `:2876-2897`, catches form-laziness, not
fabrication), no loop detector that stops. calxgloss runs the opposite
shape: *fault monitors* end attempts on named signatures, logging
recovery guidance (ch. 10 :87-91); the *strategy ladder* routes each
failing *verdict* into a different prompt and a larger tier. Both retry
on local models; only calxgloss retries *informed by what went wrong*.

### Verdict: LLM self-review is not a verdict — say it plainly

OGhidra's terminal judgment is always a model judging prose: the
evaluator parsing "GOAL ACHIEVED" (§7), the reviewer's APPROVED /
NEEDS_IMPROVEMENT (§6), the completion-signal regex (§4). calxgloss's
*verdict* is `cargo check` + behavioral tests against Wine-captured
baselines + ordered API-trace containment (ch. 10 :287-295) — machine
evidence that exists independently of the model that produced the code.
**There is no equivalence to be had here**: OGhidra's self-review can
tell you the agent believes it finished; it cannot tell you the binary
was understood, because nothing in OGhidra can fail in a way that
falsifies a wrong answer. The strict-parsing details (§6's regex
gatekeeping) show the authors knew exactly how much to distrust the
model's conclusion — and had nothing to replace it with.

### Steppers and brakes

calxgloss has no stepper because its LLM holds no mutating tools —
nothing to pause (ch. 31 §tool surface). OGhidra designed the pause for
itself and never closed the loop: gate triggers fire, log, and execute
anyway; ASK_USER pauses are cleared with "Phase 1: Log and continue"
(§9, §4). The interesting borrowing target is not OGhidra's gate but
the combination neither ships: calxgloss has the verdict machinery and
lacks an interactive point; OGhidra sketched the interactive point
(gate signals, feedback injection at `bridge.py:2984-2988`) and lacks
the machinery worth pausing *for*.

### Observability

Both projects log full LLM I/O: calxgloss has `prompt_strategy_log.json`,
`token_usage.json`, `llm_io/log.jsonl` keyed to *attempts* and strategies
(ch. 10 :260-262); OGhidra has per-interaction JSONL with prompts,
responses, real `eval_count` counts, and timings, phase-tagged and on by
default (§12). OGhidra's phase tags and toggles are nicer config;
calxgloss's logs carry *policy context* (which strategy, which verdict
followed) that OGhidra's cannot, because OGhidra has no verdict; the
`throttle_state` record has no calxgloss counterpart (steal list below).

### Overlap / calxgloss-only / OGhidra-only

- **Overlap:** retry-on-local-models premise; full raw prompt/response
  logging on by default; duplicate-call suppression (calxgloss by
  "evidence is never re-gathered", ADR-0051; OGhidra by `executed_tools`
  + step-id pointers); budget-guarded engine calls (per-function budgets,
  ch. 10 :140-141, vs char caps); keyword-priority compaction preserving
  headers and retrieval pointers (`result_compactor.py:91-134`);
  pre-digestion before prompts (rankers/hints vs the scan registry).
- **calxgloss-only:** machine verdicts (compile/test/trace); fault
  monitors with named signatures; strategy ladder + five context tiers;
  git-backed attempt branches/records; declared query families with
  capability admission; typed refusals; human steering at *unit boundaries*.
- **OGhidra-only:** free-form LLM-planned multi-tool exploration of the
  live program; the workplan library; *task modes* that swap methodology
  wholesale; a detector set (artifact regexes, doom-loop counter,
  implied-action nudge) whose brakes are unwired; LLM summarization of
  oversized tool output; per-phase model routing; tiered history with a
  `get_cached_result` retrieval escape hatch.

### Verdict

The agentic core is an industrious prompt-engineering artifact — every
failure mode its authors hit produced another guardrail (commented as
such: "ninja trojan investigation failure", `:483-485`) — but it is a
loop with no epistemology. Its counters bound the *cost* of
confabulation; nothing bounds its *correctness*, and the one component
built to bound correctness (forced reflection every 3 tools, §11) is
unwired. calxgloss's fixed pipeline looks impoverished next to OGhidra's
playbook richness — and is richer where it counts: its retry story
routes on machine *verdicts*, not another prompt. **OGhidra manages
context more cleverly than calxgloss manages prompt assembly; calxgloss
knows when to stop and whether to believe itself, which OGhidra never
can.**

Steal list, in priority order:

1. **Tiered history with retrieval pointers** (`context_manager.py:614-654`
   + step-id sidecar): as calxgloss bundles grow (P44, P21), an *age-tier*
   policy — full this attempt, summary last attempt, one-line + record-id
   reference older — keeps retry-loop prompts small while every dropped
   byte stays fetchable from attempt records: calxgloss drops sections
   when evidence is missing; this drops *staleness*, keeps retrievability.
2. **Result-compaction shape** (`result_compactor.py`): header-preserving
   (the `[Total:]` invariant ch. 31 already adopted), keyword-priority
   rows, tail lines, explicit "full output at id" marker — the template
   for compacting filed documents into *evidence bundle* sections without
   lying about what was cut.
3. **Workplan playbooks as prose methodology** (task-mode DISCOVER→
   LOCATE→TRACE→VERIFY, limit≤20 rules, `config.py:775-799`): P29
   (interactive ad-hoc queries) needs exactly this methodology text, and
   OGhidra's vuln checklist ("unquoted service paths", deployment risk)
   is field-tested RE craft worth transcribing.
4. **Doom-loop / artifact *detection* as fault-monitor signals**:
   3-identical-call signatures belong beside calxgloss's infinite-loop
   monitor (`infinite_loop.rs`); detect-and-*log*-only is the right first
   phase — OGhidra proves phase-2 wiring is where such features go to die.
5. **Phase-keyed `model_map`** (`config.py:244-261`): config-level
   routing (a cheaper model for digest/consolidation calls) — calxgloss's
   ladder is model-agnostic today.
6. **`throttle_state` telemetry + Retry-After-aware client behavior**
   (`custom_api_client.py:74-135`) for shared local-model deployments.
7. **"Already done" banners on ladder re-entry** (`:3108-3134`,
   `:2086-2100`): show later *attempts* what earlier ones already
   asserted, where calxgloss currently just swaps the tier.

What calxgloss should **not** copy: the `EXECUTE:` prose-protocol with
its five-format fallback parser and parameter auto-repair (§5 — never
make *syntax* the model's game to fumble); the gate-theater pattern of
detectors with unwired brakes and `# Phase 2 will truly block` comments
shipped forever; LLM self-evaluation ("GOAL ACHIEVED", FINAL RESPONSE
regex-gatekeeping) as any stop condition; the `len//4` token fiction as
accounting (calxgloss already gets real counts from its API logs — never
budget in fake tokens); the one-giant-`try` wrapping whole workflows
into an error *string*; dead-orphan modules (381-line builder, no
importer — "delete orphans, don't park them", ch. 10 :250-251, is the
vaccine); and destructive in-place compaction of run history without a
record — the attempt ledger never rewrites the past, which is precisely
why its audit works.

## Sources

- OGhidra clone at `6224d26` (branch `main`): `src/bridge.py` (7,845
  lines; loop :2002-2360, execution loop :2960-3428, prompt builder
  :3462-3585, review :2806-2958, evaluation :4373-4494, cache getters
  :1302-1348/:1898-1960, budget sizing :550-579, phase/prompt selection
  :838-875, workplan notepad :428-476, orphans :478-549/:5280-5333,
  constructor state :210-240); `src/config.py` (2,000; constants
  :29-261, prompts :643-1019, logging defaults :74-80/:1195/:1257/:1310,
  `max_steps` :1470); `src/command_parser.py` (606; grammar :19-28,
  repair :211-356, feedback :549-606); `src/execution_gate.py` (353;
  :37-40, :45-57, :61-84, :325); `src/context_manager.py` (1,119;
  :200-214, :94-183, :465-488, :614-654, :717-758);
  `src/session_compactor.py` (280; :21-23, :86, :109-224, :253-276);
  `src/result_compactor.py` (181; policy :15-181);
  `src/intelligent_context_builder.py` (381; orphan verified by
  whole-tree grep); `src/user_question.py:53-57`;
  `src/ollama_client.py` (:130-138, :164, :186, :325-343, :364-382),
  `src/custom_api_client.py` (:19, :57, :74-135, :206-276);
  `src/cag/manager.py:485-497`; `src/cag/workplans/progressive_analysis.md`
  (218); `src/gui/query_input_panel.py:53-65`; `main.py:105-1290, :1396`;
  `.env.example:25,74,80-86,103-164`; `README.md:251-261`;
  `tests/test_bridge.py:35-52`, `tests/test_execution_gate.py:251-279`.
- Grep-complete checks on the clone (2026-11-01): `tiktoken` — absent;
  `IntelligentContextBuilder` — no importers; `_ui_gate_callback` /
  `_ui_question_callback` — never assigned; `_should_analyze_findings` /
  `_create_analysis_checkpoint` — no callers; `task_mode` — absent from
  `main.py`; `inject_feedback` — tests only. LOC counts by `wc -l`.
- calxgloss side: [10-calxgloss-baseline](10-calxgloss-baseline.md)
  (pipeline loop :50-55; attempt seam + ladder :71-78; five tiers
  :79-83; fault monitors :84-88; git flow :197-203; logs :256-259;
  verification :269-296); ADR-0051/0055;
  [31](31-ghidra-bridge-and-backends.md) (tool surface, errors-as-data,
  gate preview :236-239/:444); [20 §9](20-oghidra-inventory.md);
  [21](21-history-and-releases.md).
- Sibling chapters: [33](33-knowledge-rag-and-sessions.md) (CAG workplan
  retrieval and the pattern engine are ch. 33's; this chapter covers
  their consumption by the loop), [34](34-ui-cli-bulk-and-reports.md)
  (the CLI commands this chapter deliberately does not cover).

# 34 — Agent layer: ReAct orchestration, MCP transports, tool catalog, approval gates

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-02.

This chapter maps the whole agent layer end to end: the ReAct orchestrator that turns a Query-tab objective into a plan→act→reflect→synthesize loop, the prompts it feeds the LLM, the MCP client stack that carries tool calls, the built-in IDA tool catalogs (internal + graphrag + Actions-tab), and the approval gate that covers only some paths.

## 1. ReAct orchestrator — `src/services/react/react_orchestrator.py` (797 LOC)

### Phases

`analyze()` (react_orchestrator.py:119-245) runs three phases, not the classic free-form ReAct loop:

1. **Planning** (:148-157). If the controller already obtained user approval for a plan, the orchestrator seeds its todo manager from that plan text and *skips a second planning LLM call* (:150-153). Otherwise `_run_planning` (:247-262) sends the planning prompt with tools disabled and parses the reply into todos.
2. **Investigation loop** (:162-207). One iteration = one todo item. Loop breaks on `max_iterations` (:167-169), all todos complete (:171-173), or no pending todo (:176-179). Each iteration: mark next todo in-progress → run `_run_investigation_iteration` → mark complete → run reflection (:201-207).
3. **Synthesis** (:209-213). `_run_synthesis` (:509-522) is the only phase that streams content to the UI (`emit_content=True`); planning/reflection output is internal, rendered as task cards instead.

There is no separate "act" phase — acting is a multi-turn tool-calling loop inside each iteration (§ below). "Reflect" is a per-iteration LLM call with adaptive planning.

### The act loop (investigation iteration)

`_run_investigation_iteration` (:264-390): builds the iteration prompt from objective + todo list + findings (:274-280), then loops: LLM-with-tools → execute tools → append results → call LLM again with an empty user message (`""`, :381) until the model stops emitting tool calls. `max_tool_rounds = 10` is hardcoded per iteration (:286) — this is *ReAct's* loop guard; the 5-round/3-repeat guard from ch33 belongs to the plain Query path only.

Two anti-loop mechanisms beyond rounds:

- **Per-tool failure escalation** (:339-351): 2 consecutive failures appends "Consider using a different tool"; 3+ appends "Do NOT call it again — use a different approach or skip this step."
- **Orphan cleanup on cancel** (:296-323): an assistant message with tool calls but no results is popped before/after tool execution so the history stays valid; `_cleanup_orphaned_tool_calls` (:91-117) delegates to `ContextWindowManager._validate_and_fix_tool_pairs`.

### Findings cache — `src/services/react/findings_cache.py`

`FindingsCache.extract_from_tool_output` (:59-94) scrapes tool output heuristically: per line, skip if <20 or >300 chars, skip JSON-ish lines, require `:` or ≥4 words, dedupe, and take **at most 3 findings per tool result** (:92-93). Relevance is keyword-scored: HIGH list (vulnerability/exploit/overflow/…, :22-28) → 9, MEDIUM list (function/xref/string/…, :30-34) → 6, else 3, and lines scoring ≤3 are discarded (:78-80, :96-106). `format_for_prompt(max_findings=50)` (:108-131) injects the top-50 sorted by relevance into iteration/reflection prompts; `format_detailed` (:133-149) raises the cap to 100 findings plus per-iteration summaries truncated at 2000 chars for synthesis. There is no eviction — the cache is only `clear()`ed at the start of `analyze()` (:136).

### Todo list — `src/services/react/todo_list_manager.py`

States are `PENDING / IN_PROGRESS / COMPLETE` (react_models.py:16-20). Parsing accepts three formats in order of specificity: markdown checkbox `- [ ]`, numbered `1.`, plain bullets (:35-51 in todo_list_manager.py); an unparsable plan falls back to one default todo "Investigate the user's question" (:59-62). Prompt-facing rendering uses `- [x]` / `- [->]` / `- [ ]` markers (:148-170); the iteration prompt tells the model to "Focus on the task marked with [->]" (react_prompts.py:76). Reflection-driven updates only remove **pending** todos (never in-progress/complete) and dedupe additions by substring match (:186-217). `to_transcript_snapshot` (:126-146) is the payload for `todo_updated`-style transcript cards: summary string "N/M tasks complete" (:122-124), per-task status + evidence, counts.

### Reflection & adaptive planning

`_run_reflection` (:392-466) is skipped until `min_findings_for_ready = 5` findings exist (:405-407, react_models.py:89). The reply is regex-parsed for `DECISION:` (READY), `- ADD:` and `- REMOVE:` lines (:468-507). Newly added tasks **extend the budget**: `max_iterations += 2 * len(new_tasks)` (:428-432) — so a runaway reflector can grow the investigation unboundedly (inference: no cap on this extension). Each reflection emits two synthetic findings, e.g. `"Decision: READY - Sufficient information gathered, synthesizing final answer"` (:443-465).

### Context compaction call sites

`ContextWindowManager` is constructed per orchestrator with ReAct-owned config (:66-73 from react_models.py:91-95: 150 000 token window, 0.75 threshold, 10 000-token tool-result cap, 2 recent tool pairs preserved). Four call sites:

- `:107` — `_validate_and_fix_tool_pairs` during error/cancel cleanup (orphan removal).
- `:354` — `truncate_tool_result` on *every* tool result before it enters history (10k-token cap; context_window_manager.py:188).
- `:547` — `check_and_manage` before every no-tools LLM call (plan/reflect/synthesize); tools are passed in only when history already contains tool messages, a Bedrock-via-LiteLLM quirk (:537-549).
- `:648` — `check_and_manage` before every with-tools LLM call.

`check_and_manage` compresses when `token_count >= trigger_threshold` (context_window_manager.py:111), i.e. 75% of 150k — the same numbers seen in ch33, consumed here.

### Other mechanics

- LLM calls retry `NetworkError` up to `max_retries=3` with doubling delay from 2s (:573-615, react_models.py:97-99).
- With-tools calls set `tool_choice=ToolChoiceMode.REQUIRED_INITIAL.to_openai_tool_choice(history)` (:671). The enum (`src/services/models/transcript_models.py:25-40`; *cite corrected 2026-11-02 — :44+ is `ArtifactRef`*) returns `"required"` unless the last non-system message is a `tool` result → **forces the model to call at least one tool when starting each fresh prompt**, then `"auto"` once tool results are in history.
- Temperature 0.7, `stream=True`, `max_tokens` from provider (:564-571, :664-672).
- Tool lifecycle events fire through `on_tool_event` with phases `requested / started / completed / failed` (:743-788) — these feed the Query tab's tool cards.

### Plan approval flow end-to-end (controller ↔ Approve Plan button)

All in `src/controllers/query_controller.py`:

1. `_submit_agentic_query` (:3784+) generates a `react_run_id`, loads context, and calls `_start_react_planning` (:3682-3695) which runs `ReActPlanningThread` (class defined at :492) with a prompt built by `_build_react_planning_prompt` (:3667-3680) — the planner prompt plus "Return only the proposed markdown checklist…" or, on refinement, the previous plan + "## User Refinement Request" block.
2. `_on_react_plan_ready` (:3697-3714) stores `_pending_react_plan`, shows it in the view (`set_pending_plan`) and appends a todo snapshot with `agent_phase: "plan_pending"`.
3. The user can refine repeatedly: `_refine_react_plan` (:3724-3743) logs the refinement as a `USER_MESSAGE` transcript event (`agent_phase: plan_refinement`) and re-plans with the previous plan in context.
4. The view's `plan_approved_requested` signal (:658) is wired to `on_react_plan_approved` (:3756-3782): emits an `iteration_notice` event "Approved agentic investigation plan" (`category: plan_approved`), creates the provider, and calls `_start_react_analysis(..., approved_plan=self._pending_react_plan)` — which lands in the orchestrator's seed-and-skip path (:150-153). `_start_react_analysis` (:3892-3942; *corrected 2026-11-02 — def at :3892*) defaults the config via the caller's fallback to `ReActConfig(max_iterations=15, reflection_enabled=True)` (:3780), pulls tools via `mcp_connection_manager.get_available_tools_for_llm()` if empty (:3902-3904), and wires the thread signals to transcript appenders (:3931-3940).

### Continuation bridge consumption

`_build_react_continuation_bridge` (:2606-2622) asks `transcript_service.build_react_continuation_bridge(binary_hash, chat_id)` for a markdown digest of the last ReAct run (run id, `finding_count`, `pending_count`); `_inject_react_bridge_message` (:2626-2632; *corrected 2026-11-02 — earlier draft said :2624-2631*) inserts it as an **assistant** message right after the system prompt. It is applied in `_prepare_native_messages` (:2647) and again at :3322, so after a chat reload a plain follow-up message still carries the prior investigation's findings. (The bridge builder itself lives in `transcript_service` — seam for another chapter.)

## 2. The prompts — `src/services/react/react_prompts.py` (verbatim)

System prompt (:17-26):

> You are an expert reverse engineering assistant conducting an autonomous investigation.
> You have access to MCP tools for binary analysis. Use these tools to systematically investigate the user's question.
> Guidelines: … "Be thorough but efficient - don't make redundant tool calls" … "Know when you have enough information to provide a comprehensive answer"

Planning prompt (:35-54) — the plan the Approve Plan UI shows is exactly this format:

> **Task**: Based on the user's question, propose a list of 3-5 investigation steps to answer this question thoroughly.
> Format your response as a markdown checklist:
> - [ ] First investigation step …
> Keep steps concrete and achievable in 1-2 tool calls each.

Investigation/act prompt (:65-83), injected per iteration:

> **Current Task**: Focus on the task marked with [->] in the progress list above.
> **Instructions**:
> 1. Think about what information you still need for the current task
> 2. Call the appropriate MCP tool(s) to gather that information
> 3. After receiving results, briefly summarize what you learned
> If you believe the current task is complete based on previous findings, you may proceed without additional tool calls.

Plus a soft budget nudge when ≤3 iterations remain (:62-63): "Only {remaining_iterations} iterations remaining. Consider synthesizing your answer soon…".

Reflection prompt (:89-123) — machine-parsed contract:

> **Required Response Format** (use plain text, keep label and content on same line):
> **Assessment:** … **Plan Updates:** - ADD: [task] (or "None") - REMOVE: [task] (or "None")
> **Decision:** READY or CONTINUE
> Say **READY** only if ALL planned tasks are complete OR remaining tasks would not meaningfully improve the answer
> Do NOT use code blocks, backticks, or extra newlines after labels

Synthesis prompt (:129-149):

> You've completed your investigation. … synthesize your findings into a clear, actionable response that:
> 1. Directly addresses the user's question 2. References specific evidence from your investigation 3. Highlights the most important discoveries 4. Provides recommendations or next steps if applicable

`get_tool_guidance_prompt` (:151-161) lists available tool names, but is **not called anywhere in the orchestrator** (verified negative: no `get_tool_guidance_prompt` call in react_orchestrator.py via grep of the file's content read above). No model-facing tool schema descriptions are defined in this file; schemas come from the tool catalogs (§6-7).

## 3. Threading — `src/controllers/react_thread.py` (166 LOC)

`ReActOrchestratorThread(QThread)` runs the async orchestrator in a fresh `asyncio` event loop per thread (:87-97) and translates every orchestrator callback into a Qt `Signal` (:29-38): `planning_complete`, `iteration_started(int,str)`, `iteration_complete(int,str)`, `todos_updated(object)`, `finding_discovered(object)`, `progress_update(str,int)`, `content_chunk(str)`, `tool_event(object)`, `analysis_complete(object)`, `analysis_error(str)`. `cancel()` sets a flag and forwards to the orchestrator (:74-79); all emit-callbacks skip emission once cancelled (:134-166).

## 4. Data shapes — `src/services/models/react_models.py` (99 LOC)

- `TodoStatus{PENDING,IN_PROGRESS,COMPLETE}` (:16-20); `ReActStatus{SUCCESS,MAX_ITERATIONS,CANCELLED,ERROR}` (:23-28).
- `Todo(task, status, evidence, tools_used)` (:31-47); `Finding(fact, evidence, tool_used, relevance 1-10, timestamp, iteration)` (:50-58).
- `ReActResult(status, answer, findings, iteration_count, tool_call_count, duration_seconds, iteration_summaries)` (:61-80).
- `ReActConfig` (:83-99): `max_iterations=15`, `tool_timeout=30.0` (not enforced by the orchestrator itself — the MCP orchestrator has its own 30s; inference), `reflection_enabled=True`, `min_findings_for_ready=5`, `context_window_tokens=150000`, `context_threshold_percent=0.75`, `max_tool_result_tokens=10000`, `min_recent_tool_pairs=2`, `max_retries=3`, `retry_delay=2.0`.

## 5. MCP stack

### Transports — `src/services/mcp_client.py` (446 LOC)

Exact transport strings: `"sse"`, `"streamablehttp"`, `"stdio"` (dispatch at :86-93). SDK imports are individually guarded: `mcp.client.sse.sse_client` (:37), `mcp.client.streamable_http.streamablehttp_client` (:45), `mcp.client.stdio.stdio_client, StdioServerParameters` (:53). `streamablehttp_client` yields `(read, write, session_id)` — the third value is discarded (:192-194). Stdio builds `StdioServerParameters(command=…, args=…, env=…, cwd=…)` (:218-223) — the settings columns from cf39541 — and redirects server stderr to `os.devnull` when IDA's `sys.stderr` has no `fileno()` (:147-159), with a Windows hint to install `pywin32` (:213-216). Session `initialize()` is wrapped in `asyncio.wait_for(timeout=config.timeout)` on all three paths (:179, :202, :231). Failed connects call `_cleanup_contexts` to exit half-entered async context managers in the same task, avoiding anyio "cancel scope in a different task" errors (:99-145).

Per-connection tool discovery caches `MCPTool` objects from `session.list_tools()` (:244-272) and resources from `list_resources()` (:273-289). `call_tool` flattens `result.content` parts to joined text (:291-327).

Multi-server merge: `MCPClient._merge_tools` prefixes collisions with `"{server_name}.{tool_name}"` for the *second* server (:390-398). *This class is largely legacy* — the live runtime path is `MCPClientService`.

### `MCPClientService` (598 LOC) — connect-once, call-fresh

- Config load reads `settings_service.get_mcp_providers()` and normalizes the transport string via map `{'http','streamablehttp','streamable_http' → 'streamablehttp'; 'sse'; 'stdio'}`, default `streamablehttp`, timeout default 30.0, plus `command/args/env/cwd` passthrough (:87-138).
- `_run_in_background_with_events(fn, timeout)` runs anyio work on a `ThreadPoolExecutor` while pumping `QApplication.processEvents()` on the main thread (:205-231) — because in-IDA MCP servers (IDAssistMCP) call `idaapi.execute_sync`, which would deadlock a blocked main thread.
- `_connect_server_async` (:397-451): connects with a **capped 10s timeout** (`dc_replace(server_config, timeout=10.0)`), discovers tools, caches metadata in `MCPConnectionInfo`, then **disconnects**. Connections are not kept alive.
- `execute_tool` (:495-556) opens a **fresh connection per tool call** via `_execute_with_fresh_connection` (:562-587) so async context managers enter/exit inside one `anyio.run()`. `get_tools_for_llm(server_filter)` (:482-493) formats cached tools via `MCPTool.to_llm_format()`.
- Singleton with per-process lifecycle flag (:55-81, :329-361).

### `MCPConnectionManager` (296 LOC) — the tool surface the tabs consume

Lazy init: `ensure_connections()` rate-limits retries to one attempt per 5s (:52-53, :119-171). `get_available_tools_for_llm()` (:66-117) is the merge point, cached 60s (:52): **external MCP tools + internal tools + graphrag tools**, where external wins name collisions (`get_internal_tools_for_llm(exclude_names=external_names)`, `get_graphrag_tools_for_llm(exclude_names=external_names)`; comment: external "is typically more featureful" :70-74). Graphrag tools are "always available, even without MCP connection" (:106-107). OpenAI-format conversion (name/description/parameters, minimal `{}` schema when absent) at :196-241.

### `MCPToolOrchestrator` (520 LOC) — dispatch

- Routing table `_INTERNAL_TOOL_NAMES = internal ∪ graphrag` (:38); `_tool_server_map` refreshed on a 30s TTL (:43-45).
- `execute_tool_calls` runs up to **3 tools concurrently** on a `ThreadPoolExecutor` (`_max_concurrent_tools=3`, :46, :161-187), overall collect timeout `tool_timeout + 10` (:169); results re-sorted to original call order (:185).
- Per call (:189-335): graphrag tools first (require a binary hash; server label `"__graphrag__"`; error dicts inside JSON content are promoted to `ToolResult.error` :222-229), then internal tools (label `"__internal__"`, :241-256) — internal/graphrag only apply when *no external server owns that name* (:195-196, :241-242), with a stale-map fallback re-check (:260-281), else external via `mcp_service.execute_tool` with `timeout=30.0` (:47, :296-303).
- Argument enhancement injects `filename` / `address` from binary context for whitelisted tool names (:337-393) — aimed at third-party servers like the `get_function_info`/`decompile_function` family.
- Post-hook: `rename_function` renames are synced into the knowledge graph via `GraphStore.update_node_name`, best-effort (:247-249, :395-430), and also recorded for provenance inside the internal tool itself (internal_tools.py:355-366).
- Error shaping for the LLM: `format_tool_results_for_llm` wraps failures as `ERROR: Tool 'x' failed with error: … (Server: …) (Execution time: …s)` (:443-480); a human-readable card summary at :482-520.

`mcp_exceptions.py`: hierarchy `MCPError` → `MCPConfigurationError / MCPConnectionError(→MCPTimeoutError, MCPTransportError, MCPAuthenticationError) / MCPToolError / MCPResourceError / MCPProtocolError` (:9-51). `requirements.txt:8` pins `mcp==1.23.3`.

## 6. Internal tools — `src/services/internal_tools.py` (466 LOC)

Built-ins, no external MCP server needed; all IDA calls go through `execute_on_main_thread`. `INTERNAL_TOOL_DEFINITIONS` (:50-155), 9 tools:

| Tool | Purpose | Effect |
|---|---|---|
| `decompile_function` | Hex-Rays pseudo-C for a function (:52-61) | read-only |
| `get_disassembly` | disasm listing of a function (:63-72) | read-only |
| `get_xrefs` | code+data xrefs to/from an address, `direction` enum (:74-84) | read-only |
| `navigate_to` | move IDA cursor (`ida_kernwin.jumpto`, :322) | UI-only |
| `rename_function` | rename via `ida_name.set_name(SN_CHECK)` (:346) | **IDB-mutating** + `record_llm_rename` provenance (:364) |
| `rename_variable` | `ida_hexrays.rename_lvar` (:383) | **IDB-mutating** |
| `get_function_list` | list functions with filter/limit=100 (:397-426) | read-only |
| `get_strings` | strings ≥min_length, limit=100 (:429-453) | read-only |
| `ga_add_document` | create a standalone markdown chat document via registered handler (:144-154, :456-466) | DB-mutating (chat store) |

Exposure: `MCPConnectionManager.get_available_tools_for_llm` adds them to the LLM tool list (mcp_connection_manager.py:104), so they are available to **both Query (with MCP checkbox) and ReAct** — `query_controller.py:1378` (plain path) and :3903 (ReAct) pull from the same merged list. Execution falls back to internal handlers only when no external server claims the name (mcp_tool_orchestrator.py:241-242, :266-281).

### Actions-tab tools — `actions_tools.py` + `actions_tool_registry.py`

A separate, proposal-only catalog of 4 (`actions_tool_registry.py:33-38`): `rename_function`, `rename_variable`, `retype_variable`, `create_struct` — each backed by `RenameFunctionTool` etc. Their descriptions are "Suggest a better name…" (:50), "Suggest more specific variable types…" (:212), "Suggest struct definitions…" (:297) (*line mapping corrected 2026-11-02 — :131 is rename_variable's description, not quoted here; earlier draft's "(:50, 131, 212, 297)" implied a 4th quote*). Executing one **records an `ActionProposal`** into the registry's `active_suggestions` (actions_tool_registry.py:87-98) — it never touches IDA: verified negative, grep of actions_tools.py for `ida_` finds only the `src.ida_compat import log` line; no mutation APIs. The registry is used **only by the Actions tab** (`actions_controller.py:16, :152`) — not merged into the Query/ReAct tool list. Note the name overlap: `rename_function`/`rename_variable` exist in *both* catalogs with opposite semantics (Actions = suggestion, internal = live IDB edit); the internal one is what Query/ReAct executes.

## 7. Graph tools — `src/services/graphrag/graphrag_tools.py` (698 LOC)

9 tools, "Write tools (3)" (graphrag_tools.py:48) and "Read tools (6)" (:159). Module docstring: writes let the LLM annotate the graph during conversations; reads give structured access (graphrag_tools.py:7-9). Descriptions verbatim-condensed:

| Tool | Purpose (from `description`) |
|---|---|
| `ga_record_vulnerability` (:50-87) | "Record a discovered vulnerability on a function … propagates CALLS_VULNERABLE to callers." (required: vulnerability_type, severity, description) |
| `ga_add_security_flag` (:89-113) | add flag to a function node; "Common flags: HANDLES_USER_INPUT, PARSES_NETWORK_DATA, CRYPTO_OPERATION, PRIVILEGE_CHECK, AUTHENTICATION, SENSITIVE_DATA, MEMORY_ALLOCATOR, ERROR_HANDLER." |
| `ga_create_edge` (:115-157) | create semantic/security/community edge; allowed types incl. SIMILAR_PURPOSE, RELATED_TO, DEPENDS_ON, IMPLEMENTS; VULNERABLE_VIA, TAINT_FLOWS_TO, CALLS_VULNERABLE, NETWORK_SEND/RECV; BELONGS_TO_COMMUNITY, SIBLING; confidence 0.0-1.0 default 0.8 |
| `ga_get_semantic_analysis` (:161-179) | "full semantic analysis … LLM summary, security flags, callers, callees, and raw code." |
| `ga_search_semantic` (:181-199) | "Full-text search on LLM summaries and function names in the knowledge graph." |
| `ga_get_call_context` (:201-227) | caller/callee context with summaries + flags; depth default 1, direction both |
| `ga_get_security_analysis` (:229-247) | flags, taint paths, attack surface, vulnerable callers |
| `ga_get_activity_analysis` (:249-267) | network/file profile: APIs, IPs, URLs, domains, registry keys |
| `ga_get_module_summary` (:269-288) | community/module purpose, member functions, count |

`GRAPHRAG_TOOL_NAMES` frozenset (:290) feeds both the tool merger (`get_graphrag_tools_for_llm(exclude_names=…)`, :293-300) and dispatch (`execute_graphrag_tool`, mcp_tool_orchestrator.py:194-237). All graph writes are scoped to the current binary hash. The graph itself is ch35's seam.

## 8. Tool approval — `src/services/tool_approval_service.py` (200 LOC)

- **Risk tiers** (:25-29): `READ_ONLY / MUTATING / EXTERNAL / UNKNOWN`. Assignment in `classify` (:55-66): source starting `mcp:` → READ_ONLY if name looks read-only else UNKNOWN; name containing push/sync/upload/network/http → EXTERNAL; name containing rename/retype/patch/comment/set/create/delete/update → MUTATING; otherwise read-only-by-prefix else UNKNOWN. `_looks_read_only` (:192-195): prefixes get/list/query/lookup/search/fetch or tokens current/graph/semantic/decomp/disasm/xref/range. Dotted (server-prefixed) names are classified on the last segment (:57-58).
- **Gate**: `request_approval` returns `None` (= auto-allow) when `chat_id <= 0` or the call is READ_ONLY (:70-74); otherwise an `ApprovalRequest` (uuid request_id, 2000-char args preview) is stored pending and an `approval_requested` transcript event is emitted (:81-102).
- **Decisions** (:39-42): `allow_once / allow_session / deny`; `resolve_pending` treats anything unrecognized as deny (:114-116), `allow_session` persists a grant, and every decision lands as an `approval_decision` transcript event with scope `session`/`once` (:117-126). Cancelling a chat denies all its pending approvals (:128-131).
- **Grants**: `BNChatApprovalGrants` rows `(chat_id, tool_name, scope='session', risk_tier, created_at, updated_at)` (:176-190); `has_session_grant` matches `tool_name IN (name, '*')` (:142-153). The **Accept All Tools checkbox** is exactly a `'*'` session grant (`is_accept_all_tools_enabled` / `set_accept_all_tools_enabled`, :157-174; view wiring in query_controller.py:656, :817-827).
- **Where it applies**: the plain Query path — the sole `request_approval` call site is `query_controller.py:948`, with the Allow Once/Session/Deny buttons resolved through a single `resolve_pending` call at `:836` inside the decision handler, followed by the approved-calls re-dispatch in `_continue_pending_tool_approvals` (`:962-992`; *corrected 2026-11-02 — earlier draft cited ":840, :970-986" as both being resolve_pending*). **ReAct does not gate**: verified negative — grep `request_approval|tool_approval` across `src/services/react/`, `src/controllers/react_thread.py`, `src/services/mcp_tool_orchestrator.py` returns zero hits; ReAct reuses the same ungated `MCPToolOrchestrator` instance (query_controller.py:3922). Consequence: ReAct's `rename_function`/`rename_variable`/graph-write tools run **without approval**, like the Explain tab (ch32). *(inference: the approval UX from ch33 — Accept All, Allow Once — only protects the plain tool-call path.)*

## 9. Effectiveness-relevant limits (ReAct)

| Limit | Value | Where |
|---|---|---|
| Max iterations | 15 (extendable +2 per reflection-added task, uncapped) | react_models.py:86; react_orchestrator.py:428-432 |
| Tool rounds per iteration | 10 | react_orchestrator.py:286 |
| Reflection gate | needs ≥5 extracted findings | react_orchestrator.py:405-407 |
| Findings extracted per tool result | ≤3 | findings_cache.py:92-93 |
| Findings shown in prompts / synthesis | top 50 / top 100 | findings_cache.py:108-149 |
| Context compression trigger | 75% of 150k tokens | react_models.py:92-93 → orchestrator :67-73; context_window_manager.py:111 |
| Tool-result truncation | 10k tokens each | react_models.py:94 → orchestrator :354 |
| Preserved recent tool pairs | 2 | react_models.py:95 |
| Network retries | 3, delay 2s doubling | react_models.py:97-99 → orchestrator :575-612 |
| Tool timeout | 30s (+10s collection slack); connect/test hard-capped at 10s | mcp_tool_orchestrator.py:47,169; mcp_client_service.py:274,411-416 |
| Concurrency | 3 tools at once | mcp_tool_orchestrator.py:46 |
| Tools cache TTLs | 60s (manager) / 30s (orchestrator map) | mcp_connection_manager.py:52; mcp_tool_orchestrator.py:45 |
| Same-tool failure warnings | soft @2, "do NOT call again" @3 | react_orchestrator.py:340-351 |

## Gaps

- `transcript_service.build_react_continuation_bridge` internals (payload shape/selection rules) — consumed here, owned elsewhere.
- `ReActPlanningThread` body (query_controller.py:492+) and `MCPServerConfig`/`MCPTool.to_llm_format` defaults (models/mcp_models.py) not read line-by-line.
- Whether ReAct ever honors `ReActConfig.tool_timeout` — no enforcement site found in the orchestrator itself; dispatch timeout lives in the MCP orchestrator instead.

## Sources

- `src/services/react/react_orchestrator.py:1-797` (full read) — phases, limits, events
- `src/services/react/react_prompts.py:1-161` (full read) — prompt texts quoted
- `src/services/react/todo_list_manager.py:1-230`, `src/services/react/findings_cache.py:1-167` (full reads)
- `src/services/models/react_models.py:1-99`, `src/controllers/react_thread.py:1-166` (full reads)
- `src/services/mcp_client.py:1-446`, `src/services/mcp_exceptions.py:1-51`, `src/services/mcp_connection_manager.py:1-296`, `src/services/mcp_tool_orchestrator.py:1-520` (full reads); `src/services/mcp_client_service.py:1-598`
- `src/services/internal_tools.py:1-466` (full read); `src/services/actions_tools.py` (grep of classes/descriptions, :50-353), `src/services/actions_tool_registry.py:1-149`
- `src/services/graphrag/graphrag_tools.py:7-290` (sed/grep window)
- `src/services/tool_approval_service.py:1-200` (full read)
- `src/controllers/query_controller.py:492, 615-658, 817-827, 840-986, 2606-2650, 3667-3799, 3880-3940`
- `src/services/models/transcript_models.py:25-40`; `src/services/context_window_manager.py:29-35,111,188`; `requirements.txt:8`
- Verified negatives named inline: no `request_approval`/`tool_approval` in `src/services/react/`+`react_thread.py`+`mcp_tool_orchestrator.py`; no `ida_*` mutation calls in `actions_tools.py`; `get_tool_guidance_prompt` uncalled by the orchestrator.
- Clone HEAD `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302` at `/tmp/opencode/IDAssist`.

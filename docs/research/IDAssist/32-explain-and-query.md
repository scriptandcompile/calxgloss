# 32 — Explain and Query tabs: prompts, context, streaming, transcripts, RLHF

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-02.

All paths are relative to the read-only clone at `/tmp/opencode/IDAssist`. The two tabs are the tool's core UX: Explain is a one-shot (function- or line-scoped) prompt with a persistent cache; Query is a persistent, provider-native chat with macros, tool-calling, a transcript event log, and chat editing. Both share the context service, the streaming renderer stack, and the RLHF plumbing.

## 1. Documented behavior and doc drift

Four docs describe these tabs: `docs/tabs/explain-tab.md` (92 LOC), `docs/tabs/query-tab.md` (138 LOC), `docs/workflows/explain-workflow.md` (113 LOC), `docs/workflows/query-workflow.md` (165 LOC). Their overall shape matches the code (buttons, streaming, caching, macros, ReAct mode). Verified drift:

1. **RLHF database path.** `docs/tabs/explain-tab.md:64` says feedback is stored in "`~/.idapro/idassist/rlhf.db`". The actual writer, `RLHFService`, resolves its DB to `analysis.db` in the user data dir ("Use same database as AnalysisDBService for consistency", `src/services/rlhf_service.py:41-55`) and inserts into the `feedback` table (`src/services/rlhf_service.py:99-110`, INSERT at `:103`). The Settings tab does expose an `rlhf_db_path` setting defaulting to `rlhf.db` (`src/views/settings_tab_view.py:398-407`, `src/services/settings_service.py:190-191`) and `settings_controller.py:1690` displays it, but `RLHFService._get_database_path()` never reads that setting — the UI setting is decorative for writes. *(Verified by reading both files; `grep -rn "rlhf_db_path" --include="*.py" src` shows only settings-service/controller/view hits, no read by rlhf_service.)*
2. **`#range` expansion content.** `docs/tabs/query-tab.md:74` says `#range(start, end)` expands to "Disassembly for the given address range" and `:130` says it uses `ida_lines`. The code calls `self.context_service.get_hexdump(start_addr, size)` and emits an `address: hex_bytes  ascii` listing (`src/controllers/query_controller.py:1253-1268`) — a hex dump of raw bytes, not a disassembly.
3. **`#func` pseudocode preference.** `docs/tabs/query-tab.md:76` says "For `#func`, IDAssist prefers Hex-Rays pseudocode when available and falls back to disassembly." In the macro path there is no PSEUDO_C→ASM fallback ladder: it uses the *current* view level (`get_code_at_level(current_offset, current_level)`, `src/controllers/query_controller.py:1167-1168`) and, on failure, silently substitutes the literal words `current function` (`:1176`, `:1179`, `:1183`). It is the *Explain* tab that does the explicit fallback ladder: try current level, then `[ViewLevel.PSEUDO_C, ViewLevel.ASM]` (`src/controllers/explain_controller.py:265-278`).
4. **Undocumented UI: tool approval and ReAct plan approval.** Neither `query-tab.md` nor `query-workflow.md` mentions the `Accept All Tools` checkbox (`src/views/query_tab_view.py:178-181`), the per-tool `Allow Once` / `Allow for Session` / `Deny` buttons (`:258-260`), or the `Approve Plan` button for ReAct plan review (`:891`, flow at `src/controllers/query_controller.py:3667-3783`). The Query tab gates every tool call through an approval service (see §3.4); the docs describe tool calling as unconditional.
5. **Provenance leftovers.** `query_controller._expand_macros` still says "using current Binary Ninja context" (`src/controllers/query_controller.py:1157`) and `ViewLevel` is documented as "simplified from BinAssist" (`src/services/binary_context_service.py:37`) — the plugin descends from a Binary Ninja ("BinAssist") predecessor; macro semantics still speak Binary Ninja terms (`get_display_messages`, `#line` calling `get_line_context`).

The README claim under test — "automatic security analysis including risk level, activity profile, security flags, and API detection" (`README.md:18`) — is real but *not* LLM-derived; see §2.3.

## 2. Explain tab (`src/controllers/explain_controller.py`, 2155 LOC)

### 2.1 Top-level shape

`ExplainController` (`:26`) holds a `ReasoningFilter` (`:71`) and a `StreamingMarkdownRenderer`, and drives two independent query slots: function and line. The full def-map (via `grep -n "def \|^class "`) splits into: request handlers (`explain_function` `:187`, `explain_line` `:333`, `clear_explanation` `:439`), prompt builders (`_format_function_explanation` `:606`, `_format_line_explanation` `:663`, `_generate_llm_query` `:728`, `_generate_line_explanation_prompt` `:1686`), the MCP tool round-trip (`_on_tool_calls_detected` `:984` … `_continue_llm_after_tools` `:1127`), cache loaders (`:1494`, `:1560`), and three QThreads: `LLMQueryThread` (`:1888`), `ExplainLLMThread` with MCP support (`:1972`), `ExplainToolExecutorThread` (`:2109`).

### 2.2 What `explain_function()` collects, and the prompt verbatim

Flow (`:187-331`): context dict → cache checks (see §2.5) → code extraction at the current view level with fallback → RAG/MCP flags → active provider → prompt → RLHF tracking → async query. Collection itself is delegated to `BinaryContextService` (§4.1): the prompt embeds function context (name, prototype, address range, size, basic-block count, call sites, **callers and callees** — `_get_function_context`, `src/services/binary_context_service.py:218-278`), binary info (filename, architecture, platform), and the code body as `>>> addr: line` or decompiler text (`explain_controller.py:636-655`). **No disassembly+xrefs mixture, no strings, no imports** are injected in the Explain prompt — xref information appears only as caller/callee address lists (`binary_context_service.py:247-258`); IDA imports/strings/entry-points extraction exists in the service (`_get_imports` `:712`, `_get_interesting_strings` `:754`) but is not referenced by the Explain prompt builders.

The user-message header doubles as the instruction (verbatim, `explain_controller.py:612-616`):

> Describe the functionality of the decompiled code below. Provide a summary paragraph section followed by an analysis section that details the functionality of the code. The analysis section should be Markdown formatted. Try to identify the function name from the functionality present, or from string constants or log messages if they are present. But only fallback to strings or log messages that are clearly function names for this function. Include any other relavant details such as possible data structures and security issues,

(quoted exactly, including the typo "relavant"). The line-level header (`:681`):

> Analyze the specific instruction/line of code below. Provide a detailed explanation of what this instruction does, its purpose within the function context, potential side effects, and any security considerations. Focus on the technical details of this single instruction.

Optional prompt tail: RAG snippets appended as `**RAG Context**` sections (`:748-756`) or the one-liner `"**MCP Context**: Please leverage Model Context Protocol tools and resources for enhanced analysis."` (`:760`). The system message comes from the configurable SystemPrompts store, `settings_service.get_system_prompt()` (`explain_controller.py:799-814`), whose default is:

> You are an AI assistant specialized in binary analysis and reverse engineering. Help users understand code, identify patterns, and provide actionable insights for their reverse engineering tasks. (`src/services/settings_service.py:872`)

If no LLM provider is configured, the same formatter runs with `include_llm_prompt=False` and the static markdown is shown with a "*This is a static analysis…*" disclaimer (`explain_controller.py:292-297`, `:657-659`).

### 2.3 The security panel is static analysis, not parsed LLM output

The README's risk level / activity profile / flags / API detection do **not** come from structured output or JSON parsing of the explanation. They live on GraphRAG nodes:

- The panel is filled from a `GraphNode`: `update_security_info(node.risk_level, node.category, node.activity_profile, node.security_flags, node.network_apis, node.file_io_apis)` (`explain_controller.py:1813-1825`).
- Those fields are computed **statically** by `src/services/graphrag/security_features.py`: risk score thresholds `score>=6 → HIGH, >=3 → MEDIUM, else LOW` (`:243-248`), flag synthesis (`NETWORK_CAPABLE`, `WRITES_FILES`, `CALLS_DANGEROUS_FUNCTIONS`, `POTENTIAL_DATA_EXFILTRATION` from network∧file-io, …) (`:251-316`). They are refreshed onto the node by `SemanticExtractor._refresh_security_features` (`src/services/graphrag/semantic_extractor.py:180-206`) and also at indexing time (`structure_extractor.py:107-108`).
- `explain_function` triggers the node upsert itself: `self.graphrag_service.index_function(func, binary_hash)` then `_update_security_panel_from_node(node)` (`explain_controller.py:314-325`).
- The LLM response is stored **as markdown**; the only parse is `extract_category(response)`, which string-finds a `**Category:` header in the prose (`src/services/graphrag/extraction_prompts.py:241-261`); the summary itself is `node.llm_summary = response.strip()` with fixed `confidence = 0.85` (`semantic_extractor.py:133-136`). So parsing robustness is: header scan with plain-text fallback; everything else survives as prose. There is no JSON schema request in any Explain prompt *(verified: `grep -rn "json" src/controllers/explain_controller.py` — 8 hits, all tool-argument markdown formatting at `:1047-1049` and `:1476-1478`, plus `RLHFFeedbackEntry.create_metadata_json` at `:1861`/`:1873`; *corrected 2026-11-02 — earlier draft said "only `:1476-1477`"*)*.

Robustness consequence: the security panel is deterministic (regex/known-API based, ch35's graph domain) while the prose is free-form; they can disagree, and a stale explanation still shows whatever static features the node currently has.

### 2.4 Line-level explanation

`explain_line` (`:333-437`): per-line cache first — `analysis_db.get_line_explanation(binary_hash, current_offset, view_type)` keyed by line address **and view type string** (`:369-379`) — then `get_line_with_context(current_offset, current_view_level, context_lines=5)` (`:382-384`; pseudo variant `binary_context_service.py:534`, asm variant `:586`). The pending save context (`line_content`, `context_before/after`) is staged at `:418-426` and written to `BNLineExplanations` via `analysis_db.save_line_explanation(...)` on completion (`_on_line_llm_response_complete` `:1620-1651`). Navigating also auto-loads per-line caches (`_load_cached_line_explanation_for_offset` `:1560-1580`).

### 2.5 Caching policy

Order of preference on both manual run and cursor navigation (`_load_cached_analysis_for_offset` `:1494-1553`):

1. **GraphRAG node summary** if `node.llm_summary and not node.is_stale` (`:226-237`, `:1506-1513`).
2. **Legacy `BNAnalysis` row** `get_function_analysis(binary_hash, function_start, "explain_function")` (`:239-253`; `explain_line` rows under type `"explain_line"` are also auto-loaded, `:1530-1541`).
3. Fresh LLM query otherwise.

Reuse is unconditional once written: `_should_refresh_cache()` returns `False` with the comment "For now, always use cache. Future: check timestamps, model versions, etc." (`:1429-1432`). Editing is manual (edit mode → `_save_edited_explanation` `:498`). And the write-back is bidirectional: when a fresh LLM explanation completes, it is saved to `BNAnalysis` with metadata `{view_level, model, offset}` **and** copied onto the GraphRAG node (`node.llm_summary = complete_content; confidence = 0.85; is_stale = False; upsert_node`) so the next visit hits path 1 (`:899-948`).

### 2.6 Streaming and threading

`LLMQueryThread` / `ExplainLLMThread` are **`QThread` subclasses**, not `DaemonWorker` — the `DaemonWorker` base (`src/daemon_worker.py:10`) is only used by settings workers (`grep -rn "DaemonWorker" --include="*.py" src`: settings-worker subclasses at `settings_controller.py:153,268,357,429` — the last is `SymGraphTestWorker` — plus the base-class def `src/daemon_worker.py:10` and the import at `settings_controller.py:7`). Each thread runs `asyncio.run(self._async_query())` and emits Qt signals `response_chunk / response_complete / response_error / tool_calls_detected / stop_reason_received` (`explain_controller.py:1974-1978`). Chunks go through `ReasoningFilter.feed` → `StreamingMarkdownRenderer.on_chunk` → `StreamingMarkdownBrowser.apply_render_update` (§3.5). Completion finalizes markdown, re-renders for feedback links, updates RLHF context, and saves (`:879-961`).

Explain's tool loop (MCP enabled): `ExplainLLMThread` streams until `finish_reason`; detected tool calls land in `_on_tool_calls_detected` (`:984-1003`) → **executed immediately, no approval gate** → results appended to the in-memory conversation (`_add_assistant_with_tool_calls_to_history` `:1178`, `_add_tool_results_to_history` `:1234`) → `_continue_llm_after_tools` (`:1127`). The only guard is a loop breaker: max 5 tool rounds, max 3 calls of the same `name:hash(args)` key (`:1010-1036`). Tool executions are flattened into the saved explanation as a `## Tool Execution` markdown section (`_save_tool_execution_to_db` `:1434-1465`, `_format_tool_execution_as_markdown` `:1467-1487`).

### 2.7 `function_summary_service.py` — not Explain-side

`FunctionSummaryService` (`src/services/function_summary_service.py:17`) reproduces the *same* Explain-style prompt for background summarization: `format_function_prompt` builds context at a fixed address (screen-EA lookups "unreliable" off-UI-thread, `:65-67`), defaults to `PSEUDO_C` with ASM fallback (`:77-86`), and appends the same RAG/MCP tail (`:119-131`). Its callers are `semantic_graph_controller.py:831-833` and `graphrag/semantic_extractor.py:120-161` ("unified prompt … falls back to legacy prompt") — `explain_controller.py` never imports it (`grep -rn "function_summary_service" --include="*.py" src`: hits at `semantic_graph_controller.py:832`, `graphrag/semantic_extractor.py:15`, and two docstring mentions in `graphrag/extraction_prompts.py:71,73` — nothing on the Explain path; *corrected 2026-11-02 — earlier draft said "only those hits"*). So it is the semantic-graph tab (ch35) reusing the Explain prompt format; Explain's own tab does not call it. The unified prompt explains why a GraphRAG summary and an Explain answer read alike.

## 3. Query tab (`src/controllers/query_controller.py`, 4190 LOC)

### 3.1 Chat session model and persistence

Three-layer storage (tables owned by ch31's persistence chapter; roles here are what the Query controller writes):

- **Legacy `BNChatHistory`** (`analysis_db_service.py:386`): `_add_message_to_chat` writes `{role, content, timestamp}` with `metadata={"message_order": n}` per message (`query_controller.py:2301-2331`). Roles beyond user/assistant are display-only in-memory (`tool_call`, `tool_response`, `tool_status`, `error`, `edited` — `_format_chat_as_markdown` `:2398-2444`).
- **Native `BNChatMessages`** (`:1030-1032`, column `native_message_data`): the provider-format history. `_save_user_message_native` (`:2690-2719`), `_save_assistant_response_native` (`:2721-2777`), `_save_tool_response_native` (`:2779-2812`), plus a callback the provider invokes with the fully reconstructed streaming assistant message including `tool_calls` and `reasoning_content`/`thinking_blocks` (`_create_native_message_callback` `:2814-2832`; producer side `src/services/llm_providers/litellm_provider.py:848-880`). On the next turn, `_prepare_native_messages` replays `get_native_messages_for_provider(binary_hash, chat_id, provider_type)` so the provider sees its **own** message shape (Anthropic blocks vs OpenAI tool messages — ch33 formats), dedupes the just-saved current query by substring match (`:2667-2677`), and falls back to the legacy `chat_messages[:-2]` replay if native history is empty (`_prepare_llm_messages` `:2581-2604`). `native_message_data` is exactly this serialized provider-native payload; display reads `get_display_messages` instead (`_load_chat_from_native_storage` `:2369-2395`).
- **`BNChatMetadata`** (`:401`, `metadata TEXT` column added by migration at `:413`): per-chat name + JSON metadata holding `chat_type` (normalized in `_normalize_chat_metadata` `:2071-2087`; non-default types are "document chats" — a document-push feature adjacent to RAG/symgraph, `_is_document_chat` `:663-669`). Loaded for the tab at startup via `analysis_db.get_all_chats(binary_hash)` (`load_existing_chats` `:993-1027`); rename via `on_chat_name_changed` `:1668` + `_save_chat_metadata` `:2097-2109`.

`submit_query` (`:1294-1397`) is the spine: macro-expand (`:1299`) → route to ReAct if the checkbox is on (`:1302-1307`, ch34) → add user message (legacy `:1342`, native `:1345-1346`, transcript event `:1347-1352`) → assistant placeholder `*Thinking...*` kept in memory only (`:1355`, `save_to_db=False`) → build native messages (`:1366`) → RLHF track (`:1369`) → MCP tool list via `mcp_connection_manager` (`:1372-1379`, ch34 seam) → `_start_llm_query` (`:2957`).

### 3.2 Context macros — `_expand_macros` (`:1156-1292`)

Plain string/regex replacement on the submitted text before anything else (Enter-submit path at `query_tab_view.py:335` reaches `submit_query`):

- **`#func`** (`:1162-1183`): `get_code_at_level(current_offset, current_view_level)` → joined line contents wrapped as `f"\n\n```\n{func_code}\n```\n\n"`. On any failure the macro collapses to the literal `"current function"`.
- **`#line`** (`:1186-1207`): `get_line_context(offset, level)` (service `binary_context_service.py:645`) wrapped in the same fence; failure → `"current line"`.
- **`#addr`** (`:1210-1223`): `f"0x{current_addr:x}"`; failure → `"0x0"`.
- **`#range(start, end)`** (`:1226-1283`): regex `r'#range\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)'`; hex-or-decimal parsing (`:1237-1251`); then `get_hexdump(start_addr, end_addr-start_addr)` rendered as `"{address}: {hex}  {ascii}"` lines inside a fence (`:1256-1268`). Invalid/failed ranges degrade to `0x…-0x…` or `invalid range (…)` text.

No other macros exist (the four above are all `#`-tokens in the function; verified by reading `:1156-1292` in full). Expansion happens once, at submit; saved history contains the expanded text, so replaying a chat replays the *old* expanded code (the query-workflow's follow-up advice `docs/workflows/query-workflow.md:52-59` therefore re-sends historical code, and trimming is ReAct-only — §4.2).

### 3.3 Query prompt

System message, verbatim core (`query_controller.py:2839-2862`):

> You are IDAssist, an AI assistant specialized in reverse engineering and binary analysis.
> … Current Analysis Context: Filename / Path / Architecture / Platform / Current Offset … Capabilities: RAG (Documentation Search): Enabled/Disabled, MCP (External Tools): Enabled/Disabled … Instructions: - Provide detailed, technical analysis relevant to reverse engineering …

plus, when MCP is on, a tool-calling nudge (`:2864-2875`):

> Tool Usage Guidelines: … Start with basic tools like get_binary_status, then use specific analysis tools … For function analysis, typically use: get_binary_status → get_function_pseudo_c → get_references, etc.

The user turn gets RAG snippets (`_get_rag_context` `:2897-2927`) and, if MCP is on, the appended line `Use the available tool calls as needed.` (`_enhance_query_with_context` `:2879-2895`). Note the Query system prompt is hard-coded — unlike Explain, it does not use the editable SystemPrompts store *(verified: `_build_system_message` takes no settings input, `:2834-2877`)*.

### 3.4 Tool-use loop in the plain path (ch34 seam)

Signals from `LLMQueryThread` (`:39-43`): `tool_calls_detected` starts the loop. `QueryController._on_tool_calls_detected` (`:3070-3113`): loop guard first (**Query's own variant: only the 3-repeats-per-unique-`name:hash(args)` cap — `if current_count > 3` at `:3154`; no rounds counter exists in `query_controller.py`, unlike Explain's 5-round cap**, `:1010-1036`; on breach a transcript `iteration_notice` with `category="loop_guard"` is written, `:3076-3081`), then `_begin_tool_workflow` (`:922-960`): every call is assigned a correlation id, logged as a transcript `tool_call_requested` event, and gated through `tool_approval_service.request_approval(...)` (`:948-958`) — denied calls get synthetic results. This approval gate is the seam to ch34 (approval grants / Accept-All); detail omitted here. Approved batches run on `ToolExecutorThread` against `mcp_orchestrator` (`:3119-3136`); `_on_tool_results_ready` (`:3217-3260`) orders results, writes `tool_call_completed/failed` events, then `_prepare_continuation_messages` (`:3293-3401`) rebuilds the message list, inserting an explicit assistant message carrying `tool_calls` immediately before the tool-result block (`:3380-3399`) so providers requiring call/result pairing stay valid. The continuation is a *separate* `LLMContinuationThread` (`:217`) whose chunks merge back into the same assistant buffer (`_on_continuation_chunk` `:3407-3410`) and whose own `tool_calls_detected` re-enters the loop — a multi-round cycle bounded only by the loop guard.

### 3.5 Extended thinking and the streaming renderer (`src/services/streaming/`, 457 LOC)

Wiring in both controllers: `ReasoningFilter(on_content=renderer.on_chunk, on_thinking_start=self._on_thinking_start)` (`query_controller.py:596-602`, `explain_controller.py:71`). Per chunk: `response_chunk` → `self._llm_response_buffer += chunk` (raw, kept for RLHF/DB) and `_reasoning_filter.feed(chunk)` (`query_controller.py:2987-2992`).

- **`reasoning_filter.py` (86 LOC)** — a small two-state machine (`NORMAL`/`IN_REASONING`, `:8-10`) that strips `<reasoning>…</reasoning>` spans from the *displayed* text: content is emitted up to `<`, tag open switches state and fires `on_thinking_start` once (`:61-66`), reasoning bytes are discarded (`:73-76`), partial tag prefixes are held back to avoid splitting tags across chunks (`:67-68`, `:83-84`). What the user sees during reasoning is only the `*Thinking...*` placeholder injected by the controller (`_on_thinking_start` `:2344-2346`). Note: no prompt text in `src/` instructs the model to emit `<reasoning>` tags — `grep -rn "<reasoning>" --include="*.py" src` matches only this filter and controller comments; the filter is defensive against tag-emitting models and against user-edited SystemPrompts *(inference: the tag convention must originate in user-configured prompts).*
- **Provider-side thinking** never enters the content stream: LiteLLM accumulates `delta.reasoning_content` separately (`litellm_provider.py:788-789`) and only attaches it to the persisted native message as `reasoning_content` + Anthropic `thinking_blocks` (`:872-880`). On replay, `query_controller.py:125-132` (and `:320-327` in the continuation thread) preserve `thinking_blocks`/`reasoning_content` in native messages "for LiteLLM Anthropic thinking" so Anthropic-style thinking signatures survive multi-turn (budget config is ch33's). Net effect: *thinking text is stored for provider fidelity but never rendered in the UI*; visible thinking is only the placeholder.
- **`block_boundary.py` (90 LOC)** — `find_last_stable_boundary` (`:17-50`) commits only complete markdown blocks: boundaries are blank lines, ATX headings, thematic breaks, list items, block quotes; table rows are never boundaries; inside a ```/~~~ fence nothing is a boundary until the fence closes; a final unterminated line is held pending (`:31-33`).
- **`streaming_renderer.py` (239 LOC)** — `StreamingMarkdownRenderer.on_chunk` (`:199-218`) splits pending markdown at the stable boundary, renders the stable prefix as `committed_html` and the rest as `pending_html` (python-markdown with table/hr/list/soft-break preprocessors, `:34-160`); `on_stream_complete` (`:220-230`) promotes everything and emits one `full_replace` re-parse for cross-block consistency.
- **`render_update.py` (36 LOC)** — frozen dataclass with two kinds, `INCREMENTAL(committed, pending)` and `FULL_REPLACE(full)` (`:8-35`).
- **Consumer**: `src/views/streaming_markdown_browser.py:68` `StreamingMarkdownBrowser(QTextBrowser)` applies them with cursor-based appends (`apply_render_update` `:167`), keeps markdown source for Ctrl+C copy (not rendered HTML — `:73`, `:106-124`), and auto-scroll bookkeeping (`:47-64`).

### 3.6 Transcripts (`transcript_service.py` 454 + `transcript_renderer.py` 300)

Event kinds are an enum of 14 (`src/services/models/transcript_models.py:8-22`): `user_message`, `assistant_message`, `tool_call_requested`, `tool_call_started`, `tool_call_completed`, `tool_call_failed`, `approval_requested`, `approval_decision`, `todo_updated`, `finding_added`, `iteration_notice`, `context_compacted`, `system_notice`, `document_snapshot`. Producers in this chapter's scope: `submit_query` (user event), `_begin_tool_workflow` (requested), `_on_tool_results_ready` (completed), `query_tab_view` approval buttons via controller (`on_approval_decision_requested` `:829-847`); `src/services/tool_approval_service.py` emits the approval events (ch34 seam); ReAct events (`todo/finding/iteration`) are ch34's.

Storage: `append_event` (`transcript_service.py:122-178`) inserts into `BNChatTranscriptEvents` with a monotonic per-chat `event_index`. **Artifacts**: when a `TOOL_CALL_COMPLETED`/`FAILED` payload exceeds `LARGE_ARTIFACT_THRESHOLD = 4000` chars (`:25`, `:129-135`), the full text is written to disk at `<analysis.db dir>/transcript_artifacts/<binary_hash>/<chat_id>/<uuid4>.txt` (`:30`, `:314-336`), the DB row stores only a 800-char preview + `artifact_id`, and lookup goes back through `get_artifact` (`:338-356`). Legacy chats with no events are backfilled from native (or legacy) messages on first view (`ensure_backfilled` `:43-81`). Rendering into the tab's HTML — `TranscriptRenderer.render` (`transcript_renderer.py:16`) groups tool events into collapsible cards (`_group_events` `:39`, `_render_tool_group` `:83`), renders task cards (`:145`) and message cards (`:244`); the controller layers the *live* streaming markdown on top without re-rendering the base during a stream (`_apply_streaming_transcript_update` `:737-751`, throttled refresh `:753-781`). Transcript events also feed a ReAct **continuation bridge**: `build_react_continuation_bridge` (`:358-429`) summarizes prior findings into markdown that `query_controller._build_react_continuation_bridge`/`_inject_react_bridge_message` (`:2606-2632`) injects as a synthetic assistant message after the system prompt — i.e. ReAct state survives chat reloads (ch34 seam).

### 3.7 Chat editing (`src/controllers/chat_edit_manager.py`, 342 LOC)

Edit mode is a **destructive in-place rewrite of the stored conversation, not edit-resend and not branching**. The manager serializes each message with a hidden marker `<!-- CHUNK:msg_<dbid>_<role>_<order>_<md5(content)[:8]> -->` (`:35-39`, `:56-61`) and on save diffs the edited markdown against the originals, classifying chunks as `MODIFIED / DELETED / ADDED / MOVED` (`:18-23`, `parse_edited_content` `:151`). The controller then ignores the diff for content purposes and **deletes the entire native chat** (`analysis_db.delete_native_chat` at `query_controller.py:1861`) and re-inserts every parsed chunk in order as edited messages (`:1864-1870`, service `analysis_db_service.py:1524-1546` — `save_edited_message` def at `:1524`; *corrected 2026-11-02*); title edits update `BNChatMetadata` (`:1876-1893`). A second, narrower flow edits only the latest assistant message (`_prepare_latest_assistant_edit_mode` `:1729`, `_save_latest_assistant_edit` `:1742`). Because storage is provider-native, the rebuilt messages are re-serialized generically — provider-specific thinking blocks inside edited messages are lost on rebuild *(inference from the `save_edited_message(role, content)` signature taking text only, `analysis_db_service.py:1526`)*.

## 4. Shared context machinery

### 4.1 `src/services/binary_context_service.py` (824 LOC)

`ViewLevel` is only `ASM`/`PSEUDO_C` (`:36-39`); the active level comes from the focused IDA widget (`BWN_PSEUDOCODE`/`BWN_DISASM`), falling back to a UI-hook-tracked last code view, then ASM (`:317-332`, tracked var `:42-48`). Context dicts are built on IDA's main thread (`get_current_context` `:84`, `get_context_for_address` `:101`; decompilation marshalled via `_pseudo_c_to_text` "safe to call from background threads" `:454-459`). Functions exposed: binary info (`:119`), function context with FlowChart basic-block count and caller/callee sets from `CodeRefsTo`/`CodeRefsFrom` (`:218-278`), `get_code_at_level` dispatch ASM/pseudo (`:334-356`), `get_hexdump` (`:479`), `get_line_with_context` pseudo/asm variants (`:518`, `:534`, `:586`), `get_line_context` (`:645`), and triage helpers — imports (`:712`), exports (`:737`), interesting strings (`:754`), entry points (`:773`), `_get_security_features` (`:800`) — consumed by GraphRAG indexing, not by the Explain/Query prompt builders *(verified: `grep -n "get_triage_metadata\|_get_imports\|get_binary_info" src/controllers/explain_controller.py src/controllers/query_controller.py` shows only `get_binary_metadata_for_rlhf` reaching the tabs)*. It also owns `get_binary_metadata_for_rlhf` (`:172-196`) for §5.

### 4.2 `src/services/context_window_manager.py` (874 LOC)

**Not used by either tab's plain path.** The only instantiator is `src/services/react/react_orchestrator.py:73` (calls at `:107`, `:354`, `:547`, `:648`) — verified: `grep -rn "ContextWindowManager(" --include="*.py" src` returns only that hit, the `class ContextWindowManager:` def at `src/services/context_window_manager.py:16`, and a docstring usage example at `context_window_manager.py:38` (*corrected 2026-11-02 — the second hit is the docstring example, not the class def; the sole-instantiator conclusion stands*). So plain Query chats can overflow the model window; compaction is a ReAct-agent feature (ch34). Mechanics, for completeness:

- **Token estimation**: provider `count_tokens` on a temporary `ChatRequest` including tool definitions; on failure, `total_chars // 4` (`context_window_manager.py:223-242`); tool-result truncation also uses `len//4` (`:201-214`).
- **Hard limits / triggers** (`src/services/models/context_models.py:14-41`): `context_limit_tokens=150_000` ("Conservative default for Anthropic"), compression at `threshold_percent=0.75`, per-tool-result cap `max_tool_result_tokens=10_000` with a `[... truncated: …]` notice at a line boundary (`manager :188-221`).
- **What survives / what goes** (`_compress_history` `:244-300`): always keep all system messages, the last `min_recent_messages=4`, and the last `min_recent_tool_pairs=2`; everything older is replaced by one summary, with tool call/result pairs never split (`:253-256`, validation pass `_validate_and_fix_tool_pairs` `:566`). The summary prompt is LLM-based by default (`use_llm_summary=True`) with a fixed template — verbatim opener (`:51-55`): *"Summarize the following investigation conversation concisely. Preserve these key elements: - Important discoveries and findings - Tools that were used and their significant results…"* — with an extractive fallback (`_extractive_summary` `:386`) and an emergency truncator (`:783`).

## 5. RLHF: write-only telemetry (verified negative)

Per thumbs-up/down, one `RLHFFeedbackEntry` (model_name, prompt, system, response, feedback bool, timestamp, metadata JSON with filename/size/sha256 — `src/services/models/rlhf_models.py:9-60`) is inserted into the `feedback` table of `analysis.db` (`rlhf_service.py:99-110`; `handle_rlhf_feedback` explain `:1842-1885`, query `:3617-3666`; context captured at send time via `_track_rlhf_context` `:1829-1836` / `:3597-3612`). Feedback links are HTML anchors `rlhf://upvote|downvote` appended under the rendered explanation (`explain_tab_view.py:494-506`) and signals wired in `idassist_form.py:181,203`.

**No consumer reads it back.** Exhaustive search — `grep -rn "get_feedback_entries\|get_feedback_stats\|store_feedback\|RLHFService\|rlhf_service\." --include="*.py" src` — yields exactly two non-definition hits: `explain_controller.py:1877` and `query_controller.py:3653`, both `store_feedback`. The retrieval APIs `get_feedback_entries` (`rlhf_service.py:125`) and `get_feedback_stats` (`:164`) have zero callers, and no prompt-building code anywhere selects feedback rows. So the feedback loop is, as of HEAD 09dd910d, **archive-only**: stored for "future reference" (`docs/workflows/explain-workflow.md:52`) but never influencing prompts, rankings, or model choice. Stated plainly as a verified negative.

## 6. The views

- **`src/views/explain_tab_view.py` (557 LOC)**: RAG checkbox (`:136`), MCP checkbox (`:141`), Edit/Save toggle (`:147`), Explain Function / Explain Line / Clear buttons (`:211-213`), during generation the two explain buttons re-label to "Stop" (`:529`, `:546`); line panel with `×` close (`:193`); security panel with two API text areas (`:242-250`); RLHF anchors (`:494-506`). There is **no model picker** in this tab — model choice lives in Settings (ch31/ch33 seam) *(verified: no `QComboBox` in explain_tab_view.py)*.
- **`src/views/query_tab_view.py` (901 LOC)**: RAG / MCP / **ReAct Agent** / **Accept All Tools** checkboxes (`:161-181`), Edit button (`:184`), approval bar `Allow Once` / `Allow for Session` / `Deny` (`:258-260`), Submit/New/Delete (`:313-315`) with Enter-submit / Ctrl+Enter-newline (`:335`) and Submit↔Stop restyle (`:568-574`), chat history table whose rows carry a chat-type `QComboBox` (`:730-746`) and a `Approve Plan` button for the ReAct plan-review step (`:891`).
- **`src/views/streaming_markdown_browser.py`**: shared display surface for both tabs (§3.5) — QTextBrowser fed by `RenderUpdate`s, markdown-source clipboard, auto-scroll latch.

## 7. What I did not fully read (honest gaps)

- Full bodies of `LLMQueryThread._async_query` (`query_controller.py:67-217`) and `ExplainLLMThread._async_query` (`explain_controller.py:2001-2107`) beyond the cited spans; `LLMContinuationThread` internals; all `#`-independent ReAct handlers (`:3667-4190`) — left to ch34.
- `transcript_renderer` HTML/CSS details beyond card structure; `_render_transcript_view_now` throttling internals (`query_controller.py:783-805`) only skimming-verified.
- `graphrag_service.index_function` / GraphStore internals (ch35); provider thinking-bubble config (ch33).
- Whether any SystemPrompts default shipped in Settings asks for `<reasoning>` tags — I only verified no code-side prompt emits that instruction.

## Sources

- `docs/tabs/explain-tab.md`, `docs/tabs/query-tab.md`, `docs/workflows/explain-workflow.md`, `docs/workflows/query-workflow.md`, `README.md` (HEAD clone, cited inline).
- `src/controllers/explain_controller.py`, `src/controllers/query_controller.py`, `src/controllers/chat_edit_manager.py`.
- `src/services/binary_context_service.py`, `src/services/context_window_manager.py`, `src/services/function_summary_service.py`, `src/services/rlhf_service.py`, `src/services/models/rlhf_models.py`, `src/services/models/context_models.py`, `src/services/models/transcript_models.py`, `src/services/transcript_service.py`, `src/services/transcript_renderer.py`.
- `src/services/streaming/{block_boundary,reasoning_filter,render_update,streaming_renderer}.py`.
- `src/services/graphrag/{semantic_extractor,security_features,extraction_prompts,structure_extractor}.py`, `src/services/llm_providers/litellm_provider.py`, `src/services/react/react_orchestrator.py`, `src/services/analysis_db_service.py`, `src/services/settings_service.py`.
- `src/views/{explain_tab_view,query_tab_view,streaming_markdown_browser,settings_tab_view,idassist_form}.py`, `src/daemon_worker.py`.

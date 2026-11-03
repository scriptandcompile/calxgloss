# 37 — Actions tab: suggestion tool-calling, confidence table, apply-to-IDB

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-02.

The Actions tab is IDAssist's human-gated write-back path: the LLM proposes renames/retypes/
structs through four *suggestion-only* tools, the proposals accumulate in a table with
model-reported confidence, and only a human "Apply Actions" click reaches the IDB — through a
separate apply layer (`ActionsService`) that re-parses the table rows, discarding the model's
original proposal object.

## 1. `docs/tabs/actions-tab.md` (99 LOC) — summary and drift

The doc describes: a 5-column table (Select / Action / Description / Status / Confidence) with
editable Description and a confidence column "0.0 to 1.0" (`docs/tabs/actions-tab.md:22-28`);
four action checkboxes — Rename Function, Rename Variable, Retype Variable, Auto Create Struct
(`:38-47`); three buttons — Analyse Function, Apply Actions, Clear (`:49-55`); a five-step
workflow select-types → analyse → review → checkbox-select → apply (`:57-63`); and IDA claims:
"`ida_name.set_name()`", "`ida_hexrays.rename_lvar()`", main-thread execution via
"`idaapi.execute_sync(callback, MFF_FAST)`" (`:87-93`). All three API claims check out against
code (`actions_service.py:181`, `:257`; `ida_compat.py:63-79` — def+docstring :63-74, the
`idaapi.execute_sync(callback, idaapi.MFF_FAST)` call itself at :79; span corrected 2026-11-02).

Drift found:

- **Status vocabulary**: doc says "Pending, Applying..., Applied, or Error" (`:27`); the
  controller actually writes `"Ready"` or `"Low Confidence"` as the initial status
  (`actions_controller.py:433`). "Pending" is only the view's default parameter, never passed by
  the controller (`actions_tab_view.py:128`).
- **Assembly renames omitted**: doc only cites `rename_lvar` (`:90`); the code has a second
  path that renames *stack frame members* via `idc.set_member_name` when the analysis ran at
  assembly level (`actions_service.py:306-335`).
- **"Structure creation requires Hex-Rays"** (`:93`) is wrong — the struct apply path uses only
  `ida_typeinf` (`actions_service.py:470-483`); no Hex-Rays call in that method.
- **Editable columns**: doc says only Description is editable (`:26`); the view opens editing on
  columns 1–4 — Action, Description, Status *and* Confidence (`actions_tab_view.py:201-205`).
- Doc never mentions the Stop-toggle on Analyse Function (`actions_controller.py:188-190`,
  `actions_tab_view.py:264-282`) or the right-click entry point (see §9).

## 2. `analyze_current_function()` — what context is collected

Entry points: the Analyse Function button (`actions_tab_view.py:105-110`) and the plugin
right-click action, which opens the form, switches tabs, and calls
`form.actions_controller.analyze_function()` (`idassist_plugin.py:65-81`, at `:75`). **Bug**:
`ActionsController` defines `analyze_current_function` (`actions_controller.py:184`), *not*
`analyze_function`. Exhaustive grep `grep -rn "def analyze_function\b\|analyze_function()" src/ *.py`
returns only the call site (`idassist_plugin.py:75`) — the right-click path raises AttributeError
swallowed by the action's try/except and shows `[IDAssist] ERROR: …` (`idassist_plugin.py:76-77`).
**Lead-verified 2026-11-02** by reading `idassist_plugin.py:65-82` in full: the tab switch at
`:74` succeeds, then `:75` throws — so right-click "Rename Suggestions" opens the Actions tab
but generates nothing; the panel's own Analyse Function button still works.

Context collection inside `analyze_current_function`:

- `context_service.get_current_context()` (`actions_controller.py:215`); bail on `error` key.
- `context_service.get_code_at_level(offset, current_view_level)` with fallback order
  PSEUDO_C → ASM if the current level fails, tracking `effective_view_level`
  (`:224-237`).
- The effective view level is pushed into every suggestion tool via
  `actions_tool_registry.set_view_level(...)` (`:247`; registry fans out at
  `actions_tool_registry.py:121-124`) — this is how proposals later know pseudocode-vs-assembly.
- Registry suggestions are cleared per run: `clear_suggestions()` (`:252`;
  `actions_tool_registry.py:126-130`) — "UI table keeps previous suggestions, registry gets new
  ones" (`:250-251`).

Selected action-type checkboxes map display names → `ActionType` enums
(`actions_controller.py:377-406`) and then to the tool names that get sent to the LLM:
`AUTO_CREATE_STRUCT → "create_struct"` (`:626-631`). Only the *selected* tools are exposed per
call (`:633-644`).

## 3. The LLM call — one-shot tool calling, no JSON, no result loop

`_query_llm_with_action_tools` builds a **single user message** (no system prompt,
`actions_controller.py:600`) from `_generate_actions_analysis_prompt`: function name/address/
architecture plus the full formatted code body (`:650-698`, code dump at `:681-682` via
`_format_code_for_analysis` at `:704-727`), then per-selected-action instructions
(`:662-669`) and this nudge:

> Call the appropriate tools with your suggestions. Provide high confidence scores (0.7+) only
> for suggestions you're confident about based on clear evidence in the code.
> (`actions_controller.py:696`)

`ActionsLLMThread` (`actions_llm_thread.py:18`) sends a `ChatRequest` with
`tools=self.action_tools`, `stream=True`, `temperature=0.1`, `max_tokens` from provider config
(`:85-92`). Tool calls are harvested from streamed chunks; on `stop_reason == "tool_calls"` the
accumulated calls are emitted and the thread returns (`:115-134`). `ActionsToolExecutorThread`
executes each call through the registry (`:169-188`). **One round-trip only**: after tool
execution completes, the controller populates the table and ends the analysis
(`actions_controller.py:804-822`) — tool results are never fed back to the LLM, and there is no
second LLM turn. Streaming text is deliberately hidden (`:730-733`).

Registry safety filter: incoming tool calls are filtered by `is_action_tool` before execution
(`actions_controller.py:774`; `actions_tool_registry.py:59-61`).

## 4. The four suggestion tools and the ActionProposal shape

Tool definitions are OpenAI-function-schema dicts wrapped as `{"type":"function","function":…}`
(`actions_tool_registry.py:45-57`). One definition verbatim (`actions_tools.py:294-325`):

```python
"name": "create_struct",
"description": "Suggest struct definitions based on consistent memory access patterns and offset usage",
"parameters": { "type": "object", "properties": {
    "struct_name": {...}, "offset_pattern": {...},
    "suggested_definition": {"description": "C struct definition with field names and types"},
    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0, ...},
    "rationale": {...} },
  "required": ["struct_name", "offset_pattern", "suggested_definition", "confidence", "rationale"]}
```

`execute()` on each tool does exactly three things: check required fields, range-check
confidence, and build an `ActionProposal` returned in a dict — e.g.
`RenameFunctionTool.execute` (`actions_tools.py:77-121`, proposal at `:98-106`). **No tool
touches the IDB**: `actions_tools.py` imports only `typing`/`abc`, the two model/service modules
(`models.action_models`) and `src.ida_compat`'s **log** helper (`:10-16`; inventory corrected
2026-11-02 — earlier draft said "typing/abc and the two services" only) — no `ida_*` SDK module
appears anywhere in the file (confirmed by reading the full
372 LOC; a case-insensitive grep for `ida` in that file hits only that `ida_compat` log import,
"IDAssist" identifiers and comments — no IDA API; *corrected 2026-11-02 — earlier draft said
"nothing beyond docstrings"*). The registry merely
appends the proposal: `self.active_suggestions.append(proposal)`
(`actions_tool_registry.py:87-92`).

`ActionProposal` (`src/services/models/action_models.py:20-29`, full):

```python
action_type: ActionType   # RENAME_FUNCTION/RENAME_VARIABLE/RETYPE_VARIABLE/AUTO_CREATE_STRUCT (:12-17)
target: str               # Function/variable name being acted upon
current_value: str        # Current name/type
proposed_value: str       # Proposed new name/type
confidence: float         # 0.0 to 1.0
rationale: str            # Why this change is suggested
view_level: Optional[str] # "assembly" or "pseudo_c"
```

plus `ActionResult(success, message, action_type, target, old_value, new_value, error)`
(`:32-41`).

**Confidence source**: purely model-reported (a required tool parameter). Validation is a hard
reject, not a clamp: out-of-range returns `{"success": False, "error": "Confidence must be
between 0.0 and 1.0"}` (`actions_tools.py:89-95`, `:170-176`, `:255-261`, `:340-346`). Nothing
otherwise calibrates or verifies the number. *(inference: confidence is decorative calibration
text the model invents.)*

## 5. Table population and the view

`_populate_proposals_in_view` (`actions_controller.py:408-453`): description is formatted
`f"{proposal.target} -> {proposal.proposed_value}"` (`:426`), duplicates are skipped by
description string (`:429-431`), status is `"Ready" if confidence >= 0.5 else "Low Confidence"`
(`:433`), confidence is shown as `{:.2f}` (`:434`), and `view_level` rides as hidden
`Qt.UserRole` data on the description cell (`:442-446`).

View (`actions_tab_view.py`): 5 columns Select/Action/Description/Status/Confidence (`:71-74`);
per-row select checkbox cell widget (`:133-141`); all four data cells editable via double-click
(`:201-205`); Apply Actions emits only checked rows' text, collected as dicts including the
UserRole `view_level` (`:173-191`, `:207-211`); status colors light-yellow "Applying…",
light-green "Applied", light-red "Error: …" (`:234-258`); buttons Analyse Function / Apply
Actions / Clear (`:105-107`) with busy-state toggling and Stop style (`:264-282`). There is no
per-row Apply/Ignore button and no filters — batch apply only. `populate_sample_data`
(`:213-232`) is dead demo scaffolding referencing a nonexistent `add_comment` action (`:222`).

## 6. Apply layer — `ActionsApplyThread` + `ActionsService`

`apply_selected_actions` marks rows "Applying…" and spawns `ActionsApplyThread`
(`actions_controller.py:262-298`, marking at `:575-586`). The worker applies actions sequentially
with per-action success/failure counts (`actions_controller.py:49-89`), then the controller
refreshes IDA views on the main thread — `ida_kernwin.refresh_idaview_anyway()` plus
`vu.refresh_view(True)` on Pseudocode widgets A–H (`:552-573`).

**Critical: the apply path re-parses the table, not the proposal.** `_convert_view_data_to_proposal`
(duplicated at `:91-136` and `:455-498`) maps the display Action text back to an ActionType,
splits the *editable description* on `" -> "` into target/proposed (`:475-478`), and **hard-codes
`confidence=0.8, rationale="User-selected action from table"`** (`:489-490`). A row without " -> "
becomes target=description, proposed=`new_{description}` (`:479-481`). So the model's proposal
object, rationale and real confidence are discarded at apply time — but user table edits DO flow
through to the IDB write.

`ActionsService.apply_action` re-reads context on the main thread and dispatches by type
(`actions_service.py:80-118`). All IDB mutation happens inside `execute_on_main_thread`
closures; the wrapper is `idaapi.execute_sync(..., MFF_FAST)` (`ida_compat.py:63-79`, call at :79).
Per-type APIs, verified:

| Action | IDA call | Site |
|---|---|---|
| Rename function | `ida_name.set_name(func.start_ea, new_name, ida_name.SN_CHECK)` | `actions_service.py:181-183` |
| Rename variable (pseudocode) | `ida_hexrays.rename_lvar(func.start_ea, old, new)` | `:257` |
| Rename variable (assembly) | `idc.get_frame_id` + `idautils.StructMembers` + `idc.set_member_name(frame_id, offset, new)` | `:319-327` |
| Retype variable | `ida_hexrays.decompile` → `cfunc.get_lvars()` → `ida_typeinf.parse_decl(tinfo, til, type+";", 0)` → `target_lvar.set_lvar_type(tinfo)` + `cfunc.save_lvars()` | `:400-429` |
| Create struct | `ida_typeinf.parse_decl(struct_def+";")` → `tinfo.set_named_type(til, name, NTF_REPLACE)` | `:472-479` |

Retype is refused for assembly-level proposals ("switch to pseudocode and re-analyze")
(`:379-386`). Variable rename dispatches on `proposal.view_level == "assembly"` (`:236-240`).
Failure surfacing: each closure fills a `result_holder` error string; the apply thread emits
per-row status, rendering `Error: {msg}` in red (`:174-225`, view `:254-258`).

**Undo**: none. `grep -rin "undo"` over all five Actions files returns zero hits — the plugin
never records old values for rollback (old_value exists in `ActionResult` but only for the
success message, e.g. `actions_service.py:211`). Recovery is manual re-rename (or whatever IDA
itself offers). *(inference.)*

**Suspected bug — struct success test inverted**: `set_named_type` success is treated as
`rc != 0` (`:479-483`). In Hex-Rays typeinf, 0 is the OK status code, so this looks inverted —
structs that apply cleanly may report "set_named_type failed" and vice versa
(`*(inference — IDA API semantics not verifiable from this repo.)*).

**Struct limits**: the proposal carries a free-text "C struct definition with field names and
types" (tool schema `actions_tools.py:309-312`) parsed by one `parse_decl` call — so nested
types/arrays are only as good as IDA's local-types parser; no iterative member-by-member
building, no idapalettes, no local-types-editor scripting. On success the struct is *named into
the local type library* via `set_named_type(..., NTF_REPLACE)`; existing definitions are
**replaced** (`actions_service.py:479`). Nothing then applies the struct to any variable —
retro-fitting a variable to the new struct requires a separate retype suggestion.

## 7. The `llm_renames` audit trail

Table from migration 007: `llm_renames(binary_id, address, symbol_type, new_name, created_at,
PRIMARY KEY(binary_id,address,symbol_type))` (`db_migrations.py:507-527`), written with
`INSERT OR REPLACE` (`analysis_db_service.py:1866-1879`).

Writers (exhaustive — `grep -rn "llm_renames\|record_llm_rename\|save_llm_rename" src/`):
- Actions function rename: also syncs graph node name via `GraphStore.update_node_name` then
  `db.record_llm_rename(hash, addr, 'function', new_name)` — best-effort, "non-fatal"
  (`actions_service.py:191-207`).
- Actions variable rename, both pseudocode (`:266-278`) and assembly (`:337-349`) —
  symbol_type `'variable'`.
- Internal Query/ReAct function tool: `internal_tools.py:356-366` (record at `:364`).

Readers: exactly one — SymGraph's provenance classifier `is_llm_renamed` deciding
`'llm'` vs `'user'` labels (`symgraph_controller.py:829-843`, call at `:838`; seam per ch38).
Notable gaps: **retype and struct-creation are never recorded**, and the internal
`_rename_variable` path never records (`internal_tools.py:372-391` — no `record_llm_rename`
call, confirmed by the same grep). *(inference: provenance coverage is rename-of-what-I-touched,
not all-mutations.)*

## 8. Three rename paths compared

| | (a) Actions tab | (b) internal `rename_function`/`rename_variable` (Query/ReAct) | (c) SymGraph pull (ch38 seam) |
|---|---|---|---|
| Mechanism | tool-calling → `ActionProposal` → table → human checkbox → apply (`actions_controller.py:769-810`, `:262-298`) | model calls mutating tool directly; IDB write inside the tool (`internal_tools.py:333-370`) | graph pull/sync of names (ch38; not re-verified here) |
| Gate | human reviews table & clicks Apply; gating is absolute — suggestion tools can't write (`actions_tools.py:10-16`) | approval-gated in plain Query, ungated in ReAct (ch34 verified context) | n/a (seam) |
| IDA APIs | `set_name`/`rename_lvar`/`set_member_name`/`parse_decl`+`set_lvar_type`/`set_named_type` (table in §6) | `ida_name.set_name(..., SN_CHECK)` `:346`; `ida_hexrays.rename_lvar` `:383` | (ch38) |
| `llm_renames` | yes for renames (`actions_service.py:205`, `:276`, `:347`); no for retype/struct | yes for functions only (`internal_tools.py:364`) | reader side only (`symgraph_controller.py:838`) |
| Transcript/other | no chat transcript involvement — streaming text is discarded (`actions_controller.py:730-733`) | chat transcript of the query session (ch34) | graph nodes; function renames from path (a) also sync node names (`actions_service.py:204`) |

Paths (a) and (b) duplicate the same IDA calls independently (`actions_service.py:181` vs
`internal_tools.py:346`) — two apply implementations that happen to match.

## 9. Effectiveness facts

- **No pre-apply verification beyond the model's word.** `ActionsService` defines
  `validate_function_name` / `validate_variable_name` / `validate_variable_type` (length/charset/
  no-op checks, `actions_service.py:130-165`) but they are **never called** — exhaustive grep
  `validate_function_name\|validate_variable_name\|validate_variable_type` matches only the
  three `def` lines. Dead validation layer.
- Name-collision safety is only IDA's `SN_CHECK` flag on `set_name` (`actions_service.py:182`,
  `internal_tools.py:346`); the apply then reports False as "ida_name.set_name returned False"
  (`:184-185`). No pre-check of existing names in IDAssist code.
- Confidence numbers: model-reported; prompt asks for 0.7+ only with clear evidence
  (`actions_controller.py:696`); table status flips at the 0.5 threshold (`:433`); out-of-range
  values reject the whole tool call (§4). No suggestion is ever auto-filtered by confidence.
- Batching: one apply pass over checked rows, sequential, stoppable via Stop
  (`actions_controller.py:45-57`); no per-row apply, no apply-all shortcut, no re-analyse loop
  (one-shot LLM, §3).
- Doc-vs-code: doc claims match the main APIs (`docs/tabs/actions-tab.md:89-92`) but miss the
  assembly rename path, mis-state struct creation as Hex-Rays-dependent, and understate
  editability (all §1 drift). The right-click shortcut — the doc's implied convenience entry —
  is broken at this HEAD (§2).

## Gaps

- Did not verify `BinaryContextService.get_current_context`/`get_code_at_level` internals
  (covered elsewhere); did not trace `GraphStore.update_node_name` (ch38 territory).
- `set_named_type` return-code semantics asserted from knowledge, not repo evidence.
- No runtime execution, so the right-click AttributeError and the inverted struct success test
  remain static-analysis findings.

## Sources

- `docs/tabs/actions-tab.md:1-99` (full read)
- `src/controllers/actions_controller.py:1-836` (full read; key spans :32-136, 184-260, 262-298, 408-498, 552-586, 589-702, 769-822)
- `src/controllers/actions_llm_thread.py:1-192` (full read)
- `src/services/actions_tools.py:1-372` (full read)
- `src/services/actions_tool_registry.py:1-149` (full read)
- `src/services/actions_service.py:1-525` (full read)
- `src/services/models/action_models.py:1-41` (full read)
- `src/views/actions_tab_view.py:1-287` (full read)
- `src/ida_compat.py:63-79`; `src/services/db_migrations.py:507-527`
- `src/services/analysis_db_service.py:1866-1894`; `src/services/internal_tools.py:333-391`
- `idassist_plugin.py:60-85, 240-255`; `src/views/idassist_form.py:220-224, 233-234`
- `src/controllers/symgraph_controller.py:829-843`
- Greps (named in-text): `llm_renames|record_llm_rename|save_llm_rename`;
  `def analyze_function\b|analyze_function()`; `validate_*_name|validate_variable_type`;
  `undo` in the five Actions files; `is_llm_renamed`.
- Clone: `/tmp/opencode/IDAssist` @ `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302`.

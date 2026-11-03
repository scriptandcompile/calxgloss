# 31 — Plugin foundation: entry, compat, threading, persistence, settings

> Part of the [overview](README.md). Clone HEAD 09dd910d…, written 2026-11-01; lead spot-check of key citations 2026-11-02 (all confirmed: `plugin_t`/`PLUGIN_KEEP`/hotkey, the `on_name_changed` grep, `execute_sync(MFF_FAST)`, stored-IDB SHA path, PySide6 6.8.0 skip, DB paths, schema table list, `settings.db` + plaintext `api_key`).

This chapter covers the layers every IDAssist feature sits on: the plugin entry
point, the IDA and Qt compatibility shims, the background-worker threading model,
the dockable UI shell, the service container, and the two SQLite databases
(analysis + settings) with their migration machinery. All paths are relative to
the clone at `/tmp/opencode/IDAssist`.

---

## 1. Entry point — `idassist_plugin.py` (313 LOC)

**Plugin base class: the legacy `idaapi.plugin_t`, not `plugin2_t`.**
`IDAssistPlugin(idaapi.plugin_t)` at `idassist_plugin.py:192`, with
`flags = idaapi.PLUGIN_KEEP` (`:195`) so the plugin stays resident after
`init()`. `PLUGIN_ENTRY()` at `:311-313` just returns an instance.

- **Hotkeys.** The plugin's own activation hotkey is `Ctrl+Shift+A`
  (`PLUGIN_HOTKEY`, `:27`, wired via `wanted_hotkey`, `:199`) — it triggers
  `run()`. Two *additional* action hotkeys exist: `Ctrl+Shift+E` (explain) and
  `Ctrl+Shift+Q` (query), registered as action accelerators at `:241` and `:257`.
- **`init()` (`:207-231`)** logs the load, registers three actions
  (`_register_actions`, `:233-264`), installs an `IDB_Hooks` subclass and a
  `UI_Hooks` subclass, then installs a **one-shot `_DeferredOpenHook`**
  (`:180-189`) whose `ready_to_run()` calls `self.run(0)` and unhooks — the
  panel auto-opens once IDA's UI is up. Returns `PLUGIN_KEEP`; any exception
  yields `PLUGIN_SKIP` (`:231`).
- **`run()` (`:266-274`)** does exactly one thing: `IDAssistForm.open()` (the
  singleton dockable panel), with traceback printed to IDA's message window on
  failure.
- **`term()` (`:276-308`)** shuts down the settings controller's workers *while
  their Qt owners are still valid* (`:279-285`), unregisters the three actions,
  unhooks both hook sets, then calls `registry.shutdown()` if the service
  registry is initialized (`:300-303`).
- Version is read at import time from `ida-plugin.json` (`_load_version`,
  `:30-39`).

**The `activate`/`update` at ~49-123 are `action_handler_t` methods, not
`plugin_t` methods.** Four action classes populate context menus and hotkeys:

| Action | `activate` does | registered as |
|---|---|---|
| `ExplainFunctionAction` (`:46-62`) | opens form, switches to Explain tab, calls `explain_controller.explain_function()` (`:51-56`) | `idassist:explain_function`, hotkey `Ctrl+Shift+E` (`:237-244`) |
| `RenameSuggestionsAction` (`:65-81`) | same but `actions_controller.analyze_function()` (`:70-75`) | `idassist:rename_suggestions`, **no hotkey** (`None`, `:249`) |
| `AskAboutSelectionAction` (`:84-102`) | switches to Query tab and pre-fills `"What does this function do? #func"` (`:92-96`) | `idassist:ask_about_selection`, `Ctrl+Shift+Q` (`:253-259`) |
| `ExplainHotkeyAction`/`QueryHotkeyAction` (`:105-124`) | thin wrappers delegating to the two above | — (comment-only; hotkeys live on the action descs) |

`update()` returns `AST_ENABLE_FOR_WIDGET` for menu actions (`:62`, `:81`,
`:102`) and `AST_ENABLE_ALWAYS` for the hotkey wrappers (`:113`, `:124`).

**Event hooks (`IDAssistIDBHooks`, `:131-154`):**
- `renamed(ea, new_name, is_local)` (`:134-146`) — tries to call
  `semantic_graph_controller.on_name_changed(ea, new_name)` behind a
  `hasattr` guard (`:142-143`) to "mark graph as potentially stale" (`:140`).
  **However, no definition of `on_name_changed` exists anywhere in the repo** —
  grep finds only the two call-site lines in `idassist_plugin.py:142-143`. As
  shipped, the `renamed` hook is a silent no-op; nothing consumes IDB renames.
- `func_added` (`:148-150`) and `func_updated` (`:152-154`) are stubs that just
  `return 0`; they feed nothing.

**Context-menu population (`IDAssistPopupHooks`, `:161-173`):** in
`finish_populating_widget_popup`, if the widget type is disassembly or
pseudocode (`BWN_DISASM`, `BWN_PSEUDOCODE`, `:167`), the three actions are
attached under an `"IDAssist/"` submenu prefix (`:168-173`).

---

## 2. IDA compat layer — `src/ida_compat.py` (137 LOC)

Import of `idaapi`/`ida_kernwin`/`ida_nalt` is wrapped in try/except setting
`_IN_IDA` (`:11-18`) so every helper degrades to a no-op/print path outside IDA.

- **Logging:** `IDALogger` (`:21-56`) — four static methods
  (`log_debug/info/warn/error`) that wrap `ida_kernwin.msg()` with a
  `[IDAssist]` prefix, or plain `print()` outside IDA. A module-level `log`
  instance is created at `:60`; the docstring says the interface deliberately
  matches Binary Ninja's `log.Logger` so ported code only changes its import
  (`:24-25`).
- **`execute_on_main_thread(callback)` (`:63-79`)** is *signal-free and
  timer-free*: it is a straight wrapper around `idaapi.execute_sync(callback,
  idaapi.MFF_FAST)` (`:79`), with an outside-IDA passthrough `callback()`
  (`:75-77`). The return value of `execute_sync` (i.e. the callback's return)
  is returned to the caller — but in practice worker threads pass results back
  by closing over mutable holders, e.g. `bh_holder[0] = get_binary_hash()`
  (`actions_service.py:199`, `internal_tools.py:361`). There are 30+ call
  sites across `binary_context_service.py`, `internal_tools.py` (header: "All
  tools that call IDA APIs use `execute_on_main_thread()`", `:7`),
  `actions_service.py` (header: "All apply methods use
  `execute_on_main_thread()` since IDA database…", `:7`), graphrag extractors,
  and controllers.
- **`get_user_data_dir()` (`:82-95`):** `idaapi.get_user_idadir()` (fallback
  `~/.idapro`) joined with `idassist`, created on demand — this is the root of
  both databases (see §7/§8).
- **`get_binary_hash()` (`:98-132`) is the IDB-binding mechanism.** It *prefers
  the SHA-256 that IDA stored inside the IDB* —
  `ida_nalt.retrieve_input_file_sha256()`, feature-detected with `getattr`
  (`:110-116`) — with the comment "Prefer the original input SHA-256 stored in
  the IDB so detached .i64/.idb databases still resolve to the correct binary
  identity" (`:108-109`). Only if that is unavailable does it fall back to
  re-hashing the on-disk input file in 8 KiB chunks (`:118-128`). This is
  exactly the mechanism of commit `a321ad1` — "Use stored IDB SHA for detached
  database queries" (verified via `git show -s a321ad1`).

---

## 3. Qt compat layer — `src/qt_compat.py` (130 LOC)

Single shim module consumers import from (`from ..qt_compat import QWidget,
Signal, exec_dialog, ...`, docstring `:1-7`).

- **Binding order: PySide6 first, PyQt5 fallback** (`:25-52`); the header
  comment ties this to IDA versions: "PySide6 (IDA >= 9.2) is tried first;
  falls back to PyQt5 (IDA <= 9.1)" (`:4`). `QT_BINDING` is set to the winning
  binding name (`:43`, `:52`) and `QT_AVAILABLE` derived at `:54`.
- **Symbol re-export is not `import *`:** `_binding_exports(*modules)`
  (`:9-22`) walks `dir(module)` and copies every public attribute into
  `globals()` (`:40`, `:49`), because "Some PySide6 builds used by IDA with
  Python 3.14 do not expose all of QtCore/QtGui/QtWidgets through wildcard
  imports" (`:11-15`). Two names are then *explicitly* aliased across the
  binding split: `Signal = _QtCore.Signal` vs `pyqtSignal` (`:41`, `:50`) and
  `QAction` from `QtGui` (PySide6) vs `QtWidgets` (PyQt5) (`:42`, `:51`).
- **The PySide6 6.8.0 skip (`:26-35`):** before importing PySide6, the version
  is read from package metadata via `importlib.metadata.version("PySide6")`
  (no import needed); if it equals `"6.8.0"` an `ImportError` is raised —
  "PySide6 6.8.0 is known to crash IDA Pro; falling back to PyQt5" — citing
  the upstream bug `spyder-ide/qtpy#494` (`:26-27`). The `except Exception` at
  `:33-35` re-raises *only* if the message contains `6.8.0`, so a missing
  PySide6 metadata entry still falls through to a normal import attempt.
- **Behavior shims:** `exec_dialog()` — `.exec()` vs `.exec_()` (`:78-82`);
  `utc_timezone()` — `QTimeZone.utc()` vs `QTimeZone(0)` (`:85-89`); a
  red stop-button stylesheet plus `apply_stop_button_style`/
  `clear_stop_button_style` that stash the base stylesheet in a dynamic Qt
  property and force `unpolish`/`polish` to make the style change take effect
  cross-platform (`:57-130`).
- **Test guard (`tests/test_qt_compat.py`, 49 LOC):** two tests. (1)
  `_binding_exports` must collect named members even when the fake module's
  `__all__` is empty (`:15-28`). (2) An AST scan of every `.py` under `src/`
  collects *every symbol imported from any `qt_compat` module* and asserts
  `hasattr(qt_compat, name)` for all of them in the current binding — a
  completeness regression net for the re-export list (`:30-45`).

---

## 4. Threading — `src/daemon_worker.py` (117 LOC)

`DaemonWorker(QObject)` (`:10`) is the project's answer to the classic
QThread-lifetime crash: the docstring explains a `QThread` object must outlive
its native thread, and deleting (e.g.) a settings dialog mid-request "can
otherwise abort the entire IDA process" — so the worker is a plain **daemon
Python thread** (`threading.Thread(..., daemon=True)`, `:34-39`) whose stack
keeps the bound worker object alive until `run()` returns (`:13-17`).

Mechanics:
- `start()` spawns `_bootstrap` (`:41-49`), which calls subclass `run()`
  (`:51-52`, `NotImplementedError`) and then emits the Qt signal
  `finished = Signal()` (`:20`) — the *only* signal declared here; subclass
  workers declare their own result signals. `finished.emit()` swallows
  `RuntimeError` because "IDA may already be tearing down its Qt objects"
  (`:45-49`). Qt auto-connection of a signal emitted from the worker thread to
  a UI-thread receiver is how results reach widgets. *(inference: the exact
  delivery mechanism for per-subclass result signals follows the same
  Signal/slot pattern; subclass wiring lives in the controllers chapter.)*
- Cancellation mirrors QThread's API: `requestInterruption()` sets a
  `threading.Event` **and**, if an asyncio task is registered, cancels it via
  `loop.call_soon_threadsafe(task.cancel)` (`:57-68`); `isInterruptionRequested`
  (`:70-71`), `quit()` (`:73-74`), `wait(timeout_ms)` joins with a guard
  against self-join (`:76-85`).
- `run_async_task(loop, task, timeout_seconds)` (`:100-117`) is a helper for
  subclasses whose `run()` drives an asyncio loop: it pumps
  `loop.run_until_complete(asyncio.wait({task}, timeout=min(0.1, remaining)))`
  in ≤100 ms slices so interruption is checked cooperatively, and on deadline
  cancels, drains with `return_exceptions=True`, and raises
  `asyncio.TimeoutError`.
- Subclasses found in this read pass: `ProviderTestWorker`,
  `ProviderModelFetchWorker`, `MCPTestWorker`, `SymGraphTestWorker`
  (`settings_controller.py:153,268,357,429`).

**The other half of the threading story is `execute_on_main_thread`** (§2):
worker threads do the network/LLM work, and every IDB read or mutation inside
`run()` is marshalled back through `idaapi.execute_sync(MFF_FAST)` into IDA's
main thread, with results returned via closure holders
(`actions_service.py:189-200` shows the rename + hash-capture pattern). The
daemon-thread + `MFF_FAST` pair is the plugin's core concurrency contract.

---

## 5. UI shell — `src/views/idassist_form.py` (300 LOC)

**Docking is done with `idaapi.PluginForm`, not `ida_QWidget` directly:**
`IDAssistForm(idaapi.PluginForm)` (`:60`); `OnCreate` converts the IDA form
handle to a Qt widget with the inherited `self.FormToPyQtWidget(form)` (`:94`)
and sets a margin-free `QVBoxLayout` holding one `QTabWidget` (`:97-113`).
The singleton pattern is class-level: `_instance` (`:63`), and `open()`
(`:66-78`) creates it once then calls `Show("IDAssist", options=…)` with
`WOPN_TAB | WOPN_RESTORE | WOPN_PERSIST` (`:71-77`) — docked as a tab, layout
restored, panel kept across workspace changes.

**Tab order as actually added (`:104-110` + each `_init_*`):**
Explain → Query → Actions → Semantic Graph → SymGraph → RAG → Settings.
(The module docstring at `:7` lists them as "Explain, Query, Actions, Semantic
Graph, RAG, SymGraph, Settings" — the code inits SymGraph *before* RAG; minor
doc drift.)

**Controller construction is eager-at-open, with lazy *imports*.** It is not
lazy per-tab-click: each `_init_*_tab` imports the view+controller classes
*inside the method* (so a broken tab's import failure can't sink the whole
panel) then immediately constructs both and `addTab`s the view, each wrapped
in try/except + `log.log_error` — e.g. Explain at `:172-187`, Settings at
`:160-170`, SymGraph at `:269-282` (SymGraphController additionally receives
`query_controller=getattr(self, 'query_controller', None)`, `:276-279`).
Explain and Query views wire an `rlhf_feedback_requested` Qt signal to their
controller's `handle_rlhf_feedback` (`:181`, `:203`).

**Cursor/context plumbing (`IDAssistUIHooks`, `:16-57`):** `screen_ea_changed`
fans the new EA out to registered listener callbacks (`:37-43`); Explain,
Query, Actions and Semantic Graph register listeners that forward to their
controller's `set_current_offset` (`:184-192`, `:206-214`, `:226-234`,
`:247-255`). `current_widget_changed` (`:45-57`) tracks whether the last
active view was pseudocode or disassembly and pushes that into
`binary_context_service.set_tracked_view_level(ViewLevel.PSEUDO_C / .ASM)` —
so "what does this line do?" questions answer against the right view.
`_initialize_binary_context` (`:125-158`) computes `get_binary_hash()`, calls
`initialize_binary()` on five controllers, and seeds each with
`get_screen_ea()`. `OnClose` (`:284-300`) shuts down the settings controller,
unhooks and nulls `_ui_hooks`, and finally clears `_instance`.

---

## 6. Service DI — `src/services/service_registry.py` (142 LOC)

Small hand-rolled container, not a framework. `ServiceRegistry.initialize()`
(`:31-53`) holds a `threading.Lock`, is idempotent, and wires **only two
services in dependency order**: `SettingsService()` first (`:41-42`), then
`LLMService(settings_service)` (`:44-46`). On failure it clears everything and
re-raises as `RuntimeError` (`:50-53`). `get_service()` lazily initializes on
first access (`:65-66`); typed getters `get_settings_service` /
`get_llm_service` raise if missing (`:70-82`). `shutdown()` iterates the
insertion order **reversed**, duck-typing a `shutdown()` method per service
(`:86-97`); `reset()` = shutdown + initialize (`:99-102`). A module-global
singleton is created under `_registry_lock` (`:117-133`), with
`reset_service_registry()` for tests (`:135-142`).

Everything else — `AnalysisDBService`, `RLHFService`,
`BinaryContextService`, MCP services — is **not** in the registry; the
singleton-style services self-manage (e.g. `__new__` singletons with a class
lock in `settings_service.py:24-28` and `rlhf_service.py:22-28`). *(inference
from the greps: construction sites of those other services live in the
controller layer.)*

---

## 7. Persistence — analysis DB, schema, IDB binding, migrations

### File location and IDB binding (single shared DB, hash-keyed rows)

`AnalysisDBService._init_database` puts the DB at
`<get_user_data_dir()>/analysis.db` = `~/.idapro/idassist/analysis.db`
(`analysis_db_service.py:46-60`). **There is no per-IDB database file**: one
shared `analysis.db` serves all binaries, and every domain table carries a
`binary_hash` (or `binary_id`) column as its first-class key (`:360`, `:375`,
`:388`, `:442`; graph tables use `binary_id`, `:215`, `:264`). The DB binds to
an IDB *logically* through §2's `get_binary_hash()` — the IDB-stored
`retrieve_input_file_sha256` preferred path (`ida_compat.py:108-116`) is what
makes a detached `.i64`/`.idb` (input file gone) still resolve to the same
`binary_hash` rows. `get_binary_hash()` is called from form, controllers,
services and the MCP orchestrator (repo grep: 37 bare matches,
21 of them `get_binary_hash()` invocations; e.g.
`idassist_form.py:128`, `actions_service.py:199`).

Thread-safety: connection factory uses `check_same_thread=False` (`:57`, `:67`)
with `PRAGMA foreign_keys = ON` and `PRAGMA journal_mode = WAL` (`:69-70`),
gated by a `threading.RLock` (`:37`) that is deliberately exposed to other
services via `get_db_lock()` (`:479-481`).

### Base schema (`_create_tables`, `:349-473`)

| Table | Columns (abridged) | Stores |
|---|---|---|
| `BNAnalysis` (`:358-368`) | binary_hash, function_start, query_type, response, metadata, created/updated; UNIQUE(hash, start, query_type) | cached LLM analysis responses per function+query kind |
| `BNContext` (`:373-381`) | binary_hash, function_start, context_data, **expires_at**; UNIQUE(hash, start) | TTL'd function-context cache |
| `BNChatHistory` (`:386-397`) | binary_hash, chat_id, message_order, role, content, metadata | legacy chat transcripts (superseded by migration 003) |
| `BNChatMetadata` (`:401-415`) | binary_hash, chat_id, name, metadata + `ALTER … ADD COLUMN metadata` retry (`:412-415`) | chat titles/settings |
| `SystemPrompts` (`:419-426`) | prompt, version, is_active | versioned system-prompt store |
| `BNLineExplanations` (`:440-458`) | binary_hash, function_start, line_address, view_type, line_content, context_before/after, explanation, metadata; UNIQUE(hash, addr, view_type) | per-line explanation cache for disasm vs pseudocode |

Indexes at `:429-436` and `:457-458`. The `BN*` prefixes are Binary Ninja
porting residue — the tables now store IDA-side data (addresses as EAs).

### GraphRAG schema (`_ensure_graphrag_schema`, def `:139`, body `:210-347`)

Deliberately re-ensured on every startup ("even if the stored schema_version
is stale", `:460-464`), because legacy PascalCase tables (`GraphNodes`,
`GraphEdges`, …) are renamed to `*_backup_N` rather than mutated (`:204-206`,
helper `_rename_table_with_counter` `:97-102` via `_ensure_table_schema`
`:109`).

- `graph_nodes` (`:211-240`): TEXT PK id; type, address, **binary_id**, name,
  signature, decompiled_code, disassembly, raw_content, llm_summary,
  confidence, **embedding BLOB**, security_flags, network_apis, file_io_apis,
  ip_addresses, urls, file_paths, domains, registry_keys, category,
  risk_level, activity_profile, analysis_depth, created/updated, `is_stale`,
  `user_edited` — the semantic knowledge graph's node payloads.
- `graph_edges` (`:247-258`): source/target FKs with `ON DELETE CASCADE`,
  weight, metadata; UNIQUE index `(source_id,target_id,type)` enforces edge
  dedup at the DB level (`:301`).
- `graph_communities` (`:261-274`): Leiden-style hierarchical communities
  (level, self-FK `parent_community_id`, name, summary, member_count,
  is_stale defaults 1).
- `community_members` (`:280-288`): community↔node join with membership_score.
- `node_fts` FTS5 **external-content** virtual table over
  id/name/signature/llm_summary/security_flags (`:315-324`) kept in sync by
  three hand-written triggers `graph_nodes_ai/ad/au` (`:326-345`); if the
  SQLite build lacks FTS5 the failure is only a warning (`:346-347`).
- 14 index statements at `:290-306` (13 `CREATE INDEX` + 1 `CREATE UNIQUE INDEX` at `:301`).

### Migration mechanism (`src/services/db_migrations.py`, 775 LOC)

Versioning table `schema_version(id AUTOINCREMENT, version, applied_at)`
(`:48-54`); the current version is the newest insert
(`SELECT version … ORDER BY id DESC LIMIT 1`, `:30`).
`migrate_analysis_db()` (`:71-102`) is the startup entry: read version, walk a
hard-coded ordered list of ten migrations (`:76-87`), run each with
`current_version < version`, and bump the version only on success — any
failure aborts the chain and returns False (`:89-96`).
`AnalysisDBService._run_migrations()` calls it after `_create_tables`
(`analysis_db_service.py:43-44, 483-487`).

What each numbered migration does:

1. **001 initial schema** — creates the base analysis tables
   (`db_migrations.py:105`).
2. **002 add indexes** — `created_at` indexes on BNAnalysis / BNChatHistory
   (`:124-125`).
3. **003 native message storage** — creates `BNChatMessages` (binary_hash,
   chat_id, message_order, **provider_type**, **native_message_data** (the
   provider-native JSON), role, content_text, message_type,
   parent_message_id self-FK, conversation_thread_id; `:143-160`), copies old
   `BNChatHistory` rows best-effort (`:169-175`), renames the legacy table to
   `BNChatHistory_backup` (`:209`).
4. **004 GraphRAG tables** — first `graph_nodes`/`graph_edges` + indexes
   (`:282, :315, :328-336`).
5. **005 GraphRAG communities** — `graph_communities` + `community_members`
   (`:384, :400, :410-413`).
6. **006 GraphRAG FTS** — `node_fts` FTS5 virtual table (`:459`).
7. **007 LLM renames** — `llm_renames(binary_id, address, symbol_type,
   new_name, created_at; PK(binary_id,address,symbol_type))` — tracks
   AI-applied renames (`:513-521`).
8. **008 chat document metadata** — `ALTER TABLE BNChatMetadata ADD COLUMN
   metadata TEXT` (`:540`).
9. **009 graph node code fields** — `ALTER TABLE graph_nodes ADD COLUMN
   signature/decompiled_code/disassembly` (`:559-561`) plus `node_fts`
   rebuild (`:587`).
10. **010 transcript & approvals** — `BNChatTranscriptEvents` (event_index,
    event_kind, correlation_id, actor_role, artifact_id, source message
    linkage; `:643-662`), `BNChatArtifacts` (artifact_id PK, mime_type,
    **file_path**, preview_text — blobs live on disk; `:665-675`), and
    `BNChatApprovalGrants` (chat_id, tool_name, scope, risk_tier —
    MCP/tool-approval grants; `:678-689`). TranscriptService stores artifact
    files in a `transcript_artifacts/` directory beside the DB
    (`transcript_service.py:30`).

`DatabaseCleanup` (`:699-770`) supplies `cleanup_expired_data`,
`get_database_size_info` and `vacuum_database`, wired from
`analysis_db_service.py:1854` (cleanup_expired_data), `:1901` (vacuum_database), `:1912` (get_database_size_info).

### RLHF data

RLHF feedback also lives in **the same `analysis.db`** (comment: "Use same
database as AnalysisDBService for consistency", `rlhf_service.py:41-48`;
fallback `idassist_rlhf.db` on path failure, `:50-53`), in a `feedback` table:
model_name, prompt, system, response, feedback INTEGER, timestamp, metadata
(`rlhf_service.py:64-74`). This is the persistence end of the
`rlhf_feedback_requested` signals wired in the form (§5).

---

## 8. Settings — `src/services/settings_service.py` (934 LOC; schema + public API read)

**Separate DB confirmed:** `~/.idapro/idassist/settings.db`
(`settings_service.py:53`), distinct from `analysis.db`; same connection
pattern (`check_same_thread=False`, `:65`, guarded by `_db_lock`, `:69`).

Schema (`_create_tables`, `:67-141`):
- `settings` (`:76-83`) — typed key/value store: key PK, value, `type`
  (serialized via `_serialize_value`/`_deserialize_value`, `:832-861`),
  `category`, timestamps; index on category (`:131`).
- `llm_providers` (`:88-110`) — the provider config shape, one row per named
  provider: `name` UNIQUE, `model`, `url`, `max_tokens` (4096), **`api_key`
  stored as plaintext TEXT in the DB** (`:94`), `disable_tls`, `provider_type`
  (default `'openai_platform'`), `reasoning_effort`, `model_family`,
  `is_bedrock`, `litellm_params` (JSON text), `timeout` (90 s),
  `bypass_proxy`, four AWS columns (`aws_region`, `aws_profile`,
  `aws_access_key_id`, `aws_secret_access_key`), `is_active` singleton flag
  with index (`:132`).
- `mcp_providers` (`:115-127`) — MCP servers: name UNIQUE, url, enabled,
  `transport` (default `streamablehttp`, stdio fields below), `command`,
  `args` (JSON), `env` (JSON), `cwd`.

Migrations run at service init (`_run_migrations`, `:143-171`) by calling
nine one-shot scripts from `src/services/migrations/` in fixed order
(`:157-165`); failures are warnings only — "Migration failures shouldn't
prevent plugin loading" (`:166-171`). Each script is standalone (own
`sqlite3.connect`, idempotent `ADD COLUMN` with try/except; several have
`__main__` blocks pointed at `settings.db`, e.g.
`add_litellm_configs.py:74-76`). What each changes:

| Script | Change |
|---|---|
| `add_provider_type.py` | `llm_providers ADD COLUMN provider_type TEXT DEFAULT 'openai_platform'` + backfill UPDATE (`:28-39`) |
| `add_reasoning_effort.py` | `ADD COLUMN reasoning_effort TEXT DEFAULT 'none'` (`:39`) |
| `add_litellm_configs.py` | `ADD COLUMN model_family / is_bedrock / litellm_params` (`:34-50`) |
| `add_provider_timeout.py` | `ADD COLUMN timeout INTEGER DEFAULT 90` (`:27`) |
| `add_bypass_proxy.py` | `ADD COLUMN bypass_proxy BOOLEAN DEFAULT 0` (`:27`) |
| `add_aws_bedrock_config.py` | `ADD COLUMN aws_region/aws_profile/aws_access_key_id/aws_secret_access_key` (`:31-55`) |
| `add_mcp_stdio_fields.py` | `mcp_providers ADD COLUMN command/args/env/cwd` (`:22-25`) |
| `add_oauth_credentials.py` | `CREATE TABLE oauth_credentials` (`:51`) |
| `migrate_provider_type_names.py` | data-only rewrite: `UPDATE llm_providers` to canonical provider-type strings (`:77`) |

Public surface (method map, `:250-928`): generic get/set/delete_setting +
by-category (`:250-328`); LLM provider CRUD (`add_llm_provider` `:361`,
`get_llm_providers` `:396`, `update_llm_provider` `:435`,
`update_llm_provider_api_key_by_name` `:487`, `delete_llm_provider` `:507`)
plus `set_active_llm_provider`/`get_active_llm_provider` (`:524`, `:553`)
with model-family detection (`_detect_model_family` `:330`,
`_is_bedrock_model` `:357`); MCP provider CRUD (`:632-759`); OAuth token
store/get/clear/has (`:761-830`); active system prompt get/save (`:863-897`
— the `SystemPrompts` table is in the *analysis* DB, so this method pair
crosses the two-DB boundary) *(inference from `get_system_prompt` living in
SettingsService while the table is created in `analysis_db_service.py:419`)*;
SymGraph API URL/key/auto-refresh settings (`:899-926`). `close()` at `:928`.

The settings-vs-analysis split: **configuration + credentials** (settings.db)
vs **all learned/derived data** keyed by binary identity (analysis.db); the
split is by file and by key column — nothing joins across the two DBs (SQLite
ATTACH is not used anywhere in the files read *(inference based on the read
scope)*).

---

## 9. IDA-version compatibility evidence — a real discrepancy

- `ida-plugin.json` (plugin store manifest) declares `"idaVersions": ["9.1",
  "9.2", "9.3", "9.4"]` and `version 2.4.0` (`ida-plugin.json:6, 19`).
- `README.md:11` ("runs as a dockable panel inside IDA Pro **9.0+**") and
  `README.md:170` ("**IDA Pro 9.0+** with Python 3 and PySide6") claim 9.0
  support; `README.md:111` even uses `/opt/idapro-9.0` as the example path.
  The manifest omits 9.0 — flag this as a docs/manifest inconsistency
  (9.0 is where IDA switched to PySide6, and `qt_compat.py:4` assumes ≤9.1
  ships PyQt5; if 9.0 actually ships PySide6 the shim's own comment is off).
- **No code branches on an IDA version number.** Grep for
  `idaapi.get_ida_version|ida_version|INF_.*VERSION|9\.2|9\.4` over `src/`
  returns only comments and docstrings (`qt_compat.py:4`,
  `idassist_plugin.py:9` "Target: IDA Pro 9.x"). Version differences are
  instead handled by **feature detection**: the try/except binding order
  Qt5↔Qt6 (`qt_compat.py:25-52`) and `getattr(ida_nalt,
  "retrieve_input_file_sha256", None)` (`ida_compat.py:110-111`).
- Manifest python deps (`ida-plugin.json:22-32`) include `pysqlite3`,
  `mcp==1.23.3`, `whoosh` — notably every module read in this chapter imports
  stdlib `sqlite3`. **Lead-verified 2026-11-02: `pysqlite3` is imported
  nowhere in the tracked code** (`grep -rn 'pysqlite3' --include='*.py' src/
  tests/ idassist_plugin.py` → no hits). Declared-but-unused dependency at
  HEAD; presumably installed so IDA's Python gets a newer FTS5-capable SQLite
  that stdlib `sqlite3` binds against, but no code references it.

---

## Coverage notes (honest gaps)

- `analysis_db_service.py` (1931 LOC) and `settings_service.py` (934 LOC) were
  read as schema/init/API surfaces plus targeted spans; method bodies after
  line ~500 in each (caching policy, upsert flow, cleanup scheduling) were
  not read.
- `_migration_001_initial_schema` (`db_migrations.py:105`) body not read past
  the connect; its description is from its name/registration.
- Result-signal wiring for individual workers (e.g. how
  `ExplainController`'s LLM worker delivers tokens to the view) lives in the
  controllers chapter; only `DaemonWorker` itself and the settings-worker
  subclasses were verified here.
- `oauth_credentials` table columns beyond creation (`add_oauth_credentials.py:51`)
  not enumerated.
- Whether `pysqlite3` is imported anywhere was not exhaustively grepped.

## Sources

All from clone `/tmp/opencode/IDAssist` @ `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302`
(read-only; no IDA module was imported or executed):

- `idassist_plugin.py:11-313` — plugin_t lifecycle, actions, IDB/UI hooks, deferred open.
- `src/ida_compat.py:11-137` — `_IN_IDA`, IDALogger, `execute_sync(MFF_FAST)`, `get_user_data_dir`, `get_binary_hash` (stored-IDB-SHA path; commit `a321ad1` verified via `git show -s`).
- `src/qt_compat.py:4-130` — binding order, 6.8.0 skip, `_binding_exports`, exec/UTC/stop-button shims.
- `tests/test_qt_compat.py:15-45` — export-completeness tests.
- `src/daemon_worker.py:10-117` — daemon-thread worker, interruption, asyncio pump.
- `src/views/idassist_form.py:16-300` — PluginForm docking, tab order, UI hooks, binary-context init.
- `src/services/service_registry.py:17-142` — settings→llm init order, locks, reverse shutdown.
- `src/services/analysis_db_service.py:31-60, 65-71, 204-347, 349-473, 483-489, 1854/1901/1912` — DB path, PRAGMAs, full schema incl. GraphRAG + FTS triggers, migration hookup, cleanup entry points.
- `src/services/db_migrations.py:15-102, 136-167, 209, 282-336, 384-413, 459, 513-521, 540, 559-561, 587, 636-689, 699-770` — versioning + migrations 002-010 + cleanup.
- `src/services/migrations/*.py` — nine settings-DB migration scripts (lines as tabled in §8).
- `src/services/settings_service.py:24-171, 250-928 (def map)` — settings.db schema, provider/MCP/OAuth surface.
- `src/services/rlhf_service.py:20-83` — shared analysis.db, `feedback` table.
- `src/services/transcript_service.py:30` — on-disk artifact directory.
- `ida-plugin.json:6, 19, 22-32` vs `README.md:11, 111, 170` — idaVersions discrepancy.
- `src/services/actions_service.py:7, 189-200`, `src/services/internal_tools.py:7, 361`, `src/controllers/settings_controller.py:153, 268, 357, 429` — `execute_on_main_thread` + `DaemonWorker` usage evidence.

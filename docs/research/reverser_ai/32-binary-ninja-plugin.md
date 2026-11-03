# ReverserAI Binary Ninja plugin layer — commands, settings, HLIL, traversal

> Part of the [ReverserAI overview](README.md). The BN-facing half of the
> project end to end: plugin packaging and import-time registration, the three
> user-facing commands and their exact steps, the settings UI vs the TOML
> config, the HLIL decompiler layer (including the inverted `hlil_if_available`
> guard shipped in v1.1), the bottom-up call-graph traversal, context
> enrichment, renaming semantics, and failure handling. The LLM-facing half is
> in [33 — AI layer and prompts](33-ai-layer-and-prompts.md). All `path:line`
> cites are clone-relative at HEAD `1d572da` (tag v1.2, clone at
> `/tmp/opencode/reverser_ai`) unless a tag/commit is given.

## 1. Packaging: the repo root *is* the BN plugin directory

Binary Ninja discovers plugins by directory: any subdirectory of `plugins/`
containing a `plugin.json` (metadataversion 2) plus a root `__init__.py` is
imported as a Python module when BN starts. ReverserAI is laid out exactly
that way:

- `plugin.json` — `"pluginmetadataversion": 2`, `type: ["helper"]`,
  `api: ["python3"]`, `"version": "1.2"`,
  `"minimumbinaryninjaversion": 2487`; author Tim Blazytko; GPL-2.0 license
  text inlined. The v1.0 `dependencies.pip` block (auto-install of
  `toml`/`huggingface_hub`/`llama-cpp-python`) was **removed in `d7f098a`
  (v1.0.1)**; since then dependencies must be installed manually
  (`pip3 install -r requirements.txt`, README "Installation").
- Root `__init__.py` (123 lines) — the BN entry module: registers all
  `PluginCommand`s and all `Settings` at import time (registration code runs
  during BN startup, not lazily).
- `reverser_ai/` — an importable *library* package (`reverser_ai/__init__.py`
  is blank), not part of BN's plugin discovery. It is made importable because
  the README instructs `pip3 install .` (setup.py), i.e. the root `__init__.py`
  does `from .reverser_ai.binary_ninja import …` (`__init__.py:4-8`), relying
  on the package also being on `sys.path`.

Quirk: there are two `__init__.py` files at the plugin root's top level (root
`__init__.py` and `reverser_ai/__init__.py`); only the root one is BN's entry
point. `reverser_ai/gpt/__init__.py` is empty (0 lines).

## 2. PluginCommand registration — the exact user-facing surface

All three commands are registered in root `__init__.py` at import time. In the
UI they appear under `Plugins → ReverserAI\…` (BN renders the backslash as a
submenu level).

| Cmd | Menu name (exact) | Help text (exact) | Registration | Callback |
|---|---|---|---|---|
| C1 | `ReverserAI\Rename Current Function` | "Renames the selected function with an AI-generated suggestion." | `PluginCommand.register_for_function`, `__init__.py:13-17` | `plugin_wrapper_rename_function_bg` |
| C2 | `ReverserAI\Rename All Functions` | "Renames all functions using AI-generated suggestions." | `PluginCommand.register`, `__init__.py:19-23` | `plugin_wrapper_rename_all_functions_bg` |
| C3 | `ReverserAI\Enhance Function Naming with Context` | "Enhances function names using context-aware AI-generated suggestions for better accuracy and relevance." | `PluginCommand.register`, `__init__.py:26-30` | `plugin_wrapper_context_enriched_function_naming_bg` |

- `register_for_function` (C1) makes it context-sensitive: BN invokes it with
  `(bv, function)` for the function under the cursor / currently selected in
  any view. C2 and C3 take only `(bv)`.
- History: v1.0 registered C2 first, then C1, under the **misspelled** prefix
  `ReverseAI\` (v1.0 `__init__.py:8-18`); `d7f098a` (v1.0.1) renamed the
  prefix to `ReverserAI\` (menu *names are part of the command identifier*, so
  this was an API-name fix, cf. PR #1 "Fix API names in config, documentation
  and screenshots"). C3 was added in `eb940ea` (context-enriched naming,
  v1.1 cycle).
- The three callbacks are imported from `reverser_ai/binary_ninja`
  (`__init__.py:4-8`). Everything below lives in
  `reverser_ai/binary_ninja/__init__.py` (237 lines) unless noted.

## 3. Background-task plumbing

BN refuses to do slow work on the UI thread; the plugin wraps every command in
a `BackgroundTaskThread` subclass:

- `BGTask(BackgroundTaskThread)` — `binary_ninja/__init__.py:12-34`.
  `__init__(bv, msg, f)` calls `super().__init__(msg, True)` (line 26 — second
  arg is BN's `progression=True`, an indeterminate progress bar in the task
  bar); `run()` just executes `self.f(self.bv)` (line 34).
- `BGTaskFunction(BackgroundTaskThread)` — lines 37-61, same but `run()` calls
  `self.f(self.bv, self.arg)` (line 61); used only by C1 to carry the selected
  `Function` object.
- The three `*_bg` wrappers only construct and start these threads:
  `plugin_wrapper_rename_function_bg` (184-201, message "Querying GPT for a
  function name suggestion and applying it to the selected function." line
  197), `plugin_wrapper_rename_all_functions_bg` (204-219, msg "Renaming all
  functions in the binary based on GPT suggestions." line 216),
  `plugin_wrapper_context_enriched_function_naming_bg` (222-237, msg
  "Enhancing function names in the binary with context-aware AI suggestions."
  line 234).

## 4. Model singleton — one LLM process-wide

`BinjaFunctionNameGPTManager` (64-94) is a hand-rolled singleton holding one
`FunctionNameGPTWrapper`; `get_instance()` constructs it lazily on first call
(92-94) and the manager itself is module-global (line 98,
`manager_function_name_gpt`; renamed from `manager` in `16bde89`). Consequence:
the **first** invocation of any command blocks in the background thread while
`hf_hub_download` fetches the ~5 GB GGUF (if not cached) and `Llama(...)`
loads it; subsequent commands reuse the loaded model. There is no unload, no
reconfigure, and no sharing across BN instances.

## 5. The three commands, step by step

### C1 — Rename Current Function (`plugin_wrapper_rename_function`, 101-116)

1. Get the singleton wrapper (line 113). The `bv` argument is discarded (`_`
   parameter, line 101).
2. `gpt.apply_suggestion(f)` (line 116) — one query, unconditional: **no
   `hlil_if_available` check and no `is_derived_func_name` check** on this
   path. A named/derived function selected by the user still gets a query and
   gets renamed if the model answers. If HLIL cannot be produced, the
   `AttributeError`/decompiler failure escapes `apply_suggestion`'s
   `except ValueError` (`function_name_gpt_wrapper.py:96`) and dies in the
   background thread.

### C2 — Rename All Functions (`plugin_wrapper_rename_all_functions`, 119-146)

1. Singleton (line 136).
2. Iterate `traverse_functions_bottom_up(bv)` (line 139) — call-graph
   post-order, callees before callers (§8).
3. Skip functions without HLIL: `if f.hlil_if_available is None: continue`
   (lines 141-142; the v1.1-era version of this guard was inverted — §7).
4. Skip non-anonymous functions: `if not is_derived_func_name(f.name):
   gpt.apply_suggestion(f)` (145-146) — i.e. rename **only** BN-anonymous
   `sub_<hex>` functions (§9).

Docstring (124-127) states the intent: rename "leaf" functions first so their
new names propagate as context into the prompts of their callers.

### C3 — Enhance Function Naming with Context (`plugin_wrapper_context_enriched_function_naming`, 149-181)

1. Singleton (line 166).
2. Build a *preselection set*:
   `collect_symbol_related_functions(bv).union(collect_string_related_functions(bv))`
   (169-171) — functions that reference imported/library/external symbols or
   strings (`binary_ninja/utils.py:61-102, 105-135`, §9).
3. Iterate **`bv.functions`** (line 174) — BinaryView address order, *not*
   bottom-up, despite the loop comment on line 173 claiming "in a bottom-up
   order"; the docstring (155-160) also promises bottom-up propagation. The
   bottom-up call was removed when `4d94939` deleted the "TODO: buttom-up
   traversal currently disabled due to a bug" comment: the line had been
   broken as `bv.functions(bv)` and was replaced by plain `bv.functions`,
   and C3 still iterates `bv.functions` at HEAD. Only C2 uses the traversal.
4. Same HLIL guard (176-177) and preselection + anonymity filter:
   `if f in preselected_functions and not is_derived_func_name(f.name):
   gpt.apply_suggestion(f)` (180-181).

So "context-enriched" does **not** change the prompt. It (a) narrows *which*
functions get queried to those touching strings/imports (functions where the
HLIL text itself will visibly contain import/library call names and string
data), and (b) relies on renamed callee names appearing inside the parent's
HLIL dump. No callee list, string list, or symbol list is ever appended to
the prompt — grep for `callee` in the wrapper/gpt layer finds only graph
construction in `binary_ninja/utils.py:52`.

## 6. Interactions: there are none

Zero uses of `InteractionHandler`, `TextDialog`, or any confirmation UI in the
whole repo (verified by grep). Every accepted suggestion is applied silently
and reported only via the BN Log window under logger `ReverserAI`
(`function_name_gpt_wrapper.py:92`). The README ("this may take a while…
appear in the Log window", `imgs/plugin_results.png`) matches this. There is
no progress feedback per function beyond the one indeterminate BGTask bar, no
cancel handling (the task never checks `is_cancelled`), and no settings dialog
of its own — configuration goes through BN's global Settings UI (§7).

## 7. Settings: BN Settings API registration (the screenshot surface)

Root `__init__.py:36` registers group `("reverser_ai", "ReverserAI")`; six
settings follow (the README's `imgs/plugin_settings.png` is exactly this
screen; replaced by `c6b1fd4`). Every setting has `"requiresRestart": true`
because the singleton `Llama` is built once at first command.

| Key | Type | Default | Registered | Consumed at |
|---|---|---|---|---|
| `reverser_ai.use_mmap` | boolean | `true` | `__init__.py:39-50` | wrapper `read_config` → `Llama(use_mmap=…)` |
| `reverser_ai.n_threads` | number | `0` | `__init__.py:52-63` | → `Llama(n_threads=…)` |
| `reverser_ai.n_gpu_layers` | number | `99` | `__init__.py:65-76` | → `Llama(n_gpu_layers=…)` |
| `reverser_ai.seed` | number | `0` | `__init__.py:78-89` | → `Llama(seed=…)` |
| `reverser_ai.verbose` | boolean | `false` | `__init__.py:91-102` | → `Llama(verbose=…)` |
| `reverser_ai.model_identifier` | string enum `["mistral-7b-instruct", "mixtral-8x7b-instruct"]` | `"mistral-7b-instruct"` | `__init__.py:104-123` | → `MODEL_IDENTIFIERS[key]` |

- The enum descriptions carry the RAM numbers: "~5GB RAM" (line 116) and
  "~25GB RAM" (line 117) — the 25 figure was corrected from 45 in `456bc1e`
  (README, this file, `example_config.toml`, `gpt/models.py` comment).
- The `use_mmap` description ("loads parts of the model on-demand instead of
  the entire model") was fixed from the wrong v1.0 wording ("loading the
  entire model into memory") in `09d4e00`.
- `model_identifier` did not exist until `5597fb7` — before that the model
  was hardcoded (`v1.0:gpt/function_name_gpt.py:28`:
  `config['model_identifier'] = MODEL_IDENTIFIERS["mistral-7b-instruct"]`).
- v1.0 used the prefix `reverse_ai.` (group "ReverseAI"); renamed to
  `reverser_ai.` in `d7f098a` (v1.0.1).
- No validation beyond the enum: `n_threads`, `n_gpu_layers`, `seed` are free
  numbers; a BN quirk is that `Settings().get_integer` returns the registered
  default only after registration, which import-time guarantees.
- Quirk (llama-cpp side): the BN description says of `n_threads` "set to 0 to
  disable CPU" (`__init__.py:56`) and `example_config.toml:14` says "set to 0
  to prioritize GPU usage over CPU". llama-cpp-python 0.2.56 actually maps
  `n_threads=0` via `n_threads or max(cpu_count()//2, 1)` to *half the CPU
  cores*, not "CPU disabled". The default config (0 threads, 99 GPU layers)
  therefore still runs CPU inference for prompt eval of non-offloaded layers.

There is **no** `SettingsRepository`-style abstraction: consumption is one
static method, `FunctionNameGPTWrapper.read_config`
(`function_name_gpt_wrapper.py:27-49`), which reads the six keys with
`Settings().get_string/get_bool/get_integer` (lines 40-47) into a plain dict.

### TOML config (scripts only)

`reverser_ai/config.py` (22 lines) is a 10-line `toml.load` wrapper
(`load_user_config`, lines 4-22, no schema validation at all). It is used
**only** by `scripts/gpt_function_namer.py:46`. `example_config.toml` mirrors
the six BN settings (`model_identifier = "mistral-7b-instruct"` line 9,
`use_mmap = true` 12, `n_threads = 0` 15, `n_gpu_layers = 99` 18, `seed = 0`
21, `verbose = false` 24). The plugin *never* reads any TOML file; the
existence of two parallel config systems is a v1.0 CLI-era leftover.
`reverser_ai/utils.py:4-19` `get_plugin_directory()` — resolves the plugin
dir from `__file__` — was evidently meant to locate a bundled config file but
has **zero callers** in the repo (dead code).

## 8. Decompiler layer: HLIL only

- Extraction: `FunctionNameGPTWrapper.get_hlil_output`
  (`function_name_gpt_wrapper.py:51-66`) returns
  `f"{str(f)}\n"` (BN's `Function.__str__`, i.e. the function header with its
  current name) concatenated with every HLIL line stringified and tab-prefixed
  from `f.hlil.root.lines` (line 65). So the prompt body = function header +
  full HLIL listing. Other ILs (MLIL/LLIL/disasm) are never used anywhere.
- The guard and the extraction are *different APIs*: the bulk commands check
  `f.hlil_if_available` (BN: "HLIL exists without forcing decompilation") at
  `binary_ninja/__init__.py:141,176`, while the wrapper then reads the forcing
  property `f.hlil` at wrapper:65. If `hlil_if_available` is non-None it is
  already decompiled, so in practice the read is cheap; the single-function
  command has no guard at all and forces decompilation in the background
  thread.

### The inverted-guard bug (v1.1 → fixed only in v1.2)

At HEAD the guard is correct:

```python
if f.hlil_if_available is None:   # binary_ninja/__init__.py:141 (C2), :176 (C3)
    continue
```

At tag **v1.1** it was inverted (`v1.1:binary_ninja/__init__.py:138,172`):

```python
if f.hlil_if_available != None:
    continue
```

Timeline (verified with `git log -S` and `git merge-base --is-ancestor`):

| State | Where |
|---|---|
| v1.0, v1.0.1 | no guard at all — every function queried |
| `cf8e449` (2024-06-20, "fix: gpt is only queried if HLIL output exists") | guard *introduced*, but inverted (`!= None: continue`) — the fix itself was the bug |
| v1.1 (`d7b6700`, contains `cf8e449`) | ships inverted |
| `b4b4cc2` (CI/ruff format pass) | ruff rewrote `!= None` → `is not None` — *still inverted*, and now reads canonically correct |
| `1d572da` (v1.2) | flipped to `is None` — the semantic fix landed in the release commit itself |

Practical effect at v1.1: C2/C3 skipped **every function that had HLIL** and
queried only those lacking it — i.e. bulk renaming silently did nothing for
the normal case, and for the rare no-HLIL functions the model query would
fail in `get_hlil_output` (AttributeError on missing `hlil.root`, not caught
by the `except ValueError` at wrapper:96). Both bulk commands were effectively
broken across the whole v1.0.1+guard→v1.2 window for the intended path
(v1.0/v1.0.1 had no guard but did query everything; the inversion then
swallowed nearly all queries).

## 9. `binary_ninja/utils.py` (135 lines) — filters and graph

- **`is_derived_func_name(function_name)`** (7-26): the *only* name filter.
  Rule: `re.fullmatch(r"^sub_[0-9a-f]+$", name)` → returns **False**
  (line 24; "not derived", i.e. BN-anonymous → *renameable*); any other name
  → **True** ("derived", i.e. from symbols/APIs/user → skip). Callers use it
  as `if not is_derived_func_name(f.name): apply` (145, 180), so **only
  lowercase-hex `sub_XXXXXXXX` functions are ever renamed**. Quirks: the
  boolean reads backwards from its name (docstring 8-17 compounds the
  confusion); uppercase-hex `sub_…` forms and BN's `function_…` internal
  names are treated as "derived" and skipped; a user-renamed function can
  never be re-renamed by C2/C3 (arguably a feature); nothing ever strips
  `sub_` from a model suggestion. There is no comment filter and no
  min-length rule anywhere (the task-adjacent assumption of such rules is
  absent — the only output normalization is `filter_output` in the GPT layer,
  see file 33).
- **`traverse_functions_bottom_up(bv)`** (29-58): builds a
  `networkx.DiGraph` (line 44), adds every `bv.functions` entry as a node
  (line 47), adds edge **`call_graph.add_edge(f, callee)`** per call (line
  55) — direction caller→callee, i.e. edges point *toward* leaves — then
  returns `nx.dfs_postorder_nodes(call_graph)` (line 58) with default root
  (iterates from graph insertion order). Post-order on a caller→callee
  forest yields callees before callers ⇒ leaves-first, bottom-up: exactly the
  order needed so callee renames land in the database *before* a parent's
  HLIL is rendered for its own prompt. `networkx>=3.2.1` was added as a
  dependency by `4d94939`.
- **`collect_symbol_related_functions(bv)`** (61-102): target symbol types =
  `{ImportAddressSymbol, LibraryFunctionSymbol, ExternalSymbol,
  ImportedDataSymbol, ImportedFunctionSymbol}` (77-83). Iterates
  `bv.data_vars` addresses (89), `get_data_var_at` (91), skips vars with no
  symbol or non-target symbol type (94-95), and pulls `code_ref.function`
  from each data var's `code_refs` (98-100).
- **`collect_string_related_functions(bv)`** (105-135): for every
  `bv.strings` entry (123), `get_data_var_at(s.start)` (125), skip if no data
  var (128-129), else add each `code_ref.function` (132-133).
  Quirks: string addresses with no defined data var are dropped (BN defines
  most strings as data vars, but not all — e.g. strings referenced only via
  IL immediates may lack one); the sets are computed **once** at command
  start, so renames made during the run don't re-preselect anything.

### Traversal archaeology

| Version | Implementation |
|---|---|
| v1.0 (`cfa9908`) | `for f in sorted(bv.functions, key=lambda f: len(f.callees))` (v1.0:binary_ninja/`__init__.py:78`) — "fewest callees first" heuristic; not a real dependency order (a 1-callee root can precede its leaf). |
| `d488e82` ("fix algorithm to propagate information from leaves to roots") | hand-rolled worklist inline in the command: pop last, process only `if all(callee in done …)`, re-push current and unprocessed callees. |
| `16bde89` ("refactored bottom-up traversal") | worklist moved into `binary_ninja/utils.py:traverse_functions_bottom_up` (now a generator). |
| the hand-rolled generator | self-documented endless-loop bug — TODO comment: *"Current implementation triggers an endless loop because of inproper handling of re-adding function callers again. Must be refactored into a clean version of iterative post-order traversal."* (removed in `4d94939`'s diff). C2 was meanwhile running over plain `bv.functions` with a "TODO: buttom-up traversal currently disabled due to a bug" note, and that intermediate line even read `for f in bv.functions(bv):` — a call on a non-callable — i.e. C2 was crashing/unused. |
| `4d94939` ("fix traverse_functions_bottom_up") | replaced the worklist with the networkx DiGraph + `dfs_postorder_nodes` version shipped today; re-enabled it in C2 (line 139); added the networkx requirement. |

Residual quirks of the shipped traversal: `nx.dfs_postorder_nodes(call_graph)`
has no root and no cycle handling guarantee beyond networkx's own (networkx
post-order on cyclic DFS treats back-edges as already visited, so
strongly-connected call cycles are *some* order, not a fixpoint — a parent in
a cycle may be queried before its cycle-mate is renamed); BN `Function`
objects are hashable graph nodes but equality is per-view, fine here.

## 10. Applying the rename

`FunctionNameGPTWrapper.apply_suggestion`
(`function_name_gpt_wrapper.py:81-97`):

```python
try:
    suggested_name = self.get_function_name_suggestion(f)
    log_info(f"Renaming {f.name} to {suggested_name}", logger="ReverserAI")
    f.name = suggested_name
except ValueError as err:
    log_warn(f"Function {f.name}: {err}", logger="ReverserAI")
```

- **Acceptance condition** = "the function's current name matched
  `^sub_[0-9a-f]+$`" (enforced by callers at 145/180; *not* enforced for C1)
  plus "the model returned without raising" — the returned string itself is
  never validated: an empty first line (`""`), a sentence, or arbitrary
  Unicode can be set as the BN function name. There is no
  identifier-charset/length check, no `sub_`-prefix rejection on the output,
  and no user confirmation.
- BN API used: the `Function.name` **property setter** (line 94), not
  `set_user_name()` called directly — BN's setter performs the equivalent
  user-rename. Undo semantics are BN's own: the rename enters BN's undo
  history as a user action undoable in the BN UI (Ctrl+Z) — but the rename
  is *issued from a background thread*; the repo contains no explicit undo,
  transaction, or save handling (BN autosave of the bndb applies).
- `log_info`/`log_warn` come from the BN API
  (`function_name_gpt_wrapper.py:1`), routed to a custom logger named
  `ReverserAI` in BN's Log window. The logger string was misspelled
  `ReverseAI` until `c7c681a` ("fixed typo in logger", v1.1 era); before
  `aeb265c` the "log" was a bare `print()` to stdout
  (v1.0:binary_ninja/`function_name_gpt_wrapper.py:85`).

## 11. `function_name_gpt_wrapper.py` (97 lines) — role

Not dead: it is the *only* bridge BN→LLM, instantiated by the singleton
(§4) and used by all three commands. Its content is three things: (a) read
BN Settings → config dict (`read_config`, 27-49; `model_identifier` line only
added in `5597fb7`), (b) HLIL extraction (51-66, §8), (c) query + apply + log
(68-97, §10). It wraps `FunctionNameGPT` (imported line 4; constructed line
25). Before `aeb265c` it also passed the original name into
`get_function_name_suggestion(f.name, hlil)` as a silent fallback — v1.0's
error path returned the original name and renamed nothing silently; see file
33 §5 for the current failure path.

## 12. Failure handling and logging

- Bulk commands: only `ValueError` from the GPT layer is caught (§10); BN-side
  errors (forced-decompile failures on C1, attribute errors) are uncaught and
  terminate the background task with BN's generic thread-failure log.
- Progress/telemetry: nothing per-function except the log line on success;
  no counters, no summary, no way to see which functions failed without
  scrolling the Log window.
- The repo's own `reverser_ai/utils.py` is **not** a logging setup — it is
  dead code (§7). Logging exists only via BN's `log_info`/`log_warn`.
- No global try/except around bulk loops: one uncaught error kills the whole
  run mid-way (renames already applied stay applied).

## Sources

- Clone `/tmp/opencode/reverser_ai`, HEAD `1d572da` (v1.2):
  `__init__.py`, `plugin.json`, `reverser_ai/binary_ninja/__init__.py`,
  `reverser_ai/binary_ninja/utils.py`,
  `reverser_ai/binary_ninja/function_name_gpt_wrapper.py`,
  `reverser_ai/config.py`, `reverser_ai/utils.py`, `example_config.toml`,
  `requirements.txt`, `setup.py`, `README.md`, `examples/README.md` —
  every file read in full.
- Historical states: `git show v1.0|v1.1:<path>` for the guard/menu/config
  line numbers cited as `v1.x:…`; commits `cfa9908` (v1.0), `d7f098a`
  (v1.0.1), `d488e82`, `aeb265c`, `c318f28`, `eb940ea`, `16bde89`, `4d94939`,
  `5597fb7`, `cf8e449`, `c7c681a`, `7b3ecd8` (v1.1 string), `456bc1e`,
  `09d4e00`, `b4b4cc2`, `1d572da` (v1.2) via `git show` / `git log -S` /
  `git merge-base --is-ancestor`.
- llama-cpp-python v0.2.56 `Llama.__init__` (`n_threads or
  max(cpu_count()//2, 1)`) from the pinned upstream source, for the
  `n_threads=0` quirk note.
- Related dossiers: [20 — inventory](20-reverser-ai-inventory.md),
  [21 — history](21-history-and-releases.md),
  [33 — AI layer and prompts](33-ai-layer-and-prompts.md).

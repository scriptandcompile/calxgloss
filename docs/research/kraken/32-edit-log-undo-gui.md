# KRAKEN's workbench data model — the edit log, undo and attribution, the viewmodel, and the GUI

> Part of the [KRAKEN overview](README.md). The persistence-and-intent layer end
> to end: the SQLite edit log as source of truth, the op vocabulary and entity
> keys, snapshots and the materialising fold, attribution and runs, undo and
> concurrency, the additive-only agent policy and proposals, the untrusted-data
> rules, the headless viewmodel, and the egui GUI — then the direct comparison
> against calxgloss's `re/` record tree, overlay files, and git attempt
> branches. Engine-side write-back, the `Mutator` facet, checkpoints/watermarks
> and `rebuild` were covered in [ch. 31](31-analysis-engines.md); this chapter
> builds on them and does not repeat them. KRAKEN claims cite the clone at
> `68718c6`, paths relative to the clone root.
>
> One honesty note before any "decision NN" is quoted below: code comments cite
> numbered decisions (27–29, 34, 38, 57–58, 61, 70, 74…) that are **not** the
> 14 published `docs/design/` ADRs — they point to the gitignored local working
> plans (`CLAUDE.md:61`: "Local working plans: `plans/` (gitignored; not part of
> the repo)"). Where a design doc says the same thing, it is cited instead.

## What KRAKEN does

### 1. The edit log: an append-only SQLite source of truth

Every project directory holds `project.kraken.sqlite` (ch. 31 §8). Design 0002
sets the rule: the log "is append-only and is the only truth," each entry
carries "an operation, an anchor, the old and new value, the author, the run
id, provenance, a read-set, and a status," and the engine project is Layer 2 —
"it can be dropped at any time" (`docs/design/0002-edit-log-is-source-of-truth.md:14-18`). The design doc is the Ghidra-era short version; the
machinery itself is `kraken-model`'s `store.rs`. The `MIGRATIONS` const
(`crates/kraken-model/src/store.rs:20-65`) creates, in migration 1:

- `entries` (`crates/kraken-model/src/store.rs:21-36`) — the log itself: `op`
  (versioned JSON), `keys`, `author_kind`/`author_id`, `run_id`, `provenance`,
  `read_set`, `status` with a CHECK of `applied|rejected|orphaned` (:30),
  `reason`, `sync` with a CHECK of `pending|pushed|engine_rejected` (:32),
  `undoes_entry_id` — the link a compensating entry writes (:34) — and `ts`,
  plus indexes on run, undo-link and sync (:37-39);
- `runs` (:40-44) — run id → author → start time, inserted lazily on first
  write of a run (`ensure_run`, :229-238);
- `entity_versions` (:45-49) — one row per entity key: an integer `version`
  and `last_author_kind` (`user|agent`), bumped on every applied write
  (`bump_version`, :218-227);
- `push_watermark` (:50-54) — the single-row record of the last pushed entry
  plus the engine checkpoint saved with it (`watermark`/`set_watermark`,
  :591-619; consumed by the resync path ch. 31 §8, `current_checkpoint` probe
  at `crates/kraken-registry/src/session.rs:680`);
- `snapshots` (:55-59) — materialised annotation state stashed at an entry id;
  and migrations 2–6 add `proposals`, `tainted`, `bookmarks`, AI-usage and
  patch tables (:60-64), so bookmarks and byte-patch records live in the same
  database as the log.

**Op vocabulary.** The logged operation is a tagged, versioned enum,
`VersionedLogOp { schema_version, op }` with `LOG_SCHEMA_VERSION = 1`
(`crates/kraken-proto/src/logop.rs:15-16, 178-183`); new ops are added as new
variants **without** a migration, and changing an existing op's meaning bumps
the version (`logop.rs:3-5`). `enum LogOp` itself
(`crates/kraken-proto/src/logop.rs:55`) has nine variants — `Rename` (:57),
`SetType` (:67), `SetComment` with five Ghidra comment slots `plate|pre|eol|post|repeatable`
(:21-32, :77), `CreateFunction` (:90), `DeleteFunction` (:101),
`SetFunctionBounds` (:109), `SetCodeData` (`code|data|undefined`, :39-50, :119),
`SetCallingConvention` (:132), and `SetPatch` (:144). Every op carries **the
old value** (`old_name`, `old`, `old_body`, `original` bytes) precisely so undo
is a pure inversion (:52-53 doc). `SetPatch` is the one op that never reaches
the engine — byte patches are a project-local overlay, "logged and undone like
any edit but never applied to the engine" (`is_engine_op`, :168-173).

**Entity keys and address resilience.** The key an entry locks is built from
the op alone: `anchor_key` renders the anchor as `native:ram:0x401000` (or
`managed:<mvid>:0x…` for .NET) and — deliberately — "only the address (or
module and token) identifies the entity; the function hash is not part of the
key" (`crates/kraken-model/src/keys.rs:15-25`). The aspect suffix comes from
the op: `name`, `type`, `comment:<kind>`, `function`, `bounds`, `codedata`,
`cc`, `patch` (`op_aspect`, :34-47), giving keys like
`native:ram:0x401000:name` (`entity_key`, :27-30). The *anchor* stored inside
the op is richer: `Anchor::Native` is space + offset + the containing
function's entry + a hash of its **original bytes**
(`crates/kraken-proto/src/locator.rs:60-93`); byte patches never disturb those
hashes (`docs/design/0002-edit-log-is-source-of-truth.md:30`). Resilience is a
two-layer bargain: keys are plain addresses, so a rename or re-analysis cannot
orphan an annotation key; the fn_entry/fn_hash pair is instead enforced at
**push** time by the engine — "an anchor whose function hash is neither the
current body's, the found body's … nor the one a `create_function` carried" is
`conflict_stale_read`, as is a rename whose `old_name` is stale
(`docs/design/0014-native-engine.md:82`; the anchor is built live from the
engine's answer in `crates/kraken-registry/src/mutate.rs:38-80`). Design 0002
planned a further mechanism: an edit whose entry and hash no longer match is
"marked orphaned and goes to a review queue," with a fallback ladder deferred
behind a measured precision test
(`docs/design/0002-edit-log-is-source-of-truth.md:20`). In this revision
`orphaned` is **reserved vocabulary without a producer**: it exists in the
CHECK (:30), in `LogStatus::Orphaned` (`crates/kraken-proto/src/meta.rs:25-35`)
and in sample metadata (`xtask/src/samples.rs:352`), but no write path sets it —
engine refusals ride the separate `sync='engine_rejected'` channel
(`mark_engine_rejected`, `crates/kraken-model/src/store.rs:569-571`) and report
in `project_info`, not as a log status.

**Snapshots and the fold.** Ops are absolute — "they set the new value, never
a delta, so a fold over applied entries is order-correct without consulting
`old` values" (`crates/kraken-model/src/state.rs:74-79`). `apply_op` maps one
op onto an entity-key → `StateValue` map, with clearing sentinels (empty name,
`undefined` type, empty range) removing the key so undo of a from-nothing edit
inverts cleanly (:80-120). The store then keeps current state cheap:
`current_state()` = the newest snapshot plus `fold_applied` over the entries
after it (`crates/kraken-model/src/store.rs:696-701`, fold :312-327, snapshot
read :329-342); `replay_full()` re-folds from empty, ignoring snapshots, as the
correctness check (:703-708); `create_snapshot()` stashes the fold result at
the newest entry id (:710-726). This is the code half of design 0002's "periodic
snapshots of the annotation state speed up loading" (:26) — the drift-report
`rebuild` that proves the whole cache is disposable is ch. 31's territory
(ch. 31 §8; the richer rebuild machinery is code, not design 0002).

**Statuses.** `Store::append`
(`crates/kraken-model/src/store.rs:430-463`) decides status in one transaction:
validate first (next section); a refused attempt is stored **as `rejected` with
the reason inline**, kept "for audit," and the error carries
`rejected_entry_id` (:434-448); a passing entry is `applied` with `sync`
starting `pending`, and the written key's version is bumped (:450-461). So the
log never deletes: refused attempts and undo entries are ordinary rows.
`applied | rejected | orphaned` is the *acceptance* axis
(`LogStatus`, `crates/kraken-proto/src/meta.rs:20-35`); engine delivery is the
orthogonal `pending | pushed | engine_rejected` `SyncState` axis (:37-52),
settled by `mark_pushed`/`mark_engine_rejected` (`store.rs:563-588`).

### 2. Attribution and runs: how the log answers who / when / why

An entry's author is `Author { kind: User|Agent, id }`
(`crates/kraken-model/src/lib.rs:41-75`), its provenance is one of `User |
Agent | AgentFromBinaryText` — the last "always treated as untrusted" (§4) —
(`crates/kraken-proto/src/meta.rs:8-18`, decision 61), and its run is a free
`RunId(String)` that the store auto-registers in `runs`
(`store.rs:229-238`). The `Surface` a call arrives on (`Cli | Mcp | Gui |
Test`) is carried in `CallContext` alongside author, run id and quota key
(`crates/kraken-registry/src/context.rs:12-24, 95-115`); the GUI logs under
the literal name `gui-user` (`crates/kraken-viewmodel/src/inprocess.rs:23`).
An agent that gives no run id gets a synthetic per-agent one, `adhoc-<id>`, so
even one-off agent edits are undoable as a batch
(`effective_run`, `crates/kraken-registry/src/mutate.rs:23-30`).

The *why* is layered. The op itself says what changed (old → new);
`read_set` records "the versions of what it was based on: its target, the
types it used, the callees it saw" (`docs/design/0006-undo-and-concurrency.md:14`)
— an explicit dependency statement per edit; `reason` explains a refusal
inline; rejected attempts and compensating entries stay in the log, giving the
"full audit trail, including undone work" design 0006 promises (:31). The
`entity_versions` table adds a per-key monotonic version and
`last_author_kind` (`store.rs:45-49`), which is what both the compare-and-set
and the dependency machinery below run on. `HistoryEntryView`
(`crates/kraken-model/src/lib.rs:93-117`) exposes all of it — author, run,
provenance, read-set, status, sync, `undoes_entry_id`, `undone_by`, `ts_ms`.

### 3. Undo and concurrency

Design 0006 (`docs/design/0006-undo-and-concurrency.md`, read fully) is the
charter: **"Undo is a new log entry"** — a compensating entry, history never
rewritten, derived data "marked stale, not reversed" (:12); read-sets from 0.1
(:14); compare-and-set over the **whole read-set**, stale writes failing with a
structured error so the agent re-reads (:16); **human priority** — on a
collision "the human edit wins. The agent attempt is logged as rejected" (:18);
one write queue in the daemon ordering all writes, plus a cursor-based event
stream for clients (:20); and a staged undo plan — 0.1 per-change and per-run,
0.2 dependency-listing UI "possible without a migration" because read-sets
already carry the data (:22-25). Rejected alternatives are recorded: delete-on-undo
loses audit; last-writer-wins loses human edits; target-only checks miss
neighbour dependence; locking "blocks interactive work behind long agent runs"
(:36-41).

The code implements all of it, and the 0.2 part is already there:

- **Inverse values, not recipes.** `invert_op` swaps `old`/`new` and exchanges
  `CreateFunction`↔`DeleteFunction`; undoing a delete recreates the function
  unnamed, because the delete didn't record a name — a documented, honest gap
  (`crates/kraken-model/src/state.rs:123-163`). A compensating entry stores
  `undoes_entry_id` (`store.rs:34`) and is authored by the *undoer*.
- **Granularity is per-change, per-author, and per-run — never a global
  stack.** `undo_last` reverses *the calling author's* most recent applied,
  not-yet-undone, non-compensating entry (`store.rs:621-642`); `undo_entry`
  reverses one named entry (:646-650); `undo_run` reverses every live entry
  of one run, newest first, in a single transaction, and an unknown run is an
  error (:652-687). Each goes through `undo_ids` →
  `lineage::compensate` (:689-694). The registry exposes exactly these three —
  `undo` ("Reverses your own latest edit… You cannot undo someone else's edit
  this way"), `undo_run` ("find the `run_id` in `history`… Open proposals of
  the run are left alone"), and `undo_entry` with `cascade`
  (`crates/kraken-registry/src/commands/edit.rs:670-758`; doc strings
  :686-688, :736-738; `undo_entry.rs:1-2`). So there is **no
  machine-global undo stack**: Ctrl+Z-like stepping is scoped to the author
  identity of the surface.
- **Dependency-aware undo is shipped, not planned.** `lineage.rs` states the
  rule: "A later applied edit *depends on* an earlier one when its read-set
  names a key the earlier one wrote; dependence is transitive," and undo
  either refuses (listing dependents) or cascades, dependents newest first
  (`crates/kraken-model/src/lineage.rs:1-9`; `UndoPolicy::Cascade|Refuse`
  :38-43; `dependents_of` scans entries in id order :102-114). Undoing a
  **type or calling-convention** edit marks the written keys *tainted* —
  "decompiler output, explanations… is stale, not reversed, until a caller
  clears the marker" (:1-9; `TaintedKey` :67-78; the `tainted` table :28-33).
  The registry wraps that as `undo_preview` / `undo_entry` / `tainted_list` /
  `tainted_clear` (`crates/kraken-registry/src/commands/undo_entry.rs:1-2`),
  and after any settled undo `finish_undo` pushes the compensating entries to
  the engine and `refresh_after_undo` re-reads the tainted functions (capped
  at 64, :22) and diffs them against the log, returning `tainted` + `drift`
  lists (`edit.rs:623-646`, `undo_entry.rs:152-178`) — undo ends with a
  mini-drift-report, the same honesty channel as `rebuild`.
- **Serialization.** One per-project async write mutex in the session guards
  every mutation path (`write_lock`, `crates/kraken-registry/src/session.rs:381`,
  taken at :576, :625 and by each undo command, e.g. `edit.rs:705`); the
  daemon hosts one session per project, so CLI/GUI/MCP/agent writers all
  funnel through it, and design 0002 adds the cross-process rule: a project
  is held by one process at a time via an advisory `kraken.lock`, "a second
  process gets an error naming the holder's pid and pointing at the daemon"
  (`docs/design/0002-edit-log-is-source-of-truth.md:24`). Edits made while
  analysis runs are appended (logged!) but held: `settle` returns
  `queued` and flushes them when the job finishes, reporting
  `flushed_entries`/`rejected_entries` (`crates/kraken-registry/src/mutate.rs:144-176`;
  `crates/kraken-registry/src/commands/jobs.rs:112-117`; ch. 31 §7).
  Cross-client visibility is the event half of design 0006:20: after a
  mutation the daemon broadcasts `entry_applied` / `proposal_created` to every
  connected client (`crates/krakend/src/handler.rs:304-306`;
  `crates/kraken-host/src/daemon.rs:132, 134`), which the GUI backend turns
  into live refreshes (§5).

### 4. Proposals, the additive-only agent policy, and untrusted data

**Additive-only (decision 29; matches `docs/design/0005-agent-safety.md:12`).**
`kraken-model::policy` classifies every op against the *current log state*:
`Additive` = naming an unnamed or default-named symbol (`FUN_`, `DAT_`,
`LAB_`, … `DEFAULT_PREFIXES`, `crates/kraken-model/src/policy.rs:17-28`), a new
comment, a type on an undefined item, a first patch; `Overwrite` = everything
else, "including all structural ops and clearing a value" (:10-15, :32-66).
The op's own `old` field is trusted only when the log holds nothing — "since
the engine may have named or typed the item before any log entry" (:30-31).
`entity_versions.last_author_kind` (§2) is what makes the human-priority rule
mechanical: `validate` refuses an agent write to a key whose last writer was a
user at a version above what the agent read, with error
`rejected_human_priority` and details naming key/read/current version
(`crates/kraken-model/src/store.rs:280-292`), and separately compare-and-sets
the **entire read-set**, failing with `conflict_stale_read` and a
`stale_keys` list (:293-309) — both designed for agents to re-read and retry
(design 0006:16).

**The proposal gate.** `submit` (`crates/kraken-registry/src/mutate.rs:186-295`)
is the single mutation pipeline: read-set built (absent `expect_versions`
means "current version"), `validate_draft` first — a failing agent attempt is
*appended as rejected* for audit (:237-241) — then for agents: if
`classify` says Overwrite, or the run is at the `per_run_cap` (default 200,
`crates/kraken-registry/src/session.rs:178, 196`), counted both per-run
(`count_applied_agent_entries`, `crates/kraken-model/src/store.rs:503-514`)
and per-agent-credential via `quota_key`, "stable across reconnects, unlike
the ephemeral run id" (`mutate.rs:213-217`, `context.rs:106-109`), the edit
becomes a **proposal** instead of an entry: stored in the `proposals` table
(`crates/kraken-model/src/proposals.rs:14-24`) with the *reason it was held*
(:66-94), status `open|accepted|rejected`. The store "only tracks the
proposal; applying an accepted proposal is the caller's job (the registry
appends the op as the accepting user)" (:1-5) — so an accepted agent edit is
re-run through the *full* pipeline as the human's own entry (with the
proposal's run kept, `submit_as`, `mutate.rs:197-204`), and accepting is a
human-only act: agents get `rejected_human_priority` from `require_user`
("agents cannot decide on proposals",
`crates/kraken-registry/src/commands/edit.rs:768-777`; `proposal_accept` doc:
"People only… If the engine refuses it, the proposal stays open", :780-799).
A mutation's answer is tri-valued — `applied`, `queued`, or `proposed`
(`rename_symbol` doc, `edit.rs:95-99`) — which is what design 0005's
"Overwriting a user's edit, or going past the cap, becomes a proposal batch"
commits to. Dangerous commands (patching, exec) ask every time and **deny**
when no approval channel is attached (`DenyApprover`,
`crates/kraken-registry/src/context.rs:60-79`; design 0005:14).

**Untrusted data (decision 61; design 0005:18-20).** Binary-derived text is a
typed hazard, not a convention: `Untrusted<T>` serializes as
`{"untrusted": true, "value": …}` and deserialization *fails* if the flag is
missing or false (`crates/kraken-proto/src/untrusted.rs:9-14, 49-67`).
`sanitize` strips ANSI escapes, control characters except `\n`/`\t`,
bidirectional controls, zero-width and tag characters ("ASCII smuggling")
that "can hide instructions from a person while a model still reads them"
(:85-122), with capped variants and an offset map that keeps byte spans valid
(:124-179); `sanitize_value` scrubs error details recursively because they can
quote engine logs. The `Provenance::AgentFromBinaryText` tag (§2) keeps
agent output derived from binary text marked forever after. Even the `history`
command's doc warns agents that its `description` "can hold binary-derived
text: untrusted data" (`crates/kraken-registry/src/commands/history.rs:47-50`).

### 5. The viewmodel: all GUI state, zero egui

`kraken-viewmodel` (41.6k lines across 90 files, the biggest crate in the
repo) is "all GUI state and logic, with no egui dependency"
(`crates/kraken-viewmodel/src/lib.rs:1`). `ViewModel`
(`crates/kraken-viewmodel/src/vm.rs:75`) holds the whole workbench: connection
and loading state, the function list, the selected address, the current
decompiled function, back/forward `NavHistory`, the rename and comment
dialogs, the History and Proposals panels, analysis progress, the command
palette, toasts, the daemon link state, all program views, the AI assistant,
the rewrite tab, and the undo flow (`vm.rs:88-131`). Backend calls run on
tokio; results arrive as closures drained by `poll` "once per frame, so the UI
never blocks and never sees a half-applied result" (`vm.rs:1-5, 50-72`).

The seam to the registry is the `Backend` trait — "commands in, JSON out"
(`crates/kraken-viewmodel/src/backend.rs:1-4`) — with three implementations:
`InProcessBackend` runs `Registry::standard()` inside the GUI process as
`gui-user` (`crates/kraken-viewmodel/src/inprocess.rs:1-23, 38-46`);
`DaemonClientBackend` (the GUI default) speaks the `krakend` socket and maps
its notifications — `entry_applied`, `proposal_created`, jobs, sidecar
restarts, `gui_navigate` — into `BackendEvent`s, reconnecting and replaying
(`crates/kraken-viewmodel/src/lib.rs:6-9`; `src/daemon.rs:1-7, 640-641`);
`testing::FakeBackend` scripts replies for headless tests (`lib.rs:8-9`).
`BackendEvent::EntryApplied(ChangeInfo)` carries command, by_agent, author,
run id, entry ids and the entity key (`backend.rs:135-150, 154-213`) — the
log's attribution surfacing live in every client.

**Views and page rendering.** `views/` holds listing, hex, graph, xrefs,
strings, symbols, bytes and decompiler state; each "loads lazily through the
data commands (`disassemble`, `read_bytes`, `cfg`, `xrefs`, `strings`, …)" and
the GUI calls `ensure_*` methods while drawing, which fetch only what is
missing (`crates/kraken-viewmodel/src/views/mod.rs:1-6`). Pagination is
protocol-level everywhere: `MAX_PAGE_LIMIT = 500`, default 100, cursors opaque
(`crates/kraken-proto/src/page.rs:6-9, 22-29` — these are the real page-budget
types; `tokens.rs` is *not* a budget module but a client-side C tokenizer that
derives the GUI's clickable token map because `decompile` returns text plus
references, not spans (`crates/kraken-viewmodel/src/tokens.rs:1-6`)). The
registry clamps pages to per-command caps — history's cap is 100
(`crates/kraken-registry/src/session.rs:182, 198`; `page_request`,
`crates/kraken-registry/src/commands/mod.rs:178-186`) — so any surface, agent
included, reads the workbench in bounded pages. The GUI asks for 200-function
pages (`FUNCTION_PAGE`, `vm.rs:30`). Navigation tools are first-class:
browser-style address history (`src/nav.rs:1-3`), a fuzzy command palette over
app actions *and* backend commands (`src/palette.rs:1`, `src/fuzzy.rs`), and
"navigation and editing tools on par with Ghidra and IDA: Go to, Search,
Bookmarks, Patches, the Retype / Edit signature / Create and Delete function
dialogs, and the generated forms that let the command palette run every
registry command" (`src/navtools/mod.rs:1-3`) — bookmarks are stored in the
project SQLite itself (`store.rs:62`).

### 6. The GUI: egui over the same registry

Design 0010 chose "egui with eframe and egui_dock for docking," pinned to
egui/eframe 0.36 with both glow and wgpu renderers, because the workbench
needs many dockable panes and custom painting with no second UI language
(`docs/design/0010-gui-framework.md:12-16`; the pin is literal in
`crates/kraken-gui/Cargo.toml:23-24`). Its testing stance is the reason the
viewmodel exists: "GUI state lives in a headless view-model crate that is
tested without egui," with egui_kittest semantics and Xvfb smoke tests (:22).
`kraken-gui` is the eframe application owning the viewmodel
(`crates/kraken-gui/src/app.rs:1`) plus panels (`src/panels/`: listing, hex,
graph, xrefs, strings, symbols, search, bookmarks, patches, source-edit),
menu, dialogs, tour; `kraken-gui-widgets` shared widgets; `kraken-layout` a
pure Sugiyama-style CFG layout that runs on a worker thread
(`crates/kraken-layout/src/lib.rs:2-4`). `docs/gui.md` is the generated tour
("Generated by `cargo xtask docs`", `docs/gui.md:3`): menus File/Edit/View/
Navigate/Analysis/Rewrite/AI/Help/Patch, and panels Functions, Decompiler,
Hex, Listing, Graph, Xrefs, Strings, Imports/Exports, Search, Bookmarks,
Patches, Edit (experimental C→patch), History, Proposals, Assistant, Rewrite,
AI Activity — every menu item also in the palette (Ctrl+K) (:7). The GUI is a
*client of the registry*, not a parallel implementation: by default it talks
to `krakend` (§5), so its edits land in the same log with `gui-user`
attribution and its view of concurrency — another client's edits arriving as
events, refreshes, toasts — is the daemon's (`activity.rs` tracks "what
agents (clients other than the GUI itself) did lately"
`crates/kraken-viewmodel/src/activity.rs:1-3`). `gui_navigate` completes the
loop: an agent (MCP/ACP) runs the command and "every connected GUI of the
project" receives the event and shows the address in a named tab
(`crates/kraken-registry/src/commands/gui_navigate.rs:1, 65-74`;
`crates/krakend/src/handler.rs:248-257`; `backend.rs:204-212`), with sibling
`ui_action`/`ui_highlight` events driving the window outright
(`handler.rs:239-247`). There is no terminal UI anywhere in KRAKEN: the
surfaces are the GUI client, the CLI, MCP/ACP, Python and `krakend` itself.

### 7. The History surface: humans meeting the log

`history` is a Safe query, newest first, paginated at 100, whose doc says it
includes "rejected attempts and undo entries" and warns about untrusted
descriptions (`crates/kraken-registry/src/commands/history.rs:39-52`). The
GUI History tab draws every change "grouped by agent run, with a per-change
Undo that previews the later edits depending on it, and the dialog that asks
before undoing them too" (`crates/kraken-gui/src/history/mod.rs:1-2`), driven
by headless logic in `crates/kraken-viewmodel/src/history/mod.rs:1-5`:
`group_history` folds consecutive rows of one agent run into a group with a
live-undoable count (:136-151, :154), the preview dialog renders the exact
sentence "Undoing this also undoes N later edits that depended on it: …"
(:84-107) plus the stale-decompile note (:109-124), a run with dependents is
previewed and undone one-by-one under a 40-entry cap (:21-22), and
`HistoryEntry.status/sync` are the `applied|rejected|orphaned` +
`pending|pushed|engine_rejected` pair made visible
(`crates/kraken-viewmodel/src/state.rs:291-295`). Undoing a whole agent run
is a History-tab action (`UndoTarget::Run`, `history/mod.rs:28-33`) wired to
`undo_run`; Ctrl+Z is the per-author `undo` command (`docs/gui.md:310`).
Design 0005:16's promise — agent edits "styled differently in the UI until
confirmed" — is `by_agent` on every history row.

## Comparison with calxgloss

### Source of truth for intent: the edit log vs the `re/` tree + overlays + git

calxgloss has **no edit log, by design**: "Humans never rename or comment at
an address, so there is nothing an edit log could log"
(`docs/research/kraken/10-calxgloss-baseline.md:159-166`). Its memory of an
effort is the `re/` record tree — per-engine scan documents, run logs, caches
(baseline :168-182) — plus **overlay files** for reviewer intent, the ADR-0003
decision that intent "is persisted as overlay files on top of the
artifact-derived state, under `re/review/`" (`docs/adr/0003-reviewer-intent-lives-in-overlay-files-not-derived-artifacts.md:15-20`; e.g. `re/review/skips.json` — one of the overlay file names named in
`docs/data_flow.md:738`),
plus **git** for work: one branch per attempt `re/{binary}/{function}v{N}`,
never deleted, structured justification blocks in every commit
(`crates/pipeline/calxgloss-git/src/lib.rs:5, 15-27`; principle 6,
`README.md:18`). KRAKEN's answer to the same question ("where does human
intent live, durably?") is the per-change SQLite log. The two are not the
same *unit*: KRAKEN's atomic unit is one annotated-address edit with author,
read-set and inverse; calxgloss's is one attempt at one unit of work, whose
attribution is the commit justification block and whose "read-set" analogue is
the recorded dependency list. Both share the deeper rules: append-only, never
rewrite history (compensating entries ↔ failed branches kept forever,
`calxgloss-git/src/lib.rs:11`), derived state disposable and rebuildable
(design 0002:14-18 ↔ the loaded program re-loadable from binary + engine +
records, baseline :159-166), and machine-checkable human priority (ADR-0021's
never-overrule-a-hand-typed-slot write-back rule,
`docs/adr/0021-apply-write-back-in-program-order-narrowing-only-undefined-slots.md:27-30`,
is the same instinct as `last_author_kind` + `rejected_human_priority`).

### Undo: compensation vs isolation

KRAKEN undoes by *appending inverses*: per-author, per-entry, per-run, with
transitive dependency cascade and tainted-marker staleness (§3). calxgloss
undoes by *isolation*: the attempt branch exists until merged; discarding a
bad attempt means never merging it — principle 5, "LLM-first,
discard-when-wrong… throwing away incorrect output is cheap"
(`README.md:17`), and principle 6 makes every attempt restorable by
construction (`README.md:18`).
Because each attempt ran in its own branch and its own scratch verify project
(baseline §Verification), no compensation entries are needed and no
dependency cascade can surprise anyone: later work built on a discarded branch
never existed on `main`. KRAKEN needs compensation because a human's and an
agent's edits *interleave live* in one project — exactly the premise design
0006 names (`docs/design/0006-undo-and-concurrency.md:8`). Where the
mechanisms genuinely rhyme: `undo_run` of an agent run ≈ keeping/dropping a
whole attempt branch; and KRAKEN's post-undo `refresh_after_undo` drift report
is the interactive analogue of calxgloss re-verifying after a send-back.
Neither system rewrites history; KRAKEN reverses effects in place, calxgloss
never lets the effect reach the trunk.

### Staleness: entity versions and watermarks vs coverage stamps

Both systems answer "is what you derived from still true?" and both refuse to
let derived state lie. KRAKEN: `entity_versions` (key → version →
`last_author_kind`) makes every future write validate against what it read
(`store.rs:45-49, 293-309`), the push watermark + engine checkpoint detects an
engine behind the log (ch. 31 §8), and tainted markers name whose decompile is
stale after an undo. calxgloss: each scan stamps **its own coverage record**
beside provenance at scan time, "absent coverage reads as unknown, never
absent" (ADR-0053,
`docs/adr/0053-scan-coverage-is-the-scans-own-record-stamped-at-scan-time-beside-provenance-read-as-unknown-when-absent-and-pinned-to-the-engines-declared-facets.md:33-37`;
baseline :184-189), and cache validity is keyed to binary hash + engine build
(ADR-0055, ch. 31 §8). The axes differ — KRAKEN tracks *log-vs-engine* drift
and *read-vs-write* races; calxgloss tracks *evidence-vs-facets* completeness
— but the honesty principle is identical, and ch. 31 already verified both
side's cache-identity choices converge.

### Live viewmodel vs static artifacts; proposals vs verdicts

KRAKEN's viewmodel is live state over an event stream: panels refresh when
another client edits, agents drive the GUI itself (`gui_navigate`), every
view is paged bounded JSON from the same registry the agents use. calxgloss's
web UI is deliberately the opposite: "Both views are read-only over persisted
artifacts, and no new persistence format appears" (ADR-0006,
`docs/adr/0006-web-views-read-only-over-existing-artifacts.md:16-20`), with
honest degradation and analytics computed on demand (baseline §Web API); its
live-only slice is pipeline control state in `live`, nothing per-address. The
prompt-side analogue of the viewmodel is the evidence-bundle projector — a
separate registered-rows seam whose output is the single render input of the
bundle-fed templates (ADR-0048/0049,
`docs/adr/0048-the-prompt-read-path-is-one-analysisdoc-seam-of-registered-projection-rows-kept-separate-from-the-scan-descriptor-write-seam.md:32-34`)
— static, one-shot, per-unit, not an interactive session. On gating: KRAKEN's
proposals table is per-edit human approval for agent writes
(`proposals.rs:1-5`); calxgloss's human gate is per-*unit* accept / send-back /
patch verdicts behind a compile+test verification gate (baseline §Review) —
far coarser, but the machine check (verification) runs *before* the human
sees anything, which KRAKEN's proposal queue has no analogue of.

### Overlap / calxgloss-only / KRAKEN-only

- **Overlap:** append-only, never-rewrite history; full audit including
  refused/failed attempts inline (rejected entries ↔ kept branches);
  provenance on every derived claim (`Provenance` + `Untrusted` ↔
  coverage-stamped scan records); machine-checked precedence of human intent
  over machine writes (`last_author_kind`/`rejected_human_priority` ↔
  ADR-0020/0021 write-back rules); bounded pagination on every read surface;
  one shared command surface across humans and agents (ch. 33's territory);
  undo-at-run-granularity ↔ attempt-branch granularity.
- **calxgloss-only:** whole-unit isolation (branch + scratch project) making
  undo a merge decision rather than a compensation calculation; the
  verification gate preceding the human gate; overlay files as the entire
  reviewer-intent vocabulary (skips, queue order, overrides — nothing
  per-address, by ADR-0003); scan coverage honesty as the staleness axis.
- **KRAKEN-only:** the SQLite edit log with entity keys, versions, read-sets
  and compensating entries; dependency-aware cascade undo with a preview
  sentence; per-author undo (no global stack); proposals with per-run caps
  and cross-reconnect quotas; typed `Untrusted<T>` + sanitize stack at the
  wire level; per-address attribution and the History/Proposals GUI panels;
  live cross-client event broadcast and agents driving the GUI; the headless
  viewmodel pattern itself.

### Verdict

For calxgloss's unattended pipeline, the edit log is the right design for a
problem calxgloss does not have: interleaved live writers at one address.
calxgloss's isolation (branch per attempt) plus single-writer pipeline gets
KRAKEN's audit and undo guarantees with a fraction of the machinery — git is
the edit log, and merge is the accept. The chapters' shared verdict holds:
calxgloss should import *none* of the log/fold/CAS core, and its overlay +
git model is confirmed as the correct minimum for verdict-level steering.
What survives scrutiny to steal is narrower than the machinery itself:

1. **Provenance stamped on machine-written slots.** KRAKEN's
   `entity_versions.last_author_kind` + `classify` (`policy.rs:32-66`) is
   exactly the data ADR-0021's "never overrule a hand-typed slot" needs to be
   checkable rather than conventional: a per-slot
   `origin + version` stamp on write-back (`docs/adr/0021-…:27-30`) makes
   "narrow-only, never overrule" a predicate, not a policy comment.
2. **Wire-level untrusted marking for the bundle → prompt path.** calxgloss
   feeds binary-derived strings (names, contents) through bundle sections
   into askama templates (ADR-0049); its only sanitizers today are identifier
   and filename mangling (`crates/interface/calxgloss-cli/src/utils.rs:137-149`,
   `crates/evidence/calxgloss-consts/src/codegen.rs:55`), and there is no
   untrusted marker anywhere (`grep untrusted` over `crates/` and
   `docs/adr/`: nothing). KRAKEN's decision-61 stack — a wrapper that cannot
   deserialize without its flag plus an invisible-character sanitizer that
   keeps byte spans valid (`untrusted.rs:9-14, 49-67, 85-179`) — is a small,
   testable addition for calxgloss's projector output.
3. **The preview-before-destroy dialogue.** The History dialog's sentence
   "Undoing this also undoes N later edits that depended on it" plus a stale
   note (`history/mod.rs:84-124`) is a UX pattern calxgloss's send-back /
   archive actions should copy in words even though the data model differs:
   name the dependents, *then* ask.

**Confirm:** never-rewrite history, run-granularity reversibility,
machine-checked human priority, honest staleness markers, and pagination caps
as a protocol constant (KRAKEN's `MAX_PAGE_LIMIT` 500 / history cap 100 are
calxgloss's instinct, made explicit).
**Don't copy:** the edit log and fold for annotations calxgloss never makes;
proposals per edit (calxgloss's gate is per unit and verification-first —
weaker gate, coarser unit is *not* the direction to move); the live
viewmodel (ADR-0006's read-only honesty is worth more here than live events —
and with `serve` vs `live` there is no daemon to stream from); compare-and-set
read-sets (single-writer sidesteps the race entirely); and orphaned-anchor
machinery that is, in this revision, itself only reserved vocabulary.

## Sources

- `crates/kraken-model/src/{store,keys,state,lineage,policy,proposals,lib}.rs`
- `crates/kraken-proto/src/{logop,locator,meta,page,untrusted}.rs`
- `crates/kraken-registry/src/{mutate,session,context,views}.rs`,
  `src/commands/{edit,history,undo_entry,jobs,gui_navigate,mod}.rs`,
  `crates/krakend/src/handler.rs`, `crates/kraken-host/src/daemon.rs`
- `crates/kraken-viewmodel/src/{lib,vm,backend,inprocess,daemon,tokens,nav,palette,state,activity}.rs`,
  `src/{views,history,navtools}/mod.rs`, `src/history/mod.rs`
- `crates/kraken-gui/src/{app,history/mod}.rs`, `kraken-gui/Cargo.toml`,
  `crates/kraken-layout/src/lib.rs`, `CLAUDE.md`
- `docs/design/0002-edit-log-is-source-of-truth.md`,
  `docs/design/0005-agent-safety.md`,
  `docs/design/0006-undo-and-concurrency.md`,
  `docs/design/0010-gui-framework.md`, `docs/design/0014-native-engine.md`,
  `docs/gui.md`
- calxgloss: `docs/research/kraken/10-calxgloss-baseline.md`;
  `docs/adr/0003, 0006, 0020, 0021, 0048, 0049, 0052, 0053`;
  `docs/data_flow.md`; `README.md`; `crates/pipeline/calxgloss-git/src/lib.rs`;
  `crates/interface/calxgloss-cli/src/utils.rs`; ch. 31 §7–8.

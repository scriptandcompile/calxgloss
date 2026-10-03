# Web User Override — Implementation Plan

> Adding three user-driven scheduling overrides to the review dashboard:
> reordering translation priority, marking files for stubbing, and deferring entire
> DLLs/EXEs.

---

## 1. Shared Architecture

### 1.1 Central Configuration File

All three overrides share a single source of truth: `re/queue-config.json` in the
translation output repository. The dashboard builder and pipeline scheduler both read
from this file.

```jsonc
{
  // ── Per-DLL overrides ──────────────────────────────────────────
  "dlls": {
    "ntdll.dll": {
      "deferred": true
    },
    "fmod.dll": {
      "priority": 5
    }
  },

  // ── Per-function overrides ─────────────────────────────────────
  "functions": {
    "my_game.dll/SomeComplexFunc": {
      "stub": false,
      "priority": 100
    },
    "my_game.dll/SomeStubFunc": {
      "stub": true
    }
  },

  // ── Global manual order (drag-and-drop from the web UI) ────────
  "manual_order": [
    "my_game.dll/FunctionA",
    "my_game.dll/FunctionB",
    "my_game.dll/FunctionC"
  ]
}
```

### 1.2 Configuration Loading Pipeline

```
User action (web UI)
    │
    ├──→ API handler (PATCH/POST)
    │       │
    │       ├──→ Validate input
    │       ├──→ Write to re/queue-config.json
    │       └──→ Return 200
    │
    └──→ Dashboard rebuild
            │
            ├──→ DashboardBuilder reads re/queue-config.json
            ├──→ Enriches UnitOfWork with override fields
            └──→ Sorted queue incorporates overrides
```

**Error handling:** If the file is missing or malformed, fall back to the existing
automatic ordering silently. Log a warning to stderr.

---

## 2. Feature 1 — Defer Entire DLLs/EXEs

### 2.1 Data Model Changes

#### `re/queue-config.json`
Already shown in §1.1 — `"dlls"` key with per-DLL `"deferred"` flag.

#### `calxgloss-types` — `UnitOfWork` extension
Add one field to `UnitOfWork`:

```rust
pub struct UnitOfWork {
    // ... existing fields ...
    pub deferred: bool,           // NEW
}
```

### 2.2 Dashboard Builder Changes

**File:** `crates/calxgloss-reports/src/dashboard/builder.rs`

1. After discovering DLLs in `read_classification_records()`, load
   `re/queue-config.json` if it exists.
2. For any DLL listed with `"deferred": true`, set `UnitOfWork::deferred = true`.
3. Deferreed units remain in the dashboard view but are visually distinguished
   (greyed-out row, "deferred" badge) and excluded from `sorted_queue()` and
   `next_in_dependency_order()`.

### 2.3 API Endpoints

**File:** `crates/calxgloss-web/src/server/handlers/queue.rs` (new handlers)

```
PATCH /api/dlls/{name}
  Body: { "deferred": true | false }
  → Updates re/queue-config.json "dlls" key
  → Returns updated UnitOfWork

GET /api/dlls
  → Lists all discovered DLLs with their current override state
```

### 2.4 Web Frontend Changes

- **"DLLs" tab** alongside the existing queue view.
- Table columns: DLL name, category badge, export count, **Defer** toggle,
  **Stub All** toggle, priority slider.
- Defer action → `PATCH /api/dlls/{name}`.
- Toggling "Defer" hides the DLL's functions from the main queue and shows them
  under a collapsed "Deferred" section.

### 2.5 Pipeline Integration

- The batch translator and auto-queue logic call a helper:

```rust
pub fn should_skip_dll(dll: &str, config: &QueueConfig) -> bool {
    config.dlls.get(dll).is_some_and(|c| c.deferred)
}
```

- Deferred DLLs are excluded from the `batch_translate` call and from any
  automatic classification scheduling.

---

## 3. Feature 2 — Mark Files as "Should Be Stubbed"

### 3.1 Data Model Changes

#### `re/queue-config.json`
Already shown — `"functions"` key with per-function `"stub": true`.

#### `calxgloss-types` — `UnitOfWork` extension

```rust
pub struct UnitOfWork {
    // ... existing fields ...
    pub stub_requested: bool,     // NEW
}
```

#### New enum variant
Add to `WorkUnitKind`:

```rust
pub enum WorkUnitKind {
    // ... existing variants ...
    StubGeneration,               // NEW
}
```

### 3.2 Stub Generation Logic

**New file:** `crates/calxgloss-testgen/src/stubs.rs`

This module takes a DLL's export table (from `calxgloss-testgen::pe::PeImage`)
and Ghidra's type information (from `calxgloss_ghidra`) and generates raw FFI
bindings — no LLM round-trip.

```rust
/// Generate FFI stub bindings for an entire DLL.
///
/// For each exported function, produces an `extern "system"` declaration
/// with a body that panics with "stub — not yet translated".
pub fn generate_stubs(
    dll_name: &str,
    exports: &[ExportEntry],
    type_info: &HashMap<String, GhidraType>,
) -> String {
    // 1. Read PE image for the export table
    // 2. For each export, read Ghidra function signature
    // 3. Generate:
    //      #[link(name = "original.dll")]
    //      extern "system" {
    //          pub fn SomeExport(p1: i32, p2: *mut u8) -> i32;
    //      }
    // 4. Optionally wrap in a module: `mod original_dll_name { ... }`
}
```

**Output:** Written to `re/stubs/{dll_name}.rs` so the dashboard knows stubs
are ready and a `StubGeneration` work unit can be created.

### 3.3 Dashboard Builder Changes

**File:** `crates/calxgloss-reports/src/dashboard/builder.rs`

1. Load `re/queue-config.json` and check `"functions"` key.
2. For any function marked `"stub": true`, set `UnitOfWork::stub_requested = true`.
3. If a stub file already exists in `re/stubs/{dll}.rs`, change the unit's
   `kind` to `WorkUnitKind::StubGeneration` with status `Accepted`.
4. Stubbed units appear with a "stub" badge and are excluded from the translation
   queue.

### 3.4 API Endpoints

```
POST /api/units/{id}/stub
  → Sets stub_requested = true, writes to re/queue-config.json

POST /api/units/{id}/unstub
  → Clears stub_requested, writes to re/queue-config.json
  → If stub file exists, triggers regenerating it without the function
```

### 3.5 Web Frontend Changes

- Each function row in the dashboard gets a **checkbox/toggle** labeled "Stub".
- When checked:
  - Row gets a "stub" badge
  - Toggle calls `POST /api/units/{id}/stub`
  - Row moves to a "Stubbed" section (or disappears from the active queue)
- Bulk action: "Mark all as stub" button per DLL (uses the DLL-level config).

---

## 4. Feature 3 — Manual Drag-and-Drop Priority Reordering

### 4.1 Data Model Changes

#### `re/queue-config.json`
Already shown — `"manual_order"` key (array of unit IDs).

#### `calxgloss-types` — `ReviewDashboard` extension

Add a `custom_order` index map:

```rust
pub struct ReviewDashboard {
    // ... existing fields ...
    pub custom_order: HashMap<String, usize>,  // unit_id → position
}
```

This map is populated from `manual_order` by the dashboard builder.

### 4.2 Sorting Logic

**File:** `crates/calxgloss-types/src/dashboard/review.rs`

Modify `sorted_queue()` to incorporate custom order:

```
Sort order (highest priority first):
  1. Non-deferred units before deferred ones
  2. Non-stubbed units before stubbed ones
  3. Dependency order (topological sort) — HARD CONSTRAINT
  4. Custom order index (from manual_order)
  5. WorkUnitLevel (shim < PAL < test < func < integrate < fix)
  6. Alphabetical by ID
```

Topological sort is still the hard constraint — you can't reorder a function
before its shim layer or DLL classification. Custom ordering only applies
**within the same topological depth**.

### 4.3 API Endpoints

```
POST /api/queue/reorder
  Body: { "order": ["unit-id-1", "unit-id-2", ...] }
  → Overwrites manual_order in re/queue-config.json
  → Validates no impossible reorderings (logs warnings)
  → Returns updated QueueResponse

GET /api/queue
  → Returns QueueResponse with `queue_position_override` field
    (the manual order index for each unit, or None if not manually ordered)
```

### 4.4 Web Frontend Changes

- Each function row gets a **drag handle icon** (⠿ or ⋮⠿).
- Users drag rows up/down within the same depth level.
- On drop:
  1. Compute the new order array from DOM state
  2. POST to `/api/queue/reorder`
  3. Refresh the queue view

**No custom JS framework needed** — vanilla HTML5 drag-and-drop API or a tiny
library like `dnd-kit` / `sortablejs` for smoother UX.

---

## 5. Implementation Phases

### Phase 1 — Core Infrastructure (2 days)

| Task | File(s) | Description |
|------|---------|-------------|
| `QueueConfig` type | `calxgloss-types/src/queue_config.rs` | New file — parse `re/queue-config.json` |
| Load config in builder | `calxgloss-reports/src/dashboard/builder.rs` | Read and apply overrides |
| `reorder` API handler | `calxgloss-web/src/server/handlers/queue.rs` | POST endpoint |
| Write shared `QueueConfig` struct | | Used by builder + web server |

**Outcome:** The system can read/write a `re/queue-config.json` and the dashboard
displays it, but no UI toggles yet.

---

### Phase 2 — Defer DLLs (1–2 days)

| Task | File(s) | Description |
|------|---------|-------------|
| `deferred` field | `calxgloss-types/src/dashboard/work_unit.rs` | Add to `UnitOfWork` |
| DLL-level override | `builder.rs` | Set `deferred` from config |
| `PATCH /api/dlls/{name}` | `queue.rs` (new file) | Toggle deferred |
| Deferred DLL filter | `review.rs` | Exclude deferred from `sorted_queue()` |
| "DLLs" tab | Frontend | Table with deferred toggle per DLL |
| Pipeline skip | `calxgloss-translator/src/pipeline.rs` | Skip deferred DLLs in batch |

**Outcome:** Users can mark any DLL as deferred and it disappears from the
translation queue.

---

### Phase 3 — Stub Generation (3–5 days)

| Task | File(s) | Description |
|------|---------|-------------|
| `stub_requested` field | `work_unit.rs` | Add to `UnitOfWork` |
| `WorkUnitKind::StubGeneration` | `types.rs` | New enum variant |
| Stub generator | `calxgloss-testgen/src/stubs.rs` | NEW FILE — FFI binding gen |
| Stub marker logic | `builder.rs` | Detect stub requests, set `kind` |
| Stub file output | `testgen/src/stubs.rs` | Write to `re/stubs/{dll}.rs` |
| API stub/unstub | `queue.rs` | POST endpoints |
| Frontend checkbox | Frontend | Per-function and bulk "stub all" |
| Stub queue exclusion | `review.rs` | Exclude stubbed from translation queue |

**Outcome:** Users can mark individual functions (or entire DLLs) for stubbing.
Stub files are generated as raw FFI bindings without LLM round-trips.

---

### Phase 4 — Drag-and-Drop Reordering (2–3 days)

| Task | File(s) | Description |
|------|---------|-------------|
| `custom_order` field | `review.rs` | Add `HashMap<String, usize>` |
| Sort with custom order | `review.rs::sorted_queue()` | Incorporate priority |
| Frontend drag handle | Frontend | HTML5 drag-and-drop per row |
| Reorder API | `queue.rs` (new handler) | Accepts order array |
| Depth-scoped reorder | `review.rs` | Enforce topological depth constraint |

**Outcome:** Users can drag-and-drop function rows to control translation priority
within dependency-safe boundaries.

---

## 6. Files Modified (Summary)

| File | Changes |
|------|---------|
| `crates/calxgloss-types/src/queue_config.rs` | **NEW** — `QueueConfig` type + JSON parse |
| `crates/calxgloss-types/src/dashboard/work_unit.rs` | Add `deferred`, `stub_requested` |
| `crates/calxgloss-types/src/dashboard/types.rs` | Add `WorkUnitKind::StubGeneration` |
| `crates/calxgloss-types/src/dashboard/review.rs` | Modify `sorted_queue()`, add `custom_order` |
| `crates/calxgloss-reports/src/dashboard/builder.rs` | Read `queue-config.json`, enrich units |
| `crates/calxgloss-web/src/server/handlers/queue.rs` | New: `PATCH /api/dlls/`, `stub/unstub`, `reorder` |
| `crates/calxgloss-testgen/src/stubs.rs` | **NEW** — FFI stub generator |
| `crates/calxgloss-translator/src/pipeline.rs` | Filter deferred DLLs in batch translate |
| Frontend (new/modified components) | DLLs tab, drag handles, stub toggles |

---

## 7. Risks & Considerations

### 7.1 Race Conditions
If the web UI changes `re/queue-config.json` while a batch translation is running,
the running translation won't see the update. Mitigation: the batch translator
should re-read the config file before processing each DLL (it already reads
configuration per-batch).

### 7.2 Topological Depth Constraint for Reordering
Users should not be able to reorder a function before its shim layer — but the
current UI doesn't show depth. Mitigation: only enable drag handles for rows
within the same depth level (dim/grey out rows at other depths as non-droppable).

### 7.3 Stub Generation Accuracy
Generating FFI bindings from Ghidra type info is imperfect. Ghidra's type database
may be incomplete or incorrect. Mitigation:
- Generate the stub but don't auto-accept it.
- Mark stubs as `PendingReview` so the user can verify.
- Provide a diff view (`GET /api/units/{id}/diff`) so users can inspect the
  generated FFI code before accepting.

### 7.4 Persistence Format
TOML would be more user-editable (like `calxgloss.toml`), but JSON is already
used for patch records, baselines, and actions in `re/`. JSON is the path of
least resistance — but if the team prefers TOML for the queue config, the
`QueueConfig` type can be deserialized with either format using serde's
`#[serde(deserialize_with = "...")]` or a wrapper.

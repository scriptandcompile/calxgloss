# ReVa analysis workflows + effect — from import to annotations, diff, and proof it works

> Part of the [ReVa overview](README.md). How ReVa *does* analysis end-to-end — the import →
> auto-analysis path, the write-back annotation tools and their read-before-write gate, the
> 13-tool diff workflow — and what evidence the repo has that any of it works. Citations are
> `path:line` in clone `/tmp/opencode/cyberkaida-rea` @ `a2fcd946` (2026-10-27). Tool schemas:
> ch. 31; headless launcher: ch. 32; skill prose: ch. 33, cross-referenced.

## 1. The canonical path: import → auto-analysis

`import-file` (`tools/project/ProjectToolProvider.java:1467-1930`) is Ghidra's batch import in
Java: `BatchInfo` + FSRL + `LoadSpec.getLoader().load(settings)` + `loaded.save()`;
`enableVersionControl` → `addToVersionControl` (:1792). **Analysis is not implied**:
`analyzeAfterImport` defaults to `ConfigManager.isWaitForAnalysisOnImport()` with
`DEFAULT_WAIT_FOR_ANALYSIS_ON_IMPORT=false` (`plugin/ConfigManager.java:82`), and an
un-analyzed import returns `analyzed:false, analysisRecommended:true, nextSteps` — handing the
agent the next call (:1832-1841). Post-import analysis (`runFullAnalysisAfterImport` :456-482)
dodges a Ghidra trap (fresh programs: plain `startAnalysis` only analyzes queued addresses):
the order is `AutoAnalysisManager.getAnalysisManager` → `initializeOptions()` → transaction
`"ReVa: Auto Analysis (post-import)"` → `GhidraProgramUtilities.isAnalyzed()` check →
`reAnalyzeAll(null)` (queue everything) → `startAnalysis(monitor)` → `markProgramAnalyzed`.
`analyze-program` (:701-867) uses a **hybrid wait**: start, block up to `waitSeconds` (default
10); if still running return `{status:"running", jobId, log, logCursor, hint}` and let the
agent poll; `persist ∈ {auto,save,none}` (:742-757); analyzer-override names validated against
`ANALYSIS_PROPERTIES` (:759-784); one job per program via `startOrAttach` (:791-796).

`services/AnalysisJobManager.java` mints `analysis-N` ids, caps history at
`MAX_TERMINAL_JOBS=50`, runs one worker thread `reva-analysis` + a 1 Hz ticker
`pumpMessageLogs` (catches `Throwable`); `startOrAttach` is `synchronized` — concurrent
callers attach to the live job (:151-170). `services/AnalysisJobRunner.java:58-217`:
analyzer-option overrides applied and restored in transactions; full vs incremental by
`isAnalyzed()`; result reports `analyzed`, `wasFullAnalysis`, `analyzersRun`, `messages`
(`aam.getTimedTasks()`/`getMessageLog()`); persist failure is non-fatal; terminal statuses
`COMPLETED/CANCELLED/TIMED_OUT`. Durability (`util/ProgramPersistenceUtil.java`):
`PersistMode{AUTO,SAVE,NONE}`, `PersistAction{CHECKIN,ADD_TO_VC,SAVE,SKIP}`,
save-then-checkin. Annotation tools never auto-save — durability is `checkin-program` (:304)
or analyze-`persist`; `plugin/RevaProgramManager.java:197-239` auto-checks-out
(`checkoutBeforeOpen`).

## 2. The nine annotation tools — writing back into Ghidra

- `rename-variables` — `tools/decompiler/DecompilerToolProvider.java:1080-1189`: transaction
  (:1148-1168) around `HighFunctionDBUtil.updateDBVariable(symbol, newName, null,
  SourceType.USER_DEFINED)` (:1156); replies with a before/after decompilation diff (:1186).
- `change-variable-datatypes` — :1221+: `DataTypeParserUtil.parseDataTypeObjectFromString`
  (:496) → `updateDBVariable(symbol, null, newDataType, …)` (:505).
- `set-decompilation-comment` — :1841+: forgiving line→address via `findNearbyAddressForLine`
  (stale line numbers get a note when moved), then `listing.setComment(targetAddress,
  commentType, comment)` (:1931).
- `set-comment` / `remove-comment` — `tools/comments/CommentToolProvider.java:73-105,
  233-262`: `listing.setComment` (:104); removal nulls the entry (:262).
- `apply-data-type` — `tools/data/DataToolProvider.java:97+`: transaction "Apply Data Type",
  parse :127; unresolvable type names bounce to get-data-type-archives.
- `create-label` — :190+: `symbolTable.createLabel` (:232).
- `set-function-prototype` — `tools/functions/FunctionToolProvider.java:966-1138`:
  `FunctionSignatureParser` (:997), transaction (:1031), optional `createIfNotExists` →
  `createFunction` (:1044), `setCustomVariableStorage(true)` (:1058-1063), `setName` (:1067),
  `setReturnType` (:1098), `replaceParameters` (`CUSTOM_STORAGE` vs
  `DYNAMIC_STORAGE_ALL_PARAMS`, :1102-1106), `setVarArgs` (:1110).
- `create-function` — :1371-1470: `CreateFunctionCmd` (:1430); refuses over an existing
  function and names it in the error (:1400-1406); `setName` (:1451).

Adjacent writers outside the nine: bookmarks, function tags
(`FunctionToolProvider.java:1591-1623`), structures
(`StructureToolProvider.java:151-177,409-435,538-556`), `run-script` — which opens **no**
transaction (the script author must, `ScriptToolProvider.java:150-154`) — and diff markup
transfer (§4); `DEVELOPER.md:84` scopes "Annotations" to Comment+Bookmark. Two absences: **no
`rename-function` tool** (only via `set-function-prototype`/`create-function`) and **no undo
tool** — `grep -ri undo src/main` is empty; the only rollback is a tool aborting its own
transaction (`endTransaction(id,false)`). Writes commit to the open program immediately but
reach disk only via checkin/save (§1).

## 3. The read-before-write gate

`DecompilerToolProvider.java:85` keeps a `readDecompilationTracker` (`ConcurrentHashMap`)
keyed `programPath + ":" + formatAddress(entry)`, stamped by `get-decompilation` (:959-961),
`get-callers-decompiled` (:2101), `get-referencers-decompiled` (:2284); cleared on
`programClosed` (:99-113); entries expire after 30 min (:149; `hasReadDecompilation`
:1695-1704). Exactly **three** tools consult it — `rename-variables` (:1117-1120),
`change-variable-datatypes` (:1260), `set-decompilation-comment` (:1885-1888) — failing
verbatim: "You must read the decompilation for function '…' using get-decompilation tool
before making variable changes. This ensures you understand the current state of the code."
`set-function-prototype`, `apply-data-type`, `create-label`, `create-function` and comment
tools are **not** gated. Both harnesses pin it: `test_workflow_correctness.py:3168-3213` greps
replies for "must read the decompilation"; slow JUnit
`DecompilerToolProviderIntegrationTest.java:663-684` asserts `isError` mentions it.

## 4. Diff workflow — 13 tools, staged correlators, persisted sessions

All in `tools/diff/DiffToolProvider.java`: list/delete-sessions :56/:78, summary :314,
list-functions :376, function :542, strings :680, data :701, transfer-markup :821, apply-match
:876, status :959, cancel :1065, create-session :1146, add-correlator :1232. Correlators
(`util/VersionTrackingUtil.java:32-63`) map onto Ghidra VT factories; default sequence
`symbol-name, exact-bytes, exact-instructions, exact-mnemonics, duplicate-instructions,
function-reference`; `combined-reference` opt-in. Sessions persist as `VTSessionDB`
DomainFiles under folder `ReVaDiffSessions` (`DiffSessionManager.java:37`) — match state lives
in the project. `createStaged` (:125-185) reuses an existing session unless `force` or the
correlator selection changed, then runs each correlator as a stage over the unmatched
residual, `save("ReVa diff stage: …")` per stage — a crash keeps prior stages; `addCorrelator`
(:188-204) appends one stage. `diff-create-session` hard-requires
`requireAnalyzed(source/dest)` (:1175-1176) and resolves scope errors eagerly before any job
starts (:1180-1185). `summarize()` (:251-295) adds an **honesty guard**: if over half the
matched functions have degenerate 1-address bodies, `diff-summary` emits `analysisWarning`
(:285-293): "…program appears UNDER-ANALYZED… 'changed' will read near-0 regardless of
includeBodyByteChanges. Run analyze-program on both programs…" — refusing to let a flat diff
silently read as "nothing changed". `diff-transfer-markup` (`transferMarkup` :738-800) takes
the best match per pair with a similarity `confidence` floor, returns below-floor pairs as
`proposed` (unapplied), and commits in two transactions (VT session + destination)
all-or-nothing via `acceptAndApplyMarkup` (:280-288, Ghidra `ApplyMarkupItemTask`).

## 5. Evidence that it works — tests, and the absence of measurement

Suites: `src/test` 267 `@Test` (36 files); `src/test.slow` 231 (50); `tests/` 172 `def test_`
(20). The Python suite drives the product over MCP like any agent — ch. 32's biggest
executable proof: launcher → stdio client → tool calls → *effect* assertions, not replies.
`tests/conftest.py` anatomy: session-scoped `ghidra_initialized` boots PyGhidra once;
`mcp_stdio_client` spawns **one** `uv run mcp-reva` subprocess per session (:275-369). CI:
`test-headless.yml:110` `uv run pytest tests/ -v --timeout=180` (one server per worker, not
"~110 JVM boots"); `test-ghidra.yml:61` `gradle test`. Per-test `isolated_workspace`.

`tests/test_workflow_correctness.py` (3,633 lines) states the posture (:1-12): "These tests
answer 'did the tool give the right answer?', not just 'did the tool respond?'" Fixture
`tests/fixtures/test_arm64` compiles `test_program.c`; `_import_and_analyze` (:64-102)
deliberately imports un-analyzed, then `analyze-program forceFullAnalysis=true`. Ground truth:
entry decompilation must contain `"_printf("`, `"_add("`, `"_multiply("` (:179-187); a rename
is walked through persistence — rename → `checkin-program` asserting `action=="checked_in"`
(:329-331) → re-decompilation contains `reva_e2e_renamed_*` (:245-352);
`set-function-prototype "int _add(int alpha, int beta)"` shows the param names in the
*re-decompiled output*; `apply-data-type` success is verified by an **independent** `get-data`
read (:447-461), whose comment names the anti-pattern: "a handler that reports success
without writing would pass". `tests/test_e2e_workflow.py` covers the VC arc
(`action=="added_to_version_control"` :183-186; comment survives cache release :217) while its
docstring (:68-72) *admits* cross-process persistence is not verified.
`tests/test_diff_e2e.py` imports the fixture twice, renames `_add` in the destination via
`run-script` (manual transaction, :101-148), then asserts `matched.changed >= 1` via the
callees lens (:231-233); `calleeChanges.removed` contains `"_add"`, `added` the new name
(:294-302); `diff-function` reports `hasChanges`, `changedLineCount >= 1`, and
`bodyBytesChanged is False` — a symbol-only rename leaves bytes alone (:331-345); identical
pairs report `changeTypes == []` (:314-317). `test_analysis_jobs_e2e.py` drives the job handle
to completion (`analyzed=True`); `test_import_e2e.py`: zip → 4 programs, fat binary → 2 arch
slices.

**Gates vs enforcement, and the ceiling.** `ReVa/skills/deep-analysis/SKILL.md:18-73`
prescribes READ→UNDERSTAND→IMPROVE→VERIFY(re-read)→FOLLOW→TRACK, an "ON-TASK CHECK" every 3-5
calls, the six write tools under IMPROVE (:54-62), a 10-15 tool-call budget per function
(:412, :456, :467-468, :526-527) — none enforced by code (no `allowed-tools`, no tool hooks;
only SessionStart, ch. 33); the only compiled discipline is the §3 gate + output caps. The
repo has no `docs/` dir, no benchmarks, no showcase/CTF writeups (`examples.md` is teaching,
ch. 33). Effect is *asserted* by doctrine (`README.md:6-27`: context-rot, "tool driven
approach") and *defended* by ~470 Java + 172 Python self-written tests — ground truth on a
self-authored fixture, but self-referential: convincing engineering, not measurement. The
ceiling is structural: output is Ghidra state (names, types, comments, markup) plus LLM prose
— nothing compiles or runs recovered logic, no conformance loop exists, and in headless CLI
mode the temp project is `rmtree`'d (ch. 32) — no durable artifact outside a real Ghidra
project.

## Comparison with calxgloss

- **Overlap.** Both certify by *side effects*, not replies: ReVa's independent read-backs
  (`get-data` after `apply-data-type`, :447-461) rhyme with calxgloss's `FailedTest` carrying
  `expected_side_effects`, `expected/actual_api_calls`, `trace_divergence_index` and the
  "Silence never counts as a pass" comments
  (`crates/shared/calxgloss-types/src/verification.rs`). Both run real things under test:
  calxgloss's Wine harness executes the original DLL
  (`crates/pipeline/calxgloss-testgen/src/wine/harness.rs`); ReVa boots real Ghidra on a
  compiled fixture. Both persist work products (`ReVaDiffSessions/`; attempt branches,
  `docs/Calxgloss.md:18`).
- **calxgloss-only.** An FFI oracle that *executes the original binary* to judge the
  translation (`crates/pipeline/calxgloss-verify/src/engine.rs:117`); the compile→test→retry
  loop; a typed human review queue — `ReviewStatus{Queued,
  PendingReview,InProgress,Accepted,SendBack,PatchRequested,Blocked,Skipped,DoNotTranslate}`
  (`crates/shared/calxgloss-types/src/dashboard/types.rs:135-167`); per-run verdicts
  (`10-calxgloss-baseline.md`). ReVa has **no reviewer construct**: "accepted" = markup
  applied, or a human watched the chat.
- **ReVa-only (this layer).** The server-side read-before-write gate (§3); durable diff
  sessions with staged, checkpointed correlators and the under-analysis refusal (:285-293);
  hybrid-wait/single-flight job management (§1); ground-truth MCP tests of its own product.
- **Verdict.** ReVa certifies *tool correctness*, not analysis soundness — every assertion
  asks "did the tool give the right answer about the fixture?"; the analysis itself stays
  LLM+Ghidra, ungated. calxgloss certifies the opposite layer: its translation is judged by
  running the original DLL, yet its tool layer has nothing like workflow_correctness's
  paranoia about success-without-writing. Different failure modes — "tool lies to the agent"
  vs "translation misbehaves" — each blind to the other's.

**Steal-list.**
1. **Workflow-correctness invariants for calxgloss's evidence commands**: pin known-answer
   facts about a fixture DLL (call sites, strings) and assert per-command *answers*, never
   exit codes or shapes; the "reports success without writing would pass" pattern (:447-461)
   is the template for calxgloss-bdiff write-backs — verify via an independent reader.
2. **Durable diff sessions for calxgloss-bdiff**: mirror `DiffSessionManager` — reusable
   sessions, staged correlators checkpoint-saved per stage, `force`-vs-reuse semantics, and
   summary-level refusal when lenses would report near-zero changes
   (`DiffToolProvider.java:285-293`).
3. **The read-before-write gate** for any calxgloss surface letting an LLM write into Ghidra:
   copy the tracker (per-program, expiring, cleared on close) and pin its error text in tests
   (:3168-3213).
4. **Hybrid wait + single-flight for long jobs** (verify runs, testgen): short inline wait,
   then `jobId` + log cursor; concurrent callers attach, never stack
   (`AnalysisJobManager.java:151-170`).

## Sources

ReVa (`/tmp/opencode/cyberkaida-rea` @ `a2fcd946ec9c0bcf204da308365c16abb781dc53`):
`tools/project/ProjectToolProvider.java`; `plugin/{ConfigManager,RevaProgramManager}.java`;
`util/ProgramPersistenceUtil.java`, `util/VersionTrackingUtil.java`;
`services/{AnalysisJobManager,AnalysisJobRunner}.java`;
`tools/{decompiler,functions,data,comments,structure,script}/…ToolProvider.java`;
`tools/diff/{DiffToolProvider,DiffSessionManager}.java`; `ReVa/skills/deep-analysis/SKILL.md`;
`DEVELOPER.md`; `README.md:6-27`;
`tests/{conftest,test_workflow_correctness,test_e2e_workflow,test_diff_e2e,test_analysis_jobs_e2e,test_import_e2e}.py`
+ fixtures;
`src/test.slow/java/reva/tools/decompiler/DecompilerToolProviderIntegrationTest.java`;
`.github/workflows/{test-ghidra,test-headless}.yml`. Suite counts via greps; test bodies not
exhaustively read.

calxgloss: `crates/shared/calxgloss-types/src/verification.rs`, `dashboard/types.rs:135-167`;
`crates/pipeline/calxgloss-verify/src/engine.rs:117`;
`crates/pipeline/calxgloss-testgen/src/wine/harness.rs`; `docs/Calxgloss.md:18`;
`10-calxgloss-baseline.md`; sibling chs. 31-33.

# Interface

The human touchpoints of the reverse-engineering effort: where a run is started and steered, where units are reviewed, and where results are reported. This context owns the words for the CLI commands, the web review surface, and the reports — the operator's side of every word other contexts define underneath.

## Language

### Entry points and commands

**Live**:
The one process that runs the pipeline and the review server together — the only place pipeline control exists, and the recommended day-to-day entry point.

**Serve**:
The review server standing alone, without a pipeline. Control endpoints answer honestly that there is nothing to control rather than pretend otherwise.

**Auto**:
The command that reads the project's state and runs the next step.
_Avoid_: conflating it with the retry-strategy value "auto" — unrelated, same word

**Doctor**:
The self-check that loads the target through the analysis engine and reports what it saw — a machine-gateable result, not a description.

**Scan command**:
One of the fifteen manual entry points, one per evidence engine. Each uses the pipeline's schedule row for its engine. `--show` prints the engine's filed document without running the scan.

**Refresh cache**:
The request to re-read from the engine regardless of what the scan read cache holds.
_Avoid_: force-rescan — the ADR's older spelling of the same act

**Dashboard (command)**:
The terminal review surface — the same dashboard the web renders.
_Avoid_: as a verb for reviewing work

**BDiff (command)**:
The reviewer's view of a binary version change: which functions paired, which changed, which are new — stale documents reported as stale, never as empty success.

**Config (command)**:
The command that shows the configuration in force and which layer each value came from.

**Init**:
The command that writes the project's configuration template.

**Settings fold**:
The CLI's act of composing resolved settings into the pipeline's pass description. The fold itself belongs to this context. The words for the settings belong to Shared.

### Reviewing

**Review action**:
The reviewer's act on a unit — *accept*, *send back*, *request patch* — each with its git effect. The verdicts are Pipeline's words. The buttons are this context's.
_Avoid_: reject — the CLI subcommand that carried the old word; retire it from every surface

**Unknown record**:
The open question a unit carries for the reviewer to see: listed on the web unit detail and queue tallies and on the terminal dashboard, each with its severity, its question, and the evidence that would close it. Settled records are counted apart from open ones.

**Reviewer resolution**:
The reviewer's act on one open unknown record.
*Rules:*
- *resolve* it: the fact is established, with a stated reason.
- *dismiss* it: the question is judged irrelevant, and it stays visible as dismissed.
- *reopen* a settled one.
- It rides the existing review-action seam with the same conflict discipline.
- It is not a review verdict. It never accepts a unit, touches a branch, or changes a review status.
_Avoid_: resolve as a verdict — settling a question is not accepting a unit

**Reviewer intent**:
What the operator has decided and persisted: ordering, priorities, skips, overrides. It lives in its own records. It is never derived from artifacts, and no derived rebuild may edit it.

**Queue overlay**:
The reviewer's persisted manual ordering and priority. It only breaks ties between units at the same dependency depth.

**Skip set**:
The reviewer's persisted skips, shown and honored on every dashboard rebuild.

**Parked (status label)**:
The review status carried by a binary that classification marked do-not-translate. It is distinct from a reviewer's skip.
_Avoid_: Parked as a label — say *Do Not Translate*; *parking* is Evidence's classification act, not a status word

**Decompiler context**:
The reviewer's view of the unit's decompiled body, in the decompile dialect.
_Avoid_: "Ghidra Context" — the retired label for this surface

**Attempt comparison**:
The unit-detail view that diffs one attempt against another. It compares exactly the attempts that exist — branches plus patch records — and never invents any.

**LLM I/O log**:
The kept record of prompts and responses the reviewer can read and search. Old entries are honestly absent, not hidden.

**Honest degradation**:
The standing rule for every surface: a missing or corrupt artifact reads as *no artifact*. An unmeasured value renders blank, never zero.

### Running and steering

**Pipeline control**:
The run commands that only live accepts — pause, resume, stop, start, restart, cancel-current. When one does not fit the run's state, it is refused, and the refusal names the command rather than silently ignoring it.

**Cancel-current**:
Aborting the in-flight unit at the earliest safe point and recording the attempt as a cancelled failure.

**Focus**:
Moving one discovered binary to the front of the run with a single press.
_Avoid_: park (the route comments' third sense of the word) — parking is Evidence's act

**Scope controls**:
Steering what a run touches.
*Rules:*
- Which binaries are in, held, or skipped.
- Which functions are skipped or prioritized.
- The budgets that bound what the run consumes.

**Run request**:
The start/restart form's choices: which phase runs, against which targets, over which slice of units.

### Reporting

**Terminal dashboard**:
The text review board built from branch state and the persisted records. The web renders the same model.

**Unknown ledger**:
The per-target-binary statement the run close and the dashboard print: what was never established, at what severity, with the evidence that would have closed it — and what review already settled and what it deliberately dismissed, counted apart.

**Scenario status**:
The per-target-binary reading the review surfaces print beside the queue.
*Rules:*
- Every scenario a filed scenario document names appears: declared or not declared, captured or not captured, and what its verdict says — assessed pass, assessed fail naming each failed dimension, or unassessed.
- Every missing record renders as its honest negative, never as empty success.
- The shape rides the shared dashboard model. `ReviewDashboard.scenario_statuses` carries one entry per binary (`binary`, `scenarios`), each scenario its own row (`scenario`, `declared`, `captured`, `verdict`), and the verdict is encoded `unassessed`, `assessed_pass`, or `assessed_fail` with its `failed_dimensions`.
- It is target-binary-level evidence. It changes no unit's review status and blocks no accept on its own.

**Analytics on demand**:
Numbers computed at request time from the persisted logs. There are no stored rollups, because a second copy of the truth would drift.

**Persisted logs**:
The fault, token-usage, and prompt-strategy records analytics reads. Any count covers only the log's kept window, and that limit is stated rather than hidden.

**Phase bar**:
The progress strip over the master-plan phases. A phase with no backing data source renders as having no data, never as empty progress.

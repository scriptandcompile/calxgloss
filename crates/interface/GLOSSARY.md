# Interface

The human touchpoints of the reverse-engineering effort: where a run is started and steered, where units are reviewed, and where results are reported. This context owns the language of the CLI commands, the web review surface, and the reports — the operator's side of every word other contexts define underneath.

## Language

### Entry points and commands

**Live**:
The one process that runs the pipeline and the review server together — the only place pipeline control exists, and the recommended day-to-day entry point.

**Serve**:
The review server standing alone, without a pipeline; control endpoints answer honestly that there is nothing to control rather than pretend otherwise.

**Auto**:
The command that reads the project's state and runs the next step.
_Avoid_: conflating it with the retry-strategy value "auto" — unrelated, same word

**Doctor**:
The self-check that loads the target through the analysis engine and reports what it saw — a machine-gateable result, not a description.

**Scan command**:
One of the fifteen manual entry points, one per evidence engine, each riding the pipeline's schedule row for its engine; `--show` prints the engine's filed document without running the scan.

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
The CLI's act of composing resolved settings into the pipeline's pass description — the fold lives here; the settings themselves are Shared's.

### Reviewing

**Review action**:
The reviewer's act on a unit — *accept*, *send back*, *request patch* — each with its git effect. The verdicts are Pipeline's words; the buttons are this context's.
_Avoid_: reject — the CLI subcommand that carried the old word; retire it from every surface

**Reviewer intent**:
What the operator has decided and persisted — ordering, priorities, skips, overrides — held in its own records, never derived from artifacts, and never edited by any derived rebuild.

**Queue overlay**:
The reviewer's persisted manual ordering and priority; it only breaks ties between units at the same dependency depth.

**Skip set**:
The reviewer's persisted skips, shown and honored on every dashboard rebuild.

**Parked (status label)**:
The review status a classified do-not-translate binary carries, distinct from a reviewer's skip.
_Avoid_: Parked as a label — say *Do Not Translate*; *parking* is Evidence's classification act, not a status word

**Decompiler context**:
The reviewer's view of the unit's decompiled body, in the decompile dialect.
_Avoid_: "Ghidra Context" — the retired label for this surface

**Attempt comparison**:
The unit-detail view diffing one attempt against another, over exactly the attempts that exist — branches plus patch records, never anything invented.

**LLM I/O log**:
The kept record of prompts and responses the reviewer can read and search; old entries are honestly absent, not hidden.

**Honest degradation**:
The standing rule for every surface: a missing or corrupt artifact reads as *no artifact*, an unmeasured value renders blank, never zero.

### Running and steering

**Pipeline control**:
The live-only run commands — pause, resume, stop, start, restart, cancel-current — refused with a name rather than silently ignored when they don't fit the run's state.

**Cancel-current**:
Aborting the in-flight unit at the earliest safe point and recording the attempt as a cancelled failure.

**Focus**:
Pulling one discovered binary to the front of the run with a single press.
_Avoid_: park (the route comments' third sense of the word) — parking is Evidence's act

**Scope controls**:
Steering what a run touches — which binaries are in, held, or skipped; which functions are skipped or prioritized; and the budgets that bound what it consumes.

**Run request**:
The start/restart form's choices: which phase runs, against which targets, over which slice of units.

### Reporting

**Terminal dashboard**:
The text review board built from branch state plus the persisted records — the same model the web renders.

**Analytics on demand**:
Numbers computed at request time from the persisted logs; no stored rollups — a second copy of the truth would drift.

**Persisted logs**:
The fault, token-usage, and prompt-strategy records analytics reads; any count covers only the log's kept window, and that limit is stated rather than hidden.

**Phase bar**:
The progress strip over the master-plan phases; a phase with no backing data source renders as having no data, never as empty progress.

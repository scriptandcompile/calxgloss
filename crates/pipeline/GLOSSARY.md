# Pipeline

The translation loop of the reverse-engineering effort: every unit of work is translated from decompiled code, verified against the original binary's behavior, and committed. This context owns the language of doing that work — units, attempts, verdicts, verification, and substitution.

## Language

### Units and attempts

**Unit of work**:
One function or struct definition produced by the reverse-engineering effort, delivered as one commit. Shortened to *unit*.
_Avoid_: work unit, task, job

**Unit key**:
A unit's identity string: `{file}/{function}`, where `{file}` is the binary identity. Carried verbatim through API payloads, review records, and artifact paths.

**Attempt**:
One try at a unit; each attempt is a fresh translation. Attempts are numbered, and the number rides the attempt branch name.
_Avoid_: version, revision

### Targets and workspace

**Target**:
The software being reverse-engineered as a whole.
_Avoid_: subject, binary

**Target binary**:
One individual EXE or DLL under analysis.
_Avoid_: bare "target"

**Binary identity**:
A target binary's filename verbatim, extension included — `game_logic.dll`, `eqgame.exe`. The same string, with no normalization, names that binary across branches, unit keys, artifacts, records, and UI display. Deriving *Rust identifiers* from a binary name (crate and shim file names) takes the stem — that is naming, not identity.
_Avoid_: stem, extension-stripped name (as an identity)

**Paused target binary**:
A target binary the operator has held out of the queue while the run keeps working on the rest — steering, not lifecycle. The binary stays in scope; its units simply never start being translated, and an in-flight hold takes effect at the next unit boundary. *Pause* on its own is the run-wide lifecycle control; a binary is *held* / *paused*.
_Avoid_: stopped binary, suspended binary

**Workspace**:
The working directory of one reverse-engineering effort: it holds the translated Rust, the record of the effort (`re/`), scratch, and the git repo that makes every unit restorable.
_Avoid_: repo_dir, workspace_root, output_dir

### Run and steering

**Run**:
One continuous working session of the pipeline, start to stop. Lifecycle controls act on the run; steering acts within it and takes effect at a **unit boundary** — where one unit's work ends and the next begins.
_Avoid_: session, process

**Operator**:
The human who starts, stops, and steers the run, and whose overrides outrank the system's own judgments.

**Queue**:
The run's ordered waiting list of units. The call graph sets the natural order; steering edits it.

**Priority**:
An operator-chosen elevation of a unit above the natural work order, in two qualified surfaces: *scope priority* orders the run's work itself; *queue priority* (the reviewer's overlay elevation) only breaks ties between units at the same dependency depth.
_Avoid_: bare priority where the two could be confused

**Skip**:
The operator's act of holding a unit out of translation work while the run goes on.
_Avoid_: park — that is a target binary's classification act, owned by Evidence; pause / hold — target-binary steering within the run

**Override**:
The operator's standing decision that outranks the system's own judgment — a classification override outranks PE facts and name tables.

### Verification

**Verification**:
The compile-and-baseline-test loop a unit must pass before review.
_Avoid_: validation, checking

**Verified**:
A unit that compiles and passes its baseline tests.

**Baseline test**:
A test capturing the original binary's observable behavior, run against the original implementation as ground truth.

**Scratch project**:
A sandboxed throwaway build project that each verification compiles and tests in.

**Cross-platform suite**:
The CI suites that prove translated code behaves identically on Windows, macOS, and Linux.
_Avoid_: verification tests

### Substitution

**Stub**:
A set of functions carrying the original signatures that return default values without performing the real action — used to mock functionality while testing other parts of the code, or on paths where side effects must be avoided but the data shape is needed.

**FFI binding**:
A generated binding that calls the original DLL so baseline tests can capture ground truth.
_Avoid_: FFI stub

**Restitching**:
Replacing a stub or FFI binding with verified Rust, one unit at a time.

### Review

**Accept**:
The review verdict that admits a unit into the codebase; its git effect is a merge.
_Avoid_: merge (as a verdict), approve

**Send back**:
The review verdict that returns a unit for a fresh attempt.
_Avoid_: reject, work-on-it

**Request patch**:
The review verdict that routes a unit to a human-filed issue instead of another automated attempt.
_Avoid_: reject

**Justification**:
What every unit presents to the reviewer: what and how it was translated, evidence of correctness, attempt history, and confidence.

**Known gaps**:
The limitations of a translation that its unit admits up front, presented alongside the justification.

**Unit confidence**:
The reviewer-facing trust in a unit, on a 0.0–1.0 scale.
_Avoid_: bare "confidence" — evidence confidence is a different scale, owned by Evidence

### Scan scheduling

**Descriptor row**:
One evidence engine's entry in the pipeline's pre-translation scan schedule. The schedule table's words — the table itself, its fan-out, a cached-hit short-circuit — are Pipeline's; what a row *means* — scan row name, per-binary document, facets — is Evidence's.

### Prompting

**Context tier**:
One of the five scopes of decompiled context handed to the LLM, from *Signature* (name and signature only) up to full module context.
_Avoid_: prompt tier, bare "tier"

**Retry strategy**:
How a failed attempt is re-attempted: compile fix, test fix, escalation of context, or edge-case fix.
_Avoid_: bare "strategy" — classification strategy belongs to Evidence

**Evidence bundle**:
One unit's gathered evidence over the evidence engines' per-binary documents: the single render input of the bundle-fed prompt templates. The bundle, not rendered strings, crosses the seam; missing evidence means sections omitted, never a failed prompt.

### History

**Archive**:
The resting place of unmerged work branches: renamed away from the live refs, never deleted — nothing is discarded.
_Avoid_: deletion

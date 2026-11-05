# Pipeline

The translation loop of the reverse-engineering effort: every unit of work is translated from decompiled code, verified against the original binary's behavior, and committed. This context owns the language of doing that work — units, attempts, verdicts, verification, and substitution.

## Language

### Units and attempts

**Unit of work**:
One function or struct definition produced by the reverse-engineering effort, delivered as one commit. Shortened to *unit*.
_Avoid_: work unit, task, job

**Unit key**:
A unit's identity string: `{file}/{function}`, where `{file}` is the binary identity. The key is passed through unchanged in API payloads, review records, and artifact paths.

**Attempt**:
One try at a unit; each attempt is a fresh translation. Attempts are numbered, and the number appears in the attempt branch's name.
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
A target binary the operator has held out of the queue while the run keeps working on the rest. This is steering, not lifecycle. The binary stays in scope; its units simply never start being translated, and a hold that starts mid-flight takes effect at the next unit boundary. *Pause* on its own is the run-wide lifecycle control; a binary is *held* / *paused*.
_Avoid_: stopped binary, suspended binary

**Workspace**:
The working directory of one reverse-engineering effort: it holds the translated Rust, the record of the effort (`re/`), scratch, and the git repo that makes every unit restorable.
_Avoid_: repo_dir, workspace_root, output_dir

### Run and steering

**Run**:
One continuous working session of the pipeline, from start to stop. Lifecycle controls act on the whole run. Steering acts inside the run and takes effect at a **unit boundary** — the point where one unit's work ends and the next begins.
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

**Scenario contract**:
The closed declaration of how one EXE target binary is to be run for one scenario: working dir, explicit env, argv, scripted interactions (timed input at an at-offset, resize, signal — sensitive inputs stored as byte-count placeholders), terminal geometry, filesystem observation paths, idle window and max run duration, output caps, versioned normalization rules, and a finalization grace. Interface owns its authorship; pipeline and testgen only read the filed document (`re/scenarios/<binary identity>.json`, one per binary).
_Avoid_: scenario run — that is the execution; config

**Scenario run**:
One child execution of a target program under a scenario contract. Never the run-wide *Run*: a scenario run is launched, bounded, and finalized on its own, while the run keeps working elsewhere.
_Avoid_: Run, session, process (bare)

**Scenario capture**:
The filed document of what one *scenario run* was observed to do: an optional block per dimension — terminal output chunks under the cap with its truncation mark, the acknowledged interaction offsets, the exit disposition from the closed set with its code when one exists, the before/after classification of the declared observation paths (created / deleted / modified / unchanged, each with size, whole-file sha256, and 4 KiB block digests — files are weighed by content, never by existence), and the process sample. Bounded evidence, never a claim: a capture that hit its cap never states more than it saw. It files at `re/scenarios/captures/<binary identity>-<scenario key>.json` — exactly one current capture per scenario name, a re-capture replacing the previous document outright.
_Avoid_: baseline — that is the harness's ground-truth capture; capture event log — that is the *reference-app run*'s record; transcript

**Pairing rule**:
The rule that says which two *scenario captures* may be compared: only captures whose pairing stamps agree — the sha256 of the program bytes the run executed and the Wine version that ran them — pair for comparison. A digest mismatch is a stated mismatch, never silent: the CLI names both digests before a re-capture files over the current document.
_Avoid_: fingerprint — that is PE identity; hash (bare)

### Verification

**Verification**:
The compile-and-baseline-test loop a unit must pass before review.
_Avoid_: validation, checking

**Verified**:
A unit that compiles and passes its baseline tests.

**Baseline test**:
A test capturing the original binary's observable behavior, run against the original implementation as ground truth.

**Mined input**:
An argument vector a real caller actually passed to an export entry, captured there and replayed against the original binary to fold a case into the filed baseline suite. Call testgen's inputs today are signature-derived guesses; mining is additive — the invented suite stays exactly as it is.

**Captured call entry**:
The shared record of one such call as it really arrived at an export entry: binary identity, export name, capture lane (baseline-run hook, reference-app run, or minidump), the run event or crash a reviewer can trace it back to, and ordered argument descriptors — scalars carried with the harness's own encode tags, pointer-like arguments with captured bytes, captured size, and a truncation flag. Float arguments cannot enter this vocabulary; such entries are refused with a named reason, never mis-encoded. The record proves a real caller passed the values; only the replay against the original is authority.

**Case origin**:
The stamp every baseline case carries on how it came to exist: *generated* (testgen invented it — the read default for documents saved before the stamp existed) or *mined* from a captured call entry, naming its capture id and event sequence, or its dump digest and faulting thread. The strongest claim a passing case supports is read off the origin at read time, never stored beside it — there is no second field that can rot against the first.

**Record-and-replay fold**:
The testgen path that turns a *capture event log* into filed baseline cases: each captured call entry whose argument vector the export's signature can hold is replayed against the original binary, and what the replay observed is filed as a *mined input*'s case. Authority rests on the replay, never on the capture. An entry the signature cannot hold is refused with a named reason and files a `capture_refused` unknown record; a replay that faults files a *crash-reproduction record* and no case. A mined case dedups against the generated suite on exact input-vector equality — the collision keeps the mined origin — and mined cases stand outside the per-function generation cap: the cap bounds invention, and captured events are evidence.

**Minidump lane**:
The testgen path that folds Windows crash dumps through the *record-and-replay fold*. A dump proves a call happened but never which export received it, so the lane claims a *captured call entry* only where both halves line up: the dump's module matches the target by *binary identity*, and the fault address lands exactly on a listed export entry — a near miss or an identity mismatch claims nothing and is stated as an unclaimed mapping candidate. The faulting thread's machine context plus the x64 calling convention reconstruct the argument vector, pointer targets read from the dump's captured memory under the *capture bound*; the dump's content digest serves as the capture id and the faulting thread's id as the event sequence. ELF cores are out of scope.

**Capture event log**:
One capture session's (or minidump's) captured call entries stored on disk as capture order, capture id, and — when the capture ran out of event budget — a stated dropped-event count. Truncation is stated, never silent; the count folds into the ingest report beside the refusals.

**Entry hook (entry-recording trampoline)**:
The generated harness's mechanism for recording calls at an export entry: an armed baseline run patches the target's export address table right after the load, so every later `GetProcAddress` hands back a recording trampoline in place of the real entry. The trampoline records each integer argument at its incoming slot and probes each pointer argument under the *capture bound* — bytes only from verified committed memory — then tail-jumps to the real entry, so the call's return value is untouched. Because the baseline harness maps the target without binding its imports, the arm pass binds the import address table first, and an unresolvable import leaves the hooks not armed at all, naming why; an arm that does not verify through `GetProcAddress` restores the original entry. Floats sit outside the recording vocabulary, so a signature with a float argument is never armed. x86-64 only; elsewhere the run stands uninstrumented with a coverage note. Distinct from the *IAT interposer*: the interposer watches calls the target makes, an entry hook watches calls the target receives.

**Entry event**:
One call as it arrived at an *entry hook*, recorded by the harness as raw wire entries — integer slots with their encode tags, pointer probes with their bytes and observed size. The runner, never the harness, gives the event its identity — capture id `baseline-hook:{binary}:{function}` and a per-export event sequence — and numbers the events into the *capture event log*; an event carrying an argument the runner cannot name leaves the log entirely and rides a note, never a partial vector.

**Recording proxy**:
A generated stand-in DLL wearing the target's binary identity — its file name and its full export name set — so a caller loads it believing it found the real target. Each export slot is a forwarding shim: it records the arriving argument vector as an *entry event* (integer slots with their encode tags, pointer probes under the *capture bound*), then tail-jumps to the same-named export of the real module sitting beside it, leaving the return value untouched. The proxy needs no cooperation from caller or target — it records calls the target receives from the outside, where an *entry hook* can only watch calls the harness's own run makes. x86-64 only; for a target built for any other architecture generation admits defeat with a coverage note instead of producing a proxy — never faked events.

**Reference-app run**:
A capture session in which a caller outside the harness reaches the target — the reference application of the P23 parent's real-caller quest — and the calls that arrive are recorded through a *recording proxy*. Its *captured call entries* carry the `reference_app` lane and the capture id `reference-app:{binary}`: the lane states what it proves — the argument vectors came from a real caller, but which case prompted them is unknown — and only the *record-and-replay fold*'s replay makes a filed case authoritative.

**Capture budget**:
One of the three caps — max events, duration, event-log size — that stop a *reference-app run* from outrunning the operator's intent; an unbudgeted duration defaults to 300 seconds. Whichever budget fires, the run stops through one signal path and the truncation is stated in the *capture event log*'s notes and the command's count report — never silently. The size budget additionally trims trailing entries until the written document, annotations included, fits the cap, counting every trim as a drop beside the drops the run itself counted.

**Ownership token**:
A launched process's identity — its pid plus the OS start stamp behind that pid — bound at launch and rechecked before every termination signal. A PID that no longer answers to the identity it was bound to (the process exited, or a stranger reused the number) is signaled not at all: owned-process discipline is never a bare-PID kill, and it prefigures the scenario contract P24 makes of it.

**Instrumented run dir**:
The directory a *reference-app run* stands the target in: the real module parked inside under its real file name, and the *recording proxy* wearing the target's binary identity in front of it, with the run dir on the launched application's DLL search path. Whatever how the run ends — finished, budget-stopped, errored — the run dir's finalize takes the proxy out and puts the real module back under its own identity, the finished *capture event log* staying beside it: the application tree can never keep resolving through a recorder.

**Capture bound**:
The one shared protocol constant — 64 KiB — that caps how far a capture's pointer read may go, honored at both ends of the *record-and-replay fold*: at record time it sizes a captured pointer descriptor (anything past it is stored truncated, and the descriptor says so), and at replay time it bounds what a descriptor may claim — a pointer whose bytes fall short of the size it observed, or that claims more than the bound can have delivered, is refused as a truncation naming the bound, never silently reconstructed whole. A pointer descriptor with no captured bytes at all is the one shape no replay can honor: an *unmaterializable pointer*, refused by name.

**Crash-reproduction record**:
The unknown record a *replay seam* files when a replay of a *mined input* faults, naming the capture and the event whose inputs faulted at the original binary — for a *capture event log*, its capture id and event sequence; for the *minidump lane*, the dump digest as capture id and the faulting thread's id as the event sequence. The capture is trusted to name inputs, never to promise the target survived: the fault is established by the replay, and no baseline case is filed for that entry.

**Ordered API-call trace**:
The sequence of API names one baseline case recorded, in call order — deliberately nothing else: no arguments, counts, or thread attribution. A missing or empty trace reads as *unassessed*, never as "the target called nothing".

**IAT interposer**:
The generated harness's mechanism for observing the original's API calls: every slot in the target's import address table is replaced — scoped API names with a recording trampoline that tail-jumps to the real routine, all other imports with the real routines themselves. x86-64 only; elsewhere it degrades to running unhooked.

**In-scope API roster**:
The API set one unit is scoped to: every API the apidetect document records for its function — used directly or reached through callees — de-duplicated in first-seen order. It scopes the fold of captured traces onto the generated suite's cases; no document means no roster, and the trace dimension stays unassessed.

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
The limitations of a translation. The unit states them up front, alongside the justification.

**Unit confidence**:
The reviewer-facing trust in a unit, on a 0.0–1.0 scale.
_Avoid_: bare "confidence" — evidence confidence is a different scale, owned by Evidence

### Scan scheduling

**Descriptor row**:
One evidence engine's entry in the pipeline's pre-translation scan schedule. The schedule-table words belong to Pipeline: the table itself, its fan-out, and the cached-hit short-circuit. The words for what a row *means* belong to Evidence: scan row name, per-binary document, facets.

### Prompting

**Context tier**:
One of the five scopes of decompiled context handed to the LLM, from *Signature* (name and signature only) up to full module context.
_Avoid_: prompt tier, bare "tier"

**Retry strategy**:
How a failed attempt is re-attempted: compile fix, test fix, escalation of context, or edge-case fix.
_Avoid_: bare "strategy" — classification strategy belongs to Evidence

**Evidence bundle**:
One unit's gathered evidence, built from the evidence engines' per-binary documents. It is the single input rendered into the bundle-fed prompt templates. The bundle itself crosses the seam — not already-rendered strings. When evidence is missing, its sections are simply left out; a prompt never fails.

### Unknown residue

**Unknown record**:
A gap the batch admitted from data already on disk, shaped as the shared record at the point of admission, by one of four producers: the coverage fold (a facet that fell short), the held capability report (a family declared unavailable, against units whose retry posture re-asks it), the verification signal (a unit that ran zero baseline cases; an export no filed baseline document covers), and the ladder's own pruned escalate and refused tier step. A record states what is not known — never what to do about it.

**Unknown ledger**:
The pipeline's own filing of what a batch admitted: one document per target binary, in deterministic scan order; each batch's filing replaces the last.
_Avoid_: audit ledger — the printed report is Interface's word

**Reviewer resolution**:
The reviewer's recorded answer to an unknown record. Pipeline only reads it: *resolved* and *dismissed* records fold out of the fed prompts, a reopened one rides back in. Settling a question is Interface's act.

### History

**Archive**:
The resting place of unmerged work branches: renamed away from the live refs, never deleted — nothing is discarded.
_Avoid_: deletion

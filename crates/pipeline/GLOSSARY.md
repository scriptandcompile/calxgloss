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
One try at a unit. Each attempt is a fresh translation. Attempts are numbered, and the number appears in the attempt branch's name.
_Avoid_: version, revision

### Targets and workspace

**Target**:
The software being reverse-engineered as a whole.
_Avoid_: subject, binary

**Target binary**:
One individual EXE or DLL under analysis.
_Avoid_: bare "target"

**Binary identity**:
A target binary's filename verbatim, extension included — `game_logic.dll`, `eqgame.exe`.
*Rules:*
- The same string, with no normalization, names that binary across branches, unit keys, artifacts, records, and UI display.
- Deriving *Rust identifiers* from a binary name (crate and shim file names) takes the stem — that is naming, not identity.
_Avoid_: stem, extension-stripped name (as an identity)

**Paused target binary**:
A target binary the operator has held out of the queue while the run keeps working on the rest. This is steering, not lifecycle.
*Rules:*
- The binary stays in scope. Its units simply never start being translated.
- A hold that starts mid-flight takes effect at the next unit boundary.
- *Pause* on its own is the run-wide lifecycle control. A binary is *held* / *paused*.
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
The run's ordered waiting list of units. The call graph sets the natural order. Steering edits it.

**Priority**:
An operator-chosen elevation of a unit above the natural work order, in two qualified surfaces.
*Rules:*
- *scope priority* orders the run's work itself.
- *queue priority* (the reviewer's overlay elevation) only breaks ties between units at the same dependency depth.
_Avoid_: bare priority where the two could be confused

**Skip**:
The operator's act of holding a unit out of translation work while the run goes on.
_Avoid_: park — that is a target binary's classification act, owned by Evidence; pause / hold — target-binary steering within the run

**Unit gate**:
The one check both batch passes run at every unit boundary: it reads the operator's four steering controls in a fixed order — stop signal, token budget, paused target binary, pipeline control — and names the first control that holds.
*Rules:*
- The fixed order decides precedence when several controls hold at one boundary; the earliest named wins.
- A paused target binary outranks a pipeline-control halt, so the batch returns instead of waiting in a run-level pause.
- The named reason and the remaining unit count go into the boundary log line.
_Avoid_: gate check, steering check

**Override**:
The operator's standing decision that outranks the system's own judgment — a classification override outranks PE facts and name tables.

**Scenario contract**:
The closed declaration of how one EXE target binary is to be run for one scenario, filed at `re/scenarios/<binary identity>.json`, one per binary.
*Rules:*
- Declares: working dir, explicit env, argv, scripted interactions (timed input at an at-offset, resize, signal — sensitive inputs stored as byte-count placeholders), terminal geometry, filesystem observation paths, idle window and max run duration, output caps, versioned normalization rules, and a finalization grace.
- Interface owns its authorship. Pipeline and testgen only read the filed document.
_Avoid_: scenario run — that is the execution; config

**Scenario run**:
One child execution of a target program under a scenario contract. Never the run-wide *Run*: a scenario run is launched, bounded, and finalized on its own, while the run keeps working elsewhere.
_Avoid_: Run, session, process (bare)

**Scenario capture**:
The filed record of what one *scenario run* was observed to do — bounded evidence, never a claim. Exactly one current capture per scenario name at `re/scenarios/captures/<binary identity>-<scenario key>.json`. A re-capture replaces the previous document outright.
*Rules:*
- One optional block per dimension: terminal, interaction, exit, filesystem, process. A capture that hit its cap never states more than it saw.
- Terminal: output chunks under the cap with its truncation mark, beside them the *terminal geometry* — the opening geometry measured off the host PTY and the *rendered states* read back off the live terminal after each resize. The terminal dimension has content, not just bytes.
- Interaction: every interaction delivered while the run stood is acknowledged at its at-offset. A placeholder input counts once its *typed secret* stood at that offset.
- Exit: the disposition from the closed set, with its code when one exists and its *finalization outcome* when a window closed the run.
- Filesystem: before/after classification of the declared observation paths (created / deleted / modified / unchanged), each with size, whole-file sha256, and 4 KiB block digests — files are weighed by content, never by existence.
- Process: the launch sample plus the ones swept from the run's standing process tree, so a program that spawns children shows them in the record.
_Avoid_: baseline — that is the harness's ground-truth capture; capture event log — that is the *reference-app run*'s record; transcript

**Scenario replay**:
A *scenario run* of a declared *scenario contract* against any program the operator *names by path*. The original standing in the target dir is not the only option — a restitched build checked out on an attempt branch is the point.
*Rules:*
- Its capture files beside the original's at `re/scenarios/captures/<binary identity>-<scenario key>-replay.json`. Exactly one current replay per (binary, scenario name). A re-replay replaces the previous document outright.
- The replay depends on no whole-EXE build machinery. A path is the only thing named, and it shares the capture's run machinery whole.
- In the operator chain declare → capture → replay → compare, a *scenario compare* with neither side named pairs the filed original on the left with the filed replay on the right.
- The *pairing rule* is stated beside both captures, never assumed: identical program bytes pair, differing bytes say what paired against what.
_Avoid_: re-capture — that replaces a capture of the same program; regression run

**Scenario verdict**:
The judgment of a pair of *scenario captures* under one *scenario contract*, filed as a digest-bearing document at `re/scenarios/verdicts/<binary identity>-<scenario key>.json`. One current verdict per pair. A re-compare replaces the previous document outright.
*Rules:*
- Each of the five dimensions — terminal, interaction, exit, filesystem, process — reads assessed pass, assessed fail, or unassessed.
- An absent or empty block reads unassessed: silence is never mistaken for a pass and never fails by silence.
- Every failure names its divergent field, with both sides beside it.
- Only the contract's declared, versioned normalization rules ever equalize, and the verdict states the version it judged under.
- Fired caps, mismatched Wine versions, and every file outside the declared observation paths ride as stated residual unknowns. Any one of them blocks a complete-equivalence claim — a bounded pair never claims more than it saw.
- The comparator is pure record logic: two capture documents and the contract in, the verdict out — it launches nothing and needs no Wine.
- Its content digest (sha256 over the document's own JSON with the digest field blanked) is how P25's receipts and P26's ledger cite it, and the verdict cites the two captures it judged by theirs.
_Avoid_: diff — divergences are named fields, not a byte dump; judgment, comparison report

**Typed secret**:
The run-time typed form of one byte-count placeholder of a *scenario contract*, alive only for one *scenario run*.
*Rules:*
- It must match both the offset and the count its placeholder filed. Any disagreement is refused before anything launches.
- It never reaches a record tree. The run types it echo-less and the guest console acknowledges it by byte count alone.
_Avoid_: password; credential — that is the credential slices' word (P24.7)

**Rendered state**:
A *terminal geometry* read back off the live host PTY after a scripted resize stood acknowledged — proof the geometry landed on the rendering, not a restatement of the declared interaction. The opening geometry is read the same way: measured, never declared.
_Avoid_: window size; resolution

**Pairing rule**:
The rule saying which two *scenario captures* may be compared.
*Rules:*
- The normalization stamp decides pairing: two captures pair only when both name the *normalization rules* version their captures ran under, and the versions agree.
- An unstamped or cross-version pair is refused by name, never silently bridged.
- Program bytes and Wine travel beside the pair rather than gating it: comparing original against restitched bytes is the point, so differing program digests pair while the verdict carries both pairing blocks.
- A mismatching Wine version rides as a stated residual unknown that blocks complete-equivalence claims.
- At the filing point the CLI names both program digests before a re-capture files over the current document — a digest mismatch is stated, never silent.
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
An argument vector a real caller actually passed to an export entry, captured there and replayed against the original binary to fold a case into the filed baseline suite. Call testgen's inputs today are signature-derived guesses. Mining is additive — the invented suite stays exactly as it is.

**Captured call entry**:
The shared record of one such call as it really arrived at an export entry.
*Rules:*
- Carries binary identity, export name, capture lane (baseline-run hook, reference-app run, or minidump), the run event or crash a reviewer can trace it back to, and ordered argument descriptors.
- Scalars are carried with the harness's own encode tags. Pointer-like arguments carry captured bytes, captured size, and a truncation flag.
- Float arguments cannot enter this vocabulary. Such entries are refused with a named reason, never mis-encoded.
- The record proves a real caller passed the values. Only the replay against the original is authority.

**Case origin**:
The stamp every baseline case carries on how it came to exist.
*Rules:*
- *generated*: testgen invented it — the read default for documents saved before the stamp existed.
- *mined*: from a captured call entry, naming its capture id and event sequence, or its dump digest and faulting thread.
- The strongest claim a passing case supports is read off the origin at read time, never stored beside it — there is no second field that can rot against the first.

**Record-and-replay fold**:
The testgen path that turns a *capture event log* into filed baseline cases. Authority rests on the replay, never on the capture.
*Rules:*
- Each captured call entry whose argument vector the export's signature can hold is replayed against the original binary, and what the replay observed is filed as a *mined input*'s case.
- An entry the signature cannot hold is refused with a named reason and files a `capture_refused` unknown record.
- A replay that faults files a *crash-reproduction record* and no case.
- A mined case dedups against the generated suite on exact input-vector equality, and the collision keeps the mined origin.
- Mined cases stand outside the per-function generation cap: the cap bounds invention, and captured events are evidence.

**Minidump lane**:
The testgen path that folds Windows crash dumps through the *record-and-replay fold*.
*Rules:*
- A dump proves a call happened but never which export received it, so the lane claims a *captured call entry* only where both halves line up: the dump's module matches the target by *binary identity*, and the fault address lands exactly on a listed export entry.
- A near miss or an identity mismatch claims nothing and is stated as an unclaimed mapping candidate.
- The faulting thread's machine context plus the x64 calling convention reconstruct the argument vector, with pointer targets read from the dump's captured memory under the *capture bound*.
- The dump's content digest serves as the capture id and the faulting thread's id as the event sequence.
- ELF cores are out of scope.

**Capture event log**:
One capture session's (or minidump's) captured call entries stored on disk as capture order, capture id, and — when the capture ran out of event budget — a stated dropped-event count. Truncation is stated, never silent. The count folds into the ingest report beside the refusals.

**Entry hook (entry-recording trampoline)**:
The generated harness's mechanism for recording calls at an export entry. An entry hook watches the calls the target receives. The *IAT interposer* watches the calls the target makes.
*Rules:*
- An armed baseline run patches the target's export address table right after the load, so every later `GetProcAddress` hands back a recording trampoline in place of the real entry.
- The trampoline records each integer argument at its incoming slot and probes each pointer argument under the *capture bound* — bytes only from verified committed memory. It then tail-jumps to the real entry, so the call's return value is untouched.
- Because the baseline harness maps the target without binding its imports, the arm pass binds the import address table first. An unresolvable import leaves the hooks not armed at all, naming why. An arm that does not verify through `GetProcAddress` restores the original entry.
- Floats sit outside the recording vocabulary, so a signature with a float argument is never armed.
- x86-64 only. Elsewhere the run stands uninstrumented with a coverage note.

**Entry event**:
One call as it arrived at an *entry hook*, recorded by the harness as raw wire entries — integer slots with their encode tags, pointer probes with their bytes and observed size.
*Rules:*
- The runner, never the harness, gives the event its identity: capture id `baseline-hook:{binary}:{function}` and a per-export event sequence.
- The runner numbers the events into the *capture event log*.
- An event carrying an argument the runner cannot name leaves the log entirely and rides a note, never a partial vector.

**Recording proxy**:
A generated stand-in DLL wearing the target's binary identity — its file name and its full export name set — so a caller loads it believing it found the real target. The proxy needs no cooperation from caller or target. It records calls the target receives from the outside, where an *entry hook* can only watch calls the harness's own run makes.
*Rules:*
- Each export slot is a forwarding shim: it records the arriving argument vector as an *entry event* (integer slots with their encode tags, pointer probes under the *capture bound*), then tail-jumps to the same-named export of the real module sitting beside it, leaving the return value untouched.
- x86-64 only. For a target built for any other architecture, generation admits defeat with a coverage note instead of producing a proxy — never faked events.

**Reference-app run**:
A capture session in which a caller outside the harness reaches the target — the reference application of the P23 parent's real-caller quest. The calls that arrive are recorded through a *recording proxy*.
*Rules:*
- Its *captured call entries* carry the `reference_app` lane and the capture id `reference-app:{binary}`.
- The lane states what it proves: the argument vectors came from a real caller, but which case prompted them is unknown.
- Only the *record-and-replay fold*'s replay makes a filed case authoritative.

**Capture budget**:
One of the three caps — max events, duration, event-log size — that stop a *reference-app run* from outrunning the operator's intent. An unbudgeted duration defaults to 300 seconds.
*Rules:*
- Whichever budget fires, the run stops through one signal path, and the truncation is stated in the *capture event log*'s notes and the command's count report — never silently.
- The size budget additionally trims trailing entries until the written document, annotations included, fits the cap, counting every trim as a drop beside the drops the run itself counted.

**Ownership token**:
A launched process's identity — its pid plus the OS start stamp behind that pid — bound at launch and rechecked before every termination signal.
*Rules:*
- A PID that no longer answers to the identity it was bound to (the process exited, or a stranger reused the number) is signaled not at all.
- Owned-process discipline is never a bare-PID kill. It prefigures the scenario contract P24 makes of it.

**Instrumented run dir**:
The directory a *reference-app run* stands the target in: the real module parked inside under its real file name, and the *recording proxy* wearing the target's binary identity in front of it, with the run dir on the launched application's DLL search path.
*Rules:*
- However the run ends — finished, budget-stopped, errored — the run dir's finalize takes the proxy out and puts the real module back under its own identity, the finished *capture event log* staying beside it. The application tree can never keep resolving through a recorder.

**Capture bound**:
The one shared protocol constant — 64 KiB — that caps how far a capture's pointer read may go, honored at both ends of the *record-and-replay fold*.
*Rules:*
- At record time it sizes a captured pointer descriptor. Anything past it is stored truncated, and the descriptor says so.
- At replay time it bounds what a descriptor may claim. A pointer whose bytes fall short of the size it observed, or that claims more than the bound can have delivered, is refused as a truncation naming the bound, never silently reconstructed whole.
- A pointer descriptor with no captured bytes at all is the one shape no replay can honor: an *unmaterializable pointer*, refused by name.

**Crash-reproduction record**:
The unknown record a *replay seam* files when a replay of a *mined input* faults, naming the capture and the event whose inputs faulted at the original binary. The capture is trusted to name inputs, never to promise the target survived: the fault is established by the replay, and no baseline case is filed for that entry.
*Rules:*
- For a *capture event log*, it names the capture id and event sequence.
- For the *minidump lane*, it names the dump digest as capture id and the faulting thread's id as the event sequence.

**Ordered API-call trace**:
The sequence of API names one baseline case recorded, in call order — deliberately nothing else: no arguments, counts, or thread attribution. A missing or empty trace reads as *unassessed*, never as "the target called nothing".

**IAT interposer**:
The generated harness's mechanism for observing the original's API calls: every slot in the target's import address table is replaced — scoped API names with a recording trampoline that tail-jumps to the real routine, all other imports with the real routines themselves. x86-64 only. Elsewhere it degrades to running unhooked.

**In-scope API roster**:
The API set one unit is scoped to: every API the apidetect document records for its function — used directly or reached through callees — de-duplicated in first-seen order. It scopes the fold of captured traces onto the generated suite's cases. No document means no roster, and the trace dimension stays unassessed.

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
The review verdict that admits a unit into the codebase. Its git effect is a merge.
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
One unit's gathered evidence, built from the evidence engines' per-binary documents. It is the single input rendered into the bundle-fed prompt templates. The bundle itself crosses the seam — not already-rendered strings. When evidence is missing, its sections are simply left out. A prompt never fails.

### Unknown residue

**Unknown record**:
A gap the batch admitted from data already on disk, filed as a shared record at the point of admission. A record states what is not known — never what to do about it.
*Rules:*
- Four producers: the coverage fold (a facet that fell short), the held capability report (a family declared unavailable, against units whose retry posture re-asks it), the verification signal (a unit that ran zero baseline cases, or an export no filed baseline document covers), and the ladder's own pruned escalate and refused tier step.

**Unknown ledger**:
The pipeline's own filing of what a batch admitted: one document per target binary, in deterministic scan order. Each batch's filing replaces the last.
_Avoid_: audit ledger — the printed report is Interface's word

**Reviewer resolution**:
The reviewer's recorded answer to an unknown record. Pipeline only reads it: *resolved* and *dismissed* records fold out of the fed prompts, and a reopened one rides back in. Settling a question is Interface's act.

### History

**Archive**:
The resting place of unmerged work branches: renamed away from the live refs, never deleted — nothing is discarded.
_Avoid_: deletion

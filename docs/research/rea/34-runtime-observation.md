# REA runtime observation — Frida, debug sessions, process scenarios, native UI

> Part of the [REA overview](README.md). How REA gets *runtime* facts — facts
> about a native target while it is actually executing, not just from its
> bytes: Frida injection, GDB/Rizin debug sessions, PTY process
> scenarios, macOS native UI/call observation, and connecting static and
> runtime evidence.
> Browser/Electron/JS/ADB/pcap lanes out of scope; provider table, crash cores
> and Evidence semantics are in ch. 31/32/33, not repeated. REA clone
> `/tmp/opencode/rea` @ `28a33ca`.

## What REA does

### Frida instrumentation lane

The pinned Node binding `frida@17.23.2` is an `optionalDependency` with an
`allowScripts` exception for that pin (needed by its prebuilt binary; REA
`package.json:409–413`), loads only per Frida operation; REA never installs
frida-server on targets (`docs/frida-instrumentation.md:3`). The npm archive
omits a license doc, so REA vendors it verbatim — `LGPL-2.0 WITH
WxWindows-exception-3.1` (`licenses/frida-17.23.2-COPYING.txt:1–25`,
`THIRD_PARTY_NOTICES.md:31–36`) — and *verifies* the pin:
`tsconfig.frida-verification.json:7–8` type-checks
`src/frida/frida-bindings.d.ts` plus a compatibility verifier, and
`npm run verify:frida` runs the bindings on Linux against a short-lived local
Node fixture (+ a remote lane, `-- --address HOST:PORT --pid PID`); mocks don't
establish real-device compatibility (`frida-instrumentation.md:29`).

Lifecycle (`:7`): `list_frida_devices`/`list_frida_processes` →
`start_frida_session` (attach or spawn; a spawn starts **paused** so scripts
load before target code runs) → `load_frida_script` → `resume_frida_session` →
`frida_session_status` → `close_frida_session` (unloads scripts, detaches,
**never kills the target**; a paused spawn resumes only after cleanup is
confirmed). MCP sessions die with the server; the one-shot CLI
`instrument-with-frida` observes a script for a bounded duration. Runtime
facts are whatever **caller-authored JavaScript** reports: messages capped at
16 MiB, truncation explicit; script source never stored — only path + SHA-256;
`frida_session_status detail="summary"` returns state, scripts,
`messages_retained/truncated`, payloads in parent Evidence (`:9`, `:27`).
Remote endpoints carry host, token, cert, origin, keepalive (s, per Frida Core
17.23.2); auth values excluded from Evidence (`:5`).

### Debug-session lane (GDB + Rizin)

Distinct from the ch. 31 provider table: these are *live debugging* lanes.
Sessions live only for the MCP server's lifetime, are **Linux-only**, and any
unrestricted debugger command **closes the active binary-analysis session**, so
a fresh provider cannot rebind over still-writing command effects
(`docs/reverse-engineering-tools.md:3–13`).

**GDB**: `start_gdb_session` → `gdb_console` → `gdb_session_status` →
`close_gdb_session`; GDB/MI (`--nx --quiet --interpreter=mi3`, MI2 fallback,
auto-load disabled); optional `inferior_tty` gives detached inferior processes
an output destination that outlives the session; closing with one live inferior
and a verified TTY **auto-detaches it, which can resume execution**, annotated
destructive; close confirms live thread
groups and "never infers target ownership from a PID or path"; the console is
unrestricted (shell, files, network in the REA user's context), output to 16 MiB
(`:34–38`).

**Rizin**: `start_rizin_debug_session` / `rizin_debug_command` /
`rizin_debug_session_status` / close; explicit `inferior_tty` required;
`dbg.exitkills=false` so the target may outlive the debugger; close *proves* the
detach — `olj` descriptor list, detach only a unique `ptrace://` descriptor,
verify `/proc/<pid>/fd/1,2` still point at the selected TTY by device+inode (`:50`);
30 s startup, 120 s/frame, 64-frame history, no override (`:54`). Cores are a
separate lane (ch. 32); the `trace_crash` prompt brings crash, static, and
capture Evidence together (`docs/mcp-prompts.md:14`).

### Process-behavior lane

`capture_process_scenario` runs a caller-selected command in a PTY and records:
raw PTY chunks *and* rendered terminal states; timed
interactions (`input` at_ms, `sensitive` inputs persisted as byte-count
placeholders; `resize`; `signal`); exit disposition
(`exited`/`timeout`/`idle_timeout`/`cancelled`/`failed`) with optional
`finalization_ms` SIGTERM→SIGKILL grace; sampled process-tree rows; and, for
selected paths, `files_before`/`files_after` classified
created/deleted/modified/unchanged with whole-file SHA-256 digests
(`docs/process-capture.md:3–13,191–238,311–336`); explicitly "not a sandbox",
and the filesystem evidence is "bounded snapshots, not a syscall trace"
(`:9–13,236–238`).

`compare_process_captures` compares two captures across five dimensions —
`terminal, interaction, exit, filesystem, process`
(`src/domain/process/processComparison.ts:39–45`) — under a *comparison
contract* (working dir, explicit env, observation paths, terminal size,
scripted events, timeouts, limits, normalization versions); mismatches are
rejected field-by-field, and the docs frame the use case as "an authority
build and a reconstruction" — literally original-vs-restitched
(`process-capture.md:5–6,93–99`). Normalization (literal + port patterns) makes
flaky output comparable without silent equalizing (`:281–299`); a trace spec
accepts declared re-orderings (`:86–91`); residual unknowns or truncation block
a complete-equivalence claim (`:81–84`).
Hosts: Linux/macOS only — Windows capture is unavailable; Windows can still
*compare* saved captures (`:17–26`).

### Native desktop & call observation

`inspect_desktop_application` yields runtime *candidates* without touching a
process: it scans an installation directory and reports families (.NET, Unity
Mono/IL2CPP, Godot, GameMaker, Unreal, Electron) plus component path markers —
BepInEx/MelonLoader/EAC/BattlEye "identify path conventions only; runtime
presence stays unknown" (`docs/desktop-applications.md:3–8,94–114`; cf. ch. 32
for the PE-header comparison). The live native-UI tools are macOS-centric
(`docs/native-investigation.md`):

- `observe_native_ui`: one explicitly selected existing PID/window;
  ScreenCaptureKit window screenshot (macOS 14+) + accessibility reads
  in-window; exe bytes + start-time guard PID reuse; missing permissions yield
  actionable errors, not broad capture (`:595–601`).
- `capture_native_ui_scenario`: accessibility-action driving only — child-index
  paths for press, scroll, text entry, waits capped at 180 s; no global event
  injection; ordered before/after captures with gaps; **application state left
  as-is** (`:603–622`).
- `observe_native_calls`: launches a Mach-O as a **new, owned process under
  LLDB**, stops at caller-selected breakpoints (exact symbol names per image;
  ObjC selectors per class), records per hit: thread, image, symbol, load +
  file address, **raw integer argument registers**, optional caller frames, and
  for ObjC the `_cmd` selector + receiver's dynamic class (`:626–644`). Ends at
  exit, `max_events`, `duration_ms`, or budget; 1 MiB stdout/stderr per stream,
  8 MiB event JSON, truncation explicit (`:646–690`). Limits: only *entries*
  observed — no returns, float/stack args, inlined or `objc_direct` calls; the
  target runs with user permissions (files, UI, network); hardened-runtime
  targets need `get-task-allow`, else `debugger-attach-denied` (`:692–700`).

### Static↔runtime correlation

`correlate_static_and_runtime` is where the two kinds of evidence meet; it is
deliberately humble about what it can show.
Inputs: ≥1 *static comparison* Evidence record (output of
`compare_functions`/`compare_artifacts` — dimensions `identity, pseudocode,
assembly, comments, calls, references, strings_names, cfg`) + ≥1 *runtime
comparison* record (output of `compare_process_captures`) + **caller-declared
mappings**: a static selector (artifact logical path or one function dimension)
bound to one runtime dimension with `side_alignment` and a hypothesis carrying
an `expected_pattern` of `cochanged | static_only | runtime_only |
both_unchanged` (`src/domain/staticRuntimeCorrelation.ts:28–47,64–89`). Per
mapping it computes the `observed_pattern`, classifies each pairing
`hypothesis`/`contradiction`/`unresolved_branch`, and reports overall
`correlated/contradicted/unknown/truncated` + counts (`:122–146`). In plain
terms: a static diff of one function (its `calls` changed) is put together with
the behavioral diff of its scenario captures (whose `filesystem` didn't) and a
stated hypothesis about the pair; REA marks
contradictions — "matching patterns are hypotheses, not causality"
(`references/evidence-workflows.md:57–58`). Nothing live is touched:
`sessionEvidence` (`src/contracts/toolEffects.ts:722`).

### Effect & safety model

No approval protocol — **disclosure**. Every tool carries a closed-vocabulary
effect record (`mutatesTarget, writesFilesystem, launchesProcess,
accessesNetwork, changesUiState, mayDiscardData, executesForeignCode, …`) from
which MCP `readOnlyHint`/`destructiveHint`/… derive
(`src/contracts/toolEffects.ts:1–27`). `executesForeignCode` ("runs or drives
code REA does not own") is set for `load_frida_script`, `gdb_console`,
`rizin_debug_command`, `observe_native_calls`, `capture_native_ui_scenario`,
`capture_process_scenario` (`:71–115,206–255,574–612,706–712`); the
pure-analysis comparisons (`compare_*`, `correlate_static_and_runtime`) only
produce evidence.
Annotations are "hints, not authorization controls"; REA "does not require
permission grants or per-call approval flags" — requests name their target and
lifecycle; MCP clients own the confirmation UI
(`docs/mcp-contracts.md:768–790`). The skill's web lane forbids action claims
("never claim REA clicked, navigated, evaluated page JavaScript…") and splits
user (passive) vs agent (declared scenario) actors
(`references/runtime-observation.md:13–15,27–42`); the native analogue is the
warning before `observe_native_calls`: "the target runs and may change files or
use the network" (`references/native-and-artifacts.md:248–251`). Ownership keeps cleanup honest: never attach to an unlaunched process
(`native-investigation.md:644`); Frida never kills the target; process-capture
binds the run's start identity to an ownership token, rechecks it before every
finalization signal, and never falls back to a bare PID kill
(`process-capture.md:327–336`); the macOS check runs through a compiled Swift
helper plus `/bin/ps` — setuid, so a sandbox can refuse it with `spawn EPERM`,
and REA reports `cleanup_incomplete` rather than kill unverified (`:537–593`).

## Comparison with calxgloss

### Black-box replay vs instrumented observation

| | calxgloss (`testgen`→`verify`) | REA runtime observation |
|---|---|---|
| Mechanism | Generated FFI bindings call the **original DLL's exports** in-process (Windows execution); recorded results become a test crate replayed against the translated Rust | Frida JS inside a live process; LLDB entry-traces; GDB/Rizin MI console; PTY scenarios; AX UI probes |
| Granularity | Whole exported function: arguments → return/globals/observable output | Call entries: argument registers, receiver class, backtraces; terminal/exit/filesystem/UI dimensions |
| Who drives | Nobody — inputs generated statically from exports + type evidence | Someone authors every scenario, breakpoint set, or script (agent or human) |
| Equivalence claim | The baseline test *is the gate* — same inputs, both sides, blocks the commit | The comparison contract proves the *scenario* matched; differences/unknowns reported, never enforced |
| Target formats | Windows PE32/PE32+ native DLLs (managed PEs are parked, ADR-0044) | Frida: any OS it supports (incl. Windows processes); LLDB trace: Mach-O; PTY capture: Linux/macOS; native UI: macOS; debug: Linux |

### Where calxgloss's approach is stronger

- **Zero driving.** testgen→verify→retry→commit never waits for an operator to
  author a scenario; every REA runtime tool requires one.
- **Replayable by construction.** The same baseline re-runs against every
  restitch, continuously. REA is blunt: it "does not replay a previous
  execution or emulate dependencies" (`process-capture.md:6–7`).
- **Inputs generated automatically** from export signatures +
  typesdb/typeinfer evidence; REA only records inputs a real caller supplies.
- **It is a gate, not a report.** REA's runtime facts inform the agent; its
  only enforcement is the hand-authored `verify_reconstruction` spec (ch. 33):
  calxgloss has the weaker observation and the stronger *decision*.

### Where calxgloss's lane is blind

- **Nothing inside the DLL**: FFI sees exports only — no call sequence,
  internal state, heap or threads; right bytes via the wrong path passes.
- **No interactive targets**: exports can't drive stdin, TUI or GUI; EXE-level
  windowed behavior has no baseline at all.
- **Invented inputs**: real caller argument vectors never enter the tests
  (echoes ch. 32's "testgen invents inputs").
- **Effects unrecorded**: file/registry/network writes during a baseline run
  are invisible; REA's `filesystem`/`process` dimensions exist for that.
- **Thin failure diagnostics**: hang/crash in a baseline run = failed test, no
  registers or dumps (crash-dump steal, ch. 32). And execution is
  Windows-only — every REA lane except Frida refuses the host calxgloss needs.

### REA-only capabilities relevant to calxgloss's mission

- **Differential API-call tracing as a verify signal.** `observe_native_calls`
  answers "which functions a binary actually calls in one run"
  (`native-investigation.md:626`); the same entry-trace at the original-vs-
  restitched DLL boundary (import-table hooking; Frida-style interposition,
  `frida-instrumentation.md:7`) adds an ordered *API-call-sequence* dimension,
  catching PAL-mapping errors value tests miss (right result, wrong GDI path).
- **Scenario captures for EXE targets.** `target_dir` holds EXEs; the
  `capture_process_scenario` schema + five compare dimensions is a ready-made
  baseline contract for console/TUI behavior FFI can't reach; REA's own
  framing, "authority build and reconstruction" (`process-capture.md:5–6`), is
  literally original-vs-Rust.
- **Static↔runtime correlation for retry-loop unknowns.** A stuck function's
  unknown becomes a declared mapping (static `calls`/`cfg` ↔ runtime
  `exit`/`filesystem`, expected `cochanged`/`static_only`/…); a recorded
  `contradiction` is auditable evidence for choosing `escalate` vs
  `edge_case_fix` — the evidence-authority layer ch. 33 asks for.

### Verdict

calxgloss runs the *narrowest* runtime lane in either project — one mechanism,
exports only, one OS — but the only fully automated, replayable equivalence
**gate**. REA observes far more — internals, interactions, effects, UI — yet
nothing it observes becomes a gate: every lane needs an author, and its honesty
budget (limits, truncation, unknowns) is per-call overhead a hot pipeline won't
pay. Steal the two highest-leverage facts — *which calls happened*, *what real
callers passed* — and build them into the gate.

### Steal ideas

1. **Differential call trace in `verify`.** Record the ordered Win32/PAL API
   call sequence per tested export: IAT interposer around the original DLL in
   the testgen harness, PAL wrapper counters on the Rust side; store it as an
   extra baseline dimension, compare order not membership — `calxgloss-apidetect`
   supplies the expected shape, fully automatable.
2. **Runtime-mined test inputs.** Hook the original DLL's export entries during
   a baseline or reference-app run, record raw argument vectors (the
   `observe_native_calls` event shape, `native-investigation.md:638–644`), and
   replay them as extra tests — kills the invented-inputs blind spot.
3. **Scenario-capture contract for EXEs.** Reuse the process-capture scenario
   schema and comparison-contract rule (`process-capture.md:93–99`) as the
   EXE-level baseline format — declared interactions, filesystem observation,
   exit + finalization — with the five dimensions as the EXE verify signal.
4. **Hypothesis ledger for the retry loop.** Log each unclosable unknown as a
   `correlate_static_and_runtime`-shaped mapping + expected pattern;
   contradictions steer retry-strategy escalation and survive as reviewable
   evidence records (pairs with ch. 33's unknown-ledger steal).
5. **Owned-process discipline in testgen.** When launching the original binary
   (hung calls, crash repro), bind launch-time identity to an ownership token
   and recheck before every kill instead of signaling a bare PID
   (`process-capture.md:327–336`); keep Frida's spawn-paused→load→resume order
   for instrumented runs (`frida-instrumentation.md:7`).

## Sources

REA (`/tmp/opencode/rea` @ `28a33ca`): `docs/frida-instrumentation.md:3–9,27–29`;
`package.json:409–413`; `tsconfig.frida-verification.json:7–8`;
`THIRD_PARTY_NOTICES.md:31–36`; `licenses/frida-17.23.2-COPYING.txt:1–25`; `src/frida/`;
`docs/reverse-engineering-tools.md:3–13,34–38,50–54`;
`docs/process-capture.md:3–26,72–102,191–246,281–299,311–336,537–593`;
`src/domain/process/processComparison.ts:39–45`;
`docs/desktop-applications.md:3–8,94–114`; `docs/native-investigation.md:593–700`
(plus `:752–763`: IB hierarchy coverage is static keyed-archive parsing, not runtime);
`src/domain/staticRuntimeCorrelation.ts:28–47,64–89,122–146`;
skill references `evidence-workflows.md:50–64`, `runtime-observation.md:13–42`,
`native-and-artifacts.md:248–251`; `docs/mcp-contracts.md:768–795,1145–1147`;
`docs/mcp-prompts.md:14`; `src/contracts/toolEffects.ts:1–27,71–115,206–255,574–612,706–722`.
calxgloss: `10-*.md`, `20-rea-inventory.md` §5, `31/32/33-*.md` (providers; crash
cores; compare tools, verify authority, unknown ledger).

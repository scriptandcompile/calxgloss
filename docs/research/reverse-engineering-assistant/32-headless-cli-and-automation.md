# ReVa headless mode and the `mcp-reva` CLI — Ghidra without a UI

> Part of the [ReVa overview](README.md). How ReVa runs Ghidra with no UI: the Java `RevaHeadlessLauncher`, the
> Python `mcp-reva` stdio bridge, session-scoped projects, the PyGhidra scripting group, the security posture behind
> exposing it, and what CI ships. Citations `path:line` are relative to clone root `/tmp/opencode/cyberkaida-rea` @
> `a2fcd94`; tool surface in [ch. 31](31-mcp-tool-surface.md).

## 1. Two startup sequences

**Assistant mode.** Install the extension, activate it *twice* — "ReVa Application Plugin" in the Project view,
"ReVa Plugin" in the CodeBrowser tool — then Save Tool (`README.md:66-69`). The server belongs to the front-end
plugin: `init()` builds `McpServerManager(tool)` over a ToolOptions-backed `ConfigManager`, registers
`RevaMcpService`, calls `startServer()` (`RevaApplicationPlugin.java:70-80`), tracks project open/close without
restarting (`:83-92, 146-160`), hangs a shutdown hook (`:95-102`). `RevaPlugin` is a *client* of that service: it
hands the server its tool and program lifecycle (`RevaPlugin.java:68-127`); its own UI panel is commented out
(`:98-100`) — ReVa's "UI" is Tool Options plus one toolbar toggle. `startServer()`
(`McpServerManager.java:305-359`): public-binding guard first (`:326-330`), Jetty 12 `ServerConnector` on `host`,
600 s idle timeout, `start()` on Ghidra's `GThreadPool`, 10 s poll on `serverReady` (`:353-397`), endpoint
`/mcp/message` (`:85`); live Tool Options edits restart or revert the server (`:687-768`).

**Headless.** No `analyzeHeadless`, no plugin loader: PyGhidra (CPython + JPype) owns the JVM and the Java launcher
boots Ghidra inside it (`pyghidra.start()`, then `from reva.headless import RevaHeadlessLauncher`,
`README.md:152-171`). The Java classes come from the *Ghidra install* (the wheel ships Python only,
`pyproject.toml:73-75`); CI unzips the extension into `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/` and installs
PyGhidra from that same tree (`test-headless.yml:81-99`). `start()` (`RevaHeadlessLauncher.java:189-272`) runs, in
order: `Application.initializeApplication(new GhidraApplicationLayout(), new
HeadlessGhidraApplicationConfiguration())` (`:193-209`); `GhidraScriptUtil.acquireBundleHostReference()`
(`:211-222`) — a refcount dance, and what makes `run-script` work later; `useRandomPort` → `ServerSocket(0)`
(`:234-237`); a constructor API key enables auth *before* start (`:239-245`); tool-group allow/deny applied
pre-registration (`:248, 278-324`); persistent project if a marker file says so (`:251-258, 333-356`); then `new
McpServerManager(...)` + `startServer()` (`:261-262`), with an honest `Msg.warn` if it did *not* bind (`:264-271`).
`stop()` closes the project **without deleting it** (`:361-398`); releasing the bundle host stops the OSGi
framework. Headless degrades what it cannot do: Follow-Me no-op, null `PluginTool`, consent dialog → refusal
(`McpServerManager.java:549-559`).

## 2. The Python CLI — `src/reva_cli` (879 LOC), console script `mcp-reva`

Package `reverse-engineering-assistant`, setuptools_scm version from git tags (`pyproject.toml:103-106`), deps
`pyghidra>=3.1.0`, `mcp>=2.3,<3`, `httpx2` (`:42-46`), console script `mcp-reva` (`:55-56`). Boot order is
deliberate: all blocking work happens before `asyncio.run` (`__main__.py:167-221`) — `pyghidra.start(verbose=)`
("3-5 s"), lazy `ProjectManager`, a per-session key `ReVa-<uuid4>` unless `--config` was given (`:185-188`), then
`ReVaLauncher(use_random_port=True).start()` → port ("4-7 s"). So an MCP `initialize` sent immediately just queues
in the pipe buffer while the JVM boots — no handshake race (`conftest.py:305-309`). Flags: `--config`, `--verbose`,
`--version` (hardcoded `3.0.0` at `:136`, drifting from setuptools_scm), and mutually exclusive
`--disable-tool-group` / `--tool-group` allowlist (`:139-153`, ids per `ToolGroup.java:26-52`); no `--port`, no
`--project`. `launcher.py` wraps the Java object in-process through JPype (`:68-69`), always uses the 6-arg
constructor so the key is threaded either way (`:87-104`), `mkdtemp(prefix="reva_project_")` for the project dir
(`:73-85`), pushes tool-group CSVs before `start()`, and waits `waitForServer(60000)` (`:45-54, 107-124`).

The bridge (`stdio_bridge.py`) is the interesting piece: an MCP **server** over stdio whose handlers (`:170-178`)
proxy to an MCP **client** against `http://localhost:{port}/mcp/message` (`:165`) — stdio in, streamable-HTTP out,
SDK-typed both ends (`:2-19`). `ReconnectingBackend` rebuilds transport + session + `initialize` only on transport
errors, including SDK v2's `MCPError(-32001 REQUEST_TIMEOUT)`; MCP-level errors propagate untouched (`:63-77,
125-142`). The httpx client disables keepalive and carries `X-API-Key` as a default header (`:46-60`); `call_tool`
re-wraps failures as `is_error=True` so the model still sees the text (`:193-214`); `SIGINT`/`SIGTERM`/`SIGHUP`
tear down bridge → project → launcher (`__main__.py:48-92`).

## 3. Projects: `.reva/projects/`, temp dirs, and what survives

Three models coexist. Persistent-by-constructor (Java): the project outlives `stop()`
(`RevaHeadlessLauncher.java:374-384`) — the "long-running server" mode (`headless/CLAUDE.md:222-228`).
Ephemeral-by-CLI: `mkdtemp` + `shutil.rmtree` (`launcher.py:73-85, 164-173`). And `ProjectManager`, modelling
`.reva/projects/<sanitized-cwd>` through PyGhidra's `GhidraProject` (`project_manager.py:24-120`) — its
`import_binary` path is never called by the stdio flow. `README.md:149` still promises ".reva/projects/ in the
current working directory"; the test pins the truth — after startup *and* after a real `import-file`, `.reva` must
not exist (`tests/test_cli_e2e.py:146-185`). Nothing is auto-imported at boot: batch intake is `import-file` —
files, directories or archives, `maxDepth` 10, analysis off by default with `analysisRecommended` set
(`ProjectToolProvider.java:1420-1500`). Inside a session work persists: save→checkin
(`util/ProgramPersistenceUtil.java:26-71`), renames surviving save + reopen
(`test_workflow_correctness.py:245-349`), diff sessions under `ReVaDiffSessions/` (ch. 31 §4). `rmtree` takes the
database with it.

## 4. PyGhidra scripting: five tools, and the blast radius they carry

The `scripting` group is `run-script`, `list-scripts`, `read-script`, `write-script`, `edit-script`
(`tools/scripts/CLAUDE.md:5-14`, registered at `ScriptToolProvider.java:166, 312, 381, 452, 528`). `run-script`
takes exactly one of `code` / `scriptPath` / `scriptName` (`:186-195`); inline code goes to a temp `.py` prefixed
`# @runtime PyGhidra`, deleted in `finally` (`:68, 205-212`); a `scriptPath` must sit inside a registered readable
directory (`:216-227`). Execution is Ghidra's own scripting framework; a missing provider or load failure becomes
`PyGhidraNotAvailableException` with launch guidance (`GhidraScriptRunner.java:47-77`) — the stock `ghidraRun` GUI
never wires `PyGhidraScriptProvider`, so `run-script` is a *mode* property: yes under `mcp-reva` / `pyghidra-gui`,
no under `ghidraRun`. It runs with a copy-constructed `GhidraState` (suppresses plugin events),
`ScriptControls(stdout, stderr, monitor)`, a bundle-host bracket, `TimeoutTaskMonitor.timeoutIn(...)` and
per-stream `CappedWriter` (`GhidraScriptRunner.java:79-86`, `PythonScriptExecutor.java:88-96`), defaults 60 s /
65536 chars (`ConfigManager.java:87-88`). The result JSON reports
`success/stdout/stderr/*Truncated/durationMs/timedOut`, sniffing PyGhidra's `Traceback` marker so a raising script
is `success:false`, not a tool error (`ScriptToolProvider.java:270-300`). Scripts open their own transactions — the
tool deliberately does not (`:150-154`) — so a script's damage is committed by default.
`write-script`/`edit-script` land in the user scripts dir (system dirs read-only,
`ScriptDirectoryManager.java:31-60`), so scripts outlive the ephemeral project, and `write-script → run-script` by
name is covered e2e (`test_run_script_e2e.py:1-19`). Containment is one boolean, `ToolGroup.SCRIPTING`, verified in
Java (`HeadlessLauncherToolGroupIntegrationTest.java:61-91`) and by a real `mcp-reva --disable-tool-group
scripting` whose `tools/list` lacks `run-script` (`test_tool_group_cli_e2e.py:59-61`).

## 5. Security posture end to end

Defaults: `127.0.0.1`, auth **off**, scripting **on** (`ConfigManager.java:69-75`); `README.md:71-76` states the
contract — a public interface requires the API key *or* the scripting group off. A key exists even when auth is off
(`:241-247`; `ConfigManagerSecurityTest.java:55-65`), so enabling it is one edit, not a key ceremony. In CLI mode
the hole is closed by design: fresh `ReVa-<uuid4>` per session (`__main__.py:185-188`) → `setApiKey` +
`setApiKeyEnabled(true)` before start (`RevaHeadlessLauncher.java:239-245`) → filter installed with the connector
(`McpServerManager.java:337-343`) → the bridge presents it on every request (`stdio_bridge.py:46-60`), pinned by
`tests/test_api_key_injection.py:11-43`. The filter compares one header with `String.equals` — no constant-time
compare, no TLS (`ApiKeyAuthFilter.java:39, 98`). The real safety engineering is the public-binding guard: *risky*
= no auth **and** a non-loopback bind (`util/NetworkUtil.java:27-33`); GUI mode prompts a consent dialog, headless
mode refuses to start and prints the three fixes, naming `run-script` as remote code execution (`:406-455`). Tests
cover the four quadrants (`PublicBindingGuardIntegrationTest.java:47-85`) plus the runtime case — a change that
would create exposure is refused and reverted, the server keeping its old bind (`:736-768`). No `SECURITY.md`:
loopback by default, key by default in CLI mode, refuse-to-bind headless, one boolean between the server and
arbitrary Python.

## 6. CI/CD, Docker, and the per-Ghidra-version release ladder

"Docker" is a bullet and nothing else (`README.md:130-136`) — no `Dockerfile` or `compose.yaml` anywhere. What *is*
shipped is ReVa's own CI, and `test-headless.yml` is the headless user story verbatim: matrix over Ghidra `12.0 /
12.1 / 12.1.4 / 12.2 / latest` × ubuntu/macos, macOS trimmed to oldest+newest because hosted runners are ~4× slower
(`:19-36`), `buildNatives` on macOS because Ghidra ships no macOS decompiler natives (`:68-76`), extension unzipped
into the Ghidra tree (`:78-86`), PyGhidra installed *from that same tree* (`:96-104`), then `uv run pytest
--timeout=180` under a 30-minute cap whose comment states the cost model — one shared `mcp-reva` per xdist worker
instead of ~110 JVM boots at ~10 s (Linux) / ~40 s (macOS) each (`:106-121`).

Version coupling is three-way. Java: `GHIDRA_INSTALL_DIR` is mandatory at build time (`build.gradle:35-43`) and the
build reads that install's `application.properties` to gate a JVM arg on Ghidra ≥ 12.1 (`:138-167`);
`publish-ghidra.yml` builds one extension zip **per Ghidra version** (`:19-23`), Sigstore-signs and attaches it
(`:70-80`); `README.md:53-57` says match your exact Ghidra. Python: one version-agnostic wheel, trusted publishing
+ Sigstore (`publish-pypi.yml:29-46`); the glue is the runtime floor `pyghidra>=3.1.0` (`pyproject.toml:43`). Docs
drift is the tax: `scripts/reva_headless_server.py`, the documented headless entry point, was deleted (commit
`d7b48ed`) yet is still cited by `DEVELOPER.md:67`, `CLAUDE.md:97`, `.claude/launch.json:7` and *printed* in the
`run-script` error hint (`GhidraScriptRunner.java:48-51`).

## 7. How close does headless + skills get to a batch pipeline?

The pitch fits in four lines: `export GHIDRA_INSTALL_DIR=…`, `uv tool install reverse-engineering-assistant`,
`claude mcp add --scope user ReVa -- mcp-reva`, `claude -p "Import /bin/ls with ReVa and tell me how it works"`
(`README.md:140-147`). The Claude marketplace package hard-wires it: `.mcp.json` runs `uv run mcp-reva`, and the
marketplace installs six skills — triage, deep-analysis, ctf-crypto/rev/pwn, pyghidra-scripting
(`README.md:173-191`). "Unattended ReVa" is one throwaway MCP subprocess plus prose telling the model the order of
operations. What makes it work: `import-file` swallows directories and archives, analysis and diff are background
jobs with status/cancel handles (ch. 31 §4), and caps/pagination plus error-redirect keep the model fed and
repairing its own bad calls. Where it stops: **the loop is the model.** The run owns one temp project that `rmtree`
deletes — no artifact, no record, nothing to re-run: the output is prose in a terminal. Nothing gates a claim:
ReVa's determinism lives in its tests, not its runs — `test_workflow_correctness.py:1-9` distinguishes "did the
tool give the right answer?" from "did it respond?" and asserts `_printf(` / `_add(` / `_multiply(` in `entry`'s
decompilation (`:179-185`) over a fixture binary built from checked-in C (`tests/fixtures/test_program.c`). Those
are gates the project writes *for itself*; a headless run emits no verdict a pipeline could consume. Batch
economics fail too: one JVM boot per target (10-40 s, `conftest.py:355-366`), the ~15-20k-token schema bill (ch. 31
§5), and a `$GHIDRA_INSTALL_DIR`-plus-matching-zip dance ReVa automates only with a setup *agent*
(`.claude/agents/reva-setup-installer.md`).

## Comparison with calxgloss

| | calxgloss (`calxgloss-cli`, 29 subcommands) | ReVa headless (`mcp-reva`) |
|---|---|---|
| Unattended unit | `calxgloss auto` reads project state, runs the next step (`crates/interface/calxgloss-cli/src/commands/auto.rs:1-4`); commands are the API (`cli_types.rs:197-519`) | `claude -p "…"` one-shot; the driver is the model's tool loop |
| What sits in the loop | the pipeline; retry is programmatic — 4 strategies, ≤3 attempts (`10-calxgloss-baseline.md:47-51`) | the LLM, at every tool call |
| Engine dependency | compiled in — Kuna vendored at `v1.984` (`10-calxgloss-baseline.md:64-66`); `doctor` loads the target in-process, `--fix` is a documented no-op (`cli_types.rs:181-196`) | external `$GHIDRA_INSTALL_DIR` + a matching per-Ghidra-version zip + a PyGhidra JVM per session |
| Session state | durable record tree, decompile cache, corrections store (`10-calxgloss-baseline.md:57-61`) | ephemeral temp project (`launcher.py:73-85, 164-173`); scripts/diff-sessions survive outside it |
| Stop condition | per-function gate: compile + baseline tests + assessed API-call traces (`VerificationResult`, `crates/shared/calxgloss-types/src/verification.rs:76-108`; `10-calxgloss-baseline.md`), verify is a hard gate | the model decides it is done; nothing checks it |
| Reproducibility | same binary + version + seed ⇒ byte-identical (`10-calxgloss-baseline.md:16-19`) | nothing; the run is deleted with the project |
| Own CI | none (no `.github`; `just test`) (`10-calxgloss-baseline.md:104-105`) | full headless e2e matrix, 5 Ghidra versions × 2 OSes (`test-headless.yml:19-36`) |

### Overlap

Both are CLI-shaped, subprocess-friendly, driven from a shell script; both bound what a long analysis emits
(calxgloss by context tiers, ReVa by per-stream caps and pagination); both keep durable intermediates so a second
run beats the first (record tree / decompile cache vs persistent-project mode, `ReVaDiffSessions/`).

### calxgloss-only

An engine with no install step — ReVa's unattended fragility is precisely `GHIDRA_INSTALL_DIR` plus a zip built per
Ghidra version, hence its setup agent; a gate that ends runs with a verdict on each claim; deterministic replay; no
per-target LLM or JVM boot; machine-readable output for another process.

### ReVa-only

An unattended *general* RE capability on anything Ghidra loads, invoked by one prompt line; a stdio↔streamable-HTTP
bridge giving an agent a stdio server while the real server stays loopback and key-authenticated per session;
`RevaHeadlessLauncher` usable from Python as a library for its own harness (`README.md:152-171`); tool-group
allowlisting as a startup-time capability cut; CI running the *product's* headless path, not unit mocks; honest
refusal where a server won't bind publicly.

### Verdict

Two opposite answers to "what runs when nobody is watching?" ReVa headless is **unattended Ghidra + LLM**: an
operator-shaped agent loop with no operator, buying generality (any format, any ISA, any question) at the cost of
reproducibility — it deletes its own database, and no run carries a verdict. calxgloss is **unattended codegen +
verify**: narrow (PE, x86), fully specified, so it can gate, replay and publish. ReVa proves the
deterministic-fixture + right-answer e2e pattern works over a live engine, and proves packaging an agent can drive
(stdio subprocess, ephemeral sandbox, capability cut, per-session auth) — the layer calxgloss has no CI for and no
surface for. calxgloss proves a batch pipeline needs the engine inside the artifact, and a stop condition that is a
verdict, not a model's satisfaction.

### Steal ideas

1. **Headless e2e harness, as-is.** Boot once per session, assert through a real client (`conftest.py:39-61,
   274-397`), with the LFS-pointer guard (`test_cli_e2e.py:32-55`) and on-failure log replay (`conftest.py:63-116`) —
   this is the shape for calxgloss's missing CI (`10-calxgloss-baseline.md:104-105`).
2. **Deterministic fixture + right-answer assertions.** A hand-built binary from checked-in source with known
   callees is a regression gate that survives engine upgrades; calxgloss has the fixture habit but not the assertion
   habit.
3. **Capability cut at startup.** A `--tool-group`-style allowlist for any agent surface calxgloss exposes
   (read-only vs write-back), enforced before registration, not by runtime checks.
4. **Refuse-to-bind over silent exposure.** For `calxgloss-web` on a non-loopback host,
   `McpServerManager.java:406-440` (GUI prompt / headless refusal / revert on a runtime change, `:736-768`) is a
   complete, tested policy in ~60 lines.
5. **Ephemeral sandbox, durable artifact, separated.** ReVa's mistake is deleting the container holding the
   *answers*; keep the throwaway work dir, persist outputs explicitly — the bridge from a ReVa-style front end to
   calxgloss's record tree.

## Sources

Every `path:line` above is relative to `/tmp/opencode/cyberkaida-rea` @ `a2fcd94`, under `src/main/java/reva/`
unless prefixed. Files behind it: `README.md`, `DEVELOPER.md`, `headless/*`, `plugin/*`, `server/{McpServerManager,
ApiKeyAuthFilter}.java`, `util/*`, `tools/{scripts, project}/*`; `src/reva_cli/*.py`; `pyproject.toml`,
`build.gradle`, `config/reva-headless-example.properties`; `.github/workflows/{test-headless, test-ghidra,
publish-ghidra, publish-pypi}.yml`; `tests/*` (harness `conftest.py`, fixture `tests/fixtures/test_program.c`);
`src/test.slow/java/reva/{headless, server}/*IntegrationTest.java`; `ReVa/{.mcp.json, skills/*}`; deleted
`scripts/` in `d7b48ed`. calxgloss: `10-calxgloss-baseline.md` and
`crates/interface/calxgloss-cli/src/{cli_types.rs, commands/auto.rs}`.


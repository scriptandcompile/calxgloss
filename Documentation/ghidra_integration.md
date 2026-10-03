# Ghidra Lifecycle Integration — Design

Goal: starting any Ghidra-dependent calxgloss command (`classify`, `translate`,
`batch-translate`, `auto`, `patch`) should Just Work — calxgloss verifies the
Ghidra install, starts a GhidraMCP server headless if none is running, ensures
the extension is present and compatible, attaches to the right port, and
opens (or creates) a Ghidra project in the output directory containing every
DLL/EXE the run needs.

Everything below was verified against the local stack on 2026-10-03:
Ghidra 12.1.2 at `~/ghidra_12.1.2_PUBLIC`, GhidraMCP 6.0.0 extension,
bridge repo `~/Programming/ghidra-mcp` @ v6.0.0.

---

## 1. What the stack already gives us (verified)

| Capability | Where | Evidence |
|---|---|---|
| Headless server, no GUI | `com.xebyte.headless.GhidraMCPHeadlessServer` (a `GhidraLaunchable`) inside the installed extension jar | `~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP/lib/GhidraMCP-6.0.0.jar`; 195 endpoints |
| Server args | `--port <n> --bind <addr> --project <path> --file <path>` | class javadoc + `docker/entrypoint.sh` |
| Health/version probe | `GET /check_connection` → `Connection OK - GhidraMCP Headless Server v6.0.0` (headless); GUI answers `Connected: GhidraMCP plugin running with program '<name>'` | live probe on 8089 |
| Headless-only probes | `GET /health`, `GET /server_status` | README endpoint list (404 on GUI — usable to tell GUI from headless) |
| Project lifecycle (headless) | `create_project`, `open_project`, `close_project`, `get_project_info`, `archive_project`, `restore_project` | README "Headless Project & Program Lifecycle" |
| Program lifecycle (headless) | `load_program` (raw binary → project), `load_program_from_project`, `import_program` (.gzf), `export_program` | same section |
| Analysis control | `run_analysis`, `reanalyze`, `analysis_status` (poll long first-time analysis) | already in `calxgloss-ghidra` tool surface |
| Multi-program | `list_open_programs`, `switch_program` (already implemented in `calxgloss-ghidra`) | live tests pass |
| Instance discovery | every server registers a UDS at `$XDG_RUNTIME_DIR/ghidra-mcp/ghidra-<pid>.sock` (filename carries the PID; the Python bridge enumerates these to find pid/project/tcp_port) | `/run/user/1000/ghidra-mcp/` |
| Extension manifest | `Extensions/GhidraMCP/extension.properties` has `version=12.1.2` (the Ghidra build it was compiled against); plugin version in `description` | live file |
| Ghidra version | install dir name `ghidra_<X.Y.Z>_PUBLIC`; user state dir is `~/.config/ghidra/ghidra_<X.Y.Z>_PUBLIC/` | live dirs |
| Launch recipe | `java -Dghidra.home=$GHIDRA_HOME -Dapplication.name=GhidraMCP -cp <ext jar>:<Ghidra Framework/Features/Processors jars> com.xebyte.headless.GhidraMCPHeadlessServer --port … --project …` | `docker/entrypoint.sh` lines 52–75, 115–124 |

So nothing upstream is missing — the entire feature is **calxgloss-side orchestration**.

---

## 2. Target UX

```text
$ calxgloss translate --target eqmain.dll --dll eqmain.dll --function FUN_18008ed50

ghidra preflight
  install        ~/ghidra_12.1.2_PUBLIC            (12.1.2 ≥ 12.1.2 ✓)
  extension      GhidraMCP 6.0.0 for 12.1.2        (✓)
  server         none on 127.0.0.1:8080            → starting headless…
  headless       pid 4123, port 8089               (health ✓, v6.0.0 ✓)
  project        re/ghidra/EverQuest.gpr           (created 2026-10-03, reused)
  programs       eqmain.dll loaded+analyzed, now current
```

Rules:
- A **running GUI instance is never killed or replaced** — if one answers on
  the configured (or discovered) port, calxgloss attaches to it.
- A server **calxgloss started is owned by calxgloss**: `close_project` + child
  kill on exit, pid file for crash recovery.
- `--ghidra-url` / `CALXGLOSS_GHIDRA_URL` / `ghidra.url` still win; preflight
  only fills gaps. `--no-ghidra-autostart` (or `ghidra.auto_start = false`)
  makes preflight check-only and fail fast.
- Nothing installed at all? `calxgloss doctor --fix` downloads and installs the
  whole pair (§3.5) — still never without explicit consent, since Ghidra is a
  ~570 MB download.

---

## 3. Components to build

### 3.1 `calxgloss-ghidra` — client additions

New endpoints on the existing HTTP client:

```rust
impl GhidraClient {
    pub async fn check_connection(&self) -> Result<ServerInfo>;  // parse "…Headless Server v6.0.0" vs GUI form
    pub async fn health(&self) -> Result<HealthInfo>;            // headless only
    pub async fn project_info(&self) -> Result<ProjectInfo>;     // get_project_info
    pub async fn open_project(&self, path: &Path) -> Result<()>;
    pub async fn close_project(&self) -> Result<()>;
    pub async fn create_project(&self, dir: &Path, name: &str) -> Result<()>;
    pub async fn load_program(&self, file: &Path, analyze: bool) -> Result<LoadedProgram>;
    pub async fn load_program_from_project(&self, path_in_project: &str) -> Result<LoadedProgram>;
    pub async fn run_analysis(&self, program: Option<&str>) -> Result<()>;   // long: raise per-request timeout
    pub async fn analysis_status(&self) -> Result<AnalysisStatus>;           // poll while run_analysis runs
}
```

Notes:
- `check_connection` is the canonical "is this a GhidraMCP server, which kind,
  which version" probe — add it to `probe()` so a wrong port (e.g. pointing at
  the local AI on 8080!) fails with *"that port answers but is not GhidraMCP"*
  instead of a malformed-response error.
- New `GhidraError` variants: `NotGhidraMcp { url, hint }`, `VersionMismatch`,
  `ServerUnreachable`.
- GUI/headless parity caveat: cursor endpoints (`get_current_address`,
  `get_current_function`) are GUI-only. `probe()` must branch on server kind —
  headless uses `check_connection` + `get_current_program_info` instead.

### 3.2 New module `calxgloss-ghidra::lifecycle` (or crate `calxgloss-ghidra-launcher`)

```text
lifecycle/
  install.rs     GhidraInstall::discover()      — $GHIDRA_INSTALL_DIR → config
                 ghidra.install_dir → glob ~/*ghidra_*_PUBLIC (highest semver).
                 Version parsed from dir name; validate Ghidra/Framework exists.
  extension.rs   Extension::discover(ghidra_ver) — ~/.config/ghidra/
                 ghidra_<ver>_PUBLIC/Extensions/GhidraMCP/extension.properties.
                 Checks: present, built for this Ghidra version, plugin ≥ MIN_PLUGIN (6.0).
  discovery.rs   scan $XDG_RUNTIME_DIR/ghidra-mcp/ghidra-<pid>.sock → live PIDs
                 (kill -0 / /proc) + query each UDS for its TCP port/project.
                 Used to auto-correct a stale configured port.
  server.rs      HeadlessServer::start(cfg) — build the java command exactly as
                 docker/entrypoint.sh does (ext jar + Ghidra jar globs on -cp,
                 -Dghidra.home), tokio::process::Command, stdout/stderr →
                 <repo>/re/ghidra/headless.log, pid file re/ghidra/headless.pid,
                 kill_on_drop; then poll /check_connection with backoff (≤ ~90 s
                 JVM+Ghidra boot).
  project.rs     ensure_project(client, path, binaries) —
                 get_project_info; if not this project → open_project; if the
                 .gpr doesn't exist on disk → create_project.
                 For each needed DLL/EXE: list_open_programs → else
                 load_program_from_project → else load_program(file) +
                 run_analysis (poll analysis_status; emit ProgressEvents).
```

Project location default: **`<repo_dir>/ghidra/<target>.gpr`** (with the `<target>.gpr.lock`
and `<target>/` dir beside it), matching the existing output layout
(`crates/`, `re/`, `scratch/`). Add `ghidra/` to the generated `.gitignore` —
Ghidra project files are binary and large.

### 3.3 CLI wiring

- `calxgloss doctor` — read-only report of every check above (install, version,
  extension, server kind/version/port, project, per-DLL program status).
  Formatted via `calxgloss-reports`. Exit code ≠ 0 on failures, with remediation
  hints (e.g. "extension built for 12.1.1 but Ghidra is 12.1.2 → reinstall the
  6.0.0 zip into `~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/`").
- `GhidraSession::ensure(&settings, &binaries) -> (GhidraClient, Owned)` called
  at the top of every Ghidra command, replacing today's bare
  `GhidraClient::new(url)` + probe.
- New `ProgressEvent` variants: `GhidraServerStarted`, `GhidraProjectCreated`,
  `GhidraProgramAnalyzed { dll, secs }` — surfaced on the web dashboard too.

### 3.4 Config additions (`[ghidra]`)

```toml
[ghidra]
url         = "http://127.0.0.1:8080"   # unchanged default
auto_start  = true          # spawn headless when nothing answers
headless    = "auto"        # auto | always | never (never = GUI-only, today's behavior)
install_dir = ""            # empty → discover
project     = ""            # empty → <repo_dir>/ghidra/<target>.gpr
min_version = "12.1.2"      # Ghidra; plugin pinned ≥ 6.0 by the extension check
start_timeout_secs = 90
```

### 3.5 Bootstrap: from nothing installed to fully working (`calxgloss doctor --fix`)

Optional opt-in path that takes a machine with **no Ghidra and no plugin** to a
working headless setup. Verified against GitHub on 2026-10-03:

| Fact | Value |
|---|---|
| Ghidra repo/assets | `NationalSecurityAgency/ghidra`, tag `Ghidra_<ver>_build`, one asset `ghidra_<ver>_PUBLIC_<date>.zip` (~570 MB) |
| Plugin repo/assets | `bethington/ghidra-mcp`, tag `v<ver>`, one extension zip `GhidraMCP-<ver>.zip` (~730 KB) |
| Checksums | **both** expose `digest: "sha256:…"` directly in the releases API response — verify after download |
| Version coupling | the plugin zip is built for **one** Ghidra build (`extension.properties` → `version=12.1.2` for 6.0.0). Latest Ghidra (12.1.4) ≠ plugin's Ghidra (12.1.2) |
| Hard prerequisite | **Java 21 LTS** — Ghidra 12.x won't run without it |

**Strategy: plugin-first.** The plugin pins the Ghidra version, so:

```text
1. JDK check        java -version ≥ 21 (or ghidra.java_home config).
                    Missing → stop with exact remediation (no silent JDK installs).
2. Plugin           GET repos/bethington/ghidra-mcp/releases/latest
                    → download GhidraMCP-<ver>.zip (small) → verify sha256 digest
                    → unzip to cache → READ extension.properties → required Ghidra version X.
3. Ghidra           GET repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_X_build
                    (fall back to listing releases for nearest ≥ X)
                    → stream ~570 MB with progress + resume (HTTP Range)
                    → verify sha256 → unzip.
4. Install          Ghidra  → <install_prefix>/ghidra_X_PUBLIC/   (default
                    ~/.local/share/calxgloss/ghidra/), restore exec bits on
                    ghidraRun + support/*.sh.
                    Plugin  → unzip into ~/.config/ghidra/ghidra_X_PUBLIC/Extensions/
                    (matches how the user installs manually; works for GUI and headless).
5. Verify           run the full P0–P2 preflight: headless start → check_connection
                    → project → programs.
```

Selection rules:
- **Ghidra present, plugin missing/mismatched** → pick the newest GhidraMCP
  release whose `extension.properties` matches the installed Ghidra (scan
  releases backwards; the zip is small, so probing is cheap).
- **Plugin present, Ghidra missing** → read its `extension.properties` and
  fetch exactly that Ghidra.
- **Both missing** → plugin-first as above.
- Pin with `ghidra.pin_version` / `--ghidra-version` to override.

CLI + config:
- `calxgloss doctor --fix` (or `calxgloss setup ghidra`) runs the bootstrap;
  plain `doctor` stays read-only.
- `ghidra.auto_install = false` by default — a ~570 MB download always needs
  explicit consent; `--install-ghidra` opts in per run.
- Offline/air-gapped: `--ghidra-zip <path>` / `--plugin-zip <path>` install
  local artifacts (same checksum-free path, exec-bit fixup still applies).
- Downloads cached in `$XDG_CACHE_HOME/calxgloss/` so retries don't refetch.
- Optional `GHIDRA_MCP_GITHUB_TOKEN` for API rate limits.

Safety:
- Never sudo; install only under user-writable prefixes.
- Verify the API `digest` on every download before unzipping.
- Existing installs are never modified or upgraded without `--fix` + a
  confirmation showing old → new versions.
- An install manifest (`~/.local/share/calxgloss/ghidra-install.json`) records
  what calxgloss installed where, enabling clean upgrade/uninstall and letting
  `doctor` distinguish calxgloss-managed from user-managed installs.

---

## 4. Phasing

| Phase | Deliverable | Notes |
|---|---|---|
| **P0** | `check_connection` + `doctor` (checks only, no spawning) | Small; immediately useful; catches the 8080-is-my-AI class of error |
| **P1** | Headless spawn/supervise + port discovery + ownership/shutdown | The launch recipe is proven by `docker/entrypoint.sh` |
| **P2** | Project bootstrap: create/open `.gpr`, `load_program` + `run_analysis` with progress | First analysis of a big DLL is minutes — progress events + resumable (project persists, later runs are fast) |
| **P3** | Polish: pid-file reuse across runs, `--no-ghidra-autostart`, GUI-vs-headless probe branching, program-selector params for multi-program safety (`GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1`) | |
| **P4** | Bootstrap (`doctor --fix`): plugin-first download of GhidraMCP + matching Ghidra release, sha256 verify, install, then run P0–P2 verification. JDK-21 prerequisite check gates it | Takes a bare machine to fully working; see §3.5 |

## 5. Risks / decisions

1. **First-run analysis time** — auto-analysis dominates (minutes per large
   DLL). Mitigate: persistent project, `analysis_status` polling, and a
   `re/ghidra/analysis_cache.json` recording which files were analyzed so
   re-runs skip it.
2. **GUI vs headless divergence** — cursor endpoints are GUI-only; `probe()`
   and anything using them must branch on server kind. Headless is the right
   default for pipelines; GUI stays supported for interactive work.
3. **Version coupling is strict** — the extension jar is compiled against one
   Ghidra build (`version=12.1.2` in `extension.properties`). A Ghidra upgrade
   silently breaks the extension; `doctor` must compare the two and say so.
   This is also why bootstrap is **plugin-first**: the plugin release decides
   which Ghidra version to fetch (plugin 6.0.0 targets 12.1.2 while the newest
   Ghidra is already 12.1.4 — "latest of each" would produce a broken pair).
4. **Port collisions** — 8080 is the local AI. Never auto-bind: calxgloss
   starts the headless server on the *configured* port only if free, else on
   the bridge default 8089, and discovery (UDS scan) reconciles the client URL.
5. **Ownership** — killing a Ghidra GUI we didn't start is a hard no. Track
   ownership explicitly (`Owned` vs `Attached`).
6. **Security env** — respect the bridge defaults: script execution endpoints
   are off (`GHIDRA_MCP_ALLOW_SCRIPTS` unset), and consider
   `GHIDRA_MCP_REQUIRE_PROGRAM_SELECTORS=1` once multiple programs load at once.

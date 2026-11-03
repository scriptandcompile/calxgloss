# The analysis pipeline end to end — CLI, workers, ingest, and where results land

> Part of the [OpenAPK/OpenBin overview](README.md). This chapter traces the
> whole analysis pipeline: binary on a laptop → local Docker worker → ingest
> transport → platform-stored analysis data → frontend reads. Claims cite
> clone-relative `path:line` at `/tmp/opencode/openbin` @ `aee59b05`;
> anything not directly verified is marked *(unverified)*.

## 0. Shape of the pipeline

Three kinds, three transport shapes (V16/V30; `ProjectKind` dispatch in
`ProjectService.upload`, `projects/ProjectService.java:212-244`):

| Kind | Engine runs | Binary bytes | Analysis bytes | Server entry |
|---|---|---|---|---|
| **BIN** (ELF/PE/Mach-O) | ghidra-worker container **on the user's laptop** (CLI) | never uploaded | gzip of worker JSON → presigned S3 PUT | `/api/projects/ingest/initiate` + `/finalize` |
| **APK** | jadx-worker container **on the laptop** (CLI) | **the APK itself is uploaded** | the decompiled tree.tar.gz rides the same multipart POST | `POST /api/projects` (`file` + `decompiledTree` parts) |
| **SCRIPT** (npm/PyPI/shell) | cloud Lambda / RIE HTTP (server-invoked) | tarball streamed to S3 | findings.json from S3 → Postgres | `POST /api/projects/script` (sync) |

The design pivot: cloud Ghidra and cloud JADX were **sunset for cost** and
replaced by local-worker Docker + upload of *results*, not *compute*
(`projects/GhidraSunsetMessage.java:5-16` — "this isn't a feature cut — it's
a re-shape"). The backend treats CLI-sourced and worker-sourced submissions
identically: the CLI runs the byte-identical image
(`cli/ghidra.go:22-26` — "running it locally guarantees byte-identical
decompile output … the backend's ingest path doesn't need to discriminate").

## 1. The Go CLI (`cli/`)

### 1.1 Commands and auth

Seven subcommands (inventory §6 unchanged): `login` is OAuth 2.0 device
authorization grant against Keycloak client `openbin-cli`
(`cli/auth.go:94-136` — `device_code` / `verification_uri[_complete]`
polling with `urn:ietf:params:oauth:grant-type:device_code`); tokens land in
`~/.config/openbin/credentials.json`, XDG-aware (`cli/config.go:133-138`),
and every API call refreshes via the refresh token before hitting the
backend, persisting the rotated pair (`cli/auth.go:169-178`; `api.go`
refreshes *again* between initiate and finalize because the S3 PUT can take
minutes — `cli/api.go:141-144`). API/auth bases default to
`api.openapk.ai`/`auth.openapk.ai`, overridable by `OPENBIN_API_URL` /
`OPENBIN_AUTH_URL` or a saved server config (`cli/config.go:94-112`).

### 1.2 Local worker images: where they come from, how they run

Confirmed and refined inventory §6:

- Tags `openbin/ghidra-worker:7` / `openapk/jadx-worker:bundled-2`
  (`cli/config.go:62,69`); ingest schema `"2.0"` (`cli/config.go:32`).
- `ensureDockerImage` (`cli/ghidra.go:169-212`), explicit comment "No
  `docker pull` and no registry auth" (:167-168). Order: `docker inspect`
  hit → tarball found next-to-binary / `$XDG_DATA_HOME/openbin/` /
  `/usr/local/share/openbin/` / cwd (`:306-333`) → lazy download from
  `https://github.com/openbin-ai/platform/releases/latest/download`
  (`cli/imagefetch.go:18`; `.part` + rename so an interrupted download never
  looks complete, 60-min client timeout `:47-49`; 32 MB progress ticks
  `:85-105`) → `docker load` + tag verification (`:215-227`). Stale-cache
  re-download when a loaded tarball lacks the expected tag after a worker
  version bump (`:192-205`). Air-gapped override: `OPENBIN_RELEASE_BASE`
  env or the server's `downloadsBase` captured by `login --server`
  (`cli/imagefetch.go:11-18`).
- `dockerPreflight` runs before any load/run: `exec.LookPath` + bounded
  15s `docker info` with platform-tailored messages (`cli/ghidra.go:225-241`).
- `runLocalGhidra` (`cli/ghidra.go:59-99`): free port via
  `net.Listen("tcp","127.0.0.1:0")` (:367-369), `docker run -d -p
  127.0.0.1:<port>:8000` — **loopback-only publish**, and *intentionally no
  `--rm`* so a dead Ghidra survives long enough for `docker logs` +
  `docker inspect` post-mortem (:380-397). Health-poll 60s, then
  `POST /analyze` multipart; logs streamed with `[ghidra]` prefix + a
  wall-clock heartbeat; failures dump container logs. Timeout overrides
  render as `-e GHIDRA_ANALYZE_TIMEOUT=` / `-e GHIDRA_PER_FILE_TIMEOUT=`
  (:28-50); `--processor` forces a Ghidra language ID for raw firmware.

### 1.3 What actually leaves the laptop

The sunset message claims "your binary never leaves your machine"
(`GhidraSunsetMessage.java:23-25`). Precisely:

- **BIN flow**: the binary itself is never uploaded. What leaves: metadata
  (`name`, `originalFilename`, `archHint`, `sizeBytes`, **sha256**,
  `schemaVersion`, `source:"cli"`, `uploadSizeBytes`, optional `bundleId` —
  `cli/api.go:31-44`), then the **gzipped worker JSON** PUT directly to S3.
  That JSON contains decompiled C for every function, per-instruction
  disassembly, the full program listing, strings, imports/exports, memory
  blocks (`ghidra-worker/scripts/extract.py:19-46`) — a derived, near-total
  semantic representation of the binary. The claim holds *literally about
  the file bytes*, not about the information.
- **APK flow**: the APK/XAPK **is** uploaded, streamed together with the
  decompiled tree in one multipart body (`cli/apk_upload.go:12-24`). No
  claim of sample-locality here at all.
- **Native-lib flow**: sha256 is "currently informational" and sizeBytes
  unused on the native ingest path (`cli/api.go:227-228`).

### 1.4 Ingest v2 vs legacy v1 upload

`cli/api.go:14-27` documents the why in the CLI itself: v1.0 POSTed the
whole worker JSON as one body → Jackson tree = 5-10× heap, 100 MB JSONB
row; v2.0 gzips to a temp file (comment: 200 MB JSON gzips to 20-40 MB —
`api.go:75-79`), `POST /api/projects/ingest/initiate` mints a presigned PUT
(+ `x-amz-tagging status=pending` required header echoed back), streams the
gz from the file handle, `POST /ingest/finalize`. Retries: 3 attempts w/
exp backoff on initiate/finalize (5xx/network) and 3 on the PUT — the
presigned URL is reusable until its TTL (`api.go:23-27`). Three variants:
`ingestProjectV2` (:73), `ingestNativeLib` (:194, targets
`/api/projects/{apkId}/native/ingest/*`, body carries `libPath`+`sha256`,
finalize carries `nativeAnalysisId` — :171-178), `ingestSampleV2` (:299,
V41 multi-sample). The APK path is a different transport entirely: one
multipart `POST /api/projects`, retried **once** with the io.Pipe rebuilt
per attempt, 4xx surfaced as-is (`apk_upload.go:16-50`).

## 2. ghidra-worker

### 2.1 FastAPI wrapper around analyzeHeadless

`ghidra-worker/app/main.py` (262 LOC) — one endpoint `POST /analyze`
(multipart `binary` + form `arch`/`processor`/`loader`), deliberately
**synchronous**: "the OpenAPK core wraps this call in its own @Async
executor … we don't have to ship a separate job store here" (:1-8). Budget
stack (`:38-51`): `GHIDRA_ANALYZE_TIMEOUT` 1500 s whole-subprocess wall,
`GHIDRA_PER_FILE_TIMEOUT` 1200 s Ghidra-internal per-file, and
`GHIDRA_EXTRACT_TAIL_MARGIN` 150 s sliced off and handed to extract.py as
`GHIDRA_EXTRACT_DEADLINE_EPOCH` (:43-51 + :156-161) so the
post-script **emits a partial result before** the hard kill — the comment
names the old failure mode: "a 504 with nothing salvaged". The `processor`
form is regex-validated as `family:endian:size:variant`
(`_PROCESSOR_RE`, :73-75) "so a caller-supplied value can't smuggle
arbitrary argv tokens"; `loader=binary` forces Ghidra's raw BinaryLoader
and *requires* processor (:104-108). `cmd` is built with `-postScript
extract.py <out.json>` (:131-153); a preflight pre-script runs first
(§2.3). Errors: nonzero analyzeHeadless exit, missing result file,
and a `{"error":…}` result are all mapped to 500 with a debuggable blob
(`_build_error_detail`, tail of file); temp workspace removed in `finally`.

### 2.2 scripts/extract.py — the analysis JSON contract

The docstring at `ghidra-worker/scripts/extract.py:19-46` is the
authoritative schema (matches inventory §7; verified field-by-field):
`functions[]` — `name, address, size, signature, decompiled` (C, null for
external/thunk), `disassembly[{addr,text}]`, `line_map[[line,[addr…]]]` and
`vars[{name,addrs}]` for the side-by-side cross-highlight,
`xrefs{callers,callees}`, `external/thunk` flags; plus `strings[]`,
`imports[]`, `exports[]`, `entry_points[]`, `tls_callbacks[]` ("anti-debug
hook surface"), `data_symbols[]`, `memory_blocks[]`, `listing[]`
(full Ghidra-Listing-style per-section disasm, undefined bytes coalesced
into 16-byte hexdump rows with ASCII column), `metadata{compiler,language,
executable_format,image_base,*_count}`. The `vars` list is regex-filtered
to identifier shape so constants and punctuated data names don't pollute
cross-highlighting (`:54-59`). The critical operational fact, restated:
**analyzeHeadless's exit code reflects the analysis, NOT the post-script**
— extract.py therefore writes either the full JSON or `{"error": …}` on
every path (`:10-15`). Jython 2.7 constraints spelled out (module-level
code only, `currentProgram` injected globals) `:6-8`.

### 2.3 preflight.py — stripped-binary tuning, sync/stateless design

`scripts/preflight.py:1-13`: analyzeHeadless runs pre-scripts *after
import, before analysis*; Ghidra defaults find only `.dynsym` exports on
stripped ELF — "WhatsApp's libs.so (17MB, stripped) yielded 10 functions on
defaults" — so ten analyzers get force-enabled (Function Start Search ×3,
Decompiler Parameter ID / Switch Analysis, Demangler GNU, ELF Scalar Operand
References, Reference, Subroutine References, Embedded Media); **AIF is
deliberately not enabled** ("can 10x analysis time"). Missing options are
skipped silently; a tuning failure never blocks analysis (:41-59). The
worker is stateless: per-job temp dir, JSON in/out, no job store — the
@Async executor on the Spring side is the only job state
(`app/main.py:1-8`).

## 3. jadx-worker

`jadx-worker/app/main.py` (315 LOC): `POST /decompile` returns
`application/gzip` = `tar -cz` of the JADX out dir, streamed 64 KB at a
time (:273-295), with response headers `X-OpenApk-Job-Id`,
`X-OpenApk-Jadx-Returncode`, `X-OpenApk-Sources-Count` (:295-299) — the
backend inspects the returncode *against output existence*: if sources
exist, partial output is accepted, otherwise hard failure (:255-268).
Containment: `prlimit` wraps the JVM for memory+CPU (:215-233; the comment
notes RLIMIT_AS kills the JVM at startup so it's a JVM-sized cap, not an
RSS cage, :55-62), `JADX_TIMEOUT_SEC` 900 s wall (:53), non-root uid 10001
in the image (`Dockerfile:63-65`). `X-Worker-Token` is compared with
`hmac.compare_digest` — **but when the worker's own `WORKER_TOKEN` env is
blank the check is a no-op** (:88-92; blank = local dev per
`application.yml:199-201`). Split-container guards: max 64 inner APKs,
4 GiB expanded total, `config.*` files dropped (:80-85 + :134) — zip-bomb
and input-count containment.

## 4. Server side

### 4.1 `projects/ingest` — the state machine

`IngestService` (352 LOC) carries the migration history in its own javadoc
(`:41-67`): schema whitelist `SUPPORTED_SCHEMAS = Set.of("1.0","2.0")`
(:67) — **the legacy v1 inline-JSONB `/ingest` path is still live** for old
CLIs (stores into `binary_analysis_jsonb`). Initiate
(`:196-260`): 503 unless `openapk.analysis-storage.bucket` is configured;
pre-create the project row in `INGEST_PENDING` (status also
`workflow_status NEW`, `sha256 "pending"`→ real from the initiate body —
*(unverified: exact sha256 wiring in `initiate`*) ); **pre-set the S3 key
on the row** so a CLI crash between PUT and finalize stays
forensically-recoverable; presign the PUT tagged `status=pending` so a
**1-day "orphan ingest" S3 lifecycle rule** reaps abandoned uploads.
Finalize (`:262-352`): require status `INGEST_PENDING`; HEAD the object;
stream-parse the gzip token-by-token via `AnalysisMetadataExtractor` —
never a JsonNode tree — extracting arch/format/compiler/languageId/imageBase
(worker arch beats the CLI's `archHint`) and function count; persist etag +
size; flip to `READY` + `decompiledAt`; then **flip the S3 object's tag
pending→ready** — a failure here is logged but must not fail finalize, with
an explicit comment that the lifecycle rule would otherwise delete the good
result ~24h later (:329-341).

### 4.2 `nativeanalysis` — per-`.so` lifecycle + the cloud-disabled gate

The config flag: `application.yml:179-184` —
`openapk.ghidra.worker-disabled: ${OPENAPK_GHIDRA_DISABLED:true}`, comment
"2026-06-03: cloud Ghidra disabled. AWS compute cost outpaced what a free
OSS project can carry… Flip back to false … once sponsorship lands." The
JADX twin at `:199-204` (`OPENAPK_JADX_DISABLED:true`, "biggest line on the
AWS bill"). Enforcement code (all throw **503 with `GhidraSunsetMessage.TEXT`
/ `JadxSunsetMessage.TEXT` as the body — the frontend renders that exact
string as the "download the CLI" card, `GhidraSunsetMessage.java:5-13`):

- BIN upload gate: `ProjectService.java:224-230` — reject *before* saving
  the upload, "that would waste a quota slot and look like a crash";
- APK upload gate: `:232-244` — an APK **without** a CLI-supplied
  `decompiledTree` gets the sunset 503; with a tree it "sail[s] through —
  no worker, no quota charge";
- per-`.so` kickoff: `NativeAnalysisService.java:167-170`.

`NativeAnalysisStatus` (file :10-26) is five-valued: `PENDING`/`RUNNING`
(cloud dispatch, sunset-era) + `INGEST_PENDING` (CLI flow) + `READY` /
`FAILED`. Kickoff (`:159-226`) is idempotent in-flight (returns current
view), resolves concurrent-INSERT races to the winner, and reserves the
`WorkerQuotaService` slot **after** flushing the PENDING row but **before**
dispatch so a 429 rolls the row back. The `@Async` runner
(`NativeAnalysisRunner.java:46-103`) drives RUNNING→READY/FAILED and never
throws; even a failed FAILED-write is logged and the row left as-is.

### 4.3 `jnibridge` — `.so` ↔ Java bridge

`JniBridgeScanService` (655 LOC pkg) regex-walks the decompiled JADX tree
for `System.loadLibrary("foo")` / `System.load("/abs/libfoo.so")` /
`Runtime.getRuntime().loadLibrary(…)` (`:49-52,78-85`), groups the project's
`.so` files under `resources/lib` by short name **and** by absolute-path
basename (`:407-408`), and joins them against `native_analyses` results —
loading each `.so`'s Ghidra JSON through `NativeAnalysisJsonLoader`
(S3-or-JSONB, same dual-read as §4.5) — to pair loader call sites with
library exports and `native` method declarations. Result cached in
`projects.jni_bridge_jsonb` (V15); `POST /rescan` recomputes. The CLI
`attach-native` command runs ghidra-worker locally on a `.so` and ships it
via `ingestNativeLib` (§1.4) — i.e. the bridge's Ghidra input also arrives
through the local-worker + presigned-PUT pipeline, not cloud Ghidra
(`nativeanalysis/NativeAnalysisIngestService.java:38-40` names this as the
sunset replacement path).

### 4.4 `decompile_progress` (V14) and status UX

V14 adds `decompile_phase` + `decompile_started_at`; the migration comment
enumerates the phase enum `OPENING_APK, DECOMPILING, BUILDING_TREE,
INDEXING_SYMBOLS, INDEXING_USAGES` and the rationale: a static
"decompiling…" chip during a 1-5 min JADX run is UX poison; the timestamp
drives an elapsed-time display. Written from `ProjectService.java:570,584`
(`STARTING` at dispatch). Pipeline status is separate from the case
`workflow_status` (V2/V5) and both ride the Projects list; INGEST_PENDING
(V23) slots between. With the JADX sunset, the same post-decompile
pipeline (tree cache, symbol/usages indexing) runs against the CLI-supplied
tree, so the phase chips still apply to the CLI flow *(unverified: which
phase strings are written in the CLI-tree path specifically)*.

### 4.5 The JSONB→S3 migration (V22/V23/V25) — the five-phase plan

V22's header comment self-identifies as **"Phase 1 of the JSONB→S3
migration"** and names the endgame: "Phase 5 drops [`binary_analysis_jsonb`]
once dashboards confirm zero reads." Phases 2-4 are *not enumerated
anywhere in the clone* — only the endpoints are (unverified intermediate
steps). What the code proves of the plan: V22 columns are additive and
dual-write-compatible (JSONB stays nullable, still read as fallback); V23
is the prod-hotfix widening the `status` CHECK because "V22 shipped the
value before the constraint allowed it" (V23 file :1-7); V25 mirrors the
same five columns + INGEST_PENDING index for `native_analyses` ("Dual-read
compatible … prefers analysis_s3_key when set" header). The read funnel is
`projects/analysis/BinaryAnalysisLoader` (:13-27): **single read path for
all six analysis consumers**, preference order *legacy JSONB first, then S3*
(inline wins if both populated), **deliberately not cached** — "the
analysis JSON can be tens of MB and we don't want to pin it per-project in
the heap; … a small Caffeine cache keyed on (projectId, etag) is the right
next step". Upload path never touches disk (`ProjectService` streams to
S3); reads serve through a **short-TTL CloudFront signed URL** surfaced as
`analysisDownloadUrl` on the project response — the openbin frontend
fetches the worker JSON **directly from CloudFront** when present and falls
back to `/api/projects/{id}/binary-analysis` only for legacy inline blobs
(`openbin-frontend/src/pages/ProjectView.tsx:274-279`). Forking shares the
blob by S3 key with refcount checks (`ProjectService.java:746-750` —
"source has no analysis to fork" is a CONFLICT).

### 4.6 Re-analysis policy

No automatic re-run exists. For BIN projects the analysis blob is written
once (worker or ingest) and is immutable in normal use; a fresh analysis
means re-running the CLI (new project row, new S3 object) or re-kicking the
cloud path — `NativeAnalysisService.kickoff` doubles as the re-analysis
entry: an existing READY `native_analyses` row is **reset** (status
PENDING, `result_json` cleared, error/analyzedAt nulled —
`NativeAnalysisService.java:188-196`) and re-dispatched, subject to the
sunset 503 + quota. There is no `force` parameter on any of these paths
(grep-verified). `POST /digest/rescan` (analysis package) re-scans the
*static digest*, not the Ghidra blob *(unverified beyond the endpoint
listing)*.

## 5. Supply-chain workers (script / pypi / shell)

### 5.1 Detection and invocation

`script` package (1,588 LOC): `ScriptAnalysisService.uploadAndAnalyze`
(:97-240) is **synchronous by design** — validate (≤25 MB,
`application.yml:230`), create the SCRIPT project row, sniff ecosystem
*before* paying the upload (`:145-147`), stream the upload straight to the
analysis S3 bucket, invoke the right worker (90 s cap vs the Lambda's 60 s,
`application.yml:232-234`), pull `findings.json` back from S3, persist,
flip READY. Routing (`ScriptEcosystemDetector`, 170 LOC): extension first
—.ps1/.psm1/.sh/.bash/.zsh → shell, no sniffing (:52-57); then magic bytes
(:60-77); then a shallow zip peek — any `*.dist-info/` entry is a wheel →
PyPI (:121-127); manifest names `package.json`→NPM, `setup.py` /
`pyproject.toml` / `PKG-INFO` / `setup.cfg` → PyPI (:147-148). A friendly
500 tells users to `unzip -P infected` password-protected archives first
(:190-198). Config: `openapk.script-analyzer` (`application.yml:208-234`)
— `enabled:false` by default, `mode: lambda|http` (http = the same three
worker containers under the Lambda **Runtime Interface Emulator** for
self-host), three separate function names, one per ecosystem.

### 5.2 What each detects

- **script-worker** (JS, Babel AST): the 8 rules are enumerated verbatim at
  `src/analyzer.js:1-9` — secret-theft, fs-traversal, known-c2, net-exfil
  (HIGH), eval-surface, spawn (HIGH), install-hook (from `package-json-parser`,
  severity set in handler), entropy-blob (INFO); CRITICAL>HIGH>MEDIUM>INFO.
  Deobfuscation has **two layers**: analysis-time `tryDeobfuscate` (runs on
  every file, fires only when confident, "never costs the user a choice")
  vs analyst-pressed on-demand engines (`src/engines.js:3-19`):
  `obfuscator-io` (ben-sb), `generic` (ben-sb js-deobfuscator), `caesar`
  (own Caesar-over-fromCharCode decoder — "the dominant NPM dropper
  shape"), plus `auto` best-scoring; the honesty note that both third-party
  engines "frequently fail to resolve the string array" on v4
  javascript-obfuscator output is why the UI offers a choice. Fixtures
  (`fixtures/obfuscated/README.md`): `plain.js` (real credential-theft +
  HTTPS-exfil source), `string-array.js` (genuine javascript-obfuscator
  output, regen command in the README), `caesar-dropper.js` (synthetic,
  "the Shai-Hulud, lottiefiles, the Red Hat campaign" shape — generated so
  no live malware sits in the repo). Also `benign-pkg/` and
  `malicious-pkg/` (install.js hook) fixtures.
- **pypi-worker** (Python `ast`): byte-for-byte rule twin, enumerated at
  `src/analyzer.py:1-13` (same 8 ids; net-exfil = urllib/requests/httpx/
  socket; spawn = subprocess/os.system/os.popen w/ shell=True); install
hooks come from `manifest_parser` over setup.py/pyproject.
- **shell-worker** (regex on purpose, per README): rule categories present
  in `src/analyzer.py`: `POWERSHELL_RULES` (:79) + `POSIX_RULES` (:124);
  emitted rule ids seen: encoded-cmd (CRITICAL/HIGH: `-enc`,
  `base64 -d|bash`), eval-surface (`IEX(`, `Invoke-Expression`,
  `[scriptblock]::Create`), net-exfil, persistence (CRITICAL/HIGH),
  secret-theft, spawn — the inventory's `curl | sh` example verified in
  spirit *(exact rule list not exhaustively grepped — unverified beyond the
  six ids)*.

### 5.3 Where results land; script-worker vs project_scripts

Landing (V30): `script_analyses` — findings JSONB **in Postgres**
(tens-of-KB, unlike the 100 MB BIN blob that forced S3), severity counts,
package name/version, `findings_text` tsvector, `bundle_s3_key` (the only
S3-resident artifact for scripts). Deobfuscation results land in
`script_deobfuscations` (V38, per project+file+engine). **Do not confuse
the two script subsystems**: `script` (singular) = the supply-chain
Lambda analyzers above; `scripts` (plural, V46) = `ProjectScriptService` —
saved analyst/BINNY scripts, "nothing here is ever executed server-side"
(inventory §2, V46 comment verified). Same word, opposite threat models.

## 6. Post-ingest: how frontends read analysis data

- **BIN blob**: `GET /api/projects/{id}/binary-analysis` returns the full
  worker JSON string, **renames already applied backend-side**
  (`ProjectService.binaryAnalysisJsonFor`, :872-882; the public variant
  :861-870 shares the exact code "so the public path can never diverge"),
  409 unless READY. The fast path skips Spring entirely: the project
  response carries `analysisDownloadUrl` (short-TTL CloudFront signer over
  the S3 object) and the frontend fetches from CDN (`ProjectView.tsx:274-279,
  561-603`); sample-switcher uses `/samples/{id}/binary-analysis` (V41).
  Every analysis consumer (digest, analysis, crypto, callchain, deobf,
  renames) reads through `BinaryAnalysisLoader` (§4.5).
- **APK tree**: files are served from storage with rename replay at
  read-time (inventory §2); `file_tree_jsonb` (V12) pre-built at JADX
  completion avoids 100k+ stat calls on tree render — write sites verified
  in `ProjectService`/`SymbolService`/`RenameService` (grep
  `setFileTreeJson`/`setSymbolIndexJson`).
- **Symbols**: declarations cached in `symbol_index_jsonb` (V7) by
  `SymbolService` (`/symbols` + `/symbols/rebuild`); usages live in
  `project_usages` rows (V13) queried via JdbcTemplate, powering
  `/symbols/definition` + `/symbols/usages` and the call-chain walker.
- **Status UX**: dual status (pipeline V2/V23 × workflow V5) + V14 phase
  chips + elapsed timer; INGEST_PENDING renders as an in-progress ingest;
  sunset 503 bodies are rendered as the CLI-download card.

## 7. calxgloss comparison

**Overlap (same problem, different shape).**
- *Engine isolation*: OpenBin isolates the analysis engine as a **Docker
  sidecar over HTTP with one fat JSON contract** (ghidra-worker, extract.py
  schema §2.2); calxgloss deletes the bridge entirely and runs Kuna
  in-process behind the `ScanSource` seam (ADRs 0039/0040/0041 —
  `docs/adr/0039-the-analysis-engine-is-a-seam-choice-kuna-loads-the-target-in-process-…`,
  `0041-kuna-is-the-only-analysis-engine-…`; `crates/integrations/calxgloss-decomp/`).
  Both converge on *byte-stable engine output as a contract*: OpenBin pins
  the image tag (`openbin/ghidra-worker:7`) precisely so local and cloud
  output are byte-identical; calxgloss keys its scan-read cache to the
  **engine-build identity** so a swap can never replay stale answers
  (ADR-0055).
- *Whole-binary batch before per-item work*: OpenBin's Ghidra auto-analysis
  + extract pass is one whole-binary batch whose JSON is later sliced per
  function/consumer; calxgloss runs the 15-scan pre-batch
  (`run_prebatch_scans`, `crates/pipeline/calxgloss-translator/src/pipeline/scan_phase.rs:273`)
  and slices per unit at prompt time. Same "scan once, answer many" shape.
- *Result caching*: OpenBin's `BinaryAnalysisLoader` explicitly *refuses*
  a cache ("tens of MB … Caffeine keyed on (projectId, etag) is the right
  next step") because the blob lives in S3; calxgloss's three-tier
  read-through cache (ADR-0042/0043, `calxgloss-decomp/src/cache.rs`) is
  the same keying idea ((binary hash, format version, engine build) instead
  of (projectId, etag)) done locally.
- *Coverage honesty*: preflight.py's "enabled 10 / skipped 4" println and
  the AIF refusal is a crude cousin of calxgloss's scan-coverage records +
  admission lines (ADR-0053) — both admit what the analyzer skipped, but
  only calxgloss makes it a durable, per-scan record.

**calxgloss-only.** Everything past the analysis blob: per-function
verification gate (Wine baselines + API-call trace, ADR-0057), attempt-branch
git history, retry ladder + fault monitors, unknown ledger (ADR-0056),
write-back through a typed seam, version pairing (bdiff). OpenBin stores a
*dead snapshot* of pseudocode; calxgloss keeps the program live and
queryable. OpenBin has no notion of "was this decompilation correct" — the
analyzeHeadless-exit-code-lies problem (§2.2) is met with an error channel,
not a correctness verdict.

**OpenBin-only.** The transport problem itself: presigned-PUT ingest v2
with gzip streaming, orphan-tag lifecycle reaping, dual-write migration
with dual-read fallback (V22→V25, §4.5). calxgloss dodges all of it by
staying local (JSON files under `re/`) — but calxgloss has *no answer* for
multi-tenant analysis storage; if it ever shipped hosted results, V22-V23's
prod-bug arc (ship the enum value, widen the CHECK in V23) is the caution.
Also OpenBin-only: the supply-chain analyzers (3 rule-set workers, zero
calxgloss counterpart), local-worker image distribution as version-less
GitHub release assets with stale-cache recovery (`imagefetch.go` +
`ensureDockerImage`), and the cost-sunset pattern — the platform *shrunk
itself* by moving compute to users rather than paywalling.

**Verdict.** The pipelines meet at the same middle — a batched, pinned,
whole-binary engine pass serialized as JSON — and diverge at both ends.
OpenBin's ends are transport (laptop→S3→CDN) and consumption (human
annotation, reports); calxgloss's ends are evidence depth (15 scans,
coverage honesty) and verification (tests prove the reading). For
calxgloss's purposes: the ghidra-worker extract schema is a good external
validation of "one fat per-binary document, consumed by many views"
(it independently evolved line_map/xref/vars fields calxgloss carries as
typed records), and the S3 five-phase migration is the template study for
any future "ship scan documents somewhere remote" move — but nothing in
OpenBin challenges calxgloss's in-process seam + ADR-0043/0055-keyed cache
stance; if anything it *confirms* it, since OpenBin pays every cost that
calxgloss's locality avoids (heap blowups, orphan objects, sunset gates).

## 8. Corrections to the inventory chapter

Within this chapter's domain, `20-openbin-inventory.md` holds up; the
gaps/corrections found:

1. **Gap (v1 still live)**: §6 presents ingest v2 without saying the
   legacy v1 inline-JSONB `POST /api/projects/ingest` is *still accepted* —
   `SUPPORTED_SCHEMAS = Set.of("1.0","2.0")`
   (`projects/ingest/IngestService.java:67`) and 1.0 stores into
   `binary_analysis_jsonb`.
2. **Gap (orphan lifecycle mechanics)**: the 1-day S3 lifecycle rule keyed
   on the `status=pending` tag, the pre-set S3 key for crash forensics, and
   the finalize-time tag flip pending→ready (whose silent failure can reap
   a *good* object ~24h later) are not in §6/§4-V22 rows —
   `IngestService.java:234-236,256,329-341`.
3. **Refinement (read order)**: §2 calls `BinaryAnalysisLoader` a "single
   JSONB-or-S3 read path" — true, but the preference is **JSONB first**
   when both exist, and it is deliberately uncached
   (`BinaryAnalysisLoader.java:41-48`); worth stating for perf analysis.
4. **Gap (five-phase plan is half-documented)**: V22 names "Phase 1" and
   "Phase 5 (drop JSONB)"; phases 2-4 exist nowhere in the clone — the
   inventory's "five-phase migration" framing (from our own brief) is
   only partially evidenced in-repo.
5. **Refinement (native statuses)**: V8/V25 rows imply
   INGEST_PENDING/READY/FAILED; the enum also carries `PENDING` and
   `RUNNING` for the sunset cloud path
   (`nativeanalysis/NativeAnalysisStatus.java:20-26`), and the quota
   reserve-before-dispatch ordering (`NativeAnalysisService.java:207-211`)
   is missing.
6. **Gap (jadx auth is conditional)**: `X-Worker-Token` is only enforced
   when the worker's own `WORKER_TOKEN` env is set; blank = wide-open
   (`jadx-worker/app/main.py:88-92`). §7 says "shared secret for its
   public ECS endpoint" without the self-host caveat.
7. **Gap (BIN blob serving bypasses Spring)**: the short-TTL CloudFront
   `analysisDownloadUrl` fast path (frontend fetches the worker JSON
   directly from CDN; `/binary-analysis` is the legacy-JSONB fallback) is
   absent from §2/§8 (`ProjectView.tsx:274-279`).
8. **Nit**: `cli/auth.go:16` comment says `~/.config/openapk/credentials.json`
   while the code resolves `openbin` (`config.go:133-138`); the inventory
   prints the correct path but the clone contains the stale comment.
9. **Gap (script-analyzer sync design + RIE detail)**: §2's
   `HttpScriptWorkerInvoker (self-host RIE)` is right, but the
   synchronous-by-design invoke chain (25 MB cap → S3 → 90 s sync invoke →
   findings pulled back) and the ecosystem routing table
   (`application.yml:208-234`, `ScriptEcosystemDetector`) aren't captured.

# 37. Local inference (`kraken-infer`), the test corpus, the eval harness, e2e, CI, xtask, spikes

**The QA/eval layer is as engineered as the analysis layer.** KRAKEN ships a
supervised local-inference stack (`kraken-infer`), a 47 MB reproducible binary
corpus with machine-readable ground truth (`corpus/`), a *task-scored* assistant
evaluator (`kraken-eval`), end-to-end tests that literally execute the milestone
exit criterion from design 0012 (`kraken-e2e`), a two-speed CI plus a nightly
fixture-drift job (`.github/workflows/`), ten `cargo xtask` codegen/build
modules, and the week-one spikes that seeded it all (`spikes/`). For calxgloss
this chapter is the single richest comparison surface: KRAKEN has an executable
definition-of-done, a scored RE-quality eval, and a drift loop against pinned
third-party engines — three things calxgloss does not have (roadmap P33 is
precisely the first of them).

## 1. `kraken-infer` — supervised local inference backends

`crates/kraken-infer` (8,649 LOC) is "Supervised local inference backends for
KRAKEN": an `InferenceBackend` "launches an engine as a supervised child process
that exposes an OpenAI-compatible server on 127.0.0.1"
(`crates/kraken-infer/src/lib.rs:3-6`). The design rule is the one from CLAUDE.md:
"Engine and inference backends run as supervised child processes"
(`CLAUDE.md:55`).

### The seam

`trait InferenceBackend` (`crates/kraken-infer/src/backend.rs:53`) requires
`id`, `capabilities`, a JSON-Schema `settings_schema` the GUI renders generically,
and `start(settings, budget) -> RunningBackend` which "Validates `settings`,
checks the memory budget, spawns the engine and returns at once"
(`crates/kraken-infer/src/backend.rs:66-68`). `RunningBackend` carries the
endpoint: `base_url()` returns `http://127.0.0.1:<port>/v1`
(`crates/kraken-infer/src/backend.rs:115-117`) — exactly what
`kraken_agent::OpenAiCompatible` talks to (`crates/kraken-infer/src/lib.rs:4-5`) —
plus per-run API keys (`crates/kraken-infer/src/backend.rs:93-103`), a
loading-progress stream and a bounded log ring
(`crates/kraken-infer/src/backend.rs:131-143`). `BackendCapabilities` declares
OS/arch/GPU-API/platform fit and license
(`crates/kraken-infer/src/backend.rs:24-38`). Three engine families register:
llama.cpp, Strata, and any TOML-manifest OpenAI server (`CLAUDE.md:31`).

### The supervisor

`ManagedProcess` (`crates/kraken-infer/src/supervisor.rs:400`) spawns the engine
and keeps it healthy. Each incarnation is owned by a dedicated OS thread because
"On Linux `PR_SET_PDEATHSIG` fires when the *thread* that forked the child exits"
(`crates/kraken-infer/src/supervisor.rs:1-6`); the spawner sets
`PR_SET_PDEATHSIG`→SIGKILL in `pre_exec`
(`crates/kraken-infer/src/supervisor.rs:236-240`) and additionally uses
`kraken_procguard::watch_parent_death` and a `ProcessGuard`
(`crates/kraken-infer/src/supervisor.rs:259-260`). The child env is *scrubbed*:
only `DEFAULT_ENV_ALLOWLIST` names survive
(`crates/kraken-infer/src/supervisor.rs:27-49`, applied via `filter_env` at
`crates/kraken-infer/src/supervisor.rs:134` and `env_clear()` at
`crates/kraken-infer/src/supervisor.rs:220`), and the allowlist deliberately
includes the GPU-visible-devices and Vulkan-ICD variables so device enumeration
stays consistent (`crates/kraken-infer/src/supervisor.rs:41-48`). `ProcessSpec`
holds argv, port, health path, a `RestartPolicy` (max restarts, backoff,
"running at least this long resets the crash counter",
`crates/kraken-infer/src/supervisor.rs:53-62`), SIGTERM→SIGKILL grace and a
progress parser hook (`crates/kraken-infer/src/supervisor.rs:95-112`). The
supervise loop restarts with exponential backoff until `RestartPolicy` gives out
(`crates/kraken-infer/src/supervisor.rs:545-580`, `backoff_or_fail` at
`crates/kraken-infer/src/supervisor.rs:674`), polls `/health` over loopback
(`http_status`, `crates/kraken-infer/src/supervisor.rs:373`), and `Drop` stops
the child (`crates/kraken-infer/src/supervisor.rs:539`).

### Ports and keys

Everything is loopback-only (`LOOPBACK: &str = "127.0.0.1"`,
`crates/kraken-infer/src/port.rs:9`). Ports are picked by binding a
`TcpListener` on port 0 and handing the port to the child
(`pick_free_port`, `crates/kraken-infer/src/port.rs:21`), and
`start_with_port_retry` (`crates/kraken-infer/src/port.rs:48`) re-picks when the
engine's own log shows a bind failure — a text-marker check
(`BIND_FAILURE_MARKERS`, `crates/kraken-infer/src/port.rs:27-37`) rather than a
race-prone port scan. Each run gets a random bearer key
(`generate_api_key`, `crates/kraken-infer/src/port.rs:95`); for llama.cpp it is
passed in the environment variable `LLAMA_API_KEY`
(`crates/kraken-infer/src/llama.rs:109`).

### Hardware probe, budget, model recommendation

`hardware::detect` (`crates/kraken-infer/src/hardware.rs:128`) collects RAM
(`/proc/meminfo`, `parse_meminfo_total`,
`crates/kraken-infer/src/hardware.rs:594`), free disk
(`parse_df_free`, `crates/kraken-infer/src/hardware.rs:685`) and GPU info;
`detect_devices` (`crates/kraken-infer/src/hardware.rs:159`) parses
`nvidia-smi --query-gpu` (`parse_nvidia`,
`crates/kraken-infer/src/hardware.rs:254`), `rocm-smi` JSON
(`parse_rocm`, `crates/kraken-infer/src/hardware.rs:313`) and
`llama-server --list-devices` (`list_llama_devices`,
`crates/kraken-infer/src/hardware.rs:484`), and `display_cards`
(`crates/kraken-infer/src/hardware.rs:614`) flags cards driving a monitor.
`budget::MemoryBudget` (`crates/kraken-infer/src/budget.rs:39`) tracks
reservations against machine RAM/VRAM with `Verdict`
(`crates/kraken-infer/src/budget.rs:25`); `footprint` models weights + KV cache
(128 KiB/token, `crates/kraken-infer/src/budget.rs:201`) + 512 MiB engine
overhead (`crates/kraken-infer/src/budget.rs:208`), and `fit`
(`crates/kraken-infer/src/budget.rs:219`) returns `Fits`/`Tight`/`NoFit`
(`crates/kraken-infer/src/budget.rs:191`) with a margin of a tenth of the need
(at least 512 MiB), summing or min-ing per-card pools depending on multi-GPU
mode. `recommend::recommend(hw, catalog)`
(`crates/kraken-infer/src/recommend.rs:98`) picks the engine (CUDA if an NVIDIA
card has ≥4 GiB VRAM, else Vulkan, else CPU capped at 8 B params —
`CPU_MAX_PARAMS_B`, `crates/kraken-infer/src/recommend.rs:19`) and "the biggest,
best-quality model that fits" from a **bundled, hash-pinned catalog**:
`data/models.toml` ships GGUF URLs with `sha256` = the Hugging Face LFS object
id, and "a download that differs is deleted"
(`crates/kraken-infer/data/models.toml:1-2`; `ModelEntry` at
`crates/kraken-infer/src/recommend.rs:23-35`). Models land in
`$XDG_DATA_HOME/kraken/models` (`models_dir_with`,
`crates/kraken-infer/src/recommend.rs:50-69`). KRAKEN "never downloads a model
by itself" — the user picks in guided setup (`docs/local-models.md:16`).

### llama.cpp backend

`LlamaServerBackend` (`crates/kraken-infer/src/llama.rs:212`,
`impl InferenceBackend` at `crates/kraken-infer/src/llama.rs:294`) builds argv
from `LlamaSettings` (`build_argv`, `crates/kraken-infer/src/llama.rs:74`),
finds an existing `llama-server`/`.exe` (`discover_binary`,
`crates/kraken-infer/src/llama.rs:121`), detects its GPU APIs from `--version`
output (`detect_gpu_apis`, `crates/kraken-infer/src/llama.rs:159`), and maps a
"load_progress=" log line to a fraction for the GUI progress bar
(`parse_progress`, `crates/kraken-infer/src/llama.rs:204`). Releases are
pinned upstream: `kraken-host`'s `llama_setup` pins tag `b11696`
(`LLAMA_TAG`, `crates/kraken-host/src/llama_setup.rs:23`) and hashes the
downloaded artifact (`ArtifactSpec` via `LlamaRelease::spec`,
`crates/kraken-host/src/llama_setup.rs:150`).

### Strata — what it is

"Strata" is a **third engine**, not a KRAKEN concept: an external MoE-serving
engine ("https://github.com/Niko1221/Strata, MIT") that "serves large MoE models
on small VRAM by keeping the experts in system RAM"
(`crates/kraken-infer/data/strata.toml:1-2`; module doc at
`crates/kraken-infer/src/strata.rs:1-6`). Everything about it is pinned in the
bundled manifest `data/strata.toml`: engine version 0.2.1 at a pinned commit
with a SHA-256'd source tarball, a SHA-256 of its `requirements.txt`, and its
own minimums (12 GiB VRAM / 32 GiB RAM / 80 GiB disk) — "setup refuses any
download whose SHA-256 differs" (`crates/kraken-infer/data/strata.toml:1-19`).
KRAKEN's half: `strata::manifest()` loads the pinned manifest
(`crates/kraken-infer/src/strata.rs:208`); `missing_prerequisites`
(`crates/kraken-infer/src/strata.rs:290`) and `assess`
(`crates/kraken-infer/src/strata.rs:417`) say what this computer lacks and which
models fit; `strata::existing_model` recognises a GGUF the user already owns by
its shard naming (`crates/kraken-infer/src/strata.rs:130`); and
`backend_manifest` (`crates/kraken-infer/src/strata.rs:557`) emits the generic
manifest that makes the installed Strata a supervised backend — install itself
belongs to `kraken-host` (`StrataLayout`/`StrataInstall`,
`crates/kraken-host/src/strata_setup.rs:81,236`; the recommendation gate uses
`STRATA_MIN_VRAM/RAM/DISK`, `crates/kraken-infer/src/recommend.rs:12-14`).
`strata_plan.rs` is a **multi-GPU planner** calibrated on measurements, not
guesses: its constants come from running the model "on an RTX 3070 Ti (8 GiB,
main) with an RTX 2060 (6 GiB, second)" — one card ≈650–690 tok/s prefill,
a second card as peer tier raises prefill but lowers generation
(`crates/kraken-infer/src/strata_plan.rs:1-8`) — and it degrades through five
memory "levels" (context size and speculative draft on/off,
`crates/kraken-infer/src/strata_plan.rs:42-77`). `strata_run.rs` then writes
the per-run config — nine engine flags it owns and strips before rewriting, so
the installed config file is never mutated
(`OWNED`, `crates/kraken-infer/src/strata_run.rs:1-13`).

### Manifest backends + registry

`GenericOpenAiServerBackend` (`crates/kraken-infer/src/generic.rs:289`) turns
any OpenAI-compatible engine into a backend via a TOML manifest: an argv
template with `{port}`/`{host}` reserved for KRAKEN and every other placeholder
resolved from a JSON-Schema settings form (`crates/kraken-infer/src/generic.rs:1-7`,
`expand` at `crates/kraken-infer/src/generic.rs:262`);
`manifests/example-engine.toml:1-6` is the documented template ("names no real
project"). `BackendRegistry::load_manifest_dir`
(`crates/kraken-infer/src/registry.rs:57`) lets users drop in new engines "from
a TOML manifest without new Rust code" (`crates/kraken-infer/src/lib.rs:5-6`).

### Stats and the fake server

`stats::StatsSampler` (`crates/kraken-infer/src/stats.rs:426`, spawned on an
interval at `crates/kraken-infer/src/stats.rs:443`) feeds the GUI's title-bar
model chips (`CLAUDE.md:31`): llama.cpp counters come from its Prometheus
endpoint (`parse_prometheus`, `crates/kraken-infer/src/stats.rs:125`;
`LlamaStats` at `crates/kraken-infer/src/stats.rs:93`), Strata from a
`/metrics` JSON (`StrataStats`, `crates/kraken-infer/src/stats.rs:56`),
per-process VRAM from `nvidia-smi`/`rocm-smi` (`GpuProcUse`,
`crates/kraken-infer/src/stats.rs:174`), and RAM as RSS summed over the process
tree read from procfs (`process_tree`/`rss_sum`,
`crates/kraken-infer/src/stats.rs:238,266`). `kraken-fake-server`
(`crates/kraken-infer/src/bin/kraken-fake-server.rs:1-10`) is the test-only
stand-in: `/health`, `--ready-after`, `--crash-after`, `--load-steps`,
Prometheus counters advancing at exactly 100 tok/s — so the supervisor and
stats tests are deterministic (its tests live in
`crates/kraken-infer/tests/supervisor.rs`, `.../hardware.rs`, `.../stats.rs`).

## 2. `kraken-eval` — the scored evaluation harness

`crates/kraken-eval` (3,313 LOC) is the "KRAKEN evaluation harness (`kraken
eval`): scripted tasks over the test corpus, scored against ground truth, for
any assistant backend" (`crates/kraken-eval/Cargo.toml:3`; module doc
`crates/kraken-eval/src/lib.rs:1-20`). The CLI is `kraken eval list|run`
(`crates/kraken-cli/src/eval_cmd.rs:1`).

### Task taxonomy

Three kinds (`crates/kraken-eval/src/suite.rs:33-41`):

| kind | ask | expect |
|---|---|---|
| `name_functions` | name the stripped functions of a program | names per address, scored vs DWARF |
| `find_function` | "the function that does X" | address inside the truth function (`Expect::Function`, `crates/kraken-eval/src/suite.rs:56-77`) |
| `question` | strings/imports Q&A | yes/no, set, exact text |

The built-in suite is a compiled-in JSON (`BUILTIN`,
`crates/kraken-eval/src/suite.rs:23`) of **27 tasks** — 15 `find_function`, 8
`question`, 4 `name_functions` — over four *stripped O0* programs
(`crates/kraken-eval/data/corpus.json`; user docs `docs/assistant.md:602`).
Functions under 40 bytes are excluded from naming tasks — "a four-instruction
stub says too little to name" (`MIN_NAMED_SIZE`,
`crates/kraken-eval/src/suite.rs:25-27`). Suite `validate` cross-checks each
expectation against live engine facts via `Check` declarations
(`crates/kraken-eval/src/suite.rs:81-93`, `Suite::validate` at
`crates/kraken-eval/src/suite.rs:270`), so a truth-file regression fails the
suite, not the eval.

### Scoring without a model

Scores are "between 0 and 1 and need no model to compute"
(`crates/kraken-eval/src/score.rs:3-4`). Names: **token-set F1** between the
predicted name and the DWARF name — tokens split at underscores/camelCase/digits,
plurals stemmed, filler words dropped (`parse`-era doc
`crates/kraken-eval/src/score.rs:5-7`; `name_tokens`
`crates/kraken-eval/src/score.rs:60`, `token_f1`
`crates/kraken-eval/src/score.rs:106`); "parse_header vs header_parse scores 1,
parse_file 0.5" (`crates/kraken-eval/src/score.rs:5-6`); the task score is the
mean over its functions (`crates/kraken-eval/src/score.rs:268-275`). Function:
1 iff the answered address is in `[start, start+size)`
(`crates/kraken-eval/src/score.rs:276-286`). Set answers score F1 of names;
text/yes-no are exact (`crates/kraken-eval/src/score.rs:8-12`, `score()`
dispatch at `crates/kraken-eval/src/score.rs:225`). The answer itself is read
from a `<kraken-answer>…</kraken-answer>` block (`ANSWER_OPEN`/`ANSWER_CLOSE`,
`crates/kraken-eval/src/prompt.rs:10-12`; `extract_answer` falls back to the
last JSON object and records an "unreadable" problem with score 0
(`crates/kraken-eval/src/score.rs:133-152`); the answer format is appended to
the system prompt as *trusted* instructions, the task goal is the user message
(`ResolvedTask.instructions`, `crates/kraken-eval/src/suite.rs:173-186`;
`prompt::instructions` `crates/kraken-eval/src/prompt.rs:54`).

### The run

`Runner { corpus, env, source, registry, options }`
(`crates/kraken-eval/src/runner.rs:128-140`) opens each corpus binary via an
`Environment` trait ("a recorded fixture in CI, a real engine live",
`crates/kraken-eval/src/runner.rs:3-5`; `Prepared` carries the tool backend and
load base, `crates/kraken-eval/src/runner.rs:30-40`), gets one `Assistant` per
task from an `AssistantSource` (`crates/kraken-eval/src/runner.rs:63-73`) — so
"the model API, a local model and a terminal agent are all measured the same
way" (`crates/kraken-eval/src/lib.rs:11-13`) — and drives the task through
KRAKEN's own read-only registry tools (`crates/kraken-eval/src/runner.rs:198-200`;
docs: "The assistant gets the same read-only tools it has everywhere else",
`docs/assistant.md:604`). `RunOptions` selects by id-prefix/kind/limit, times
out per task (default 900 s) and carries token prices
(`crates/kraken-eval/src/runner.rs:76-104`). The report is JSON + Markdown +
one transcript per task (`report.json`/`report.md`/`transcripts/`,
`crates/kraken-eval/src/report.rs:426-433`; Markdown table links transcripts at
`crates/kraken-eval/src/report.rs:339`); `Summary` = mean score, exact count,
problems, per-kind breakdown, tokens, cost, tool calls
(`crates/kraken-eval/src/report.rs:148-170`). `--min-score` makes `kraken eval`
exit 1 below a threshold "so a script or a CI job can gate on it"
(`crates/kraken-cli/src/eval_cmd.rs:141`, gating at
`crates/kraken-cli/src/eval_cmd.rs:464-470`).

### Cassettes — task-keyed LLM record/replay

`EvalCassette` is a versioned JSON file mapping **task id → ordered list of
recorded model responses** (`crates/kraken-eval/src/cassette.rs:21-30`). The
keying is the deliberate difference from `kraken-agent`'s ordinary
`ReplayProvider`, which fingerprints whole requests so "any change to a tool
description or the system prompt makes every recording miss"; an eval asks the
same questions in the same order, so "the n-th model call of a task gets the
n-th recorded response" (`crates/kraken-eval/src/cassette.rs:3-8`). Recording
is transparent via `RecordingSource` and replay via `ReplaySource`
(`crates/kraken-eval/src/sources.rs:53-70,120-127`); the same mechanism appears
again in the rewrite pipeline's cassettes
(`crates/kraken-rewrite/cassettes`, mentioned in `CLAUDE.md:33`).

### CI mode — eval without a model or a decompiler

`crates/kraken-eval/src/ci.rs` makes "the whole thing deterministic and
offline" (`crates/kraken-eval/src/lib.rs:17-20`). Two halves:

- **Engine side**: `FixtureEnvironment` opens corpus binaries on
  `engine-fake` over the recorded Ghidra fixtures — "no decompiler, no network"
  (`crates/kraken-eval/src/ci.rs:275-277`).
- **Model side**: a committed script answers each task deterministically from
  the ground truth — and **deliberately misses** to exercise every score
  outcome: naming every 3rd function wrong with a boilerplate name, a quarter of
  `find_function` answers landing one function over, yes/no flipped on odd
  tasks, a set answer dropping one member and adding `puts`, and the last text
  task answered as "I could not find that string." (`stand_in`,
  `crates/kraken-eval/src/ci.rs:96-190`). The same script is delivered two ways:
  as an `EvalCassette` through `ReplayProvider` (`--backend ci-replay`) and as
  the answer file of the **fake ACP agent** (`--backend ci-agent`;
  `crates/kraken-eval/src/ci.rs:9-11`; `FakeAgentSource` launches
  `kraken-fake-acp-agent` (`crates/kraken-acp/src/bin/kraken-fake-acp-agent.rs`)
  with the script in `FAKE_ACP_EVAL_ANSWERS` and a scrubbed environment
  (`crates/kraken-eval/src/sources.rs:159-171,206,217-219`);
  `crates/kraken-cli/src/eval_cmd.rs:30` lists the three backends: `config`,
  `ci-replay`, `ci-agent`).

The committed artifacts `data/ci-script.json` (319 lines) and
`data/ci-cassette.json` (709 lines) are generated, and a unit test re-generates
them and asserts byte equality — "data/ci-script.json is out of date: run the
tests with KRAKEN_EVAL_BLESS=1" (`crates/kraken-eval/tests/ci.rs:34-55`, message
at `crates/kraken-eval/tests/ci.rs:47`). Further tests prove the whole 27-task
suite replays deterministically, that record→replay round-trips to the same
report, that a missing cassette entry is a clear error, and that the fake agent
scores identically to the cassette (`crates/kraken-eval/tests/ci.rs:81,229,256,316`).
The honesty note is explicit: "A CI score therefore says the harness, the
scoring and both backends work. It says nothing about any model; use a live run
for that." (`crates/kraken-eval/src/ci.rs:12-13`). Live runs (Ollama,
llama-server, Claude Code) are a documented human workflow
(`docs/assistant.md:592-643`), not a CI job — no API keys in CI.

## 3. `corpus/` — the reproducible test corpus

`corpus/` (47 MB, 371 files) is KRAKEN's ground truth: 118 executable-bit
files, 135 truth JSONs, 48 Ghidra-recording fixtures. The layout: 8 target
directories (`bin` = the x86-64 ELF host set, `pe`, `elf32`, `aarch64`,
`arm32`, `riscv32`, `riscv64`, `dotnet`, each with its own `bin`/`truth`/
fixtures), plus `src/` (5 programs), `lib/` (31: one library built as *every
kind* of library — `.so`, `.a`, `.o`, DLL, `.lib`, import lib, `.obj`, x64 and
x86), `xlib/` (27: the same library for the four cross targets), `tools/` (3
truth generators), `expected/` (program oracle outputs), `build.sh`,
`Containerfile`, `MANIFEST.sha256`, `README.md`, `TOOLCHAIN.txt`.

**Why stripped × unstripped × O0/O2**: each program builds at `-O0` and `-O2`
with `-g`, and the `-stripped` twins are `strip --strip-all` "of the same file,
so addresses are identical" — truth for the stripped binary is inherited from
the unstripped twin via `ground_truth_from` (`corpus/README.md:24-27`). DWARF
gives the names; stripping makes the *analysis* honest: the eval runs on the
stripped builds "so names cannot be read off" (`docs/assistant.md:602`). At
`-O2` inlined helpers vanish from truth — "inlined helpers … have no
standalone function, so they are absent" — the matrix is the point: it exercises
the jump-table, vtable, function-pointer and static-link shapes (`corpus/README.md:12-18`,
`corpus/README.md:33-34`).

**Truth schema**, verbatim excerpt (`corpus/truth/stripped_calc-O2-stripped.json:1-10`):

```json
{
  "binary": "stripped_calc-O2-stripped",
  "ground_truth_from": "stripped_calc-O2",
  "sha256": "da36a210959cdc1af96f37048038b3203272306730ae4ff2a6df1e6ccdcde267",
  "source_file": "src/stripped_calc.c",
  "opt": "O2",
  "functions": [
    { "name": "main", "demangled": "main", "entry": "0x1080", "size": 213 },
```

schema doc at `corpus/README.md:29-32`. Truth generators are host-binutils
Python (`corpus/tools/groundtruth.py`, `groundtruth_pe.py`,
`groundtruth_lib.py`).

**Reproducible build**: `Containerfile` pins the base image *by digest* —
`debian:trixie-slim@sha256:a29215f6…` — with separate apt layers/stages so
adding the mingw/multilib/cross compilers never changes the layer the existing
sets were built in (`corpus/Containerfile:1-6`, `corpus/Containerfile:17-30`).
Deterministic flags: `SOURCE_DATE_EPOCH=1704067200`, `-ffile-prefix-map`,
`-Wl,--build-id=none`; "A second build produced identical hashes" and
`MANIFEST.sha256` (28 entries for the host set) covers `bin/`, `src/`,
`build.sh`, Containerfile and the truth tool (`corpus/README.md:180-183`);
every set records its toolchain — `TOOLCHAIN.txt:1-10` shows gcc 14.2.0-19,
binutils 2.44, pinned base digest. Cross sets additionally *run* their binaries
under qemu-user and diff output vs x86-64 (`QEMU-CHECK.txt`,
`corpus/README.md:120-122`); `corpus/expected/*.json` freeze the program
oracles, re-blessable with `KRAKEN_CORPUS_BLESS=1`
(`corpus/README.md:126-132`). "Binaries are committed. Rebuilding is a manual
job: it should open a PR, never run in normal CI." (`corpus/README.md:8`)

**Fixtures → drift loop** (connects to ch. 31): `kraken-record` re-records the
`engine-fake` fixtures from real Ghidra — functions with decompilation,
listing, CFG, xrefs, strings, imports — with a function cap
(`crates/kraken-record/src/main.rs:14-21`); with `--check` it re-records in
memory and compares *structurally*, exiting 1 on drift
(`crates/kraken-record/src/main.rs:21-24`). The nightly `drift.yml` does
exactly that against the pinned Ghidra 12.1.4 (SHA-256-pinned download,
`.github/workflows/drift.yml:13-17`) via
`cargo run --release -p kraken-record -- --check --jobs 2`
(`.github/workflows/drift.yml:67-68`), after building the extension with
`cargo xtask ghidra-ext` (`.github/workflows/drift.yml:64-65`). The design
promise dates to the milestone ADR: "`FakeEngine` fixtures are recorded from
real Ghidra by a tool, and a nightly job checks for drift"
(`docs/design/0012-milestones.md:25`). So the chain is: pinned Ghidra +
`kraken-record` → committed fixtures → `engine-fake` serves the eval and the
safety tests → nightly re-record keeps fixtures honest → *changing* the Ghidra
pin forces a deliberate re-record PR.

## 4. `kraken-e2e` — and the exit criterion that *is* a test

`crates/kraken-e2e` (2,177 LOC, four test files, `src/lib.rs` is a stub) holds
the tests that treat the whole product as the unit under test. The headline:
design 0012's 0.1a milestone defines its **exit criterion in prose** — "an agent
over MCP loads a corpus ELF, renames and retypes functions, creates a function
and undoes the edits. A Ghidra project rebuilt from the log then matches"
(`docs/design/0012-milestones.md:16`) — and KRAKEN turned that sentence into
an executable test: `exit_criterion.rs`, "0.1a exit criterion (decision 81),
against real Ghidra" (`crates/kraken-e2e/tests/exit_criterion.rs:1`). (The
"decision NN" markers throughout KRAKEN's comments point at its local working
plans, `plans/`, which are gitignored (`CLAUDE.md:61`, `.gitignore:3`) — they
are *not* the design record, which is `docs/design/` (`CLAUDE.md:60`).)

What `exit_criterion.rs` asserts: an rmcp client drives the **built `kraken mcp`
binary as a child process** ("it loads a corpus ELF, renames two functions,
retypes one, and proposes deleting and recreating a small one"; "structural
edits are never auto-applied for agents, so the user accepts those proposals
with the CLI between MCP sessions"; "A third agent session undoes its last
edit, rebuilds the Ghidra project from the log and checks that the rebuild
matches the log", `crates/kraken-e2e/tests/exit_criterion.rs:8-13`); the binary
is corpus `pie_list-O0-stripped` chosen *because* Ghidra default names make the
agent's renames additive and auto-apply (`crates/kraken-e2e/tests/exit_criterion.rs:14-16`);
the recreate target is the 30-byte `cmp_id` leaf taken from the truth file
(`crates/kraken-e2e/tests/exit_criterion.rs:30-32`); the test env is isolated
(no user config, private runtime dir, cached Ghidra/JDK discovery,
`crates/kraken-e2e/tests/exit_criterion.rs:58-74`); after the rebuild "from the
log" every rename must still hold (`assert_eq!(fresh.get(addr), Some(name))`,
`crates/kraken-e2e/tests/exit_criterion.rs:502`). `exit_criterion_native.rs`
replays the same flow against the JVM-free native engine — same script,
in-process MCP, project reopen replaying `native-state.json` each step — and
"prints skipped and passes" when the native sources/specs are absent
(`crates/kraken-e2e/tests/exit_criterion_native.rs:1-18`). Both are `#[ignore]`d
and run in CI's real-Ghidra job (run command in the test header,
`crates/kraken-e2e/tests/exit_criterion.rs:2-5`).

`safety.rs` is the MCP safety contract over `engine-fake` fixtures with hostile
strings: permission classes map to tool annotations
(`crates/kraken-e2e/tests/safety.rs:300`); additive agent edits apply and
overwrites become proposals (`crates/kraken-e2e/tests/safety.rs:363`); a per-run
cap turns further edits into proposals (`crates/kraken-e2e/tests/safety.rs:410`);
"an agent cannot decide its own proposals"
(`crates/kraken-e2e/tests/safety.rs:439`); canary strings "come back untrusted,
sanitised and inert", with control/bidi characters asserted absent even in
escaped form (`FORBIDDEN`, `crates/kraken-e2e/tests/safety.rs:31-45`; test at
`crates/kraken-e2e/tests/safety.rs:476`); reads never grow the edit history
(`crates/kraken-e2e/tests/safety.rs:576`); a client that cannot do elicitation
is denied dangerous tools, and declining is denying
(`crates/kraken-e2e/tests/safety.rs:595,619`); hostile agent-supplied names are
rejected as invalid arguments (`crates/kraken-e2e/tests/safety.rs:640`).
`undo_dependents.rs` pins dependency-aware undo against real Ghidra: undoing a
prototype read by another edit is refused until that edit is listed, `cascade`
undoes it, and "a rebuild from the log must report no drift"
(`crates/kraken-e2e/tests/undo_dependents.rs:1-12`).

## 5. `xtask` — ten modules of build/codegen

`xtask/` (2,913 LOC) is the repo's build toolbox, dispatched in
`xtask/src/main.rs:63-77`:

| module | one-liner |
|---|---|
| `bench.rs:1-3` | runs the `#[ignore]`d performance benchmarks that render `docs/performance.md` tables |
| `docs.rs:1` | regenerates `docs/reference/commands.md` from the command registry (ch. 33's doc pipeline) |
| `gui_docs.rs:1-3` | also renders `docs/gui.md` from `kraken-viewmodel` actions/panels |
| `emu_sysroots.rs:1-4` | extracts Debian glibc sysroots *from the corpus build images* for kraken-emu (the corpus Containerfile feeding back!) |
| `native_src.rs:1-4` | fetches the pinned Ghidra source tarball, SHA-256-checks, extracts the decompiler C++ |
| `native_sla.rs:1-4` | builds Ghidra's Sleigh compiler and compiles processor specs so the native engine needs no Ghidra at runtime |
| `native_licenses.rs:1-4` | keeps the license/notice texts for the C++ compiled into `engine-native-sys` |
| `notices.rs:1-2` | renders `THIRD-PARTY-NOTICES.md` from `cargo metadata` (stale-notice tests gate it) |
| `samples.rs:1-2` | one JSON sample per `kraken-proto` type/variant — 53 files in `schema/samples/` — which the Java sidecar re-parses as a wire-conformance check |
| `main.rs` | `ghidra-ext`, `ghidra-ext-test`, `dotnet-ext`, `schema` commands inline |

## 6. `spikes/` — archaeology

Design 0012 opens with "**Spike (week one).** Throwaway proofs: a minimal MCP
server, an egui window with docking, a sidecar that echoes under confinement, a
Ghidra extension built by `cargo xtask`. Exact versions are recorded … in the
pins" (`docs/design/0012-milestones.md:14`). All three week-one spikes are
committed, each a standalone `[workspace]`:

| spike | NOTES verdict | what became of it |
|---|---|---|
| `spikes/mcp-echo` (rmcp echo server + client test, `spikes/mcp-echo/src/main.rs:1-12`) | pins rmcp 3.5.1/schemars/tokio, API notes, "Server must never print to stdout" (`spikes/NOTES-S1.md:5-11`, `spikes/NOTES-S1.md:47`) | the MCP server surface of ch. 33 (`kraken-mcp`); the spike keeps its own passing test (`spikes/mcp-echo/tests/echo.rs`) |
| `spikes/gui-hello` (eframe/egui_dock docked window, both renderers) | key finding: egui_dock 0.21.1 does **not** support egui 0.37 — chosen fix: pin 0.36.2 (option 1, `spikes/NOTES-S1.md:13-24`); screenshots need xvfb in CI (`spikes/NOTES-S1.md:69-71`) | `kraken-gui`'s pin decision (design 0010); the 0.36 pin survived into the workspace |
| `spikes/sidecar-echo` ("spawn the KRAKEN Ghidra sidecar under confinement and analyse /bin/ls", `spikes/sidecar-echo/src/main.rs:1-4`) | pins Ghidra 12.1.4 + Temurin 21 **with the exact SHA-256s later copied verbatim into ci.yml/drift.yml** (`spikes/NOTES-S2.md:9-14` vs `.github/workflows/ci.yml:10-14`); "Gradle works offline"; "confinement costs nothing measurable"; Switch Analysis ≈13 s is the cost driver (`spikes/NOTES-S2.md:23-28`, `spikes/NOTES-S2.md:107-111`) | `engine-ghidra` + `kraken-sidecar` + `xtask ghidra-ext` (the notes name each, `spikes/NOTES-S2.md:17-21`) |
| `spikes/dotnet-engine/NOTES.md` | "a second engine kind works behind the existing traits"; pins .NET SDK 10.0.402 by sha512 + ILSpy 11.1.0 (`spikes/dotnet-engine/NOTES.md:1-19`) | `engine-dotnet` + `dotnet/kraken-dotnet` + `corpus/dotnet` (ch. 31) |
| `spikes/native-engine/NOTES.md` | "the design and the phase plan are in ADR 0014 … this file records how the code works" (`spikes/native-engine/NOTES.md:3` — i.e. `docs/design/0014-native-engine.md`) | `engine-native-sys` + `engine-native` (ch. 31) |
| `spikes/rewrite-loop/NOTES.md` | "the proposals at the end of this file became ADR 0013 and the pipeline core in `crates/kraken-rewrite` … where they differ, the ADR wins" (`spikes/rewrite-loop/NOTES.md:3`); loop "works end to end, offline and deterministically" and "a deliberately wrong translation is caught every time" (`spikes/rewrite-loop/NOTES.md:13-14`) | `kraken-rewrite` (ch. 36) |

The pattern: every spike ends in a *decision record* (NOTES → design doc or
pin), and the notes stay in the repo as archaeology. Note also the workflow
constraint the whole chapter inherits: "Do not commit; the main loop commits"
(`CLAUDE.md:10`).

## 7. CI map — 4 workflows, 8 jobs in `ci.yml`

Both long poles are pinned by URL **and SHA-256** at the workflow env level
(Ghidra 12.1.4 `ddac49f9…`, Temurin 21 `ce79869e…`,
`.github/workflows/ci.yml:10-14`; identical pins in
`.github/workflows/drift.yml:13-17`), cached under `~/.cache/kraken-dev`
(`.github/workflows/ci.yml:97-102`).

| job | what it runs | notes |
|---|---|---|
| `fmt` | `cargo fmt --all --check` (`ci.yml:17-24`) | |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` (`ci.yml:26-33`) | gate from `CLAUDE.md:8-9` |
| `test` | `cargo test --workspace` after `cargo fetch --locked` (`ci.yml:35-44`); *plus* live daemon tests under a **symlinked TMPDIR** to reproduce macOS `/var → /private/var` path canonicalization on Linux (`ci.yml:45-51`) | this is where every kraken-eval ci.rs test, safety.rs and all FakeEngine tests run; failures are surfaced as annotations (`ci.yml:52-58`) |
| `deny` | `cargo-deny` (`ci.yml:60-66`) | allowlist + reasoned waivers in `deny.toml` (`CLAUDE.md:50`) |
| `docs` | mdbook build of `docs/` (`ci.yml:68-75`) | publishing is a separate manual `docs.yml` (`docs.yml:1-7`) |
| `real-ghidra` | preflight probe prints the runner's **Landlock ABI** and userns posture (`ci.yml:84-95`); download+`sha256sum -c` Ghidra/JDK (`ci.yml:104-115`); `cargo xtask ghidra-ext` (`ci.yml:134-135`); then `cargo test --workspace -- --ignored --test-threads=1 --skip screenshot --skip _png` (`ci.yml:140-142`) | this is the corpus/eval invocation: the ignored suite includes kraken-e2e's `exit_criterion*`/`undo_dependents` over corpus binaries and `engine-native` agreement tests vs the fixtures; "Fails loudly when Landlock is unavailable: allow_unconfined stays false" (`ci.yml:137-139`) |
| `python` | wheel built **twice**: release (must not carry the test hook — `_native.has_testing()` asserted false, `ci.yml:169-175`) then with `testing` feature for pytest against a FakeEngine project + private `krakend` (`ci.yml:151-153`, `ci.yml:181-189`); finally "No daemon left behind" kills check (`ci.yml:190-193`) | matrix 3.10/3.13 (`ci.yml:158-159`) |
| `test-other-os` | macOS-14 + Windows: `cargo build --workspace --all-targets` then `cargo test --workspace --no-fail-fast` (`ci.yml:195-213`) | `continue-on-error: true` — "Non-blocking for now: Linux first (decision 95)" (`ci.yml:198`); real-Ghidra tests stay Linux-only until the sandbox exists there (`ci.yml:195-196`) |

`release.yml` builds the shipped artifacts against the same pins, including the
.NET sidecar and a "Check the notices are current" step
(`.github/workflows/release.yml:104-134`).

## 8. Comparison with calxgloss's QA/test/eval infrastructure

(Anchor: [10-calxgloss-baseline.md](10-calxgloss-baseline.md), "Testing ground:
one source-built fixture DLL for the engine harnesses; no corpus/truth/eval
layer" — `docs/research/kraken/10-calxgloss-baseline.md:348`.)

### calxgloss QA reality (verified)

- **Fixture DLL crate**: `crates/integrations/calxgloss-testfixtures` — "a
  small PE DLL target binary built from source for engine tests"
  (`crates/integrations/calxgloss-testfixtures/Cargo.toml:5`). Its `build.rs`
  compiles `fixtures/fixture_target.c` with mingw-w64
  (`DEFAULT_CC: &str = "x86_64-w64-mingw32-gcc"`, `build.rs:18`), and a missing
  compiler is only a warning — the crate then reports `ToolchainMissing`
  (`crates/integrations/calxgloss-testfixtures/build.rs:7-9`). `load_target()`
  shape-validates the DLL so "a broken fixture" fails a smoke test, not an
  engine test deep inside itself (`src/lib.rs:8-11`).
- **Live-Kuna tests over it**: `crates/integrations/calxgloss-kuna/tests/kuna_scan.rs`
  drives `KunaSource` over the fixture DLL; the seam itself is pinned in
  `crates/integrations/calxgloss-decomp/tests/kuna_scan.rs:1-8`
  ("Every read the trait defines answers from the one program loaded in the
  process"), and the web e2e scan runs the same seam end-to-end and re-reads
  the saved records (`crates/interface/calxgloss-web/tests/kuna_scan_e2e.rs:1-9`).
  The generic-driver helper is `drive_reads<S: ScanSource>`
  (`crates/integrations/calxgloss-decomp/tests/cache_tests.rs:67`), *not* a
  "drive_all" — no such symbol exists.
- **Evidence crates test over hand-canned fakes**: e.g.
  `impl ScanSource for FakeProgram` in
  `crates/evidence/calxgloss-callback/tests/integration_tests.rs:75`,
  `crates/evidence/calxgloss-consts/tests/integration_tests.rs:82`,
  `crates/evidence/calxgloss-apidetect/tests/integration_tests.rs:89` —
  literal in-memory programs, no binary involved.
- **No recorded engine output**: nothing in `crates/` replays a Kuna
  transcript; the only "canned" mechanism is `canned_llm` in
  `crates/pipeline/calxgloss-translator/src/retry/attempt.rs:768` — an
  in-test HTTP stub that answers every OpenAI-compatible request with a fixed
  body — so the LLM seam is tested hermetically against the *protocol*, not
  against recordings of real model output (`LlmClient` itself is a concrete
  reqwest client, `crates/integrations/calxgloss-llm/src/client.rs:303`; ADR-0051
  fixed the attempt seam around it —
  `docs/adr/0051-an-attempt-is-one-seam-prompt-llm-verification-and-record-the-loop-keeps-only-policy-strategies-are-adapters-at-the-existing-door-and-the-failing-verdict-routes-into-the-next-prompt.md:1`).
- **No CI at all**: there is no `.github/` in the repo (no workflow files
  anywhere), so no gate, no drift job, no cross-OS matrix.
- **No scored RE-quality eval**: roadmap P33, "Whole-task measurement harness —
  benchmark pipeline tasks end to end (tokens, RSS, ms) with an oracle
  independent of the implementation, counting discovery, retries, and
  continuations in every token claim", is "⬜ not started"
  (`docs/roadmap.md:125`); P24 scenario-capture (`docs/roadmap.md:116`) and
  P25 verification receipts (`docs/roadmap.md:117`) likewise.
- **Wine is used but *not* pinned** — correcting ch. 35's claim of absence:
  `WineRunner` lives in `crates/pipeline/calxgloss-testgen/src/wine.rs:74` and
  discovers Wine from `CALXGLOSS_WINE`, defaulting to whatever `wine` is on
  PATH (`crates/pipeline/calxgloss-testgen/src/wine.rs:94`); the testgen
  baseline tests declare Wine a precondition ("Wine, to run the cross-compiled
  harness", `crates/pipeline/calxgloss-testgen/tests/baseline.rs:6`). No
  version, digest or container pins it anywhere. What *is* pinned: the Kuna
  engine itself — git tag `v1.984` in the workspace root
  (`Cargo.toml:65-71`) plus a rev fingerprint re-exported as `KUNA_PIN_REV`
  (`crates/integrations/calxgloss-kuna/src/engine.rs:29`, stamped by the build
  script `crates/integrations/calxgloss-kuna/build.rs:211`) and asserted in
  the saved scan records (`crates/interface/calxgloss-web/tests/kuna_scan_e2e.rs:74,88`).

### Axis by axis

| axis | KRAKEN | calxgloss | verdict |
|---|---|---|---|
| Ground truth corpus | 47 MB, 8 arch/formats, 135 truth JSONs, deterministic digest-pinned rebuild | one mingw-built fixture DLL (`fixture_target.c`), no truth JSONs, no arch matrix | **steal, scoped**: add `truth.json` (export names, import pairs, jump-table span, string list — all already constants in `testfixtures/src/lib.rs`) beside the one fixture, and a `corpus/truth`-style layout when a second target exists |
| Task-scored RE eval | `kraken eval`: 27 scored tasks, 0–1 F1 formulas, `--min-score` gate | none; P33 is tokens/RSS/ms only | **steal the mechanism**: an eval over the fixture DLL + truth JSON (name-exported functions from stripped disassembly, locate the jump table, import Q&A) is small, model-free to score, and *is* P33's missing "oracle independent of the implementation" |
| LLM record/replay | `EvalCassette` keyed by task id + n-th call, survives prompt churn (`crates/kraken-eval/src/cassette.rs:3-8`); rewrite cassettes (`CLAUDE.md:33`) | `canned_llm` HTTP stub (per-test, protocol-level) | **steal later, confirm now**: calxgloss's protocol stub already gives hermetic pipeline tests; a cassette buys regression coverage of *real* transcripts — worth it once P33 exists, not before |
| Engine drift | nightly `kraken-record --check` vs pinned Ghidra (`drift.yml:67-68`) | nothing — Kuna pinned at v1.984 but no output snapshots to drift-check | **steal** (this is the P33-adjacent gap ch. 31 flagged): record a `FixtureFile`-style JSON per fixture-DLL scan at the pinned rev, CI-diff it on bump |
| Reproducible build pins | Containerfile by digest + MANIFEST.sha256 + TOOLCHAIN.txt (`corpus/README.md:180-183`) | Kuna tag+rev pinned; mingw and Wine unpinned, no container | **confirm**: calxgloss's in-process Kuna already kills the JVM/version problem KRAKEN's Ghidra pin manages; **don't copy** the container unless the repo grows a CI — then pin mingw/Wine first |
| Executable exit criterion | design 0012 prose → `kraken-e2e/tests/exit_criterion.rs` runs it (`crates/kraken-e2e/tests/exit_criterion.rs:1`) | roadmap P-list: prose rows, ⬜/✅ status, nothing executable | **steal the pattern**: each spec'd roadmap P should land with one `tests/` file that fails until the P is done (calxgloss already writes contract-pinning e2e tests like `kuna_scan_e2e.rs` — make that the P-closure ritual) |
| e2e safety | `safety.rs`: canary/bidi sanitisation, proposal rules, elicitation denial as MCP tests | safety is *design* (attempt gating per ADR-0051, no LLM write authority by construction) but no adversarial-string e2e tests | **steal**: feed hostile strings through the decomp→prompt path and assert the emitted prompt/tool inputs are clean |
| CI | 4 workflows, 8 jobs, two-speed ignored tests, cross-OS non-blocking | none | **confirm**: everything in this chapter presupposes CI; calxgloss's first workflow (test+clippy, then the two pins above) precedes any KRAKEN-clone job |

### Verdict

KRAKEN's answer to "how do we know it works" is layered: fixtures recorded
from the pinned engine and drift-checked nightly; a scored model eval whose CI
mode proves the harness itself; e2e tests that execute milestone exit
criteria; and a corpus whose *build* is reproducible by digest. calxgloss has
strong seams (one ScanSource, one attempt) and honest test discipline at the
unit level, but its top layer is missing: no CI, no truth corpus, no scored
eval, no drift check, unpinned Wine. The highest-leverage steals are ordered:
(1) any CI, (2) truth JSON beside the fixture DLL + a ~10-task scored eval
(the P33 oracle), (3) a Kuna fixture-drift check, (4) exit-criterion tests per
roadmap P. Do not copy the multi-arch corpus or the container until there is a
second real target format and a CI to feed.

## Sources

- KRAKEN @ `68718c6`: `crates/kraken-infer` (lib/backend/supervisor/port/launch/recommend/hardware/budget/stats/generic/strata*/llama + `data/models.toml`, `data/strata.toml`), `crates/kraken-eval` (lib/suite/score/runner/sources/cassette/ci/report/prompt/corpus + `data/`, `tests/ci.rs`), `corpus/` (README, Containerfile, TOOLCHAIN.txt, MANIFEST.sha256, truth + fixture counts measured with `find`), `crates/kraken-record`, `crates/kraken-e2e`, `xtask/`, `spikes/` (code + NOTES), `.github/workflows/{ci,drift,docs,release}.yml`, `docs/assistant.md`, `docs/local-models.md`, `docs/design/0012-milestones.md`, `CLAUDE.md`.
- calxgloss: `docs/research/kraken/10-calxgloss-baseline.md`, `docs/roadmap.md`, `docs/adr/ADR-0051…`, workspace `Cargo.toml`, `crates/integrations/{calxgloss-testfixtures,calxgloss-kuna,calxgloss-decomp,calxgloss-llm}`, `crates/evidence/{calxgloss-callback,calxgloss-consts,calxgloss-apidetect}`, `crates/pipeline/{calxgloss-translator,calxgloss-testgen}`, `crates/interface/calxgloss-web`.

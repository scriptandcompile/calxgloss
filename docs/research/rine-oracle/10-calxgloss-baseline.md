# calxgloss baseline — how Wine is used as an oracle, and every seam that hurts

> Part of the [rine-oracle overview](README.md). This chapter pins down, with
> file:line, exactly what calxgloss asks of an emulator at the harness seam —
> the contract any replacement (rine) must satisfy — and every Wine
> limitation the lanes already work around or document.

## 1. Four lanes, three of them on Wine

| Lane | Entry point | What runs under Wine | Output artifact |
|---|---|---|---|
| Baseline capture | `crates/pipeline/calxgloss-testgen/src/run.rs` (`BaselineRunner`) | generated harness EXE that calls the target DLL's export | `re/baseline/{binary}/{function}/baseline.json` |
| Reference-app capture (P24.12) | `crates/pipeline/calxgloss-testgen/src/wine/capture.rs` (`ReferenceCapture`) | operator-named EXE wearing a recording proxy DLL | `re/captures/{binary}/{stem}-{slug}-{stamp}.json` (capture-log-v1) |
| Scenario capture/replay (P24) | `crates/pipeline/calxgloss-testgen/src/scenario_run.rs` | fixture console EXE on a host PTY | `re/scenarios/captures/{binary}-{scenario}.json` |
| **Verify** | `crates/pipeline/calxgloss-verify/src/engine.rs` | **nothing** — consumes `baseline.json` as data; PAL stubs run natively on Linux | verification receipt pair |

The single Wine execution primitive is `WineRunner` in
`crates/pipeline/calxgloss-testgen/src/wine.rs`; the scenario and reference
lanes launch `wine <exe>` directly (`scenario_run.rs:400-474`). So rine's
blast radius is exactly the three capture lanes — verify never touches the
emulator.

## 2. The wire contract an oracle must satisfy

Everything the lanes demand at the emulator seam, pinned to code:

**Preflight and identity.** The binary comes from `CALXGLOSS_WINE` or `PATH`;
`preflight()` runs `<wine> --version` and parses it into a semver-ish tuple —
an oracle that cannot answer `--version` parseably is refused before any work
(`wine.rs:75-134`). `WINEPREFIX` is a host absolute path handed through
unchanged (`wine.rs:82-85`), and the scenario lane reads it back out of guest
environments to scope process sampling.

**Execution of the generated harness.** The harness EXE is cross-compiled
`x86_64-pc-windows-gnu` and executed with piped stdio:

- stdin: `<tag>:<value>` case lines joined by `separator` (`\u{1f}`)
  (`wine.rs:300-318`);
- stdout: `<index>\t<ok|err>\t<value>[\t<trace>]` verdict lines
  (`wine.rs:552-603`) plus `EVENT\t{json}` trace lines (`wine.rs:533-540`);
- stderr: scanned for exactly `module base = 0x{hex:016x}`, emitted by the
  harness itself — the emulator must **not pollute stderr**
  (`wine.rs:340-349`, `wine/harness.rs:1445-1448`);
- crash protocol: harness installs `SetUnhandledExceptionFilter` →
  `TerminateProcess(133)`; the emulator must deliver the filter and exit with
  the harness's own code — no debugger, no GUI (`wine/harness.rs:608-618,1456-1458`;
  `HARNESS_CRASH_EXIT = 133` at `wine.rs:29-33`);
- batching: all cases in one launch; a crash kills the batch, then per-case
  isolated relaunches re-establish per-case verdicts (`wine.rs:162-235,452-491`);
- timeouts: the baseline lane has **none** — a hang is fatal and unbounded
  (`wine.rs:40-45`). Reference capture has `max_events` / `max_duration_secs`
  / `max_log_bytes` budgets with explicit truncation notes (`run.rs:30-36`,
  `capture.rs:13-33`); scenario has idle-window + max-run windows
  (`scenario_run.rs:380-385,597`).

**Win32 surface the harness and proxy themselves call** (from the generated
templates, `wine/harness.rs:537-569`, `wine/proxy.rs:374-508`):

- `LoadLibraryExW` with `DONT_RESOLVE_DLL_REFERENCES` — the image must stay
  mapped with a readable export table including forwarder strings, and
  forwarded names must fail `GetProcAddress` with 127
  (`harness.rs:883,933`, `types.rs:6-21`);
- `GetProcAddress` (armed exports + self-verification, `harness.rs:884-903`),
  `GetModuleFileNameW` (forwarder resolution, `proxy.rs:404-417`),
  `GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)`;
- `VirtualAlloc(MEM_COMMIT|MEM_RESERVE)` for pointer args (cap 256 MiB),
  `VirtualProtect(PAGE_EXECUTE_READ)` on thunks, and `VirtualQuery` for the
  bounded guarded-pointer probe — the probe enumerates committed regions of
  **host-allocated (non-module) memory** and must report `PAGE_GUARD` without
  ever faulting it (`harness.rs:29,235-264,1257-1336,715-771`);
- arbitrary RWX guest code: `global_asm` register shims and inline IAT
  patching (`harness.rs:651-668,1281-1288`), manual import binding
  (`harness.rs:947-995`);
- `WriteFile` on `GetStdHandle(...)` raw handles — the DLL must **not** use
  CRT stdout (`proxy.rs:374-386`);
- `SetUnhandledExceptionFilter`, `TerminateProcess`, `ExitProcess`;
- DLL search order: harness sits beside `target.dll` in CWD
  (`run.rs:257-267`); the capture lane injects `WINEPATH` for the parked real
  module (`proxy.rs:118-124,165-170`).

**Path translation.** Host paths reach guests as `Z:\…` (`wine.rs:144-149`);
scratch work is rooted under `/tmp` specifically because Wine's `Z:` mapping
refuses the project's non-ASCII host path (`engine.rs:913-919`).

**Console subsystem (scenario lane).** Guest runs on a **host PTY**
(`scenario_run/pty.rs:1-5`); Wine's console driver drops the slave into
`~ICRNL` so input lines must end `\r` (`pty.rs:19-27`); console signals
travel the PTY path and are recorded (`scenario_run.rs:730-749`).

**Process model the scenario lane leans on.** Guest children via
`CreateProcessW` (fixture `spawn` verb); killing the client makes **wineserver
tear down the whole guest tree** — the timeout kill assumes exactly this
(`scenario_run.rs:481-484`); host-side sampling identifies guests by
`/proc/<pid>/exe == wine-preloader` scoped by `WINEPREFIX` in
`/proc/<pid>/environ`, birth-anchored, 250 ms cadence, self-described as
inherently racy (`scenario_run/sampler.rs:1-46,62-204`); guests see an
allowlisted env under `env_clear` (`scenario_run.rs:512-557`); process
supervision is ownership-token based, never bare-PID (`wine/owned.rs:32-133`).

**Provenance today: absent by design.** `baseline.json` is a plain
`Vec<TestResult>` with no stamping (`generator.rs:288-292,340-349`);
scenario captures do pin `wine_version` + `program_sha256` +
`normalization_version` and comparison refuses unpaired captures
(`scenario_run.rs:144-177`). **P44** (`docs/roadmap.md:93`) plans to stamp
baselines with DLL sha256 + oracle version + load base + target triple and
re-run the live oracle on failure. An oracle that *publishes* those values
makes P44 a read instead of an inference.

## 3. Documented Wine pain points (the workarounds inventory)

1. `wineboot -u` pops a GUI dialog on Wine 10+; fresh prefixes need a bare
   silent `wine` run, plus `WINEDLLOVERRIDES="mscoree,mshtml="` for headless
   (`wine.rs:47-61`; CHANGELOG:70,73,85).
2. Hangs in the baseline lane are unbounded (`wine.rs:40-45`).
3. A batch crash loses all verdicts; per-case retry doubles launches after
   any crash (`wine.rs:217-235,452-491`).
4. Writing through a DLL's `std::io::stdout` faults under Wine — the proxy
   switched to raw `WriteFile` (CHANGELOG:217; `proxy.rs:374-386`).
5. `GetModuleHandleExW(FROM_ADDRESS)` **fails under Wine with error 126**;
   both harness and proxy carry workarounds (CHANGELOG:217;
   `proxy.rs:388-398`).
6. A `GetProcAddress` NUL-termination bug surfaced mid-capture (CHANGELOG:97).
7. conhost echo divergence (wine-11) and the `~ICRNL` newline quirk
   (CHANGELOG:67; `pty.rs:19-27`).
8. Guest process-tree sampling is racy by construction (`sampler.rs:1-46`).
9. `Z:` drive refuses non-ASCII host paths (`engine.rs:913-919`).
10. x86-64 only — WOW64 targets get `unavailable` notes and
    `entry_capture: false` (ADR-0057; `harness.rs:131,508,1223`).
11. Nondeterminism is handled by **pairing stamps, not prevention**
    (`scenario_run.rs:144-177`).
12. Privileged-instruction lesson (from the GameFrame corpus,
    `docs/research/game-frame/31-method-playbook-skills.md:496`): INT1/ICEBP
    crash under Wine and produce flaky captures — a fault must arrive as a
    *named record*, never as a nondeterministic crash.

Every one of these is a candidate deletion for a rine-based oracle — the point
is not that Wine is bad but that **all twelve sit below the API boundary,
where Wine offers no handles and calxgloss compensates in host code.**

## 4. What this chapter hands the next two

[20](20-rine-inventory.md) inventories rine against this contract;
[30](30-oracle-gap-analysis.md) adjudicates where rine could do strictly
better than Wine, not merely equally.

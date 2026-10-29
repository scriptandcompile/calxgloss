# KRAKEN's emulation and patching — a whole-program emulator in the process, and the byte-patch pipeline that feeds it

Chapters 31–34 covered the engine seam, the edit log, the command registry and the AI/safety
machine. This chapter covers the piece that lets KRAKEN *execute* what it analyses: the built-in
emulator (`kraken-emu`), how `emulate_run` drives it under OS confinement, and the byte-patching
workflow from `assemble` through `patch_set` to `patch_export` and the patched-vs-original
compare. It ends with the direct comparison to calxgloss's approach to the same problem — getting
ground-truth behaviour out of an original binary — where calxgloss uses Wine to *really run* the
DLL and KRAKEN *emulates* the program instead. The differential machinery built on top of the
emulator (function oracles, difftest, the rewrite accept loop) is chapter 36's territory; this
chapter only previews it.

Conventions as in the other chapters: KRAKEN design docs are cited as "design NNNN"
(`docs/design/`); code comments referring to "decision NN" point at KRAKEN's gitignored internal
plans, not the published design docs. All `path:line` cites are against the clone at
`/tmp/opencode/kraken` at `68718c6`, verified 2026-10-28; calxgloss cites are against this repo.

## What `kraken-emu` is

`kraken-emu` is an in-process whole-program emulator, not a debugger bridge and not QEMU. It has
no debugger, ptrace or Frida dependency; `Cargo.toml` pins the Icicle engine to one SLEIGH commit
— `rev = "638508b72f480f9be6fe2e267ef09de8f1541f9a"` (crates/kraken-emu/Cargo.toml:13-16) — and
Icicle is a p-code interpreter fed Ghidra's machine descriptions. The JIT is explicitly off:
`config.enable_jit`, `enable_shadow_stack` and `enable_recompilation` are all set to false
(crates/kraken-emu/src/machine.rs:226-228), so execution is the interpreter path only. The
language specs come from Ghidra's build, tagged `Ghidra_12.1.4_build`
(crates/kraken-emu/src/specs.rs:14).

The specs are not used raw. A per-architecture patch overlay rewrites SLEIGH p-code Icicle cannot
compile or that misbehaves (crates/kraken-emu/src/specs.rs:157-230, rationale at
crates/kraken-emu/src/specs.rs:148-156): RISC-V CSRs become ordinary registers backed by RAM at
`RISCV_CSR_BASE = 0xfff0_0000` (crates/kraken-emu/src/specs.rs:129); ARM `blx` drops the
`globalset(reloc,TMode)` the decoder rejects (crates/kraken-emu/src/specs.rs:203); x86 `CPUID`
becomes a userop routed to a faked baseline answer (crates/kraken-emu/src/specs.rs:212-214;
helper `x86_cpuid` at crates/kraken-emu/src/machine.rs:166-191); and AArch64 `BFXIL` gets a mask
fix for a constant Icicle sign-extends wrongly (crates/kraken-emu/src/specs.rs:152). Patched spec
sets are cached under `KRAKEN_EMU_SPEC_CACHE`, defaulting to `~/.cache/kraken/emu-specs`
(crates/kraken-emu/src/specs.rs:364-370).

Languages: x86, x86-64, ARM (A32 and Thumb), AArch64, RISC-V 32/64, little-endian only, ELF only
— "Windows and Mach-O programs are refused" (docs/emulation.md:34-35). PE bytes can still be
*identified* by `Arch::detect` for architecture purposes (crates/kraken-emu/src/arch.rs:137-150),
but they cannot be run. That is the first and biggest divergence from calxgloss, whose entire
target surface is PE.

## Two layers: whole-program runs and function sessions

The crate offers the same machine at two granularities. **Whole-program runs**:
`LinuxProcess::spawn` (crates/kraken-emu/src/linux/mod.rs:436) maps an ELF, builds a stack and
runs it against a small synthetic Linux syscall layer; this is what `emulate_run` uses. **Function
sessions**: a `Session` drives the same machine with breakpoints and stepping on a dedicated
thread named `kraken-emu-session`, because the Icicle CPU is not `Send`
(crates/kraken-emu/src/session.rs:387). `FunctionCaller` has two constructions
(crates/kraken-emu/src/call.rs:671-678): `load_elf` maps the image alone with every import slot
at a stub — reaching one ends the call with `CallTermination::Import`
(crates/kraken-emu/src/call.rs:699, 949) — while `after_startup` starts the whole program under
the Linux layer first so libc is initialized (crates/kraken-emu/src/call.rs:764). Import stubs
sit at `stub_base + 0x10 * (index + 1)` (crates/kraken-emu/src/call.rs:715) with a trap stub at
`stub_base + 0xff0` (crates/kraken-emu/src/call.rs:646). This is the machinery chapter 36's
function oracle rides on.

Design 0013 lists the oracle kinds: `icicle-emu/x86-64-sleigh` (implemented), `process`
(whole-program, implemented), `ghidra-pcode` and `native-process` (reserved), `compile-only`
(implemented, always inconclusive) (docs/design/0013-rewrite-pipeline.md:61-71). `native-process`
— one function of the original run natively — is named there as the only function-level kind that
could catch an emulator or SLEIGH bug; remember that when comparing with calxgloss, whose
baseline *is* native execution.

## The synthetic Linux: determinism by construction

The whole-program layer is engineered for repeatable runs, not fidelity to any real kernel. A
fixed epoch `EPOCH: u64 = 1_704_067_200` (crates/kraken-emu/src/linux/mod.rs:50) makes the guest
clock `EPOCH + icount` — wall time is instruction count
(crates/kraken-emu/src/linux/mod.rs:1073-1074). A fixed PID `PID: u64 = 1000`
(crates/kraken-emu/src/linux/mod.rs:48) and a seeded PRNG `rng: 0x9e37_79b9_7f4a_7c15`
(crates/kraken-emu/src/linux/mod.rs:518), advanced by xorshift64* and commented "deterministic, so
runs repeat exactly" (crates/kraken-emu/src/linux/mod.rs:1625-1633). The guest filesystem is
exactly two trees: `/work` (the private run directory, read-write; the program appears read-only
as `/work/prog`) plus an optional read-only sysroot, and `/dev/null`, `/dev/zero`, `/dev/urandom`
with deterministic bytes; `..` never climbs out (crates/kraken-emu/src/linux/fs.rs:1-11). No host
environment is inherited: `RunSpec` (crates/kraken-emu/src/linux/mod.rs:54-85) carries argv,
stdin, env, budgets and the sysroot explicitly, and `ProgramOutcome`
(crates/kraken-emu/src/linux/mod.rs:150-174) reports exit (enum at 109-122), captured
stdout/stderr and syscall counts.

Two x86-64 accommodations are honesty about emulation gaps: before mapping the image the emulator
zeroes `GNU_PROPERTY_X86_ISA_1_NEEDED` in the in-memory copy so glibc won't take AVX/FXSAVE paths
the decoder can't execute (crates/kraken-emu/src/linux/mod.rs:439, module `isa_marker` at line
14); and for dynamic x86-64 runs it injects `LD_BIND_NOW=1` because lazy symbol binding executes
`FXSAVE`, which is not implemented (crates/kraken-emu/src/linux/mod.rs:545-549).

## Dynamic programs: where libc comes from

A dynamically linked ELF needs a loader and shared libraries. The run first tries without one and
fails with `NeedsSysroot`; the registry then retries with a sysroot
(crates/kraken-registry/src/commands/emulate.rs:389-433). **Extracted sysroots** (preferred):
`sysroot_for` (crates/kraken-registry/src/commands/emulate.rs:249-269) finds per-arch sets under
`~/.cache/kraken-dev/emu-sysroots/<set>` (`elf32`, `arm32`, `aarch64`, `riscv64`, `x86_64`),
which `cargo xtask emu-sysroots` extracts from Docker images `kraken-corpus-builder:cross` /
`:local` and plain `debian:trixie-slim` (xtask/src/emu_sysroots.rs:1-16). The x86-64 set
deliberately comes from Debian baseline, not the host: many distros build glibc for x86-64-v3
with AVX2, which the emulated CPU cannot execute (xtask/src/emu_sysroots.rs:6-8). **Host
libraries** (fallback, added in the HEAD commit): with no extracted set,
`hostlibs::private_sysroot` copies the program's interpreter and its transitively named
`DT_NEEDED` libraries into a private temp directory that becomes the guest's `/`
(crates/kraken-emu/src/hostlibs.rs:58; `needed()` parses DT_NEEDED at line 155), capped at 512
libraries (crates/kraken-emu/src/hostlibs.rs:18) and 1 GiB (crates/kraken-emu/src/hostlibs.rs:20,
message at line 123). The result note spells out the gap: libraries opened by name at run time —
dlopen, NSS, gconv — are absent
(crates/kraken-registry/src/commands/emulate.rs:410-419).

Before this commit the fallback was mounting the host `/` read-only as the sysroot, so a guest
could read anything the user can — SSH keys, tokens — and print it through the emulator's
captured output into the assistant's context. The HEAD commit message says exactly that ("Give
emulated programs only their own libraries, not the host file system", `68718c6`), and the
regression test asserts the guest cannot use `/usr/bin/cat` to read `/etc/passwd`
(crates/kraken-registry/tests/emulate_host_libs.rs:44-53). This is a **security** fix layered on
the chapter-34 confinement story: Landlock confined the *child process*; this narrows what the
*guest* sees even inside its allowed files.

A naming trap for calxgloss readers: `corpus/lib/` and `corpus/xlib/` are corpus *target* library
sets — libkr built as `.so`/`.a`/`.dll`/`.lib`/`.obj` for analysis and rewrite tests
(corpus/README.md:64-76) — not emulation sysroot libraries. The emulation sysroots are not
committed at all; they are built locally by the xtask.

## How a run is launched: confinement, budgets, safety class

`emulate_run` never runs the emulator in the GUI/CLI process. It locates a separate child
executable, `kraken-emu-run` (error if absent at
crates/kraken-registry/src/commands/emulate.rs:337-342), and always calls
`run_program_confined` (crates/kraken-registry/src/commands/emulate.rs:386).
`confined::run_program_confined` (crates/kraken-emu/src/confined.rs:70-155) starts that child
under the sandbox: read-only paths are the runner binary, the program, the SLEIGH specs and the
sysroot; the only read-write path is the run's private temp workdir. The child reads one request
from a socket on fd 0 and answers on it (crates/kraken-emu/src/bin/kraken-emu-run.rs:1-4, 17-31;
`serve` at crates/kraken-emu/src/confined.rs:158). If the OS could not apply full confinement the
result carries a note rather than a refusal
(crates/kraken-registry/src/commands/emulate.rs:440-444). This is the `kraken-confine` stack from
chapter 34 doing the work; the emulator supplies no isolation of its own.

Budgets are enforced at two levels: the crate default is 2e9 instructions / 60s, while the
command clamps to 20M steps default, 200M max, 20s default, 120s max, 4000 output characters per
stream, 1 MiB stdin, 64 args of 4 KiB each (crates/kraken-registry/src/commands/emulate.rs:42-58;
enforced in `validate` at 199-228); `run_to_end` takes both budgets
(crates/kraken-emu/src/linux/mod.rs:1541).

The safety class is the interesting part: `emulate_run` is registered **query / safe**
(crates/kraken-registry/src/commands/emulate.rs:140-141; docs/reference/commands.md:31), and
docs/emulation.md closes with "The command changes nothing in the project, so it runs without
asking" (docs/emulation.md:86). That narrows the original rule: design 0005 states "Dangerous
tools always ask. Byte patching, executing code and running scripts need approval every time"
(docs/design/0005-agent-safety.md:14). In the shipped implementation consent sits on the
*side-effecting* steps, not on running code: `patch_set` is a mutation (kind `mutation`,
permission `mutating` — crates/kraken-registry/src/commands/patch.rs:158-159) and `patch_export`
is the only command in the registry classified **dangerous**
(crates/kraken-registry/src/commands/patch.rs:447; docs/reference/commands.md:52). Running
untrusted code became safe-by-confinement instead of safe-by-approval — defensible for an
agent-facing system, since sandbox and budgets bound what a run can do, but a real divergence
between the published design doc and the code, and the reference is candid about the mechanism
("runs a patched copy in the sandbox to check it", docs/reference/commands.md:8707).

## The patch pipeline, end to end

**Patches are log operations, never engine writes.** A patch is a `LogOp::SetPatch`
(crates/kraken-proto/src/logop.rs:144) — deliberately *not* one of the engine-pushed ops
(`is_engine_op`, crates/kraken-proto/src/logop.rs:172, contrast `SetCodeData` at line 119, which
does reach the engine). The engine always analyses pristine bytes; replacement bytes live in the
project store and are applied by the registry at read/export/run time. That is why `undo`
trivially reverses a patch (docs/reference/commands.md:8512) and why `read_original` can always
fetch the true bytes at an address from engine memory
(crates/kraken-registry/src/commands/patch.rs:244-270).

**Assembling bytes.** `assemble` turns one instruction into bytes at an address
(docs/reference/commands.md:19; command spec crates/kraken-registry/src/commands/patch.rs:604-613)
and requires the engine's `Assembler` capability, whose default is `None`
(crates/kraken-engine/src/caps.rs:179-181). The Ghidra engine implements it
(crates/engine-ghidra/src/engine.rs:955; capability wired at 944-946) through the sidecar Java
side, driving Ghidra's SLEIGH assembler with up to 8 candidate encodings
(java/kraken-ghidra/src/main/java/kraken/ghidra/Assemble.java:22), retried as-typed, upper case
and lower case because processor syntax case differs (Assemble.java:53-54). The native engine has
no assembler, so the user types hex directly (docs/patching.md:20-24).

**Editing and seeing them.** The GUI hex view paints staged patches in a warning colour over the
on-disk bytes, since the view shows the file, not the patch state
(crates/kraken-gui/src/panels/hex.rs:151-166). The Patches tab's "Run original vs patched" button
(crates/kraken-gui/src/panels/patches.rs:58) calls `run_patched_compare`
(crates/kraken-gui/src/panels/patches.rs:66).

**Compare runs.** `run_patched_compare` chains two `emulate_run` calls back to back —
`{"patched": false}` then `{"patched": true}` — rendering both sides in a `RunCompare`
(crates/kraken-viewmodel/src/navtools/patches.rs:710-734, struct at line 72). The patched side
executes a *copy*: `build_patched_copy` applies every overlay through ELF/PE/Mach-O mapping onto
a copy in the run's private temp dir, mode 0o700
(crates/kraken-registry/src/commands/emulate.rs:450-488, permissions at 485); the original file
on disk is never touched (docs/reference/commands.md:8512: "the binary is unaffected (patches are
not written until `patch_export`)").

**Export.** `patch_export` writes a fresh binary only after verifying the recorded original bytes
still match what is on disk at the patch addresses — read through program headers / sections,
with PIE base candidates tried in order starting from the engine base
(crates/kraken-registry/src/patchfile.rs:129-137, `patch_file_bytes_at` 159-208, `PIE_BASE`
candidates at line 16) — and preserves the executable bit. This is the one step with a consent
gate (docs/reference/commands.md:52, 8707).

**Source-level patching.** `patch_from_source` (job / safe —
crates/kraken-registry/src/commands/patch_source.rs:150-151) is the LLM-facing front door: edit
the decompiled C of a function, two model calls per round (a plan prompt and a check prompt). The
plan is validated mechanically before anything runs: every patch must lie inside the function's
instructions and keep covered bytes the same length, capped at `MAX_CHANGED_BYTES = 256`
(crates/kraken-rewrite/src/source_patch.rs:6-7, 33; `validate` at 193-246). The verification is
the striking part: a **second engine instance** opens a patched copy in a temporary directory and
re-decompiles the function (crates/kraken-rewrite/src/source_patch.rs:9, 362-410) within
`CHECK_TIMEOUT = 180s` (line 35); the model then judges the before/after decompile into a verdict
of `Matches` / `Partial` / `Mismatch` / unverified when no second engine exists
(crates/kraken-registry/src/commands/patch_source.rs:60-68).

**The corpus as pinned ground truth.** Four programs in `corpus/expected/` (`pie_list`,
`static_strops`, `stripped_calc`, `switch_vm`) pin sha256 of program, source and reference plus
argv/stdin→exit/stdout cases; the emulator test replays them ("outputs
`corpus/<set>/QEMU-CHECK.txt` and `corpus/expected` record",
crates/kraken-emu/tests/programs.rs:2) and the rewrite tests consume the same files
(crates/kraken-rewrite/tests/corpus_expected.rs). The QEMU reference is a corpus-build artifact:
expected outputs were cross-checked against QEMU runs at corpus build time, then frozen as JSON.

## What calxgloss does with the same problem

calxgloss never emulates. Its baseline capture *executes the real DLL*: testgen generates one
dependency-free harness per function, cross-compiles it for the DLL's own architecture, and runs
it under Wine — "Execute those inputs against the original binary under Wine to capture baseline
behavior" (crates/pipeline/calxgloss-testgen/src/lib.rs:17-19, 21-24). The harness loads the
module at runtime and calls `module_base + rva` (crates/pipeline/calxgloss-testgen/src/wine.rs:10),
the call target being `actual_base + rva` because ASLR picks the load address (wine.rs:18). Two
load modes exist because Delphi binaries such as `eqmain.dll` need runtime state a bare mapping
lacks: `LoadMode::NoResolve` (`DONT_RESOLVE_DLL_REFERENCES`, no `DllMain`) and `LoadMode::Full`
(crates/pipeline/calxgloss-testgen/src/wine.rs:22-31). Cases cross the process boundary as
`<tag>:<value>` lines on stdin and `<index>\t<ok|err>\t<value>` on stdout (wine.rs:35-38); a
faulting case kills the harness and the runner retries case-by-case to keep the rest of the
batch — but a hang is still fatal (wine.rs:40-45). `preflight_wine` checks Wine and the
cross-compile target are installed before any work (wine.rs:116-125), and the binary is
configurable via `CALXGLOSS_WINE` (wine.rs:94).

The captured artifact is JSON: `save_baseline` writes one `baseline.json` per binary+function
under `<target_dir>/re/baseline/<binary>/<function>/`
(crates/pipeline/calxgloss-testgen/src/generator.rs:255-277, path built at 263-269). Each entry
is a `TestResult`: test case, `actual_return` as JSON, observed side effects, pass flag
(crates/shared/calxgloss-types/src/test.rs:113-121). Global side-effect expectations are *not*
captured from the Wine run — the harness reports return values only; they come from the
global-state scan instead (crates/pipeline/calxgloss-testgen/src/lib.rs:26-29).

Verification closes the loop the other direction: the `Verifier` scaffolds a scratch Cargo
project, writes the translated Rust into it, runs `cargo check`, then generates and runs
behavioral tests against the baseline inputs (crates/pipeline/calxgloss-verify/src/lib.rs:11-13);
the generated test harness reads a `baseline.json` copied into the scratch project
(crates/pipeline/calxgloss-verify/src/engine.rs:294-297, read back at 336-339). And the baseline
chapter records the deliberate absence: "No debugger, emulator, hooking/Frida, or byte patching;
the original binary *executes* only for baseline capture under Wine in `testgen`"
(docs/research/kraken/10-calxgloss-baseline.md:324-325).

## The comparison, axis by axis

**(a) Making the original speak.** KRAKEN interprets the binary's own instructions against a
synthetic kernel, inside its own (confined) process; calxgloss lets the real CPU execute the real
DLL through Wine's PE loader and calls one export at a time through an injected harness.
Granularity mirrors: calxgloss's per-export capture is the same shape as KRAKEN's function
sessions, and calxgloss's whole-artifact story is what KRAKEN's `process` oracle is for (design
0013, docs/design/0013-rewrite-pipeline.md:61-71).

**(b) What each substitutes.** Every setup swaps one layer for a stand-in, and the swaps are
opposite. KRAKEN keeps ISA semantics (SLEIGH descriptions of the real instruction set) but fakes
the OS and the CPU microarchitecture: no AVX/FXSAVE paths (hence the ISA-marker trick and
`LD_BIND_NOW`), faked CPUID, no dlopen/NSS, no threads, deterministic clock and randomness by
construction (crates/kraken-emu/src/linux/mod.rs:50, 518, 1073-1074). calxgloss keeps real
execution — real loader, real `DllMain`, real floating point on real silicon — but the Windows
API surface is Wine's own implementation, and nothing in calxgloss pins a Wine version
(`wine.rs:94` defaults to whatever `wine` is on `PATH`, overridable by `CALXGLOSS_WINE`). Fidelity
fails in opposite directions: an emulator bug in KRAKEN silently produces wrong-but-confident
baselines; a Wine quirk in calxgloss produces baselines the Rust rewrite may faithfully reproduce
*against Wine* while the real Windows binary behaves differently. Design 0013's reserved
`native-process` kind says it plainly — only native runs catch emulator bugs — and calxgloss has
no equivalent of that cross-check. The fidelity ceilings differ too: KRAKEN's is the SLEIGH spec
plus its own syscall layer; calxgloss's is Wine's API completeness plus whatever the
`<tag>:<value>` numeric harness can express.

**(c) Determinism and pinning of the baseline.** KRAKEN engineered determinism into the guest:
fixed epoch, seeded PRNG, fixed PID, two visible filesystem trees, and the baseline artifacts
(`corpus/expected/*.json`) pin sha256 of the *inputs* — program, source and reference — so CI
replays without re-capturing (crates/kraken-emu/tests/programs.rs:2). calxgloss's `baseline.json`
pins outputs but not provenance: no hash of the DLL captured, no recorded Wine version, no
recorded load base. Re-running capture on another machine with another Wine can silently produce
a different baseline and nothing notices.

**(d) Consent and blast radius.** KRAKEN classifies every operation: emulate is query/safe
because OS confinement plus budgets bound the damage
(crates/kraken-registry/src/commands/emulate.rs:140-141, 42-58; confined.rs:70-155), and only the
writing step (`patch_export`) demands approval (Permission::Dangerous, patch.rs:447; the check at
crates/kraken-registry/src/command.rs:225). calxgloss has no permission taxonomy — capture is an
operator-run CLI step, and its isolation is "the process boundary Wine happens to give you"; no
Landlock/seccomp equivalent exists (confirmed absent in chapter 34's checks). KRAKEN's HEAD commit
is a lesson for calxgloss's eventual agent-facing story: running a sample can exfiltrate anything
the runner can read (crates/kraken-registry/tests/emulate_host_libs.rs:44-53).

**(e) Closing the verification loop.** Both projects check the *result*, not the process:
calxgloss compiles the rewritten function in a scratch project and replays captured
inputs→outputs against it (crates/pipeline/calxgloss-verify/src/lib.rs:11-13); KRAKEN re-runs the
patched binary in the emulator and re-decompiles through a second engine for `patch_from_source`
verdicts (source_patch.rs:362-410), with the deeper rewrite difftest in chapter 36. But the
*directions* are opposites at the baseline step: calxgloss trusts the captured outputs as truth
and diffs the Rust against them; KRAKEN trusts the emulator as truth *and* keeps pinned expected
JSON as the truth about the emulator (corpus/expected). calxgloss has nothing checking its
capture layer; KRAKEN's design 0013 reserves `native-process` precisely to add one
(docs/design/0013-rewrite-pipeline.md:61-71).

## Steal / confirm / don't copy

- **Steal — pin the capture provenance.** `baseline.json` should embed sha256 of the DLL, the
  Wine version string from `preflight_wine` (which already probes the install,
  crates/pipeline/calxgloss-testgen/src/wine.rs:116-125), the load base seen by the harness, and
  the target triple compiled for. That turns silent capture drift into a detectable mismatch —
  the trick corpus/expected uses for programs.
- **Steal — classify the capture step before any agent drives it.** KRAKEN's ordering (safe-by-
  confinement for execution, dangerous for anything that writes) and its 512-library/1 GiB
  closure caps (hostlibs.rs:18, 20) are the pattern to copy the day calxgloss lets an agent
  choose functions or binaries.
- **Steal — mechanical validation before semantic checking.** `validate` rejects out-of-range /
  wrong-length plans with pure code before any model or engine runs (source_patch.rs:193-246);
  calxgloss's translations get no equivalent mechanical pre-check (signature/size sanity) before
  the expensive compile+test loop.
- **Confirm (don't change).** The function-level baseline shape is right: KRAKEN converged on the
  same granularity (`FunctionCaller`, after_startup vs load_elf tradeoff, call.rs:671-678), and
  its trap/import-stub trick (call.rs:646, 715) is a more formal answer to the same problem
  calxgloss's `LoadMode` pair solves (wine.rs:22-31). Both arrived at "stop at the import
  boundary or initialize the runtime properly" — keep calxgloss's two modes.
- **Don't copy — replacing Wine with Icicle.** KRAKEN refuses PE outright
  (docs/emulation.md:34-35); building a Windows-PE loader plus Windows syscall layer on the
  interpreter path would mean writing the fidelity layer Wine already provides, and KRAKEN's own
  design doc concedes the emulator's truth still needs native cross-checks. calxgloss's whole
  method rests on real execution; emulating it away removes the one thing that makes its
  baselines trustworthy.
- **Don't copy — the synthetic kernel.** Fixed clock-from-icount, fake CPUID and seeded guest RNG
  (linux/mod.rs:50, 1073-1074; machine.rs:166-191) exist to make emulation reproducible. Under
  Wine, real time and real entropy run into Delphi runtime state, but they are *real*; calxgloss's
  answer to flakiness is per-case retry on crash (wine.rs:40-45), and inputs are numeric and
  harness-controlled, so determinism pressure is much lower.

## Sources

- KRAKEN at `68718c6` (clone at `/tmp/opencode/kraken`); all `path:line` cites verified 2026-10-28.
- KRAKEN docs: `docs/emulation.md` (34-35, 86); `docs/patching.md` (20-24, 82);
  `docs/reference/commands.md` (19, 31, 52, 8512, 8707); `docs/design/0005-agent-safety.md:14`;
  `docs/design/0013-rewrite-pipeline.md:61-71`.
- KRAKEN crates: `kraken-emu` (Cargo.toml:13-16; machine.rs:166-191, 226-228; specs.rs:14, 129,
  148-156, 203, 212-214, 364-370; arch.rs:137-150; session.rs:387; call.rs:646, 671-678, 699,
  715, 764, 949; linux/mod.rs:14, 48, 50, 54-85, 109-122, 150-174, 436, 439, 518, 545-549,
  1073-1074, 1541, 1625-1633; linux/fs.rs:1-11; confined.rs:70-158; bin/kraken-emu-run.rs:1-4,
  17-31; hostlibs.rs:18, 20, 58, 123, 155); `kraken-registry` (commands/emulate.rs:42-58,
  140-141, 199-228, 249-269, 337-342, 386, 389-433, 410-419, 440-444, 450-488;
  commands/patch.rs:158-159, 244-270, 447, 604-613;
  commands/patch_source.rs:60-68, 150-151; command.rs:225; patchfile.rs:16, 129-137, 159-208;
  tests/emulate_host_libs.rs:44-53); `kraken-proto` (logop.rs:119, 144, 172); `kraken-engine`
  (caps.rs:179-181); `engine-ghidra` (engine.rs:944-946, 955);
  `java/kraken-ghidra/src/main/java/kraken/ghidra/Assemble.java:22, 53-54`; `kraken-viewmodel`
  (navtools/patches.rs:72, 710-734); `kraken-gui` (panels/patches.rs:58, 66;
  panels/hex.rs:151-166); `kraken-rewrite` (source_patch.rs:6-7, 9, 33, 35, 193-246, 362-410);
  `xtask/src/emu_sysroots.rs:1-16, 6-8`; `corpus/README.md:64-76`; `corpus/expected/` (4 files);
  `kraken-emu/tests/programs.rs:2`; `kraken-rewrite/tests/corpus_expected.rs`.
- calxgloss: `crates/pipeline/calxgloss-testgen` (lib.rs:17-19, 21-24, 26-29; wine.rs:10, 18,
  22-31, 35-38, 40-45, 94, 116-125; generator.rs:255-277, 263-269);
  `crates/pipeline/calxgloss-verify` (lib.rs:11-13; engine.rs:294-297, 336-339);
  `crates/shared/calxgloss-types/src/test.rs:113-121`;
  `docs/research/kraken/10-calxgloss-baseline.md:324-325`.
- Absence checks in calxgloss (2026-10-28): Cargo.lock and `crates/` have zero unicorn / icicle /
  qemu / emulator hits; no permission or consent classification layer exists.

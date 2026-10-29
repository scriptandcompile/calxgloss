# KRAKEN — complete overview & calxgloss comparison

> **KRAKEN** ([Adam-AtlasSoftware/kraken](https://github.com/Adam-AtlasSoftware/kraken),
> GPL-3.0, pre-alpha 0.1a) is an open-source reverse-engineering workbench in
> Rust built on Ghidra's decompiler — with its own Java-free native engine —
> whose stated long-term goal is *Rust rewrites of binaries, function by
> function, checked against the original*: the same destination as
> **calxgloss**, this repo's automated PE/DLL → Rust pipeline. This directory
> is an exhaustive overview of every part of KRAKEN (~267k lines of Rust, 31
> crates), compared against calxgloss. KRAKEN reviewed at `68718c6`
> (2026-10-28); see [scope and method](00-scope-and-method.md).

## Executive summary

**KRAKEN is a workshop; calxgloss is a factory.** KRAKEN puts a human and any
number of AI agents at *one live project*: 78 commands — identical over CLI,
MCP, GUI and Python — drive an engine-seam workbench whose SQLite edit log is
the source of truth, where renames, types and patches are per-address edits,
attributed and undoable, and where a rewrite pipeline translates functions to
Rust one at a time. calxgloss encodes the whole job in a code pipeline: 15
batch evidence scans, five context tiers, attempt branches in git, Wine-captured
baselines, and a reviewer who adjudicates units, never addresses. KRAKEN's
human steers at the address; calxgloss's steers at the verdict.

**The deepest engineering difference is the verification oracle.** KRAKEN
re-runs the *original binary live* on every verification — a per-function
emulator oracle (Icicle/SLEIGH) plus whole-program runs, with counterexamples
shrunk to the smallest disagreeing input ([36](36-rewrite-pipeline.md)).
calxgloss records behavior once through Wine and replays the recording forever
([35](35-emulation-patching.md)). Each beats the other where the other is
weakest: KRAKEN cannot be fooled by a rotted recording but must trust an
emulator — it *refuses to execute PE at all* and reserves a "native-process"
oracle kind for emulator bugs; calxgloss trusts real Windows execution but
cannot detect a capture that has drifted. Steal #3 below fuses the two.

**Both projects sit in the Ghidra lineage and converged on the same doctrines
independently** — SLEIGH-based analysis (KRAKEN compiles Sleigh specs from
pinned Ghidra 12.1.4 sources; calxgloss runs Kuna in-process), callee-first
unit ordering, sandboxed model code, local-model-first economics, honest
coverage accounting ("unknown never aggregates to pass"), and verification as
the real safety net for LLM output. Each also *legislated away* what the other
needs: KRAKEN's whole governance layer (approval board, per-run caps, proposal
gates, ACP sandboxing) exists because it invites third-party agents into a live
project — the exact surface calxgloss's ADR-0051 seam-only admission refuses to
exist. ([31](31-analysis-engines.md), [33](33-automation-command-registry.md),
[34](34-ai-assistant-agents-safety.md), [36](36-rewrite-pipeline.md))

**The one axis where KRAKEN is not close is evidence quality.** KRAKEN's
translator sees one decompile plus debug-info layout notes; calxgloss floods
each attempt with 15 batch scans, coverage stamps, and tier-escalated bundles
(ADRs 0048/0049/0052/0053). KRAKEN's measured ceiling — whole-program Rust
passes on its own C++ audio simulators (`sim03`/`sim04`, byte-identical
`.wav` output, [36](36-rewrite-pipeline.md)) — is real evidence of pipeline
coherence, *not* evidence of PE feasibility: its oracle cannot run PE binaries.

## Capability matrix

Winner in **bold**. "—" = absent.

| Capability domain | KRAKEN | calxgloss | Verdict | Ch. |
|---|---|---|---|---|
| Analysis engines & seam | 3 engines (native JVM-free 22k LOC, Ghidra sidecar, .NET) behind 13 capability facets; contract suite + nightly fixture drift | Kuna only, in-process, zero lifecycle; **15 batch evidence scans**; type write-back; engine-identity-keyed read cache | split — calxgloss for batch evidence over whole PE files, KRAKEN for engine assurance + breadth | [31](31-analysis-engines.md) |
| Data model & provenance | SQLite edit log: attributed ops, versions, read-set CAS, compensating undo, proposal gate | git attempt branches + overlay verdicts + justification commits (ADR-0003/0021) | split — each fits its human's job; calxgloss's git substrate confirmed correct for verdict-level steering | [32](32-edit-log-undo-gui.md) |
| Automation surface | **one command registry → CLI/MCP/GUI/Python**; warm daemon; jobs with progress/cancel/resume; `--json`; generated docs | 29 CLI subcommands, two REST routers (ADR-0002/0006), cold runs, run-equals-`--show` (ADR-0054); no daemon/MCP/Python/`--json` | split — KRAKEN's anti-drift discipline already lives in calxgloss's scan registry (ADR-0052); the daemon would violate calxgloss's cold-run theorem | [33](33-automation-command-registry.md) |
| AI layer | assistant + built-in agent + ACP terminal-agent host + supervised local inference; cost metering with budgets | pipeline LLM as the factory worker: attempt seam (ADR-0051), 5 context tiers, fault monitors; zero external-agent surface | split — KRAKEN wider surface, calxgloss deeper gate | [34](34-ai-assistant-agents-safety.md) |
| Safety & confinement | fail-closed Landlock/seccomp/procguard around every untrusted process; typed `Untrusted<T>` + sanitizer at the wire level | scratch-dir convention; no sandbox, no untrusted typing (verified absences) | **KRAKEN, non-negotiable** — calxgloss runs model code + Wine harnesses unconfined | [34](34-ai-assistant-agents-safety.md), [35](35-emulation-patching.md) |
| Dynamic verification | live oracle: per-function emulation + whole-program runs, shrinking counterexamples (ELF only — PE refused for execution) | Wine-captured baselines once, replayed forever; branch-targeted typed inputs; live original never at verify time | split — live beats recorded (KRAKEN wins the axis); calxgloss's inputs and real-Windows fidelity beat KRAKEN's emulator | [35](35-emulation-patching.md), [36](36-rewrite-pipeline.md) |
| Rewriting to Rust | plan callee-first; bounded kind-routed repair; machine-gated accept; trace-armed program blame; Cargo-workspace export; **whole-program passes measured** | per-unit pipeline, PAL mapping DB, restitching, review UI; no whole-program pass shown | KRAKEN on measured end-to-end proof; calxgloss on per-unit machinery depth; different endgames (strangler vs replace-in-place) | [36](36-rewrite-pipeline.md) |
| Evidence into prompts | one decompile + engine layout notes | 15 scans, coverage stamps, tier escalation, bundle/projector seam | **calxgloss, by a mile** | [36](36-rewrite-pipeline.md) |
| QA & eval infra | 47 MB ground-truth corpus (8 arch sets, 135 truth JSONs), scored model eval with cassettes, nightly drift job, e2e exit-criterion tests, 8-job CI | one fixture DLL, hand-canned fakes, `canned_llm` stub, **no CI at all**; P33 open | **KRAKEN, by a mile** — and the gap is on calxgloss's roadmap already | [37](37-inference-corpus-eval.md) |
| Target breadth | analyze ELF/PE (native or Ghidra) + experimental .NET; *execute* 6-arch ELF only | Windows PE32/PE32+ by charter | KRAKEN on breadth — but its oracle's PE blind spot is exactly calxgloss's home ground | [31](31-analysis-engines.md), [35](35-emulation-patching.md) |

## What calxgloss should steal (aggregated, by value)

0. **CI first.** KRAKEN's whole QA chapter presupposes a CI calxgloss does not
   have (no `.github/` anywhere). Everything below rides on top of it.
   ([37](37-inference-corpus-eval.md))
1. **A scored truth eval — P33's missing oracle.** KRAKEN's `kraken eval`
   scores 27 model-free tasks (F1 on stripped-name recovery, address
   containment, import/string Q&A) against a truth JSON beside each binary.
   A `truth.json` for the one fixture DLL + a ~10-task scored eval is small,
   implementation-independent, and *is* roadmap P33.
   ([37](37-inference-corpus-eval.md))
2. **Fail-closed sandbox for everything that runs model output.** KRAKEN's
   `kraken-confine` vocabulary (Landlock scopes, rlimits, network denied,
   refuse-to-run when confinement is unavailable) ported around
   `calxgloss-verify` scratch projects and the Wine harness.
   ([34](34-ai-assistant-agents-safety.md), [36](36-rewrite-pipeline.md))
3. **The live-oracle hybrid.** When a verification fails, re-run the Wine
   capture on demand and diff against `baseline.json` — tells "translation
   broke" from "recording rotted" for one Wine process per case. Stamp
   `baseline.json` with capture provenance (DLL sha256, Wine version, load
   base, triple) so silent drift becomes a detectable mismatch.
   ([35](35-emulation-patching.md), [36](36-rewrite-pipeline.md))
4. **Typed untrusted data on the bundle→prompt path.** KRAKEN's `Untrusted<T>`
   (deserialization fails without the flag) + invisible-character sanitizer +
   adversarial-string e2e tests; calxgloss today has only identifier/filename
   mangling — a small testable crate closes the gap without touching pipeline
   shape. ([32](32-edit-log-undo-gui.md), [34](34-ai-assistant-agents-safety.md), [37](37-inference-corpus-eval.md))
5. **Recorded Kuna output fixtures + drift check at pin bumps.** Record the
   fixture DLL's scan output as JSON at the pinned Kuna rev, replay it in
   workspace tests, re-check on bump — KRAKEN's `kraken-record` + `drift.yml`
   pattern, and it would have caught the libmatch dialect miss.
   ([31](31-analysis-engines.md), [37](37-inference-corpus-eval.md))
6. **Staleness by content hash.** Stamp accepted units with a "made-from"
   digest of the decompile + callees; re-verify against observed hashes —
   bdiff pairs whole binaries, nothing spots intra-version drift of one
   function today. ([36](36-rewrite-pipeline.md))
7. **Mechanical pre-refusal before the first model call.** KRAKEN checks the
   signature can be expressed by the oracle and *refuses to attempt* if not
   (recorded, with reason); calxgloss churns attempts on units its FFI harness
   cannot express (struct-by-value exports). A mechanical pre-check (length/
   range/ABI sanity) belongs before the expensive compile+test loop.
   ([35](35-emulation-patching.md), [36](36-rewrite-pipeline.md))
8. **Counterexample ordering + verdict honesty rules.** Feed the *smallest*
   disagreeing input first, sorted and capped; ">50 % unevaluable → no verdict"
   and "inputs don't reach the logic" as named outcomes. Maps directly onto
   `VerificationResult`. ([36](36-rewrite-pipeline.md))
9. **P24's scenario contract, pre-designed.** Run original and restitched
   program on the same argv/stdin confined, diff exit/stdout/stderr, and
   compare written files as size+sha256+4 KiB block hashes — KRAKEN's
   `process` oracle is a concrete shape for the roadmap entry.
   ([36](36-rewrite-pipeline.md))
10. **Cost as a first-class number.** Per-attempt cost metering with budgets
    and a pre-run cost estimate that pauses before each batch — calxgloss logs
    tokens but has no money concept and no pre-run gate.
    ([34](34-ai-assistant-agents-safety.md), [36](36-rewrite-pipeline.md))
11. **Evidence-computed confidence, model self-assessment ignored.** Score
    name/type suggestions by counting *independent engine evidence kinds that
    agree*, instead of parsing the model's claimed confidence.
    ([34](34-ai-assistant-agents-safety.md))
12. **Smaller, cheap ones:** `--json` from the same definition as help text +
    a generated command reference (xtask pattern); pagination caps as protocol
    constants on bundle sections; per-slot `origin+version` stamps making
    ADR-0021's "never overrule" a predicate; prompt-hash provenance per
    attempt; one exit-criterion test per roadmap P; a "name the dependents,
    *then* ask" preview before destructive review actions.
    ([32](32-edit-log-undo-gui.md), [33](33-automation-command-registry.md), [36](36-rewrite-pipeline.md), [37](37-inference-corpus-eval.md))

## What KRAKEN confirms about calxgloss's choices

- **Kuna in-process was right.** KRAKEN tried Ghidra-as-sidecar, built a
  22k-LOC JVM-free engine over Ghidra's C++ decompiler, and still needs
  Landlock, a watchdog, sidecar supervision and a nightly drift job. calxgloss's
  in-process seam sidesteps the entire lifecycle at the cost of one narrow
  engine — and KRAKEN can't even *execute* PE. ([31](31-analysis-engines.md), [35](35-emulation-patching.md))
- **Git is the right edit log for a single-writer factory.** KRAKEN's
  log/fold/CAS machinery exists for interleaved live writers at one address —
  a problem calxgloss legislated away with run isolation and attempt branches;
  merge *is* its accept. ([32](32-edit-log-undo-gui.md))
- **No external-agent surface is a safety feature, not a missing feature.**
  KRAKEN's approval board, quotas, proposal gates and ACP sandboxing are the
  price of letting third-party agents drive a live project. calxgloss's answer
  — "the pipeline is the agent," fenced by compile + baseline-test verification
  (ADR-0051) — avoids buying any of it. ([33](33-automation-command-registry.md), [34](34-ai-assistant-agents-safety.md))
- **Real execution beats synthetic fidelity for PE.** KRAKEN itself refuses to
  emulate PE and reserves native-process runs as the emulator cross-check;
  calxgloss's Wine baselines are trustworthy *because* they're real runs —
  replacing Wine with an emulator removes the method's foundation.
  ([35](35-emulation-patching.md))
- **Independent convergence marks the load-bearing walls:** callee-first
  ordering, bounded kind-routed repair loops, sandboxed model code,
  local-model-first, honest coverage vocabularies, and registry/descriptor-
  driven command surfaces (ADR-0052 arrived at design-0003's idea solo).
  ([33](33-automation-command-registry.md), [36](36-rewrite-pipeline.md))

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, KRAKEN revision |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor) |
| [20-kraken-inventory.md](20-kraken-inventory.md) | complete KRAKEN surface (31 crates, 78 commands, docs, corpus) |
| [31-analysis-engines.md](31-analysis-engines.md) | native/Ghidra/.NET engines, the engine seam |
| [32-edit-log-undo-gui.md](32-edit-log-undo-gui.md) | edit log as source of truth, undo, viewmodel, GUI |
| [33-automation-command-registry.md](33-automation-command-registry.md) | one registry, CLI, MCP, daemon, Python |
| [34-ai-assistant-agents-safety.md](34-ai-assistant-agents-safety.md) | assistant, models, agents, safety model |
| [35-emulation-patching.md](35-emulation-patching.md) | sandboxed emulator, patching, differential runs |
| [36-rewrite-pipeline.md](36-rewrite-pipeline.md) | binary → Rust: plan, translate, difftest, accept, export |
| [37-inference-corpus-eval.md](37-inference-corpus-eval.md) | kraken-infer, corpus/truth, eval harness, spikes |

All KRAKEN claims cite clone-relative `path:line` against `/tmp/opencode/kraken`
at `68718c6`; calxgloss claims cite this repo's ADRs, crates and docs. Every
chapter passed a mechanical citation audit — 449 unique cited files verified
to exist and every cited line in range (2026-10-28).

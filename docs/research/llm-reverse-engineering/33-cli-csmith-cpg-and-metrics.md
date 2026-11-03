# 33 — llm-reverse-engineering: CLI, CSmith, CPG metrics — the abandoned oracle

> Part of the [overview](README.md). All `file:line` cite the clone at
> `aa74f48`. Files: `main.py` (252 L), `tools/code_generator.py` (271 L).

## 1. The two CLI commands

Typer app (`main.py:17`) with two commands:

- **`generate <binary>`** (`:51-121`): open one r2 session, build the agent,
  fire one query — `"Please analyze the binary file at {path} in {mode}
  mode."` (`:98`) — print/save the markdown. No sessions, no fixes, no
  extraction: raw single-shot.
- **`generate_and_analyze -n N`** (`:123-249`): the phase-1 experiment
  ([21](21-history-and-releases.md) §3) — **CSmith** generates N random C
  programs (`code_generator.py:21-37`), each compiled
  `gcc -O0 -I/usr/include/csmith` (`:39-51`), decompiled by the agent, then
  scored with a battery of metrics into a Rich table +
  `{case}_cpg_analysis.json` files (`:208-225`).

The extraction rule differs from the UI: here it's a regex taking the
**first** ```c block (`:56-63`); the UI concatenates all blocks
(`app.py:36-56`). Two extractors, two semantics — the "output contract" is
enforced nowhere except the prompt's plea.

## 2. The metric battery

### Binary metrics (`compare_binaries`, `:72-129`)

- file-size delta %; **MD5 equality** — presented as a table column
  ("MD5 Match") although two separately compiled binaries essentially
  *cannot* match (different compilation units, build-ids); the column is a
  permanent "No" except by accident. (The UI's `overall_assessment`
  likewise carries `md5_match` — [32](32-streamlit-ui-recompile-metrics-and-sessions.md) §2.)
- string-set set algebra (common/unique counts).

None of these observe *behavior*: no execution, no inputs, no stdout/exit-code
comparison. The original binary is never run.

### CPG metrics (`generate_cpg`/`compare_cpgs`, `:154-272`)

The interesting idea — and the one calxgloss should study. For **source**
comparison: `joern-parse --language c` → `joern-export --format dot` →
`networkx` read_dot → compare:

| Measure | Code | Honest read |
|---|---|---|
| Graph edit distance | `nx.graph_edit_distance(G1,G2,timeout=10)` (`:211`) | NP-hard; on real programs the 10 s timeout returns `None` and the component is **silently dropped from the score** (`:231-235`) |
| SimRank avg (`:215-219`) | O(N²) iterations | same silent-drop behavior under `except:` |
| node/edge/delta vs max (`:223-224,241-249`) | count diff | trivially gameable by code padding |
| composite `similarity_score` | mean of available components (`:251-252`) | **denominator shrinks silently** — fewer working components = fewer chances to fail; and if pygraphviz is missing, `generate_cpg` collapses to the empty-graph sentinel (`:187-189`) → score 0.0 with a log line. A metric path that *silently reports emptiness* — the exact failure class calxgloss's coverage-honesty doctrine (ADR-0053, admission lines) exists to prevent |

What CPG similarity actually measures: **AST/CFG/PDG structural closeness of
the LLM's C to the original C source** — a static semantic proxy, closer to
"same program" than any ELF metric. Two fatal limits:

1. **It needs the original source.** Real RE targets (malware, legacy
   binaries) have none. The oracle only exists in the *evaluation* setting —
   and even the author's evaluation of real targets ([34](34-evaluation-corpus-and-effect.md))
   abandoned it for manual review.
2. **Same-source ≠ same-behavior**, and vice-versa: a faithful behavioral
   rewrite with different structure scores low; a structurally-close rewrite
   can still be wrong (see the `putchar` case).

calxgloss's oracle sits on the opposite footing: **execute the original
binary** (Wine harness, return values + ordered API-trace, ADR-0057) — needs
no source, measures behavior directly. LRE's CSmith design was actually a
coherent *alternative* oracle family (known-source corpus: compile both,
compare structure); its mistake is treating graph-similarity as the verdict
instead of the screen, and never capturing *outputs* of the compiled pairs —
which, for CSmith programs, would have been one `./orig; ./decompiled;
diff` away.

## 3. What the CLI path never shipped

- No execution-comparison despite compiling both binaries (`:203-206`): the
  natural "run both, diff" is absent from the whole repo.
- `output.md` (root, first commit) is the only surviving CLI-path artifact: a
  pretty decompilation of the demo program — no scores. **Zero published
  `generate_and_analyze` results exist in the repo**: no `generated_codes/`,
  no `*_cpg_analysis.json` files, no CPG scores. The battery ran at most on
  the author's machine.
- The pipeline isn't runnable as shipped: `csmith`, `joern-parse`,
  `joern-export` are assumed on PATH (`code_generator.py:17-19`), absent
  from Docker and README setup; pygraphviz missing
  ([20](20-llm-reverse-engineering-inventory.md) §2).

## 4. Comparison with calxgloss

**Overlap.** Both compile the *result*; both want automated scoring of the
whole task; both use external tools as the measuring instrument rather than
LLM judgment (no LLM-as-judge anywhere in either repo — a genuine point of
philosophical agreement).

**calxgloss-only.** Everything downstream of a real oracle: behavioral tests
from Wine-captured baselines; ordered API-trace containment verdict; per-unit
retry strategies keyed by *failure kind* (test_fix/compile_fix/edge_case_fix);
divergence index naming where the hunt gave up; the verification result as a
data record (`VerificationResult`) flowing to CLI/dashboard/records. LRE's
retry is one prompt variant ("return only corrected code",
`app.py:545`) with a fixed 3-attempt counter.

**LRE-only.** The **CSmith corpus generator** itself: randomized-source
compilers-testing, imported from compiler fuzzing, is the only *automatable,
unbounded* evaluation idea in this whole study, and neither calxgloss (one
fixture DLL, roadmap P33 unstarted) nor any sibling study we've reviewed
(OGhidra: curated binaries + prose metrics; LLM4Decompile: hand-curated eval
sets) has an equivalent. A calxgloss version: CSmith/cresmith-C → MSVC or
MinGW-PE → testgen baselines → translated Rust → compare *behavior*, or the
known-source shortcut: CPG-similarity as a *screening* metric with admission
lines when GED/SimRank time out.

**Steal ideas (priority order).**
1. **Randomized-known-source corpus** for calxgloss P33: generation removes
   the corpus-scarcity excuse; behavior (not CPG) is the verdict; CPG-
   similarity only as a secondary, admission-honest screen. Cost: one shell
   loop over `calxgloss-testfixtures`.
2. **Compile-both-and-diff-outputs** as the *minimum* aggregate check for
   any known-source corpus case (LRE missed it by one step — don't repeat).
3. **Metric honesty rules** — LRE's silent component-dropping and 0.0
   sentinel are ADR-0053 anti-patterns; calxgloss should cite them when
   specifying P33's scorecard (every dropped component prints an admission
   line; empty ≠ zero).

**Verdict.** Phase 1 is LRE's most instructive corpse: the *right* instinct
(automated, source-known, structural scoring) killed by no execution, silent
metric collapse, and zero shipped runs. For calxgloss it converts into two
concrete P33 ingredients and a cautionary clause.

## Sources

Clone `aa74f48`: `main.py`, `tools/code_generator.py`, `output.md`, `git
log`/tree scans (no generated_codes/*_cpg_analysis.json present); corpus
grounding [34](34-evaluation-corpus-and-effect.md); anchor:
[10](10-calxgloss-baseline.md) §Verification.

# 34 — llm-reverse-engineering: evaluation corpus & effect — what it actually achieves

> Part of the [overview](README.md). This chapter is the study's *only*
> effectiveness dataset. The xlsx cells were extracted by a sub-agent with
> Python stdlib (`zipfile`+`ElementTree`), then **verbatim spot-checked by the
> lead agent** against `xl/sharedStrings.xml` (`putchar(...)`,
> `Doskonałe przekształcenie…`, `Fundamentalne niezrozumienie…`,
> `atrapą zwracającą true…` all confirmed); demo-pair claims grep-verified
> (`putchar('*')` at `demo_code/decompiled_1.c:48`, `printf("%d ", arr[i])`
> at `testing/code_projects/utils_lib/src/utils.c:11`, zero crypto/XOR
> matches in `demo_code/simple_c_program.c` vs 7 in
> `demo_code/README_simple_c_program.md`).

## 1. The corpus: a deliberate difficulty ladder

`testing/src/compile_examples.sh` builds everything with
`gcc/g++ -Wall -Wextra` — **no `-O` flag (default -O0), no `-g`, no
sanitizers** — and the 21 committed binaries are **not stripped** (BuildIDs
present, GCC 13.3.0 Ubuntu 24.04 spot-checked on 4/21).

**Confound stated plainly:** with symbol tables intact at -O0, radare2 hands
the agent *the original function names and clean structure*; "decompilation"
on this corpus is heavily assisted recovery, not reconstruction. The author
never flags this; this study must.

### 20 code examples (48–255 LOC each)

| band | files | demonstrates |
|---|---|---|
| control flow & algorithms | 01 calculator (switch+validation), 02 quicksort, 04 "optimized idioms" (inline/register/unrolling — source-level only, compiled -O0) | basics |
| indirection | 03 function pointers / jump table | vtable-adjacent dispatch |
| data structures | 05 linked list, 06 binary tree, 07 hash table (chaining+resize), 08 custom pool allocator, 09 ring buffer | structs + heap |
| systems | 10 producer/consumer (**pthreads**), 11 socket server+client, 12 signals+fork, 13 raw fd I/O | OS APIs, concurrency |
| C++ | 14 class hierarchy (pure virtuals → **vtables**), 15 templates+STL, 16 exceptions+RAII | name mangling, ABI |
| vuln demos | 17 stack overflow (`gets`, CWE-121/787), 18 use-after-free (CWE-416), 19 format string (CWE-134), 20 integer overflow (CWE-190) | deliberate UB |

### 3 multi-file projects = the xlsx's three tiers

`simple_calc` (2-file factorial, the "Proste Pliki" case), `utils_lib`
(`ar rcs libutils.a`; `src/utils.c:11` has `printf("%d ", arr[i])` — the line
the LLM mangled, see §3), `json_parser` (C++, **boost::program_options +
nlohmann::json**, `main.cpp:3`, `parser.cpp:3` — verified).

Plus `demo_code/test.c`: a **csmith 2.3.0 generated program** (seed
`7614197739445800702`) — a phase-1 hard-case relic
([33](33-cli-csmith-cpg-and-metrics.md)).

## 2. `testing/results/project_analysis.xlsx` — the evaluation

Three Polish sheets, 4 columns
(Category | Original implementation | LLM result/analysis | Verdict),
all plain strings, no formulas. Structure per sheet: 6 assessment rows, then
**Ogólna ocena** (overall grade) / **Problemy** (problems) / **Mocne
Strony** (strengths). Translated content (Polish originals preserved in the
shared strings):

### Sheet 1 "Proste Pliki" — simple_calc → **success**

- main without `scanf` validation → LLM *fixed* it: checks return, stderr,
  `EXIT_FAILURE` — "Naprawiono krytyczny błąd" (critical bug fixed).
- factorial functionally identical + comments; 2 files merged to 1 —
  accepted as "logical simplification".
- Semantic analysis "flawless"; security analysis "precise, full
  understanding" (stack overflow, int overflow, scanf risks).
- Overall: **"Doskonałe przekształcenie pliku binarnego na oryginalny kod"**
  ("excellent transformation of the binary into original code"). Problem:
  "failure to distinguish the original project structure — the code was
  refactored".

### Sheet 2 "Stat. Biblioteki" — utils_lib → **mixed; the hallucination exhibit**

- Math functions rewritten `int → int64_t` — praised as proactive hardening.
- **`print_array` rewritten from `printf("%d ", …)` to `putchar(…)`,
  printing ASCII glyphs**: verdict cell — **"Fundamentalne niezrozumienie
  celu funkcji, co psuje wynik programu"** ("fundamental misunderstanding of
  the function's purpose, breaking its output"). Worse: the LLM's own
  semantic analysis *described the rewritten behavior as if it were the
  original's* — "Analiza utrwala podstawowe nieporozumienie LLM-a" (the
  analysis entrenches the misunderstanding). The self-explanation loop
  confirmed its own mistake — the live form of the unbound-evidence
  failure ([32 §3](32-streamlit-ui-recompile-metrics-and-sessions.md)).
- Security analysis: mixed — good recursion risks plus invented build
  details ("stack protection").
- Overall: partially correct. Strength cell is the methodological gem of the
  repo: "the LLM also takes into account the decompiler's obtained
  information — not just the generated code" — the author noticed
  *evidence-grounded vs output-grounded* claims differ, which is exactly the
  coverage-honesty distinction (ADR-0053) formalized.

### Sheet 3 "Zewn. Biblioteki" — json_parser → **failure of substance**

- JSON parsing (nlohmann `file >> j`) → **stub returning `true`**; analysis
  *claims a "SAX" parser was used*: "Utracono całą logikę i zmyślono
  algorytm parsowania" (all logic lost, parsing algorithm invented).
- Data storage `map<string,string>` → stubbed; analysis invents
  `map<string,Json>` + `vector<Json>`: "failed to recognize simple data
  structures, invented more complex ones".
- `validateAndClean` (quote-stripping) logic: "completely lost and
  unmentioned".
- Security analysis again *good*: DoS by large files, weak error handling,
  path traversal (`--file ../../etc/passwd`).
- Overall: mostly correct *identification* (CLI JSON processor, main/
  parseFile/getValue/printAll purposes right) — **the program was
  recognized, its behavior stubbed**. Problem cell: "Hallucinations, failure
  to recognize the attached external libraries".

## 3. `demo_code/` — four LLM outputs of the same toy program, kept side by side

`simple_c_program.c` (38 L: banner, `fgets` name, `scanf`, recursive
factorial, star-triangle capped at 5 rows) and `simple_c_program_1.c` (52 L,
same logic split into 5 named functions):

| output | kept what | drifted |
|---|---|---|
| `decompiled.c` | literals, recursion, `strcspn`, guard | hardened: `scanf!=1`→`EXIT_FAILURE`, `long` factorial, `puts` |
| `decompiled_1.c` | **all 5 function names** + call order | `putchar('*')` replaces `printf("* ")` — output drift mirroring the xlsx `print_array` complaint |
| `decompiled_chat_output.c` | as above + `int64_t` | **pattern loop moved into the `else` branch; 5-row cap dropped** — compiles, *differs* |
| `decompiled_simple_c_program.c` | cleanest, behaviorally identical | — |

The drift cases are *the* behavioral-equivalence exhibit: every artifact
compiles; two change what the program prints ([32](32-streamlit-ui-recompile-metrics-and-sessions.md)
§2: "does it compile" cannot see them).

**The README pair** — auto-generated docs for the same binary:
`README_simple_c_program_v1.md` is accurate (welcome/factorial/triangle
program, honest build+security notes); `README_simple_c_program.md` is a
**complete fabrication**: "XOR-based encryption, SHA-256 hashing, salted
credentials", files `main.c crypto.c auth.c logger.c`, `-lcrypto`, CLI flags
`-u alice -p S3cur3P@ss` — 7 crypto/credential matches in the README, **0**
in the source. The repo commits *both* versions: an unusual act of honesty,
and the strongest single exhibit of LLM confabulation we have catalogued
across all sibling studies (it's a *product feature output*, not a chat slip).

## 4. The author's own effect claims (README, phase-2 rewrite)

Strengths: intelligent refactoring/bug-fixing on small self-contained
programs ✓ (sheet 1); high-level security context even when decompilation
fails ✓ (all three sheets); algorithm/vuln pattern recognition — plausible,
never scored. Weaknesses: external-library black box ✓ (sheet 3); tendency
to hallucinate under ambiguity, "significant risk… fundamentally flawed
output" ✓✓ (sheets 2–3 + README fabrication); loss of original architecture
(files merged) ✓ (all sheets). Best use cases: auditing small C utilities,
rapid security triage, legacy procedural C, malware pattern ID — the first
three match the evidence; the malware claim is *untested* and the README
itself lists "Malware Detection Testing" as future work.

## 5. What "effect" means here — the honest summary

- **Aggregate evidence exists and is candid**: 1 assessor, 3 tiers + 20-case
  battery, grades + named problems + named strengths, in the author's native
  language, with the failure exhibits committed. No scores, no cost data, no
  reproduction script, no second rater, confounded by unstripped symbols and
  toy scale.
- **Unit-level proof does not exist**: nothing in the pipeline can distinguish
  the behaviorally-drifted `decompiled_chat_output.c` from the correct
  `decompiled_simple_c_program.c` (both compile; ELF metrics can't tell them
  apart either).
- The **performance ceiling is visible and self-diagnosed**: success where
  symbols + familiar algorithms + -O0 carry the model; stub-and-confabulate
  where meaning lives inside external library behavior.

## 6. Comparison with calxgloss

**Mirror-image gaps.** LRE: aggregate narrative, no unit oracle. calxgloss:
hard unit oracle (Wine baselines + trace containment, ADR-0057), *no
aggregate measurement at all* (roadmap P33; one fixture DLL). Both published
nothing quantitative; LRE at least published *structured judgments*. On the
"did we ever check what our tool achieves" axis, LRE did — badly instrumented
but really; calxgloss hasn't at task level. That credit must be stated.

**Failure-taxonomy transfer.** LRE's three documented failure classes map
directly onto calxgloss mitigations, giving calxgloss a *black-box evidence
checklist*: (1) external-library black-box → `calxgloss-apidetect` per-API
summaries + `calxgloss-libmatch` static-lib signatures (mitigated — but
"mitigated" is exactly what P33 must *measure*); (2) architecture loss →
per-unit output + call-graph queue (structurally impossible by design);
(3) hallucinated structure → compile+test+trace gate. calxgloss can state
these as *testable hypotheses* for a corpus, not hopes.

**Corpus transfer (top steal).** The ladder design — flat program →
static-link project → external-dependency project; plus bands (control
flow, data structures, OS APIs, C++ vtables, deliberate vulns) — is a
ready-made axis system for calxgloss's P33 corpus, re-instantiated as PE
targets (MinGW/MSVC builds of the same bands; `calxgloss-testfixtures`
already builds source-known PEs, enabling the *same-source* shortcut
LRE's CPG used — with LRE's execution-omission fixed: capture behavior via
testgen baselines, not CPG similarity). The vuln band doubles as a test of
`calxgloss-errhandling`/`calxgloss-memory` scans.

**Steal ideas (priority).**
1. Difficulty-ladder + 3-tier link-structure corpus → P33 design input.
2. Rubric vocabulary (overall/problems/strengths + the evidence-grounding
   distinction in sheet 2's strength cell) → P26/P33 reporting shape,
   rendered from records with admission lines (ADR-0053), not prose.
3. The README-fabrication exhibit → a *regression case* for any
   documentation/explanation feature calxgloss ships (bound-evidence rule:
   a claim row without a joined record must render as unknown, never prose).
4. Anti-pattern ledger: unstripped-symbol confounding — when calxgloss runs
   known-source corpora, report both stripped and unstripped runs so
   translation quality isn't overestimated.

**Verdict.** LRE's effect story is qualitative, confounded, and one-person —
but *real, tiered, and failure-forward*, which is more than calxgloss
currently has. Its published weaknesses are the precise classes calxgloss's
engine layer claims to solve; turning that claim into measurement is the
single biggest thing this study hands calxgloss.

## Sources

`testing/results/project_analysis.xlsx` (stdlib-parsed, spot-verified —
full verbatim Polish tables in the extraction log of this study's working
notes), `testing/` tree + `compile_examples.sh`, `demo_code/` all files,
README.md:172-204, binary fingerprints (`file`/`strings`/`readelf` on 4/21
+ all `demo_code` ELFs); caveats list: 4/21 binaries fingerprinted, xlsx↔
project pairing inferred from cell content (strong), 15/16 cpp files
classified via greps. calxgloss anchors:
[10](10-calxgloss-baseline.md), roadmap P26/P33, `crates/evidence`.

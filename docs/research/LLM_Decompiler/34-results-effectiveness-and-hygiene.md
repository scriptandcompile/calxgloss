# 34. The empty `results/`, the unscored superlative, the time-currency audit, and the reception — the consolidated hygiene ledger at HEAD

> Part of the [LLM_Decompiler overview](README.md). Where the earlier chapters inventoried (ch.20),
> dated (ch.21), and dissected the pipelines (ch.31–§33), this chapter audits **what the repo actually
> produced**: the `results/` receipt system and its vacancy, the README's effectiveness claims weighed
> against artifacts, a pickaxe correction to ch.21 §6's attribution of the claim's birth, a time-currency
> audit of every external pin (OpenAI models, openai SDK, Ghidra, Jython) as fetched 2026-10-31, GitHub
> reception forensics, a consolidated hygiene ledger at `c242671`, and the effect axis against calxgloss.
> All `path:line` re-opened in the read-only clone `/tmp/opencode/LLM_Decompiler` at HEAD
> `c2426715340b84a3e2eea4e891fe913a50154f00`; verified absences name the battery. Hosted facts come from
> `gh api` / webfetch dated 2026-10-31 unless marked. End-to-end execution remains out of scope (ch.00).

## 1. `results/` — a receipts system declared up front, never once used

`results/` at HEAD contains exactly one file: `results/README.md` (29 lines). Its first line is the promise:

> "Results of every single analysis will be saved in this directory following the naming convention:" (`results/README.md:1`)

The convention it draws (`results/README.md:3-29`) is a three-shelf taxonomy per analyzed item:
`results/[item_name]/executable_analysis/` with `[item_name]_decompiled.c` and
`[item_name]_decompiled_vulnerabilities.txt`; `enhanced_executable_analysis/` adding the
`_filtered` / `_filtered_enhanced` / `_filtered_enhanced_vulnerabilities.txt` chain; and
`source_analysis/` with `[item_name].c` and `[item_name]_vulnerabilities.txt`.

Three facts make the directory forensically interesting.

**The directory never held a receipt.** `git log --all -- results/` returns exactly two commits, both
2024-05-07 (`8058050` "Adding readme" 22:04:58 +0200, `589c2c6` "Update README.md" 22:08:29 +0200). No
ever on any ref (`git log --all --diff-filter=A --name-only -- results/` → the README only). The shelf
landed on the night of 2024-05-07 (`8058050`, 22:04), twelve minutes after the scripts it documents
(`5b25d26`, 21:52), and nothing was ever put on it, forever.

**The scripts did honor it — partially.** `grep -rn "results" --include='*.sh' .` finds the convention
wired into five orchestrators: `analyze_binary.sh:24`, `analyze_enhanced_binary.sh:38`,
`analyze_and_fix.sh:43`, `analyze_and_exploit.sh:48` all set `outputDir="${basePath}/results/…"` matching
the README's folder names, and `analyze_source.sh:24` mirrors `source_analysis/`. So the vacancy is not
sloppy scripts — the plumbing wrote to `results/` on every run; the author simply never committed what the
runs produced.

**The taxonomy was documentation, not design-by-contract.** The three original orchestrators it
describes (`analyze_binary.sh`, `analyze_enhanced_binary.sh`, `analyze_source.sh`) were added by `5b25d26`
at 21:52 on 2024-05-07 — **twelve minutes before** the results README (`8058050`, 22:04) codified their
`outputDir` convention. Which is exactly why the pivot below could outrun the docs unnoticed: the README
was a same-night snapshot of script behavior, and nobody maintained it after.

**The CTF pivot outgrew the README without updating it.**
`results/${executable_name}/` (`analyze_and_fix.sh:54` moves `${executable_name}_fixes.txt` there;
`analyze_and_exploit.sh:59-60` moves `_pwn.py` and `_ctf_context.txt` there) — but none of those three
filenames appears in `results/README.md`, which predates the pivot — `e0db19e`, 2024-05-23 (ch.21 §2;
ch.33 §4-§6) — by sixteen days and was never touched again after 2024-05-07. The receipt layout is
therefore a fossil of the Juliet-era plan: correct for the two original chains, silent about the chain
that actually shipped.

The takeaway for §2: the README (`:21`) asserts results existed; the repo's own convention directory —
created 2024-05-07, two days before the claim — contains zero results at any point in history.

## 2. Effectiveness claims vs. artifacts — the ledger

Every evaluation-flavored claim, its supporting artifact (or absence), and the command that verifies the
absence. All `README.md:NN` are at HEAD; the quoted text is verbatim.

| Claim (README at HEAD) | What it asserts | Supporting artifact in repo | Verification |
|---|---|---|---|
| `:5` "LLMs have demonstrated effectiveness akin to static analyzers on source code" | literature claim, framing | none (no citation given in README) | `grep -n "et al\|http.*paper\|DOI" README.md` → 0 |
| `:9` "we sought to quantify the performance of the GPT-4 model on binary vulnerability analysis… Juliet Test Suite was chosen" | an experiment was designed and run | `dataset_scripts/process_juliet_suite.py` (added `e913125` 2024-05-08 22:55) — preparation only | ch.33 §7: the suite tree it expects cannot be built from anything in the repo (`gcc\|clang\|cmake` battery → 0); §8: no scorer, no label consumer |
| `:21` "Enhanced decompiled binary analysis using LLMs outperformed traditional methods across all evaluated metrics." | superlative over a metric set | **none — never existed** | battery below |
| `:22` "higher efficacy in identifying existing bugs but incurred more false positives" | two numbers' worth of claims | none | same battery |
| `:26` "show promise for integration into development stacks… entry level [developers]" | value claim | none | unmeasurable by construction |
| `:31-34` Capabilities: code recovery, vulnerability reporting, exploit skeletons, long code bases | capability (not measurement) claims | the four drivers exist: `llm_r.py`, `llm_d.py`, `llm_pwn.py`, `large_code_base_reconstruction.py` | these are the README's only self-supporting claims — they claim the tool *runs*, and ch.31-33 confirm the code paths exist |
| `:101`, `:108`, `:115`, `:122` script descriptions call the model "the OpenAI GPT-4 model" | model identity | contradicts the code, which says `gpt-3.5-turbo`, `gpt-4-turbo`, `gpt-4o` | `grep -io "gpt[-0-9a-z.]*" README.md` → "GPT-4" ×6, nothing else; `grep -rn 'model=' *.py` → the six real strings |

The metric battery (`-S` pickaxe over all refs, plus a HEAD grep):
`-S 'precision'` → ∅; `-S 'recall'` → ∅; `-S 'score'` → ∅; `-S 'F1'` → ∅;
`-S 'accuracy'` → `cd00540` only; `-S 'metrics'` → `cd00540` only; `-S 'benchmark'` → `cd00540` only;
`-S 'evaluat'` → `cd00540` + `a4e57fc`; restricted to `'*.py' '*.sh'` every one of the above → ∅. At
HEAD, `grep -nE "accuracy|metrics|benchmark|precision|recall|scor" *.py *.sh` → 0 hits. The words
"metrics", "accuracy", "benchmark" have existed in exactly one blob family in this repository's entire
history: README prose. No scorer, no metric definition, no results file ever spelled them out in code.

**Correction to ch.21 §6 (line 246).** That ladder line attributes the superlative to `9c64ffc`
(2024-05-08 22:28, "Installation updates"). Re-running the shows it is wrong:
`git show 9c64ffc:README.md | grep -icE "outperform|evaluated metrics|preliminary|juliet"` → **0**, and
likewise `git show cd00540^:README.md` → 0. The claims block — H1 + "Description" + "Experiment Validating
Hypothesis" (incl. the Juliet framing) + "Preliminary Results" (both bullets) — enters the surviving
lineage whole in **`cd00540`, 2024-05-09 19:30:28 +0200**, whose diff (`+33/−1`) is literally that block:
the added lines are the current `README.md:1-26` text. `cd00540`'s ladder label in ch.21 §6 ("the Usage
section skeleton") is also off — the Usage skeleton (`analyze_all` ×2) is already present in `9c64ffc`'s
README; what `cd00540` added is the claims. The one-day-earlier `a4e57fc` (2024-05-08 22:49) hit in the
`evaluat`/`Juliet` pickaxes is **not** the root README: its change is to `dataset_scripts/README.md`, the
script's own docs (`git show a4e57fc:README.md | grep -cE "juliet|outperform"` → 0). So the order is:
tooling + its docs (May 7-8) → the working Usage README (May 8) → the effectiveness narrative bolted on
retroactively (May 9, 19:30) → nothing ever scoring it (May 9 → freeze 2024-07-15). The experiment story
was written about code that already existed, not as a protocol the work followed.

Against the cited paper's own design (Goseva-Popstojanova & Perhinschi 2015, DOI 10.1016/j.infsof.2015.08.002,
"On the capability of static code analysis to detect security vulnerabilities" — named in `README.md:9`,
Crossref, as cited in ch.33 §8), the shipped repo has exactly one of the needed legs: a corpus-prep script.
Missing: corpus construction (the Juliet tree cannot be built, ch.33 §7), the scorer (ch.33 §8 verified
absence), the control arm (no static analyzer wired anywhere), and the results directory it itself
prescribed (§1 above, empty forever). The claim at `:21` is not underdetermined — it is unbacked at every
level the repo's own documentation specifies.

## 3. Time-currency audit — every external pin as fetched 2026-10-31

**OpenAI models.** The eight call sites (imports/clients ledger: ch.20 §4) and their status against
OpenAI's own deprecations page (https://developers.openai.com/api/docs/deprecations, fetched 2026-10-31):

| Call site | Model string | Status as of 2026-10-31 |
|---|---|---|
| `llm_d.py:52`, `llm_f.py:36`, `llm_r.py:38` | `gpt-4-turbo` | **API-shutdown 2026-10-23** — page's 2026-04-22 "Legacy GPT model snapshots" entry shuts `gpt-4-turbo \| gpt-4-turbo-2024-04-09` down 2026-10-23; alias confirmed in the page's "Plain-text aliases" list |
| `large_code_base_reconstruction.py:49` | `gpt-3.5-turbo` | **API-shutdown 2026-10-23** — same entry shuts `gpt-3.5-turbo-0125 \| gpt-3.5-turbo` down 2026-10-23 |
| `llm_pwn.py:26`, `llm_fix.py:23`, `llm_ctf_context.py:24`, `llm_translate.py:21` | `gpt-4o` | **alive but scheduled**: the 2026-10-14 entry deprecates GPT-4o (`gpt-4o-2024-08-06`, `-2024-11-20`) and the whole 4o family for **2027-01-14** shutdown; the `gpt-4o-2024-05-13` snapshot was already shut down 2026-10-23 |

So as of this chapter's date, **four of the eight model call sites are dead endpoints**, eight days past
their shutdown; the other four have a published end date roughly fourteen weeks out. Every endpoint this
repo can address, anywhere, has either shut down or a shutdown date — there is no version of "run the
pipeline today" that does not involve editing model strings.

The correction matters in both directions: a working assumption carried into this investigation held that
gpt-4-turbo and gpt-3.5-turbo were retired **2025-07-15**; the deprecations page contains no 2025-07-15
model retirement at all (the July-2025 entries are `o1-preview` 2025-07-28 and `gpt-4.5-preview`
2025-07-14 shutdowns). The true dates (2026-10-23) are *more recent than this repo's whole life* — the
models were live throughout the repo's active window and died 27 months after it froze. Corroborating
secondary context (fetched 2026-10-31): the Wikipedia GPT-4 article states GPT-4 was removed from ChatGPT
in 2025 and from the API on 2026-10-23, citing that same deprecations page; the Wikipedia GPT-4o article
records ChatGPT-side retirement of GPT-4o on 2026-02-13 (announcement
openai.com/index/retiring-gpt-4o-and-older-models/).

**openai SDK.** The repo pins nothing: `git log --all -- requirements.txt` → ∅,
`git log --all --diff-filter=A -- '*requirements*' '*setup.py' '*setup.cfg' '*pyproject.toml'` → ∅,
and a `-S '1.3.3' --all` pickaxe → ∅. No dependency file has **ever** existed in this repository's
history — any remembered "requirements.txt pins openai==1.3.3" is folklore; the README's only dependency
instruction is `:50` ("Change the openai key with you own key in the .env file"). The import surface the
eight files use (`from openai import OpenAI`, `OpenAI(api_key=OPENAI_API_KEY)` at `llm_d.py:3,15`,
`llm_f.py:3,8`, `llm_r.py:3,14`, `large_code_base_reconstruction.py:4,13`, `llm_pwn.py:1,9`,
`llm_fix.py:1,9`, `llm_ctf_context.py:1,8`, `llm_translate.py:1,8`) plus
`client.chat.completions.create` (ch.20 §4) **still matches the current SDK**: PyPI serves `openai 3.42.0`
(uploaded 2026-10-31T00:27Z, requires Python ≥3.10 — https://pypi.org/pypi/openai/json), and the current
openai-python README (raw.githubusercontent.com/openai/openai-python/main/README.md) still shows exactly
this idiom, now labeling Chat Completions "the previous standard (supported indefinitely)" while the
Responses API is primary. The SDK is not the binding rot — the model strings are. One continuity note for
fairness: the Chat Completions **endpoint** the repo calls (`/v1/chat/completions`) is not on any
deprecation row of the page; only its model names are. `OpenAI(api_key=…)` direct-key auth (ch.20 §4) also
predates the SDK's current preference for `OPENAI_API_KEY`/workload-identity flows, but still works.

**Ghidra.** The harness pins `GHIDRA_PATH=./ghidra_11.0.1_PUBLIC` (`Decompiler/gd_decomp.sh:5`,
`Decompiler/gd_decomp_large.sh:5`) and the setup guide names the same version twice
(`README.md:45`, the target directory; `:48`, "If using a Ghidra release different from 11.0.1").
Release facts from the GitHub releases API
(fetched 2026-10-31): 11.0.1 published 2024-01-30; 11.1 2024-06-07; 11.2 2024-09-27; 11.3 2025-02-06;
11.4 2025-06-24; the 11.x line **ended at 11.4.3, 2025-12-03**; 12.0 2025-12-08; 12.1 2026-05-13; latest
**12.2, 2026-10-22** — two major lines and three minors past the pin, with the pinned line itself EOL for
eleven months. The upstream is emphatically alive (96,499 stars, pushed 2026-10-30, Apache-2.0 — repo API,
same fetch).

The zip-name instruction at `README.md:39` ("download the zip file named
`ghidra_release_PUBLIC_refNumber.zip`") has **never** matched a real asset name — the pinned release's own
asset is `ghidra_11.0.1_PUBLIC_20240130.zip` and 12.2's is `ghidra_12.2_PUBLIC_20261016.zip` (release
assets API). It is the wrong name even read against the version the README pins.

**Jython — correcting the assignment premise.** The premise carried into this audit was "Ghidra 11.2+
dropped Jython." Tree probes of the upstream repo via the contents API at each release tag (fetched
2026-10-31) refute it: `Ghidra/Features/Python` exists at 11.0.1; `Ghidra/Features/Jython` exists at 11.2,
11.3.2, and 12.0; at 12.1 and 12.2 it has moved to `Ghidra/Extensions/Jython` — still shipped, still
containing `jython-src` and an `extension.properties`/`README.md` pair. Jython was **renamed (11.2) and
demoted from Features to Extensions (12.1), not removed**. The real shift is toward CPython:
`Ghidra/Features/PyGhidra` is absent at 11.2's tree but present at 11.3.2 and at 12.2, whose PyGhidra
README describes the supported CPython-3 scripting/plugin path. Consequence for this repo: its
`-postscript` decompile scripts (ch.31 §3) are *not* broken by a removal — they remain runnable on 12.2
via the Jython extension or a PyGhidra port; the runnability verdicts stand where ch.31 §8 and ch.32 §7
placed them, and the premise this audit started from is what falls.

## 4. Reception forensics — twenty-seven months of silence, then two stars

Repository metadata (GitHub repo API, fetched 2026-10-31): created 2024-05-02, pushed_at
**2024-07-15T14:23:01Z** (the freeze, ch.21 §2), **3 stars, 3 forks, 2 watchers, 0 open issues, license
`null`, size 49 KiB**.

Star chronology is partially visible. The REST `/stargazers` and `/subscribers` endpoints 404 across this
entire environment (sanity-checked against LLM4Binary/LLM4Decompile, also 404 — an environment quirk, not
a property of this repo), and GraphQL `stargazers totalCount` reads 0 against REST's 3 — the two GitHub
surfaces disagree, reported as observed. The Events API (90-day retention) shows exactly two events ever
observable: `WatchEvent` by `neomafo88` 2026-10-18T17:57:58Z and by `BelT327l` 2026-10-20T22:56:21Z. All
observable reception therefore happened **~27 months after the repo froze**, inside the current 90-day
window; pre-2026 stars (if the third exists) are invisible by API retention. The two observed
WatchEvents are therefore a strict subset of the REST count of 3 — the surfaces are consistent in
direction, just truncated by the window.

The forks (`/forks` API): `ufwt/LLM_Decompiler` (created 2024-09-25), `fengjixuchui/LLM_Decompiler`
(2024-09-26, itself carrying 1 star), `mfkiwl/LLM_Decompiler` (2025-01-08). All three have
`pushed_at = 2024-07-15T14:23:01Z`, size 49, and their default branches sit at `c242671` — **every fork
is a byte-identical, zero-commits-ahead copy created after the upstream froze**. Nobody forked to extend,
fix, or contribute; the forks are archival snapshots (or scan-fodder).

The author (`/users/Lami99`): created 2021-03-01, 2 followers, **`public_repos: 1`** — LLM_Decompiler is
Lami99's only public repository. Combined with the 23-of-26 `epfl.ch` authorship from ch.21 §1, the shape
is a student project, not a practitioner's continuing tool.

Mention search (all `gh search`, fetched 2026-10-31): issues search → `[]`; code search
`'Lami99/LLM_Decompiler'` → empty; code search `'LLM_Decompiler'` → 17 hits, **all phrase collisions**
(IoMT-Lab/re_toolbox, agatho/ida-wow-analyzer, summerspringwei/llm-decompilation, Noelo-Lab/decbench,
SPIRE-GMU/SPIRE_GLLeN, Lobsters mirrors discussing the unrelated arXiv 2609.05370). Exactly one genuine
citation exists anywhere code-search can see, from searching `'Lami99'`: `abix-/modforge`,
`falcon-printer/docs/survey.md:60` (survey dated 2026-05-14 in its own header):

> "**LLM binary-decompilers** (c0ral1ne, Lami99, HKalbasi, several others). All emit C. Closest
> architectural match but wrong output target. Useful as a tactical fallback on top of Ghidra C, not as a
> primary pipeline."

modforge is a 1-star Rust modding framework (created 2026-05-04, pushed 2026-10-12); its prior-art survey
considered Lami99 and **rejected it for output-target reasons**. A year before that citation,
`gh search repositories q=LLM_Decompiler` ranks this repo #2 among 31 hits — the others being ~15
same-name projects (`c0ral1ne/llm-decompiler`, `hkalbasi/llm-decompiler` — the same two names the modforge
survey groups with Lami99 — down to `yyyyyyfaa/LLM-decompiler-metric-evaluation`, a peer project doing the
metric evaluation this one promises at `README.md:21` and never ships). Searchability is name-collision,
not reception.

**Effect tally:** three stars (two visible, both October 2026), three verbatim post-freeze forks, zero
issues, zero pull requests, zero code references, one third-party survey citation that lists the tool as a
rejected option. That is the complete measured external effect, as far as GitHub can see it.

## 5. Consolidated hygiene ledger at `c242671`

Rows marked *this chapter* are new; everything else cross-refs, not re-derived.

| # | Item | Evidence at HEAD | First logged |
|---|---|---|---|
| 1 | API key in git history; final commit only deletes the tip | `.env` history = `72c3c11` "hide key" (2024-05-09) + `c242671` "Delete .env" (2024-07-15); `README.md:50` still instructs "Change the openai key… in the .env file" — a file HEAD deletes (ch.20 §11.1) | ch.21 §5 (redaction rule: shape `sk-…T3BlbkFJ…` never reproduced) |
| 2 | No license | repo API `license: null`; the three forks are therefore unlicensed verbatim copies | ch.20 §9; forks API, this chapter |
| 3 | No CI, no tests, no packaging | no `.github`, no test/CI files on any ref | ch.20 §9 |
| 4 | **No dependency pin ever** — requirements.txt has never existed | `git log --all -- requirements.txt` → ∅; setup/pyproject existence battery → ∅; `-S '1.3.3' --all` → ∅ | *this chapter* (corrects folklore of an `openai==1.3.3` pin) |
| 5 | 4 of 8 model call sites are dead endpoints (2026-10-23 shutdown); remaining 4 shut down 2027-01-14 | `llm_d/f/r.py` → `gpt-4-turbo`; `large_code_base_reconstruction.py:49` → `gpt-3.5-turbo`; deprecations page | *this chapter* §3 |
| 6 | Ghidra pin is two major lines behind and on an EOL line; README zip-name never matched any release asset | `gd_decomp.sh:5`/`gd_decomp_large.sh:5`/`README.md:39,45,48`; assets API | *this chapter* §3 |
| 7 | `results/` receipt convention: never a single receipt in history; CTF artifacts (`_fixes.txt`, `_pwn.py`, `_ctf_context.txt`) undocumented by it | §1 battery; `analyze_and_fix.sh:54`, `analyze_and_exploit.sh:59-60` | *this chapter* §1 (vacancy first logged ch.20 §7) |
| 8 | "outperformed… across all evaluated metrics" with no metric ever existing in any blob | §2 pickaxe battery; claim born `cd00540` | ch.20 §8, **attribution corrected here** vs ch.21 §6 line 246 |
| 9 | README/code model-string drift: README says "GPT-4" ×6, code says turbo/3.5/4o | `README.md:101,108,115,122` vs `grep 'model=' *.py` | *this chapter* §2 |
| 10 | Silent-success banners; unbounded whole-file→prompt reads | ch.31 §8, ch.32 §7 (drivers' variants: ch.33 §3) | ch.31/32/33 |
| 11 | No executable bits while README prescribes `bash ./x.sh`-style invocations | `git ls-files -s` → all `100644` | ch.20 §11.2 |

Twelve items in ch.20 §11 measured code-as-written breakage; this ledger adds the environment-side rot
(rows 4-6, 9) and re-homes the claim problem (row 8) in history. Sum across both: the repo was already
brittle at write-time and is, at read-time, **unrunnable as addressed** — four call sites return model
errors before any Ghidra or prompt question arises.

## 6. The effect axis — measured against calxgloss at `40fbf91f`

LLM_Decompiler's measurable external effect is the §4 tally: three stars (two observable, both 27 months
post-freeze), three byte-identical forks, one rejected-option citation, zero contributions. Internally the
repo is **unmeasurable by construction**: no scorer (ch.33 §8), no corpus build (ch.33 §7), no receipts
ever (§1), no metric vocabulary in code (§2).

calxgloss at the ch.10 baseline (`40fbf91f`, P33 open, one fixture DLL
`calxgloss-testfixtures`, no CI per P42) today has **no scored evaluation either** — that symmetry is
stated first so the comparison is honest. The difference is kind, not degree:

- **Receipts by construction.** ADR-0057 gates every decompile attempt (compile + Wine + trace), each
  attempt lands on its own `re/{binary}/{function}v{N}` branch, and `re/analysis/token_usage.json` records
  spend. The artifacts whose absence §1-§2 spent a whole chapter documenting are, on the calxgloss side,
  produced automatically per attempt before any scoring exists.
- **Claims are rationed.** LLM_Decompiler shipped a superlative on day 8 with zero receipts behind it
  (§2); calxgloss's open P33 says, in effect, *no effectiveness claim until there is a score*. A repo can
  be behind on measurement (calxgloss) or ahead of its evidence (LLM_Decompiler); only the second is a
  correctness defect in the documentation itself.
- **Asymmetry size.** LLM_Decompiler: 26 commits, 0 artifact commits in any results location, across the
  full history. calxgloss: receipts (branches, telemetry, gate outputs) exist from the first attempt
  forward; what is missing is the scorer to judge them — a missing judge vs. missing evidence for a judge
  to judge.

## Steal ideas for calxgloss

- **Ship the receipts dir in the same commit as the first claim.** `results/` was created on day one and
  stayed empty; claims arrived two days later anyway. When P33's scorer lands, the results layout, the
  scorer, and any README sentence citing a number should be one indivisible merge — a claim without its
  receipt path should fail review.
- **Claims need measurement IDs.** Adopt the discipline that every efficacy sentence names the artifact
  backing it (branch + `token_usage.json` window + gate output). `cd00540` is the cautionary specimen:
  one +33-line README commit bolted a whole experiment narrative onto a tool that had already been built,
  with no protocol and no scores on either side of it.
- **Treat model strings as dated expiry labels.** OpenAI's deprecations page now publishes shutdown dates
  for every family; a repo that hard-codes model names should record the shutdown date next to the pin
  (calxgloss's telemetry could carry the model string + its announced EOL the way it carries spend).
- **Toolchain-currency checks over folklore.** This audit started with two wrong ecosystem premises (the
  2025-07-15 model retirement date; "Jython was dropped in 11.2"). Both were settled in minutes by
  tree-probing upstream at tags. Any calxgloss ADR that asserts something about Wine/Ghidra/GCC versions
  should cite the probe (tag, path, date), the way graft cites file:line — and a periodic
  "is our pinned line still released" check is cheap (11.x died 2025-12-03 with no ceremony).
- **Reception snapshots with retention caveats.** The Events API only shows 90 days; REST counts and
  GraphQL disagree. If calxgloss ever keeps a reception ledger, snapshot at observation time and note the
  surface each number came from.

## Sources

- Read-only clone `/tmp/opencode/LLM_Decompiler` @ `c2426715340b84a3e2eea4e891fe913a50154f00` (never
  modified): `git log --all -- results/` and `--diff-filter=A --name-only` batteries; README blob reads
  `git show {9c64ffc,cd00540^,cd00540,9c64ffc}:README.md`; `-S` pickaxes (§2); `git ls-tree`,
  `git merge-base --is-ancestor a4e57fc HEAD`; per-file greps (§1, §5).
- GitHub API (all fetched 2026-10-31): `repos/Lami99/LLM_Decompiler` (3/3/2, license null, size 49,
  pushed 2024-07-15, created 2024-05-02); `…/forks` (ufwt 2024-09-25, fengjixuchui 2024-09-26, mfkiwl
  2025-01-08; all pushed_at = upstream, heads at `c242671`); `users/Lami99` (public_repos 1);
  `repos/NationalSecurityAgency/ghidra` (96,499 stars) and `releases?per_page=100` (full 11.x/12.x date
  ladder) and `releases/tags/Ghidra_{11.0.1,12.2}_build` asset names; contents-API tree probes of
  `Ghidra/Features/{Python,Jython,PyGhidra}` and `Ghidra/Extensions/Jython` at refs 11.0.1, 11.2, 11.3.2,
  12.0, 12.1, 12.2; `search/repositories?q=LLM_Decompiler` (31 hits); Events API (2 WatchEvents). REST
  `stargazers`/`subscribers` 404 across the environment (cross-checked against
  `scriptandcompile/LLM4Binary`, `fgirengo/L4D_public`), GraphQL `stargazers` `totalCount 0` — both
  reported as observed inconsistency.
- `gh search` code/issues/repositories (2026-10-31): `'Lami99/LLM_Decompiler'` ∅; `'LLM_Decompiler'` 17
  false-positive hits; `'Lami99'` → genuine hit `abix-/modforge falcon-printer/docs/survey.md:60` (raw
  fetch + modforge meta: 1 star, created 2026-05-04, pushed 2026-10-12); issues search `[]`.
- Web, all fetched 2026-10-31 unless noted: https://developers.openai.com/api/docs/deprecations (the
  authoritative model-status table: 2026-04-22 entry → 2026-10-23 shutdowns of `gpt-3.5-turbo`,
  `gpt-4-turbo`, `gpt-4o-2024-05-13`; 2026-10-14 entry → GPT-4o family 2027-01-14; plain-text-aliases
  section); https://pypi.org/pypi/openai/json (openai 3.42.0, uploaded 2026-10-31, Python ≥3.10);
  https://raw.githubusercontent.com/openai/openai-python/main/README.md (chat-completions "supported
  indefinitely"; Responses API primary); https://en.wikipedia.org/wiki/GPT-4 (page last edited 2026-10-29;
  ChatGPT removal 2025, API removal 2026-10-23 citing the deprecations page);
  https://en.wikipedia.org/wiki/GPT-4o (ChatGPT retirement 2026-02-13; API alias/snapshot status);
  https://en.wikipedia.org/wiki/GPT-3 (GPT-3.5 section; stable snapshot `gpt-3.5-turbo-0125`, 2024-01-25).
- Cross-links: receipts vacancy and README-claims ledger — ch.20 §7, §8; chronology, README ladder, and
  key forensics — ch.21 §2, §5, §6 (**line 246 corrected by §2 above**); runnability and harness —
  ch.31 §3, §8, ch.32 §7; unscored experiment, scorer battery, 2015 paper design — ch.33 §4-§8; calxgloss
  anchors — ch.10 at `40fbf91f` (P33, ADR-0057, per-attempt branches, `token_usage.json`, P42); style
  sibling — LLM4Decompile ch.32.

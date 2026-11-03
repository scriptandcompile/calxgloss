# LLM_Decompiler history & release archaeology (26 commits, no tags)

> Part of the [LLM_Decompiler overview](README.md). The complete commit
> history — 26 commits, one human, 69 days of public life — reconstructed from
> the read-only clone at `/tmp/opencode/LLM_Decompiler`
> (`c2426715340b84a3e2eea4e891fe913a50154f00`): per-commit numstat, name-status
> with rename detection, the merge graph, and the API-key forensics that this
> repo's file index euphemistically calls the `.env` story. **There are zero
> tags and zero GitHub Releases** (API battery, 2026-10-31), so there is no
> release ladder at all — the README is the only release narrative, and it
> rots. All dates are commit dates at author timezone `+0200`, author ==
> committer on every commit; web facts fetched 2026-10-31.

## 1. Commit shape and the one human behind 26 commits

Single branch `main` (clone: `origin/main` only; API `branches: ["main"]`);
**26 commits total** (`git rev-list --count --all` = 26 = `HEAD`), oldest
`9a5b3e0` "Initial commit" (2024-05-02 16:48), newest `c242671` "Delete .env"
(2024-07-15 16:23) — which is also GitHub `pushed_at` (14:23:01Z). Exactly
**one merge commit** in the entire history: `ba1aa02` "Merge branch 'main' of
https://github.com/Lami99/LLM_Decompiler" (parents `a80331c` + `fadee84`), a
plain self-sync pull mid-session, not a PR merge. There are no PRs at all
(API `pulls?state=all` → 0).

`git log --all --format='%ae' | sort | uniq -c`:

| Identity | Commits | Which |
|---|---:|---|
| `Fatnassi <slim.fatnassi@epfl.ch>` | 23 | everything done from the CLI |
| `Fatnassi <79871958+Lami99@users.noreply.github.com>` | 3 | `9a5b3e0` (repo-creation commit), `fadee84` "Delete Dataset_scripts directory", `c242671` "Delete .env" — the latter two are unmistakably GitHub **web-UI folder/file deletes** |

Same human, two GitHub identities (the noreply form is what GitHub web
operations write when email privacy is on); API contributors list = `Lami99`,
26/26. Commit-message style is half CLI half web-UI: 9 commits are literally
"Update README.md", web-UI sentences elsewhere ("Create
process_juliet_suite.py" — though `e913125` carries the epfl identity —
"Update analyze_and_exploit.sh", "Delete .env"), CLI phrases for the real
work ("Functionality scripts", "headless ghidra automation", "hide key",
"Support for large source code base", "Functionality extension").

Activity is not spread — it is **six bursts**:

| Day | Commits | Window (local) |
|---|---:|---|
| 2024-05-02 | 1 | 16:48 |
| 2024-05-07 | 7 | 21:52 → 22:14 (22 min) |
| 2024-05-08 | 8 | 22:28 → 22:56 (28 min) |
| 2024-05-09 | 7 | 16:30 → 19:34 (3 h 04 m) |
| 2024-05-23/24 | 2 | 20:43; next-day 12:23 |
| 2024-07-15 | 1 | 16:23 |

22 of the 26 commits fall inside those three same-evening windows (7 in 22
minutes, 8 in 28 minutes, 7 in 3 h 04 m); the remaining four are the stub,
the CTF pivot, its next-day fix, and the deletion. The gaps are silence,
not pace.

## 2. Full chronology (all 26 commits)

Per-commit file counts and +/- from the numstat battery (`num.txt`). Dates
2024, `+0200`.

| # | Sha | Time | Message | Files (±) |
|---:|---|---|---|---|
| 1 | `9a5b3e0` | 05-02 16:48 | Initial commit | README +2 |
| 2 | `5b25d26` | 05-07 21:52 | Functionality scripts | **9 files +456**: `analyze_all` 41, `analyze_binary` 31, `analyze_enhanced_binary` 50, `analyze_source` 35, `decompile_pipe` 35, `large_code_base_reconstruction.py` 98, `llm_d` 63, `llm_f` 54, `llm_r` 49 — key hardcoded in 4 of them (§5) |
| 3 | `95016c1` | 05-07 21:55 | Adding decompilation script | `decompiler.py` +40 (repo root) |
| 4 | `3363516` | 05-07 21:57 | headless ghidra automation | `Decompiler/gd_decomp.sh` +24 |
| 5 | `8058050` | 05-07 22:04 | Adding readme | `Decompiler/exec/README.md` +1, `results/README.md` +16 |
| 6 | `589c2c6` | 05-07 22:08 | Update README.md | `results/README.md` +13 |
| 7 | `49df012` | 05-07 22:12 | Adding helper scripts | 5 +235: `Dataset_scripts/process_juliet_suite.py` 58, `helper_scripts/{count_cpp_files 35, regroup_subdirs 41, select_from_cwe 55, strip_binaries 46}` |
| 8 | `9316783` | 05-07 22:14 | Update process_juliet_suite.py | 1/1 |
| 9 | `9c64ffc` | 05-08 22:28 | Installation updates | **R100** `decompiler.py → Decompiler/decompilation_scripts/…`; README +87/−1 |
| 10 | `a4e57fc` | 05-08 22:49 | Update readme | **R100** `helper_scripts/select_from_cwe.py → dataset_scripts/…`; `dataset_scripts/README.md` +39; `helper_scripts/README.md` +26; README +4/−2 |
| 11 | `d23429f` | 05-08 22:51 | Update README.md | `dataset_scripts/README.md` 2/2 |
| 12 | `fadee84` | 05-08 22:53 | Delete Dataset_scripts directory | **D** `Dataset_scripts/process_juliet_suite.py` (−58) — web-UI identity |
| 13 | `a80331c` | 05-08 22:54 | Update README.md | `dataset_scripts/README.md` 6/7 |
| 14 | `ba1aa02` | 05-08 22:54:47 | Merge branch 'main' of …Lami99/LLM_Decompiler | merge (parents `a80331c`, `fadee84`) |
| 15 | `e913125` | 05-08 22:55 | Create process_juliet_suite.py | **A** `dataset_scripts/process_juliet_suite.py` +58 — byte-identical to the deleted file (§4) |
| 16 | `2e7fee2` | 05-08 22:56 | Update README.md | `dataset_scripts/README.md` 3/2 |
| 17 | `72c3c11` | 05-09 16:30 | hide key | **A** `.env` +1; README +10/−7; `large_code_base_reconstruction.py` + `llm_{d,f,r}.py` +3/−2 each (§5) |
| 18 | `8eff39b` | 05-09 17:07 | Support for large source code base | +3 files: `large_decompiler.py` 24, `gd_decomp_large.sh` 24, `decompile_large_pipe.sh` 35; `large_code_base_reconstruction.py` −2 (debug prints); README 1/1 |
| 19 | `cd00540` | 05-09 19:30 | Update README.md | README +33/−1 |
| 20 | `517710b` | 05-09 19:32 | Update README.md | README 11/10 |
| 21 | `768f219` | 05-09 19:33 | Update README.md | README 4/4 |
| 22 | `f6af70f` | 05-09 19:33 | Update README.md | README +1 (a blank line, per the diff) |
| 23 | `5a7de76` | 05-09 19:34 | Update README.md | README 8/8 |
| 24 | `e0db19e` | 05-23 20:43 | Functionality extension | 6 new files +333: `analyze_and_exploit` 62, `analyze_and_fix` 56, `llm_ctf_context` 54, `llm_fix` 53, `llm_pwn` 60, `llm_translate` 48 |
| 25 | `51a2c98` | 05-24 12:23 | Update analyze_and_exploit.sh | 1/1 — fixes `e0db19e`'s broken 4-arg `llm_ctf_context.py` call |
| 26 | `c242671` | 07-15 16:23 | Delete .env | **D** `.env` (−1) — the only file touched; web-UI identity |

Note row 2: `5b25d26` is the **big bang** — at 21:52 on 2024-05-07 the repo
goes from a 2-line README to a complete working toolkit (decompile → filter →
rename → detect) in one 456-line commit, and the tree at that commit is
exactly 10 files (`git ls-tree -r 5b25d26`). Everything after is dressing:
rehoming, docs, hygiene, and one late pivot.

## 3. The development arc in five phases

- **P0 — stub (May 2).** `9a5b3e0` puts a 2-line README and nothing else.
  Repo-creation commit carries the GitHub noreply identity.
- **P1 — the toolkit all at once (May 7, 22 minutes).** `5b25d26` lands the
  four `analyze_*` scripts, both pipes, the rename/filter/detect drivers and
  the large-codebase loop — with the OpenAI key hardcoded in four of them
  (§5). Then, in 22-minute order: the Ghidra postScript at repo root
  (`95016c1`), its `analyzeHeadless` launcher (`3363516`), the `results/`
  naming-convention READMEs (`8058050`, `589c2c6`), and the Juliet/helper
  batch under **capital-D** `Dataset_scripts/` (`49df012`, `9316783`). No
  `Decompiler/` directory yet — the postScript sits at the root.
- **P2 — rehome + docs (May 8, 28 minutes).** `9c64ffc` ("Installation
  updates") performs the first of the repo's two real renames — `decompiler.py`
  into `Decompiler/decompilation_scripts/` — and rewrites the README from 2
  to 88 content lines (Ghidra 11.0.1 install guide appears). `a4e57fc`
  performs the second rename (`select_from_cwe.py` → the new lowercase
  `dataset_scripts/`) and creates both sub-READMEs. The dataset-dir case
  dance (`fadee84` delete → `ba1aa02` merge → `e913125` byte-identical
  recreate) is §4.
- **P3 — hygiene + large-codebase support + README polishing (May 9).**
  `72c3c11` "hide key" moves the API key from four scripts into a 1-line
  `.env` (§5). `8eff39b` at 17:07 adds the JSON twin path
  (`large_decompiler.py`, `gd_decomp_large.sh`, `decompile_large_pipe.sh`),
  deletes two debug prints from `large_code_base_reconstruction.py`, and —
  in its README line — writes the fatal phrase "in the .env file" into setup
  step 2 (`README.md:50`, per its diff). Then a 5-commit README burst at
  19:30–19:34 (`cd00540` +33/−1, `517710b`, `768f219`, `f6af70f`, `5a7de76`)
  builds the final Usage section and reaches the frozen 127-content-line
  README.
- **P4 — the CTF pivot (May 23–24).** After 14 days of silence, `e0db19e`
  "Functionality extension" adds six files (+333) that turn the tool from
  "detect vulnerabilities" to "category, hints, pwn skeleton, fixes,
  translate" — `analyze_and_exploit.sh` chains `llm_pwn` + `llm_ctf_context`,
  `analyze_and_fix.sh` chains `llm_fix`, and `llm_translate.py` lands with
  **no caller at all**. The README is not touched. The pipeline is broken on
  arrival (`llm_ctf_context.py` called with 4 args vs its 3-arg parser) and
  fixed 16 h later by `51a2c98`, which touches exactly that line.
- **P5 — the deletion (Jul 15).** `c242671`, via the GitHub web UI, deletes
  `.env` and nothing else. It is the last commit of the repository — the
  README still tells users to edit that file (`README.md:50`) and six
  undocumented scripts still ship. Deletion-as-cleanup with no history
  rewrite achieves nothing secret-wise (§5) and breaks setup as a side
  effect (inventory §11.1).

README content-line ladder across its 10 touches: **2 → 88 → 90 → 93 → 93 →
125 → 126 → 126 → 127 → 127** (`wc -l` 126 + no trailing newline at HEAD).
Code-side, the last two phases add 669 lines with exactly zero README
documentation for them — that is the entire drift budget.

## 4. The dataset-directory case dance (and the two real renames)

`git log --all -M --diff-filter=R` returns **exactly two renames**, both
R100 (content-identical):

```
9c64ffc  decompiler.py → Decompiler/decompilation_scripts/decompiler.py   (05-08 22:28)
a4e57fc  helper_scripts/select_from_cwe.py → dataset_scripts/select_from_cwe.py (05-08 22:49)
```

`select_from_cwe.py`'s md5 at `a4e57fc` equals its md5 at HEAD
(`b97aa7d7…`, verified in-clone) — a pure move.

The `Dataset_scripts/ → dataset_scripts/` "rename" is a different animal and
the repo's only cross-machine moment:

| Step | Commit | What |
|---|---|---|
| born | `49df012` 05-07 22:12 | `Dataset_scripts/process_juliet_suite.py` +58 (capital D) |
| edited | `9316783` 05-07 22:14 | 1/1 |
| deleted remotely | `fadee84` 05-08 22:53 | GitHub web-UI "Delete Dataset_scripts directory" (−58, noreply identity) |
| synced | `a80331c` 22:54 → `ba1aa02` 22:54:47 | local edit + the history's only merge |
| recreated | `e913125` 05-08 22:55 | `dataset_scripts/process_juliet_suite.py` +58 |

The recreate is **byte-identical to the deleted file**: md5 `69436350…` of
`e913125`'s blob = md5 of the same path at `fadee84^` = md5 at HEAD (in-clone
battery). The whole point of the dance was the lowercase directory name —
GitHub's web UI deleted the folder, and one minute after the merge the author
re-committed the identical file under the new case, since web-UI file
creation can't rename directories. Hence: only two of the repo's three
directory moves show up as git renames, and case-correct moves via web UI
leave a delete+recreate scar with a merge in the middle.

## 5. SECRET HYGIENE FORENSICS — one key, committed twice, still recoverable at HEAD

The secret is an OpenAI legacy-format API key, shape `sk-<20 alnum>T3BlbkFJ<20
alnum>` (51 characters, length-verified in-clone). **It is deliberately never
reproduced in this dossier.** Everything below was established by commands run
inside the clone, with key material redacted or hashed at extraction time.

**Life ledger:**

| When | Commit | What happened to the key |
|---|---|---|
| 2024-05-07 21:52 | `5b25d26` | Key **born hardcoded** — exactly 1 occurrence each in `llm_d.py`, `llm_f.py`, `llm_r.py`, `large_code_base_reconstruction.py` (per-blob `grep -c 'sk-'` = 1,1,1,1) |
| 2024-05-09 16:30 | `72c3c11` "hide key" | Per script, the 2 lines `# Replace the placeholder…` + `OPENAI_API_KEY = 'sk-…'` are replaced by `load_dotenv()` + `os.getenv('OPENAI_API_KEY')` (+3/−2 each) — and the same key is **re-committed verbatim** in the new 1-line `.env` (blob `620a651fb3d86c649de962d85c11b03283af03db`, no trailing newline) |
| 2024-07-15 16:23 | `c242671` "Delete .env" | `.env` removed at HEAD; **no history rewrite** — every prior blob stays reachable from `main` |

All five committed instances (4 hardcoded at `5b25d26` + 1 in `.env` at
`72c3c11`) are the **same key**: `sha256` of the extracted `sk-…` literals
inside the clone matches across all five (digest prefix `fb7d38bf…`); the key
itself was never printed.

**Pickaxe:** `git log --all -S 'sk-'` returns exactly three commits —
`5b25d26` (added it), `72c3c11` (moved it), `c242671` (removed it from the
tree). Nothing else ever introduced or carried the string.

**HEAD cleanliness vs recoverability:** `grep -rn 'sk-'` in a worktree at
`c242671` → **0 hits**. But `git show 5b25d26:llm_d.py` or
`git show 72c3c11:.env` in any clone of this public repo prints the live key
(verified — recovered into a scratch path and hashed, never transcribed).
"Delete .env" as a final commit is therefore **security theatre with a setup
regression attached**: the secret is forever in reachable history, while the
fresh-clone user now has no `.env` at all, only `README.md:50` promising one.

**Hygiene context:** no `.gitignore` was ever committed (§9 of the inventory),
so `.env` was tracked from birth to death; there is no rotation or revocation
note anywhere (NEGATIVE FINDING: worktree grep for `revok\|rotat\|expire` →
0 hits, and `git log --all -S` for each of the three terms → 0 commits;
README still says "change the openai key with you own key", `:50`). Whether
the key was ever rotated at OpenAI is unknowable from
the repo. Public exposure window in the default branch: 2024-05-07 21:52 →
2024-07-15 16:23 ≈ **69 days** — and, since the blobs were never rewritten,
indefinitely thereafter.

## 6. README as the only release narrative — what each doc burst claimed

With no tags, no releases, and no CHANGELOG, the ten README-touching commits
are the entire release record:

| Commit | Δ | What it added |
|---|---|---|
| `9a5b3e0` | +2 | title + one line |
| `9c64ffc` | +87/−1 | Setup Guide: Ghidra 11.0.1 install guide (its text survives verbatim to HEAD `README.md:37`–`:48`) + the numbered script-description section (entries 1–9) |
| `a4e57fc` | +4/−2 | pointer to the new `dataset_scripts/` + dataset setup step |
| `72c3c11` | +10/−7 | setup step 2 for the key (dotenv), matching the same-commit code change |
| `8eff39b` | 1/1 | appends "in the .env file" to step 2 — the sentence HEAD's last commit makes false |
| `cd00540` | +33/−1 | the claims block: new H1, Description, *Experiment Validating Hypothesis*, **Preliminary Results**, Conclusion, Capabilities (becomes HEAD `README.md:1-26`) |
| `517710b` | 11/10 | `<ins>` section headers (verified in diff) |
| `768f219` | 4/4 | Capabilities bullets moved |
| `f6af70f` | +1 | one blank line |
| `5a7de76` | 8/8 | reflow only |

Everything after May 9 19:34 is **documentation of the old tool only**:
`e0db19e`'s six CTF scripts (+333 lines — 28% of the 1,171 code lines at
HEAD) have no
README entry, no usage example, and no mention of their `~/Desktop/sp_new`
hardcoding — and `c242671` then de-syncs the setup guide (inventory §11,
items 1 and 12). The "Preliminary Results" claims enter the README whole in
`cd00540` (outperformed traditional methods "across all evaluated metrics",
HEAD `:21`–`:22`) and are, at every commit including HEAD, backed by zero artifact —
`results/` never held anything but its own README (§7 of the inventory;
`git log --all -- 'results/*'` shows only the README's A+M).

## 7. Releases, branching, and maintenance status

API battery (`gh api`, 2026-10-31): `releases` → **0**; `tags` → **0**;
`pulls?state=all` → **0**; `branches` → `["main"]`; `open_issues` → **0**;
contributors → `Lami99` 26/26; `created_at` 2024-05-02T14:48:22Z;
`pushed_at` 2024-07-15T14:23:01Z; `license` → **null** (unlicensed);
`fork` → false; `size` 49 KB; 3 stars, 3 forks. Phrase boundary: there are
simply no issues and no PRs — nothing in the repo or its history suggests
anyone other than the author ever touched it.

The maintenance picture is a single 69-day session (three active evenings +
one pivot + one cleanup) followed by ~27½ months of stillness as of
2026-10-31. No fork has fixed the CTF pipelines' `Desktop` hardcoding or the
missing exec bits (3★/3 forks, zero PRs). For the comparison this matters in
one specific way: LLM_Decompiler is **frozen mid-drift** — its README, code,
and hygiene state will never converge, so any calxgloss-vs-LLM_Decompiler
judgement is judging a closed case (the drift is complete, inventory §11).

## Steal ideas for calxgloss

- **History as an attack-surface audit**: the key forensics (§5) is the
  template — pickaxe (`-S`), per-blob counts, digest-equality instead of
  transcription, `grep` at HEAD **plus** `git show` at ancestors. calxgloss
  handles API keys for local endpoints and (P-series) cloud models; a
  `.gitignore`-from-day-one + pickaxe-in-CI habit (P42) is the whole lesson,
  since LLM_Decompiler shows the failure mode: one missing `.gitignore` line
  → the key is *committed twice* and survives its own deletion.
- **Case-only renames break web-UI workflows into merge scars**: if calxgloss
  ever cares about repo-external editing (docs, review-UI exports), git
  rename detection silently misses delete+recreate moves — worth one CI
  check that flags byte-identical D+A pairs (§4).
- **Never let a cleanup commit be the last word**: `c242671` deleted a file
  its own README depended on. calxgloss's review-UI + docs-drift posture
  should treat "commit touches file X while prose references X" as a
  lintable pattern — this repo is the existence proof, verbatim, in one line.
- **Web-UI identity fingerprinting** (noreply commits = web ops) is a cheap,
  reliable archaeology tool; useful whenever calxgloss dossiers review
  third-party repos.

## Sources

- Read-only clone `/tmp/opencode/LLM_Decompiler` @ `c242671…f00` — batteries
  captured to `/tmp/opencode/facts2/`: full chronology numstat (`num.txt`),
  name-status with `-M` rename detection (`ns-m.txt`), merge-graph +
  `cat-file` parentage of `ba1aa02`, `git shortlog`/`%ae` identity battery,
  `git log --all -S 'sk-'` pickaxe, per-blob `sk-` counts at `5b25d26`,
  `.env` blob extraction + sha256 equality (`620a651…`), `git show` diffs of
  `72c3c11`, `51a2c98`, `8eff39b`, `f6af70f`, `517710b`, `768f219`,
  md5 equality for the `select_from_cwe` and `process_juliet_suite` lineages,
  `rev-list --count`, `branch -a`.
- GitHub REST API via `gh api` (fetched 2026-10-31): metadata, releases,
  tags, pulls, branches, contributors — captured to
  `/tmp/opencode/facts2/web.txt`.
- Cross-chapter: inventory chapter §9 (negative-findings battery), §10–§11
  (hygiene + staleness), [10-calxgloss-baseline.md](10-calxgloss-baseline.md).

# LLM4Decompile history & release archaeology (219 commits, no tags)

> Part of the [LLM4Decompile overview](README.md). The full commit shape, who
> the six actual contributors are, what moved when (including the one and only
> git-detected rename: `decompile-eval/ → legacy-test/`), and the reconstructed
> release ladder V1 → V1.5 → V2 → 9B/22B → ghidra-100k → DCBench v1.6 →
> SK²Decompile → VERL/BringUpBench — reconstructed because the repo has
> **zero git tags and zero GitHub Releases**: every "release" is a Hugging Face
> model drop announced in a README bullet. All history claims verified in the
> clone at `/tmp/opencode/LLM4Decompile` (`git log`, `git show`,
> `git log --diff-filter`, `git shortlog -sne --all`); HF dates from the HF
> model API; GitHub metadata fetched 2026-10-31.

## 1. Commit shape and the six humans behind 219 commits

219 commits on a single `main`; oldest `6260410` "Initial commit"
(2024-02-28 11:16 +0800); newest `85b364b` "Merge pull request #73 from
BaiRiDreamer/main" (2026-02-12) — also HEAD and GitHub `pushed_at`
(2026-02-12T03:02:03Z). Only 5 merge commits exist, all PR merges (§7).
Dates are consistently +0800 (China-time authored).

`git shortlog -sne --all` (verified), with identity collapsing:

| Identity | Commits | Emails (commits) | Notes |
|---|---:|---|---|
| **albertan017** = Hanzhuo Tan (repo owner) | 168 | noreply (164), hanzhuo.tan@connect.polyu.hk (4) | ~77% of history |
| **Qi Luo** = rocky-lq | 43 | rocky_lq@icloud.com (30), noreply (13) | coauthor, most README/model edits |
| **7Sageer** = Hanrui Qi | 3 | 12210216@mail.sustech.edu.cn under two display names | SUSTech student, PRs #48/#50/#55 |
| **hanXen** | 3 | shl9798@naver.com | Docker PR #61 |
| **BaiRiDreamer** | 2 | 12110415@mail.sustech.edu.cn | PR #73 (the VERL/BringUpBench finale) |

Two orgs' emails recur (sustech.edu.cn students; PolyU for the owner) —
matching the paper author roster (Tan/Luo/Li/Zhang, SUSTech–PolyU line).

Commit-message style is drop-driven: 25 commits are literally "Add files via
upload" (GitHub web UI), big ones get one-word messages ("V1.5", "legacy",
"evaluation", "sk2decompile"). The only Conventional-Commit-style messages in
the entire history are BaiRiDreamer's two (`e33b3e7 feat(sk2decompile):
integrate VERL RL training pipeline…`, `239cba2 feat(sk2decompile): add
BringUpBench evaluation pipeline and results`) — the external contributor is
the only one writing engineering-style commits.

Monthly activity (`git log --date=format:%Y-%m | uniq -c`):

```
2024: 02:38  03:26  04:2  05:23  06:33  07:0  08:5  09:8  10:35  11:0  12:0
2025: 01–04:0 05:23 06:6  07:0   08:5   09:0  10:6  11:0  12:4
2026: 01:2    02:3
```

Two silence gaps define the line: **Nov 2024 – Apr 2025 entirely empty**
(last 2024 commit `72d403f` "Update youtube link" 2024-10-28, next commit
2025-05-21) and **Jul + Sep + Nov 2025 empty** around the 2025 model/paper
drops. After `85b364b` (2026-02-12) the repo has been idle for ~8.5 months.

## 2. Phase 1 — the EMNLP paper repo (Feb–Mar 2024, 64 commits)

- `6260410` Initial commit, 2024-02-28: README, MIT `LICENSE`, and
  `data/decompile-eval.json`. The "between 1.3 billion and 33 billion
  parameters" line is *not* in the initial README (`git show 6260410:README.md
  | grep -c "33 billion"` → 0); it arrives later the same day in `3a5326b`
  "Update README.md". The 33 B claim
  predates any 33 B model ever existing; it was never removed at the root
  level (still at `README.md:66` at HEAD, §9 of the
  [inventory](20-llm4decompile-inventory.md)).
- Eval tooling landed within 24 h: `a3ebf92` (2024-02-28, Qi Luo) TGI script
  lineage → today's `evaluation/` + `scripts/`.
- **The dataset dir shuffled three times in month one** (full lineage, §3):
  `data/` deleted `77b7aeb` (2024-02-29) → `decompiler-eval/` created
  `4b3a8d3`+`f4d5e9c` (2024-02-29) → renamed to `decompile-eval/` `7e9c413`
  "fix evaluation path issue" with `4a90466` "delete old evaluation dataset"
  the same day (2024-03-25).
- `8ca101c` 2024-03-16 adds the `llm4decompile-6.7b-uo` README bullet — HF
  `arise-sustech/llm4decompile-6.7b-uo` created 2024-03-16 (verified via HF
  API). This "unrestricted optimization" model lives under a **third org**
  (`arise-sustech`), never under `LLM4Binary`; it was the top performer
  (avg re-executability ≈0.219) and quietly lost its table row in `ab29592`
  (2024-10-25).
- `LICENSE-MODEL` added `701d433` 2024-03-20 — the day the DeepSeek base-model
  weights became a licensing concern (see §5 ladder: V1 models are DeepSeek
  fine-tunes and are **gated on HF** — API returns 401 for `llm4decompile-
  {1.3b,6.7b}-v1`).
- `5733b6b` 2024-03-18 adds `train/compile.py` — first training-adjacent
  script.

## 3. The one real rename, and the four-life lineage of the eval set

`git log --all -M --diff-filter=R` returns exactly **one rename commit**:
`757b7a2` "legacy" (2025-05-21) — four R100 (pure content-identical) moves:

```
decompile-eval/{README.md, decompile-eval.json,
  decompile-eval-executable-gcc-obj.json, decompile-eval-executable-gcc-ghidra.json}
  → legacy-test/…
```

Everything else in this repo's history was done as delete + add (the web-UI
workflow), which is why the dataset's full lineage has to be stitched across
D/A pairs:

| Generation | Files | Created | Ended |
|---|---|---|---|
| G0 `data/decompile-eval.json` | initial commit | `6260410` 2024-02-28 | deleted `77b7aeb` 2024-02-29 |
| G1 `decompiler-eval/` | README + json (4,594 lines) | `f4d5e9c`+`4b3a8d3` 2024-02-29 | deleted `4a90466` 2024-03-25 |
| G2 `decompile-eval/` | same json, renamed dir | `7e9c413` 2024-03-25 | → `legacy-test/` via `757b7a2` 2025-05-21 |
| G2+ data | `…-gcc-obj.json` (+4,594 L) | `f17d7e1` 2024-05-16 (V1.5 executable era) | alive at HEAD |
| G2+ data | `…-gcc-ghidra.json` (+4,594 L) | `9730d26` 2024-06-19 (V2/Ghidra era) | alive at HEAD |

The V1/V1.5/V2 input modality for each model generation is visible in *when
each eval variant was added* (objdump for paper-era, gcc-obj for V1.5, gcc-
ghidra for V2) — the eval corpus grew a new front-end per architecture change.

Image churn is all delete-style: `samples/logo.png` deleted `a1c2173`
(2024-10-21); `results_paper.png` deleted `6f0b610`, `results_refine.png`
added `155c018` then deleted `522d6d5` (2024-10-25); `results_v1.5.png` added
`56ff846`/`ff24263` (2024-05-11). `git log --diff-filter=D` shows no deleted
Python beyond the `evaluation/metrics|utils` curation (2024-05's README-era
"multi-gpu" helper scripts were **never tracked** — `git log --all --name-only
-- evaluation/` lists only HEAD's five files; §8).

## 4. Phase 2 — V1.5 → V2 → training (May–Oct 2024, 104 commits)

- **V1.5 (announced 2024-05-13, `README.md:31`)**: HF `llm4decompile-
  {1.3b,6.7b}-v1.5` created **2024-05-10**; repo drop is *pure docs*:
  `ea918cf` "V1.5" 2024-05-11 changes only README.md (+18/−13); figures via
  `56ff846`/`ff24263` same day; the executable-obj eval JSON follows 2024-05-16
  (`f17d7e1`). **No V1.5 training code was ever committed** — the 15B-token
  dataset lives on HF only.
- **V2 Ref (announced 2024-06-19, `README.md:30`)**: HF `llm4decompile-6.7b-v2`
  created **2024-06-18** (one day *before* the announcement); same-day repo
  drop `6141703` (`ghidra/README.md`), `c723ac6` (`ghidra/decompile.py`),
  `7cfe7bd` (`ghidra/demo.py`), `9730d26` (ghidra eval JSON). 22B row added by
  Qi Luo in `1779360` 2024-06-25; HF `llm4decompile-22b-v2` created 2024-06-23.
- **Training stack #1**: `c18472e` "init colossal training script."
  2024-06-27 (+1,595 L, 14 files) = `train/colossalai_llm4decompile/`.
  **Never touched after 2024-06-27** — a fossil now superseded by the
  LLaMA-Factory example that heads `train/README.md:1`.
- Quiet Aug (5 commits, all README — Qi Luo's `f552c23` 2024-08-07 closes the
  silent month; his next commit is the `f525784` colab demo on 2024-09-21).
- **Colab demo**: `f525784` 2024-09-21 "add colab demo" (announced
  `README.md:28`).
- **9B-v2 (announced 2024-09-23, `README.md:29`)** — the only model in the
  ladder **not based on DeepSeek**: fine-tuned from `01-ai/Yi-Coder-9B`;
  HF created 2024-09-23T01:01Z, repo row `0fbf9f1` hours later. Its 64.9% is
  still the repo's headline number.
- **ghidra-100k replication kit (2024-10-17, `README.md:27`)**: `52871dd` adds
  `train/finetune.py` (225 L) + `train/configs/ds_config_zero3.json` +
  `train/requirements.txt` (+275 L); bullets `8129a08`/`f540bfc` same day by
  Qi Luo. This is the "3.5 h on one A100, under $20, 0.26 re-executability"
  story — i.e. the repo ships a *cheapest-replication path*, not the original
  training recipe.
- October cleanup (`README.md:32` row removal for -uo in `ab29592`; image
  deletions, §3) then **`72d403f` 2024-10-28 — then seven months of silence**.

## 5. Phase 3 — Decompile-Bench and the community PRs (2025-05 → 2025-08)

The May-2025 burst is exactly **one day** of owner activity plus later PR
merges:

- **2025-05-21** (14 commits): `757b7a2` legacy rename (§3) + the
  `decompile-bench/` folder lands in five commits — `9eb2fdc` readme,
  `1354ed4`/`156dea6` `decompile-bench/metrics/` (`cal_execute_rate.py`, `cal_edit_sim.py`),
  `e6551ae` `decompile-bench/run_exe_rate.py`, `61265b5` humaneval JSON, `15c3a07` mbpp JSON
  (+~96 MB). HF `llm4decompile-1.3b-v1.6` created **2025-05-21T08:49Z the
  same day**. The README bullet is dated 2025-05-20 (`README.md:26`) — the HF
  collection and model were dropped before the repo folder existed.
  **v1.6/DCBench has no training or inference code anywhere in the repo** —
  it appears only as a row in `decompile-bench/readme.md:66` (20.89%) and a
  run_exe_rate example. Note the same checkpoint family scores *differently*
  across the two tables: 1.3b-v1.5 = 27.3% root (`README.md:70`) vs 16.22%
  DCBench (`decompile-bench/readme.md:65`) — the DCBench-day re-score was
  never propagated back to the root README.
- **PR #48** (merged `717032a` 2025-05-29): 7Sageer/Hanrui Qi adds
  `train/llama_factory_llm4decompile/` example (`e30c73c`).
- **PR #50** (merged `36a2d57` 2025-06-12): `4c38c50` "fix: add missing
  training script" — the example PR had shipped `train/run_training.sh` nowhere;
  this adds it (+71 L). A contributor fixing his own contribution two weeks
  later: the PR-review layer of this repo is one student deep.
- **PR #55** (merged `e0f3f65` 2025-06-30): same author, requirements/data
  follow-up for the LLaMA-Factory example.
- **PR #61** (merged `3eee369` 2025-08-22): hanXen (`shl9798@naver.com`) adds
  `7ed839a` Dockerfile (2025-08-20), then `473973c`/`4001fbd` pin pytorch
  2.7.1/cuda12.8 and the demo requirements → `requirements-docker.txt`.
  Owner-side `cf685cd` same day.

## 6. Phase 4 — SK²Decompile: paper-first, repo-second (2025-10 → 2026-02)

The SK² line (arXiv:2509.22114, Sep 2025) inverts the usual order — the
models and paper exist before any repo artifact:

| Date | Event (verified) |
|---|---|
| 2025-10-02 | HF `LLM4Binary/sk2decompile-{struct,ident}-6.7b` created (HF API) |
| 2025-10-03 | community GGUF conversions appear (incl. one named after the README's later-corrected `-6.7`) |
| 2025-10-04 | `766f3ec` — announcement is literally **1 added line** in root README (bullet, now `README.md:25`) |
| 2025-10-08 | `357705d` "sk2decompile": 19 files **+62,422 L** — Preprocess, LLaMA-Factory configs+data, evaluation suite (incl. the stray Haskell `sk2decompile/evaluation/stack.yaml`), normsrcpseudo data (30 MB), `verl/…/sk2decompile-rl-examples.jsonl`, and the SK² README — whose bibtex literally read `author={Your Name and Collaborators}`, `arXiv:XXXX.XXXXX` |
| 2025-10-16 | `b82f0e5`+`71b120a`: inference arrives late — `sk2decompile/evaluation/llm_server.py`,
  `sk2decompile/evaluation/normalize_pseudo.py` (+212 L), `sk2decompile/evaluation/sk2decompile_inf.py` (+179 L).
  The usage instructions written on 2025-10-08 reference `normalize_pseudo.py` under `Preprocess/` **before the file existed anywhere in the repo** — and it still lives in `evaluation/`, not `Preprocess/` (broken instruction `sk2decompile/README.md:77,83`) |
| 2025-12-05 | README refactor quartet: `86857f4` install/usage, `061b8e8`, `f5a6f43` headings, `2169186` **fixes the placeholder bibtex** — 58 days late: real authors (Tan, Weihao Li, Xiaolong Tian, Siyi Wang, Jiaming Liu, Jing Li, Yuqun Zhang) + real arXiv id |
| 2026-01-25 | `1c164e2` "fix model name error" `sk2decompile-ident-6.7 → -6.7b` — but only inside `sk2decompile/README.md:159,172,174`; the root `README.md:25` and sk2 `README.md:17` keep the wrong id to this day. `410e3d1` adds detailed usage instructions (+28 L) |

- **PR #64** (BaiRiDreamer, "add initial sk2decompile framework") was **closed
  unmerged** — then the same author lands PR #73: `e33b3e7` 2026-02-11 (+995 L:
  `verl/SK2DECOMPILE/reward_functions/` ×5 + `run_{struct,ident}_rl.sh` +
  README with the Eq.3/Eq.4 reward formulations and VERL v0.4.1 pin) and
  `239cba2` 2026-02-12 (+6,313 L: the entire BringUpBench pipeline, 1,822-entry
  func maps, 1,488-entry infer results, four `reports/O*_results.md`).
  Merged as `85b364b` = HEAD.
- **The results predate the pipeline**: every report file embeds
  `Timestamp: 20251119-17…` (`sk2decompile/evaluation/bringupbench/reports/O0_results.md:3`) — i.e.
  ~3 months **before** the VERL training code that produces the scored
  `infer-out-model2` results (`e33b3e7`, 2026-02-11) and ~5 months before the
  commit that checked them in. The repo ships *evidence from private runs*
  whose generating code landed later; the `sk2decompile-ident-6.7b` HF repos
  were themselves modified 2026-01-25 (HF API), after those runs.

## 7. PR & issue ledger (GitHub API, fetched 2026-10-31)

13 PRs ever; **5 merged** (all listed above: #48, #50, #55, #61, #73);
4 closed-unmerged (#64, #78, #17, #7); 4 open and stale (#79, #76, #60, #25).
`open_issues_count` 47 = 43 issues + 4 open PRs. The owner merges fast
(days) and reviews lightly — #73 (+7.3 K lines incl. multi-MB JSONL) went in
without incident. External contributions cluster in two windows: mid-2025
(training + Docker, SUSTech/outsider) and Feb 2026 (the SK² RL/eval tail).

## 8. The release ladder — what each drop is and what shipped with it

| Generation | Announced (README) | HF id (`LLM4Binary/` unless noted) | HF created | Base model | Code shipped at drop |
|---|---|---|---|---|---|
| V1 End | (no bullet left post-refactor) | `llm4decompile-{1.3b,6.7b}-v1` | early 2024, **gated (401)** | deepseek-coder 1.3b/6.7b-base | eval harness only (`a3ebf92`) |
| -uo (side branch) | 2024-03-16 `README.md:32` | `arise-sustech/llm4decompile-6.7b-uo` | 2024-03-16 | deepseek-coder-6.7b-base | none |
| V1.5 End | 2024-05-13 `README.md:31` | `llm4decompile-{1.3b,6.7b}-v1.5` | 2024-05-10 | deepseek-coder-base | README+figures (`ea918cf`), new eval JSON 05-16 |
| V2 Ref | 2024-06-19 `README.md:30` | `llm4decompile-6.7b-v2` (+1.3b) | 2024-06-18 | deepseek-coder-6.7b-base | `ghidra/` trio + ghidra eval JSON |
| 22B-V2 | 2024-06-25 (row `1779360`) | `llm4decompile-22b-v2` | 2024-06-23 | (undeclared in repo) | none |
| 9B-V2 | 2024-09-23 `README.md:29` | `llm4decompile-9b-v2` | 2024-09-23 | **Yi-Coder-9B** | none (row only) |
| ghidra-100k kit | 2024-10-17 `README.md:27` | dataset `LLM4Binary/decompile-ghidra-100k` | 2024-10 | — | `train/finetune.py` stack |
| DCBench v1.6 | 2025-05-20 `README.md:26` | `llm4decompile-1.3b-v1.6` | 2025-05-21 | base never declared; "trained on 10% of Decompile-Bench" (`decompile-bench/readme.md:14`) | `decompile-bench/` eval folder; no training code |
| SK² struct+ident | 2025-10-04 `README.md:25` | `sk2decompile-{struct,ident}-6.7b` | 2025-10-02 (2 days *before* the announcement) | base not declared in repo (DeepSeek-Coder per the paper) | README bullet only; code 4 days later |
| SK² RL/eval tail | (PR, no bullet) | — (HF weights re-touched 2026-01-25) | — | — | VERL rewards + BringUpBench (`e33b3e7`/`239cba2`) |

Reading the ladder as data: **model drops almost never ship code** (22B, 9B,
v1.6, SK² announcement = README edits); **code drops track papers, not models**
(the two big code landings, `357705d` and `239cba2`, are the two papers);
training recipes for the *shipped* flagship models (15B-token V1.5, DCBench
2M-pair v1.6) were never committed at all.

## 9. Maintenance status & what it means

Last substantive commit `85b364b` (2026-02-12); stars 7,195 / forks 567 /
watchers 82 at 2026-10-31; 43 open issues; a wave of community forks keeping
GGUF mirrors current (HF search shows `mradermacher/*-GGUF` updated into
2026-10). The repo's operating model — README-bullet versioning, HF-side
weights, checked-in results rather than reproducible pipelines — means the
git record *is* the release record and simultaneously its least reliable
part: scores contradict each other (§5), timestamps predate their code (§6),
and the newest 7 K lines are someone else's experiment export merged whole.

## Steal ideas for calxgloss

- **Score provenance discipline**: two tables, one checkpoint, 27.3% vs
  16.22% with no reconciliation note (`README.md:70` vs
  `decompile-bench/readme.md:65`). calxgloss's future P33 scoreboard must pin
  (harness, corpus, scenario-set, date) per number or it will rot the same way.
- **"Checked-in evidence from private runs" is a trap**: BringUpBench reports
  timestamped 2025-11-19 shipped 2026-02-12 against code that landed later.
  calxgloss's verdict artifacts (compile/run traces) should carry the harness
  build hash inline — an artifact's timestamp must be inside the artifact,
  not in git.
- **The README bullet pattern is cheap and effective** for a
  model-card-less, package-less project — calxgloss P42-adjacent docs could
  borrow the dated-updates ledger, *provided* links are machine-checked
  (LLM4Decompile's 5 dead `decompile-eval/` refs are the counterexample).
- **Community PR pattern to expect**: the strongest late-stage content (Docker,
  RL, BringUpBench) came from exactly two external contributors whose emails
  mark them as students — calxgloss's harness docs should assume drive-by
  contributors and make the contribution surface (entry points, scenario
  format) self-explanatory.
- **Gated weights, ungated repo**: MIT code + DeepSeek-licensed *weights*
  (PRC law, no-military clause) is why V1 models are 401 on HF. calxgloss
  never trains, so it inherits none of this — a comparison point for
  40-comparison.md's licensing axis, not a steal.

## Sources

- Clone `/tmp/opencode/LLM4Decompile` @ `85b364b`: `git log --format=…`
  (all 219 commits, oldest-first listing with authors/dates),
  `git shortlog -sne --all`, `git log --merges`, `git log --diff-filter=A/D/R`
  (`-M`), `git log -S "33 billion"`, `git log -S "llm4decompile-6.7b-uo"`,
  `git show --stat {6260410, a3ebf92, 77b7aeb, 4b3a8d3, f4d5e9c, 7e9c413,
  4a90466, 701d433, 8ca101c, 5733b6b, ea918cf, 56ff846, ff24263, f17d7e1,
  6141703, c723ac6, 7cfe7bd, 9730d26, 1779360, c18472e, 54a1764, f552c23,
  f525784, 0fbf9f1, 52871dd, 8129a08, f540bfc, a1c2173, 6f0b610, 155c018,
  522d6d5, ab29592, 72d403f, 757b7a2, 0a5aafc, 02f240f, 9eb2fdc, 1354ed4,
  156dea6, e6551ae, 61265b5, 15c3a07, e30c73c, 4c38c50, 7ed839a, 473973c,
  4001fbd, cf685cd, 766f3ec, 357705d, b82f0e5, 71b120a, 86857f4, 061b8e8,
  f5a6f43, 2169186, 1c164e2, 410e3d1, e33b3e7, 239cba2}`, monthly commit
  histogram, report timestamps in `bringupbench/reports/O*_results.md`.
- `https://api.github.com/repos/albertan017/LLM4Decompile` + `/releases`
  (`[]`), `/tags` (`[]`), `/pulls?state=all` (13 PRs; merged set
  #48/#50/#55/#61/#73), issues search (43 open) — fetched 2026-10-31.
- `https://huggingface.co/api/models/LLM4Binary/…` and
  `…/arise-sustech/llm4decompile-6.7b-uo`, `?search=sk2decompile` — creation
 /modification dates quoted in §2, §4–§6 and the inventory §10; gated V1
  repos verified by 401 responses.
- arXiv: `https://arxiv.org/abs/2403.05286` (V1 paper),
  `https://arxiv.org/abs/2509.22114` (SK² paper, per corrected bibtex in
  `sk2decompile/README.md` after `2169186`).

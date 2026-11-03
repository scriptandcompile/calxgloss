# ReverserAI history & release archaeology (25 commits, v1.0 → v1.2)

> Part of the [ReverserAI overview](README.md). Every commit in the public
> history, tag-by-tag diff archaeology (what was added, changed, and broken at
> each boundary), the model/agent question, and the 2023 research-era gap in
> the git record. All claims verified in the clone at `/tmp/opencode/reverser_ai`
> via `git show`/`git diff <tag>`/`git grep $(git rev-list --all)`; release
> metadata from the GitHub API.

## 1. Complete commit table (`git log --format=…`, oldest first)

25 commits on `main`, no other branches (`git branch -a`: only `main`); tags
v1.0/v1.0.1/v1.1/v1.2 are all **lightweight** (verified: `git cat-file -t`
returns `commit` for each).

| # | SHA | Date | Author | Message |
|---|---|---|---|---|
| 1 | `cfa9908` | 2024-03-17 | Tim Blazytko | initial release **← tag v1.0** |
| 2 | `d7f098a` | 2024-03-19 | Tim Blazytko | Fix API names in config, documentation and screenshots (#1) **← tag v1.0.1** |
| 3 | `ccae97b` | 2024-03-19 | Tim Blazytko | added new version release string |
| 4 | `d488e82` | 2024-03-20 | Tim Blazytko | renaming all functions: fix algorithm to propagate information from leaves to roots |
| 5 | `aeb265c` | 2024-03-20 | Tim Blazytko | Do not silently fail in case of too long code inputs; catch error about too much tokens |
| 6 | `c318f28` | 2024-03-21 | Tim Blazytko | added more powerful model to model file -- not yet configurable |
| 7 | `2ec64bb` | 2024-03-21 | Tim Blazytko | added documentation to filter/normalization function |
| 8 | `16bde89` | 2024-03-21 | Tim Blazytko | refactored bottom-up traversal |
| 9 | `eb940ea` | 2024-03-21 | Tim Blazytko | added feature: context-enriched function naming |
| 10 | `4d94939` | 2024-03-22 | Tim Blazytko | fix traverse_functions_bottom_up |
| 11 | `5597fb7` | 2024-03-24 | Tim Blazytko | added model selection |
| 12 | `845626f` | 2024-03-27 | Tim Blazytko | added typer requirement |
| 13 | `950386c` | 2024-03-27 | Tim Blazytko | smaller cleanups in README |
| 14 | `84b1a3e` | 2024-04-04 | Lays | Fix incorrect parameter passing (#5) |
| 15 | `cf8e449` | 2024-06-20 | Tim Blazytko | fix: gpt is only queried if HLIL output exists |
| 16 | `c7c681a` | 2024-06-20 | Tim Blazytko | fixed typo in logger |
| 17 | `7b3ecd8` | 2024-06-20 | Tim Blazytko | changed version string to 1.1 |
| 18 | `456bc1e` | 2024-06-20 | Tim Blazytko | fixed documentation of model size: 25 gb instead of 45 gb |
| 19 | `af29a1d` | 2024-06-20 | Tim Blazytko | fix comment |
| 20 | `09d4e00` | 2024-06-21 | Tim Blazytko | fix description of use_mmap |
| 21 | `4bf725f` | 2024-06-21 | Tim Blazytko | extended readme |
| 22 | `c6b1fd4` | 2024-06-21 | Tim Blazytko | replaced settings screensho |
| 23 | `d7b6700` | 2024-06-21 | Tim Blazytko | Merge pull request #6 from mrphrazer/improvements **← tag v1.1** |
| 24 | `b4b4cc2` | 2026-05-20 | Tim Blazytko | added ci quality gates |
| 25 | `1d572da` | 2026-05-20 | Tim Blazytko | Release ReverserAI v1.2 with dependency install fixes **← tag v1.2** |

Contributors (`git shortlog -sne --all`): Tim Blazytko 24 commits (22 as
`tim@blazytko.to`, 2 as `mrphrazer@users.noreply.github.com`), Lays
(`<l4ys.tw@gmail.com>`) 1 commit. The "(#1)"/"(#6)" merges are the author's
own branches; only #5 is an outside contribution.

## 2. Tag-by-tag archaeology

Diff stats (verified): `git diff --stat v1.0 v1.1` → 16 files, +420/−145;
`git diff --stat v1.1 v1.2` → 15 files, +133/−76. **No source file is added or
removed at any tag boundary except `v1.0.1 → v1.2`, which adds
`.github/workflows/ci.yml`** (the four tag trees are otherwise the same 24
paths; `git ls-tree -r --name-only <tag>`).

### 2.1 v1.0 = `cfa9908` "initial release" (2024-03-17) — the squashed start

GitHub reports the repo `created_at` **2024-03-17T07:14:56Z**
([api.github.com/repos/mrphrazer/reverser_ai](https://api.github.com/repos/mrphrazer/reverser_ai)),
the same day and minute range as the first commit — **the public history
begins fully squashed**: everything before commit 1 (the entire 2023 research
era) lives outside this git repo; no branch, stash, or earlier object exists
in the clone. There is no ancestor history to mine.

What v1.0 already contained (all via `git show v1.0:<path>`): the full
3-layer architecture of today (BN plugin + `gpt/` + `binary_ninja/`), a
generic `LLM_Agent` (`v1.0:reverser_ai/gpt/agent.py` — hf_hub_download +
`Llama` init + raw-completion `generate_response`), the `FunctionNameGPT`
naming class with the **identical one-shot Mistral prompt** used at HEAD
(`v1.0:reverser_ai/gpt/function_name_gpt.py`), the `model_download.py` +
`gpt_function_namer.py` scripts, `example_config.toml`, `imgs/`, and
`examples/samples.zip` (zip entry timestamp 2024-03-16 21:20, per
`unzip -l`). Differences from HEAD at v1.0:

- The plugin called itself **ReverseAI** — commands `ReverseAI\…`, settings
  group `reverse_ai`, keys `reverse_ai.*` (`v1.0:__init__.py:8-71`).
- Exactly **2 model entries**: `mythomax_13b` + `mistral-7b-instruct`
  (`v1.0:reverser_ai/gpt/models.py`); model fixed in code:
  `config['model_identifier'] = MODEL_IDENTIFIERS["mistral-7b-instruct"]`
  (`v1.0:reverser_ai/gpt/function_name_gpt.py` — overrides any user config).
- Bulk rename iterated `sorted(bv.functions, key=lambda f: len(f.callees))`
  — a callee-count heuristic, not a traversal
  (`v1.0:reverser_ai/binary_ninja/__init__.py`).
- Errors were **silently swallowed**: bare `except: return original_name`
  in `get_function_name_suggestion(original_name, code)`; results printed
  with `print()`, not BN logging (`v1.0:reverser_ai/gpt/function_name_gpt.py`,
  `v1.0:reverser_ai/binary_ninja/function_name_gpt_wrapper.py`).
- `requirements.txt`: 3 deps (toml, huggingface_hub, llama-cpp-python), no
  trailing newline (`v1.0:requirements.txt`); `plugin.json` additionally had
  `"dependencies": {"pip": ["toml","huggingface_hub","llama-cpp-python"]}`
  (`v1.0:plugin.json`). Version strings 1.0 everywhere.
- No CI, no tests, no model-selection setting.

**Relation to the 2023 research era (verified negative results):** the repo
cites *no paper anywhere* — grep for `arxiv`/`paper` across all `.md`/`.py`
/`.toml`/`.json` at HEAD returns zero hits; README only says the project
"represents a culmination of research" (`README.md:18`) and `examples/README.md:19`
links the author's blog post dated 2023-08-02
(`https://synthesis.to/2023/08/02/api_functions.html`) — that blog link is the
*only* 2023-era artifact referenced inside the repo. Note for downstream
files: the scope file's claim that ReverserAI is the companion code of
*"REverserAI: Explainable Auto-symbolication…"* (**arXiv:2304.02000**,
`00-scope-and-method.md:13-16`) **failed verification**: arXiv:2304.02000
resolves to a pure-math paper ("Tensor product of holomorphic discrete series
representations of U(p,q) and quivers", Baldoni & Vergne, 2023-04-04, via
`http://export.arxiv.org/api/query?id_list=2304.02000`), and arXiv full-text
searches for `"ReverserAI"` and `"auto-symbolication"/"autosymbolication"`
return **0 entries**. Whether such a paper/manuscript exists under a
different identifier could not be confirmed from any of the fetched sources;
treat the paper lineage in `00-scope-and-method.md` as unverified.

### 2.2 v1.0.1 = `d7f098a` (+`ccae97b`), 2024-03-19 — rename-only patch

Nothing functional: the entire v1.0→v1.0.1 delta is
- `d7f098a` "Fix API names… (#1)": `ReverseAI\…`→`ReverserAI\…` commands,
  settings group `reverse_ai`→`reverser_ai` and all 5 keys in `__init__.py`
  and in the wrapper's `read_config`, plus replaced screenshots
  (`plugin_menu.png`, `plugin_settings.png`) — verified hunk-by-hunk in
  `git show d7f098a`;
- **removal** of the `plugin.json` `"dependencies": {"pip": [...]}` block
  (7 lines, same commit) — dependency installation moved entirely to
  README instructions;
- `ccae97b`: version strings 1.0 → 1.0.1 in README/plugin.json/setup.py.

Release v1.0.1 body (GitHub API): "changed `reverse_ai` to `reverser_ai` in
settings, readme and screenshots". Published 2024-03-18T23:08:36Z.

### 2.3 v1.0.1 → v1.1 = `d7b6700` (merge of `improvements`), 2024-06-21 — the feature window

13 commits, 2024-03-19 → 2024-06-21. Release notes (GitHub API body): "added
a more powerful model · added feature for context-aware function renaming ·
added documentation · various smaller bug and documentation fixes". The
substance per commit:

- **`d488e82` — propagation algorithm.** Replaces the v1.0
  `sorted(key=len(f.callees))` heuristic with an inline worklist that
  renames a function only once all its callees are done ("propagate
  contextual information … from leaves to roots"). Design decision:
  the LLM prompt input is current HLIL, so renaming callees first feeds
  learned names into caller queries.
- **`aeb265c` — error visibility.** `get_function_name_suggestion(code)`
  loses the `original_name` fallback parameter; failures now `raise
  ValueError("…may exceed the maximum token limit…")`, caught in
  `apply_suggestion` and logged via `log_info/log_warn(logger=…)` instead of
  bare `print()` or silent fallback. (This commit itself introduced a typo —
  it changed the demo call to the string literal
  `gpt.get_function_name_suggestion("c_function_code")` — fixed two weeks
  later by outside PR `84b1a3e`, "Fix incorrect parameter passing (#5)".)
- **`c318f28` — Mixtral.** Adds the `mixtral-8x7b-instruct` GGUF entry to
  `models.py` ("not yet configurable").
- **`16bde89` → `4d94939` — traversal rewrite saga.** Bottom-up traversal
  moves into `binary_ninja/utils.py` as a hand-rolled worklist whose own
  docstring admits a bug ("triggers an endless loop because of inproper
  handling of re-adding function callers again", `16bde89`); for a window
  (commits `eb940ea`→`4d94939`) bulk renaming shipped with traversal
  **disabled** and a TODO comment plus a broken line
  `for f in bv.functions(bv):`. `4d94939` settles it by delegating to
  **networkx**: `nx.DiGraph` + `nx.dfs_postorder_nodes`
  (`4d94939:reverser_ai/binary_ninja/utils.py`, still the HEAD form at
  `reverser_ai/binary_ninja/utils.py:29-58`) and adds `networkx>=3.2.1` to
  requirements.
- **`eb940ea` — the one real feature: context-enriched function naming.**
  Adds the third plugin command (`Enhance Function Naming with Context`),
  `collect_symbol_related_functions` + `collect_string_related_functions`
  (preselect functions referencing imports/library/external symbols and
  strings), 212 insertions. **This did *not* add the agent**:
  `reverser_ai/gpt/agent.py` exists since v1.0 (`git log --follow` →
  `cfa9908`); the "generic agent" is part of the initial squashed release.
- **`5597fb7` — model selection.** User-facing `model_identifier` setting
  (enum), `example_config.toml` key, wrapper reads it, `agent.py` resolves
  `MODEL_IDENTIFIERS[config['model_identifier']]`, and the hard-coded
  mistral override in `function_name_gpt.py` is deleted.
- **`845626f` — adds `typer>=0.11` to requirements**; no code in any
  subsequent commit ever imports typer (dead at v1.1 and at HEAD).
- **`cf8e449` — the HLIL guard *shipped inverted*.** Intent per message:
  "gpt is only queried if HLIL output exists", but the added guard is
  `if f.hlil_if_available != None: continue` (`git show cf8e449`) — i.e.
  skip functions **that have** HLIL. At v1.1 both bulk workflows carry the
  inverted guard (`v1.1:reverser_ai/binary_ninja/__init__.py:138,172`):
  functions with decompiler output were skipped, functions *without* HLIL
  were queried, and their prompt build (`get_hlil_output` accessing
  `f.hlil.root.lines`, `v1.1:reverser_ai/binary_ninja/function_name_gpt_wrapper.py:64-66`)
  then failed into the `ValueError`/`log_warn` path from `aeb265c`. Net
  effect: **v1.1's "Rename All Functions"/"Enhance … with Context" could not
  apply any rename**; v1.0 (no guard) worked, v1.1 regressed, v1.2 fixed it
  (§2.4). The commit message is the only hint the bug exists.
- **`456bc1e` — 45 GB → 25 GB** for mixtral RAM claims in README, settings
  description, example_config.toml and models.py comment: shows the docs
  were written from a wrong model-size assumption (the Q4_K_M GGUF of
  Mixtral-8x7B is ~25 GB, not 45) and users may have been told to budget
  nearly 2× the RAM.
- **`c7c681a`** logger name typo `ReverseAI`→`ReverserAI` (the name shipped
  wrong from `aeb265c` through v1.0.1). **`7b3ecd8`** version strings →
  1.1. **Docs/UX**: `950386c`, `09d4e00` (use_mmap description corrected),
  `4bf725f` README extended (static-analysis + model-size sections),
  `2ec64bb`, `af29a1d`, `c6b1fd4` (screenshot; message typo "screensho").
- **`d7b6700`** merge commit — tagged v1.1; release published
  2024-06-21T03:57:00Z.

Net file-level additions across the boundary (from `git diff v1.0 v1.1`):
new functions `traverse_functions_bottom_up`, `collect_symbol_related_functions`,
`collect_string_related_functions` (`reverser_ai/binary_ninja/utils.py`
+111); new 3rd plugin command + `model_identifier` setting (`__init__.py`);
mixtral model entry; requirements +networkx +typer; README "Static Analysis"
and model-comparison sections. Removals: the `sorted(len(callees))` loop,
the silent name-fallback path, the hard-coded model pin.

### 2.4 v1.1 → v1.2 = `1d572da`, 2026-05-20 — 23-month gap, then CI + install fixes

Zero commits between 2024-06-21 and 2026-05-20. Two commits land the same
day, and **neither adds functionality**:

- **`b4b4cc2` "added ci quality gates"** — adds `.github/workflows/ci.yml`
  (43 lines: ruff format check, ruff lint, setup.py metadata check, AST
  syntax check on py3.11 — see [inventory §3](20-reverser-ai-inventory.md))
  and *therefore* reformats every source file (`ruff format`) with logic-
  preserving rewrites only (123 insert / 72 delete across 11 files). One
  rewrite is notable: `!= None` → `is not None` — **still the inverted
  guard**, now ruff-clean.
- **`1d572da` "Release ReverserAI v1.2 with dependency install fixes"** —
  the actual fixes (full diff verified):
  1. `requirements.txt: huggingface_hub>=0.21.4` →
     `huggingface-hub>=0.21.4` (the underscore spelling is not the real PyPI
     name; v1.1's `pip install -r requirements.txt`/`pip install .` failed
     on that line);
  2. `setup.py`: parse requirements.txt into `install_requires` (v1.1's
     package declared **no dependencies at all**) and version bump;
  3. version strings → 1.2 (README title `# ReverserAI (v1.2)`,
     `plugin.json:27`, `setup.py:13`);
  4. the latent bug fix: `is not None: continue` → `is None: continue` in
     both bulk workflows — the corrected HLIL guard at
     `reverser_ai/binary_ninja/__init__.py:141,177`.

Release v1.2 body (GitHub API): "added dependency fixes" (published
2026-05-20T11:24:36Z). So the ~2-year gap ended with a release whose only
substantive content is packaging repair plus the repair of a bug that had
silently disabled bulk renaming in v1.1.

## 3. Models shipped per release — fine-tuned vs off-the-shelf

Exhaustive `git grep` over **every commit ever**
(`git grep -il <term> $(git rev-list --all)`):

| Term | Hits across all 25 commits |
|---|---|
| `CodeGen`, `codegen`, `tinyllama`/`TinyLlama`, `ReverserAI-` | **0** — no fine-tuned/custom model ever appears in the repo |
| `gguf` | only `README.md` + `reverser_ai/gpt/models.py`: TheBloke GGUF filenames |
| `mistral`, `mixtral`, `mythomax` | `models.py` (all revs) + config/docs |
| `model_download` | `README.md` + `scripts/model_download.py` only |

- **v1.0**: `mistral-7b-instruct` (Mistral-7B-Instruct-v0.2 GGUF Q4_K_M,
  default, hard-pinned) + `mythomax_13b` (MythoMax-L2-Kimiko-v2-13B GGUF
  Q6_K — uncensored roleplay model, selectable in code only).
- **v1.1**: + `mixtral-8x7b-instruct` (Mixtral-8x7B-Instruct-v0.1 GGUF
  Q4_K_M, ~25 GB per corrected docs), user-selectable from
  mistral/mixtral (mythomax stays off-UI; still so at HEAD
  `reverser_ai/gpt/models.py:17-20`, `__init__.py:111-114`).
- **v1.2**: identical model catalogue; no model-related change.

Every version ever shipped uses **off-the-shelf instruction models via
llama.cpp GGUF from HF Hub** (`TheBloke/*` repos;
`reverser_ai/gpt/models.py:29-45`). Fine-tuning never happened *in this
repo*: it is listed as future work (`README.md:156`, "Fine-tuning existing
models or developing specialized models"). Cross-checks (2026-10-31):
HF model search `q=ReverserAI` → **0 models**
(`https://huggingface.co/api/models?search=ReverserAI`); no model matching
"function renaming" in the checked searches. So any fine-tuned
Code-Gen/TinyLlama artifacts attributed to the 2023 research phase
(`00-scope-and-method.md:34-38`) are **outside the public repository and
were not findable via its history, HF search, or arXiv search** in this
pass.

## 4. Release cadence & maintenance status

| Tag | Commit | Commit date | GitHub release | Notes body (verbatim) |
|---|---|---|---|---|
| v1.0 | `cfa9908` | 2024-03-17 | 2024-03-17T07:16:10Z | "initial release" |
| v1.0.1 | `d7f098a` | 2024-03-19 | 2024-03-18T23:08:36Z | "changed `reverse_ai` to `reverser_ai` in settings, readme and screenshots" |
| v1.1 | `d7b6700` | 2024-06-21 | 2024-06-21T03:57:00Z | "added a more powerful model · added feature for context-aware function renaming · added documentation · various smaller bug and documentation fixes" |
| v1.2 | `1d572da` | 2026-05-20 | 2026-05-20T11:24:36Z | "added dependency fixes" |

(Release metadata: `https://api.github.com/repos/mrphrazer/reverser_ai/releases`;
no release assets attached to any tag.)

Pattern: **one compressed research burst** (v1.0→v1.1 within ~14 weeks:
feature work March 2024, then a 6-week pause, a June 2024 tidy-up week and
immediate release), then **23 months of silence**, broken only by v1.2's
same-day CI+packaging repair. Maintenance status per the GitHub API
(fetched 2026-10-31): not archived, `pushed_at` = v1.2 only, 0 open issues,
14 watchers vs 1,168 stars / 94 forks — interest is broad, engagement is
minimal; one external contribution ever. Reasonable read: the repo
functions as a citable reference implementation of the 2024 paper-era
result, not as an actively developed tool. The bug-fix record maps the
design decisions: propagation-through-call-graph (d488e82), fail-loud on
token overflow (aeb265c), don't query without HLIL (cf8e449 — implemented
backwards until v1.2), model sizing honesty (456bc1e), packaging-name
repair (1d572da).

## Sources

- Clone `/tmp/opencode/reverser_ai` @ `1d572da`: `git log` (all 25 commits),
  `git shortlog -sne --all`, `git branch -a`, `git cat-file -t <tag>`,
  `git ls-tree -r --name-only <tag>`, `git diff --stat v1.0 v1.1`,
  `git diff v1.1 v1.2`, `git diff v1.0 v1.1 -- requirements.txt`,
  `git show {v1.0,v1.0.1,v1.1,v1.2}:<path>`, `git show <sha>` for
  `cfa9908 d7f098a ccae97b d488e82 aeb265c c318f28 2ec64bb 16bde89 eb940ea
  4d94939 5597fb7 845626f 84b1a3e cf8e449 c7c681a 7b3ecd8 456bc1e af29a1d
  09d4e00 4bf725f c6b1fd4 d7b6700 b4b4cc2 1d572da`,
  `git grep -il … $(git rev-list --all)`, `git log --follow --
  reverser_ai/gpt/agent.py`, `unzip -l examples/samples.zip`.
- `https://api.github.com/repos/mrphrazer/reverser_ai/releases` (4 releases:
  dates + verbatim bodies)
- `https://api.github.com/repos/mrphrazer/reverser_ai` (created_at,
  pushed_at, stars/forks/watchers/issues)
- `https://huggingface.co/api/models?search=ReverserAI` (0 results)
- `http://export.arxiv.org/api/query?id_list=2304.02000` (resolves to a
  mathematics paper by Baldoni & Vergne) and arXiv searches
  `all:"ReverserAI"`, `all:"auto-symbolication"` (0 results each) —
  contradicting the paper citation in `00-scope-and-method.md:13-16`
- `https://github.com/mrphrazer/reverser_ai/releases` (landing page for the
  four tags; content identical to the API)

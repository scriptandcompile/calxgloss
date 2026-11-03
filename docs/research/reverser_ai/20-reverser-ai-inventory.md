# ReverserAI complete inventory (HEAD `1d572da`, v1.2)

> Part of the [ReverserAI overview](README.md). Fixed surface map of the repo at
> HEAD: every file with line counts, packaging and marketplace metadata, CI,
> examples, dependencies, and project meta. All claims cite clone-relative
> `path:line` verified against the clone at `/tmp/opencode/reverser_ai`,
> HEAD `1d572da` (2026-05-20, tag v1.2, 25 commits, 4 tags).

## 1. Repo shape and scale

Flat single-plugin repo: the repo root *is* the Binary Ninja plugin directory
(root `__init__.py` registers commands), `reverser_ai/` is the importable
library, `scripts/` are CLI entry points. No tests, no docs/ dir, one branch
(`main`). 25 checked-in paths at v1.2 (verified: `git ls-tree -r --name-only v1.2`).

Directory tree (line counts from `wc -l` on the clone; ★ = Python):

```
reverser_ai/            (repo root)
├── __init__.py             123 ★  BN plugin entry: 3 plugin commands + 6 settings
├── plugin.json              29    BN marketplace metadata (v1.2, min BN build 2487)
├── setup.py                 28    setuptools packaging (PyPI-style, never published)
├── requirements.txt          5    5 pinned-minimum dependencies
├── example_config.toml      24    CLI config sample (6 parameters)
├── README.md               167    full project documentation
├── LICENSE                 339    GPL-2.0 text (plugin.json says "or later" — GPL-2.0+)
├── .gitignore              160    stock GitHub Python template
├── .github/workflows/
│   └── ci.yml               43    the only CI (added at v1.2)
├── examples/
│   ├── README.md            18*   example writeups (Triton stub, static linking)
│   └── samples.zip           —    1,311 B zip; 1 file: triton_inject.bin (2,104 B)
├── imgs/
│   ├── plugin_menu.png       —    52,507 B
│   ├── plugin_results.png    —    131,778 B
│   └── plugin_settings.png   —    307,742 B
├── reverser_ai/                    library package
│   ├── __init__.py           1    empty (blank line only)
│   ├── config.py            22    TOML loader for CLI configs
│   ├── utils.py             19    get_plugin_directory() — never called (dead)
│   ├── gpt/                       LLM layer
│   │   ├── __init__.py       0    empty
│   │   ├── agent.py         97    generic local-LLM agent (llama.cpp + HF download)
│   │   ├── function_name_gpt.py
│   │                         123  naming task: prompt, params, output filtering
│   │   └── models.py        46    3 HF GGUF model identifiers
│   └── binary_ninja/               BN integration layer
│       ├── __init__.py      237   bg tasks, singleton, 3 plugin workflows
│       ├── function_name_gpt_wrapper.py
│                            97    HLIL → GPT → apply rename, BN Settings reader
│       └── utils.py         135   call-graph traversal + context collectors
└── scripts/
    ├── gpt_function_namer.py 62   CLI demo: name a hard-coded xor C function
    └── model_download.py     38   pre-download the default GGUF model
```

`*` `wc -l` reports 18 for `examples/README.md` (missing final newline); it
holds 19 content lines. Python: **14 files, 1,028 lines** total
(`find . -name '*.py' | xargs wc -l` = 1028), of which the two package
`__init__.py` files contribute 1. The scope file's "1 224 lines of Python
across 13 files" (`00-scope-and-method.md:65-68`) does not match this
measurement in either file count or LOC.

The one capability shipped: **LLM-suggested function renaming**, exposed as
three Binary Ninja commands (`__init__.py:13-30`): "Rename Current Function"
(per-function), "Rename All Functions" (whole binary, bottom-up call-graph
order), "Enhance Function Naming with Context" (rename-all restricted to
functions touching strings/import symbols). A CLI demo path exists
(`scripts/gpt_function_namer.py`) but on a hard-coded XOR function, not on
user input.

## 2. Packaging & distribution

### 2.1 Binary Ninja plugin marketplace

`plugin.json` (v1.2) is the BN plugin-manager manifest:
`pluginmetadataversion: 2`, name "ReverserAI", author "Tim Blazytko"
(`plugin.json:2-4`), `type: ["helper"]` (`:5-7`), `api: ["python3"]`
(`:8-10`), description (`:11`), **empty `longdescription`** (`:12`),
embedded license block (`:13-16`), `platforms: ["Darwin","Windows","Linux"]`
(`:17-21`), empty per-platform install instructions (`:22-26`),
`"version": "1.2"` (`:27`), **`minimumbinaryninjaversion: 2487`** (`:28`).
Note the v1.0-era `"dependencies": {"pip": [...]}` block was **removed** at
v1.0.1 (see [21-history-and-releases.md](21-history-and-releases.md) §2.2) —
v1.2 has no dependency field in the manifest at all.

README's install path (`README.md:38-49`): BN plugin manager, or clone into
Binary Ninja's `plugins` folder + `pip3 install -r requirements.txt` +
`pip3 install .`. On first launch the default model
`mistral-7b-instruct-v0.2.Q4_K_M.gguf` (~5 GB) auto-downloads
(`README.md:51`); `scripts/model_download.py:17-34` builds a throwaway config
and instantiates `FunctionNameGPT` to trigger the download (module-level call
at `scripts/model_download.py:38`).

### 2.2 PyPI — **no published package**

`setup.py` packages `ReverserAI` v1.2, author Tim Blazytko
`<tim@blazytko.to>`, `python_requires=">=3.10"`
(`setup.py:12-13,14-15,27`), README as long_description
(`setup.py:3-4,17-18`), requirements.txt parsed into
`install_requires` (`setup.py:6-9,26` — the parsing block was added at v1.2,
`git show 1d572da`), classifiers GPLv2+/Linux (`setup.py:20-24`).

**Despite the scope file's expectation (`00-scope-and-method.md:29,62`), no
PyPI distribution exists** (checked 2026-10-31):
`https://pypi.org/pypi/reverser-ai/json`, `/pypi/reverserai/json`,
`/pypi/reverser_ai/json`, `/pypi/ReverserAI/json` and the simple index
`https://pypi.org/simple/reverser-ai/` all return **404**; a control request
(`https://pypi.org/pypi/toml/json`) returns 200 through the same path, so the
404s are genuine. There is no version/date history to inventory on PyPI.
`setup.py` exists only for the local `pip3 install .` flow (README:48) and CI
metadata check (§3). Note also `setuptools.find_packages()` (`setup.py:25`)
would exclude the root plugin entry `__init__.py` even if it were published.

## 3. CI — exactly one workflow, added only at v1.2

`.github/workflows/ci.yml` (43 lines, single job `quality`,
`runs-on: ubuntu-latest`) triggers on every push and PR (`ci.yml:3-5`). It
gates on, in order:

| Step | Command | Cite |
|---|---|---|
| Checkout | `actions/checkout@v4` | `ci.yml:12` |
| Python | `actions/setup-python@v5`, `python-version: "3.11"` | `ci.yml:15-17` |
| Tooling | `pip install --upgrade pip setuptools wheel` + `pip install ruff` (unpinned) | `ci.yml:21-22` |
| Format | `ruff format --check .` | `ci.yml:25` |
| Lint | `ruff check .` | `ci.yml:28` |
| Metadata | `python setup.py check --metadata --strict` | `ci.yml:31` |
| Syntax | inline Python: `ast.parse` every non-dot `*.py` | `ci.yml:34-43` |

There is **no type checker (no mypy), no test run, no dependency install, no
ruff version pin, no matrix**. CI existed nowhere before v1.2 (absent from
`v1.0`, `v1.0.1`, `v1.1` trees; added by `b4b4cc2`, 2026-05-20 — see
[history file](21-history-and-releases.md) §2.4).

## 4. Examples

`examples/README.md` (19 content lines) documents two use cases:

1. **Triton malware stub** (`examples/README.md:12-14`): sample
   `triton_inject.bin` — a PowerPC stub from the Triton (BadRabbit) malware
   family ([Wikipedia](https://en.wikipedia.org/wiki/Triton_(malware)),
   linked in the README), 23 functions with custom logic; LLM naming sorts
   data-copy vs complex-pattern functions. Called out as "worth a closer
   look" (`:9`).
2. **Statically-linked executables** (`examples/README.md:17-19`): idea only —
   filter most-called functions and ask the LLM to spot `memcpy`/`strlen`;
   cites mrphrazer's 2023-08-02 blog post
   <https://synthesis.to/2023/08/02/api_functions.html>; "detailed examples
   will be provided in future updates" — never provided through v1.2.

`samples.zip` (on-disk 1,311 B; verified with `unzip -l`): **exactly one
file, `triton_inject.bin`, uncompressed size 2,104 bytes**. Password-protected
with the RE-community convention `"infected"` (`examples/README.md:3`). It is
a real-malware fragment, not a CTF challenge. So the shipped example corpus is
one 2 KB sample; no corpus, no ground-truth data, no eval fixtures.

## 5. Dependencies (`requirements.txt:1-5`) and where each is used

| Requirement | Used by | Role |
|---|---|---|
| `huggingface-hub>=0.21.4` | `reverser_ai/gpt/agent.py:1,70` (`hf_hub_download`) | downloads GGUF files from HF Hub |
| `llama-cpp-python>=0.2.56` | `reverser_ai/gpt/agent.py:2,48-56` (`Llama`) | local inference engine; mmap/threads/GPU layers/seed plumbed at init |
| `networkx>=3.2.1` | `reverser_ai/binary_ninja/utils.py:3,44-58` (`nx.DiGraph`, `nx.dfs_postorder_nodes`) | call-graph bottom-up (post-order) traversal |
| `toml>=0.10.2` | `reverser_ai/config.py:1,20` | CLI TOML config loading |
| `typer>=0.11` | **nowhere** — zero `typer` imports in the tree (grep, verified 2026-10-31); the CLI uses `sys.argv` (`scripts/gpt_function_namer.py:3,36-43`) | dead requirement (added at v1.1 by `845626f`) |

`binaryninja` itself is the implicit host-provided dependency (imports at
`__init__.py:1-2`, `reverser_ai/binary_ninja/*` throughout); it is not in
requirements.txt and cannot be pip-installed. The v1.0 `plugin.json` pip
block (toml, huggingface_hub, llama-cpp-python — `git show v1.0:plugin.json`)
was dropped at v1.0.1 and never restored.

## 6. Project meta

- **License**: file `LICENSE` is the verbatim GPL-2.0 body (339 lines,
  `LICENSE:1-2`); `plugin.json:15` names "GPL-2.0" but its text says "either
  version 2 of the License, or (at your option) **any later version**" →
  **GPL-2.0-or-later** (GPL-2.0+), matching the `setup.py:22` classifier
  "GPLv2+". GitHub's API tags it `GPL-2.0`
  ([api.github.com/repos/mrphrazer/reverser_ai](https://api.github.com/repos/mrphrazer/reverser_ai),
  `license.spdx_id`). Implication for reuse: derivatives (including any BN
  plugin incorporating it) must be licensed under GPL-2.0+; Binary Ninja
  itself is non-free, a known GPL-in-context tension, but the plugin code is
  plainly copyleft. No CLA/copyright assignment.
- **Author**: Tim Blazytko (mrphrazer) — README:2, plugin.json:4,
  setup.py:14-15; contact is a Twitter link only (`README.md:165-167`).
  External contributors: one commit by "Lays" (PR #5). Repo stats (GitHub API,
  2026-10-31): 1,168 stars (page shows "1.2k"), 94 forks, 14 watchers, 0 open
  issues, not archived, repo size 852 KB, created 2024-03-17.
- **README structure** (167 lines): title+one-liner (`README.md:1-4`),
  description + ML-expertise disclaimer (`:6-18`), core features (`:21-33`),
  installation + auto model download (`:36-51`), hardware requirements — ≥16 GB
  RAM, 12 threads, 20–30 s/query CPU vs 2–5 s on Apple-silicon GPU
  (`:54-56`), usage/UI + screenshots (`:59-75`), configuration parameters
  `model_identifier/use_mmap/n_threads/n_gpu_layers/seed/verbose` (`:78-97`),
  BN settings + restart requirement (`:100-108`), CLI parameter tuning with a
  1.55 s sample run (`:111-122`), static-analysis context section (`:125-132`),
  code organization (`:135-146`), limitations/future work — server hosting,
  **fine-tuning models**, more tasks, IDA/Ghidra ports all listed as *not done*
  (`:148-162`), contact (`:165-167`).
- **`imgs/`**: 3 PNGs only — `plugin_menu.png` (52,507 B, command menu),
  `plugin_results.png` (131,778 B, log-window results), `plugin_settings.png`
  (307,742 B, BN settings screen; replaced at v1.1 by `c6b1fd4`). No charts,
  no benchmark figures.

## 7. Code-layer notes that matter for the comparison

Concrete surface facts, all at HEAD:

- **Settings schema** (`__init__.py`): group `reverser_ai` (`:36`);
  `use_mmap` bool default `true` (`:39-50`), `n_threads` number default `0`
  (`:52-63`), `n_gpu_layers` number default `99` (`:65-76`), `seed` default
  `0` (`:78-89`), `verbose` default `false` (`:91-102`), `model_identifier`
  string enum `["mistral-7b-instruct","mixtral-8x7b-instruct"]` default
  `mistral-7b-instruct` (`:104-123`). All settings `requiresRestart: true`.
  `example_config.toml:9-24` mirrors these six keys — no prompt/context/
  generation knobs are user-tunable.
- **Model catalogue** (`reverser_ai/gpt/models.py:9-45`): 3 off-the-shelf
  TheBloke GGUF repos — `mythomax_13b` =
  `TheBloke/MythoMax-L2-Kimiko-v2-13B-GGUF`, Q6_K (`:17-20`);
  `mistral-7b-instruct` = `Mistral-7B-Instruct-v0.2-GGUF`, Q4_K_M (`:29-32`);
  `mixtral-8x7b-instruct` = `Mixtral-8x7B-Instruct-v0.1-GGUF`, Q4_K_M
  (`:42-45`). `mythomax_13b` (uncensored roleplay model) is selectable in code
  but **not exposed** in the settings enum or CLI examples — vestigial.
- **Inference config** is hard-coded in the task class, not user-tunable:
  `n_context=4000` (`reverser_ai/gpt/function_name_gpt.py:27`) with
  `max_tokens=5000`, `stop=["</s>"]`, `min_p=0.1`, `temperature=0.8`,
  `repeat_penalty=1` (`:30-41`) — note `max_tokens` > `n_context`.
- **Prompt** (`function_name_gpt.py:46-64`): Mistral-Instruct chat tags,
  one-shot (the one example answer is the literal `add_two_values`),
  "up to 20 characters", "discard all explanations"; agent appends
  `"\n### Response:"` (`reverser_ai/gpt/agent.py:83`). Raw completion API,
  no chat API, no tool use.
- **Output handling**: first line only, `\_;` unescape, backticks stripped
  (`function_name_gpt.py:100-123`); no validation that the result is a legal
  identifier. Over-length input surfaces as `ValueError` ("may exceed the
  maximum token limit", `:94-98`) which the BN wrapper logs as a warning
  instead of renaming (`reverser_ai/binary_ninja/function_name_gpt_wrapper.py:81-97`).
- **HLIL input** = `f"{str(f)}\n"` (the prototype signature line) + tab-prefixed
  `str()` of every HLIL root line
  (`function_name_gpt_wrapper.py:51-66`) — signature text is itself a naming
  hint fed to the model.
- **Call-graph order** only for "Rename All": `nx.DiGraph` over
  `bv.functions` + `f.callees`, yielded by `nx.dfs_postorder_nodes`
  (`reverser_ai/binary_ninja/utils.py:29-58`); post-order ⇒ leaves renamed
  before callers, and earlier renames show up in later prompts because the
  prompt contains the *current* HLIL (renames mutate the BN DB). "Enhance …
  with Context" preselects functions referencing import/library/external
  symbols or strings (`binary_ninja/utils.py:61-102,105-135`) but then iterates plain
  `bv.functions` — the docstring claims bottom-up, the code does not do it
  (`reverser_ai/binary_ninja/__init__.py:173-174`).
- **Rename policy**: `is_derived_func_name` (`binary_ninja/utils.py:7-26`)
  returns `False` only for `^sub_[0-9a-f]+$` and `True` for everything else
  (docstring is inverted vs behavior); both bulk workflows therefore rename
  only anonymous `sub_…` functions and never touch symbol-derived names
  (`binary_ninja/__init__.py:145,180`).
- **HLIL guard**: both bulk workflows skip functions whose
  `hlil_if_available is None` (`binary_ninja/__init__.py:141,177`) — correct
  only at v1.2; shipped inverted through v1.0.1→v1.1 (§2.3 of the
  [history file](21-history-and-releases.md)).
- **Dead code**: `reverser_ai/utils.py:4-19` `get_plugin_directory()` has no
  callers (verified by grep across all `.py`); `typer` unused; mythomax
  unreachable from UI. Singleton wrapper per BN session
  (`binary_ninja/__init__.py:64-98`); every bulk run re-instantiates and
  re-loads the whole model only once per plugin session.

## Sources

- Clone `/tmp/opencode/reverser_ai` @ `1d572da` (v1.2), all paths above read in
  full; `wc -l`, `git ls-tree -r --name-only v1.2`, `unzip -l examples/samples.zip`.
- `https://github.com/mrphrazer/reverser_ai` (stars/forks/watchers, file tree; fetched 2026-10-31)
- `https://api.github.com/repos/mrphrazer/reverser_ai` (created/updated/pushed dates, `stargazers_count` 1168, `forks_count` 94, `open_issues_count` 0, `license.spdx_id` GPL-2.0, `size` 852)
- PyPI non-existence: `https://pypi.org/pypi/reverser-ai/json` (404),
  `https://pypi.org/pypi/reverserai/json` (404),
  `https://pypi.org/pypi/reverser_ai/json` (404),
  `https://pypi.org/simple/reverser-ai/` (404), control
  `https://pypi.org/pypi/toml/json` (200)
- `https://en.wikipedia.org/wiki/Triton_(malware)` and
  `https://synthesis.to/2023/08/02/api_functions.html` (links cited by `examples/README.md`)

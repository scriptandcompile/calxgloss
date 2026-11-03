# 21 — IDAssist history, releases, and community

> Part of the [overview](README.md). All git facts verified 2026-11-01 against a read-only clone at
> HEAD `09dd910d70016c7b3f7e8bc01a4d5bc1035ec302` (2026-09-20); web facts from the GitHub pages cited in Sources.
> 76 commits total on `master`, plugin version 2.4.0.

## 1. Commit archaeology

- **Span**: first commit `6ae6172` "Initial commit." 2026-02-26; last `09dd910` "Update model guidance to current LLM families" 2026-09-20 (`git log --pretty='%h %ci %an %ae %s'`). ~7 months of history, no commits before 2026-02-26.
- **Velocity** (`git log --pretty='%ad' --date=format:'%Y-%m' | sort | uniq -c`):

  | Month | 2026-02 | 03 | 04 | 05 | 06 | 08 | 09 |
  |---|---|---|---|---|---|---|---|
  | Commits | 10 | 30 | 27 | 4 | 1 | 2 | 2 |

  Intense build-out Feb–Apr (67/76 commits), then a long tail of maintenance-sized changes (May: 4, Jun: 1, Jul: 0, Aug: 2, Sep: 2).

- **Author breakdown** (`git shortlog -sne HEAD`):

  | Commits | Author | Email / domain |
  |---|---|---|
  | 68 | Jason Tang | `jason.tang@badc0ded.net` |
  | 2 | Nikolas Sturm | `code@nsturm.me` |
  | 2 | SymGraph | `admin@symgraph.ai` (merge bot/org account) |
  | 1 | Presmanes | `presmanes3@gmail.com` |
  | 1 | Zakir Jiwani | `108548454+JiwaniZakir@users.noreply.github.com` |
  | 1 | gagmeng | `gagmeng@163.com` |
  | 1 | jtang613 | `11688468+jtang613@users.noreply.github.com` (merge of PR #11) |

  Jason Tang authored 68/76 (89%). The `jtang613` GitHub noreply address (user id 11688468) appears only as merge-committer of PR #11; GitHub user id 11688468 is identical in both addresses.

- **Commit-message style**: dominant maintainer style is terse imperative, often content-free — 8 commits are literally "Updates.", and 11 commits total carry one of "Updates." / "Bump version." / "Version bump." / "Version fix." (e.g. `b422b4c`, `63a80a7`, `4dd2d71`, `4436797`, `99a29f9`). Conventional Commits appear in the external Bedrock contribution (`feat(bedrock): …` `574fc78`, by Presmanes) — the maintainer also uses the style himself (`fix(bedrock): …` `9555cb9`/`f1157c1`, `fix: harden LiteLLM Bedrock compatibility` `3c7b184`, all Jason Tang; *attribution corrected 2026-11-02 — an earlier draft wrongly called the two `fix(bedrock)` commits external*). One non-English Chinese-language commit by gagmeng (`2906952`). Squash-style local merges ("Merge branch 'master' into pr-6", `cc9eeca`) show PRs were sometimes pulled manually rather than via GitHub.

## 2. Version history (`ida-plugin.json` "version" field)

From `git log -p -- ida-plugin.json | grep -E '^(commit |[+-].*"version")'`, with tag dates from `git log -1 --format='%ci' <tag>`:

| Version | Date | Manifest bump commit | Tag commit (tag date) |
|---|---|---|---|
| 1.0.0 | 2026-02-28 | `d6c550f` (field added) | `d6c550f` (2026-02-28) |
| 1.0.1 | 2026-02-28 | `99a29f9` | `99a29f9` |
| 1.0.2 | 2026-02-28 | `a92b26f` | `a92b26f` |
| 1.0.3 | 2026-03-02 | `4436797` | `2381ac0` (2026-03-02) |
| 1.0.4 | 2026-03-09 | `1eb7456` | `1eb7456` |
| 1.1.0 | 2026-03-14 | `fa4ff1f` (1.0.4→1.1.0) | `eda5f78` "Version fix." (2026-03-14) |
| 1.2.0 | 2026-03-14 | `eefc4c8` | `eefc4c8` |
| 1.3.0 | 2026-03-18 | `b422b4c` | `b422b4c` |
| 1.4.0 | 2026-03-19 | `e2e5529` | `e2e5529` |
| 1.5.0 | 2026-03-29 | `51f4603` | `347b515` (2026-03-29) |
| 1.6.0 | 2026-04-03 | `ce7134d` | `ce7134d` |
| 1.7.0 | 2026-04-09 | `7c64634` | `dec7e7c` (2026-04-09) |
| 1.8.0 | 2026-04-11 | `ec6a645` | `ec6a645` |
| 1.9.0 | 2026-04-12(16) | `fb5819c` bump 2026-04-12 | `a321ad1` (2026-04-16) |
| 2.0.0 | 2026-04-19 | `3cdb161` | `3cdb161` |
| 2.1.0 | 2026-05-25 | `44c0c16` | `44c0c16` |
| 2.2.0 | 2026-06-28 | *no manifest bump found* | `7b9e2de` (2026-06-28) |
| 2.3.0 | 2026-08-30 | `df056c4` (2.1.0→2.3.0, skips 2.2.0 in manifest) | `df056c4` |
| 2.4.0 | 2026-09-12 | `3c7b184` | `3c7b184` |

Anomalies: **2.2.0 was tagged but never set in the manifest** — the manifest jumped 2.1.0→2.3.0 in `df056c4`; the tag points at `7b9e2de` (OpenWebUI provider) which does not touch the version field. Tag 1.1.0's tag commit `eda5f78` is literally "Version fix." (the only one; the other "Version fix." commit `fcf2e50` carries no tag and touches no version field), and other tag commits are terse bumps too, so tag date and manifest-bump commit can differ by days (1.5.0: bump 03-21, tag 03-29; 1.7.0: bump 04-04, tag 04-09 — the table's Date column tracks tag dates).

## 3. Releases & tags

- `git tag` in the clone: **19 tags**, `1.0.0 … 2.4.0` (every minor/patch above). So tags are NOT empty.
- Fetched https://github.com/symgraph/IDAssist/tags (page 1, 10 newest): each tag shows zip/tar.gz source archives; 2.3.0 additionally has "Notes" (a written release body). Page 2 not fetched (older tags 1.4.0 and earlier).
- Fetched https://github.com/symgraph/IDAssist/releases: releases exist **under `symgraph/IDAssist`** (page 1 covers 2.4.0 "Latest" down to 1.4.0; a page 2 exists with older entries — not fetched). Every listed release shows "Assets 2" (GitHub's automatic zip/tarball source archives; whether any custom IDA-plugin package assets exist beyond that is *(unverified)*). Release titles: 2.4.0 "Fixes", 2.3.0 "IDA 9.4 and Python 3.14 Compatibility" (only one with a full changelog body), 2.2.0 "Fixes OpenWebUI provider issue.", 2.1.0 "Various updates, features and fixes.", 2.0.0 "New feature: SymGraph service tab", 1.9.0, 1.7.0 "Chat overhaul", 1.6.0, 1.5.0, 1.4.0 "Updates".
- Release/publisher identity: releases from 1.4.0 to 2.4.0 except 2.0.0 were published by **@symgraph** (org, GitHub user id 252476222); **2.0.0 was published by @jtang613**. Release tag commits (`3c7b184`, `df056c4`, `7b9e2de`, `44c0c16`, `3cdb161`, `a321ad1`, `dec7e7c`, `ce7134d`, `347b515`, `e2e5529`) all match the clone's history exactly, so release tags match the repo.
- The README's release links under `jtang613/IDAssist` were not fetched (outside allowed URLs); the fetched pages served releases fully under `symgraph/IDAssist`, and the repo's own history shows why (see §6: commit `1eb7456` re-homed the repo URL from `jtang613/IDAssist` to `symgraph/IDAssist` on 2026-03-09).
- https://github.com/symgraph/IDAssist/graphs/contributors returned only the "Crunching the latest data…" placeholder — **no contributor numbers extracted** (JS-rendered; failure recorded).
- Star/fork counts 901 stars / 95 forks as of 2026-11-01: *(lead fact, not re-verified here)*.

## 4. Contributors, PRs, and community

Merge commits (`git log --merges --pretty=…`): 4 total.

| PR | Merged | Merge author | Contribution |
|---|---|---|---|
| #11 `nikolas-sturm/fix/semantic-analysis` | 2026-04-18 | `jtang613` (noreply) | `cb10700` "Fix semantic analysis context and OAuth response parsing" (Nikolas Sturm) |
| #9 `nikolas-sturm/feature/mcp-stdio-support` | 2026-04-18 | `SymGraph <admin@symgraph.ai>` | `cf39541` "Add stdio MCP server support" + `migrations/add_mcp_stdio_fields.py` + manifest pywin32 dep |
| #10 `JiwaniZakir/fix/7-crashes-ida-pro-9-2…` | 2026-04-18 | `SymGraph <admin@symgraph.ai>` | `4353cb0` "Skip PySide6 6.8.0 import to prevent IDA Pro 9.2 crash" — fixes issue **#7** |
| (local) `master` into `pr-6` | 2026-04-03 | Jason Tang | manual merge, no GitHub footer |

So three outside code contributors (Nikolas Sturm ×2, Zakir Jiwani, Presmanes ×1 Bedrock commit — the two follow-up `fix(bedrock)` commits are the maintainer's, gagmeng ×1 UI commit in Chinese) all landed their work in a burst between 2026-03-31 and 2026-05-20. All three GitHub PRs merged in one sitting on 2026-04-18. Issue count: the fetched pages' navigation shows **"Issues (1)"** open — the issue's title was not fetched (issues page outside allowed URLs), *(unverified)*. Issue #7 (IDA Pro 9.2 Windows crash) is referenced in PR #10's merge body and was closed by the merge.

**Fork/org naming**: commit `1eb7456` (2026-03-09) "Bump version. Re-home repo." changed `ida-plugin.json` from `"name": "idassist"` / `"repository": "https://github.com/jtang613/IDAssist"` to `"IDAssist"` / `"https://github.com/symgraph/IDAssist"`. The clone's `git remote -v` shows only `origin https://github.com/symgraph/IDAssist`. GitHub user `jtang613` (id 11688468) and maintainer Jason Tang are separate commit identities in the metadata; any identity link between them is *(unverified)* beyond that jtang613 merged PR #11 and published the 2.0.0 release.

## 5. Feature archaeology (when each capability landed)

Via `git log --diff-filter=A --pretty='@ %h %ci %s' --name-only -- <paths>`. Key observation: **almost every major subsystem arrived fully-formed in the very first commit** (`6ae6172`, 2026-02-26): `src/services/graphrag/` (13 files incl. `graph_store.py`, `query_engine.py`, `taint_analyzer.py`, `community_detector.py`, `network_flow_analyzer.py`), `src/services/react/` (5 files), `src/services/rag_service.py`, `src/services/rlhf_service.py`, `src/services/symgraph_service.py`, `src/services/mcp_client*.py` + `mcp_tool_orchestrator.py`, and 14 `src/services/llm_providers/` files (9 provider modules incl. `base_provider` + 4 OAuth utils + factory + `__init__`; *corrected 2026-11-02 — earlier draft said 11*).

| Capability | Commit | Date |
|---|---|---|
| GraphRAG, ReAct, RAG, RLHF, SymGraph sync, MCP client, Qt UI — all at once | `6ae6172` Initial commit | 2026-02-26 |
| Providers present at initial commit: Anthropic Claude CLI, Anthropic OAuth, Anthropic API, OpenAI OAuth, OpenAI API, Ollama, LiteLLM | `6ae6172` | 2026-02-26 |
| Gemini OAuth provider (+ `graphrag_tools.py`) | `d6c550f` | 2026-02-28 |
| Qt5/Qt6 compatibility layer (IDA 9.1+) | `eefc4c8` | 2026-03-14 |
| Chunked symbol/graph push; EXTERNAL graph node type | `b1dbaa0`, `95a9ce1` | 2026-03-17 |
| VULNERABLE_VIA edges + taint improvements | `c54ab1b` | 2026-03-13 |
| ReAct transcript UI port, streaming cards | `1cf823a`, `1eeed66` | 2026-04-08/09 |
| Unified function signature generation (+ `graphrag/function_signature_generator.py`) | `e5efed6`, `25454e0` | 2026-03-29 / 03-27 |
| MCP **stdio** server support (PR #9) + `add_mcp_stdio_fields.py` | `cf39541` | 2026-04-16 |
| OAuth credential persistence/refresh | `41763c4` | 2026-04-11 |
| Native AWS Bedrock provider (Converse API) + `add_aws_bedrock_config.py` | `574fc78` (+`f1157c1`,`9555cb9` fixes) | 2026-05-16 → 05-20 |
| ReAct **plan approval** step (matches "Add ReAct plan approval step.", `git log --grep='approval'`) — v2.1.0 | `44c0c16` | 2026-05-25 |
| OpenWebUI API-path provider | `7b9e2de` | 2026-06-28 |
| LiteLLM Bedrock hardening; IDA 9.4/Qt fixes | `3c7b184`, `bbe8017` | 2026-09-12 / 08-30 |

## 6. Added, removed, deprecated

`git log --diff-filter=D --pretty='@ %h %ci %s' --name-only -- '*.py'`:

- `5971d8c` 2026-02-27 deleted `src/mcp_server/server.py`, `src/mcp_server/resources.py`; `d6c550f` 2026-02-28 deleted `src/mcp_server/__init__.py` and `src/mcp_server/tools.py` (modified at `5971d8c`, deleted next) — the **standalone MCP server package (4 modules) was deleted within days** of first public commit (superseded by the client stack under `src/services/`).
- `e2e5529` 2026-03-19 deleted `src/services/llm_providers/anthropic_oauth_provider.py`. Its release body (fetched, release 1.4.0): "Remove the ANTHROPIC_OAUTH provider type, anthropic_oauth_provider, AnthropicOAuthWorker, and all associated UI authentication flows… Update provider_types, factory, message format adapter mapping, and migration maps accordingly."
  - **Docs/code divergence (lead-verified 2026-11-01):** at HEAD, `grep -rn 'anthropic_oauth' README.md docs/ src/` hits **only** `README.md:130`, `docs/tabs/settings-tab.md:58`, `docs/index.md:64` — zero hits in `src/` (`src/services/models/provider_types.py` defines `GEMINI_OAUTH`/`OPENAI_OAUTH` only, :36,:40). The README still advertises `anthropic_oauth` as a supported provider type five months after its removal: the docs lag the code.
- `f656683` 2026-03-14 reverts `13afe98` "Add Qt environment validation…" — an approach tried and rolled back same-day; the problem was fixed instead by the Qt5/Qt6 compatibility layer (`eefc4c8`, also 2026-03-14, *corrected 2026-11-02 — earlier draft said "next day"*) and later by PySide6 6.8.0 import skip (`4353cb0`) and the 2.3.0 release body's "blank plugin panels" fixes *(GitHub release body — no 2.3.0-range commit message in the clone mentions blank panels; the range holds only `bbe8017` "Fix IDA 9.4 Qt and provider test crashes" + version bump)*.
- **Provider-type renames**: `src/services/migrations/migrate_provider_type_names.py` was added in the **initial commit** `6ae6172` — the rename of stored provider-type names predates this repo's public history; no later commit introduced it. Later migrations layered on: `add_bypass_proxy.py` (`2906952`, 2026-03-31, gagmeng), `add_provider_timeout.py` (`aac0c1f`, 2026-04-03), `add_mcp_stdio_fields.py` (`cf39541`), `add_aws_bedrock_config.py` (`574fc78`).
- Repo identity change: `1eb7456` (2026-03-09) re-homed manifest repo URL `jtang613/IDAssist` → `symgraph/IDAssist` (verbatim `-`/`+` lines shown in §1 style note source: `git log -p -- ida-plugin.json`).

## 7. Project lineage

First commits (`git log --reverse` head): `6ae6172` Initial commit. (2026-02-26) → `12a117a` Fix MCP client. (02-26) → `6392569` Add MIT License. (02-26) → `5971d8c` Fixes and updates. (02-27) → `92fb617` Updates. (02-28).

The initial commit is a **squashed import of a mature app**: 107 files, 45,169 insertions (`git show --shortstat 6ae6172`), top-level only `.gitignore`, `idassist_plugin.py`, `requirements.txt`, `src/`. It already contained the full GraphRAG/ReAct/RLHF/MCP/full-provider stack **plus** five database migration scripts (`add_provider_type.py`, `migrate_provider_type_names.py`, `add_oauth_credentials.py` etc.) — schema migrations that rewrite *stored user data* imply an earlier pre-public development/release cycle; that is inference, stated as such. No vendored third-party tree was observed in the initial file list *(only paths visible at that depth; full vendor audit not performed)*. The deleted `src/mcp_server/` package in commit #4 (`5971d8c`) further suggests the import snapshot itself was already mid-refactor.

## Limitations

- Releases page 2 (≤1.3.0) and tags page 2 not fetched; whether every early tag has a GitHub *release* (vs bare tag) is unverified.
- Contributors graph page never rendered (JS); star/fork counts and the one open issue's title are lead facts / not fetched.
- Release asset contents (beyond GitHub auto source archives) not downloaded or compared to the clone.

## Sources

Commands (all run inside the clone at HEAD `09dd910d…`):
`git rev-parse HEAD` · `git remote -v` · `git log --pretty='%h %ci %an %ae %s'` · `git shortlog -sne HEAD` · `git log --pretty='%ad' --date=format:'%Y-%m' | sort | uniq -c` · `git tag` · `git log -1 --format='%ci' <tag>` per tag · `git log --merges --pretty=…` · `git log -p -- ida-plugin.json | grep -E '^(commit |[+-].*"version")'` and a second grep over the same log for non-version manifest diffs · `git log --diff-filter=A --pretty=… --name-only -- src/services/graphrag/ 'src/services/mcp_*' src/services/react/ src/services/rag_service.py src/services/symgraph_service.py src/services/llm_providers/ src/services/rlhf_service.py src/services/migrations/` · `git log --diff-filter=D --pretty=… --name-only -- '*.py'` · `git log --oneline -i --grep='approval'` · `git log --reverse` · `git show --shortstat 6ae6172` · `git ls-tree -r --name-only 6ae6172 | wc -l` · `git ls-tree --name-only 6ae6172`

Web (fetched 2026-11-01):
- https://github.com/symgraph/IDAssist/releases (page 1: 2.4.0–1.4.0, publishers, assets, 1.4.0 body)
- https://github.com/symgraph/IDAssist/tags (page 1: 2.4.0–1.5.0, tag dates/commits, source archives)
- https://github.com/symgraph/IDAssist/graphs/contributors (placeholder only — no data)

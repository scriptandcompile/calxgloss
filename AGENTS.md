<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->

## Agent skills

### Coding standards

Documented coding standards live in `docs/standards.md`. The code-review skill's Standards axis checks diffs against that file.

### Issue tracker

Issues and specs live in GitHub Issues at `scriptandcompile/calxgloss`, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The default triage label vocabulary is `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Domain docs are split by context. The root `GLOSSARY-MAP.md` points to per-context `GLOSSARY.md` files (`crates/<context>/GLOSSARY.md`). ADRs live in `docs/adr/` (system-wide) and `crates/<context>/docs/adr/` (context-scoped). See `docs/agents/domain.md`.

### Commits

Write commit messages in plain English. The subject line is a lowercase
imperative verb doing a plain verb to a plain object — say what the change
makes the code do — and use a glossary term only where it adds precision the
plain words can't carry. The body must be readable by someone who has never
read the glossary; later sentences may then use glossary terms for exactness.

- Before: `honor the harness-error honesty rule at the verify seam`
- After: `record a broken test harness as a harness-error receipt, never a unit verdict (issue #415)`

Never stack nominalized metaphors ("the receipt fold", "the honesty edge") —
those are invented variants, banned by `docs/standards.md`. See that file's
*Writing that reads* section for the full sentence rules and a worked example.

### Reply style

When reporting work to a human in conversation:

- Lead with what the change gives a person, in complete sentences.
- Cite file:line, issue numbers, and record paths (e.g. `re/unknowns/…`)
  instead of coined abstractions ("the P21 mechanism" → "the unknown-record
  mechanism, decided in ADR-0056").
- One sentence, one claim. No aphoristic closers ("neither edge is a log
  line"), no rhetorical flourishes. End on the fact.
- The same rules as `docs/standards.md` *Writing that reads* apply: name an
  actor and a verb in every sentence, and make the first sentence of any
  paragraph readable without the glossary.
# LLM_Decompiler — complete overview & calxgloss comparison

> **LLM_Decompiler** ([Lami99/LLM_Decompiler](https://github.com/Lami99/LLM_Decompiler),
> **no license**, 3★) is a small single-author **Ghidra-headless + GPT prompt
> pipeline**: batch-decompile a binary into per-function C, then walk those
> files with eight hardcoded OpenAI prompt scripts to detect/fix vulnerabilities,
> rename, and reconstruct — plus a late CTF/exploit pivot and a Juliet-suite/CWE
> corpus-prep line. It is the dossier line's **null hypothesis**: the same
> front end and same "LLM decompiles Ghidra output" idea as calxgloss, with
> every load-bearing mechanism absent. Reviewed at HEAD `c242671` (2024-07-15,
> 26 commits, no tags); calxgloss at HEAD `40fbf91f` (2026-10-31); see
> [scope and method](00-scope-and-method.md).

## Executive summary

**LLM_Decompiler is calxgloss minus the machine.** Both start identically —
Ghidra `analyzeHeadless` dumps per-function pseudo-C for an LLM to work on —
then the paths separate completely: knowledge lives in eight hardcoded prompt
strings, not in 15 scans and versioned DBs; context is one whole-file
`system`-role message with zero budget code; queue order is Ghidra's address
order, not call-graph-topological; renames are pasted back verbatim into `.c`;
and the verification oracle is **zero** — nothing the tool ever writes is
re-read by the tool ([31](31-ghidra-harness-and-core-pipeline.md),
[32](32-large-codebase-reconstruction.md), [40](40-comparison.md)). This is
the control case every calxgloss doctrine can finally be priced against.

**The null configuration's measured outcome, over 69 days of life and 27
months of freeze:** 12 verified run-breaking defects in 1,390 lines — zero
exec bits while the README says `./script`, README setup pointing at the file
HEAD itself deleted, a CTF pipeline broken-on-arrival for 16 hours
([20](20-llm-decompiler-inventory.md) §11); a live OpenAI key committed twice,
surviving its own deletion, never revoked
([21](21-history-and-releases.md) §5); four of eight pinned model literals now
*dead endpoints* (retired 2026-10-23; the rest scheduled 2027-01-14) and the
Ghidra pin two major lines back on an EOL line
([34](34-results-effectiveness-and-hygiene.md) §3).

**Its one superlative is unbacked at every level its own docs prescribe.**
"Outperformed traditional methods across all evaluated metrics"
(`README.md:21-22`) entered the README whole in one commit (`cd00540`, +33/−1)
after the repo's measured output had already collapsed; the Juliet experiment
it gestures at shipped exactly one of four legs (corpus prep — with label
blinding); no build step, no scorer, no results artifact ever
([33](33-security-ctf-and-datasets.md) §7–§8). Reception: 3★/3 verbatim
post-freeze forks/zero issues; the one genuine external citation (modforge's
prior-art survey) calls it "wrong output target… tactical fallback… not a
primary pipeline" ([34](34-results-effectiveness-and-hygiene.md)). Against
LLM4Decompile's lesson — *measurement without provenance rots* — this dossier
adds the lower control arm: **assertion without measurement rots faster and
more visibly.**

**The steal direction is small but real: its Juliet line is the gift, and its
corpses are P42's checklist.** The corpus-prep scripts blind `good()`/`bad()`
labels and sample paired bad/good binaries per CWE — the paired-case eval
substrate P33 needs, shipped as corpus prep with no build step and no scorer:
the four-leg lesson in one folder. And 12 verified breakages with no CI ever
supply six mechanical P42 CI checks reverse-engineered from real defects
([40](40-comparison.md)). For calxgloss, which has no aggregate score (P33
open) and no CI (P42 open), this 1,390-line repo is the quantified cost of
both — at 200× the mass.

## Capability matrix (condensed — full 14-row table in [40](40-comparison.md))

Winner in **bold**. "—" = absent.

| Capability domain | LLM_Decompiler | calxgloss | Verdict |
|---|---|---|---|
| Decompilation front end | Ghidra headless (11.0.1 pin, EOL line) | Ghidra-derived dump + 15 evidence scans | split — the one genuine commonality, ending exactly at the dump |
| Where knowledge lives | 8 hardcoded prompt strings | scans, PAL/pattern/libmatch DBs, 57 ADRs | **calxgloss, by construction** |
| Context into the model | whole file, one shot, Θ(N²) name-map relay, zero budget code | 5-tier ladder, ADR-0055/0056 unknowns, P50 budgeting | **calxgloss** — one-shot is unbudgeted, not simpler |
| Inter-procedural ordering | Ghidra address order | call-graph-topological queue | **calxgloss** — the name map proves the need; a string solved it |
| Naming doctrine | renames pasted back verbatim | never applies; types-only write-back (ADR-0020/0021) | split by doctrine, asymmetric in consequence |
| Verification oracle | **zero** — nothing written is ever re-read | compile + Wine baselines + trace containment (ADR-0057), every attempt | **calxgloss — the null-hypothesis row** |
| State & retry | one-shot, silent except, no records | attempt branches, failure-informed retries, unknown ledger (ADR-0051/0056) | **calxgloss, non-negotiable** |
| Model layer | 8 hosted literals; 4/8 dead endpoints 2026-10-23 | local endpoint, config-only, token telemetry | **calxgloss** — the control ran the experiment we refuse |
| Evaluation substrate | Juliet prep w/ label blinding; no build/scorer/results — the scorer was a human at a desk | none (P33 open); per-unit receipts by construction | split — the only domain where calxgloss can't simply win |
| License & measured effect | unlicensed; 3★; claims never measured | MIT; no aggregate score, no claim to one | **calxgloss, by honesty posture** |

## What calxgloss should steal (aggregated — full argument in [40](40-comparison.md))

1. **Juliet's corpus shape for P33**: bad/good paired cases per CWE +
   label-blinding as fixture design; the meta-lesson "corpus + build + scorer
   ship as one unit or not at all" ([33](33-security-ctf-and-datasets.md) §7–§8).
2. **The modforge survey sentence as positioning intel**: the field's only
   external assessment — "all emit C… wrong output target" — records calxgloss's
   differentiator (output language + verification) at zero cost
   ([34](34-results-effectiveness-and-hygiene.md)).
3. **P42's concrete first CI battery — six checks reverse-engineered from this
   repo's twelve corpses**: exec bits vs documented `./script`, README setup
   vs HEAD reality, dead `mv`/`rm` targets, hardcoded personal paths, deps
   manifest, input-filename relay algebra ([20](20-llm-decompiler-inventory.md) §11).
   **Rejected**: whole-file one-shot prompting (unbudgeted Θ(N²) relay),
   paste-back renames + name-map (ADR-0020/0021 make write-back types-only),
   silent except→original fallbacks, hosted-model pinning.

## What LLM_Decompiler confirms about calxgloss's choices

- **Every gate earns its keep**: 27 months of observable consequences for a
  pipeline with every gate removed — the defect table is the itemized invoice
  for ADR-0057, ADR-0051, and the review UI ([40](40-comparison.md)).
- **"Model quality substitutes for infrastructure" died here first and
  verifiably**: the claims cite GPT-4's name; the code never even uses it —
  4/8 pinned endpoints are already dead ([34](34-results-effectiveness-and-hygiene.md) §3),
  vindicating the local-endpoint, config-only model layer.
- **Knowledge left as prose rots on the repository's own clock** — README→code
  drift on every command path — which prices ADR-0051's config-not-prompts
  doctrine and P42's existence.
- **Claims have a half-life when the repository is the evidence**: the
  27-month nullity of an unverified superlative is the case for verdict-bearing
  commits (P41) and for P33 done with provenance, not headlines.

## File index

| File | Domain |
|------|--------|
| [00-scope-and-method.md](00-scope-and-method.md) | scope, method, pinned HEADs, verified repo metadata |
| [10-calxgloss-baseline.md](10-calxgloss-baseline.md) | calxgloss capability inventory (comparison anchor, HEAD `40fbf91f`) + LLM_Decompiler comparison anchors |
| [20-llm-decompiler-inventory.md](20-llm-decompiler-inventory.md) | complete 30-file/1,390-line surface, model ledger, packaging negatives, 12-item staleness ledger |
| [21-history-and-releases.md](21-history-and-releases.md) | 26-commit archaeology, five-phase arc, secret-key forensics, delete/recreate case dance |
| [31-ghidra-harness-and-core-pipeline.md](31-ghidra-harness-and-core-pipeline.md) | analyzeHeadless call dissection, Jython postScripts, `decompile_pipe.sh`, `llm_d.py` prompt verbatim, stage-vs-stage table vs calxgloss |
| [32-large-codebase-reconstruction.md](32-large-codebase-reconstruction.md) | JSON path, `large_code_base_reconstruction.py`, name-map relay, Θ(N²) context ledger, helper_scripts trio |
| [33-security-ctf-and-datasets.md](33-security-ctf-and-datasets.md) | the five `analyze_*.sh` orchestrators, GPT-4o task drivers, CTF chain, Juliet label blinding + CWE sampling |
| [34-results-effectiveness-and-hygiene.md](34-results-effectiveness-and-hygiene.md) | `results/` vacancy, claims-vs-artifacts ledger, model/Ghidra currency audit, reception forensics |
| [40-comparison.md](40-comparison.md) | full 14-domain comparison, effect axis, convergences, steal list, confirmations, verdict |

## Citation notes

- LLM_Decompiler claims cite clone-relative `path:line` against
  `/tmp/opencode/LLM_Decompiler` at `c242671`; history claims cite
  `<short-sha> <path>`; web/GitHub-API claims cite fetched URLs (OpenAI
  deprecations page, PyPI, Ghidra/Jython tree probes, GitHub REST/GraphQL —
  all fetched 2026-10-31). calxgloss claims cite crate-relative paths
  (resolved under `crates/<group>/calxgloss-*/…`) at HEAD `40fbf91f`, or ADR
  numbers.
- Each chapter's own citations were machine-verified in-range by its author
  agent (ch20: 233 line-cites + 68 sha-cites; ch33: ~202; ch32: 69 explicit +
  ~90 bare; ch31: 85 + inline grep batteries). At assembly, a consolidated
  sweep of all nine files resolved 255 `path:line` tokens against the clone,
  **0 out-of-range**; the single unresolved token (`abix-/modforge
  falcon-printer/docs/survey.md:60`) is an external repo path, named as such
  in [34](34-results-effectiveness-and-hygiene.md) and [40](40-comparison.md).
- Cross-chapter slips corrected at assembly (7 edits): the claims-block birth
  commit (`cd00540`, not `9c64ffc`) in [21](21-history-and-releases.md) §6,
  a README commit count, and three over-cited anchors in
  [10](10-calxgloss-baseline.md). Secret forensics are reported by sha256
  digest and redacted shape only — no live key is reproduced anywhere in this
  dossier.
- Upstream note: the GitHub repo was renamed — the legacy `itsgizmo` URL 404s
  at `Lami99/LLM_Decompiler`'s history; the live remote == this clone (30
  files) ([40](40-comparison.md) Sources).

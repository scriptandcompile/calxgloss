# REA evidence + reconstruction methodology

> Part of the [REA overview](README.md). How REA makes a finding trustworthy —
> the Evidence envelope, unknown tracking, bundles, comparison tools, and the
> reconstruction conformance/verification machinery — compared against
> calxgloss's verification loop and review discipline. Providers and format
> decoders are in 31/32; not repeated here.

## What REA does

### The evidence contract

REA's *evidence contract* is the fixed record format that every
Evidence-producing tool must return. The record has four parts:
`normalized_result` (the operation data), `evidence_id` (a stable identity),
`raw_result` (a distinct provider representation, `null` when none), and an
always-present `analysis_profile` that participates in semantic identity —
omission is rejected (mcp-contracts.md:16–27). It carries **limitations,
coverage, and residual unknowns** as first-class fields
(evidence-workflows.md:6). Coverage is a fact owned by the producing tool:
`coverage.status ∈ {complete, unknown}` per collection, consumers reject
records lacking it, and "limitations are explanatory and do not supply or
infer coverage" (:37–57). A dossier's `facet_availability` map separates
"checked and not found" from "not checked at all", so `compare_functions`
keeps a dimension `unknown` for unavailable facets. An empty call list with
partial coverage "is not proof that the function has no calls"
(:59–84, 122–132).

**Retained-reference vs inline-evidence modes.** REA can return a full
record, or keep it in the session's Evidence ledger and return only a
summary that points back to it. `detail: "summary"` is the second mode: the
complete record stays in the ledger, the reply is a derived summary with
`parent_evidence_id`, and later questions read the record through
`inspect_analysis_view` without re-running the producer
(mcp-contracts.md:306–362; evidence-workflows.md:8–12). Comparisons accept
inline Evidence or a `{"kind":"retained-evidence","evidence_id":"ev_…"}`
reference per side (:452–475). References are kept in the *connection's*
ledger, which `close_binary` clears — "keeping only an Evidence ID across
close is insufficient"; export a bundle first (:477–495). A reply too large
for the pinned 10 MiB stdio budget returns `resource_constraint` with a
ready-to-call view continuation. The analysis "remains complete in the
ledger" (:134–152, 194–204).

**Compact schemas + error contract.** Advertised input schemas are re-projected
for weak clients: the default `REA_MCP_INPUT_SCHEMA_PROFILE=compact` renders
every schema under a 13,312-byte budget (below observed Moonshot/Kimi caps),
eliding nested validation detail on five oversized schemas while the canonical
server-side schema still rejects malformed calls (mcp-contracts.md:1058–1111).
Failures return `isError: true` plus a canonical `{error}` with code,
`partial_observation`, remediation, and bounded `recovery` that never invites
an unchanged repeat call (:91–120); a host timeout without a REA result means
"execution and cleanup remain unknown", and raising a client deadline cannot
extend REA's budget (:250–265). The skill binds the agent to the same posture:
conclusions must distinguish observations, inferences and unknowns, cite
Evidence IDs, and never "imply that static analysis observed execution"
(SKILL.md:387–390); comparison claims require "complete, compatible page sets"
(evidence-workflows.md:45–60).

### Unknown tracking: four tools, one ledger

`record_unknown` creates a deterministic residual unknown with immutable
mutation evidence — question, severity, domain, `required_authority` /
`required_confidence` / `required_environment` (what evidence *would* close
it), recommended probes, supporting/contradicting Evidence IDs; duplicate
stable identity is rejected (sessionToolContracts.ts:147–156).
`update_unknown` appends an immutable full-state revision guarded by
`expected_revision`; stale writers fail — reread "instead of retrying
blindly" (:157–161; evidence-workflows.md:38–43). `list_unknowns` pages
current heads deterministically, keeping unresolved, contradicted, and
non-truth dispositions distinct (:142–146). `verify_unknown_resolution`
revalidates the head against live bundle evidence, the declared
authority/confidence/environment requirements, and revision integrity —
**only qualifying observed evidence can verify a resolution**; withdrawn /
out-of-scope are not truth claims (:162–166; evidence-workflows.md:42–43).
Tools auto-record residual questions with the result's immutable Evidence ID,
deduped (mcp-contracts.md:225–229); an `audit_residual_unknowns` prompt drives
review (mcp-prompts.md:13–18), and the skill's findings ledger forbids calling
an investigation complete while required questions stay open (SKILL.md:424–431).

### Evidence bundles

`export_evidence_bundle` atomically writes the session's deterministic bundle
(canonical byte-stable ordering, `overwrite: true` required);
`import_evidence_bundle` validates every Evidence ID and canonical manifest,
then atomically merges — imported content "is data only and is never executed",
and failed validation leaves state unchanged (sessionToolContracts.ts:87–95;
mcp-contracts.md:85–89). `get_evidence_bundle` returns the whole retained
ledger plus unknowns, or `detail: "summary"` to discover records by exact
filters without payloads or starting a provider (sessionToolContracts.ts:167–171).
The purpose is **handoff**: sessions die, bundles survive — the release-compare
recipe is export `list_procedures` Evidence from each target *before closing
it*, import both bundles, then match (native-and-artifacts.md:3–12).

### Version & function comparison

**`match_native_functions`** pairs two retained inventories: unique exact
names first, then exact body bytes (every byte, equal size, unique SHA-256,
same known architecture — "extents are never guessed from the next entry").
Duplicates stay `unresolved` groups; `only_left/right` never prove
addition/removal; decompiling everything is never required, and matched dossier
pairs ship ready-made `compare_functions_input` (native-function-matching.md:
22–49, 81–84). **`compare_functions`** compares two explicit dossiers over
identity, exact provider text, calls, references, strings, address-normalized
CFG; `changed` text "establishes a textual difference, not a behavior change",
equal CFGs establish only equal block sizes/successors, cross-provider text
stays unknown (sessionToolContracts.ts:117–121; mcp-contracts.md:1138–1149).
**`compare_artifacts`** is in 32-native-artifact-intelligence.md.
**`compare_bundles`** diffs exported bundle JSONs by record membership,
observation pairs, and *complete residual-unknown revision histories*; missing
members "describe omission only, never behavioral equivalence"
(sessionToolContracts.ts:122–126); CLI alias `compare-bundles`
(cliCommandNames.ts:178, 190). **`find_changed_behavior`** aggregates validated
comparisons: runtime observations stay distinct from static candidates, missing
comparisons yield unresolved findings, "never causal claims"
(:127–131). **Bounded static traces**: `trace_call_path` reports limited
expansions in `residual_unknowns` — an unreached goal with an unresolved
expansion is `unknown`, not `not_reached` (mcp-contracts.md:128–132);
`trace_native_values` def-use traces are budgeted, alias/variadic/ambiguous
effects left unknown (native-investigation.md:252–302).

### Reconstruction conformance: coverage, readiness, obligation ledgers

REA's most distinctive layer — a machine-checkable notion of "reconstruction
done". REA's *obligation ledger* is the list of things the reconstruction must
prove, each marked open or closed:

- **Obligation ledgers** (`build_reconstruction_obligation_ledger`, CLI twin)
  turn authenticated Evidence into a deterministic claim list, *conservative by
  design*: static Application-Graph facts yield only *candidate* obligations. A
  **required** obligation closes only if one manifest binding supplies: unique
  owner + `owner_sha256`, the required parser/schema/domain type, case fixtures
  covering every declared `required_case_kinds` (positive / negative /
  malformed / cancellation / teardown), and a passing verifier whose authority
  is *comparable to the original observation*, enumerating the obligation ID,
  its result in the bundle. Contradictions, duplicate owners, residual
  unknowns, or unavailable authority keep closure open or failed; "a green unit
  test cannot close a `packaged-process` obligation", and `blocked`/
  `out-of-scope` "records the disposition but does not silently count it as
  verified" (reconstruction-obligation-ledgers.md:3–18, 226–321); the result is
  digest-sealed by `ledger_id` + `closure_digest` (:330–332).
- **Coverage evaluation** (`evaluate_reconstruction_coverage`) authenticates
  Evidence IDs and manifests, then checks each verifier result cites Evidence
  whose source/confidence matches the claim's declared *contract authority*
  (`controlled-replay` claims need `observed` replay Evidence) — "a passing
  verifier summary cannot promote inferred Evidence into a replay observation";
  that yields `unknown`, a missing or tampered record is an input error
  (reconstruction-coverage.md:9–30).
- **Readiness conformance** (`npm run verify:readiness`, repo-internal): a
  nine-stage report (discover-classify → … → verify-reconstruction-closure →
  export-replay); every stage and check occurs exactly once and links to
  Evidence; **"fail, unknown, unsupported, truncated, and skipped never
  aggregate to pass"**. Fail-closed rules withhold readiness when a bounded
  capability omits its limits, a typed CLI failure exits zero, truncation or
  contradiction is labeled equivalent, a divergence isn't localized, or "the
  reconstruction obligation ledger is not `ready` [...] or retains an
  unowned/unverified required obligation" (reconstruction-readiness.md:33–74).
  *Fail-closed* means: absence of qualifying evidence never defaults to pass —
  `unknown` blocks the verdict, and a deliberately faulty fixture proves every
  injected fault survives into the final report (:88–93).

### verify_reconstruction + the DX-Ball/TH04 methodology

`verify_reconstruction` "verifies a finite typed behavioral and structural
specification against a canonical Evidence bundle. Pass means every declared
claim has complete comparable authority — not global source equivalence;
changed claims fail and missing, limited, or unresolved evidence stays
unknown" (sessionToolContracts.ts:142–146; evidence-workflows.md:59). The
showcases show the methodology — **DX-Ball**: pseudocode → C reconstruction
passing **3,205 original-x86 cases** and reproducing **all 63 compiled
function bytes**; **TH04**: 16-bit PC-98 bullet-ring angle math recovered into
C++, compared against historical compiler output (README.md:246–253, 262–269).
Run the original binary over a case suite *and* check the recompiled bytes. REA
holds itself to the same standard: `docs/verification/` keeps 14 dated md+json
report pairs pinning commands, digests and measured costs —
gpu-code-objects-2026-10-21.md replays whole MCP workflows counting
tokens/RSS/ms per variant, and states what its validation *doesn't* establish.

### Limits & recovery design

`docs/design/limits-and-recovery.md` rules every REA-owned ceiling: name the
default constant, add a floor/max-bounded setting when operators need headroom,
never fall back silently from an invalid value (`configuration_invalid`), and
make the failure text name the limit, effective value, source, next action,
restart requirement, and *what the change does not raise* (:9–79); agents
follow `remediation.action` literally (:81–116).

## Comparison with calxgloss

### Direct mappings

| REA | calxgloss |
|---|---|
| Evidence envelope: coverage/facet availability + limitations + unknowns on every record | Evidence engines emit typed claims into prompts with no first-class limitations/coverage fields; honesty is left to the *reviewer*, not the data (10-calxgloss-baseline.md) |
| Justification discipline: cite Evidence IDs, keep a findings ledger (SKILL.md:387–390, 424–431) | Justification requirements enforced at commit + review UI (calxgloss-git, `calxgloss-web`) — same goal, different checkpoint: human gate vs per-record contract |
| Unknown ledger: record/update/verify with required authority + optimistic revisions | Failure records + retry strategies `compile_fix`/`test_fix`/`escalate`/`edge_case_fix`/`auto` (`docs/data_flow.md` §8): functions are tracked, but resolution = the retry compiled and passed tests — no statement of *what evidence would establish the fact*, nothing auditable after the run |
| Obligation ledger + coverage: declared case kinds, owner digest, comparable-authority verifier, `closure_digest` | Per-function unit of work + review queue + attempt branches: the branch commit *is* an owner with a content digest, the queue *is* an open-obligation list — but no case-kind requirements, no fail-closed "DLL complete" check, nothing digest-sealing overall status |
| `verify_reconstruction` over a hand-authored finite spec | `calxgloss-testgen` auto-derives the spec by FFI-calling the real DLL, `calxgloss-verify` compiles + runs. calxgloss's verifier has the *stronger* authority in REA's own table — `controlled-replay` at `observed` confidence (reconstruction-coverage.md:19–24) — running continuously, not once |
| Evidence bundles: portable, digest-validated, tamper-detectable handoff; `compare_bundles` history diffing | None. Git substitutes: attempt branches + scan read cache (`re/cache/<binary>/<sha256>/`) persist state — but carry no Evidence identity, no authentication, nothing diffable as claims + unknowns |
| Byte-identity claims (DX-Ball: 63 compiled bytes) | Excluded by construction: PAL mapping (tiny-skia/wgpu) makes identical machine code impossible |
| Verification receipts (md+json pairs pinning commands/costs/digests) | Verify results are pipeline-ephemeral; the attempt-branch commit is the only durable artifact of a verify pass |

### The philosophical clash

REA's flagship results chase **byte-exact reproduction**: DX-Ball isn't
trusted until all 63 compiled bytes match and 3,205 original-x86 cases pass
(README.md:246–253). That standard is total — byte identity subsumes behavioral
identity for that unit — but it suits single-function archaeology with a pinned
toolchain and generalizes to nothing portable. calxgloss picks the opposite
pole: "functional equivalence over binary precision," cross-platform output
verified by an FFI oracle against the original DLL (10-calxgloss-baseline.md).
Gains: whole-binary automation, real portability, a verifier needing no
human-authored spec. Costs: equivalence is only as wide as the generated tests
(an un-called export stays `unknown` in REA's terms, yet the pipeline counts
the function translated), and no claim can exceed "passed the baseline cases."
REA's own contracts concede the same wall — `changed` text ≠ behavior change, a
`verify_reconstruction` pass "covers only declared comparable claims, not
global equivalence" (mcp-contracts.md:1140–1144; evidence-workflows.md:59–60).
The difference is cultural: REA advertises byte-exactness as the showcase gold
standard; calxgloss's principles forbid even wanting it.

### calxgloss-only / REA-only + verdict

**calxgloss-only:** closed auto loop (LLM → compile → FFI-test → retry);
baseline capture by *executing the original DLL*; 11+ batch evidence engines;
type write-back; PAL + restitching; review UI adjudication; failure-informed
retries; fault monitors. **REA-only:** unknown ledger with authority-gated
resolution; obligation ledgers + fail-closed conformance evaluator; portable
authenticated Evidence bundles + history diffing; byte-identity claims; dated
verification receipts; the comparison tool family; limits/recovery contracts.

On *verification execution* calxgloss is ahead: it runs the real DLL, sends
the captured baselines straight into a compile-test loop, and never needs a
human to author claims. On *verification bookkeeping* REA is far ahead: it can say, in
digest-checkable machine terms, which claims are open, who owns them, what
evidence would close them — and refuse to call the whole thing done. calxgloss
cannot currently distinguish "DLL fully translated" from "pipeline stopped with
nobody complaining"; that gap is REA's fail-closed ledger.

### Steal ideas

1. **First-class unknown record surfaced in the review UI.** Per function,
   emit what the evidence engines couldn't determine (ambiguous vtable target,
   unresolved this-pointer, un-called export) with `required_evidence` text, in
   REA's record/update/verify shape (sessionToolContracts.ts:147–166):
   reviewers resolve them, `escalate` retry strategies read them, and the run
   leaves an audit trail instead of silent gaps.
2. **Obligation ledger for restitching status.** Per unit of work: owner =
   attempt-branch commit digest; required case kinds (positive/negative/
   malformed — testgen can already classify its inputs); verifier =
   `calxgloss-verify` result + its evidence digest; seal whole-binary status
   with a `closure_digest` (reconstruction-obligation-ledgers.md:226–332).
3. **Fail-closed completeness check before declaring a DLL done.** Adopt
   reconstruction-readiness.md:47–74's aggregation rule: skipped, parked
   (ADR-0044), overridden, or un-reviewed units *never aggregate to complete*;
   an export with no generated baseline case stays `unknown` — turning the
   dashboard's "queue empty" into a real conformance verdict.
4. **Evidence-limitation fields on evidence-engine output.** REA's
   `coverage.status` + `facet_availability` pair (mcp-contracts.md:37–84):
   `libmatch` says "signature match, version unknown", `typesdb` says "vtable
   scan unavailable here" instead of reporting nothing — prompts and reviewers
   never read inferred as observed.
5. **Verification receipts: md+json pairs per verify run.** Store
   `calxgloss-verify` outcomes as digest-paired receipts on the attempt branch
   (commands, case counts, timings), à la `docs/verification/` — durable,
   machine-diffable justification for accepted commits, `compare_bundles`-style
   diffable between attempts.

## Sources

REA (`/tmp/opencode/rea`, commit 28a33ca): `docs/mcp-contracts.md` (tool
results, retained Evidence, schema advertisement, function-comparison
limitations; per-tool schemas skipped);
`.agents/skills/reverse-engineer-anything/references/evidence-workflows.md`
(full) + `SKILL.md:347–452` + `references/native-and-artifacts.md`
(release-compare routing only); `docs/native-function-matching.md`,
`docs/reconstruction-{coverage,readiness,obligation-ledgers}.md`,
`docs/design/limits-and-recovery.md` (full);
`docs/native-investigation.md:252–302`;
`src/contracts/sessionToolContracts.ts:87–171`,
`src/contracts/unknownContractExamples.ts`, `src/cliCommandNames.ts`;
`docs/mcp-prompts.md`; `README.md:242–274`;
`docs/verification/gpu-code-objects-2026-10-21.md` (skimmed; 14 md+json report
pairs in `docs/verification/`).

calxgloss: `docs/rea/10-calxgloss-baseline.md`, `docs/rea/20-rea-inventory.md`
§4, chs. 31/32, `docs/data_flow.md` §8, ADR-0044.

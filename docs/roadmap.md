# Calxgloss Roadmap — Methodology Tracks

> **Purpose:** index of all open tracks — status, dependencies, and what's
> next. This is the *roadmap*, not the plan of record for active work.
>
> **Where plans live:** when a track is picked up, its detailed plan is
> published to GitHub Issues (`scriptandcompile/calxgloss`) via `/to-spec` →
> `/to-tickets` (tickets carry native blocking links + triage labels), and the
> epic link is added to the status matrix below. `/implement` works the
> tickets; `CHANGELOG.md` stays the record of what shipped.
>
> **Where done tracks go:** a completed track is removed from this roadmap —
> its shipped history lives in `CHANGELOG.md` and its key decisions are
> recorded as ADRs in `docs/adr/` (W0 → ADR-0002, W1 → ADR-0003, W2 →
> ADR-0004, W3 → ADR-0005, W4 → ADR-0006, G1 → ADR-0007, X2 → ADR-0008,
> P1.5 → ADR-0009–0013, X5 → ADR-0041).

## How a track gets built

1. Pick the next unblocked track from the matrix (table order = priority).
2. `/to-spec` — synthesize the track summary here (plus its archive section)
   into a spec issue.
3. `/to-tickets` — decompose into tracer-bullet tickets with blocking edges;
   label `ready-for-agent`.
4. `/implement` — drive the tickets (tdd + code-review per ticket).
5. Update this matrix when a phase completes.

Test counts in the archive are indicative targets, not exact requirements.

## Status matrix

| # | Track | Crate | Effort | Status | Next step | Epic |
|---|-------|-------|--------|--------|-----------|------|
| P18 | Binary-version diffing (BinDiff-style) — pair functions across binary versions by structural similarity so accepted translations carry over and only changed functions re-enter the queue | evidence (`calxgloss-bdiff` (new)) + pipeline (`calxgloss-translator`, `calxgloss-git`) + interface (`calxgloss-cli`) | — | 🔶 in progress | #296 normalized-body pairing family | [#233](https://github.com/scriptandcompile/calxgloss/issues/233) |

Legend: ✅ done · 🔶 in progress · ⬜ not started.

## P18 — Binary-version diffing (BinDiff-style) (evidence + pipeline + interface)

**When the target updates, the harness treats the new version as a brand-new
target.** Function names are address-derived and addresses shift between
versions, so the (dll, function) join key — attempt branches, the review
queue, baseline suites — almost never matches across versions: every unit
re-enters the queue from zero, including functions whose bytes are identical,
and accepted merged translations are silently orphaned. A new evidence crate,
`calxgloss-bdiff`, runs a document-level pairing pass when a binary's bytes
change: the scan cache keys on identity + SHA-256 of the file bytes (ADR-0043),
so the previous version's scan document is already on disk, and the pass reads
only the two cached scan documents — no new seam methods (ADR-0026), no
write-back (ADR-0020), no LLM. Pairing is a strongest-wins ladder: name
identity (exported/demangled exact match, 95), normalized-body structural
equivalence (riding the shared normalizer P14/#227 shipped and now owns —
`calxgloss-libmatch`'s `normalize` module), and call-graph topology
propagation over already-paired neighbors (ADR-0024's rails; 70, two paired
neighbors required, a lone paired neighbor claims nothing; corroboration bumps
beat any single reading). Pairings are one-to-one — best wins, ties keep first
seen in scan order (ADR-0028's precedent) — and one pairing document per
(identity, old hash, new hash) persists under the analysis-directory convention
(ADR-0043) as a new file, so every existing artifact loads unchanged. Consumer:
the auto run's queue — a new function paired at ≥80 to an old function with a
merged branch gets its first attempt seeded from the accepted translation (a
standard attempt branch under the new name, pre-populated with the accepted
code) and verification re-runs against the new version's freshly captured
baseline — the translation carries, the ground truth does not; below-floor or
unpaired functions queue fresh, today's behavior exactly. A CLI breakdown
command lists pairs, scores, families, and one-sided-only functions. The
record shape — (function, function, confidence, family, evidence) — is chosen
so the sibling-seeding follow-up (seeding a machine attempt from a
near-identical accepted sibling within one scan) needs no re-derivation.
Spec: #233. Tickets: #294–#300 filed (`/to-tickets`); #294 and #295 shipped, #296 next.

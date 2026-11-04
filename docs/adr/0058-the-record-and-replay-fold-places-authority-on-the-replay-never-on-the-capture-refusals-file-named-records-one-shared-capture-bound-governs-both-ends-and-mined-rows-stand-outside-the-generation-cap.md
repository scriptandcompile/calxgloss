# ADR-0058: The record-and-replay fold places authority on the replay, never on the capture — refusals file named records, one shared capture bound governs both ends, and mined rows stand outside the generation cap

- **Status:** Accepted
- **Date:** 2026-11-04 (P23 shipped, epic #390, slices #395–#401)
- **Deciders:** Arthur (solo project)

## Context

Track P23 closed the gate's blind spot of invented inputs: testgen built every
baseline case's argument vector from signatures plus type evidence, and a real
caller's vectors never entered the suite. Two input lanes shipped on one shared
machinery — the **hook lane** (entry hooks arming the baseline run's export
entries, a generated **recording proxy** wearing the target's binary identity
for **reference-app runs**, and the `capture` command driving them under
budgets and an **ownership token**) and the **minidump lane** (Windows crash
dumps claiming a **captured call entry** only where the dump's module matches
the target by binary identity *and* the fault lands exactly on a listed export
entry). The **record-and-replay fold** decodes each entry against the export's
parsed signature, replays the vector against the original binary through the
existing ground-truth walk, and files what the replay observed as a mined case
in the filed baseline suite.

The lane records *what really arrived*; it does not observe what the target
*did* with the values. Deciding where authority, honesty, and refusal live was
the track's real design work.

## Decision

- **Authority rests on the replay, never on the capture.** A captured call
  entry is trusted to name *inputs* only. The expected return, side-effect
  trace, and API trace of a mined case are observed by replaying against the
  original — never read off the recording. A capture that ran, and a dump that
  faults, prove a call happened; only the replay proves what it produced.
- **Authority is read off the case-origin stamp, never stored beside it.**
  Every baseline case carries a *case origin*: *generated*, or *mined-hook*
  naming its capture id and event sequence, or *mined-minidump* naming its
  dump digest and faulting thread. The strongest claim a passing case supports
  — controlled-replay at observed confidence, the claim P25's receipts and
  P26's ledger will cite — is read off the origin at read time: there is no
  second field that can rot against the first.
- **Refusal is recorded, never silent, never fabricated.** The fold's refusal
  vocabulary is closed — float-argument (scanned at the raw level before any
  typed parse could hide the reason), no-parseable-signature,
  unmaterializable-pointer, truncated-capture, argument-shape-not-in-signature
  — and each refused entry files a `capture_refused` unknown record at its
  `{capture}#{event}` slot naming its reason. A replay that faults files a
  *crash-reproduction record* naming the event and no case: the capture is
  trusted to name inputs, never to promise the target survived.
- **One shared capture bound governs both ends of the fold.** The 64 KiB
  pointer ceiling is a single shared protocol constant, spelled from that
  constant at codegen, honored at record time (the entry-hook probe and the
  proxy shim capture only bytes from verified committed memory, capped and
  flagged truncated) and at replay time (a descriptor claiming more than the
  bound, or bytes short of its observed size, refuses as a truncation naming
  the bound). A truncated buffer never silently becomes a full one at replay;
  a pointer descriptor with no captured bytes at all is the one shape no
  replay can honor, refused by name.
- **Mining is additive: twins dedup, order is fixed, and mined rows stand
  outside the generation cap.** A mined vector equal to a generated case's
  dedups to one filed row, the collision keeping the *stronger* mined origin;
  the suite never pads. Filed order is generated rows first, mined rows after
  in first-seen capture order, and a repeat ingest is byte-stable. The
  per-function case cap bounds *invention*; captured events are evidence, so
  mined rows are exempt from it.
- **The fold is the standing `ExportUncovered` closure mechanism.** Once a
  mined replay files a suite for a previously uncovered export, the next
  ledger write closes that export's gap while every other gap stands. Batch
  ledger writes carry capture-origin records they never re-derive — a named
  fact that landed is never silently dropped by a later write.
- **The capture lanes inherit ADR-0057's honesty line: events are never
  faked.** Entry hooks and proxies are x86-64 only; elsewhere the baseline run
  compiles uninstrumented with an admitted coverage note and proxy generation
  admits defeat instead of producing a proxy.
- **The replay seam pins without Wine.** In production the fold's replay seam
  is the Wine baseline harness; the standing end-to-end pins drive the whole
  walk — event log in, filed suite out — against a fake seam at testgen's
  filed-baseline seam, so every build machine pins the fold. The real-DLL,
  Wine-gated tests live behind the existing `#[ignore]` gate and prove the
  trampolines record and the replay files for a live fixture DLL.

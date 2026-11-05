# ADR-0059: The scenario lane files one current document per (binary, scenario)

- **Status:** Accepted
- **Date:** 2026-11-04 (P24 shipped, epic #391, slices #402–#409)
- **Deciders:** Arthur (solo project)

## Context

Track P24 gave EXE targets a verification signal the FFI gate can never
reach. `target_dir` holds executables whose behavior — stdin, TUI, windowed
flows, written files, child processes — no export-call harness touches. The
track adopted REA's process-capture contract as the *scenario contract*:
working dir, explicit env, argv, scripted interactions, terminal geometry,
observation paths, idle and max-run windows, output caps, versioned
normalization, and finalization grace. The track grew the lane in seven more
slices: the console fixture EXE (#403), the first *scenario capture* (#404),
hung runs named by their windows plus process-tree sampling (#405),
interactions and *rendered states* with sensitive inputs as byte-count
placeholders (#406), the five-dimension *scenario verdict* (#407), the
*scenario replay* against any program named by path (#408), and the
*scenario status* on the review surfaces (#409).

Two framings did most of the design work. The record lane's file protocol had
to be nailed down before P25's receipts and P26's ledger could cite it by
digest. And the review surfaces had to state scenario evidence without
starting to decide with it — the same line the *unknown ledger* holds.

## Decision

- **One current document per (binary, scenario), replaced outright.** The
  contract set files at `re/scenarios/<binary identity>.json` — one document
  per target binary, its scenarios keyed by name. The capture files at
  `re/scenarios/captures/<binary identity>-<scenario key>.json`, and the
  replay files beside it as `<binary identity>-<scenario key>-replay.json`.
  The verdict files at `re/scenarios/verdicts/<binary identity>-<scenario key>.json`.
  Nothing is versioned and nothing is appended: a re-declare,
  re-capture, re-replay, or re-compare replaces the document that stood.
  Every reader — the CLI, the comparator, the dashboard — reads that one
  path. There is no second copy of the truth to drift. The file-name fold
  (`scenario_file_key`) keeps every declared name inside its directory.
- **Interface owns authorship. Pipeline and testgen only read these
  documents.** The scenario contract is authored by the operator through the
  CLI's `scenario declare`, not by the pipeline. The rest of the record tree
  is written by the tracks that produce it. This lane is the exception, and
  it is deliberate: the contract is a declaration of intent. Intent the
  pipeline invented would be a claim nobody made.
- **The file envelope is part of the protocol, not a label.** A *scenario
  capture* names only its scenario inside. The binary it describes rides in
  its file name, so the read side recovers the binary by peeling the
  scenario's own key fold off the envelope. The exact-name reading comes
  first: a scenario genuinely named `boot-replay` stays itself instead of
  reading as a replay of `boot`. Contract and verdict documents must speak
  for the binary their envelope names. A document whose envelope disagrees
  with its content is named and skipped, never attributed to a guess.
- **The comparator is pure record logic.** Input: two *scenario captures*
  plus the filed *scenario contract*. Output: the verdict. `compare_captures`
  launches nothing, looks for no Wine, and reads captures from whichever
  paths are named. The obvious shape — weigh two live runs against each
  other — was refused so the whole rule set pins on every build machine. The
  pinning is itself the proof nothing launches. Live-run behavior pins
  separately, behind the Wine gate.
- **Normalization gates pairing. Program bytes never do.** Only the
  contract's declared, versioned normalization rules ever equalize a pair.
  The verdict states the version it judged under. A pair stamped under
  different versions — or unstamped at all — is refused by name rather than
  silently bridged. Program bytes ride beside the pair without gating it.
  Original-against-restitched is the entire point of a replay, so differing
  program digests pair. The verdict carries both *pairing rule* blocks
  stating what ran against what. Fired caps, mismatched Wine versions, and
  files outside the declared observation paths ride as stated residual
  unknowns. Any one of them blocks the document from claiming complete
  equivalence.
- **Silence never launders a pass, continuing ADR-0053 → ADR-0057 →
  ADR-0058.** Each of the five dimensions — terminal, interaction, exit,
  filesystem, process — reads assessed pass, assessed fail, or unassessed.
  An absent or empty block reads unassessed: never a pass, never a failure
  by silence either. Every failure names its divergent field with both sides
  beside it. A thing one side never produced stands named absent rather than
  defaulted — pids are run accidents and never a divergence. The review
  surfaces' *scenario status* is the read-side mirror of the filed verdict.
  It invents no reading the document does not carry.
- **Scenario evidence is target-binary-level evidence: it reports and never
  decides.** A filed failing verdict changes no unit's review status, files
  no review action, and blocks no accept. The pinning stands at the web e2e
  seam and at the CLI's terminal print — the same way the *unknown ledger*
  reports without deciding. Wiring a failing scenario verdict into the
  send-back and conformance machinery is the decision side of the line. That
  wiring is held for P26/P27 and deliberately kept out of the surfaces.
- **Nothing sensitive and nothing unowned reaches a record.** A
  `--secret-at` interaction files a byte-count placeholder only. The *typed secret*
  is alive for one run, and it must match its placeholder's offset
  and count exactly or be refused before anything launches. It reaches no
  terminal chunk and no filed document. Observation paths are refused when
  absolute or when they climb out of the run dir. Finalization reaches the
  process only through the *ownership token*: SIGTERM first, the declared
  grace to end on its own, SIGKILL past it. A pid answering to a different
  identity than its launch bound is untouched, with the record saying so by
  name.
- **The verdict's content digest is the citable handle.** The digest is
  sha256 over the document's own JSON with the digest field blanked, and it
  cites the two captures it judged by theirs. P25's receipts and P26's
  obligation ledger cite a scenario verdict by that digest. The verdict
  document is what makes an EXE claim citable at all.

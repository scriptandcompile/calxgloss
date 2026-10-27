# ADR-0052: One CLI scan command rides the registry's descriptor rows — each engine contributes one CLI-side entry, engine loading folds into the generic command, and force-rescan rides the overwrite policy

- **Status:** Accepted
- **Date:** 2026-10-25 (P39 shipped, issues #338–#343, spec #337)
- **Deciders:** Arthur (solo project)

## Context

P34's evidence-scan registry (spec #301, shipped #302–#309) made the
pipeline's scan phase descriptor-driven: every scan enters through one row
— name, document location, evidence engine build, persist, warn-and-continue
degradation, cached-hit short-circuit — and the registry's own docs said the
table is public because "the later generic CLI scan command (P39) iterates
these same rows." The CLI never used the table. All fifteen scan
subcommands (`typesdb`, `typeinfer`, `algorithm`, `memory`, `libmatch`,
`sync`, `globalstate`, `consts`, `callback`, `controlflow`, `stringctx`,
`apidetect`, `serialize`, `errhandling`, `floatsimd`) each had its own clap
variant block, its own 150–570-line command module, and its own
`main.rs` match arm, and every module wrote the same body again: resolve the
workspace, load the analysis engine, build the evidence engine, scan,
persist through the engine's own persistor, print a report. Only the report
printer and a handful of per-engine flags were genuinely per-engine
knowledge. A contributor adding an evidence engine had to touch the
pipeline's registry **and** hand-write a whole CLI module from scratch — and
the two hand-written versions could drift; they already had once (the
`libmatch` drift, spec #301). ADR-0050 had also left a line standing: "P39
folds engine loading." — the generic command would load the analysis
engine once for all commands.

The shape decisions worth fixing: whether the CLI writes the scan shape out
again or consumes the registry's rows; what stays per-engine at the CLI and
where it lives; where analysis engine loading happens and what it honors;
whether the CLI adopts the scan phase's cached-hit short-circuit or keeps
force-rescan (Interface's word for the same act is *refresh cache*); and how
the two rosters — registry rows and CLI commands — are kept from drifting.

## Decision

One generic command at the CLI reads the registry's own table; per-engine
knowledge shrinks to one contribution entry; the two rosters are checked
one-for-one.

- **One CLI scan command reads the registry's descriptor rows.**
  `crates/interface/calxgloss-cli/src/commands/scan_command.rs` holds one
  generic handler (`handle_scan_command`) that resolves the entry's row
  from the registry's public `scan_rows()` table and runs it end to end —
  evidence engine build, scan, persist, degradation wording, document
  location — the same rows the scan phase runs, so those facts have exactly
  one definition across both interfaces. `main.rs` keeps one match arm that
  sends all fifteen scan variants through the handler's row table; `bdiff`
  stays its own pure-report arm — it has no row to use, no scan, and no
  analysis engine read.
- **Each evidence engine contributes at the CLI exactly one entry in a
  contribution table keyed to its row.** A `ScanContributionSteps` states
  which registry row it serves and supplies the four genuinely per-engine
  steps: the cached-document loader (through the engine's own persistor,
  with remediation wording naming the exact command that produced the
  document), the report printer, the derivation of `ScanRunOptions` from
  the command's parsed clap flags, and an optional post-scan step over the
  retained analysis engine source and the entry's own document — plus a
  `show_loads_program` answer for the `--show` path. The clap variant blocks
  and help text stay untouched; only the flag *interpretation* moves into
  the entry. Type erasure mirrors the registry's own
  (`ScanContribution::new`), so loader and printer always share one document
  type and a downcast miss surfaces as an error, not a panic. Printers
  consume the persisted document: after a run the generic command reads the
  freshly filed document back through the entry's own loader — the accepted
  extra disk read that makes the run's report and a later `--show` report
  the same read of the same document, byte-identical.
- **Analysis engine loading is moved into the generic command,** doing what
  ADR-0050 left for P39: one Kuna load that reads the settings and honors
  the `[analysis]` per-function budgets, wrapped as the pipeline's shared
  read source — the fifteen duplicated load sites and their error wording
  are gone. Loading happens only when a step actually reads the program:
  `--show` alone never loads the analysis engine; `--show --write-back`
  does. A one-shot CLI run hands the row empty completion latches (it
  orders itself with nothing); the callback-detection row's own pre-scan
  hook builds its content from cached documents regardless, so the CLI
  keeps that enrichment with no new mechanism.
- **The CLI keeps force-rescan semantics through the descriptor's
  overwrite policy** (issue #338's
  `ScanRunOptions.overwrite_filed_document`) **rather than adopting the
  scan phase's cached-hit short-circuit.** A scan command always re-scans;
  a failed re-scan still leaves the previously filed document in place,
  because only a successful scan saves. Per-run options reach evidence
  engine construction through the run entry point `run_with_options`,
  interpreted inside each row's own build step — the set-file override
  serving `algorithm --patterns` / `libmatch --signatures`, and write
  suppression serving `typesdb --no-tag` — with no evidence-engine-named
  vocabulary entering the shared shape; the scan phase keeps calling
  `run(ctx)` with default options, so the shipped machinery — the fan-out
  window (how many evidence scans run at once), the completion latches, and
  the heartbeats — and its locking tests are untouched.
- **The two rosters are checked one-for-one at the data level.** A pairing
  check reads the contribution entries' own row names against
  `scan_rows()`' own roster and spells every drift as a returned fault: a
  roster row with no CLI entry, an entry naming a row outside the roster,
  or two entries crowded onto one row. Three tests sit on that check: the
  green one-for-one pass over fifteen entries and fifteen rows, and two
  fault fixtures proving each drift direction. The behavior suite runs
  exactly the entries the pairing reads, so a green pairing means every
  evidence engine in the roster is exercised through the generic handler. A
  grep-based source check was rejected: the check is at the data level (a
  confirmed seam decision), and it is discoverable from either side by
  documentation cross-reference.
- **One descriptor now serves two interfaces,** so "add an evidence engine"
  is finally one registry row plus one small contribution entry — the
  doctrine that caught the `libmatch` drift, extended to cover the CLI
  half.
- **The seams stay two.** P39 uses the scan-descriptor *write* seam's
  table; it does not merge it with ADR-0048's projection *read* seam.
  On-disk document paths, formats, and locations are untouched (ADR-0043's
  document discipline), and the scan read cache (`re/cache/`) is left
  exactly as it is — making cache keys name the analysis engine build
  stays P20's decision.

## Consequences

- Operator-visible behavior is unchanged for all fifteen commands — same
  `--binary` requirement, same clap help text, same failure and degradation
  wording byte-for-byte, same reports, same force-rescan and `--show`
  contracts, same `--patterns`/`--signatures`/`--no-tag`/`--write-back`
  workflows. The whole behavior suite asserts only outward results: document
  filed at the row's own `document_path`, report printed, `--show` failure
  naming the command that produced the document, force-rescan over a filed
  document, and a failed rescan leaving the previous document intact —
  driven over every command that goes through the generic handler at once,
  so a change to the generic command trips a test for every evidence
  engine.
- The fifteen command modules collapsed to their contribution entry plus
  printer (the old `handle_*` bodies and per-module load/scan/persist/save
  plumbing deleted, printer tests moving with the printers), and the fifteen
  `main.rs` scan arms to one; the CLI test suite stands at 82 unit tests,
  6 tests against the real analysis engine, and 5 scan-command process
  tests.
- P19's coverage/limitation fields now have exactly one per-engine home:
  the report printer inside the evidence engine's contribution entry.
- Contributor contract: adding an evidence engine means one registry row
  plus one `ScanContributionSteps` entry (and its clap variant); a row
  without a CLI entry, an orphan entry, or a crowded pair fails the pairing
  tests loudly, exactly as the registry's roster test guards the scan
  phase.
- Type-inference write-back stays deliberately outside the descriptor — a
  CLI post-scan step over the retained analysis engine source through the
  type-inference crate's own write-back API, on both the scan path and the
  `--show` path — so descriptor machinery never takes on
  operator-workflow concerns.

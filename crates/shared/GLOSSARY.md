# Shared

The exchange currency of the reverse-engineering effort: the records every context reads and writes, and the settings that say how the whole harness behaves. Nothing here owns a domain — the words below are the carriers, not the meanings. The meanings live in the contexts that speak them.

## Language

### Records

**Progress event**:
A pipeline milestone announced verbatim. The log file, the live view, and the dashboards all read the same event names, and none are invented downstream.

**Master-plan phase**:
One of the eight segments of the original plan the phase bar renders; the vocabulary is fixed, and a segment with no backing data says so as its own state.
_Avoid_: confusing master-plan phases with a unit's in-flight steps

**No data source**:
The honest phase state meaning *this progress cannot be known*, never faked as not-started or complete.

**Heartbeat**:
The working pass's latest touch. It proves the run is alive without asking the run a question.

**Live state**:
What the pipeline is *doing* right now — as distinct from the dashboard, which shows what a unit *achieved*.

**Run state machine**:
The one shared record of whether the run is idle, running, paused, stopping, complete, or errored. Every control acts on it. An illegal transition is refused, and the refusal names it. The run itself is Pipeline's concept; the state machine record lives here.

**Control handle**:
A cloneable handle to a run that can be passed across threads. It covers stop, cancel-current, and run-request. All three are modeled on the stop signal: set it, and it takes effect at the next safe point.

**Dashboard model**:
A unit's review-facing state, *derived* from branch state and rebuilt fresh every time. That is why reviewer intent lives in separate persisted overlays, never in the derived state.

**Overlay record**:
The persisted form of reviewer intent — queue ordering, skips, overrides — surviving every rebuild.

**Review status**:
Where a unit stands on the dashboard. Notably, a reviewer's *skipped* and a classification's *do-not-translate* are different states, and neither one clears the other.

**Staleness**:
The age bands on a unit's review state — fresh, stale, critical — because waiting work degrades.

**Work kind**:
What sort of tracked work a row is. Only function translation is a *unit of work* in the strict sense. The other kinds (classification, shims, PAL, tests, integration) are ordered ahead of it.

**Confidence**:
The shared record type holds the 0–100 integer of evidence confidence. Unit confidence is Pipeline's separate scale and does not travel through this type.

**Unknown record**:
The one shared shape for an unanswered question about a target binary — plus the function, where the gap is function-specific: a kind from a closed roster, a severity from a closed scale, one bounded question line, one bounded required-evidence line, the origin it was derived from, and a revision every write is checked against. Consumers render its stored wording; they do not restate it.
_Avoid_: gap — *known gaps* is Pipeline's free-text limitations carrier, a different thing; hole, concern

**Unknown ledger**:
The pipeline's per-target-binary document of unknown records, `re/unknowns/<binary identity>.json`. Its filing envelope — the binary it speaks for and when it was filed — is how a reader tells a filed ledger from a stray document.

**Reviewer resolution**:
The reviewer's answer to one unknown record, bound to the record's id: a disposition — *resolved* or *dismissed* — a bounded reason, and the revision it was written against. It persists in the reviewer's own resolutions document and survives every derived rebuild; a reopen is a durable mark, not a deletion.

### Settings

**Settings layers**:
Flag, then environment, then config file, then built-in default — most specific wins, so a one-off always overrides and a machine is described only once.

**Source**:
The layer a value came from, carried alongside the value — what makes layered configuration debuggable, and what the config command shows.

**Config file**:
The project's `calxgloss.toml` beside the workspace, with a machine-wide file under the user config directory; a `--config` path must exist.

**Environment layer**:
Settings named after their file section — one variable per key; set-but-empty counts as absent.

**Unknown-key refusal**:
A misspelled setting fails loudly at parse time, naming the bad key, rather than surfacing later as mysterious default behavior.

**Record tree**:
The effort's on-disk memory under the workspace's `re/` — classification, analysis documents, reviewer intent, patches, and the caches each owner writes. Each owner names its own location, and each document has exactly one owner: the unknown ledgers under `re/unknowns/` are the pipeline's documents, the reviewer's resolutions at `re/review/unknown_resolutions.json` are the reviewer's. No one reads another owner's files by guessing paths.

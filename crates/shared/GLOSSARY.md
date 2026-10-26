# Shared

The exchange currency of the reverse-engineering effort: the records every context reads and writes, and the settings that say how the whole harness behaves. Nothing here owns a domain — the words below are the carriers, not the meanings, which live in the contexts that speak them.

## Language

### Records

**Progress event**:
A pipeline milestone announced verbatim — log file, live view, and dashboards all read the same event names, with none invented downstream.

**Master-plan phase**:
One of the eight segments of the original plan the phase bar renders; the vocabulary is fixed, and a segment with no backing data says so as its own state.
_Avoid_: confusing master-plan phases with a unit's in-flight steps

**No data source**:
The honest phase state meaning *this progress cannot be known*, never faked as not-started or complete.

**Heartbeat**:
The working pass's latest touch, proving the run is alive without asking it a question.

**Live state**:
What the pipeline is *doing* right now — as distinct from the dashboard, which shows what a unit *achieved*.

**Run state machine**:
The one shared record of whether the run is idle, running, paused, stopping, complete, or errored — every control acts on it, and an illegal transition is refused by name. The run as a domain concept is Pipeline's; the machine carrying it is here.

**Control handle**:
The cloneable cross-thread grip on a run — stop, cancel-current, run-request — all modeled on the stop signal: set it, and it takes effect at the next safe point.

**Dashboard model**:
A unit's review-facing state, *derived* from branch state and rebuilt fresh every time — which is why reviewer intent lives in separate persisted overlays, never in the derived state.

**Overlay record**:
The persisted form of reviewer intent — queue ordering, skips, overrides — surviving every rebuild.

**Review status**:
Where a unit stands on the dashboard; notably, a reviewer's *skipped* and a classification's *do-not-translate* are different states, and neither clears the other.

**Staleness**:
The age bands on a unit's review state — fresh, stale, critical — because waiting work degrades.

**Work kind**:
What sort of tracked work a row is — only function translation is a *unit of work* in the strict sense; the other kinds (classification, shims, PAL, tests, integration) order ahead of it.

**Confidence**:
The shared record type carries the 0–100 integer of evidence confidence. Unit confidence is Pipeline's separate scale and does not travel through this type.

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
A misspelled setting fails loudly at parse time, naming the offender, rather than surfacing later as mysterious default behavior.

**Record tree**:
The effort's on-disk memory under the workspace's `re/` — classification, analysis documents, reviewer intent, patches, and the caches each owner writes. Each owner names its own location; nothing reads another's files by guessing.

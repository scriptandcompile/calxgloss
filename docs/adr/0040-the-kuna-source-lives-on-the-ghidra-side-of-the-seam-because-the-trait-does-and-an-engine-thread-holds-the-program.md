# ADR-0040: The Kuna source lives on the Ghidra side of the seam because the trait does, and an engine thread holds the !Send program with every call guarded

- **Status:** Accepted
- **Date:** 2026-10-16 (X5-#206 shipped, epic #203)
- **Deciders:** Arthur (solo project)

## Context

X5-#206 builds `KunaSource`, the read seam (ADR-0039) over an
in-process Kuna `ConsoleProgram`. Two constraints collide:

- The `ScanSource` trait lives in `calxgloss-ghidra`. It speaks
  `GhidraError` and `DecompileResult`, and `PipelineSource` — the
  pipeline's analysis engine choice — lives there too.
- Kuna's `ConsoleProgram` is `!Send + !Sync`, and the acceptance
  criterion is that an analysis engine panic must surface as a named
  error at the seam, never abort the process.

A natural instinct is to put `KunaSource` in `calxgloss-kuna` and have
it implement the trait. Cargo rejects that: it would make
`calxgloss-kuna` depend on `calxgloss-ghidra`, and `calxgloss-ghidra`
already depends on `calxgloss-kuna` (the `PipelineSource::Kuna`
variant needs the type) — a dependency cycle.

## Decision

**The dependency direction is ghidra → kuna, and the trait impl sits
with the trait.** `calxgloss-kuna::source::KunaSource` exposes
inherent methods over kuna-native DTOs (`KunaFunction`,
`KunaDecompiled`, `KunaSymbol` — name + address, mirroring the Ghidra
seam, no library field); `calxgloss-ghidra::scan_source` provides the
`impl ScanSource for KunaSource`, the `PipelineSource::Kuna` arm, and
the error mapping (`FunctionNotFound` → `GhidraError::NotFound`,
everything else → `GhidraError::Reported`). The kuna crate never names
the ghidra crate.

**The source is an actor, not a shared handle.** A dedicated analysis
engine thread owns the `ConsoleProgram`. Commands arrive over a
channel, and each one runs inside `catch_unwind`, so a panicking
analysis engine call becomes `KunaError::EngineFault { call, panic }`
at the seam. The load itself runs on the analysis engine thread, so a
binary that panics during loading fails the constructor rather than
killing a caller's task. The handshake deliberately uses
`std::sync::mpsc` — tokio's `blocking_recv` panics when called from
inside a runtime, and the constructor may be called from one.

**Container metadata comes from the `object` crate, not the analysis
engine.** Imports, exports, and the image base are read from the file
bytes captured on the analysis engine thread beside the load itself —
one snapshot, so no read can answer from bytes that drifted after the
program loaded. This keeps the "wrong program is structurally
impossible" guarantee (ADR-0039): one source, one file, one program.
Import entries carry no address — the generic
`object::read::Object::imports` yields none — and no consumer reads
one.

## Consequences

- `calxgloss-kuna` stays analysis-engine-only and cycle-free; adding a
  third analysis engine means another inherent-methods type plus an
  impl arm beside the trait, not a new dependency edge.
- Every seam call pays one channel round-trip. Acceptable: the seam is
  already async and the calls are analysis-scale.
- `EngineFault` loses the panic's backtrace (only its message is
  captured). The process surviving is the point; debugging depth can
  wait until it matters.
- The DTO duplication (kuna-native vs. seam types) is the price of the
  cycle rule; the mapping is twelve lines and mechanical.

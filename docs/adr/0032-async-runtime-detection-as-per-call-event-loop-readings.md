# ADR-0032: Async runtime detection as per-call event-loop readings

- **Status:** Accepted
- **Date:** 2026-10-14
- **Deciders:** Arthur (solo project)

## Context

Phase 5 of the sync scan tracks concurrency shapes inside decompiled
bodies. The thread-local storage detector (issue #164) already reads
per-thread key creation and access. Issue #165 asks the scan to also
identify a binary's async runtime shape from the event loop a function
drives: I/O completion ports, epoll, select/poll, and the Win32
message pump. The reading must use the same tagged-union finding list,
persistence, CLI kind breakdown, and escalate prompt path as every
other detector. It must not change the existing scan-order or
exactly-once-decompile contracts.

## Decision

Model an async runtime reading as a per-call finding, following the
shape of the atomic-operation detector rather than the paired TLS
detector:

- A new `AsyncRuntime` record (`function`, `operation`, `suggestion`,
  `confidence`, `evidence`) is added to `SyncFinding` as the
  `AsyncRuntime` variant. It is serialized under the `async_runtime`
  kind tag, at confidence 70, and it uses the union accessors and the
  prompt conversion unchanged.
- The new `AsyncDetector` has two configured name sets: the event-loop
  spellings that read as `tokio` (the completion-port and epoll
  families, plus `select`/`poll`), and the spellings that read as an
  explicit event loop (the Win32 message pump). Each matched call
  becomes one `AsyncRuntime` finding in call order, with its call line
  as evidence.
- The detector is a pure module over one `DecompiledFunction`. It is
  not serialized itself. It can be replaced whole through a new
  `with_async`/`with_async_runtime` evidence engine builder method, so
  custom spellings reach the scan. Async findings are appended after
  the TLS records, keeping the within-function order stable (`mutex`,
  `atomic`, `thread`, `tls`, `async_runtime`).

## Consequences

- One finding per recognized loop call keeps the list diffable, and
  avoids inventing a pairing the decompiler's naming cannot support.
  Readers that need the full family still see every spelling in the
  persisted evidence.
- Known concern: a body may contain several members of one family (for
  example both `CreateIoCompletionPort` and `GetQueuedCompletionStatus`),
  so the count is per call rather than per family. That matches how
  atomic calls are counted today, and it keeps the scan order honest.
- Adding a fifth finding kind required touching every `match` over
  `SyncFinding` in the crate. The compiler enforces exhaustiveness, so
  the change had to update the persisted path and the prompt path
  together. No existing on-disk document format changes, beyond the
  new variant value that documents gain when it is written.
- The two-set detector shape lets later work split tokio from the
  event-loop families without re-running the scan.

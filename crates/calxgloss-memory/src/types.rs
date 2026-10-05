//! Core data types for memory lifecycle information.
//!
//! This module holds the serialized shape of everything the lifecycle
//! detectors produce:
//!
//! - `MemoryHint`, `AllocationType`: per-function detection records —
//!   the resource a function manages, how it is allocated and released,
//!   and the Rust ownership pattern the pairing suggests.
//! - `HandleLifecycle`, `ReferenceCount`: the handle-lifecycle and
//!   reference-counting shapes beside plain allocations.
//! - `MemoryResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

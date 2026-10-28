//! Integration with the Kuna engine — the in-process decompiler behind
//! `analysis.engine = kuna` (issue #205, part of epic #203).
//!
//! Kuna (Apache-2.0, `Noelo-Lab/kuna`, pinned to a release tag by ADR-0039)
//! is a clean-room Ghidra decompiler written in Rust. Unlike the old
//! GhidraMCP path, there is no JVM, server, or bridge to reach: loading a
//! target is a function call inside this process.
//!
//! Since #206, Kuna answers the core scan reads. Since #207, every read
//! that comes through the `ScanSource` seam — the string listing, xrefs
//! and callers, the type-library reads, data items, and raw memory —
//! comes from that one loaded program, so every evidence engine works
//! unchanged under `engine = kuna`. Since #209, the write side of the
//! seam answers too: Kuna never writes back into the loaded image, so a
//! write is recorded in a directive plane that calxgloss owns, and every
//! load replays it (ADR-0039's state model). Since #211, a Kuna pass
//! sends the same progress heartbeats the retired Ghidra path used to
//! send, and the per-function decompile budgets from config keep one
//! obfuscated function from taking the whole machine down.
//!
//! # Architecture
//!
//! - `error.rs` — `KunaError` and the crate-wide `Result` alias.
//! - `budget.rs` — `KunaBudget`, the per-function decompile budgets armed
//!   at load (issue #211).
//! - `engine.rs` — `load` and the loaded-program handle `KunaProgram`.
//! - `directives.rs` — the code that turns write-seam calls into
//!   directives, and the `DirectivePlane` that keeps them in a file in
//!   the record of effort.
//! - `source.rs` — `KunaSource`, the thread that owns one loaded program
//!   and answers every scan read, isolating panics at the seam. It also
//!   sends the analysis-pass heartbeat (issue #211).
//! - `specs.rs` — the embedded compiled SLEIGH tree and its cache unpacker
//!   (provisioned by `build.rs`).

pub mod budget;
pub mod directives;
pub mod engine;
pub mod error;
pub mod source;
pub(crate) mod specs;

pub use budget::KunaBudget;
pub use directives::{DirectiveOutcome, DirectivePlane, KunaNewField, directive_file_path};
pub use engine::{KUNA_PIN_REV, KUNA_RELEASE, KunaProgram, load};
pub use error::{KunaError, Result};
pub use source::{
    KunaDataItem, KunaDataType, KunaDecompiled, KunaEnumDefinition, KunaEnumMember, KunaFunction,
    KunaSource, KunaString, KunaStructField, KunaStructLayout, KunaSymbol, KunaXref,
};

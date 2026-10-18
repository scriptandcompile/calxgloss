//! Kuna engine integration — the in-process decompiler behind
//! `analysis.engine = kuna` (issue #205, part of epic #203).
//!
//! Kuna (Apache-2.0, `Noelo-Lab/kuna`, pinned to a release tag by ADR-0039)
//! is a clean-room Ghidra decompiler in Rust, so unlike the GhidraMCP path
//! there is no JVM, server, or bridge to reach: loading a target is a
//! function call in this process. Since #206 it answers the core scan
//! reads, and since #207 every read the `ScanSource` seam carries — the
//! string listing, xrefs and callers, the type-library reads, data items,
//! and raw memory — comes from that one loaded program, so each evidence
//! engine works unchanged under `engine = kuna`. Since #209 the type
//! write-back seam answers too: Kuna never writes back into the image, so
//! a write lands in a directive plane calxgloss owns and every load
//! replays it (ADR-0039's state model). Since #211 a Kuna pass beats the
//! same progress heartbeats a Ghidra pass does, and per-function
//! decompile budgets from config bound one obfuscated function instead of
//! the box. Only live-analysis commands —
//! things that need a mutated saved program — still need the Ghidra engine.
//!
//! # Architecture
//!
//! - `error.rs` — `KunaError` and the crate-wide `Result` alias.
//! - `budget.rs` — `KunaBudget`, the per-function decompile budgets armed
//!   at load (issue #211).
//! - `engine.rs` — `load` and the loaded-program handle `KunaProgram`.
//! - `directives.rs` — the write-seam-to-directive compilers and the
//!   `DirectivePlane` that mirrors them on a file in the record of effort.
//! - `source.rs` — `KunaSource`, the actor thread that owns one program and
//!   answers every scan read with panic isolation at the seam; it also
//!   carries the analysis-pass heartbeat (issue #211).
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

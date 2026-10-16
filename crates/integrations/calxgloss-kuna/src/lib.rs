//! Kuna engine integration — the in-process decompiler behind
//! `analysis.engine = kuna` (issue #205, part of epic #203).
//!
//! Kuna (Apache-2.0, `Noelo-Lab/kuna`, pinned to a release tag by ADR-0039)
//! is a clean-room Ghidra decompiler in Rust, so unlike the GhidraMCP path
//! there is no JVM, server, or bridge to reach: loading a target is a
//! function call in this process. This crate is the seam that later tickets
//! (#206–#213) build the full scan path on; in this release it loads a
//! program and reports its identity, and every other command keeps running
//! on the Ghidra engine.
//!
//! # Architecture
//!
//! - `error.rs` — `KunaError` and the crate-wide `Result` alias.

pub mod error;

pub use error::{KunaError, Result};

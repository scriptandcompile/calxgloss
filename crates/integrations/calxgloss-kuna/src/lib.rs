//! Kuna engine integration — the in-process decompiler behind
//! `analysis.engine = kuna` (issue #205, part of epic #203).
//!
//! Kuna (Apache-2.0, `Noelo-Lab/kuna`, pinned to a release tag by ADR-0039)
//! is a clean-room Ghidra decompiler in Rust, so unlike the GhidraMCP path
//! there is no JVM, server, or bridge to reach: loading a target is a
//! function call in this process. This crate is the seam that later tickets
//! (#206–#213) build the full scan path on; since #206 it answers the core
//! scan reads — functions, decompile, imports, exports, image base — from
//! one loaded program, and every other command keeps running on the Ghidra
//! engine.
//!
//! # Architecture
//!
//! - `error.rs` — `KunaError` and the crate-wide `Result` alias.
//! - `engine.rs` — `load` and the loaded-program handle `KunaProgram`.
//! - `source.rs` — `KunaSource`, the actor thread that owns one program and
//!   answers the core scan reads with panic isolation at the seam.
//! - `specs.rs` — the embedded compiled SLEIGH tree and its cache unpacker
//!   (provisioned by `build.rs`).

pub mod engine;
pub mod error;
pub mod source;
pub(crate) mod specs;

pub use engine::{KUNA_RELEASE, KunaProgram, load};
pub use error::{KunaError, Result};
pub use source::{KunaDecompiled, KunaFunction, KunaSource, KunaSymbol};

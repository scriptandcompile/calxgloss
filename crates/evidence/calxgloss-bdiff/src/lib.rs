//! Binary-version pairing: which function in the new version *is* the
//! function from the old one?
//!
//! When a target binary's bytes change, its scan re-mints function names
//! from the new addresses — `FUN_…` spellings that almost never match
//! the previous version's names — and every accepted translation for an
//! unchanged function silently orphans. This crate pairs the two scans:
//! given an in-memory snapshot of the old scan and one of the new scan
//! of the same binary identity, it computes one confidence-scored,
//! one-to-one pairing of old functions to new functions and persists it
//! as one pairing document per (binary identity, old bytes, new bytes),
//! so the queue can tell "same function, new address" from "changed
//! function" from "genuinely new function" and carry accepted
//! translations across the version change.
//!
//! The pass is pure text and structure over documents: no engine reads
//! (ADR-0026 untouched), no program mutation (ADR-0020), no LLM.
//! Pairings resolve strongest-claim-wins (ADR-0022) with ties keeping
//! the first seen in scan order (ADR-0028's precedent), and a lone
//! signal — address equality on its own — claims nothing (ADR-0038).
//!
//! # Architecture
//!
//! The crate opens with its persistence plumbing; the snapshot model
//! and the pairing pass land in this track's follow-up modules:
//!
//! * [`error`] — [`BdiffError`], the crate's error type.
pub mod error;

pub use error::{BdiffError, Result};

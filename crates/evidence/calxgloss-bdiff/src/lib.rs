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
//! * [`types`] — the document model: [`ScanSnapshot`] and
//!   [`FunctionEntry`], one scan's in-memory listing; [`PairingDocument`],
//!   [`PairingRecord`], and [`MatchFamily`], the one persisted pairing;
//!   the name-identity and byte-equal-body bands and the carry-over
//!   confidence floor as named constants.
//! * [`engine`] — [`pair_versions`], the pairing pass: a pure function
//!   over two snapshots, documents in and pairing document out, opening
//!   the ladder with the name-identity and normalized-body families
//!   before the one-to-one resolution rule (strongest claim wins, ties
//!   first seen in scan order).
//! * [`persist`] — [`BdiffPersistor`], the JSON document store: one
//!   pairing document per (binary identity, old bytes, new bytes) under
//!   `re/analysis/bdiff/`, keyed on the hash pair so a stale document
//!   is detectable and the file's existence is the pass's cache check.
//! * [`error`] — [`BdiffError`], the crate's error type.
pub mod engine;
pub mod error;
pub mod persist;
pub mod types;

pub use engine::pair_versions;
pub use error::{BdiffError, Result};
pub use persist::BdiffPersistor;
pub use types::{
    BODY_EQUAL_CONFIDENCE, BODY_SIMILARITY_FLOOR, CARRY_OVER_CONFIDENCE_FLOOR, FunctionEntry,
    MatchFamily, NAME_IDENTITY_CONFIDENCE, PairingDocument, PairingRecord, ScanSnapshot,
};

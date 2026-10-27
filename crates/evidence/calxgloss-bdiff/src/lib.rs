//! Binary-version pairing: which function in the new version *is* the
//! function from the old one?
//!
//! When a target binary's bytes change, its scan generates function
//! names from the new addresses again. The new `FUN_…` spellings almost
//! never match the previous version's names, so every accepted
//! translation for an unchanged function silently loses its owner. This
//! crate pairs the two scans. It takes an in-memory snapshot of the old
//! scan and one of the new scan of the same binary identity, computes
//! one confidence-scored, one-to-one pairing of old functions to new
//! functions, and persists it as one pairing document per (binary
//! identity, old bytes, new bytes). The queue can then tell "same
//! function, new address" from "changed function" from "genuinely new
//! function", and accepted translations carry across the version change.
//!
//! The pass only reads and writes text and structure in documents. It
//! makes no analysis-engine reads (ADR-0026 stays untouched), mutates
//! no program (ADR-0020), and uses no LLM. Resolution keeps the
//! strongest claim (ADR-0022); on a tie it keeps the claim first seen
//! in scan order (ADR-0028's precedent). A lone signal — address
//! equality on its own — claims nothing (ADR-0038).
//!
//! # Architecture
//!
//! * [`types`] — the document model: [`ScanSnapshot`] and
//!   [`FunctionEntry`], one scan's in-memory listing; [`PairingDocument`],
//!   [`PairingRecord`], and [`MatchFamily`], the one persisted pairing.
//!   It also holds the named constants: the name-identity,
//!   byte-equal-body, and call-topology confidence bands, the topology
//!   agreement bump, and the carry-over confidence floor.
//! * [`engine`] — [`pair_versions`], the pairing pass: a pure function
//!   over two snapshots, documents in and pairing document out. The
//!   confidence ladder opens with the name-identity and
//!   normalized-body families; then the pass propagates the call
//!   graph's topology claims to a fixed point and raises the confidence
//!   of body pairs the topology agrees on. All of this runs before the
//!   one-to-one resolution rule (strongest claim wins, ties go to the
//!   claim first seen in scan order). The call map is built from the
//!   bodies the snapshots themselves carry; the pass reads nothing from
//!   the analysis engine (ADR-0024).
//! * [`persist`] — [`BdiffPersistor`], the JSON document store: one
//!   pairing document per (binary identity, old bytes, new bytes) under
//!   `re/analysis/bdiff/`. Documents are keyed on the hash pair, so a
//!   stale document is detectable, and the file's existence is the
//!   pass's cache check.
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
    TOPOLOGY_AGREEMENT_BUMP, TOPOLOGY_CONFIDENCE, TOPOLOGY_MIN_PAIRED_NEIGHBORS,
};

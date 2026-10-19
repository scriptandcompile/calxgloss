//! Global-state reference sets: which globals each function reads and writes.
//!
//! The decompiler names most globals by their Ghidra address (`DAT_0040a050`),
//! so the question "what global state does this function touch?" cannot be
//! answered from the listing alone. This crate answers it: it walks the
//! decompiled body of every function in a binary and records each global
//! access — reads and writes, with the evidence line and a confidence band —
//! as a finding document that downstream tickets consume: #253 rolls the
//! records up into a shared-globals index, #254 injects them into the
//! translation prompt, and #255 has the sync engine consume them instead of
//! re-deriving the same reading itself.
//!
//! # Architecture
//!
//! * [`detector`] — the reading: [`GlobalStateDetector`] walks one function
//!   body and produces [`GlobalAccess`] records plus a [`FunctionPurity`]
//!   summary. Global identification is lexical: a plain identifier that is
//!   not a decompiler local (`param_*`, `local_*`, `uVar1`, `iVar_2`, …),
//!   not a type word, and not a declaration target, accessed outside call
//!   arguments, string literals, qualified names and casts, is a global.
//!   Names spelled `DAT_*` score above other plain identifiers — the exact
//!   Ghidra spelling is positive evidence of a data reference, while a bare
//!   name could still be a macro or a missed local.
//! * [`types`] — the document model: [`GlobalStateFinding`] (a read or a
//!   write of one global by one function) and [`FunctionPurity`], aggregated
//!   into [`GlobalStateResult`].
//! * [`engine`] — [`GlobalStateEngine`], the scan entry point: decompiles
//!   every function through a [`calxgloss_types::scan::ScanSource`] and
//!   runs the detector over each body.
//! * [`persist`] — [`GlobalStatePersistor`], the JSON document store, one
//!   file per binary under `re/analysis/globalstate/`.
//! * [`error`] — [`GlobalStateError`], the crate's error type.

pub mod detector;
pub mod engine;
pub mod error;
pub mod types;

pub use detector::{EXACT_SPELLING_CONFIDENCE, GlobalStateDetector, SHAPE_ONLY_CONFIDENCE};
pub use engine::GlobalStateEngine;
pub use error::{GlobalStateError, Result};
pub use types::{AccessKind, FunctionPurity, GlobalAccess, GlobalStateFinding, GlobalStateResult};

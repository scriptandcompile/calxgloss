//! Error-handling idiom evidence: reading the try/catch frame, named
//! handlers and failure codes from kept function bodies as
//! decompile-level evidence, persisted per binary.
//!
//! This crate is the first slice of P15 (the error-handling recovery
//! pass): it detects the one error-handling shape the decompiler
//! spells outright — an SEH `try`/`catch` frame carried in kept body
//! text — and persists the finding as an evidence document under
//! `re/analysis/errhandling/`. It deliberately stops there: the
//! remaining evidence families (hidden exception paths, named
//! handlers, the RAII shape, failure codes), the cross-function
//! propagation reading, the whole-program pass and the prompt
//! consumers are follow-up issues against this same artifact, and
//! nothing here feeds an annotation prompt or a translation yet
//! (ADR-0046).
//!
//! The reading is decompile-level only — per-function body text. No
//! disassembly, no CFG, no call-fact reads, and nothing written back
//! to the program (ADR-0020); an earlier draft of the pass was
//! rejected for exactly those violations, and the catalog's
//! whole-program frame rule (ADR-0023) stays a future reading this
//! artifact prepares (ADR-0046).
//!
//! Architecture:
//! - [`types`] — the finding records, the tagged finding union, and
//!   the metadata-stamped per-binary result.
//! - [`seh_frame`] — the spelled `try`/`catch` frame detector: pure
//!   text analysis of one kept body.
//! - [`engine`] — [`ErrhandlingEngine`]: decompiles every function
//!   listing entry once, detects the idiom on each kept body, and
//!   assembles the metadata-stamped result.
//! - [`persist`] — [`ErrhandlingPersistor`]: strict JSON at
//!   `re/analysis/errhandling/<basename>.json` (ADR-0043).
//! - [`error`] — the crate's error type.

pub mod engine;
pub mod error;
pub mod persist;
pub mod seh_frame;
pub mod types;

pub use engine::ErrhandlingEngine;
pub use error::{ErrhandlingError, Result};
pub use persist::ErrhandlingPersistor;
pub use seh_frame::{SEH_FRAME_SUGGESTION, SPELLED_FRAME_CONFIDENCE, SehFrameDetector};
pub use types::{ErrhandlingFinding, ErrhandlingResult, SehFrame};

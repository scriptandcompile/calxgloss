//! Float/SIMD usage flags: which functions do float math, and what shape.
//!
//! On targets where the decompiler mangles vector math into garbage
//! pseudo-C — `CONCAT44`, `SUB4`, undefined-typed arithmetic over
//! `DAT_*` loads — the translator reads the mangled body as integer
//! or pointer logic and mistranslates it. This crate answers the
//! question the listing cannot: does this function do float math, and
//! does the evidence spell scalar float math, vector/matrix idioms,
//! or both? It walks the decompiled body of every function in a
//! binary and records one flag per flagged function — the shape, the
//! strongest evidence line, and a confidence band — as a document
//! that downstream tickets consume: the translate prompts carry the
//! flag so the LLM translates float as float, a reviewer triages the
//! functions most likely mistranslated, and a later testgen track can
//! swap integer boundary sampling for rounding/NaN-boundary sampling
//! for flagged functions without re-deriving the flag.
//!
//! # Architecture
//!
//! * [`detector`] — the reading: [`FloatsimdDetector`] walks one
//!   function body for four evidence families — explicit `float`/
//!   `double` tokens and float literals, CRT math import calls,
//!   `CONCAT44`/`SUB4`-style vector assembly idioms, and parallel
//!   x/y/z component reads — and folds everything a body fires into
//!   at most one flag naming its shape.
//! * [`types`] — the document model: [`FloatsimdFinding`] (the tagged
//!   union over the three shapes, wrapping one [`FloatsimdRecord`])
//!   aggregated into [`FloatsimdResult`].
//! * [`engine`] — [`FloatsimdEngine`], the scan entry point:
//!   decompiles every function through a
//!   [`calxgloss_types::scan::ScanSource`] — each exactly once, on
//!   the skip-rate breaker's rails — and runs the detector over each
//!   kept body. The reading adds no engine reads beyond the
//!   decompiles themselves.
//! * [`persist`] — [`FloatsimdPersistor`], the JSON document store,
//!   one file per binary under `re/analysis/floatsimd/`.
//! * [`error`] — [`FloatsimdError`], the crate's error type.

pub mod detector;
pub mod engine;
pub mod error;
pub mod persist;
pub mod types;

pub use detector::{
    COMPONENT_TRIPLET_CONFIDENCE, CRT_MATH_CONFIDENCE, EXPLICIT_FLOAT_CONFIDENCE,
    FloatsimdDetector, VECTOR_IDIOM_CONFIDENCE,
};
pub use engine::FloatsimdEngine;
pub use error::{FloatsimdError, Result};
pub use persist::FloatsimdPersistor;
pub use types::{FloatsimdFinding, FloatsimdRecord, FloatsimdResult, ShapeKind};

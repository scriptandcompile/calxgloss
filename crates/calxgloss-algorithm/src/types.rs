//! Core data types for recognized algorithm information.
//!
//! This module holds the serialized shape of everything the recognition
//! detectors produce:
//!
//! - `AlgorithmHint`, `AlgorithmCategory`, `DetectionMethod`,
//!   `AlgorithmPattern`: per-function detection records — the recognized
//!   algorithm and its category, which detector produced the hint, and
//!   the pattern behind the match.
//! - `AlgorithmRecognitionResult`, `ScanMetadata`: the persisted
//!   per-binary result and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

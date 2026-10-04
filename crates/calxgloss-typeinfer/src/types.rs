//! Core data types for inferred type information.
//!
//! This module holds the serialized shape of everything the inference
//! detectors produce:
//!
//! - `InferredParamType`, `InferenceMethod`, `InferenceScope`: per-parameter
//!   inference records — the narrowed type, which detector produced it, and
//!   how far the inference reaches.
//! - `InferredType`, `InferredLocalType`, `InferredCallType`: inferred types
//!   for parameters, local variables, and call sites.
//! - `TypeInferenceResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

//! Type inference and propagation for calxgloss.
//!
//! Propagates type information through function analysis — examining
//! decompiled pseudo-C, disassembly, and known function signatures — to
//! narrow parameter types from `undefined4` to concrete types like
//! `Sprite *`, `u32`, `char *`.
//!
//! # Architecture
//!
//! The crate is organized into nine modules:
//!
//! - [`types`] - Core data types: `InferredParamType`, `InferenceMethod`,
//!   `InferenceScope` for per-parameter inference records; `InferredLocalType`
//!   and `InferredCallType` for inferred local variables and call-site
//!   arguments; `InferredType` as the union over the three record kinds;
//!   `TypeInferenceResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - [`engine`] - Scan orchestration: `TypeInferEngine` decompiles each
//!   function of a program exactly once, reads it with all three detectors,
//!   and assembles their records into one `TypeInferenceResult`;
//!   `DecompileSource` abstracts the decompiler reads so tests run the
//!   orchestration over canned bodies.
//! - [`this_ptr`] - C++ this-pointer detection: `ThisPointerDetector`
//!   parses decompiled output for `vtable[index]` call patterns and
//!   first-parameter usage, extracts class names from vtable function
//!   names, avoids namespace false positives, and detects COM interfaces.
//! - [`param_size`] - Parameter size detection: `ParameterSizeDetector`
//!   scans decompiled text for pointer, integer, and string usage patterns
//!   — string-function calls, integer bit patterns, pointer arithmetic —
//!   and resolves competing readings by confidence.
//! - [`known_type`] - Known type propagation: `KnownTypePropagationEngine`
//!   extracts calls from decompiled text and propagates parameter types
//!   through a signature database of well-known library functions, with
//!   A/W-suffix name matching and per-signature confidence scores.
//! - [`reading`] - Detector-internal accumulator: the single `Reading`
//!   shape every detector feeds, with highest-confidence-wins resolution
//!   and shared record assembly.
//! - [`confidence`] - Shared confidence model: `resolve_conflicts` —
//!   highest-confidence-wins resolution when several detectors read one
//!   parameter, local, or call-site argument differently.
//! - [`persist`] - JSON persistence: `TypeInferPersistor` saves and loads
//!   the per-binary inference results under `re/analysis/typeinfer/`.
//! - [`error`] - [`TypeInferError`] and the crate-wide [`Result`] alias.

pub mod confidence;
pub mod engine;
pub mod error;
pub mod known_type;
pub mod param_size;
pub mod persist;
pub(crate) mod reading;
pub mod this_ptr;
pub mod types;

pub use error::{Result, TypeInferError};

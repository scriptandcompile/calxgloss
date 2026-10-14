//! Type inference and propagation for calxgloss.
//!
//! Propagates type information through function analysis — examining
//! decompiled pseudo-C, disassembly, and known function signatures — to
//! narrow parameter types from `undefined4` to concrete types like
//! `Sprite *`, `u32`, `char *`.
//!
//! # Architecture
//!
//! The crate is organized into fourteen modules:
//!
//! - [`types`] - Core data types: `InferredParamType`, `InferenceMethod`,
//!   `InferenceScope` for per-parameter inference records; `InferredLocalType`,
//!   `InferredCallType`, and `InferredReturnType` for inferred local
//!   variables, call-site arguments, and function return values;
//!   `InferredType` as the union over the four record kinds;
//!   `TypeInferenceResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - [`engine`] - Scan orchestration: `TypeInferEngine` decompiles each
//!   function of a program exactly once, reads it with the inline
//!   detectors and its listing name with the mangling detector, and
//!   propagates the surviving readings across function boundaries, and
//!   assembles everything into one `TypeInferenceResult`;
//!   the shared `ScanSource` trait abstracts the decompiler reads so tests
//!   run the orchestration over canned bodies.
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
//! - [`cross_function`] - Cross-function propagation: `CrossFunctionPropagator`
//!   carries each function's surviving parameter readings to the arguments
//!   at that callee's call sites — and to the caller's own parameter when
//!   the argument is one, so types climb the call chain.
//! - [`local_chain`] - Local-variable inference via assignment chains:
//!   `LocalChainDetector` types a stack slot assigned a parameter with a
//!   surviving reading, a known-signature call's result, or an
//!   already-typed local — one hop per chain — as the local record kind.
//! - [`return_usage`] - Return-type inference from caller usage:
//!   `ReturnUsageDetector` types a function's return by how its callers
//!   use the value — assigned to a typed local, passed at a
//!   known-signature position, or dereferenced — as the return record kind.
//! - [`mangling`] - C++ mangling analysis: `ManglingDetector` reads the
//!   contract carried in a name — an MSVC-mangled listing symbol decoded
//!   for convention, argument count, and rough argument types, and a
//!   demangled qualified name with a spelled parameter list — typing the
//!   parameters (and where the name spells one, the return) it names.
//! - [`reading`] - Detector-internal accumulator: the single `Reading`
//!   shape every detector feeds, with highest-confidence-wins resolution
//!   and shared record assembly.
//! - [`confidence`] - Shared confidence model: `resolve_conflicts` —
//!   highest-confidence-wins resolution when several detectors read one
//!   parameter, local, call-site argument, or return differently.
//! - [`persist`] - JSON persistence: `TypeInferPersistor` saves and loads
//!   the per-binary inference results under `re/analysis/typeinfer/`.
//! - [`write_back`] - Writing the surviving inferences into the open
//!   program: `WriteBack` applies records through the `TypeWriteSource`
//!   seam in program order — missing named types first, then function
//!   prototypes, then local-variable types — gated by a confidence floor,
//!   never overwriting a concretely-typed slot, and reporting what it
//!   applied, skipped, and failed.
//! - [`error`] - [`TypeInferError`] and the crate-wide [`Result`] alias.

pub mod confidence;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod known_type;
pub mod local_chain;
pub mod mangling;
pub mod param_size;
pub mod persist;
pub(crate) mod reading;
pub mod return_usage;
pub mod this_ptr;
pub mod types;
pub mod write_back;

pub use error::{Result, TypeInferError};

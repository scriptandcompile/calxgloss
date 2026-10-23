//! Type inference and propagation for calxgloss.
//!
//! Propagates type information through function analysis — examining
//! decompiled pseudo-C, disassembly, and known function signatures — to
//! narrow parameter types from `undefined4` to concrete types like
//! `Sprite *`, `u32`, `char *`.
//!
//! # Architecture
//!
//! The crate is organized into nineteen modules:
//!
//! - [`types`] - Core data types: `InferredParamType`, `InferenceMethod`,
//!   `InferenceScope` for per-parameter inference records; `InferredLocalType`,
//!   `InferredCallType`, and `InferredReturnType` for inferred local
//!   variables, call-site arguments, and function return values;
//!   `CallingConvention` and `InferredConvention` for the closed set of
//!   calling conventions and the reading a name gives one;
//!   `Direction` and `InferredParamDirection` for the closed set of
//!   parameter directions and the reading a body gives one of its
//!   pointer parameters;
//!   `InferredType` as the union over the six record kinds;
//!   `TypeInferenceResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - [`engine`] - Scan orchestration: `TypeInferEngine` decompiles each
//!   function of a program exactly once, reads it with the inline
//!   detectors — including the direction readings of the parameter
//!   direction detector — reads its listing name with the mangling and convention
//!   detectors, reads its machine listing once with the listing-borne
//!   convention detectors — the 32-bit stack discipline and the
//!   Microsoft-x64 shape — reads its import names with the convention
//!   detector, and propagates the surviving readings across function
//!   boundaries, and
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
//! - [`param_direction`] - Parameter direction readings: `ParamDirectionDetector`
//!   reads which way data flows through each pointer parameter off the
//!   body the scan already keeps — a write through the pointer makes it
//!   out, a string-function read makes it in, both together make it
//!   inout, and no deciding shape records nothing — as the direction
//!   record kind, keyed beside the parameter's type record.
//! - [`mangling`] - C++ mangling analysis: `ManglingDetector` reads the
//!   contract carried in a name — an MSVC-mangled listing symbol decoded
//!   for convention, argument count, and rough argument types, and a
//!   demangled qualified name with a spelled parameter list — typing the
//!   parameters (and where the name spells one, the return) it names.
//! - [`convention`] - Calling-convention detection: `ConventionDetector`
//!   reads how a function is called off its name — the convention letter
//!   of an MSVC-mangled listing symbol and the `@N` decoration of an
//!   import — each in its own confidence band, as the convention record
//!   kind.
//! - [`stack_discipline`] - Calling-convention detection off the machine
//!   listing: `StackDisciplineDetector` reads the 32-bit stack discipline
//!   an `esp`-spelled disassembly spells — a callee epilogue popping its
//!   own arguments (`ret N`, stdcall) and a caller popping after a call
//!   site naming its callee (`add esp, N`, cdecl) — each in its own
//!   confidence band, and its machine-class pass is the single dispatch
//!   both listing-borne families ride, keyed on the stack register the
//!   listing itself names so the 32-bit and 64-bit families never
//!   cross-fire.
//! - [`x64_shape`] - Calling-convention detection off the machine
//!   listing: `X64ShapeDetector` reads the Microsoft-x64 call shape an
//!   `rsp`-spelled disassembly spells — shadow-space allocation in the
//!   prologue, the argument registers spelled, and no callee or caller
//!   stack cleanup the convention ever leaves behind — one shape-only
//!   reading at the modest band, routed by the same machine-class
//!   dispatch as the 32-bit family.
//! - [`corroboration`] - Calling-convention detection across functions:
//!   `ConventionCorroborator` is the post-inline pass that trusts
//!   agreement above any single reading — a callee epilogue, clean call
//!   sites in other listings, and the declared `@N` bytes all agreeing
//!   raise the reading, and every detected callee convention lands a
//!   call-site record in each caller whose listing calls it, keyed by
//!   the caller and naming the callee, over exactly the listings the
//!   scan already read.
//! - [`reading`] - Detector-internal accumulator: the single `Reading`
//!   shape every detector feeds, with highest-confidence-wins resolution
//!   and shared record assembly.
//! - [`confidence`] - Shared confidence model: `resolve_conflicts` —
//!   highest-confidence-wins resolution when several detectors read one
//!   parameter, local, call-site argument, return, convention, or
//!   parameter direction differently.
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
pub mod convention;
pub mod corroboration;
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod known_type;
pub mod local_chain;
pub mod mangling;
pub mod param_direction;
pub mod param_size;
pub mod persist;
pub(crate) mod reading;
pub mod return_usage;
pub mod stack_discipline;
pub mod this_ptr;
pub mod types;
pub mod write_back;
pub mod x64_shape;

pub use error::{Result, TypeInferError};

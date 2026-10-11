//! Library and API identification for calxgloss.
//!
//! Identifies the libraries a binary imports and the APIs each function
//! reaches, mapping each identified API to the Rust crate that stands in
//! for it — `flate2` for zlib's `inflate`, `windows / std::fs` for
//! Win32's `CreateFileA`, `sdl2` for `SDL_Init`. Results are injected as
//! structured LIBRARIES AND APIS sections so the LLM calls the API
//! through the suggested crate instead of transliterating the raw import
//! or declaring it as an `extern "C"` stub.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
//!
//! - [`types`] - Core data types: `ApiSignature` for a binary-level
//!   import-table record; `ApiUsage` for a function-level API usage with
//!   its call path; `ApiFinding` as the union over the two record kinds;
//!   `ApiDetectionResult`, `ScanMetadata` for the persisted per-binary
//!   results.
//! - [`lib_mapping`] - The mapping database: `MappingDatabase` maps
//!   import names to their library and Rust crate suggestion, with the
//!   builtin table covering DirectX 9, SDL2, Win32, POSIX, PNG, zlib,
//!   stdio, and the C++ STL, and `with_library` adding a whole entry
//!   for custom binaries.
//! - [`import_table`] - Binary-level identification: `ImportTableScanner`
//!   reads the program's import table and classifies every entry,
//!   keeping unidentified and ordinal-only imports as plain records.
//! - [`api_summary`] - Function-level identification: `ApiSummaryDetector`
//!   walks the built call graph and records the APIs each function
//!   reaches directly or transitively, with the call path as evidence.
//! - [`engine`] - Scan orchestration: `ApiEngine` runs both detectors
//!   over one open Ghidra program through the shared `ScanSource` trait
//!   (for the import listing) plus a `CallGraphSource` (for the built
//!   call graph), one sequential pass that keeps the findings in scan
//!   order.
//! - [`persist`] - JSON persistence: `ApiPersistor` saves and loads the
//!   per-binary detection results under `re/analysis/apidetect/`.
//! - [`error`] - [`ApiError`] and the crate-wide [`Result`] alias.

pub mod api_summary;
pub mod engine;
pub mod error;
pub mod import_table;
pub mod lib_mapping;
pub mod persist;
pub mod types;

pub use error::{ApiError, Result};
pub use types::{ApiDetectionResult, ApiFinding, ApiSignature, ApiUsage, ScanMetadata};

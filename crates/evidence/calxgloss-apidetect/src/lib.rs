//! Library and API identification for calxgloss.
//!
//! This crate identifies the libraries a target binary imports and the
//! APIs each function reaches. It maps each identified API to the Rust
//! crate that stands in for it: `flate2[zlib]` for zlib's `inflate`,
//! `windows / std::fs` for Win32's `CreateFileA`, `sdl2` for
//! `SDL_Init`. Every finding records its API category.
//!
//! Two binary-level claims come out of the import listing. A binary
//! that imports both Win32 and POSIX/stdio APIs is flagged as
//! platform-divergent, suggesting cfg-gated translation. A binary whose
//! names show COM signals — runtime imports, the IUnknown-shape trio,
//! interface-decorated names — is flagged with `com_interface` claims,
//! each suggesting the interface be modeled as a Rust trait with its
//! methods. Results are injected as structured LIBRARIES AND APIS
//! sections so the LLM calls the API through the suggested crate
//! instead of transliterating the raw import or declaring it as an
//! `extern "C"` stub.
//!
//! # Architecture
//!
//! The crate is organized into ten modules:
//!
//! - [`types`] - Core data types. `ApiSignature` is a binary-level
//!   import-table record. `ApiUsage` is a function-level API usage with
//!   its call path. `PlatformDivergence` is the binary-level claim that
//!   the imports mix Win32 and POSIX/stdio families. `ComInterface` is
//!   the binary-level claim that the binary drives a COM interface or
//!   the COM runtime. `ApiFinding` is the union over the record kinds.
//!   `ApiDetectionResult` and `ScanMetadata` hold the persisted
//!   per-binary results.
//! - [`lib_mapping`] - The mapping database. `MappingDatabase` maps
//!   import names to their library and Rust crate suggestion. Each
//!   entry also records its API category (aligned with the PAL
//!   `ApiCategory` display names) and the crate's feature flags. The
//!   builtin table covers DirectX 9, SDL2, Win32, POSIX, PNG, zlib,
//!   stdio, and the C++ STL, and `with_library` adds a whole entry for
//!   custom binaries.
//! - [`import_table`] - Binary-level identification. `ImportTableScanner`
//!   reads the program's import table and classifies every entry.
//!   Unidentified and ordinal-only imports are kept as plain records.
//! - [`api_summary`] - Function-level identification. `ApiSummaryDetector`
//!   walks the built call graph and records the APIs each function
//!   reaches directly or transitively, with the call path as evidence.
//! - [`divergence`] - Platform-divergence detection. `detect_divergence`
//!   reads the classified import listing the scanner already emitted.
//!   It records one binary-level claim when both a Win32-category and
//!   a POSIX/stdio-category import appear, suggesting cfg-gated
//!   translation.
//! - [`com`] - COM interface suggestion. `detect_com` reads the COM
//!   signals in the classified import listing and the call-graph names
//!   the scan already holds — COM runtime imports, the IUnknown-shape
//!   trio, interface-decorated names. It records one `com_interface`
//!   claim per recoverable interface, or one runtime-level claim when
//!   no name is recoverable, suggesting the trait-plus-methods shape.
//! - [`engine`] - Scan orchestration. `ApiEngine` runs the detectors
//!   and the divergence and COM passes over one loaded program. It
//!   reads the import listing through the shared `ScanSource` trait
//!   and the built call graph through a `CallGraphSource`. One
//!   sequential pass keeps the findings in scan order.
//! - [`persist`] - JSON persistence. `ApiPersistor` saves and loads
//!   the per-binary detection results under `re/analysis/apidetect/`.
//!   The rendered FFI bindings and dependency manifest are filed
//!   beside each JSON document.
//! - [`ffi_bindings`] - Rendered artifacts. `render_ffi_bindings` turns
//!   a loaded detection result into a Rust source string declaring every
//!   crate-less import as an `extern "system"` function, grouped by
//!   library when known. `render_dependency_manifest` turns it into
//!   a Cargo.toml-style manifest aggregating the identified findings'
//!   crates — sorted, feature flags inlined, no versions claimed. Both
//!   are deterministic, timestamp-free derived artifacts that are
//!   never read back.
//! - [`error`] - [`ApiError`] and the crate-wide [`Result`] alias.

pub mod api_summary;
pub mod com;
pub mod divergence;
pub mod engine;
pub mod error;
pub mod ffi_bindings;
pub mod import_table;
pub mod lib_mapping;
pub mod persist;
pub mod types;

pub use error::{ApiError, Result};
pub use types::{
    ApiDetectionResult, ApiFinding, ApiSignature, ApiUsage, ComInterface, PlatformDivergence,
    ScanMetadata,
};

//! Data structure recovery for calxgloss.
//!
//! Recovers struct layouts, class hierarchies, vtables, and type aliases from
//! a binary loaded under the engine, persists them to a per-DLL JSON type
//! database, and feeds the results into LLM translation prompts as structured
//! context.
//!
//! # Architecture
//!
//! The crate is organized into eight modules:
//!
//! - [`types`] - Core data types: `NamedType`, `TypeKind`, `StructField` for
//!   named types from Ghidra's Type Manager; `Vtable`, `VtableMethod` for
//!   detected vtables; `InferredStruct`, `InferredField`, `FieldType` for
//!   string-inferred layouts; `TypeDatabase`, `ScanMetadata` for the
//!   persisted per-DLL database.
//! - [`scanner`] - Named type recovery: `TypeLibraryScanner` queries the
//!   Type Manager through the seam's `data_types()` / `struct_layout()` /
//!   `enum_values()` reads, covering types never applied to a symbol.
//! - [`vtable`] - Vtable detection: `VtableDetector` scans `data_items()`
//!   output for vtable-shaped data objects, resolves method pointers to names
//!   and addresses, tracks base-class inheritance, and detects COM interfaces.
//! - [`string_infer`] - String-guided inference: `StringInferenceEngine`
//!   infers struct layouts from string collection, cross-reference
//!   clustering, and confidence scoring.
//! - [`stl`] - STL/MFC shape detection: [`stl::detect`] matches recovered
//!   names against known standard-library shapes (`basic_string`/`CString`,
//!   `vector`, `list`, the `map`/`set` family, smart pointers) and names the
//!   family with `StlKind`; the scan flags matching records, never filters
//!   them out.
//! - [`engine`] - Orchestration: [`engine::TypesDBEngine`] runs the three
//!   recovery engines concurrently over one program and assembles their
//!   results into a single [`types::TypeDatabase`].
//! - [`persist`] - JSON persistence: `TypeDatabasePersistor` saves and loads
//!   the per-DLL database under `re/analysis/typesdb/`, and files the
//!   rendered Rust declarations beside it.
//! - [`rust_decls`] - Rust codegen: [`rust_decls::render_rust_decls`] turns a
//!   recovered database into a deterministic `#[repr(C)]` declarations file
//!   a reviewer can read; the file is a derived artifact, never read back.
//! - [`error`] - [`TypesDbError`] and the crate-wide [`Result`] alias.

pub mod engine;
pub mod error;
pub mod persist;
pub mod rust_decls;
pub mod scanner;
pub mod stl;
pub mod string_infer;
pub mod types;
pub mod vtable;

pub use error::{Result, TypesDbError};

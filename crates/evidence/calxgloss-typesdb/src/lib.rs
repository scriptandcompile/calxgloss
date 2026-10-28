//! Data structure recovery for calxgloss: the type-database evidence engine.
//!
//! It recovers struct layouts, class hierarchies, vtables, and type aliases
//! from a program loaded in the analysis engine. It saves the results as one
//! JSON type database per target binary, and passes them to LLM translation
//! prompts as structured context.
//!
//! # Architecture
//!
//! The crate is organized into nine modules:
//!
//! - [`types`] - Core data types: `NamedType`, `TypeKind`, `StructField` for
//!   named types from the engine's type listing; `Vtable`, `VtableMethod` for
//!   detected vtables; `InferredStruct`, `InferredField`, `FieldType` for
//!   string-inferred layouts; `TypeDatabase`, `ScanMetadata` for the
//!   saved per-binary database.
//! - [`scanner`] - Named type recovery: `TypeLibraryScanner` queries the
//!   Type Manager through the seam's `data_types()` / `struct_layout()` /
//!   `enum_values()` reads, covering types never applied to a symbol.
//! - [`vtable`] - Vtable detection: `VtableDetector` scans `data_items()`
//!   output for vtable-shaped data objects, resolves method pointers to names
//!   and addresses, tracks base-class inheritance, and detects COM interfaces.
//! - [`string_infer`] - String-guided inference: `StringInferenceEngine`
//!   infers struct layouts from string collection, cross-reference
//!   clustering, and evidence confidence scoring.
//! - [`stl`] - STL/MFC shape detection: [`stl::detect`] matches recovered
//!   names against known standard-library shapes (`basic_string`/`CString`,
//!   `vector`, `list`, the `map`/`set` family, smart pointers) and records
//!   the matched family as an `StlKind`. The scan flags matching records and
//!   never filters them out.
//! - [`engine`] - Orchestration: [`engine::TypesDBEngine`] runs the three
//!   recovery engines at the same time over one loaded program, then merges
//!   their results into a single [`types::TypeDatabase`].
//! - [`persist`] - JSON persistence: `TypeDatabasePersistor` saves and loads
//!   the per-binary database under `re/analysis/typesdb/`, and saves the
//!   rendered Rust declarations beside it.
//! - [`rust_decls`] - Rust codegen: [`rust_decls::render_rust_decls`] turns a
//!   recovered database into a deterministic `#[repr(C)]` declarations file
//!   a reviewer can read. The file is a derived artifact and is never read
//!   back.
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

//! Data structure recovery for calxgloss.
//!
//! Recovers struct layouts, class hierarchies, vtables, and type aliases from
//! a binary loaded in Ghidra, persists them to a per-DLL JSON type database,
//! and feeds the results into LLM translation prompts as structured context.
//!
//! # Architecture
//!
//! The crate is organized into seven modules:
//!
//! - [`types`] - Core data types: `NamedType`, `TypeKind`, `StructField` for
//!   named types from Ghidra's Type Manager; `Vtable`, `VtableMethod` for
//!   detected vtables; `InferredStruct`, `InferredField`, `FieldType` for
//!   string-inferred layouts; `TypeDatabase`, `ScanMetadata` for the
//!   persisted per-DLL database.
//! - [`scanner`] - Named type recovery: `TypeLibraryScanner` queries Ghidra's
//!   Type Manager through the bridge's `list_data_types` / `get_struct_layout`
//!   / `get_enum_values` endpoints, covering types never applied to a symbol.
//! - [`vtable`] - Vtable detection: `VtableDetector` scans `list_data_items`
//!   output for vtable-shaped data objects, resolves method pointers to names
//!   and addresses, tracks base-class inheritance, and detects COM interfaces.
//! - [`string_infer`] - String-guided inference: `StringInferenceEngine`
//!   infers struct layouts from string collection, cross-reference
//!   clustering, and confidence scoring.
//! - [`engine`] - Orchestration: [`engine::TypesDBEngine`] runs the three
//!   recovery engines concurrently over one program and assembles their
//!   results into a single [`types::TypeDatabase`].
//! - [`persist`] - JSON persistence: `TypeDatabasePersistor` saves and loads
//!   the per-DLL database under `re/analysis/typesdb/`.
//! - [`error`] - [`TypesDbError`] and the crate-wide [`Result`] alias.

pub mod engine;
pub mod error;
pub mod persist;
pub mod scanner;
pub mod string_infer;
pub mod types;
pub mod vtable;

pub use error::{Result, TypesDbError};

//! Core data types for the recovered type database.
//!
//! This module holds the serialized shape of everything the recovery engines
//! produce:
//!
//! - `NamedType`, `TypeKind`, `StructField`: named types pulled from Ghidra's
//!   Type Manager (struct, class, union, enum) with field layouts.
//! - `Vtable`, `VtableMethod`: detected vtables with resolved method pointers
//!   and base-class inheritance.
//! - `InferredStruct`, `InferredField`, `FieldType`: struct layouts inferred
//!   from string-literal clustering, with confidence scores.
//! - `TypeDatabase`, `ScanMetadata`: the persisted per-DLL database and its
//!   scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

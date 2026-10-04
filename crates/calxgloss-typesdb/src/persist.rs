//! JSON persistence for the type database.
//!
//! This module will provide `TypeDatabasePersistor`, saving and loading the
//! per-DLL `TypeDatabase` as JSON under the shared analysis directory:
//!
//! ```text
//! re/analysis/typesdb/
//!     └── {dll}.json
//! ```

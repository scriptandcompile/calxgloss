//! JSON persistence for memory lifecycle detection results.
//!
//! This module will provide `MemoryPersistor`, wrapping
//! [`calxgloss_types::persist::JsonStore`] the way `TypeDatabasePersistor`,
//! `TypeInferPersistor`, and `AlgorithmPersistor` do, saving and loading
//! the per-binary `MemoryResult` as JSON under the shared analysis
//! directory:
//!
//! ```text
//! re/analysis/memory/
//!     └── {dll}.json
//! ```

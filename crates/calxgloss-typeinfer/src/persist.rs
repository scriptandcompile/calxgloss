//! JSON persistence for type inference results.
//!
//! This module will provide `TypeInferPersistor`, wrapping
//! [`calxgloss_types::persist::JsonStore`] the way `TypeDatabasePersistor`
//! and `CallGraphPersistor` do, saving and loading the per-binary
//! `TypeInferenceResult` as JSON under the shared analysis directory:
//!
//! ```text
//! re/analysis/typeinfer/
//!     └── {dll}.json
//! ```

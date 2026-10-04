//! JSON persistence for type inference results.
//!
//! This module will provide `TypeInferPersistor`, saving and loading the
//! per-binary `TypeInferenceResult` as JSON under the shared analysis
//! directory:
//!
//! ```text
//! re/analysis/typeinfer/
//!     └── {dll}.json
//! ```

//! JSON persistence for algorithm recognition results.
//!
//! This module will provide `AlgorithmPersistor`, wrapping
//! [`calxgloss_types::persist::JsonStore`] the way `TypeDatabasePersistor`
//! and `TypeInferPersistor` do, saving and loading the per-binary
//! `AlgorithmRecognitionResult` as JSON under the shared analysis
//! directory:
//!
//! ```text
//! re/analysis/algorithm/
//!     └── {dll}.json
//! ```

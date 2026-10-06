//! String & Configuration Context (P8).
//!
//! Classifies the strings a function uses — error messages, user-visible text,
//! file paths, resource names, debug logs, network config, internal
//! identifiers, format strings — and maps them to the functions that
//! reference them, so the translator can infer a function's purpose and its
//! likely argument types.
//!
//! This crate provides:
//! - [`StringClassifyEngine`] — classifies strings into the nine categories
//! - [`FormatStringEngine`] — extracts Rust type hints from format specifiers
//! - [`HybridXrefMapper`] — maps strings to functions via decompiled-body
//!   parsing with an xref fallback
//! - [`StringContextEngine`] — orchestrates the above over a scan source
//! - [`StringContextPersistor`] — saves/loads results as per-binary JSON
//!
//! # Example
//!
//! ```
//! use calxgloss_stringctx::{StringClassifyEngine, StringClassification};
//!
//! let engine = StringClassifyEngine::with_default_patterns();
//! assert_eq!(
//!     engine.classify("Unable to connect to server"),
//!     StringClassification::Error
//! );
//! ```

pub mod classify;
pub mod error;
pub mod format_str;
pub mod hybrid_mapper;
pub mod persist;
pub mod types;

pub use classify::{CategoryPatterns, StringClassifyEngine};
pub use error::{Result, StringCtxError};
pub use format_str::{FormatStringEngine, extract_format_hints};
pub use hybrid_mapper::{
    BODY_CONFIDENCE, FormatCall, HybridXrefMapper, MappedString, XREF_CONFIDENCE,
};
pub use persist::StringContextPersistor;
pub use types::{
    ClassifiedString, FormatHint, FormatStringUse, StringClassification, StringContextResult,
    StringFinding, StringSource,
};

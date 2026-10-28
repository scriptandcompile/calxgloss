//! String & Configuration Context (P8).
//!
//! This crate works out what the strings a function uses are for — error
//! messages, user-visible text, file paths, resource names, debug logs,
//! network config, internal identifiers, format strings. It also maps each
//! string to the functions that reference it. The translator uses both
//! results to infer a function's purpose and its likely argument types.
//!
//! This crate provides:
//! - [`StringClassifyEngine`] — classifies strings into the nine categories
//! - [`FormatStringEngine`] — extracts Rust type hints from format specifiers
//! - [`HybridXrefMapper`] — maps strings to functions by parsing decompiled
//!   bodies, with an xref fallback
//! - [`LocalizationDetector`] — reads localization signals (language names,
//!   locale codes, non-ASCII user-facing text) from a function's mapped strings
//! - [`CrossFunctionAnalyzer`] — finds strings that pass across call
//!   boundaries between decompiled bodies
//! - [`StringContextEngine`] — runs the parts above against one scan source
//! - [`StringContextPersistor`] — saves and loads results as per-binary JSON
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
pub mod cross_function;
pub mod engine;
pub mod error;
pub mod format_str;
pub mod hybrid_mapper;
pub mod localization;
pub mod persist;
pub mod types;

pub use classify::{CategoryPatterns, StringClassifyEngine};
pub use cross_function::{
    CROSS_FUNCTION_CONFIDENCE, CROSS_FUNCTION_SUGGESTION, CrossFunctionAnalyzer,
};
pub use engine::{ScanSource, StringContextEngine};
pub use error::{Result, StringCtxError};
pub use format_str::{FormatStringEngine, extract_format_hints, summarize_hints};
pub use hybrid_mapper::{
    BODY_CONFIDENCE, FormatCall, HybridXrefMapper, MappedString, XREF_CONFIDENCE,
};
pub use localization::{LOCALIZATION_CONFIDENCE, LOCALIZATION_SUGGESTION, LocalizationDetector};
pub use persist::StringContextPersistor;
pub use types::{
    ClassifiedString, CrossFunctionFlow, FormatHint, FormatStringUse, LocalizationSignalKind,
    LocalizationSignals, StringClassification, StringContextResult, StringFinding, StringSource,
};

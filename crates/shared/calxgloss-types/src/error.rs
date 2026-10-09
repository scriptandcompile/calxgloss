//! Domain errors for the calxgloss-types crate.
//!
//! This module defines `TypesError`, the unified error type used throughout
//! the shared types crate. It wraps serialization failures and domain-specific
//! validation errors encountered when constructing or manipulating types
//! such as [`GitBranch`](crate::GitBranch).

use thiserror::Error;

/// Unified error type for calxgloss-types operations.
///
/// Covers serialization failures, validation errors (e.g., empty DLL or
/// function names), and domain-specific conditions like missing exports or
/// imports in a DLL.
#[derive(Debug, Error)]
pub enum TypesError {
    /// JSON serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A binary identity was empty or unparseable.
    #[error("empty binary name")]
    EmptyBinaryName,

    /// A function name was empty or unparseable.
    #[error("empty function name")]
    EmptyFunctionName,

    /// No exports were found in the requested DLL.
    #[error("no exports found in DLL: {0}")]
    NoExports(String),

    /// No imports were found in the requested DLL.
    #[error("no imports found in DLL: {0}")]
    NoImports(String),

    /// The requested function was not found in the specified binary.
    #[error("function not found: {binary}!{function}")]
    FunctionNotFound { binary: String, function: String },

    /// The generated branch name was invalid.
    #[error("invalid branch name: {0}")]
    InvalidBranchName(String),
}

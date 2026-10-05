//! Configuration error types.

use std::path::PathBuf;
use thiserror::Error;

/// Errors from locating, reading, or parsing configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A file named with `--config` does not exist.
    #[error("--config was given {path}, but that file does not exist")]
    MissingExplicitFile { path: PathBuf },

    /// A candidate file could not be read.
    #[error("Could not read the config file at {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A candidate file is not valid TOML, or does not match the schema.
    #[error(
        "The config file at {path} is not valid:\n{problem}\n\nA minimal file is:\n\n{expected}"
    )]
    Invalid {
        path: PathBuf,
        /// The parser's own explanation, including a line and column.
        problem: String,
        /// A commented example showing every recognised key.
        expected: &'static str,
    },
}

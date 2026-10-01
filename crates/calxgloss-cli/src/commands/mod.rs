//! Command handlers for the CLI.

pub mod init;
pub mod classify;
pub mod auto_shim;
pub mod translate;
pub mod batch_translate;
pub mod dashboard;
pub mod auto;
pub mod verify;
pub mod serve;
pub mod live;

// Re-export helper functions used across command files.
pub use init::{scan_targets, classification_record_exists};

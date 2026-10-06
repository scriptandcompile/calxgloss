//! Command handlers for the CLI.

pub mod algorithm;
pub mod apidetect;
pub mod auto;
pub mod auto_shim;
pub mod batch_translate;
pub mod callback;
pub mod classify;
pub mod consts;
pub mod controlflow;
pub mod dashboard;
pub mod gc;
pub mod init;
pub mod live;
pub mod memory;
pub mod serialize;
pub mod serve;
pub mod stringctx;
pub mod sync;
pub mod translate;
pub mod typeinfer;
pub mod typesdb;
pub mod verify;

// Re-export helper functions used across command files.
pub use init::{classification_record_exists, scan_targets};

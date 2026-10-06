//! Endianness and serialization detection for calxgloss.
//!
//! Analyzes byte-swap calls, manual bit-packing, and format sniffing
//! within each function of an open Ghidra program. Results are injected
//! as structured SERIALIZATION sections that name the Rust
//! serialization pattern — `byteorder::BE::read_u32`, `bitvec` or
//! named-field masking, `png::Decoder`, `flate2::read::GzDecoder`,
//! `zip::ZipArchive` — the translation should aim at, so a binary's
//! hand-rolled wire formats become typed reads instead of transliterated
//! shift-and-or chains.
//!
//! # Architecture
//!
//! The crate is organized around the detectors the engine runs:
//!
//! - [`types`] - Core data types: `ByteSwapOperation` for the
//!   per-function byte-swap record; `SerializeFinding` as the union
//!   over the record kinds; `SerializeResult`, `ScanMetadata` for the
//!   persisted per-binary results.
//! - [`persist`] - JSON persistence: `SerializePersistor` saves and
//!   loads the per-binary detection results under `re/analysis/serialize/`.
//! - [`error`] - [`SerializeError`] and the crate-wide [`Result`] alias.
//!
//! The byte-swap, bit-pack, and magic-byte detectors and the scan
//! engine land alongside them as the phase progresses.

pub mod error;
pub mod persist;
pub mod types;

pub use error::{Result, SerializeError};

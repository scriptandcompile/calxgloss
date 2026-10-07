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
//! - [`byteswap`] - Byte-swap call detection: `ByteSwapDetector`
//!   recognizes `ntohs`/`ntohl`/`htons`/`htonl`, `bswap32`, and the
//!   `__builtin_bswap16/32/64` spellings and suggests the matching
//!   `byteorder` reader.
//! - [`bitpack`] - Bit-packing pattern detection: `BitPackDetector`
//!   reads shift-and-or pack chains and shift-then-mask unpack chains
//!   and suggests `bitvec` or named-field masking and shifting.
//! - [`engine`] - Scan orchestration: `SerializeEngine` runs the
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order.
//! - [`persist`] - JSON persistence: `SerializePersistor` saves and
//!   loads the per-binary detection results under `re/analysis/serialize/`.
//! - [`error`] - [`SerializeError`] and the crate-wide [`Result`] alias.
//!
//! The magic-byte detector lands alongside these as the phase
//! progresses.

pub mod bitpack;
pub mod byteswap;
pub mod engine;
pub mod error;
pub mod persist;
pub mod types;

pub use error::{Result, SerializeError};

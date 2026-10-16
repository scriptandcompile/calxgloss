//! Endianness and serialization detection for calxgloss.
//!
//! Analyzes byte-swap calls, manual bit-packing, format sniffing,
//! cross-field validation, and the composed serialization layout within
//! each function of an open Ghidra
//! program. Results are injected as structured SERIALIZATION sections
//! that name the Rust
//! serialization pattern — `byteorder::BE::read_u32`, `bitvec` or
//! named-field masking, `png::Decoder`, `flate2::read::GzDecoder`,
//! `zip::ZipArchive`, a checked parse or validate step — the
//! translation should aim at, so a binary's hand-rolled wire formats
//! become typed reads instead of transliterated shift-and-or chains.
//!
//! # Architecture
//!
//! The crate is organized around the detectors the engine runs:
//!
//! - [`types`] - Core data types: `ByteSwapOperation` for the
//!   per-function byte-swap record; `CrossFieldValidation` for the
//!   message-integrity record; `SerializeFinding` as the union
//!   over the record kinds; `SerializeResult`, `ScanMetadata` for the
//!   persisted per-binary results.
//! - [`byteswap`] - Byte-swap call detection: `ByteSwapDetector`
//!   recognizes `ntohs`/`ntohl`/`htons`/`htonl`, `bswap32`, and the
//!   `__builtin_bswap16/32/64` spellings and suggests the matching
//!   `byteorder` reader.
//! - [`bitpack`] - Bit-packing pattern detection: `BitPackDetector`
//!   reads shift-and-or pack chains and shift-then-mask unpack chains
//!   and suggests `bitvec` or named-field masking and shifting.
//! - [`magic_bytes`] - Magic-byte detection: `MagicByteDetector`
//!   recognizes comparisons against the PNG, gzip, and ZIP file-format
//!   signatures and suggests the matching decoder — `png::Decoder`,
//!   `flate2::read::GzDecoder`, `zip::ZipArchive`.
//! - [`validation`] - Cross-field validation detection:
//!   `ValidationDetector` reads the comparisons that define message
//!   integrity — a stored field checked against a value computed from
//!   other fields (a checksum) and a read length checked against a
//!   buffer size or remaining count (framing) — and suggests the check
//!   be modelled on the Rust type as a checked parse or validate step.
//! - [`format`] - Serialization format inference: `FormatCombiner`
//!   composes the byte-swap and bit-pack readings one function carries
//!   into a single `SerializationFormat` layout — an ordered field
//!   sequence with wire byte orders and bitfield widths, and a
//!   reader-or-writer direction only when the swap name families
//!   agree — riding end to end instead of as scattered per-call hints.
//! - [`engine`] - Scan orchestration: `SerializeEngine` runs the
//!   detectors over one open Ghidra program through a `ScanSource`
//!   (function listing + decompile-by-name), one sequential pass that
//!   decompiles each function exactly once and keeps the findings in
//!   scan order.
//! - [`persist`] - JSON persistence: `SerializePersistor` saves and
//!   loads the per-binary detection results under `re/analysis/serialize/`.
//! - [`error`] - [`SerializeError`] and the crate-wide [`Result`] alias.

pub mod bitpack;
pub mod byteswap;
pub mod engine;
pub mod error;
pub mod format;
pub mod magic_bytes;
pub mod persist;
mod scan;
pub mod types;
pub mod validation;

pub use error::{Result, SerializeError};

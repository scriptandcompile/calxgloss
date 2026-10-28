//! Endianness and serialization detection for calxgloss.
//!
//! The serialization scan finds byte-swap calls, manual bit-packing,
//! format sniffs, cross-field validation, the composed serialization
//! layout, and corroborated protocol message handlers in each function
//! of a loaded program. It also maps the program-wide endianness that
//! the byte-swap calls add up to.
//!
//! The scan's results are injected as structured SERIALIZATION sections.
//! Each section names the Rust serialization pattern the translation
//! should aim at — `byteorder::BE::read_u32`, `bitvec` or named-field
//! masking, `png::Decoder`, `flate2::read::GzDecoder`, `zip::ZipArchive`,
//! a checked parse or validate step, a named protocol's decoding. This
//! turns a binary's hand-rolled wire formats into typed reads instead of
//! word-for-word copies of its shift-and-or chains.
//!
//! # Architecture
//!
//! The crate is organized around the detectors the scan runs:
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
//!   buffer size or remaining count (framing). It suggests modelling
//!   the check as a checked parse or validate step on the Rust type.
//! - [`format`] - Serialization format inference: `FormatCombiner`
//!   combines the byte-swap and bit-pack readings found in one function
//!   into a single `SerializationFormat` layout — an ordered field
//!   sequence with wire byte orders and bitfield widths, and a
//!   reader-or-writer direction only when the swap name families
//!   agree. The layout is used as one whole record, instead of as
//!   scattered per-call hints.
//! - [`protocol`] - Protocol message identification:
//!   `ProtocolMessageCombiner` promotes a protocol-table magic
//!   comparison, when a network-order swap or a cross-field validation
//!   corroborates it, into a single `ProtocolMessage` finding. The
//!   finding names the protocol and lists its corroborating readings.
//!   A bare sniff and a file-format magic never promote.
//! - [`endianness`] - Program-wide endianness mapping:
//!   `EndiannessProfiler` groups the scan's byte-swap findings by
//!   entry width into one `EndiannessMap` finding: which widths have
//!   network-order traffic, and which functions contribute each
//!   width. The scan appends it after the per-function findings.
//! - [`engine`] - Scan orchestration: `SerializeEngine` runs the
//!   detectors over one loaded program through a `ScanSource` (a
//!   function listing plus decompile-by-name). It is one sequential
//!   pass: it decompiles each function exactly once and keeps the
//!   findings in scan order.
//! - [`persist`] - JSON persistence: `SerializePersistor` saves and
//!   loads the per-binary detection results under `re/analysis/serialize/`.
//! - [`error`] - [`SerializeError`] and the crate-wide [`Result`] alias.

pub mod bitpack;
pub mod byteswap;
pub mod endianness;
pub mod engine;
pub mod error;
pub mod format;
pub mod magic_bytes;
pub mod persist;
pub mod protocol;
mod scan;
pub mod types;
pub mod validation;

pub use error::{Result, SerializeError};

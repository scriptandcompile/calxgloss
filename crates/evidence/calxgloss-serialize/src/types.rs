//! Core data types for endianness and serialization information.
//!
//! This module holds the serialized shape of everything the serialization
//! detectors produce:
//!
//! - `ByteSwapOperation`: the per-function byte-swap record — the
//!   recognized swap call the function makes, the width it swaps, and
//!   the `byteorder` reader the call reads like.
//! - `BitPackRecord`, `BitPackPattern`: the bit-packing record — the
//!   pack or unpack chain the function carries, the field widths its
//!   shifts and masks carve, and the typed-field suggestion they read
//!   like.
//! - `MagicFormat`: the format-sniffing record — the file-format
//!   signature the function compares buffer content against, the
//!   format it names, and the decoder crate suggested for it.
//! - `CrossFieldValidation`, `ValidationShape`: the message-integrity
//!   record — the stored field the function compares against a value
//!   computed from other fields (a checksum check) or the read length
//!   it compares against a buffer size or remaining count (framing),
//!   and which of the two shapes the check was read from.
//! - `SerializationFormat`, `FormatField`, `WireEndianness`,
//!   `FormatDirection`: the composed-layout record — the byte-swap and
//!   bit-pack readings one function carries, combined in body order
//!   into an ordered field layout naming each field's width, the wire
//!   byte order for swapped fields, the bitfield widths for packed
//!   chains, and a reader-or-writer direction only when the swap name
//!   families agree.
//! - `ProtocolMessage`: the identified message handler — made by the
//!   protocol combiner, not a body detector — the protocol-table magic
//!   the function compares against, the protocol it names, and the
//!   corroborating readings (network-order swaps, cross-field
//!   validations) that promote the sniff to a handler.
//! - `EndiannessMap`, `EndiannessEntry`: the binary-level endianness
//!   profile — made by the endianness profiler, not a body detector —
//!   the scan's byte-swap findings coalesced by operation width: each
//!   entry names the width, the wire byte order the swap names
//!   support (BE for the network-order family, reversal-only for
//!   direction-neutral builtins), and the contributing functions in
//!   listing order; widths with no observed swaps are absent.
//! - `SerializeFinding`: the union over the record kinds — one finding
//!   whichever detector made it — serde-tagged by `kind`.
//! - `SerializeResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm, and
// memory convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Byte-swap operations
// ============================================================

/// One byte-swap observation about one function, with the evidence
/// behind it.
///
/// A record says the function reorders bytes through the recognized
/// call spelling [`operation`](Self::operation) — `ntohl`, `htons`,
/// `__builtin_bswap32`, and their kin — swapping a value
/// [`width`](Self::width) bits wide. The call reads like
/// [`suggestion`](Self::suggestion): the `byteorder` reader or writer
/// for that width, which makes the host-order-to-network-order hop an
/// explicit type instead of a transliterated call. The call line is
/// kept as [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSwapOperation {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The call spelling that performed the swap, e.g. `ntohl`.
    pub operation: String,
    /// The width the call swaps, in bits: 16, 32, or 64.
    pub width: u32,
    /// The Rust pattern the call suggests, e.g.
    /// `byteorder::BE::read_u32`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the swap call —
    /// kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Bit-packing records
// ============================================================

/// The bit-packing shape a finding was read from.
///
/// The shape says which direction the code moves bits: a
/// `shift_or_pack` builds a word out of fields — `(a << 0x18) |
/// (b << 0x10) | ...` — and a `shift_mask_unpack` takes a word apart —
/// `(w >> 0x18) & 0xff` — the two halves of a hand-rolled format's
/// read and write. Both read like the same Rust suggestion: `bitvec`,
/// or named-field masking and shifting on a plain integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitPackPattern {
    /// Fields shifted to their offsets and ORed into a word.
    ShiftOrPack,
    /// A word shifted right and masked to pull a field out.
    ShiftMaskUnpack,
}

calxgloss_types::display_serde_label!(BitPackPattern {
    ShiftOrPack => "shift_or_pack",
    ShiftMaskUnpack => "shift_mask_unpack",
});

/// One bit-packing observation about one function, with the evidence
/// behind it.
///
/// A record says the function packs or unpacks a word through the
/// [`pattern`](Self::pattern) shape — a shift-and-or chain or a run of
/// shift-then-mask extractions — carving out fields of the
/// [`widths`](Self::widths) its shifts and masks imply, in bit order
/// from the top of the word down. The shape reads like
/// [`suggestion`](Self::suggestion): a typed field view — `bitvec`, or
/// named-field masking and shifting — instead of the hand-rolled
/// shifts. The matched expression (or, for an unpack chain, the
/// extractions joined) is kept as [`evidence`](Self::evidence) so a
/// reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitPackRecord {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The packing shape the record was read from.
    pub pattern: BitPackPattern,
    /// The field widths the shifts and masks carve out, in bits, from
    /// the top of the word down.
    pub widths: Vec<u32>,
    /// The Rust pattern the chain suggests, e.g. `bitvec or
    /// named-field masking/shifting`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line or lines that support the record — the
    /// pack expression, or the unpack extractions joined — kept so a
    /// reviewer (or a translation prompt) can check the reasoning.
    pub evidence: String,
}

// ============================================================
// Magic-byte records
// ============================================================

/// One format-sniffing observation about one function, with the
/// evidence behind it.
///
/// A record says the function compares loaded buffer content against
/// the [`magic`](Self::magic) bytes of a known file format —
/// [`format`](Self::format), e.g. `PNG` — sniffing for a format it
/// then parses by hand. The sniff reads like
/// [`suggestion`](Self::suggestion): the decoder type from the crate
/// that format has — `png::Decoder`, `flate2::read::GzDecoder`,
/// `zip::ZipArchive` — which replaces the sniff *and* the hand-rolled
/// parse that follows it. The comparison line is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicFormat {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The signature bytes matched, spelled as the comparison spells
    /// them, e.g. `0x8950_4E47` for PNG.
    pub magic: u64,
    /// The format the signature names, e.g. `PNG`.
    pub format: String,
    /// The Rust type the sniff suggests, e.g. `png::Decoder`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the signature
    /// comparison — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Cross-field validation records
// ============================================================

/// The validation shape a cross-field finding was read from.
///
/// The shape says which integrity check the comparison performs: a
/// `checksum` compares a stored field against a value computed from
/// other fields — `if (checksum == computed_sum)` — and a `length`
/// compares a read length against a buffer size or remaining count,
/// the framing check that keeps a parser inside its buffer. Both read
/// like the same Rust suggestion: the check modelled on the type — a
/// checked parse or validate step — instead of a bare comparison that
/// translation can silently drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationShape {
    /// A stored field compared against a value computed from other
    /// fields.
    Checksum,
    /// A read length compared against a buffer size or remaining
    /// count.
    Length,
}

calxgloss_types::display_serde_label!(ValidationShape {
    Checksum => "checksum",
    Length => "length",
});

/// One message-integrity observation about one function, with the
/// evidence behind it.
///
/// A record says the function validates its input through the
/// [`shape`](Self::shape) check — comparing the stored
/// [`field`](Self::field) against the [`computed`](Self::computed)
/// expression the check verifies it against — the checksum or framing
/// logic that defines a wire format's integrity story. The check reads
/// like [`suggestion`](Self::suggestion): modelled on the Rust type as
/// a checked parse or validate step, so translated code keeps the
/// integrity logic instead of dropping the comparison. The comparison
/// line is kept as [`evidence`](Self::evidence) so a reviewer (or a
/// translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFieldValidation {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The stored field the check validates, spelled as the
    /// comparison spells it, e.g. `uVar7`.
    pub field: String,
    /// The computed side the field is verified against — the
    /// expression over the other fields (or the size or remaining
    /// count) the comparison puts on the far side, e.g.
    /// `uVar5 + uVar6`.
    pub computed: String,
    /// The validation shape the record was read from.
    pub shape: ValidationShape,
    /// The Rust pattern the check suggests, e.g. `checked parse or
    /// validate step on the Rust type`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the comparison
    /// — kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Serialization format records
// ============================================================

/// The wire byte order a swapped layout field carries.
///
/// The claim comes from the swap name family alone: a network-order
/// spelling (`ntohl`, `htons`, and their kin) says the field arrives
/// big-endian, while a direction-neutral builtin (`__builtin_bswap32`
/// and friends) only says the bytes are reversed — which wire order
/// that reversal corresponds to depends on the host, so the record
/// claims no endianness for such a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireEndianness {
    /// A network-order swap name: the field's wire order is big-endian.
    #[serde(rename = "be")]
    BigEndian,
    /// A direction-neutral swap name: the bytes are reversed and no
    /// wire order is claimed.
    #[serde(rename = "reversal_only")]
    ReversalOnly,
}

calxgloss_types::display_serde_label!(WireEndianness {
    BigEndian => "be",
    ReversalOnly => "reversal_only",
});

/// Which way the composed layout moves bytes, named only when the
/// directional swap names all point the same way.
///
/// A `reader` layout comes from network-to-host names only — the
/// function pulls messages in; a `writer` layout from host-to-network
/// names only — it puts messages out. Direction-neutral names
/// (builtins, a program's own swap spelling) neither corroborate nor
/// contradict a direction; when the directional families disagree, or
/// when no directional name was seen at all, the layout names no
/// direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatDirection {
    /// Every directional swap name moves bytes network-to-host.
    Reader,
    /// Every directional swap name moves bytes host-to-network.
    Writer,
}

calxgloss_types::display_serde_label!(FormatDirection {
    Reader => "reader",
    Writer => "writer",
});

/// One field of a composed layout: its width and, for a field the
/// function moves through a byte-swap call, the wire byte order that
/// call's name family implies. A packed bitfield carved out of a
/// shift-and-mask chain carries no endianness — the chain moves bits
/// inside one word, not bytes over a wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatField {
    /// The field's width, in bits.
    pub width: u32,
    /// The wire byte order the field arrives with — present for a
    /// field read or written through a byte-swap call, absent for a
    /// packed bitfield.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<WireEndianness>,
}

/// The composed serialization layout one function's readings add up
/// to — made by the format combiner, not by a body detector.
///
/// A record says the function carries at least two serialization
/// readings — byte-swap calls and/or bit-pack chains — and combines
/// them, in body order, into an ordered [`fields`](Self::fields)
/// sequence: each swapped field names its width and its
/// [`endianness`](Self::endianness), each packed chain contributes
/// its bitfield widths, and [`direction`](Self::direction) names a
/// reader or a writer only when the swap name families agree. The
/// sequence reads like [`suggestion`](Self::suggestion): a typed
/// field-sequence reader sketch in `byteorder` style, so a translation
/// prompt sees one real reader instead of scattered per-call hints.
/// The body lines behind the sequence are kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializationFormat {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The layout's fields, in the body order the readings appear in.
    pub fields: Vec<FormatField>,
    /// The direction the layout moves bytes — named only when the
    /// swap name families agree, absent when they disagree or only
    /// direction-neutral names were seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<FormatDirection>,
    /// The Rust pattern the sequence suggests, e.g. `byteorder
    /// reader: read_u32 then 8+8 bitfields`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines behind the sequence — the contributing
    /// readings' own evidence lines, in body order — kept so a
    /// reviewer (or a translation prompt) can check the composition.
    pub evidence: String,
}

// ============================================================
// Protocol message records
// ============================================================

/// One protocol-message-handler identification about one function —
/// made by the protocol combiner, not by a body detector.
///
/// A record says the function compares loaded buffer content against
/// the [`magic`](Self::magic) of a protocol-table entry — naming the
/// [`protocol`](Self::protocol), e.g. `IPv6` — and corroborates the
/// sniff with at least one independent reading, a network-order swap
/// or a cross-field validation, each listed in
/// [`corroborations`](Self::corroborations) so the identification is
/// auditable. The handler reads like [`suggestion`](Self::suggestion):
/// protocol-aware decoding of the named protocol's messages, so the
/// translation parses the message with the protocol's own structure
/// instead of transliterating a bare sniff. The magic comparison and
/// the corroborating readings' own lines are kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The protocol signature bytes matched, spelled as the
    /// comparison spells them, e.g. `0x86dd` for IPv6.
    pub magic: u64,
    /// The protocol the signature names, e.g. `IPv6`.
    pub protocol: String,
    /// The corroborating readings, each naming the reading and what
    /// it was — `ntohl swap`, `checksum validation` — in the order
    /// the scan collected them.
    pub corroborations: Vec<String>,
    /// The Rust pattern the handler suggests, e.g. `protocol-aware
    /// IPv6 message decode (byteorder BE reads)`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled lines behind the identification — the magic
    /// comparison and the corroborating readings' own lines — kept so
    /// a reviewer (or a translation prompt) can audit the promotion.
    pub evidence: String,
}

// ============================================================
// Endianness map records
// ============================================================

/// One width's entry in the binary-level endianness profile: the
/// width the swap calls carry, the wire byte order their names
/// support, and the functions that made the observations.
///
/// The endianness comes from the swap name family alone, exactly as
/// the composed layout's per-field order does: a network-order
/// spelling (`ntohl`, `htons`, and their kin) says the width travels
/// big-endian, while a width seen only through direction-neutral
/// builtins carries [`WireEndianness::ReversalOnly`] — the bytes
/// reverse and no wire order is claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndiannessEntry {
    /// The width the swaps carry, in bits: 16, 32, or 64.
    pub width: u32,
    /// The wire byte order the swap names support for this width.
    pub endianness: WireEndianness,
    /// The functions that made the observations, in listing order,
    /// each named once however many swaps it made at this width.
    pub functions: Vec<String>,
}

/// The binary-level endianness profile one scan coalesces from its
/// byte-swap findings — made by the endianness profiler, not by a
/// body detector.
///
/// A record says the binary moves [`entries`](Self::entries) — one
/// per width its swap calls were seen at, ascending — each naming
/// the wire byte order the names support and the contributing
/// functions; widths with no observed swaps are absent, so the record
/// claims only what was seen. Like the apidetect divergence claim the
/// profile belongs to the binary rather than any one function, so
/// [`function`](Self::function) reads as the empty string. The
/// profile reads like [`suggestion`](Self::suggestion): the
/// `byteorder` types the widths' wire orders imply, so a
/// function-level translation prompt still gets the program-level
/// profile. The first swap line seen at each width is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the profile against the decompilations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndiannessMap {
    /// Empty: the claim belongs to the binary, not to one function —
    /// the apidetect divergence precedent.
    pub function: String,
    /// One entry per observed width, ascending; widths with no
    /// observed swaps are absent.
    pub entries: Vec<EndiannessEntry>,
    /// The Rust pattern the profile suggests, e.g. `program-wide BE
    /// wire order at u32 (byteorder BE types)`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The first swap line seen at each entry's width, in entry
    /// order — kept so a reviewer (or a translation prompt) can
    /// check the profile.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One serialization finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function, suggestion,
/// confidence, evidence — without naming which detector produced it.
/// The detectors read disjoint body shapes — a swap call, a shift-and-or
/// chain, a signature comparison, an integrity comparison — so nothing
/// is resolved between variants (the validation detector's gate against
/// magic hits runs where the engine hands it the magic findings, not in
/// the union, and the format and protocol-message records are composed
/// by the engine's post-read over the findings the pass already made,
/// not by a detector). The serde `kind` tag names the record shape in
/// the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SerializeFinding {
    /// A byte reordering through a recognized swap call.
    #[serde(rename = "byteswap")]
    ByteSwap(ByteSwapOperation),
    /// A hand-rolled pack or unpack chain moving fields through a word.
    #[serde(rename = "bitpack")]
    BitPack(BitPackRecord),
    /// A comparison against a known file-format signature.
    #[serde(rename = "magic")]
    Magic(MagicFormat),
    /// A stored field checked against a value computed from other
    /// fields, or a read length checked against a size or remaining
    /// count.
    #[serde(rename = "cross_field_validation")]
    CrossFieldValidation(CrossFieldValidation),
    /// Two or more serialization readings composed into one ordered
    /// field layout.
    #[serde(rename = "serialization_format")]
    SerializationFormat(SerializationFormat),
    /// A protocol-table magic comparison corroborated by a
    /// network-order swap or a cross-field validation — an identified
    /// protocol message handler.
    #[serde(rename = "protocol_message")]
    ProtocolMessage(ProtocolMessage),
    /// The scan's byte-swap findings coalesced by operation width
    /// into one binary-level wire-order profile.
    #[serde(rename = "endianness_map")]
    EndiannessMap(EndiannessMap),
}

impl SerializeFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.function,
            SerializeFinding::BitPack(record) => &record.function,
            SerializeFinding::Magic(record) => &record.function,
            SerializeFinding::CrossFieldValidation(record) => &record.function,
            SerializeFinding::SerializationFormat(record) => &record.function,
            SerializeFinding::ProtocolMessage(record) => &record.function,
            SerializeFinding::EndiannessMap(record) => &record.function,
        }
    }

    /// The Rust serialization pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.suggestion,
            SerializeFinding::BitPack(record) => &record.suggestion,
            SerializeFinding::Magic(record) => &record.suggestion,
            SerializeFinding::CrossFieldValidation(record) => &record.suggestion,
            SerializeFinding::SerializationFormat(record) => &record.suggestion,
            SerializeFinding::ProtocolMessage(record) => &record.suggestion,
            SerializeFinding::EndiannessMap(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            SerializeFinding::ByteSwap(record) => record.confidence,
            SerializeFinding::BitPack(record) => record.confidence,
            SerializeFinding::Magic(record) => record.confidence,
            SerializeFinding::CrossFieldValidation(record) => record.confidence,
            SerializeFinding::SerializationFormat(record) => record.confidence,
            SerializeFinding::ProtocolMessage(record) => record.confidence,
            SerializeFinding::EndiannessMap(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.evidence,
            SerializeFinding::BitPack(record) => &record.evidence,
            SerializeFinding::Magic(record) => &record.evidence,
            SerializeFinding::CrossFieldValidation(record) => &record.evidence,
            SerializeFinding::SerializationFormat(record) => &record.evidence,
            SerializeFinding::ProtocolMessage(record) => &record.evidence,
            SerializeFinding::EndiannessMap(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `byteswap`, `bitpack`, `magic`,
    /// `cross_field_validation`, `serialization_format`,
    /// `protocol_message`, or `endianness_map` — naming the reading
    /// behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            SerializeFinding::ByteSwap(_) => "byteswap",
            SerializeFinding::BitPack(_) => "bitpack",
            SerializeFinding::Magic(_) => "magic",
            SerializeFinding::CrossFieldValidation(_) => "cross_field_validation",
            SerializeFinding::SerializationFormat(_) => "serialization_format",
            SerializeFinding::ProtocolMessage(_) => "protocol_message",
            SerializeFinding::EndiannessMap(_) => "endianness_map",
        }
    }

    /// What the finding names, spelled for a report row: the swap call
    /// spelling, the packing shape and the field widths it carves, the
    /// format and the signature bytes that name it, the validation
    /// shape and the field it validates, the composed layout —
    /// direction when it is named, then the ordered fields with their
    /// widths and wire byte orders — the identified protocol and the
    /// magic bytes that name it, or the endianness profile — each
    /// observed width with the wire byte order its names support.
    pub fn target(&self) -> String {
        match self {
            SerializeFinding::ByteSwap(record) => record.operation.clone(),
            SerializeFinding::BitPack(record) => {
                let widths: Vec<String> = record.widths.iter().map(|w| w.to_string()).collect();
                format!("{} {}", record.pattern, widths.join("+"))
            }
            SerializeFinding::Magic(record) => {
                format!("{} {:#x}", record.format, record.magic)
            }
            SerializeFinding::CrossFieldValidation(record) => {
                format!("{} {}", record.shape, record.field)
            }
            SerializeFinding::SerializationFormat(record) => {
                let layout = layout_target(&record.fields);
                match record.direction {
                    Some(direction) => format!("{direction} {layout}"),
                    None => layout,
                }
            }
            SerializeFinding::ProtocolMessage(record) => {
                format!("{} {:#x}", record.protocol, record.magic)
            }
            SerializeFinding::EndiannessMap(record) => {
                let entries: Vec<String> = record
                    .entries
                    .iter()
                    .map(|entry| format!("u{}:{}", entry.width, entry.endianness))
                    .collect();
                entries.join(", ")
            }
        }
    }
}

/// The composed layout spelled for a report row: each swapped field as
/// its width and wire byte order (`u32:be`, `u16:reversal_only`),
/// consecutive packed bitfields grouped into one `8+8 bits` run, the
/// fields joined in body order.
fn layout_target(fields: &[FormatField]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut packed_run: Vec<u32> = Vec::new();
    for field in fields {
        match field.endianness {
            Some(endianness) => {
                flush_packed_run(&mut parts, &mut packed_run);
                parts.push(format!("u{}:{}", field.width, endianness));
            }
            None => packed_run.push(field.width),
        }
    }
    flush_packed_run(&mut parts, &mut packed_run);
    parts.join(" > ")
}

/// Flush one run of consecutive packed bitfield widths into the
/// layout parts as a single `8+8 bits` entry.
fn flush_packed_run(parts: &mut Vec<String>, run: &mut Vec<u32>) {
    if !run.is_empty() {
        let widths: Vec<String> = run.iter().map(|w| w.to_string()).collect();
        parts.push(format!("{} bits", widths.join("+")));
        run.clear();
    }
}

// ============================================================
// Prompt conversions
// ============================================================

/// Render a finding as prompt data: the function it is about, the kind
/// of serialization pattern the detector read, the Rust pattern the
/// finding suggests, and the confidence and evidence behind the claim —
/// so the escalate prompt shows the hypothesis and how strongly it was
/// made, whichever detector produced it.
impl From<&SerializeFinding> for calxgloss_prompts::SerializationInfo {
    fn from(finding: &SerializeFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The serialization result for one binary — the document persisted to
/// `re/analysis/serialize/{dll}.json`.
///
/// The findings are the detectors' outputs in scan order: function by
/// function, and within one function the byte swaps, then the bit
/// packs, then the magic-byte comparisons, then the cross-field
/// validation checks, then the composed format layout, then the
/// protocol-message identification; the binary-level endianness map
/// appends after every per-function finding. The detectors
/// read disjoint body shapes, so a function can carry findings of
/// every kind at once and none competes with another; the stable
/// order means two scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializeResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<SerializeFinding>,
}

impl SerializeResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    ///
    /// The binary-level endianness map is yielded for each of its
    /// contributing functions — the program-level profile is part of
    /// what a function-level prompt reads — and stays absent for the
    /// functions it never names.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &SerializeFinding> {
        self.findings
            .iter()
            .filter(move |finding| match &**finding {
                SerializeFinding::EndiannessMap(record) => record
                    .entries
                    .iter()
                    .any(|entry| entry.functions.iter().any(|f| f == function)),
                other => other.function() == function,
            })
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn byte_swap() -> ByteSwapOperation {
        ByteSwapOperation {
            function: "FUN_18003ab00".into(),
            operation: "ntohl".into(),
            width: 32,
            suggestion: "byteorder::BE::read_u32".into(),
            confidence: Confidence::new(70),
            evidence: "uVar1 = ntohl(local_18);".into(),
        }
    }

    #[test]
    fn a_byte_swap_operation_serde_round_trips() {
        let record = byte_swap();
        let json = serde_json::to_string(&record).unwrap();
        // The width serializes as a plain number and the confidence as
        // one too, matching the workspace's serde convention.
        assert!(json.contains("\"operation\":\"ntohl\""));
        assert!(json.contains("\"width\":32"));
        assert!(json.contains("\"confidence\":70"));
        let back: ByteSwapOperation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_byte_swap_record_names_the_function_the_call_the_width_and_the_pattern() {
        let json = serde_json::to_value(byte_swap()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["operation"], "ntohl");
        assert_eq!(json["width"], 32);
        assert_eq!(json["suggestion"], "byteorder::BE::read_u32");
        assert_eq!(json["confidence"], 70);
    }

    #[test]
    fn a_builtin_bswap_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "operation": "__builtin_bswap64",
            "width": 64,
            "suggestion": "byteorder::BE::read_u64",
            "confidence": 70,
            "evidence": "uVar2 = __builtin_bswap64(uVar1);"
        }"#;
        let back: ByteSwapOperation = serde_json::from_str(json).unwrap();
        assert_eq!(back.operation, "__builtin_bswap64");
        assert_eq!(back.width, 64);
        assert_eq!(back.suggestion, "byteorder::BE::read_u64");
    }

    #[test]
    fn a_byteswap_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::ByteSwap(byte_swap());
        let json = serde_json::to_string(&finding).expect("byteswap finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"byteswap\""));
        assert!(json.contains("\"operation\":\"ntohl\""));
        let back: SerializeFinding =
            serde_json::from_str(&json).expect("byteswap finding should read back");
        assert_eq!(back, finding);
    }

    fn bit_pack() -> BitPackRecord {
        BitPackRecord {
            function: "FUN_18003ab00".into(),
            pattern: BitPackPattern::ShiftOrPack,
            widths: vec![8, 8, 8, 8],
            suggestion: "bitvec or named-field masking/shifting".into(),
            confidence: Confidence::new(60),
            evidence:
                "uVar1 = (uVar2 << 0x18) | ((uint)uVar3 << 0x10) | (uVar4 << 8) | (uint)uVar5;"
                    .into(),
        }
    }

    #[test]
    fn a_bit_pack_record_serde_round_trips() {
        let record = bit_pack();
        let json = serde_json::to_string(&record).unwrap();
        // The pattern serializes snake_case and the widths as a plain
        // array, matching the workspace's serde convention.
        assert!(json.contains("\"pattern\":\"shift_or_pack\""));
        assert!(json.contains("\"widths\":[8,8,8,8]"));
        assert!(json.contains("\"confidence\":60"));
        let back: BitPackRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_bit_pack_record_names_the_function_the_pattern_the_widths_and_the_pattern_suggestion() {
        let json = serde_json::to_value(bit_pack()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["pattern"], "shift_or_pack");
        assert_eq!(json["widths"], serde_json::json!([8, 8, 8, 8]));
        assert_eq!(json["suggestion"], "bitvec or named-field masking/shifting");
        assert_eq!(json["confidence"], 60);
    }

    #[test]
    fn an_unpack_bit_pack_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "pattern": "shift_mask_unpack",
            "widths": [8, 8, 8],
            "suggestion": "bitvec or named-field masking/shifting",
            "confidence": 60,
            "evidence": "iVar2 = (uVar1 >> 0x18) & 0xff; iVar3 = (uVar1 >> 0x10) & 0xff;"
        }"#;
        let back: BitPackRecord = serde_json::from_str(json).unwrap();
        assert_eq!(back.pattern, BitPackPattern::ShiftMaskUnpack);
        assert_eq!(back.widths, [8, 8, 8]);
    }

    #[test]
    fn a_bitpack_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::BitPack(bit_pack());
        let json = serde_json::to_string(&finding).expect("bitpack finding should serialize");
        assert!(json.contains("\"kind\":\"bitpack\""));
        assert!(json.contains("\"pattern\":\"shift_or_pack\""));
        let back: SerializeFinding =
            serde_json::from_str(&json).expect("bitpack finding should read back");
        assert_eq!(back, finding);
    }

    fn magic_format() -> MagicFormat {
        MagicFormat {
            function: "FUN_18003ab00".into(),
            magic: 0x8950_4E47,
            format: "PNG".into(),
            suggestion: "png::Decoder".into(),
            confidence: Confidence::new(80),
            evidence: "if (uVar1 == 0x89504e47) {".into(),
        }
    }

    #[test]
    fn a_magic_format_record_serde_round_trips() {
        let record = magic_format();
        let json = serde_json::to_string(&record).unwrap();
        // The magic bytes serialize as a plain number, matching the
        // workspace's serde convention.
        assert!(json.contains("\"format\":\"PNG\""));
        assert!(json.contains("\"magic\":2303741511"));
        assert!(json.contains("\"confidence\":80"));
        let back: MagicFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_magic_format_record_names_the_function_the_bytes_the_format_and_the_crate() {
        let json = serde_json::to_value(magic_format()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["magic"], 0x8950_4E47u64);
        assert_eq!(json["format"], "PNG");
        assert_eq!(json["suggestion"], "png::Decoder");
        assert_eq!(json["confidence"], 80);
    }

    #[test]
    fn a_gzip_magic_format_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "magic": 35615,
            "format": "gzip",
            "suggestion": "flate2::read::GzDecoder",
            "confidence": 80,
            "evidence": "if (*(ushort *)pvVar2 == 0x8b1f) {"
        }"#;
        let back: MagicFormat = serde_json::from_str(json).unwrap();
        assert_eq!(back.format, "gzip");
        assert_eq!(back.magic, 0x8B1F);
        assert_eq!(back.suggestion, "flate2::read::GzDecoder");
    }

    #[test]
    fn a_magic_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::Magic(magic_format());
        let json = serde_json::to_string(&finding).expect("magic finding should serialize");
        assert!(json.contains("\"kind\":\"magic\""));
        assert!(json.contains("\"format\":\"PNG\""));
        let back: SerializeFinding =
            serde_json::from_str(&json).expect("magic finding should read back");
        assert_eq!(back, finding);
    }

    fn cross_field_validation() -> CrossFieldValidation {
        CrossFieldValidation {
            function: "FUN_18003ab00".into(),
            field: "uVar7".into(),
            computed: "uVar5 + uVar6".into(),
            shape: ValidationShape::Checksum,
            suggestion: "checked parse or validate step on the Rust type".into(),
            confidence: Confidence::new(65),
            evidence: "if (uVar7 == uVar5 + uVar6) {".into(),
        }
    }

    #[test]
    fn a_cross_field_validation_record_serde_round_trips() {
        let record = cross_field_validation();
        let json = serde_json::to_string(&record).expect("record should serialize");
        // The shape serializes snake_case, matching the workspace's
        // serde convention, and reads back whole.
        assert!(json.contains("\"shape\":\"checksum\""));
        assert!(json.contains("\"field\":\"uVar7\""));
        assert!(json.contains("\"computed\":\"uVar5 + uVar6\""));
        assert!(json.contains("\"confidence\":65"));
        let back: CrossFieldValidation =
            serde_json::from_str(&json).expect("record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_length_validation_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003e750",
            "field": "uVar4",
            "computed": "local_18 + -4",
            "shape": "length",
            "suggestion": "checked parse or validate step on the Rust type",
            "confidence": 65,
            "evidence": "if (uVar4 == local_18 + -4) {"
        }"#;
        let back: CrossFieldValidation =
            serde_json::from_str(json).expect("length record should read back");
        assert_eq!(back.shape, ValidationShape::Length);
        assert_eq!(back.field, "uVar4");
        assert_eq!(back.computed, "local_18 + -4");
    }

    #[test]
    fn a_cross_field_validation_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::CrossFieldValidation(cross_field_validation());
        let json = serde_json::to_string(&finding)
            .expect("cross-field validation finding should serialize");
        assert!(json.contains("\"kind\":\"cross_field_validation\""));
        assert!(json.contains("\"shape\":\"checksum\""));
        let back: SerializeFinding =
            serde_json::from_str(&json).expect("cross-field validation finding should read back");
        assert_eq!(back, finding);
    }

    fn serialization_format() -> SerializationFormat {
        SerializationFormat {
            function: "FUN_18003ab00".into(),
            fields: vec![
                FormatField {
                    width: 32,
                    endianness: Some(WireEndianness::BigEndian),
                },
                FormatField {
                    width: 8,
                    endianness: None,
                },
                FormatField {
                    width: 8,
                    endianness: None,
                },
            ],
            direction: Some(FormatDirection::Reader),
            suggestion: "byteorder reader: read_u32 then 8+8 bitfields".into(),
            confidence: Confidence::new(75),
            evidence: "uVar1 = ntohl(local_18); uVar2 = (uVar3 << 0x8) | (uint)uVar4;".into(),
        }
    }

    #[test]
    fn a_serialization_format_record_serde_round_trips() {
        let record = serialization_format();
        let json = serde_json::to_string(&record).expect("record should serialize");
        // The endianness and direction serialize as their serde labels,
        // a packed field omits its absent endianness, and the direction
        // rides as a plain string — matching the workspace convention.
        assert!(json.contains("\"endianness\":\"be\""));
        assert!(!json.contains("\"endianness\":null"));
        assert!(json.contains("\"direction\":\"reader\""));
        assert!(json.contains("\"confidence\":75"));
        let back: SerializationFormat =
            serde_json::from_str(&json).expect("record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_directionless_format_record_reads_back_from_json() {
        // A layout whose swap families disagree carries no direction at
        // all: the field is absent on disk and reads back as `None`.
        let json = r#"{
            "function": "FUN_18003e750",
            "fields": [
                { "width": 16, "endianness": "reversal_only" },
                { "width": 32, "endianness": "be" }
            ],
            "suggestion": "byteorder field sequence: read_u16 then read_u32",
            "confidence": 75,
            "evidence": "uVar1 = __builtin_bswap16(local_18); uVar2 = ntohl(local_20);"
        }"#;
        let back: SerializationFormat =
            serde_json::from_str(json).expect("directionless record should read back");
        assert_eq!(back.direction, None);
        assert_eq!(
            back.fields[0].endianness,
            Some(WireEndianness::ReversalOnly)
        );
        assert_eq!(back.fields[1].endianness, Some(WireEndianness::BigEndian));
    }

    #[test]
    fn the_layout_target_spells_direction_endianness_and_packed_runs() {
        // Reversal-only fields say `reversal_only`, packed runs group
        // into one `bits` entry, and a layout with no named direction
        // leads with the layout itself.
        let record = SerializationFormat {
            function: "FUN_18003e750".into(),
            fields: vec![
                FormatField {
                    width: 16,
                    endianness: Some(WireEndianness::ReversalOnly),
                },
                FormatField {
                    width: 4,
                    endianness: None,
                },
                FormatField {
                    width: 12,
                    endianness: None,
                },
                FormatField {
                    width: 32,
                    endianness: Some(WireEndianness::BigEndian),
                },
            ],
            direction: None,
            suggestion:
                "byteorder field sequence: u16.swap_bytes() then 4+12 bitfields then read_u32"
                    .into(),
            confidence: Confidence::new(75),
            evidence: "uVar1 = __builtin_bswap16(local_18);".into(),
        };
        let finding = SerializeFinding::SerializationFormat(record);
        assert_eq!(finding.target(), "u16:reversal_only > 4+12 bits > u32:be");
    }

    #[test]
    fn a_serialization_format_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::SerializationFormat(serialization_format());
        let json =
            serde_json::to_string(&finding).expect("serialization format finding should serialize");
        assert!(json.contains("\"kind\":\"serialization_format\""));
        assert!(json.contains("\"direction\":\"reader\""));
        let back: SerializeFinding =
            serde_json::from_str(&json).expect("serialization format finding should read back");
        assert_eq!(back, finding);
    }

    fn protocol_message() -> ProtocolMessage {
        ProtocolMessage {
            function: "FUN_18003ab00".into(),
            magic: 0x86DD,
            protocol: "IPv6".into(),
            corroborations: vec!["ntohl swap".into(), "checksum validation".into()],
            suggestion: "protocol-aware IPv6 message decode (byteorder BE reads)".into(),
            confidence: Confidence::new(85),
            evidence: "if (uVar1 == 0x86dd) { uVar2 = ntohl(local_18);".into(),
        }
    }

    #[test]
    fn a_protocol_message_record_serde_round_trips() {
        let record = protocol_message();
        let json = serde_json::to_string(&record).expect("protocol message should serialize");
        let back: ProtocolMessage =
            serde_json::from_str(&json).expect("protocol message should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_protocol_message_record_reads_back_from_json() {
        let json = r#"{
            "function": "FUN_18003ab00",
            "magic": 34525,
            "protocol": "IPv6",
            "corroborations": ["ntohl swap", "checksum validation"],
            "suggestion": "protocol-aware IPv6 message decode (byteorder BE reads)",
            "confidence": 85,
            "evidence": "if (uVar1 == 0x86dd) { uVar2 = ntohl(local_18);"
        }"#;
        let record: ProtocolMessage =
            serde_json::from_str(json).expect("protocol message should read back");
        assert_eq!(record.protocol, "IPv6");
        assert_eq!(record.magic, 0x86DD);
        assert_eq!(
            record.corroborations,
            vec!["ntohl swap", "checksum validation"]
        );
        assert_eq!(record.confidence, Confidence::new(85));
    }

    #[test]
    fn a_protocol_message_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::ProtocolMessage(protocol_message());
        let json = serde_json::to_string(&finding).expect("finding should serialize");
        assert!(json.contains("\"kind\":\"protocol_message\""));
        let back: SerializeFinding = serde_json::from_str(&json).expect("finding should read back");
        assert_eq!(back, finding);
    }

    fn endianness_map() -> EndiannessMap {
        EndiannessMap {
            function: String::new(),
            entries: vec![
                EndiannessEntry {
                    width: 16,
                    endianness: WireEndianness::BigEndian,
                    functions: vec!["FUN_18003ab00".into()],
                },
                EndiannessEntry {
                    width: 32,
                    endianness: WireEndianness::ReversalOnly,
                    functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
                },
            ],
            suggestion:
                "program-wide BE wire order at u16 (byteorder BE types); reversal-only at u32"
                    .into(),
            confidence: Confidence::new(75),
            evidence: "uVar1 = htons(local_18); uVar3 = __builtin_bswap32(uVar3);".into(),
        }
    }

    #[test]
    fn an_endianness_map_record_serde_round_trips() {
        let record = endianness_map();
        let json = serde_json::to_string(&record).expect("endianness map should serialize");
        let back: EndiannessMap =
            serde_json::from_str(&json).expect("endianness map should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn an_endianness_map_record_reads_back_from_json() {
        // The wire spelling of the profile: widths with their `be` and
        // `reversal_only` tags, and the contributing functions per width.
        let json = r#"{
            "function": "",
            "entries": [
                {"width": 16, "endianness": "be", "functions": ["FUN_18003ab00"]},
                {"width": 32, "endianness": "reversal_only", "functions": ["FUN_18003ab00", "FUN_18003e750"]}
            ],
            "suggestion": "program-wide BE wire order at u16 (byteorder BE types); reversal-only at u32",
            "confidence": 75,
            "evidence": "uVar1 = htons(local_18); uVar3 = __builtin_bswap32(uVar3);"
        }"#;
        let record: EndiannessMap =
            serde_json::from_str(json).expect("endianness map should read back");
        assert_eq!(record, endianness_map());
    }

    #[test]
    fn an_endianness_map_finding_serde_round_trips_under_its_kind_tag() {
        let finding = SerializeFinding::EndiannessMap(endianness_map());
        let json = serde_json::to_string(&finding).expect("finding should serialize");
        assert!(json.contains("\"kind\":\"endianness_map\""));
        let back: SerializeFinding = serde_json::from_str(&json).expect("finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            SerializeFinding::ByteSwap(byte_swap()),
            SerializeFinding::BitPack(bit_pack()),
            SerializeFinding::Magic(magic_format()),
            SerializeFinding::CrossFieldValidation(cross_field_validation()),
            SerializeFinding::SerializationFormat(serialization_format()),
            SerializeFinding::ProtocolMessage(protocol_message()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        assert_eq!(findings[0].confidence(), Confidence::new(70));
        assert_eq!(findings[1].confidence(), Confidence::new(60));
        assert_eq!(findings[2].confidence(), Confidence::new(80));
        assert_eq!(findings[3].confidence(), Confidence::new(65));
        assert_eq!(findings[4].confidence(), Confidence::new(75));
        assert_eq!(findings[5].confidence(), Confidence::new(85));

        // The endianness map belongs to the binary, not a function, so it
        // reads through the same accessors with its own function spelling.
        let map = SerializeFinding::EndiannessMap(endianness_map());
        assert_eq!(map.function(), "");
        assert!(!map.suggestion().is_empty());
        assert!(!map.evidence().is_empty());
        assert_eq!(map.confidence(), Confidence::new(75));

        let kinds: Vec<&str> = findings
            .iter()
            .chain(std::iter::once(&map))
            .map(|f| f.kind())
            .collect();
        assert_eq!(
            kinds,
            vec![
                "byteswap",
                "bitpack",
                "magic",
                "cross_field_validation",
                "serialization_format",
                "protocol_message",
                "endianness_map"
            ]
        );
        let targets: Vec<String> = findings
            .iter()
            .chain(std::iter::once(&map))
            .map(|f| f.target())
            .collect();
        assert_eq!(
            targets,
            vec![
                "ntohl",
                "shift_or_pack 8+8+8+8",
                "PNG 0x89504e47",
                "checksum uVar7",
                "reader u32:be > 8+8 bits",
                "IPv6 0x86dd",
                "u16:be, u32:reversal_only"
            ]
        );
    }

    #[test]
    fn the_endianness_map_answers_each_of_its_contributing_functions() {
        // The program-level profile is part of what a function-level
        // lookup reads: every function the map names gets it, and the
        // functions it never names do not.
        let result = SerializeResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![SerializeFinding::EndiannessMap(endianness_map())],
        };
        for contributor in ["FUN_18003ab00", "FUN_18003e750"] {
            let found: Vec<&SerializeFinding> = result.for_function(contributor).collect();
            assert_eq!(found.len(), 1, "{contributor} is named by the map");
            assert_eq!(found[0].kind(), "endianness_map");
        }
        assert!(result.for_function("FUN_180099999").next().is_none());
    }

    #[test]
    fn a_serialize_result_serde_round_trips() {
        let result = SerializeResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
                coverage: None,
            },
            findings: vec![SerializeFinding::ByteSwap(byte_swap())],
        };
        let json = serde_json::to_string(&result).expect("serialize result should serialize");
        let back: SerializeResult =
            serde_json::from_str(&json).expect("serialize result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a finding landed still load, and an
        // empty scan stays small on disk.
        let result = SerializeResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty serialize result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: SerializeResult =
            serde_json::from_str(&json).expect("empty serialize result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = SerializeFinding::ByteSwap(ByteSwapOperation {
            function: "FUN_18003e750".into(),
            operation: "htons".into(),
            width: 16,
            suggestion: "byteorder::BE::write_u16".into(),
            confidence: Confidence::new(70),
            evidence: "local_14 = htons(0x1234);".into(),
        });
        let result = SerializeResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), SerializeFinding::ByteSwap(byte_swap())],
        };
        let found: Vec<&SerializeFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }

    #[test]
    fn a_finding_renders_into_prompt_data_whichever_kind_it_is() {
        // The prompt conversion reaches through the union, so every kind
        // carries its label, suggestion, confidence, and evidence whole
        // into `SerializationInfo`.
        let swap = SerializeFinding::ByteSwap(byte_swap());
        let info = calxgloss_prompts::SerializationInfo::from(&swap);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "byteswap");
        assert_eq!(info.suggestion, "byteorder::BE::read_u32");
        assert_eq!(info.confidence, 70);
        assert_eq!(info.evidence, "uVar1 = ntohl(local_18);");

        let pack = SerializeFinding::BitPack(bit_pack());
        let info = calxgloss_prompts::SerializationInfo::from(&pack);
        assert_eq!(info.kind, "bitpack");
        assert_eq!(info.suggestion, "bitvec or named-field masking/shifting");
        assert_eq!(info.confidence, 60);

        let magic = SerializeFinding::Magic(magic_format());
        let info = calxgloss_prompts::SerializationInfo::from(&magic);
        assert_eq!(info.kind, "magic");
        assert_eq!(info.suggestion, "png::Decoder");
        assert_eq!(info.confidence, 80);

        let validation = SerializeFinding::CrossFieldValidation(cross_field_validation());
        let info = calxgloss_prompts::SerializationInfo::from(&validation);
        assert_eq!(info.kind, "cross_field_validation");
        assert_eq!(
            info.suggestion,
            "checked parse or validate step on the Rust type"
        );
        assert_eq!(info.confidence, 65);
        assert_eq!(info.evidence, "if (uVar7 == uVar5 + uVar6) {");

        let format = SerializeFinding::SerializationFormat(serialization_format());
        let info = calxgloss_prompts::SerializationInfo::from(&format);
        assert_eq!(info.kind, "serialization_format");
        assert_eq!(
            info.suggestion,
            "byteorder reader: read_u32 then 8+8 bitfields"
        );
        assert_eq!(info.confidence, 75);

        let protocol = SerializeFinding::ProtocolMessage(protocol_message());
        let info = calxgloss_prompts::SerializationInfo::from(&protocol);
        assert_eq!(info.kind, "protocol_message");
        assert_eq!(
            info.suggestion,
            "protocol-aware IPv6 message decode (byteorder BE reads)"
        );
        assert_eq!(info.confidence, 85);

        let map = SerializeFinding::EndiannessMap(endianness_map());
        let info = calxgloss_prompts::SerializationInfo::from(&map);
        assert_eq!(info.function, "");
        assert_eq!(info.kind, "endianness_map");
        assert_eq!(
            info.suggestion,
            "program-wide BE wire order at u16 (byteorder BE types); reversal-only at u32"
        );
        assert_eq!(info.confidence, 75);
    }
}

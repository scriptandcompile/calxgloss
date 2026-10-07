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
// Finding union
// ============================================================

/// One serialization finding, whichever detector made it.
///
/// The detectors emit the concrete records; the union is what the
/// persisted result carries, so one list can hold every finding for a
/// binary and a consumer reads the shared shape — function, suggestion,
/// confidence, evidence — without naming which detector produced it.
/// The detectors read disjoint body shapes — a swap call, a shift-and-or
/// chain, a signature comparison — so nothing is resolved between
/// variants. The serde `kind` tag names the record shape in the
/// persisted JSON.
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
}

impl SerializeFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.function,
            SerializeFinding::BitPack(record) => &record.function,
            SerializeFinding::Magic(record) => &record.function,
        }
    }

    /// The Rust serialization pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.suggestion,
            SerializeFinding::BitPack(record) => &record.suggestion,
            SerializeFinding::Magic(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            SerializeFinding::ByteSwap(record) => record.confidence,
            SerializeFinding::BitPack(record) => record.confidence,
            SerializeFinding::Magic(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.evidence,
            SerializeFinding::BitPack(record) => &record.evidence,
            SerializeFinding::Magic(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `byteswap`, `bitpack`, or `magic` —
    /// naming the detector behind the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            SerializeFinding::ByteSwap(_) => "byteswap",
            SerializeFinding::BitPack(_) => "bitpack",
            SerializeFinding::Magic(_) => "magic",
        }
    }

    /// What the finding names, spelled for a report row: the swap call
    /// spelling, the packing shape and the field widths it carves, or
    /// the format and the signature bytes that name it.
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
        }
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
/// packs, then the magic-byte comparisons. The detectors read disjoint
/// body shapes, so a function can carry findings of every kind at once
/// and none competes with another; the stable order means two scans of
/// the same program diff cleanly.
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
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &SerializeFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
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

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            SerializeFinding::ByteSwap(byte_swap()),
            SerializeFinding::BitPack(bit_pack()),
            SerializeFinding::Magic(magic_format()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        assert_eq!(findings[0].confidence(), Confidence::new(70));
        assert_eq!(findings[1].confidence(), Confidence::new(60));
        assert_eq!(findings[2].confidence(), Confidence::new(80));
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(kinds, vec!["byteswap", "bitpack", "magic"]);
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec!["ntohl", "shift_or_pack 8+8+8+8", "PNG 0x89504e47"]
        );
    }

    #[test]
    fn a_serialize_result_serde_round_trips() {
        let result = SerializeResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
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
    }
}

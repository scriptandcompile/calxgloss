//! Core data types for endianness and serialization information.
//!
//! This module holds the serialized shape of everything the serialization
//! detectors produce:
//!
//! - `ByteSwapOperation`: the per-function byte-swap record — the
//!   recognized swap call the function makes, the width it swaps, and
//!   the `byteorder` reader the call reads like.
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
}

impl SerializeFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.function,
        }
    }

    /// The Rust serialization pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            SerializeFinding::ByteSwap(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            SerializeFinding::ByteSwap(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `byteswap` — naming the detector behind
    /// the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            SerializeFinding::ByteSwap(_) => "byteswap",
        }
    }

    /// What the finding names, spelled for a report row: the swap call
    /// spelling.
    pub fn target(&self) -> String {
        match self {
            SerializeFinding::ByteSwap(record) => record.operation.clone(),
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

    #[test]
    fn the_union_accessors_reach_through_the_variant() {
        let finding = SerializeFinding::ByteSwap(byte_swap());
        assert_eq!(finding.function(), "FUN_18003ab00");
        assert_eq!(finding.confidence(), Confidence::new(70));
        assert_eq!(finding.suggestion(), "byteorder::BE::read_u32");
        assert_eq!(finding.evidence(), "uVar1 = ntohl(local_18);");
        assert_eq!(finding.kind(), "byteswap");
        assert_eq!(finding.target(), "ntohl");
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
}

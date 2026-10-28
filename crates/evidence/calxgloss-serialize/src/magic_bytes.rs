//! Magic-byte (format signature) detection.
//!
//! This module provides [`MagicByteDetector`]. It holds the signature
//! table the scan checks decompiled bodies against: the PNG, gzip, and
//! ZIP file-format magics, and the well-known network-protocol magics
//! (IPv4, ARP, IPv6, VLAN). When a body compares loaded buffer content
//! against one of these values, the scan records format sniffing that
//! a Rust translation should express through the matching format
//! crate: `png::Decoder`, `flate2::read::GzDecoder`, `zip::ZipArchive`.
//!
//! Each entry is a [`MagicSignature`]. It keeps the
//! [`magic`](MagicSignature::magic) bytes as the decompiler writes them
//! in a comparison, the [`format`](MagicSignature::format) they name,
//! and the [`suggestion`](MagicSignature::suggestion) crate type that
//! reads them. [`default_signatures`] is the standard table, and
//! [`MagicByteDetector::with_default_signatures`] builds a detector
//! that scans against it. A scan that knows a proprietary header can
//! replace the whole table.
//!
//! The standard table also has a protocol section. Its entries are
//! network-protocol magics, [`flagged`](MagicSignature::protocol) as
//! protocol entries, so the protocol combiner can tell them from the
//! file-format entries when it decides whether a function is a protocol
//! message handler. This reading does not use the flag: a protocol
//! magic comparison produces exactly what a file-format one does, a
//! plain [`MagicFormat`] finding.
//!
//! [`MagicByteDetector::detect`] runs the reading. It walks a
//! decompiled body line by line and writes one [`MagicFormat`] for
//! each line that compares a value against a configured signature. The
//! same constant outside a comparison is not sniffing, so the
//! comparison context is what turns a match into a finding.

use crate::types::MagicFormat;
use calxgloss_decomp::DecompiledFunction;
use serde::{Deserialize, Serialize};

// ============================================================
// Format signatures
// ============================================================

/// One signature the detector recognizes: the magic bytes, the format
/// or protocol they name, and the Rust type or pattern that reads them.
///
/// A signature is a constant, not a shape. It says that comparing the
/// value [`magic`](Self::magic) against loaded buffer content
/// identifies [`format`](Self::format), and that the code doing the
/// comparison wants [`suggestion`](Self::suggestion): the decoder type
/// from the crate that parses that format. The bytes are stored the way
/// the decompiler writes them in a comparison, which is the signature
/// as the program loads it — little-endian on x86. So the gzip magic
/// `1F 8B` is written `0x8B1F`, and the ZIP magic `PK\x03\x04` is
/// written `0x04034B50`.
///
/// A [`protocol`](Self::protocol) entry names a network protocol
/// instead of a file format. Protocol fields are numbered big-endian
/// on the wire, so a protocol magic is stored in wire order: it is the
/// value a handler compares against after swapping the field into host
/// order. The IPv6 ethertype `86 DD` is written `0x86DD`. The flag
/// changes nothing about this reading — a protocol magic comparison
/// gives a plain [`MagicFormat`] like any other entry. It only marks
/// the entry as one the protocol combiner may promote to a protocol
/// message finding when the function corroborates the sniff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicSignature {
    /// The format or protocol the bytes name, e.g. `PNG` or `IPv6`.
    pub format: String,
    /// The signature as a value, spelled the way the comparison
    /// spells it, e.g. `0x8950_4E47` for PNG.
    pub magic: u64,
    /// The Rust type or pattern the comparison suggests, e.g.
    /// `png::Decoder`.
    pub suggestion: String,
    /// Whether the entry names a network protocol rather than a file
    /// format. The protocol combiner reads this flag to tell the two
    /// sections of the table apart.
    #[serde(default)]
    pub protocol: bool,
}

impl MagicSignature {
    /// Builds a file-format signature that recognizes the constant
    /// `magic` as the start of `format`, read in Rust through
    /// `suggestion`.
    pub fn new(format: impl Into<String>, magic: u64, suggestion: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            magic,
            suggestion: suggestion.into(),
            protocol: false,
        }
    }

    /// Builds a network-protocol signature. It recognizes the
    /// wire-order constant `magic` as naming `protocol`, decoded in
    /// Rust through `suggestion`. The entry is flagged
    /// [`protocol`](Self::protocol), so the protocol combiner can tell
    /// it from a file-format entry.
    pub fn protocol(
        protocol: impl Into<String>,
        magic: u64,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            format: protocol.into(),
            magic,
            suggestion: suggestion.into(),
            protocol: true,
        }
    }
}

/// The standard signature table. First come the three formats whose
/// magics show up most in a binary that handles files — PNG, gzip, and
/// ZIP — each paired with the crate type that decodes it. Then comes
/// the protocol section: the well-known network-protocol magics — the
/// Ethernet types IPv4, ARP, IPv6, and VLAN — each flagged as a
/// protocol entry and paired with the decoding pattern that reads it.
pub fn default_signatures() -> Vec<MagicSignature> {
    vec![
        // The PNG magic is the first four bytes of the file, `89 50 4E 47`,
        // compared as a loaded word.
        MagicSignature::new("PNG", 0x8950_4E47, "png::Decoder"),
        // gzip starts with `1F 8B`. Loaded little-endian, the comparison
        // reads 0x8B1F.
        MagicSignature::new("gzip", 0x8B1F, "flate2::read::GzDecoder"),
        // ZIP local file headers start `PK\x03\x04`; loaded little-endian, 0x04034B50.
        MagicSignature::new("ZIP", 0x0403_4B50, "zip::ZipArchive"),
        // The protocol section: Ethernet type values, spelled in wire
        // order. This is the value a packet handler compares against
        // after swapping the 16-bit field into host order.
        MagicSignature::protocol("IPv4", 0x0800, "ipv4 header decode via byteorder BE reads"),
        MagicSignature::protocol("ARP", 0x0806, "arp packet decode via byteorder BE reads"),
        MagicSignature::protocol("IPv6", 0x86DD, "ipv6 header decode via byteorder BE reads"),
        MagicSignature::protocol("VLAN", 0x8100, "vlan tag decode via byteorder BE reads"),
    ]
}

// ============================================================
// Detector
// ============================================================

/// Magic-byte comparison detection over decompiled functions.
///
/// The detector owns the signature table the scan checks bodies
/// against: [`MagicSignature`] records, each one a constant, a format
/// name, and the crate type it suggests. The table is configurable.
/// Supply the whole table through
/// [`with_signatures`](Self::with_signatures) for a scan that knows a
/// proprietary header, or add entries one at a time with
/// [`add_signature`](Self::add_signature).
/// [`signatures`](Self::signatures) reports the table in configuration
/// order, so two detectors built the same way scan identically and
/// their results diff cleanly. The detector holds no scan source of
/// its own and never writes back to the program. One detector serves
/// an entire scan and can be shared by reference across concurrent
/// per-function passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MagicByteDetector {
    signatures: Vec<MagicSignature>,
}

impl MagicByteDetector {
    /// Builds a detector with no signatures configured. Every body it
    /// receives reads nothing, until the standard table arrives through
    /// [`with_default_signatures`](Self::with_default_signatures) or
    /// entries are added one at a time through
    /// [`add_signature`](Self::add_signature).
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a detector that scans against the standard signature
    /// table, [`default_signatures`], in its configuration order.
    pub fn with_default_signatures() -> Self {
        Self::with_signatures(default_signatures())
    }

    /// Builds a detector that scans against exactly `signatures`,
    /// keeping each entry in the order it is given.
    pub fn with_signatures(signatures: impl IntoIterator<Item = MagicSignature>) -> Self {
        Self {
            signatures: signatures.into_iter().collect(),
        }
    }

    /// Add one signature to the table this detector scans against.
    pub fn add_signature(&mut self, signature: MagicSignature) {
        self.signatures.push(signature);
    }

    /// The signatures this detector scans against, in configuration order.
    pub fn signatures(&self) -> &[MagicSignature] {
        &self.signatures
    }

    /// Finds the format-sniffing comparisons in one function's body.
    ///
    /// The reading walks the body line by line. Every line that
    /// compares a value against a configured signature becomes one
    /// [`MagicFormat`]. The format and suggestion come from the
    /// signature, the matched magic is the signature's own constant,
    /// and the evidence is the comparison's line. A bare constant
    /// outside a comparison — an arithmetic operand, an initializer —
    /// is not sniffing, so only lines with `==` or `!=` count.
    /// Findings come back in body order, and within one line in table
    /// order, so two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<MagicFormat> {
        let mut records = Vec::new();

        for line in func.body.lines() {
            let line = line.trim();
            // Format sniffing is a comparison against the signature.
            // The same constant anywhere else is just a number.
            if line.is_empty() || !(line.contains("==") || line.contains("!=")) {
                continue;
            }
            let chars: Vec<char> = line.chars().collect();
            let values = crate::scan::all_literals(&chars);
            for signature in &self.signatures {
                if values.contains(&signature.magic) {
                    records.push(MagicFormat {
                        function: func.name.clone(),
                        magic: signature.magic,
                        format: signature.format.clone(),
                        suggestion: signature.suggestion.clone(),
                        confidence: MAGIC_CONFIDENCE.into(),
                        evidence: line.to_string(),
                    });
                }
            }
        }

        records
    }
}

// ============================================================
// The reading
// ============================================================

/// The evidence confidence of a format reading from an exact signature
/// comparison. The constant is the format's registered magic number,
/// so this comparison is the strongest evidence a text scan can get.
/// It sits above the shape-read bit packs, and above the swap calls: a
/// binary can carry those names without parsing any format at all.
const MAGIC_CONFIDENCE: u8 = 80;

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn function(body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: "FUN_18003ab00".into(),
            signature: "undefined FUN_18003ab00(void)".into(),
            body: format!("undefined FUN_18003ab00(void)\n\n{{\n{body}\n}}\n"),
        }
    }

    fn detect(body: &str) -> Vec<MagicFormat> {
        MagicByteDetector::with_default_signatures().detect(&function(body))
    }

    #[test]
    fn a_png_signature_comparison_names_png_and_the_png_decoder() {
        let records = detect("  if (uVar1 == 0x89504e47) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].format, "PNG");
        assert_eq!(records[0].magic, 0x8950_4E47);
        assert_eq!(records[0].suggestion, "png::Decoder");
        assert_eq!(records[0].confidence, MAGIC_CONFIDENCE);
        assert_eq!(records[0].evidence, "if (uVar1 == 0x89504e47) {");
    }

    #[test]
    fn a_gzip_signature_comparison_names_gzip_and_the_gz_decoder() {
        // The decompiler writes the two-byte magic the way the program
        // loads it: `1F 8B` little-endian reads as 0x8b1f.
        let records = detect("  if (*(ushort *)pvVar2 == 0x8b1f) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].format, "gzip");
        assert_eq!(records[0].suggestion, "flate2::read::GzDecoder");
    }

    #[test]
    fn a_zip_signature_comparison_names_zip_and_the_zip_archive() {
        let records = detect("  if (iVar1 != 0x4034b50) goto LAB_18003ab50;");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].format, "ZIP");
        assert_eq!(records[0].suggestion, "zip::ZipArchive");
    }

    #[test]
    fn an_arbitrary_constant_comparison_yields_nothing() {
        let records = detect("  if (iVar1 == 0x1234) {");
        assert!(records.is_empty());
    }

    #[test]
    fn the_same_constant_outside_a_comparison_is_not_sniffing() {
        // A signature-shaped constant used as an arithmetic operand, or
        // as an initializer, has no comparison in front of it. Nothing is
        // being sniffed, so nothing is reported.
        let records = detect(
            "\
  uVar1 = 0x89504e47;
  uVar2 = uVar1 + 0x89504e47;
",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn a_detector_without_signatures_reads_nothing() {
        let detector = MagicByteDetector::new();
        assert!(
            detector
                .detect(&function("  if (uVar1 == 0x89504e47) {"))
                .is_empty()
        );
    }

    #[test]
    fn a_custom_signature_table_replaces_the_default_wholesale() {
        // A scan that knows a proprietary header replaces the whole
        // table. The custom magic reads, and the standard magics read
        // nothing.
        let detector = MagicByteDetector::with_signatures([MagicSignature::new(
            "CALX",
            0x4341_4C58,
            "calx::Header",
        )]);
        let records = detector.detect(&function(
            "\
  if (uVar1 == 0x43414c58) {
  if (uVar2 == 0x89504e47) {
",
        ));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].format, "CALX");
        assert_eq!(records[0].suggestion, "calx::Header");
    }

    #[test]
    fn a_custom_signature_adds_to_the_table_one_at_a_time() {
        let mut detector = MagicByteDetector::with_default_signatures();
        detector.add_signature(MagicSignature::new("CALX", 0x4341_4C58, "calx::Header"));
        let records = detect_with(&detector, "  if (uVar1 == 0x43414c58) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].format, "CALX");
        assert_eq!(detector.signatures().len(), 8);
    }

    fn detect_with(detector: &MagicByteDetector, body: &str) -> Vec<MagicFormat> {
        detector.detect(&function(body))
    }

    #[test]
    fn findings_come_back_in_body_order() {
        let records = detect(
            "\
  if (uVar1 == 0x89504e47) {
  if (iVar2 == 0x4034b50) {
  if (uVar3 == 0x8b1f) {
",
        );
        let formats: Vec<&str> = records.iter().map(|r| r.format.as_str()).collect();
        assert_eq!(formats, vec!["PNG", "ZIP", "gzip"]);
    }

    #[test]
    fn one_line_comparing_two_signatures_yields_two_findings() {
        let records = detect("  if (uVar1 == 0x89504e47 || iVar2 == 0x8b1f) {");
        let formats: Vec<&str> = records.iter().map(|r| r.format.as_str()).collect();
        assert_eq!(formats, vec!["PNG", "gzip"]);
    }

    #[test]
    fn the_default_table_carries_file_formats_then_protocol_entries() {
        let detector = MagicByteDetector::with_default_signatures();
        let formats: Vec<&str> = detector
            .signatures()
            .iter()
            .map(|s| s.format.as_str())
            .collect();
        assert_eq!(
            formats,
            vec!["PNG", "gzip", "ZIP", "IPv4", "ARP", "IPv6", "VLAN"]
        );
    }

    #[test]
    fn the_protocol_entries_are_flagged_and_the_file_formats_are_not() {
        let table = default_signatures();
        let flagged: Vec<&str> = table
            .iter()
            .filter(|s| s.protocol)
            .map(|s| s.format.as_str())
            .collect();
        assert_eq!(flagged, vec!["IPv4", "ARP", "IPv6", "VLAN"]);
        assert!(
            table
                .iter()
                .filter(|s| !s.protocol)
                .all(|s| matches!(s.format.as_str(), "PNG" | "gzip" | "ZIP")),
            "the file-format section stays unflagged"
        );
    }

    #[test]
    fn a_protocol_magic_comparison_lands_a_plain_magic_finding() {
        // A protocol magic on its own reads exactly like a file-format
        // one: a plain magic finding that names the protocol and its
        // decoding pattern, and nothing more.
        let records = detect("  if (uVar1 == 0x86dd) {");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].format, "IPv6");
        assert_eq!(records[0].magic, 0x86DD);
        assert_eq!(
            records[0].suggestion,
            "ipv6 header decode via byteorder BE reads"
        );
        assert_eq!(records[0].confidence, MAGIC_CONFIDENCE);
        assert_eq!(records[0].evidence, "if (uVar1 == 0x86dd) {");
    }

    #[test]
    fn a_custom_signature_is_not_a_protocol_entry() {
        // The one-at-a-time path and the whole-table path both build
        // file-format entries with `protocol` false. Only the protocol
        // constructor sets the flag.
        assert!(!MagicSignature::new("CALX", 0x4341_4C58, "calx::Header").protocol);
        assert!(MagicSignature::protocol("MYPROTO", 0x1234, "proto decode").protocol);
    }
}

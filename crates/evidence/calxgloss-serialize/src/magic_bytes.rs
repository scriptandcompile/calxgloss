//! Magic-byte (format signature) detection.
//!
//! This module provides [`MagicByteDetector`], which carries the
//! file-format signatures a scan reads decompiled bodies against — the
//! PNG, gzip, and ZIP magics — and reads each comparison of loaded
//! buffer content against one as format sniffing a Rust translation
//! should express through the matching format crate: `png::Decoder`,
//! `flate2::read::GzDecoder`, `zip::ZipArchive`.
//!
//! Each entry is a [`MagicSignature`]: the [`magic`](MagicSignature::magic)
//! bytes as the decompiler writes them in a comparison, the
//! [`format`](MagicSignature::format) they name, and the
//! [`suggestion`](MagicSignature::suggestion) crate type they read
//! like. [`default_signatures`] carries the standard table, and
//! [`MagicByteDetector::with_default_signatures`] builds a detector
//! that scans against it — the whole table is swappable for a scan that
//! knows a proprietary header.
//!
//! [`MagicByteDetector::detect`] runs the reading: it walks a
//! decompiled body line by line and emits one [`MagicFormat`] per line
//! that compares against a configured signature — a bare constant
//! wearing the same face outside a comparison is not sniffing, so the
//! comparison context is what makes the match a finding.

use crate::types::MagicFormat;
use calxgloss_ghidra::DecompiledFunction;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ============================================================
// Format signatures
// ============================================================

/// One file-format signature the detector recognizes: the magic bytes,
/// the format they name, and the Rust type that reads it.
///
/// A signature is a constant, not a shape: it says that the value
/// [`magic`](Self::magic), compared against loaded buffer content,
/// identifies [`format`](Self::format) — and that the code doing the
/// comparison wants [`suggestion`](Self::suggestion), the decoder type
/// from the crate that parses that format. The bytes are stored as the
/// decompiler writes them in a comparison: the signature read as the
/// program loads it, little-endian on x86, so the gzip magic `1F 8B`
/// is written `0x8B1F` and the ZIP magic `PK\x03\x04` `0x04034B50`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MagicSignature {
    /// The format the bytes name, e.g. `PNG`.
    pub format: String,
    /// The signature as a value, spelled the way the comparison
    /// spells it, e.g. `0x8950_4E47` for PNG.
    pub magic: u64,
    /// The Rust type the comparison suggests, e.g. `png::Decoder`.
    pub suggestion: String,
}

impl MagicSignature {
    /// A signature recognizing the constant `magic` as the start of
    /// `format`, read in Rust through `suggestion`.
    pub fn new(format: impl Into<String>, magic: u64, suggestion: impl Into<String>) -> Self {
        Self {
            format: format.into(),
            magic,
            suggestion: suggestion.into(),
        }
    }
}

/// The standard signature table: the three formats whose magics show up
/// most in a binary that handles files — PNG, gzip, and ZIP — each
/// paired with the crate type that decodes it.
pub fn default_signatures() -> Vec<MagicSignature> {
    vec![
        // The PNG magic is the first four bytes of the file, `89 50 4E 47`,
        // compared as a loaded word.
        MagicSignature::new("PNG", 0x8950_4E47, "png::Decoder"),
        // gzip starts `1F 8B`; loaded little-endian the comparison reads 0x8B1F.
        MagicSignature::new("gzip", 0x8B1F, "flate2::read::GzDecoder"),
        // ZIP local file headers start `PK\x03\x04`; loaded little-endian, 0x04034B50.
        MagicSignature::new("ZIP", 0x0403_4B50, "zip::ZipArchive"),
    ]
}

// ============================================================
// Detector
// ============================================================

/// Magic-byte comparison detection over decompiled functions.
///
/// The detector owns the signature table a scan reads bodies against:
/// [`MagicSignature`] records, each a constant, a format name, and the
/// crate type it suggests. The table is configurable — supply it whole
/// through [`with_signatures`](Self::with_signatures) for a scan that
/// knows a proprietary header, or grow it one entry at a time with
/// [`add_signature`](Self::add_signature) — and
/// [`signatures`](Self::signatures) reports it in configuration order,
/// so two detectors built the same way scan identically and results
/// diff cleanly. The detector holds no Ghidra client of its own and
/// never writes back to the program; one detector serves an entire
/// scan and can be shared by reference across concurrent per-function
/// passes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MagicByteDetector {
    signatures: Vec<MagicSignature>,
}

impl MagicByteDetector {
    /// A detector with no signatures configured: every body it is
    /// handed reads nothing until the standard table arrives through
    /// [`with_default_signatures`](Self::with_default_signatures) or
    /// entries join one at a time through [`add_signature`](Self::add_signature).
    pub fn new() -> Self {
        Self::default()
    }

    /// A detector that scans against the standard signature table —
    /// [`default_signatures`] — in its configuration order.
    pub fn with_default_signatures() -> Self {
        Self::with_signatures(default_signatures())
    }

    /// A detector that scans against exactly `signatures`, each kept in
    /// the order it is given.
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

    /// The format-sniffing comparisons one function's body carries.
    ///
    /// The reading walks the body line by line and reports every line
    /// that compares a value against a configured signature as one
    /// [`MagicFormat`]: the format and suggestion come from the
    /// signature, the matched bytes are its constant, and the evidence
    /// is the comparison's own line. A bare constant outside a
    /// comparison — an arithmetic operand, an initializer — is not
    /// sniffing, so only `==` and `!=` lines count. Findings come back
    /// in body order, signatures in table order within one line, so
    /// two scans of one body diff cleanly.
    pub fn detect(&self, func: &DecompiledFunction) -> Vec<MagicFormat> {
        let literals = literal_re();
        let mut records = Vec::new();

        for line in func.body.lines() {
            let line = line.trim();
            // Format sniffing is a comparison against the signature;
            // the same constant anywhere else is just a number.
            if line.is_empty() || !(line.contains("==") || line.contains("!=")) {
                continue;
            }
            let values: Vec<u64> = literals
                .captures_iter(line)
                .filter_map(|cap| parse_int_literal(cap.get(1).map(|m| m.as_str()).unwrap_or("")))
                .collect();
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

/// Confidence of a format reading from an exact signature comparison:
/// the constant is the format's registered magic number, so the
/// comparison is the strongest evidence a text scan can get — above
/// the shape-read bit packs, and above the swap calls, whose names a
/// binary could carry without any format being parsed at all.
const MAGIC_CONFIDENCE: u8 = 80;

/// A decimal or `0x`-prefixed integer literal — the constants the
/// decompiler writes its comparisons with.
fn literal_re() -> Regex {
    Regex::new(r"\b(0[xX][0-9a-fA-F]+|[0-9]+)\b").expect("valid regex")
}

/// Parse a decimal or `0x`-prefixed integer literal as written by the
/// decompiler.
fn parse_int_literal(text: &str) -> Option<u64> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

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
        // The decompiler writes the two-byte magic as the loaded word:
        // `1F 8B` little-endian is 0x8b1f.
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
        // A signature-shaped constant as an arithmetic operand or an
        // initializer carries no comparison, so nothing is being
        // sniffed and nothing is reported.
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
        // A scan that knows a proprietary header swaps the whole table:
        // the custom magic reads, and the standard magics read nothing.
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
        assert_eq!(detector.signatures().len(), 4);
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
    fn the_default_table_carries_png_gzip_and_zip() {
        let detector = MagicByteDetector::with_default_signatures();
        let formats: Vec<&str> = detector
            .signatures()
            .iter()
            .map(|s| s.format.as_str())
            .collect();
        assert_eq!(formats, vec!["PNG", "gzip", "ZIP"]);
    }
}

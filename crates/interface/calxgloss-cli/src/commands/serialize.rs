//! The `serialize` command — detect endianness and serialization
//! patterns for a binary.
//!
//! Runs the serialization detectors — byte-swap call matching, manual
//! bit-packing recognition, magic-byte format sniffing, cross-field
//! validation reading, the composed serialization layout, the
//! corroborated protocol message identification, and the program-wide
//! endianness profile — against the
//! loaded program and saves the result to
//! `re/analysis/serialize/{binary}.json` in the workspace, the same file
//! batch translation will read as prompt context. Batch translation runs
//! the same scan before its first batch when no result is cached; this
//! command is the manual entry point: it rebuilds the result on demand
//! and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_serialize::engine::SerializeEngine;
use calxgloss_serialize::persist::SerializePersistor;
use calxgloss_serialize::types::SerializeResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `serialize` subcommand: detect serialization patterns for
/// `binary`, or print the cached result when `show` is set.
pub async fn handle_serialize(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = SerializePersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached serialization result for {binary}; \
                 run `calxgloss serialize --binary {binary}` to produce one"
            )
        })?;
        print_serialization_report(&result, &persistor.path_for(binary));
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Detecting serialization patterns");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = SerializeEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Serialization detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the serialization result for {binary}"))?;

    print_serialization_report(&result, &persistor.path_for(binary));
    Ok(())
}

/// Print a summary of a serialization result: where it is filed, when it
/// was built, and what the findings say.
fn print_serialization_report(result: &SerializeResult, path: &Path) {
    println!();
    hsep_bold();
    println_content(format!("  Serialization — {}", result.metadata.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:      "),
        dim(&path.display().to_string())
    ));
    let scanned = DateTime::from_timestamp(result.metadata.scanned_at as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("unix {}", result.metadata.scanned_at));
    println_content(format!(
        "  {}{} {}",
        white_bold("Scanned:   "),
        scanned,
        dim(&format!("({}s)", result.metadata.duration_secs))
    ));
    println!();

    // Findings, broken down by the record kind the union carries.
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Findings:  "),
        result.findings.len(),
        dim(&kind_breakdown(result).join(", "))
    ));

    let top_confidence = result
        .findings
        .iter()
        .map(|finding| finding.confidence().value())
        .max();
    println_content(format!(
        "  {}{}",
        white_bold("Top conf:  "),
        match top_confidence {
            Some(confidence) => confidence_color(confidence)(&confidence.to_string()),
            None => dim("(none)"),
        }
    ));
    println!();

    if !result.findings.is_empty() {
        hsep();
        println_content("  Findings:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            println_content(format!(
                "  ●  {:<14} {:<24} {:<30} {}",
                finding.function(),
                finding.target(),
                finding.suggestion(),
                confidence_color(finding.confidence().value())(&format!(
                    "{} {}",
                    finding.confidence(),
                    finding.kind()
                ))
            ));
        }
        print_hidden_count("finding", result.findings.len());
        println!();
    }

    hsep_bold();
    if result.is_empty() {
        println!(
            "  {} The scan found nothing — no byte-swap calls, bit-packing chains, magic-byte comparisons, cross-field validation checks, composed serialization layouts, protocol message handlers, or program-wide endianness profile were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Serialization detection ready — batch translation reads it as prompt context.",
            green_bold("✓")
        );
    }
    println!();
}

/// The report's kind breakdown: every kind tag the finding union can
/// carry, in report order, each with the count of findings of that
/// kind in this result; kinds with no findings drop out. The list is
/// the union's full kind set — a kind missing from it would print
/// nothing no matter how many findings the scan made beside it.
fn kind_breakdown(result: &SerializeResult) -> Vec<String> {
    [
        "byteswap",
        "bitpack",
        "magic",
        "cross_field_validation",
        "serialization_format",
        "protocol_message",
        "endianness_map",
    ]
    .into_iter()
    .map(|kind| {
        (
            kind,
            result
                .findings
                .iter()
                .filter(|finding| finding.kind() == kind)
                .count(),
        )
    })
    .filter(|(_, count)| *count > 0)
    .map(|(kind, count)| format!("{kind} {count}"))
    .collect()
}

/// Color a 0–100 confidence score the way the other reports color pass rates.
fn confidence_color(confidence: u8) -> fn(&str) -> String {
    if confidence >= 70 {
        green_bold
    } else if confidence >= 50 {
        yellow_bold
    } else {
        red_bold
    }
}

/// The "…and N more" line a detail section ends with when it collapsed.
fn print_hidden_count(noun: &str, total: usize) {
    if total > DETAIL_LIMIT {
        println_content(format!(
            "  {} …and {} more {noun}",
            dim("●"),
            total - DETAIL_LIMIT
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_serialize::types::{
        BitPackPattern, BitPackRecord, ByteSwapOperation, Confidence, CrossFieldValidation,
        EndiannessEntry, EndiannessMap, FormatDirection, FormatField, MagicFormat, ProtocolMessage,
        SerializationFormat, SerializeFinding, ValidationShape, WireEndianness,
    };
    use calxgloss_types::scan::ScanMetadata;

    /// Sample result carrying exactly one finding of every kind the
    /// union can carry — the report breakdown must name each of them.
    fn sample_one_of_every_kind() -> SerializeResult {
        let findings = vec![
            SerializeFinding::ByteSwap(ByteSwapOperation {
                function: "FUN_18003ab00".into(),
                operation: "ntohl".into(),
                width: 32,
                suggestion: "byteorder::BE::read_u32".into(),
                confidence: Confidence::new(70),
                evidence: "uVar1 = ntohl(local_18);".into(),
            }),
            SerializeFinding::BitPack(BitPackRecord {
                function: "FUN_18003ab00".into(),
                pattern: BitPackPattern::ShiftOrPack,
                widths: vec![8, 8, 8, 8],
                suggestion: "bitvec or named-field masking/shifting".into(),
                confidence: Confidence::new(60),
                evidence: "uVar2 = (uVar3 << 0x18) | ((uint)uVar4 << 0x10);".into(),
            }),
            SerializeFinding::Magic(MagicFormat {
                function: "FUN_18003ab00".into(),
                magic: 0x8950_4E47,
                format: "PNG".into(),
                suggestion: "png::Decoder".into(),
                confidence: Confidence::new(80),
                evidence: "if (uVar7 == 0x89504e47) {".into(),
            }),
            SerializeFinding::CrossFieldValidation(CrossFieldValidation {
                function: "FUN_18003ab00".into(),
                field: "uVar7".into(),
                computed: "uVar5 + uVar6".into(),
                shape: ValidationShape::Checksum,
                suggestion: "checked parse or validate step on the Rust type".into(),
                confidence: Confidence::new(65),
                evidence: "if (uVar7 == uVar5 + uVar6) {".into(),
            }),
            SerializeFinding::SerializationFormat(SerializationFormat {
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
                ],
                direction: Some(FormatDirection::Reader),
                suggestion: "byteorder reader: read_u32 then 8 bitfields".into(),
                confidence: Confidence::new(75),
                evidence: "uVar1 = ntohl(local_18);".into(),
            }),
            SerializeFinding::ProtocolMessage(ProtocolMessage {
                function: "FUN_18003ab00".into(),
                magic: 0x86DD,
                protocol: "IPv6".into(),
                corroborations: vec!["ntohl swap".into()],
                suggestion: "protocol-aware IPv6 message decode (byteorder BE reads)".into(),
                confidence: Confidence::new(85),
                evidence: "if (uVar2 == 0x86dd) { uVar1 = ntohl(local_18);".into(),
            }),
            SerializeFinding::EndiannessMap(EndiannessMap {
                function: String::new(),
                entries: vec![EndiannessEntry {
                    width: 32,
                    endianness: WireEndianness::BigEndian,
                    functions: vec!["FUN_18003ab00".into()],
                }],
                suggestion: "program-wide BE wire order at u32 (byteorder BE types)".into(),
                confidence: Confidence::new(75),
                evidence: "uVar1 = ntohl(local_18);".into(),
            }),
        ];
        SerializeResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings,
        }
    }

    #[test]
    fn the_report_breakdown_names_every_kind_the_union_can_carry() {
        // The breakdown line is the report's kind index: every kind
        // tag the finding union carries must show up with its count,
        // or a scan full of that kind prints as though it found
        // nothing of it.
        let result = sample_one_of_every_kind();
        let breakdown = kind_breakdown(&result);
        assert_eq!(
            breakdown,
            vec![
                "byteswap 1",
                "bitpack 1",
                "magic 1",
                "cross_field_validation 1",
                "serialization_format 1",
                "protocol_message 1",
                "endianness_map 1",
            ],
            "every kind the union carries is named"
        );
        assert_eq!(
            breakdown.len(),
            result.findings.len(),
            "every finding is counted — a union variant missing from the breakdown list fails here"
        );
    }

    #[test]
    fn the_report_breakdown_drops_kinds_with_no_findings() {
        // A kind the scan made no finding of stays out of the line —
        // the breakdown names what was seen, not the whole kind set.
        let mut result = sample_one_of_every_kind();
        result
            .findings
            .retain(|finding| finding.kind() == "byteswap");
        assert_eq!(kind_breakdown(&result), vec!["byteswap 1"]);
    }
}

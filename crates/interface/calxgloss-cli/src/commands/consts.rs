//! The `consts` command — detect constant structures for a binary.
//!
//! Runs the three constant detectors — bitflag group detection,
//! enumerated-dispatch detection, and repeated-magic-number frequency
//! analysis — against the loaded program and saves the
//! result to `re/analysis/consts/{binary}.json` in the workspace, the same
//! file batch translation will read as prompt context, together with a
//! rendered Rust codegen file spelling the reconstructed flag families,
//! enums, and constants out beside the JSON. Batch translation
//! runs the same scan before its first batch when no result is cached;
//! this command is the manual entry point: it rebuilds the result on
//! demand and can print what a cached one holds.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_consts::codegen::render_codegen;
use calxgloss_consts::engine::ConstEngine;
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_consts::types::ConstResult;
use chrono::DateTime;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// Handle the `consts` subcommand: detect constant structures for
/// `binary`, or print the cached result when `show` is set.
pub async fn handle_consts(
    binary: &str,
    workspace: &Path,
    show: bool,
    settings: &Settings,
) -> Result<()> {
    let persistor = ConstPersistor::new(workspace);

    if show {
        let result = persistor.load(binary).with_context(|| {
            format!(
                "No cached constant result for {binary}; \
                 run `calxgloss consts --binary {binary}` to produce one"
            )
        })?;
        print_constant_report(
            &result,
            &persistor.path_for(binary),
            persistor
                .codegen_exists(binary)
                .then(|| persistor.codegen_path_for(binary))
                .as_deref(),
        );
        return Ok(());
    }

    info!(binary, workspace = %workspace.display(), "Detecting constant structures");

    let kuna = load_kuna_source(settings, binary)?;

    let engine = ConstEngine::new(&kuna);
    let result = engine
        .scan(binary)
        .await
        .with_context(|| format!("Constant detection failed for {binary}"))?;
    persistor
        .save(&result)
        .with_context(|| format!("Failed to save the constant result for {binary}"))?;
    persistor
        .save_codegen(binary, &render_codegen(&result))
        .with_context(|| format!("Failed to write the constant codegen for {binary}"))?;

    print_constant_report(
        &result,
        &persistor.path_for(binary),
        Some(&persistor.codegen_path_for(binary)),
    );
    Ok(())
}

/// Print a summary of a constant result: where it is filed, where its
/// rendered Rust codegen is (when it exists), when it was built, and
/// what the findings say.
fn print_constant_report(result: &ConstResult, path: &Path, codegen_path: Option<&Path>) {
    println!();
    hsep_bold();
    println_content(format!("  Constants — {}", result.metadata.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:      "),
        dim(&path.display().to_string())
    ));
    if let Some(codegen_path) = codegen_path {
        println_content(format!(
            "  {}{}",
            white_bold("Codegen:   "),
            dim(&codegen_path.display().to_string())
        ));
    }
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
            // A program-level named constant belongs to every function
            // that uses its value; the report shows the usage count
            // where a per-function name would go.
            let subject = match finding.function().is_empty() {
                true => "(program)".to_string(),
                false => finding.function().to_string(),
            };
            println_content(format!(
                "  ●  {:<14} {:<24} {:<30} {}",
                subject,
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
            "  {} The scan found nothing — no bitflag groups, enum candidates, or repeated magic numbers were found in the decompiled bodies.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} Constant detection ready — batch translation reads it as prompt context.",
            green_bold("✓")
        );
    }
    println!();
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

/// The report's kind breakdown: every kind tag the finding union can
/// carry, in report order, each with the count of findings of that
/// kind in this result; kinds with no findings drop out. The list is
/// the union's full kind set — a kind missing from it would print
/// nothing no matter how many findings the scan made beside it.
fn kind_breakdown(result: &ConstResult) -> Vec<String> {
    [
        "bitflag_group",
        "enum_candidate",
        "named_constant",
        "flag_family",
        "protocol_constant",
        "color_constant",
        "data_table",
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

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_consts::types::{
        BitflagGroup, ColorConstant, ConstFinding, Confidence, DataTable, EnumCandidate,
        FlagFamily, NamedConstant, ProtocolConstant, ScanMetadata,
    };

    /// Sample result carrying exactly one finding of every kind the
    /// union can carry — the report breakdown must name each of them.
    fn sample_one_of_every_kind() -> ConstResult {
        let findings = vec![
            ConstFinding::BitflagGroup(BitflagGroup {
                function: "FUN_18003ab00".into(),
                bits: vec![8, 10],
                mask: 0x500,
                bit_width: 12,
                suggestion: "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400 */ }".into(),
                confidence: Confidence::new(70),
                evidence: "uVar1 & 0x400 | uVar1 | 0x100".into(),
            }),
            ConstFinding::EnumCandidate(EnumCandidate {
                function: "FUN_18003ab00".into(),
                values: vec![0, 1, 2, 3],
                count: 4,
                suggestion: "enum State { Variant0 = 0, Variant1 = 1, Variant2 = 2, \
                             Variant3 = 3 }"
                    .into(),
                confidence: Confidence::new(75),
                evidence: "switch(local_10) { case 0: case 1: case 2: case 3:".into(),
            }),
            ConstFinding::NamedConstant(NamedConstant {
                value: 0x400,
                count: 5,
                functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
                name: None,
                suggestion: "const VALUE_0x400: u32 = 0x400;".into(),
                confidence: Confidence::new(60),
                evidence: "0x400 used 5 times in FUN_18003ab00, FUN_18003e750".into(),
            }),
            ConstFinding::FlagFamily(FlagFamily {
                bits: vec![8, 10, 11],
                mask: 0xd00,
                bit_width: 12,
                functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
                suggestion: "bitflags! struct Flags: u16 { /* bits: 0x100, 0x400, 0x800 */ }"
                    .into(),
                confidence: Confidence::new(80),
                evidence: "FUN_18003ab00: bits 0x100, 0x400; FUN_18003e750: bits 0x400, 0x800"
                    .into(),
            }),
            ConstFinding::ProtocolConstant(ProtocolConstant {
                value: 0xdeadbeef,
                name: "DEAD_BEEF_MARKER".into(),
                protocol: "debug sentinel value".into(),
                count: 1,
                functions: vec!["FUN_18003ab00".into()],
                suggestion: "const DEAD_BEEF_MARKER: u32 = 0xdeadbeef;".into(),
                confidence: Confidence::new(75),
                evidence: "0xdeadbeef used 1 times in FUN_18003ab00 — table match: \
                           DEAD_BEEF_MARKER (debug sentinel value)"
                    .into(),
            }),
            ConstFinding::ColorConstant(ColorConstant {
                values: vec![0x123456, 0xff00ff],
                functions: vec!["FUN_18003ab00".into(), "FUN_18003e750".into()],
                suggestion: "const COLOR_0x123456: u32 = 0x123456; const COLOR_0xff00ff: u32 = \
                             0xff00ff;"
                    .into(),
                confidence: Confidence::new(60),
                evidence: "0x123456 used 2 times in FUN_18003ab00".into(),
            }),
            ConstFinding::DataTable(DataTable {
                symbol: "DAT_1400a1b60".into(),
                address: 0x1400_a1b60,
                element_type: "u16".into(),
                count: 12,
                values: (1..=12).collect(),
                values_truncated: false,
                functions: vec!["FUN_18003ab00".into()],
                suggestion: "const DAT_1400A1B60: [u16; 12];".into(),
                confidence: Confidence::new(70),
                evidence: "FUN_18003ab00: uVar3 = DAT_1400a1b60[uVar2];".into(),
            }),
        ];
        ConstResult {
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
                "bitflag_group 1",
                "enum_candidate 1",
                "named_constant 1",
                "flag_family 1",
                "protocol_constant 1",
                "color_constant 1",
                "data_table 1",
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
            .retain(|finding| finding.kind() == "data_table");
        assert_eq!(kind_breakdown(&result), vec!["data_table 1"]);
    }
}

//! The `consts` command's CLI contribution — detect constant structures
//! for a binary (issue #340, spec #337).
//!
//! The shape of a scan — build the analysis engine, scan, persist,
//! degrade — lives in the pipeline's `constants` registry row. This
//! module contributes only what belongs to this evidence engine: the
//! cached-document loader, the report printer, and a post-scan step for
//! the one side effect the row does not file — rendered Rust codegen
//! that spells out the reconstructed flag families, enums, and
//! constants beside the JSON.
//!
//! The generic handler ([`scan_command`](crate::commands::scan_command))
//! runs the command end to end. A scan run always rebuilds the result —
//! the CLI's refresh-cache contract — and `--show` prints what a cached
//! document holds. The row files the document at
//! `re/analysis/consts/{binary}.json`, the same file batch translation
//! reads as prompt context. The run's report and a later `--show`
//! report read the same document the same way.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_consts::codegen::render_codegen;
use calxgloss_consts::persist::ConstPersistor;
use calxgloss_consts::types::ConstResult;
use calxgloss_decomp::PipelineSource;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{
    PostScanFuture, ScanContribution, ScanContributionSteps, ScanFlags,
};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `consts` entry in the CLI-side contribution table. It serves the
/// registry's `constants` row and supplies this command's loader,
/// printer, and codegen post-scan step. The command takes no flags
/// beyond `--binary` and `--show`, so its flag derivation returns the
/// plain default options. The generic handler sets the overwrite policy.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "constants",
        load: load_filed_result,
        print: print_report,
        derive_options: |_flags| ScanRunOptions::default(),
        post_scan: Some(write_codegen),
        show_loads_program: |_flags| false,
    })
}

/// Read the filed result through the evidence engine's own persistor.
/// The same loader serves the `--show` report and reads back the
/// document a run just filed. When the document is missing, the error
/// carries the remediation wording naming the exact command that
/// produces one.
fn load_filed_result(workspace: &Path, binary: &str) -> Result<ConstResult> {
    ConstPersistor::new(workspace)
        .load(binary)
        .with_context(|| {
            format!(
                "No cached constant result for {binary}; \
                 run `calxgloss consts --binary {binary}` to produce one"
            )
        })
}

/// Write the rendered Rust codegen beside the filed document. It is the
/// one side effect the `constants` row does not file. The codegen
/// renders from the document the row just saved, so a later scan run
/// replaces it along with the document.
fn write_codegen<'a>(
    _source: &'a PipelineSource,
    workspace: &'a Path,
    binary: &'a str,
    _flags: &'a ScanFlags,
    result: &'a mut ConstResult,
) -> PostScanFuture<'a> {
    Box::pin(async move {
        ConstPersistor::new(workspace)
            .save_codegen(binary, &render_codegen(result))
            .with_context(|| format!("Failed to write the constant codegen for {binary}"))
    })
}

/// The report printer: renders the loaded result and names where the
/// document is filed, plus where the codegen sits when it exists. The
/// run report and a later `--show` report read the same on-disk state,
/// so over one document the two reports come out byte-identical.
fn print_report(result: &ConstResult, workspace: &Path, binary: &str) -> Result<()> {
    let persistor = ConstPersistor::new(workspace);
    print_constant_report(
        result,
        &persistor.path_for(binary),
        persistor
            .codegen_exists(binary)
            .then(|| persistor.codegen_path_for(binary))
            .as_deref(),
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

    // Findings, broken down by record kind.
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

    // Print the scan's own admission next to the counts it qualifies
    // (issue #348): the shared type's one bounded admission line, shown
    // under `Coverage:` and printed only when there is something to
    // admit. The line names the function bodies and memory windows the
    // scan never reached — an object the scan read and found no table
    // in is a fact about the object, not a limit of the scan.
    print_coverage(result.metadata.coverage.as_ref());
    println!();

    if !result.findings.is_empty() {
        hsep();
        println_content("  Findings:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            // A program-level named constant belongs to every function
            // that uses its value, so it has no single home function;
            // the report shows "(program)" where a per-function name
            // would go, and the value itself in the target column.
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

/// The report's kind breakdown: it counts the findings of each kind in
/// this result and lists every kind with at least one finding, in
/// report order. Kinds with no findings drop out. This list must hold
/// the finding type's full kind set — a kind missing from it would
/// print nothing no matter how many findings of it the scan made.
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
        BitflagGroup, ColorConstant, Confidence, ConstFinding, DataTable, EnumCandidate,
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

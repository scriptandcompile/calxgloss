//! The `apidetect` command's CLI contribution — identify the libraries
//! and APIs of a binary (issue #340, spec #337).
//!
//! The shape of a scan — build the analysis engine, scan, persist,
//! degrade — lives in the pipeline's `library-api` registry row. This
//! module contributes only what belongs to this evidence engine: the
//! cached-document loader, the report printer, and a post-scan step for
//! the two side effects the row does not file. Those are the rendered
//! FFI bindings file, which declares the imports no crate replaces, and
//! the Cargo.toml-style dependency manifest, which collects the crates
//! the identified findings suggest; both sit beside the JSON.
//!
//! The generic handler ([`scan_command`](crate::commands::scan_command))
//! runs the command end to end. A scan run always rebuilds the result —
//! the CLI's refresh-cache contract — and `--show` prints what a cached
//! document holds. The row files the document at
//! `re/analysis/apidetect/{binary}.json`, the same file batch
//! translation reads as prompt context. The run's report and a later
//! `--show` report read the same document the same way.

use std::path::Path;

use anyhow::{Context, Result};
use calxgloss_apidetect::ffi_bindings::{render_dependency_manifest, render_ffi_bindings};
use calxgloss_apidetect::persist::ApiPersistor;
use calxgloss_apidetect::types::ApiDetectionResult;
use calxgloss_decomp::PipelineSource;
use calxgloss_translator::scan_registry::ScanRunOptions;
use chrono::DateTime;

use crate::commands::scan_command::{
    PostScanFuture, ScanContribution, ScanContributionSteps, ScanFlags,
};
use crate::utils::*;

/// How many entries a detail section lists before collapsing the rest.
const DETAIL_LIMIT: usize = 10;

/// The `apidetect` entry in the CLI-side contribution table. It serves
/// the registry's `library-api` row and supplies this command's loader,
/// printer, and post-scan step, which writes the bindings and the
/// manifest. The command takes no flags beyond `--binary` and `--show`,
/// so its flag derivation returns the plain default options. The
/// generic handler sets the overwrite policy.
pub(crate) fn contribution() -> ScanContribution {
    ScanContribution::new(ScanContributionSteps {
        row: "library-api",
        load: load_filed_result,
        print: print_report,
        derive_options: |_flags| ScanRunOptions::default(),
        post_scan: Some(write_side_effects),
        show_loads_program: |_flags| false,
    })
}

/// Read the filed result through the evidence engine's own persistor.
/// The same loader serves the `--show` report and reads back the
/// document a run just filed. When the document is missing, the error
/// carries the remediation wording naming the exact command that
/// produces one.
fn load_filed_result(workspace: &Path, binary: &str) -> Result<ApiDetectionResult> {
    ApiPersistor::new(workspace).load(binary).with_context(|| {
        format!(
            "No cached API result for {binary}; \
                 run `calxgloss apidetect --binary {binary}` to produce one"
        )
    })
}

/// Write the rendered FFI bindings and the dependency manifest beside
/// the filed document. These are the two side effects the `library-api`
/// row does not file. Both render from the document the row just
/// saved, so a later scan run replaces them along with it.
fn write_side_effects<'a>(
    _source: &'a PipelineSource,
    workspace: &'a Path,
    binary: &'a str,
    _flags: &'a ScanFlags,
    result: &'a mut ApiDetectionResult,
) -> PostScanFuture<'a> {
    Box::pin(async move {
        let persistor = ApiPersistor::new(workspace);
        persistor
            .save_bindings(binary, &render_ffi_bindings(result))
            .with_context(|| format!("Failed to write the FFI bindings for {binary}"))?;
        persistor
            .save_manifest(binary, &render_dependency_manifest(result))
            .with_context(|| format!("Failed to write the dependency manifest for {binary}"))
    })
}

/// The report printer: renders the loaded result and names where the
/// document is filed, plus where the bindings and the manifest sit when
/// they exist. The run report and a later `--show` report read the same
/// on-disk state, so over one document the two reports come out
/// byte-identical.
fn print_report(result: &ApiDetectionResult, workspace: &Path, binary: &str) -> Result<()> {
    let persistor = ApiPersistor::new(workspace);
    print_api_report(
        result,
        &persistor.path_for(binary),
        persistor
            .bindings_exists(binary)
            .then(|| persistor.bindings_path_for(binary))
            .as_deref(),
        persistor
            .manifest_exists(binary)
            .then(|| persistor.manifest_path_for(binary))
            .as_deref(),
    );
    Ok(())
}

/// Print a summary of an API result: where it is filed, where its
/// rendered FFI bindings and dependency manifest are (when they exist),
/// when it was built, and what the findings say.
fn print_api_report(
    result: &ApiDetectionResult,
    path: &Path,
    bindings_path: Option<&Path>,
    manifest_path: Option<&Path>,
) {
    println!();
    hsep_bold();
    println_content(format!("  Libraries & APIs — {}", result.metadata.binary));
    hsep();
    println!();

    println_content(format!(
        "  {}{}",
        white_bold("File:      "),
        dim(&path.display().to_string())
    ));
    if let Some(bindings_path) = bindings_path {
        println_content(format!(
            "  {}{}",
            white_bold("Bindings:  "),
            dim(&bindings_path.display().to_string())
        ));
    }
    if let Some(manifest_path) = manifest_path {
        println_content(format!(
            "  {}{}",
            white_bold("Manifest:  "),
            dim(&manifest_path.display().to_string())
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
    let kind_breakdown: Vec<String> = [
        "import",
        "platform_divergence",
        "com_interface",
        "api_usage",
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
    .collect();
    println_content(format!(
        "  {}{:<5}{}",
        white_bold("Findings:  "),
        result.findings.len(),
        dim(&kind_breakdown.join(", "))
    ));

    let identified = result
        .findings
        .iter()
        .filter(|finding| finding.library().is_some())
        .count();
    println_content(format!(
        "  {}{} identified",
        white_bold("Identified:"),
        identified
    ));

    // Print the scan's own admission next to the counts it qualifies
    // (issue #346): the shared type's one bounded admission line, shown
    // under `Coverage:` and printed only when there is something to
    // admit.
    print_coverage(result.metadata.coverage.as_ref());
    println!();

    if !result.findings.is_empty() {
        hsep();
        println_content("  Findings:");
        hsep();
        for finding in result.findings.iter().take(DETAIL_LIMIT) {
            let function = if finding.function().is_empty() {
                "(binary)"
            } else {
                finding.function()
            };
            let suggestion = finding.suggestion();
            println_content(format!(
                "  ●  {:<14} {:<24} {:<22} {}",
                function,
                finding.target(),
                if suggestion.is_empty() {
                    "(unidentified)"
                } else {
                    &suggestion
                },
                confidence_color(finding.confidence().value())(&format!(
                    "{} {}",
                    finding.confidence().value(),
                    finding.kind()
                ))
            ));
        }
        print_hidden_count("finding", result.findings.len());
        println!();
    }

    hsep_bold();
    if result.findings.is_empty() {
        println!(
            "  {} The scan found nothing — the binary imports nothing the mapping database knows.",
            yellow_bold("◉")
        );
    } else {
        println!(
            "  {} API detection ready — batch translation reads it as prompt context.",
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

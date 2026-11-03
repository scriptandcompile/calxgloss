//! The `capture` command — ingest a captured call event log (P23.2, issue #396).
//!
//! `capture --ingest <LOG>` folds the log into the workspace through the
//! record-and-replay lane: every captured argument vector a listed export's
//! signature can hold is replayed against the original binary through the
//! baseline harness, and what the replay observed is filed as a baseline
//! case under `re/baseline/{binary}/{function}/baseline.json`. Authority
//! rests on the replay, not the capture — a refused entry names its reason
//! and files a `capture_refused` record; a replay that faults files a
//! `crash_reproduction` record naming the event and files no case. The
//! command prints the count report — events seen, cases mined, twins
//! deduplicated, refusals named, truncations stated — and lands the named
//! records in the binary's unknown ledger, the same merge doctrine batch
//! writes use. The next batch run closes the standing `export_uncovered`
//! record for any export the fold filed a suite for.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss_testgen::{Replay, TestGenerator, file_capture_records, fold_capture_event_log};
use calxgloss_types::Export;
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// Handle the `capture` subcommand: ingest `ingest` as a capture event log
/// for `binary`, replaying what the signatures can hold through the
/// baseline harness against the target directory's current bytes.
pub async fn handle_capture(
    binary: &str,
    ingest: &Path,
    workspace: &Path,
    settings: &Settings,
) -> Result<()> {
    // The replay runs against the target directory's current bytes — the
    // same file the scan commands load.
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"));
    let dll_path = target_dir.join(binary);

    let log: serde_json::Value = std::fs::read_to_string(ingest)
        .with_context(|| format!("Failed to read the capture event log: {}", ingest.display()))?
        .parse()
        .with_context(|| {
            format!(
                "The capture event log at {} is not valid JSON — expected a `capture-log-v1` \
                 document",
                ingest.display()
            )
        })?;

    // The listing the fold checks each event against: every named export
    // of the current bytes, with the prototype line Kuna's decompiler
    // renders for it. An export whose prototype Kuna will not render
    // enters the listing with no signature — the fold then refuses any
    // event naming it with the `no-parseable-signature` reason, naming
    // the gap instead of guessing a vector.
    let source = load_kuna_at(settings, &dll_path)?;
    let mut exports: Vec<Export> = Vec::new();
    for symbol in source
        .list_exports()
        .await
        .context("The export listing never came back from Kuna")?
    {
        if symbol.imported || symbol.name.is_empty() {
            continue;
        }
        let signature = source
            .decompile_function(&symbol.name)
            .await
            .map(|decompiled| decompiled.signature)
            .unwrap_or_default();
        exports.push(Export {
            name: symbol.name,
            address: symbol.address,
            signature,
        });
    }
    info!(binary, exports = exports.len(), "Capture listing loaded");

    let generator = TestGenerator::new(workspace);
    let folded = fold_capture_event_log(
        &generator,
        binary,
        &exports,
        &log,
        &Replay::Harness {
            dll_path: &dll_path,
        },
    )
    .await
    .with_context(|| format!("Failed to fold the capture event log for {binary}"))?;

    // The count report the issue asks the command to print, refusal by
    // refusal.
    print!("{}", folded.report);
    for (binary, function, rows) in &folded.filed {
        println!("  filed {binary}/{function}: {} baseline cases", rows.len());
    }

    let landed = file_capture_records(workspace, binary, &folded.unknown_records)
        .context("Failed to file the capture fold's unknown records")?;
    if landed > 0 {
        println!(
            "  unknowns: {landed} record{} landed in re/unknowns/{binary}.json",
            if landed == 1 { "" } else { "s" }
        );
    }
    Ok(())
}

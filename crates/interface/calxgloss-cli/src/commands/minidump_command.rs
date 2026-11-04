//! The `minidump` command — file crash reproductions from crash dumps
//! (P23.7, issue #401).
//!
//! Each `--dumps` file is a Windows minidump: a record of one moment
//! in a crashed process — the modules it had loaded, the threads it
//! had running, and the exception that broke it down to the faulting
//! thread's machine context. The command parses each dump, matches it
//! to the target binary by module identity (name, mapped size,
//! timestamp), and — where the fault lands exactly on a listed export
//! entry — reconstructs the call vector the x64 convention left in
//! the thread's registers and stack.
//!
//! Each reconstructed vector folds through the same record-and-replay
//! lane `capture --ingest` uses, so dedup and filed order are exactly
//! that command's: a replay observation files a baseline case, a
//! replay that faults files a `crash_reproduction` unknown naming the
//! dump digest and the faulting thread, and anything the dump cannot
//! express in the replay vocabulary is refused with the reason named
//! and lands in the binary's unknown ledger. A near miss — a fault
//! between entries, outside the module, in a dump whose module does
//! not match the target — claims nothing and is stated as an
//! unclaimed mapping candidate; a file that is not a minidump, or an
//! ELF core, is refused by name. ELF cores are out of scope and
//! managed (.NET) PEs stay parked with their own minidump story
//! (ADR-0044).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss_testgen::{Replay, TestGenerator, file_capture_records, fold_minidumps};
use tracing::info;

use crate::Settings;
use crate::utils::*;

/// Handle the `minidump` subcommand for `binary`: fold each dump in
/// `dumps` order against the target directory's current bytes.
pub async fn handle_minidump(
    binary: &str,
    dumps: &[PathBuf],
    workspace: &Path,
    settings: &Settings,
) -> Result<()> {
    // The replay and the identity both run against the target
    // directory's current bytes — the same file the scan commands load.
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"));
    let dll_path = target_dir.join(binary);

    // The listing the dumps are matched against — the same one the
    // capture fold checks events against, with Kuna's prototype lines.
    let exports = kuna_export_listing(settings, &dll_path).await?;
    info!(binary, exports = exports.len(), "Minidump listing loaded");

    let generator = TestGenerator::new(workspace);
    let dump_refs: Vec<&Path> = dumps.iter().map(PathBuf::as_path).collect();
    let folded = fold_minidumps(
        &generator,
        binary,
        &dll_path,
        &exports,
        &dump_refs,
        &Replay::Harness {
            dll_path: &dll_path,
        },
    )
    .await
    .with_context(|| format!("Failed to fold the crash dumps for {binary}"))?;

    // One report per dump, in fold order: the digest names it in every
    // record the fold files, the count report reads exactly as the
    // capture ingest's does, and an unclaimed candidate states why.
    for dump in &folded {
        println!("minidump: {}", dump.digest);
        if dump.candidates_unclaimed > 0 {
            let reason = dump.candidate_reason.as_deref().unwrap_or("no claim");
            println!("  unclaimed mapping candidate: {reason}");
        }
        print!("{}", dump.report);
        for (binary, function, rows) in &dump.filed {
            println!("  filed {binary}/{function}: {} baseline cases", rows.len());
        }
        let landed = file_capture_records(workspace, binary, &dump.unknown_records)
            .context("Failed to file the minidump fold's unknown records")?;
        if landed > 0 {
            println!(
                "  unknowns: {landed} record{} landed in re/unknowns/{binary}.json",
                if landed == 1 { "" } else { "s" }
            );
        }
    }
    Ok(())
}

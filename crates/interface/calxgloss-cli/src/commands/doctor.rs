//! `calxgloss doctor` — a read-only report of the Kuna engine (issue #214).
//!
//! The Kuna engine is compiled into calxgloss, so there is no install,
//! plugin, extension, or port to check: the doctor loads the `--binary`
//! target in-process and reports the program identity the Kuna engine
//! reads from it.
//! Nothing is spawned, installed, or modified; a failing check exits
//! non-zero so CI can gate on the command.

use anyhow::{Result, bail};
use std::path::Path;
use tracing::info;

use crate::cli_types::DoctorArgs;
use crate::printers::{cyan_bold, dim, green_bold, white_bold};
use crate::settings::Settings;

/// Load the target with the Kuna engine and print the report; a failure is
/// an error exit.
pub async fn handle_doctor(_settings: &Settings, args: &DoctorArgs) -> Result<()> {
    info!("Running the Kuna engine check: loading the target in-process");
    let Some(binary) = args.binary.as_ref() else {
        bail!(
            "no target binary was named: re-run with --binary <FILE> — the Kuna \
             engine loads the target in-process, so the doctor needs the file to check"
        );
    };
    if args.fix {
        println!(
            "note: --fix has nothing to install for the Kuna engine — it is \
             compiled into calxgloss; running the check as-is"
        );
    }
    let program = calxgloss_kuna::load(binary)?;
    print_kuna_report(
        binary,
        calxgloss_kuna::KUNA_RELEASE,
        program.identity(),
        program.entry(),
        program.num_symbols(),
    );
    Ok(())
}

/// Print the Kuna engine's doctor report (issue #205): the target loaded
/// in-process and the program identity the Kuna engine reports. There is
/// no install, extension, or server to check — the Kuna engine is
/// compiled into calxgloss — so the report names what was loaded instead
/// of pretending to check an installed stack.
fn print_kuna_report(
    path: &Path,
    release: &str,
    identity: &str,
    entry: Option<u64>,
    symbols: usize,
) {
    let sep = cyan_bold(&"═".repeat(58));
    println!("{} Kuna Engine Report", sep);
    println!();
    pass(
        "Engine",
        &format!("kuna {release} — in-process; no install, extension, or port to check"),
    );
    println!();
    pass("Target", &path.display().to_string());
    note(&format!("language: {identity}"));
    match entry {
        Some(entry) => note(&format!("entry point: {entry:#x}")),
        None => note("entry point: none named by the file format"),
    }
    note(&format!("function symbols: {symbols}"));
    println!();
    println!("{}", dim(&"─".repeat(58)));
    println!("  {}", green_bold("the kuna engine loaded the target"));
}

/// A passing check line.
fn pass(label: &str, detail: &str) {
    println!("  {:<11}{}", white_bold(label), green_bold("✓"));
    println!("  {:<11}{}", "", detail);
}

/// A supporting detail under a check line.
fn note(text: &str) {
    println!("  {:<11}{}", "", dim(text));
}

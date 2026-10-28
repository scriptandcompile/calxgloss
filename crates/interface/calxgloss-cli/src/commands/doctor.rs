//! `calxgloss doctor` — a read-only report of the Kuna engine (issue #214).
//!
//! The Kuna engine is compiled into calxgloss, so there is no install,
//! plugin, extension, or port to check: the doctor loads the `--binary`
//! target in-process and reports the program identity the Kuna engine
//! reads from it.
//! Nothing is spawned, installed, or modified; a failing check exits
//! non-zero so CI can gate on the command.

use anyhow::{Result, bail};
use calxgloss_reports::doctor::print_kuna_report;
use tracing::info;

use crate::cli_types::DoctorArgs;
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

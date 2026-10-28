//! Formatting for `calxgloss doctor`'s read-only Kuna engine report.
//!
//! The Kuna engine is compiled into calxgloss, so there is no install,
//! extension, or port to check: the report names the loaded target and the
//! program identity the Kuna engine reads from it. The data comes from the
//! Kuna load; this module only formats it.

use std::path::Path;

use crate::{cyan_bold, dim, green_bold, white_bold};

/// Print the Kuna engine's doctor report (issue #205): the target loaded
/// in-process and the program identity the Kuna engine reports. There is
/// no install, extension, or server to check — the Kuna engine is
/// compiled into calxgloss — so the report names what was loaded instead
/// of pretending to check an installed stack.
pub fn print_kuna_report(
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

//! The `verify` command — verify a translated function against baseline tests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss_testgen::TestGenerator;
use calxgloss_verify::Verifier;
use tracing::info;

use crate::utils::*;

/// Handle the `verify` subcommand: verify a translated function.
pub async fn handle_verify(
    dll: &str,
    function: &str,
    rust_source: &Path,
    baseline_path: Option<&Path>,
) -> Result<()> {
    info!(dll = %dll, function = %function, "Starting verification");

    let target_dir = rust_source
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let output_dir = baseline_path.map(PathBuf::from).unwrap_or(target_dir);

    // Read the translated Rust code
    let rust_code = std::fs::read_to_string(rust_source)
        .with_context(|| format!("Failed to read Rust source from {}", rust_source.display()))?;

    info!(code_len = rust_code.len(), "Loaded translated code");

    // Load baseline tests if available
    let baseline_path = baseline_path
        .map(PathBuf::from)
        .or_else(|| Some(TestGenerator::new(&output_dir).baseline_path(dll, function)));

    let baseline_tests: Vec<calxgloss::TestCase> = match &baseline_path {
        Some(path) if path.exists() => {
            info!(path = %path.display(), "Loading baseline tests");
            serde_json::from_str(
                &std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read baseline from {}", path.display()))?,
            )
            .with_context(|| format!("Failed to parse baseline from {}", path.display()))?
        }
        _ => {
            info!("No baseline found, proceeding without tests");
            Vec::new()
        }
    };

    // Verify
    let verifier = Verifier::new(&output_dir).context("Failed to create verifier")?;
    let verification = verifier
        .verify(dll, function, &rust_code, &baseline_tests)
        .await
        .context("Verification failed")?;

    // Print results
    println!();
    println!(
        "{} Verification Results {}",
        cyan_bold(&"═".repeat(58)),
        cyan_bold(&"═".repeat(58))
    );
    println!("  {}{}", white_bold("  Function: "), function);
    let label = if dll.to_lowercase().ends_with(".exe") {
        "File:"
    } else {
        "DLL:"
    };
    println!("  {}{}", white_bold(&format!("  {label} ")), dll);
    println!("  {}{}", white_bold("  Source: "), rust_source.display());
    println!("{}", cyan_bold(&"═".repeat(58)));
    print_verification_results(&verification);
    println!("{}", cyan_bold(&"═".repeat(58)));

    let all_passed = verification.tests_passed == verification.tests_total;
    if all_passed || verification.tests_total == 0 {
        if verification.tests_total > 0 {
            println!(
                "  {}{}",
                white_bold("  Status: "),
                green_bold("PASS \u{2713}")
            );
        } else {
            println!(
                "  {}{}",
                white_bold("  Status: "),
                yellow_bold("PASS (no baseline tests)")
            );
        }
    } else {
        println!(
            "  {}{}",
            white_bold("  Status: "),
            red_bold("FAIL \u{2717}")
        );
    }

    Ok(())
}

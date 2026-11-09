//! The `verify` command — verify a translated function against baseline tests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use calxgloss_testgen::TestGenerator;
use calxgloss_verify::{Verifier, VerifyContext};
use tracing::info;

use crate::utils::*;

/// Handle the `verify` subcommand: verify a translated function.
///
/// The run files its *verification receipt* pair under the record tree
/// (`re/verification/<binary>/<function>/attempt-1.json`/`.md`) and the
/// command prints the pair's content digest — what P26's ledger will
/// cite a verified unit by. The command commits nothing: the pair stands
/// on disk beside `re/baseline/`, staged like any other record when its
/// branch is built.
pub async fn handle_verify(
    binary: &str,
    function: &str,
    rust_source: &Path,
    baseline_path: Option<&Path>,
    workspace: &Path,
) -> Result<()> {
    info!(binary = %binary, function = %function, "Starting verification");

    // Read the translated Rust code
    let rust_code = std::fs::read_to_string(rust_source)
        .with_context(|| format!("Failed to read Rust source from {}", rust_source.display()))?;

    info!(code_len = rust_code.len(), "Loaded translated code");

    // Load baseline tests if available
    let baseline_path = baseline_path
        .map(PathBuf::from)
        .or_else(|| Some(TestGenerator::new(workspace).baseline_path(binary, function)));

    let baseline_tests: Vec<calxgloss_types::TestCase> = match &baseline_path {
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

    // A standalone verify command sits outside any retry ladder: attempt
    // one, no strategy. The suite digest names the baseline file only
    // when one actually stood on disk and was read.
    let read_baseline = baseline_path.filter(|path| path.exists());
    let context = VerifyContext {
        baseline_file: read_baseline.as_deref(),
        ..VerifyContext::default()
    };

    // Verify — the run files its own digest-paired receipt pair.
    let verifier = Verifier::new(workspace).context("Failed to create verifier")?;
    let run = verifier
        .verify(binary, function, &rust_code, &baseline_tests, &context)
        .await
        .context("Verification failed")?;
    let verification = run.result;

    // Print results
    println!();
    println!(
        "{} Verification Results {}",
        cyan_bold(&"═".repeat(58)),
        cyan_bold(&"═".repeat(58))
    );
    println!("  {}{}", white_bold("  Function: "), function);
    let label = if binary.to_lowercase().ends_with(".exe") {
        "File:"
    } else {
        "DLL:"
    };
    println!("  {}{}", white_bold(&format!("  {label} ")), binary);
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

    // The receipt pair the run filed, and the digest that pairs it: the
    // handle any later green claim cites this verdict by.
    println!();
    println!(
        "  {}{} {}",
        white_bold("  Receipt: "),
        calxgloss_types::verification_receipt_path(
            workspace,
            &run.receipt.binary,
            function,
            run.receipt.attempt
        )
        .display(),
        dim(&format!("(+ {})", run.receipt.digest))
    );

    Ok(())
}

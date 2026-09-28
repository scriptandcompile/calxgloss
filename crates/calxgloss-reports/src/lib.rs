//! Terminal output formatting for human review of translation units.
//!
//! This crate provides functions for formatting and displaying translation
//! results, verification outcomes, Git branch status, and interactive prompts
//! in the terminal using ANSI-colored text output.
//!
//! # Functions
//!
//! - [`print_translation_summary`] — Display translation results (code, model, tokens)
//! - [`print_verification_results`] — Display compilation and test results
//! - [`print_git_status`] — Display Git branch creation status
//! - [`print_success`] — Display successful translation with acceptance prompt (returns `true` if accepted)
//! - [`print_failure`] — Display failed translation with diagnostic details
//! - [`prompt_acceptance`] — Interactive y/n prompt for human acceptance
//! - [`print_classification_report`] — Display DLL classification results
//! - [`print_batch_summary`] — Display batch translation results (pass/fail per function)
//! - [`render_dashboard`] — Display the review dashboard as a text-based table

pub mod dashboard;

use std::io::{self, Write};

use calxgloss_analysis::DllClassification;
use calxgloss_analysis::Strategy;
use calxgloss_translator::{BatchTranslationResult, Translation};
use calxgloss_types::FailedTest;
use calxgloss_types::GitBranch;
use calxgloss_types::VerificationResult;

// ============================================================
// ANSI color codes
// ============================================================

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_CYAN: &str = "\x1b[36m";

fn bold(text: &str) -> String {
    format!("{}{}", ANSI_BOLD, text)
}

fn bold_color(text: &str, code: &str) -> String {
    format!("{}{}{}", ANSI_BOLD, code, text)
}

fn dim(text: &str) -> String {
    format!("{}{}{}", ANSI_DIM, text, ANSI_RESET)
}

fn green_bold(text: &str) -> String {
    bold_color(text, ANSI_GREEN)
}

fn red_bold(text: &str) -> String {
    bold_color(text, ANSI_RED)
}

fn yellow_bold(text: &str) -> String {
    bold_color(text, ANSI_YELLOW)
}

fn cyan_bold(text: &str) -> String {
    bold_color(text, ANSI_CYAN)
}

fn white_bold(text: &str) -> String {
    bold(text)
}

// ============================================================
// print_translation_summary
// ============================================================

/// Print a summary of a translation result.
///
/// Displays the DLL name, function name, generated code line count, model used,
/// token usage, and the number of baseline tests generated.
pub fn print_translation_summary(translation: &Translation) {
    let sep = cyan_bold(&"═".repeat(58));
    println!("{} Translation Summary", sep);

    println!(
        "  {}{}: {}{}",
        white_bold("  Function: "),
        translation.function,
        dim("("),
        dim(&translation.dll)
    );
    println!(
        "  {}{}{}",
        white_bold("  Rust code: "),
        translation.rust_code.lines().count(),
        dim(" lines")
    );
    println!("  {}{}", white_bold("  Model: "), translation.model);
    if let Some(tokens) = translation.tokens_used {
        println!("  {}{}", white_bold("  Tokens: "), tokens);
    }
    println!(
        "  {}{}{}",
        white_bold("  Baseline tests: "),
        translation.baseline_tests.len(),
        dim(" generated")
    );
    println!("{}", sep);
}

// ============================================================
// print_verification_results
// ============================================================

/// Print verification results (compilation status, test pass/fail counts, errors).
///
/// Displays whether compilation succeeded, how many tests passed,
/// and details of any compilation errors or test failures.
pub fn print_verification_results(result: &VerificationResult) {
    if result.compiled {
        println!("  {}{}", white_bold("Compiled: "), green_bold("yes"));

        if result.tests_total > 0 {
            let pass_rate = result.tests_passed as f64 / result.tests_total as f64 * 100.0;
            let color = if result.tests_passed == result.tests_total {
                green_bold(&format!(
                    "{}/{} passed ({:.0}%)",
                    result.tests_passed, result.tests_total, pass_rate
                ))
            } else if pass_rate >= 90.0 {
                yellow_bold(&format!(
                    "{}/{} passed ({:.0}%)",
                    result.tests_passed, result.tests_total, pass_rate
                ))
            } else {
                red_bold(&format!(
                    "{}/{} passed ({:.0}%)",
                    result.tests_passed, result.tests_total, pass_rate
                ))
            };
            println!("  {}", color);
        } else {
            println!("  {}", dim("Tests: none"));
        }

        if !result.failed_tests.is_empty() {
            println!("  {}", yellow_bold("  Failed:"));
            for failed in &result.failed_tests {
                print_failed_test_detail(failed);
            }
        }
    } else {
        println!("  {}{}", white_bold("Compiled: "), red_bold("no"));

        if !result.compilation_errors.is_empty() {
            println!("  {}", red_bold("  Errors:"));
            for error in &result.compilation_errors {
                for line in error.lines() {
                    println!("    {}", dim(line));
                }
            }
        }
    }
}

/// Print details of a single failed test.
fn print_failed_test_detail(failed: &FailedTest) {
    let inputs_str = match &failed.inputs {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(arr) => {
            let strs: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_i64())
                .map(|n| n.to_string())
                .collect();
            format!("[{}]", strs.join(", "))
        }
        serde_json::Value::String(s) => format!("\"{}\"", s),
        _ => format!("{}", failed.inputs),
    };

    let expected_str = match &failed.expected {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        _ => format!("{}", failed.expected),
    };

    let actual_str = match &failed.actual {
        serde_json::Value::String(s) if s.contains("panicked") || s.contains("PANIC") => {
            format!("panicked ({})", s)
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => format!("\"{}\"", s),
        _ => format!("{}", failed.actual),
    };

    println!(
        "    {}{}: {} (expected {}, got {})",
        dim("input_"),
        failed.test_index,
        white_bold(&inputs_str),
        expected_str,
        actual_str
    );
}

// ============================================================
// print_git_status
// ============================================================

/// Print the Git branch creation status.
///
/// Displays the branch name and whether it was newly created or already existed.
pub fn print_git_status(branch: &GitBranch, merged: bool) {
    if merged {
        println!(
            "  {}{}{}",
            white_bold("  Branch: "),
            branch.name,
            dim(" → merged to main")
        );
    } else {
        println!(
            "  {}{}{}",
            white_bold("  Branch: "),
            branch.name,
            dim(" (not merged)")
        );
    }

    let status_color = if merged { green_bold } else { yellow_bold };
    let status_text = if merged { "MERGED" } else { "UNMERGED" };
    println!(
        "  {}{}",
        white_bold("  Status: "),
        status_color(status_text)
    );
}

// ============================================================
// print_success
// ============================================================

/// Print a success summary with the full translation + verification output.
///
/// Returns `true` if the user accepted the translation, `false` otherwise.
///
/// The output includes:
/// - Translation summary (function, model, tokens, code size)
/// - Verification results (compilation, tests)
/// - Git branch status
/// - Overall status with pass/fail indicator
/// - Interactive acceptance prompt
pub fn print_success(branch: &GitBranch, verification: &VerificationResult) -> bool {
    println!();
    println!("{}", cyan_bold(&"╔".repeat(60)));
    println!(
        "  {}TRANSLATION COMPLETE{}",
        cyan_bold("║  "),
        cyan_bold(" ║")
    );
    println!("{}", cyan_bold(&"║".repeat(60)));

    // Function info
    println!("  {}{}", white_bold("  Function: "), branch.function);
    println!("  {}{}", white_bold("  DLL: "), branch.dll);
    println!("{}", cyan_bold(&"║".repeat(60)));

    // Verification results
    print_verification_results(verification);

    // Git status
    print_git_status(branch, true);

    // Overall status
    let all_passed = verification.tests_passed == verification.tests_total;
    if all_passed {
        println!(
            "  {}{}",
            white_bold("  Status: "),
            green_bold("PASS \u{2713}")
        );
    } else if verification.tests_passed > 0 && verification.failed_tests.len() <= 2 {
        println!(
            "  {}{}",
            white_bold("  Status: "),
            yellow_bold("PASS (with warnings)")
        );
    } else {
        println!(
            "  {}{}",
            white_bold("  Status: "),
            yellow_bold("PASS (with failures)")
        );
    }

    println!("{}", cyan_bold(&"╚".repeat(60)));

    if verification.failed_tests.is_empty() {
        return true;
    }

    prompt_acceptance()
}

// ============================================================
// print_failure
// ============================================================

/// Print a failure summary with diagnostic details.
///
/// Displays the branch name, compilation errors, and test failures.
/// Always prompts for acceptance (though acceptance is typically not relevant for failures).
pub fn print_failure(branch: &GitBranch, verification: &VerificationResult) {
    println!();
    println!("{}", cyan_bold(&"╔".repeat(60)));
    println!(
        "  {}TRANSLATION FAILED{}",
        cyan_bold("║  "),
        cyan_bold(" ║")
    );
    println!("{}", cyan_bold(&"║".repeat(60)));

    // Function info
    println!("  {}{}", white_bold("  Function: "), branch.function);
    println!("  {}{}", white_bold("  DLL: "), branch.dll);
    println!("{}", cyan_bold(&"║".repeat(60)));

    // Verification results
    print_verification_results(verification);

    // Git status
    print_git_status(branch, false);

    // Overall status
    println!(
        "  {}{}",
        white_bold("  Status: "),
        red_bold("FAIL \u{2717} — fix required")
    );

    println!("{}", cyan_bold(&"╚".repeat(60)));

    println!(
        "  {}",
        dim("  Tip: A new branch will be created for retry attempt.")
    );
}

// ============================================================
// prompt_acceptance
// ============================================================

/// Prompt the user for acceptance (y/n).
///
/// Returns `true` if the user enters 'y' or 'Y', `false` otherwise.
/// Reads from stdin line by line.
pub fn prompt_acceptance() -> bool {
    print!("  {}", yellow_bold("Accept (y/n): "));
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();

    let accepted = input.trim().eq_ignore_ascii_case("y");

    if accepted {
        println!("  {}", green_bold("  Accepted."));
    } else {
        println!("  {}", dim("  Rejected."));
    }

    accepted
}

// ============================================================
// Classify command output
// ============================================================

/// Print a DLL classification report.
///
/// Displays the DLL name, its category, the recommended strategy,
/// and counts of exports and imports.
pub fn print_classification_report(classifications: &[DllClassification]) {
    let sep = cyan_bold(&"═".repeat(58));
    println!("{} DLL Classification Report", sep);
    println!();

    for classification in classifications {
        let strategy_color = match &classification.strategy {
            Strategy::PalMapping => green_bold,
            Strategy::CrateReplacement { .. } => yellow_bold,
            Strategy::ReverseEngineer => red_bold,
        };

        let strategy_text = match &classification.strategy {
            Strategy::PalMapping => "PAL Mapping".to_string(),
            Strategy::CrateReplacement { crate_name } => {
                format!("Crate Replacement ({})", crate_name)
            }
            Strategy::ReverseEngineer => "Reverse Engineer".to_string(),
        };

        println!("  {}{}", white_bold("  DLL: "), classification.dll);
        println!(
            "  {}{}",
            white_bold("  Category: "),
            format_category(&classification.category)
        );
        println!(
            "  {}{}",
            white_bold("  Strategy: "),
            strategy_color(&strategy_text)
        );
        println!(
            "  {}{} exports, {} imports",
            white_bold("  "),
            classification.exports_count,
            classification.imports_count
        );
        if let Some(ref replacement) = classification.crate_replacement {
            println!("  {}{}", dim("    Crate: "), dim(replacement));
        }
        println!();
    }

    println!("{}", sep);

    // Summary counts
    let pal_count = classifications
        .iter()
        .filter(|c| matches!(c.strategy, Strategy::PalMapping))
        .count();
    let crate_count = classifications
        .iter()
        .filter(|c| matches!(c.strategy, Strategy::CrateReplacement { .. }))
        .count();
    let re_count = classifications
        .iter()
        .filter(|c| matches!(c.strategy, Strategy::ReverseEngineer))
        .count();

    println!(
        "  {} Summary: {} PAL, {} crate replacement, {} reverse engineer",
        bold(&dim("  Summary:")),
        green_bold(&pal_count.to_string()),
        yellow_bold(&crate_count.to_string()),
        red_bold(&re_count.to_string())
    );
}

/// Format a DLL category for display.
fn format_category(category: &calxgloss_types::DllCategory) -> String {
    match category {
        calxgloss_types::DllCategory::WindowsOs => "Windows OS".to_string(),
        calxgloss_types::DllCategory::MicrosoftSdk => "Microsoft SDK".to_string(),
        calxgloss_types::DllCategory::KnownThirdParty => "Known Third-Party".to_string(),
        calxgloss_types::DllCategory::ProjectSpecific => "Project-Specific".to_string(),
        calxgloss_types::DllCategory::UnknownThirdParty => "Unknown Third-Party".to_string(),
    }
}

// ============================================================
// Batch translation summary
// ============================================================

/// Print a summary of a batch translation run.
///
/// Displays:
/// - A header with the DLL name and total function count
/// - Per-function pass/fail lines with model used
/// - A summary row showing total succeeded, failed, and the pass rate
pub fn print_batch_summary(result: &BatchTranslationResult) {
    let sep = cyan_bold(&"═".repeat(58));
    println!();
    println!("{} Batch Translation — {}", sep, result.dll);
    println!("{}", sep);

    for (idx, func_result) in result.results.iter().enumerate() {
        let func_line = format!("  {}. {}", idx + 1, func_result.function);

        if func_result.success {
            println!("  {} {}", green_bold("\u{2713}"), func_line);
            if let Some(rust_code) = &func_result.rust_code {
                let lines = rust_code.lines().count();
                println!(
                    "     {}{} Rust code, {} lines",
                    dim("  model: "),
                    func_result
                        .retry_result
                        .success_strategy
                        .as_deref()
                        .unwrap_or("initial"),
                    lines
                );
            }
        } else {
            println!("  {} {}", red_bold("\u{2717}"), func_line);
            // Show how many attempts were made
            let attempts = func_result.retry_result.attempts.len();
            if attempts > 0 {
                println!("     {}{} attempts exhausted", dim("  "), attempts);
            }
        }
    }

    println!("{}", sep);

    let total = result.total_count();
    let success = result.success_count();
    let failure = result.failure_count();

    let overall_color = if failure == 0 && total > 0 {
        green_bold
    } else if success > 0 {
        yellow_bold
    } else {
        red_bold
    };

    let pass_rate = if total > 0 {
        success as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    println!(
        "  {}{} succeeded, {} failed ({:.0}% pass rate)",
        overall_color(&success.to_string()),
        white_bold(&dim(" ").to_string()),
        red_bold(&failure.to_string()),
        pass_rate
    );

    if !result.results.is_empty() {
        let all = result.all_success();
        let label = if all { "ALL PASS" } else { "INCOMPLETE" };
        println!(
            "  {}",
            if all {
                green_bold(label)
            } else {
                yellow_bold(label)
            }
        );
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_category() {
        assert_eq!(
            format_category(&calxgloss_types::DllCategory::WindowsOs),
            "Windows OS"
        );
        assert_eq!(
            format_category(&calxgloss_types::DllCategory::MicrosoftSdk),
            "Microsoft SDK"
        );
        assert_eq!(
            format_category(&calxgloss_types::DllCategory::KnownThirdParty),
            "Known Third-Party"
        );
        assert_eq!(
            format_category(&calxgloss_types::DllCategory::ProjectSpecific),
            "Project-Specific"
        );
        assert_eq!(
            format_category(&calxgloss_types::DllCategory::UnknownThirdParty),
            "Unknown Third-Party"
        );
    }

    #[test]
    fn test_failed_test_display_json_types() {
        let failed = FailedTest {
            test_index: 0,
            inputs: serde_json::json!([1, 2, 3]),
            expected: serde_json::json!(6),
            actual: serde_json::json!(7),
            error: "expected 6, got 7".to_string(),
        };
        assert_eq!(failed.test_index, 0);
        assert_eq!(failed.error, "expected 6, got 7");
    }
}

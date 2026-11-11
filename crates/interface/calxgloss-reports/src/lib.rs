//! Terminal output formatting for human review of translation units.
//!
//! This crate provides functions for formatting and displaying translation
//! results, verification outcomes, Git branch status, and interactive prompts
//! in the terminal using ANSI-colored text output.
//!
//! The CLI's own terminal printers — the batch-summary, classification-report,
//! verification-results, git-status, and failure printers and the doctor
//! engine report — now live inside the CLI crate (issue #481). What remains
//! here is the review-facing terminal output still standing in this crate:
//! the dashboard, and the acceptance-prompt flow with the private printers
//! it calls. Those go away when their surfaces do (issues #484, #485).
//!
//! # Functions
//!
//! - [`print_translation_summary`] — Display translation results (code, model, tokens)
//! - [`print_success`] — Display successful translation with acceptance prompt (returns `true` if accepted)
//! - [`prompt_acceptance`] — Interactive y/n prompt for human acceptance
//! - [`verification_receipt_markdown`] — Render a *verification receipt*'s
//!   human twin (re-exported from the record's owning crate)
//! - [`dashboard::render_dashboard`] — Display the review dashboard as a text-based table

pub mod dashboard;

/// Human rendering of a *verification receipt* at the review surface.
///
/// The rendering is owned by the record itself in `calxgloss-types` —
/// the document renders its own human twin, so the pair's facts can
/// never drift from its JSON authority — and re-exported here beside
/// this crate's other human renderings, so a reader at the report
/// surface imports it from one place.
pub use calxgloss_types::verification_receipt_markdown;

use std::io::{self, Write};

use calxgloss_translator::Translation;
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
        dim(&translation.binary)
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
fn print_verification_results(result: &VerificationResult) {
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

    // A failed test whose case expected global side effects lists them
    // by their typed kinds, so the difference in global handling shows
    // up as `GlobalWrite DAT_...` instead of prose to be parsed.
    if !failed.expected_side_effects.is_empty() {
        let named: Vec<String> = failed
            .expected_side_effects
            .iter()
            .map(|effect| match &effect.kind {
                calxgloss_types::SideEffectKind::Other(note) => format!("Other {note}"),
                kind => format!("{kind:?} {}", effect.detail),
            })
            .collect();
        println!(
            "    {}{}",
            dim("expected side effects: "),
            dim(&named.join(", "))
        );
    }
}

// ============================================================
// print_git_status
// ============================================================

/// Print the Git branch creation status.
///
/// Displays the branch name and whether it was newly created or already existed.
fn print_git_status(branch: &GitBranch, merged: bool) {
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
/// Returns `true` when the translation is accepted: either there are no
/// failed tests (then it returns without prompting) or the user answers
/// yes to the acceptance prompt.
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
    println!("  {}{}", white_bold("  DLL: "), branch.binary);
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

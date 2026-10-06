//! Dashboard terminal rendering — ANSI-colored text output for the review dashboard.
//!
//! This module provides functions for rendering a [`ReviewDashboard`] to the
//! terminal, including the main dashboard view and per-unit detail views.

use std::time::{Duration, Instant};

use calxgloss_git::GitManager;
use calxgloss_types::dashboard::{
    ReviewDashboard, ReviewStatus, Staleness, StatusCounts, UnitOfWork, WorkUnitKind,
};
use chrono::Utc;

use super::builder::DashboardBuilder;
use super::view::UnitViewData;

// ============================================================
// ANSI codes
// ============================================================

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_BLUE: &str = "\x1b[34m";

fn bold(text: &str) -> String {
    format!("{}{}{}", ANSI_BOLD, text, ANSI_RESET)
}

fn dim(text: &str) -> String {
    format!("{}{}{}", ANSI_DIM, text, ANSI_RESET)
}

fn green_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_GREEN, text, ANSI_RESET)
}

fn red_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_RED, text, ANSI_RESET)
}

fn yellow_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_YELLOW, text, ANSI_RESET)
}

fn blue_bold(text: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, ANSI_BLUE, text, ANSI_RESET)
}

fn format_dim(text: &str) -> String {
    dim(text)
}

// ============================================================
// Status helpers
// ============================================================

fn status_symbol(status: &ReviewStatus) -> &str {
    match status {
        ReviewStatus::Queued => "  ?",
        ReviewStatus::PendingReview => " ◉",
        ReviewStatus::InProgress => " ⟳",
        ReviewStatus::Accepted => " ✓",
        ReviewStatus::SendBack => " ✗",
        ReviewStatus::PatchRequested => " ⚑",
        ReviewStatus::Merged => " ◆",
        ReviewStatus::Blocked => " ✖",
    }
}

fn format_kind(kind: &WorkUnitKind) -> String {
    match kind {
        WorkUnitKind::DllClassification => "classify".to_string(),
        WorkUnitKind::ShimLayer => "shim".to_string(),
        WorkUnitKind::FunctionTranslation => "func".to_string(),
        WorkUnitKind::TestCaseAddition => "test".to_string(),
        WorkUnitKind::PalTrait => "pal".to_string(),
        WorkUnitKind::IntegrationStep => "integrate".to_string(),
        WorkUnitKind::BugFix => "fix".to_string(),
    }
}

fn format_status_display(status: &ReviewStatus) -> String {
    let symbol = status_symbol(status);
    let text = match status {
        ReviewStatus::Queued => "queued",
        ReviewStatus::PendingReview => "pending",
        ReviewStatus::InProgress => "in_progress",
        ReviewStatus::Accepted => "accepted",
        ReviewStatus::SendBack => "send_back",
        ReviewStatus::PatchRequested => "patch",
        ReviewStatus::Merged => "merged",
        ReviewStatus::Blocked => "blocked",
    };
    format!("{} {}", symbol, text)
}

fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn truncate(text: &str, max_width: usize) -> String {
    if text.len() <= max_width {
        text.to_string()
    } else {
        format!("{}…", &text[..max_width.saturating_sub(1)])
    }
}

// ============================================================
// Dashboard rendering
// ============================================================

/// Width of horizontal dividers (no vertical borders, no corners).
const SEP_WIDTH: usize = 78;

fn hsep() {
    println!("  {}", "─".repeat(SEP_WIDTH));
}

fn hsep_bold() {
    println!("  {}", "═".repeat(SEP_WIDTH));
}

fn println_content(content: impl AsRef<str>) {
    let s = content.as_ref();
    let visible: String = s.chars().filter(|c| !c.is_control()).collect();
    let padded = if visible.len() < SEP_WIDTH {
        format!("{:<SEP_WIDTH$}", s)
    } else {
        let mut end = SEP_WIDTH.min(visible.len());
        while !visible.is_char_boundary(end) {
            end -= 1;
        }
        let mut vcount = 0usize;
        let mut bend = 0usize;
        for (bi, ch) in s.chars().enumerate() {
            if !ch.is_control() {
                vcount += 1;
            }
            if vcount >= end {
                bend = bi + ch.len_utf8();
                break;
            }
        }
        s[..bend].to_string()
    };
    println!("  {}", padded);
}

/// Renders a [`ReviewDashboard`] to the terminal as a flat text report.
pub fn render_dashboard(dashboard: &ReviewDashboard, follow: bool) {
    let total = dashboard.status_counts.total();
    let now = Utc::now().format("%Y-%m-%d %H:%M UTC");

    hsep_bold();
    println_content(format!("  Calxgloss Review Dashboard — {}  ", now));
    hsep();

    render_status_summary(&dashboard.status_counts);
    hsep();

    let queue = &dashboard.review_queue;
    if queue.is_empty() {
        println_content("  No pending units in the review queue.");
    } else {
        println_content("  Review Queue");
        println_content("");
        render_queue_table(queue);
        println_content("");
    }

    let blocked = dashboard.blocked_units();
    if !blocked.is_empty() {
        println_content(format!("  Blocked units ({}):", blocked.len()));
        for unit in &blocked {
            let name = format!("{} ({})", unit.name, unit.dll);
            println_content(format!(
                "    ✖ {} — depends on: {}",
                name,
                unit.dependencies.join(", ")
            ));
        }
        println_content("");
    }

    let stale_units: Vec<&UnitOfWork> = dashboard
        .review_queue
        .iter()
        .filter(|u| u.stale.is_stale())
        .collect();
    if !stale_units.is_empty() {
        let critical_count = stale_units
            .iter()
            .filter(|u| matches!(u.stale, Staleness::Critical(_)))
            .count();
        let warning_count = stale_units.len() - critical_count;

        println_content(format!(
            "  Stale work ({}): {} warning, {} critical",
            stale_units.len(),
            warning_count,
            critical_count
        ));
        for unit in &stale_units {
            let name = format!("{} ({})", unit.name, unit.dll);
            let stale = unit.stale;
            match stale {
                Staleness::Critical(elapsed) => {
                    println_content(format!(
                        "    {} {} — pending for {}",
                        red_bold("⚠"),
                        name,
                        fmt_duration(elapsed)
                    ));
                }
                Staleness::Stale(elapsed) => {
                    println_content(format!(
                        "    {} {} — pending for {}",
                        yellow_bold("⏳"),
                        name,
                        fmt_duration(elapsed)
                    ));
                }
                Staleness::Fresh => {}
            }
        }
        println_content("");
    }

    let recent = &dashboard.recent_activity;
    if !recent.is_empty() {
        println_content(format!("  Recent activity ({}):", recent.len()));
        for unit in recent.iter().rev().take(5) {
            let test_info = match (unit.baseline_tests_passed, unit.baseline_tests_total) {
                (Some(passed), Some(total)) => format!("{}/{} tests", passed, total),
                _ => "—".to_string(),
            };
            let confidence = unit
                .confidence
                .map(|c| format!("({:.0}%)", c * 100.0))
                .unwrap_or_else(|| "no confidence".to_string());

            println_content(format!(
                "    ✓ {} [{}] — {} — {}",
                unit.name, unit.dll, test_info, confidence
            ));
        }
        println_content("");
    }

    println_content(format!("  {} branches found in re/*", total));
    if follow {
        println_content("  Watching for changes (Ctrl+C to stop). Press 'r' to refresh.");
    }

    hsep_bold();
    println!();
}

fn render_status_summary(counts: &StatusCounts) {
    let total = counts.total();
    let parts = [
        green_bold(&format!("OK {}", counts.accepted + counts.merged)),
        yellow_bold(&format!(
            "Pending {}",
            counts.pending_review + counts.patch_requested
        )),
        red_bold(&format!("Failed {}", counts.send_back)),
        blue_bold(&format!("Queued {}", counts.queued)),
        dim(&format!("Blocked {}", counts.blocked)),
        bold(&format!("Total: {}", total)),
    ];
    println_content(parts.join("  │  "));
}

fn render_queue_table(units: &[UnitOfWork]) {
    println_content(
        "  #   Kind       Function                        Status      Tests    Attempt",
    );
    hsep();

    for (idx, unit) in units.iter().enumerate() {
        let kind_str = format_kind(&unit.kind);
        let name = truncate(&unit.name, 30);
        let status_str = format_status_display(&unit.status);

        let (status_str, row_prefix) = match &unit.stale {
            Staleness::Critical(_) => (yellow_bold(&status_str), "  ⚠ "),
            Staleness::Stale(_) => (dim(&yellow_bold(&status_str)), "  ⏳ "),
            Staleness::Fresh => (status_str, "    "),
        };

        let attempt_str = format!("v{}", unit.attempt);

        let line = format!(
            "{}{}  {}  {}  {}  {}  {}",
            row_prefix,
            bold(&format!("{:<3}", idx + 1)),
            format_dim(&format!("{:<8}", kind_str)),
            format_dim(&format!("{:<30}", name)),
            status_str,
            "\t\t—\t\t",
            attempt_str,
        );
        println!("{}", line);
    }
    hsep();
}

/// Renders the dashboard in "follow" mode, refreshing periodically.
pub fn render_dashboard_follow(git: &GitManager, interval: Duration) -> Result<(), anyhow::Error> {
    let builder = DashboardBuilder::new(git);
    let mut last_refresh: Option<Instant> = None;

    loop {
        let now = Instant::now();
        let should_refresh = match last_refresh {
            Some(last) => now.duration_since(last) >= interval,
            None => true,
        };

        if should_refresh {
            let dashboard = builder.build()?;
            render_dashboard(&dashboard, true);
            last_refresh = Some(now);
        }

        std::thread::sleep(Duration::from_millis(100));

        // Auto-refresh provides a good enough UX — manual refresh disabled
        let _ = should_refresh;
    }
}

// ============================================================
// Per-unit view rendering
// ============================================================

/// Render a detailed view of a single translation unit.
pub fn render_unit_view(data: &UnitViewData) {
    let sep = "─".repeat(SEP_WIDTH);
    let sep_bold = "═".repeat(SEP_WIDTH);

    println!();
    println!("{}", sep_bold);
    println_content(format!(
        "  Unit View: {}/{}",
        data.target.dll, data.target.function
    ));
    println!("{}", sep);

    // Section 1: Unit Info & Status
    println_content("  Unit Info");
    if let Some(ref unit) = data.unit {
        println_content(format!("    Name:       {}", unit.name));
        println_content(format!("    Kind:       {}", unit.kind));
        println_content(format!(
            "    Status:     {}",
            format_status_display(&unit.status)
        ));
        println_content(format!(
            "    Confidence: {:.0}%",
            unit.confidence.unwrap_or(0.0) * 100.0
        ));
        if let Some(ref model) = unit.llm_model {
            println_content(format!("    LLM Model:  {}", model));
        }
        if let Some(tier) = unit.context_tier {
            println_content(format!("    Context Tier: {}", tier));
        }
        if !unit.dependencies.is_empty() {
            println_content(format!(
                "    Dependencies: {}",
                unit.dependencies.join(", ")
            ));
        }
        if !unit.known_gaps.is_empty() {
            println_content("    Known Gaps:");
            for gap in &unit.known_gaps {
                println_content(format!("      • {}", gap));
            }
        }
    }

    if let Some(ref branch) = data.branch_name {
        let status = if data.merged {
            green_bold("merged ◆")
        } else {
            yellow_bold("unmerged ◉")
        };
        println_content(format!("    Branch:     {} ({})", branch, status));
    } else {
        println_content("    Branch:     <not found>");
    }

    if let Some(ref category) = data.dll_category {
        println_content(format!("    DLL Category: {}", category));
    }
    if let Some(ref strategy) = data.dll_strategy {
        println_content(format!("    Strategy:   {}", strategy));
    }

    println_content("");

    // Section 2: Diff Summary
    println_content("  Diff Summary (branch vs main)");
    if let Some(ref diff) = data.diff_summary {
        if diff.files_changed > 0 {
            let ins = green_bold(&diff.insertions.to_string());
            let del = red_bold(&diff.deletions.to_string());
            println_content(format!(
                "    Files changed: {}  |  +{} lines  |  {}- lines",
                diff.files_changed, ins, del
            ));
        } else {
            println_content("    No changes (branch is identical to main)");
        }
    } else {
        println_content("    Could not compute diff");
    }
    println_content("");

    // Section 3: Test Results
    println_content("  Test Results");
    if let (Some(passed), Some(total)) = (data.baseline_tests_passed, data.baseline_tests_total) {
        if total > 0 {
            let rate = (passed as f64 / total as f64 * 100.0).round();
            let color = if passed == total {
                green_bold(&format!("{}/{} passed ({:.0}%)", passed, total, rate))
            } else if rate >= 90.0 {
                yellow_bold(&format!("{}/{} passed ({:.0}%)", passed, total, rate))
            } else {
                red_bold(&format!("{}/{} passed ({:.0}%)", passed, total, rate))
            };
            println_content(format!("    Baseline: {}", color));
        } else {
            println_content("    Baseline: no tests");
        }
    } else {
        println_content("    Baseline: <no data>");
    }

    if let (Some(_passed), Some(_total)) = (data.baseline_tests_passed, data.baseline_tests_total) {
        let latest_attempt = data.attempt_history.last();
        if let Some(attempt) = latest_attempt {
            if attempt.tests_total > 0 {
                let ver_passed = attempt.tests_passed.min(attempt.tests_total);
                println_content(format!(
                    "    Verification (latest): {}/{} tests passed",
                    ver_passed, attempt.tests_total
                ));
            } else {
                println_content("    Verification (latest): no tests run");
            }
        }
    }
    println_content("");

    // Section 4: Attempt History
    println_content("  Attempt History");
    if data.attempt_history.is_empty() {
        println_content("    No attempt records found.");
        println_content("    This unit has not been translated yet.");
    } else {
        for attempt in &data.attempt_history {
            let marker = if attempt.is_latest { " ▶" } else { "  " };
            let status_icon = if attempt.is_latest
                && attempt.compiled
                && attempt.tests_passed == attempt.tests_total
            {
                green_bold("\u{2713}")
            } else if attempt.compilation_errors.is_empty() && attempt.failed_tests.is_empty() {
                dim("\u{25cb}")
            } else {
                red_bold("\u{2717}")
            };

            println_content(format!(
                "{}  Attempt #{}  {}  committed: {}",
                marker,
                attempt.attempt,
                status_icon,
                &attempt.committed_at[..19]
            ));

            if !attempt.compilation_errors.is_empty() {
                println_content(format!(
                    "      Compile errors: {} (first: {})",
                    attempt.compilation_errors.len(),
                    &attempt.compilation_errors[0][..attempt.compilation_errors[0].len().min(80)]
                ));
            }

            if !attempt.failed_tests.is_empty() {
                let preview = attempt
                    .failed_tests
                    .iter()
                    .map(|t| {
                        let truncated = if t.len() > 80 { &t[..80] } else { t };
                        format!("\"{}\"", truncated)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                println_content(format!(
                    "      Failed tests: {} (first: {})",
                    attempt.failed_tests.len(),
                    preview
                ));
            }

            if attempt.compiled && !attempt.compilation_errors.is_empty() {
                println_content("      Status: compiled with errors");
            } else if attempt.compilation_errors.is_empty() {
                println_content("      Status: clean compile");
            }
        }
    }
    println!("{}", sep_bold);
    println!();
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::dashboard::{ReviewStatus, WorkUnitKind};

    #[test]
    fn status_symbol_mapping() {
        assert_eq!(status_symbol(&ReviewStatus::Queued), "  ?");
        assert_eq!(status_symbol(&ReviewStatus::PendingReview), " ◉");
        assert_eq!(status_symbol(&ReviewStatus::Accepted), " ✓");
        assert_eq!(status_symbol(&ReviewStatus::SendBack), " ✗");
        assert_eq!(status_symbol(&ReviewStatus::Merged), " ◆");
    }

    #[test]
    fn format_kind_mapping() {
        assert_eq!(format_kind(&WorkUnitKind::DllClassification), "classify");
        assert_eq!(format_kind(&WorkUnitKind::FunctionTranslation), "func");
        assert_eq!(format_kind(&WorkUnitKind::ShimLayer), "shim");
    }
}

//! Utility functions for the CLI.

use anyhow::Result;
pub use calxgloss_reports::{
    print_batch_summary, print_classification_report, print_failure, print_git_status,
    print_verification_results,
};
pub use calxgloss_translator::RetryStrategy;
pub use calxgloss_verify::Verifier;
use std::path::PathBuf;
pub use tracing::{debug, warn};

/// Resolve the repo directory: `--repo` flag > settings > CWD.
///
/// This is the single point of resolution for commands that use the
/// config-file / env-var layer (`auto`, `translate`, `batch-translate`).
pub(super) fn resolve_repo_dir(cli_repo: Option<&PathBuf>, settings: &crate::Settings) -> PathBuf {
    cli_repo
        .cloned()
        .or_else(|| settings.repo_dir.as_ref().map(|r| PathBuf::from(&r.value)))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Resolve the repo directory for `live` and `serve`: `--repo` flag > CWD.
///
/// These commands always operate on the workspace in the current directory
/// (where `.git`, `src/`, `scratch/` live).  Config file and env-var
/// overrides are ignored — only an explicit `--repo` flag can change this.
pub(super) fn resolve_live_repo_dir(cli_repo: Option<&PathBuf>) -> PathBuf {
    cli_repo
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Parse a retry strategy string into a [`RetryStrategy`].
pub(super) fn parse_retry_strategy(s: &str) -> Result<RetryStrategy> {
    Ok(match s {
        "compile_fix" => RetryStrategy::CompileFix,
        "test_fix" => RetryStrategy::TestFix,
        "escalate" => RetryStrategy::Escalate,
        "edge_case_fix" => RetryStrategy::EdgeCaseFix,
        "auto" => {
            // Auto mode starts with compile_fix and cycles through all strategies.
            // The cycling happens in the retry loop itself.
            RetryStrategy::CompileFix
        }
        other => anyhow::bail!(
            "Unknown retry strategy '{}'. Valid strategies: compile_fix, test_fix, \
             escalate, edge_case_fix, auto",
            other
        ),
    })
}

/// Initialize tracing with the given verbosity level and format.
pub(super) fn init_logging(verbosity: u8, format: &str) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(level)
                .init();
        }
        "text" => {
            tracing_subscriber::fmt()
                .with_target(false)
                .with_env_filter(level)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_target(false)
                .with_env_filter(level)
                .init();
        }
    };

    debug!("Logging initialized: level={}, format={}", level, format);
}

// ============================================================
// Terminal formatting helpers (mirrors calxgloss-reports internals)
// ============================================================

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_CYAN: &str = "\x1b[36m";

pub(super) fn bold(text: &str) -> String {
    format!("{}{}{}", ANSI_BOLD, text, ANSI_RESET)
}

pub(super) fn bold_color(text: &str, code: &str) -> String {
    format!("{}{}{}{}", ANSI_BOLD, code, text, ANSI_RESET)
}

pub(super) fn green_bold(text: &str) -> String {
    bold_color(text, ANSI_GREEN)
}

pub(super) fn red_bold(text: &str) -> String {
    bold_color(text, ANSI_RED)
}

pub(super) fn yellow_bold(text: &str) -> String {
    bold_color(text, ANSI_YELLOW)
}

pub(super) fn cyan_bold(text: &str) -> String {
    bold_color(text, ANSI_CYAN)
}

pub(super) fn white_bold(text: &str) -> String {
    bold(text)
}

pub(super) fn dim(text: &str) -> String {
    format!("{}{}{}", "\x1b[2m", text, ANSI_RESET)
}

pub(super) fn format_dim(text: &str) -> String {
    dim(text)
}

/// Width of horizontal dividers (no vertical borders, no corners).
const SEP_WIDTH: usize = 78;

/// A single horizontal divider.
pub(super) fn hsep() {
    println!("  {}", "─".repeat(SEP_WIDTH));
}

/// A bold horizontal divider.
pub(super) fn hsep_bold() {
    println!("  {}", "═".repeat(SEP_WIDTH));
}

/// Prints a line of content, padded to SEP_WIDTH with spaces.
/// Safe for ANSI codes and multi-byte UTF-8.
pub(super) fn println_content(content: impl AsRef<str>) {
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

// ============================================================
// Dashboard accept/reject helpers
// ============================================================

/// Walk up from CWD to find the Git repository root.
pub(super) fn find_repo_path() -> Result<PathBuf> {
    let path = std::env::current_dir()?;
    let mut search = path.clone();
    for _ in 0..10 {
        if search.join(".git").exists() || search.join(".git").is_dir() {
            return Ok(search.clone());
        }
        if !search.pop() {
            break;
        }
    }
    Ok(path)
}

/// Resolve a ViewTarget to the actual git branch name.
///
/// Searches all translation branches (`re/*`) and returns the first one
/// whose DLL and function match the target, optionally checking the
/// attempt number.
pub(super) fn resolve_branch(
    git: &calxgloss_git::GitManager,
    target: &calxgloss_reports::dashboard::ViewTarget,
) -> Result<String> {
    let candidates = git.list_translation_branches()?;
    let target_dll = target.dll.clone();
    let target_func = target.function.clone();
    let target_attempt = target.specific_attempt;

    for branch in &candidates {
        // Must start with re/
        if !branch.starts_with("re/") {
            continue;
        }

        // Use the public matching function from reports
        if !calxgloss_reports::dashboard::branch_matches(
            branch,
            &target_dll,
            &target_func,
            target_attempt,
        ) {
            continue;
        }

        return Ok(branch.clone());
    }

    // Collect available branches for a helpful error message
    let available: Vec<String> = candidates
        .iter()
        .filter(|b| b.starts_with("re/") && b.contains(&target_dll) && b.contains(&target_func))
        .cloned()
        .collect();

    if available.is_empty() {
        let all_branches: String = candidates
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Available branches: {}",
            target_dll,
            target_func,
            all_branches
        )
    } else {
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Possible matches (check attempt number): {}",
            target_dll,
            target_func,
            available.join(", ")
        )
    }
}

/// Parse a git branch name back into (dll, function, attempt) components.
///
/// Accepts branches in the format `re/{dll}/{function}v{N}` or
/// `re/{dll_without_dot}/{function}v{N}`.
pub(super) fn parse_branch_for_accept(branch: &str) -> (String, String, u32) {
    // Strip re/ prefix
    let rest = branch.strip_prefix("re/").unwrap_or(branch);

    // Split into path and attempt suffix
    // e.g. "game_logic/DrawSpritev1" → path="game_logic/DrawSprite", attempt=1
    let (path, attempt) = if let Some(vpos) = rest.rfind('v') {
        let after_v = &rest[vpos + 1..];
        if after_v.chars().all(|c| c.is_ascii_digit()) && !after_v.is_empty() {
            (rest, after_v.parse().unwrap_or(1))
        } else {
            (rest, 1)
        }
    } else {
        (rest, 1)
    };

    // Split path into dll and function on first /
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    let dll = parts[0].to_string();
    let function = parts.get(1).map(|s| s.to_string()).unwrap_or_default();

    (dll, function, attempt)
}

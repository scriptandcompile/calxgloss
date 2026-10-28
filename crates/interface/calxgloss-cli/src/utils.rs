//! Utility functions for the CLI.

use anyhow::{Context, Result};
pub use calxgloss_reports::{
    print_batch_summary, print_classification_report, print_failure, print_git_status,
    print_verification_results,
};
pub use calxgloss_translator::RetryStrategy;
use std::path::{Path, PathBuf};
pub use tracing::{debug, warn};

/// Load the Kuna engine over `target_dir/<binary>` — the scan commands'
/// single entry into the analysis engine (issue #214). Kuna reads the file
/// in-process, so there is no server to connect to. When the target is
/// missing or unreadable, the error names the path it tried.
pub(super) fn load_kuna_source(
    settings: &crate::Settings,
    binary: &str,
) -> Result<calxgloss_kuna::KunaSource> {
    let target_dir = settings
        .target_dir
        .as_ref()
        .map(|r| PathBuf::from(&r.value))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"));
    load_kuna_at(settings, &target_dir.join(binary))
}

/// Load the Kuna engine at an explicit file path, honoring the `[analysis]`
/// per-function budgets from the settings (issue #211).
pub(super) fn load_kuna_at(
    settings: &crate::Settings,
    path: &Path,
) -> Result<calxgloss_kuna::KunaSource> {
    calxgloss_kuna::KunaSource::load_with_budget(path, None, settings.kuna_budget())
        .with_context(|| format!("Failed to load {} with the Kuna engine", path.display()))
}

/// Resolve the workspace: `--workspace` flag > settings > CWD.
///
/// This is the single point of resolution for commands that use the
/// config-file / env-var layer (`auto`, `translate`, `batch-translate`).
pub(super) fn resolve_workspace(
    cli_workspace: Option<&PathBuf>,
    settings: &crate::Settings,
) -> PathBuf {
    cli_workspace
        .cloned()
        .or_else(|| settings.workspace.as_ref().map(|r| PathBuf::from(&r.value)))
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Resolve the workspace for `live` and `serve`: `--workspace` flag > CWD.
///
/// These commands always operate on the workspace in the current directory
/// (where `.git`, `src/`, `scratch/` live).  Config file and env-var
/// overrides are ignored — only an explicit `--workspace` flag can change this.
pub(super) fn resolve_live_workspace(cli_workspace: Option<&PathBuf>) -> PathBuf {
    cli_workspace
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().expect("Failed to read current directory"))
}

/// Refuse to translate a .NET managed binary at the CLI seam (issue #235).
///
/// The pipeline translates native disassembly. A managed assembly's IL is
/// not in that disassembly, so translating one burns LLM tokens on a
/// program the analysis engine cannot meaningfully decompile. The refusal
/// follows the same precedence
/// as classification itself: the operator's override wins, then the
/// managed-PE fact (the COM descriptor data directory), then the persisted
/// classification record. A binary whose in-force decision parks it gets a
/// refusal naming the gap, the detected signal, and the override escape
/// hatch; anything else passes — including a file that cannot be read or
/// parsed, which the normal flow reports as its own error.
///
/// Call it at the command entry points, before the analysis engine loads
/// and before the LLM client is constructed, so a parked target starts
/// neither.
pub(super) fn guard_managed_binary(workspace: &Path, binary: &str, target: &Path) -> Result<()> {
    use calxgloss::DllCategory;

    // The operator's word outranks the PE fact (ADR 0003): an override
    // away from DotNetManaged makes the binary fully translatable again.
    let overrides = calxgloss::ClassificationOverrideControl::open(workspace);
    if let Some(o) = overrides.get(binary) {
        if o.category != DllCategory::DotNetManaged {
            return Ok(());
        }
        return Err(anyhow::anyhow!(parked_refusal(
            binary,
            "the classification override sets its category to DotNetManaged"
        )));
    }

    // The persisted record from a previous classify run.
    if recorded_category(workspace, binary).as_ref() == Some(&DllCategory::DotNetManaged) {
        return Err(anyhow::anyhow!(parked_refusal(
            binary,
            "its classification record says DotNetManaged"
        )));
    }

    // The PE fact itself — the same COM-descriptor check the classifier
    // performs, run here so a managed binary that was never classified is
    // refused before the analysis engine loads. It wins over a stale
    // name-heuristic record.
    if calxgloss_analysis::file_is_managed_pe(target) {
        return Err(anyhow::anyhow!(parked_refusal(
            binary,
            "the file carries a COM descriptor data directory — the marker every managed PE has"
        )));
    }

    Ok(())
}

/// The refusal text every parked-target guard gives: the gap, the detected
/// signal, and the way to override (issue #235, stories 18–20).
fn parked_refusal(binary: &str, signal: &str) -> String {
    format!(
        "{binary} is a .NET managed assembly ({signal}) — we do not yet decompile .NET \
         programs, so there is no native disassembly to translate. If this is a false \
         positive, set a classification override away from DotNetManaged (from the \
         dashboard's classification panel, or re/analysis/classification_overrides.json) \
         to make {binary} translatable again."
    )
}

/// The category persisted in a binary's classification record
/// (`re/classify/{sanitized}.json`), if the record exists and names one.
fn recorded_category(workspace: &Path, binary: &str) -> Option<calxgloss::DllCategory> {
    let sanitized: String = binary
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            other => other,
        })
        .collect();
    let path = workspace
        .join("re")
        .join("classify")
        .join(format!("{sanitized}.json"));
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .and_then(|record| {
            record
                .get("category")
                .and_then(|c| serde_json::from_value(c.clone()).ok())
        })
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

/// Map the CLI verbosity flag to the effective tracing level string.
/// Shared by `init_logging` and the serve/live commands so the server
/// status endpoint reports the level that is actually active.
pub(super) fn log_level_for_verbosity(verbosity: u8) -> &'static str {
    match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

/// Initialize tracing with the given verbosity level and format.
///
/// The `EnvFilter` is installed inside a `reload` layer so the web server's
/// `PATCH /api/server/log-level` endpoint can change verbosity while the
/// process runs. The returned handle controls that layer. `serve` and
/// `live` pass it into the server state.
pub(super) fn init_logging(
    verbosity: u8,
    format: &str,
) -> tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>
{
    let level = log_level_for_verbosity(verbosity);
    let (filter, handle) =
        tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new(level));

    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    match format {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        // Text (and anything unrecognized) gets the human-readable layer.
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_target(false))
                .init();
        }
    };

    debug!("Logging initialized: level={}, format={}", level, format);
    handle
}

// ============================================================
// Translation output helpers
// ============================================================

/// Derive a crate name from a DLL or EXE filename by stripping the extension.
pub fn derive_crate_name(binary: &str) -> String {
    binary.rsplit('.').next().unwrap_or(binary).to_string()
}

/// Set up the output crate directory structure for a translated DLL/EXE.
///
/// Creates `crates/<crate_name>/src/` and writes a `Cargo.toml` (only if it
/// doesn't already exist, so repeated calls are safe).
///
/// Returns `(crate_dir, src_dir)` for further file creation.
pub fn setup_translation_crate(workspace: &Path, binary: &str) -> Result<(PathBuf, PathBuf)> {
    let crate_name = derive_crate_name(binary);
    let crate_dir = workspace.join("crates").join(&crate_name);
    let crate_src_dir = crate_dir.join("src");

    std::fs::create_dir_all(&crate_src_dir).context("Failed to create crate src directory")?;

    let cargo_toml_path = crate_dir.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        let cargo_toml = format!(
            "[package]\nname = \"{crate_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            crate_name = crate_name,
        );
        std::fs::write(&cargo_toml_path, cargo_toml).context("Failed to write Cargo.toml")?;
        debug!(path = %cargo_toml_path.display(), "Created Cargo.toml");
    }

    Ok((crate_dir, crate_src_dir))
}

/// Write a single translated function to the crate's `src/` directory and
/// register it as a module in `mod.rs`.
///
/// The file is written as `src/<function>.rs`.  If `mod.rs` exists it is
/// updated with `pub mod <function>;` (duplicates are avoided).
pub fn write_translation_function(
    crate_src_dir: &Path,
    function: &str,
    rust_code: &str,
) -> Result<PathBuf> {
    let output_path = crate_src_dir.join(format!("{function}.rs"));
    std::fs::create_dir_all(output_path.parent().unwrap())
        .context("Failed to create output directory")?;
    std::fs::write(&output_path, rust_code).context("Failed to write translated function")?;
    debug!(path = %output_path.display(), "Wrote translated function");

    // Register the function as a module in mod.rs
    let mod_rs_path = crate_src_dir.join("mod.rs");
    let mod_contents = if mod_rs_path.exists() {
        std::fs::read_to_string(&mod_rs_path).unwrap_or_default()
    } else {
        String::new()
    };
    let module_decl = format!("pub mod {function};\n");
    if !mod_contents.contains(&module_decl) {
        let mut updated = mod_contents;
        updated.push_str(&module_decl);
        std::fs::write(&mod_rs_path, updated).ok();
    }

    Ok(output_path)
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

/// Whether `ch` occupies a terminal column. Control characters do not, and
/// neither do the printable parameter and final bytes of an ANSI escape.
/// Only the ESC that opens the sequence is a control character; if the
/// rest were counted as visible, a line that still fits would be cut.
fn visible_char(ch: char) -> bool {
    !ch.is_control() && ch != '\u{1b}'
}

/// The number of columns `s` occupies, skipping whole ANSI escape sequences.
fn visible_len(s: &str) -> usize {
    let mut count = 0usize;
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            // Skip a CSI sequence (ESC [ params… final byte @-~) whole; any
            // other escape is the single character after the ESC.
            if chars.peek().is_some_and(|next| *next == '[') {
                chars.next();
                for param in chars.by_ref() {
                    if ('@'..='~').contains(&param) {
                        break;
                    }
                }
            }
            continue;
        }
        if visible_char(ch) {
            count += 1;
        }
    }
    count
}

/// Prints a line of content, padded to SEP_WIDTH with spaces.
/// Safe for ANSI codes and multi-byte UTF-8.
pub(super) fn println_content(content: impl AsRef<str>) {
    let s = content.as_ref();
    // Count visible *characters*, not bytes. Otherwise a multi-byte
    // character like the ● bullet would push a short line into the
    // truncation branch, where the character-counting cut below never
    // reaches the byte-based limit and the whole line prints empty.
    let visible_chars = visible_len(s);
    let padded = if visible_chars < SEP_WIDTH {
        format!("{:<SEP_WIDTH$}", s)
    } else {
        // Cut at the SEP_WIDTH-th visible column, keeping the escape
        // sequences that surround it so the colours still close.
        let mut vcount = 0usize;
        let mut bend = s.len();
        let mut chars = s.char_indices().peekable();
        while let Some((bi, ch)) = chars.next() {
            if ch == '\u{1b}' {
                if chars.peek().is_some_and(|(_, next)| *next == '[') {
                    chars.next();
                    for (_, param) in chars.by_ref() {
                        if ('@'..='~').contains(&param) {
                            break;
                        }
                    }
                }
                continue;
            }
            if visible_char(ch) {
                vcount += 1;
            }
            if vcount >= SEP_WIDTH {
                bend = bi + ch.len_utf8();
                break;
            }
        }
        s[..bend].to_string()
    };
    println!("  {}", padded);
}

/// Prints a scan's own admission beside the counts it qualifies (issues
/// #346–#348). The shared type's line goes under the `Coverage:` label,
/// and prints only when there is something to admit.
///
/// A line that fits the report's column prints whole, byte-identical to
/// how it always printed. A line that does not fit breaks at its facet
/// boundaries instead of at the column — such a line comes from a scan
/// whose every facet fell short, like a region-limited constant scan.
/// The status word stays beside the label, and each falling-short facet's
/// limitation line gets its own continuation line. A reason is never cut
/// mid-word, and the report's box stays intact.
pub(super) fn print_coverage(coverage: Option<&calxgloss_types::ScanCoverage>) {
    let Some(coverage) = coverage else { return };
    let Some(admission) = coverage.admission() else {
        return;
    };
    const LABEL: &str = "Coverage:  ";
    if 2 + LABEL.len() + admission.chars().count() < SEP_WIDTH {
        println_content(format!("  {}{}", white_bold(LABEL), dim(&admission)));
        return;
    }
    // The break's continuation indent: the label's width, so the
    // limitation lines start under the status word, not under the box.
    let indent = " ".repeat(LABEL.len());
    println_content(format!(
        "  {}{}",
        white_bold(LABEL),
        dim(&coverage.status.to_string())
    ));
    for facet in coverage
        .facets
        .iter()
        .filter(|facet| facet.status != calxgloss_types::CoverageStatus::Complete)
    {
        if let Some(limitation) = &facet.limitation {
            println_content(format!("  {indent}{}", dim(limitation)));
        }
    }
}

/// The run report's seam admission lines (issue #355): one line per query
/// family the **opened seam itself** declared unavailable. Each line names
/// the family and the seam's own bounded reason. The report never falls
/// silent on an unavailable family and never invents an answer.
///
/// A family the seam declared answerable prints nothing. So does a family
/// the declaration never mentioned — that reads as unknown. Under an
/// all-answerable declaration there is no line at all, and the whole
/// report is byte-identical to before this line existed.
///
/// The lines print on the run path only. A capability is live session
/// state, and a `--show` re-render opens no seam to ask (ADR-0054).
pub(super) fn seam_admission_lines(report: &calxgloss_types::CapabilityReport) -> Vec<String> {
    report
        .families
        .iter()
        .filter_map(|entry| {
            entry
                .admission()
                .map(|admission| format!("{} — {admission}", entry.id))
        })
        .collect()
}

/// Print each seam admission line beside the scan report, under a `Seam:`
/// label column aligned with the coverage line's.
pub(super) fn print_seam_admissions(report: &calxgloss_types::CapabilityReport) {
    for line in seam_admission_lines(report) {
        println_content(format!("  {}{}", white_bold("Seam:      "), dim(&line)));
    }
}

// ============================================================
// Dashboard accept/send-back helpers
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
    let target_binary = target.binary.clone();
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
            target_binary.as_str(),
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
        .filter(|b| {
            b.starts_with("re/") && b.contains(target_binary.as_str()) && b.contains(&target_func)
        })
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
            target_binary,
            target_func,
            all_branches
        )
    } else {
        anyhow::bail!(
            "No translation branch found for '{}/{}'.\n\
             Possible matches (check attempt number): {}",
            target_binary,
            target_func,
            available.join(", ")
        )
    }
}

/// Parse a git branch name back into (binary, function, attempt) components.
///
/// Delegates to [`calxgloss_types::parse_branch_name`], the one owner of the
/// `re/{file}/{function}v{N}` grammar (issue #69). A name the grammar cannot
/// read yields empty components, which [`calxgloss_types::GitBranch::new`]
/// then rejects as an invalid branch name.
pub(super) fn parse_branch_for_accept(branch: &str) -> (String, String, u32) {
    match calxgloss_types::parse_branch_name(branch) {
        Some(parts) => (
            parts.binary.to_string(),
            parts.function.unwrap_or_default(),
            parts.attempt.unwrap_or(1),
        ),
        None => (String::new(), String::new(), 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE32+ image, byte-assembled — the same fixture shape the
    /// analyzer's classification tests use: `managed` carries the full
    /// COM-descriptor chain goblin walks (directory #14 → section → COR20
    /// header → `BSJB` metadata root); a native one leaves every data
    /// directory zero.
    fn fixture_pe(managed: bool) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let coff = 0x44;
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // one section
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // opt header size
        pe[coff + 18..coff + 20].copy_from_slice(&0x2002u16.to_le_bytes()); // DLL, executable
        let opt = coff + 20;
        pe[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
        pe[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
        pe[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
        pe[opt + 56..opt + 60].copy_from_slice(&0x1200u32.to_le_bytes()); // size of image
        pe[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        pe[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem: console
        pe[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // data directory count
        let sec = opt + 240;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 8..sec + 12].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        pe[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
        pe[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // raw data size
        pe[sec + 20..sec + 24].copy_from_slice(&0x300u32.to_le_bytes()); // raw data pointer
        pe[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // characteristics
        if managed {
            let dd14 = opt + 112 + 14 * 8;
            pe[dd14..dd14 + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // COM descriptor RVA
            pe[dd14 + 4..dd14 + 8].copy_from_slice(&0x48u32.to_le_bytes()); // and size
            pe[0x300..0x304].copy_from_slice(&0x48u32.to_le_bytes()); // COR20 header size
            pe[0x304..0x306].copy_from_slice(&2u16.to_le_bytes()); // major runtime version
            pe[0x306..0x308].copy_from_slice(&5u16.to_le_bytes()); // minor runtime version
            pe[0x308..0x30C].copy_from_slice(&0x1048u32.to_le_bytes()); // metadata RVA
            pe[0x30C..0x310].copy_from_slice(&0x40u32.to_le_bytes()); // metadata size
            pe[0x348..0x34C].copy_from_slice(b"BSJB");
            pe[0x34C..0x350].copy_from_slice(&1u32.to_le_bytes()); // major=1, minor=0
            pe[0x354..0x358].copy_from_slice(&4u32.to_le_bytes()); // version string length
            pe[0x358..0x35C].copy_from_slice(b"v4.0");
        }
        pe
    }

    /// A workspace with the fixture PEs laid down in a `target` dir.
    fn fixture_workspace(fixtures: &[(&str, bool)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp workspace");
        let target = dir.path().join("target");
        std::fs::create_dir_all(&target).expect("target dir");
        for (name, managed) in fixtures {
            std::fs::write(target.join(name), fixture_pe(*managed)).expect("write fixture PE");
        }
        dir
    }

    #[test]
    fn guard_refuses_managed_pe_naming_gap_signal_and_override() {
        // Stories 17–20: the refusal is a non-zero error whose message
        // states the gap, names the detected signal, and points at the
        // classification-override hatch.
        let dir = fixture_workspace(&[("managed_app.dll", true)]);
        let target = dir.path().join("target").join("managed_app.dll");

        let refusal = guard_managed_binary(dir.path(), "managed_app.dll", &target)
            .expect_err("a managed PE is refused");
        let message = refusal.to_string();
        assert!(
            message.contains("we do not yet decompile .NET programs"),
            "the message states the gap, got: {message}"
        );
        assert!(
            message.contains("COM descriptor"),
            "the message names the signal, got: {message}"
        );
        assert!(
            message.contains("classification override") && message.contains("DotNetManaged"),
            "the message points at the override hatch, got: {message}"
        );
    }

    #[test]
    fn guard_passes_native_pe_exactly_as_before() {
        // Story 24: native targets are untouched by the guard.
        let dir = fixture_workspace(&[("game_logic.dll", false)]);
        let target = dir.path().join("target").join("game_logic.dll");
        guard_managed_binary(dir.path(), "game_logic.dll", &target)
            .expect("a native PE passes the guard");
    }

    #[test]
    fn guard_override_away_from_managed_releases_the_binary() {
        // Stories 21–22: the escape hatch is real — an operator override
        // away from DotNetManaged makes the binary fully translatable.
        let dir = fixture_workspace(&[("managed_app.dll", true)]);
        let analysis = dir.path().join("re").join("analysis");
        std::fs::create_dir_all(&analysis).expect("analysis dir");
        std::fs::write(
            analysis.join("classification_overrides.json"),
            r#"{"overrides":{"managed_app.dll":{"category":"ProjectSpecific","crate_replacement":null,"known_runtime":false}}}"#,
        )
        .expect("write overrides");
        let target = dir.path().join("target").join("managed_app.dll");

        guard_managed_binary(dir.path(), "managed_app.dll", &target)
            .expect("an overridden-away binary passes the guard");
    }

    #[test]
    fn guard_honors_a_parked_classification_record() {
        // The record is the durable fact: a binary classified
        // DotNetManaged is refused even before the PE is consulted.
        let dir = fixture_workspace(&[("managed_app.dll", true)]);
        let classify = dir.path().join("re").join("classify");
        std::fs::create_dir_all(&classify).expect("classify dir");
        std::fs::write(
            classify.join("managed_app.dll.json"),
            r#"{"binary":"managed_app.dll","category":"DotNetManaged","strategy":"DoNotTranslate","known_runtime":false,"reason":"we do not yet decompile .NET programs"}"#,
        )
        .expect("write record");
        let target = dir.path().join("target").join("managed_app.dll");

        let refusal = guard_managed_binary(dir.path(), "managed_app.dll", &target)
            .expect_err("a parked record refuses");
        assert!(
            refusal.to_string().contains("classification record"),
            "the refusal names the record, got: {refusal}"
        );
    }

    #[test]
    fn guard_passes_unreadable_file_for_the_normal_flow_to_report() {
        // Story 26: the guard does not change what a corrupt or missing
        // file does — it passes, and the Kuna engine load surfaces the
        // error.
        let dir = fixture_workspace(&[]);
        let target = dir.path().join("target").join("broken.dll");
        guard_managed_binary(dir.path(), "broken.dll", &target)
            .expect("an unreadable file passes the guard");
    }
}

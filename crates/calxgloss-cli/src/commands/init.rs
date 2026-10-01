//! The `init` command — scaffold a configuration file.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::utils::{bold, green_bold, println_content};

const PROJECT_FILE: &str = "calxgloss.toml";
const EXAMPLE: &str = r#"# Calxgloss configuration
#
# This file controls the connection to GhidraMCP and the LLM.
# Override any value with a --flag or CALXGLOSS_* env var.

[ghidra]
url = "http://127.0.0.1:8080"
# api_key = "..."

[llm]
url = ""
model = ""
# api_key = "..."
# max_tokens = 8192
# temperature = 0.1
# max_retries = 3
# strategy = "compile_fix"
"#;

/// Handle the `init` subcommand: writes a `calxgloss.toml` template.
pub fn handle_init() -> Result<()> {
    let path = PathBuf::from(PROJECT_FILE);
    let config = EXAMPLE.to_string();
    std::fs::write(&path, &config)
        .with_context(|| format!("Failed to write configuration to {}", path.display()))?;
    println!(
        "  {} Created {}",
        green_bold("✓"),
        bold(&path.display().to_string())
    );
    println!();
    println_content("Edit this file with your GhidraMCP and LLM server addresses.");
    println_content("Then run `calxgloss auto` to start the pipeline.");
    println_content("");
    println_content("  ghidra.url → GhidraMCP server endpoint");
    println_content("  llm.url    → OpenAI-compatible LLM server");
    println_content("  llm.model  → model identifier the server reports");
    println!();
    Ok(())
}

/// Scans a directory for DLL and EXE files.
pub fn scan_targets(target_dir: &std::path::Path) -> Vec<String> {
    let mut exe_files = Vec::new();
    let mut dll_files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(target_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy().to_lowercase();
            if name.ends_with(".exe") {
                exe_files.push(file_name.to_string_lossy().to_string());
            } else if name.ends_with(".dll") {
                dll_files.push(file_name.to_string_lossy().to_string());
            }
        }
    }
    exe_files.sort();
    dll_files.sort();
    exe_files.extend(dll_files);
    exe_files
}

/// Check whether a classification record exists for the given file.
pub fn classification_record_exists(base_path: &std::path::Path, dll: &str) -> bool {
    let sanitized: String = dll
        .chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            other => other,
        })
        .collect();
    let record = base_path
        .join("re")
        .join("classify")
        .join(format!("{sanitized}.json"));
    record.is_file()
}

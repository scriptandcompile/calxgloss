//! Configuration file schema (TOML sections and types).

use serde::Deserialize;

/// The contents of a Calxgloss TOML configuration file.
///
/// Every field is optional so that a file can set as little or as much as it
/// likes; a missing key defers to the next source down rather than resetting the
/// value.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    /// Directory containing DLLs (read-only; binaries are read from here).
    pub target_dir: Option<String>,

    /// Where translation output is written (src/, re/, scratch, git repo).
    pub repo_dir: Option<String>,

    /// How to reach GhidraMCP.
    pub ghidra: GhidraSection,

    /// How to reach the OpenAI-compatible LLM server.
    pub llm: LlmSection,
}

/// The `[ghidra]` table.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GhidraSection {
    /// Base URL of the GhidraMCP server.
    pub url: Option<String>,

    /// Bearer token, for a server behind a proxy.
    pub api_key: Option<String>,
}

/// The `[llm]` table.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmSection {
    /// Base URL of an OpenAI-compatible server, including the `/v1` suffix.
    pub url: Option<String>,

    /// Model identifier, exactly as the server reports it.
    pub model: Option<String>,

    /// Bearer token. Rarely needed for a local server.
    pub api_key: Option<String>,

    /// Generation length limit.
    pub max_tokens: Option<usize>,

    /// Sampling temperature.
    pub temperature: Option<f32>,

    /// Attempts before a translation is abandoned.
    pub max_retries: Option<u32>,

    /// Retry strategy: compile_fix, test_fix, escalate, edge_case_fix, or auto.
    pub strategy: Option<String>,
}

/// A commented configuration file listing every recognised key.
///
/// Printed when a file fails to parse, so the fix does not require reading the
/// source to discover what is allowed.
pub const EXAMPLE: &str = r#"# Calxgloss configuration.
#
# Every key is optional. Command-line flags and environment variables
# (CALXGLOSS_GHIDRA_URL, CALXGLOSS_LLM_URL, CALXGLOSS_LLM_MODEL, ...) take
# precedence over this file.

# Directory containing DLLs and EXEs (required).
# target_dir = "/path/to/binaries"

# Where translation output goes: src/, re/, scratch, git repo (defaults to CWD).
# repo_dir = "/path/to/workspace"

[ghidra]
url = "http://127.0.0.1:8080"
# api_key = "..."

[llm]
url  = "http://127.0.0.1:1919/v1"
model = "Qwen3.6-35B-A3B-FP8"
# api_key = "..."
max_tokens = 8192
temperature = 0.1
max_retries = 3
# strategy = "auto"  # compile_fix | test_fix | escalate | edge_case_fix | auto
"#;

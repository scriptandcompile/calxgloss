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

    /// The workspace: where the translated Rust, `re/`, scratch, and the git
    /// repo live.
    pub workspace: Option<String>,

    /// How to reach the OpenAI-compatible LLM server.
    pub llm: LlmSection,

    /// The `[analysis]` table: per-function Kuna budgets.
    pub analysis: AnalysisSection,
}

/// The `[analysis]` table.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisSection {
    /// Per-function instruction budget for the Kuna engine — the control-flow
    /// walk stops after this many instructions and the function fails by name.
    /// Kuna's own default applies when unset; `0` means "no limit".
    pub max_fn_instructions: Option<u64>,

    /// Per-function wall-clock budget, in seconds, for the Kuna engine.
    /// Kuna's own default (no limit) applies when unset; `0` means "no limit".
    pub max_fn_seconds: Option<u64>,

    /// Per-function resident-memory budget, in MiB, for the Kuna engine.
    /// Kuna's own default (no limit) applies when unset; `0` means "no limit".
    pub max_fn_memory_mib: Option<u64>,
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

    /// Token budget for a single LLM request: prompt plus generated output
    /// together must fit inside this. The client derives each request's
    /// output limit from it, so it should match the server's context window.
    pub context_window: Option<usize>,

    /// Sampling temperature.
    pub temperature: Option<f32>,

    /// Attempts before a translation is abandoned.
    pub max_retries: Option<u32>,

    /// Per-request LLM timeout, in seconds. Covers the whole HTTP exchange,
    /// including the time the server spends generating the answer. The
    /// built-in default is 300 (5 minutes); raise it for slow local models
    /// on modest hardware.
    pub timeout_secs: Option<u64>,

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
# (CALXGLOSS_LLM_URL, CALXGLOSS_LLM_MODEL, ...) take precedence over this
# file. Kuna is the only analysis engine: a [ghidra] block or an
# analysis.engine key is refused by name — delete them.

# Directory containing DLLs and EXEs (required).
# target_dir = "/path/to/binaries"

# The workspace: where the translated Rust, re/, scratch, and the git repo live
# (defaults to CWD).
# workspace = "/path/to/workspace"

[analysis]
# Per-function budgets for the Kuna engine (0 = no limit, unset = engine default)
# max_fn_instructions = 100000
# max_fn_seconds = 0
# max_fn_memory_mib = 0

[llm]
url  = "http://127.0.0.1:1919/v1"
model = "Qwen3.6-35B-A3B-FP8"
# api_key = "..."
# Token budget for one request: prompt + output must fit inside it.
# Set to the server's context window.
context_window = 8192
temperature = 0.1
max_retries = 3
# Per-request timeout in seconds, covering the whole HTTP exchange
# including generation (default: 300, i.e. 5 minutes).
# timeout_secs = 300
# strategy = "auto"  # compile_fix | test_fix | escalate | edge_case_fix | auto
"#;

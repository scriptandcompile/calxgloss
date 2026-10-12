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

    /// Where the Ghidra install lives. Empty or absent means discover it:
    /// `$GHIDRA_INSTALL_DIR`, then this key, then a `*ghidra_*_PUBLIC` glob
    /// in the home directory (highest version wins).
    pub install_dir: Option<String>,

    /// Whether calxgloss may start a headless Ghidra server when none is
    /// running. `false` makes the preflight check-only: it fails fast naming
    /// what is missing instead of spawning anything.
    pub auto_start: Option<bool>,

    /// GUI-vs-headless preference: `auto` attaches to a running server or
    /// spawns a headless one, `always` spawns headless even when a GUI is
    /// open, `never` only ever attaches (no spawn).
    pub headless: Option<String>,

    /// The Ghidra project (`.gpr`) a run uses, overriding the default
    /// `<workspace>/ghidra/<target>.gpr`.
    pub project: Option<String>,

    /// The minimum acceptable Ghidra install version, e.g. `12.1`. A
    /// discovered install below it fails the install check by name.
    pub min_version: Option<String>,

    /// How long a spawned headless server may take to boot, in seconds.
    pub start_timeout_secs: Option<u64>,

    /// Whether `doctor --fix` may download a Ghidra + GhidraMCP pair without
    /// the explicit `--install-ghidra` flag. `false` (the default) keeps the
    /// ~570 MB download behind consent.
    pub auto_install: Option<bool>,

    /// Pin the Ghidra version the bootstrap fetches, overriding the build the
    /// plugin's `extension.properties` names.
    pub pin_version: Option<String>,

    /// The JDK the bootstrap's Java gate runs (`<java_home>/bin/java`).
    /// Absent means `java` on PATH; calxgloss never installs a JDK itself.
    pub java_home: Option<String>,
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

# The workspace: where the translated Rust, re/, scratch, and the git repo live
# (defaults to CWD).
# workspace = "/path/to/workspace"

[ghidra]
url = "http://127.0.0.1:8080"
# api_key = "..."
# install_dir = "/path/to/ghidra_12.1.2_PUBLIC"  # empty → discover
# auto_start = true            # false → preflight checks only, never spawns
# headless = "auto"            # auto | always | never
# project = "/path/to/run.gpr" # default: <workspace>/ghidra/<target>.gpr
# min_version = "12.1"         # gate the discovered install by version
# start_timeout_secs = 90      # boot budget for a spawned server
# auto_install = false         # doctor --fix may download without --install-ghidra
# pin_version = "12.1.2"       # pin the Ghidra build the bootstrap fetches
# java_home = "/usr/lib/jvm/java-21"  # JDK for the bootstrap's Java gate

[llm]
url  = "http://127.0.0.1:1919/v1"
model = "Qwen3.6-35B-A3B-FP8"
# api_key = "..."
# Token budget for one request: prompt + output must fit inside it.
# Set to the server's context window.
context_window = 8192
temperature = 0.1
max_retries = 3
# strategy = "auto"  # compile_fix | test_fix | escalate | edge_case_fix | auto
"#;

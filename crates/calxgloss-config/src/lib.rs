//! Layered configuration for Calxgloss.
//!
//! Three sources supply every setting, most specific first:
//!
//! 1. a command-line flag,
//! 2. an environment variable,
//! 3. a TOML configuration file,
//! 4. a built-in default.
//!
//! Flags win so a one-off run can always override a saved setting, and the file
//! wins over defaults so a machine only has to be described once.
//!
//! # The file
//!
//! ```toml
//! [ghidra]
//! url = "http://127.0.0.1:8080"
//!
//! [llm]
//! url  = "http://127.0.0.1:1919/v1"
//! model = "Qwen3.6-35B-A3B-FP8"
//! ```
//!
//! Every key is optional and every section may be omitted, so a file that sets
//! only the LLM model is valid. Unknown keys are **rejected** rather than
//! ignored: a mistyped `modle = ` that was silently dropped would surface much
//! later as a confusing model-not-found error from the server.
//!
//! # Where the file is looked for
//!
//! In order, stopping at the first that exists:
//!
//! 1. the path given to `--config`,
//! 2. `./calxgloss.toml` for per-project settings,
//! 3. `$XDG_CONFIG_HOME/calxgloss/config.toml`, or `~/.config/calxgloss/config.toml`.
//!
//! A file named explicitly with `--config` must exist. The others are optional,
//! because not every setup has one.

/// Built-in default values.
pub mod defaults {
    /// The default GhidraMCP URL: a fixed loopback address on port 8080
    /// rather than `localhost`.
    ///
    /// The address is spelled out because `localhost` can resolve to `::1`
    /// first, and the bridge binds IPv4, which turns a correct URL into a
    /// connection refusal.
    ///
    /// Note that the GhidraMCP 6.x bridge listens on **8080** by default, so
    /// against a stock 6.x setup this default must be overridden with
    /// `ghidra.url` in the config file or `CALXGLOSS_GHIDRA_URL`.
    pub const GHIDRA_URL: &str = "http://127.0.0.1:8080";

    /// Generation length for translations.
    pub const LLM_MAX_TOKENS: usize = 8192;

    /// Sampling temperature. Low, because a translation is a mechanical
    /// transformation rather than a creative one.
    pub const LLM_TEMPERATURE: f32 = 0.1;

    /// Attempts before a translation is abandoned.
    pub const LLM_MAX_RETRIES: u32 = 3;
}

mod error;
mod layers;
mod loader;
mod schema;

pub use error::ConfigError;
pub use layers::{Layers, Resolved, Source};
pub use loader::{LoadedConfig, PROJECT_FILE, load};
pub use schema::{EXAMPLE, FileConfig, GhidraSection, LlmSection};

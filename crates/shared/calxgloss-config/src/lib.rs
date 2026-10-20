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
    /// Generation length for translations.
    pub const LLM_CONTEXT_WINDOW: usize = 8192;

    /// Sampling temperature. Low, because a translation is a mechanical
    /// transformation rather than a creative one.
    pub const LLM_TEMPERATURE: f32 = 0.1;

    /// Attempts before a translation is abandoned.
    pub const LLM_MAX_RETRIES: u32 = 3;

    /// Per-request LLM HTTP timeout, in seconds. Five minutes: the wait
    /// covers the server generating the answer, and a large local model on
    /// slow hardware can take minutes for one completion.
    pub const LLM_TIMEOUT_SECS: u64 = 300;
}

mod error;
mod layers;
mod loader;
mod schema;

pub use error::ConfigError;
pub use layers::{Layers, Resolved, Source};
pub use loader::{LoadedConfig, PROJECT_FILE, load};
pub use schema::{AnalysisSection, EXAMPLE, FileConfig, LlmSection};

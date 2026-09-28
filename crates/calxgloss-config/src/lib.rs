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

use std::path::{Path, PathBuf};

use serde::Deserialize;
use tracing::debug;

/// Values used when no flag, environment variable, or file supplies one.
pub mod defaults {
    /// GhidraMCP's own default port, and a fixed loopback address rather than
    /// `localhost`.
    ///
    /// The address is spelled out because `localhost` can resolve to `::1`
    /// first, and GhidraMCP binds IPv4, which turns a correct URL into a
    /// connection refusal.
    pub const GHIDRA_URL: &str = "http://127.0.0.1:8080";

    /// Generation length for translations.
    pub const LLM_MAX_TOKENS: usize = 8192;

    /// Sampling temperature. Low, because a translation is a mechanical
    /// transformation rather than a creative one.
    pub const LLM_TEMPERATURE: f32 = 0.1;

    /// Attempts before a translation is abandoned.
    pub const LLM_MAX_RETRIES: u32 = 3;
}

// ============================================================
// Errors
// ============================================================

/// Errors from locating, reading, or parsing configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A file named with `--config` does not exist.
    #[error("--config was given {path}, but that file does not exist")]
    MissingExplicitFile { path: PathBuf },

    /// A candidate file could not be read.
    #[error("Could not read the config file at {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A candidate file is not valid TOML, or does not match the schema.
    #[error(
        "The config file at {path} is not valid:\n{problem}\n\nA minimal file is:\n\n{expected}"
    )]
    Invalid {
        path: PathBuf,
        /// The parser's own explanation, including a line and column.
        problem: String,
        /// A commented example showing every recognised key.
        expected: &'static str,
    },
}

// ============================================================
// File schema
// ============================================================

/// The contents of a Calxgloss TOML configuration file.
///
/// Every field is optional so that a file can set as little or as much as it
/// likes; a missing key defers to the next source down rather than resetting the
/// value.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
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

// ============================================================
// Discovery
// ============================================================

/// A loaded configuration file, and where it was found.
#[derive(Debug, Clone, Default)]
pub struct LoadedConfig {
    /// The file's contents, empty when no file was found.
    pub file: FileConfig,
    /// The path it was read from, or `None` when no file was found.
    pub path: Option<PathBuf>,
    /// Every path that was checked, whether or not it existed.
    ///
    /// Kept so a `--verbose` run can show why a file was not picked up.
    pub searched: Vec<PathBuf>,
}

impl LoadedConfig {
    /// Whether a file contributed anything.
    pub fn is_empty(&self) -> bool {
        self.path.is_none()
    }
}

/// The default name of a per-project configuration file.
pub const PROJECT_FILE: &str = "calxgloss.toml";

/// Load configuration, honouring an explicitly named file first.
///
/// `explicit` comes from `--config`. When given, the file must exist: naming a
/// file that is not there is a mistake worth reporting rather than a hint to
/// fall back on.
pub fn load(explicit: Option<&Path>) -> Result<LoadedConfig, ConfigError> {
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(ConfigError::MissingExplicitFile {
                path: path.to_path_buf(),
            });
        }
        let file = read(path)?;
        return Ok(LoadedConfig {
            file,
            path: Some(path.to_path_buf()),
            searched: vec![path.to_path_buf()],
        });
    }

    let candidates = candidate_paths();
    let mut searched = Vec::with_capacity(candidates.len());
    for path in candidates {
        searched.push(path.clone());
        if !path.is_file() {
            debug!(?path, "No config file there");
            continue;
        }
        let file = read(&path)?;
        return Ok(LoadedConfig {
            file,
            path: Some(path),
            searched,
        });
    }

    Ok(LoadedConfig {
        file: FileConfig::default(),
        path: None,
        searched,
    })
}

/// Every place a configuration file is looked for, most specific first.
fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(PROJECT_FILE)];
    if let Some(user) = user_config_path() {
        paths.push(user);
    }
    paths
}

/// The per-user configuration path, following the XDG base directory spec.
///
/// Read from the environment rather than through a directory-lookup crate: the
/// spec is two variables, and a dependency that resolves them would also need
/// trusting to pick the same platform conventions.
fn user_config_path() -> Option<PathBuf> {
    // XDG_CONFIG_HOME is absolute by definition; a relative value is malformed
    // and the spec says to ignore it.
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME")
        && !dir.is_empty()
    {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Some(dir.join("calxgloss").join("config.toml"));
        }
        debug!("Ignoring a relative XDG_CONFIG_HOME");
    }

    let home = std::env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("calxgloss")
            .join("config.toml"),
    )
}

/// Read and validate one configuration file.
fn read(path: &Path) -> Result<FileConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;

    toml::from_str(&text).map_err(|e| ConfigError::Invalid {
        path: path.to_path_buf(),
        problem: e.to_string(),
        expected: EXAMPLE,
    })
}

// ============================================================
// Resolution
// ============================================================

/// Which layer a resolved value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A command-line flag.
    Flag,
    /// An environment variable.
    Env,
    /// The configuration file.
    File,
    /// A built-in default.
    Default,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Source::Flag => "flag",
            Source::Env => "environment",
            Source::File => "config file",
            Source::Default => "default",
        };
        f.write_str(name)
    }
}

/// A value together with the layer that supplied it.
///
/// Carrying the source alongside the value is what makes a three-layer
/// configuration debuggable: a surprising value can be attributed to the layer
/// that actually chose it, rather than guessed at.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved<T> {
    /// The value in force.
    pub value: T,
    /// Where it came from.
    pub source: Source,
}

/// The layers a setting can be supplied by, most specific first.
#[derive(Debug, Clone, Default)]
pub struct Layers {
    /// Values from command-line flags.
    pub flags: FileConfig,
    /// Values from environment variables.
    pub env: FileConfig,
    /// Values from the configuration file.
    pub file: FileConfig,
}

impl Layers {
    /// Read the environment into a layer.
    ///
    /// The variables are `CALXGLOSS_` plus the section and key, so
    /// `CALXGLOSS_LLM_URL` sets `[llm] url`. A variable that is set but empty is
    /// treated as absent: an empty `CALXGLOSS_LLM_URL=` in a shell profile
    /// should not blank out a working configuration.
    pub fn from_env() -> Self {
        Self {
            flags: FileConfig::default(),
            env: FileConfig {
                ghidra: GhidraSection {
                    url: var("CALXGLOSS_GHIDRA_URL"),
                    api_key: var("CALXGLOSS_GHIDRA_API_KEY"),
                },
                llm: LlmSection {
                    url: var("CALXGLOSS_LLM_URL"),
                    model: var("CALXGLOSS_LLM_MODEL"),
                    api_key: var("CALXGLOSS_LLM_API_KEY"),
                    max_tokens: usize_var("CALXGLOSS_LLM_MAX_TOKENS"),
                    temperature: f32_var("CALXGLOSS_LLM_TEMPERATURE"),
                    max_retries: u32_var("CALXGLOSS_LLM_MAX_RETRIES"),
                    strategy: var("CALXGLOSS_LLM_STRATEGY"),
                },
            },
            file: FileConfig::default(),
        }
    }

    /// Resolve one setting across every layer.
    ///
    /// `default` applies only when no layer has a value. `None` comes back when
    /// no layer *and* no default supply one, which is the case the caller turns
    /// into a message naming the ways to provide it. A setting cannot be
    /// invented at that point, so the absence is reported rather than papered
    /// over with a placeholder.
    pub fn resolve<T>(
        &self,
        flag: Option<T>,
        env: Option<T>,
        file: Option<T>,
        default: Option<T>,
    ) -> Option<Resolved<T>> {
        [
            (flag, Source::Flag),
            (env, Source::Env),
            (file, Source::File),
            (default, Source::Default),
        ]
        .into_iter()
        .find_map(|(value, source)| value.map(|value| Resolved { value, source }))
    }
}

/// Read an environment variable, treating an empty value as absent.
fn var(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// Read a numeric environment variable, ignoring one that does not parse.
///
/// A malformed value is skipped rather than fatal, so a typo in a shell profile
/// degrades to the next layer instead of breaking every command.
macro_rules! numeric_var {
    ($name:expr, $ty:ty) => {
        var($name).and_then(|v| match v.trim().parse::<$ty>() {
            Ok(n) => Some(n),
            Err(_) => {
                debug!(variable = $name, value = %v, "Ignoring unparseable environment variable");
                None
            }
        })
    };
}

fn usize_var(name: &str) -> Option<usize> {
    numeric_var!(name, usize)
}

fn u32_var(name: &str) -> Option<u32> {
    numeric_var!(name, u32)
}

fn f32_var(name: &str) -> Option<f32> {
    numeric_var!(name, f32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Saves and restores environment variables on drop.
    ///
    /// This is the correct way to temporarily change `HOME`, `XDG_CONFIG_HOME`,
    /// or other process-wide variables from a test: the guard's `Drop` impl
    /// always restores the original state even if the test panics, and the
    /// guard holds the previous values so they are never lost.
    struct EnvGuard {
        vars: Vec<(&'static str, Option<String>)>,
        cwd: PathBuf,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self {
                vars: Vec::new(),
                cwd: std::env::current_dir().unwrap_or_default(),
            }
        }

        /// Set `var` to `value`, removing it if `value` is `None`.
        fn set(&mut self, var: &'static str, value: Option<String>) {
            let previous = std::env::var(var).ok();
            match &value {
                Some(v) => unsafe { std::env::set_var(var, v) },
                None => unsafe { std::env::remove_var(var) },
            }
            self.vars.push((var, previous));
        }

        /// Change the current directory and record the old one for restoration.
        fn chdir(&mut self, path: &Path) {
            self.cwd = std::env::current_dir().unwrap_or_default();
            std::env::set_current_dir(path).unwrap();
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // Restore variables in reverse order.
            for (var, prev) in self.vars.iter().rev() {
                match prev {
                    Some(v) => unsafe { std::env::set_var(var, v) },
                    None => unsafe { std::env::remove_var(var) },
                }
            }
            // Restore the working directory.
            let _ = std::env::set_current_dir(&self.cwd);
        }
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write config");
        path
    }

    #[test]
    fn test_an_empty_file_is_all_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "");
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.file, FileConfig::default());
    }

    #[test]
    fn test_reads_both_sections() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "c.toml",
            r#"
[ghidra]
url = "http://10.0.0.5:8080"

[llm]
url = "http://10.0.0.6:1919/v1"
model = "some-model"
max_tokens = 4096
temperature = 0.7
max_retries = 5
"#,
        );
        let c = load(Some(&path)).unwrap().file;
        assert_eq!(c.ghidra.url.as_deref(), Some("http://10.0.0.5:8080"));
        assert_eq!(c.llm.url.as_deref(), Some("http://10.0.0.6:1919/v1"));
        assert_eq!(c.llm.model.as_deref(), Some("some-model"));
        assert_eq!(c.llm.max_tokens, Some(4096));
        assert_eq!(c.llm.temperature, Some(0.7));
        assert_eq!(c.llm.max_retries, Some(5));
    }

    #[test]
    fn test_a_partial_file_leaves_the_rest_unset() {
        // A file that sets only the model must not blank the URL, which is what
        // treating missing keys as empty strings would do.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[llm]\nmodel = \"m\"\n");
        let c = load(Some(&path)).unwrap().file;
        assert_eq!(c.llm.model.as_deref(), Some("m"));
        assert_eq!(c.llm.url, None);
        assert_eq!(c.ghidra.url, None);
    }

    #[test]
    fn test_a_typo_is_rejected_rather_than_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[llm]\nmodle = \"m\"\n");
        let err = load(Some(&path)).unwrap_err();
        let ConfigError::Invalid {
            problem, expected, ..
        } = err
        else {
            panic!("expected an invalid-config error, got {err:?}");
        };
        assert!(
            problem.contains("modle"),
            "problem should name the key: {problem}"
        );
        // The message has to show what *is* allowed, or fixing it needs the source.
        assert!(expected.contains("model"));
    }

    #[test]
    fn test_an_unknown_section_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[nope]\nx = 1\n");
        assert!(matches!(
            load(Some(&path)),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn test_a_wrongly_typed_value_is_rejected() {
        // A quoted max_tokens is a string, not a number, and silently coercing
        // it would hide the mistake.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[llm]\nmax_tokens = \"lots\"\n");
        assert!(matches!(
            load(Some(&path)),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn test_malformed_toml_reports_the_location() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[llm\nurl = \"x\"\n");
        let err = load(Some(&path)).unwrap_err();
        let ConfigError::Invalid { problem, .. } = err else {
            panic!("expected invalid");
        };
        // The parser's span information is what makes the message actionable.
        assert!(
            problem.contains("line") || problem.contains('|'),
            "problem should locate the error: {problem}"
        );
    }

    #[test]
    fn test_an_explicitly_named_missing_file_is_an_error() {
        // Silently falling back would mean the flag appeared to do nothing.
        let err = load(Some(Path::new("/nonexistent/calxgloss.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::MissingExplicitFile { .. }));
    }

    #[test]
    #[serial_test::serial]
    fn test_a_missing_optional_file_is_not_an_error() {
        // A project-local file that does not exist is the normal case on a fresh
        // checkout, so falling through to the user-global path must succeed
        // rather than fail.
        let dir = tempfile::tempdir().unwrap();
        let mut guard = EnvGuard::new();
        guard.set("XDG_CONFIG_HOME", None);
        guard.set("HOME", Some(dir.path().to_string_lossy().into_owned()));
        guard.chdir(dir.path());
        let loaded = load(None);
        // Guard drops and restores HOME / XDG_CONFIG_HOME / cwd here.
        drop(guard);

        let loaded = loaded.expect("a missing optional file must not be an error");
        assert!(loaded.is_empty());
        assert_eq!(loaded.path, None);
        // The search still records what it looked at, for diagnostics.
        assert!(
            loaded.searched.iter().any(|p| p.ends_with(PROJECT_FILE)),
            "searched: {:?}",
            loaded.searched
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_a_found_file_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        // Temporarily neutralize user-global config paths so no user config
        // overrides the project-level value being tested.
        let mut guard = EnvGuard::new();
        guard.set("XDG_CONFIG_HOME", None);
        guard.set("HOME", Some(dir.path().to_string_lossy().into_owned()));
        guard.set("CALXGLOSS_LLM_MODEL", None);
        guard.chdir(dir.path());
        std::fs::write(PROJECT_FILE, "[llm]\nmodel = \"from-project\"\n").unwrap();
        let loaded = load(None);
        // Guard drops and restores env here.
        drop(guard);

        let loaded = loaded.unwrap();
        assert_eq!(loaded.file.llm.model.as_deref(), Some("from-project"));
        assert!(loaded.path.as_ref().unwrap().ends_with(PROJECT_FILE));
    }

    #[test]
    fn test_precedence_is_flag_then_env_then_file_then_default() {
        let layers = Layers {
            flags: FileConfig {
                llm: LlmSection {
                    model: Some("from-flag".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            env: FileConfig {
                llm: LlmSection {
                    model: Some("from-env".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
            file: FileConfig {
                llm: LlmSection {
                    model: Some("from-file".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let all = Some("x".to_string());
        let r = layers
            .resolve(
                layers.flags.llm.model.clone(),
                layers.env.llm.model.clone(),
                layers.file.llm.model.clone(),
                all.clone(),
            )
            .unwrap();
        assert_eq!(r.value, "from-flag");
        assert_eq!(r.source, Source::Flag);

        let r = layers
            .resolve(
                None,
                layers.env.llm.model.clone(),
                layers.file.llm.model.clone(),
                all.clone(),
            )
            .unwrap();
        assert_eq!(r.value, "from-env");
        assert_eq!(r.source, Source::Env);

        let r = layers
            .resolve(None, None, layers.file.llm.model.clone(), all.clone())
            .unwrap();
        assert_eq!(r.value, "from-file");
        assert_eq!(r.source, Source::File);

        let r = layers.resolve(None, None, None, all.clone()).unwrap();
        assert_eq!(r.value, "x");
        assert_eq!(r.source, Source::Default);
    }

    #[test]
    fn test_a_setting_with_no_source_is_absent() {
        // There is no sensible default LLM endpoint, so this is the case the
        // caller has to turn into a helpful message.
        let layers = Layers::default();
        assert_eq!(layers.resolve::<String>(None, None, None, None), None);
    }

    #[test]
    fn test_source_names_are_readable() {
        assert_eq!(Source::File.to_string(), "config file");
        assert_eq!(Source::Default.to_string(), "default");
    }

    #[test]
    fn test_the_example_parses() {
        // The example is printed to users on a parse error, so it has to be
        // valid itself.
        let parsed: FileConfig = toml::from_str(EXAMPLE).expect("EXAMPLE must parse");
        assert_eq!(parsed.llm.model.as_deref(), Some("Qwen3.6-35B-A3B-FP8"));
        assert_eq!(parsed.ghidra.url.as_deref(), Some("http://127.0.0.1:8080"));
    }
}

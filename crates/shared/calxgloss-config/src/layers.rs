//! Layered configuration resolution (flag → env → file → default).

use tracing::debug;

use crate::schema::{AnalysisSection, FileConfig, LlmSection};

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
                target_dir: var("CALXGLOSS_TARGET_DIR"),
                workspace: var("CALXGLOSS_WORKSPACE"),
                llm: LlmSection {
                    url: var("CALXGLOSS_LLM_URL"),
                    model: var("CALXGLOSS_LLM_MODEL"),
                    api_key: var("CALXGLOSS_LLM_API_KEY"),
                    context_window: usize_var("CALXGLOSS_LLM_CONTEXT_WINDOW"),
                    temperature: f32_var("CALXGLOSS_LLM_TEMPERATURE"),
                    max_retries: u32_var("CALXGLOSS_LLM_MAX_RETRIES"),
                    strategy: var("CALXGLOSS_LLM_STRATEGY"),
                },
                analysis: AnalysisSection {
                    // Budgets are file-only: they belong in the config file,
                    // not the environment.
                    max_fn_instructions: None,
                    max_fn_seconds: None,
                    max_fn_memory_mib: None,
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
    use crate::{ConfigError, EXAMPLE, FileConfig, Layers, LlmSection, PROJECT_FILE, load};
    use std::path::{Path, PathBuf};

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
        assert_eq!(loaded.file, Default::default());
    }

    #[test]
    fn test_reads_the_llm_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "c.toml",
            r#"
[llm]
url = "http://10.0.0.6:1919/v1"
model = "some-model"
context_window = 4096
temperature = 0.7
max_retries = 5
"#,
        );
        let c = load(Some(&path)).unwrap().file;
        assert_eq!(c.llm.url.as_deref(), Some("http://10.0.0.6:1919/v1"));
        assert_eq!(c.llm.model.as_deref(), Some("some-model"));
        assert_eq!(c.llm.context_window, Some(4096));
        assert_eq!(c.llm.temperature, Some(0.7));
        assert_eq!(c.llm.max_retries, Some(5));
    }

    #[test]
    fn test_a_stale_ghidra_section_is_refused_by_name() {
        // Issue #214: Kuna is the only analysis engine. A leftover [ghidra]
        // block is an unknown section — the parse error names it, and the
        // printed example shows the file that replaces it.
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "c.toml",
            r#"
[ghidra]
url = "http://10.0.0.5:8080"
install_dir = "/opt/ghidra_12.1.2_PUBLIC"
"#,
        );
        let err = load(Some(&path)).unwrap_err();
        let ConfigError::Invalid {
            problem, expected, ..
        } = err
        else {
            panic!("expected an invalid-config error, got {err:?}");
        };
        assert!(
            problem.contains("ghidra"),
            "problem should name the stale section: {problem}"
        );
        assert!(
            expected.contains("[llm]"),
            "the example should show the valid file"
        );
    }

    #[test]
    fn test_a_stale_ghidra_key_is_refused_by_name() {
        // A near-miss like `autostart` inside a stale block is also refused,
        // naming the offending key.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[ghidra]\nautostart = false\n");
        assert!(matches!(
            load(Some(&path)),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_the_ghidra_env_vars_are_no_longer_read() {
        // Issue #214: the CALXGLOSS_GHIDRA_* variables are gone; setting one
        // changes nothing.
        let mut guard = EnvGuard::new();
        guard.set("CALXGLOSS_GHIDRA_URL", Some("http://10.0.0.5:8080".into()));
        guard.set("CALXGLOSS_GHIDRA_AUTO_START", Some("false".into()));
        let layers = Layers::from_env();
        // Guard drops and restores the env here.
        drop(guard);

        assert_eq!(layers.env, FileConfig::default());
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
    fn test_a_stale_analysis_engine_key_is_refused_by_name() {
        // Issue #214: the engine is no longer a choice; a leftover
        // `engine = ` line is an unknown key, refused by name.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[analysis]\nengine = \"kuna\"\n");
        let err = load(Some(&path)).unwrap_err();
        let ConfigError::Invalid {
            problem, expected, ..
        } = err
        else {
            panic!("expected an invalid-config error, got {err:?}");
        };
        assert!(
            problem.contains("engine"),
            "problem should name the stale key: {problem}"
        );
        assert!(
            expected.contains("[analysis]"),
            "the example should show the valid file"
        );
    }

    #[test]
    fn test_the_decompile_budget_keys_come_from_the_file_layer() {
        // Issue #211: the per-function budgets ride with the engine choice.
        let dir = tempfile::tempdir().unwrap();
        let toml = "[analysis]\nmax_fn_instructions = 5000\nmax_fn_seconds = 30\nmax_fn_memory_mib = 512\n";
        let path = write(dir.path(), "c.toml", toml);
        let c = load(Some(&path)).unwrap().file;
        assert_eq!(c.analysis.max_fn_instructions, Some(5000));
        assert_eq!(c.analysis.max_fn_seconds, Some(30));
        assert_eq!(c.analysis.max_fn_memory_mib, Some(512));
    }

    #[test]
    fn test_a_wrongly_typed_decompile_budget_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "c.toml",
            "[analysis]\nmax_fn_seconds = \"30\"\n",
        );
        assert!(matches!(
            load(Some(&path)),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn test_an_unknown_analysis_key_is_rejected() {
        // The new section must not loosen the deny list: `engien` is a
        // misconfiguration, not something to ignore.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[analysis]\nengien = \"kuna\"\n");
        assert!(matches!(
            load(Some(&path)),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    #[serial_test::serial]
    fn test_the_analysis_engine_env_var_is_no_longer_read() {
        // Issue #214: CALXGLOSS_ANALYSIS_ENGINE is gone; setting it changes
        // nothing.
        let mut guard = EnvGuard::new();
        guard.set("CALXGLOSS_ANALYSIS_ENGINE", Some("kuna".into()));
        let layers = Layers::from_env();
        // Guard drops and restores the env here.
        drop(guard);
        assert_eq!(layers.env, FileConfig::default());
    }

    #[test]
    fn test_a_wrongly_typed_value_is_rejected() {
        // A quoted context_window is a string, not a number, and silently coercing
        // it would hide the mistake.
        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), "c.toml", "[llm]\ncontext_window = \"lots\"\n");
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
        use EXAMPLE;
        let parsed: FileConfig = toml::from_str(EXAMPLE).expect("EXAMPLE must parse");
        assert_eq!(parsed.llm.model.as_deref(), Some("Qwen3.6-35B-A3B-FP8"));
    }
}

//! Turning layered configuration into the values the commands actually use.
//!
//! The command line has to answer one question that no single layer can: *if the
//! user did not pass a flag, where did this value come from?* Every setting
//! resolved here keeps its [`Source`], so `calxgloss config` can show that
//! rather than leaving it to guesswork.

use std::path::PathBuf;

use anyhow::{Result, bail};
use calxgloss_config::{
    EXAMPLE, FileConfig, GhidraSection, Layers, LlmSection, LoadedConfig, Resolved, defaults,
};

/// Every setting the commands need, after layering.
///
/// The Ghidra URL is always present: GhidraMCP has a well-known default port, so
/// a sensible value exists and guessing it beats refusing to run. The LLM URL and
/// model are genuinely optional here, because a local inference server has no
/// conventional address — they are demanded by [`require`] at the point of use
/// and reported with instructions when absent.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Where to reach GhidraMCP.
    pub ghidra_url: Resolved<String>,
    /// Bearer token for GhidraMCP, when one is required.
    pub ghidra_api_key: Option<Resolved<String>>,
    /// Where the Ghidra install lives, when configured; absent means discover.
    pub ghidra_install_dir: Option<Resolved<String>>,
    /// Whether calxgloss may start a headless Ghidra server (G1-T7).
    pub ghidra_auto_start: Resolved<bool>,
    /// The GUI-vs-headless preference: `auto`, `always`, or `never`.
    pub ghidra_headless: Resolved<String>,
    /// The `.gpr` project override, when configured; absent means the default.
    pub ghidra_project: Option<Resolved<String>>,
    /// The minimum acceptable Ghidra install version, when configured.
    pub ghidra_min_version: Option<Resolved<String>>,
    /// Boot budget for a spawned headless server, in seconds.
    pub ghidra_start_timeout_secs: Resolved<u64>,
    /// Whether `doctor --fix` may download without `--install-ghidra` (G1-T8).
    pub ghidra_auto_install: Resolved<bool>,
    /// The Ghidra version pinned for the bootstrap, when configured.
    pub ghidra_pin_version: Option<Resolved<String>>,
    /// The JDK home the bootstrap's Java gate runs, when configured.
    pub ghidra_java_home: Option<Resolved<String>>,
    /// Where to reach the LLM server, if configured.
    pub llm_url: Option<Resolved<String>>,
    /// Which model to ask for, if configured.
    pub llm_model: Option<Resolved<String>>,
    /// Bearer token for the LLM server.
    ///
    /// Kept as a [`Resolved`] even though the value is never printed: whether a
    /// key came from a flag or from a file is worth knowing when a request is
    /// rejected, and only the value has to stay secret.
    pub llm_api_key: Option<Resolved<String>>,
    /// Generation length limit.
    pub max_tokens: Resolved<usize>,
    /// Sampling temperature.
    pub temperature: Resolved<f32>,
    /// Attempts before a translation is abandoned.
    pub max_retries: Resolved<u32>,
    /// Which retry strategy to use.
    pub retry_strategy: Option<Resolved<String>>,
    /// Target directory for DLLs (read-only).
    pub target_dir: Option<Resolved<String>>,
    /// The workspace: where the translated Rust, `re/`, scratch, and the git repo live.
    pub workspace: Option<Resolved<String>>,
    /// Where the configuration file was read from, for diagnostics.
    pub config_path: Option<PathBuf>,
    /// Every location that was checked for a configuration file.
    pub config_searched: Vec<PathBuf>,
}

impl Settings {
    /// Collapse the flag, environment, and file layers into the values in force.
    pub fn resolve(layers: &Layers, flags: FileConfig, loaded: &LoadedConfig) -> Self {
        let LlmSection {
            url: flag_url,
            model: flag_model,
            api_key: flag_key,
            max_tokens: flag_tokens,
            temperature: flag_temp,
            max_retries: flag_retries,
            strategy: _,
        } = flags.llm;
        let GhidraSection {
            url: flag_ghidra,
            api_key: flag_ghidra_key,
            install_dir: flag_ghidra_install,
            auto_start: flag_ghidra_auto_start,
            headless: flag_ghidra_headless,
            project: flag_ghidra_project,
            min_version: flag_ghidra_min_version,
            start_timeout_secs: flag_ghidra_start_timeout,
            auto_install: flag_ghidra_auto_install,
            pin_version: flag_ghidra_pin_version,
            java_home: flag_ghidra_java_home,
        } = flags.ghidra;

        Self {
            ghidra_url: layers
                .resolve(
                    flag_ghidra,
                    layers.env.ghidra.url.clone(),
                    layers.file.ghidra.url.clone(),
                    Some(defaults::GHIDRA_URL.to_string()),
                )
                .expect("the Ghidra URL has a default, so it always resolves"),
            ghidra_api_key: layers.resolve(
                flag_ghidra_key,
                layers.env.ghidra.api_key.clone(),
                layers.file.ghidra.api_key.clone(),
                None,
            ),
            ghidra_install_dir: layers.resolve(
                flag_ghidra_install,
                layers.env.ghidra.install_dir.clone(),
                layers.file.ghidra.install_dir.clone(),
                None,
            ),
            ghidra_auto_start: layers
                .resolve(
                    flag_ghidra_auto_start,
                    layers.env.ghidra.auto_start,
                    layers.file.ghidra.auto_start,
                    Some(defaults::GHIDRA_AUTO_START),
                )
                .expect("auto_start has a default"),
            ghidra_headless: layers
                .resolve(
                    flag_ghidra_headless,
                    layers.env.ghidra.headless.clone(),
                    layers.file.ghidra.headless.clone(),
                    Some(defaults::GHIDRA_HEADLESS.to_string()),
                )
                .expect("headless has a default"),
            ghidra_project: layers.resolve(
                flag_ghidra_project,
                layers.env.ghidra.project.clone(),
                layers.file.ghidra.project.clone(),
                None,
            ),
            ghidra_min_version: layers.resolve(
                flag_ghidra_min_version,
                layers.env.ghidra.min_version.clone(),
                layers.file.ghidra.min_version.clone(),
                None,
            ),
            ghidra_start_timeout_secs: layers
                .resolve(
                    flag_ghidra_start_timeout,
                    layers.env.ghidra.start_timeout_secs,
                    layers.file.ghidra.start_timeout_secs,
                    Some(defaults::GHIDRA_START_TIMEOUT_SECS),
                )
                .expect("start_timeout_secs has a default"),
            ghidra_auto_install: layers
                .resolve(
                    flag_ghidra_auto_install,
                    layers.env.ghidra.auto_install,
                    layers.file.ghidra.auto_install,
                    Some(defaults::GHIDRA_AUTO_INSTALL),
                )
                .expect("auto_install has a default"),
            ghidra_pin_version: layers.resolve(
                flag_ghidra_pin_version,
                layers.env.ghidra.pin_version.clone(),
                layers.file.ghidra.pin_version.clone(),
                None,
            ),
            ghidra_java_home: layers.resolve(
                flag_ghidra_java_home,
                layers.env.ghidra.java_home.clone(),
                layers.file.ghidra.java_home.clone(),
                None,
            ),
            llm_url: layers.resolve(
                flag_url,
                layers.env.llm.url.clone(),
                layers.file.llm.url.clone(),
                None,
            ),
            llm_model: layers.resolve(
                flag_model,
                layers.env.llm.model.clone(),
                layers.file.llm.model.clone(),
                None,
            ),
            llm_api_key: layers.resolve(
                flag_key,
                layers.env.llm.api_key.clone(),
                layers.file.llm.api_key.clone(),
                None,
            ),
            max_tokens: layers
                .resolve(
                    flag_tokens,
                    layers.env.llm.max_tokens,
                    layers.file.llm.max_tokens,
                    Some(defaults::LLM_MAX_TOKENS),
                )
                .expect("max_tokens has a default"),
            temperature: layers
                .resolve(
                    flag_temp,
                    layers.env.llm.temperature,
                    layers.file.llm.temperature,
                    Some(defaults::LLM_TEMPERATURE),
                )
                .expect("temperature has a default"),
            max_retries: layers
                .resolve(
                    flag_retries,
                    layers.env.llm.max_retries,
                    layers.file.llm.max_retries,
                    Some(defaults::LLM_MAX_RETRIES),
                )
                .expect("max_retries has a default"),
            retry_strategy: layers.resolve(
                flags.llm.strategy.clone(),
                layers.env.llm.strategy.clone(),
                layers.file.llm.strategy.clone(),
                None,
            ),
            target_dir: layers.resolve(
                flags.target_dir.clone(),
                layers.env.target_dir.clone(),
                layers.file.target_dir.clone(),
                None,
            ),
            workspace: layers.resolve(
                flags.workspace.clone(),
                layers.env.workspace.clone(),
                layers.file.workspace.clone(),
                None,
            ),
            config_path: loaded.path.clone(),
            config_searched: loaded.searched.clone(),
        }
    }

    /// The LLM server URL, or an explanation of how to supply one.
    pub fn require_llm_url(&self) -> Result<&str> {
        let found = require(
            self.llm_url.as_ref().map(|r| r.value.as_str()),
            Setting {
                what: "LLM server URL",
                flag: "--llm-url",
                table: "llm",
                key: "url",
                env: "CALXGLOSS_LLM_URL",
            },
            &self.config_searched,
        )?;
        Ok(found)
    }

    /// The model identifier, or an explanation of how to supply one.
    pub fn require_llm_model(&self) -> Result<&str> {
        let found = require(
            self.llm_model.as_ref().map(|r| r.value.as_str()),
            Setting {
                what: "LLM model name",
                flag: "--llm-model",
                table: "llm",
                key: "model",
                env: "CALXGLOSS_LLM_MODEL",
            },
            &self.config_searched,
        )?;
        Ok(found)
    }
}

/// How to describe a setting that no layer supplied.
///
/// Kept as data rather than a hand-written string per call site so every missing
/// setting produces the same shape of message, listing all three ways to fix it.
pub struct Setting {
    /// What the setting is, in prose.
    pub what: &'static str,
    /// The command-line flag that sets it.
    pub flag: &'static str,
    /// The config-file table it lives in.
    pub table: &'static str,
    /// The key within that table.
    pub key: &'static str,
    /// The environment variable that sets it.
    pub env: &'static str,
}

/// Demand a value, or explain every way to provide one.
///
/// Naming all three layers matters: a user who has been passing a flag may not
/// know a config file exists, and one who edited the file may not know a flag
/// can override it.
fn require<'a, T: ?Sized>(
    value: Option<&'a T>,
    setting: Setting,
    searched: &[PathBuf],
) -> Result<&'a T> {
    if let Some(value) = value {
        return Ok(value);
    }

    let mut message = format!(
        "No {} is configured.\n\nSet it in any one of:",
        setting.what
    );
    message.push_str(&format!(
        "\n  {} <value>              (this run only)",
        setting.flag
    ));
    message.push_str(&format!("\n  {}=<value>       (this shell)", setting.env));
    message.push_str(&format!(
        "\n  {} = \"<value>\"      (persistent; in one of: {})",
        format_args!("[{}] {}", setting.table, setting.key),
        describe_searched(searched),
    ));
    message.push_str("\n\nFor example:\n\n");
    message.push_str(
        &EXAMPLE
            .lines()
            .skip_while(|l| !l.contains(&format!("[{}]", setting.table)))
            .take(4)
            .map(|l| format!("  {l}\n"))
            .collect::<String>(),
    );
    bail!(message)
}

/// Render the searched paths, marking which one was used.
fn describe_searched(searched: &[PathBuf]) -> String {
    if searched.is_empty() {
        return "no location was searched".to_string();
    }
    searched
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render the whole configuration for `calxgloss config`.
///
/// Secrets are replaced rather than printed: this output is meant to be pasted
/// into a bug report, and a leaked key in one is unrecoverable.
pub fn render(s: &Settings) -> String {
    let mut out = String::new();

    match &s.config_path {
        Some(path) => out.push_str(&format!("Config file: {}\n", path.display())),
        None => out.push_str("Config file: none found\n"),
    }
    if !s.config_searched.is_empty() {
        out.push_str(&format!(
            "Searched:    {}\n",
            describe_searched(&s.config_searched)
        ));
    }
    out.push('\n');

    /// Append one `name  value  (source)` line.
    ///
    /// An absent value is printed with no source at all: labelling it
    /// "(default)" would claim a layer supplied something it did not, which is
    /// exactly the kind of wrong attribution this command exists to avoid.
    /// `secret` suppresses the value itself.
    fn row(out: &mut String, name: &str, value: Option<&Resolved<String>>, secret: bool) {
        let Some(resolved) = value else {
            out.push_str(&format!("  {name:<12} <not set>\n"));
            return;
        };
        let text = if secret {
            "<set>".to_string()
        } else {
            resolved.value.clone()
        };
        out.push_str(&format!("  {name:<12} {text:<34} ({})\n", resolved.source));
    }

    /// Append a line for a non-string setting, which has no source struct.
    fn num<T: std::fmt::Display>(out: &mut String, name: &str, r: &Resolved<T>) {
        out.push_str(&format!("  {name:<12} {:<34} ({})\n", r.value, r.source));
    }

    out.push_str("target_dir\n");
    row(&mut out, "path", s.target_dir.as_ref(), false);

    out.push_str("\nworkspace\n");
    row(&mut out, "path", s.workspace.as_ref(), false);

    out.push_str("\nghidra\n");
    row(&mut out, "url", Some(&s.ghidra_url), false);
    row(&mut out, "api_key", s.ghidra_api_key.as_ref(), true);
    row(
        &mut out,
        "install_dir",
        s.ghidra_install_dir.as_ref(),
        false,
    );
    num(&mut out, "auto_start", &s.ghidra_auto_start);
    row(&mut out, "headless", Some(&s.ghidra_headless), false);
    row(&mut out, "project", s.ghidra_project.as_ref(), false);
    row(
        &mut out,
        "min_version",
        s.ghidra_min_version.as_ref(),
        false,
    );
    num(&mut out, "start_timeout_secs", &s.ghidra_start_timeout_secs);
    num(&mut out, "auto_install", &s.ghidra_auto_install);
    row(
        &mut out,
        "pin_version",
        s.ghidra_pin_version.as_ref(),
        false,
    );
    row(&mut out, "java_home", s.ghidra_java_home.as_ref(), false);

    out.push_str("\nllm\n");
    row(&mut out, "url", s.llm_url.as_ref(), false);
    row(&mut out, "model", s.llm_model.as_ref(), false);
    row(&mut out, "api_key", s.llm_api_key.as_ref(), true);
    num(&mut out, "max_tokens", &s.max_tokens);
    num(&mut out, "temperature", &s.temperature);
    num(&mut out, "max_retries", &s.max_retries);

    out.push_str("\ntranslation\n");
    row(&mut out, "retry_strategy", s.retry_strategy.as_ref(), false);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_config::Source;
    use calxgloss_config::load;

    fn settings_from(flags: FileConfig, file: FileConfig) -> Settings {
        let layers = Layers {
            file,
            ..Default::default()
        };
        let loaded = LoadedConfig {
            file: layers.file.clone(),
            path: None,
            searched: vec![PathBuf::from("calxgloss.toml")],
        };
        Settings::resolve(&layers, flags, &loaded)
    }

    #[test]
    fn test_ghidra_url_falls_back_to_the_default() {
        let s = settings_from(FileConfig::default(), FileConfig::default());
        assert_eq!(s.ghidra_url.value, defaults::GHIDRA_URL);
        assert_eq!(s.ghidra_url.source, Source::Default);
    }

    #[test]
    fn test_a_flag_beats_the_file() {
        let file = FileConfig {
            ghidra: GhidraSection {
                url: Some("http://from-file:8080".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let flags = FileConfig {
            ghidra: GhidraSection {
                url: Some("http://from-flag:8080".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(flags, file);
        assert_eq!(s.ghidra_url.value, "http://from-flag:8080");
        assert_eq!(s.ghidra_url.source, Source::Flag);
    }

    #[test]
    fn test_ghidra_install_dir_comes_from_the_file_layer() {
        // The install dir has no default on purpose: absence means "discover",
        // which is a different state from a guessed path.
        let file = FileConfig {
            ghidra: GhidraSection {
                install_dir: Some("/opt/ghidra_12.1.2_PUBLIC".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(FileConfig::default(), file);
        assert_eq!(
            s.ghidra_install_dir.as_ref().expect("set").value,
            "/opt/ghidra_12.1.2_PUBLIC"
        );
        assert_eq!(
            s.ghidra_install_dir.as_ref().expect("set").source,
            Source::File
        );
        let s = settings_from(FileConfig::default(), FileConfig::default());
        assert!(s.ghidra_install_dir.is_none());
    }

    #[test]
    fn test_ghidra_lifecycle_settings_fall_back_to_their_defaults() {
        // G1-T7: spawning is the norm, so the knobs default to "do the
        // sensible thing" rather than demanding configuration.
        let s = settings_from(FileConfig::default(), FileConfig::default());
        assert!(s.ghidra_auto_start.value);
        assert_eq!(s.ghidra_auto_start.source, Source::Default);
        assert_eq!(s.ghidra_headless.value, "auto");
        assert_eq!(s.ghidra_headless.source, Source::Default);
        assert!(s.ghidra_project.is_none());
        assert!(s.ghidra_min_version.is_none());
        assert_eq!(
            s.ghidra_start_timeout_secs.value,
            defaults::GHIDRA_START_TIMEOUT_SECS
        );
        assert_eq!(s.ghidra_start_timeout_secs.source, Source::Default);
        // G1-T8: a ~570 MB download is never consented to by default.
        assert!(!s.ghidra_auto_install.value);
        assert_eq!(s.ghidra_auto_install.source, Source::Default);
        assert!(s.ghidra_pin_version.is_none());
        assert!(s.ghidra_java_home.is_none());
    }

    #[test]
    fn test_ghidra_lifecycle_keys_come_from_the_file_layer() {
        let file = FileConfig {
            ghidra: GhidraSection {
                auto_start: Some(false),
                headless: Some("always".into()),
                project: Some("/run/eq/ghidra/EverQuest.gpr".into()),
                min_version: Some("12.1".into()),
                start_timeout_secs: Some(120),
                auto_install: Some(true),
                pin_version: Some("12.1.2".into()),
                java_home: Some("/usr/lib/jvm/java-21".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(FileConfig::default(), file);
        assert!(!s.ghidra_auto_start.value);
        assert_eq!(s.ghidra_auto_start.source, Source::File);
        assert_eq!(s.ghidra_headless.value, "always");
        assert_eq!(s.ghidra_headless.source, Source::File);
        assert_eq!(
            s.ghidra_project.as_ref().expect("set").value,
            "/run/eq/ghidra/EverQuest.gpr"
        );
        assert_eq!(s.ghidra_min_version.as_ref().expect("set").value, "12.1");
        assert_eq!(s.ghidra_start_timeout_secs.value, 120);
        assert_eq!(s.ghidra_start_timeout_secs.source, Source::File);
        assert!(s.ghidra_auto_install.value);
        assert_eq!(s.ghidra_pin_version.as_ref().expect("set").value, "12.1.2");
        assert_eq!(
            s.ghidra_java_home.as_ref().expect("set").value,
            "/usr/lib/jvm/java-21"
        );
    }

    #[test]
    fn test_no_autostart_flag_beats_a_file_that_allows_it() {
        // `--no-ghidra-autostart` is the flag layer's only lifecycle input,
        // and it only ever turns autostart off.
        let file = FileConfig {
            ghidra: GhidraSection {
                auto_start: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let flags = FileConfig {
            ghidra: GhidraSection {
                auto_start: Some(false),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(flags, file);
        assert!(!s.ghidra_auto_start.value);
        assert_eq!(s.ghidra_auto_start.source, Source::Flag);
    }

    #[test]
    fn test_llm_url_is_absent_until_configured() {
        // No default exists for a local inference server, so the setting stays
        // unresolved and the error is raised at the point of use.
        let s = settings_from(FileConfig::default(), FileConfig::default());
        assert!(s.llm_url.is_none());
    }

    #[test]
    fn test_a_missing_llm_url_names_all_three_ways_to_set_it() {
        let s = settings_from(FileConfig::default(), FileConfig::default());
        let err = s.require_llm_url().unwrap_err().to_string();
        assert!(err.contains("--llm-url"), "{err}");
        assert!(err.contains("CALXGLOSS_LLM_URL"), "{err}");
        assert!(err.contains("[llm] url"), "{err}");
        // The paths actually searched, so the instruction points at a real file
        // rather than a generically named one.
        assert!(err.contains("calxgloss.toml"), "{err}");
    }

    #[test]
    fn test_a_missing_llm_model_names_all_three_ways_to_set_it() {
        let s = settings_from(FileConfig::default(), FileConfig::default());
        let err = s.require_llm_model().unwrap_err().to_string();
        assert!(err.contains("--llm-model"), "{err}");
        assert!(err.contains("CALXGLOSS_LLM_MODEL"), "{err}");
        assert!(err.contains("[llm] model"), "{err}");
    }

    #[test]
    fn test_a_configured_llm_url_resolves() {
        let file = FileConfig {
            llm: LlmSection {
                url: Some("http://127.0.0.1:1919/v1".into()),
                model: Some("m".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(FileConfig::default(), file);
        assert_eq!(s.require_llm_url().unwrap(), "http://127.0.0.1:1919/v1");
        assert_eq!(s.require_llm_model().unwrap(), "m");
    }

    #[test]
    fn test_render_reports_the_source_of_each_value() {
        let file = FileConfig {
            llm: LlmSection {
                url: Some("http://127.0.0.1:1919/v1".into()),
                model: Some("Qwen".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(FileConfig::default(), file);
        let out = render(&s);
        assert!(out.contains("(config file)"), "{out}");
        assert!(out.contains("(default)"), "{out}");
        assert!(out.contains("http://127.0.0.1:1919/v1"), "{out}");
        // The G1-T7 lifecycle knobs are reported too, with their sources.
        assert!(out.contains("auto_start"), "{out}");
        assert!(out.contains("headless"), "{out}");
        assert!(out.contains("start_timeout"), "{out}");
    }

    #[test]
    fn test_render_never_prints_a_secret() {
        let file = FileConfig {
            llm: LlmSection {
                api_key: Some("sk-super-secret-value".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let s = settings_from(FileConfig::default(), file);
        let out = render(&s);
        assert!(
            !out.contains("sk-super-secret-value"),
            "secret leaked:\n{out}"
        );
        assert!(out.contains("<set>"), "{out}");
    }

    #[test]
    fn test_render_says_when_no_file_was_found() {
        let s = settings_from(FileConfig::default(), FileConfig::default());
        let out = render(&s);
        assert!(out.contains("none found"), "{out}");
    }

    #[test]
    fn test_an_unset_value_is_not_attributed_to_a_layer() {
        // "<not set> (default)" would claim the default layer chose a value it
        // never provided, which is precisely the misreading this command avoids.
        let s = settings_from(FileConfig::default(), FileConfig::default());
        let out = render(&s);
        assert!(out.contains("<not set>"), "{out}");
        assert!(
            !out.contains("<not set> ")
                || !out
                    .lines()
                    .any(|l| l.contains("<not set>") && l.contains("(")),
            "an unset value must carry no source:\n{out}"
        );
    }

    #[test]
    fn test_settings_take_the_file_path_from_the_loaded_config() {
        // The CLI reads the file once and hands both the contents and the path
        // over; the path must survive so `config` can name it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, "[llm]\nmodel = \"m\"\n").unwrap();
        let loaded = load(Some(&path)).unwrap();

        // The CLI copies the file's contents into the file layer, so the
        // resolver sees the same values the file supplied.
        let layers = Layers {
            file: loaded.file.clone(),
            ..Default::default()
        };
        let s = Settings::resolve(&layers, FileConfig::default(), &loaded);
        assert_eq!(s.config_path.as_deref(), Some(path.as_path()));
        assert_eq!(s.require_llm_model().unwrap(), "m");
    }
}

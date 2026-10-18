//! Turning layered configuration into the values the commands actually use.
//!
//! The command line has to answer one question that no single layer can: *if the
//! user did not pass a flag, where did this value come from?* Every setting
//! resolved here keeps its [`Source`], so `calxgloss config` can show that
//! rather than leaving it to guesswork.

use std::path::PathBuf;

use anyhow::{Result, bail};
use calxgloss_config::{
    AnalysisSection, EXAMPLE, FileConfig, Layers, LlmSection, LoadedConfig, Resolved, defaults,
};

/// Every setting the commands need, after layering.
///
/// Kuna is the only analysis engine (issue #214): it is compiled in and
/// loaded from the target file, so there is no engine choice and no server
/// to configure. The LLM URL and model are genuinely optional here, because
/// a local inference server has no conventional address — they are demanded
/// by [`require`] at the point of use and reported with instructions when
/// absent.
#[derive(Debug, Clone)]
pub struct Settings {
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
    /// Token budget for a single LLM request (prompt + output).
    pub context_window: Resolved<usize>,
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
    /// Per-function instruction budget for the Kuna engine, when configured.
    pub max_fn_instructions: Option<Resolved<u64>>,
    /// Per-function time budget, in seconds, for the Kuna engine, when configured.
    pub max_fn_seconds: Option<Resolved<u64>>,
    /// Per-function memory budget, in MiB, for the Kuna engine, when configured.
    pub max_fn_memory_mib: Option<Resolved<u64>>,
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
            context_window: flag_window,
            temperature: flag_temp,
            max_retries: flag_retries,
            strategy: _,
        } = flags.llm;
        let AnalysisSection {
            max_fn_instructions: flag_max_fn_instructions,
            max_fn_seconds: flag_max_fn_seconds,
            max_fn_memory_mib: flag_max_fn_memory_mib,
        } = flags.analysis;

        Self {
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
            context_window: layers
                .resolve(
                    flag_window,
                    layers.env.llm.context_window,
                    layers.file.llm.context_window,
                    Some(defaults::LLM_CONTEXT_WINDOW),
                )
                .expect("context_window has a default"),
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
            // Budgets have no calxgloss default: absence means "use Kuna's own",
            // so they resolve with no default and stay unset until configured.
            max_fn_instructions: layers.resolve(
                flag_max_fn_instructions,
                layers.env.analysis.max_fn_instructions,
                layers.file.analysis.max_fn_instructions,
                None,
            ),
            max_fn_seconds: layers.resolve(
                flag_max_fn_seconds,
                layers.env.analysis.max_fn_seconds,
                layers.file.analysis.max_fn_seconds,
                None,
            ),
            max_fn_memory_mib: layers.resolve(
                flag_max_fn_memory_mib,
                layers.env.analysis.max_fn_memory_mib,
                layers.file.analysis.max_fn_memory_mib,
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

    /// Fold the configured budget knobs into the shape the Kuna engine takes.
    ///
    /// Unset knobs stay `None`, which leaves Kuna's own defaults in force;
    /// the values pass through verbatim, including `0`'s "no limit" meaning.
    pub fn kuna_budget(&self) -> calxgloss_kuna::KunaBudget {
        calxgloss_kuna::KunaBudget {
            max_instructions: self.max_fn_instructions.as_ref().map(|r| r.value),
            max_fn_seconds: self.max_fn_seconds.as_ref().map(|r| r.value),
            max_fn_memory_mib: self.max_fn_memory_mib.as_ref().map(|r| r.value),
        }
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

    /// Append a line for an optional non-string setting: an absent value is
    /// "<not set>" with no source, like the string rows.
    fn opt_num<T: std::fmt::Display>(out: &mut String, name: &str, r: Option<&Resolved<T>>) {
        match r {
            Some(r) => out.push_str(&format!("  {name:<12} {:<34} ({})\n", r.value, r.source)),
            None => out.push_str(&format!("  {name:<12} <not set>\n")),
        }
    }

    out.push_str("target_dir\n");
    row(&mut out, "path", s.target_dir.as_ref(), false);

    out.push_str("\nworkspace\n");
    row(&mut out, "path", s.workspace.as_ref(), false);

    out.push_str("\nanalysis\n");
    opt_num(
        &mut out,
        "max_fn_instructions",
        s.max_fn_instructions.as_ref(),
    );
    opt_num(&mut out, "max_fn_seconds", s.max_fn_seconds.as_ref());
    opt_num(&mut out, "max_fn_memory_mib", s.max_fn_memory_mib.as_ref());

    out.push_str("\nllm\n");
    row(&mut out, "url", s.llm_url.as_ref(), false);
    row(&mut out, "model", s.llm_model.as_ref(), false);
    row(&mut out, "api_key", s.llm_api_key.as_ref(), true);
    num(&mut out, "context_window", &s.context_window);
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

    #[test]
    fn test_unset_budgets_fold_into_an_empty_kuna_budget() {
        // Issue #211: absence means "leave Kuna's own defaults", so the
        // folded budget carries no knobs and render reports none as set.
        let s = settings_from(FileConfig::default(), FileConfig::default());
        let budget = s.kuna_budget();
        assert_eq!(budget, calxgloss_kuna::KunaBudget::default());
        let out = render(&s);
        assert!(out.contains("max_fn_instructions <not set>"), "{out}");
        assert!(out.contains("max_fn_seconds <not set>"), "{out}");
        assert!(out.contains("max_fn_memory_mib <not set>"), "{out}");
    }

    #[test]
    fn test_the_budget_keys_come_from_the_file_layer_and_fold_into_the_kuna_budget() {
        let file = FileConfig {
            analysis: AnalysisSection {
                max_fn_instructions: Some(5000),
                max_fn_seconds: Some(30),
                max_fn_memory_mib: Some(512),
            },
            ..Default::default()
        };
        let s = settings_from(FileConfig::default(), file);
        assert_eq!(
            s.max_fn_instructions.as_ref().expect("set").source,
            Source::File
        );
        let budget = s.kuna_budget();
        assert_eq!(budget.max_instructions, Some(5000));
        assert_eq!(budget.max_fn_seconds, Some(30));
        assert_eq!(budget.max_fn_memory_mib, Some(512));
        let out = render(&s);
        assert!(
            out.contains("max_fn_seconds") && out.contains("30"),
            "{out}"
        );
    }
}

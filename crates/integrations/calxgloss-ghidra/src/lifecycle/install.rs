//! Discovery of the Ghidra install on disk.
//!
//! The search order is fixed by the design doc (`docs/ghidra_integration.md`
//! §3.2): `$GHIDRA_INSTALL_DIR` → the `ghidra.install_dir` config value → a
//! `*ghidra_*_PUBLIC` glob in the home directory, where the highest version
//! wins. An install only counts as real when its layout validates — a bare
//! `Ghidra/Framework` directory inside it — because a half-extracted or
//! renamed directory otherwise discovers as a working stack and fails much
//! later inside a run.

use std::path::{Path, PathBuf};

use tracing::debug;

use super::properties_value;
use crate::client::plugin_version_at_least;

/// A discovered Ghidra install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraInstall {
    /// The install directory itself, e.g. `~/ghidra_12.1.2_PUBLIC`.
    pub path: PathBuf,
    /// The Ghidra version, read from the directory name
    /// (`ghidra_12.1.2_PUBLIC` → `12.1.2`), falling back to
    /// `Ghidra/application.properties` when the name does not carry one.
    pub version: String,
}

/// Which layer supplied the install, so a report can name the knob to turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    /// The `$GHIDRA_INSTALL_DIR` environment variable.
    EnvVar,
    /// The `ghidra.install_dir` configuration value.
    Config,
    /// The `*ghidra_*_PUBLIC` glob over the home directory.
    HomeGlob,
}

impl std::fmt::Display for InstallSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvVar => write!(f, "$GHIDRA_INSTALL_DIR"),
            Self::Config => write!(f, "ghidra.install_dir"),
            Self::HomeGlob => write!(f, "home directory"),
        }
    }
}

/// The outcome of install discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDiscovery {
    /// An install was found and its layout validated.
    Found {
        /// The install itself.
        install: GhidraInstall,
        /// Which layer named it.
        source: InstallSource,
    },
    /// A layer named a path, but it is not a valid Ghidra install.
    ///
    /// Reported rather than fallen through past: an explicitly named path that
    /// does not validate is a misconfiguration worth seeing, and silently
    /// discovering a *different* install would make the named path look like
    /// it did nothing.
    Invalid {
        /// The named path.
        path: PathBuf,
        /// Which layer named it.
        source: InstallSource,
    },
    /// No layer named anything that validated.
    NotFound,
}

/// Discover the Ghidra install.
///
/// `env_dir` is `$GHIDRA_INSTALL_DIR` and `config_dir` is the resolved
/// `ghidra.install_dir`, each checked in that order; `home` supplies the glob,
/// whose highest-version entry wins. Every input is a parameter rather than a
/// process lookup so the whole search is testable against tempdir fixtures.
pub fn discover(
    env_dir: Option<&Path>,
    config_dir: Option<&Path>,
    home: Option<&Path>,
) -> InstallDiscovery {
    // An empty named path counts as unset, like the config layers' `var()`.
    let env_dir = env_dir.filter(|p| !p.as_os_str().is_empty());
    let config_dir = config_dir.filter(|p| !p.as_os_str().is_empty());
    for named in [
        env_dir.map(|p| (p, InstallSource::EnvVar)),
        config_dir.map(|p| (p, InstallSource::Config)),
    ] {
        let Some((dir, source)) = named else {
            continue;
        };
        return match version_of_valid(dir) {
            Some(version) => InstallDiscovery::Found {
                install: GhidraInstall {
                    path: dir.to_path_buf(),
                    version,
                },
                source,
            },
            None => {
                debug!(path = %dir.display(), %source, "Named Ghidra install did not validate");
                InstallDiscovery::Invalid {
                    path: dir.to_path_buf(),
                    source,
                }
            }
        };
    }

    if let Some(found) = home.and_then(glob_highest) {
        return InstallDiscovery::Found {
            install: found,
            source: InstallSource::HomeGlob,
        };
    }
    InstallDiscovery::NotFound
}

/// Whether `path` looks like a Ghidra install: the `Ghidra/Framework` directory
/// is what every launcher and the headless recipe expect inside it.
fn layout_valid(path: &Path) -> bool {
    path.join("Ghidra").join("Framework").is_dir()
}

/// The version of a validated install, or `None` when it does not validate.
///
/// The version comes from the directory name first — the canonical
/// `ghidra_<X.Y.Z>_PUBLIC` spelling — and falls back to the
/// `application.version` key inside `Ghidra/application.properties` for
/// installs pointed at under a custom name.
fn version_of_valid(path: &Path) -> Option<String> {
    if !path.is_dir() || !layout_valid(path) {
        return None;
    }
    version_from_name(path)
        .or_else(|| version_from_properties(path))
        .filter(|version| parses_as_version(version))
}

/// Parse the version out of a `ghidra_<X.Y.Z>_PUBLIC` directory name.
fn version_from_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let middle = name.strip_prefix("ghidra_")?.strip_suffix("_PUBLIC")?;
    Some(middle.to_string())
}

/// Parse `application.version` out of `Ghidra/application.properties`.
fn version_from_properties(path: &Path) -> Option<String> {
    let body = std::fs::read_to_string(path.join("Ghidra").join("application.properties")).ok()?;
    properties_value(&body, "application.version")
}

/// Whether a version string is dot-separated numbers, the only spelling the
/// highest-version tie rule can order. Every component must be numeric, so a
/// junk name like `12.x` never outranks a real install.
fn parses_as_version(version: &str) -> bool {
    let mut components = version.split('.').peekable();
    components.peek().is_some()
        && components.all(|part| !part.is_empty() && part.parse::<u64>().is_ok())
}

/// The highest-versioned `*ghidra_*_PUBLIC` install in `home`.
///
/// Entries that do not validate or carry no orderable version are skipped:
/// the glob is a best-effort fallback, and a stray directory should not
/// outrank a working install.
fn glob_highest(home: &Path) -> Option<GhidraInstall> {
    let entries = std::fs::read_dir(home).ok()?;
    let mut best: Option<GhidraInstall> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        if !name.contains("ghidra_") || !name.ends_with("_PUBLIC") {
            continue;
        }
        let Some(version) = version_of_valid(&path) else {
            continue;
        };
        let replace = best
            .as_ref()
            .is_none_or(|current| plugin_version_at_least(&version, &current.version));
        if replace {
            best = Some(GhidraInstall { path, version });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake install `<home>/ghidra_<version>_PUBLIC` with a valid layout.
    fn sample_install(home: &Path, version: &str) -> PathBuf {
        let path = home.join(format!("ghidra_{version}_PUBLIC"));
        std::fs::create_dir_all(path.join("Ghidra").join("Framework")).expect("create layout");
        path
    }

    #[test]
    fn test_finds_the_install_named_by_the_env_var_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from_env = sample_install(dir.path(), "11.1.2");
        // A newer install sits in the home glob; the env var still wins,
        // because an explicitly named path outranks a guessed one.
        sample_install(dir.path(), "12.1.2");
        let found = discover(Some(&from_env), None, Some(dir.path()));
        match found {
            InstallDiscovery::Found { install, source } => {
                assert_eq!(install.version, "11.1.2");
                assert_eq!(source, InstallSource::EnvVar);
            }
            other => panic!("expected a found install, got {other:?}"),
        }
    }

    #[test]
    fn test_config_outranks_the_home_glob() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from_config = sample_install(dir.path(), "11.1.2");
        sample_install(dir.path(), "12.1.2");
        let found = discover(None, Some(&from_config), Some(dir.path()));
        match found {
            InstallDiscovery::Found { install, source } => {
                assert_eq!(install.version, "11.1.2");
                assert_eq!(source, InstallSource::Config);
            }
            other => panic!("expected a found install, got {other:?}"),
        }
    }

    #[test]
    fn test_the_glob_picks_the_highest_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        sample_install(dir.path(), "11.1.2");
        sample_install(dir.path(), "12.1.10");
        sample_install(dir.path(), "12.1.2");
        let found = discover(None, None, Some(dir.path()));
        match found {
            InstallDiscovery::Found { install, source } => {
                // Numeric component order, not lexical: 12.1.10 beats 12.1.2.
                assert_eq!(install.version, "12.1.10");
                assert_eq!(source, InstallSource::HomeGlob);
            }
            other => panic!("expected a found install, got {other:?}"),
        }
    }

    #[test]
    fn test_a_named_path_that_does_not_validate_is_reported_not_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A Ghidra-looking directory with no Ghidra/Framework inside.
        let hollow = dir.path().join("ghidra_12.1.2_PUBLIC");
        std::fs::create_dir_all(hollow.join("Ghidra")).expect("create hollow install");
        // A perfectly good install sits in the glob — but the named path is
        // the misconfiguration the user needs to see, not a silent fallback.
        sample_install(dir.path(), "11.1.2");
        let found = discover(Some(&hollow), None, Some(dir.path()));
        match found {
            InstallDiscovery::Invalid { path, source } => {
                assert_eq!(path, hollow);
                assert_eq!(source, InstallSource::EnvVar);
            }
            other => panic!("expected an invalid install, got {other:?}"),
        }
    }

    #[test]
    fn test_a_custom_named_install_falls_back_to_application_properties() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("my-ghidra");
        std::fs::create_dir_all(path.join("Ghidra").join("Framework")).expect("create layout");
        std::fs::write(
            path.join("Ghidra").join("application.properties"),
            "#generated\napplication.version=12.1.2\n",
        )
        .expect("write properties");
        let found = discover(Some(&path), None, None);
        match found {
            InstallDiscovery::Found { install, .. } => assert_eq!(install.version, "12.1.2"),
            other => panic!("expected a found install, got {other:?}"),
        }
    }

    #[test]
    fn test_a_junk_version_never_outranks_a_real_install() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `12.x` sorts above `12.1.2` lexically and would outrank it under a
        // lenient first-component check — it must be skipped entirely.
        sample_install(dir.path(), "12.x");
        sample_install(dir.path(), "12.1.2");
        let found = discover(None, None, Some(dir.path()));
        match found {
            InstallDiscovery::Found { install, .. } => assert_eq!(install.version, "12.1.2"),
            other => panic!("expected a found install, got {other:?}"),
        }
    }

    #[test]
    fn test_an_empty_named_path_counts_as_unset() {
        let dir = tempfile::tempdir().expect("tempdir");
        sample_install(dir.path(), "12.1.2");
        // `GHIDRA_INSTALL_DIR=""` is unset in spirit, not a path to report invalid.
        let empty = std::path::Path::new("");
        let found = discover(Some(empty), Some(empty), Some(dir.path()));
        match found {
            InstallDiscovery::Found { source, .. } => assert_eq!(source, InstallSource::HomeGlob),
            other => panic!("expected a found install, got {other:?}"),
        }
    }

    #[test]
    fn test_nothing_found_is_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("not-ghidra")).expect("create decoy");
        assert_eq!(
            discover(None, None, Some(dir.path())),
            InstallDiscovery::NotFound
        );
        assert_eq!(discover(None, None, None), InstallDiscovery::NotFound);
    }

    #[test]
    fn test_source_names_point_at_the_knob_to_turn() {
        assert_eq!(InstallSource::EnvVar.to_string(), "$GHIDRA_INSTALL_DIR");
        assert_eq!(InstallSource::Config.to_string(), "ghidra.install_dir");
        assert_eq!(InstallSource::HomeGlob.to_string(), "home directory");
    }
}

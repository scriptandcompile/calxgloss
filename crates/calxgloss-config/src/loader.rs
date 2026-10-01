//! Loading a configuration file from disk.

use std::path::{Path, PathBuf};
use tracing::debug;

use crate::ConfigError;
use crate::schema::FileConfig;

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
    use crate::schema::EXAMPLE;

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

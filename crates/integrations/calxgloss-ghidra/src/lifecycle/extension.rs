//! Discovery of the GhidraMCP extension inside a Ghidra version's state dir.
//!
//! The extension installs per Ghidra build —
//! `~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/GhidraMCP/` — and its
//! jar is compiled against exactly one Ghidra build (ADR-0001: the
//! `version=` key in `extension.properties` names that build). A Ghidra
//! upgrade therefore silently breaks an installed extension, which is why the
//! pairing check is strict equality rather than a range.

use std::path::{Path, PathBuf};

use super::properties_value;
use crate::client::MIN_PLUGIN_VERSION;

/// A discovered GhidraMCP extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraExtension {
    /// The extension directory, e.g. `~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP`.
    pub dir: PathBuf,
    /// The Ghidra build the extension was compiled against — the `version=`
    /// key in `extension.properties`.
    pub built_for: String,
    /// The plugin version, read from the `GhidraMCP-<version>.jar` in `lib/`,
    /// falling back to the "Plugin version X" note in the manifest's
    /// `description`. `None` when neither names one.
    pub plugin_version: Option<String>,
}

/// The outcome of extension discovery for one Ghidra version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionDiscovery {
    /// The extension directory was read; whether it pairs with the installed
    /// Ghidra is the caller's verdict to make.
    Found(GhidraExtension),
    /// Nothing sits at the per-version path the extension would live at.
    Missing {
        /// Where it was looked for.
        expected: PathBuf,
    },
    /// The directory exists but its manifest could not be read at all.
    Unreadable {
        /// The extension directory.
        dir: PathBuf,
    },
}

/// How the extension stands against the discovered Ghidra install — the
/// strict-pairing verdict (ADR-0001) plus the plugin floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionVerdict {
    /// Present, built for exactly this Ghidra build, plugin at or above the
    /// pinned minimum.
    Ok {
        /// Plugin version as the install names it, when it names one.
        plugin_version: Option<String>,
        /// The Ghidra build it was compiled against.
        built_for: String,
    },
    /// Not installed for this Ghidra version at all.
    Missing {
        /// The directory a manual install would drop the zip's contents into.
        extensions_dir: PathBuf,
    },
    /// Present, but compiled against a different Ghidra build — the failure a
    /// Ghidra upgrade leaves behind.
    WrongBuild {
        /// The build the extension names.
        built_for: String,
        /// The Ghidra actually installed.
        ghidra: String,
        /// The per-version `Extensions` directory the zip belongs in.
        extensions_dir: PathBuf,
    },
    /// Paired with this Ghidra, but older than the bridge calxgloss needs.
    TooOld {
        /// The plugin version found.
        plugin_version: String,
        /// The minimum from [`MIN_PLUGIN_VERSION`].
        required: String,
    },
    /// Present but not loadable: no manifest, or no jar and no version note.
    Broken {
        /// The extension directory.
        dir: PathBuf,
    },
}

/// Judge a discovery against the installed Ghidra version.
///
/// Strict pairing first — a jar built for another Ghidra build is the
/// load-bearing failure (ADR-0001) — then the plugin floor.
pub fn verdict(discovery: &ExtensionDiscovery, ghidra_version: &str) -> ExtensionVerdict {
    match discovery {
        ExtensionDiscovery::Missing { expected } => ExtensionVerdict::Missing {
            extensions_dir: expected.parent().unwrap_or(expected).to_path_buf(),
        },
        ExtensionDiscovery::Unreadable { dir } => ExtensionVerdict::Broken { dir: dir.clone() },
        ExtensionDiscovery::Found(extension) => {
            if extension.built_for != ghidra_version {
                return ExtensionVerdict::WrongBuild {
                    built_for: extension.built_for.clone(),
                    ghidra: ghidra_version.to_string(),
                    extensions_dir: extension
                        .dir
                        .parent()
                        .unwrap_or(&extension.dir)
                        .to_path_buf(),
                };
            }
            match &extension.plugin_version {
                Some(version)
                    if !crate::client::plugin_version_at_least(version, MIN_PLUGIN_VERSION) =>
                {
                    ExtensionVerdict::TooOld {
                        plugin_version: version.clone(),
                        required: MIN_PLUGIN_VERSION.to_string(),
                    }
                }
                // No version named anywhere: the pairing still holds, and the
                // running server's own probe enforces the floor end to end.
                _ => ExtensionVerdict::Ok {
                    plugin_version: extension.plugin_version.clone(),
                    built_for: extension.built_for.clone(),
                },
            }
        }
    }
}

/// Ghidra's per-version state directory: `<config_root>/ghidra_<version>_PUBLIC`.
pub(crate) fn state_dir(config_root: &Path, ghidra_version: &str) -> PathBuf {
    config_root.join(format!("ghidra_{ghidra_version}_PUBLIC"))
}

/// Discover the GhidraMCP extension for one Ghidra version.
///
/// `config_root` is Ghidra's own config root — normally `~/.config/ghidra` —
/// taken as a parameter so the search is testable against tempdir fixtures.
pub fn discover(config_root: &Path, ghidra_version: &str) -> ExtensionDiscovery {
    let dir = state_dir(config_root, ghidra_version)
        .join("Extensions")
        .join("GhidraMCP");
    if !dir.is_dir() {
        return ExtensionDiscovery::Missing { expected: dir };
    }
    let body = match std::fs::read_to_string(dir.join("extension.properties")) {
        Ok(body) => body,
        Err(_) => return ExtensionDiscovery::Unreadable { dir },
    };
    let Some(built_for) = properties_value(&body, "version") else {
        return ExtensionDiscovery::Unreadable { dir };
    };
    ExtensionDiscovery::Found(GhidraExtension {
        dir: dir.clone(),
        plugin_version: plugin_version(&dir, &body),
        built_for,
    })
}

/// The plugin version: the `GhidraMCP-<version>.jar` in `lib/` is what Ghidra
/// actually loads, so it outranks the manifest's `description` note.
fn plugin_version(dir: &Path, manifest: &str) -> Option<String> {
    let jar = std::fs::read_dir(dir.join("lib")).ok().and_then(|entries| {
        entries.flatten().find_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let version = name
                .strip_prefix("GhidraMCP-")?
                .strip_suffix(".jar")?
                .to_string();
            Some(version)
        })
    });
    jar.or_else(|| {
        // The manifest's own note, e.g. "... Plugin version 6.0.0."
        let rest = manifest.split("Plugin version ").nth(1)?;
        let version = rest.split_whitespace().next()?.trim_end_matches('.');
        (!version.is_empty()).then(|| version.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake `~/.config/ghidra` fixture: extension for `built_for` with a
    /// `GhidraMCP-<plugin>.jar`, installed under state dir `state_for`.
    fn sample_extension(
        config_root: &Path,
        state_for: &str,
        built_for: &str,
        plugin: &str,
    ) -> PathBuf {
        let dir = state_dir(config_root, state_for)
            .join("Extensions")
            .join("GhidraMCP");
        std::fs::create_dir_all(dir.join("lib")).expect("create extension dirs");
        std::fs::write(
            dir.join("extension.properties"),
            format!(
                "name=GhidraMCP\n\
                 description=A plugin that runs an embedded HTTP server. Plugin version {plugin}.\n\
                 author=Ben Ethington\n\
                 version={built_for}\n"
            ),
        )
        .expect("write manifest");
        std::fs::write(dir.join("lib").join(format!("GhidraMCP-{plugin}.jar")), b"")
            .expect("write jar");
        dir
    }

    #[test]
    fn test_reads_the_built_for_version_and_the_jar_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = sample_extension(dir.path(), "12.1.2", "12.1.2", "6.0.0");
        let found = discover(dir.path(), "12.1.2");
        match &found {
            ExtensionDiscovery::Found(extension) => {
                assert_eq!(extension.dir, installed);
                assert_eq!(extension.built_for, "12.1.2");
                assert_eq!(extension.plugin_version.as_deref(), Some("6.0.0"));
            }
            other => panic!("expected a found extension, got {other:?}"),
        }
        assert_eq!(
            verdict(&found, "12.1.2"),
            ExtensionVerdict::Ok {
                plugin_version: Some("6.0.0".into()),
                built_for: "12.1.2".into(),
            }
        );
    }

    #[test]
    fn test_a_build_mismatch_is_verdicted_against_the_installed_ghidra() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The live incident shape: extension installed under the 12.1.2 state
        // dir but built for 12.1.1 (or a stale manifest after an upgrade).
        sample_extension(dir.path(), "12.1.2", "12.1.1", "6.0.0");
        let found = discover(dir.path(), "12.1.2");
        let verdict = verdict(&found, "12.1.2");
        match verdict {
            ExtensionVerdict::WrongBuild {
                built_for,
                ghidra,
                extensions_dir,
            } => {
                assert_eq!(built_for, "12.1.1");
                assert_eq!(ghidra, "12.1.2");
                assert!(
                    extensions_dir.ends_with("ghidra_12.1.2_PUBLIC/Extensions"),
                    "hint path: {}",
                    extensions_dir.display()
                );
            }
            other => panic!("expected a wrong-build verdict, got {other:?}"),
        }
    }

    #[test]
    fn test_a_plugin_below_the_pinned_minimum_is_too_old() {
        let dir = tempfile::tempdir().expect("tempdir");
        sample_extension(dir.path(), "12.1.2", "12.1.2", "5.9.0");
        let found = discover(dir.path(), "12.1.2");
        assert_eq!(
            verdict(&found, "12.1.2"),
            ExtensionVerdict::TooOld {
                plugin_version: "5.9.0".into(),
                required: MIN_PLUGIN_VERSION.into(),
            }
        );
    }

    #[test]
    fn test_missing_extension_names_where_the_zip_goes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let found = discover(dir.path(), "12.1.2");
        assert!(matches!(&found, ExtensionDiscovery::Missing { .. }));
        match verdict(&found, "12.1.2") {
            ExtensionVerdict::Missing { extensions_dir } => {
                assert!(
                    extensions_dir.ends_with("ghidra_12.1.2_PUBLIC/Extensions"),
                    "hint path: {}",
                    extensions_dir.display()
                );
            }
            other => panic!("expected a missing verdict, got {other:?}"),
        }
    }

    #[test]
    fn test_the_description_note_backstops_a_missing_jar_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ext_dir = state_dir(dir.path(), "12.1.2")
            .join("Extensions")
            .join("GhidraMCP");
        std::fs::create_dir_all(&ext_dir).expect("create extension dir");
        std::fs::write(
            ext_dir.join("extension.properties"),
            "name=GhidraMCP\ndescription=Runs an HTTP server. Plugin version 6.0.0.\nversion=12.1.2\n",
        )
        .expect("write manifest");
        let found = discover(dir.path(), "12.1.2");
        match &found {
            ExtensionDiscovery::Found(extension) => {
                assert_eq!(extension.plugin_version.as_deref(), Some("6.0.0"));
            }
            other => panic!("expected a found extension, got {other:?}"),
        }
    }

    #[test]
    fn test_a_directory_without_a_readable_manifest_is_broken() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ext_dir = state_dir(dir.path(), "12.1.2")
            .join("Extensions")
            .join("GhidraMCP");
        std::fs::create_dir_all(&ext_dir).expect("create extension dir");
        let found = discover(dir.path(), "12.1.2");
        assert!(matches!(&found, ExtensionDiscovery::Unreadable { .. }));
        assert_eq!(
            verdict(&found, "12.1.2"),
            ExtensionVerdict::Broken { dir: ext_dir }
        );
    }
}

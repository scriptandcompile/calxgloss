//! The install manifest: what calxgloss installed, where.
//!
//! `~/.local/share/calxgloss/ghidra-install.json` records the installs the
//! bootstrap made, which is what lets `doctor` distinguish a
//! calxgloss-managed install from a user-managed one — and what lets an
//! upgrade replace the right directory without ever touching an install
//! calxgloss did not make (design §3.5, safety).
//!
//! Reading is degrading, never fatal: a missing or corrupt manifest just
//! means "nothing is recorded as managed", the same posture the analysis
//! cache takes. Writing is best-effort for the same reason — losing it costs
//! the upgrade/uninstall bookkeeping, not the working install.

use std::path::{Path, PathBuf};

use calxgloss_types::persist::{PersistError, load_json, save_json};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// A Ghidra install calxgloss made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedInstall {
    /// The Ghidra version, e.g. `12.1.2`.
    pub version: String,
    /// The install directory, e.g. `~/.local/share/calxgloss/ghidra/ghidra_12.1.2_PUBLIC`.
    pub path: PathBuf,
}

/// The GhidraMCP extension calxgloss installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedPlugin {
    /// The plugin version, when the artifact names one.
    pub version: Option<String>,
    /// The Ghidra build the extension was compiled against.
    pub built_for: String,
    /// The extension directory, e.g. `~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP`.
    pub path: PathBuf,
}

/// What calxgloss has installed, as persisted in the manifest file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallManifest {
    /// The Ghidra install, when calxgloss made one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ghidra: Option<ManagedInstall>,
    /// The GhidraMCP extension, when calxgloss installed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<ManagedPlugin>,
}

impl InstallManifest {
    /// Whether the Ghidra install at `path` is the one calxgloss installed.
    ///
    /// Paths are compared canonically where possible, so a symlinked prefix
    /// still recognises its own install as managed.
    pub fn is_managed_ghidra(&self, path: &Path) -> bool {
        self.ghidra
            .as_ref()
            .is_some_and(|managed| same_path(&managed.path, path))
    }
}

/// The manifest path under a user's local state dir.
pub fn manifest_path(state_dir: &Path) -> PathBuf {
    state_dir.join("calxgloss").join("ghidra-install.json")
}

/// Load the manifest; a missing or unreadable file is an empty manifest.
pub fn load_manifest(path: &Path) -> InstallManifest {
    match load_json::<InstallManifest>(path) {
        Ok(manifest) => manifest,
        Err(PersistError::NotFound { .. }) => {
            debug!(path = %path.display(), "No Ghidra install manifest");
            InstallManifest::default()
        }
        Err(source) => {
            warn!(path = %path.display(), error = %source, "The Ghidra install manifest is unreadable; treating every install as user-managed");
            InstallManifest::default()
        }
    }
}

/// Write the manifest, creating its directory. A failure is logged, not
/// returned: the installs it describes already work, and losing the
/// bookkeeping must not fail the command that made them.
pub fn save_manifest(path: &Path, manifest: &InstallManifest) {
    if let Err(source) = save_json(path, manifest) {
        warn!(path = %path.display(), error = %source, "Could not write the Ghidra install manifest");
    }
}

/// Canonical equality with a raw fallback for paths that do not exist.
fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_keeps_both_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = manifest_path(dir.path());
        let manifest = InstallManifest {
            ghidra: Some(ManagedInstall {
                version: "12.1.2".into(),
                path: "/state/calxgloss/ghidra/ghidra_12.1.2_PUBLIC".into(),
            }),
            plugin: Some(ManagedPlugin {
                version: Some("6.0.0".into()),
                built_for: "12.1.2".into(),
                path: "/config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/GhidraMCP".into(),
            }),
        };
        save_manifest(&path, &manifest);
        assert_eq!(load_manifest(&path), manifest);
    }

    #[test]
    fn test_a_missing_or_corrupt_manifest_is_empty_not_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = manifest_path(dir.path());
        assert_eq!(load_manifest(&path), InstallManifest::default());
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, "not json at all").expect("write junk");
        assert_eq!(load_manifest(&path), InstallManifest::default());
    }

    #[test]
    fn test_managed_recognition_follows_the_recorded_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let install = dir.path().join("ghidra_12.1.2_PUBLIC");
        std::fs::create_dir_all(&install).expect("create install");
        let manifest = InstallManifest {
            ghidra: Some(ManagedInstall {
                version: "12.1.2".into(),
                path: install.clone(),
            }),
            plugin: None,
        };
        assert!(manifest.is_managed_ghidra(&install));
        assert!(!manifest.is_managed_ghidra(&dir.path().join("ghidra_11.1.2_PUBLIC")));
        // An empty manifest records nothing, so nothing is managed.
        assert!(!InstallManifest::default().is_managed_ghidra(&install));
    }

    #[test]
    fn test_the_manifest_path_is_the_documented_one() {
        assert_eq!(
            manifest_path(Path::new("/home/u/.local/share")),
            Path::new("/home/u/.local/share/calxgloss/ghidra-install.json")
        );
    }
}

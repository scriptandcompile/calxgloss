//! Dependency checking — shim layer branch resolution.
//!
//! Builds and validates dependency graphs for translation units of work.
//! Given a DLL name and classification, the checker determines which
//! shim layer and PAL trait branches must be merged into `main` before
//! a function translation branch can be safely created.
//!
//! # Dependency Rules
//!
//! | DLL Category | Required Dependencies |
//! |-------------|----------------------|
//! | `MicrosoftSdk` | Shim layer branch (e.g. `re/shim/wgpu`) |
//! | `KnownThirdParty` | Shim layer branch (e.g. `re/shim/fmod-rs`) |
//! | `WindowsOs` | No shim deps — PAL uses std lib directly |
//! | `ProjectSpecific` | No shim deps — pure RE target |
//! | `UnknownThirdParty` | No shim deps — treat as opaque |
//! | `RuntimeLibrary` | No shim deps — skip during translation |

use std::collections::HashMap;

use calxgloss_types::DllCategory;
use git2::Repository;

/// Encodes the mapping from DLL names to their required shim layer crates.
///
/// This is the canonical lookup used by [`DependencyChecker`] to determine
/// what shim branches must be merged before a function branch for a given DLL
/// can be safely created.
///
/// The mapping covers all Microsoft SDK and known third-party DLLs that have
/// Rust crate equivalents but need a shim layer for API compatibility.
///
/// # Examples
///
/// | DLL | Shim crate |
/// |-----|-----------|
/// | `d3d9.dll` | `wgpu` |
/// | `d3d11.dll` | `wgpu` |
/// | `fmod.dll` | `fmod-rs` |
/// | `openal32.dll` | `cpal` |
#[derive(Debug, Clone, Default)]
pub struct ShimDependencyMap(HashMap<String, String>);

impl ShimDependencyMap {
    /// Creates a new shim dependency map populated with all known mappings.
    pub fn new() -> Self {
        let mut map = HashMap::new();
        // DirectX → wgpu
        map.insert("d3d9.dll".to_string(), "wgpu".to_string());
        map.insert("d3d10.dll".to_string(), "wgpu".to_string());
        map.insert("d3d10_1.dll".to_string(), "wgpu".to_string());
        map.insert("d3d11.dll".to_string(), "wgpu".to_string());
        map.insert("d3d12.dll".to_string(), "wgpu".to_string());
        map.insert("dxgi.dll".to_string(), "wgpu".to_string());
        // Audio → cpal / fmod-rs
        map.insert("fmod.dll".to_string(), "fmod-rs".to_string());
        map.insert("fmodL.dll".to_string(), "fmod-rs".to_string());
        map.insert("openal32.dll".to_string(), "cpal".to_string());
        // 2D graphics → tiny-skia
        map.insert("d2d1.dll".to_string(), "tiny-skia".to_string());
        map.insert("dwrite.dll".to_string(), "skrifa".to_string());
        // UI frameworks
        map.insert("qt5_core.dll".to_string(), "iced".to_string());
        map.insert("qt5_gui.dll".to_string(), "iced".to_string());
        map.insert("qt5_widgets.dll".to_string(), "iced".to_string());
        // Math / geometry
        map.insert("gdi32.dll".to_string(), "tiny-skia".to_string());
        map.insert("gdiplus.dll".to_string(), "tiny-skia".to_string());
        Self(map)
    }

    /// Returns the shim crate name for a DLL, if known.
    pub fn get(&self, dll: &str) -> Option<&str> {
        self.0.get(dll).map(|s| s.as_str())
    }
}

/// Result of a dependency check before branch creation.
#[derive(Debug, Clone, Default)]
pub struct DependencyCheckResult {
    /// All required dependency branch names.
    pub required: Vec<String>,
    /// Dependencies that are already merged into main.
    pub satisfied: Vec<String>,
    /// Dependencies that are NOT yet merged (unblocked predecessors).
    pub unmet: Vec<String>,
}

impl DependencyCheckResult {
    /// Returns `true` if all dependencies are satisfied.
    pub fn is_complete(&self) -> bool {
        self.unmet.is_empty()
    }

    /// Returns `true` if there are unmet dependencies.
    pub fn has_unmet(&self) -> bool {
        !self.unmet.is_empty()
    }
}

/// Controls how branch creation handles dependency checking.
///
/// - `Skip` — no dependency checking (default, backwards-compatible).
/// - `Warn` — check dependencies but only log a warning if unmet. The branch
///   is still created.
/// - `Enforce` — block branch creation when dependencies are unmet. The caller
///   must resolve dependencies first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchCreationPolicy {
    /// No dependency checking.
    Skip,
    /// Check dependencies, warn on unmet, but allow branch creation.
    Warn(DependencyPolicy),
    /// Block branch creation when dependencies are unmet.
    Enforce(DependencyPolicy),
}

/// Dependency information passed to `create_branch` for enforcement.
///
/// Contains the DLL's classification and any crate-replacement info needed
/// to determine which shim layers and PAL traits are required before a
/// function translation can proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPolicy {
    /// The DLL's classification category.
    pub category: DllCategory,
    /// The recommended Rust crate name (for `CrateReplacement` DLLs).
    pub crate_replacement: Option<String>,
}

/// Builds and validates dependency graphs for translation units of work.
///
/// Given a DLL name and classification, the checker determines which
/// shim layer and PAL trait branches must be merged into `main` before
/// a function translation branch can be safely created.
///
/// # Example
///
/// ```
/// use calxgloss_git::DependencyChecker;
/// use calxgloss_types::DllCategory;
///
/// let checker = DependencyChecker::new();
/// let deps = checker.check("d3d9.dll", &DllCategory::MicrosoftSdk, Some("wgpu"));
/// assert_eq!(deps.required.len(), 1);
/// assert!(deps.required.iter().any(|s| s.contains("wgpu")));
/// ```
pub struct DependencyChecker {
    shim_map: ShimDependencyMap,
}

impl DependencyChecker {
    /// Creates a new dependency checker with the default shim mapping.
    pub fn new() -> Self {
        Self {
            shim_map: ShimDependencyMap::new(),
        }
    }

    /// Creates a new dependency checker with a custom shim mapping.
    pub fn with_shim_map(shim_map: ShimDependencyMap) -> Self {
        Self { shim_map }
    }

    /// Returns the expected shim branch name for a DLL.
    ///
    /// Returns `None` if the DLL has no known shim layer.
    pub fn shim_branch_name(&self, dll: &str) -> Option<String> {
        self.shim_map
            .get(dll)
            .map(|crate_name| format!("re/shim/{}", crate_name))
    }

    /// Checks all dependencies for a DLL's functions.
    ///
    /// Given the DLL name, category, and optional crate replacement, returns
    /// which dependencies must be merged before branch creation.
    ///
    /// For `MicrosoftSdk` and `KnownThirdParty` DLLs, this checks for a
    /// corresponding shim layer branch that has been merged into `main`.
    /// For all other categories, the required list is empty (no shim deps).
    ///
    /// # Arguments
    ///
    /// * `dll` — The DLL filename (e.g. `d3d9.dll`).
    /// * `category` — The DLL's classification category.
    /// * `crate_replacement` — The recommended Rust crate name, if any.
    pub fn check(
        &self,
        dll: &str,
        category: &DllCategory,
        crate_replacement: Option<&str>,
    ) -> DependencyCheckResult {
        let mut required = Vec::new();
        let satisfied = Vec::new();
        let mut unmet = Vec::new();

        // Only shim-layer categories require dependency checking
        match category {
            DllCategory::MicrosoftSdk | DllCategory::KnownThirdParty => {
                // Check the shim branch from the DLL-name lookup first
                if let Some(shim) = self.shim_branch_name(dll) {
                    required.push(shim.clone());
                    unmet.push(shim);
                } else if let Some(crate_name) = crate_replacement {
                    // Fallback: use the crate replacement name if no known mapping
                    let shim = format!("re/shim/{}", crate_name);
                    required.push(shim.clone());
                    unmet.push(shim);
                }
                // If both shim_branch_name and crate_replacement are available,
                // prefer the DLL-name lookup (it's more authoritative).
            }
            // WindowsOs, ProjectSpecific, UnknownThirdParty, RuntimeLibrary — no shim deps
            DllCategory::WindowsOs
            | DllCategory::ProjectSpecific
            | DllCategory::UnknownThirdParty
            | DllCategory::RuntimeLibrary => {}
        }

        DependencyCheckResult {
            required,
            satisfied,
            unmet,
        }
    }

    /// Resolves unmet dependencies by checking which ones are already merged.
    ///
    /// This is the full check-and-resolve loop: it populates `satisfied` and
    /// `unmet` by querying the repository to see which branches are already
    /// ancestors of `main`.
    ///
    /// # Arguments
    ///
    /// * `repo` — The Git repository to query.
    /// * `dll` — The DLL being translated.
    /// * `category` — The DLL's classification.
    /// * `crate_replacement` — Optional crate replacement name.
    pub fn resolve(
        &self,
        repo: &Repository,
        dll: &str,
        category: &DllCategory,
        crate_replacement: Option<&str>,
    ) -> DependencyCheckResult {
        let mut result = self.check(dll, category, crate_replacement);

        // Clear the placeholder unmet list and repopulate based on actual
        // merge status. The `check` method pre-fills `unmet` with the
        // required names; we replace them with accurate resolved values.
        result.unmet.clear();

        // Check each required dependency against main
        for dep in &result.required {
            if Self::is_branch_merged(repo, dep) {
                result.satisfied.push(dep.clone());
            } else {
                result.unmet.push(dep.clone());
            }
        }

        result
    }

    /// Checks whether a dependency branch is merged into `main`.
    fn is_branch_merged(repo: &Repository, branch_name: &str) -> bool {
        let main_ref = repo
            .find_branch("main", git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        let branch_ref = repo
            .find_branch(branch_name, git2::BranchType::Local)
            .ok()
            .and_then(|b| b.get().peel_to_commit().ok());

        match (main_ref, branch_ref) {
            (Some(main_commit), Some(branch_commit)) => repo
                .graph_ahead_behind(branch_commit.id(), main_commit.id())
                .map(|(ahead, _)| ahead == 0)
                .unwrap_or(false),
            _ => false,
        }
    }
}

impl Default for DependencyChecker {
    fn default() -> Self {
        Self::new()
    }
}

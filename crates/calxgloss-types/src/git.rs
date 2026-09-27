//! Git automation types for branch and commit tracking.
//!
//! This module defines types representing the Git branches and commits
//! created by the harness during translation, along with a constructor
//! for generating canonical branch names.

use serde::{Deserialize, Serialize};

use crate::error::TypesError;

/// Represents a Git branch created for a single translation attempt.
///
/// Branch names follow the convention `re/{dll_without_dotdll}/{function}v{N}`,
/// e.g., `re/game_logic/DrawSpritev1`. Each attempt to translate a function
/// gets its own branch, and failed branches are retained as historical record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitBranch {
    /// The full branch name (e.g., `re/game_logic/DrawSpritev1`).
    pub name: String,

    /// The DLL this translation targets.
    pub dll: String,

    /// The function name being translated.
    pub function: String,

    /// The attempt number (1-based). Retries increment this.
    pub attempt: u32,
}

/// Represents a commit within a translation branch.
///
/// Records the branch, commit message, SHA hash, and list of files changed.
/// Every translation attempt produces at least one commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommit {
    /// The branch this commit belongs to.
    pub branch: String,

    /// The structured commit message following the `re/<phase>/<unit>` convention.
    pub message: String,

    /// The full SHA-1 hash of the commit.
    pub hash: String,

    /// Files included in the commit (paths relative to repo root).
    pub files: Vec<String>,
}

impl GitBranch {
    /// Creates a new `GitBranch` with a canonical branch name.
    ///
    /// The branch name is constructed as `re/{dll_without_dotdll}/{function}v{attempt}`.
    /// Returns an error if `dll` or `function` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use calxgloss_types::GitBranch;
    ///
    /// let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).unwrap();
    /// assert_eq!(branch.name, "re/game_logic/DrawSpritev1");
    /// assert_eq!(branch.attempt, 1);
    /// ```
    pub fn new(dll: &str, function: &str, attempt: u32) -> Result<Self, TypesError> {
        if dll.is_empty() {
            return Err(TypesError::EmptyDllName);
        }
        if function.is_empty() {
            return Err(TypesError::EmptyFunctionName);
        }
        let branch_name = format!(
            "re/{}/{}v{}",
            dll.replace(".dll", ""),
            function,
            attempt
        );
        Ok(GitBranch {
            name: branch_name,
            dll: dll.to_string(),
            function: function.to_string(),
            attempt,
        })
    }

    /// Returns the branch name for display or use as a key.
    ///
    /// This is equivalent to accessing `.name` directly but provides
    /// a semantic name for cases where `.name` might be confusing.
    pub fn branch_display(&self) -> &str {
        &self.name
    }
}

//! Git automation types for branch and commit tracking.
//!
//! This module defines types representing the Git branches and commits
//! created by the harness during translation, along with a constructor
//! for generating canonical branch names.

use serde::{Deserialize, Serialize};

use crate::error::TypesError;
use crate::identity::BinaryIdentity;

/// Represents a Git branch created for a single translation attempt.
///
/// Branch names follow the convention `re/{file}/{function}v{N}`, where
/// `{file}` is the target binary's filename verbatim, extension included —
/// binary identity is never normalized (issue #68). E.g.,
/// `re/game_logic.dll/DrawSpritev1`. Each attempt to translate a function
/// gets its own branch, and failed branches are retained as historical record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitBranch {
    /// The full branch name (e.g., `re/game_logic.dll/DrawSpritev1`).
    pub name: String,

    /// The target binary this translation is for.
    pub binary: BinaryIdentity,

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
    /// The branch name is constructed as `re/{binary}/{function}v{attempt}`,
    /// with the binary identity used verbatim — the filename including its
    /// extension is the binary's identity (issue #68). Returns an error if
    /// the binary identity or function name is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use calxgloss_types::GitBranch;
    ///
    /// let branch = GitBranch::new("game_logic.dll", "DrawSprite", 1).unwrap();
    /// assert_eq!(branch.name, "re/game_logic.dll/DrawSpritev1");
    /// assert_eq!(branch.attempt, 1);
    /// ```
    pub fn new(
        binary: impl Into<BinaryIdentity>,
        function: &str,
        attempt: u32,
    ) -> Result<Self, TypesError> {
        let binary = binary.into();
        if binary.is_empty() {
            return Err(TypesError::EmptyBinaryName);
        }
        if function.is_empty() {
            return Err(TypesError::EmptyFunctionName);
        }
        let branch_name = format!("re/{binary}/{function}v{attempt}");
        Ok(GitBranch {
            name: branch_name,
            binary,
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

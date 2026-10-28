//! Git branch, commit, and merge automation for translation units of work.
//!
//! This crate provides [`git_manager::GitManager`]. It performs every Git
//! operation the translation pipeline needs. Every attempt gets its own
//! branch, following the naming convention `re/{binary}/{function}v{N}` —
//! N is the attempt number.
//!
//! # Branching Strategy
//!
//! - **Success**: the branch is created, its files are committed, and it is merged into `main`.
//! - **Failure**: the branch is created and its files committed; the branch is retained, never deleted.
//! - **Retries**: each fresh attempt gets a new branch with the next attempt number.
//!
//! # Commit Message Convention
//!
//! Every commit follows a structured format for traceability:
//!
//! ```text
//! re/translation/<function>: translate <function> to Rust
//!
//! Attempt: <N> of <total-attempts> (or "last" if not known)
//! Dependencies: <list of merged branches this depends on>
//! Tests: <count> baseline tests, <count> verification tests
//! Passing: <yes/no>
//! LLM model: <model name>
//! Context size: <N> tokens
//! ```

mod dependency;
pub mod git_manager;
pub mod helpers;

// Re-export public types from submodules
pub use dependency::{
    BranchCreationPolicy, DependencyCheckResult, DependencyChecker, DependencyPolicy,
    ShimDependencyMap,
};
pub use git_manager::{BranchResult, FailureRecord, GitManager, MergeResult, PatchRecord};

// Re-export types used by the public API
pub use calxgloss_types::{BinaryIdentity, DllCategory, GitBranch, GitCommit, TypesError};
/// Configuration for Git repository initialization.
#[derive(Debug, Clone)]
pub struct InitConfig {
    pub author_name: String,
    pub author_email: String,
    pub committer_name: Option<String>,
    pub committer_email: Option<String>,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            author_name: "Calxgloss".to_string(),
            author_email: "calxgloss@system".to_string(),
            committer_name: None,
            committer_email: None,
        }
    }
}

#[cfg(test)]
mod tests;

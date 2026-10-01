//! Git branch, commit, and merge automation for translation units of work.
//!
//! This crate provides [`git_manager::GitManager`], the central orchestrator
//! for all Git operations performed during the translation pipeline. Every
//! translation attempt gets its own branch following the naming convention
//! `re/{dll}/{function}v{N}`.
//!
//! # Branching Strategy
//!
//! - **Success**: Branch created → files committed → merged to `main`
//! - **Failure**: Branch created → files committed → branch retained (never deleted)
//! - **Retries**: New attempt gets a new branch with incremented version number
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

pub mod helpers;
pub mod git_manager;
mod dependency;

// Re-export public types from submodules
pub use dependency::{BranchCreationPolicy, DependencyChecker, DependencyCheckResult, DependencyPolicy, ShimDependencyMap};
pub use git_manager::{BranchResult, GitManager, MergeResult, PatchRecord};

// Re-export types used by the public API
pub use calxgloss_types::{DllCategory, GitBranch, GitCommit, TypesError};
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

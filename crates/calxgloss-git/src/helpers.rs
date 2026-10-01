//! Helper functions for Git operations.

use calxgloss_types::TypesError;
use git2::Repository;
use git2::Signature;

/// Create a Git signature from repo config or the provided InitConfig.
pub(super) fn make_signature(
    repo: &Repository,
    config: &super::InitConfig,
) -> Result<Signature<'static>, TypesError> {
    repo.signature()
        .or_else(|_| Signature::now(&config.author_name, &config.author_email))
        .map_err(|e| TypesError::InvalidBranchName(format!("Failed to create signature: {}", e)))
}

/// Format git2 status flags into a human-readable string.
pub fn format_flags(status: git2::Status) -> String {
    let mut flags = Vec::new();
    if status.is_index_new() {
        flags.push("added");
    }
    if status.is_index_modified() {
        flags.push("modified in index");
    }
    if status.is_index_deleted() {
        flags.push("deleted in index");
    }
    if status.is_wt_new() {
        flags.push("untracked");
    }
    if status.is_wt_modified() {
        flags.push("modified in working dir");
    }
    if status.is_wt_deleted() {
        flags.push("deleted in working dir");
    }
    if status.is_wt_renamed() {
        flags.push("renamed");
    }
    if status.is_conflicted() {
        flags.push("conflicted");
    }
    if flags.is_empty() {
        "unmodified".to_string()
    } else {
        flags.join(", ")
    }
}

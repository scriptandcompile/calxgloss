//! Dashboard data construction for the review report surfaces.
//!
//! This module builds [`ReviewDashboard`] instances from a Git repository's
//! branches, patch records, and baseline files, and derives the per-binary
//! readings the model carries. The web review payload serialises the model.
//! Nothing here renders to a terminal (issue #485).
//!
//! # Architecture
//!
//! - [`builder`] — [`DashboardBuilder`], [`parse_branch_name`]
//! - [`audit`] — [`derive_binary_unknown_ledgers`], [`binary_unknown_ledger`]
//! - [`conformance`] — [`derive_binary_conformance`], [`conformance_binaries`]
//! - [`scenarios`] — [`derive_scenario_statuses`]

pub mod audit;
pub mod builder;
pub mod conformance;
pub mod scenarios;

pub use audit::{binary_unknown_ledger, derive_binary_unknown_ledgers};
pub use builder::{DashboardBuilder, parse_branch_name};
pub use conformance::{conformance_binaries, derive_binary_conformance};
pub use scenarios::derive_scenario_statuses;

// Re-export types used in public API
pub use calxgloss_types::dashboard::{
    ReviewDashboard, ReviewStatus, Staleness, StatusCounts, UnitOfWork, WorkKind,
};

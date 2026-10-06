//! Dashboard data model for the review interface.
//!
//! This module defines the data types that power both the terminal review
//! dashboard and the future web review UI.
//! These are pure domain types — no web/HTTP dependencies.
//!
//! # Architecture
//!
//! - [`types`] — `WorkLevel`, `WorkKind`, `ReviewStatus`, `Staleness`
//! - [`work_unit`] — `UnitOfWork`
//! - [`graph`] — `DependencyNode`, `DependencyEdge`, `DependencyGraph`
//! - [`status`] — `StatusCounts`
//! - [`review`] — `ReviewDashboard`
//! - [`action`] — `ReviewAction`, `ReviewActionKind`

pub mod action;
pub mod graph;
pub mod review;
pub mod status;
pub mod types;
pub mod work_unit;

// Re-export at module level for internal use
pub use action::{ReviewAction, ReviewActionKind};
pub use graph::{DependencyEdge, DependencyGraph, DependencyNode};
pub use review::ReviewDashboard;
pub use status::StatusCounts;
pub use types::{ReviewStatus, Staleness, WorkKind, WorkLevel};
pub use work_unit::UnitOfWork;

#[cfg(test)]
mod tests;

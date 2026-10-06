//! Dashboard data construction and terminal rendering for the review dashboard.
//!
//! This module builds [`ReviewDashboard`] instances from a Git repository's
//! branches, patch records, and baseline files — then renders them as an
//! ANSI-colored text table suitable for terminal output.
//!
//! # Architecture
//!
//! - [`view`] — [`ViewTarget`], [`UnitViewData`], [`DiffSummary`], [`AttemptInfo`]
//! - [`builder`] — [`DashboardBuilder`], [`parse_branch_name`], [`branch_matches`]
//! - [`render`] — [`render_dashboard`], [`render_dashboard_follow`], [`render_unit_view`]

pub mod builder;
pub mod render;
pub mod view;

pub use builder::{DashboardBuilder, branch_matches, parse_branch_name};
pub use render::{render_dashboard, render_dashboard_follow, render_unit_view};
pub use view::{AttemptInfo, DiffSummary, UnitViewData, ViewTarget};

// Re-export types used in public API
pub use calxgloss_types::dashboard::{
    ReviewDashboard, ReviewStatus, Staleness, StatusCounts, UnitOfWork, WorkKind,
};

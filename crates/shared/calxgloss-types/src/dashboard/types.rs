//! Core enums for the dashboard data model.
//!
//! - [`WorkLevel`] — dependency priority ordering
//! - [`WorkKind`] — the kind of work
//! - [`ReviewStatus`] — the review status of a unit
//! - [`Staleness`] — how stale a unit is

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ============================================================
// WorkLevel — dependency priority ordering
// ============================================================

/// The processing level of a piece of work in the dependency graph.
///
/// Levels define the *phase* the work belongs to in the pipeline.
/// Work at a lower level must be processed before work at a
/// higher level, even when the DAG has no explicit edge between them.
///
/// This ordering implements the requirement from Phase 4 / Step 4.2:
///
/// ```text
/// shim layers → PAL traits → function translations → integration
/// ```
///
/// The level is used to break ties in topological sorting: when two
/// units have the same topological depth, the one at the lower level
/// is returned first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum WorkLevel {
    /// DLL classification — roots of the dependency graph, no dependencies.
    #[default]
    DllClassification,
    /// Shim layer — translates the original DLL's API surface to a Rust crate's API.
    ShimLayer,
    /// PAL trait — platform abstraction layer trait implementation.
    PalTrait,
    /// Test case addition — new test cases for verified functionality.
    TestCaseAddition,
    /// Function translation — reverse engineering a single function.
    FunctionTranslation,
    /// Integration step — merging translated code into the project.
    IntegrationStep,
    /// Bug fix — fixing issues discovered during verification.
    BugFix,
}

impl WorkLevel {
    /// Returns a short human-readable label for this level.
    pub fn label(&self) -> &'static str {
        match self {
            WorkLevel::DllClassification => "classify",
            WorkLevel::ShimLayer => "shim",
            WorkLevel::PalTrait => "pal",
            WorkLevel::TestCaseAddition => "test",
            WorkLevel::FunctionTranslation => "func",
            WorkLevel::IntegrationStep => "integrate",
            WorkLevel::BugFix => "fix",
        }
    }
}

impl std::fmt::Display for WorkLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ============================================================
// WorkKind — the kind of work
// ============================================================

/// The kind of work tracked in the review dashboard.
///
/// Only [`WorkKind::FunctionTranslation`] is a *unit of work* in the
/// glossary sense (one function or struct definition, delivered as one
/// commit); the other kinds are the supporting work — classification,
/// shim layers, PAL traits, test cases, integration, bug fixes — that
/// the pipeline schedules and reviews alongside units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkKind {
    /// DLL classification — categorizing a DLL.
    DllClassification,
    /// Shim layer generation — creating a shim for a crate-replacement DLL.
    ShimLayer,
    /// Function translation — reverse engineering a single function.
    FunctionTranslation,
    /// Test case addition — adding test cases for verified functionality.
    TestCaseAddition,
    /// PAL trait — platform abstraction layer trait implementation.
    PalTrait,
    /// Integration step — merging translated code into the project.
    IntegrationStep,
    /// Bug fix — fixing issues discovered during verification.
    BugFix,
}

impl WorkKind {
    /// Maps a work kind to its processing level.
    pub fn level(&self) -> WorkLevel {
        match self {
            WorkKind::DllClassification => WorkLevel::DllClassification,
            WorkKind::ShimLayer => WorkLevel::ShimLayer,
            WorkKind::PalTrait => WorkLevel::PalTrait,
            WorkKind::TestCaseAddition => WorkLevel::TestCaseAddition,
            WorkKind::FunctionTranslation => WorkLevel::FunctionTranslation,
            WorkKind::IntegrationStep => WorkLevel::IntegrationStep,
            WorkKind::BugFix => WorkLevel::BugFix,
        }
    }
}

impl std::fmt::Display for WorkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkKind::DllClassification => write!(f, "DLL Classification"),
            WorkKind::ShimLayer => write!(f, "Shim Layer"),
            WorkKind::FunctionTranslation => write!(f, "Function Translation"),
            WorkKind::TestCaseAddition => write!(f, "Test Case Addition"),
            WorkKind::PalTrait => write!(f, "PAL Trait"),
            WorkKind::IntegrationStep => write!(f, "Integration Step"),
            WorkKind::BugFix => write!(f, "Bug Fix"),
        }
    }
}

// ============================================================
// ReviewStatus — the review status of a unit
// ============================================================

/// The current status of a unit of work in the review process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewStatus {
    /// The unit is queued and waiting to be processed.
    Queued,
    /// Translation is complete and awaiting human review.
    PendingReview,
    /// A human is currently reviewing this unit.
    InProgress,
    /// The unit has been accepted and merged to the main branch.
    Accepted,
    /// The unit was sent back to the LLM with reviewer comments.
    SendBack,
    /// A patch was requested for a specific issue.
    PatchRequested,
    /// The unit is blocked because one or more dependencies are not in a passing state.
    Blocked,
}

impl std::fmt::Display for ReviewStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewStatus::Queued => write!(f, "queued"),
            ReviewStatus::PendingReview => write!(f, "pending_review"),
            ReviewStatus::InProgress => write!(f, "in_progress"),
            ReviewStatus::Accepted => write!(f, "accepted"),
            ReviewStatus::SendBack => write!(f, "send_back"),
            ReviewStatus::PatchRequested => write!(f, "patch_requested"),
            ReviewStatus::Blocked => write!(f, "blocked"),
        }
    }
}

// ============================================================
// Staleness — how stale a unit is
// ============================================================

/// How stale a unit of work is, based on how long it has been pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Staleness {
    /// Unit is fresh (less than 24 hours old).
    Fresh,
    /// Unit has been pending ≥24 hours (warning — yellow highlight).
    Stale(Duration),
    /// Unit has been pending ≥48 hours (critical — red highlight).
    Critical(Duration),
}

impl Staleness {
    /// Computes staleness from a timestamp, using the given now-time.
    pub fn from_elapsed(now: DateTime<Utc>, updated_at: DateTime<Utc>) -> Self {
        let elapsed = now - updated_at;
        let threshold_stale = chrono::Duration::hours(24);
        let threshold_critical = chrono::Duration::hours(48);

        if elapsed >= threshold_critical {
            Staleness::Critical(elapsed.to_std().unwrap_or(Duration::ZERO))
        } else if elapsed >= threshold_stale {
            Staleness::Stale(elapsed.to_std().unwrap_or(Duration::ZERO))
        } else {
            Staleness::Fresh
        }
    }

    /// Returns true if this unit is stale or critical.
    pub fn is_stale(&self) -> bool {
        matches!(self, Staleness::Stale(_) | Staleness::Critical(_))
    }

    /// Returns the elapsed duration if stale or critical, None if fresh.
    pub fn elapsed(&self) -> Option<Duration> {
        match self {
            Staleness::Fresh => None,
            Staleness::Stale(d) | Staleness::Critical(d) => Some(*d),
        }
    }
}

impl std::fmt::Display for Staleness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Staleness::Fresh => write!(f, "fresh"),
            Staleness::Stale(d) => write!(f, "stale ({})", fmt_duration(*d)),
            Staleness::Critical(d) => write!(f, "critical ({})", fmt_duration(*d)),
        }
    }
}

fn fmt_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

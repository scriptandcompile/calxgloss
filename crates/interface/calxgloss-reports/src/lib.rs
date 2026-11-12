//! The model behind the review report surfaces — and nothing else.
//!
//! This crate builds the shared review dashboard. It derives the per-binary
//! readings the model carries — the unknown ledger, the conformance verdict,
//! and the scenario status — fresh from the filed documents on every build.
//! The web review payload serialises that model; no line here writes to a
//! terminal (issue #485). The terminal dashboard renderer, the unit-view
//! loader and its target-matching machinery, the acceptance-prompt flow,
//! and this crate's ANSI colour set are gone with the surfaces that used
//! them (issues #481, #484).
//!
//! # Architecture
//!
//! - [`dashboard`] — the dashboard build and the model derivations beside it
//! - [`verification_receipt_markdown`] — Render a *verification receipt*'s
//!   human twin (re-exported from the record's owning crate)

pub mod dashboard;

/// Human rendering of a *verification receipt* at the review surface.
///
/// The rendering is owned by the record itself in `calxgloss-types` —
/// the document renders its own human twin, so the pair's facts can
/// never drift from its JSON authority — and re-exported here beside
/// this crate's other human renderings, so a reader at the report
/// surface imports it from one place.
pub use calxgloss_types::verification_receipt_markdown;

//! Confidence scoring and conflict resolution.
//!
//! The confidence *score* itself is the shared [`calxgloss_types::Confidence`]
//! type (a 0–100 value) now that every engine rates evidence the same way.
//!
//! This module will provide the rest of the confidence model used by every
//! detector: score composition per inference method, configurable
//! thresholds, and highest-confidence-wins resolution when several
//! detectors infer different types for the same parameter.
//!
//! [`calxgloss_types::Confidence`]: calxgloss_types::Confidence

//! Confidence scoring and conflict resolution.
//!
//! This module will provide the shared confidence model used by every
//! detector: score composition per detection method, configurable
//! thresholds, and highest-confidence-wins resolution when several
//! detectors hint at different algorithms for the same function.

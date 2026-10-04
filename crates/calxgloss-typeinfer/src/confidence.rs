//! Confidence scoring and conflict resolution.
//!
//! This module will provide the shared confidence model used by every
//! detector: score composition per inference method, configurable
//! thresholds, and highest-confidence-wins resolution when several
//! detectors infer different types for the same parameter.

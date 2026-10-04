//! A shared confidence score for recovered and inferred evidence.
//!
//! The recovery and inference engines all rate how strongly their evidence
//! supports a finding — a string-inferred struct, a propagated parameter type —
//! on the same 0–100 scale, and they all resolve competing findings by keeping
//! the highest score. That score is the same concept in every crate, so it is a
//! named type here rather than a bare `u8` restated at each site.
//!
//! Note this is the *evidence* confidence (0–100). The fault and progress
//! diagnosis scores are a separate 0–10 scale and deliberately stay `u8`.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A confidence score on the 0–100 scale used by the recovery and inference
/// engines.
///
/// The value is clamped to `0..=100` on construction so a score can never
/// exceed the scale its thresholds and reports assume. It serializes as a plain
/// number (`#[serde(transparent)]`), so persisted documents keep the same shape
/// as a bare `u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Confidence(u8);

impl Confidence {
    /// The highest score on the scale.
    pub const MAX: u8 = 100;

    /// A score of `value`, clamped to [`MAX`](Self::MAX).
    pub const fn new(value: u8) -> Self {
        Confidence(if value > Self::MAX { Self::MAX } else { value })
    }

    /// The raw score, 0–100.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Whether the score reaches `threshold` (a bare 0–100 number).
    pub fn at_least(self, threshold: u8) -> bool {
        self.0 >= threshold
    }
}

impl From<u8> for Confidence {
    fn from(value: u8) -> Self {
        Confidence::new(value)
    }
}

impl From<Confidence> for u8 {
    fn from(confidence: Confidence) -> Self {
        confidence.0
    }
}

// Compare directly against a bare 0–100 number so thresholds and detector
// constants stay plain `u8` at their call sites.
impl PartialEq<u8> for Confidence {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u8> for Confidence {
    fn partial_cmp(&self, other: &u8) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_score_is_clamped_to_the_scale() {
        assert_eq!(Confidence::new(150).value(), Confidence::MAX);
        assert_eq!(Confidence::new(79).value(), 79);
    }

    #[test]
    fn scores_order_by_their_value() {
        assert!(Confidence::new(70) > Confidence::new(50));
        assert_eq!(Confidence::new(70), Confidence::new(70));
    }

    #[test]
    fn a_score_compares_against_a_bare_number() {
        assert!(Confidence::new(79) >= 40);
        assert_eq!(Confidence::new(79), 79);
    }

    #[test]
    fn a_score_converts_to_and_from_a_number() {
        assert_eq!(u8::from(Confidence::new(55)), 55);
        assert_eq!(Confidence::from(55).value(), 55);
    }

    #[test]
    fn a_score_serializes_as_a_plain_number() {
        let json = serde_json::to_string(&Confidence::new(79)).unwrap();
        assert_eq!(json, "79");
        let back: Confidence = serde_json::from_str("79").unwrap();
        assert_eq!(back, Confidence::new(79));
    }
}

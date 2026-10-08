//! Context tier selection for LLM prompt construction.
//!
//! This module defines [`ContextTier`] — the five context tiers that determine
//! how much information the translation pipeline sends to the LLM for a given
//! function. The goal is to minimize token usage by starting with the smallest
//! context that can do the job, and escalating only when lower tiers fail.
//!
//! # Tiers
//!
//! | Tier | Name | Context Sent |
//! |------|------|-------------|
//! | 0 | `Signature` | Function name, signature, call graph neighbors |
//! | 1 | `Disassembly` | Full disassembly + Ghidra pseudo-C + type info |
//! | 2 | `WithTests` | Tier 1 + baseline test results + failing test cases |
//! | 3 | `ModuleContext` | Tier 2 + neighboring functions + shared data structures |
//! | 4 | `FullModule` | Tier 3 + shim layer code + PAL trait definitions |
//!
//! # Selection Logic
//!
//! [`select_context_tier`] determines the starting tier from three signals:
//!
//! 1. **Function complexity** — from [`crate::FunctionComplexity`]
//! 2. **API call count** — number of distinct Windows API calls
//! 3. **Previous success rate** — historical pass rate for similar functions
//!
//! The default starting tier is computed at the beginning of a translation
//! run (no prior data). On failure, the tier is escalated automatically
//! by the translation pipeline's retry loop.

use serde::{Deserialize, Serialize};

/// The context tier to send to the LLM for a function translation.
///
/// Each tier is a superset of the previous one. The pipeline starts at the
/// minimum viable tier and escalates on failure.
///
/// # Tier descriptions
///
/// - **Signature** — Only the function name, signature, and call graph
///   neighbors. Suitable for trivial functions where the LLM can reason from
///   the decompiler's pseudo-C alone. Named for what it sends, not for a
///   stub: in this codebase a stub is a mock that returns default values
///   without the real action (see the pipeline glossary).
/// - **Disassembly** — Full disassembly, decompiler output, and type
///   information. The LLM gets the raw instructions plus Ghidra's
///   type-inferred signature.
/// - **WithTests** — Everything in `Disassembly`, plus baseline test inputs
///   (and failing test details if retrying). This gives the LLM concrete
///   behavior to match.
/// - **ModuleContext** — Tier 2 plus neighboring function disassembly and
///   shared data structures. Needed when the function has complex inter-
///   function dependencies or operates on shared state.
/// - **FullModule** — Tier 3 plus shim-layer code and PAL trait definitions.
///   Used when translating functions that call through shim layers (e.g.,
///   DirectX → wgpu) and need the full translation-layer context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextTier {
    /// Tier 0 — Name and signature only.
    Signature,
    /// Tier 1 — Disassembly + decompiler + type info.
    Disassembly,
    /// Tier 2 — Tier 1 + baseline tests.
    WithTests,
    /// Tier 3 — Tier 2 + module context (neighbors, data structures).
    ModuleContext,
    /// Tier 4 — Tier 3 + shim layer + PAL traits.
    FullModule,
}

impl ContextTier {
    /// Returns the tier number (0–4).
    pub fn number(self) -> u32 {
        match self {
            Self::Signature => 0,
            Self::Disassembly => 1,
            Self::WithTests => 2,
            Self::ModuleContext => 3,
            Self::FullModule => 4,
        }
    }

    /// Returns the tier label for logging and display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Disassembly => "disassembly",
            Self::WithTests => "with_tests",
            Self::ModuleContext => "module_context",
            Self::FullModule => "full_module",
        }
    }

    /// Returns the human-readable tier description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Signature => "Function name, signature, call graph neighbors",
            Self::Disassembly => "Full disassembly + Ghidra pseudo-C + type info",
            Self::WithTests => "Tier 1 + baseline test results + failing test cases",
            Self::ModuleContext => "Tier 2 + neighboring functions + shared data structures",
            Self::FullModule => "Tier 3 + shim layer code + PAL trait definitions",
        }
    }

    /// Escalate to the next tier. Returns `None` if already at the maximum tier.
    pub fn escalate(self) -> Option<Self> {
        match self {
            Self::Signature => Some(Self::Disassembly),
            Self::Disassembly => Some(Self::WithTests),
            Self::WithTests => Some(Self::ModuleContext),
            Self::ModuleContext => Some(Self::FullModule),
            Self::FullModule => None, // already at max
        }
    }

    /// Resolve a tier from its [`label`](Self::label) string (as stored in
    /// token-usage entries). Returns `None` for unknown labels.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "signature" => Some(Self::Signature),
            "disassembly" => Some(Self::Disassembly),
            "with_tests" => Some(Self::WithTests),
            "module_context" => Some(Self::ModuleContext),
            "full_module" => Some(Self::FullModule),
            _ => None,
        }
    }

    /// Resolve a tier from its [`number`](Self::number) (0–4).
    /// Returns `None` for out-of-range numbers.
    pub fn from_number(number: u32) -> Option<Self> {
        match number {
            0 => Some(Self::Signature),
            1 => Some(Self::Disassembly),
            2 => Some(Self::WithTests),
            3 => Some(Self::ModuleContext),
            4 => Some(Self::FullModule),
            _ => None,
        }
    }
}

impl std::fmt::Display for ContextTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "T{} ({})", self.number(), self.label())
    }
}

/// Success rate for a function or API category.
///
/// Tracks how many attempts succeeded out of the total, used to inform
/// tier selection for future translations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessRate {
    /// Number of successful attempts.
    pub successes: u32,
    /// Total number of attempts.
    pub total: u32,
}

impl SuccessRate {
    /// Create a new success rate.
    pub fn new(successes: u32, total: u32) -> Self {
        Self {
            successes: successes.min(total),
            total,
        }
    }

    /// Returns the pass rate as a floating-point value in [0.0, 1.0].
    /// Returns `1.0` if total is zero (no data yet).
    pub fn rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0; // No data — assume optimal to avoid penalizing new functions
        }
        self.successes as f64 / self.total as f64
    }

    /// Returns true if we have no historical data.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
}

/// Select the starting context tier for a function translation.
///
/// This is the core tier-selection logic. It uses three signals to pick
/// the minimum tier that should work:
///
/// 1. **Function complexity** — from the disassembly analysis. More
///    complex functions start at a higher tier to avoid wasting tokens
///    on failed low-tier attempts.
/// 2. **API call count** — the number of distinct Windows API calls
///    identified in the disassembly. Functions with many API calls
///    (especially cross-category) need more context.
/// 3. **Previous success rate** — if this function (or one with similar
///    complexity) has been translated before, the success rate influences
///    the starting tier. High success rates allow starting lower; low
///    rates push the starting tier up.
///
/// # Arguments
///
/// * `complexity` — The function's complexity classification.
/// * `api_call_count` — Number of distinct Windows API calls in this function.
/// * `success_rate` — Historical pass rate for similar functions (empty = no data).
///
/// # Returns
///
/// The minimum context tier that should be sufficient for translation.
/// The actual prompt content is assembled by the pipeline based on this tier.
pub fn select_context_tier(
    complexity: &crate::FunctionComplexity,
    api_call_count: usize,
    success_rate: SuccessRate,
) -> ContextTier {
    // Map complexity to a base tier index
    let base_tier = match complexity {
        crate::FunctionComplexity::Minimal => 0,  // Signature
        crate::FunctionComplexity::Standard => 1, // Disassembly
        crate::FunctionComplexity::Rich => 2,     // WithTests
        crate::FunctionComplexity::Detailed => 3, // ModuleContext
    };

    // Start with a default tier based on complexity
    let mut tier: i32 = base_tier;

    // Adjust for API call count
    if api_call_count > 5 {
        tier = (tier + 1).min(4);
    }

    // Adjust for success rate: if we have historical data and the rate is
    // low, bump the tier. If high, allow staying lower.
    if !success_rate.is_empty() {
        let rate = success_rate.rate();
        if rate < 0.5 {
            // Poor success rate — escalate starting tier
            tier = (tier + 1).min(4);
        } else if rate >= 0.8 {
            // Strong success rate — allow dropping one tier if we're not at the minimum
            if tier > 0 {
                tier = tier.saturating_sub(1);
            }
        }
    }

    // Clamp to valid range and return
    match tier {
        0 => ContextTier::Signature,
        1 => ContextTier::Disassembly,
        2 => ContextTier::WithTests,
        3 => ContextTier::ModuleContext,
        _ => ContextTier::FullModule,
    }
}

/// Record a translation result for future tier selection decisions.
///
/// Call this after a translation attempt completes (success or failure)
/// to update the success rate tracking. The returned [`SuccessRate`] can
/// be passed to [`select_context_tier`] on the next translation of a
/// similar function.
///
/// # Arguments
///
/// * `previous` — The prior success rate (empty on first use).
/// * `succeeded` — Whether this attempt passed verification.
///
/// # Returns
///
/// The updated success rate.
pub fn record_translation_result(previous: SuccessRate, succeeded: bool) -> SuccessRate {
    let mut rate = previous;
    rate.total += 1;
    if succeeded {
        rate.successes += 1;
    }
    rate
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FunctionComplexity;

    #[test]
    fn test_context_tier_numbers() {
        assert_eq!(ContextTier::Signature.number(), 0);
        assert_eq!(ContextTier::Disassembly.number(), 1);
        assert_eq!(ContextTier::WithTests.number(), 2);
        assert_eq!(ContextTier::ModuleContext.number(), 3);
        assert_eq!(ContextTier::FullModule.number(), 4);
    }

    #[test]
    fn test_context_tier_labels() {
        assert_eq!(ContextTier::Signature.label(), "signature");
        assert_eq!(ContextTier::Disassembly.label(), "disassembly");
        assert_eq!(ContextTier::WithTests.label(), "with_tests");
        assert_eq!(ContextTier::ModuleContext.label(), "module_context");
        assert_eq!(ContextTier::FullModule.label(), "full_module");
    }

    #[test]
    fn test_context_tier_from_label_round_trips() {
        for tier in [
            ContextTier::Signature,
            ContextTier::Disassembly,
            ContextTier::WithTests,
            ContextTier::ModuleContext,
            ContextTier::FullModule,
        ] {
            assert_eq!(ContextTier::from_label(tier.label()), Some(tier));
        }
        assert_eq!(ContextTier::from_label("nonsense"), None);
        assert_eq!(ContextTier::from_label(""), None);
    }

    #[test]
    fn test_context_tier_from_number_round_trips() {
        for tier in [
            ContextTier::Signature,
            ContextTier::Disassembly,
            ContextTier::WithTests,
            ContextTier::ModuleContext,
            ContextTier::FullModule,
        ] {
            assert_eq!(ContextTier::from_number(tier.number()), Some(tier));
        }
        assert_eq!(ContextTier::from_number(5), None);
        assert_eq!(ContextTier::from_number(u32::MAX), None);
    }

    #[test]
    fn test_context_tier_escalation() {
        assert_eq!(
            ContextTier::Signature.escalate(),
            Some(ContextTier::Disassembly)
        );
        assert_eq!(
            ContextTier::Disassembly.escalate(),
            Some(ContextTier::WithTests)
        );
        assert_eq!(
            ContextTier::WithTests.escalate(),
            Some(ContextTier::ModuleContext)
        );
        assert_eq!(
            ContextTier::ModuleContext.escalate(),
            Some(ContextTier::FullModule)
        );
        assert_eq!(ContextTier::FullModule.escalate(), None);
    }

    #[test]
    fn test_success_rate_rate_empty() {
        let rate = SuccessRate::new(0, 0);
        assert_eq!(rate.rate(), 1.0); // No data = assume optimal
        assert!(rate.is_empty());
    }

    #[test]
    fn test_success_rate_rate_perfect() {
        let rate = SuccessRate::new(5, 5);
        assert_eq!(rate.rate(), 1.0);
        assert!(!rate.is_empty());
    }

    #[test]
    fn test_success_rate_rate_half() {
        let rate = SuccessRate::new(3, 6);
        assert!((rate.rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_translation_result_success() {
        let rate = SuccessRate::new(0, 0);
        let updated = record_translation_result(rate, true);
        assert_eq!(updated.successes, 1);
        assert_eq!(updated.total, 1);
        assert!((updated.rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_translation_result_failure() {
        let rate = SuccessRate::new(0, 0);
        let updated = record_translation_result(rate, false);
        assert_eq!(updated.successes, 0);
        assert_eq!(updated.total, 1);
        assert!((updated.rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_translation_result_accumulates() {
        let rate = SuccessRate::new(0, 0);
        let rate = record_translation_result(rate, true);
        let rate = record_translation_result(rate, true);
        let rate = record_translation_result(rate, false);

        assert_eq!(rate.successes, 2);
        assert_eq!(rate.total, 3);
    }

    #[test]
    fn test_select_tier_minimal_no_apis_no_history() {
        let rate = SuccessRate::new(0, 0);
        let tier = select_context_tier(&FunctionComplexity::Minimal, 0, rate);
        assert_eq!(tier, ContextTier::Signature);
    }

    #[test]
    fn test_select_tier_standard_no_apis_no_history() {
        let rate = SuccessRate::new(0, 0);
        let tier = select_context_tier(&FunctionComplexity::Standard, 0, rate);
        assert_eq!(tier, ContextTier::Disassembly);
    }

    #[test]
    fn test_select_tier_rich_no_apis_no_history() {
        let rate = SuccessRate::new(0, 0);
        let tier = select_context_tier(&FunctionComplexity::Rich, 0, rate);
        assert_eq!(tier, ContextTier::WithTests);
    }

    #[test]
    fn test_select_tier_detailed_no_apis_no_history() {
        let rate = SuccessRate::new(0, 0);
        let tier = select_context_tier(&FunctionComplexity::Detailed, 0, rate);
        assert_eq!(tier, ContextTier::ModuleContext);
    }

    #[test]
    fn test_select_tier_bumps_for_many_apis() {
        let rate = SuccessRate::new(0, 0);
        // Minimal complexity but >10 API calls → bump one tier
        let tier = select_context_tier(&FunctionComplexity::Minimal, 12, rate);
        assert_eq!(tier, ContextTier::Disassembly);
    }

    #[test]
    fn test_select_tier_low_success_rate_bumps() {
        // Low success rate should bump the tier
        let rate = SuccessRate::new(1, 5); // 20% pass rate
        let tier = select_context_tier(&FunctionComplexity::Minimal, 0, rate);
        // Minimal base = 0, but low success rate bumps to 1
        assert_eq!(tier, ContextTier::Disassembly);
    }

    #[test]
    fn test_select_tier_high_success_rate_drops() {
        // High success rate allows dropping one tier
        let rate = SuccessRate::new(8, 10); // 80% pass rate
        let tier = select_context_tier(&FunctionComplexity::Standard, 0, rate);
        // Standard base = 1, high rate drops to 0
        assert_eq!(tier, ContextTier::Signature);
    }

    #[test]
    fn test_select_tier_capped_at_full_module() {
        let rate = SuccessRate::new(0, 0);
        // Detailed + many APIs should not exceed FullModule
        let tier = select_context_tier(&FunctionComplexity::Detailed, 15, rate);
        assert_eq!(tier, ContextTier::FullModule);
    }

    #[test]
    fn test_select_tier_serialization() {
        let tier = ContextTier::WithTests;
        let json = serde_json::to_string(&tier).unwrap();
        let deserialized: ContextTier = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, tier);
    }

    #[test]
    fn test_select_tier_success_rate_serialization() {
        let rate = SuccessRate::new(3, 5);
        let json = serde_json::to_string(&rate).unwrap();
        let deserialized: SuccessRate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, rate);
    }
}

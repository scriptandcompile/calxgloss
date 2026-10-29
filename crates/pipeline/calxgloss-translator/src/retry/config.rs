//! Retry and translation result types.

/// Configuration for the retry loop.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of total attempts (including the first).
    pub max_attempts: u32,

    /// The strategy to use on the first retry attempt.
    pub retry_strategy: RetryStrategy,

    /// Whether to escalate context on subsequent failures.
    pub escalate_on_failure: bool,

    /// Optional cap on context escalation (issue #93, W2.5). When set, the
    /// retry loop never selects a context tier above this one — automatic
    /// escalation stops at the cap. `None` means no cap (today's behaviour).
    pub max_context_tier: Option<calxgloss_types::ContextTier>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            retry_strategy: RetryStrategy::CompileFix,
            escalate_on_failure: true,
            max_context_tier: None,
        }
    }
}

/// The strategy for fixing a failed translation attempt.
///
/// The closed set lives in [`calxgloss_types::RetryStrategy`] — the same
/// enum the reviewer overrides store and the dashboard offers — and is
/// re-exported here so the retry loop's namespace stays flat.
pub use calxgloss_types::RetryStrategy;

/// The sequence of strategies to try when using auto mode.
///
/// Each strategy is tried in order; on failure the next one in the cycle is used.
pub const AUTO_STRATEGY_CYCLE: &[RetryStrategy] = &[
    RetryStrategy::CompileFix,
    RetryStrategy::TestFix,
    RetryStrategy::Escalate,
    RetryStrategy::EdgeCaseFix,
];

impl RetryConfig {
    /// The next context tier to escalate to, honoring the operator's
    /// `max_context_tier` cap (issue #93, W2.5). Returns `None` when the
    /// tier is already at the maximum tier or the cap blocks the step —
    /// escalation then stops at the current tier.
    pub fn next_tier_within_cap(
        &self,
        current: calxgloss_types::ContextTier,
    ) -> Option<calxgloss_types::ContextTier> {
        let next = current.escalate()?;
        if self
            .max_context_tier
            .is_some_and(|cap| next.number() > cap.number())
        {
            None
        } else {
            Some(next)
        }
    }

    /// The next strategy in the escalation ladder — the one owner of the
    /// order the two hand-rolled loop ladders used to each spell (issue
    /// #334). The order is [`AUTO_STRATEGY_CYCLE`]'s spelled body: step
    /// forward, cycle back at the end. `Default` is not in the cycle; it
    /// steps to the cycle's head, exactly as the old ladders spelled.
    /// Selection policy — the `escalate_on_failure` gate, the forced
    /// starting strategy, and the tier caps — stays loop-side; this owns
    /// only the step.
    pub fn next_strategy(&self, current: RetryStrategy) -> RetryStrategy {
        match AUTO_STRATEGY_CYCLE.iter().position(|s| *s == current) {
            Some(i) => AUTO_STRATEGY_CYCLE[(i + 1) % AUTO_STRATEGY_CYCLE.len()],
            None => AUTO_STRATEGY_CYCLE[0],
        }
    }
}

/// Details about a single translation attempt.
#[derive(Debug, Clone)]
pub struct TranslationAttempt {
    /// The attempt number (1-based).
    pub attempt: u32,

    /// The generated Rust code.
    pub rust_code: String,

    /// Whether this attempt compiled.
    pub compiled: bool,

    /// Compilation error messages, if any.
    pub compilation_errors: Vec<String>,

    /// Number of tests that passed.
    pub tests_passed: usize,

    /// Total number of tests.
    pub tests_total: usize,

    /// The failing test cases, if any.
    pub failed_tests: Vec<String>,

    /// The retry strategy used for this attempt (0 = initial, 1+ = retry).
    pub retry_strategy: String,

    /// Number of tokens the LLM used for this attempt, if reported.
    pub tokens_used: Option<usize>,

    /// The context tier used for this attempt's prompt (Tier 0–4).
    pub context_tier: Option<String>,
}

impl TranslationAttempt {
    /// Whether this attempt was successful: it compiled and either all its
    /// tests pass or it had no tests to run. A translation that fails to
    /// compile is never successful, regardless of test counts — otherwise the
    /// retry loop would treat broken code as done and never retry it.
    pub fn is_successful(&self) -> bool {
        self.compiled && (self.tests_passed == self.tests_total || self.tests_total == 0)
    }
}

/// The result of a retry loop.
#[derive(Debug, Clone)]
pub struct RetryResult {
    /// All attempts made, in order.
    pub attempts: Vec<TranslationAttempt>,

    /// Whether the final result is successful.
    pub success: bool,

    /// The successful translation code, if any.
    pub rust_code: Option<String>,

    /// The strategy that produced success, if any.
    pub success_strategy: Option<String>,

    /// The unknown records this ladder's own pruned decisions admitted
    /// (issue #372): one `retry_pruned` record per escalate rung the held
    /// report blocked, one `tier_refused` record per refused context-tier
    /// step, in the order the walk made the decisions and deduplicated by
    /// id — a later prune on the same family re-admits the same standing
    /// question. The records leave the ladder as evidence for the
    /// pipeline's ledger; nothing in this set feeds the walk itself, the
    /// ladder still owns which prompt runs.
    pub unknown_residue: Vec<calxgloss_types::UnknownRecord>,
}

impl Default for RetryResult {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryResult {
    /// Create a new retry result with no attempts.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
            success: false,
            rust_code: None,
            success_strategy: None,
            unknown_residue: Vec::new(),
        }
    }

    /// Append an attempt to the result.
    pub fn add_attempt(&mut self, attempt: TranslationAttempt) {
        if attempt.is_successful() {
            self.success = true;
            self.rust_code = Some(attempt.rust_code.clone());
            self.success_strategy = Some(attempt.retry_strategy.clone());
        }
        self.attempts.push(attempt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::ContextTier;

    // ─── Operator context-tier cap (issue #93, W2.5) ─────────────────

    /// Without a cap the tier walk behaves exactly as before: one step up
    /// until the maximum tier.
    #[test]
    fn tier_walk_without_cap_escalates_to_the_maximum() {
        let config = RetryConfig::default();
        assert_eq!(
            config.next_tier_within_cap(ContextTier::Signature),
            Some(ContextTier::Disassembly)
        );
        assert_eq!(
            config.next_tier_within_cap(ContextTier::FullModule),
            None,
            "the built-in maximum still ends the walk"
        );
    }

    /// An operator cap stops the walk at the cap — the retry loop may climb
    /// to it but never past it.
    #[test]
    fn tier_walk_stops_at_the_operator_cap() {
        let config = RetryConfig {
            max_context_tier: Some(ContextTier::Disassembly),
            ..RetryConfig::default()
        };
        assert_eq!(
            config.next_tier_within_cap(ContextTier::Signature),
            Some(ContextTier::Disassembly),
            "climbing to the cap is allowed"
        );
        assert_eq!(
            config.next_tier_within_cap(ContextTier::Disassembly),
            None,
            "the walk stops at the cap"
        );
    }

    /// A cap at or above the built-in maximum changes nothing.
    #[test]
    fn tier_cap_at_or_above_the_maximum_is_a_no_op() {
        let config = RetryConfig {
            max_context_tier: Some(ContextTier::FullModule),
            ..RetryConfig::default()
        };
        assert_eq!(
            config.next_tier_within_cap(ContextTier::ModuleContext),
            Some(ContextTier::FullModule)
        );
    }

    /// The strategy ladder's order is `AUTO_STRATEGY_CYCLE`'s spelled body,
    /// cycling back at the end — the single owner both old ladders collapsed
    /// into (#334), pinned by order.
    #[test]
    fn strategy_ladder_walks_the_auto_cycle_and_wraps_at_the_end() {
        let config = RetryConfig::default();
        let mut strategy = RetryStrategy::CompileFix;
        let mut walked = Vec::new();
        for _ in AUTO_STRATEGY_CYCLE {
            strategy = config.next_strategy(strategy);
            walked.push(strategy);
        }
        assert_eq!(
            walked,
            vec![
                RetryStrategy::TestFix,
                RetryStrategy::Escalate,
                RetryStrategy::EdgeCaseFix,
                RetryStrategy::CompileFix,
            ]
        );
    }

    /// `Default` enters the cycle at its head, exactly as both old
    /// hand-rolled ladders spelled it.
    #[test]
    fn strategy_ladder_enters_at_the_cycle_head_from_default() {
        let config = RetryConfig::default();
        assert_eq!(
            config.next_strategy(RetryStrategy::Default),
            RetryStrategy::CompileFix
        );
    }
}

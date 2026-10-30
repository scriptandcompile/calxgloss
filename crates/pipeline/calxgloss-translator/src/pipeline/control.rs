//! The pipeline's operator-control reads: the stop signal, pipeline and
//! per-binary pause, function scope, reviewer overrides, hints, and forced
//! strategies, the token budget and its accounting, and event emission.

use super::*;

impl TranslationPipeline {
    /// Whether the attached stop signal, if any, has been requested.
    pub(super) fn stop_requested(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| s.is_stopped())
    }

    /// Check the lifecycle control at a unit boundary (issue #90, W2.1).
    ///
    /// Returns `false` when the batch must end: `Stopping` (a stop was
    /// requested) or `Complete` (stop-current ended the run) halt after the
    /// unit in flight. A stop signal that arrives while the loop is held in
    /// a pause releases the hold the same way — shutting down must never
    /// wait on a paused run. Returns `true` when the next unit may start.
    pub(super) async fn control_allows_next_unit(&self) -> bool {
        let Some(control) = self.pipeline_control.as_ref() else {
            return true;
        };
        loop {
            match control.state() {
                PipelineState::Paused => {
                    if self.stop_requested() {
                        return false;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                state if state.is_halted() => return false,
                _ => return true,
            }
        }
    }

    /// Whether the operator has paused the batch's target binary (issue #219,
    /// part of #217).
    ///
    /// A run-level pause holds the loop at a unit boundary until the operator
    /// resumes it; a paused binary, by contrast, **ends** the batch at the
    /// next boundary — the batch returns instead of waiting, so the run can
    /// move on to another binary. The batch loops check this just before
    /// [`control_allows_next_unit`](Self::control_allows_next_unit), so the
    /// pause is honored at the boundary even while the run itself is on
    /// hold. With no scope handle attached, no binary is ever paused.
    pub(super) fn binary_paused(&self, binary: &str) -> bool {
        self.scope
            .as_ref()
            .is_some_and(|scope| scope.is_paused(binary))
    }

    /// Resolves once a cancellation has arrived for the named unit (issue
    /// #91, W2.2). With no cancellation handle attached it never resolves,
    /// so the `select!` in the batch loop simply never takes the abort branch.
    ///
    /// The poll interval is short (50 ms) because cancel-current exists to
    /// stop a runaway unit from spending tokens *now* — unlike a pause,
    /// which only matters at unit boundaries.
    pub(super) async fn wait_for_unit_cancel(&self, binary: &str, function: &str) {
        match self.unit_cancellation.as_ref() {
            None => std::future::pending::<()>().await,
            Some(cancellation) => loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if cancellation.is_cancelled_for(binary, function) {
                    break;
                }
            },
        }
    }

    /// Apply the operator's function scope and the reviewer's per-unit
    /// overrides when the queue is selected (issues #93, W2.5 and #96, W2.7).
    ///
    /// Skipped functions leave the plan before the first unit starts — they
    /// are never attempted — and priority functions sort ahead of the rest
    /// of the queue: the priority group keeps its relative order, and
    /// everything after it keeps its original order (a stable split). A
    /// reviewer override's skip flag removes its one unit the same way, so
    /// one hopeless function never blocks the rest of its binary's pass.
    /// With neither handle attached, the list passes through untouched.
    ///
    /// `name_of` reads the function name out of a queue item, so the same
    /// filtering works for plain name lists and call-graph plan entries.
    pub(super) fn apply_function_scope<T>(
        &self,
        binary: &str,
        items: Vec<T>,
        name_of: impl Fn(&T) -> &str,
    ) -> Vec<T> {
        // W2.7: reviewer-skipped units leave the plan at the same point in
        // the selection as operator-skipped functions.
        let items = match self.overrides.as_ref() {
            None => items,
            Some(overrides) => {
                let total = items.len();
                let kept: Vec<T> = items
                    .into_iter()
                    .filter(|item| !overrides.is_skipped(binary, name_of(item)))
                    .collect();
                let skipped = total - kept.len();
                if skipped > 0 {
                    info!(
                        binary,
                        skipped, "Override filter — reviewer-skipped units leave the queue plan"
                    );
                }
                kept
            }
        };
        let Some(scope) = self.scope.as_ref() else {
            return items;
        };
        let plan = scope.scope();
        if plan.skipped_functions.is_empty() && plan.priority_functions.is_empty() {
            return items;
        }
        let total = items.len();
        let kept: Vec<T> = items
            .into_iter()
            .filter(|item| !plan.is_skipped(binary, name_of(item)))
            .collect();
        let skipped = total - kept.len();
        if skipped > 0 {
            info!(
                binary,
                skipped, "Scope filter — skipped functions leave the queue plan"
            );
        }
        let (mut front, rest): (Vec<T>, Vec<T>) = kept
            .into_iter()
            .partition(|item| plan.is_priority(binary, name_of(item)));
        if !front.is_empty() {
            info!(
                binary,
                prioritized = front.len(),
                "Scope filter — priority functions sort ahead of the queue"
            );
        }
        front.extend(rest);
        front
    }

    /// Bound the retry config with the operator's constraints (issue #93,
    /// W2.5).
    ///
    /// `max_attempts` can only lower the configured attempt count (a
    /// constraint caps spending, it never raises the limit), and
    /// `max_context_tier` goes into [`RetryLoopCtx`](retry::RetryLoopCtx),
    /// where it caps automatic context tier escalation. With no scope
    /// handle attached the config passes through untouched.
    pub(super) fn constrained_retry_config(
        &self,
        config: &retry::RetryConfig,
    ) -> retry::RetryConfig {
        let Some(scope) = self.scope.as_ref() else {
            return config.clone();
        };
        let constraints = scope.constraints();
        let mut capped = config.clone();
        if let Some(max) = constraints.max_attempts {
            capped.max_attempts = capped.max_attempts.min(max);
        }
        capped.max_context_tier = match (capped.max_context_tier, constraints.max_context_tier) {
            (Some(existing), Some(cap)) => Some(if existing.number() <= cap.number() {
                existing
            } else {
                cap
            }),
            (existing, cap) => existing.or(cap),
        };
        capped
    }

    /// Whether the attached scope's token budget has been reached (issue
    /// #93). No handle, or no budget, means never reached — the batch runs
    /// on. Checked at unit boundaries, like the stop signal and the pause.
    pub(super) fn budget_exhausted(&self) -> bool {
        self.scope.as_ref().is_some_and(|s| s.budget_exhausted())
    }

    /// Add a completed unit's attempt tokens to the run's token budget
    /// (issue #93). An attempt that never reported a token count adds
    /// nothing.
    pub(super) fn record_unit_tokens(&self, result: &batch::FunctionResult) {
        let Some(scope) = self.scope.as_ref() else {
            return;
        };
        let spent: u64 = result
            .retry_result
            .attempts
            .iter()
            .filter_map(|a| a.tokens_used)
            .map(|t| t as u64)
            .sum();
        if spent > 0 {
            scope.record_tokens(spent);
        }
    }

    /// Send a progress event, if an event emitter is attached.
    pub(super) fn emit(&self, event: ProgressEvent) {
        if let Some(ref emitter) = self.events {
            let _ = emitter.emit(event);
        }
    }

    /// The function's C signature, as the decompiler worked it out.
    ///
    /// The reviewer's override record for a unit, when there is one (issue #96, W2.7).
    pub(super) fn unit_override(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_types::FunctionOverride> {
        self.overrides
            .as_ref()
            .and_then(|o| o.get(binary, function))
    }

    /// The context tier a reviewer forced for this unit, when there is one —
    /// the context builder uses it instead of the automatic choice.
    pub(super) fn forced_context_tier(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_types::ContextTier> {
        self.unit_override(binary, function)
            .and_then(|o| o.tier_override)
    }

    /// The retry strategy a reviewer forced for this unit, when there is
    /// one. The record's field is the shared
    /// [`calxgloss_types::RetryStrategy`] enum, so a stored value is always
    /// a real strategy — an unknown label was stopped at the override
    /// boundary (issue #120) and never reached the record.
    pub(super) fn forced_retry_strategy(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<retry::RetryStrategy> {
        self.unit_override(binary, function)
            .and_then(|o| o.retry_strategy_override)
    }

    /// The reviewer's custom hints for this unit, added to its prompts.
    pub(super) fn reviewer_hints_for(&self, binary: &str, function: &str) -> Vec<String> {
        self.unit_override(binary, function)
            .map(|o| o.custom_hints)
            .unwrap_or_default()
    }

    /// Add the reviewer's custom hints to a prompt that is already built.
    ///
    /// The hints go into a clearly-marked section at the end of the prompt —
    /// what the reviewer knows about the function (what it really does, its
    /// known quirks) that the automatic context gathering cannot produce.
    pub(super) fn append_reviewer_hints(prompt: String, hints: &[String]) -> String {
        let mut out = prompt;
        out.push_str("\n\n## Reviewer hints\n\n");
        out.push_str("Additional context supplied by the human reviewer steering this run:\n");
        for hint in hints {
            out.push_str(&format!("- {hint}\n"));
        }
        out
    }
}

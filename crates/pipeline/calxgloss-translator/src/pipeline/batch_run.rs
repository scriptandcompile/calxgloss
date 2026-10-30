//! The batch translation pass and its carry-over provenance: what a unit
//! inherits from the previous run of the same binary, and what files it.

use super::*;

impl TranslationPipeline {
    /// Translate the given functions in one binary as a batch.
    ///
    /// Returns a `BatchTranslationResult` holding each function's translation outcome.
    #[allow(clippy::type_complexity)]
    pub async fn batch_translate(
        &self,
        binary: &str,
        functions: &[String],
        config: &retry::RetryConfig,
        verifier: &Verifier,
        mut on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(
            binary,
            count = functions.len(),
            "Starting batch translation"
        );

        self.begin_cached_source(binary).await;

        self.run_prebatch_scans(binary).await;

        // W2.5: operator scope — skipped functions never enter the queue and
        // priority functions move to the front.
        let functions = self.apply_function_scope(binary, functions.to_vec(), |f| f.as_str());

        // Carry-over seeding (issue #299): the scan step just saved the
        // pairing documents for these exact bytes, so collect the seeds for
        // this queue now and the batch's inputs are settled before its first
        // unit starts.
        self.refresh_carry_over_seeds(binary, &functions);

        // Unknown residue (issues #369, #371): the batch's ledger write
        // files the current derived set, so the previous batch's
        // accumulated set starts out gone — what this batch's producers
        // admit replaces it.
        *self.unknown_residue.lock().expect("unknown residue lock") = None;

        // Verification residue (issue #373): every export no filed
        // baseline document covers files its standing question ahead of
        // the queue, so the binary-level facts lead the ledger's derived
        // order and re-file a batch after covering an export simply stops
        // landing that entry.
        self.record_export_residue(binary).await;

        let mut batch_result = batch::BatchTranslationResult::new(binary.to_string());

        for (idx, function) in functions.iter().enumerate() {
            if self.stop_requested() {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Stop signal received — ending batch at unit boundary"
                );
                break;
            }

            if self.budget_exhausted() {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Token budget exhausted — ending batch at unit boundary"
                );
                break;
            }

            // A paused binary ends this batch — unlike a run-level pause it
            // never holds the loop open (issue #219, part of #217).
            if self.binary_paused(binary) {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Binary paused — ending batch at unit boundary"
                );
                break;
            }

            if !self.control_allows_next_unit().await {
                info!(
                    binary,
                    remaining = functions.len() - idx,
                    "Pipeline control halt — ending batch at unit boundary"
                );
                break;
            }

            info!(
                binary,
                function,
                index = idx + 1,
                total = functions.len(),
                "Translating function in batch"
            );

            // Mark the unit in-flight so the web server's cancel-current
            // endpoint has something to name (issue #91, W2.2).
            if let Some(cancellation) = self.unit_cancellation.as_ref() {
                cancellation.begin_unit(binary, function);
            }

            // The unit races the cancellation watch: a cancellation that
            // arrives mid-unit drops the in-flight future — the first safe
            // point, because an attempt has saved nothing until the unit
            // completes — and the unit is recorded as a failed attempt while
            // the batch carries on with the next unit. A stopped root symbol
            // is recorded skipped rather than failed, and the flag keeps it
            // out of the completion callback (see below).
            let mut unit_refused = false;
            let (mut result, mut aborted) = tokio::select! {
                outcome = self.try_translate_with_retry(binary, function, config, verifier) => {
                    let result = match outcome {
                        Ok(retry_result) => {
                            if retry_result.success {
                                info!(
                                    binary,
                                    function,
                                    attempts = retry_result.attempts.len(),
                                    "Batch function succeeded"
                                );
                                let rust_code = retry_result.rust_code.clone().unwrap_or_default();
                                batch::FunctionResult::success(
                                    binary.to_string(),
                                    function.clone(),
                                    rust_code,
                                    retry_result,
                                    None, // git handled by caller via callback
                                )
                            } else {
                                warn!(
                                    binary,
                                    function,
                                    attempts = retry_result.attempts.len(),
                                    "Batch function exhausted all retries"
                                );
                                batch::FunctionResult::failure(
                                    binary.to_string(),
                                    function.clone(),
                                    retry_result,
                                )
                            }
                        }
                        Err(e) => {
                            // A root symbol named directly on the CLI is a
                            // request the pipeline stops, not a unit that
                            // failed: record it skipped, the way the
                            // call-graph path records its Skip nodes.
                            if matches!(e, TranslatorError::SkippedRoot { .. }) {
                                info!(
                                    binary,
                                    function,
                                    error = %e,
                                    "Batch function is a root symbol — recorded skipped, not failed"
                                );
                                unit_refused = true;
                                batch::FunctionResult::skipped(binary.to_string(), function.clone())
                            } else {
                                warn!(
                                    binary,
                                    function,
                                    error = %e,
                                    "Batch function translation failed (pipeline error)"
                                );
                                // Create a minimal failed result so the caller sees it
                                let empty_result = retry::RetryResult::new();
                                batch::FunctionResult::failure(
                                    binary.to_string(),
                                    function.clone(),
                                    empty_result,
                                )
                            }
                        }
                    };
                    (result, false)
                }
                _ = self.wait_for_unit_cancel(binary, function) => {
                    warn!(
                        binary,
                        function,
                        "Operator cancelled the in-flight unit — aborting at earliest safe point"
                    );
                    let empty_result = retry::RetryResult::new();
                    (
                        batch::FunctionResult::failure(
                            binary.to_string(),
                            function.clone(),
                            empty_result,
                        ),
                        true,
                    )
                }
            };

            // The unit is no longer in flight — a cancel-current arriving
            // between here and the next unit's start is refused, not taken.
            // Releasing the registration is also the race-free check for a
            // cancellation that arrived while the unit's own work was
            // finishing: the operator's cancel still outranks the completion
            // it raced with, so the unit is recorded cancelled, not completed.
            if let Some(cancellation) = self.unit_cancellation.as_ref()
                && cancellation.end_unit_was_cancelled()
            {
                if result.success {
                    warn!(
                        binary,
                        function,
                        "Operator cancelled as the unit completed — recording it cancelled"
                    );
                    let empty_result = retry::RetryResult::new();
                    result = batch::FunctionResult::failure(
                        binary.to_string(),
                        function.clone(),
                        empty_result,
                    );
                }
                aborted = true;
            }

            // Carry-over history (issue #299): when attempt 1 arrived with
            // an accepted translation and that code is what succeeded, the
            // record says so — the git callback's commit message reads it.
            self.attach_carry_over_provenance(&mut result);

            let success = result.success;
            // W2.5: add the unit's token spend to the run's budget.
            self.record_unit_tokens(&result);
            batch_result.add(result.clone());

            // Send the progress event for live tracking. A cancelled unit
            // already got its final `UnitCancelled` event from the
            // cancellation handle the moment the cancel arrived — no
            // completion event on top of that.
            if !aborted {
                self.emit(ProgressEvent::FunctionCompleted {
                    binary: binary.to_string().into(),
                    function: function.clone(),
                    success,
                    attempts: 0,  // filled by caller after git branch creation
                    branch: None, // filled by caller after git branch creation
                });
            }

            // Run the caller's callback (for example, for git commits as the
            // batch goes). Cancelled units go through it too — the caller
            // owns git cleanup, and per the Archive rule a cancelled unit's
            // branch is archived under the archive refs, never deleted. A
            // stopped root symbol never reaches this: it was never attempted,
            // so it has no translated code to write and no branch to clean
            // up, and a caller that assumed success means code would panic.
            let continue_batch = if let Some(ref mut cb) = on_function_completed
                && !unit_refused
            {
                cb(binary, function, &mut result)
            } else {
                true
            };

            // The unit is complete — file this binary's unknown ledger so
            // the gaps the batch's folds admitted stand on disk even if
            // the batch stops before its last unit (issue #369).
            self.file_unknown_ledger(binary)?;

            if !continue_batch {
                info!(binary, function, "Batch stopped early by callback");
                break;
            }
        }

        info!(
            binary,
            total = batch_result.total_count(),
            success = batch_result.success_count(),
            failure = batch_result.failure_count(),
            "Batch translation complete"
        );

        Ok(batch_result)
    }

    /// Collect this batch's carry-over seeds (issue #299), right after
    /// [`run_prebatch_scans`] wrote the pairing documents for the bytes being
    /// translated now.
    ///
    /// One directory pass, one hash, and one accepted-code lookup per paired
    /// candidate — milliseconds next to an LLM batch. With no port wired, no
    /// workspace or binary path, no eligible documents, or no accepted twin for
    /// a function, the map stays empty and every unit translates fresh, byte
    /// for byte as it does today. The batch never fails over this: the
    /// documents are context a user may want, not an input it needs.
    pub(super) fn refresh_carry_over_seeds(&self, binary: &str, functions: &[String]) {
        let mut seeds = self.carry_over_seeds.lock().expect("carry-over seeds lock");
        seeds.clear();
        let (Some(source), Some(workspace), Some(binary_path)) = (
            self.accepted_attempt_source.as_ref(),
            self.workspace.as_deref(),
            self.binary_path.as_deref(),
        ) else {
            return;
        };
        if functions.is_empty() {
            return;
        }
        let collected =
            crate::carry_over::collect_seeds(workspace, binary, binary_path, functions, source);
        if !collected.is_empty() {
            info!(
                binary,
                seeds = collected.len(),
                "Carry-over: attempt 1 will seed from accepted translations of paired functions"
            );
        }
        *seeds = collected;
    }

    /// Attach the carry-over history to a completed unit's result (issue
    /// #299): the record names the old function and the attempt branch that
    /// the winning code arrived on, so the batch callback's commit message,
    /// and anyone reading the record, can see where attempt 1's code came
    /// from.
    ///
    /// Attached only when the unit succeeded **with the seed's code** — if the
    /// fresh attempt chain won instead, the code is the LLM's own, and claiming
    /// a carry-over for it would be false provenance.
    pub(super) fn attach_carry_over_provenance(&self, result: &mut batch::FunctionResult) {
        if !result.success {
            return;
        }
        let seed = self
            .carry_over_seeds
            .lock()
            .expect("carry-over seeds lock")
            .get(&result.function)
            .cloned();
        let (Some(seed), Some(code)) = (seed, result.rust_code.as_deref()) else {
            return;
        };
        if code == seed.rust_code {
            result.carry_over = Some(crate::carry_over::CarryOverRecord {
                old_function: seed.old_function,
                old_attempt: seed.old_attempt,
                family: seed.family,
                confidence: seed.confidence,
            });
        }
    }
}

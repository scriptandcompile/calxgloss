//! The call-graph plan and the batch translation that rides it: the plan
//! entry point, its state-sharing edges, and the call-graph-fed batch pass.

use super::*;

impl TranslationPipeline {
    /// Translate several functions from one DLL, one at a time.
    ///
    /// Each function goes through the full pipeline with retry logic, the
    /// same path as the single-function
    /// [`try_translate_with_retry`](Self::try_translate_with_retry). The
    /// functions are processed in the order they are given.
    ///
    /// Before the first function, the per-binary type database, the type
    /// inference result, the algorithm recognition result, the memory
    /// lifecycle result, and the concurrency result are collected, or loaded
    /// from their caches, so the higher context tiers have data structure,
    /// parameter type, algorithm, and concurrency context. The fifteen
    /// evidence scans run through one shared scan phase, `run_prebatch_scans`.
    ///
    /// The caller may pass a callback (`on_function_completed`) that runs
    /// **immediately after each function completes**, before the next one
    /// starts. That allows git commits as the batch goes and per-function
    /// follow-up work without delaying the later translations.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL that holds all the functions to translate.
    /// * `functions` — The names of the functions to translate.
    /// * `config` — The retry config used for every function.
    /// * `verifier` — The Verifier that checks each translation.
    /// * `on_function_completed` — Optional closure that runs after each
    ///   function completes. It gets the DLL name, the function name, a
    ///   mutable reference to the [`batch::FunctionResult`], and a boolean
    ///   telling the caller whether to continue with the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`](crate::BatchTranslationResult) with each
    /// function's outcome. A function counts as a failure when its retry
    /// attempts run out without producing tests that pass.
    ///
    /// # Notes
    ///
    /// - If the LLM cannot be reached, the batch carries on with the rest of
    ///   the functions, recording each failure on its own.
    /// - The retry strategy (compile_fix → test_fix → escalate) applies to
    ///   each function separately.
    /// - The callback runs on the **same task** that is running the batch, so
    ///   it should return `true` quickly and not delay the next function. If
    ///   it returns `false`, the batch stops early.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     workspace: Path::new("/tmp/calxgloss-work").to_path_buf(),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// let functions = vec!["DrawSprite".to_string(), "UpdatePosition".to_string()];
    /// let results = pass.pipeline.batch_translate(
    ///     "game_logic.dll",
    ///     &functions,
    ///     &pass.retry,
    ///     &verifier,
    ///     Some(&mut |_dll, _function, _result| true), // keep going
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed", results.success_count(), results.failure_count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Produce a translation plan ordered by priority from a call graph.
    ///
    /// This method connects call-graph analysis to the batch translation path.
    /// Through [`TranslationOrderer`](calxgloss_callgraph::TranslationOrderer)
    /// it turns a [`CallGraph`](calxgloss_callgraph::CallGraph) into a list of
    /// [`FunctionTranslationPlan`](calxgloss_callgraph::FunctionTranslationPlan) records,
    /// each with its priority group (root / middle / leaf) and topological
    /// position. A saved global-state document for the graph's binary adds
    /// state-sharing edges to that order: within a group, a global's first
    /// definer comes before the units that reuse it (issue #256). With no
    /// document, today's order is unchanged.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph to plan from.
    /// * `max_functions` — An optional cap on how many functions the plan holds.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_callgraph::CallGraph;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    ///
    /// // Build or load the call graph first (e.g. via Analyzer::build_call_graph)
    /// let call_graph = /* CallGraph */ todo!();
    ///
    /// // Get a priority-ordered plan (max 100 functions)
    /// let plan = pass.pipeline.plan_from_callgraph(&call_graph, Some(100))?;
    ///
    /// for function in plan {
    ///     println!("{:?} {} ({} callers, {} callees)",
    ///         function.priority, function.name,
    ///         function.caller_count, function.callee_count);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn plan_from_callgraph(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
        max_functions: Option<usize>,
    ) -> crate::error::Result<Vec<calxgloss_callgraph::FunctionTranslationPlan>> {
        let mut orderer = calxgloss_callgraph::TranslationOrderer::new();
        if let Some(max) = max_functions {
            orderer = orderer.with_max_functions(max);
        }
        // State-sharing edges from the saved shared-globals index extend
        // the order when the global-state scan has run for this binary
        // (issue #256); the plan reads the saved file, it never runs the
        // scan itself.
        orderer = orderer.with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;
        Ok(plan.into_iter().collect())
    }

    /// The state-sharing edges that the saved shared-globals index names for
    /// this binary (issue #256, part of #225). The orderer uses the file the
    /// global-state scan wrote; it never runs the scan itself. A missing
    /// workspace, a missing document, or a corrupt one gives an empty set,
    /// so today's dependency order stays exactly as it is.
    pub(super) fn state_sharing_edges(
        &self,
        binary: &str,
    ) -> calxgloss_callgraph::StateSharingEdges {
        let Some(workspace) = self.workspace.as_deref() else {
            return calxgloss_callgraph::StateSharingEdges::default();
        };
        let persistor = calxgloss_globalstate::persist::GlobalStatePersistor::new(workspace);
        match persistor.load(binary) {
            Ok(result) => calxgloss_callgraph::StateSharingEdges::from_pairs(
                calxgloss_globalstate::rollup::state_sharing_pairs(
                    result.findings.iter().filter_map(
                        calxgloss_globalstate::types::GlobalStateFinding::shared_global,
                    ),
                ),
            ),
            Err(error) => {
                debug!(
                    binary,
                    error = %error,
                    "No usable global-state result; ordering without state-sharing edges"
                );
                calxgloss_callgraph::StateSharingEdges::default()
            }
        }
    }

    /// Translate several functions from one DLL, in an order the call
    /// graph sets.
    ///
    /// This method uses a [call graph] to pick the translation order:
    ///
    /// 1. [Leaf] functions (they call external APIs) — translated first
    /// 2. [Middle] functions — translated second
    /// 3. [Root] functions — translated last
    ///
    /// Within each group, functions are sorted so that a function is only
    /// translated after every function it calls. That lets the LLM use
    /// already-translated callee code when it writes shim layers or caller
    /// wrappers.
    ///
    /// Before the first function, the per-binary type database, the type
    /// inference result, the algorithm recognition result, the memory
    /// lifecycle result, and the concurrency result are collected, or loaded
    /// from their caches, so the higher context tiers have data structure,
    /// parameter type, algorithm, memory, and concurrency context. The fifteen
    /// evidence scans run through one shared scan phase, `run_prebatch_scans`.
    ///
    /// The caller can provide a callback (`on_function_completed`) that runs
    /// **immediately after each function finishes** (before the next one
    /// starts). That allows incremental git commits and per-function
    /// follow-up work without delaying the rest of the batch.
    ///
    /// # Arguments
    ///
    /// * `graph` — The call graph holding all the functions to translate.
    ///   Root functions get a minimal Stub automatically (they have no
    ///   translation work). Runtime library functions
    ///   (`NodeCategory::Skip`) are not stubbed.
    /// * `config` — The retry config applied to every function.
    /// * `verifier` — The Verifier used to check the translations.
    /// * `on_function_completed` — Optional closure called after each function
    ///   finishes. It receives the DLL name, the function name, a mutable
    ///   reference to the [`batch::FunctionResult`], and a boolean saying
    ///   whether to keep going with the remaining functions.
    ///
    /// # Returns
    ///
    /// A [`BatchTranslationResult`](crate::BatchTranslationResult) with each
    /// function's outcome. A function counts as a failure when its retry
    /// attempts run out without producing passing tests.
    ///
    /// Root functions from the call graph get a Stub automatically and
    /// appear in the result with `batch::FunctionResult::stubbed`. Functions
    /// classified as [`NodeCategory::Skip`] (runtime library functions) are
    /// not stubbed and appear as `batch::FunctionResult::skipped`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_verify::Verifier;
    /// use calxgloss_analysis::build_enriched_call_graph;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = calxgloss_kuna::KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = calxgloss_llm::LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let verifier = Verifier::new(Path::new("/tmp/calxgloss-work"))?;
    ///
    /// // Build or load the enriched call graph first (reads through the seam)
    /// let call_graph = build_enriched_call_graph(
    ///     &calxgloss_decomp::PipelineSource::from(engine.clone()),
    ///     "game_logic.dll",
    ///     Path::new("/tmp/calxgloss-work"),
    ///     None,
    /// ).await?;
    ///
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    ///
    /// let results = pass.pipeline.batch_translate_from_callgraph(
    ///     &call_graph,
    ///     &pass.retry,
    ///     &verifier,
    ///     Some(&mut |_dll, _function, _result| true), // keep going
    /// ).await?;
    ///
    /// println!("{} succeeded, {} failed, {} skipped",
    ///     results.success_count(), results.failure_count(), results.skipped_count());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [call graph]: calxgloss_callgraph::CallGraph
    /// [Leaf]: calxgloss_types::NodeCategory::Leaf
    /// [Middle]: calxgloss_types::NodeCategory::Middle
    /// [Root]: calxgloss_types::NodeCategory::Root
    #[allow(clippy::type_complexity)]
    pub async fn batch_translate_from_callgraph(
        &self,
        graph: &calxgloss_callgraph::CallGraph,
        config: &retry::RetryConfig,
        verifier: &Verifier,
        mut on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(binary = %graph.binary, count = graph.functions.len(), "Starting call-graph batch translation");

        self.begin_cached_source(&graph.binary).await;

        self.run_prebatch_scans(&graph.binary).await;

        // Build the plan in priority order, extended by the saved
        // shared-globals index when the global-state scan has run for
        // this binary (issue #256) — it reads the artifact, never scans.
        let orderer = calxgloss_callgraph::TranslationOrderer::new()
            .with_state_sharing(self.state_sharing_edges(&graph.binary));
        let plan = orderer
            .order(graph)
            .map_err(|e| TranslatorError::CallGraph(e.to_string()))?;

        let plan: Vec<_> = plan.into_iter().collect();
        let binary = &graph.binary;

        // W2.5: operator scope — skipped functions are taken out of the plan
        // before the first unit starts, and priority functions sort first.
        let plan = self.apply_function_scope(binary, plan, |p| p.name.as_str());

        // Carry-over seeding (issue #299): the scan step saved the pairing
        // documents for these exact bytes; collect the seeds for this plan
        // before its first unit starts.
        let queue_names: Vec<String> = plan.iter().map(|p| p.name.clone()).collect();
        self.refresh_carry_over_seeds(binary, &queue_names);

        // Unknown residue (issues #369, #371): the batch's ledger write
        // files the current derived set, so the previous batch's
        // accumulated set starts out gone — what this batch's producers
        // admit replaces it.
        *self.unknown_residue.lock().expect("unknown residue lock") = None;

        // Verification residue (issue #373): the export-coverage check
        // runs ahead of the queue here too — every export no filed
        // baseline document covers files its standing question into the
        // same accumulator the ladder and seam residues land in.
        self.record_export_residue(binary).await;

        let mut batch_result = batch::BatchTranslationResult::new(binary.clone());

        for (idx, plan_func) in plan.iter().enumerate() {
            use calxgloss_callgraph::TranslationPriority;

            if self.stop_requested() {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Stop signal received — ending call-graph batch at unit boundary"
                );
                break;
            }

            if self.budget_exhausted() {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Token budget exhausted — ending call-graph batch at unit boundary"
                );
                break;
            }

            // A paused binary ends this batch — unlike a run-level pause it
            // never holds the loop open (issue #219, part of #217).
            if self.binary_paused(binary) {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Binary paused — ending call-graph batch at unit boundary"
                );
                break;
            }

            if !self.control_allows_next_unit().await {
                info!(
                    binary,
                    remaining = plan.len() - idx,
                    "Pipeline control halt — ending call-graph batch at unit boundary"
                );
                break;
            }

            // Handle root functions (entry points) — generate Stubs, not translations
            if matches!(plan_func.priority, TranslationPriority::Root) {
                // Skip functions are recorded as skipped (runtime library functions)
                if matches!(plan_func.category, NodeCategory::Skip) {
                    info!(
                        binary,
                        name = %plan_func.name,
                        address = plan_func.address,
                        "Skipping runtime library function"
                    );
                    let skipped =
                        batch::FunctionResult::skipped(binary.clone(), plan_func.name.clone());
                    batch_result.add(skipped);

                    self.emit(ProgressEvent::FunctionCompleted {
                        binary: binary.clone().into(),
                        function: plan_func.name.clone(),
                        success: true,
                        attempts: 0,
                        branch: None,
                    });

                    // A skipped plan node never reaches the caller's
                    // callback: it was never attempted, so it has no
                    // translated code to write and no branch to clean up,
                    // and a caller that assumes a success always carries
                    // code would panic.

                    continue;
                }

                // Generate a Stub for entry-point functions
                info!(
                    binary,
                    name = %plan_func.name,
                    address = plan_func.address,
                    "Generating stub for root function"
                );
                let stub_code = self.generate_stub(&plan_func.name, "");
                let stubbed = batch::FunctionResult::stubbed(
                    binary.clone(),
                    plan_func.name.clone(),
                    stub_code,
                );
                batch_result.add(stubbed.clone());

                self.emit(ProgressEvent::FunctionCompleted {
                    binary: binary.clone().into(),
                    function: plan_func.name.clone(),
                    success: true,
                    attempts: 0,
                    branch: None,
                });

                // Run the caller's callback even for functions that got a Stub
                if let Some(ref mut cb) = on_function_completed
                    && !cb(binary, &plan_func.name, &mut stubbed.clone())
                {
                    info!(binary, function = %plan_func.name, "Batch stopped early by callback");
                    break;
                }

                continue;
            }

            info!(
                binary,
                name = %plan_func.name,
                address = plan_func.address,
                priority = ?plan_func.priority,
                index = idx + 1,
                total = plan.len(),
                "Translating function in batch"
            );

            // A stopped root — a name-pattern root that reached the unit
            // anyway, or a self-call thunk the name patterns cannot see
            // (issue #269) — is a request the pipeline stops, not a unit
            // that failed: record it as skipped, the way the explicit-list
            // path does, and the flag keeps it out of the completion
            // callback below (a stopped unit has no code to write).
            let mut unit_refused = false;
            let mut result = match self
                .try_translate_with_retry(binary, &plan_func.name, config, verifier)
                .await
            {
                Ok(retry_result) => {
                    if retry_result.success {
                        info!(
                            binary,
                            name = %plan_func.name,
                            attempts = retry_result.attempts.len(),
                            "Batch function succeeded"
                        );
                        let rust_code = retry_result.rust_code.clone().unwrap_or_default();
                        batch::FunctionResult::success(
                            binary.clone(),
                            plan_func.name.clone(),
                            rust_code,
                            retry_result,
                            None,
                        )
                    } else {
                        warn!(
                            binary,
                            name = %plan_func.name,
                            attempts = retry_result.attempts.len(),
                            "Batch function exhausted all retries"
                        );
                        let empty_result = retry::RetryResult::new();
                        batch::FunctionResult::failure(
                            binary.clone(),
                            plan_func.name.clone(),
                            empty_result,
                        )
                    }
                }
                Err(e) => {
                    // A stopped root is a stop, not a failure: record it
                    // as skipped, exactly as the explicit-list path does.
                    if matches!(e, TranslatorError::SkippedRoot { .. }) {
                        info!(
                            binary,
                            name = %plan_func.name,
                            error = %e,
                            "Plan function is a root symbol — recorded skipped, not failed"
                        );
                        unit_refused = true;
                        batch::FunctionResult::skipped(binary.clone(), plan_func.name.clone())
                    } else {
                        warn!(
                            binary,
                            name = %plan_func.name,
                            error = %e,
                            "Batch function translation failed (pipeline error)"
                        );
                        let empty_result = retry::RetryResult::new();
                        batch::FunctionResult::failure(
                            binary.clone(),
                            plan_func.name.clone(),
                            empty_result,
                        )
                    }
                }
            };

            // Carry-over history (issue #299): when attempt 1 arrived on an
            // accepted translation and that code is what succeeded, say so on
            // the record — the git callback's commit message reads it.
            self.attach_carry_over_provenance(&mut result);

            let success = result.success;
            // W2.5: charge the unit's token spend against the run budget.
            self.record_unit_tokens(&result);
            batch_result.add(result.clone());

            // Send the progress event used for real-time tracking
            self.emit(ProgressEvent::FunctionCompleted {
                binary: binary.clone().into(),
                function: plan_func.name.clone(),
                success,
                attempts: 0,  // filled by caller after git branch creation
                branch: None, // filled by caller after git branch creation
            });

            // Run the caller's callback. A stopped root never reaches
            // it: it was never attempted, so it has no translated code to
            // write and no branch to clean up, and a caller that assumes a
            // success carries code would panic.
            let continue_batch = if let Some(ref mut cb) = on_function_completed
                && !unit_refused
            {
                cb(binary, &plan_func.name, &mut result)
            } else {
                true
            };

            // The unit is complete — file this binary's unknown ledger so
            // the gaps the batch's folds admitted stand on disk even if
            // the batch stops before its last unit (issue #369).
            self.file_unknown_ledger(binary)?;

            if !continue_batch {
                info!(
                    binary,
                    function = %plan_func.name,
                    "Batch stopped early by callback"
                );
                break;
            }
        }

        info!(
            binary,
            total = batch_result.total_count(),
            success = batch_result.success_count(),
            failure = batch_result.failure_count(),
            "Call-graph batch translation complete"
        );

        Ok(batch_result)
    }
}

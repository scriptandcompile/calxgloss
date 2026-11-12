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
    /// The run's queue is built ahead of the batch's opening steps
    /// through the call-graph adapter: the ordered plan becomes planned
    /// units, with entry points planned Stub, runtime-library functions
    /// planned skip, and every other unit planned to translate
    /// (issue #488). The pass over that queue is the one batch
    /// protocol, [`run_batch`](Self::run_batch) (issue #490). A
    /// call-graph batch answers operator cancellation like an
    /// explicit-list batch. It keeps its attempt history and files its
    /// ledgers the same way.
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
        on_function_completed: Option<
            &mut dyn FnMut(&str, &str, &mut batch::FunctionResult) -> bool,
        >,
    ) -> Result<batch::BatchTranslationResult> {
        debug!(binary = %graph.binary, count = graph.functions.len(), "Starting call-graph batch translation");

        // The run's queue comes from the call-graph adapter, ahead of
        // the batch's opening steps (issue #488): the plan in priority
        // order, extended by the saved shared-globals index when that
        // document exists for this binary (issue #256), with each unit's
        // planned disposition. Operator scope applies too: skipped
        // functions leave the queue, and priority functions sort first.
        let queue = self.callgraph_queue(graph)?;

        // The pass itself is the one batch protocol (issue #490). The
        // call-graph batch rides it exactly like the explicit-list
        // batch. The protocol owns the unit gate and the cancellation
        // watch around each in-flight unit. It keeps the real attempt
        // history on an exhausted-retries record, and files both
        // ledgers at the boundaries and at the close.
        self.run_batch(
            &graph.binary,
            &queue,
            config,
            verifier,
            on_function_completed,
        )
        .await
    }
}

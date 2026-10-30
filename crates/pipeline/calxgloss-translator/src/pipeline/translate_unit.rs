//! The single-unit translation path: `translate`, its request-fed twin, the
//! retry-wrapped attempt, the refusal guards, and prompt-request construction.

use super::*;

impl TranslationPipeline {
    /// Translate one function from the loaded program.
    ///
    /// This is the main entry point of the pipeline. It reads all the data
    /// from the analysis engine, analyzes the function, generates the
    /// baseline test's inputs, builds the prompt, and sends it to the LLM.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL containing the function. Recorded on the result;
    ///   the lookup runs against the loaded program, which must be this DLL.
    /// * `function` — The name of the function to translate.
    ///
    /// # Returns
    ///
    /// A [`Translation`] with the generated Rust code and metadata, or an
    /// error if any step of the pipeline fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use calxgloss_kuna::KunaSource;
    /// use calxgloss_llm::LlmClient;
    /// use calxgloss_translator::assembly::{LlmSelection, PipelineSpec, assemble};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let engine = KunaSource::load(std::path::Path::new("target/game_logic.dll"))?;
    /// let llm = LlmClient::from_url("http://localhost:11434/v1", "qwen3")?;
    /// let spec = PipelineSpec {
    ///     llm: Some(LlmSelection::Client(llm)),
    ///     ..PipelineSpec::default()
    /// };
    /// let pass = assemble(&spec, &engine).await?;
    ///
    /// let translation = pass.pipeline.translate("game_logic.dll", "DrawSprite").await?;
    /// println!("Generated {} lines of Rust code", translation.rust_code.lines().count());
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(binary, function))]
    pub async fn translate(&self, binary: &str, function: &str) -> Result<Translation> {
        debug!(binary, function, "Starting translation pipeline");

        // Root symbols — entry points and import thunks — hold no logic to
        // translate. The call-graph batch path already skips or stubs them,
        // but an explicitly named function gets here unchecked, and a
        // `DelayLoad_` thunk is the classic trap: its resolved-import jump
        // decompiles to an unrecovered jump table plus a bare `return`, and
        // the LLM translates that broken result as if it were real. Stop
        // before the scan fetch, before any token is spent.
        self.refuse_root_function(binary, function)?;

        // Report: translation started
        self.emit(ProgressEvent::TranslationStarted {
            binary: binary.to_string().into(),
            function: function.to_string(),
        });

        // Step 1: read the function's metadata from the analysis engine
        let function_info = self.fetch_function(binary, function).await?;
        info!(binary, function, "Fetched function metadata");

        // Body-shape guard (issue #269): an import thunk the symbol table
        // named after its import — `SetCursor` carrying only
        // `SetCursor(); return;` — matches no name-based root pattern, but
        // its body is one unconditional call to its own name. Stop it here,
        // before the prompt is built and any token is spent: the LLM would
        // translate that apparent recursion into a Rust function that calls
        // itself.
        self.refuse_self_call_thunk(binary, function, &function_info.decompiler_output)?;

        // Triage: Ghidra's analysis failures arrive inside the pseudo-C as
        // WARNING comments. Name them before the LLM sees the body — an
        // unrecovered jump table otherwise becomes a plausible, empty
        // `return` in the generated Rust, with nothing marking the address
        // that still needs a human.
        self.triage_decompiler_warnings(binary, function, &function_info.decompiler_output);

        // Report: scan fetch complete
        self.emit(ProgressEvent::ScanFetchComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            address: Some(function_info.address),
            disassembly_lines: function_info.disassembly.lines().count(),
        });

        // Step 2: read the imports and tag the Windows APIs
        let imports = self.fetch_imports(binary).await?;
        let tagged_apis = self.tag_windows_apis(&function_info.disassembly, &imports)?;
        info!(
            binary,
            function,
            tagged_apis = tagged_apis.len(),
            "Tagged Windows APIs"
        );

        // Report: API tagging complete
        self.emit(ProgressEvent::ApiTaggingComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            tagged_apis: tagged_apis.len(),
        });

        // Step 3: generate the baseline test's inputs. The control-flow
        // document loads once here and serves both users: its branch-site
        // records target the baseline suite, and its findings go into the
        // prompt's CONTROL FLOW section below — one source of truth for the
        // LLM's context and for the test oracle (issue #261). A missing or
        // corrupt document loads as nothing, leaving generation on exactly
        // today's suite.
        let control_flow =
            crate::retry::helpers::load_control_flow_result(self.workspace.as_deref(), binary);
        let branch_inventory =
            crate::retry::helpers::branch_inventory_of(control_flow.as_ref(), function);
        let baseline_tests = self
            .generate_baseline_tests(&function_info, &imports, &branch_inventory)
            .await?;
        info!(
            binary,
            function,
            tests = baseline_tests.len(),
            "Generated baseline tests"
        );

        // Report: tests generated
        self.emit(ProgressEvent::TestsGenerated {
            binary: binary.to_string().into(),
            function: function.to_string(),
            test_count: baseline_tests.len(),
        });

        // Step 4: judge the function's complexity and build the request
        let complexity = self
            .analyzer
            .detect_complexity(&function_info.disassembly, &function_info.windows_apis);
        info!(
            binary,
            function,
            complexity = %complexity,
            "Detected function complexity"
        );

        // Pick the context tier from the complexity and the API call count.
        // Tracking historical success rates is left to a later integration.
        let api_call_count = tagged_apis.len();
        let auto_tier = calxgloss_types::select_context_tier(
            &complexity,
            api_call_count,
            calxgloss_types::SuccessRate::default(),
        );
        // W2.7: a reviewer override forces the context tier — the automatic
        // choice is skipped for this unit (issue #96).
        let tier = match self.forced_context_tier(binary, function) {
            Some(forced) => {
                info!(
                    binary,
                    function,
                    tier = %forced,
                    automatic = %auto_tier,
                    "Reviewer override forces the context tier"
                );
                forced
            }
            None => auto_tier,
        };
        let complexity_label = complexity.to_string();
        info!(
            binary,
            function,
            tier = %tier,
            "Selected context tier"
        );
        self.emit(ProgressEvent::ContextTierSelected {
            binary: binary.to_string().into(),
            function: function.to_string(),
            tier: tier.to_string(),
            tier_label: tier.label().to_string(),
            complexity: complexity_label,
            api_call_count,
        });

        let request = self.build_translation_request(
            binary,
            function,
            &function_info,
            tagged_apis.clone(),
            baseline_tests.clone(),
        );

        // Add call-graph context to the prompt data when it is available.
        //
        // Build and enrich it from the engine — the auto/translate/batch
        // passes that already have a graph send it through
        // `batch_translate_from_callgraph`, which takes the graph as an
        // argument; the pipeline never kept one (issue #328 removed the
        // never-called `with_call_graph`).
        let enriched_context: Vec<FunctionContext> = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
        } else {
            let workspace = self
                .workspace
                .as_deref()
                .unwrap_or_else(|| std::path::Path::new("."));
            let cache_dir = self.callgraph_cache_dir.as_deref();
            self.begin_scan_pass(&function_info.binary, "call graph");
            let built = calxgloss_analysis::build_enriched_call_graph(
                &self.scan_source(),
                &function_info.binary,
                workspace,
                cache_dir,
            )
            .await;
            self.end_scan_pass();
            match built {
                Ok(call_graph) => {
                    if self.callgraph_verbose {
                        calxgloss_analysis::print_call_graph_stats(&call_graph);
                    }
                    let enricher = ContextEnricher::new();
                    enricher.enrich(&call_graph)
                }
                Err(e) => {
                    warn!(
                        binary,
                        function,
                        error = %e,
                        "Failed to build call graph for context enrichment; continuing without it"
                    );
                    Vec::new()
                }
            }
        };

        // Carry-over seeding (issue #299): when a pairing document pairs
        // this function confidently with a previous-version twin whose
        // translation was *accepted* (a merged review branch), attempt 1
        // carries that code — no prompt built, no LLM called, no tokens
        // spent. Everything deterministic still runs: the scan fetch and
        // root stops above, the baseline tests and context tier selection
        // just above, and the full verification against the NEW binary's
        // bytes in the retry loop ahead — the accepted code is a guess the
        // new bytes may still fail, and that failure sends the unit into
        // the fresh-attempt chain like any other failed attempt. Nothing
        // here marks the unit verified; the review overlay's model
        // (ADR-0003) is untouched — the new branch starts unmerged.
        if let Some(seed) = self
            .carry_over_seeds
            .lock()
            .expect("carry-over seeds lock")
            .get(function)
            .cloned()
        {
            info!(
                binary,
                function,
                old_function = %seed.old_function,
                old_attempt = seed.old_attempt,
                family = seed.family,
                confidence = seed.confidence,
                "Seeding attempt 1 from the accepted translation of the paired previous-version function"
            );
            return Ok(Translation {
                binary: binary.to_string().into(),
                function: function.to_string(),
                function_address: Some(function_info.address),
                rust_code: seed.rust_code,
                // No prompt was sent; the record says what arrived instead.
                prompt_used: format!(
                    "carry-over seed: {} attempt {} (paired, {} family, {}% confidence) — no prompt sent, no LLM call",
                    seed.old_function, seed.old_attempt, seed.family, seed.confidence
                ),
                model: "carry-over".to_string(),
                tokens_used: None,
                baseline_tests,
                call_graph: function_info.call_graph.clone(),
                call_graph_context: enriched_context,
                disassembly_hints: function_info.disassembly_hints.clone(),
                context_tier: tier,
            });
        }

        // Step 5: build a prompt sized to the complexity and send it to the LLM
        self.emit(ProgressEvent::LlmCallStart {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            retry_strategy: "initial".to_string(),
        });

        let prompt = match tier {
            ContextTier::Signature => {
                let stub_data =
                    calxgloss_prompts::SignaturePromptData::from_function_info(&function_info);
                calxgloss_prompts::build_signature_prompt(&stub_data)?
            }
            ContextTier::Disassembly => {
                let data =
                    calxgloss_prompts::DisassemblyPromptData::from_function_info(&function_info);
                calxgloss_prompts::build_disassembly_prompt(&data)?
            }
            ContextTier::WithTests => {
                let mut data = calxgloss_prompts::WithTestsPromptData::from_request(&request);
                data.call_graph_context = enriched_context.clone();
                calxgloss_prompts::build_with_tests_prompt(&data)?
            }
            ContextTier::ModuleContext => {
                // One pass over the analyzer caches (issue #268); the
                // call-graph lists and the in-memory control-flow result are
                // added on top of it.
                // The fold reads the filed documents through the projection
                // seam and derives their coverage residue beside the bundle:
                // what the engines already admitted on disk for this unit,
                // accumulated for the batch's ledger writer (issue #369).
                let (mut evidence, residue) =
                    crate::retry::helpers::gather_function_evidence_residue(
                        self.workspace.as_deref(),
                        &function_info.binary,
                        function,
                        &function_info.call_graph,
                    );
                self.record_unknown_residue(residue);
                evidence.call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                evidence.neighboring_functions =
                    crate::retry::helpers::extract_neighboring_context(
                        &self.scan_source(),
                        &function_info.call_graph,
                    )
                    .await;
                evidence.call_graph_context = enriched_context.clone();
                evidence.control_flow_findings =
                    crate::retry::helpers::control_flow_hints_from(control_flow.as_ref(), function);
                calxgloss_prompts::build_module_context_prompt(&request, evidence)?
            }
            ContextTier::FullModule => {
                // FullModule context tier: whole-module context + shim layer code + PAL traits
                // The fold reads the filed documents through the projection
                // seam and derives their coverage residue beside the bundle:
                // what the engines already admitted on disk for this unit,
                // accumulated for the batch's ledger writer (issue #369).
                let (mut evidence, residue) =
                    crate::retry::helpers::gather_function_evidence_residue(
                        self.workspace.as_deref(),
                        &function_info.binary,
                        function,
                        &function_info.call_graph,
                    );
                self.record_unknown_residue(residue);
                evidence.call_graph_neighbors =
                    crate::retry::helpers::extract_call_graph_neighbors_from_enriched(
                        &enriched_context,
                        function_info.address,
                    );
                evidence.neighboring_functions =
                    crate::retry::helpers::extract_neighboring_context(
                        &self.scan_source(),
                        &function_info.call_graph,
                    )
                    .await;
                evidence.call_graph_context = enriched_context.clone();
                evidence.control_flow_findings =
                    crate::retry::helpers::control_flow_hints_from(control_flow.as_ref(), function);

                // Pull the shim layer's code out of the workspace
                let shim_layers = crate::retry::helpers::extract_shim_layers(
                    self.workspace.as_deref(),
                    &function_info.binary,
                );

                // Pull PAL trait definitions for the function's Windows API categories
                let pal_traits =
                    crate::retry::helpers::extract_pal_traits(&function_info.windows_apis);

                calxgloss_prompts::build_full_module_prompt(
                    &request,
                    evidence,
                    shim_layers,
                    pal_traits,
                )?
            }
        };

        // W2.7: the reviewer's custom hints go into the prompt, so what the
        // reviewer knows about this function reaches the LLM (issue #96).
        let reviewer_hints = self.reviewer_hints_for(binary, function);
        let prompt = if reviewer_hints.is_empty() {
            prompt
        } else {
            info!(
                binary,
                function,
                hints = reviewer_hints.len(),
                "Reviewer override appends custom hints to the prompt"
            );
            Self::append_reviewer_hints(prompt, &reviewer_hints)
        };

        // Report: LLM request (full prompt)
        self.emit(ProgressEvent::LlmRequest {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            retry_strategy: "initial".to_string(),
            prompt: prompt.clone(),
        });

        let response = self
            .send_to_llm(
                &prompt,
                self.events.as_ref(),
                binary,
                function,
                1,
                "initial",
                function_info.disassembly.lines().count(),
            )
            .await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        // Report: LLM response (full content)
        self.emit(ProgressEvent::LlmResponse {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            retry_strategy: "initial".to_string(),
            content: response.content.clone(),
            tokens_used: response.tokens_used,
        });

        // Report: LLM call complete
        self.emit(ProgressEvent::LlmCallComplete {
            binary: binary.to_string().into(),
            function: function.to_string(),
            attempt: 1,
            code_length: response.content.len(),
            tokens_used: response.tokens_used,
        });

        info!(
            binary,
            function,
            code_len = response.content.len(),
            model = %response.model,
            "Translation complete"
        );

        Ok(Translation {
            binary: binary.to_string().into(),
            function: function.to_string(),
            function_address: Some(function_info.address),
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests,
            call_graph: function_info.call_graph.clone(),
            call_graph_context: enriched_context,
            disassembly_hints: function_info.disassembly_hints.clone(),
            context_tier: tier,
        })
    }

    /// Translate using a pre-built [`TranslationRequest`].
    ///
    /// Skips the scan fetch and analysis steps and goes straight to building
    /// the prompt and calling the LLM. Useful when the request's data comes
    /// from a cache or from hand-written input.
    ///
    /// # Arguments
    ///
    /// * `request` — A pre-built [`TranslationRequest`] carrying all context.
    pub async fn translate_from_request(&self, request: TranslationRequest) -> Result<Translation> {
        debug!(binary = %request.binary, function = %request.function, "Translating from request");

        // The same root-symbol guard as in [`translate`](Self::translate): a
        // pre-built request is no reason to spend LLM tokens on a thunk.
        self.refuse_root_function(&request.binary, &request.function)?;

        if request.disassembly.is_empty() && request.decompiler_output.is_empty() {
            return Err(TranslatorError::MissingContext(
                "Both disassembly and decompiler output are empty".to_string(),
            ));
        }

        // The same body-shape guard as in [`translate`](Self::translate): a
        // pre-built request carrying a thunk's self-call body is no reason to
        // spend LLM tokens on a wrapper that holds no logic.
        self.refuse_self_call_thunk(
            &request.binary,
            &request.function,
            &request.decompiler_output,
        )?;

        self.triage_decompiler_warnings(
            &request.binary,
            &request.function,
            &request.decompiler_output,
        );

        let prompt = build_translate_prompt(&request)?;
        let response = self
            .send_to_llm(
                &prompt,
                self.events.as_ref(),
                &request.binary,
                &request.function,
                1,
                "initial",
                request.disassembly.lines().count(),
            )
            .await?;

        if response.content.is_empty() {
            return Err(TranslatorError::EmptyCode {
                code_len: response.content.len(),
            });
        }

        info!(
            binary = %request.binary,
            function = %request.function,
            code_len = response.content.len(),
            "Translation from request complete"
        );

        Ok(Translation {
            binary: request.binary,
            function: request.function,
            function_address: None,
            rust_code: response.content,
            prompt_used: prompt,
            model: self.llm.model().to_string(),
            tokens_used: response.tokens_used,
            baseline_tests: request.baseline_tests,
            call_graph: Vec::new(),
            call_graph_context: Vec::new(),
            disassembly_hints: Vec::new(),
            context_tier: ContextTier::WithTests,
        })
    }

    /// Translate with automatic retry when Verification fails.
    ///
    /// This is the main entry point for production use. It runs the full
    /// pipeline, verifies the result, and when Verification fails it retries
    /// with escalating retry strategies:
    ///
    /// 1. **Initial attempt** — the full pipeline, then Verification
    /// 2. **Compile fix** — if compilation fails, send the errors back to the LLM
    /// 3. **Test fix** — if tests fail, send the failing cases back to the LLM
    /// 4. **Escalate** — add more context and try again
    ///
    /// The retry loop continues until it succeeds or reaches `max_attempts`.
    ///
    /// # Arguments
    ///
    /// * `binary` — The DLL that contains the function.
    /// * `function` — The name of the function to translate.
    /// * `config` — The retry config (default: 3 attempts, compile_fix strategy).
    /// * `verifier` — The Verifier used to check the translation.
    ///
    /// # Returns
    ///
    /// A [`RetryResult`](crate::RetryResult) with every attempt and the final result.
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
    /// let result = pass.pipeline.try_translate_with_retry(
    ///     "game_logic.dll",
    ///     "DrawSprite",
    ///     &pass.retry,
    ///     &verifier,
    /// ).await?;
    ///
    /// if result.success {
    ///     println!("Success after {} attempts", result.attempts.len());
    ///     println!("{}", result.rust_code.as_ref().unwrap());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn try_translate_with_retry(
        &self,
        binary: &str,
        function: &str,
        config: &retry::RetryConfig,
        verifier: &Verifier,
    ) -> Result<retry::RetryResult> {
        debug!(
            binary,
            function, "Starting translation with retry (max {} attempts)", config.max_attempts
        );

        // The ladder's posture, settled before the unit's first attempt:
        // W2.5's operator constraints (max attempts, max context tier) cap
        // the retry policy, and W2.7 a reviewer override can force the retry
        // strategy and add its custom hints to the loop's prompts that follow
        // a failure (issue #96). Steering lands at unit boundaries, so the
        // reads below belong ahead of Step 1 — the seam-residue filing and
        // the loop itself walk one and the same settled posture.
        let source = self.scan_source();
        let mut bounded_config = self.constrained_retry_config(config);
        if let Some(strategy) = self.forced_retry_strategy(binary, function) {
            info!(
                binary,
                function,
                strategy = %strategy,
                configured = %config.retry_strategy,
                "Reviewer override forces the retry strategy"
            );
            bounded_config.retry_strategy = strategy;
        }
        let reviewer_hints = self.reviewer_hints_for(binary, function);
        // The batch's stored capability declaration, taken from the stored
        // copy for this prompt — the seam is never asked again (issue #355).
        let seam_report = self.seam_report();

        // Seam residue (issue #371): every family the held report declares
        // `unavailable`, and this unit's ladder posture would re-ask, files
        // its standing question against the unit — the P20 admission that
        // pruned the re-ask (issue #356) is now a record a reviewer can
        // resolve. Filed at the unit's entry into the retry wrapper: the
        // posture, not the unit's outcome, is what the admission bears on.
        // A family the report never declared — which reads unknown — files
        // nothing, and so does a posture that never re-asks.
        let residue = crate::seam_residue::seam_residue(
            binary,
            function,
            &seam_report,
            crate::seam_residue::posture_reask_families(&bounded_config),
            calxgloss_types::scan::now_unix_secs(),
        );
        if !residue.is_empty() {
            // A seam that admitted nothing opens nothing: the fold stays
            // the only writer that files an empty ledger (issue #369).
            self.record_unknown_residue(residue);
        }

        // Step 1: the first translation attempt, through the full pipeline.
        // The futures below are boxed so that downstream crates' `Send` checks
        // stop at this boundary instead of walking down the whole pipeline,
        // which overflows the compiler's trait evaluation recursion limit (see
        // rust-lang/rust#159228).
        let initial_translation: std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Translation>> + Send + '_>,
        > = Box::pin(self.translate(binary, function));
        let initial = initial_translation.await?;

        info!(
            binary,
            function,
            code_len = initial.rust_code.len(),
            "Initial translation complete, beginning verification loop"
        );

        // Step 2: run the retry loop
        let ctx = retry::RetryLoopCtx {
            verifier,
            llm: &self.llm,
            source: &source,
            config: &bounded_config,
            workspace: self.workspace.as_deref(),
            events: self.events.as_ref(),
            resource_detector: None,
            fault_logger: None,
            reviewer_hints: &reviewer_hints,
            seam_report: &seam_report,
        };
        // Boxed for the same reason as in step 1.
        let retry_loop: std::pin::Pin<
            Box<dyn std::future::Future<Output = retry::RetryResult> + Send + '_>,
        > = Box::pin(retry::try_translate_with_retry(initial, &ctx));
        let result = retry_loop.await;

        // Ladder residue (issue #372): every escalate rung the walk pruned
        // and every context-tier step it refused on a declared unavailable
        // filed its record at the decision — the loop hands them up, and
        // the pipeline folds them into the same per-binary accumulator
        // every other record lands in, deduplicated by id. The walk has
        // already run: a filed record feeds nothing back into which rung
        // or tier comes next (that door is P27's). A ladder that pruned
        // nothing opens nothing.
        if !result.unknown_residue.is_empty() {
            self.record_unknown_residue(result.unknown_residue.clone());
        }

        // Verification residue (issue #373): a unit that reached review
        // having run zero baseline cases files its standing question
        // against the unit — the walk's own verification counters (no
        // attempt ever moved `tests_total`) say this unit's behavior was
        // never exercised, and "translated" must not read as "proven"
        // about it. The counters are read after the walk, never back into
        // which rung comes next, and a walk whose cases ran opens nothing.
        if !result
            .attempts
            .iter()
            .any(|attempt| attempt.tests_total > 0)
        {
            self.record_unknown_residue(vec![crate::verification_residue::zero_case_residue(
                binary,
                function,
                calxgloss_types::scan::now_unix_secs(),
            )]);
        }

        if result.success {
            self.emit(ProgressEvent::TranslationCompleted {
                binary: binary.to_string().into(),
                function: function.to_string(),
                total_attempts: result.attempts.len(),
                success_strategy: result.success_strategy.clone(),
            });
            info!(
                binary,
                function,
                attempts = result.attempts.len(),
                strategy = %result.success_strategy.as_deref().unwrap_or("unknown"),
                "Translation succeeded via retry loop"
            );
        } else {
            self.emit(ProgressEvent::TranslationFailed {
                binary: binary.to_string().into(),
                function: function.to_string(),
                total_attempts: result.attempts.len(),
            });
            warn!(
                binary,
                function,
                attempts = result.attempts.len(),
                "All retry attempts exhausted without success"
            );
        }

        // Record the final result for later context tier selection tracking.
        // (The success-rate tracking itself comes in a follow-up.)

        Ok(result)
    }

    /// Stop a translate request for a function that the built-in root
    /// patterns mark as skip — entry points and import thunks (`DelayLoad_*`,
    /// `_imp_*`, `thunk_*`).
    ///
    /// The matched pattern's description becomes the error's reason, so the
    /// operator learns *why* this function was stopped: the thunk holds no
    /// logic, and the caller's translation reaches the real API through the
    /// PAL mappings instead. Only the `Skip` action stops here —
    /// `GenerateStub` is a batch-path policy, and a single explicit request
    /// still gets a real translation attempt.
    pub(super) fn refuse_root_function(&self, binary: &str, function: &str) -> Result<()> {
        if let Some(pattern) = self.root_detector.matched_pattern(function)
            && matches!(pattern.action, calxgloss_callgraph::RootAction::Skip)
        {
            warn!(
                binary,
                function,
                pattern = pattern.description,
                "Refusing to translate a root symbol named explicitly — it owns no logic to translate"
            );
            return Err(TranslatorError::SkippedRoot {
                binary: binary.to_string(),
                function: function.to_string(),
                reason: pattern.description.to_string(),
            });
        }
        Ok(())
    }

    /// Stop a translate request when the function's whole decompiled body
    /// is one unconditional call to its own name — an import thunk that the
    /// decompiler renders as a self-call (issue #269).
    ///
    /// The name-based root patterns cannot see these: the symbol table names
    /// the wrapper after the import it tail-jumps to, so `SetCursor` carries
    /// no `thunk_` marker and matches no pattern. The body's shape is the
    /// sign, and unlike the name guard this one can only run once the body
    /// is in hand — still, that is before the prompt is built and any LLM
    /// token is spent. The reason describes the shape, so the operator
    /// learns the same *why* the root patterns give: the wrapper holds no
    /// logic, and the caller's translation reaches the real API through the
    /// PAL mappings. A genuinely recursive function — a self-call inside
    /// real logic, with a base case — is not this shape and is never stopped.
    pub(super) fn refuse_self_call_thunk(
        &self,
        binary: &str,
        function: &str,
        decompiler_output: &str,
    ) -> Result<()> {
        if crate::triage::is_self_call_thunk(function, decompiler_output) {
            warn!(
                binary,
                function,
                "Refusing to translate a function whose whole body is a call to its own name — an import thunk the decompiler renders as a self-call"
            );
            return Err(TranslatorError::SkippedRoot {
                binary: binary.to_string(),
                function: function.to_string(),
                reason: "import thunk decompiled as a self-call (the body is only a call to its own name)".to_string(),
            });
        }
        Ok(())
    }

    /// Log the decompiler warnings that change what a translation can mean.
    ///
    /// A warning is not a failure — the translation still runs — but an
    /// unrecovered jump table means the body's dispatch is missing, and the
    /// generated Rust will be empty exactly there. Logging the address turns
    /// "the Rust is just a `return`" into a pointer at the jump to recover
    /// in the decompiler (or rebuild from the disassembly's table). Kuna's
    /// inline slug comment gives no address, so the jump is logged as an
    /// unknown site.
    pub(super) fn triage_decompiler_warnings(
        &self,
        binary: &str,
        function: &str,
        decompiler_output: &str,
    ) {
        for table in crate::triage::scan_unrecovered_jump_tables(decompiler_output) {
            let address = table.address.map_or_else(
                || "unknown".to_string(),
                |address| format!("{address:#010x}"),
            );
            warn!(
                binary,
                function,
                address = %address,
                reason = %table.reason,
                "the decompiler could not recover this jump table — the indirect jump decompiles as a call; the dispatch needs human recovery before the translation can be trusted"
            );
        }
    }

    /// Build a [`TranslationRequest`] from all the gathered context.
    pub(crate) fn build_translation_request(
        &self,
        binary: &str,
        function: &str,
        function_info: &FunctionInfo,
        tagged_apis: Vec<calxgloss_types::WindowsApiCall>,
        baseline_tests: Vec<TestCase>,
    ) -> TranslationRequest {
        TranslationRequest {
            binary: binary.to_string().into(),
            function: function.to_string(),
            disassembly: function_info.disassembly.trim().to_string(),
            decompiler_output: function_info.decompiler_output.trim().to_string(),
            windows_apis: tagged_apis,
            baseline_tests,
        }
    }

    /// The decompiler's first line is a real signature with real parameter
    /// types, so it is preferred. Only when that line is unusable — the
    /// decompilation failed, or the text is not pseudo-C — does this fall back
    /// to a placeholder, which gives boundary-value tests for the wrong
    /// parameter count rather than no tests at all.
    ///
    /// A signature that names no calling convention — a usable line without a
    /// convention word, or the placeholder — has the convention the scan
    /// detected for this function written into it, so the FFI binding built
    /// from the same string calls the original with the right convention
    /// instead of the blanket `__stdcall` (issue #251, part of #226). A
    /// decompiler line that does name a convention still wins: that line
    /// describes the function itself better. Microsoft x64 has no C keyword
    /// for it — the default ABI already is the x64 convention — so the
    /// convention slot is left empty rather than inventing a keyword. With no
    /// convention record, or no artifact, today's default stands.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn signature_for(&self, function_info: &FunctionInfo) -> String {
        let detected = self.detected_convention(&function_info.binary, &function_info.name);

        if let Some(parsed) =
            calxgloss_decomp::parse::parse_decompiled(&function_info.decompiler_output)
        {
            // Write in the detected convention only where the line named none,
            // and only when the convention has a C keyword at all.
            if let Some(spelling) = detected
                .and_then(|convention| convention.c_spelling())
                .filter(|_| !names_convention(&parsed.signature))
                && let Some(refined) = spell_convention(&parsed.signature, spelling)
            {
                return refined;
            }
            return parsed.signature;
        }

        warn!(
            function = %function_info.name,
            "No signature in the decompiled output; falling back to a parameter-less one"
        );
        // The default `__stdcall` is kept only when no record named a
        // convention; a record that did writes its own keyword, and the x64
        // record writes none because the parser's default already fits.
        let convention = match detected {
            Some(convention) => convention.c_spelling().unwrap_or_default(),
            None => "__stdcall",
        };
        if convention.is_empty() {
            format!("int {}()", function_info.name)
        } else {
            format!("int {convention} {}()", function_info.name)
        }
    }

    /// The calling convention that the saved type-inference record detected
    /// for this function (issue #251, part of #226). Only the function's own
    /// record describes its signature: a call-site view of a callee's
    /// convention is stored beside the caller's records and must never be
    /// mistaken for the caller's own. A missing workspace, a missing or
    /// corrupt artifact, or no convention record gives nothing, so the
    /// existing default convention stays in force.
    pub(super) fn detected_convention(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<calxgloss_typeinfer::types::CallingConvention> {
        let workspace = self.workspace.as_deref()?;
        let result = match TypeInferPersistor::new(workspace).load(binary) {
            Ok(result) => result,
            Err(error) => {
                debug!(
                    binary,
                    error = %error,
                    "No usable type inference result; synthesizing the signature without a detected convention"
                );
                return None;
            }
        };
        result.for_function(function).find_map(|inference| {
            match inference {
                // The records resolve to one convention per function, so the
                // first record naming its own convention is the whole answer;
                // call-site views (callee named) stay out.
                InferredType::Convention(record) if record.callee.is_none() => {
                    Some(record.convention)
                }
                _ => None,
            }
        })
    }

    /// Generate a Stub implementation for a root function.
    ///
    /// Root functions include entry points (`main`, `WinMain`, `DllMain`) and
    /// runtime library initializers. These do not go through the LLM;
    /// instead, a minimal Stub is generated from the function's name and
    /// signature, as a placeholder that can be compiled and linked.
    ///
    /// # Arguments
    ///
    /// * `name` — The function name (for example `mainCRTStartup`, `WinMain`).
    /// * `signature` — The C signature the decompiler worked out.
    ///
    /// # Returns
    ///
    /// A string holding a minimal Stub implementation. For a well-known entry
    /// point, the Stub says something meaningful. For an unknown root
    /// function, the Stub is a general placeholder that still compiles
    /// and links.
    pub fn generate_stub(&self, name: &str, signature: &str) -> String {
        // Match the common entry-point patterns
        let stub = match name {
            // C/C++ entry points — return 0
            "main" | "wmain" | "_main" | "WinMain" | "WinMain@16" | "WinMain@20" | "wWinMain"
            | "wWinMain@16" | "wWinMain@20" | "mainCRTStartup" | "__mainCRTStartup"
            | "_mainCRTStartup" => {
                format!(
                    "/// Entry point stub for `{name}`.\npub fn {name}() {{\n    std::process::exit(0);\n}}"
                )
            }
            // DLL entry points
            "DllMain" | "DllMain@16" | "DllMainCRTStartup" | "__DllMainCRTStartup" => {
                format!(
                    "/// DLL entry point stub for `{name}`.\npub fn {name}() {{\n    // DLL initialization\n}}"
                )
            }
            // Ghidra auto-generated entry
            "entry" => {
                "/// Entry point stub.\npub fn entry() {\n    std::process::exit(0);\n}".to_string()
            }
            // VB6 initialization
            name if name.starts_with("__vba") => {
                format!(
                    "/// VB6 runtime initialization stub for `{name}`.\npub fn {name}() {{\n    // VB6 runtime init\n}}"
                )
            }
            // .NET CLR entry
            "__managed_main" | "_CorExeMain" | "_CorDllMain" => {
                format!(
                    "/// .NET CLR entry stub for `{name}`.\npub fn {name}() {{\n    // CLR host initialization\n}}"
                )
            }
            // MinGW entry
            "_start" | "__libc_start_main" => {
                format!(
                    "/// MinGW entry stub for `{name}`.\npub fn {name}() {{\n    std::process::exit(0);\n}}"
                )
            }
            // MSVC debug runtime
            name if name.starts_with("_RTC_") => {
                format!(
                    "/// MSVC runtime check stub for `{name}`.\npub fn {name}() {{\n    // Runtime check\n}}"
                )
            }
            // Generic entry point — use the signature to work out a Stub
            _ => {
                // Pull the return type and parameters out of the signature
                let safe_name = if name.starts_with("FUN_") {
                    // Ghidra auto-generated name — keep as-is
                    name.to_string()
                } else {
                    name.to_string()
                };
                format!(
                    "/// Auto-generated stub for `{safe_name}`.\npub fn {safe_name}() {{\n    // TODO: Translate\n}}"
                )
            }
        };

        // Keep the signature in the output, as a comment for reference
        format!("{stub}\n// Signature: {signature}")
    }
}

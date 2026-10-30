//! The per-unit reads around one translation: function and import fetches,
//! Windows API tagging, baseline test generation, and the LLM send.

use super::*;

impl TranslationPipeline {
    /// Read the function's metadata through the batch's scan source.
    ///
    /// The name is turned into an address using the function listing first,
    /// and only an exact match counts: a substring match would quietly
    /// translate a different function.
    pub(super) async fn fetch_function(
        &self,
        binary: &str,
        function: &str,
    ) -> Result<FunctionInfo> {
        let context = |source| TranslatorError::ScanFetch {
            binary: binary.to_string(),
            function: function.to_string(),
            source: Box::new(source),
        };

        let source = self.scan_source();
        let functions = ScanSource::functions(&source).await.map_err(context)?;
        let found = functions
            .iter()
            .find(|f| f.name == function)
            .ok_or_else(|| TranslatorError::ScanFetch {
                binary: binary.to_string(),
                function: function.to_string(),
                source: Box::new(calxgloss_decomp::EngineError::NotFound {
                    kind: "function",
                    query: function.to_string(),
                }),
            })?;

        let decompiled = ScanSource::decompile(&source, function)
            .await
            .map_err(context)?;

        let call_graph = if self.no_callgraph.load(Ordering::Relaxed) {
            Vec::new()
        } else {
            // Callers come from the cross-references to the entry; callees
            // are read out of the decompiled body, so they cannot include
            // calls made through a function pointer.
            let callers = ScanSource::callers(&source, found.address)
                .await
                .map_err(context)?;
            callers
                .into_iter()
                .chain(calxgloss_decomp::parse::callees_from_decompiled(
                    &decompiled.body,
                ))
                .collect()
        };

        Ok(FunctionInfo {
            name: found.name.clone(),
            address: found.address,
            binary: binary.to_string().into(),
            // Kuna's answer is the decompiler's; there is no separate
            // disassembly listing to carry.
            disassembly: String::new(),
            decompiler_output: decompiled.body,
            windows_apis: Vec::new(),
            call_graph,
            disassembly_hints: Vec::new(),
        })
    }

    /// Get the names of the target binary's imports.
    ///
    /// These come back as names rather than [`calxgloss_decomp::Import`]
    /// values: the engine reports an import as a name plus an external slot
    /// with no module attached, so there is no module name to put in an `Import`.
    pub(super) async fn fetch_imports(&self, binary: &str) -> Result<Vec<String>> {
        ScanSource::imports(&self.scan_source())
            .await
            .map(|symbols| symbols.into_iter().map(|s| s.name).collect())
            .map_err(|e| TranslatorError::ScanFetch {
                binary: binary.to_string(),
                function: "<imports>".to_string(),
                source: Box::new(e),
            })
    }

    /// Tag Windows API calls in the function's disassembly and imports.
    pub(super) fn tag_windows_apis(
        &self,
        disassembly: &str,
        imports: &[String],
    ) -> Result<Vec<calxgloss_types::WindowsApiCall>> {
        // Use the analyzer that was built with the pipeline, so its tagging runs
        let tagged = self
            .analyzer
            .tag_windows_apis(disassembly, imports)
            .map_err(|e| TranslatorError::TestGen(anyhow::anyhow!("API tagging failed: {e}")))?;

        // The analyzer already writes the shared `WindowsApiCall` values, so
        // its tagged list is the prompt's list — no conversion needed.
        Ok(tagged)
    }

    /// Generate the baseline test's inputs for a function, aimed at the
    /// branch sites that the loaded control-flow findings listed for it
    /// (issue #261). An empty list — no records, or no usable document —
    /// gives exactly today's suite.
    pub(super) async fn generate_baseline_tests(
        &self,
        function_info: &FunctionInfo,
        _imports: &[String],
        branch_inventory: &[calxgloss_controlflow::types::BranchSite],
    ) -> Result<Vec<TestCase>> {
        // The signature the decompiler worked out, which gives the
        // parameters that the test cases pass in.
        let signature = self.signature_for(function_info);

        // Generate the test inputs from the signature, the disassembly, and
        // the branch list: one case per branch target, de-duplicated
        // against the boundary cases, with a cap per function.
        let mut tests = calxgloss_testgen::generate_test_inputs(
            &signature,
            &function_info.disassembly,
            branch_inventory,
        )
        .map_err(TranslatorError::TestGen)?;

        // The saved global-state artifact provides the typed side-effect
        // expectations: when a stored global-state document names globals
        // for this function, every test case carries them as
        // GlobalRead/GlobalWrite expectations that name each global — a
        // global side effect is always a named kind, never an Other string.
        // No document (the scan has not run) or a corrupt one leaves the
        // expectations empty, exactly as before.
        if let Some(workspace) = self.workspace.as_deref() {
            let expectations = calxgloss_testgen::global_state_expectations(
                workspace,
                &function_info.binary,
                &function_info.name,
            );
            if !expectations.is_empty() {
                for test in &mut tests {
                    test.expected_side_effects.clone_from(&expectations);
                }
            }
        }

        Ok(tests)
    }

    /// Send a prompt to the LLM and take the Rust code out of the response.
    ///
    /// When `events` is present, a `LlmCallInProgress` keepalive event goes
    /// out every 30 seconds while the request is running.
    ///
    /// After the response arrives, the context-window detector checks whether
    /// the output reaches or passes the model's configured limit. A detected
    /// fault is logged with `tracing::warn!` so the caller can act on it —
    /// for example by splitting the function and trying again.
    ///
    /// # Arguments
    ///
    /// * `disassembly_lines` — How many lines the function's disassembly has,
    ///   used to suggest a chunk count for the retry splitter when a
    ///   context-window fault is detected.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn send_to_llm(
        &self,
        prompt: &str,
        events: Option<&TranslationEvents>,
        binary: &str,
        function: &str,
        attempt: u32,
        retry_strategy: &str,
        disassembly_lines: usize,
    ) -> Result<calxgloss_llm::LlmResponse> {
        let messages = vec![LlmMessage::user(prompt)];

        // Pre-check: is the prompt itself already too large for the context?
        if let Some(fault) = self.context_detector.detect_prompt_too_large(&messages) {
            warn!(
                binary,
                function,
                attempt,
                retry_strategy,
                prompt_size = fault.response_size,
                limit = fault.limit,
                "Prompt exceeds model context limit — splitting function",
            );
            // The call still goes ahead; the LLM server handles the
            // truncation, and the check after the response sees the real output.
        }

        let response = if let Some(em) = events {
            let em = em.clone();
            let em_err = em.clone();
            let dll_s = binary.to_string();
            let function_s = function.to_string();
            let strategy_s = retry_strategy.to_string();

            // Copy the values before moving them into the keepalive closure
            let dll_kp = dll_s.clone();
            let function_kp = function_s.clone();
            let strategy_kp = strategy_s.clone();

            // Start a keepalive task that sends a progress event every 30 seconds
            let keepalive_handle = tokio::task::spawn(async move {
                let interval = std::time::Duration::from_secs(30);
                let mut elapsed = interval;
                loop {
                    tokio::time::sleep(interval).await;
                    let secs = elapsed.as_secs();
                    let _ = em.emit(ProgressEvent::LlmCallInProgress {
                        binary: dll_kp.clone().into(),
                        function: function_kp.clone(),
                        attempt,
                        retry_strategy: strategy_kp.clone(),
                        elapsed_secs: secs,
                    });
                    elapsed += interval;
                }
            });

            let result = self.llm.complete(&messages).await;
            keepalive_handle.abort();

            match &result {
                Ok(_) => {}
                Err(e) => {
                    let _ = em_err.emit(ProgressEvent::LlmCallFailed {
                        binary: dll_s.clone().into(),
                        function: function_s.clone(),
                        attempt,
                        retry_strategy: strategy_s.clone(),
                        error: e.to_string(),
                    });
                }
            }

            result
        } else {
            self.llm.complete(&messages).await
        }?;

        // Post-check: look for a context-window-exceeded fault.
        if let Some(fault) = self
            .context_detector
            .detect_response(&response, disassembly_lines)
        {
            warn!(
                binary,
                function,
                attempt,
                retry_strategy,
                response_size = fault.response_size,
                limit = fault.limit,
                overflow = fault.overflow_chars,
                "Context window exceeded — function should be split into {} chunks",
                fault.suggested_chunk_count(),
            );
        }

        // Hallucination check: look through the generated code for API or
        // function references that do not exist. When invented references
        // turn up, log a warning and send a progress event so the caller can act.
        let hallucinations = self
            .hallucination_detector
            .as_ref()
            .map(|d| d.detect(&response.content))
            .unwrap_or_default();
        if !hallucinations.is_empty() {
            let names: Vec<String> = hallucinations.iter().map(|h| h.name.clone()).collect();
            warn!(
                binary,
                function,
                attempt,
                retry_strategy,
                count = names.len(),
                apis = ?names,
                "Hallucinated API/function references detected",
            );
            if let Some(em) = events {
                let _ = em.emit(ProgressEvent::HallucinationDetected {
                    binary: binary.to_string().into(),
                    function: function.to_string(),
                    attempt,
                    retry_strategy: retry_strategy.to_string(),
                    hallucinated_apis: names.clone(),
                });
            }
        }

        debug!(
            code_len = response.content.len(),
            model = %self.llm.model(),
            "Received LLM response"
        );

        Ok(response)
    }
}

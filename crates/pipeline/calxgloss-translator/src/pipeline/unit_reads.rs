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

    /// Tag the Windows API calls the function's body names, from the
    /// binary's import list.
    pub(super) fn tag_windows_apis(
        &self,
        body: &str,
        imports: &[String],
    ) -> Result<Vec<calxgloss_types::WindowsApiCall>> {
        // Use the analyzer that was built with the pipeline, so its tagging runs
        let tagged = self
            .analyzer
            .tag_windows_apis(body, imports)
            .map_err(|e| TranslatorError::TestGen(anyhow::anyhow!("API tagging failed: {e}")))?;

        // The analyzer already writes the shared `WindowsApiCall` values, so
        // its tagged list is the prompt's list — no conversion needed.
        Ok(tagged)
    }

    /// File the unit's tagged Windows APIs as the per-function analysis
    /// artifact: `re/analysis/{binary}/{function}.json`, the document the
    /// web review UI's Windows API mappings panel reads. The document
    /// carries just the `windows_apis` array, in the shape the panel's
    /// reader deserializes.
    ///
    /// Nothing to file when the pipeline has no workspace. The artifact is
    /// panel context, never pipeline input, so a failed write is logged
    /// and never fails the translation.
    pub(super) fn file_analysis_artifact(
        &self,
        binary: &str,
        function: &str,
        windows_apis: &[calxgloss_types::WindowsApiCall],
    ) {
        let Some(workspace) = self.workspace.as_deref() else {
            return;
        };
        let path = calxgloss_types::analysis_dir(workspace)
            .join(binary)
            .join(format!("{function}.json"));
        let document = serde_json::json!({ "windows_apis": windows_apis });
        if let Err(error) = calxgloss_types::save_json(&path, &document) {
            warn!(
                binary,
                function,
                error = %error,
                "Failed to file the per-function analysis artifact; the Windows API \
                 mappings panel will show no mappings for this unit"
            );
        }
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

            // The API-call trace dimension (#386, P22): the trace the
            // saved baseline captured for a case becomes that case's
            // expectation — scoped to the in-scope API roster the
            // apidetect document records for this function (direct uses
            // and through callees alike) and spelled onto the verify PAL
            // surface the gate's recorder names. A recorded name outside
            // the roster (chatter the unit merely passes through) or
            // spelled for nothing on the surface drops out of the
            // expectation: the fold never manufactures an expectation
            // the restitched body can be failed for without cause. A
            // case with no matching capture, or a missing or corrupt
            // apidetect document, leaves the trace dimension unassessed
            // — the honest degradation the side-effect expectations take
            // alongside (#276).
            let roster = self.api_scope_roster(&function_info.binary, &function_info.name);
            if !roster.is_empty() {
                match calxgloss_testgen::TestGenerator::new(workspace)
                    .load_baseline(&function_info.binary, &function_info.name)
                {
                    Ok(captures) => {
                        for test in &mut tests {
                            if let Some(capture) = captures
                                .iter()
                                .find(|record| record.test_case.inputs == test.inputs)
                            {
                                test.expected_api_calls = capture
                                    .actual_api_calls
                                    .iter()
                                    .filter(|name| roster.iter().any(|api| api == *name))
                                    .filter_map(|name| api_surface_name(name))
                                    .map(str::to_string)
                                    .collect();
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            binary = &*function_info.binary,
                            function = %function_info.name,
                            error = %e,
                            "No saved baseline document to fold captured api-call traces from; the trace dimension stays unassessed for this unit"
                        );
                    }
                }
            }
        }

        Ok(tests)
    }

    /// The in-scope API roster for one unit (#386, P22): every API the
    /// apidetect document credits the function with — used directly or
    /// through callees it reaches — de-duplicated in first-seen order.
    /// No document, or a corrupt one, means no roster, and the trace
    /// fold leaves the dimension unassessed.
    fn api_scope_roster(&self, binary: &str, function: &str) -> Vec<String> {
        let Some(workspace) = self.workspace.as_deref() else {
            return Vec::new();
        };
        let result = match calxgloss_apidetect::persist::ApiPersistor::new(workspace).load(binary) {
            Ok(result) => result,
            Err(e) => {
                debug!(
                    binary,
                    function,
                    error = %e,
                    "No usable apidetect result; the API-call trace dimension stays unassessed for this unit"
                );
                return Vec::new();
            }
        };
        let mut roster: Vec<String> = Vec::new();
        for finding in result.for_function(function) {
            if let calxgloss_apidetect::types::ApiFinding::ApiUsage(usage) = finding {
                if !roster.iter().any(|api| api == &usage.api) {
                    roster.push(usage.api.clone());
                }
            }
        }
        roster
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

/// Spell a captured Win32 import name onto the verify PAL surface method
/// it stands in for (#386, P22).
///
/// The baseline capture records each call by the name the binary's import
/// table carries; the gate's recorder names calls by the verify PAL
/// surface. The roster scopes the fold, and this table spells the
/// surviving names where restitched code can actually satisfy them: when
/// the surface stands in for a name at all, the call drops out of the
/// expectation rather than forcing an `expected [GetLastError], got []`
/// failure no repair could answer. The keys are real DLL imports; the
/// values are exactly the names the verify stubs hand to
/// `record_api_call`.
fn api_surface_name(api: &str) -> Option<&'static str> {
    Some(match api {
        // Drawing into a device context, as the graphics surface stands in for it.
        "BitBlt" | "StretchBlt" => "blit",
        "CreateDIBSection" => "create_texture",
        "TextOutA" | "TextOutW" | "DrawTextA" | "DrawTextW" => "draw_text",
        "FillRect" => "draw_rect",
        "MoveToEx" | "LineTo" => "draw_line",
        // The window shell and the message pump.
        "CreateWindowExA" | "CreateWindowExW" => "create_window",
        "ShowWindow" => "show",
        "DestroyWindow" => "destroy_window",
        "GetMessageA" | "GetMessageW" | "PeekMessageA" | "PeekMessageW" => "process_events",
        // Files through the kernel32 handles the storage surface wraps.
        "CreateFileA" | "CreateFileW" => "open",
        "ReadFile" => "read",
        "WriteFile" => "write",
        "CloseHandle" => "close",
        "CreateDirectoryA" | "CreateDirectoryW" => "create_dir",
        "DeleteFileA" | "DeleteFileW" => "delete",
        // Threads as the concurrency surface names them.
        "Sleep" => "sleep",
        "CreateThread" => "spawn",
        "WaitForSingleObject" => "join",
        // Audio playback.
        "PlaySoundA" | "PlaySoundW" | "sndPlaySoundA" | "sndPlaySoundW" => "play_sample",
        _ => return None,
    })
}

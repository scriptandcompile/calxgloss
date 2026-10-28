//! Behavior tests for the pipeline assembly seam (issue #323).
//!
//! These tests reach the seam through the module path
//! (`calxgloss_translator::assembly`) — the facade's route — and check each setting by
//! running an assembled pass over the shared fixture target: what the prompt
//! carries, what the engine honors, what the pass refuses to build. They
//! never assert the sequence of `with_*` setter calls; the proof is always
//! the assembled pass's observable behavior.

use calxgloss_kuna::{KunaBudget, KunaSource};
use calxgloss_llm::LlmClient;
use calxgloss_pal::{ApiMapping, ApiMappings};
use calxgloss_testfixtures::{TARGET_FILE_NAME, load_target};
use calxgloss_translator::TranslatorError;
use calxgloss_translator::assembly::{
    BinaryTarget, LlmDescription, LlmSelection, PipelineSpec, assemble, assemble_patch,
};
use calxgloss_types::{ApiCategory, ContextTier, FunctionOverride, OverrideControl, RetryStrategy};

// ============================================================
// Harness
// ============================================================

/// The fixture target loaded as a scan source — the engine the facade would
/// hand to `assemble` for a normal pass.
fn fixture_engine() -> KunaSource {
    let target = load_target().expect("fixture target should build and validate");
    KunaSource::load(target.path()).expect("the fixture must load for scanning with Kuna")
}

/// A fake OpenAI-compatible server answering every request with `canned_content`
/// (which must be JSON-safe: no quotes, backslashes, or newlines). Reads the
/// full request body by `Content-Length` before answering, so the client's
/// write completes cleanly however large the prompt is. Returns the base URL
/// to point an endpoint description or client at.
async fn fake_llm(canned_content: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake LLM should bind");
    let addr = listener.local_addr().expect("fake LLM address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut request: Vec<u8> = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            let Some(header_end) =
                                request.windows(4).position(|w| w == b"\r\n\r\n")
                            else {
                                continue;
                            };
                            let headers = String::from_utf8_lossy(&request[..header_end]);
                            let need = headers
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.trim()
                                        .eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().to_string())
                                })
                                .and_then(|value| value.parse::<usize>().ok())
                                .unwrap_or(0);
                            if request.len() >= header_end + 4 + need {
                                break;
                            }
                        }
                    }
                }
                let body = format!(
                    r#"{{"choices":[{{"message":{{"role":"assistant","content":"{canned_content}"}}}}],"usage":{{"completion_tokens":10,"prompt_tokens":20,"total_tokens":30}}}}"#
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

/// A code-shaped canned answer for the fixture's `fixture_tick`.
const TICK_CODE: &str = "fn fixture_tick(code: u32) -> u32 { code }";

/// A spec for a pass over the fixture target in `workspace` talking to `llm`.
fn fixture_spec(workspace: &std::path::Path, llm: LlmSelection) -> PipelineSpec {
    let target = load_target().expect("fixture target");
    PipelineSpec {
        llm: Some(llm),
        workspace: workspace.to_path_buf(),
        target_binary: Some(BinaryTarget {
            name: TARGET_FILE_NAME.to_string(),
            path: target.path().to_path_buf(),
        }),
        ..PipelineSpec::default()
    }
}

// ============================================================
// The LLM: mandatory, and both selection routes reach the pass
// ============================================================

#[tokio::test]
async fn a_spec_without_an_llm_is_an_assembly_error() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let spec = PipelineSpec {
        workspace: ws.path().to_path_buf(),
        ..PipelineSpec::default()
    };

    let error = assemble(&spec, &fixture_engine())
        .await
        .expect_err("a pass without an LLM must not assemble");

    assert!(
        matches!(error, TranslatorError::MissingLlm { .. }),
        "expected MissingLlm, got: {error}"
    );
    assert!(
        error.to_string().contains("without an LLM"),
        "the error should say why: {error}"
    );
}

#[tokio::test]
async fn an_llm_description_that_cannot_build_a_client_fails_assembly() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let mut spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(LlmClient::from_url("http://127.0.0.1:1/v1", "m").expect("client")),
    );
    spec.llm = Some(LlmSelection::Description(LlmDescription {
        endpoint: "not a url".to_string(),
        model: "fixture-model".to_string(),
        api_key: None,
        context_window: None,
        temperature: None,
        timeout_secs: None,
    }));

    let error = assemble(&spec, &fixture_engine())
        .await
        .expect_err("an unbuildable endpoint must fail the assembly");

    // Falls into the crate's existing error type — the LLM failure variant,
    // not a new enum and not a pass that silently lacks an LLM.
    assert!(matches!(error, TranslatorError::Llm(_)), "got: {error}");
}

#[tokio::test]
async fn an_assembled_pass_translates_through_a_described_llm_endpoint() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let base = fake_llm(TICK_CODE).await;
    let spec = fixture_spec(
        ws.path(),
        LlmSelection::Description(LlmDescription {
            endpoint: base,
            model: "fixture-model".to_string(),
            api_key: None,
            context_window: None,
            temperature: None,
            timeout_secs: None,
        }),
    );

    let pass = assemble(&spec, &fixture_engine())
        .await
        .expect("a described endpoint assembles a client into the pass");

    // The built-in default table answers for an unset mapping spec.
    assert!(!pass.pipeline.api_mappings().is_empty());

    let translation = pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect("the described endpoint answers the pass");
    assert_eq!(translation.model, "fixture-model");
    assert_eq!(translation.rust_code, TICK_CODE);
    assert!(
        translation.prompt_used.contains("fixture_tick"),
        "the prompt should carry the unit under translation"
    );
}

#[tokio::test]
async fn a_prebuilt_client_reaches_the_assembled_pass() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let base = fake_llm(TICK_CODE).await;
    let client = LlmClient::from_url(&base, "prebuilt-model").expect("llm client");
    let spec = fixture_spec(ws.path(), LlmSelection::Client(client));

    let pass = assemble(&spec, &fixture_engine())
        .await
        .expect("a prebuilt client wires straight through");

    let translation = pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect("the prebuilt client answers the pass");
    assert_eq!(translation.model, "prebuilt-model");
    assert_eq!(translation.rust_code, TICK_CODE);
}

// ============================================================
// API mappings: the spec's table is the table the pass detects with
// ============================================================

#[tokio::test]
async fn custom_api_mappings_reach_the_prompt_through_an_assembled_pass() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let base = fake_llm(TICK_CODE).await;

    // The fixture imports `puts`, which the built-in default table does not
    // name; a custom table that does must put its mapping row in the prompt.
    // The automatic tier for this unit is Signature, whose prompt carries no
    // API rows at all, so the reviewer-override knob forces WithTests — a
    // tier whose template renders the tagged-call section — and doubles as
    // the proof that the spec's overrides carry through.
    let overrides = OverrideControl::new();
    overrides
        .set(
            TARGET_FILE_NAME,
            "fixture_tick",
            FunctionOverride {
                tier_override: Some(ContextTier::WithTests),
                ..FunctionOverride::default()
            },
        )
        .expect("in-memory override stores");
    let custom = ApiMappings::from_custom(vec![ApiMapping::new(
        "puts",
        ApiCategory::Win32Core,
        "CUSTOM_PAL_MARKER",
        "test-only mapping",
    )]);
    let mut spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(LlmClient::from_url(&base, "m").expect("llm client")),
    );
    spec.api_mappings = Some(custom);
    spec.overrides = Some(overrides.clone());

    let pass = assemble(&spec, &fixture_engine())
        .await
        .expect("the custom table assembles");
    let translation = pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect("the pass translates");
    assert!(
        translation.prompt_used.contains("CUSTOM_PAL_MARKER"),
        "the custom mapping should reach the prompt:\n{}",
        translation.prompt_used
    );

    // The same pass with the default table never shows the marker — the
    // prompt row can only come from the spec's table.
    let mut default_spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(LlmClient::from_url(&base, "m").expect("llm client")),
    );
    default_spec.overrides = Some(overrides);
    let default_pass = assemble(&default_spec, &fixture_engine())
        .await
        .expect("the default table assembles");
    let default_translation = default_pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect("the default pass translates");
    assert!(
        default_translation
            .prompt_used
            .contains("WINDOWS API CALLS"),
        "the forced tier should render tagged calls:\n{}",
        default_translation.prompt_used
    );
    assert!(
        !default_translation
            .prompt_used
            .contains("CUSTOM_PAL_MARKER"),
        "the default table must not grow the custom marker"
    );
}

// ============================================================
// Patch mode: the engine load this assembly makes honors the budget
// ============================================================

#[tokio::test]
async fn an_assembled_patch_pass_honors_the_configured_kuna_budget() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let base = fake_llm(TICK_CODE).await;

    let mut spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(LlmClient::from_url(&base, "m").expect("llm client")),
    );
    spec.patch_mode = true;
    // One instruction per function decompile: the fixture's bodies cannot
    // complete under it, and the trip must name the budget (issue #211).
    spec.kuna_budget = KunaBudget {
        max_instructions: Some(1),
        ..KunaBudget::default()
    };

    let pass = assemble(&spec, &fixture_engine())
        .await
        .expect("the patch-mode load arms the budget and succeeds");

    let error = pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect_err("the armed instruction budget must trip on the fixture body");
    assert!(
        error.to_string().contains("budget tripped"),
        "the failure should name the budget trip: {error}"
    );

    // Same patch-mode spec, untripped budget: the pass reads through the
    // engine it loaded and translates cleanly.
    let mut open_spec = spec.clone();
    open_spec.kuna_budget = KunaBudget::default();
    let open_pass = assemble(&open_spec, &fixture_engine())
        .await
        .expect("the default-budget patch load assembles");
    let translation = open_pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect("with the budget unset the patch pass translates");
    assert_eq!(translation.rust_code, TICK_CODE);
}

// ============================================================
// assemble_patch: the web server's entry — spec in, pass out
// ============================================================

#[tokio::test]
async fn assemble_patch_refuses_a_spec_without_an_llm_before_touching_the_engine() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    // A patch-mode spec that names a real, loadable binary but carries no
    // LLM: the refusal is the missing LLM, not an engine failure — the seam
    // builds the LLM first, so a server started without LLM settings meets
    // the clear assembly error at patch-request time (issue #327 AC6).
    let spec = PipelineSpec {
        patch_mode: true,
        target_binary: fixture_spec(
            ws.path(),
            LlmSelection::Client(
                LlmClient::from_url("http://127.0.0.1:1/v1", "m").expect("llm client"),
            ),
        )
        .target_binary,
        workspace: ws.path().to_path_buf(),
        ..PipelineSpec::default()
    };

    let error = assemble_patch(&spec)
        .await
        .expect_err("a patch pass without an LLM must not assemble");
    assert!(
        matches!(error, TranslatorError::MissingLlm { .. }),
        "the LLM is checked before the engine load, got: {error}"
    );
}

#[tokio::test]
async fn assemble_patch_names_a_missing_patch_target() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    // The LLM is fine but no binary is named: a patch pass loads its engine
    // from that path, so the refusal says so by name (issue #327's honest
    // failure surface — nothing half-assembled).
    let spec = PipelineSpec {
        llm: Some(LlmSelection::Client(
            LlmClient::from_url("http://127.0.0.1:1/v1", "m").expect("llm client"),
        )),
        patch_mode: true,
        workspace: ws.path().to_path_buf(),
        ..PipelineSpec::default()
    };

    let error = assemble_patch(&spec)
        .await
        .expect_err("a patch pass with no target binary cannot load its engine");
    match error {
        TranslatorError::MissingPatchTarget { reason } => assert!(
            reason.contains("target binary"),
            "the refusal names what is missing: {reason}"
        ),
        other => panic!("expected MissingPatchTarget, got: {other}"),
    }
}

#[tokio::test]
async fn assemble_patch_loads_its_engine_under_the_configured_budget() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let base = fake_llm(TICK_CODE).await;

    // The patch-mode budget test above through the web entry: spec in, no
    // engine handed in, and the load the assembly performs still honors the
    // configured budgets (issue #327 carries the settings' knobs through).
    let mut spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(LlmClient::from_url(&base, "m").expect("llm client")),
    );
    spec.patch_mode = true;
    spec.kuna_budget = KunaBudget {
        max_instructions: Some(1),
        ..KunaBudget::default()
    };

    let pass = assemble_patch(&spec)
        .await
        .expect("the patch load arms the budget and succeeds");

    let error = pass
        .pipeline
        .translate(TARGET_FILE_NAME, "fixture_tick")
        .await
        .expect_err("the armed instruction budget must trip on the fixture body");
    assert!(
        error.to_string().contains("budget tripped"),
        "the failure should name the budget trip: {error}"
    );
}

// ============================================================
// Retry: the spec's policy lands on the hand-built retry config's shape
// ============================================================

#[tokio::test]
async fn retry_config_from_a_spec_with_no_policy_matches_the_hand_built_default() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(
            LlmClient::from_url("http://127.0.0.1:1/v1", "m").expect("llm client"),
        ),
    );

    let pass = assemble(&spec, &fixture_engine())
        .await
        .expect("the spec assembles");

    // Today's hand-built retry config with settings defaults: 3 attempts,
    // compile-fix, escalation always on, no context-tier cap.
    assert_eq!(pass.retry.max_attempts, 3);
    assert_eq!(pass.retry.retry_strategy, RetryStrategy::CompileFix);
    assert!(pass.retry.escalate_on_failure, "escalation is always on");
    assert_eq!(
        pass.retry.max_context_tier, None,
        "assembly never caps tiers"
    );
}

#[tokio::test]
async fn retry_config_from_a_spec_carrying_a_policy_matches_the_hand_built_ladder() {
    let ws = tempfile::TempDir::new().expect("temp workspace");
    let mut spec = fixture_spec(
        ws.path(),
        LlmSelection::Client(
            LlmClient::from_url("http://127.0.0.1:1/v1", "m").expect("llm client"),
        ),
    );
    spec.retry_max_attempts = Some(5);
    spec.retry_strategy = Some(RetryStrategy::TestFix);

    let pass = assemble(&spec, &fixture_engine())
        .await
        .expect("the spec assembles");

    // Same construction the CLI commands write inline: the policy values
    // carry through, the fixed fields do not move.
    assert_eq!(pass.retry.max_attempts, 5);
    assert_eq!(pass.retry.retry_strategy, RetryStrategy::TestFix);
    assert!(pass.retry.escalate_on_failure);
    assert_eq!(pass.retry.max_context_tier, None);
}

//! Scenario tests split from `tests/e2e.rs`.

use super::*;

/// Issue #380: the per-function analysis artifact the translate path files
/// (issue #379) reaches the Windows API mappings panel intact. A pass
/// assembled from the fixture target's description runs a real `translate`
/// against it; the description points the LLM at a closed port, so the run
/// fails at the LLM call — but the artifact is filed at step 2, before any
/// prompt is built, so it is on disk either way. The unit that translation
/// belongs to enters the review queue the way every unit does, through a
/// translation branch named for it, and the panel section must carry the
/// tagged APIs from the writer's document over `GET /api/units/{id}`.
///
/// The payload fields are pinned exactly as the panel's reader renders
/// them: if the writer's document shape drifts from what `load_api_mappings`
/// deserializes — a renamed key or field, `category` spelled differently —
/// this test fails. Tagging's body-scoping stays pinned on the producer
/// side by the translator's own translate test; what it still guarantees
/// here end to end is that the import the PAL table maps but the function's
/// body never names (`OutputDebugStringA`) stays absent from the panel.
#[tokio::test]
async fn test_translation_artifact_reaches_api_mappings_panel() {
    let fixture = TestFixture::new();
    let repo = fixture.repo_path();
    let binary = calxgloss_testfixtures::TARGET_FILE_NAME;

    let spec = PipelineSpec {
        llm: Some(closed_port_llm_selection()),
        workspace: repo.clone(),
        api_mappings: Some(test_only_api_mappings()),
        ..Default::default()
    };
    let fixture_target =
        calxgloss_testfixtures::load_target().expect("fixture target should build and validate");
    let analysis_engine = calxgloss_kuna::KunaSource::load(fixture_target.path())
        .expect("the fixture should load for scanning with Kuna");
    let pass = calxgloss_translator::assembly::assemble(&spec, &analysis_engine)
        .await
        .expect("the pass assembles");

    // The run fails at the closed LLM port — expected. The artifact filed
    // at step 2 is on disk regardless of how the run ends.
    let outcome = pass.pipeline.translate(binary, "fixture_tick").await;
    assert!(
        outcome.is_err(),
        "the pass should fail at the closed LLM port, not complete"
    );
    let artifact = calxgloss_types::analysis_dir(&repo)
        .join(binary)
        .join("fixture_tick.json");
    assert!(
        artifact.exists(),
        "the run should have filed the artifact at step 2 before failing: {outcome:?}"
    );

    // The unit enters the review queue through its translation branch, the
    // same as every unit on this surface.
    let git = GitManager::open(&repo).expect("open the fixture repo");
    git.create_branch(binary, "fixture_tick", 1, None)
        .expect("create the v1 branch");
    let branch = GitBranch::new(binary, "fixture_tick", 1).expect("branch name");
    std::fs::create_dir_all(repo.join("src/modules")).expect("src dir");
    std::fs::write(
        repo.join("src/modules").join("fixture_tick.rs"),
        "pub fn fixture_tick() {}\n",
    )
    .expect("write translation");
    git.commit(
        &branch,
        "Translate fixture_tick",
        &["src/modules/fixture_tick.rs"],
    )
    .expect("commit translation");

    // Serve the workspace and read the panel's section off the real
    // endpoint.
    let state = ServerState::new(repo);
    let router = build_router(state);
    let _server = spawn_server(router, fixture.port()).await;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let unit_id = format!("{binary}/fixture_tick/v1");
    let encoded_id = urlencoding::encode(&unit_id);
    let resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/units/{}",
        fixture.port(),
        encoded_id
    ))
    .await
    .expect("unit detail request succeeds");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("unit detail body is JSON");
    assert_eq!(body["success"], true);

    let mappings = body["unit"]["analysis"]["api_mappings"]
        .as_array()
        .expect("api_mappings array");
    assert_eq!(
        mappings,
        &[serde_json::json!({
            "name": "GetTickCount",
            "category": "Win32Core",
            "pal_mapping": "std::time::Instant",
        })],
        "the writer's document reaches the panel with every field intact: \
         exactly the API the body names, spelled as the reader reads it"
    );
}

/// The pass's LLM, described against a closed port (issue #380): the pass
/// reaches step 2's artifact filing, then fails at the first LLM call —
/// and the artifact is on disk regardless of how the run ends.
fn closed_port_llm_selection() -> calxgloss_translator::assembly::LlmSelection {
    calxgloss_translator::assembly::LlmSelection::Description(
        calxgloss_translator::assembly::LlmDescription {
            endpoint: "http://127.0.0.1:1/v1".to_string(),
            model: "qwen3".to_string(),
            api_key: None,
            context_window: None,
            temperature: None,
            timeout_secs: None,
        },
    )
}

/// A two-entry PAL table for the pass, as the translator's translate test
/// uses (issue #380): the expectations this scenario asserts are literals,
/// independent of any drift in the built-in table. Both entries name real
/// imports of the fixture target, so the import-table filter engages; only
/// `GetTickCount` is named in the translated body, which is exactly what
/// body-scoped tagging must let through.
fn test_only_api_mappings() -> calxgloss_pal::ApiMappings {
    calxgloss_pal::ApiMappings::from_custom(vec![
        calxgloss_pal::ApiMapping::new(
            "GetTickCount",
            calxgloss_types::ApiCategory::Win32Core,
            "std::time::Instant",
            "test-only mapping",
        ),
        calxgloss_pal::ApiMapping::new(
            "OutputDebugStringA",
            calxgloss_types::ApiCategory::Win32Gui,
            "log::info!",
            "test-only mapping",
        ),
    ])
}

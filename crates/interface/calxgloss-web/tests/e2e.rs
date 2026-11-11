//! End-to-end tests for the web review UI.
//!
//! These tests spin up the axum server in a real git repository with sample
//! data, then verify both API responses and headless-browser rendering.
//! This file holds no helper functions (issue #478). The fixture
//! repository, the booted worlds, the record writers, the waits, and the
//! browser seam all live in the `support` module. All three web test
//! targets wire that module: this e2e family, the accept-conflict test,
//! and the Kuna-scan e2e. The scenario submodules below split out of an
//! earlier version of this file and reach the adapter through `support`.
//!
//! Run everything, API and browser tests alike:
//! `cargo test --features server --test e2e`
//! Browser tests skip themselves at runtime when no Chrome/Chromium is
//! installed; set `$CHROME` to name a browser binary outside the usual search.

#[path = "e2e/analysis_artifact_contract.rs"]
mod analysis_artifact_contract;
#[path = "e2e/analytics_api.rs"]
mod analytics_api;
#[path = "e2e/attempts_api_and_analytics_views.rs"]
mod attempts_api_and_analytics_views;
#[path = "e2e/conformance_web.rs"]
mod conformance_web;
#[path = "e2e/conformance_web_js.rs"]
mod conformance_web_js;
#[path = "e2e/control_endpoints.rs"]
mod control_endpoints;
#[path = "e2e/dashboard_api.rs"]
mod dashboard_api;
#[path = "e2e/headless_binary_and_unit_views.rs"]
mod headless_binary_and_unit_views;
#[path = "e2e/headless_queue_graph_live.rs"]
mod headless_queue_graph_live;
#[path = "e2e/honest_degradation.rs"]
mod honest_degradation;
#[path = "e2e/pipeline_progress_and_llm_log.rs"]
mod pipeline_progress_and_llm_log;
#[path = "e2e/scenario_status.rs"]
mod scenario_status;
#[path = "e2e/support.rs"]
mod support;
#[path = "e2e/unit_detail_and_server_basics.rs"]
mod unit_detail_and_server_basics;
#[path = "e2e/unknown_ledger_web.rs"]
mod unknown_ledger_web;

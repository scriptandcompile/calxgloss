//! The route table for the web server: the shared routes, the live-only
//! routes, and the three router variants assembled from them.
//!
//! Issue #450 moved this table out of `server/mod.rs`, so the live-view
//! store extraction of issue #449 no longer shares the routing file.
//! Nothing about the routes themselves changed.

use axum::{
    Router,
    extract::{DefaultBodyLimit, WebSocketUpgrade},
    middleware,
    routing::{get, patch, post},
};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::actions::ActionsState;
use super::events::{SessionManager, UnitPhaseMessage, WsMessage};
use super::handlers;
use super::llm_io_log::LlmIoLog;
use super::{CombinedState, ProgressState, ServerState};

/// Routes shared by **every** router — plain `serve`, `serve` with review
/// actions, and `live`. An endpoint that reads live translation state must
/// not be added here unless it degrades to an honest empty payload when no
/// live state is attached; `/api/pipeline` is the one such case (issue #61 —
/// the dashboard phase bar renders in every mode). Endpoints that cannot
/// answer honestly without live state belong in [`live_only_routes`]. Server
/// management (`/api/server/*`) is registered here so it is available in
/// every mode.
fn shared_routes() -> Router<CombinedState> {
    Router::new()
        .route("/", get(handlers::serve_index))
        .route("/api/dashboard", get(handlers::api_get_dashboard))
        .route("/api/pipeline", get(handlers::api_get_pipeline))
        .route("/api/units/{id}", get(handlers::api_get_unit))
        .route("/api/units/{id}/diff", get(handlers::api_get_unit_diff))
        // Unit attempt list & metadata (issue #131, W4.5): persisted
        // history only, so plain and live routers answer identically.
        .route(
            "/api/units/{id}/attempts",
            get(handlers::api_get_unit_attempts),
        )
        // Attempt side-by-side diff (issue #135, W4.6): the same read of
        // persisted history, so it is on the shared routes too.
        .route(
            "/api/units/{id}/attempts/diff",
            get(handlers::api_get_unit_attempts_diff),
        )
        .route("/api/units/{id}/decomp", get(handlers::api_get_unit_decomp))
        .route("/api/units/{id}/accept", post(handlers::api_accept_unit))
        .route(
            "/api/units/{id}/send-back",
            post(handlers::api_send_back_unit),
        )
        .route("/api/units/{id}/patch", post(handlers::api_request_patch))
        // Reviewer dispositions over P21 unknown records (issue #374):
        // resolve/dismiss/reopen settle one filed record in the reviewer's
        // own resolutions document — persisted intent, never live pipeline
        // state and never the pipeline's ledger — so they ride the shared
        // routes beside the other unit actions, and need the settings-backed
        // actions backend like the patch request does.
        .route(
            "/api/units/{id}/unknowns/{unknown_id}/resolve",
            post(handlers::api_resolve_unknown),
        )
        .route(
            "/api/units/{id}/unknowns/{unknown_id}/dismiss",
            post(handlers::api_dismiss_unknown),
        )
        .route(
            "/api/units/{id}/unknowns/{unknown_id}/reopen",
            post(handlers::api_reopen_unknown),
        )
        // Batch review actions (issue #78): apply the per-unit accept/
        // send-back/skip logic to a set of units, reporting per-item
        // results. Registered in every router, like the per-unit actions.
        // The id list grows with the queue, so these routes raise the
        // global 16 KB body limit, as the queue overlay PUT does.
        .route(
            "/api/batch/accept",
            post(handlers::api_batch_accept).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/api/batch/send-back",
            post(handlers::api_batch_send_back).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            "/api/batch/skip",
            post(handlers::api_batch_skip).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        // Skip state (issue #75): persisted in every mode — it reads/writes
        // `re/review/skips.json`, never live pipeline state.
        .route("/api/units/{id}/skip", post(handlers::api_skip_unit))
        .route("/api/units/{id}/unskip", post(handlers::api_unskip_unit))
        .route("/api/queue", get(handlers::api_get_queue))
        .route("/api/queue/next", get(handlers::api_get_next_unit))
        // Queue overlay (issue #74): persisted manual order + priority,
        // available in every mode — it reads/writes
        // `re/review/queue_overlay.json`, never live pipeline state. The
        // PUT body contains the full manual order, which grows with the
        // queue, so this route raises the global 16 KB body limit.
        .route(
            "/api/queue/overlay",
            get(handlers::api_get_queue_overlay)
                .put(handlers::api_update_queue_overlay)
                .layer(DefaultBodyLimit::max(256 * 1024)),
        )
        // LLM I/O log (issue #77): persisted in every mode — it reads
        // `re/analysis/llm_io/log.jsonl`, written by the live server as
        // requests/responses happen, never live pipeline state. A workspace
        // that has never run live honestly answers with an empty payload.
        .route("/api/llm-io", get(handlers::api_get_llm_io_log))
        .route("/api/llm-io/clear", post(handlers::api_clear_llm_io_log))
        // Fault analytics (issue #125, W3.1): persisted-history reads — they
        // aggregate `re/analysis/fault_log.json` on demand, never live
        // pipeline state — so every router answers them. A workspace whose
        // fault log is missing or corrupt honestly answers empty payloads.
        .route("/api/faults", get(handlers::api_get_faults))
        .route("/api/faults/summary", get(handlers::api_get_faults_summary))
        .route(
            "/api/faults/by-binary",
            get(handlers::api_get_faults_by_binary),
        )
        .route("/api/faults/trend", get(handlers::api_get_faults_trend))
        // Token usage analytics (issue #126, W3.2): persisted-history reads
        // — they aggregate `re/analysis/token_usage.json` on demand, never
        // live pipeline state — so every router answers them. A workspace
        // whose token log is missing or corrupt honestly answers empty
        // payloads.
        .route(
            "/api/token-usage/summary",
            get(handlers::api_get_token_usage_summary),
        )
        .route(
            "/api/token-usage/by-binary",
            get(handlers::api_get_token_usage_by_binary),
        )
        .route(
            "/api/token-usage/by-tier",
            get(handlers::api_get_token_usage_by_tier),
        )
        .route(
            "/api/token-usage/by-strategy",
            get(handlers::api_get_token_usage_by_strategy),
        )
        // Strategy analytics (issue #127, W3.3): persisted-history reads
        // — they aggregate `re/analysis/prompt_strategy_log.json` on
        // demand, never live pipeline state — so every router answers
        // them. A workspace whose prompt-strategy log is missing or
        // corrupt honestly answers empty payloads.
        .route(
            "/api/strategy-analytics/by-strategy",
            get(handlers::api_get_strategy_analytics_by_strategy),
        )
        .route(
            "/api/strategy-analytics/by-category",
            get(handlers::api_get_strategy_analytics_by_category),
        )
        // LLM performance metrics (issue #128, W3.4): persisted-history
        // reads — they aggregate `re/analysis/token_usage.json` and
        // `re/analysis/fault_log.json` on demand, never live pipeline
        // state — so every router answers them. A workspace whose logs are
        // missing or corrupt honestly answers empty payloads.
        .route(
            "/api/llm-metrics/summary",
            get(handlers::api_get_llm_metrics_summary),
        )
        .route(
            "/api/llm-metrics/by-tier",
            get(handlers::api_get_llm_metrics_by_tier),
        )
        // Binaries view (issue #130, W4.1): a persisted-history read — it
        // aggregates the `re/classify/` records with the persisted
        // classification-override layer applied, the review dashboard's
        // units, and the token-usage log, never live pipeline state — so
        // every router answers it. A workspace whose classification
        // records are missing or corrupt honestly answers an empty list.
        // The live-only `/api/binaries/{name}/classification` endpoint
        // below stays live-only; the read paths do not collide with it.
        // The detail read (issue #132, W4.2) is persisted history too —
        // an unknown binary name honestly 404s rather than answering an
        // empty shell.
        .route("/api/binaries/list", get(handlers::api_get_binaries_list))
        .route("/api/binaries/{name}", get(handlers::api_get_binary_detail))
        // The shim tracker read (issue #133, W4.3) is persisted history
        // too — shim artifacts under `re/shims/` plus the shim branch's
        // verdict in the dashboard's branch model — so every router
        // answers it; missing or corrupt artifacts honestly answer
        // "not generated".
        .route(
            "/api/binaries/{name}/shim-status",
            get(handlers::api_get_binary_shim_status),
        )
        // The PAL tracker read (issue #134, W4.4) is derived on demand
        // from persisted artifacts too — the per-function analysis
        // artifacts' API-call categories for the needed traits, the
        // workspace's generated PAL/shim sources for existence — so
        // every router answers it; missing or corrupt artifacts on
        // either side honestly answer an empty trait list.
        .route(
            "/api/binaries/{name}/pal-status",
            get(handlers::api_get_binary_pal_status),
        )
        .route("/api/graph", get(handlers::api_get_dependency_graph))
        .route("/api/gc/candidates", get(handlers::api_get_gc_candidates))
        .route("/api/gc/archive", post(handlers::api_archive_gc))
        .route("/health", get(handlers::api_health))
        .route("/api/server/status", get(handlers::api_server_status))
        .route("/api/server/shutdown", post(handlers::api_server_shutdown))
        .route("/api/server/restart", post(handlers::api_server_restart))
        .route(
            "/api/server/log-level",
            patch(handlers::api_server_log_level),
        )
        .fallback_service(axum::routing::get(handlers::static_fallback))
}

/// Routes registered **only** in the live (`calxgloss live`) router — these
/// read live translation state that plain `serve` does not own and cannot
/// report honestly without it, so on the other routers they must fall
/// through to the static 404 rather than answer with fabricated empty data.
/// Every W0–W4 endpoint reporting in-flight status belongs here;
/// `/api/pipeline` moved to [`shared_routes`] because it degrades to an
/// honest empty payload instead.
fn live_only_routes() -> Router<CombinedState> {
    Router::new()
        .route("/api/progress", get(handlers::api_get_progress))
        .route(
            "/api/progress/enhanced",
            get(handlers::api_get_progress_enhanced),
        )
        .route("/api/events/upgrade", get(api_events_upgrade_ws))
        // Pipeline lifecycle control (issue #90, W2.1): drive the live run's
        // state machine. Live-only — a plain `serve` router has no pipeline
        // to control, so these must 404 there rather than answer honestly.
        .route("/api/pipeline/pause", post(handlers::api_pause_pipeline))
        .route("/api/pipeline/resume", post(handlers::api_resume_pipeline))
        .route("/api/pipeline/stop", post(handlers::api_stop_pipeline))
        // Cancel the unit in flight (issue #91, W2.2): aborts that unit at
        // the earliest safe point while the run continues. Live-only for
        // the same reason as the other lifecycle endpoints.
        .route(
            "/api/pipeline/cancel-current",
            post(handlers::api_cancel_current_unit),
        )
        // Per-binary pause (issue #221, X6): hold one target binary out of
        // the run's queue without touching the run-level state machine.
        // Live-only — a plain `serve` router has no run queue to hold a
        // binary out of.
        .route(
            "/api/pipeline/binaries/{binary}/pause",
            post(handlers::api_pause_binary),
        )
        .route(
            "/api/pipeline/binaries/{binary}/resume",
            post(handlers::api_resume_binary),
        )
        // Per-binary start (issue #285): one press performs the swap — it
        // pauses the in-flight binary, resumes the pressed one, and puts it
        // at the front of the queue plan. Live-only like the pause/focus
        // pair — without a live loop there is no run to swap onto.
        .route(
            "/api/pipeline/binaries/{binary}/start",
            post(handlers::api_start_binary),
        )
        // Per-binary focus (issue #284): put one discovered binary in the
        // scope record's single focus slot. The running worklist moves it
        // to the front at the next boundary and clears the slot. Live-only
        // — there is no queue to steer without a live run loop.
        .route(
            "/api/pipeline/binaries/{binary}/focus",
            post(handlers::api_focus_binary),
        )
        // Start & restart (issue #92, W2.3): begin translation in a session
        // that has not translated yet, or re-run a stopped pipeline in the
        // same process. Live-only — a plain `serve` router has no live loop
        // to receive the run request.
        .route("/api/pipeline/start", post(handlers::api_start_pipeline))
        .route(
            "/api/pipeline/restart",
            post(handlers::api_restart_pipeline),
        )
        // Translation scope controls (issue #93, W2.5): steer what the run
        // touches and bound what it consumes. Live-only — a plain `serve`
        // router has no pipeline to steer.
        .route("/api/scope", get(handlers::api_scope_status))
        .route(
            "/api/scope/binaries",
            post(handlers::api_scope_set_binaries),
        )
        .route(
            "/api/scope/skip-function",
            post(handlers::api_scope_skip_function),
        )
        .route(
            "/api/scope/priority-function",
            post(handlers::api_scope_priority_function),
        )
        .route(
            "/api/scope/remove-priority-function",
            post(handlers::api_scope_remove_priority_function),
        )
        .route(
            "/api/scope/constraints",
            post(handlers::api_scope_set_constraints),
        )
        // Per-unit reviewer overrides (issue #96, W2.7): steer one unit's
        // next attempt — forced tier/strategy, custom hints, skip. Live-only
        // — a plain `serve` router has no pipeline to steer.
        .route(
            "/api/units/{id}/override",
            get(handlers::api_get_unit_override)
                .post(handlers::api_apply_unit_override)
                .delete(handlers::api_remove_unit_override),
        )
        // Binary classification overrides (issue #97, W2.8): correct a
        // target binary's category (and target crate) from the dashboard;
        // the analyzer honors it before strategy dispatch. Live-only — a
        // plain `serve` router has no run whose classifications to steer.
        .route(
            "/api/binaries/{name}/classification",
            get(handlers::api_get_binary_classification)
                .post(handlers::api_set_binary_classification),
        )
}

/// Apply the middleware layers every router shares.
fn with_common_layers(router: Router) -> Router {
    router
        .layer(middleware::from_fn(handlers::trace_middleware))
        .layer(DefaultBodyLimit::max(16 * 1024))
}

/// Assemble a router from the shared route table, attached to the given
/// combined state. The live-only table is registered exactly when the state
/// includes a [`SessionManager`] — the same dependency the live handlers
/// read — so a live route can never be registered on a router that lacks
/// the live state it needs.
fn assemble(state: CombinedState) -> Router {
    let mut routes = shared_routes();
    if state.manager.is_some() {
        routes = routes.merge(live_only_routes());
    }
    with_common_layers(routes.with_state(state))
}

/// Build the axum router for plain `calxgloss serve` — the shared review
/// surface, without the live-pipeline endpoints.
pub fn build_router(state: ServerState) -> Router {
    assemble(CombinedState {
        server: state,
        manager: None,
        bridge: None,
        actions: None,
        progress: None,
    })
}

/// Build the router for `calxgloss serve` with the review-actions backend
/// attached — still no live-pipeline endpoints.
pub fn build_router_with_actions(state: ServerState, actions: ActionsState) -> Router {
    assemble(CombinedState {
        server: state,
        manager: None,
        bridge: None,
        actions: Some(actions),
        progress: None,
    })
}

/// Build the router for `calxgloss live`: the shared surface plus the
/// live-only pipeline-progress and WebSocket endpoints, with the settings-
/// backed review-actions backend attached (issue #327), so the review UI's
/// patch retry runs a real assembled pass in live mode too.
pub fn build_router_with_ws(
    state: ServerState,
    manager: SessionManager,
    progress: ProgressState,
    actions: ActionsState,
) -> Router {
    // Wire the session manager's callback so that every translation
    // progress event also updates the in-memory ProgressState.
    //
    // Events are handed to one consumer task over a channel rather than
    // spawning a task per event: per-event tasks raced for the state lock
    // and applied events out of order, so a unit's final state depended on
    // task scheduling instead of event order.
    let progress_clone = progress.clone();
    let manager_clone = manager.clone();
    // Server-side LLM I/O log (issue #77): every request/response/error the
    // run emits is appended to `re/analysis/llm_io/log.jsonl` as it happens,
    // so `GET /api/llm-io` can serve the history a page reload would
    // otherwise lose.
    let llm_io_log = LlmIoLog::new(state.repo_path());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<calxgloss_types::ProgressEvent>();
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            llm_io_log.record(&event);
            progress_clone.apply(&event).await;
            // WS phase events (issue #55): once a unit-scoped event is
            // applied, push that unit's full live record — current phase,
            // phase history, tier, evidence — so the live view updates the
            // row in place instead of refetching the enhanced endpoint.
            // The store hands out the shared record directly (issue #452).
            if let Some(unit) = event.unit_key()
                && let Some(record) = progress_clone
                    .entry(unit.binary().as_str(), unit.function())
                    .await
            {
                manager_clone
                    .push(WsMessage::UnitPhase(UnitPhaseMessage::new(record)))
                    .await;
            }
        }
    });
    manager.set_event_callback(move |event| {
        let _ = tx.send(event.clone());
    });

    assemble(CombinedState {
        server: state,
        manager: Some(manager),
        bridge: None,
        actions: Some(actions),
        progress: Some(Arc::new(RwLock::new(progress))),
    })
}

/// WebSocket upgrade handler for live progress events.
async fn api_events_upgrade_ws(
    ws: WebSocketUpgrade,
    axum::extract::State(combined): axum::extract::State<CombinedState>,
) -> axum::response::Response {
    let manager = combined.manager.expect("SessionManager not configured");
    ws.on_upgrade(move |ws| async move {
        let handler = manager.register_client().await;
        handler.process(ws).await;
    })
}

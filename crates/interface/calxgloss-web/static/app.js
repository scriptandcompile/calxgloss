/* ==========================================================================
   Calxgloss Web — Application entry point

   Plain ES modules, loaded natively (no build step). This file wires the
   per-view modules together: shared state, event listeners, the WebSocket
   handler, and startup. View rendering/interaction lives in ./js/*.js.
   ========================================================================== */

import { State } from "./js/state.js";
import { switchView } from "./js/views.js";
import {
    loadDashboard,
    renderQueueList,
    loadPipelineProgress,
    updateGraphFilterSummary,
} from "./js/dashboard.js";
import {
    renderFullQueue,
    showDetail,
    renderInlineDetail,
    hideDetail,
    acceptUnit,
    showSendBackModal,
    showPatchModal,
    setupQueueDragAndDrop,
    cycleQueuePriority,
    toggleQueueSkip,
} from "./js/queue.js";
import { GraphRenderer } from "./js/graph.js";
import { WSManager } from "./js/ws.js";
import { addLlmLogEntry, clearLlmLog } from "./js/llm-log.js";
import { loadGcCandidates, archiveSelectedGc } from "./js/gc.js";
import { loadLiveProgress, applyUnitPhase } from "./js/live.js";
import { showToast } from "./js/ui.js";

// ─── Event Handlers ─────────────────────────────────────────────────────

function setupEventListeners() {
    // Nav tabs
    document.querySelectorAll(".nav-tab").forEach(tab => {
        tab.addEventListener("click", () => switchView(tab.dataset.view));
    });



    // Refresh button
    document.getElementById("btn-refresh").addEventListener("click", loadDashboard);

    // Queue list clicks (dashboard) — switch to queue view
    document.getElementById("queue-list").addEventListener("click", (e) => {
        const item = e.target.closest(".queue-item");
        if (!item) return;
        switchView("queue");
        renderFullQueue(State.dashboard, item.dataset.unitId);
        renderInlineDetail(item.dataset.unitId);
    });

    // Full queue list clicks (queue view) — show inline detail; the
    // priority chip cycles the unit's priority instead (issue #74), and
    // the skip checkbox toggles skip state instead (issue #75).
    const fullQueueList = document.getElementById("full-queue-list");
    fullQueueList.addEventListener("click", (e) => {
        const item = e.target.closest(".queue-item-full");
        if (!item) return;
        if (e.target.closest(".qi-priority")) {
            cycleQueuePriority(item.dataset.unitId);
            return;
        }
        if (e.target.closest(".qi-skip-check")) return;
        State.selectedUnitId = item.dataset.unitId;
        renderInlineDetail(item.dataset.unitId);
        renderFullQueue(State.dashboard, State.selectedUnitId);
    });

    // Skip checkbox (issue #75): checking skips the unit, unchecking
    // restores it to the active queue.
    fullQueueList.addEventListener("change", (e) => {
        const box = e.target.closest(".qi-skip-check");
        if (!box) return;
        const item = box.closest(".queue-item-full");
        if (item) toggleQueueSkip(item.dataset.unitId, box.checked);
    });

    // Drag-and-drop reordering of the queue (issue #74).
    setupQueueDragAndDrop();

    // Detail panel close
    document.getElementById("detail-close").addEventListener("click", hideDetail);

    // Back to list (inline queue view)
    document.getElementById("queue-detail-close").addEventListener("click", hideDetail);

    // Detail panel actions
    document.addEventListener("click", (e) => {
        const btn = e.target.closest("[id^='btn-']");
        if (!btn) return;

        const unitId = State.selectedUnitId;
        if (!unitId) return;

        if (btn.id === "btn-accept") {
            acceptUnit(unitId);
        } else if (btn.id === "btn-send-back") {
            showSendBackModal(unitId);
        } else if (btn.id === "btn-patch") {
            showPatchModal(unitId);
        } else if (btn.id === "btn-reload-detail") {
            showDetail(unitId);
        }
    });

    // Status filter
    const filterSelect = document.getElementById("status-filter");
    filterSelect.addEventListener("change", () => {
        State.statusFilter = filterSelect.value;
        if (State.dashboard) {
            renderFullQueue(State.dashboard, State.selectedUnitId);
        }
    });

    // Graph view buttons (overlay in container)
    document.getElementById("btn-fit-graph-full")?.addEventListener("click", () => {
        if (State.graphRendererFull) {
            State.graphRendererFull.resetZoom();
        }
    });
    document.getElementById("btn-reset-graph-full")?.addEventListener("click", () => {
        if (State.graphRendererFull) {
            State.graphRendererFull.resetZoom();
        }
    });

    // Graph filter selects (issue #76) — kind × status × binary, combined
    // with AND inside the renderer.
    const filterSelects = {
        "graph-filter-kind": "kind",
        "graph-filter-status": "status",
        "graph-filter-binary": "binary",
    };
    Object.entries(filterSelects).forEach(([id, key]) => {
        document.getElementById(id)?.addEventListener("change", (e) => {
            State.graphFilters[key] = e.target.value;
            State.graphRendererFull?.applyFilters();
            updateGraphFilterSummary();
        });
    });

    // LLM I/O log clear button
    document.getElementById("btn-clear-llm-log")?.addEventListener("click", clearLlmLog);

    // GC tab buttons
    document.getElementById("btn-scan-gc")?.addEventListener("click", loadGcCandidates);
    document.getElementById("btn-archive-all-gc")?.addEventListener("click", archiveSelectedGc);
    document.getElementById("gc-select-all")?.addEventListener("change", () => {
        // Handled inline in renderGcTable
    });
    document.getElementById("gc-days-input")?.addEventListener("change", loadGcCandidates);

    // Graph click handler — opens detail panel for clicked node
    function handleGraphNodeClick(node) {
        showDetail(node.id);
    }

    // Keyboard shortcuts (graph view pan/zoom)
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            if (document.querySelector(".modal-overlay")) {
                document.querySelector(".modal-overlay")?.remove();
            } else if (document.getElementById("detail-panel").classList.contains("open")) {
                hideDetail();
            }
        }
        // Graph view keyboard shortcuts
        if (State.currentView === "graph" && State.graphRendererFull) {
            State.graphRendererFull.handleKeydown(e);
        }
    });

    // Keyboard shortcuts for queue navigation
    document.addEventListener("keydown", (e) => {
        if (State.currentView === "graph") return; // handled above
        if (e.key === "n" && State.selectedUnitId && !e.target.matches("textarea, input")) {
            if (State.dashboard) {
                const units = State.dashboard.review_queue.filter(u => !u.accepted);
                const idx = units.findIndex(u => u.id === State.selectedUnitId);
                if (idx >= 0 && idx < units.length - 1) {
                    const next = units[idx + 1];
                    showDetail(next.id);
                    renderQueueList(State.dashboard, next.id);
                    renderFullQueue(State.dashboard, next.id);
                }
            }
        }
        if (e.key === "p" && State.selectedUnitId && !e.target.matches("textarea, input")) {
            if (State.dashboard) {
                const units = State.dashboard.review_queue.filter(u => !u.accepted);
                const idx = units.findIndex(u => u.id === State.selectedUnitId);
                if (idx > 0) {
                    const prev = units[idx - 1];
                    showDetail(prev.id);
                    renderQueueList(State.dashboard, prev.id);
                    renderFullQueue(State.dashboard, prev.id);
                }
            }
        }
    });

    // Full-screen graph click handler
    document.getElementById("graph-canvas-full")?.addEventListener("click", (e) => {
        State.graphRendererFull?.handleCanvasClick(e);
    });
}

// ─── WebSocket Event Handler ────────────────────────────────────────────

/* Coalesces WS-triggered dashboard refreshes: a live run emits many events
   per second, and each one used to kick off a full git-backed dashboard
   rebuild and re-render — the visible bounce. One rebuild per short window
   keeps the data current without the churn. */
let dashboardRefreshTimer = null;
function scheduleDashboardRefresh() {
    if (dashboardRefreshTimer) return;
    dashboardRefreshTimer = setTimeout(() => {
        dashboardRefreshTimer = null;
        loadDashboard();
    }, 2000);
}

function handleWSMessage(event) {
    console.log("[WS] handleWSMessage event:", event.event);

    // Per-unit phase record pushed after each unit event (issue #55) —
    // update the live row in place. The raw event that accompanied it
    // already drives everything below, so the record itself stops here.
    if (event.event === "unit_phase") {
        applyUnitPhase(event.unit);
        return;
    }

    // Handle translation start — show a toast notification
    if (event.event === "translation_started") {
        showToast(
            `Translating ${event.function || "classify"} (${event.binary})`,
            "info"
        );
        // Update the live indicator
        const indicator = document.getElementById("live-indicator");
        if (indicator) indicator.classList.add("active");
    }

    // Handle translation completion
    if (event.event === "translation_completed" || event.event === "translation_failed") {
        showToast(
            `${event.event === "translation_completed" ? "✓" : "✗"} Done: ${event.function || "classify"} (${event.binary})`,
            event.event === "translation_completed" ? "success" : "error"
        );
    }

    // Handle classification completion
    if (event.event === "classification_complete") {
        showToast(
            `Classified ${event.binary} → ${event.category}`,
            "success"
        );
        // Reload pipeline to show updated status
        loadPipelineProgress();
    }

    // Handle batch summary
    if (event.event === "batch_summary") {
        const b = event;
        showToast(
            `Batch ${event.binary}: ${b.success_count}/${b.total_functions} succeeded`,
            b.failure_count > 0 ? "warning" : "success"
        );
        // Reload pipeline to show updated status
        loadPipelineProgress();
    }

    // Handle LLM I/O events
    if (event.event === "llm_request") {
        console.log("[WS] LLM request:", event.binary, event.function, "prompt length:", event.prompt?.length);
        addLlmLogEntry(
            "request",
            event.binary,
            event.function,
            event.attempt,
            event.strategy,
            event.prompt
        );
    } else if (event.event === "llm_response") {
        console.log("[WS] LLM response:", event.binary, event.function, "content length:", event.content?.length);
        addLlmLogEntry(
            "response",
            event.binary,
            event.function,
            event.attempt,
            event.strategy,
            event.content
        );
    } else if (event.event === "llm_call_failed") {
        console.warn("[WS] LLM call failed:", event.binary, event.function, event.error);
        addLlmLogEntry(
            "error",
            event.binary,
            event.function,
            event.attempt,
            event.strategy,
            `Error: ${event.error}`
        );
    }

    // Silently refresh dashboard data on any progress event (coalesced —
    // see scheduleDashboardRefresh). The live view needs no refetch here:
    // the server pushes a `unit_phase` record after every unit event, and
    // that updates the rows in place.
    scheduleDashboardRefresh();
}

// ─── Zoom indicator display ─────────────────────────────────────────────

function updateZoomIndicator(scale) {
    const el = document.getElementById("zoom-indicator");
    if (el) {
        el.textContent = `${Math.round(scale * 100)}%`;
    }
}

// ─── Landing view preference (issue #66) ────────────────────────────────

const LANDING_VIEW_KEY = "calxgloss_landing_view";

/* Applies the saved landing view (dashboard by default) and wires the
   topbar select so the choice persists across reloads. */
function setupLandingView() {
    const select = document.getElementById("landing-view");
    const saved = localStorage.getItem(LANDING_VIEW_KEY) || "dashboard";

    if (select) {
        select.value = saved;
        select.addEventListener("change", () => {
            localStorage.setItem(LANDING_VIEW_KEY, select.value);
        });
    }

    if (saved !== "dashboard") {
        switchView(saved);
    }
}

// ─── Initialization ─────────────────────────────────────────────────────

async function init() {
    setupEventListeners();
    setupLandingView();

    // Initialize full-screen graph renderer
    State.graphRendererFull = new GraphRenderer(document.getElementById("graph-canvas-full"), {
        onZoomChange: updateZoomIndicator,
    });
    // Debug/test handle — lets the headless e2e tests inspect node geometry
    // and drive filters without simulating canvas interaction.
    window.calxglossGraph = State.graphRendererFull;

    // Initialize WebSocket for live updates
    console.log("[WS] Initializing WebSocket manager");
    State.wsManager = new WSManager(handleWSMessage);
    // After a reconnect the records missed during the gap are gone — resync
    // the live view from a fresh snapshot rather than trust stale rows.
    State.wsManager.onOpen = () => {
        if (State.currentView === "live") {
            loadLiveProgress();
        }
    };
    State.wsManager.connect();

    // Load initial data
    await loadDashboard();

    // Auto-refresh every 30 seconds
    setInterval(loadDashboard, 30000);
}

// Start the app
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
} else {
    init();
}

/* ==========================================================================
   View (tab) switching — shared across every nav-tab entry point
   ========================================================================== */

import { State } from "./state.js";
import { renderFullQueue } from "./queue.js";
import { loadGcCandidates } from "./gc.js";
import { startLiveView, stopLiveView } from "./live.js";
import { loadPipelineProgress } from "./dashboard.js";
import { loadLlmLogHistory } from "./llm-log.js";
import { loadFaults } from "./faults.js";
import { loadTokenUsage } from "./token-usage.js";
import { loadStrategyAnalytics } from "./strategy-analytics.js";

// The tab the operator was last on, persisted so a browser reload lands
// back where they were instead of always opening on the dashboard.
const LAST_VIEW_KEY = "calxgloss_last_view";

/* The view to open on page load: the last one switched to, or dashboard
   when nothing was saved (or the saved name no longer names a real tab). */
export function lastView() {
    const saved = localStorage.getItem(LAST_VIEW_KEY);
    if (!saved) return "dashboard";
    const views = [...document.querySelectorAll(".nav-tab")].map(t => t.dataset.view);
    return views.includes(saved) ? saved : "dashboard";
}

export function switchView(viewName) {
    State.currentView = viewName;
    localStorage.setItem(LAST_VIEW_KEY, viewName);
    document.querySelectorAll(".nav-tab").forEach(t => {
        t.classList.toggle("active", t.dataset.view === viewName);
    });
    document.querySelectorAll(".view").forEach(v => {
        v.classList.toggle("view-active", v.id === `view-${viewName}`);
    });

    if (viewName === "graph" && State.graphRendererFull) {
        setTimeout(() => {
            State.graphRendererFull._resize();
            // A camera restored from a shared URL (issue #79) survives the
            // view switch — only a plain entry refits the graph.
            if (!State.graphRendererFull._restoredCamera) {
                State.graphRendererFull.resetZoom();
            }
        }, 50);
    }

    // Render full queue when switching to queue view
    if (viewName === "queue" && State.dashboard) {
        renderFullQueue(State.dashboard, State.selectedUnitId);
    }

    if (viewName === "llm-log") {
        // Reload the persisted history on entry (issue #80) — dedup keeps
        // live entries intact — and focus the log container.
        loadLlmLogHistory().catch((err) => console.warn("[LLM log] history load failed:", err));
        const container = document.getElementById("llm-log-container");
        if (container) container.focus();
    }

    // Load GC candidates when switching to the GC view
    if (viewName === "gc") {
        loadGcCandidates();
    }

    // Faults analytics (issue #125): reload the filtered set on entry so
    // the view always reflects the current fault log.
    if (viewName === "faults") {
        loadFaults().catch((err) => console.warn("[Faults] load failed:", err));
    }

    // Token usage analytics (issue #126): reload the filtered set on
    // entry so the view always reflects the current token usage log.
    if (viewName === "token-usage") {
        loadTokenUsage().catch((err) => console.warn("[Token usage] load failed:", err));
    }

    // Strategy analytics (issue #127): reload the filtered set on entry
    // so the view always reflects the current prompt-strategy log.
    if (viewName === "strategy-analytics") {
        loadStrategyAnalytics().catch((err) => console.warn("[Strategy analytics] load failed:", err));
    }

    // Live view: fetch on entry, tick elapsed clocks while visible.
    if (viewName === "live") {
        startLiveView();
    } else {
        stopLiveView();
    }

    // Pipeline view: refresh the overview on entry (issue #66).
    if (viewName === "pipeline") {
        loadPipelineProgress();
    }
}

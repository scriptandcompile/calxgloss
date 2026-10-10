/* ==========================================================================
   View (tab) switching — shared across every nav-tab entry point
   ========================================================================== */

import { State } from "./state.js";
import { renderFullQueue } from "./queue.js";
import { loadGcCandidates } from "./gc.js";
import { startLiveView, stopLiveView } from "./live.js";
import { loadPipelineProgress } from "./dashboard.js";

export function switchView(viewName) {
    State.currentView = viewName;
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
        // Focus the log container when switching to LLM log view
        const container = document.getElementById("llm-log-container");
        if (container) container.focus();
    }

    // Load GC candidates when switching to the GC view
    if (viewName === "gc") {
        loadGcCandidates();
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

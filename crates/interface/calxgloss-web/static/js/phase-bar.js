/* ==========================================================================
   Pipeline phase bar — horizontal master-plan progress (issue #61)

   Renders one segment per pipeline phase (Phases 1–7 plus Phase 2.5 PAL
   Design) from the `phases` array served by GET /api/pipeline. Honesty is
   the load-bearing rule: phases with no backing data source (Restitching,
   Documentation) render as "No data source", never as zero progress.
   ========================================================================== */

import { escapeHtml } from "./utils.js";

const PHASE_LABELS = {
    project_ingestion: "Ingestion",
    disassembly_tagging: "Disassembly",
    pal_design: "PAL Design",
    test_generation: "Test Gen",
    rust_code_generation: "Code Gen",
    behavior_verification: "Verification",
    restitching: "Restitching",
    documentation: "Docs",
};

const STATE_LABELS = {
    not_started: "Not started",
    in_progress: "In progress",
    complete: "Complete",
    no_data_source: "No data source",
};

/**
 * Render the horizontal phase bar into #pipeline-phase-bar.
 * @param {Array<{phase: string, state: string, completed?: number, total?: number}>} phases
 */
export function renderPipelinePhaseBar(phases) {
    const bar = document.getElementById("pipeline-phase-bar");
    if (!bar) return;

    if (!Array.isArray(phases) || phases.length === 0) {
        bar.innerHTML = "";
        return;
    }

    bar.innerHTML = phases.map(p => {
        const phase = p.phase || "unknown";
        const state = p.state || "not_started";
        const label = PHASE_LABELS[phase] || phase;
        const stateLabel = STATE_LABELS[state] || state;
        // No-data-source phases never show fabricated counts.
        const count = state === "no_data_source" ? "—" : `${p.completed ?? 0}/${p.total ?? 0}`;

        return `
            <div class="phase-segment state-${escapeHtml(state)}" data-phase="${escapeHtml(phase)}" title="${escapeHtml(label)}: ${escapeHtml(stateLabel)}">
                <span class="phase-segment-name">${escapeHtml(label)}</span>
                <span class="phase-segment-state">${escapeHtml(stateLabel)}</span>
                <span class="phase-segment-count">${escapeHtml(count)}</span>
            </div>`;
    }).join("");
}

/* ==========================================================================
   Dashboard view — status cards, review queue summary, activity,
   pipeline progress
   ========================================================================== */

import { API } from "./api.js";
import { State } from "./state.js";
import { KIND_LABELS, STATUS_LABELS } from "./constants.js";
import { fmtTime, escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";
import { renderFullQueue } from "./queue.js";
import { switchView } from "./views.js";

export async function loadDashboard() {
    try {
        const res = await API.dashboard();
        State.dashboard = res.dashboard;
        State.units = State.dashboard.review_queue;

        renderStatusCards(State.dashboard);
        renderQueueList(State.dashboard, State.selectedUnitId);
        renderActivity(State.dashboard.recent_activity);

        if (State.currentView === "queue") {
            renderFullQueue(State.dashboard, State.selectedUnitId);
        }

        // Update graph data
        const graphRes = await API.graph();
        const graph = graphRes.graph;

        const nodes = (graph.nodes || []).map(n => mapGraphNode(n));
        const edges = graph.edges || [];

        if (State.graphRenderer) {
            State.graphRenderer.setData(nodes, edges);
        }
        if (State.graphRendererFull) {
            State.graphRendererFull.setData(nodes, edges);
        }

        // Load pipeline progress in parallel
        loadPipelineProgress();

        // Load stale branches card (non-critical, runs in background)
        renderStaleBranchesCard();
    } catch (err) {
        showToast(`Failed to load dashboard: ${err.message}`, "error");
    }
}

export function renderStatusCards(dashboard) {
    const container = document.getElementById("status-cards");
    if (!container) return;

    const counts = dashboard.status_counts;
    const cards = [
        { cls: "queued", label: "Queued", value: counts.queued },
        { cls: "pending", label: "Pending Review", value: counts.pending_review },
        { cls: "in_progress", label: "In Progress", value: counts.in_progress },
        { cls: "accepted", label: "Accepted", value: counts.accepted },
        { cls: "sendback", label: "Send Back", value: counts.send_back },
        { cls: "blocked", label: "Blocked", value: counts.blocked },
    ];

    container.innerHTML = cards
        .filter(c => c.value > 0)
        .map(c => `
            <div class="status-card ${c.cls}">
                <div class="status-card-label">${c.label}</div>
                <div class="status-card-value">${c.value}</div>
            </div>
        `).join("");
}

export async function renderStaleBranchesCard() {
    try {
        const res = await API.gcCandidates(7);
        const container = document.getElementById("status-cards");
        if (!container) return;

        const count = res.candidates?.length || 0;
        if (count > 0) {
            const card = document.createElement("div");
            card.className = "status-card stale_branches";
            card.innerHTML = `
                <div class="status-card-label">Stale Branches</div>
                <div class="status-card-value">${count}</div>
            `;
            card.addEventListener("click", () => switchView("gc"));
            container.appendChild(card);
        }
    } catch {
        // Silently fail — stale card is non-critical
    }
}

function renderQueueItem(unit, selected = false) {
    const iconClass = unit.status.toLowerCase().replace(/\s+/g, "_");
    const name = unit.kind === "dll_classification"
        ? `Classify ${unit.dll}`
        : unit.function ? `${unit.dll} ${unit.function}` : unit.dll;

    return `
        <div class="queue-item ${selected ? "selected" : ""}" data-unit-id="${unit.id}">
            <div class="queue-item-icon ${iconClass}"></div>
            <div class="queue-item-info">
                <div class="queue-item-name" title="${name}">${name}</div>
                <div class="queue-item-meta">
                    <span>${KIND_LABELS[unit.kind] || unit.kind}</span>
                    ${unit.stale === "stale" ? '<span class="queue-item-stale">⚠ Stale</span>' : ""}
                    ${unit.stale === "critical" ? '<span class="queue-item-stale" style="color:var(--accent-red)">🔴 Critical</span>' : ""}
                </div>
            </div>
        </div>
    `;
}

export function renderQueueList(dashboard, selectedId = null) {
    const list = document.getElementById("queue-list");
    const empty = document.getElementById("queue-empty");
    const count = document.getElementById("queue-count");
    if (!list || !empty || !count) return;

    const active = dashboard.review_queue.filter(u => !u.accepted);

    count.textContent = active.length;

    if (active.length === 0) {
        list.innerHTML = "";
        empty.style.display = "flex";
        return;
    }

    empty.style.display = "none";
    list.innerHTML = active.map(u => renderQueueItem(u, u.id === selectedId)).join("");
}

export function renderActivity(activity) {
    const list = document.getElementById("activity-list");
    if (!list) return;

    if (!activity || activity.length === 0) {
        list.innerHTML = `<div class="empty-state">No recent activity.</div>`;
        return;
    }

    list.innerHTML = activity.slice(0, 10).map(u => {
        const iconCls = u.accepted ? "accept" : "sendback";
        const icon = u.accepted ? "✓" : "↩";
        const name = u.kind === "dll_classification"
            ? `Classify ${u.dll}`
            : u.function ? `${u.dll}/${u.function}` : u.dll;
        const actionText = u.accepted ? "accepted" : "sent back";

        return `
            <div class="activity-item">
                <div class="activity-icon ${iconCls}">${icon}</div>
                <div class="activity-text"><strong>${name}</strong> ${actionText}</div>
                <div class="activity-time">${fmtTime(u.updated_at)}</div>
            </div>
        `;
    }).join("");
}

// ─── Pipeline Progress ──────────────────────────────────────────────────

export async function loadPipelineProgress() {
    try {
        const res = await API.pipeline();
        renderPipelineProgress(res);
    } catch (err) {
        // Silently fail — pipeline panel is optional
        console.debug("Failed to load pipeline progress:", err.message);
    }
}

export function renderPipelineProgress(data) {
    const panel = document.getElementById("pipeline-panel");
    const summary = document.getElementById("pipeline-summary");
    const dllsContainer = document.getElementById("pipeline-dlls");

    if (!panel || !summary || !dllsContainer) return;

    const total = data.total_dlls || 0;
    const classified = data.classified_count || 0;
    const batchDone = data.batch_complete_count || 0;
    const translating = data.currently_translating || [];

    // Show panel only if there's something to show
    if (total === 0) {
        panel.style.display = "none";
        return;
    }

    panel.style.display = "block";
    summary.textContent = `${classified} classified, ${batchDone} translated, ${translating.length} translating`;

    // Build DLL progress items
    const dlls = data.dlls || [];
    if (dlls.length === 0) {
        dllsContainer.innerHTML = '<div class="empty-state" style="padding:12px">No DLLs discovered yet.</div>';
        return;
    }

    dllsContainer.innerHTML = dlls.map(dll => {
        const name = dll.dll || "unknown";
        const hasClassification = !!dll.classification;
        const hasBatch = !!dll.batch;
        const isTranslating = !!dll.in_progress;

        let statusClass = "pending";
        let statusText = "Pending";

        if (isTranslating) {
            statusClass = "translating";
            const progress = dll.in_progress;
            const pct = progress.total_entries > 0
                ? Math.round((progress.completed_entries / progress.total_entries) * 100)
                : 0;
            statusText = `<div class="pipeline-progress-bar"><div class="pipeline-progress-fill" style="width:${pct}%"></div></div>`;
        } else if (hasBatch) {
            statusClass = "complete";
            const b = dll.batch;
            statusText = `${b.success_count}/${b.total_functions} OK`;
        } else if (hasClassification) {
            statusClass = "classified";
            statusText = dll.classification.category;
        }

        // Classification details
        let meta = "";
        if (dll.classification) {
            const c = dll.classification;
            let parts = [c.strategy];
            if (c.exported_symbols > 0 || c.imported_symbols > 0) {
                parts.push(`${c.exported_symbols}↑ ${c.imported_symbols}↓`);
            }
            if (c.crate_replacement) {
                parts.push(`→ ${c.crate_replacement}`);
            }
            meta = parts.join(" · ");
        } else if (dll.batch) {
            const b = dll.batch;
            if (b.failure_count > 0) {
                meta = `${b.failure_count} failed · ${b.total_tokens} tokens`;
            } else {
                meta = `${b.total_tokens} tokens`;
            }
        }

        return `
            <div class="pipeline-dll-item">
                <span class="pipeline-dll-name">${escapeHtml(name)}</span>
                <span class="pipeline-dll-status ${statusClass}">${statusText}</span>
                ${meta ? `<span class="pipeline-dll-meta">${escapeHtml(meta)}</span>` : ""}
            </div>
        `;
    }).join("");
}

// Map API graph node to frontend format (handles old and new API formats)
function mapGraphNode(n) {
    let kind = n.kind || null;
    let kindLabel = n.kind_label || null;

    // New API: sends "kind" field directly
    if (!kind) {
        // Old API: infer from level field
        const level = n.level || n.kind || "function_translation";
        const levelMap = {
            dll_classification: "dll_classification",
            shim_layer: "shim_layer",
            pal_trait: "pal_trait",
            test_case_addition: "test_case_addition",
            function_translation: "function_translation",
            integration_step: "integration_step",
            bug_fix: "bug_fix",
        };
        kind = levelMap[level] || "function_translation";
    }
    if (!kindLabel) {
        kindLabel = KIND_LABELS[kind] || kind;
    }

    return {
        id: n.id || n.unit_id,
        name: n.label || n.name || n.unit_id,
        kind: kind,
        kind_label: kindLabel,
        status: n.status || STATUS_LABELS[n.kind] || "queued",
    };
}

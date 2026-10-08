/* ==========================================================================
   Dashboard view — status cards, review queue summary, activity,
   pipeline progress
   ========================================================================== */

import { API } from "./api.js";
import { State } from "./state.js";
import { KIND_LABELS, STATUS_LABELS } from "./constants.js";
import { fmtTime, fmtUptime, escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";
import { renderFullQueue } from "./queue.js";
import { renderPipelinePhaseBar } from "./phase-bar.js";
import { renderPipelineBinaryRows } from "./binary-rows.js";
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

        // Server status card (uptime, version, resources — non-critical)
        const serverStatus = await renderServerStatusCard();

        // Server control panel (shutdown / restart / log level — issue #60)
        if (serverStatus) {
            renderServerControlPanel(serverStatus);
        }
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

/* Server status card — uptime, version, host, log level, memory/CPU,
   WebSocket connections, open file handles, and pipeline state, all from
   GET /api/server/status (issue #59). Returns the status so the control
   panel can share it, or null when the fetch fails. */
export async function renderServerStatusCard() {
    try {
        const status = await API.serverStatus();
        const container = document.getElementById("status-cards");
        if (!container) return null;

        const pipelineLabels = { unavailable: "no pipeline", idle: "idle", running: "running" };
        const card = document.createElement("div");
        card.id = "server-status-card";
        card.className = "status-card server";
        card.title = `Pipeline: ${status.pipeline_status} · Host: ${status.host} · Log level: ${status.log_level}`;
        card.innerHTML = `
            <div class="status-card-label">Server</div>
            <div class="status-card-value" id="server-status-uptime">${fmtUptime(status.uptime_secs)}</div>
            <div class="server-status-meta">
                <span id="server-status-version">v${escapeHtml(status.version)}</span>
                <span id="server-status-pipeline">${escapeHtml(pipelineLabels[status.pipeline_status] || status.pipeline_status)}</span>
                <span id="server-status-host">${escapeHtml(status.host)}</span>
                <span id="server-status-loglevel">${escapeHtml(status.log_level)}</span>
                <span id="server-status-mem">${status.memory_mb} MB</span>
                <span id="server-status-cpu">${status.cpu_percent}%</span>
                <span id="server-status-ws">${status.ws_connections} WS</span>
                <span id="server-status-fd">${status.open_file_handles} FD</span>
            </div>
        `;
        container.appendChild(card);
        return status;
    } catch {
        // Silently fail — server status card is non-critical
        return null;
    }
}

/* Server control panel — graceful shutdown, manual restart, and runtime log
   level changes (issue #60). Rendered once below the status cards; on later
   dashboard refreshes the log-level select is re-synced to the server. */
const LOG_LEVELS = ["off", "error", "warn", "info", "debug", "trace"];

export function renderServerControlPanel(status) {
    const cards = document.getElementById("status-cards");
    if (!cards) return;

    const existing = document.getElementById("server-control-panel");
    if (existing) {
        const select = document.getElementById("server-loglevel-select");
        if (select && !select.dataset.busy) select.value = status.log_level;
        return;
    }

    const panel = document.createElement("div");
    panel.id = "server-control-panel";
    panel.className = "server-control-panel";
    panel.innerHTML = `
        <div class="server-control-header">
            <h2>🖥 Server Control</h2>
            <span class="server-control-hint">Log-level changes apply to this process only</span>
        </div>
        <div class="server-control-actions">
            <div class="server-control-group">
                <label for="server-loglevel-select">Log level</label>
                <select id="server-loglevel-select">
                    ${LOG_LEVELS.map(l =>
                        `<option value="${l}"${l === status.log_level ? " selected" : ""}>${l}</option>`
                    ).join("")}
                </select>
                <button id="server-loglevel-apply" class="btn btn-sm">Apply</button>
            </div>
            <div class="server-control-group">
                <button id="server-restart-btn" class="btn btn-sm btn-warning">Restart</button>
                <button id="server-shutdown-btn" class="btn btn-sm btn-danger">Shut down</button>
            </div>
        </div>
    `;
    cards.after(panel);

    const shutdownBtn = document.getElementById("server-shutdown-btn");
    const restartBtn = document.getElementById("server-restart-btn");
    const select = document.getElementById("server-loglevel-select");
    const applyBtn = document.getElementById("server-loglevel-apply");

    shutdownBtn.addEventListener("click", async () => {
        if (!confirm("Shut down the server? A running pipeline will finish the current unit and save it first.")) {
            return;
        }
        shutdownBtn.disabled = true;
        restartBtn.disabled = true;
        try {
            const res = await API.shutdownServer();
            showToast(res.message, "info", 8000);
        } catch (err) {
            showToast(`Shutdown failed: ${err.message}`, "error");
            shutdownBtn.disabled = false;
            restartBtn.disabled = false;
        }
    });

    restartBtn.addEventListener("click", async () => {
        if (!confirm("Restart the server? It will stop after the current unit is saved — restart the command manually.")) {
            return;
        }
        shutdownBtn.disabled = true;
        restartBtn.disabled = true;
        try {
            const res = await API.restartServer();
            showToast(res.message, "warning", 10000);
        } catch (err) {
            showToast(`Restart request failed: ${err.message}`, "error");
            shutdownBtn.disabled = false;
            restartBtn.disabled = false;
        }
    });

    applyBtn.addEventListener("click", async () => {
        applyBtn.disabled = true;
        select.dataset.busy = "1";
        try {
            const res = await API.setLogLevel(select.value);
            select.value = res.level;
            const levelSpan = document.getElementById("server-status-loglevel");
            if (levelSpan) levelSpan.textContent = res.level;
            showToast(`Log level set to ${res.level} (this process only)`, "success");
        } catch (err) {
            showToast(`Log level change failed: ${err.message}`, "error");
        } finally {
            delete select.dataset.busy;
            applyBtn.disabled = false;
        }
    });
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

    if (!panel || !summary) return;

    // The phase bar renders from the honest phase records regardless of
    // whether any binaries have been discovered yet (issue #61).
    renderPipelinePhaseBar(data.phases);

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

    // One row per target binary (issue #63): strategy, function counts,
    // tokens, success rate, shim/PAL status, placeholder quick actions.
    renderPipelineBinaryRows(data.binaries);
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

/* ==========================================================================
   Dashboard view — status cards, review queue summary, activity,
   pipeline progress
   ========================================================================== */

import { API } from "./api.js";
import { State } from "./state.js";
import { CATEGORY_LABELS, KIND_LABELS, STATUS_LABELS } from "./constants.js";
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
        State.queueEffort = res.queue_effort || {};
        State.queueOrder = res.queue_order || [];
        State.queueOverlay = res.queue_overlay || { order: [], priorities: {} };

        renderStatusCards(State.dashboard);
        renderQueueList(State.dashboard, State.selectedUnitId);
        renderActivity(State.dashboard.recent_activity);

        // Dashboard summary sections (issue #66).
        renderCategoryCards(res.binary_categories);
        renderQualitySummary(res.quality_summary);
        renderTokenBudget(res.token_usage);

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
    const visible = cards.filter(c => c.value > 0);

    // Skip the DOM churn when the counts haven't changed — wiping innerHTML
    // on every refresh is what made the card row flicker during a live run.
    const signature = visible.map(c => `${c.cls}:${c.value}`).join("|");
    if (container.dataset.counts === signature) return;
    container.dataset.counts = signature;

    // Replace only the count cards. The server status card lives in this
    // container too and must survive the swap — it is updated in place by
    // renderServerStatusCard, not rebuilt.
    const serverCard = document.getElementById("server-status-card");
    container
        .querySelectorAll(".status-card:not(#server-status-card):not(#stale-branches-card)")
        .forEach(el => el.remove());
    for (const c of visible) {
        const el = document.createElement("div");
        el.className = `status-card ${c.cls}`;
        el.innerHTML = `
            <div class="status-card-label">${c.label}</div>
            <div class="status-card-value">${c.value}</div>
        `;
        container.insertBefore(el, serverCard);
    }
}

/* Binary category cards (issue #66) — one per DllCategory, counts sourced
   from the workspace classification artifacts. The server always sends all
   six categories, so a zero is a real zero, not missing data. */
export function renderCategoryCards(categories) {
    const container = document.getElementById("category-cards");
    if (!container) return;

    container.innerHTML = (categories || [])
        .map(c => `
            <div class="category-card" data-category="${escapeHtml(c.category)}">
                <div class="category-card-label">${escapeHtml(CATEGORY_LABELS[c.category] || c.category)}</div>
                <div class="category-card-value">${c.count}</div>
            </div>
        `)
        .join("");
}

/* Quality summary (issue #66) — aggregate metrics over the dashboard units.
   A rate with no data behind it renders as an em-dash, never a zero. */
export function renderQualitySummary(summary) {
    const container = document.getElementById("quality-summary");
    if (!container) return;

    const pct = v => (v == null ? "—" : `${Math.round(v * 100)}%`);
    const stats = [
        { label: "Avg. unit confidence", value: pct(summary?.avg_unit_confidence) },
        { label: "Baseline pass rate", value: pct(summary?.baseline_pass_rate) },
        { label: "Verification pass rate", value: pct(summary?.verification_pass_rate) },
    ];

    container.innerHTML = stats
        .map(s => `
            <div class="quality-stat">
                <div class="quality-stat-label">${s.label}</div>
                <div class="quality-stat-value">${s.value}</div>
            </div>
        `)
        .join("");
}

/* Token budget visual (issue #66) — consumption comes from the pipeline's
   token-usage log; the budget itself is a local user preference. With no log
   the panel says so rather than showing a fabricated zero. */
const TOKEN_BUDGET_KEY = "calxgloss_token_budget";

export function renderTokenBudget(usage) {
    const container = document.getElementById("token-budget");
    if (!container) return;

    const budget = parseInt(localStorage.getItem(TOKEN_BUDGET_KEY) || "", 10) || 0;
    const total = usage ? usage.total_tokens : null;
    // The bar caps at 100% but the caption reports the true share, so an
    // overrun is visible rather than understated.
    const pct = usage && budget > 0 ? (total / budget) * 100 : null;

    container.innerHTML = `
        <div class="token-budget-row">
            <span class="token-budget-usage" ${total != null ? `data-total-tokens="${total}"` : ""}>
                ${total != null ? `${total.toLocaleString()} tokens used` : "No token usage recorded"}
            </span>
            ${usage ? `
                <span class="token-budget-meta">
                    ${usage.successful_tokens.toLocaleString()} on successful calls ·
                    ${usage.failed_tokens.toLocaleString()} on failed calls ·
                    ${usage.calls} calls
                </span>
            ` : ""}
            <label class="token-budget-label" for="token-budget-input">
                Budget
                <input id="token-budget-input" type="number" min="0" step="1000"
                       value="${budget || ""}" placeholder="no budget set">
            </label>
        </div>
        <div class="token-budget-bar">
            <div class="token-budget-fill" style="width:${pct != null ? `${Math.min(100, pct)}%` : "0%"}"></div>
        </div>
        <div class="token-budget-caption">
            ${pct != null
                ? `${pct.toLocaleString()}% of a ${budget.toLocaleString()} token budget`
                : "Set a budget to see consumption against it"}
        </div>
    `;

    const input = document.getElementById("token-budget-input");
    input.addEventListener("change", () => {
        const value = parseInt(input.value, 10);
        if (value > 0) {
            localStorage.setItem(TOKEN_BUDGET_KEY, String(value));
        } else {
            localStorage.removeItem(TOKEN_BUDGET_KEY);
        }
        renderTokenBudget(usage);
    });
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
        const pipelineLabel = pipelineLabels[status.pipeline_status] || status.pipeline_status;

        // Create once, then update the fields in place — recreating the card
        // on every refresh removed and re-added it, which flickered the card
        // row during a live run.
        let card = document.getElementById("server-status-card");
        if (!card) {
            card = document.createElement("div");
            card.id = "server-status-card";
            card.className = "status-card server";
            card.innerHTML = `
                <div class="status-card-label">Server</div>
                <div class="status-card-value" id="server-status-uptime"></div>
                <div class="server-status-meta">
                    <span id="server-status-version"></span>
                    <span id="server-status-pipeline"></span>
                    <span id="server-status-host"></span>
                    <span id="server-status-loglevel"></span>
                    <span id="server-status-mem"></span>
                    <span id="server-status-cpu"></span>
                    <span id="server-status-ws"></span>
                    <span id="server-status-fd"></span>
                </div>
            `;
            container.appendChild(card);
        }
        card.title = `Pipeline: ${status.pipeline_status} · Host: ${status.host} · Log level: ${status.log_level}`;
        const set = (id, text) => {
            const el = card.querySelector(id);
            if (el) el.textContent = text;
        };
        set("#server-status-uptime", fmtUptime(status.uptime_secs));
        set("#server-status-version", `v${status.version}`);
        set("#server-status-pipeline", pipelineLabel);
        set("#server-status-host", status.host);
        set("#server-status-loglevel", status.log_level);
        set("#server-status-mem", `${status.memory_mb} MB`);
        set("#server-status-cpu", `${status.cpu_percent}%`);
        set("#server-status-ws", `${status.ws_connections} WS`);
        set("#server-status-fd", `${status.open_file_handles} FD`);
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
        // Idempotent: the old innerHTML wipe deduped this card on every
        // refresh; now that the card row updates in place, the card manages
        // itself — created once, updated in place, removed when it empties.
        let card = document.getElementById("stale-branches-card");
        if (count === 0) {
            if (card) card.remove();
            return;
        }
        if (!card) {
            card = document.createElement("div");
            card.id = "stale-branches-card";
            card.className = "status-card stale_branches";
            card.innerHTML = `
                <div class="status-card-label">Stale Branches</div>
                <div class="status-card-value"></div>
            `;
            card.addEventListener("click", () => switchView("gc"));
            container.appendChild(card);
        }
        const value = card.querySelector(".status-card-value");
        if (value) value.textContent = count;
    } catch {
        // Silently fail — stale card is non-critical
    }
}

function renderQueueItem(unit, selected = false) {
    const iconClass = unit.status.toLowerCase().replace(/\s+/g, "_");
    const name = unit.kind === "dll_classification"
        ? `Classify ${unit.binary}`
        : unit.function ? `${unit.binary} ${unit.function}` : unit.binary;

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
            ? `Classify ${u.binary}`
            : u.function ? `${u.binary}/${u.function}` : u.binary;
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
        const empty = document.getElementById("pipeline-empty");
        if (empty) empty.style.display = "";
        return;
    }

    panel.style.display = "block";
    const empty = document.getElementById("pipeline-empty");
    if (empty) empty.style.display = "none";
    summary.textContent = `${classified} classified, ${batchDone} translated, ${translating.length} translating`;

    // Time remaining estimate (issue #64) — only shown when the token-usage
    // log has measured attempt durations and work remains.
    renderPipelineTimeEstimate(data.time_estimate);

    // One row per target binary (issue #63): strategy, function counts,
    // tokens, success rate, shim/PAL status, placeholder quick actions.
    renderPipelineBinaryRows(data.binaries);
}

function renderPipelineTimeEstimate(estimate) {
    const el = document.getElementById("pipeline-time-estimate");
    if (!el) return;
    if (!estimate || estimate.remaining_units == null || estimate.estimated_secs == null) {
        el.style.display = "none";
        el.textContent = "";
        return;
    }
    el.style.display = "block";
    el.textContent =
        `≈ ${fmtUptime(estimate.estimated_secs)} remaining ` +
        `(${estimate.remaining_units} functions × ~${fmtUptime(Math.round(estimate.avg_attempt_secs))}/attempt)`;
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

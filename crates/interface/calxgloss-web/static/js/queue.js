/* ==========================================================================
   Review queue view — full queue list, unit detail panel, review actions
   ========================================================================== */

import { API } from "./api.js";
import { State } from "./state.js";
import { KIND_LABELS, STATUS_LABELS } from "./constants.js";
import { fmtConfidence, fmtUptime, escapeHtml } from "./utils.js";
import { showToast, showModal } from "./ui.js";
import { loadDashboard } from "./dashboard.js";

export function renderFullQueue(dashboard, selectedId = null) {
    const list = document.getElementById("full-queue-list");
    const empty = document.getElementById("full-queue-empty");
    if (!list || !empty) return;

    let units = dashboard.review_queue.filter(u => !u.accepted);

    // Apply status filter
    const filter = State.statusFilter;
    if (filter !== "all") {
        const statusMap = {
            queued: "queued",
            pending_review: "pending_review",
            in_progress: "in_progress",
            blocked: "blocked",
        };
        units = units.filter(u => u.status.toLowerCase().replace(/\s+/g, "_") === statusMap[filter]);
    }

    if (units.length === 0) {
        list.innerHTML = "";
        empty.style.display = "flex";
        return;
    }

    empty.style.display = "none";
    list.innerHTML = units.map(u => {
        const iconClass = u.status.toLowerCase().replace(/\s+/g, "_");
        const name = u.kind === "dll_classification"
            ? `Classify ${u.binary}`
            : u.function ? `${u.binary} ${u.function}` : u.binary;

        // Effort estimate from historical attempt durations (issue #64);
        // "—" when the unit has no recorded history.
        const effort = State.queueEffort[u.id];
        const effortText = effort == null ? "—" : fmtUptime(effort);

        return `
            <div class="queue-item-full ${u.id === selectedId ? "selected" : ""}" data-unit-id="${u.id}">
                <div class="queue-item-icon ${iconClass}"></div>
                <div class="qi-name" title="${u.id}">${name}</div>
                <div class="qi-status ${iconClass}">${STATUS_LABELS[u.status] || u.status}</div>
                <div class="qi-attempt">v${u.attempt}</div>
                <div class="qi-effort" title="Estimated time per attempt">${effortText}</div>
            </div>
        `;
    }).join("");
}

// ─── Detail Panel ───────────────────────────────────────────────────────

export async function showDetail(unitId) {
    State.selectedUnitId = unitId;

    // If on queue view, show inline detail; otherwise use sidebar panel
    if (State.currentView === "queue") {
        await renderInlineDetail(unitId);
        renderFullQueue(State.dashboard, unitId);
        return;
    }

    const panel = document.getElementById("detail-panel");

    // Set header
    document.querySelector(".detail-unit-id").textContent = unitId;
    const badge = document.querySelector(".detail-status-badge");

    const body = document.getElementById("detail-body");
    try {
        const res = await API.unit(unitId);
        const u = res.unit;

        badge.className = `detail-status-badge ${u.status.toLowerCase().replace(/\s+/g, "_")}`;
        badge.textContent = STATUS_LABELS[u.status] || u.status;

        body.innerHTML = `
            <div id="detail-content">
                ${renderDetailOverview(u)}
                ${renderDetailActions(u)}
                ${renderDiffTab(u)}
            </div>
        `;

        // Load diff data
        loadDiffView(unitId);
        loadGhidraView(unitId);

    } catch (err) {
        body.innerHTML = `<div class="empty-state">Failed to load unit details: ${err.message}</div>`;
    }

    panel.classList.add("open");
}

export async function renderInlineDetail(unitId) {
    const titleEl = document.getElementById("queue-detail-title");
    const closeBtn = document.getElementById("queue-detail-close");
    const body = document.getElementById("queue-detail-body");

    if (!titleEl || !body) return;

    try {
        const res = await API.unit(unitId);
        const u = res.unit;

        titleEl.textContent = u.function
            ? `${u.binary}!${u.function}`
            : `Classify ${u.binary}`;
        titleEl.title = u.id;
        closeBtn.style.display = "";

        body.innerHTML = `
            <div id="detail-content">
                ${renderDetailOverview(u)}
                ${renderDetailActions(u)}
                ${renderDiffTab(u)}
            </div>
        `;

        // Load diff data
        loadDiffView(unitId);
        loadGhidraView(unitId);

    } catch (err) {
        body.innerHTML = `<div class="empty-state">Failed to load unit details: ${err.message}</div>`;
        closeBtn.style.display = "none";
    }
}

export function hideDetail() {
    const panel = document.getElementById("detail-panel");
    panel.classList.remove("open");
    State.selectedUnitId = null;

    // Clear inline detail if on queue view
    if (State.currentView === "queue") {
        const titleEl = document.getElementById("queue-detail-title");
        const closeBtn = document.getElementById("queue-detail-close");
        const body = document.getElementById("queue-detail-body");
        if (titleEl) {
            titleEl.textContent = "Select a unit to review";
            titleEl.title = "";
        }
        if (closeBtn) closeBtn.style.display = "none";
        if (body) body.innerHTML = '<div class="empty-state">Click an item in the list to review it.</div>';
        State.selectedUnitId = null;
    }
}

function renderDetailOverview(u) {
    const conf = fmtConfidence(u.unit_confidence);
    const bp = u.baseline_tests_passed ?? 0;
    const bt = u.baseline_tests_total ?? 0;
    const vp = u.verification_tests_passed ?? 0;
    const vt = u.verification_tests_total ?? 0;

    const bpClass = bt === 0 ? "none" : bp === bt ? "pass" : bp > 0 ? "partial" : "fail";
    const vpClass = vt === 0 ? "none" : vp === vt ? "pass" : vp > 0 ? "partial" : "fail";

    return `
        <div class="detail-section">
            <div class="detail-section-title">Overview</div>
            <div class="detail-row">
                <span class="detail-row-label">Kind</span>
                <span class="detail-row-value">${KIND_LABELS[u.kind] || u.kind}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">DLL</span>
                <span class="detail-row-value">${u.binary}</span>
            </div>
            ${u.function ? `
                <div class="detail-row">
                    <span class="detail-row-label">Function</span>
                    <span class="detail-row-value">${u.function}</span>
                </div>
            ` : ""}
            <div class="detail-row">
                <span class="detail-row-label">Attempt</span>
                <span class="detail-row-value">v${u.attempt}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">LLM Model</span>
                <span class="detail-row-value">${u.llm_model || "\u2014"}</span>
            </div>
            <div class="detail-row">
                <span class="detail-row-label">Confidence</span>
                <span class="detail-row-value">${conf.text}</span>
            </div>
            ${u.unit_confidence != null ? `
                <div class="confidence-bar-container">
                    <div class="confidence-bar ${conf.cls}" style="width:${conf.pct}%"></div>
                </div>
            ` : ""}
            <div class="detail-row">
                <span class="detail-row-label">Staleness</span>
                <span class="detail-row-value">${u.stale || "Fresh"}</span>
            </div>
        </div>

        <div class="detail-section">
            <div class="detail-section-title">Test Results</div>
            <div class="test-results">
                <div class="test-result-item">
                    <div class="test-result-label">Baseline</div>
                    <div class="test-result-value ${bpClass}">${bp}/${bt}</div>
                </div>
                <div class="test-result-item">
                    <div class="test-result-label">Verification</div>
                    <div class="test-result-value ${vpClass}">${vp}/${vt}</div>
                </div>
            </div>
        </div>

        ${u.diff_summary ? `
            <div class="detail-section">
                <div class="detail-section-title">Diff Summary</div>
                <div class="diff-stats">
                    <div class="diff-stat">
                        <div class="diff-stat-dot change"></div>
                        <span>${u.diff_summary.files_changed} files</span>
                    </div>
                    <div class="diff-stat">
                        <div class="diff-stat-dot insert"></div>
                        <span>+${u.diff_summary.insertions}</span>
                    </div>
                    <div class="diff-stat">
                        <div class="diff-stat-dot delete"></div>
                        <span>-${u.diff_summary.deletions}</span>
                    </div>
                </div>
            </div>
        ` : ""}

        ${u.dependencies.length > 0 ? `
            <div class="detail-section">
                <div class="detail-section-title">Dependencies</div>
                <div class="dependency-list">
                    ${u.dependencies.map(d => `<span class="dependency-tag">${d}</span>`).join("")}
                </div>
            </div>
        ` : ""}

        ${u.attempt_history && u.attempt_history.length > 0 ? `
            <div class="detail-section">
                <div class="detail-section-title">Attempt History (${u.attempt_history.length})</div>
                <div class="attempt-list">
                    ${u.attempt_history.map(a => {
                        const icon = a.compilation_errors.length === 0 && a.failed_tests.length === 0
                            ? "\u2705" : "\u274c";
                        return `
                            <div class="attempt-item">
                                <span class="attempt-item-icon">${icon}</span>
                                <div class="attempt-item-info">
                                    <div>Attempt ${a.attempt} \u2014 ${a.committed_at}</div>
                                    <div class="attempt-item-commit">${a.commit_hash.slice(0, 7)}</div>
                                </div>
                                ${a.failed_tests.length > 0
                                    ? `<div class="attempt-item-failures">${a.failed_tests.slice(0, 1).join("; ")}</div>`
                                    : ""}
                            </div>
                        `;
                    }).join("")}
                </div>
            </div>
        ` : ""}

        ${u.known_gaps && u.known_gaps.length > 0 ? `
            <div class="detail-section">
                <div class="detail-section-title">Known Gaps</div>
                <ul class="gap-list">
                    ${u.known_gaps.map(g => `<li>${g}</li>`).join("")}
                </ul>
            </div>
        ` : ""}

        ${renderProcessSections(u)}
        ${renderAnalysisSections(u)}
    `;
}

// ─── Process telemetry sections (issue #62) ──────────────────────────

function renderProcessSections(u) {
    const p = u.process;
    if (!p) return "";

    return `
        ${renderProcessTier(p.tier)}
        ${renderProcessFaults(p.faults)}
        ${renderProcessTokens(p.tokens)}
        ${renderProcessStrategies(p.strategies)}
    `;
}

function renderProcessTier(tier) {
    if (!tier) return "";

    let body = "";
    if (tier.tier != null) {
        const escalatedTag = tier.escalated
            ? `<span class="tier-escalated-tag">escalated</span>`
            : "";
        body += `
            <div class="detail-row">
                <span class="detail-row-label">Tier</span>
                <span class="detail-row-value">T${tier.tier}${tier.label ? ` (${escapeHtml(tier.label)})` : ""} ${escalatedTag}</span>
            </div>
        `;
        if (tier.description) {
            body += `
                <div class="tier-description">${escapeHtml(tier.description)}</div>
            `;
        }
        if (tier.rationale) {
            body += `
                <div class="detail-row">
                    <span class="detail-row-label">Complexity</span>
                    <span class="detail-row-value">${escapeHtml(tier.rationale.complexity)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-row-label">API calls</span>
                    <span class="detail-row-value">${tier.rationale.api_call_count}</span>
                </div>
            `;
        }
    } else {
        body += `<div class="process-empty">No tier telemetry recorded.</div>`;
    }

    if (tier.attempts && tier.attempts.length > 0) {
        body += `
            <div class="tier-attempt-list">
                ${tier.attempts.map(a => `
                    <div class="tier-attempt-item">
                        <span class="tier-attempt-num">#${a.attempt}</span>
                        <span class="tier-attempt-strategy">${escapeHtml(a.strategy)}</span>
                        <span class="tier-attempt-tier">${a.tier ? escapeHtml(a.tier) : "\u2014"}</span>
                    </div>
                `).join("")}
            </div>
        `;
    }

    return `
        <div class="detail-section" id="process-tier-section">
            <div class="detail-section-title">Context Tier</div>
            ${body}
        </div>
    `;
}

function renderProcessFaults(faults) {
    if (!faults) return "";

    const body = faults.length === 0
        ? `<div class="process-empty">No faults recorded for this unit.</div>`
        : `
            <div class="fault-list">
                ${faults.map(f => `
                    <div class="fault-item severity-${escapeHtml(f.severity)}">
                        <div class="fault-item-head">
                            <span class="fault-category-tag">${escapeHtml(f.category)}</span>
                            <span class="fault-severity-tag">${escapeHtml(f.severity)}</span>
                            <span class="fault-attempt">attempt ${f.attempt} \u00b7 ${escapeHtml(f.strategy)}</span>
                        </div>
                        <div class="fault-description">${escapeHtml(f.description)}</div>
                        ${f.recovery ? `<div class="fault-recovery">Recovery: ${escapeHtml(f.recovery)}</div>` : ""}
                    </div>
                `).join("")}
            </div>
        `;

    return `
        <div class="detail-section" id="process-faults-section">
            <div class="detail-section-title">Fault History (${faults.length})</div>
            ${body}
        </div>
    `;
}

function renderProcessTokens(tokens) {
    if (!tokens) return "";

    let body = `
        <div class="token-stats">
            <div class="token-stat">
                <div class="token-stat-label">Total</div>
                <div class="token-stat-value">${tokens.total_tokens.toLocaleString()}</div>
            </div>
            <div class="token-stat">
                <div class="token-stat-label">Successful</div>
                <div class="token-stat-value pass">${tokens.successful_tokens.toLocaleString()}</div>
            </div>
            <div class="token-stat">
                <div class="token-stat-label">Failed</div>
                <div class="token-stat-value ${tokens.failed_tokens > 0 ? "fail" : "none"}">${tokens.failed_tokens.toLocaleString()}</div>
            </div>
        </div>
    `;

    if (tokens.per_attempt && tokens.per_attempt.length > 0) {
        body += `
            <div class="token-attempt-list">
                ${tokens.per_attempt.map(a => `
                    <div class="token-attempt-item">
                        <span class="token-attempt-icon">${a.success ? "\u2705" : "\u274c"}</span>
                        <span class="token-attempt-num">#${a.attempt}</span>
                        <span class="token-attempt-strategy">${escapeHtml(a.strategy)}</span>
                        <span class="token-attempt-tier">${a.tier ? escapeHtml(a.tier) : "\u2014"}</span>
                        <span class="token-attempt-count">${a.tokens_used.toLocaleString()} tok</span>
                    </div>
                `).join("")}
            </div>
        `;
    }

    return `
        <div class="detail-section" id="process-tokens-section">
            <div class="detail-section-title">Token Usage (${tokens.attempts} attempts)</div>
            ${body}
        </div>
    `;
}

function renderProcessStrategies(strategies) {
    if (!strategies) return "";

    const body = strategies.length === 0
        ? `<div class="process-empty">No retry strategies recorded for this unit.</div>`
        : `
            <div class="strategy-list">
                ${strategies.map(s => {
                    const pct = Math.round(s.success_rate * 100);
                    const cls = s.success_rate >= 1 ? "pass" : s.success_rate > 0 ? "partial" : "fail";
                    return `
                        <div class="strategy-item">
                            <span class="strategy-name">${escapeHtml(s.strategy)}</span>
                            <span class="strategy-counts">${s.successes}/${s.attempts} succeeded</span>
                            <span class="strategy-rate ${cls}">${pct}%</span>
                        </div>
                    `;
                }).join("")}
            </div>
        `;

    return `
        <div class="detail-section" id="process-strategies-section">
            <div class="detail-section-title">Retry Strategies (${strategies.length})</div>
            ${body}
        </div>
    `;
}

// ─── Analysis context sections (issue #73) ─────────────────────────

function renderAnalysisSections(u) {
    const a = u.analysis;
    if (!a) return "";

    return `
        ${renderApiMappings(a.api_mappings)}
        ${renderCallGraphContext(a.call_graph)}
    `;
}

function renderApiMappings(mappings) {
    const list = mappings || [];
    const body = list.length === 0
        ? `<div class="process-empty">No Windows API mappings identified for this function.</div>`
        : `
            <div class="api-mapping-list">
                ${list.map(m => `
                    <div class="api-mapping-item">
                        <span class="api-mapping-name">${escapeHtml(m.name)}</span>
                        <span class="api-mapping-category">${escapeHtml(m.category)}</span>
                        <span class="api-mapping-target">${escapeHtml(m.pal_mapping)}</span>
                    </div>
                `).join("")}
            </div>
        `;

    return `
        <div class="detail-section" id="api-mappings-section">
            <div class="detail-section-title">Windows API Mappings (${list.length})</div>
            ${body}
        </div>
    `;
}

function renderCallGraphContext(cg) {
    const callers = (cg && cg.callers) || [];
    const callees = (cg && cg.callees) || [];

    const body = callers.length === 0 && callees.length === 0
        ? `<div class="process-empty">No call graph data available for this function.</div>`
        : `
            <div class="call-graph-group">
                <div class="call-graph-group-label">Called by (${callers.length})</div>
                <div class="dependency-list">
                    ${callers.map(n => `<span class="dependency-tag">${escapeHtml(n)}</span>`).join("")}
                </div>
            </div>
            <div class="call-graph-group">
                <div class="call-graph-group-label">Calls (${callees.length})</div>
                <div class="dependency-list">
                    ${callees.map(n => `<span class="dependency-tag">${escapeHtml(n)}</span>`).join("")}
                </div>
            </div>
        `;

    return `
        <div class="detail-section" id="call-graph-section">
            <div class="detail-section-title">Call Graph Context</div>
            ${body}
        </div>
    `;
}

function renderDetailActions(u) {
    const disabled = u.accepted;

    return `
        <div class="detail-actions">
            <div class="action-row">
                <button class="btn btn-success" id="btn-accept" ${disabled ? "disabled" : ""}>
                    \u2713 Accept
                </button>
                <button class="btn btn-warning" id="btn-send-back" ${disabled ? "disabled" : ""}>
                    \u21a9 Send Back
                </button>
            </div>
            <div class="action-row">
                <button class="btn btn-danger" id="btn-patch" ${disabled ? "disabled" : ""}>
                    \u270f Request Patch
                </button>
                <button class="btn btn-secondary" id="btn-reload-detail">\u21bb Reload</button>
            </div>
        </div>
    `;
}

// ─── Diff Tab ─────────────────────────────────────────────────────────────

function renderDiffTab(u) {
    const hasDiff = u.diff_summary.files_changed > 0;

    return `
        <div class="detail-section" id="diff-section">
            <div class="diff-tabs">
                <button class="diff-tab active" data-diff-tab="diff">Diff (${u.diff_summary.insertions}+ ${u.diff_summary.deletions}-)</button>
                <button class="diff-tab" data-diff-tab="ghidra">Ghidra Context</button>
            </div>
            <div class="diff-content" id="diff-viewer">
                ${hasDiff
                    ? '<div id="diff-body" class="diff-viewer"><div class="spinner"></div></div>'
                    : '<div class="ghidra-empty">No diff available for this unit.</div>'
                }
            </div>
            <div class="diff-content" id="ghidra-viewer" style="display:none">
                <div id="ghidra-body" class="ghidra-viewer">
                    <div class="spinner"></div>
                </div>
            </div>
        </div>
    `;
}

async function loadDiffView(unitId) {
    try {
        const res = await API.unitDiff(unitId);
        const files = res.diff || [];

        const body = document.getElementById("diff-body");
        if (!body) return;

        if (files.length === 0) {
            body.innerHTML = '<div class="ghidra-empty">No changes vs. main.</div>';
            return;
        }

        let html = "";
        for (const file of files) {
            html += `<div class="diff-file">`;
            if (file.renamed && file.old_path) {
                html += `<div class="diff-file-header">
                    <span class="path">${escapeHtml(file.path)}</span>
                    <span class="rename">\u2190 ${escapeHtml(file.old_path)}</span>
                </div>`;
            } else {
                html += `<div class="diff-file-header"><span class="path">${escapeHtml(file.path)}</span></div>`;
            }

            html += `<table class="diff-table">`;
            for (const hunk of file.hunks) {
                if (hunk.header) {
                    html += `<tr class="diff-line hunk-header">
                        <td class="diff-line-body">${escapeHtml(hunk.header)}</td>
                    </tr>`;
                }
                for (const line of hunk.lines) {
                    const cls = line.kind === "addition" ? "addition"
                        : line.kind === "deletion" ? "deletion" : "context";
                    html += `<tr class="diff-line ${cls}">
                        <td class="diff-line-num">
                            ${line.old_line != null ? `<span class="old">${line.old_line}</span>` : '<span class="empty">&nbsp;</span>'}
                        </td>
                        <td class="diff-line-num">
                            ${line.new_line != null ? `<span class="new">${line.new_line}</span>` : '<span class="empty">&nbsp;</span>'}
                        </td>
                        <td class="diff-line-body">${escapeHtml(line.content)}</td>
                    </tr>`;
                }
            }
            html += `</table></div>`;
        }

        body.innerHTML = html;

        // Set up diff tab switching
        setupDiffTabs();
    } catch (err) {
        const body = document.getElementById("diff-body");
        if (body) body.innerHTML = `<div class="ghidra-empty">Failed to load diff: ${escapeHtml(err.message)}</div>`;
    }
}

async function loadGhidraView(unitId) {
    try {
        const res = await API.unitGhidra(unitId);
        const ctx = res.context;

        const body = document.getElementById("ghidra-body");
        if (!body) return;

        if (!ctx) {
            body.innerHTML = `<div class="ghidra-empty">${escapeHtml(res.error || "No Ghidra context available.")}</div>`;
            return;
        }

        let html = "";

        // Ghidra metadata
        html += `<div style="padding:8px 12px;font-size:12px;color:var(--text-muted)">`;
        if (ctx.binary) html += `DLL: <strong style="color:var(--text-secondary)">${escapeHtml(ctx.binary)}</strong> &nbsp;`;
        if (ctx.function_name) html += `Function: <strong style="color:var(--text-secondary)">${escapeHtml(ctx.function_name)}</strong>`;
        if (ctx.address) html += ` &nbsp;Addr: <code>${escapeHtml(ctx.address)}</code>`;
        html += `</div>`;

        // Windows API calls
        if (ctx.windows_apis && ctx.windows_apis.length > 0) {
            html += `<div class="ghidra-label">Identified API Calls</div>`;
            html += `<div class="ghidra-api-calls">`;
            for (const api of ctx.windows_apis) {
                html += `<span class="ghidra-api-tag">${escapeHtml(api.name)} \u2192 ${escapeHtml(api.pal_mapping)}</span>`;
            }
            html += `</div>`;
        }

        // Decompiler output
        if (ctx.decompiler_output) {
            html += `<div class="ghidra-label">Decompiler (Pseudo-C)</div>`;
            html += `<div class="ghidra-decompiler">${escapeHtml(ctx.decompiler_output)}</div>`;
        }

        // Disassembly
        if (ctx.disassembly && ctx.disassembly.length > 0) {
            html += `<div class="ghidra-label">Disassembly</div>`;
            html += `<div class="ghidra-disassembly">`;
            for (const line of ctx.disassembly) {
                html += `<div>${escapeHtml(line.address)}&nbsp;&nbsp;${escapeHtml(line.instruction)}</div>`;
            }
            html += `</div>`;
        }

        body.innerHTML = html;
    } catch (err) {
        const body = document.getElementById("ghidra-body");
        if (body) body.innerHTML = `<div class="ghidra-empty">Failed to load Ghidra context: ${escapeHtml(err.message)}</div>`;
    }
}

function setupDiffTabs() {
    const tabs = document.querySelectorAll(".diff-tab");
    const diffViewer = document.getElementById("diff-viewer");
    const ghidraViewer = document.getElementById("ghidra-viewer");

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const tabName = tab.dataset.diffTab;
            tabs.forEach(t => t.classList.toggle("active", t === tab));

            if (tabName === "diff") {
                diffViewer.style.display = "";
                ghidraViewer.style.display = "none";
            } else {
                diffViewer.style.display = "none";
                ghidraViewer.style.display = "";
            }
        });
    });
}

// ─── Review Actions ─────────────────────────────────────────────────────

export async function acceptUnit(unitId) {
    try {
        const res = await API.acceptUnit(unitId);
        showToast(`Accepted: ${unitId}`, "success");
        await loadDashboard();
        hideDetail();
    } catch (err) {
        showToast(`Accept failed: ${err.message}`, "error");
    }
}

export function showSendBackModal(unitId) {
    showModal("Send Back", "Send Back", async (reason) => {
        if (!reason) {
            showToast("Reason is required", "warning");
            return;
        }
        try {
            await API.sendBackUnit(unitId, reason);
            showToast(`Sent back: ${unitId}`, "warning");
            await loadDashboard();
            hideDetail();
        } catch (err) {
            showToast(`Send back failed: ${err.message}`, "error");
        }
    });
}

export function showPatchModal(unitId) {
    showModal("Request Patch", "Request Patch", async (issue) => {
        if (!issue) {
            showToast("Issue description is required", "warning");
            return;
        }
        try {
            await API.patchUnit(unitId, issue);
            showToast(`Patch requested for: ${unitId}`, "info");
            await loadDashboard();
            hideDetail();
        } catch (err) {
            showToast(`Patch request failed: ${err.message}`, "error");
        }
    });
}

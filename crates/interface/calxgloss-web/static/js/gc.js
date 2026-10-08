/* ==========================================================================
   Branch cleanup (GC) view — stale branch scan and archive
   ========================================================================== */

import { API } from "./api.js";
import { State } from "./state.js";
import { fmtTime, escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

export async function loadGcCandidates() {
    const days = parseInt(document.getElementById("gc-days-input")?.value || "7", 10);
    try {
        const res = await API.gcCandidates(days);
        State.gcCandidates = res.candidates || [];
        State.gcSelectedBranches.clear();
        renderGcTable(State.gcCandidates);
        renderGcSummary(res);
    } catch (err) {
        showToast(`Failed to load GC candidates: ${err.message}`, "error");
    }
}

function renderGcSummary(res) {
    const panel = document.getElementById("gc-summary");
    const staleCount = document.getElementById("gc-stale-count");
    const recentCount = document.getElementById("gc-recent-count");
    const thresholdEl = document.getElementById("gc-threshold");
    const archiveBtn = document.getElementById("btn-archive-all-gc");

    if (!panel) return;

    panel.style.display = "";
    if (staleCount) staleCount.textContent = res.candidates?.length || 0;
    if (recentCount) recentCount.textContent = res.recent_count || 0;
    if (thresholdEl) thresholdEl.textContent = `${res.threshold_days ?? 7} days`;

    // Show archive button only when there are stale branches
    if (archiveBtn) {
        archiveBtn.style.display = (res.candidates?.length > 0) ? "" : "none";
    }
}

function renderGcTable(candidates) {
    const table = document.getElementById("gc-table");
    const tbody = document.getElementById("gc-table-body");
    const empty = document.getElementById("gc-empty");
    const selectAll = document.getElementById("gc-select-all");

    if (!tbody) return;

    if (candidates.length === 0) {
        if (table) table.style.display = "none";
        if (empty) empty.style.display = "flex";
        if (selectAll) selectAll.checked = false;
        State.gcSelectedBranches.clear();
        return;
    }

    if (table) table.style.display = "";
    if (empty) empty.style.display = "none";

    tbody.innerHTML = candidates.map(c => {
        const displayName = c.function
            ? `re/${c.dll}/${c.function}v${c.attempt}`
            : `re/${c.dll}v${c.attempt}`;
        const funcDisplay = c.function
            ? `<span style="color:var(--text-primary)">${escapeHtml(c.function)}</span>`
            : `<span style="color:var(--text-muted)">—</span>`;

        return `
            <tr>
                <td class="gc-col-select">
                    <input type="checkbox" class="gc-branch-check" data-branch="${escapeHtml(displayName)}" aria-label="Select ${escapeHtml(displayName)}">
                </td>
                <td class="gc-col-name" title="${escapeHtml(displayName)}">${displayName}</td>
                <td class="gc-col-dll">${escapeHtml(c.dll)}${funcDisplay}</td>
                <td class="gc-col-attempt">v${c.attempt}</td>
                <td class="gc-col-age">${c.days_old.toFixed(1)}d</td>
                <td class="gc-col-last">${fmtTime(c.last_commit)}</td>
                <td class="gc-col-status"><span class="gc-status-badge stale">Stale</span></td>
            </tr>
        `;
    }).join("");

    // Wire up checkboxes
    tbody.querySelectorAll(".gc-branch-check").forEach(cb => {
        cb.addEventListener("change", () => {
            const branch = cb.dataset.branch;
            if (cb.checked) {
                State.gcSelectedBranches.add(branch);
            } else {
                State.gcSelectedBranches.delete(branch);
            }
        });
    });

    // Select-all checkbox
    if (selectAll) {
        selectAll.checked = false;
        selectAll.addEventListener("change", () => {
            const checked = selectAll.checked;
            tbody.querySelectorAll(".gc-branch-check").forEach(cb => {
                cb.checked = checked;
                const branch = cb.dataset.branch;
                if (checked) {
                    State.gcSelectedBranches.add(branch);
                } else {
                    State.gcSelectedBranches.delete(branch);
                }
            });
        });
    }
}

export async function archiveSelectedGc() {
    const branches = Array.from(State.gcSelectedBranches);
    if (branches.length === 0) {
        showToast("No branches selected for archival.", "warning");
        return;
    }

    const archiveBtn = document.getElementById("btn-archive-all-gc");
    archiveBtn.disabled = true;
    archiveBtn.textContent = "Archiving...";

    try {
        const res = await API.gcArchive(branches);
        showToast(
            `Archived ${res.archived} branch(es)${res.failed > 0 ? `, ${res.failed} failed` : ""}`,
            res.failed > 0 ? "warning" : "success"
        );
        // Reload candidates
        await loadGcCandidates();
    } catch (err) {
        showToast(`Archive failed: ${err.message}`, "error");
    } finally {
        archiveBtn.disabled = false;
        archiveBtn.textContent = "Archive All Stale";
    }
}

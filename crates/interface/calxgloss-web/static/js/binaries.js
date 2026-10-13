/* ==========================================================================
   Binaries view (issue #130, W4.1) — every classified target binary as a
   row: category and strategy in force (the persisted classification-override
   layer applied), function counts from the review dashboard's units, and
   token totals from the token-usage log. The view reads only persisted
   history, so plain `serve` and `calxgloss live` behave identically — no
   live in-flight state is overlaid here. A workspace with no readable
   classification records shows an honest empty state, never a wall of
   zeros. This module is the tab pattern the follow-up W4 binaries tickets
   copy: detail panel and trackers grow on top of these rows.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

export async function loadBinaries() {
    try {
        const res = await API.binariesList();
        renderBinaries(res.binaries || []);
    } catch (err) {
        showToast(`Failed to load binaries: ${err.message}`, "error");
    }
}

function renderBinaries(binaries) {
    const body = document.getElementById("binaries-body");
    const empty = document.getElementById("binaries-empty");
    const message = document.getElementById("binaries-empty-message");
    const summaryEl = document.getElementById("binaries-filter-summary");

    // Honest empty state: no readable classification records means no
    // rows — say so plainly instead of rendering an empty table shell.
    if (binaries.length === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            "No classified binaries yet — the workspace holds no readable " +
            "classification records. Run `calxgloss classify` to classify " +
            "the target binaries; they appear here as records land.";
        summaryEl.textContent = "";
        return;
    }

    empty.style.display = "none";
    body.style.display = "";
    summaryEl.textContent = `${binaries.length} classified ${binaries.length === 1 ? "binary" : "binaries"}`;

    const tbody = document.getElementById("binaries-table-body");
    tbody.innerHTML = binaries.map(b => `
        <tr>
            <td class="fault-col-binary">${escapeHtml(b.binary)}</td>
            <td>${escapeHtml(b.category)}</td>
            <td>${escapeHtml(b.strategy)}${b.overridden
                ? ' <span class="binaries-overridden" title="Category and strategy come from a persisted classification override, not the recorded classification">overridden</span>'
                : ""}</td>
            <td class="token-col-rate">${b.functions_total}</td>
            <td class="token-col-rate">${b.functions_done}</td>
            <td class="token-col-rate">${b.functions_queued}</td>
            <td class="token-col-rate">${b.functions_failed}</td>
            <td class="token-col-rate">${(b.tokens_used || 0).toLocaleString("en-US")}</td>
        </tr>
    `).join("");
}

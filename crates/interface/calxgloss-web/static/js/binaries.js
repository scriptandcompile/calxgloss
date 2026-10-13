/* ==========================================================================
   Binaries view (issue #130, W4.1) — every classified target binary as a
   row: category and strategy in force (the persisted classification-override
   layer applied), function counts from the review dashboard's units, and
   token totals from the token-usage log. The view reads only persisted
   history, so plain `serve` and `calxgloss live` behave identically — no
   live in-flight state is overlaid here. A workspace with no readable
   classification records shows an honest empty state, never a wall of
   zeros.

   Clicking a row expands a detail panel beneath it (issue #132, W4.2):
   the classification decision actually in force — category, strategy,
   crate, reasoning, and symbol counts, override applied — and
   the binary's per-function list with each unit's review status, so a
   stalled function is findable inside its binary. The panel carries a
   shortcut to the existing classification-override flow; the endpoints
   behind it are live-only, so under plain `serve` that panel honestly
   reports itself unavailable. An unknown binary name 404s server-side
   and surfaces as an error line in the row, never an empty shell.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";
import { openClassificationPanel } from "./classification-override.js";

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
        <tr class="binaries-row" data-binary="${escapeHtml(b.binary)}"
            title="Click to expand this binary's classification and function list">
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

    wireRowExpansion(tbody);
}

// One delegated listener survives innerHTML re-renders: a row click
// toggles its detail panel (fetching it on first open), and the panel's
// Override button opens the existing classification-override flow for
// that binary.
function wireRowExpansion(tbody) {
    if (tbody.dataset.expansionWired) return;
    tbody.dataset.expansionWired = "1";
    tbody.addEventListener("click", async (e) => {
        const overrideBtn = e.target.closest(".binaries-detail-override");
        if (overrideBtn) {
            // The existing override flow (issue #97) — anchored to this
            // view's table so the panel opens where the binary is shown.
            openClassificationPanel(
                overrideBtn.dataset.binary,
                document.getElementById("binaries-table-wrap")
            );
            return;
        }
        const row = e.target.closest("tr.binaries-row");
        if (!row) return;

        const existing = row.nextElementSibling;
        if (existing && existing.classList.contains("binaries-detail-row")) {
            existing.remove();
            row.classList.remove("expanded");
            return;
        }

        // One panel open at a time — the summary table stays readable.
        tbody.querySelectorAll("tr.binaries-detail-row").forEach(r => r.remove());
        tbody.querySelectorAll("tr.binaries-row.expanded").forEach(r => r.classList.remove("expanded"));

        const detail = document.createElement("tr");
        detail.className = "binaries-detail-row";
        detail.innerHTML = `<td colspan="8"><div class="spinner"></div></td>`;
        row.after(detail);
        row.classList.add("expanded");

        try {
            const d = await API.binaryDetail(row.dataset.binary);
            detail.innerHTML = `<td colspan="8">${renderDetail(d)}</td>`;
        } catch (err) {
            // The server's own reason surfaces — a 404 for an unknown
            // name is never papered over with an empty shell.
            detail.innerHTML = `<td colspan="8"><div class="binaries-detail-error">Failed to load detail: ${escapeHtml(err.message)}</div></td>`;
        }
    });
}

// The expanded panel: the decision in force with its reasoning
// (the analyzer's own, or its synthesized override note) and symbol
// counts, the shortcut to the override flow, and the
// per-function list with each attempt's review status.
function renderDetail(d) {
    const fnRows = (d.functions || []).map(f => `
        <tr>
            <td class="fault-col-binary">${escapeHtml(f.function)}</td>
            <td class="token-col-rate">v${f.attempt}</td>
            <td><span class="binaries-fn-status" data-status="${escapeHtml(f.status)}">${escapeHtml(f.status)}</span></td>
        </tr>
    `).join("");
    const fnBody = fnRows ||
        `<tr><td colspan="3" class="binaries-detail-empty">No function-translation units recorded for this binary yet.</td></tr>`;

    return `
        <div class="binaries-detail">
            <div class="binaries-detail-classification">
                <div class="binaries-detail-decision">
                    <strong>${escapeHtml(d.category)}</strong> → ${escapeHtml(d.strategy)}${d.crate_replacement ? ` (crate: ${escapeHtml(d.crate_replacement)})` : ""}${d.overridden
                        ? ' <span class="binaries-overridden" title="Category and strategy come from a persisted classification override, not the recorded classification">overridden</span>'
                        : ""}${d.known_runtime ? " · known runtime — never a translation target" : ""}
                </div>
                <div class="binaries-detail-reason" title="Why the run classified it this way — under an override this is the reason the analyzer would record">${d.reason ? escapeHtml(d.reason) : "No reasoning recorded for this classification."}</div>
                <div class="binaries-detail-counts">Exports: ${d.exports_count} · Imports: ${d.imports_count}</div>
                <button class="btn btn-sm binaries-detail-override" data-binary="${escapeHtml(d.binary)}"
                        title="Review and override this binary's classification (POST /api/binaries/{name}/classification)">Override classification</button>
            </div>
            <table class="binaries-detail-functions">
                <thead><tr><th>Function</th><th>Attempt</th><th>Review status</th></tr></thead>
                <tbody>${fnBody}</tbody>
            </table>
        </div>
    `;
}

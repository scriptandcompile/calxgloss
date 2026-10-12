/* ==========================================================================
   Faults analytics view (issue #125, W3.1) — the whole effort's fault
   history from the persisted fault log: summary cards, per-binary bars,
   the faults-per-day trend with a 3-day moving average, and the fault
   table carrying the full attempt identity triple and the attached
   recovery guidance. Filters re-render in place; CSV export is local.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

// The last fetched (filtered) set — the CSV export builds from exactly
// what the server reported, and the binary filter options accumulate
// every binary the log has ever named.
let lastEntries = [];
let lastTotalInLog = 0;
const knownBinaries = new Set();

/* The shared query string for all four analytics endpoints — the cards,
   bars, trend, and table always describe the same filtered set. */
function filterQuery() {
    const params = new URLSearchParams();
    const category = document.getElementById("faults-filter-category")?.value || "";
    const binary = document.getElementById("faults-filter-binary")?.value || "";
    const from = document.getElementById("faults-filter-from")?.value || "";
    const to = document.getElementById("faults-filter-to")?.value || "";
    if (category) params.set("category", category);
    if (binary) params.set("binary", binary);
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const qs = params.toString();
    return qs ? `?${qs}` : "";
}

export async function loadFaults() {
    const query = filterQuery();
    try {
        const [faults, summary, byBinary, trend] = await Promise.all([
            API.faults(query),
            API.faultsSummary(query),
            API.faultsByBinary(query),
            API.faultsTrend(query),
        ]);
        lastEntries = faults.entries || [];
        lastTotalInLog = faults.total_in_log || 0;
        lastEntries.forEach(e => knownBinaries.add(e.binary));
        populateBinaryFilter();
        renderFaults({
            summary,
            byBinary: byBinary.binaries || [],
            trend: trend.days || [],
        });
    } catch (err) {
        showToast(`Failed to load fault analytics: ${err.message}`, "error");
    }
}

function renderFaults({ summary, byBinary, trend }) {
    const body = document.getElementById("faults-body");
    const empty = document.getElementById("faults-empty");
    const message = document.getElementById("faults-empty-message");
    const summaryEl = document.getElementById("faults-filter-summary");

    // Honest empty state: a missing, corrupt, or simply empty log shows
    // "no faults yet" — never a wall of zeros.
    if (lastTotalInLog === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            "No faults recorded yet — the fault log is empty or missing. " +
            "Faults appear here as the pipeline detects and recovers them.";
        summaryEl.textContent = "";
        return;
    }
    if ((summary.total || 0) === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            `No faults match the current filters — the log holds ${lastTotalInLog}.`;
        summaryEl.textContent = `0 of ${lastTotalInLog} faults`;
        return;
    }

    empty.style.display = "none";
    body.style.display = "";
    summaryEl.textContent = `${summary.total} of ${lastTotalInLog} faults`;

    renderSummaryCards(summary);
    renderBinaryBars(byBinary);
    renderTrend(trend);
    renderFaultTable(lastEntries);
}

function renderSummaryCards(summary) {
    const wrap = document.getElementById("faults-summary-cards");
    if (!wrap) return;
    const cards = [
        { label: "Total faults", value: summary.total, cls: "fault-total" },
        ...(summary.by_category || []).map(c => ({ label: c.name, value: c.count, cls: "" })),
        ...(summary.by_severity || []).map(c => ({
            label: c.name,
            value: c.count,
            cls: `fault-sev-${c.name}`,
        })),
    ];
    wrap.innerHTML = cards.map(c => `
        <div class="status-card ${c.cls}">
            <div class="status-card-label">${escapeHtml(c.label)}</div>
            <div class="status-card-value">${c.value}</div>
        </div>
    `).join("");
}

function renderBinaryBars(byBinary) {
    const wrap = document.getElementById("faults-binary-bars");
    if (!wrap) return;
    const max = Math.max(...byBinary.map(b => b.count), 1);
    wrap.innerHTML = byBinary.map(b => `
        <div class="fault-bar-row">
            <span class="fault-bar-label" title="${escapeHtml(b.binary)}">${escapeHtml(b.binary)}</span>
            <div class="fault-bar-track">
                <div class="fault-bar-fill" style="width:${(b.count / max) * 100}%"></div>
            </div>
            <span class="fault-bar-count">${b.count}</span>
        </div>
    `).join("");
}

/* The trend line: faults per day plus the 3-day moving average, drawn
   from the server's buckets so the chart and the API agree. */
function renderTrend(days) {
    const wrap = document.getElementById("faults-trend");
    if (!wrap) return;
    if (!days.length) {
        wrap.innerHTML = `<div class="empty-state">No faults in the current range.</div>`;
        return;
    }
    const W = 600, H = 160, PAD = 24;
    const max = Math.max(...days.map(d => d.count), 1);
    const x = i => days.length === 1 ? W / 2 : PAD + (i * (W - 2 * PAD)) / (days.length - 1);
    const y = v => H - PAD - (v / max) * (H - 2 * PAD);
    const countPoints = days.map((d, i) => `${x(i).toFixed(1)},${y(d.count).toFixed(1)}`).join(" ");
    const maPoints = days.map((d, i) => `${x(i).toFixed(1)},${y(d.moving_average).toFixed(1)}`).join(" ");
    wrap.innerHTML = `
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"
             aria-label="Faults per day with 3-day moving average">
            <polyline class="fault-trend-count" points="${countPoints}"/>
            <polyline class="fault-trend-ma" points="${maPoints}"/>
        </svg>
        <div class="fault-trend-legend">
            <span class="fault-trend-legend-count">faults/day</span>
            <span class="fault-trend-legend-ma">3-day average</span>
            <span class="fault-trend-range">${escapeHtml(days[0].date)} → ${escapeHtml(days[days.length - 1].date)}</span>
        </div>
    `;
}

function renderFaultTable(entries) {
    const tbody = document.getElementById("faults-table-body");
    if (!tbody) return;
    tbody.innerHTML = entries.map(e => `
        <tr>
            <td class="fault-col-category">${escapeHtml(e.category)}</td>
            <td><span class="fault-severity ${escapeHtml(e.severity)}">${escapeHtml(e.severity)}</span></td>
            <td class="fault-col-binary">${escapeHtml(e.binary)}</td>
            <td class="fault-col-function">${escapeHtml(e.function)}</td>
            <td class="fault-col-attempt">v${e.attempt}</td>
            <td>${escapeHtml(e.strategy)}</td>
            <td class="fault-col-when">${fmtUtc(e.timestamp)}</td>
            <td class="fault-col-recovery" title="${escapeHtml(e.recovery)}">${escapeHtml(e.recovery)}</td>
        </tr>
    `).join("");
}

function fmtUtc(secs) {
    return new Date(secs * 1000).toISOString().slice(0, 16).replace("T", " ");
}

/* The binary filter names every binary the log has ever named — not just
   the currently visible ones — so narrowing never hides the way back. */
function populateBinaryFilter() {
    const select = document.getElementById("faults-filter-binary");
    if (!select) return;
    const current = select.value;
    const names = [...knownBinaries].sort();
    select.innerHTML = `<option value="">All</option>` +
        names.map(n => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`).join("");
    if (names.includes(current)) select.value = current;
}

// ─── CSV export (client-side from the fetched JSON) ────────────────────

function csvCell(value) {
    const s = String(value ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/* Builds the CSV text for the current filtered set — one row per fault,
   header first. Exposed on window for the headless tests, mirroring the
   graph share/export handles. */
export function buildFaultsCsv() {
    const header = ["category", "severity", "binary", "function", "attempt",
                    "strategy", "timestamp", "recovery"];
    const rows = lastEntries.map(e => [
        e.category, e.severity, e.binary, e.function, e.attempt,
        e.strategy, e.timestamp, e.recovery,
    ]);
    return [header, ...rows].map(r => r.map(csvCell).join(",")).join("\n");
}

export function exportFaultsCsv() {
    const blob = new Blob([buildFaultsCsv()], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "faults.csv";
    a.click();
    URL.revokeObjectURL(a.href);
}

// ─── Controls ──────────────────────────────────────────────────────────

export function setupFaultsControls() {
    ["faults-filter-category", "faults-filter-binary", "faults-filter-from", "faults-filter-to"]
        .forEach(id => document.getElementById(id)?.addEventListener("change", loadFaults));
    document.getElementById("btn-export-faults-csv")?.addEventListener("click", exportFaultsCsv);
}

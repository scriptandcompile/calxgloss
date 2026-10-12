/* ==========================================================================
   Strategy analytics view (issue #127, W3.3) — retry-strategy evidence
   from the persisted prompt-strategy log: a per-strategy table with
   attempts, successes, failures, and pass rate, plus pass rates broken
   down by binary category to reveal whether one class of binary
   systematically defeats the current strategies. The time-range filter
   re-renders in place; CSV export is local. Pass-rate by complexity stays
   out of scope — complexity is never persisted per attempt, so there is
   no honest data source.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

// The last fetched (filtered) breakdowns — the CSV export builds from
// exactly what the server reported, without a refetch.
let lastStrategies = [];
let lastCategories = [];

/* The shared query string for both analytics endpoints — the strategy
   table and the category bars always describe the same filtered set. The
   time range maps onto the same inclusive UTC `from` day bound the faults
   and token-usage endpoints honor; "all time" sends no filter at all. */
function filterQuery() {
    const range = document.getElementById("strategy-analytics-filter-range")?.value || "";
    const days = range === "7d" ? 7 : range === "30d" ? 30 : 0;
    if (!days) return "";
    const from = new Date(Date.now() - (days - 1) * 86_400_000);
    const iso = from.toISOString().slice(0, 10);
    return `?from=${iso}`;
}

export async function loadStrategyAnalytics() {
    const query = filterQuery();
    try {
        const [byStrategy, byCategory] = await Promise.all([
            API.strategyAnalyticsByStrategy(query),
            API.strategyAnalyticsByCategory(query),
        ]);
        lastStrategies = byStrategy.strategies || [];
        lastCategories = byCategory.categories || [];
        renderStrategyAnalytics({
            byStrategy,
            categories: lastCategories,
        });
    } catch (err) {
        showToast(`Failed to load strategy analytics: ${err.message}`, "error");
    }
}

function renderStrategyAnalytics({ byStrategy, categories }) {
    const body = document.getElementById("strategy-analytics-body");
    const empty = document.getElementById("strategy-analytics-empty");
    const message = document.getElementById("strategy-analytics-empty-message");
    const summaryEl = document.getElementById("strategy-analytics-filter-summary");

    // Honest empty state: a missing, corrupt, or simply empty log shows
    // "no attempts yet" — never a wall of zeros.
    const totalInLog = byStrategy.total_in_log || 0;
    if (totalInLog === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            "No strategy attempts recorded yet — the prompt-strategy log is empty or missing. " +
            "Attempts appear here as the pipeline translates.";
        summaryEl.textContent = "";
        return;
    }
    if (lastStrategies.length === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            `No attempts in the selected range — the log holds ${totalInLog} attempts.`;
        summaryEl.textContent = `0 of ${totalInLog} attempts`;
        return;
    }

    const attemptsInRange = lastStrategies.reduce((sum, s) => sum + s.attempts, 0);
    empty.style.display = "none";
    body.style.display = "";
    summaryEl.textContent =
        `${attemptsInRange} of ${totalInLog} attempts in range`;

    renderStrategyTable(lastStrategies);
    renderCategoryBars(categories);
}

function renderStrategyTable(strategies) {
    const tbody = document.getElementById("strategy-analytics-strategy-body");
    if (!tbody) return;
    tbody.innerHTML = strategies.map(s => `
        <tr>
            <td class="token-col-strategy">${escapeHtml(s.strategy)}</td>
            <td>${s.attempts}</td>
            <td>${s.successes}</td>
            <td>${s.failures}</td>
            <td class="token-col-rate">${fmtPercent(s.pass_rate)}</td>
        </tr>
    `).join("");
}

/* Pass-rate bars per binary category — the bar length is the pass rate,
   so a class of binary that defeats every strategy reads as a stub. */
function renderCategoryBars(categories) {
    const wrap = document.getElementById("strategy-analytics-category-bars");
    if (!wrap) return;
    wrap.innerHTML = categories.map(c => `
        <div class="token-bar-row">
            <span class="token-bar-label" title="${escapeHtml(c.category)}">${escapeHtml(c.category)}</span>
            <div class="token-bar-track">
                <div class="token-bar-fill" style="width:${c.pass_rate}%"></div>
            </div>
            <span class="token-bar-share">${fmtPercent(c.pass_rate)}</span>
            <span class="token-bar-count">${c.attempts} attempt${c.attempts === 1 ? "" : "s"}</span>
        </div>
    `).join("");
}

function fmtPercent(p) {
    return `${(p ?? 0).toFixed(1)}%`;
}

// ─── CSV export (client-side from the fetched JSON) ────────────────────

function csvCell(value) {
    const s = String(value ?? "");
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/* Builds the CSV text for the current filtered set — the per-strategy
   breakdown first, then a blank line and the per-category breakdown, each
   with its own header. Exposed on window for the headless tests,
   mirroring the faults CSV handle. */
export function buildStrategyAnalyticsCsv() {
    const header = ["attempts", "successes", "failures", "pass_rate"];
    const strategyRows = lastStrategies.map(s => [
        s.strategy, s.attempts, s.successes, s.failures, s.pass_rate,
    ]);
    const categoryRows = lastCategories.map(c => [
        c.category, c.attempts, c.successes, c.failures, c.pass_rate,
    ]);
    const section = (label, rows) =>
        [[label, ...header], ...rows].map(r => r.map(csvCell).join(",")).join("\n");
    return [
        section("strategy", strategyRows),
        section("category", categoryRows),
    ].join("\n\n");
}

export function exportStrategyAnalyticsCsv() {
    const blob = new Blob([buildStrategyAnalyticsCsv()], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "strategy-analytics.csv";
    a.click();
    URL.revokeObjectURL(a.href);
}

// ─── Controls ──────────────────────────────────────────────────────────

export function setupStrategyAnalyticsControls() {
    document.getElementById("strategy-analytics-filter-range")
        ?.addEventListener("change", loadStrategyAnalytics);
    document.getElementById("btn-export-strategy-csv")
        ?.addEventListener("click", exportStrategyAnalyticsCsv);
}

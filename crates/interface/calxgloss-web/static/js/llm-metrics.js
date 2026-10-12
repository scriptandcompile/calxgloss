/* ==========================================================================
   LLM performance metrics view (issue #128, W3.4) — attempt-level
   performance from the persisted logs: P50/P95/P99 attempt durations from
   the token usage log's recorded durations, timeout frequency over time
   from resource-exhaustion faults of the timeout kind, and attempt
   duration correlated by context tier. Honest granularity is the heart of
   this view: durations are attempt-level wall-clock seconds (compile and
   tests included) — never raw per-LLM-call latency — and unmeasured
   values render as an em dash, never a fabricated number. The time-range
   filter re-renders in place. Per-model and response-size metrics stay
   out of scope: no model name or response size is persisted anywhere.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

/* The shared query string for both metrics endpoints — the cards, the
   timeout trend, and the tier table always describe the same filtered
   set. The time range maps onto the same inclusive UTC `from` day bound
   the other analytics endpoints honor; "all time" sends no filter at
   all. */
function filterQuery() {
    const range = document.getElementById("llm-metrics-filter-range")?.value || "";
    const days = range === "7d" ? 7 : range === "30d" ? 30 : 0;
    if (!days) return "";
    const from = new Date(Date.now() - (days - 1) * 86_400_000);
    const iso = from.toISOString().slice(0, 10);
    return `?from=${iso}`;
}

export async function loadLlmMetrics() {
    const query = filterQuery();
    try {
        const [summary, byTier] = await Promise.all([
            API.llmMetricsSummary(query),
            API.llmMetricsByTier(query),
        ]);
        renderLlmMetrics({ summary, tiers: byTier.tiers || [] });
    } catch (err) {
        showToast(`Failed to load LLM metrics: ${err.message}`, "error");
    }
}

function renderLlmMetrics({ summary, tiers }) {
    const body = document.getElementById("llm-metrics-body");
    const empty = document.getElementById("llm-metrics-empty");
    const message = document.getElementById("llm-metrics-empty-message");
    const summaryEl = document.getElementById("llm-metrics-filter-summary");

    // Honest empty state: a missing, corrupt, or simply empty token log
    // shows "no attempts yet" — never a wall of zeros.
    const totalInLog = summary.total_in_log || 0;
    if (totalInLog === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            "No attempts recorded yet — the token usage log is empty or missing. " +
            "Attempt durations appear here as the pipeline translates.";
        summaryEl.textContent = "";
        return;
    }
    if ((summary.total_attempts || 0) === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            `No attempts in the selected range — the log holds ${totalInLog} attempts.`;
        summaryEl.textContent = `0 of ${totalInLog} attempts`;
        return;
    }

    empty.style.display = "none";
    body.style.display = "";
    summaryEl.textContent =
        `${summary.total_attempts} of ${totalInLog} attempts in range`;

    renderSummaryCards(summary);
    renderTimeoutTrend(summary.timeout_trend || []);
    renderTierTable(tiers);
}

/* The percentile cards. The label spells out what the number measures —
   attempt-level wall-clock, compile and tests included — so it is never
   mistaken for raw per-LLM-call latency. Unmeasured percentiles render
   as an em dash. */
function renderSummaryCards(summary) {
    const wrap = document.getElementById("llm-metrics-summary-cards");
    if (!wrap) return;
    const cards = [
        { label: "P50 attempt", value: fmtDuration(summary.p50_secs), cls: "" },
        { label: "P95 attempt", value: fmtDuration(summary.p95_secs), cls: "" },
        { label: "P99 attempt", value: fmtDuration(summary.p99_secs), cls: "" },
        { label: "Timeouts", value: String(summary.timeouts ?? 0), cls: "llm-metrics-timeouts" },
    ];
    wrap.innerHTML = cards.map(c => `
        <div class="status-card ${c.cls}">
            <div class="status-card-label">${escapeHtml(c.label)}</div>
            <div class="status-card-value">${escapeHtml(c.value)}</div>
        </div>
    `).join("");
    const measured = document.getElementById("llm-metrics-measured-note");
    if (measured) {
        measured.textContent = summary.measured_attempts === summary.total_attempts
            ? `All ${summary.total_attempts} attempts in range recorded a duration.`
            : `${summary.measured_attempts} of ${summary.total_attempts} attempts in range recorded a duration — the rest predate duration tracking and are excluded, never imputed.`;
    }
}

/* The timeout trend: timeouts per UTC day, drawn from the server's
   gap-filled buckets so the chart and the API agree on the numbers. */
function renderTimeoutTrend(days) {
    const wrap = document.getElementById("llm-metrics-timeout-trend");
    if (!wrap) return;
    if (!days.length) {
        wrap.innerHTML = `<div class="empty-state">No timeouts in the current range.</div>`;
        return;
    }
    const W = 600, H = 160, PAD = 24;
    const max = Math.max(...days.map(d => d.count), 1);
    const x = i => days.length === 1 ? W / 2 : PAD + (i * (W - 2 * PAD)) / (days.length - 1);
    const y = v => H - PAD - (v / max) * (H - 2 * PAD);
    const countPoints = days.map((d, i) => `${x(i).toFixed(1)},${y(d.count).toFixed(1)}`).join(" ");
    wrap.innerHTML = `
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"
             aria-label="Timeouts per day">
            <polyline class="fault-trend-count" points="${countPoints}"/>
        </svg>
        <div class="fault-trend-legend">
            <span class="fault-trend-legend-count">timeouts/day</span>
            <span class="fault-trend-range">${escapeHtml(days[0].date)} → ${escapeHtml(days[days.length - 1].date)}</span>
        </div>
    `;
}

/* The per-tier correlation table — an empty tier label is the honest
   "untracked" bucket, and an unmeasured percentile is an em dash. */
function renderTierTable(tiers) {
    const tbody = document.getElementById("llm-metrics-tier-body");
    if (!tbody) return;
    tbody.innerHTML = tiers.map(t => `
        <tr>
            <td class="token-col-strategy">${escapeHtml(t.tier || "untracked")}</td>
            <td>${t.attempts}</td>
            <td>${t.measured_attempts}</td>
            <td class="token-col-rate">${fmtDuration(t.p50_secs)}</td>
            <td class="token-col-rate">${fmtDuration(t.p95_secs)}</td>
        </tr>
    `).join("");
}

/* One duration in whole seconds — an em dash when it was never measured,
   never a fabricated zero. */
function fmtDuration(secs) {
    return secs == null ? "—" : `${secs}s`;
}

// ─── Controls ──────────────────────────────────────────────────────────

export function setupLlmMetricsControls() {
    document.getElementById("llm-metrics-filter-range")
        ?.addEventListener("change", loadLlmMetrics);
}

/* ==========================================================================
   Token usage analytics view (issue #126, W3.2) — where the token spend
   went, from the persisted token usage log: the summary split into
   successful and failed attempts, per-binary bars with percentage shares,
   per-context-tier bars, and a per-strategy table with a success rate per
   strategy. The estimated-cost panel computes client-side from per-model
   pricing the operator types in (persisted in localStorage) — the server
   holds no pricing config. The time-range filter re-renders in place.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

// The last fetched (filtered) summary — the cost panel estimates from
// exactly what the server reported, without a refetch.
let lastSummary = null;

// Operator-entered pricing lives only in the browser: USD per 1M tokens
// for the model the operator is running. No server-side pricing config.
const PRICING_KEY = "calxgloss_token_pricing";

/* The shared query string for all four analytics endpoints — the cards,
   bars, and table always describe the same filtered set. The time range
   maps onto the same inclusive UTC `from` day bound the faults endpoints
   honor; "all time" sends no filter at all. */
function filterQuery() {
    const range = document.getElementById("token-usage-filter-range")?.value || "";
    const days = range === "7d" ? 7 : range === "30d" ? 30 : 0;
    if (!days) return "";
    const from = new Date(Date.now() - (days - 1) * 86_400_000);
    const iso = from.toISOString().slice(0, 10);
    return `?from=${iso}`;
}

export async function loadTokenUsage() {
    const query = filterQuery();
    try {
        const [summary, byBinary, byTier, byStrategy] = await Promise.all([
            API.tokenUsageSummary(query),
            API.tokenUsageByBinary(query),
            API.tokenUsageByTier(query),
            API.tokenUsageByStrategy(query),
        ]);
        lastSummary = summary;
        renderTokenUsage({
            summary,
            byBinary: byBinary.binaries || [],
            byTier: byTier.tiers || [],
            byStrategy: byStrategy.strategies || [],
        });
    } catch (err) {
        showToast(`Failed to load token usage analytics: ${err.message}`, "error");
    }
}

function renderTokenUsage({ summary, byBinary, byTier, byStrategy }) {
    const body = document.getElementById("token-usage-body");
    const empty = document.getElementById("token-usage-empty");
    const message = document.getElementById("token-usage-empty-message");
    const summaryEl = document.getElementById("token-usage-filter-summary");

    // Honest empty state: a missing, corrupt, or simply empty log shows
    // "no usage yet" — never a wall of zeros.
    if ((summary.total_in_log || 0) === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            "No token usage recorded yet — the token usage log is empty or missing. " +
            "Attempts appear here as the pipeline translates.";
        summaryEl.textContent = "";
        renderCostPanel();
        return;
    }
    if ((summary.total_attempts || 0) === 0) {
        body.style.display = "none";
        empty.style.display = "flex";
        message.textContent =
            `No usage in the selected range — the log holds ${summary.total_in_log} attempts.`;
        summaryEl.textContent = `0 of ${summary.total_in_log} attempts`;
        renderCostPanel();
        return;
    }

    empty.style.display = "none";
    body.style.display = "";
    summaryEl.textContent =
        `${summary.total_attempts} of ${summary.total_in_log} attempts in range`;

    renderSummaryCards(summary);
    renderBinaryBars(byBinary);
    renderTierBars(byTier);
    renderStrategyTable(byStrategy);
    renderCostPanel();
}

function renderSummaryCards(summary) {
    const wrap = document.getElementById("token-usage-summary-cards");
    if (!wrap) return;
    const cards = [
        { label: "Total tokens", value: summary.total_tokens, cls: "token-total" },
        { label: "Successful attempts", value: summary.successful_tokens, cls: "token-success" },
        { label: "Failed attempts", value: summary.failed_tokens, cls: "token-failed" },
    ];
    wrap.innerHTML = cards.map(c => `
        <div class="status-card ${c.cls}">
            <div class="status-card-label">${escapeHtml(c.label)}</div>
            <div class="status-card-value">${fmtTokens(c.value)}</div>
        </div>
    `).join("");
}

function renderBinaryBars(binaries) {
    const wrap = document.getElementById("token-usage-binary-bars");
    if (!wrap) return;
    const max = Math.max(...binaries.map(b => b.tokens), 1);
    wrap.innerHTML = binaries.map(b => `
        <div class="token-bar-row">
            <span class="token-bar-label" title="${escapeHtml(b.binary)}">${escapeHtml(b.binary)}</span>
            <div class="token-bar-track">
                <div class="token-bar-fill" style="width:${(b.tokens / max) * 100}%"></div>
            </div>
            <span class="token-bar-share">${fmtPercent(b.share_percent)}</span>
            <span class="token-bar-count">${fmtTokens(b.tokens)}</span>
        </div>
    `).join("");
}

function renderTierBars(tiers) {
    const wrap = document.getElementById("token-usage-tier-bars");
    if (!wrap) return;
    const max = Math.max(...tiers.map(t => t.tokens), 1);
    wrap.innerHTML = tiers.map(t => {
        // Entries written before tier tracking carry no label — an honest
        // "untracked" bucket, never folded into a real tier.
        const label = t.tier || "untracked";
        return `
        <div class="token-bar-row">
            <span class="token-bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
            <div class="token-bar-track">
                <div class="token-bar-fill" style="width:${(t.tokens / max) * 100}%"></div>
            </div>
            <span class="token-bar-share">${t.attempts} attempt${t.attempts === 1 ? "" : "s"}</span>
            <span class="token-bar-count">${fmtTokens(t.tokens)}</span>
        </div>`;
    }).join("");
}

function renderStrategyTable(strategies) {
    const tbody = document.getElementById("token-usage-strategy-body");
    if (!tbody) return;
    tbody.innerHTML = strategies.map(s => `
        <tr>
            <td class="token-col-strategy">${escapeHtml(s.strategy)}</td>
            <td>${fmtTokens(s.tokens)}</td>
            <td>${s.attempts}</td>
            <td>${s.successes}</td>
            <td class="token-col-rate">${fmtPercent(s.success_rate)}</td>
        </tr>
    `).join("");
}

/* The estimated-cost panel: computed here, in the browser, from the
   fetched totals and the operator-typed price — the server never learns
   anything about pricing. */
function renderCostPanel() {
    const out = document.getElementById("token-usage-cost-output");
    if (!out) return;
    const price = parseFloat(document.getElementById("token-usage-cost-price")?.value);
    const estimate = tokens =>
        (lastSummary && Number.isFinite(price) && price >= 0)
            ? `$${(tokens / 1_000_000 * price).toFixed(2)}`
            : "—";
    out.innerHTML = `
        <span class="token-cost-item">Total:
            <strong id="token-usage-cost-total">${estimate(lastSummary?.total_tokens ?? 0)}</strong></span>
        <span class="token-cost-item">Successful:
            <strong id="token-usage-cost-successful">${estimate(lastSummary?.successful_tokens ?? 0)}</strong></span>
        <span class="token-cost-item">Failed:
            <strong id="token-usage-cost-failed">${estimate(lastSummary?.failed_tokens ?? 0)}</strong></span>
    `;
}

function fmtTokens(n) {
    return (n ?? 0).toLocaleString("en-US");
}

function fmtPercent(p) {
    return `${(p ?? 0).toFixed(1)}%`;
}

// ─── Controls ──────────────────────────────────────────────────────────

export function setupTokenUsageControls() {
    document.getElementById("token-usage-filter-range")
        ?.addEventListener("change", loadTokenUsage);

    // The pricing input persists to localStorage and re-estimates in
    // place — no refetch, since the cost derives from the fetched totals.
    const price = document.getElementById("token-usage-cost-price");
    if (!price) return;
    price.value = localStorage.getItem(PRICING_KEY) || "";
    price.addEventListener("input", () => {
        localStorage.setItem(PRICING_KEY, price.value);
        renderCostPanel();
    });
}

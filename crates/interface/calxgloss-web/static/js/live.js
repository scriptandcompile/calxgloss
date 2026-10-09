/* ==========================================================================
   Live translation view — one progress bar per in-flight unit (issue #65)

   Renders the records served by GET /api/progress/enhanced: each unit's
   current phase and elapsed time, plus context tier, retry strategy, attempt,
   baseline/verification pass status, and unit confidence. Honesty is the
   load-bearing rule: values the live stream has not reported render as "—",
   never as fabricated zeros, and outside `calxgloss live` the endpoint is not
   routed at all — the view says so rather than showing an idle-looking run.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";

const PHASE_LABELS = {
    ghidra_fetch: "Ghidra Fetch",
    api_tagging: "API Tagging",
    test_gen: "Test Gen",
    context_tier: "Context Tier",
    llm_call: "LLM Call",
    compiling: "Compiling",
    testing: "Testing",
    review: "Review",
};

// Order the unit pipeline walks through; drives the bar's fill fraction.
const PHASE_ORDER = Object.keys(PHASE_LABELS);

/** Most recent payload and when it arrived, so the ticker can extrapolate
 *  elapsed time between refreshes without pretending the unit moved. */
let lastState = null;
let lastFetchedAt = 0;
let tickerId = null;

/**
 * Fetch /api/progress/enhanced and render. A 404 means the dashboard is not
 * running inside `calxgloss live` — report that honestly instead of showing
 * an empty list that looks like an idle run.
 */
export async function loadLiveProgress() {
    const list = document.getElementById("live-units");
    if (!list) return;
    try {
        const data = await API.liveProgress();
        lastState = data;
        lastFetchedAt = Date.now();
        // Anchor each row's elapsed clock to when its record arrived, so a
        // later push for another unit doesn't shift this row's clock.
        (lastState.units || []).forEach(u => { u._receivedAt = lastFetchedAt; });
        renderLiveUnits();
    } catch (err) {
        lastState = null;
        list.innerHTML = "";
        if (String(err.message || err).includes("404")) {
            showEmpty("The live view needs a running pipeline — start " +
                "`calxgloss live` to watch units translate here.");
        } else {
            showEmpty("Live progress is unavailable right now — the request failed.");
        }
    }
}

/** Start the view: first fetch plus a 1s ticker for the elapsed clocks. */
export function startLiveView() {
    loadLiveProgress();
    if (!tickerId) {
        tickerId = setInterval(tickElapsed, 1000);
    }
}

/** Stop the ticker when leaving the view. */
export function stopLiveView() {
    if (tickerId) {
        clearInterval(tickerId);
        tickerId = null;
    }
}

/**
 * Merge one pushed `unit_phase` record into the snapshot and update that
 * unit's row in place (issue #55). The server pushes a unit's full record —
 * current phase, phase history, tier, evidence — after applying each
 * unit-scoped event, so rows stay current without refetching the endpoint.
 * Records arriving before the first snapshot are ignored: opening the tab
 * fetches one.
 */
export function applyUnitPhase(unit) {
    if (!lastState || !unit || !unit.binary) return;
    unit._receivedAt = Date.now();
    const units = lastState.units || [];
    const idx = units.findIndex(u => u.binary === unit.binary && u.function === unit.function);
    if (idx >= 0) units[idx] = unit;
    else units.push(unit);
    lastState.units = units;
    lastState.count = units.length;
    lastState.in_flight = units.filter(u => !u.finished).length;

    // Update just this unit's row — replacing the whole list on every push
    // churned hover and scroll state the way the dashboard cards did.
    const list = document.getElementById("live-units");
    if (!list) return;
    if (units.length === 0) { renderLiveUnits(); return; }
    const empty = document.getElementById("live-empty");
    if (empty) empty.style.display = "none";
    const summary = document.getElementById("live-summary");
    if (summary) {
        summary.textContent = `${lastState.in_flight} in flight / ${lastState.count} tracked`;
    }
    const existing = list.querySelector(
        `.live-unit[data-dll="${cssEscape(unit.binary)}"][data-function="${cssEscape(unit.function)}"]`
    );
    if (existing) {
        existing.outerHTML = unitRowHtml(unit);
    } else {
        list.insertAdjacentHTML("beforeend", unitRowHtml(unit));
    }
}

/** Escape a value for use inside a CSS attribute selector. */
function cssEscape(value) {
    return (window.CSS && CSS.escape) ? CSS.escape(value) : String(value).replace(/["\\]/g, "\\$&");
}

function showEmpty(message) {
    const empty = document.getElementById("live-empty");
    const msg = document.getElementById("live-empty-message");
    if (msg) msg.textContent = message;
    if (empty) empty.style.display = "";
}

/** One test-evidence chip: honest label per pass state, never a bare zero. */
function passChip(cls, label, status) {
    const state = status.state || "not_run";
    let text;
    if (state === "not_run") text = "not run";
    else if (state === "pending") text = `${status.total ?? "—"} queued`;
    else text = `${status.passed ?? "—"}/${status.total ?? "—"} ${state === "passed" ? "✓" : "✗"}`;
    return `<span class="live-chip pass-chip state-${escapeHtml(state)}" data-class="${cls}">` +
        `${escapeHtml(label)}: ${escapeHtml(text)}</span>`;
}

function renderLiveUnits() {
    const list = document.getElementById("live-units");
    const empty = document.getElementById("live-empty");
    const summary = document.getElementById("live-summary");
    if (!list) return;

    const units = (lastState && lastState.units) || [];
    if (units.length === 0) {
        list.innerHTML = "";
        if (summary) summary.textContent = "";
        showEmpty("No units in flight. Start a translation to watch it here.");
        return;
    }
    if (empty) empty.style.display = "none";
    if (summary) {
        summary.textContent = `${lastState.in_flight} in flight / ${lastState.count} tracked`;
    }

    list.innerHTML = units.map(unitRowHtml).join("");
}

/** Markup for one unit row — shared by the full render and the per-push update. */
function unitRowHtml(u) {
    const phase = u.phase || "unknown";
    const phaseLabel = PHASE_LABELS[phase] || phase;
    const idx = PHASE_ORDER.indexOf(phase);
    const fill = u.finished ? 100 : Math.round(((idx + 1) / PHASE_ORDER.length) * 100);
    const confidence = typeof u.unit_confidence === "number"
        ? `${Math.round(u.unit_confidence * 100)}%`
        : "—";
    const tier = u.context_tier ? `${u.context_tier}${u.tier_label ? ` (${u.tier_label})` : ""}` : "—";
    const strategy = u.retry_strategy || "—";
    const statusClass = u.finished ? (u.succeeded ? "finished-ok" : "finished-fail") : "in-flight";
    // Phases entered, in event order — tier escalations appear twice, so
    // the retry path stays visible on hover.
    const history = (u.phase_history || [])
        .map(r => PHASE_LABELS[r.phase] || r.phase).join(" → ");
    // Each row's clock is anchored to when its own record arrived, so a push
    // for one unit never shifts the other rows' elapsed counters.
    const receivedAt = u._receivedAt || lastFetchedAt;

    return `
        <div class="live-unit ${statusClass}" data-dll="${escapeHtml(u.binary)}" data-function="${escapeHtml(u.function)}">
            <div class="live-unit-header">
                <span class="live-unit-name">${escapeHtml(u.binary)} / ${escapeHtml(u.function)}</span>
                <span class="live-chip live-phase phase-${escapeHtml(phase)}" title="${escapeHtml(history)}">${escapeHtml(phaseLabel)}</span>
                <span class="live-chip live-elapsed" data-elapsed-base="${u.elapsed_secs ?? 0}" data-received-at="${receivedAt}">${Math.floor(u.elapsed_secs ?? 0)}s</span>
            </div>
            <div class="live-unit-bar"><div class="live-unit-bar-fill phase-${escapeHtml(phase)}" style="width:${fill}%"></div></div>
            <div class="live-unit-meta">
                <span class="live-chip" title="Context tier">tier: ${escapeHtml(tier)}</span>
                <span class="live-chip" title="Retry strategy">strategy: ${escapeHtml(strategy)}</span>
                <span class="live-chip" title="Attempt">attempt: ${u.attempt ?? "—"}</span>
                ${passChip("baseline", "baseline", u.baseline || {})}
                ${passChip("verification", "verification", u.verification || {})}
                <span class="live-chip live-confidence" title="Unit confidence">confidence: ${escapeHtml(confidence)}</span>
            </div>
        </div>`;
}

/** Advance the displayed elapsed clocks from each row's own base and anchor. */
function tickElapsed() {
    if (!lastState) return;
    document.querySelectorAll("#live-units .live-elapsed").forEach(el => {
        const base = parseFloat(el.dataset.elapsedBase || "0");
        const receivedAt = parseFloat(el.dataset.receivedAt || "0") || lastFetchedAt;
        const drift = (Date.now() - receivedAt) / 1000;
        el.textContent = `${Math.floor(base + drift)}s`;
    });
}

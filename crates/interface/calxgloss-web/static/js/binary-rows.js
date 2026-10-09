/* ==========================================================================
   Per-binary pipeline rows — one row per target binary (issue #63)

   Renders the `binaries` array served by GET /api/pipeline: function
   counts (total / translated / in-progress / queued / failed), token
   consumption, success rate, and the classification state (PAL trait /
   Shim → crate / Full RE / Unclassified) in one column. The honesty
   rule carries over from the records themselves: unknown totals,
   tokens, queued counts, and rates render as "—", never as fabricated
   zeros.

   The quick-action buttons (Start Translation, Pause, Configure) are
   placeholders that announce only — real pipeline control is W2's job
   and must not be wired up here.
   ========================================================================== */

import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

const ACTION_LABELS = {
    start: "Start Translation",
    pause: "Pause",
    configure: "Configure",
};

// Classification strategies arrive as Debug-formatted strings (e.g.
// "PalMapping"), so match on containment. One table drives the state
// column: crate replacement implies a shim layer, PAL mapping a PAL
// trait, full RE neither shim nor PAL. The state column is the single
// place the classification state appears — no separate strategy column.
const STRATEGIES = [
    {
        key: "PalMapping",
        shim: () => ({ kind: "pal", text: "PAL trait" }),
    },
    {
        key: "CrateReplacement",
        shim: (b) => ({
            kind: "shim",
            text: b.crate_replacement ? `Shim → ${b.crate_replacement}` : "Shim layer",
        }),
    },
    {
        key: "ReverseEngineer",
        shim: () => ({ kind: "none", text: "Full RE" }),
    },
];

function matchStrategy(strategy) {
    if (!strategy) return null;
    return STRATEGIES.find((s) => strategy.includes(s.key)) || null;
}

// Unclassified binaries report "Unclassified"; an unknown strategy
// string renders honestly as-is rather than being guessed at.
function shimStatus(b) {
    const match = matchStrategy(b.strategy);
    if (match) return match.shim(b);
    return { kind: "unknown", text: b.strategy || "Unclassified" };
}

// No "Classified" badge: the state column already states the
// classification state (PAL trait / Shim → crate / Full RE /
// Unclassified), so a badge would only repeat it.
function statusBadge(b) {
    if ((b.functions_in_progress || 0) > 0) return { cls: "translating", text: "Translating" };
    if (b.functions_total != null) return { cls: "complete", text: "Batch done" };
    return { cls: "pending", text: "In pipeline" };
}

function fmtCount(value) {
    return value == null ? "—" : String(value);
}

function fmtTokens(value) {
    return value == null ? "—" : value.toLocaleString("en-US");
}

// Queued functions are what the batch total leaves over once translated,
// in-progress, and failed are accounted for — unknown without a total.
function queuedCount(b) {
    if (b.functions_total == null) return null;
    const accounted =
        (b.functions_translated || 0) + (b.functions_in_progress || 0) + (b.functions_failed || 0);
    return Math.max(0, b.functions_total - accounted);
}

// Success rate over terminal outcomes only — no outcomes, no rate.
function successRate(b) {
    const attempts = (b.functions_translated || 0) + (b.functions_failed || 0);
    if (attempts === 0) return null;
    return Math.round(((b.functions_translated || 0) / attempts) * 100);
}

// Column header sharing the row's grid tracks, so every column lines up.
function renderHeader() {
    return `
        <div class="pipeline-binary-row pipeline-binary-header" aria-hidden="true">
            <div>Binary</div>
            <div class="pipeline-binary-counts">
                <span>Total</span><span>Translated</span><span>In progress</span><span>Queued</span><span>Failed</span>
            </div>
            <div class="pipeline-binary-cost">
                <span>Tokens</span><span>Success</span>
            </div>
            <div>Classification</div>
            <div>Actions</div>
        </div>
    `;
}

function renderRow(b) {
    const status = statusBadge(b);
    const shim = shimStatus(b);
    const queued = queuedCount(b);
    const rate = successRate(b);
    const dll = escapeHtml(b.dll || "unknown");

    return `
        <div class="pipeline-binary-row" data-dll="${dll}" data-status="${status.cls}">
            <div class="pipeline-binary-head">
                <span class="pipeline-binary-name" title="${dll}">${dll}</span>
                <span class="pipeline-binary-status ${status.cls}">${status.text}</span>
            </div>
            <div class="pipeline-binary-counts">
                <span class="pb-count" data-count="total" title="Total functions">${fmtCount(b.functions_total)} total</span>
                <span class="pb-count ok" data-count="translated" title="Functions translated">${b.functions_translated || 0} translated</span>
                <span class="pb-count" data-count="in_progress" title="Functions in progress">${b.functions_in_progress || 0} in progress</span>
                <span class="pb-count" data-count="queued" title="Not yet translated — derived: total − translated − in progress − failed">${fmtCount(queued)} queued</span>
                <span class="pb-count fail" data-count="failed" title="Functions failed">${b.functions_failed || 0} failed</span>
            </div>
            <div class="pipeline-binary-cost">
                <span data-metric="tokens" title="Tokens consumed">${fmtTokens(b.tokens_used)} tokens</span>
                <span data-metric="success-rate" title="Translated / (translated + failed)">${rate == null ? "—" : `${rate}% success`}</span>
            </div>
            <div class="pipeline-binary-state" data-shim="${shim.kind}" title="Classification state — PAL trait / shim layer / full RE / unclassified">${escapeHtml(shim.text)}</div>
            <div class="pipeline-binary-actions">
                ${Object.entries(ACTION_LABELS)
                    .map(
                        ([action, label]) => `<button class="pipeline-action-btn" data-action="${action}" data-dll="${dll}" title="Placeholder — pipeline control arrives in W2">${label}</button>`
                    )
                    .join("")}
            </div>
        </div>
    `;
}

/**
 * Render one row per target binary into #pipeline-binaries.
 * @param {Array} binaries - the BinaryProgress records from GET /api/pipeline
 */
export function renderPipelineBinaryRows(binaries) {
    const container = document.getElementById("pipeline-binaries");
    if (!container) return;

    // One delegated listener survives innerHTML re-renders. Placeholders
    // announce only — they must never call a state-changing endpoint.
    if (!container.dataset.placeholderWired) {
        container.dataset.placeholderWired = "1";
        container.addEventListener("click", (e) => {
            const btn = e.target.closest(".pipeline-action-btn");
            if (!btn) return;
            const action = ACTION_LABELS[btn.dataset.action] || btn.dataset.action;
            showToast(
                `${action} (${btn.dataset.dll}) is a placeholder — pipeline control arrives in W2.`,
                "info"
            );
        });
    }

    if (!Array.isArray(binaries) || binaries.length === 0) {
        container.innerHTML = '<div class="empty-state" style="padding:12px">No binaries discovered yet.</div>';
        return;
    }

    container.innerHTML = renderHeader() + binaries.map(renderRow).join("");
}

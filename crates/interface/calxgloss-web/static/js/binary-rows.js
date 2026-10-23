/* ==========================================================================
   Per-binary pipeline rows — one row per target binary (issue #63)

   Renders the `binaries` array served by GET /api/pipeline: function
   counts (total / translated / in-progress / queued / failed), token
   consumption, success rate, and the classification state (PAL trait /
   Shim → crate / Full RE / Unclassified) in one column. The honesty
   rule carries over from the records themselves: unknown totals,
   tokens, queued counts, and rates render as "—", never as fabricated
   zeros.

   The quick-action buttons (Start Translation / Pause toggle, Configure,
   Classify) are real controls (issue #94). One honest translation toggle
   per row (issue #285): it reads Pause exactly while the pipeline works
   this binary, and Start Translation for everything else. Start drives
   the per-binary start endpoint, a swap composed server-side that pauses
   the in-flight binary, resumes the pressed one, and moves it to the
   front of the queue plan — never the run-level lifecycle endpoint;
   Pause steers just this binary through the per-binary pause endpoint
   (issue #222). Configure opens the restart dialog with this binary pre-
   selected as the target, Classify opens the classification-override panel
   (issue #97). The server's own reason surfaces on rejection —
   a stale click is never a silent no-op.

   PAL-mapped binaries render a compact variant of the row (issue #244):
   trait names with defined/missing markers in the state cell, an
   "N/M defined" readiness count, and Classify only — the translation
   counts, cost cell, activity line, and translation controls are
   suppressed because a PAL binary is never a translation target.
   ========================================================================== */

import { escapeHtml } from "./utils.js";
import { API } from "./api.js";
import { runControl, showRestartDialog } from "./pipeline-controls.js";
import { openClassificationPanel } from "./classification-override.js";

const ACTION_LABELS = {
    start: "Start Translation",
    pause: "Pause",
    configure: "Configure",
    classify: "Classify",
};

const ACTION_TITLES = {
    start: "Pause the binary in flight and move this one to the front of the queue (POST /api/pipeline/binaries/{name}/start)",
    pause: "Hold this binary out of the queue until resumed (POST /api/pipeline/binaries/{name}/pause)",
    configure: "Open restart options with this binary pre-selected",
    classify: "Review and override this binary's classification (POST /api/binaries/{name}/classification)",
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

// The compact PAL row (issue #244) branches on the same PalMapping
// containment match the state cell already uses — one rule decides both.
// A PAL binary is never a translation target, so its row tracks
// classification and trait readiness instead of translation progress.
function isPalRow(b) {
    return matchStrategy(b.strategy)?.key === "PalMapping";
}

// The compact row's state cell reads like a crate-replacement row's
// "Shim → mlua" cell: PAL → the traits the poll's summary names, each
// marked defined or missing. No summary means the plain "PAL trait"
// text — there is nothing to list, and none is invented.
function palStateCell(b) {
    const traits = b.pal?.traits;
    if (!traits || traits.length === 0) return escapeHtml(shimStatus(b).text);
    const listed = traits
        .map(
            (t) =>
                `<span class="pal-trait" data-state="${t.defined ? "defined" : "missing"}" title="${
                    t.defined ? "Defined in the generated PAL layer" : "Not yet defined in the generated PAL layer"
                }">${escapeHtml(t.name)}</span>`
        )
        .join(", ");
    return `PAL → ${listed}`;
}

// "N/M defined" in the counts area — an em-dash when the poll carried no
// summary, never a fabricated 0/0 for a binary whose artifacts name no
// API-call categories.
function palReadiness(b) {
    const traits = b.pal?.traits;
    if (!traits || traits.length === 0) return "—";
    const defined = traits.filter((t) => t.defined).length;
    return `${defined}/${traits.length} defined`;
}

// No badge beside the name: the state lives in the Success column
// until a real success rate exists, and the classification state
// column already says whether the binary is classified. "Working"
// means the live pipeline's batch pass for this binary is in flight
// (enumeration, testgen, translation) — no unit events needed.
// "Paused" is the operator's own steering (issue #222) and leads the
// sequence — a held-out binary reads as held, whatever its pass did.
function statusBadge(b) {
    if (b.paused) return { cls: "paused", text: "Paused" };
    if ((b.functions_in_progress || 0) > 0) return { cls: "translating", text: "Translating" };
    if (b.processing) return { cls: "translating", text: "Working" };
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

// The working pass's latest heartbeat: pass name, the item it is on, and
// the position in its work list. Unknown parts are omitted, never faked.
function activityLine(b) {
    if (!b.activity) return "";
    const a = b.activity;
    const parts = [escapeHtml(a.pass)];
    if (a.function) parts.push(`<span class="pba-item">${escapeHtml(a.function)}</span>`);
    if (a.total != null) parts.push(`${fmtCount(a.index || 0)} of ${fmtCount(a.total)}`);
    return `<div class="pipeline-binary-activity" title="Analysis pass in progress on this binary">${parts.join(" · ")}</div>`;
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
    const dll = escapeHtml(b.binary || "unknown");
    const head = `
            <div class="pipeline-binary-head">
                <span class="pipeline-binary-name" title="${dll}">${dll}</span>
            </div>`;

    // PAL rows render the compact variant (issue #244); every other row
    // renders exactly as before — the variant tracks classification, not
    // position in the table.
    if (isPalRow(b)) return renderPalRow(b, status, dll, head);

    const shim = shimStatus(b);
    const queued = queuedCount(b);
    const rate = successRate(b);
    // One honest translation toggle per row (issue #285): Pause exactly
    // while the pipeline works this binary, Start Translation for
    // everything else — the paused flag wins, a held-out row never reads
    // as working. Start and Pause are one button, never both.
    const toggle = b.processing && !b.paused ? "pause" : "start";
    const actions = [
        [toggle, ACTION_LABELS[toggle]],
        ["configure", ACTION_LABELS.configure],
        ["classify", ACTION_LABELS.classify],
    ];

    return `
        <div class="pipeline-binary-row" data-binary="${dll}" data-status="${status.cls}">
            ${head}
            <div class="pipeline-binary-counts">
                <span class="pb-count" data-count="total" title="Total functions">${fmtCount(b.functions_total)} total</span>
                <span class="pb-count ok" data-count="translated" title="Functions translated">${b.functions_translated || 0} translated</span>
                <span class="pb-count" data-count="in_progress" title="Functions in progress">${b.functions_in_progress || 0} in progress</span>
                <span class="pb-count" data-count="queued" title="Not yet translated — derived: total − translated − in progress − failed">${fmtCount(queued)} queued</span>
                <span class="pb-count fail" data-count="failed" title="Functions failed">${b.functions_failed || 0} failed</span>
            </div>
            <div class="pipeline-binary-cost">
                <span data-metric="tokens" title="Tokens consumed">${fmtTokens(b.tokens_used)} tokens</span>
                <span data-metric="success-rate" title="Translated / (translated + failed)">${
                    rate == null
                        ? `<span class="pipeline-binary-status ${status.cls}">${status.text}</span>`
                        : `${rate}% success`
                }</span>
            </div>
            <div class="pipeline-binary-state" data-shim="${shim.kind}" title="Classification state — PAL trait / shim layer / full RE / unclassified">${escapeHtml(shim.text)}</div>
            <div class="pipeline-binary-actions">
                ${actions
                    .map(
                        ([action, label]) => `<button class="pipeline-action-btn" data-action="${action}" data-binary="${dll}" title="${ACTION_TITLES[action] || ""}">${label}</button>`
                    )
                    .join("")}
            </div>
            ${activityLine(b)}
        </div>
    `;
}

// The compact PAL row (issue #244): the binary name, the state cell
// enriched with the traits it maps to, a trait readiness count in the
// counts area, and Classify alone in the actions cell. The translation
// counts, the tokens/success cell, and the activity line are suppressed
// — a PAL binary has no translation pass to count, spend, or heartbeat —
// but the counts and cost cells stay as placeholder cells so the fixed
// grid tracks keep the row aligned with full rows. Classify stays as the
// correction path for a binary wrongly routed to PAL mapping; Start
// Translation, Pause, and Configure are never rendered, so the delegated
// listener's branches cannot fire for them.
function renderPalRow(b, status, dll, head) {
    return `
        <div class="pipeline-binary-row pipeline-binary-row-pal" data-binary="${dll}" data-status="${status.cls}">
            ${head}
            <div class="pipeline-binary-counts">
                <span class="pb-pal-readiness" data-count="pal-readiness" title="PAL traits the generated layer defines">${palReadiness(b)}</span>
            </div>
            <div class="pipeline-binary-cost" aria-hidden="true"></div>
            <div class="pipeline-binary-state" data-shim="pal" title="Classification state — PAL traits the binary maps to, defined or missing">${palStateCell(b)}</div>
            <div class="pipeline-binary-actions">
                <button class="pipeline-action-btn" data-action="classify" data-binary="${dll}" title="${ACTION_TITLES.classify}">${ACTION_LABELS.classify}</button>
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

    // One delegated listener survives innerHTML re-renders. Real controls:
    // the translation toggle drives the per-binary endpoints — start the
    // swap, pause the hold (issues #285, #222) — and configure opens the
    // restart dialog for this binary.
    if (!container.dataset.actionsWired) {
        container.dataset.actionsWired = "1";
        container.addEventListener("click", async (e) => {
            const btn = e.target.closest(".pipeline-action-btn");
            if (!btn) return;
            const { action, binary } = btn.dataset;
            if (action === "configure") {
                showRestartDialog({ target: binary });
                return;
            }
            if (action === "classify") {
                openClassificationPanel(binary);
                return;
            }
            // Both halves of the toggle are steering, not lifecycle
            // (issue #217): the row's buttons never touch the run-wide
            // endpoints — start drives the per-binary swap composed
            // server-side (issue #285), pause the per-binary hold.
            const call =
                action === "start"
                    ? () => API.startBinary(binary)
                    : () => API.pauseBinary(binary);
            // Same driver as the header buttons: success adopts the server's
            // state, rejection surfaces the server's own reason.
            await runControl(action, call);
        });
    }

    if (!Array.isArray(binaries) || binaries.length === 0) {
        container.innerHTML = '<div class="empty-state" style="padding:12px">No binaries discovered yet.</div>';
        return;
    }

    container.innerHTML = renderHeader() + binaries.map(renderRow).join("");
}

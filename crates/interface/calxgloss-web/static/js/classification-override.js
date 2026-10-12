/* ==========================================================================
   Binary classification override panel (issue #97, W2.8)

   Opened from a pipeline row's Classify button. Shows what the workspace
   recorded for the binary — category, strategy, and the reasoning behind
   it — alongside the override in force, and lets the operator correct the
   classification without a CLI re-run: a category from the full DllCategory
   set, plus a target crate for the crate-replacement modes (MicrosoftSdk /
   KnownThirdParty) where the crate name actually means something.

   Honesty rules carried from the endpoints: a server without the control
   attached answers with its own reason, which renders here rather than a
   silent empty panel; a classification with no stored reasoning says so —
   records written before reasoning existed are not retroactively explained.
   Apply and Clear adopt whatever the server echoes back, so the rendered
   state is always the server's, never the form's.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

// The full DllCategory set, in the serde variant names the API speaks.
const CATEGORIES = [
    "WindowsOs",
    "MicrosoftSdk",
    "KnownThirdParty",
    "ProjectSpecific",
    "UnknownThirdParty",
    "RuntimeLibrary",
];

// The categories that route to crate replacement — the target crate input
// is only enabled for these, mirroring the analyzer's dispatch.
const CRATE_CATEGORIES = new Set(["MicrosoftSdk", "KnownThirdParty"]);

// The strategy each category routes to — the analyzer's dispatch spelled
// for the hint line.
const STRATEGY_OF = {
    WindowsOs: "PalMapping",
    MicrosoftSdk: "CrateReplacement",
    KnownThirdParty: "CrateReplacement",
    ProjectSpecific: "ReverseEngineer",
    UnknownThirdParty: "ReverseEngineer",
    RuntimeLibrary: "ReverseEngineer",
};

// The panel's current subject: { binary, classification, override } as the
// server last reported it. The form always starts from this, never from
// stale widget state.
let current = null;

function panelElement() {
    return document.getElementById("classification-override-panel");
}

function closePanel() {
    const panel = panelElement();
    if (panel) panel.remove();
    current = null;
}

// The recorded-classification block: what the run decided and why. Missing
// pieces are named, never guessed at.
function renderCurrent(c) {
    if (!c) {
        return `<div class="override-empty">No classification recorded for this binary.</div>`;
    }
    const parts = [
        `<span class="clf-current-item"><strong>${escapeHtml(c.category)}</strong>`,
        c.strategy ? `→ ${escapeHtml(c.strategy)}` : "",
        c.crate_replacement ? ` (crate: ${escapeHtml(c.crate_replacement)})` : "",
        c.known_runtime ? " · known runtime — never a translation target" : "",
        "</span>",
    ];
    const reason = c.reason
        ? `<div class="clf-reason" title="Why the analyzer classified it this way">${escapeHtml(c.reason)}</div>`
        : `<div class="override-empty">No reasoning recorded for this classification.</div>`;
    return parts.join("") + reason;
}

// The override-in-force line: what the operator's correction routes to.
function renderOverrideState(o) {
    if (!o) {
        return `<div class="override-empty">No override in force — the recorded classification is used.</div>`;
    }
    const crate = o.crate_replacement ? ` (crate: ${escapeHtml(o.crate_replacement)})` : "";
    const runtime = o.known_runtime ? " · marked known runtime" : "";
    return `<div class="clf-override-active">Override in force: <strong>${escapeHtml(o.category)}</strong>${crate}${runtime}</div>`;
}

function renderPanel() {
    const panel = panelElement();
    if (!panel || !current) return;
    const { binary, classification, override } = current;

    // The form pre-fills from the override when one is in force, otherwise
    // from the recorded classification — the operator sees the current
    // decision and nudges it, rather than starting from a blank.
    const selected = override ? override.category : classification ? classification.category : "";
    const crateValue = (override ? override.crate_replacement : classification ? classification.crate_replacement : "") || "";
    const knownRuntime = override ? !!override.known_runtime : !!(classification && classification.known_runtime);

    panel.innerHTML = `
        <div class="clf-header">
            <h2>🏷 Classification — ${escapeHtml(binary)}</h2>
            <button id="clf-close" class="btn btn-sm" title="Close this panel">Close</button>
        </div>
        <div class="clf-current">${renderCurrent(classification)}</div>
        ${renderOverrideState(override)}
        <div class="override-form">
            <div class="override-field">
                <label for="clf-category">Category</label>
                <select id="clf-category">
                    ${CATEGORIES.map(
                        (c) => `<option value="${c}"${c === selected ? " selected" : ""}>${c}</option>`
                    ).join("")}
                </select>
                <span class="clf-strategy-hint" id="clf-strategy-hint"></span>
            </div>
            <div class="override-field">
                <label for="clf-crate">Target crate (crate-replacement modes only)</label>
                <input id="clf-crate" type="text" value="${escapeHtml(crateValue)}" placeholder="e.g. wgpu" />
            </div>
            <div class="override-field override-field-inline">
                <label for="clf-runtime">Known runtime — never a translation target</label>
                <input id="clf-runtime" type="checkbox" ${knownRuntime ? "checked" : ""} />
            </div>
            <div class="override-buttons">
                <button id="clf-apply" class="btn btn-sm btn-primary">Apply override</button>
                <button id="clf-clear" class="btn btn-sm btn-danger" ${override ? "" : "disabled"}>Clear override</button>
            </div>
        </div>
    `;

    const categorySelect = panel.querySelector("#clf-category");
    const crateInput = panel.querySelector("#clf-crate");
    const hint = panel.querySelector("#clf-strategy-hint");

    const syncForm = () => {
        const category = categorySelect.value;
        crateInput.disabled = !CRATE_CATEGORIES.has(category);
        const strategy = STRATEGY_OF[category];
        hint.textContent = strategy
            ? `Routes to: ${strategy}${category === "RuntimeLibrary" ? " — and never a translation target" : ""}`
            : "";
    };
    categorySelect.addEventListener("change", syncForm);
    syncForm();

    panel.querySelector("#clf-close").addEventListener("click", closePanel);

    // The rendered state follows the server's echo, never the form.
    const adopt = (res) => {
        current = { binary: res.binary, classification: res.classification, override: res.override };
        renderPanel();
    };

    panel.querySelector("#clf-apply").addEventListener("click", async (e) => {
        const btn = e.target;
        btn.disabled = true;
        try {
            const category = categorySelect.value;
            const crate = crateInput.value.trim();
            const res = await API.setBinaryClassification(binary, {
                category,
                crate_replacement: CRATE_CATEGORIES.has(category) && crate ? crate : null,
                known_runtime: panel.querySelector("#clf-runtime").checked,
            });
            adopt(res);
            showToast(`Classification overridden: ${binary} → ${category}`, "success");
        } catch (err) {
            showToast(`Override failed: ${err.message}`, "error");
            btn.disabled = false;
        }
    });

    panel.querySelector("#clf-clear").addEventListener("click", async (e) => {
        const btn = e.target;
        btn.disabled = true;
        try {
            const res = await API.clearBinaryClassification(binary);
            adopt(res);
            showToast(`Override cleared — ${binary} falls back to its recorded classification`, "info");
        } catch (err) {
            showToast(`Clear failed: ${err.message}`, "error");
            btn.disabled = false;
        }
    });
}

function renderUnavailable(reason) {
    const panel = panelElement();
    if (!panel) return;
    panel.innerHTML = `
        <div class="clf-header">
            <h2>🏷 Classification</h2>
            <button id="clf-close" class="btn btn-sm">Close</button>
        </div>
        <div class="override-unavailable">${escapeHtml(reason)}</div>
    `;
    panel.querySelector("#clf-close").addEventListener("click", closePanel);
}

/**
 * Open the classification-override panel for one binary, below the pipeline
 * rows. Fetches the current classification and override first; the server's
 * own reason renders when the endpoints are unavailable.
 * @param {string} binary - the binary identity (filename verbatim)
 */
export async function openClassificationPanel(binary) {
    closePanel();
    const container = document.getElementById("pipeline-binaries");
    if (!container) return;

    const panel = document.createElement("div");
    panel.id = "classification-override-panel";
    panel.className = "classification-override-panel";
    container.after(panel);

    try {
        const res = await API.binaryClassification(binary);
        current = { binary: res.binary, classification: res.classification, override: res.override };
        renderPanel();
    } catch (err) {
        current = null;
        renderUnavailable(`Classification endpoints unavailable: ${err.message}`);
    }
}

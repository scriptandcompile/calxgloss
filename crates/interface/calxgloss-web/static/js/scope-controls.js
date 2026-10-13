/* ==========================================================================
   Translation scope controls panel — scope, priorities, constraints (issue #95)

   The dashboard panel that steers what the live run touches and what it may
   consume. Every control drives its live-only scope endpoint over REST, and
   the rendered state always follows the server's answer — every scope
   endpoint echoes the full status, so the panel re-renders from that and
   never keeps a local guess the server contradicts.

   The category checkboxes are a friendly view over the scope's binaries
   allow-list: each reads as "the binaries of this classification category
   are (not) in scope", and toggling one recomputes the allow-list from the
   run's own classifications and replaces it wholesale. Categories no
   checkbox speaks for (Windows OS, Microsoft SDK) keep whatever the
   server's current allow-list says. An allow-list that covers every known
   binary is sent as the empty list — the unsteered "everything, future
   binaries included" state the server starts from.

   Without a scope control attached (plain `serve`, or a live router built
   without the handle) the panel says so and stays hidden — the controls
   header's honesty rule, same shape.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";
import { categoryKey, CONTEXT_TIER_LABELS } from "./constants.js";
import { loadPipelineBinaries } from "./pipeline-binaries.js";

// The four checkboxes and the classification category each speaks for.
// "translate" mode: checked means the category's binaries are in scope;
// "skip" mode: checked means they are kept out. The wire names are derived
// from CATEGORY_LABELS — the one map of the backend's serde variant names
// — by display label, so a backend rename touches that map alone
// (issue #109). A label missing from the map removes its checkbox from
// the panel with a loud console error, and the category then keeps
// whatever the server's current allow-list says, like Windows OS and
// Microsoft SDK already do — never steering from a name that matches no
// binary.
const CHECKBOX_CATEGORIES = [
    { id: "scope-skip-runtime", label: "Runtime Library", mode: "skip" },
    { id: "scope-translate-project-specific", label: "Project Specific", mode: "translate" },
    { id: "scope-translate-known-third-party", label: "Known 3rd Party", mode: "translate" },
    { id: "scope-skip-unknown-third-party", label: "Unknown 3rd Party", mode: "skip" },
].flatMap(({ id, label, mode }) => {
    const category = categoryKey(label);
    if (category === null) {
        console.error(
            `scope-controls: no classification category labeled "${label}" — checkbox "${id}" removed`
        );
        document.getElementById(id)?.closest("label")?.remove();
        return [];
    }
    return [{ id, category, mode }];
});

// The latest ScopeStatusResponse — the panel's only source of truth. Every
// render reads from it, never from the current input values.
let status = null;
// Whether a scope call is in flight — the display refresher stands down while
// one is, so its echo-driven re-render stays the single writer.
let panelBusy = false;
// binary → classification category, from /api/pipeline. The checkboxes'
// view over which binaries each category actually holds.
let binaryCategories = new Map();

/** Wire the panel's controls to the scope endpoints (once, at startup). */
export function setupScopeControls() {
    for (const { id } of CHECKBOX_CATEGORIES) {
        const box = document.getElementById(id);
        if (box) box.addEventListener("change", () => applyScopeFromCheckboxes());
    }
    const addBtn = document.getElementById("scope-priority-add-btn");
    if (addBtn) addBtn.addEventListener("click", addPriorityFromForm);
    const applyBtn = document.getElementById("scope-constraints-apply");
    if (applyBtn) applyBtn.addEventListener("click", applyConstraintsFromForm);

    const list = document.getElementById("scope-priority-list");
    if (list) {
        list.addEventListener("click", (e) => {
            const btn = e.target.closest(".scope-priority-remove");
            if (!btn) return;
            const chip = btn.closest(".scope-priority-chip");
            if (chip) removePriority(chip.dataset.binary, chip.dataset.function);
        });
    }
}

/**
 * Read the run's current scope and constraints (and the classifications
 * the checkboxes speak over) and render the panel. On a server with no
 * scope control attached the panel shows its honest unavailable state.
 */
export async function loadScopeControls() {
    try {
        status = await API.scopeStatus();
    } catch {
        showScopeUnavailable();
        return;
    }
    await refreshBinaryCategories();
    renderScopePanel();
}

/**
 * Keep the read-only parts of the panel (summary, token remaining) fresh
 * alongside the dashboard's periodic refresh. Input values are deliberately
 * left alone — an operator mid-edit must not have their draft overwritten.
 * Cheap no-op when the panel is unavailable or a call is in flight.
 */
export async function refreshScopeDisplay() {
    if (!status || panelBusy) return;
    try {
        status = await API.scopeStatus();
    } catch {
        return; // keep the last good render; the next tick retries
    }
    renderScopeSummary();
    renderTokenRemaining();
}

/**
 * Refresh the binary → classification map from the shared pipeline-binary
 * loader, so a toggle always recomputes over the binaries discovered so
 * far — including ones that appeared after the panel loaded.
 */
async function refreshBinaryCategories() {
    try {
        const binaries = await loadPipelineBinaries();
        binaryCategories = new Map(binaries.map((b) => [b.binary, b.category || null]));
    } catch {
        // Honest: no classifications known yet — the checkboxes have no
        // category to read, and the priority select offers no binaries.
        binaryCategories = new Map();
    }
}

// ─── Rendering ──────────────────────────────────────────────────────────

function showScopeUnavailable() {
    const message = document.getElementById("scope-unavailable-message");
    if (message) {
        message.textContent =
            "No scope control attached — translation controls need a live pipeline (calxgloss live).";
    }
    const unavailable = document.getElementById("scope-unavailable");
    if (unavailable) unavailable.style.display = "";
    const body = document.getElementById("scope-body");
    if (body) body.style.display = "none";
}

/** Whether the named binary is admitted by the scope's current allow-list. */
function admits(binary) {
    const list = (status && status.scope.binaries) || [];
    return list.length === 0 || list.some((b) => String(b).toLowerCase() === String(binary).toLowerCase());
}

function categoryBinaries(category) {
    return [...binaryCategories.entries()]
        .filter(([, c]) => c === category)
        .map(([binary]) => binary);
}

/** The checked state a checkbox must show for the server's current scope. */
function checkboxChecked({ category, mode }) {
    const binaries = categoryBinaries(category);
    if (binaries.length === 0) {
        // Nothing of this category discovered yet — show what the current
        // steering implies for one that appears later: an unsteered run
        // admits it, a steered allow-list that omits it does not.
        return (status.scope.binaries || []).length === 0 ? mode === "translate" : mode === "skip";
    }
    const admitted = binaries.filter(admits).length;
    return mode === "translate" ? admitted === binaries.length : admitted === 0;
}

function renderScopePanel() {
    if (!status) return;
    const unavailable = document.getElementById("scope-unavailable");
    if (unavailable) unavailable.style.display = "none";
    const body = document.getElementById("scope-body");
    if (body) body.style.display = "";

    for (const cfg of CHECKBOX_CATEGORIES) {
        const box = document.getElementById(cfg.id);
        if (box) box.checked = checkboxChecked(cfg);
    }
    renderPriorityList();
    renderConstraints();
    renderScopeSummary();
}

function renderScopeSummary() {
    const summary = document.getElementById("scope-summary");
    if (summary && status) {
        const list = (status.scope.binaries || []).length;
        summary.textContent = list === 0 ? "all binaries in scope" : `${list} binaries in scope`;
    }
}

function renderPriorityList() {
    const list = document.getElementById("scope-priority-list");
    if (list) {
        const priorities = status.scope.priority_functions || [];
        list.innerHTML = priorities.length
            ? priorities
                  .map(
                      (p) => `
                <span class="scope-priority-chip" data-binary="${escapeHtml(p.binary)}" data-function="${escapeHtml(p.function)}">
                    ${escapeHtml(p.function)} <span class="scope-priority-binary">(${escapeHtml(p.binary)})</span>
                    <button class="scope-priority-remove" title="Remove from the priority list"
                            aria-label="Remove ${escapeHtml(p.function)}">×</button>
                </span>`
                  )
                  .join("")
            : '<p class="scope-empty">No priority functions — the queue keeps its natural order.</p>';
    }
    const select = document.getElementById("scope-priority-binary");
    if (select) {
        const binaries = [...binaryCategories.keys()].sort();
        select.innerHTML = binaries.length
            ? binaries.map((b) => `<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`).join("")
            : '<option value="">No binaries discovered yet</option>';
    }
}

function renderConstraints() {
    renderTierOptions();
    const c = status.constraints || {};
    setVal("scope-max-attempts", c.max_attempts ?? "");
    setVal("scope-max-tier", c.max_context_tier ?? "");
    setVal("scope-token-budget", c.token_budget ?? "");
    renderTokenRemaining();
}

/**
 * The tier select's values come from the status response's `context_tiers`
 * — the backend's own ContextTier enumeration — so the panel can never
 * offer a cap the constraints endpoint would refuse with a 400; the label
 * map only spells them for humans, falling back to the raw name
 * (issue #109). Options are rebuilt before the value is set, so the
 * server's current cap always lands on a real option.
 */
function renderTierOptions() {
    const select = document.getElementById("scope-max-tier");
    if (!select) return;
    const tiers = status.context_tiers || [];
    select.innerHTML =
        '<option value="">No cap</option>' +
        tiers
            .map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(CONTEXT_TIER_LABELS[t] || t)}</option>`)
            .join("");
}

function renderTokenRemaining() {
    const c = (status && status.constraints) || {};
    const spent = status.tokens_spent ?? 0;
    const el = document.getElementById("scope-token-remaining");
    if (el) {
        el.textContent =
            c.token_budget == null
                ? `${spent} tokens spent — no budget cap`
                : `${Math.max(c.token_budget - spent, 0)} of ${c.token_budget} tokens left — ${spent} spent`;
    }
}

function setVal(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value;
}

// ─── Mutations ──────────────────────────────────────────────────────────

/**
 * Drive one scope endpoint: busy-lock the panel for the request's duration,
 * adopt the full status the server echoes on success, and surface the
 * server's own reason on rejection — re-rendering from the unchanged status
 * so the inputs snap back to the server's truth.
 * @param {string} label - the operation name, for the failure toast
 * @param {Function} call - the API call returning a ScopeStatusResponse
 */
async function runScopeCall(label, call) {
    setScopeBusy(true);
    panelBusy = true;
    try {
        status = await call();
        renderScopePanel();
    } catch (err) {
        showToast(`${label} failed: ${err.message}`, "error");
        renderScopePanel();
    } finally {
        panelBusy = false;
        setScopeBusy(false);
    }
}

// How many scope calls are in flight — the lock engages on the first and
// releases on the last, so overlapping calls can never leave the panel stuck.
let busyCalls = 0;

function setScopeBusy(busy) {
    const next = busyCalls + (busy ? 1 : -1);
    if (busyCalls === 0 && next > 0) {
        const panel = document.getElementById("scope-body");
        if (panel) {
            for (const el of panel.querySelectorAll("input, select, button")) {
                el.dataset.wasDisabled = el.disabled ? "1" : "";
                el.disabled = true;
            }
        }
    } else if (busyCalls > 0 && next === 0) {
        const panel = document.getElementById("scope-body");
        if (panel) {
            for (const el of panel.querySelectorAll("input, select, button")) {
                if (el.dataset.wasDisabled === "") el.disabled = false;
                delete el.dataset.wasDisabled;
            }
        }
    }
    busyCalls = Math.max(next, 0);
}

/** Recompute the binaries allow-list from the checkboxes and replace it. */
async function applyScopeFromCheckboxes() {
    await refreshBinaryCategories();
    const excluded = new Set(
        CHECKBOX_CATEGORIES.filter(({ id, mode }) => {
            const box = document.getElementById(id);
            const on = box && box.checked;
            return mode === "skip" ? on : !on;
        }).map(({ category }) => category)
    );
    const covered = new Set(CHECKBOX_CATEGORIES.map((c) => c.category));
    const all = [...binaryCategories.keys()];
    const previous = (status && status.scope.binaries) || [];
    const steered = previous.length > 0;
    const list = all.filter((b) => {
        const category = binaryCategories.get(b);
        if (covered.has(category)) return !excluded.has(category);
        // Categories no checkbox speaks for (Windows OS, Microsoft SDK) keep
        // whatever the server's current allow-list says — never silently
        // re-admitted by an unrelated toggle.
        return !steered || previous.some((p) => String(p).toLowerCase() === String(b).toLowerCase());
    });
    // Covering every known binary is the unsteered state — send the empty
    // list so binaries discovered later stay in scope, exactly as before.
    await runScopeCall("Scope change", () => API.setScopeBinaries(list.length === all.length ? [] : list));
}

async function addPriorityFromForm() {
    const binary = document.getElementById("scope-priority-binary")?.value || "";
    const fn = (document.getElementById("scope-priority-function")?.value || "").trim();
    if (!binary || !fn) {
        showToast("Pick a binary and name the function to prioritize", "warning");
        return;
    }
    await runScopeCall("Prioritize", () => API.prioritizeScopeFunction(binary, fn));
    const input = document.getElementById("scope-priority-function");
    if (input) input.value = "";
}

async function removePriority(binary, fn) {
    await runScopeCall("Remove priority", () => API.removeScopePriorityFunction(binary, fn));
}

async function applyConstraintsFromForm() {
    const maxAttempts = intOrNull("scope-max-attempts", "Max LLM attempts");
    const tokenBudget = intOrNull("scope-token-budget", "Token budget");
    if (maxAttempts === undefined || tokenBudget === undefined) return;
    const body = {
        max_attempts: maxAttempts,
        max_context_tier: document.getElementById("scope-max-tier")?.value || null,
        token_budget: tokenBudget,
    };
    // The endpoint replaces the constraints wholesale — send all three
    // dimensions at once so a partial edit never silently drops a cap.
    await runScopeCall("Constraints", () => API.setScopeConstraints(body));
}

/**
 * Parse a constraint input: empty means no cap (null); an unparseable value
 * warns and returns undefined so Apply sends nothing rather than silently
 * lifting a cap the operator meant to keep.
 */
function intOrNull(id, label) {
    const raw = (document.getElementById(id)?.value || "").trim();
    if (raw === "") return null;
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 0) {
        showToast(`${label} must be a whole number of 0 or more — empty means no cap`, "warning");
        return undefined;
    }
    return n;
}

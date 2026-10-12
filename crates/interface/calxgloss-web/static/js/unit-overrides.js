/* ==========================================================================
   Per-unit reviewer overrides — the Overrides tab in the unit detail
   (issue #96, W2.7).

   A reviewer steering a live run overrides how one unit's next attempt
   runs: force the context tier, force the retry strategy, append custom
   hints, skip the unit, and record notes. The tab reads the current
   record from `GET /api/units/{id}/override`, and every control drives
   the apply/remove endpoint over REST — the rendered state always
   follows the record the server echoes back, never a local guess.

   Reviewer notes also surface in the detail overview, next to the unit's
   own assessment, so they are visible without opening the tab.

   Without an override control attached (plain `serve`, or a live router
   built without the handle) the tab says so and offers no controls —
   the scope panel's honesty rule, same shape.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

// The context tiers and retry strategies the server understands — the
// select options mirror the serde labels of ContextTier and of the shared
// calxgloss-types RetryStrategy enum (a label the enum doesn't know is
// refused at the API boundary).
const TIER_OPTIONS = ["Signature", "Disassembly", "WithTests", "ModuleContext", "FullModule"];
const STRATEGY_OPTIONS = ["default", "compile_fix", "test_fix", "escalate", "edge_case_fix"];

/**
 * Fetch the unit's current override and render the Overrides tab body.
 * Called right after the detail panel's HTML is set; a missing route
 * (plain `serve`) or missing handle (503) renders the honest
 * unavailable state instead of controls.
 */
export async function loadUnitOverrides(unitId) {
    const body = document.getElementById("overrides-body");
    if (!body) return;
    let record = null;
    try {
        const res = await API.unitOverride(unitId);
        record = res.override || null;
    } catch (err) {
        body.innerHTML = `
            <div class="override-unavailable">
                Overrides need a live pipeline (calxgloss live) — this server
                has no unit override control attached. (${escapeHtml(err.message)})
            </div>`;
        return;
    }
    renderOverridePanel(unitId, record);
    injectReviewerNotes(record);
}

// ─── Rendering ──────────────────────────────────────────────────────────

function renderOverridePanel(unitId, record) {
    const body = document.getElementById("overrides-body");
    if (!body) return;
    const o = record || {};

    body.innerHTML = `
        <div class="override-summary" id="override-summary">
            ${record ? renderOverrideSummary(o) : '<div class="override-empty">No override — this unit runs with automatic behavior.</div>'}
        </div>

        <div class="override-form">
            <div class="override-field">
                <label for="override-tier">Force context tier</label>
                <select id="override-tier">
                    <option value="">Automatic</option>
                    ${TIER_OPTIONS.map((t) => `<option value="${t}" ${o.tier_override === t ? "selected" : ""}>${t}</option>`).join("")}
                </select>
            </div>
            <div class="override-field">
                <label for="override-strategy">Force retry strategy</label>
                <select id="override-strategy">
                    <option value="">Automatic</option>
                    ${STRATEGY_OPTIONS.map((s) => `<option value="${s}" ${o.retry_strategy_override === s ? "selected" : ""}>${s}</option>`).join("")}
                </select>
            </div>
            <div class="override-field">
                <label for="override-hints">Custom hints (one per line)</label>
                <textarea id="override-hints" rows="3" placeholder="What you know about this function…">${escapeHtml((o.custom_hints || []).join("\n"))}</textarea>
            </div>
            <div class="override-field override-field-inline">
                <label for="override-skip">Skip this unit</label>
                <input type="checkbox" id="override-skip" ${o.skip ? "checked" : ""}>
            </div>
            <div class="override-field">
                <label for="override-notes">Reviewer notes</label>
                <textarea id="override-notes" rows="3" placeholder="Your assessment of this unit…">${escapeHtml(o.reviewer_notes || "")}</textarea>
            </div>
            <div class="override-buttons">
                <button class="btn btn-primary" id="override-apply">Apply override</button>
                <button class="btn btn-secondary" id="override-remove" ${record ? "" : "disabled"}>Remove override</button>
            </div>
        </div>
    `;

    document.getElementById("override-apply")?.addEventListener("click", () => applyOverrideFromForm(unitId));
    document.getElementById("override-remove")?.addEventListener("click", () => removeOverride(unitId));
}

/** What is in force right now, spelled out for a reviewer scanning the tab. */
function renderOverrideSummary(o) {
    const rows = [];
    rows.push(`
        <div class="detail-row">
            <span class="detail-row-label">Tier</span>
            <span class="detail-row-value">${o.tier_override ? `forced to ${escapeHtml(o.tier_override)}` : "automatic"}</span>
        </div>`);
    rows.push(`
        <div class="detail-row">
            <span class="detail-row-label">Retry strategy</span>
            <span class="detail-row-value">${o.retry_strategy_override ? `forced to ${escapeHtml(o.retry_strategy_override)}` : "automatic"}</span>
        </div>`);
    rows.push(`
        <div class="detail-row">
            <span class="detail-row-label">Custom hints</span>
            <span class="detail-row-value">${o.custom_hints && o.custom_hints.length ? `${o.custom_hints.length} appended to the prompt` : "none"}</span>
        </div>`);
    rows.push(`
        <div class="detail-row">
            <span class="detail-row-label">Skip</span>
            <span class="detail-row-value">${o.skip ? "skipped — leaves the queue at the next selection" : "not skipped"}</span>
        </div>`);
    if (o.reviewer_notes) {
        rows.push(`
            <div class="detail-row">
                <span class="detail-row-label">Notes</span>
                <span class="detail-row-value">${escapeHtml(o.reviewer_notes)}</span>
            </div>`);
    }
    return rows.join("");
}

/**
 * Show the reviewer notes in the detail overview too — the assessment
 * belongs next to the unit's own story, not only inside the tab.
 */
function injectReviewerNotes(record) {
    const content = document.getElementById("detail-content");
    if (!content || !record || !record.reviewer_notes) return;
    if (document.getElementById("reviewer-notes-section")) return;
    const section = document.createElement("div");
    section.className = "detail-section";
    section.id = "reviewer-notes-section";
    section.innerHTML = `
        <div class="detail-section-title">Reviewer Notes</div>
        <div class="reviewer-notes-text">${escapeHtml(record.reviewer_notes)}</div>
    `;
    const first = content.querySelector(".detail-section");
    if (first) first.insertAdjacentElement("afterend", section);
    else content.prepend(section);
}

// ─── Mutations ──────────────────────────────────────────────────────────

/** Read the form into an override record and apply it wholesale. */
async function applyOverrideFromForm(unitId) {
    const hints = (document.getElementById("override-hints")?.value || "")
        .split("\n")
        .map((h) => h.trim())
        .filter((h) => h.length > 0);
    const record = {
        tier_override: document.getElementById("override-tier")?.value || null,
        retry_strategy_override: document.getElementById("override-strategy")?.value || null,
        custom_hints: hints,
        skip: !!document.getElementById("override-skip")?.checked,
        reviewer_notes: (document.getElementById("override-notes")?.value || "").trim(),
    };
    setOverrideBusy(true);
    try {
        const res = await API.applyUnitOverride(unitId, record);
        renderOverridePanel(unitId, res.override || null);
        injectReviewerNotes(res.override || null);
        showToast(res.override ? "Override applied" : "Override cleared — the record was empty", "success");
    } catch (err) {
        showToast(`Override failed: ${err.message}`, "error");
    } finally {
        setOverrideBusy(false);
    }
}

async function removeOverride(unitId) {
    setOverrideBusy(true);
    try {
        const res = await API.removeUnitOverride(unitId);
        renderOverridePanel(unitId, res.override || null);
        const notes = document.getElementById("reviewer-notes-section");
        if (notes) notes.remove();
        showToast("Override removed — the unit falls back to automatic behavior", "success");
    } catch (err) {
        showToast(`Remove override failed: ${err.message}`, "error");
    } finally {
        setOverrideBusy(false);
    }
}

function setOverrideBusy(busy) {
    const panel = document.getElementById("overrides-body");
    if (!panel) return;
    for (const el of panel.querySelectorAll("input, select, textarea, button")) {
        if (el.id === "override-remove" && !busy) continue; // its disabled state follows the record
        el.disabled = busy;
    }
}

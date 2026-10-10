/* ==========================================================================
   LLM I/O log view — server-backed log browser (issue #80)

   History comes from GET /api/llm-io (the persisted server-side log), so
   the view survives a page reload; live WebSocket entries append on top.
   Filter selects (binary, function, attempt, strategy) and full-text
   search narrow the list, entries collapse to their metadata line, and
   each entry can be copied with one click.
   ========================================================================== */

import { API } from "./api.js";
import { escapeHtml } from "./utils.js";
import { showToast } from "./ui.js";

// What the browser currently shows: server history first, live entries on
// top. The server log is the source of truth — this buffer is disposable.
const llmLogEntries = [];
// Dedup keys for everything in the buffer: a live WS entry is also written
// to the server log, so the next history load must not show it twice. The
// key ignores the timestamp — a live entry and its server-side twin are
// stamped at slightly different moments — so two byte-identical calls
// (same type, unit, attempt, strategy, and content) read as one entry.
const seenKeys = new Set();

// Client-side window, matching the server's retention (MAX_LLM_IO_ENTRIES)
// so the view never holds more than a reload can bring back.
const LLM_LOG_MAX = 500;

let nextEntryId = 1;

// Active filters — "" means "all" for the selects, "" search matches everything.
const llmLogFilters = {
    binary: "",
    function: "",
    attempt: "",
    strategy: "",
    search: "",
};

const FILTER_FIELDS = ["binary", "function", "attempt", "strategy"];

function entryKey(e) {
    return `${e.type}|${e.binary}|${e.function}|${e.attempt}|${e.strategy}|${e.content}`;
}

/* One normalized entry, shared by the history load and the live WS path
   so both build the same shape. */
function makeEntry(type, binary, func, attempt, strategy, content, tokensUsed, timestamp) {
    return {
        type,
        binary,
        function: func,
        attempt,
        strategy,
        content,
        tokensUsed: tokensUsed ?? null,
        timestamp,
        expanded: false,
    };
}

function pushEntry(entry) {
    const key = entryKey(entry);
    if (seenKeys.has(key)) return false;
    seenKeys.add(key);
    entry.id = nextEntryId++;
    llmLogEntries.push(entry);

    // Trim old entries past the window, forgetting their dedup keys so a
    // later history load can still bring them back if the server kept them.
    while (llmLogEntries.length > LLM_LOG_MAX) {
        const dropped = llmLogEntries.shift();
        seenKeys.delete(entryKey(dropped));
    }
    return true;
}

// ─── Data ─────────────────────────────────────────────────────────────────

/* Load the persisted log from the server (oldest first). Entries already
   in the buffer — live WS entries — are skipped by dedup key, so this is
   safe to call on startup, on every view entry, and after reconnects. */
export async function loadLlmLogHistory() {
    const data = await API.llmIoLog();
    let added = 0;
    for (const e of data.entries) {
        if (pushEntry(makeEntry(
            e.type,
            e.binary,
            e.function,
            e.attempt,
            e.strategy,
            e.content,
            e.tokens_used,
            new Date(e.timestamp * 1000),
        ))) added++;
    }
    refreshFilterOptions();
    renderLlmLog();
    return added;
}

/* A live entry pushed over the WebSocket, appended on top of history. */
export function addLlmLogEntry(type, binary, func, attempt, strategy, content, tokensUsed) {
    pushEntry(makeEntry(type, binary, func, attempt, strategy, content, tokensUsed, new Date()));
    refreshFilterOptions();
    renderLlmLog();
}

/* Clears the view buffer only — the server-side log is append-only and
   keeps its entries; re-entering the view (or reloading) brings them back. */
export function clearLlmLog() {
    llmLogEntries.length = 0;
    seenKeys.clear();
    refreshFilterOptions();
    renderLlmLog();
}

// ─── Filtering ────────────────────────────────────────────────────────────

function visibleEntries() {
    const f = llmLogFilters;
    const needle = f.search.trim().toLowerCase();
    return llmLogEntries.filter((e) =>
        (!f.binary || e.binary === f.binary) &&
        (!f.function || e.function === f.function) &&
        (!f.attempt || String(e.attempt) === f.attempt) &&
        (!f.strategy || e.strategy === f.strategy) &&
        (!needle || e.content.toLowerCase().includes(needle))
    );
}

/* Rebuild the filter selects from the values actually present in the log.
   A selection whose value has left the buffer (trim, clear) resets both
   the select and the filter state, so the UI never claims "All" while a
   stale filter still hides entries. */
function refreshFilterOptions() {
    for (const field of FILTER_FIELDS) {
        const select = document.getElementById(`llm-log-filter-${field}`);
        if (!select) continue;
        const values = [...new Set(llmLogEntries.map((e) => String(e[field])))];
        values.sort((a, b) =>
            field === "attempt" ? Number(a) - Number(b) : a.localeCompare(b)
        );
        const current = select.value;
        select.innerHTML = `<option value="">All</option>` +
            values.map((v) => `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`).join("");
        if (values.includes(current)) {
            select.value = current;
        } else {
            select.value = "";
            llmLogFilters[field] = "";
        }
    }
}

// ─── Rendering ────────────────────────────────────────────────────────────

/* Redraw the visible entries: collapsed by default, header carrying the
   type, unit summary, token count, and copy button. */
export function renderLlmLog() {
    const container = document.getElementById("llm-log-entries");
    const empty = document.getElementById("llm-log-empty");
    if (!container) return;

    const visible = visibleEntries();
    const summaryEl = document.getElementById("llm-log-filter-summary");
    if (summaryEl) {
        summaryEl.textContent = llmLogEntries.length
            ? `${visible.length} of ${llmLogEntries.length} entries`
            : "";
    }

    if (visible.length === 0) {
        container.innerHTML = "";
        if (empty) {
            const p = empty.querySelector("p");
            if (p) {
                p.textContent = llmLogEntries.length === 0
                    ? "No LLM events yet. Start a live translation to see prompts and responses."
                    : "No entries match the current filters.";
            }
            empty.style.display = "flex";
        }
        return;
    }
    if (empty) empty.style.display = "none";

    container.innerHTML = visible.map((e) => {
        const typeLabel = e.type === "request" ? "Request" : e.type === "error" ? "⚠ Error" : "Response";
        const ts = e.timestamp.toLocaleTimeString();
        const unit = `${e.binary}!${e.function} (attempt #${e.attempt}, ${e.strategy})`;
        // Honest token display: unmeasured entries show "—", never a fake 0.
        const tokens = e.tokensUsed != null ? `${e.tokensUsed} tokens` : "— tokens";
        const safe = escapeHtml(e.content);
        const copyLabel = e.type === "request" ? "prompt" : e.type === "error" ? "error" : "response";

        return `<div class="llm-log-entry${e.expanded ? " expanded" : ""}" data-entry-id="${e.id}">
            <div class="llm-log-entry-header ${e.type}" title="Click to ${e.expanded ? "collapse" : "expand"}">
                <span class="llm-log-chevron">${e.expanded ? "▾" : "▸"}</span>
                ${typeLabel}
                <span class="meta">${ts} · ${escapeHtml(unit)} · ${tokens} · ${e.content.length} chars</span>
                <button class="llm-log-copy" title="Copy ${copyLabel}">Copy</button>
            </div>
            <div class="llm-log-entry-body"><pre>${safe}</pre></div>
        </div>`;
    }).join("");
}

// ─── Interaction ──────────────────────────────────────────────────────────

function findEntry(el) {
    if (!el) return null;
    const id = Number(el.dataset.entryId);
    return llmLogEntries.find((e) => e.id === id) || null;
}

/* One-click copy of an entry's prompt/response. The Clipboard API can be
   unavailable (insecure origin, denied permission, headless Chrome), so
   fall back to a hidden textarea + execCommand before admitting failure. */
async function copyEntryContent(entry, btn) {
    let ok = false;
    try {
        await navigator.clipboard.writeText(entry.content);
        ok = true;
    } catch {
        const ta = document.createElement("textarea");
        ta.value = entry.content;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try { ok = document.execCommand("copy"); } catch { ok = false; }
        ta.remove();
    }
    if (ok) {
        btn.textContent = "Copied";
        setTimeout(() => { btn.textContent = "Copy"; }, 1500);
    } else {
        showToast("Copy failed — clipboard unavailable", "error");
    }
}

/* Wires the filter selects, the search box, and click delegation for
   collapse/expand + copy inside the entries container. Delegation means
   re-renders never need re-wiring. */
export function setupLlmLogControls() {
    const container = document.getElementById("llm-log-entries");
    if (container) {
        container.addEventListener("click", (e) => {
            const copyBtn = e.target.closest(".llm-log-copy");
            if (copyBtn) {
                const entry = findEntry(copyBtn.closest(".llm-log-entry"));
                if (entry) copyEntryContent(entry, copyBtn);
                return;
            }
            const header = e.target.closest(".llm-log-entry-header");
            if (header) {
                const entry = findEntry(header.closest(".llm-log-entry"));
                if (entry) {
                    entry.expanded = !entry.expanded;
                    renderLlmLog();
                }
            }
        });
    }

    for (const field of FILTER_FIELDS) {
        const select = document.getElementById(`llm-log-filter-${field}`);
        if (select) {
            select.addEventListener("change", () => {
                llmLogFilters[field] = select.value;
                renderLlmLog();
            });
        }
    }

    const search = document.getElementById("llm-log-search");
    if (search) {
        search.addEventListener("input", () => {
            llmLogFilters.search = search.value;
            renderLlmLog();
        });
    }
}

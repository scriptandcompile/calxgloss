/* ==========================================================================
   LLM I/O log view — rolling buffer of prompts and responses
   ========================================================================== */

const llmLogEntries = [];
const LLM_LOG_MAX = 200;

export function addLlmLogEntry(type, dll, func, attempt, strategy, content) {
    const entry = {
        type,  // "request" or "response"
        dll,
        func,
        attempt,
        strategy,
        content,
        timestamp: new Date(),
    };
    llmLogEntries.push(entry);

    // Trim old entries
    while (llmLogEntries.length > LLM_LOG_MAX) {
        llmLogEntries.shift();
    }

    renderLlmLog();
}

export function renderLlmLog() {
    const container = document.getElementById("llm-log-entries");
    const empty = document.getElementById("llm-log-empty");
    if (!container) return;

    if (llmLogEntries.length === 0) {
        empty.style.display = "flex";
        container.innerHTML = "";
        return;
    }

    empty.style.display = "none";

    const html = llmLogEntries.map((e) => {
        const typeLabel = e.type === "request" ? "Request" : e.type === "error" ? "⚠ Error" : "Response";
        const ts = e.timestamp.toLocaleTimeString();
        const summary = `${e.dll}!${e.func} (attempt #${e.attempt}, ${e.strategy})`;
        // Only escape < and > so JSON/Code stays readable in <pre>
        const safe = e.content
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");

        return `<div class="llm-log-entry">
            <div class="llm-log-entry-header ${e.type}">
                ${typeLabel}
                <span class="meta">${ts} · ${summary} (${e.content.length} chars)</span>
            </div>
            <div class="llm-log-entry-body"><pre>${safe}</pre></div>
        </div>`;
    }).join("");

    container.innerHTML = html;
}

export function clearLlmLog() {
    llmLogEntries.length = 0;
    renderLlmLog();
}

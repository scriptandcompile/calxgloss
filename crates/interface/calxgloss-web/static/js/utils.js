/* ==========================================================================
   Shared formatting helpers
   ========================================================================== */

export function fmtTime(isoStr) {
    try {
        const d = new Date(isoStr);
        const now = new Date();
        const diff = (now - d) / 1000;

        if (diff < 60) return "just now";
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    } catch {
        return isoStr;
    }
}

export function fmtConfidence(val) {
    if (val == null) return { text: "N/A", pct: 0, cls: "" };
    const pct = Math.round(val * 100);
    let cls = "high";
    if (val < 0.5) cls = "low";
    else if (val < 0.8) cls = "medium";
    return { text: `${pct}%`, pct, cls };
}

export function escapeHtml(str) {
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

export function fmtUptime(secs) {
    if (secs == null) return "—";
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
    return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

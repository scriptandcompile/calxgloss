/* ==========================================================================
   Shareable graph URLs (issue #79) — encode the current graph view (kind /
   status / binary filters plus the zoom/pan camera) in the page URL, so
   reopening the URL restores the same view. Purely client-side: the server
   serves the same page, the query string carries the view state.
   ========================================================================== */

import { State } from "./state.js";

// Build the share URL for the renderer's current camera and the active
// filters. Filters at "all" are omitted (they're the default); the camera
// is always included so the viewport lands exactly where the sharer left it.
export function buildGraphShareUrl(renderer) {
    const params = new URLSearchParams();
    params.set("view", "graph");

    const f = State.graphFilters || {};
    if (f.kind && f.kind !== "all") params.set("gk", f.kind);
    if (f.status && f.status !== "all") params.set("gs", f.status);
    if (f.binary && f.binary !== "all") params.set("gb", f.binary);

    if (renderer) {
        params.set("gz", String(Math.round(renderer.scale * 1000) / 1000));
        params.set("gx", String(Math.round(renderer.offsetX)));
        params.set("gy", String(Math.round(renderer.offsetY)));
    }

    return `${location.origin}${location.pathname}?${params.toString()}`;
}

// Parse the current page's query string for shared graph state. Returns
// null unless the URL names the graph view; filters default to "all" and
// the camera to null (fit-to-view) when absent or malformed.
export function readGraphShareState() {
    const params = new URLSearchParams(location.search);
    if (params.get("view") !== "graph") return null;

    const filters = {
        kind: params.get("gk") || "all",
        status: params.get("gs") || "all",
        binary: params.get("gb") || "all",
    };

    let camera = null;
    const scale = parseFloat(params.get("gz"));
    if (Number.isFinite(scale)) {
        camera = {
            scale,
            offsetX: parseFloat(params.get("gx")) || 0,
            offsetY: parseFloat(params.get("gy")) || 0,
        };
    }

    return { filters, camera };
}

// Seed State.graphFilters and the filter selects from a shared URL, before
// the first data load so the initial render is already filtered. Values the
// selects don't offer (a hand-tampered URL) fall back to "all" rather than
// restoring a filter that can never match. The binary select's options are
// rebuilt after data loads (populateGraphBinaryFilter), which preserves the
// shared selection when the binary still exists.
export function applyGraphShareFilters(filters) {
    const validated = { ...filters };
    for (const [id, key] of [
        ["graph-filter-kind", "kind"],
        ["graph-filter-status", "status"],
    ]) {
        const el = document.getElementById(id);
        if (!el) continue;
        if ([...el.options].some(o => o.value === filters[key])) {
            el.value = filters[key];
        } else {
            validated[key] = "all";
        }
    }
    State.graphFilters = { ...State.graphFilters, ...validated };
}

/* ==========================================================================
   Shared application state — the single mutable store every view reads
   ========================================================================== */

export const State = {
    dashboard: null,
    currentView: "dashboard",
    selectedUnitId: null,
    units: [],
    graphRendererFull: null,
    wsManager: null,
    statusFilter: "all",
    gcCandidates: [],
    gcSelectedBranches: new Set(),
    queueEffort: {},
    queueOrder: [],
    queueOverlay: { order: [], priorities: {} },
    queueSelected: new Set(),
    graphFilters: { kind: "all", status: "all", binary: "all" },
};

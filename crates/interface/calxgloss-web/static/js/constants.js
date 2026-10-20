/* ==========================================================================
   Shared display constants — status/kind colors and labels
   ========================================================================== */

export const STATUS_COLORS = {
    queued: "#6c8cff",
    pending_review: "#facc15",
    in_progress: "#22d3ee",
    accepted: "#4ade80",
    sendback: "#f87171",
    send_back: "#f87171",
    patch_requested: "#fb923c",
    blocked: "#fb923c",
    skipped: "#9ca3af",
    // Parked (.NET managed, issue #235) — dimmer than skipped: a system
    // fact, not reviewer intent. The graph view looks statuses up by their
    // snake_case key; the queue view by the raw serde variant name.
    do_not_translate: "#6b7280",
    DoNotTranslate: "#6b7280",
};

export const STATUS_LABELS = {
    queued: "Queued",
    pending_review: "Pending Review",
    in_progress: "⟳ In Progress",
    accepted: "Accepted",
    sendback: "Send Back",
    send_back: "Send Back",
    patch_requested: "Patch Requested",
    blocked: "Blocked",
    skipped: "⊘ Skipped",
    // The graph view looks statuses up by their snake_case key; the queue
    // view by the raw serde variant name (issue #235).
    do_not_translate: "⊗ Do Not Translate",
    DoNotTranslate: "⊗ Do Not Translate",
};

export const KIND_LABELS = {
    dll_classification: "Classify",
    shim_layer: "Shim",
    function_translation: "Function",
    test_case_addition: "Test Case",
    pal_trait: "PAL Trait",
    integration_step: "Integration",
    bug_fix: "Bug Fix",
};

export const KIND_COLORS = {
    dll_classification: "#a78bfa",
    shim_layer: "#22d3ee",
    function_translation: "#6c8cff",
    test_case_addition: "#4ade80",
    pal_trait: "#facc15",
    integration_step: "#fb923c",
    bug_fix: "#f87171",
};

// DllCategory display labels (issue #66) — keys match the serde variant
// names the API sends in `binary_categories`. This map is the one place
// those wire names live: panels derive the names from it (see
// categoryKey) instead of spelling them again (issue #109).
export const CATEGORY_LABELS = {
    WindowsOs: "Windows OS",
    MicrosoftSdk: "Microsoft SDK",
    KnownThirdParty: "Known 3rd Party",
    ProjectSpecific: "Project Specific",
    UnknownThirdParty: "Unknown 3rd Party",
    RuntimeLibrary: "Runtime Library",
    DotNetManaged: ".NET Managed",
};

/**
 * The DllCategory serde variant name behind a display label — the wire
 * names live only in CATEGORY_LABELS, so a backend rename touches that
 * map alone. Returns null when no category carries the label, so a rename
 * on either side surfaces as a loudly missing control rather than a
 * control that silently matches nothing (issue #109).
 */
export function categoryKey(label) {
    return Object.keys(CATEGORY_LABELS).find((k) => CATEGORY_LABELS[k] === label) ?? null;
}

// ContextTier display labels — keys are the backend ContextTier serde
// variant names (crates/shared/calxgloss-types/src/context_tier.rs). The
// scope panel populates its tier select's values from the scope status
// response's `context_tiers`, so this map only prettifies the ones whose
// human label differs from the raw name — an unmapped tier renders under
// its raw name rather than vanishing (issue #109).
export const CONTEXT_TIER_LABELS = {
    WithTests: "With Tests",
    ModuleContext: "Module Context",
    FullModule: "Full Module",
};

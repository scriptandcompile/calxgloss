/* ==========================================================================
   Shared display constants — status/kind colors and labels
   ========================================================================== */

export const STATUS_COLORS = {
    queued: "#6c8cff",
    pending_review: "#facc15",
    in_progress: "#22d3ee",
    accepted: "#4ade80",
    sendback: "#f87171",
    blocked: "#fb923c",
    skipped: "#9ca3af",
};

export const STATUS_LABELS = {
    queued: "Queued",
    pending_review: "Pending Review",
    in_progress: "⟳ In Progress",
    accepted: "Accepted",
    sendback: "Send Back",
    blocked: "Blocked",
    skipped: "⊘ Skipped",
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
// names the API sends in `binary_categories`.
export const CATEGORY_LABELS = {
    WindowsOs: "Windows OS",
    MicrosoftSdk: "Microsoft SDK",
    KnownThirdParty: "Known 3rd Party",
    ProjectSpecific: "Project Specific",
    UnknownThirdParty: "Unknown 3rd Party",
    RuntimeLibrary: "Runtime Library",
};

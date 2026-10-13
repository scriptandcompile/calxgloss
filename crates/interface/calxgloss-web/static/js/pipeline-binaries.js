/* ==========================================================================
   Pipeline binary list — the one way panels load the run's discovered
   binaries (issue #109)

   /api/pipeline answers the full run status; every panel that only needs
   the binary list — the restart dialog's target dropdown, the scope panel's
   category view — reads it through here, so the fetch and the shape live
   in one place. The dashboard's pipeline panel needs the whole status
   (phases, counts, rows), so it keeps calling API.pipeline() directly.
   ========================================================================== */

import { API } from "./api.js";

/**
 * The pipeline's discovered binaries — entries with no binary name
 * dropped. Throws when the endpoint is unavailable (a plain `serve` has
 * no pipeline); each caller decides its own honest empty state.
 */
export async function loadPipelineBinaries() {
    const res = await API.pipeline();
    return (res.binaries || []).filter((b) => b.binary);
}

/* ==========================================================================
   Pipeline controls header — live run state + lifecycle buttons (issue #94)

   The fixed bar at the top of the dashboard: the state badge mirrors the
   pipeline's own state machine, updated over the WebSocket the moment
   anything changes — including changes made in another browser tab. The
   buttons drive the live-only lifecycle endpoints over REST.

   Buttons are gated by the same transition table the server enforces, so
   the header rarely offers an operation the machine would refuse; when a
   stale click still lands (another tab moved the state first), the server's
   own 409/503 reason surfaces as an error toast — never a silent no-op,
   never a corrupted local guess.

   Restart opens an options dialog (phase / target / scope selectors plus a
   safety explanation); Shut Down Server opens a confirmation that lists
   exactly what it does before driving the existing shutdown endpoint.
   ========================================================================== */

import { API } from "./api.js";
import { showToast } from "./ui.js";

const STATE_LABELS = {
    unavailable: "No pipeline",
    idle: "Idle",
    running: "Running",
    paused: "Paused",
    stopping: "Stopping",
    complete: "Complete",
    error: "Error",
};

// Which operations each state allows — the server's PipelineControl
// transition table restated: idle→start, running→pause/stop/cancel,
// paused→resume/stop, complete|error→restart. Stopping offers nothing; the
// run is already halting. Shut Down Server is always available — the
// server itself is always there.
const ALLOWED_OPS = {
    unavailable: [],
    idle: ["start"],
    running: ["pause", "stop", "cancel"],
    paused: ["resume", "stop"],
    stopping: [],
    complete: ["restart"],
    error: ["restart"],
};

const CONTROL_BUTTON_IDS = {
    start: "ctl-start",
    pause: "ctl-pause",
    resume: "ctl-resume",
    stop: "ctl-stop",
    cancel: "ctl-cancel",
    restart: "ctl-restart",
};

// The state the header currently believes the run is in. Every writer —
// the server-status snapshot, a WS pipeline_state_changed event, a control
// response — funnels through setPipelineState, so the badge and the
// buttons never disagree with each other.
let pipelineState = "unavailable";

/**
 * Point the header at a state — from the server-status snapshot, a WS
 * pipeline_state_changed event, or a control response. Unknown state
 * strings render honestly as-is rather than being guessed at.
 * @param {string} state - one of unavailable/idle/running/paused/stopping/complete/error
 */
export function setPipelineState(state) {
    pipelineState = state;
    const badge = document.getElementById("pipeline-state");
    if (badge) {
        badge.dataset.state = state;
        badge.textContent = STATE_LABELS[state] || state;
    }
    const allowed = ALLOWED_OPS[state] || [];
    for (const [op, id] of Object.entries(CONTROL_BUTTON_IDS)) {
        const btn = document.getElementById(id);
        if (btn && !btn.dataset.busy) btn.disabled = !allowed.includes(op);
    }
}

/** Wire the header's buttons to the lifecycle endpoints (once, at startup). */
export function setupPipelineControls() {
    const bind = (id, handler) => {
        const btn = document.getElementById(id);
        if (btn) btn.addEventListener("click", handler);
    };
    bind("ctl-start", () => runControl("start", () => API.startPipeline()));
    bind("ctl-pause", () => runControl("pause", () => API.pausePipeline()));
    bind("ctl-resume", () => runControl("resume", () => API.resumePipeline()));
    bind("ctl-stop", () => runControl("stop", () => API.stopPipeline()));
    bind("ctl-cancel", () => runControl("cancel", () => API.cancelCurrentUnit()));
    bind("ctl-restart", () => showRestartDialog());
    bind("ctl-shutdown", () => showShutdownDialog());
}

/**
 * Drive one lifecycle endpoint: busy-lock the buttons for the request's
 * duration, adopt the state the server reports on success, and surface the
 * server's own reason on rejection. Shared by the header buttons and the
 * pipeline rows' quick actions.
 * @param {string} op - the operation name, for the failure toast
 * @param {Function} call - the API call returning {message, state?}
 */
export async function runControl(op, call) {
    setControlsBusy(true);
    try {
        const res = await call();
        showToast(res.message, "success");
        if (res.state) setPipelineState(res.state);
    } catch (err) {
        // A stale button issuing an operation the machine forbids (or a
        // router with no control attached) — the server's clear error,
        // never a silent local state change.
        showToast(`${op} failed: ${err.message}`, "error");
    } finally {
        setControlsBusy(false);
        // Re-apply the gating for the state we now believe is true.
        setPipelineState(pipelineState);
    }
}

function setControlsBusy(busy) {
    for (const id of Object.values(CONTROL_BUTTON_IDS)) {
        const btn = document.getElementById(id);
        if (!btn) continue;
        if (busy) {
            btn.dataset.busy = "1";
            btn.disabled = true;
        } else {
            delete btn.dataset.busy;
        }
    }
    const shutdown = document.getElementById("ctl-shutdown");
    if (shutdown) shutdown.disabled = busy;
}

/**
 * Restart options dialog: phase / target / scope selectors plus a safety
 * explanation, driving POST /api/pipeline/restart. `target` pre-selects a
 * binary — the pipeline rows' Configure action opens it that way.
 * @param {{ target?: string }} [options] - pre-selected target binary identity
 */
export async function showRestartDialog({ target = "all" } = {}) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.id = "restart-dialog";
    overlay.innerHTML = `
        <div class="modal">
            <h3>Restart pipeline</h3>
            <div class="dialog-fields">
                <label for="restart-phase">Phase
                    <select id="restart-phase">
                        <option value="translate">Translate — honor existing classifications</option>
                        <option value="classify">Classify first — re-classify the targets</option>
                    </select>
                </label>
                <label for="restart-target">Target
                    <select id="restart-target"><option value="all">All binaries</option></select>
                </label>
                <label for="restart-scope">Scope
                    <select id="restart-scope">
                        <option value="all_functions">All functions</option>
                        <option value="only_queued">Only queued functions — never attempted</option>
                        <option value="only_failed">Only failed functions — attempted, never translated</option>
                    </select>
                </label>
            </div>
            <p class="dialog-safety">
                Restart re-runs the pipeline inside this live process. Only a finished
                or failed run can restart — nothing in flight is discarded, and every
                attempt stays recorded in the workspace. The run honors the selectors
                above from its very first unit.
            </p>
            <div class="modal-actions">
                <button class="btn btn-secondary" id="restart-cancel">Cancel</button>
                <button class="btn btn-primary" id="restart-confirm">Restart</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    // Target options come from the pipeline's own binary list; if that
    // fetch fails the dialog honestly offers only "All binaries".
    const targetSelect = overlay.querySelector("#restart-target");
    try {
        const res = await API.pipeline();
        for (const b of res.binaries || []) {
            if (!b.binary) continue;
            const opt = document.createElement("option");
            opt.value = b.binary;
            opt.textContent = b.binary;
            targetSelect.appendChild(opt);
        }
    } catch {
        // Non-critical — "All binaries" remains, and the server's default
        // restart covers everything anyway.
    }
    if ([...targetSelect.options].some((o) => o.value === target)) {
        targetSelect.value = target;
    }

    const close = () => overlay.remove();
    overlay.querySelector("#restart-cancel").addEventListener("click", close);
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) close();
    });

    overlay.querySelector("#restart-confirm").addEventListener("click", async () => {
        const body = {
            phase: overlay.querySelector("#restart-phase").value,
            target: targetSelect.value === "all" ? "all" : { binary: targetSelect.value },
            scope: overlay.querySelector("#restart-scope").value,
        };
        close();
        await runControl("restart", () => API.restartPipeline(body));
    });
}

/**
 * Shut Down Server confirmation: lists exactly what the shutdown does —
 * honest to the mode, since plain `serve` has no pipeline to pause — then
 * drives the existing POST /api/server/shutdown endpoint.
 */
export function showShutdownDialog() {
    const live = pipelineState !== "unavailable";
    const actions = live
        ? [
              "Pause the live pipeline at the current unit boundary",
              "Complete any function in flight and save its state",
              "Stop the server — the process exits",
          ]
        : ["Stop the server — the process exits"];

    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.id = "shutdown-dialog";
    overlay.innerHTML = `
        <div class="modal">
            <h3>Shut down server</h3>
            <p class="dialog-safety">This will:</p>
            <ul class="dialog-list">
                ${actions.map((a) => `<li>${a}</li>`).join("")}
            </ul>
            <div class="modal-actions">
                <button class="btn btn-secondary" id="shutdown-cancel">Cancel</button>
                <button class="btn btn-danger" id="shutdown-confirm">Shut down</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    const close = () => overlay.remove();
    overlay.querySelector("#shutdown-cancel").addEventListener("click", close);
    overlay.addEventListener("click", (e) => {
        if (e.target === overlay) close();
    });

    overlay.querySelector("#shutdown-confirm").addEventListener("click", async () => {
        close();
        try {
            const res = await API.shutdownServer();
            showToast(res.message, "info", 8000);
            // The server is going down — nothing left to drive.
            setControlsBusy(true);
        } catch (err) {
            showToast(`Shutdown failed: ${err.message}`, "error");
        }
    });
}

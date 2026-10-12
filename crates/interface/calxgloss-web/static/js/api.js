/* ==========================================================================
   API client — shared fetch helpers for every view
   ========================================================================== */

export const API = {
    async get(path) {
        const res = await fetch(path);
        if (!res.ok) {
            // The server's own reason surfaces when it sends one — an
            // honest 503 explanation beats a bare status line.
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || `API ${res.status}`);
        }
        return res.json();
    },

    async post(path, body) {
        const res = await fetch(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: body ? JSON.stringify(body) : undefined,
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || `API ${res.status}`);
        }
        return res.json();
    },

    async patch(path, body) {
        const res = await fetch(path, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: body ? JSON.stringify(body) : undefined,
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || `API ${res.status}`);
        }
        return res.json();
    },

    async put(path, body) {
        const res = await fetch(path, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: body ? JSON.stringify(body) : undefined,
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || `API ${res.status}`);
        }
        return res.json();
    },

    async delete(path) {
        const res = await fetch(path, { method: "DELETE" });
        if (!res.ok) {
            const err = await res.json().catch(() => ({ message: res.statusText }));
            throw new Error(err.message || `API ${res.status}`);
        }
        return res.json();
    },

    async dashboard() { return API.get("/api/dashboard"); },
    async unit(id) { return API.get(`/api/units/${encodeURIComponent(id)}`); },
    async unitDiff(id) { return API.get(`/api/units/${encodeURIComponent(id)}/diff`); },
    async unitGhidra(id) { return API.get(`/api/units/${encodeURIComponent(id)}/ghidra`); },
    async acceptUnit(id) { return API.post(`/api/units/${encodeURIComponent(id)}/accept`); },
    async sendBackUnit(id, reason) { return API.post(`/api/units/${encodeURIComponent(id)}/send-back`, { reason }); },
    async patchUnit(id, issue) { return API.post(`/api/units/${encodeURIComponent(id)}/patch`, { issue }); },
    async skipUnit(id) { return API.post(`/api/units/${encodeURIComponent(id)}/skip`); },
    async unskipUnit(id) { return API.post(`/api/units/${encodeURIComponent(id)}/unskip`); },
    async batchAccept(ids) { return API.post("/api/batch/accept", { unit_ids: ids }); },
    async batchSendBack(ids, reason) { return API.post("/api/batch/send-back", { unit_ids: ids, reason }); },
    async batchSkip(ids) { return API.post("/api/batch/skip", { unit_ids: ids }); },
    async queue() { return API.get("/api/queue"); },
    async nextUnit() { return API.get("/api/queue/next"); },
    async graph() { return API.get("/api/graph"); },
    async llmIoLog() { return API.get("/api/llm-io"); },
    async clearLlmIoLog() { return API.post("/api/llm-io/clear"); },
    async health() { return API.get("/health"); },
    async serverStatus() { return API.get("/api/server/status"); },
    async shutdownServer() { return API.post("/api/server/shutdown"); },
    async restartServer() { return API.post("/api/server/restart"); },
    async setLogLevel(level) { return API.patch("/api/server/log-level", { level }); },
    async pipeline() { return API.get("/api/pipeline"); },
    // Pipeline lifecycle control (issue #90/#91/#92, driven by the controls
    // header in issue #94) — live router only; plain serve answers 503/404.
    async startPipeline() { return API.post("/api/pipeline/start"); },
    async pausePipeline() { return API.post("/api/pipeline/pause"); },
    async resumePipeline() { return API.post("/api/pipeline/resume"); },
    async stopPipeline() { return API.post("/api/pipeline/stop"); },
    async restartPipeline(options) { return API.post("/api/pipeline/restart", options); },
    async cancelCurrentUnit() { return API.post("/api/pipeline/cancel-current"); },
    // Translation scope controls (issue #93, driven by the panel in issue
    // #95) — live router only; plain serve has no pipeline to steer.
    async scopeStatus() { return API.get("/api/scope"); },
    async setScopeBinaries(binaries) { return API.post("/api/scope/binaries", { binaries }); },
    async prioritizeScopeFunction(binary, fn) { return API.post("/api/scope/priority-function", { binary, function: fn }); },
    async removeScopePriorityFunction(binary, fn) { return API.post("/api/scope/remove-priority-function", { binary, function: fn }); },
    async setScopeConstraints(constraints) { return API.post("/api/scope/constraints", constraints); },
    // Per-unit reviewer overrides (issue #96) — live router only; plain
    // serve has no pipeline to steer.
    async unitOverride(id) { return API.get(`/api/units/${encodeURIComponent(id)}/override`); },
    async applyUnitOverride(id, record) { return API.post(`/api/units/${encodeURIComponent(id)}/override`, { override: record }); },
    async removeUnitOverride(id) { return API.delete(`/api/units/${encodeURIComponent(id)}/override`); },
    // Binary classification overrides (issue #97) — live router only; plain
    // serve has no run to steer. `null` removes the override.
    async binaryClassification(name) { return API.get(`/api/binaries/${encodeURIComponent(name)}/classification`); },
    async setBinaryClassification(name, record) { return API.post(`/api/binaries/${encodeURIComponent(name)}/classification`, { override: record }); },
    async clearBinaryClassification(name) { return API.post(`/api/binaries/${encodeURIComponent(name)}/classification`, { override: null }); },
    async liveProgress() { return API.get("/api/progress/enhanced"); },
    async gcCandidates(days) { return API.get(`/api/gc/candidates?days=${days}`); },
    async gcArchive(branches) { return API.post("/api/gc/archive", branches.length > 0 ? { branches } : {}); },
};

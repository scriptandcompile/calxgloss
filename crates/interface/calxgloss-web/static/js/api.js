/* ==========================================================================
   API client — shared fetch helpers for every view
   ========================================================================== */

export const API = {
    async get(path) {
        const res = await fetch(path);
        if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
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
    async health() { return API.get("/health"); },
    async serverStatus() { return API.get("/api/server/status"); },
    async shutdownServer() { return API.post("/api/server/shutdown"); },
    async restartServer() { return API.post("/api/server/restart"); },
    async setLogLevel(level) { return API.patch("/api/server/log-level", { level }); },
    async pipeline() { return API.get("/api/pipeline"); },
    async liveProgress() { return API.get("/api/progress/enhanced"); },
    async gcCandidates(days) { return API.get(`/api/gc/candidates?days=${days}`); },
    async gcArchive(branches) { return API.post("/api/gc/archive", branches.length > 0 ? { branches } : {}); },
};

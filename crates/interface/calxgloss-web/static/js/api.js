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

    async dashboard() { return API.get("/api/dashboard"); },
    async unit(id) { return API.get(`/api/units/${encodeURIComponent(id)}`); },
    async unitDiff(id) { return API.get(`/api/units/${encodeURIComponent(id)}/diff`); },
    async unitGhidra(id) { return API.get(`/api/units/${encodeURIComponent(id)}/ghidra`); },
    async acceptUnit(id) { return API.post(`/api/units/${encodeURIComponent(id)}/accept`); },
    async sendBackUnit(id, reason) { return API.post(`/api/units/${encodeURIComponent(id)}/send-back`, { reason }); },
    async patchUnit(id, issue) { return API.post(`/api/units/${encodeURIComponent(id)}/patch`, { issue }); },
    async queue() { return API.get("/api/queue"); },
    async nextUnit() { return API.get("/api/queue/next"); },
    async graph() { return API.get("/api/graph"); },
    async health() { return API.get("/health"); },
    async pipeline() { return API.get("/api/pipeline"); },
    async gcCandidates(days) { return API.get(`/api/gc/candidates?days=${days}`); },
    async gcArchive(branches) { return API.post("/api/gc/archive", branches.length > 0 ? { branches } : {}); },
};

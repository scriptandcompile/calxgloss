/* ==========================================================================
   Calxgloss Web — Application JavaScript
   ========================================================================== */

(() => {
    "use strict";

    // ─── Constants ──────────────────────────────────────────────────────

    const STATUS_COLORS = {
        queued: "#6c8cff",
        pending_review: "#facc15",
        accepted: "#4ade80",
        sendback: "#f87171",
        blocked: "#fb923c",
        merged: "#a78bfa",
    };

    const STATUS_LABELS = {
        queued: "Queued",
        pending_review: "Pending Review",
        accepted: "Accepted",
        sendback: "Send Back",
        blocked: "Blocked",
        merged: "Merged",
    };

    const KIND_LABELS = {
        dll_classification: "Classify",
        shim_layer: "Shim",
        function_translation: "Function",
        test_case_addition: "Test Case",
        pal_trait: "PAL Trait",
        integration_step: "Integration",
        bug_fix: "Bug Fix",
    };

    const KIND_COLORS = {
        dll_classification: "#a78bfa",
        shim_layer: "#22d3ee",
        function_translation: "#6c8cff",
        test_case_addition: "#4ade80",
        pal_trait: "#facc15",
        integration_step: "#fb923c",
        bug_fix: "#f87171",
    };

    // ─── API Client ─────────────────────────────────────────────────────

    const API = {
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
        async acceptUnit(id) { return API.post(`/api/units/${encodeURIComponent(id)}/accept`); },
        async sendBackUnit(id, reason) { return API.post(`/api/units/${encodeURIComponent(id)}/send-back`, { reason }); },
        async patchUnit(id, issue) { return API.post(`/api/units/${encodeURIComponent(id)}/patch`, { issue }); },
        async queue() { return API.get("/api/queue"); },
        async nextUnit() { return API.get("/api/queue/next"); },
        async graph() { return API.get("/api/graph"); },
        async health() { return API.get("/health"); },
    };

    // ─── WebSocket Manager ─────────────────────────────────────────────

    class WSManager {
        constructor(onMessage) {
            this.onMessage = onMessage;
            this.ws = null;
            this.connected = false;
            this.reconnectDelay = 3000;
            this._reconnectTimer = null;
        }

        connect() {
            this._connect();
        }

        _connect() {
            const proto = location.protocol === "https:" ? "wss:" : "ws:";
            const url = `${proto}//${location.host}/api/events/upgrade`;

            try {
                this.ws = new WebSocket(url);
                this.ws.onopen = () => {
                    this.connected = true;
                    document.getElementById("live-indicator").classList.add("active");
                    this.reconnectDelay = 3000;
                };
                this.ws.onmessage = (e) => {
                    try {
                        this.onMessage(JSON.parse(e.data));
                    } catch {
                        /* ignore malformed messages */
                    }
                };
                this.ws.onclose = () => {
                    this.connected = false;
                    this._scheduleReconnect();
                };
                this.ws.onerror = () => {
                    this.ws?.close();
                };
            } catch {
                this._scheduleReconnect();
            }
        }

        _scheduleReconnect() {
            if (this._reconnectTimer) return;
            this._reconnectTimer = setTimeout(() => {
                this._reconnectTimer = null;
                this._connect();
            }, this.reconnectDelay);
        }

        disconnect() {
            if (this._reconnectTimer) {
                clearTimeout(this._reconnectTimer);
                this._reconnectTimer = null;
            }
            this.ws?.close();
            this.connected = false;
        }
    }

    // ─── Toast System ───────────────────────────────────────────────────

    function showToast(message, type = "info", duration = 4000) {
        const container = document.getElementById("toast-container");
        if (!container) return;

        const el = document.createElement("div");
        el.className = `toast ${type}`;
        el.textContent = message;
        container.appendChild(el);

        setTimeout(() => {
            el.classList.add("toast-out");
            setTimeout(() => el.remove(), 250);
        }, duration);
    }

    // ─── Modal System ───────────────────────────────────────────────────

    function showModal(title, submitLabel, onSubmit) {
        const overlay = document.createElement("div");
        overlay.className = "modal-overlay";

        const modal = document.createElement("div");
        modal.className = "modal";
        modal.innerHTML = `
            <h3>${title}</h3>
            <textarea id="modal-input" placeholder="Enter details..."></textarea>
            <div class="modal-actions">
                <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
                <button class="btn btn-primary" id="modal-confirm">${submitLabel}</button>
            </div>
        `;

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        const input = modal.querySelector("#modal-input");
        input.focus();

        const close = () => overlay.remove();

        modal.querySelector("#modal-cancel").addEventListener("click", close);
        overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

        modal.querySelector("#modal-confirm").addEventListener("click", () => {
            const value = input.value.trim();
            close();
            onSubmit(value);
        });

        input.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                modal.querySelector("#modal-confirm").click();
            }
            if (e.key === "Escape") close();
        });
    }

    // ─── Utility ────────────────────────────────────────────────────────

    function fmtTime(isoStr) {
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

    function fmtConfidence(val) {
        if (val == null) return { text: "N/A", pct: 0, cls: "" };
        const pct = Math.round(val * 100);
        let cls = "high";
        if (val < 0.5) cls = "low";
        else if (val < 0.8) cls = "medium";
        return { text: `${pct}%`, pct, cls };
    }

    // ─── SVG Dependency Graph Renderer ──────────────────────────────────

    class GraphRenderer {
        constructor(canvas) {
            this.canvas = canvas;
            this.ctx = canvas.getContext("2d");
            this.nodes = [];
            this.edges = [];
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            this.dragging = false;
            this.dragStart = { x: 0, y: 0 };
            this.hoveredNode = null;
            this._resize();

            this._onWheel = (e) => this._handleWheel(e);
            this._onMouseDown = (e) => this._handleMouseDown(e);
            this._onMouseMove = (e) => this._handleMouseMove(e);
            this._onMouseUp = () => this._handleMouseUp();

            this.canvas.addEventListener("wheel", this._onWheel, { passive: false });
            this.canvas.addEventListener("mousedown", this._onMouseDown);
            document.addEventListener("mousemove", this._onMouseMove);
            document.addEventListener("mouseup", this._onMouseUp);

            window.addEventListener("resize", () => this._resize());
        }

        _resize() {
            const rect = this.canvas.parentElement?.getBoundingClientRect()
                || this.canvas.getBoundingClientRect();
            const dpr = window.devicePixelRatio || 1;
            this.canvas.width = rect.width * dpr;
            this.canvas.height = rect.height * dpr;
            this.canvas.style.width = rect.width + "px";
            this.canvas.style.height = rect.height + "px";
            this.w = rect.width;
            this.h = rect.height;
            this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            this.draw();
        }

        setData(nodes, edges) {
            this.nodes = nodes || [];
            this.edges = edges || [];
            this._layout();
            this.draw();
        }

        _layout() {
            if (this.nodes.length === 0) return;

            // Build adjacency for topological sort
            const nodeMap = new Map();
            this.nodes.forEach((n, i) => { nodeMap.set(n.id, { ...n, idx: i, children: [], parents: [] }); });

            this.edges.forEach((e) => {
                const child = nodeMap.get(e.target);
                const parent = nodeMap.get(e.source);
                if (child && parent) {
                    parent.children.push(child);
                    child.parents.push(parent);
                }
            });

            // Topological layers via BFS from roots
            const roots = this.nodes.filter(n => !nodeMap.get(n.id)?.parents?.length);
            const layers = [];
            const visited = new Set();
            const queue = roots.map(n => ({ node: n, layer: 0 }));

            while (queue.length > 0) {
                const { node, layer } = queue.shift();
                if (visited.has(node.id)) continue;
                visited.add(node.id);
                if (!layers[layer]) layers[layer] = [];
                layers[layer].push(node);

                for (const child of (nodeMap.get(node.id)?.children || [])) {
                    if (!visited.has(child.id)) {
                        queue.push({ node: child, layer: layer + 1 });
                    }
                }
            });

            // Layout nodes in layers
            const layerHeight = 100;
            const nodeW = 160;
            const nodeH = 36;
            const paddingX = 40;
            const paddingY = 40;

            const maxLayerWidth = Math.max(...layers.map(l => l.length), 1);
            const totalWidth = Math.max(this.w, maxLayerWidth * (nodeW + 24) + paddingX * 2);
            const totalHeight = layers.length * (layerHeight + nodeH) + paddingY * 2;

            this.totalWidth = totalWidth;
            this.totalHeight = totalHeight;

            // Center if needed
            if (totalWidth > this.w) {
                this.offsetX = (totalWidth - this.w) / 2;
            }
            if (totalHeight > this.h) {
                this.offsetY = (totalHeight - this.h) / 2;
            }

            layers.forEach((layer, li) => {
                const layerW = layer.length * (nodeW + 24);
                const startX = (totalWidth - layerW) / 2 + 12;
                const y = paddingY + li * (layerHeight + nodeH);

                layer.forEach((node, ni) => {
                    node._x = startX + ni * (nodeW + 24);
                    node._y = y;
                    node._w = nodeW;
                    node._h = nodeH;
                });
            });
        }

        _screenToWorld(sx, sy) {
            return { x: (sx - this.offsetX) / this.scale, y: (sy - this.offsetY) / this.scale };
        }

        _worldToScreen(wx, wy) {
            return { x: wx * this.scale + this.offsetX, y: wy * this.scale + this.offsetY };
        }

        _handleWheel(e) {
            e.preventDefault();
            const rect = this.canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;

            const oldScale = this.scale;
            const delta = e.deltaY > 0 ? 0.9 : 1.1;
            this.scale = Math.min(3, Math.max(0.2, this.scale * delta));

            // Zoom toward cursor
            this.offsetX = mx - (mx - this.offsetX) * (this.scale / oldScale);
            this.offsetY = my - (my - this.offsetY) * (this.scale / oldScale);

            this.draw();
        }

        _handleMouseDown(e) {
            if (e.button !== 0) return;
            this.dragging = true;
            this.dragStart = { x: e.clientX, y: e.clientY };
        }

        _handleMouseMove(e) {
            if (!this.dragging) {
                this._checkHover(e);
                return;
            }
            const dx = e.clientX - this.dragStart.x;
            const dy = e.clientY - this.dragStart.y;
            this.offsetX += dx;
            this.offsetY += dy;
            this.dragStart = { x: e.clientX, y: e.clientY };
            this.draw();
        }

        _handleMouseUp() {
            this.dragging = false;
        }

        _checkHover(e) {
            const rect = this.canvas.getBoundingClientRect();
            const { x, y } = this._screenToWorld(e.clientX - rect.left, e.clientY - rect.top);

            let found = null;
            for (const node of this.nodes) {
                if (x >= node._x && x <= node._x + node._w && y >= node._y && y <= node._y + node._h) {
                    found = node;
                    break;
                }
            }

            if (found !== this.hoveredNode) {
                this.hoveredNode = found;
                this.canvas.style.cursor = found ? "pointer" : "grab";
                this.draw();
            }
        }

        _getNodeCenter(node) {
            return { x: node._x + node._w / 2, y: node._y + node._h / 2 };
        }

        draw() {
            const ctx = this.ctx;
            ctx.clearRect(0, 0, this.w, this.h);

            ctx.save();
            ctx.translate(this.offsetX, this.offsetY);
            ctx.scale(this.scale, this.scale);

            // Draw edges
            for (const edge of this.edges) {
                const src = this.nodes.find(n => n.id === edge.source);
                const tgt = this.nodes.find(n => n.id === edge.target);
                if (!src || !tgt) continue;

                const sc = this._getNodeCenter(src);
                const tc = this._getNodeCenter(tgt);

                ctx.beginPath();
                ctx.strokeStyle = "rgba(108, 140, 255, 0.25)";
                ctx.lineWidth = 1.5;
                ctx.moveTo(sc.x, sc.y);
                ctx.lineTo(tc.x, tc.y);
                ctx.stroke();

                // Arrow
                const angle = Math.atan2(tc.y - sc.y, tc.x - sc.x);
                const arrowLen = 8;
                const ax = tc.x - Math.cos(angle) * (tgt._w / 2 + 2);
                const ay = tc.y - Math.sin(angle) * (tgt._h / 2 + 2);
                ctx.beginPath();
                ctx.strokeStyle = "rgba(108, 140, 255, 0.4)";
                ctx.lineWidth = 2;
                ctx.moveTo(ax, ay);
                ctx.lineTo(ax - arrowLen * Math.cos(angle - 0.4), ay - arrowLen * Math.sin(angle - 0.4));
                ctx.moveTo(ax, ay);
                ctx.lineTo(ax - arrowLen * Math.cos(angle + 0.4), ay - arrowLen * Math.sin(angle + 0.4));
                ctx.stroke();
            }

            // Draw nodes
            for (const node of this.nodes) {
                const isHovered = node === this.hoveredNode;
                const color = KIND_COLORS[node.kind] || "#6c8cff";
                const r = 8;

                // Shadow
                ctx.shadowColor = isHovered ? color : "rgba(0,0,0,0.3)";
                ctx.shadowBlur = isHovered ? 16 : 4;
                ctx.shadowOffsetY = 2;

                // Node body
                ctx.beginPath();
                ctx.roundRect(node._x, node._y, node._w, node._h, r);
                ctx.fillStyle = isHovered ? "#32335a" : "#2a2b4a";
                ctx.fill();

                ctx.shadowColor = "transparent";
                ctx.shadowBlur = 0;
                ctx.shadowOffsetY = 0;

                // Left accent bar
                ctx.beginPath();
                ctx.roundRect(node._x, node._y + 4, 3, node._h - 8, 1.5);
                ctx.fillStyle = color;
                ctx.fill();

                // Border
                ctx.beginPath();
                ctx.roundRect(node._x, node._y, node._w, node._h, r);
                ctx.strokeStyle = isHovered ? color : "rgba(108, 140, 255, 0.3)";
                ctx.lineWidth = isHovered ? 2 : 1;
                ctx.stroke();

                // Node text
                ctx.font = `${isHovered ? "600" : "500"} 11px ${getComputedStyle(document.body).getPropertyValue("--font-sans")}`;
                ctx.fillStyle = "#e8e9f0";
                ctx.textBaseline = "middle";

                const label = node.name || node.id;
                const truncated = label.length > 14 ? label.slice(0, 12) + "…" : label;
                ctx.fillText(truncated, node._x + 12, node._y + node._h / 2);

                // Kind label (small, below)
                ctx.font = "400 9px monospace";
                ctx.fillStyle = color;
                ctx.fillText(node.kind_label || "", node._x + 12, node._y + node._h - 6);
            }

            ctx.restore();
        }

        resetZoom() {
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            if (this.nodes.length > 0) {
                // Re-center based on layout
                this._layout();
            }
            this.draw();
        }
    }

    // ─── App State ──────────────────────────────────────────────────────

    const State = {
        dashboard: null,
        currentView: "dashboard",
        selectedUnitId: null,
        units: [],
        graphRenderer: null,
        graphRendererFull: null,
        wsManager: null,
        statusFilter: "all",
    };

    // ─── View Management ────────────────────────────────────────────────

    function switchView(viewName) {
        State.currentView = viewName;
        document.querySelectorAll(".nav-tab").forEach(t => {
            t.classList.toggle("active", t.dataset.view === viewName);
        });
        document.querySelectorAll(".view").forEach(v => {
            v.classList.toggle("view-active", v.id === `view-${viewName}`);
        });

        if (viewName === "graph" && State.graphRendererFull) {
            setTimeout(() => State.graphRendererFull._resize(), 50);
        }
    }

    // ─── Render: Status Cards ───────────────────────────────────────────

    function renderStatusCards(dashboard) {
        const container = document.getElementById("status-cards");
        if (!container) return;

        const counts = dashboard.status_counts;
        const cards = [
            { cls: "queued", label: "Queued", value: counts.queued },
            { cls: "pending", label: "Pending Review", value: counts.pending_review },
            { cls: "accepted", label: "Accepted", value: counts.accepted },
            { cls: "sendback", label: "Send Back", value: counts.send_back },
            { cls: "blocked", label: "Blocked", value: counts.blocked },
            { cls: "merged", label: "Merged", value: counts.merged },
        ];

        container.innerHTML = cards
            .filter(c => c.value > 0)
            .map(c => `
                <div class="status-card ${c.cls}">
                    <div class="status-card-label">${c.label}</div>
                    <div class="status-card-value">${c.value}</div>
                </div>
            `).join("");
    }

    // ─── Render: Queue Items ────────────────────────────────────────────

    function renderQueueItem(unit, selected = false) {
        const iconClass = unit.status.toLowerCase().replace(/\s+/g, "_");
        const name = unit.kind === "dll_classification"
            ? `Classify ${unit.dll}`
            : unit.function ? `${unit.dll}/${unit.function}` : unit.dll;

        return `
            <div class="queue-item ${selected ? "selected" : ""}" data-unit-id="${unit.id}">
                <div class="queue-item-icon ${iconClass}"></div>
                <div class="queue-item-info">
                    <div class="queue-item-name" title="${name}">${name}</div>
                    <div class="queue-item-meta">
                        <span>${KIND_LABELS[unit.kind] || unit.kind}</span>
                        ${unit.stale === "stale" ? '<span class="queue-item-stale">⚠ Stale</span>' : ""}
                        ${unit.stale === "critical" ? '<span class="queue-item-stale" style="color:var(--accent-red)">🔴 Critical</span>' : ""}
                    </div>
                </div>
            </div>
        `;
    }

    function renderQueueList(dashboard, selectedId = null) {
        const list = document.getElementById("queue-list");
        const empty = document.getElementById("queue-empty");
        const count = document.getElementById("queue-count");
        if (!list || !empty || !count) return;

        const active = dashboard.review_queue.filter(u =>
            !u.accepted && u.status !== "merged"
        );

        count.textContent = active.length;

        if (active.length === 0) {
            list.innerHTML = "";
            empty.style.display = "flex";
            return;
        }

        empty.style.display = "none";
        list.innerHTML = active.map(u => renderQueueItem(u, u.id === selectedId)).join("");
    }

    // ─── Render: Activity ───────────────────────────────────────────────

    function renderActivity(activity) {
        const list = document.getElementById("activity-list");
        if (!list) return;

        if (!activity || activity.length === 0) {
            list.innerHTML = `<div class="empty-state">No recent activity.</div>`;
            return;
        }

        list.innerHTML = activity.slice(0, 10).map(u => {
            const iconCls = u.accepted ? "accept" : "sendback";
            const icon = u.accepted ? "✓" : "↩";
            const name = u.kind === "dll_classification"
                ? `Classify ${u.dll}`
                : u.function ? `${u.dll}/${u.function}` : u.dll;
            const actionText = u.accepted ? "accepted" : "sent back";

            return `
                <div class="activity-item">
                    <div class="activity-icon ${iconCls}">${icon}</div>
                    <div class="activity-text"><strong>${name}</strong> ${actionText}</div>
                    <div class="activity-time">${fmtTime(u.updated_at)}</div>
                </div>
            `;
        }).join("");
    }

    // ─── Render: Full Queue List ────────────────────────────────────────

    function renderFullQueue(dashboard, selectedId = null) {
        const list = document.getElementById("full-queue-list");
        const empty = document.getElementById("full-queue-empty");
        if (!list || !empty) return;

        let units = dashboard.review_queue.filter(u => !u.accepted && u.status !== "merged");

        // Apply status filter
        const filter = State.statusFilter;
        if (filter !== "all") {
            const statusMap = {
                queued: "queued",
                pending_review: "pending_review",
                blocked: "blocked",
            };
            units = units.filter(u => u.status.toLowerCase().replace(/\s+/g, "_") === statusMap[filter]);
        }

        if (units.length === 0) {
            list.innerHTML = "";
            empty.style.display = "flex";
            return;
        }

        empty.style.display = "none";
        list.innerHTML = units.map(u => {
            const iconClass = u.status.toLowerCase().replace(/\s+/g, "_");
            const name = u.kind === "dll_classification"
                ? `Classify ${u.dll}`
                : u.function ? `${u.dll}/${u.function}` : u.dll;

            return `
                <div class="queue-item-full ${u.id === selectedId ? "selected" : ""}" data-unit-id="${u.id}">
                    <div class="queue-item-icon ${iconClass}"></div>
                    <div class="qi-name" title="${name}">${name}</div>
                    <div class="qi-dll">${u.dll}</div>
                    <div class="qi-status ${iconClass}">${STATUS_LABELS[u.status] || u.status}</div>
                    <div class="qi-attempt">v${u.attempt}</div>
                </div>
            `;
        }).join("");
    }

    // ─── Render: Detail Panel ───────────────────────────────────────────

    async function showDetail(unitId) {
        State.selectedUnitId = unitId;
        const panel = document.getElementById("detail-panel");

        // Set header
        document.querySelector(".detail-unit-id").textContent = unitId;
        const badge = document.querySelector(".detail-status-badge");

        try {
            const res = await API.unit(unitId);
            const u = res.unit;

            badge.className = `detail-status-badge ${u.status.toLowerCase().replace(/\s+/g, "_")}`;
            badge.textContent = STATUS_LABELS[u.status] || u.status;

            const body = document.getElementById("detail-body");
            body.innerHTML = `
                <div id="detail-content">
                    ${renderDetailOverview(u)}
                    ${renderDetailActions(u)}
                </div>
            `;
        } catch (err) {
            body.innerHTML = `<div class="empty-state">Failed to load unit details: ${err.message}</div>`;
        }

        panel.classList.add("open");
    }

    function hideDetail() {
        document.getElementById("detail-panel").classList.remove("open");
        State.selectedUnitId = null;
    }

    function renderDetailOverview(u) {
        const conf = fmtConfidence(u.confidence);
        const bp = u.baseline_tests_passed ?? 0;
        const bt = u.baseline_tests_total ?? 0;
        const vp = u.verification_tests_passed ?? 0;
        const vt = u.verification_tests_total ?? 0;

        const bpClass = bt === 0 ? "none" : bp === bt ? "pass" : bp > 0 ? "partial" : "fail";
        const vpClass = vt === 0 ? "none" : vp === vt ? "pass" : vp > 0 ? "partial" : "fail";

        return `
            <div class="detail-section">
                <div class="detail-section-title">Overview</div>
                <div class="detail-row">
                    <span class="detail-row-label">Kind</span>
                    <span class="detail-row-value">${KIND_LABELS[u.kind] || u.kind}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-row-label">DLL</span>
                    <span class="detail-row-value">${u.dll}</span>
                </div>
                ${u.function ? `
                    <div class="detail-row">
                        <span class="detail-row-label">Function</span>
                        <span class="detail-row-value">${u.function}</span>
                    </div>
                ` : ""}
                <div class="detail-row">
                    <span class="detail-row-label">Attempt</span>
                    <span class="detail-row-value">v${u.attempt}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-row-label">LLM Model</span>
                    <span class="detail-row-value">${u.llm_model || "—"}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-row-label">Confidence</span>
                    <span class="detail-row-value">${conf.text}</span>
                </div>
                ${u.confidence != null ? `
                    <div class="confidence-bar-container">
                        <div class="confidence-bar ${conf.cls}" style="width:${conf.pct}%"></div>
                    </div>
                ` : ""}
                <div class="detail-row">
                    <span class="detail-row-label">Staleness</span>
                    <span class="detail-row-value">${u.stale || "Fresh"}</span>
                </div>
            </div>

            <div class="detail-section">
                <div class="detail-section-title">Test Results</div>
                <div class="test-results">
                    <div class="test-result-item">
                        <div class="test-result-label">Baseline</div>
                        <div class="test-result-value ${bpClass}">${bp}/${bt}</div>
                    </div>
                    <div class="test-result-item">
                        <div class="test-result-label">Verification</div>
                        <div class="test-result-value ${vpClass}">${vp}/${vt}</div>
                    </div>
                </div>
            </div>

            ${u.diff_summary ? `
                <div class="detail-section">
                    <div class="detail-section-title">Diff Summary</div>
                    <div class="diff-stats">
                        <div class="diff-stat">
                            <div class="diff-stat-dot change"></div>
                            <span>${u.diff_summary.files_changed} files</span>
                        </div>
                        <div class="diff-stat">
                            <div class="diff-stat-dot insert"></div>
                            <span>+${u.diff_summary.insertions}</span>
                        </div>
                        <div class="diff-stat">
                            <div class="diff-stat-dot delete"></div>
                            <span>-${u.diff_summary.deletions}</span>
                        </div>
                    </div>
                </div>
            ` : ""}

            ${u.dependencies.length > 0 ? `
                <div class="detail-section">
                    <div class="detail-section-title">Dependencies</div>
                    <div class="dependency-list">
                        ${u.dependencies.map(d => `<span class="dependency-tag">${d}</span>`).join("")}
                    </div>
                </div>
            ` : ""}

            ${u.attempt_history && u.attempt_history.length > 0 ? `
                <div class="detail-section">
                    <div class="detail-section-title">Attempt History (${u.attempt_history.length})</div>
                    <div class="attempt-list">
                        ${u.attempt_history.map(a => {
                            const icon = a.compilation_errors.length === 0 && a.failed_tests.length === 0
                                ? "✅" : "❌";
                            return `
                                <div class="attempt-item">
                                    <span class="attempt-item-icon">${icon}</span>
                                    <div class="attempt-item-info">
                                        <div>Attempt ${a.attempt} — ${a.committed_at}</div>
                                        <div class="attempt-item-commit">${a.commit_hash.slice(0, 7)}</div>
                                    </div>
                                    ${a.failed_tests.length > 0
                                        ? `<div class="attempt-item-failures">${a.failed_tests.slice(0, 1).join("; ")}</div>`
                                        : ""}
                                </div>
                            `;
                        }).join("")}
                    </div>
                </div>
            ` : ""}

            ${u.known_gaps && u.known_gaps.length > 0 ? `
                <div class="detail-section">
                    <div class="detail-section-title">Known Gaps</div>
                    <ul class="gap-list">
                        ${u.known_gaps.map(g => `<li>${g}</li>`).join("")}
                    </ul>
                </div>
            ` : ""}
        `;
    }

    function renderDetailActions(u) {
        const disabled = u.accepted || u.status === "merged";

        return `
            <div class="detail-actions">
                <div class="action-row">
                    <button class="btn btn-success" id="btn-accept" ${disabled ? "disabled" : ""}>
                        ✓ Accept
                    </button>
                    <button class="btn btn-warning" id="btn-send-back" ${disabled ? "disabled" : ""}>
                        ↩ Send Back
                    </button>
                </div>
                <div class="action-row">
                    <button class="btn btn-danger" id="btn-patch" ${disabled ? "disabled" : ""}>
                        ✏ Request Patch
                    </button>
                    <button class="btn btn-secondary" id="btn-reload-detail">↻ Reload</button>
                </div>
            </div>
        `;
    }

    // ─── Render: Graph Legend ───────────────────────────────────────────

    function renderGraphLegend(container) {
        if (!container) return;
        container.innerHTML = Object.entries(KIND_COLORS).map(([kind, color]) => `
            <div class="legend-item">
                <div class="legend-dot" style="background:${color}"></div>
                <span>${KIND_LABELS[kind] || kind}</span>
            </div>
        `).join("");
    }

    // ─── Data Loading ───────────────────────────────────────────────────

    async function loadDashboard() {
        try {
            const res = await API.dashboard();
            State.dashboard = res.dashboard;
            State.units = State.dashboard.review_queue;

            renderStatusCards(State.dashboard);
            renderQueueList(State.dashboard, State.selectedUnitId);
            renderActivity(State.dashboard.recent_activity);

            if (State.currentView === "queue") {
                renderFullQueue(State.dashboard, State.selectedUnitId);
            }

            // Update graph
            const graphRes = await API.graph();
            const graph = graphRes.graph;

            const nodes = (graph.nodes || []).map(n => ({
                id: n.id,
                name: n.label || n.id,
                kind: n.kind || "function_translation",
                kind_label: KIND_LABELS[n.kind] || n.kind,
            }));

            const edges = graph.edges || [];

            if (State.graphRenderer) {
                State.graphRenderer.setData(nodes, edges);
            }
            if (State.graphRendererFull) {
                State.graphRendererFull.setData(nodes, edges);
            }
        } catch (err) {
            showToast(`Failed to load dashboard: ${err.message}`, "error");
        }
    }

    // ─── Event Handlers ─────────────────────────────────────────────────

    function setupEventListeners() {
        // Nav tabs
        document.querySelectorAll(".nav-tab").forEach(tab => {
            tab.addEventListener("click", () => switchView(tab.dataset.view));
        });

        // Sidebar toggle
        const sidebar = document.getElementById("sidebar");
        const main = document.getElementById("main");
        document.getElementById("sidebar-toggle").addEventListener("click", () => {
            sidebar.classList.toggle("collapsed");
            main.classList.toggle("expanded");
            setTimeout(() => State.graphRenderer?._resize(), 300);
        });
        document.getElementById("sidebar-close").addEventListener("click", () => {
            sidebar.classList.add("collapsed");
            main.classList.add("expanded");
            setTimeout(() => State.graphRenderer?._resize(), 300);
        });

        // Refresh button
        document.getElementById("btn-refresh").addEventListener("click", loadDashboard);

        // Queue list clicks (event delegation)
        document.getElementById("queue-list").addEventListener("click", (e) => {
            const item = e.target.closest(".queue-item");
            if (!item) return;
            showDetail(item.dataset.unitId);
        });

        // Full queue list clicks (event delegation)
        document.getElementById("full-queue-list").addEventListener("click", (e) => {
            const item = e.target.closest(".queue-item-full");
            if (!item) return;
            State.selectedUnitId = item.dataset.unitId;
            showDetail(item.dataset.unitId);
            renderFullQueue(State.dashboard, State.selectedUnitId);
        });

        // Detail panel close
        document.getElementById("detail-close").addEventListener("click", hideDetail);

        // Detail panel actions
        document.addEventListener("click", (e) => {
            const btn = e.target.closest("[id^='btn-']");
            if (!btn) return;

            const unitId = State.selectedUnitId;
            if (!unitId) return;

            if (btn.id === "btn-accept") {
                acceptUnit(unitId);
            } else if (btn.id === "btn-send-back") {
                showSendBackModal(unitId);
            } else if (btn.id === "btn-patch") {
                showPatchModal(unitId);
            } else if (btn.id === "btn-reload-detail") {
                showDetail(unitId);
            }
        });

        // Status filter
        const filterSelect = document.getElementById("status-filter");
        filterSelect.addEventListener("change", () => {
            State.statusFilter = filterSelect.value;
            if (State.dashboard) {
                renderFullQueue(State.dashboard, State.selectedUnitId);
            }
        });

        // Graph view buttons
        document.getElementById("btn-fit-graph")?.addEventListener("click", () => {
            if (State.graphRendererFull) State.graphRendererFull._resize();
        });
        document.getElementById("btn-reset-graph")?.addEventListener("click", () => {
            if (State.graphRendererFull) State.graphRendererFull.resetZoom();
        });

        // Keyboard shortcuts
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                if (document.querySelector(".modal-overlay")) {
                    document.querySelector(".modal-overlay")?.remove();
                } else if (document.getElementById("detail-panel").classList.contains("open")) {
                    hideDetail();
                }
            }
            // Arrow keys to navigate queue
            if (e.key === "n" && State.selectedUnitId && !e.target.matches("textarea, input")) {
                if (State.dashboard) {
                    const units = State.dashboard.review_queue.filter(u =>
                        !u.accepted && u.status !== "merged"
                    );
                    const idx = units.findIndex(u => u.id === State.selectedUnitId);
                    if (idx >= 0 && idx < units.length - 1) {
                        const next = units[idx + 1];
                        showDetail(next.id);
                        renderQueueList(State.dashboard, next.id);
                        renderFullQueue(State.dashboard, next.id);
                    }
                }
            }
            if (e.key === "p" && State.selectedUnitId && !e.target.matches("textarea, input")) {
                if (State.dashboard) {
                    const units = State.dashboard.review_queue.filter(u =>
                        !u.accepted && u.status !== "merged"
                    );
                    const idx = units.findIndex(u => u.id === State.selectedUnitId);
                    if (idx > 0) {
                        const prev = units[idx - 1];
                        showDetail(prev.id);
                        renderQueueList(State.dashboard, prev.id);
                        renderFullQueue(State.dashboard, prev.id);
                    }
                }
            }
        });
    }

    // ─── Action Functions ───────────────────────────────────────────────

    async function acceptUnit(unitId) {
        try {
            const res = await API.acceptUnit(unitId);
            showToast(`Accepted: ${unitId}`, "success");
            await loadDashboard();
            hideDetail();
        } catch (err) {
            showToast(`Accept failed: ${err.message}`, "error");
        }
    }

    function showSendBackModal(unitId) {
        showModal("Send Back", "Send Back", async (reason) => {
            if (!reason) {
                showToast("Reason is required", "warning");
                return;
            }
            try {
                await API.sendBackUnit(unitId, reason);
                showToast(`Sent back: ${unitId}`, "warning");
                await loadDashboard();
                hideDetail();
            } catch (err) {
                showToast(`Send back failed: ${err.message}`, "error");
            }
        });
    }

    function showPatchModal(unitId) {
        showModal("Request Patch", "Request Patch", async (issue) => {
            if (!issue) {
                showToast("Issue description is required", "warning");
                return;
            }
            try {
                await API.patchUnit(unitId, issue);
                showToast(`Patch requested for: ${unitId}`, "info");
                await loadDashboard();
                hideDetail();
            } catch (err) {
                showToast(`Patch request failed: ${err.message}`, "error");
            }
        });
    }

    // ─── WebSocket Event Handler ────────────────────────────────────────

    function handleWSMessage(event) {
        // Silently refresh data on any progress event
        // Could also update the UI incrementally with specific event types
        loadDashboard();
    }

    // ─── Initialization ─────────────────────────────────────────────────

    async function init() {
        setupEventListeners();

        // Initialize graph renderers
        State.graphRenderer = new GraphRenderer(document.getElementById("graph-canvas"));
        State.graphRendererFull = new GraphRenderer(document.getElementById("graph-canvas-full"));
        renderGraphLegend(document.getElementById("graph-legend"));

        // Initialize WebSocket for live updates
        State.wsManager = new WSManager(handleWSMessage);
        State.wsManager.connect();

        // Load initial data
        await loadDashboard();

        // Auto-refresh every 30 seconds
        setInterval(loadDashboard, 30000);
    }

    // Start the app
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

})();

/* ==========================================================================
   Calxgloss Web — Application JavaScript
   ========================================================================== */

(() => {
    "use strict";

    // ─── Constants ──────────────────────────────────────────────────────

    const STATUS_COLORS = {
        queued: "#6c8cff",
        pending_review: "#facc15",
        in_progress: "#22d3ee",
        accepted: "#4ade80",
        sendback: "#f87171",
        blocked: "#fb923c",
    };

    const STATUS_LABELS = {
        queued: "Queued",
        pending_review: "Pending Review",
        in_progress: "⟳ In Progress",
        accepted: "Accepted",
        sendback: "Send Back",
        blocked: "Blocked",
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

            console.log("[WS] Connecting to:", url);

            try {
                this.ws = new WebSocket(url);
                this.ws.onopen = () => {
                    this.connected = true;
                    document.getElementById("live-indicator").classList.add("active");
                    this.reconnectDelay = 3000;
                    console.log("[WS] Connected successfully");
                };
                this.ws.onmessage = (e) => {
                    console.log("[WS] Received message:", e.data);
                    try {
                        const parsed = JSON.parse(e.data);
                        console.log("[WS] Parsed event:", parsed.event);
                        this.onMessage(parsed);
                    } catch {
                        console.error("[WS] Failed to parse message:", e.data);
                    }
                };
                this.ws.onclose = (e) => {
                    this.connected = false;
                    console.warn("[WS] Disconnected (code:", e.code, "reason:", e.reason, ")");
                    this._scheduleReconnect();
                };
                this.ws.onerror = (err) => {
                    console.error("[WS] Error:", err);
                    this.ws?.close();
                };
            } catch (err) {
                console.error("[WS] Connection error:", err);
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

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    // ─── Enhanced SVG Dependency Graph Renderer ─────────────────────────

    class GraphRenderer {
        constructor(canvas, options = {}) {
            this.canvas = canvas;
            this.ctx = canvas.getContext("2d");

            // Data
            this.nodes = [];
            this.edges = [];
            this._totalWidth = 0;
            this._totalHeight = 0;

            // Camera
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;

            // Interaction state
            this.dragging = false;
            this.dragStart = { x: 0, y: 0 };
            this.hoveredNode = null;
            this.selectedNode = null;
            this._highlightedNodes = new Set();
            this._dimmedNodes = new Set();

            // Callbacks
            this.onNodeClick = options.onNodeClick || null;
            this.onZoomChange = options.onZoomChange || null;

            // Dimensions
            this._resize();

            // Event listeners
            this._onWheel = (e) => this._handleWheel(e);
            this._onMouseDown = (e) => this._handleMouseDown(e);
            this._onMouseMove = (e) => this._handleMouseMove(e);
            this._onMouseUp = () => this._handleMouseUp();
            this._onDblClick = () => this._handleDblClick();

            this.canvas.addEventListener("wheel", this._onWheel, { passive: false });
            this.canvas.addEventListener("mousedown", this._onMouseDown);
            document.addEventListener("mousemove", this._onMouseMove);
            document.addEventListener("mouseup", this._onMouseUp);
            this.canvas.addEventListener("dblclick", this._onDblClick);

            window.addEventListener("resize", () => this._resize());

            // Tooltip element
            this._tooltip = document.createElement("div");
            this._tooltip.className = "graph-tooltip";
            const container = canvas.parentElement;
            if (container) {
                container.appendChild(this._tooltip);
            }
        }

        // ── Resize

        _resize() {
            const rect = this.canvas.parentElement?.getBoundingClientRect()
                || this.canvas.getBoundingClientRect();
            const dpr = window.devicePixelRatio || 1;
            this.canvas.width = rect.width * dpr;
            this.canvas.height = rect.height * dpr;
            this.canvas.style.width = rect.width + "px";
            this.canvas.style.height = rect.height + "px";
            this._w = rect.width;
            this._h = rect.height;
            this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            this.draw();
        }

        // ── Data

        setData(nodes, edges) {
            this.nodes = nodes || [];
            this.edges = edges || [];
            this._highlightedNodes.clear();
            this._dimmedNodes.clear();
            this.selectedNode = null;
            this._layout();
            this.draw();
            if (this.onZoomChange) this.onZoomChange(this.scale);
        }

        // ── Sugiyama-style layered layout with crossing reduction

        _layout() {
            if (this.nodes.length === 0) {
                return;
            }

            const NODE_W = 180;
            const NODE_H = 42;
            const PAD_X = 40;
            const PAD_Y = 40;
            const LAYER_GAP = 100;
            const NODE_GAP = 20;
            const ROW_GAP = 10;
            const MAX_COLS = 4;

            // Build adjacency maps
            const nodeSet = new Set(this.nodes.map(n => n.id));
            const parentMap = new Map();
            const childMap = new Map();
            this.nodes.forEach(n => {
                parentMap.set(n.id, []);
                childMap.set(n.id, []);
            });
            this.edges.forEach(e => {
                if (nodeSet.has(e.from) && nodeSet.has(e.to)) {
                    parentMap.get(e.from).push(e.to);
                    childMap.get(e.to).push(e.from);
                }
            });

            // Step 1: Assign layers via longest path from roots (BFS)
            const layers = new Map();
            const roots = this.nodes.filter(n => parentMap.get(n.id).length === 0);
            const queue = roots.map(n => ({ id: n.id, layer: 0 }));
            const visited = new Set();

            while (queue.length > 0) {
                const { id, layer } = queue.shift();
                if (visited.has(id)) {
                    layers.set(id, Math.max(layers.get(id), layer));
                    continue;
                }
                visited.add(id);
                layers.set(id, layer);

                for (const child of (childMap.get(id) || [])) {
                    queue.push({ id: child, layer: layer + 1 });
                }
            }

            // Handle isolated or cycle nodes
            this.nodes.forEach(n => {
                if (!layers.has(n.id)) layers.set(n.id, 0);
            });

            // Group nodes by layer
            const layerGroups = new Map();
            this.nodes.forEach(n => {
                const l = layers.get(n.id);
                if (!layerGroups.has(l)) layerGroups.set(l, []);
                layerGroups.get(l).push(n);
            });

            const maxLayer = Math.max(...layerGroups.keys(), 0);

            // Step 2: Barycenter ordering to reduce crossings (3 passes)
            for (let pass = 0; pass < 3; pass++) {
                for (let l = 1; l <= maxLayer; l++) {
                    const group = layerGroups.get(l);
                    if (!group || group.length <= 1) continue;

                    group.sort((a, b) => {
                        const aParents = (parentMap.get(a.id) || [])
                            .map(pid => {
                                const prev = layerGroups.get(l - 1);
                                return prev ? prev.findIndex(n => n.id === pid) : -1;
                            })
                            .filter(i => i >= 0);
                        const bParents = (parentMap.get(b.id) || [])
                            .map(pid => {
                                const prev = layerGroups.get(l - 1);
                                return prev ? prev.findIndex(n => n.id === pid) : -1;
                            })
                            .filter(i => i >= 0);

                        const aAvg = aParents.length ? aParents.reduce((s, i) => s + i, 0) / aParents.length : 0;
                        const bAvg = bParents.length ? bParents.reduce((s, i) => s + i, 0) / bParents.length : 0;
                        return aAvg - bAvg;
                    });
                }
            }

            // Step 3: Compute content dimensions with multi-row wrapping per layer
            let maxRowsInLayer = 1;
            let maxNodesInLayer = 0;
            layerGroups.forEach(g => {
                if (g.length > maxNodesInLayer) maxNodesInLayer = g.length;
            });
            const totalWidth = Math.max(this._w || 800, maxNodesInLayer * (NODE_W + NODE_GAP) + PAD_X * 2);

            // Calculate max rows needed by any layer
            layerGroups.forEach(g => {
                const rows = Math.ceil(g.length / MAX_COLS);
                if (rows > maxRowsInLayer) maxRowsInLayer = rows;
            });

            // Each layer gets space for maxRowsInLayer rows, plus layer gap
            const layerHeight = NODE_H * maxRowsInLayer + (maxRowsInLayer - 1) * ROW_GAP + LAYER_GAP;
            const totalHeight = (maxLayer + 1) * layerHeight + PAD_Y * 2;

            this._totalWidth = totalWidth;
            this._totalHeight = totalHeight;

            // Step 4: Position nodes in each layer as a grid (up to MAX_COLS columns)
            layerGroups.forEach((group, layerNum) => {
                const count = group.length;
                const numCols = Math.min(count, MAX_COLS);
                const groupWidth = numCols * NODE_W + (numCols - 1) * NODE_GAP;
                const startX = (totalWidth - groupWidth) / 2;
                const layerTop = PAD_Y + layerNum * layerHeight;

                group.forEach((node, idx) => {
                    const col = idx % numCols;
                    const row = Math.floor(idx / numCols);
                    node._x = startX + col * (NODE_W + NODE_GAP);
                    node._y = layerTop + row * (NODE_H + ROW_GAP);
                    node._w = NODE_W;
                    node._h = NODE_H;
                    node._layer = layerNum;
                });
            });

            // Initial fit-to-view
            this._fitView();
        }

        // ── Coordinate transforms

        _screenToWorld(sx, sy) {
            return {
                x: (sx - this.offsetX) / this.scale,
                y: (sy - this.offsetY) / this.scale,
            };
        }

        _worldToScreen(wx, wy) {
            return {
                x: wx * this.scale + this.offsetX,
                y: wy * this.scale + this.offsetY,
            };
        }

        // ── Hit testing

        _hitTest(sx, sy) {
            const { x, y } = this._screenToWorld(sx, sy);
            for (let i = this.nodes.length - 1; i >= 0; i--) {
                const n = this.nodes[i];
                if (n._x != null && x >= n._x && x <= n._x + n._w && y >= n._y && y <= n._y + n._h) {
                    return n;
                }
            }
            return null;
        }

        // ── Wheel (zoom toward cursor)

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
            if (this.onZoomChange) this.onZoomChange(this.scale);
        }

        // ── Drag (pan)

        _handleMouseDown(e) {
            if (e.button !== 0) return;
            this.dragging = true;
            this.dragStart = { x: e.clientX, y: e.clientY };
        }

        _handleMouseMove(e) {
            if (this.dragging) {
                const dx = e.clientX - this.dragStart.x;
                const dy = e.clientY - this.dragStart.y;
                this.offsetX += dx;
                this.offsetY += dy;
                this.dragStart = { x: e.clientX, y: e.clientY };
                this.draw();
                return;
            }

            const rect = this.canvas.getBoundingClientRect();
            const sx = e.clientX - rect.left;
            const sy = e.clientY - rect.top;
            const hit = this._hitTest(sx, sy);

            if (hit !== this.hoveredNode) {
                this.hoveredNode = hit;
                this.canvas.style.cursor = hit ? "pointer" : "grab";
                this._updateTooltip(e);
                this.draw();
            } else if (hit) {
                this._updateTooltip(e);
            }
        }

        _handleMouseUp() {
            this.dragging = false;
        }

        _handleDblClick() {
            this._fitView();
            this.draw();
        }

        // ── Tooltip

        _updateTooltip(e) {
            if (!this.hoveredNode) {
                this._tooltip.classList.remove("visible");
                return;
            }

            const n = this.hoveredNode;
            const statusColor = STATUS_COLORS[n.status] || STATUS_COLORS.queued;

            this._tooltip.innerHTML = `
                <div class="graph-tooltip-name">${escapeHtml(n.name || n.id)}</div>
                <div class="graph-tooltip-meta">
                    <span>
                        <span class="graph-tooltip-dot" style="background:${statusColor}"></span>
                        ${STATUS_LABELS[n.status] || n.status}
                    </span>
                    <span>${KIND_LABELS[n.kind] || n.kind}</span>
                </div>
            `;
            this._tooltip.classList.add("visible");

            // Position tooltip to the right of the node
            const s = this._worldToScreen(n._x + n._w + 4, n._y - 4);
            this._tooltip.style.transform = `translate(${s.x}px, ${s.y}px) scale(${this.scale})`;
        }

        // ── Selection & highlighting

        selectNode(node) {
            if (this.selectedNode === node) {
                this.selectedNode = null;
                this._highlightedNodes.clear();
                this._dimmedNodes.clear();
            } else {
                this.selectedNode = node;
                this._updateHighlight(node);
            }
            this.draw();
        }

        _updateHighlight(node) {
            this._highlightedNodes.clear();
            this._dimmedNodes.clear();

            if (!node) return;

            this._highlightedNodes.add(node.id);

            // Find directly connected nodes (both dependencies and dependents)
            this.edges.forEach(e => {
                if (e.from === node.id && this.nodes.some(n => n.id === e.to)) {
                    this._highlightedNodes.add(e.to);
                }
                if (e.to === node.id && this.nodes.some(n => n.id === e.from)) {
                    this._highlightedNodes.add(e.from);
                }
            });

            // Dim everything else
            this.nodes.forEach(n => {
                if (!this._highlightedNodes.has(n.id)) {
                    this._dimmedNodes.add(n.id);
                }
            });
        }

        // ── Fit-to-view

        _fitView() {
            if (this.nodes.length === 0) {
                this.scale = 1;
                this.offsetX = 0;
                this.offsetY = 0;
                return;
            }

            const PAD_X = 60;
            const PAD_Y = 80;
            const MIN_SCALE = 0.3;
            const MAX_SCALE = 1.5;

            let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
            this.nodes.forEach(n => {
                if (n._x == null) return;
                minX = Math.min(minX, n._x);
                minY = Math.min(minY, n._y);
                maxX = Math.max(maxX, n._x + n._w);
                maxY = Math.max(maxY, n._y + n._h);
            });

            if (minX === Infinity) return;

            const contentW = maxX - minX + PAD_X * 2;
            const contentH = maxY - minY + PAD_Y * 2;

            const scaleX = this._w / contentW;
            const scaleY = this._h / contentH;
            this.scale = Math.max(MIN_SCALE, Math.min(MAX_SCALE, Math.min(scaleX, scaleY)));

            const scaledW = contentW * this.scale;
            const scaledH = contentH * this.scale;

            this.offsetX = (this._w - scaledW) / 2 - minX * this.scale + PAD_X * this.scale;
            this.offsetY = (this._h - scaledH) / 2 - minY * this.scale + PAD_Y * this.scale;
        }

        // ── Drawing

        draw() {
            const ctx = this.ctx;
            ctx.clearRect(0, 0, this._w, this._h);

            ctx.save();
            ctx.translate(this.offsetX, this.offsetY);
            ctx.scale(this.scale, this.scale);

            // Edges behind nodes
            this._drawEdges(ctx);
            // Nodes on top
            this._drawNodes(ctx);

            ctx.restore();
        }

        _drawEdges(ctx) {
            for (const edge of this.edges) {
                const src = this.nodes.find(n => n.id === edge.from);
                const tgt = this.nodes.find(n => n.id === edge.to);
                if (!src || !tgt || src._x == null || tgt._x == null) continue;

                const sc = { x: src._x + src._w, y: src._y + src._h / 2 };
                const tc = { x: tgt._x, y: tgt._y + tgt._h / 2 };

                // Bezier control points — curves from source right edge to target left edge
                const dx = Math.abs(tc.x - sc.x);
                const c1x = sc.x + Math.max(30, dx * 0.3);
                const c1y = sc.y;
                const c2x = tc.x - Math.max(30, dx * 0.3);
                const c2y = tc.y;

                const isHighlighted = this.selectedNode &&
                    (edge.from === this.selectedNode.id || edge.to === this.selectedNode.id);

                // Edge color
                ctx.beginPath();
                ctx.strokeStyle = isHighlighted
                    ? "rgba(108, 140, 255, 0.7)"
                    : this._dimmedNodes.size > 0
                        ? "rgba(108, 140, 255, 0.06)"
                        : "rgba(108, 140, 255, 0.25)";
                ctx.lineWidth = isHighlighted ? 2 : 1.5;
                ctx.moveTo(sc.x, sc.y);
                ctx.bezierCurveTo(c1x, c1y, c2x, c2y, tc.x, tc.y);
                ctx.stroke();

                // Arrowhead at target
                if (!this._dimmedNodes.size || isHighlighted) {
                    const angle = Math.atan2(tc.y - c2y, tc.x - c2x);
                    const arrowLen = 7;
                    const ax = tc.x;
                    const ay = tc.y;

                    ctx.beginPath();
                    ctx.strokeStyle = isHighlighted
                        ? "rgba(108, 140, 255, 0.7)"
                        : "rgba(108, 140, 255, 0.4)";
                    ctx.lineWidth = 2;
                    ctx.moveTo(ax, ay);
                    ctx.lineTo(ax - arrowLen * Math.cos(angle - 0.4), ay - arrowLen * Math.sin(angle - 0.4));
                    ctx.moveTo(ax, ay);
                    ctx.lineTo(ax - arrowLen * Math.cos(angle + 0.4), ay - arrowLen * Math.sin(angle + 0.4));
                    ctx.stroke();
                }
            }
        }

        _drawNodes(ctx) {
            const isDimmed = (n) => this._dimmedNodes.size > 0 && this._dimmedNodes.has(n.id);

            for (const node of this.nodes) {
                if (node._x == null) continue;

                const isHovered = node === this.hoveredNode;
                const isSelected = node === this.selectedNode;
                const dimmed = isDimmed(node);
                const color = KIND_COLORS[node.kind] || "#6c8cff";
                const statusColor = STATUS_COLORS[node.status] || STATUS_COLORS.queued;
                const r = 8;

                // Dim unconnected nodes
                if (dimmed) {
                    ctx.globalAlpha = 0.25;
                }

                // Shadow
                ctx.shadowColor = isSelected ? color : "rgba(0,0,0,0.3)";
                ctx.shadowBlur = isSelected ? 16 : isHovered ? 10 : 4;
                ctx.shadowOffsetY = 2;

                // Node body
                ctx.beginPath();
                ctx.roundRect(node._x, node._y, node._w, node._h, r);
                ctx.fillStyle = dimmed
                    ? "#1a1b2e"
                    : (isSelected ? "#32335a" : "#2a2b4a");
                ctx.fill();

                ctx.shadowColor = "transparent";
                ctx.shadowBlur = 0;
                ctx.shadowOffsetY = 0;

                // Left accent bar (kind color)
                ctx.beginPath();
                ctx.roundRect(node._x, node._y + 5, 3, node._h - 10, 1.5);
                ctx.fillStyle = dimmed ? "rgba(108,140,255,0.3)" : color;
                ctx.fill();

                // Border
                ctx.beginPath();
                ctx.roundRect(node._x, node._y, node._w, node._h, r);
                ctx.strokeStyle = isSelected ? color
                    : isHovered ? statusColor
                    : "rgba(108, 140, 255, 0.3)";
                ctx.lineWidth = isSelected ? 2 : isHovered ? 1.5 : 1;
                ctx.stroke();

                // Status indicator dot (top-right corner)
                const dotR = 4;
                const dotX = node._x + node._w - 10;
                const dotY = node._y + 8;
                ctx.beginPath();
                ctx.arc(dotX, dotY, dotR, 0, Math.PI * 2);
                ctx.fillStyle = dimmed ? "rgba(108,140,255,0.2)" : statusColor;
                ctx.fill();
                if (isSelected || isHovered) {
                    ctx.strokeStyle = "#1a1b2e";
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }

                // Node text
                ctx.globalAlpha = dimmed ? 0.3 : 1;
                ctx.font = `${isSelected ? "700" : isHovered ? "600" : "500"} 11px ${getComputedStyle(document.body).getPropertyValue("--font-sans")}`;
                ctx.fillStyle = dimmed ? "#4a4b6a" : "#e8e9f0";
                ctx.textBaseline = "middle";

                const label = node.name || node.id;
                const maxLen = isSelected ? 22 : 16;
                const truncated = label.length > maxLen ? label.slice(0, maxLen - 1) + "\u2026" : label;
                ctx.fillText(truncated, node._x + 12, node._y + node._h / 2 - 5);

                // Kind label (small, below)
                const kindLabel = KIND_LABELS[node.kind] || node.kind;
                ctx.font = "400 9px monospace";
                ctx.fillStyle = dimmed ? "rgba(108,140,255,0.3)" : color;
                ctx.fillText(kindLabel, node._x + 12, node._y + node._h - 7);

                ctx.globalAlpha = 1;
            }
        }

        // ── Click handler (call from event listener)

        handleCanvasClick(e) {
            const rect = this.canvas.getBoundingClientRect();
            const sx = e.clientX - rect.left;
            const sy = e.clientY - rect.top;
            const hit = this._hitTest(sx, sy);

            if (hit) {
                if (this.onNodeClick) {
                    this.onNodeClick(hit);
                }
                this.selectNode(hit);
            } else {
                this.selectedNode = null;
                this._highlightedNodes.clear();
                this._dimmedNodes.clear();
                this.draw();
            }
        }

        // ── Public controls

        resetZoom() {
            this._fitView();
            this.draw();
            if (this.onZoomChange) this.onZoomChange(this.scale);
        }

        destroy() {
            this.canvas.removeEventListener("wheel", this._onWheel);
            this.canvas.removeEventListener("mousedown", this._onMouseDown);
            document.removeEventListener("mousemove", this._onMouseMove);
            document.removeEventListener("mouseup", this._onMouseUp);
            this.canvas.removeEventListener("dblclick", this._onDblClick);
            this._tooltip?.remove();
        }

        // ── Keyboard shortcuts (graph view)

        handleKeydown(e) {
            if (State.currentView !== "graph") return;
            if (e.target.matches("textarea, input")) return;

            const PAN = 40;
            let handled = false;

            switch (e.key) {
                case "+":
                case "=":
                    this.scale = Math.min(3, this.scale * 1.2);
                    this.draw();
                    if (this.onZoomChange) this.onZoomChange(this.scale);
                    handled = true;
                    break;
                case "-":
                    this.scale = Math.max(0.2, this.scale / 1.2);
                    this.draw();
                    if (this.onZoomChange) this.onZoomChange(this.scale);
                    handled = true;
                    break;
                case "ArrowLeft":
                    this.offsetX += PAN;
                    this.draw();
                    handled = true;
                    break;
                case "ArrowRight":
                    this.offsetX -= PAN;
                    this.draw();
                    handled = true;
                    break;
                case "ArrowUp":
                    this.offsetY += PAN;
                    this.draw();
                    handled = true;
                    break;
                case "ArrowDown":
                    this.offsetY -= PAN;
                    this.draw();
                    handled = true;
                    break;
                case "0":
                    this.resetZoom();
                    handled = true;
                    break;
                case "Escape":
                    this.selectedNode = null;
                    this._highlightedNodes.clear();
                    this._dimmedNodes.clear();
                    this.draw();
                    handled = true;
                    break;
            }

            if (handled) {
                e.preventDefault();
            }
        }
    }

    // ─── App State ──────────────────────────────────────────────────────

    const State = {
        dashboard: null,
        currentView: "dashboard",
        selectedUnitId: null,
        units: [],
        graphRendererFull: null,
        wsManager: null,
        statusFilter: "all",
        gcCandidates: [],
        gcSelectedBranches: new Set(),
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
            setTimeout(() => {
                State.graphRendererFull._resize();
                State.graphRendererFull.resetZoom();
            }, 50);
        }

        // Render full queue when switching to queue view
        if (viewName === "queue" && State.dashboard) {
            renderFullQueue(State.dashboard, State.selectedUnitId);
        }

        if (viewName === "llm-log") {
            // Focus the log container when switching to LLM log view
            const container = document.getElementById("llm-log-container");
            if (container) container.focus();
        }

        // Load GC candidates when switching to the GC view
        if (viewName === "gc") {
            loadGcCandidates();
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
            { cls: "in_progress", label: "In Progress", value: counts.in_progress },
            { cls: "accepted", label: "Accepted", value: counts.accepted },
            { cls: "sendback", label: "Send Back", value: counts.send_back },
            { cls: "blocked", label: "Blocked", value: counts.blocked },
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

    async function renderStaleBranchesCard() {
        try {
            const res = await API.gcCandidates(7);
            const container = document.getElementById("status-cards");
            if (!container) return;

            const count = res.candidates?.length || 0;
            if (count > 0) {
                const card = document.createElement("div");
                card.className = "status-card stale_branches";
                card.innerHTML = `
                    <div class="status-card-label">Stale Branches</div>
                    <div class="status-card-value">${count}</div>
                `;
                card.addEventListener("click", () => switchView("gc"));
                container.appendChild(card);
            }
        } catch {
            // Silently fail — stale card is non-critical
        }
    }

    // ─── Render: Queue Items ────────────────────────────────────────────

    function renderQueueItem(unit, selected = false) {
        const iconClass = unit.status.toLowerCase().replace(/\s+/g, "_");
        const name = unit.kind === "dll_classification"
            ? `Classify ${unit.dll}`
            : unit.function ? `${unit.dll} ${unit.function}` : unit.dll;

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

        const active = dashboard.review_queue.filter(u => !u.accepted);

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

        let units = dashboard.review_queue.filter(u => !u.accepted);

        // Apply status filter
        const filter = State.statusFilter;
        if (filter !== "all") {
            const statusMap = {
                queued: "queued",
                pending_review: "pending_review",
                in_progress: "in_progress",
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
                : u.function ? `${u.dll} ${u.function}` : u.dll;

            return `
                <div class="queue-item-full ${u.id === selectedId ? "selected" : ""}" data-unit-id="${u.id}">
                    <div class="queue-item-icon ${iconClass}"></div>
                    <div class="qi-name" title="${u.id}">${name}</div>
                    <div class="qi-status ${iconClass}">${STATUS_LABELS[u.status] || u.status}</div>
                    <div class="qi-attempt">v${u.attempt}</div>
                </div>
            `;
        }).join("");
    }

    // ─── Render: Detail Panel ───────────────────────────────────────────

    async function showDetail(unitId) {
        State.selectedUnitId = unitId;

        // If on queue view, show inline detail; otherwise use sidebar panel
        if (State.currentView === "queue") {
            await renderInlineDetail(unitId);
            renderFullQueue(State.dashboard, unitId);
            return;
        }

        const panel = document.getElementById("detail-panel");

        // Set header
        document.querySelector(".detail-unit-id").textContent = unitId;
        const badge = document.querySelector(".detail-status-badge");

        const body = document.getElementById("detail-body");
        try {
            const res = await API.unit(unitId);
            const u = res.unit;

            badge.className = `detail-status-badge ${u.status.toLowerCase().replace(/\s+/g, "_")}`;
            badge.textContent = STATUS_LABELS[u.status] || u.status;

            body.innerHTML = `
                <div id="detail-content">
                    ${renderDetailOverview(u)}
                    ${renderDetailActions(u)}
                    ${renderDiffTab(u)}
                </div>
            `;

            // Load diff data
            loadDiffView(unitId);
            loadGhidraView(unitId);

        } catch (err) {
            body.innerHTML = `<div class="empty-state">Failed to load unit details: ${err.message}</div>`;
        }

        panel.classList.add("open");
    }

    async function renderInlineDetail(unitId) {
        const titleEl = document.getElementById("queue-detail-title");
        const closeBtn = document.getElementById("queue-detail-close");
        const body = document.getElementById("queue-detail-body");

        if (!titleEl || !body) return;

        try {
            const res = await API.unit(unitId);
            const u = res.unit;

            titleEl.textContent = u.function
                ? `${u.dll}!${u.function}`
                : `Classify ${u.dll}`;
            titleEl.title = u.id;
            closeBtn.style.display = "";

            body.innerHTML = `
                <div id="detail-content">
                    ${renderDetailOverview(u)}
                    ${renderDetailActions(u)}
                    ${renderDiffTab(u)}
                </div>
            `;

            // Load diff data
            loadDiffView(unitId);
            loadGhidraView(unitId);

        } catch (err) {
            body.innerHTML = `<div class="empty-state">Failed to load unit details: ${err.message}</div>`;
            closeBtn.style.display = "none";
        }
    }

    function hideDetail() {
        const panel = document.getElementById("detail-panel");
        panel.classList.remove("open");
        State.selectedUnitId = null;

        // Clear inline detail if on queue view
        if (State.currentView === "queue") {
            const titleEl = document.getElementById("queue-detail-title");
            const closeBtn = document.getElementById("queue-detail-close");
            const body = document.getElementById("queue-detail-body");
            if (titleEl) {
                titleEl.textContent = "Select a unit to review";
                titleEl.title = "";
            }
            if (closeBtn) closeBtn.style.display = "none";
            if (body) body.innerHTML = '<div class="empty-state">Click an item in the list to review it.</div>';
            State.selectedUnitId = null;
        }
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
                    <span class="detail-row-value">${u.llm_model || "\u2014"}</span>
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
                                ? "\u2705" : "\u274c";
                            return `
                                <div class="attempt-item">
                                    <span class="attempt-item-icon">${icon}</span>
                                    <div class="attempt-item-info">
                                        <div>Attempt ${a.attempt} \u2014 ${a.committed_at}</div>
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
        const disabled = u.accepted;

        return `
            <div class="detail-actions">
                <div class="action-row">
                    <button class="btn btn-success" id="btn-accept" ${disabled ? "disabled" : ""}>
                        \u2713 Accept
                    </button>
                    <button class="btn btn-warning" id="btn-send-back" ${disabled ? "disabled" : ""}>
                        \u21a9 Send Back
                    </button>
                </div>
                <div class="action-row">
                    <button class="btn btn-danger" id="btn-patch" ${disabled ? "disabled" : ""}>
                        \u270f Request Patch
                    </button>
                    <button class="btn btn-secondary" id="btn-reload-detail">\u21bb Reload</button>
                </div>
            </div>
        `;
    }

    // ─── Diff Tab ─────────────────────────────────────────────────────────

    function renderDiffTab(u) {
        const hasDiff = u.diff_summary.files_changed > 0;

        return `
            <div class="detail-section" id="diff-section">
                <div class="diff-tabs">
                    <button class="diff-tab active" data-diff-tab="diff">Diff (${u.diff_summary.insertions}+ ${u.diff_summary.deletions}-)</button>
                    <button class="diff-tab" data-diff-tab="ghidra">Ghidra Context</button>
                </div>
                <div class="diff-content" id="diff-viewer">
                    ${hasDiff
                        ? '<div id="diff-body" class="diff-viewer"><div class="spinner"></div></div>'
                        : '<div class="ghidra-empty">No diff available for this unit.</div>'
                    }
                </div>
                <div class="diff-content" id="ghidra-viewer" style="display:none">
                    <div id="ghidra-body" class="ghidra-viewer">
                        <div class="spinner"></div>
                    </div>
                </div>
            </div>
        `;
    }

    async function loadDiffView(unitId) {
        try {
            const res = await API.unitDiff(unitId);
            const files = res.diff || [];

            const body = document.getElementById("diff-body");
            if (!body) return;

            if (files.length === 0) {
                body.innerHTML = '<div class="ghidra-empty">No changes vs. main.</div>';
                return;
            }

            let html = "";
            for (const file of files) {
                html += `<div class="diff-file">`;
                if (file.renamed && file.old_path) {
                    html += `<div class="diff-file-header">
                        <span class="path">${escapeHtml(file.path)}</span>
                        <span class="rename">\u2190 ${escapeHtml(file.old_path)}</span>
                    </div>`;
                } else {
                    html += `<div class="diff-file-header"><span class="path">${escapeHtml(file.path)}</span></div>`;
                }

                html += `<table class="diff-table">`;
                for (const hunk of file.hunks) {
                    if (hunk.header) {
                        html += `<tr class="diff-line hunk-header">
                            <td class="diff-line-body">${escapeHtml(hunk.header)}</td>
                        </tr>`;
                    }
                    for (const line of hunk.lines) {
                        const cls = line.kind === "addition" ? "addition"
                            : line.kind === "deletion" ? "deletion" : "context";
                        html += `<tr class="diff-line ${cls}">
                            <td class="diff-line-num">
                                ${line.old_line != null ? `<span class="old">${line.old_line}</span>` : '<span class="empty">&nbsp;</span>'}
                            </td>
                            <td class="diff-line-num">
                                ${line.new_line != null ? `<span class="new">${line.new_line}</span>` : '<span class="empty">&nbsp;</span>'}
                            </td>
                            <td class="diff-line-body">${escapeHtml(line.content)}</td>
                        </tr>`;
                    }
                }
                html += `</table></div>`;
            }

            body.innerHTML = html;

            // Set up diff tab switching
            setupDiffTabs();
        } catch (err) {
            const body = document.getElementById("diff-body");
            if (body) body.innerHTML = `<div class="ghidra-empty">Failed to load diff: ${escapeHtml(err.message)}</div>`;
        }
    }

    async function loadGhidraView(unitId) {
        try {
            const res = await API.unitGhidra(unitId);
            const ctx = res.context;

            const body = document.getElementById("ghidra-body");
            if (!body) return;

            if (!ctx) {
                body.innerHTML = `<div class="ghidra-empty">${escapeHtml(res.error || "No Ghidra context available.")}</div>`;
                return;
            }

            let html = "";

            // Ghidra metadata
            html += `<div style="padding:8px 12px;font-size:12px;color:var(--text-muted)">`;
            if (ctx.dll) html += `DLL: <strong style="color:var(--text-secondary)">${escapeHtml(ctx.dll)}</strong> &nbsp;`;
            if (ctx.function_name) html += `Function: <strong style="color:var(--text-secondary)">${escapeHtml(ctx.function_name)}</strong>`;
            if (ctx.address) html += ` &nbsp;Addr: <code>${escapeHtml(ctx.address)}</code>`;
            html += `</div>`;

            // Windows API calls
            if (ctx.windows_apis && ctx.windows_apis.length > 0) {
                html += `<div class="ghidra-label">Identified API Calls</div>`;
                html += `<div class="ghidra-api-calls">`;
                for (const api of ctx.windows_apis) {
                    html += `<span class="ghidra-api-tag">${escapeHtml(api.name)} \u2192 ${escapeHtml(api.pal_mapping)}</span>`;
                }
                html += `</div>`;
            }

            // Decompiler output
            if (ctx.decompiler_output) {
                html += `<div class="ghidra-label">Decompiler (Pseudo-C)</div>`;
                html += `<div class="ghidra-decompiler">${escapeHtml(ctx.decompiler_output)}</div>`;
            }

            // Disassembly
            if (ctx.disassembly && ctx.disassembly.length > 0) {
                html += `<div class="ghidra-label">Disassembly</div>`;
                html += `<div class="ghidra-disassembly">`;
                for (const line of ctx.disassembly) {
                    html += `<div>${escapeHtml(line.address)}&nbsp;&nbsp;${escapeHtml(line.instruction)}</div>`;
                }
                html += `</div>`;
            }

            body.innerHTML = html;
        } catch (err) {
            const body = document.getElementById("ghidra-body");
            if (body) body.innerHTML = `<div class="ghidra-empty">Failed to load Ghidra context: ${escapeHtml(err.message)}</div>`;
        }
    }

    function setupDiffTabs() {
        const tabs = document.querySelectorAll(".diff-tab");
        const diffViewer = document.getElementById("diff-viewer");
        const ghidraViewer = document.getElementById("ghidra-viewer");

        tabs.forEach(tab => {
            tab.addEventListener("click", () => {
                const tabName = tab.dataset.diffTab;
                tabs.forEach(t => t.classList.toggle("active", t === tab));

                if (tabName === "diff") {
                    diffViewer.style.display = "";
                    ghidraViewer.style.display = "none";
                } else {
                    diffViewer.style.display = "none";
                    ghidraViewer.style.display = "";
                }
            });
        });
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

            // Update graph data
            const graphRes = await API.graph();
            const graph = graphRes.graph;

            const nodes = (graph.nodes || []).map(n => _mapGraphNode(n));
            const edges = graph.edges || [];

            if (State.graphRenderer) {
                State.graphRenderer.setData(nodes, edges);
            }
            if (State.graphRendererFull) {
                State.graphRendererFull.setData(nodes, edges);
            }

            // Load pipeline progress in parallel
            loadPipelineProgress();

            // Load stale branches card (non-critical, runs in background)
            renderStaleBranchesCard();
        } catch (err) {
            showToast(`Failed to load dashboard: ${err.message}`, "error");
        }
    }

    // ─── Pipeline Progress ───────────────────────────────────────────────

    async function loadPipelineProgress() {
        try {
            const res = await API.pipeline();
            renderPipelineProgress(res);
        } catch (err) {
            // Silently fail — pipeline panel is optional
            console.debug("Failed to load pipeline progress:", err.message);
        }
    }

    function renderPipelineProgress(data) {
        const panel = document.getElementById("pipeline-panel");
        const summary = document.getElementById("pipeline-summary");
        const dllsContainer = document.getElementById("pipeline-dlls");

        if (!panel || !summary || !dllsContainer) return;

        const total = data.total_dlls || 0;
        const classified = data.classified_count || 0;
        const batchDone = data.batch_complete_count || 0;
        const translating = data.currently_translating || [];

        // Show panel only if there's something to show
        if (total === 0) {
            panel.style.display = "none";
            return;
        }

        panel.style.display = "block";
        summary.textContent = `${classified} classified, ${batchDone} translated, ${translating.length} translating`;

        // Build DLL progress items
        const dlls = data.dlls || [];
        if (dlls.length === 0) {
            dllsContainer.innerHTML = '<div class="empty-state" style="padding:12px">No DLLs discovered yet.</div>';
            return;
        }

        dllsContainer.innerHTML = dlls.map(dll => {
            const name = dll.dll || "unknown";
            const hasClassification = !!dll.classification;
            const hasBatch = !!dll.batch;
            const isTranslating = !!dll.in_progress;

            let statusClass = "pending";
            let statusText = "Pending";

            if (isTranslating) {
                statusClass = "translating";
                const progress = dll.in_progress;
                const pct = progress.total_entries > 0
                    ? Math.round((progress.completed_entries / progress.total_entries) * 100)
                    : 0;
                statusText = `<div class="pipeline-progress-bar"><div class="pipeline-progress-fill" style="width:${pct}%"></div></div>`;
            } else if (hasBatch) {
                statusClass = "complete";
                const b = dll.batch;
                statusText = `${b.success_count}/${b.total_functions} OK`;
            } else if (hasClassification) {
                statusClass = "classified";
                statusText = dll.classification.category;
            }

            // Classification details
            let meta = "";
            if (dll.classification) {
                const c = dll.classification;
                let parts = [c.strategy];
                if (c.exported_symbols > 0 || c.imported_symbols > 0) {
                    parts.push(`${c.exported_symbols}↑ ${c.imported_symbols}↓`);
                }
                if (c.crate_replacement) {
                    parts.push(`→ ${c.crate_replacement}`);
                }
                meta = parts.join(" · ");
            } else if (dll.batch) {
                const b = dll.batch;
                if (b.failure_count > 0) {
                    meta = `${b.failure_count} failed · ${b.total_tokens} tokens`;
                } else {
                    meta = `${b.total_tokens} tokens`;
                }
            }

            return `
                <div class="pipeline-dll-item">
                    <span class="pipeline-dll-name">${escapeHtml(name)}</span>
                    <span class="pipeline-dll-status ${statusClass}">${statusText}</span>
                    ${meta ? `<span class="pipeline-dll-meta">${escapeHtml(meta)}</span>` : ""}
                </div>
            `;
        }).join("");
    }

    // Map API graph node to frontend format (handles old and new API formats)
    function _mapGraphNode(n) {
        let kind = n.kind || null;
        let kindLabel = n.kind_label || null;

        // New API: sends "kind" field directly
        if (!kind) {
            // Old API: infer from level field
            const level = n.level || n.kind || "function_translation";
            const levelMap = {
                dll_classification: "dll_classification",
                shim_layer: "shim_layer",
                pal_trait: "pal_trait",
                test_case_addition: "test_case_addition",
                function_translation: "function_translation",
                integration_step: "integration_step",
                bug_fix: "bug_fix",
            };
            kind = levelMap[level] || "function_translation";
        }
        if (!kindLabel) {
            kindLabel = KIND_LABELS[kind] || kind;
        }

        return {
            id: n.id || n.unit_id,
            name: n.label || n.name || n.unit_id,
            kind: kind,
            kind_label: kindLabel,
            status: n.status || STATUS_LABELS[n.kind] || "queued",
        };
    }

    // ─── Event Handlers ─────────────────────────────────────────────────

    function setupEventListeners() {
        // Nav tabs
        document.querySelectorAll(".nav-tab").forEach(tab => {
            tab.addEventListener("click", () => switchView(tab.dataset.view));
        });



        // Refresh button
        document.getElementById("btn-refresh").addEventListener("click", loadDashboard);

        // Queue list clicks (dashboard) — switch to queue view
        document.getElementById("queue-list").addEventListener("click", (e) => {
            const item = e.target.closest(".queue-item");
            if (!item) return;
            switchView("queue");
            renderFullQueue(State.dashboard, item.dataset.unitId);
            renderInlineDetail(item.dataset.unitId);
        });

        // Full queue list clicks (queue view) — show inline detail
        document.getElementById("full-queue-list").addEventListener("click", (e) => {
            const item = e.target.closest(".queue-item-full");
            if (!item) return;
            State.selectedUnitId = item.dataset.unitId;
            renderInlineDetail(item.dataset.unitId);
            renderFullQueue(State.dashboard, State.selectedUnitId);
        });

        // Detail panel close
        document.getElementById("detail-close").addEventListener("click", hideDetail);

        // Back to list (inline queue view)
        document.getElementById("queue-detail-close").addEventListener("click", hideDetail);

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

        // Graph view buttons (overlay in container)
        document.getElementById("btn-fit-graph-full")?.addEventListener("click", () => {
            if (State.graphRendererFull) {
                State.graphRendererFull.resetZoom();
            }
        });
        document.getElementById("btn-reset-graph-full")?.addEventListener("click", () => {
            if (State.graphRendererFull) {
                State.graphRendererFull.resetZoom();
            }
        });

        // LLM I/O log clear button
        document.getElementById("btn-clear-llm-log")?.addEventListener("click", clearLlmLog);

        // GC tab buttons
        document.getElementById("btn-scan-gc")?.addEventListener("click", loadGcCandidates);
        document.getElementById("btn-archive-all-gc")?.addEventListener("click", archiveSelectedGc);
        document.getElementById("gc-select-all")?.addEventListener("change", () => {
            // Handled inline in renderGcTable
        });
        document.getElementById("gc-days-input")?.addEventListener("change", loadGcCandidates);

        // Graph click handler — opens detail panel for clicked node
        function handleGraphNodeClick(node) {
            showDetail(node.id);
        }

        // Keyboard shortcuts (graph view pan/zoom)
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") {
                if (document.querySelector(".modal-overlay")) {
                    document.querySelector(".modal-overlay")?.remove();
                } else if (document.getElementById("detail-panel").classList.contains("open")) {
                    hideDetail();
                }
            }
            // Graph view keyboard shortcuts
            if (State.currentView === "graph" && State.graphRendererFull) {
                State.graphRendererFull.handleKeydown(e);
            }
        });

        // Keyboard shortcuts for queue navigation
        document.addEventListener("keydown", (e) => {
            if (State.currentView === "graph") return; // handled above
            if (e.key === "n" && State.selectedUnitId && !e.target.matches("textarea, input")) {
                if (State.dashboard) {
                    const units = State.dashboard.review_queue.filter(u => !u.accepted);
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
                    const units = State.dashboard.review_queue.filter(u => !u.accepted);
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

        // Full-screen graph click handler
        document.getElementById("graph-canvas-full")?.addEventListener("click", (e) => {
            State.graphRendererFull?.handleCanvasClick(e);
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

    // ─── LLM I/O Log ────────────────────────────────────────────────────

    const llmLogEntries = [];
    const LLM_LOG_MAX = 200;

    function addLlmLogEntry(type, dll, func, attempt, strategy, content) {
        const entry = {
            type,  // "request" or "response"
            dll,
            func,
            attempt,
            strategy,
            content,
            timestamp: new Date(),
        };
        llmLogEntries.push(entry);

        // Trim old entries
        while (llmLogEntries.length > LLM_LOG_MAX) {
            llmLogEntries.shift();
        }

        renderLlmLog();
    }

    function renderLlmLog() {
        const container = document.getElementById("llm-log-entries");
        const empty = document.getElementById("llm-log-empty");
        if (!container) return;

        if (llmLogEntries.length === 0) {
            empty.style.display = "flex";
            container.innerHTML = "";
            return;
        }

        empty.style.display = "none";

        const html = llmLogEntries.map((e) => {
            const typeLabel = e.type === "request" ? "Request" : e.type === "error" ? "⚠ Error" : "Response";
            const ts = e.timestamp.toLocaleTimeString();
            const summary = `${e.dll}!${e.func} (attempt #${e.attempt}, ${e.strategy})`;
            // Only escape < and > so JSON/Code stays readable in <pre>
            const safe = e.content
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;");

            return `<div class="llm-log-entry">
                <div class="llm-log-entry-header ${e.type}">
                    ${typeLabel}
                    <span class="meta">${ts} · ${summary} (${e.content.length} chars)</span>
                </div>
                <div class="llm-log-entry-body"><pre>${safe}</pre></div>
            </div>`;
        }).join("");

        container.innerHTML = html;
    }

    function clearLlmLog() {
        llmLogEntries.length = 0;
        renderLlmLog();
    }

    function escapeHtml(str) {
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    // ─── WebSocket Event Handler ────────────────────────────────────────

    function handleWSMessage(event) {
        console.log("[WS] handleWSMessage event:", event.event);

        // Handle translation start — show a toast notification
        if (event.event === "translation_started") {
            showToast(
                `Translating ${event.function || "classify"} (${event.dll})`,
                "info"
            );
            // Update the live indicator
            const indicator = document.getElementById("live-indicator");
            if (indicator) indicator.classList.add("active");
        }

        // Handle translation completion
        if (event.event === "translation_completed" || event.event === "translation_failed") {
            showToast(
                `${event.event === "translation_completed" ? "✓" : "✗"} Done: ${event.function || "classify"} (${event.dll})`,
                event.event === "translation_completed" ? "success" : "error"
            );
        }

        // Handle classification completion
        if (event.event === "classification_complete") {
            showToast(
                `Classified ${event.dll} → ${event.category}`,
                "success"
            );
            // Reload pipeline to show updated status
            loadPipelineProgress();
        }

        // Handle batch summary
        if (event.event === "batch_summary") {
            const b = event;
            showToast(
                `Batch ${event.dll}: ${b.success_count}/${b.total_functions} succeeded`,
                b.failure_count > 0 ? "warning" : "success"
            );
            // Reload pipeline to show updated status
            loadPipelineProgress();
        }

        // Handle LLM I/O events
        if (event.event === "llm_request") {
            console.log("[WS] LLM request:", event.dll, event.function, "prompt length:", event.prompt?.length);
            addLlmLogEntry(
                "request",
                event.dll,
                event.function,
                event.attempt,
                event.strategy,
                event.prompt
            );
        } else if (event.event === "llm_response") {
            console.log("[WS] LLM response:", event.dll, event.function, "content length:", event.content?.length);
            addLlmLogEntry(
                "response",
                event.dll,
                event.function,
                event.attempt,
                event.strategy,
                event.content
            );
        } else if (event.event === "llm_call_failed") {
            console.warn("[WS] LLM call failed:", event.dll, event.function, event.error);
            addLlmLogEntry(
                "error",
                event.dll,
                event.function,
                event.attempt,
                event.strategy,
                `Error: ${event.error}`
            );
        }

        // Silently refresh dashboard data on any progress event
        loadDashboard();
    }

    // ─── Zoom indicator display ─────────────────────────────────────────

    function updateZoomIndicator(scale) {
        const el = document.getElementById("zoom-indicator");
        if (el) {
            el.textContent = `${Math.round(scale * 100)}%`;
        }
    }

    // ─── Branch Cleanup (GC) ────────────────────────────────────────────

    async function loadGcCandidates() {
        const days = parseInt(document.getElementById("gc-days-input")?.value || "7", 10);
        try {
            const res = await API.gcCandidates(days);
            State.gcCandidates = res.candidates || [];
            State.gcSelectedBranches.clear();
            renderGcTable(State.gcCandidates);
            renderGcSummary(res);
        } catch (err) {
            showToast(`Failed to load GC candidates: ${err.message}`, "error");
        }
    }

    function renderGcSummary(res) {
        const panel = document.getElementById("gc-summary");
        const staleCount = document.getElementById("gc-stale-count");
        const recentCount = document.getElementById("gc-recent-count");
        const thresholdEl = document.getElementById("gc-threshold");
        const archiveBtn = document.getElementById("btn-archive-all-gc");

        if (!panel) return;

        panel.style.display = "";
        if (staleCount) staleCount.textContent = res.candidates?.length || 0;
        if (recentCount) recentCount.textContent = res.recent_count || 0;
        if (thresholdEl) thresholdEl.textContent = `${res.threshold_days ?? 7} days`;

        // Show archive button only when there are stale branches
        if (archiveBtn) {
            archiveBtn.style.display = (res.candidates?.length > 0) ? "" : "none";
        }
    }

    function renderGcTable(candidates) {
        const table = document.getElementById("gc-table");
        const tbody = document.getElementById("gc-table-body");
        const empty = document.getElementById("gc-empty");
        const selectAll = document.getElementById("gc-select-all");

        if (!tbody) return;

        if (candidates.length === 0) {
            if (table) table.style.display = "none";
            if (empty) empty.style.display = "flex";
            if (selectAll) selectAll.checked = false;
            State.gcSelectedBranches.clear();
            return;
        }

        if (table) table.style.display = "";
        if (empty) empty.style.display = "none";

        tbody.innerHTML = candidates.map(c => {
            const displayName = c.function
                ? `re/${c.dll}/${c.function}v${c.attempt}`
                : `re/${c.dll}v${c.attempt}`;
            const funcDisplay = c.function
                ? `<span style="color:var(--text-primary)">${escapeHtml(c.function)}</span>`
                : `<span style="color:var(--text-muted)">—</span>`;

            return `
                <tr>
                    <td class="gc-col-select">
                        <input type="checkbox" class="gc-branch-check" data-branch="${escapeHtml(displayName)}" aria-label="Select ${escapeHtml(displayName)}">
                    </td>
                    <td class="gc-col-name" title="${escapeHtml(displayName)}">${displayName}</td>
                    <td class="gc-col-dll">${escapeHtml(c.dll)}${funcDisplay}</td>
                    <td class="gc-col-attempt">v${c.attempt}</td>
                    <td class="gc-col-age">${c.days_old.toFixed(1)}d</td>
                    <td class="gc-col-last">${fmtTime(c.last_commit)}</td>
                    <td class="gc-col-status"><span class="gc-status-badge stale">Stale</span></td>
                </tr>
            `;
        }).join("");

        // Wire up checkboxes
        tbody.querySelectorAll(".gc-branch-check").forEach(cb => {
            cb.addEventListener("change", () => {
                const branch = cb.dataset.branch;
                if (cb.checked) {
                    State.gcSelectedBranches.add(branch);
                } else {
                    State.gcSelectedBranches.delete(branch);
                }
            });
        });

        // Select-all checkbox
        if (selectAll) {
            selectAll.checked = false;
            selectAll.addEventListener("change", () => {
                const checked = selectAll.checked;
                tbody.querySelectorAll(".gc-branch-check").forEach(cb => {
                    cb.checked = checked;
                    const branch = cb.dataset.branch;
                    if (checked) {
                        State.gcSelectedBranches.add(branch);
                    } else {
                        State.gcSelectedBranches.delete(branch);
                    }
                });
            });
        }
    }

    async function archiveSelectedGc() {
        const branches = Array.from(State.gcSelectedBranches);
        if (branches.length === 0) {
            showToast("No branches selected for archival.", "warning");
            return;
        }

        const archiveBtn = document.getElementById("btn-archive-all-gc");
        archiveBtn.disabled = true;
        archiveBtn.textContent = "Archiving...";

        try {
            const res = await API.gcArchive(branches);
            showToast(
                `Archived ${res.archived} branch(es)${res.failed > 0 ? `, ${res.failed} failed` : ""}`,
                res.failed > 0 ? "warning" : "success"
            );
            // Reload candidates
            await loadGcCandidates();
        } catch (err) {
            showToast(`Archive failed: ${err.message}`, "error");
        } finally {
            archiveBtn.disabled = false;
            archiveBtn.textContent = "Archive All Stale";
        }
    }

    // ─── Zoom indicator display ─────────────────────────────────────────

    // ─── Initialization ─────────────────────────────────────────────────

    async function init() {
        setupEventListeners();

        // Initialize full-screen graph renderer
        State.graphRendererFull = new GraphRenderer(document.getElementById("graph-canvas-full"), {
            onZoomChange: updateZoomIndicator,
        });

        // Initialize WebSocket for live updates
        console.log("[WS] Initializing WebSocket manager");
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

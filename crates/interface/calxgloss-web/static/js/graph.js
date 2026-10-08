/* ==========================================================================
   Dependency graph view — canvas renderer with layered layout
   ========================================================================== */

import { State } from "./state.js";
import { STATUS_COLORS, STATUS_LABELS, KIND_LABELS, KIND_COLORS } from "./constants.js";
import { escapeHtml } from "./utils.js";

export class GraphRenderer {
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

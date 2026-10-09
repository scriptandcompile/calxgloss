/* ==========================================================================
   WebSocket manager — live pipeline events with auto-reconnect
   ========================================================================== */

export class WSManager {
    constructor(onMessage) {
        this.onMessage = onMessage;
        this.onOpen = null;
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
                this.onOpen?.();
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

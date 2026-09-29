//! WebSocket connection management for live progress streaming.
//!
//! Manages active WebSocket connections during a translation session and
//! fans out progress events to all connected clients.

use calxgloss_types::ProgressEvent;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

// ─── Session manager ───────────────────────────────────────────

/// Manages active WebSocket connections for a single translation session.
///
/// A `SessionManager` owns a broadcast loop that reads events from an
/// `mpsc::Receiver<ProgressEvent>` and fans them out to all registered
/// WebSocket clients.
///
/// # Construction
///
/// ```
/// let (manager, event_tx) = SessionManager::new();
/// // Feed events into event_tx
/// // Register clients via manager.register_client().await
/// ```
pub struct SessionManager {
    clients: std::sync::Arc<std::sync::Mutex<Vec<mpsc::Sender<ProgressEvent>>>>,
    commands: mpsc::Sender<WsCommand>,
}

enum WsCommand {
    Register(mpsc::Sender<ProgressEvent>),
}

impl SessionManager {
    /// Create a new session manager.
    ///
    /// Returns the manager and an event sender. Feed progress events into
    /// the sender and they will be distributed to all registered clients.
    pub fn new() -> (Self, mpsc::Sender<ProgressEvent>) {
        let (event_tx, event_rx) = mpsc::channel::<ProgressEvent>(128);
        let (cmd_tx, cmd_rx) = mpsc::channel::<WsCommand>(64);

        let clients = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let clients_clone = clients.clone();

        tokio::spawn(broadcast_loop(clients_clone, event_rx, cmd_rx));

        (
            Self {
                clients,
                commands: cmd_tx,
            },
            event_tx,
        )
    }

    /// Register a new WebSocket client.
    ///
    /// Returns a `(WebSocketHandler, client_sender)` pair:
    /// - `WebSocketHandler` — owns the event receiver and forwards to the WebSocket
    /// - `client_sender` — can be used to send events to this specific client
    pub async fn register_client(&self) -> (WebSocketHandler, mpsc::Sender<ProgressEvent>) {
        let (tx, rx) = mpsc::channel::<ProgressEvent>(128);
        let _ = self.commands.send(WsCommand::Register(tx.clone())).await;

        (WebSocketHandler::new(rx), tx)
    }

    pub fn client_count(&self) -> usize {
        let clients = self.clients.lock().unwrap();
        clients.len()
    }
}

async fn broadcast_loop(
    clients: std::sync::Arc<std::sync::Mutex<Vec<mpsc::Sender<ProgressEvent>>>>,
    mut events: mpsc::Receiver<ProgressEvent>,
    mut commands: mpsc::Receiver<WsCommand>,
) {
    loop {
        tokio::select! {
            Some(event) = events.recv() => {
                let mut clients = clients.lock().unwrap();
                clients.retain(|tx| !tx.is_closed());
                for tx in clients.iter() {
                    let _ = tx.send(event.clone()).await;
                }
            }
            Some(cmd) = commands.recv() => match cmd {
                WsCommand::Register(tx) => {
                    let mut clients = clients.lock().unwrap();
                    clients.push(tx);
                }
            }
            else => break,
        }
    }
}

// ─── WebSocket handler ─────────────────────────────────────────

/// Handles a single WebSocket client's event stream.
pub struct WebSocketHandler {
    rx: mpsc::Receiver<ProgressEvent>,
}

impl WebSocketHandler {
    fn new(rx: mpsc::Receiver<ProgressEvent>) -> Self {
        Self { rx }
    }

    /// Process the WebSocket connection.
    ///
    /// Reads events from the handler's receiver and writes them as JSON
    /// over the WebSocket. Returns when the client disconnects.
    ///
    /// # Arguments
    ///
    /// * `ws` — The axum `WebSocket` to send events over.
    pub async fn process(self, ws: axum::extract::WebSocket) {
        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut rx = self.rx;

        // Spawn a task that forwards events to the WebSocket
        let events_task = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let json = match serde_json::to_string(&event) {
                    Ok(json) => json,
                    Err(e) => {
                        warn!(error = %e, "Failed to serialize progress event");
                        continue;
                    }
                };
                if ws_tx.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        });

        // Spawn a task to handle incoming messages (keep-alive)
        let keepalive_task = tokio::spawn(async move {
            while let Some(Ok(_msg)) = ws_rx.next().await {
                // Currently no client-to-server messages
            }
        });

        // Wait for either task to finish (client disconnect)
        tokio::select! {
            _ = events_task => {},
            _ = keepalive_task => {},
        }

        info!("WebSocket client disconnected");
    }
}

// ─── Bridge ─────────────────────────────────────────────────────

/// Bridges pipeline progress events into the `mpsc` channel consumed by a [`SessionManager`].
///
/// The translation pipeline uses `calxgloss_types::TranslationEvents` (a broadcast channel).
/// This bridge converts those events into the mpsc channel format expected by
/// the `SessionManager`.
pub struct EventsBridge(mpsc::Sender<ProgressEvent>);

impl EventsBridge {
    /// Create a new bridge with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self(mpsc::channel(capacity).0)
    }

    /// Emit a progress event into the bridge.
    pub fn emit(&self, event: ProgressEvent) {
        let _ = self.0.try_send(event);
    }

    /// Get the underlying sender for passing to a session manager.
    pub fn into_sender(self) -> mpsc::Sender<ProgressEvent> {
        self.0
    }
}

impl From<mpsc::Sender<ProgressEvent>> for EventsBridge {
    fn from(tx: mpsc::Sender<ProgressEvent>) -> Self {
        Self(tx)
    }
}

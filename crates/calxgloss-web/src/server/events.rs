//! WebSocket connection management for live progress streaming.

use calxgloss_types::ProgressEvent;
use futures_util::{StreamExt, SinkExt};
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{info, warn};
use axum::extract::ws::WebSocket;

#[derive(Clone)]
pub struct SessionManager {
    clients: std::sync::Arc<Mutex<Vec<mpsc::Sender<ProgressEvent>>>>,
    commands: mpsc::Sender<WsCommand>,
}

enum WsCommand {
    Register(mpsc::Sender<ProgressEvent>),
}

impl SessionManager {
    pub fn new() -> (Self, mpsc::Sender<ProgressEvent>) {
        let (event_tx, event_rx) = mpsc::channel::<ProgressEvent>(128);
        let (cmd_tx, cmd_rx) = mpsc::channel::<WsCommand>(64);
        let clients = std::sync::Arc::new(Mutex::new(Vec::new()));
        let clients_clone = clients.clone();
        tokio::spawn(broadcast_loop(clients_clone, event_rx, cmd_rx));
        (
            Self { clients, commands: cmd_tx },
            event_tx,
        )
    }

    /// Create a session manager that drives the broadcast loop from an
    /// existing broadcast receiver (e.g., from `TranslationEvents`).
    ///
    /// This lets the translation pipeline's broadcast channel feed directly
    /// into the WebSocket server without an intermediate mpsc bridge.
    pub fn new_with_broadcast(
        receiver: broadcast::Receiver<ProgressEvent>,
    ) -> Self {
        let clients = std::sync::Arc::new(Mutex::new(Vec::new()));
        let (cmd_tx, cmd_rx) = mpsc::channel::<WsCommand>(64);
        let clients_clone = clients.clone();
        tokio::spawn(broadcast_loop_from_broadcast(
            clients_clone,
            receiver,
            cmd_rx,
        ));
        Self {
            clients,
            commands: cmd_tx,
        }
    }

    pub async fn register_client(&self) -> (WebSocketHandler, mpsc::Sender<ProgressEvent>) {
        let (tx, rx) = mpsc::channel::<ProgressEvent>(128);
        let _ = self.commands.send(WsCommand::Register(tx.clone())).await;
        (WebSocketHandler::new(rx), tx)
    }

    pub fn client_count(&self) -> usize {
        let clients = self.clients.blocking_lock();
        clients.len()
    }
}

async fn broadcast_loop(
    clients: std::sync::Arc<Mutex<Vec<mpsc::Sender<ProgressEvent>>>>,
    mut events: mpsc::Receiver<ProgressEvent>,
    mut commands: mpsc::Receiver<WsCommand>,
) {
    loop {
        tokio::select! {
            Some(event) = events.recv() => {
                let mut clients = clients.lock().await;
                clients.retain(|tx| !tx.is_closed());
                for tx in clients.iter() {
                    let _ = tx.send(event.clone()).await;
                }
            }
            Some(cmd) = commands.recv() => match cmd {
                WsCommand::Register(tx) => {
                    let mut clients = clients.lock().await;
                    clients.push(tx);
                }
            },
            else => break,
        }
    }
}

/// Broadcast loop that reads from a broadcast receiver instead of an mpsc
/// receiver. Used by `SessionManager::new_with_broadcast()` to connect
/// a `TranslationEvents` channel directly to the WebSocket server.
async fn broadcast_loop_from_broadcast(
    clients: std::sync::Arc<Mutex<Vec<mpsc::Sender<ProgressEvent>>>>,
    mut events: broadcast::Receiver<ProgressEvent>,
    mut commands: mpsc::Receiver<WsCommand>,
) {
    loop {
        tokio::select! {
            result = events.recv() => {
                match result {
                    Ok(event) => {
                        let mut clients = clients.lock().await;
                        clients.retain(|tx| !tx.is_closed());
                        for tx in clients.iter() {
                            let _ = tx.send(event.clone()).await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(lagged = n, "Event subscriber lagged; dropping events");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            Some(cmd) = commands.recv() => match cmd {
                WsCommand::Register(tx) => {
                    let mut clients = clients.lock().await;
                    clients.push(tx);
                }
            },
            else => break,
        }
    }
}

pub struct WebSocketHandler {
    rx: mpsc::Receiver<ProgressEvent>,
}

impl WebSocketHandler {
    fn new(rx: mpsc::Receiver<ProgressEvent>) -> Self {
        Self { rx }
    }

    pub async fn process(self, ws: WebSocket) {
        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut rx = self.rx;

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

        let keepalive_task = tokio::spawn(async move {
            while let Some(Ok(_msg)) = ws_rx.next().await {
                // Keep-alive
            }
        });

        tokio::select! {
            _ = events_task => {},
            _ = keepalive_task => {},
        }

        info!("WebSocket client disconnected");
    }
}

#[derive(Clone)]
pub struct EventsBridge(mpsc::Sender<ProgressEvent>);

impl EventsBridge {
    pub fn new(capacity: usize) -> Self {
        Self(mpsc::channel(capacity).0)
    }

    pub fn emit(&self, event: ProgressEvent) {
        let _ = self.0.try_send(event);
    }

    pub fn into_sender(self) -> mpsc::Sender<ProgressEvent> {
        self.0
    }
}

impl From<mpsc::Sender<ProgressEvent>> for EventsBridge {
    fn from(tx: mpsc::Sender<ProgressEvent>) -> Self {
        Self(tx)
    }
}

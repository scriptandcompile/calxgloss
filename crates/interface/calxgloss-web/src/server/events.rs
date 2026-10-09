//! WebSocket connection management for live progress streaming.

use axum::extract::ws::WebSocket;
use calxgloss_types::{LiveUnitProgress, ProgressEvent};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, info, warn};

/// One message on the WebSocket wire.
///
/// `Event` forwards a raw pipeline event verbatim; `UnitPhase` carries the
/// unit's full live record (phase, phase history, tier, evidence) after the
/// server has applied the event, so the live view updates rows from the
/// pushed record instead of refetching `/api/progress/enhanced`. Untagged so
/// both variants serialize exactly as their inner type — pipeline events keep
/// their `event` tag, and the record envelope carries its own `"unit_phase"`
/// tag on the same field, which is how clients tell them apart.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum WsMessage {
    /// Raw pipeline event, forwarded verbatim.
    Event(ProgressEvent),
    /// Per-unit live-progress record pushed after the event was applied.
    UnitPhase(UnitPhaseMessage),
}

/// The `unit_phase` envelope: `{"event": "unit_phase", "unit": {...}}`.
#[derive(Debug, Clone, Serialize)]
pub struct UnitPhaseMessage {
    /// Wire discriminator — same `event` field pipeline events are tagged by.
    event: &'static str,
    /// The unit's full live record, phase history included.
    pub unit: LiveUnitProgress,
}

impl UnitPhaseMessage {
    /// Wrap one live record for the wire.
    pub fn new(unit: LiveUnitProgress) -> Self {
        Self {
            event: "unit_phase",
            unit,
        }
    }
}

/// Callback type for intercepting progress events before forwarding to clients.
type EventCallback =
    std::sync::Arc<std::sync::Mutex<Option<Box<dyn Fn(&ProgressEvent) + Send + Sync + 'static>>>>;

#[derive(Clone)]
pub struct SessionManager {
    clients: std::sync::Arc<Mutex<Vec<mpsc::Sender<WsMessage>>>>,
    commands: mpsc::Sender<WsCommand>,
    callback: EventCallback,
}

enum WsCommand {
    Register(mpsc::Sender<WsMessage>),
    /// Inject a *server-derived* message (e.g. a `unit_phase` record) into the
    /// broadcast, alongside the forwarded pipeline events. This is not a
    /// client→server command channel — clients still only send keep-alives;
    /// the spec's control path stays REST. Boxed: a record is far larger
    /// than a sender, and the command enum shouldn't pay for it.
    Send(Box<WsMessage>),
}

impl SessionManager {
    pub fn new() -> (Self, mpsc::Sender<ProgressEvent>) {
        let (event_tx, event_rx) = mpsc::channel::<ProgressEvent>(128);
        let (cmd_tx, cmd_rx) = mpsc::channel::<WsCommand>(64);
        let clients = std::sync::Arc::new(Mutex::new(Vec::new()));
        let clients_clone = clients.clone();
        tokio::spawn(broadcast_loop(clients_clone, event_rx, cmd_rx));
        (
            Self {
                clients,
                commands: cmd_tx,
                callback: std::sync::Arc::new(std::sync::Mutex::new(None)),
            },
            event_tx,
        )
    }

    /// Attach a callback that is invoked for every event before it is
    /// forwarded to WebSocket clients.  This lets the server update
    /// its own state (e.g. `ProgressState`) without duplicating the
    /// broadcast loop.
    pub fn set_event_callback<F>(&self, cb: F)
    where
        F: Fn(&ProgressEvent) + Send + Sync + 'static,
    {
        *self.callback.lock().unwrap() = Some(Box::new(cb));
    }

    /// Create a session manager that drives the broadcast loop from an
    /// existing broadcast receiver (e.g., from `TranslationEvents`).
    ///
    /// This lets the translation pipeline's broadcast channel feed directly
    /// into the WebSocket server without an intermediate mpsc bridge.
    pub fn new_with_broadcast(receiver: broadcast::Receiver<ProgressEvent>) -> Self {
        let clients = std::sync::Arc::new(Mutex::new(Vec::new()));
        let (cmd_tx, cmd_rx) = mpsc::channel::<WsCommand>(64);
        let clients_clone = clients.clone();
        let callback: EventCallback = std::sync::Arc::new(std::sync::Mutex::new(None));
        let callback_clone = callback.clone();
        tokio::spawn(broadcast_loop_from_broadcast(
            clients_clone,
            receiver,
            cmd_rx,
            callback_clone,
        ));
        Self {
            clients,
            commands: cmd_tx,
            callback,
        }
    }

    pub async fn register_client(&self) -> (WebSocketHandler, mpsc::Sender<WsMessage>) {
        let (tx, rx) = mpsc::channel::<WsMessage>(128);
        let _ = self.commands.send(WsCommand::Register(tx.clone())).await;
        // Async-safe count — `client_count()` blocks and must never run on a
        // runtime thread (it would panic under a DEBUG-enabled filter).
        let total = self.clients.lock().await.len();
        debug!("WS client registered, total clients: {total}");
        (WebSocketHandler::new(rx), tx)
    }

    /// Inject a server-derived message (e.g. a `unit_phase` record) to every
    /// connected client, ordered with the forwarded pipeline events because
    /// both flow through the same broadcast loop.
    pub async fn push(&self, msg: WsMessage) {
        if self
            .commands
            .send(WsCommand::Send(Box::new(msg)))
            .await
            .is_err()
        {
            debug!("Broadcast loop closed, dropping pushed WS message");
        }
    }

    pub fn client_count(&self) -> usize {
        let clients = self.clients.blocking_lock();
        clients.len()
    }

    /// Number of live WebSocket sessions, pruning senders whose client has
    /// disconnected. Async-safe for use from request handlers (unlike
    /// [`SessionManager::client_count`], which must never run on a runtime
    /// thread because it blocks).
    pub async fn connection_count(&self) -> usize {
        let mut clients = self.clients.lock().await;
        clients.retain(|tx| !tx.is_closed());
        clients.len()
    }
}

/// Prune disconnected clients and forward one message to the rest.
async fn forward_to_clients(
    clients: &std::sync::Arc<Mutex<Vec<mpsc::Sender<WsMessage>>>>,
    msg: WsMessage,
) {
    let mut clients = clients.lock().await;
    clients.retain(|tx| !tx.is_closed());
    for tx in clients.iter() {
        let _ = tx.send(msg.clone()).await;
    }
}

async fn broadcast_loop(
    clients: std::sync::Arc<Mutex<Vec<mpsc::Sender<WsMessage>>>>,
    mut events: mpsc::Receiver<ProgressEvent>,
    mut commands: mpsc::Receiver<WsCommand>,
) {
    loop {
        tokio::select! {
            Some(event) = events.recv() => {
                let mut clients = clients.lock().await;
                clients.retain(|tx| !tx.is_closed());
                for tx in clients.iter() {
                    let _ = tx.send(WsMessage::Event(event.clone())).await;
                }
            }
            Some(cmd) = commands.recv() => match cmd {
                WsCommand::Register(tx) => {
                    let mut clients = clients.lock().await;
                    clients.push(tx);
                }
                WsCommand::Send(msg) => forward_to_clients(&clients, *msg).await,
            },
            else => break,
        }
    }
}

/// Broadcast loop that reads from a broadcast receiver instead of an mpsc
/// receiver. Used by `SessionManager::new_with_broadcast()` to connect
/// a `TranslationEvents` channel directly to the WebSocket server.
async fn broadcast_loop_from_broadcast(
    clients: std::sync::Arc<Mutex<Vec<mpsc::Sender<WsMessage>>>>,
    mut events: broadcast::Receiver<ProgressEvent>,
    mut commands: mpsc::Receiver<WsCommand>,
    callback: EventCallback,
) {
    debug!("Broadcast loop started");
    loop {
        tokio::select! {
            result = events.recv() => {
                match result {
                    Ok(event) => {
                        // Invoke callback (updates ProgressState, etc.)
                        {
                            if let Some(cb) = callback.lock().unwrap().as_ref() {
                                cb(&event);
                            }
                        }

                        debug!("Broadcast loop received event: {}", event);
                        let mut clients = clients.lock().await;
                        clients.retain(|tx| !tx.is_closed());
                        if clients.is_empty() {
                            debug!("No WS clients connected, dropping event: {}", event);
                        } else {
                            debug!("Forwarding event {} to {} clients", event, clients.len());
                            for tx in clients.iter() {
                                let _ = tx.send(WsMessage::Event(event.clone())).await;
                            }
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
                    debug!("Client registered, total: {}", clients.len());
                }
                WsCommand::Send(msg) => forward_to_clients(&clients, *msg).await,
            },
            else => break,
        }
    }
}

pub struct WebSocketHandler {
    rx: mpsc::Receiver<WsMessage>,
}

impl WebSocketHandler {
    fn new(rx: mpsc::Receiver<WsMessage>) -> Self {
        Self { rx }
    }

    pub async fn process(self, ws: WebSocket) {
        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut rx = self.rx;

        let events_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let json = match serde_json::to_string(&msg) {
                    Ok(json) => json,
                    Err(e) => {
                        warn!(error = %e, "Failed to serialize WS message");
                        continue;
                    }
                };
                if ws_tx
                    .send(axum::extract::ws::Message::Text(json.into()))
                    .await
                    .is_err()
                {
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

//! A fake IAP relay for the tunnel and engine tests: a WebSocket server that speaks the relay v4 subprotocol (`gcp::relay`) in front of a
//! TCP target, checks the headers gcloud sends, keeps a session across a reconnect (resending what the client did not acknowledge) and
//! misbehaves on demand: refuse the handshake, close with a code, cut the socket after some bytes, or never announce the session. Like
//! `ssh::testing::proxy::Proxy` it owns a small tokio runtime, so tests stay synchronous. Test code only.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{http, Message};

use super::relay::{self, Frame, ACK_THRESHOLD, MAX_DATA_FRAME, ORIGIN, SUBPROTOCOL};

/// What the relay does with the next connection(s). `CloseAfter` and `DropAfter` fire once and then the relay bridges again, so a test
/// that sets one before opening sees exactly one incident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// A faithful relay.
    Bridge,
    /// The HTTP handshake is refused with this status.
    RefuseHandshake(u16),
    /// The WebSocket opens, and a Close frame with this code comes instead of the session announcement.
    CloseAtOpen(u16, &'static str),
    /// Once this many bytes have been relayed (both directions together), a Close frame with this code.
    CloseAfter(u64, u16, &'static str),
    /// Once this many bytes have been relayed, the socket is cut without a Close frame (a broken link).
    DropAfter(u64),
    /// The WebSocket opens and the relay says nothing, ever.
    NeverSucceed,
}

#[derive(Default)]
struct Stats {
    connects: AtomicUsize,
    reconnects: AtomicUsize,
    open: AtomicUsize,
}

/// One relay session: the TCP connection to the target, what the client sent and what we sent the client and it has not acknowledged.
struct Session {
    target: OwnedWriteHalf,
    /// Bytes received from the client in all (what a reconnect is told).
    received: u64,
    /// The last total we acknowledged to the client.
    acked: u64,
    /// Bytes sent to the client that it has not acknowledged, and the stream position of the first of them.
    window: VecDeque<u8>,
    window_base: u64,
    /// The current WebSocket's writer, when one is connected.
    client: Option<mpsc::UnboundedSender<Message>>,
    /// Bytes relayed in both directions, for `CloseAfter` and `DropAfter`.
    relayed: u64,
}

type Sessions = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<Session>>>>>;

struct Shared {
    token: String,
    target_port: u16,
    behaviour: Mutex<Behaviour>,
    stats: Stats,
    sessions: Sessions,
    next_sid: AtomicU64,
    headers: Mutex<Vec<(String, String)>>,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct FakeRelay {
    /// `ws://127.0.0.1:<port>/v4`, for `Endpoint::url_root`.
    pub url_root: String,
    shared: Arc<Shared>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl FakeRelay {
    /// A relay in front of `127.0.0.1:target_port` that accepts the bearer token `token`.
    pub fn start(target_port: u16, token: &str) -> FakeRelay {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("the fake relay's runtime");
        // Bound synchronously: `start` is also called from inside a test's own runtime, where `block_on` is not allowed.
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the fake relay");
        listener.set_nonblocking(true).expect("a non-blocking listener");
        let port = listener.local_addr().expect("relay address").port();
        let shared = Arc::new(Shared {
            token: token.to_string(),
            target_port,
            behaviour: Mutex::new(Behaviour::Bridge),
            stats: Stats::default(),
            sessions: Arc::default(),
            next_sid: AtomicU64::new(1),
            headers: Mutex::new(Vec::new()),
        });
        let serving = Arc::clone(&shared);
        runtime.spawn(async move {
            let listener = TcpListener::from_std(listener).expect("the listener joins the relay's runtime");
            while let Ok((stream, _)) = listener.accept().await {
                let shared = Arc::clone(&serving);
                tokio::spawn(async move {
                    shared.stats.open.fetch_add(1, Ordering::SeqCst);
                    let _ = serve(stream, &shared).await;
                    shared.stats.open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        FakeRelay { url_root: format!("ws://127.0.0.1:{port}/v4"), shared, runtime: Some(runtime) }
    }

    pub fn set(&self, behaviour: Behaviour) {
        *locked(&self.shared.behaviour) = behaviour;
    }

    /// Sessions started with `/v4/connect`.
    pub fn connects(&self) -> usize {
        self.shared.stats.connects.load(Ordering::SeqCst)
    }

    /// Sessions resumed with `/v4/reconnect`.
    pub fn reconnects(&self) -> usize {
        self.shared.stats.reconnects.load(Ordering::SeqCst)
    }

    /// WebSocket connections alive right now (counted from the TCP accept to the end of the handler).
    pub fn open_connections(&self) -> usize {
        self.shared.stats.open.load(Ordering::SeqCst)
    }

    /// The headers of the latest handshake, names in lower case.
    pub fn last_headers(&self) -> Vec<(String, String)> {
        locked(&self.shared.headers).clone()
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

fn close_frame(code: u16, reason: &str) -> Message {
    Message::Close(Some(CloseFrame { code: CloseCode::from(code), reason: reason.into() }))
}

fn error_response(status: u16) -> ErrorResponse {
    let mut response = ErrorResponse::new(None);
    *response.status_mut() = http::StatusCode::from_u16(status).expect("a valid status");
    response
}

/// The query parameters of a request path, decoded.
fn query_pairs(uri: &http::Uri) -> HashMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes()).into_owned().collect()
}

async fn serve(stream: TcpStream, shared: &Arc<Shared>) -> Result<(), ()> {
    let behaviour = *locked(&shared.behaviour);
    let seen = Arc::new(Mutex::new(None::<(String, HashMap<String, String>)>));
    let recorded = Arc::clone(&seen);
    let token = shared.token.clone();
    let headers_sink = Arc::new(Mutex::new(Vec::new()));
    let headers_out = Arc::clone(&headers_sink);
    let callback = move |request: &Request, mut response: Response| -> Result<Response, ErrorResponse> {
        let headers: Vec<(String, String)> =
            request.headers().iter().map(|(name, value)| (name.as_str().to_lowercase(), value.to_str().unwrap_or("").to_string())).collect();
        *locked(&headers_out) = headers.clone();
        *locked(&recorded) = Some((request.uri().path().to_string(), query_pairs(request.uri())));
        if let Behaviour::RefuseHandshake(status) = behaviour {
            return Err(error_response(status));
        }
        let header = |name: &str| headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str());
        if header("authorization") != Some(format!("Bearer {token}").as_str()) {
            return Err(error_response(401));
        }
        if header("origin") != Some(ORIGIN) {
            return Err(error_response(403));
        }
        if !header("sec-websocket-protocol").is_some_and(|protocols| protocols.split(',').any(|protocol| protocol.trim() == SUBPROTOCOL)) {
            return Err(error_response(400));
        }
        response.headers_mut().insert("sec-websocket-protocol", SUBPROTOCOL.parse().expect("a header value"));
        Ok(response)
    };
    let websocket = tokio_tungstenite::accept_hdr_async(stream, callback).await;
    *locked(&shared.headers) = locked(&headers_sink).clone();
    let websocket = websocket.map_err(|_| ())?;
    let (path, query) = locked(&seen).clone().ok_or(())?;
    let (mut sink, mut source) = websocket.split();

    match behaviour {
        Behaviour::NeverSucceed => {
            while let Some(Ok(_)) = source.next().await {}
            return Ok(());
        }
        Behaviour::CloseAtOpen(code, reason) => {
            let _ = sink.send(close_frame(code, reason)).await;
            let _ = sink.close().await;
            return Ok(());
        }
        _ => {}
    }

    let (to_client, mut outgoing) = mpsc::unbounded_channel::<Message>();
    let session = match path.as_str() {
        "/v4/connect" => {
            let target = TcpStream::connect((Ipv4Addr::LOCALHOST, shared.target_port)).await.map_err(|_| ())?;
            let (mut target_read, target_write) = target.into_split();
            let sid = format!("sid-{}", shared.next_sid.fetch_add(1, Ordering::SeqCst));
            let session = Arc::new(tokio::sync::Mutex::new(Session {
                target: target_write,
                received: 0,
                acked: 0,
                window: VecDeque::new(),
                window_base: 0,
                client: Some(to_client.clone()),
                relayed: 0,
            }));
            locked(&shared.sessions).insert(sid.clone(), Arc::clone(&session));
            shared.stats.connects.fetch_add(1, Ordering::SeqCst);
            // The target's output goes to whichever WebSocket is connected, and stays in the window until the client acknowledges it.
            let reading = Arc::clone(&session);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; MAX_DATA_FRAME];
                while let Ok(count) = target_read.read(&mut buffer).await {
                    if count == 0 {
                        break;
                    }
                    let mut session = reading.lock().await;
                    session.window.extend(&buffer[..count]);
                    session.relayed += count as u64;
                    if let Some(client) = &session.client {
                        let _ = client.send(Message::Binary(relay::encode_data(&buffer[..count]).into()));
                    }
                }
                // The target closed: the client learns it through a Close frame.
                let session = reading.lock().await;
                if let Some(client) = &session.client {
                    let _ = client.send(close_frame(1000, "target closed"));
                }
            });
            let mut frame = Vec::new();
            frame.extend(1u16.to_be_bytes());
            frame.extend((sid.len() as u32).to_be_bytes());
            frame.extend_from_slice(sid.as_bytes());
            sink.send(Message::Binary(frame.into())).await.map_err(|_| ())?;
            session
        }
        "/v4/reconnect" => {
            let sid = query.get("sid").cloned().unwrap_or_default();
            let ack: u64 = query.get("ack").and_then(|ack| ack.parse().ok()).unwrap_or(0);
            let Some(session) = locked(&shared.sessions).get(&sid).cloned() else {
                let _ = sink.send(close_frame(4010, "unknown session")).await;
                return Ok(());
            };
            shared.stats.reconnects.fetch_add(1, Ordering::SeqCst);
            let mut guard = session.lock().await;
            guard.client = Some(to_client.clone());
            let mut frame = Vec::new();
            frame.extend(2u16.to_be_bytes());
            frame.extend(guard.received.to_be_bytes());
            sink.send(Message::Binary(frame.into())).await.map_err(|_| ())?;
            // Everything after the client's ack goes again, in frames of the usual size.
            let skip = usize::try_from(ack.saturating_sub(guard.window_base)).unwrap_or(usize::MAX);
            let pending: Vec<u8> = guard.window.iter().skip(skip).copied().collect();
            for chunk in pending.chunks(MAX_DATA_FRAME) {
                sink.send(Message::Binary(relay::encode_data(chunk).into())).await.map_err(|_| ())?;
            }
            drop(guard);
            session
        }
        _ => {
            let _ = sink.send(close_frame(4040, "unknown path")).await;
            return Ok(());
        }
    };

    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            if sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // An incident (`CloseAfter`, `DropAfter`) is read live, so a test may arm one on a session that is already up; it fires once.
    let mut dropped = false;
    let mut closing = false;
    let relayed = session.lock().await.relayed;
    react(fire(shared, relayed), &to_client, &mut dropped, &mut closing);
    while !dropped && !closing {
        let Some(Ok(message)) = source.next().await else { break };
        let mut guard = session.lock().await;
        match message {
            Message::Binary(bytes) => match relay::decode(&bytes) {
                Ok(Frame::Data(data)) => {
                    if guard.target.write_all(&data).await.is_err() {
                        break;
                    }
                    guard.received += data.len() as u64;
                    guard.relayed += data.len() as u64;
                    if guard.received - guard.acked > ACK_THRESHOLD {
                        guard.acked = guard.received;
                        let _ = to_client.send(Message::Binary(relay::encode_ack(guard.received).into()));
                    }
                }
                Ok(Frame::Ack(acked)) => {
                    let drop_count = usize::try_from(acked.saturating_sub(guard.window_base)).unwrap_or(usize::MAX).min(guard.window.len());
                    guard.window.drain(..drop_count);
                    guard.window_base += drop_count as u64;
                }
                _ => {}
            },
            Message::Close(_) => break,
            _ => {}
        }
        let relayed = guard.relayed;
        drop(guard);
        react(fire(shared, relayed), &to_client, &mut dropped, &mut closing);
    }
    let mut guard = session.lock().await;
    if guard.client.as_ref().is_some_and(|client| client.same_channel(&to_client)) {
        guard.client = None;
    }
    drop(guard);
    if dropped {
        // Cut without a Close frame: abort the writer so nothing more goes out, and let the socket drop.
        writer.abort();
        drop(source);
    } else {
        drop(to_client);
        let _ = writer.await;
    }
    Ok(())
}

/// What a fired incident does to the connection: a Close frame goes out, or the socket is marked for cutting.
fn react(fired: Option<Behaviour>, to_client: &mpsc::UnboundedSender<Message>, dropped: &mut bool, closing: &mut bool) {
    match fired {
        Some(Behaviour::CloseAfter(_, code, reason)) => {
            let _ = to_client.send(close_frame(code, reason));
            *closing = true;
        }
        Some(_) => *dropped = true,
        None => {}
    }
}

/// Fires `CloseAfter`/`DropAfter` once the relayed bytes reach their threshold, whichever connection notices first, and puts the relay
/// back to `Bridge`.
fn fire(shared: &Shared, relayed: u64) -> Option<Behaviour> {
    let mut behaviour = locked(&shared.behaviour);
    match *behaviour {
        Behaviour::CloseAfter(after, ..) | Behaviour::DropAfter(after) if relayed >= after => {
            let fired = *behaviour;
            *behaviour = Behaviour::Bridge;
            Some(fired)
        }
        _ => None,
    }
}

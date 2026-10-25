//! An IAP TCP-forwarding tunnel as a byte stream: a WebSocket to Google's relay speaking `gcp::relay`'s frames, pumped into a duplex
//! pipe whose other end the SSH engine reads and writes like a socket. Ported from gcloud's `iap_tunnel_websocket.py` and
//! `iap_tunnel_websocket_helper.py` (Apache License 2.0, see `NOTICE.md`), including its reconnect rule: a WebSocket that fails without
//! a Close frame, or that the relay closes with code 4004 (reauthentication), is reconnected by session id with a fresh token and the
//! unacknowledged frames are sent again; any other Close frame is the relay ending the session, and so ends the stream.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::task::AbortHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{HeaderValue, AUTHORIZATION, ORIGIN as ORIGIN_HEADER, SEC_WEBSOCKET_PROTOCOL, USER_AGENT};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::auth::{AuthError, TokenSource};
use super::relay::{self, Bookkeeping, Endpoint, Frame, MAX_DATA_FRAME, MAX_UNSENT_FRAMES, ORIGIN, SUBPROTOCOL};
use crate::ssh::Secret;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// How much the engine may write ahead of the relay: gcloud queues `MAX_UNSENT_FRAMES` frames; here the pipe between the engine and the
/// pump holds that many frames' worth of bytes, and a full pipe holds the engine's writer back.
pub const DUPLEX_BUFFER: usize = MAX_UNSENT_FRAMES * MAX_DATA_FRAME;
/// How long a reconnect attempt waits for the relay's acknowledgement (gcloud's `MAX_WEBSOCKET_OPEN_WAIT_TIME_SEC`).
const OPEN_WAIT: Duration = Duration::from_secs(60);
/// The relay's "reauthentication required" close code: the one close that is reconnected, with a fresh token.
const REAUTH_CLOSE_CODE: u16 = 4004;

/// How reconnects are paced: gcloud's `Retryer(max_wait_ms=15 min, exponential_sleep_multiplier=1.1, wait_ceiling_ms=20 s)` from
/// `RECONNECT_INITIAL_SLEEP_MS`. Tests use a quicker one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Backoff {
    pub initial: Duration,
    pub multiplier: f64,
    pub ceiling: Duration,
    /// The whole reconnect may not take longer than this.
    pub budget: Duration,
}

impl Backoff {
    pub const GCLOUD: Backoff = Backoff { initial: Duration::from_millis(1500), multiplier: 1.1, ceiling: Duration::from_secs(20), budget: Duration::from_secs(15 * 60) };

    pub fn schedule(&self) -> Schedule {
        Schedule { next: self.initial, backoff: *self }
    }
}

/// The successive sleeps of one reconnect.
pub struct Schedule {
    next: Duration,
    backoff: Backoff,
}

impl Schedule {
    /// The next sleep, never over the ceiling.
    pub fn next(&mut self) -> Duration {
        let now = self.next.min(self.backoff.ceiling);
        let grown = (self.next.as_millis() as f64 * self.backoff.multiplier).round() as u64;
        self.next = Duration::from_millis(grown).min(self.backoff.ceiling);
        now
    }
}

/// Why a tunnel could not be opened, or (as the pump's own record) why it ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IapError {
    Credentials(AuthError),
    /// The relay refused the WebSocket handshake with this HTTP status (gcloud's "Handshake status 40x").
    Refused { status: u16 },
    /// The relay closed the WebSocket with this code before the session was up, or instead of it.
    Closed { code: u16, reason: String },
    /// The relay broke the subprotocol.
    Protocol(String),
    /// The connection failed below the subprotocol: TCP, TLS, or the WebSocket itself.
    Io(String),
    /// Fifteen minutes of reconnect attempts came to nothing.
    ReconnectExhausted,
}

impl fmt::Display for IapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IapError::Credentials(error) => write!(f, "{error}"),
            IapError::Refused { status } => write!(f, "the relay refused the WebSocket handshake with HTTP {status}"),
            IapError::Closed { code, reason } if reason.is_empty() => write!(f, "the relay closed the tunnel ({code})"),
            IapError::Closed { code, reason } => write!(f, "the relay closed the tunnel ({code}: {reason})"),
            IapError::Protocol(text) | IapError::Io(text) => f.write_str(text),
            IapError::ReconnectExhausted => f.write_str("the IAP tunnel could not be reconnected within 15 minutes"),
        }
    }
}

impl std::error::Error for IapError {}

/// An open tunnel: the engine's end of the pipe, and the guard that aborts the pump while the SSH handshake over it is still running.
pub struct Tunnel {
    pub stream: DuplexStream,
    pub guard: TunnelGuard,
}

/// Holds the pump's abort handle. Dropped before `release` (the handshake over the tunnel ran out of time), it aborts the pump: the pump's
/// end of the pipe goes with it and the engine's reader sees end-of-file; russh's task, which may be detached by then, ends on it.
pub struct TunnelGuard(Option<AbortHandle>);

impl TunnelGuard {
    /// The tunnel now belongs to the connection; the pump lives until the stream is dropped or the relay ends the session.
    pub fn release(mut self) {
        self.0 = None;
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        if let Some(pump) = self.0.take() {
            pump.abort();
        }
    }
}

/// Opens a tunnel to `endpoint` with gcloud's reconnect pacing. The caller bounds the call with its own timeout (the engine spends the
/// hop's connect budget on it); nothing here waits for a person.
pub async fn open(endpoint: Endpoint, tokens: Arc<dyn TokenSource>, account: Option<String>, user_agent: String) -> Result<Tunnel, IapError> {
    open_with(endpoint, tokens, account, user_agent, Backoff::GCLOUD).await
}

/// `open` with the reconnect pacing given.
pub async fn open_with(endpoint: Endpoint, tokens: Arc<dyn TokenSource>, account: Option<String>, user_agent: String, backoff: Backoff) -> Result<Tunnel, IapError> {
    let token = fetch_token(&tokens, account.as_deref()).await.map_err(IapError::Credentials)?;
    let mut socket = dial(&endpoint.connect_url(), &token, &user_agent).await?;
    let sid = match first_frame(&mut socket).await? {
        Frame::ConnectSuccess { sid } => sid,
        other => return Err(IapError::Protocol(format!("the relay answered the connect with {}", describe_frame(&other)))),
    };
    let (ours, theirs) = tokio::io::duplex(DUPLEX_BUFFER);
    let session = Session { endpoint, tokens, account, user_agent, sid, books: Bookkeeping::default(), backoff };
    let pump = tokio::spawn(pump(session, socket, theirs));
    Ok(Tunnel { stream: ours, guard: TunnelGuard(Some(pump.abort_handle())) })
}

/// The access token, fetched on the blocking pool: `TokenSource` is synchronous (it may read files and call the token service).
async fn fetch_token(tokens: &Arc<dyn TokenSource>, account: Option<&str>) -> Result<Secret, AuthError> {
    let tokens = Arc::clone(tokens);
    let account = account.map(str::to_string);
    match tokio::task::spawn_blocking(move || tokens.access_token(account.as_deref())).await {
        Ok(result) => result.map(|token| token.value),
        Err(_) => Err(AuthError::Network("the token request was interrupted".to_string())),
    }
}

/// The WebSocket handshake with the headers gcloud sends.
async fn dial(url: &str, token: &str, user_agent: &str) -> Result<Socket, IapError> {
    let mut request = url.into_client_request().map_err(|error| IapError::Protocol(format!("the relay URL is invalid: {error}")))?;
    let header = |value: &str| HeaderValue::from_str(value).map_err(|_| IapError::Protocol("a header value is not valid HTTP".to_string()));
    let mut authorization = header(&format!("Bearer {token}"))?;
    authorization.set_sensitive(true);
    let headers = request.headers_mut();
    headers.insert(AUTHORIZATION, authorization);
    headers.insert(ORIGIN_HEADER, header(ORIGIN)?);
    headers.insert(SEC_WEBSOCKET_PROTOCOL, header(SUBPROTOCOL)?);
    headers.insert(USER_AGENT, header(user_agent)?);
    match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _response)) => Ok(socket),
        Err(tungstenite::Error::Http(response)) => Err(IapError::Refused { status: response.status().as_u16() }),
        Err(error) => Err(IapError::Io(error.to_string())),
    }
}

/// The relay's first frame on a new WebSocket (the session announcement), or how the WebSocket ended instead.
async fn first_frame(socket: &mut Socket) -> Result<Frame, IapError> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Binary(bytes))) => return relay::decode(&bytes).map_err(|error| IapError::Protocol(error.to_string())),
            Some(Ok(Message::Close(frame))) => return Err(closed(frame)),
            Some(Ok(Message::Text(_))) => return Err(IapError::Protocol("the relay sent a text message".to_string())),
            Some(Ok(_)) => continue,
            Some(Err(error)) => return Err(IapError::Io(error.to_string())),
            None => return Err(IapError::Io("the relay ended the connection before announcing the session".to_string())),
        }
    }
}

fn closed(frame: Option<CloseFrame>) -> IapError {
    match frame {
        Some(frame) => IapError::Closed { code: u16::from(frame.code), reason: frame.reason.to_string() },
        None => IapError::Closed { code: 1005, reason: String::new() },
    }
}

fn describe_frame(frame: &Frame) -> &'static str {
    match frame {
        Frame::ConnectSuccess { .. } => "a session announcement",
        Frame::ReconnectSuccess { .. } => "a reconnect acknowledgement",
        Frame::Data(_) => "a data frame",
        Frame::Ack(_) => "an acknowledgement",
        Frame::Unknown(_) => "an unknown frame",
    }
}

/// One tunnel session across its WebSockets.
struct Session {
    endpoint: Endpoint,
    tokens: Arc<dyn TokenSource>,
    account: Option<String>,
    user_agent: String,
    sid: Vec<u8>,
    books: Bookkeeping,
    backoff: Backoff,
}

/// How one WebSocket of a session ended.
enum Outcome {
    /// The engine dropped its end of the pipe: the tunnel is done.
    LocalClosed,
    /// The relay ended the session, or broke the subprotocol: the tunnel is done.
    Fatal,
    /// The link broke, or the relay asked for a fresh token: connect again by session id.
    Reconnect,
}

/// Carries bytes between the pipe and the relay until the tunnel is done. Dropping `local` at the end is what tells the engine.
async fn pump(mut session: Session, mut socket: Socket, mut local: DuplexStream) {
    loop {
        match run_socket(&mut session, &mut socket, &mut local).await {
            Outcome::LocalClosed | Outcome::Fatal => {
                let _ = socket.close(None).await;
                return;
            }
            Outcome::Reconnect => match reconnect(&mut session).await {
                Ok(next) => socket = next,
                Err(_) => return,
            },
        }
    }
}

/// Pumps until the WebSocket fails or one side is done. A write the relay does not take, or a read that fails without a Close frame, is a
/// broken link; a Close frame is the relay's decision, reconnected only for 4004.
async fn run_socket(session: &mut Session, socket: &mut Socket, local: &mut DuplexStream) -> Outcome {
    let mut buffer = vec![0u8; MAX_DATA_FRAME];
    loop {
        tokio::select! {
            read = local.read(&mut buffer) => match read {
                Ok(0) | Err(_) => return Outcome::LocalClosed,
                Ok(count) => {
                    let chunk = buffer[..count].to_vec();
                    session.books.note_sent(chunk.clone());
                    if socket.send(Message::Binary(relay::encode_data(&chunk).into())).await.is_err() {
                        return Outcome::Reconnect;
                    }
                }
            },
            message = socket.next() => match message {
                Some(Ok(Message::Binary(bytes))) => match relay::decode(&bytes) {
                    Ok(Frame::Data(data)) => {
                        if local.write_all(&data).await.is_err() {
                            return Outcome::LocalClosed;
                        }
                        session.books.note_received(data.len());
                        if let Some(total) = session.books.ack_due() {
                            if socket.send(Message::Binary(relay::encode_ack(total).into())).await.is_err() {
                                return Outcome::Reconnect;
                            }
                            session.books.mark_acked(total);
                        }
                    }
                    Ok(Frame::Ack(ack)) => {
                        if session.books.confirm(ack).is_err() {
                            return Outcome::Fatal;
                        }
                    }
                    Ok(Frame::Unknown(_)) => {}
                    Ok(Frame::ConnectSuccess { .. } | Frame::ReconnectSuccess { .. }) | Err(_) => return Outcome::Fatal,
                },
                Some(Ok(Message::Close(frame))) => {
                    let code = frame.as_ref().map(|frame| u16::from(frame.code));
                    return if code == Some(REAUTH_CLOSE_CODE) { Outcome::Reconnect } else { Outcome::Fatal };
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Outcome::Reconnect,
            }
        }
    }
}

/// Connects again by session id, paced by the backoff, until the relay acknowledges or the budget is spent. A fresh token each time;
/// a credential error that needs a person ends the tunnel, a transient one is retried. The frames the relay had not confirmed are sent
/// again before the socket is handed back.
async fn reconnect(session: &mut Session) -> Result<Socket, IapError> {
    let started = Instant::now();
    let mut schedule = session.backoff.schedule();
    loop {
        let wait = schedule.next();
        if started.elapsed() + wait > session.backoff.budget {
            return Err(IapError::ReconnectExhausted);
        }
        tokio::time::sleep(wait).await;
        let token = match fetch_token(&session.tokens, session.account.as_deref()).await {
            Ok(token) => token,
            Err(error) if error.is_retryable() => continue,
            Err(error) => return Err(IapError::Credentials(error)),
        };
        let url = session.endpoint.reconnect_url(&session.sid, session.books.total_received());
        let Ok(mut socket) = dial(&url, &token, &session.user_agent).await else { continue };
        match tokio::time::timeout(OPEN_WAIT, first_frame(&mut socket)).await {
            Ok(Ok(Frame::ReconnectSuccess { ack })) => {
                if let Err(error) = session.books.confirm(ack) {
                    return Err(IapError::Protocol(error.to_string()));
                }
                let pending = session.books.take_unconfirmed();
                let mut failed = false;
                for chunk in &pending {
                    if socket.send(Message::Binary(relay::encode_data(chunk).into())).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                for chunk in pending {
                    session.books.requeue(chunk);
                }
                if failed {
                    continue;
                }
                return Ok(socket);
            }
            // A Close frame on a reconnect: the relay does not know the session any more (or asked for yet another token, which the next
            // attempt brings); anything else said instead of the acknowledgement is a broken relay.
            Ok(Err(IapError::Closed { code, .. })) if code == REAUTH_CLOSE_CODE => continue,
            Ok(Err(error @ IapError::Closed { .. })) => return Err(error),
            Ok(Ok(other)) => return Err(IapError::Protocol(format!("the relay answered the reconnect with {}", describe_frame(&other)))),
            Ok(Err(_)) | Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::{AuthError, StaticToken, Token, TokenSource};
    use crate::gcp::relay::Endpoint;
    use crate::gcp::testing::{Behaviour, FakeRelay};
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    const TOKEN: &str = "t0k";

    /// Quick retries, so a test waits milliseconds instead of gcloud's seconds.
    fn quick() -> Backoff {
        Backoff { initial: Duration::from_millis(20), multiplier: 1.1, ceiling: Duration::from_millis(100), budget: Duration::from_secs(10) }
    }

    fn endpoint(relay: &FakeRelay) -> Endpoint {
        Endpoint {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            port: 22,
            url_root: Some(relay.url_root.clone()),
        }
    }

    async fn open_quick(relay: &FakeRelay, tokens: Arc<dyn TokenSource>) -> Result<Tunnel, IapError> {
        open_with(endpoint(relay), tokens, Some("frank@retower.io".into()), "lunport-test".into(), quick()).await
    }

    /// A TCP server that echoes everything, on the test's runtime.
    async fn echo_server() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        port
    }

    /// A TCP server that keeps every byte it receives.
    async fn sink_server() -> (u16, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let sink = Arc::clone(&sink);
                tokio::spawn(async move {
                    let mut buffer = vec![0u8; 65536];
                    while let Ok(count) = socket.read(&mut buffer).await {
                        if count == 0 {
                            break;
                        }
                        sink.lock().unwrap().extend_from_slice(&buffer[..count]);
                    }
                });
            }
        });
        (port, seen)
    }

    /// A token source that answers from a script and counts its calls; the last answer repeats once the script runs out.
    struct Scripted {
        answers: Mutex<VecDeque<Result<String, AuthError>>>,
        calls: AtomicUsize,
    }

    impl Scripted {
        fn new(answers: Vec<Result<String, AuthError>>) -> Arc<Scripted> {
            Arc::new(Scripted { answers: Mutex::new(answers.into()), calls: AtomicUsize::new(0) })
        }
    }

    impl TokenSource for Scripted {
        fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().unwrap();
            let answer = if answers.len() > 1 { answers.pop_front().unwrap() } else { answers.front().cloned().unwrap() };
            answer.map(|value| Token { value: Zeroizing::new(value), account: account.unwrap_or("static@example.com").to_string() })
        }
    }

    async fn read_exact(stream: &mut tokio::io::DuplexStream, count: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; count];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buffer)).await.expect("the bytes arrive in time").expect("the stream is readable");
        buffer
    }

    /// Reads until the stream ends; `Some(bytes read)` when it ends within `limit`.
    async fn read_to_end_within(stream: &mut tokio::io::DuplexStream, limit: Duration) -> Option<usize> {
        let mut total = 0;
        let mut buffer = [0u8; 4096];
        let deadline = Instant::now() + limit;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, stream.read(&mut buffer)).await {
                Ok(Ok(0)) => return Some(total),
                Ok(Ok(count)) => total += count,
                Ok(Err(_)) => return Some(total),
                Err(_) => return None,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytes_flow_both_ways_through_the_relay() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        let mut tunnel = open_quick(&relay, Arc::new(StaticToken(TOKEN.into()))).await.expect("the tunnel opens");
        tunnel.stream.write_all(b"ping").await.unwrap();
        assert_eq!(read_exact(&mut tunnel.stream, 4).await, b"ping");
        let headers = relay.last_headers();
        let header = |name: &str| headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone());
        assert_eq!(header("origin").as_deref(), Some("bot:iap-tunneler"));
        assert_eq!(header("sec-websocket-protocol").as_deref(), Some("relay.tunnel.cloudproxy.app"));
        assert_eq!(header("authorization").as_deref(), Some("Bearer t0k"));
        assert_eq!(header("user-agent").as_deref(), Some("lunport-test"));
        assert_eq!((relay.connects(), relay.reconnects()), (1, 0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrong_token_is_refused_with_the_http_status() {
        let relay = FakeRelay::start(echo_server().await, "other");
        let error = open_quick(&relay, Arc::new(StaticToken(TOKEN.into()))).await.err().expect("refused");
        assert_eq!(error, IapError::Refused { status: 401 });
        relay.set(Behaviour::RefuseHandshake(403));
        let error = open_quick(&relay, Arc::new(StaticToken("other".into()))).await.err().expect("refused");
        assert_eq!(error, IapError::Refused { status: 403 });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_codes_4003_and_4033_end_the_open_with_the_code() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        for (code, reason) in [(4003u16, "failed to connect to backend"), (4033, "not authorized")] {
            relay.set(Behaviour::CloseAtOpen(code, reason));
            let error = open_quick(&relay, Arc::new(StaticToken(TOKEN.into()))).await.err().expect("closed");
            assert_eq!(error, IapError::Closed { code, reason: reason.to_string() });
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_that_never_sends_the_sid_times_out_under_the_callers_timeout() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::NeverSucceed);
        let result = tokio::time::timeout(Duration::from_secs(2), open_quick(&relay, Arc::new(StaticToken(TOKEN.into())))).await;
        assert!(result.is_err(), "the open must still be waiting when the caller's timeout passes");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_megabyte_written_across_a_drop_arrives_once_and_in_order() {
        let (port, seen) = sink_server().await;
        let relay = FakeRelay::start(port, TOKEN);
        relay.set(Behaviour::DropAfter(300_000));
        let mut tunnel = open_quick(&relay, Arc::new(StaticToken(TOKEN.into()))).await.expect("the tunnel opens");
        let pattern: Vec<u8> = (0..1024 * 1024u32).map(|index| (index % 251) as u8).collect();
        for chunk in pattern.chunks(8192) {
            tunnel.stream.write_all(chunk).await.expect("writes go through, held back while the relay is away");
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while seen.lock().unwrap().len() < pattern.len() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let received = seen.lock().unwrap().clone();
        assert_eq!(received.len(), pattern.len(), "every byte arrived exactly once");
        assert!(received == pattern, "the bytes arrived in order");
        assert_eq!(relay.reconnects(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_4004_close_is_reconnected_with_a_fresh_token() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::CloseAfter(0, 4004, "reauthentication required"));
        let tokens = Scripted::new(vec![Ok(TOKEN.into())]);
        let mut tunnel = open_quick(&relay, tokens.clone()).await.expect("the tunnel opens");
        tunnel.stream.write_all(b"after").await.unwrap();
        assert_eq!(read_exact(&mut tunnel.stream, 5).await, b"after");
        assert_eq!(relay.reconnects(), 1);
        assert!(tokens.calls.load(Ordering::SeqCst) >= 2, "a fresh token was fetched for the reconnect");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn any_other_close_frame_after_the_session_is_up_ends_the_tunnel_without_reconnecting() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::CloseAfter(0, 1000, "bye"));
        let mut tunnel = open_quick(&relay, Arc::new(StaticToken(TOKEN.into()))).await.expect("the tunnel opens");
        assert_eq!(read_to_end_within(&mut tunnel.stream, Duration::from_secs(2)).await, Some(0), "the stream ends, with nothing in it");
        assert_eq!(relay.reconnects(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transient_token_failure_during_reconnect_is_retried_and_invalid_grant_ends_the_tunnel() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::DropAfter(1));
        let tokens = Scripted::new(vec![
            Ok(TOKEN.into()),
            Err(AuthError::Network("timed out".into())),
            Err(AuthError::Http { status: 503 }),
            Ok(TOKEN.into()),
        ]);
        let mut tunnel = open_quick(&relay, tokens.clone()).await.expect("the tunnel opens");
        tunnel.stream.write_all(b"one").await.unwrap();
        assert_eq!(read_exact(&mut tunnel.stream, 3).await, b"one");
        assert_eq!(relay.reconnects(), 1);
        assert_eq!(tokens.calls.load(Ordering::SeqCst), 4, "two refused refreshes were retried before the one that worked");

        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::DropAfter(1));
        let tokens = Scripted::new(vec![Ok(TOKEN.into()), Err(AuthError::SignInExpired { account: "frank@retower.io".into() })]);
        let mut tunnel = open_quick(&relay, tokens.clone()).await.expect("the tunnel opens");
        tunnel.stream.write_all(b"two").await.unwrap();
        assert!(read_to_end_within(&mut tunnel.stream, Duration::from_secs(5)).await.is_some(), "an expired sign-in ends the stream");
        assert_eq!(relay.reconnects(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_guard_before_release_aborts_the_pump() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        let Tunnel { mut stream, guard } = open_quick(&relay, Arc::new(StaticToken(TOKEN.into()))).await.expect("the tunnel opens");
        drop(guard);
        assert_eq!(read_to_end_within(&mut stream, Duration::from_secs(2)).await, Some(0));
        let deadline = Instant::now() + Duration::from_secs(3);
        while relay.open_connections() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(relay.open_connections(), 0, "the relay saw the socket go");
    }

    #[test]
    fn the_production_backoff_is_gclouds() {
        assert_eq!(Backoff::GCLOUD.initial, Duration::from_millis(1500));
        assert_eq!(Backoff::GCLOUD.multiplier, 1.1);
        assert_eq!(Backoff::GCLOUD.ceiling, Duration::from_secs(20));
        assert_eq!(Backoff::GCLOUD.budget, Duration::from_secs(15 * 60));
        assert_eq!(DUPLEX_BUFFER, 5 * 16384);
        let mut schedule = Backoff::GCLOUD.schedule();
        assert_eq!(schedule.next(), Duration::from_millis(1500));
        assert_eq!(schedule.next(), Duration::from_millis(1650));
        for _ in 0..100 {
            schedule.next();
        }
        assert_eq!(schedule.next(), Duration::from_secs(20), "the sleep is capped");
    }
}

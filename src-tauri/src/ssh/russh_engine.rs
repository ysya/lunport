//! The russh-backed engine (own-ssh spec §6): the only file in the app that imports russh (`ssh/mod.rs` has a test that keeps it so).
//!
//! The engine owns a dedicated tokio runtime and drives it with `block_on`, so everything on the `SshEngine` side is synchronous. The
//! caller's references (`&dyn HostKeyPolicy`, `&dyn AuthSource`) never leave the connect call: the connection tasks russh spawns see only
//! `'static` data, and the one question they must ask the caller (is this host key trusted?) travels over a channel to the thread that
//! is blocked in `connect`, which answers it.
//!
//! What the phase-0 spike taught, as rules (spec §6.2, §6.3): a handshake or a login call that waits for the application stalls the
//! whole connection, so nothing here waits for a person inside a callback; every wait is bounded, and the wait for the server's answer
//! during the handshake and the login ends before the keepalive interval does (`stall_limit`); a failed or abandoned login drops the
//! connection instead of switching method on it; liveness is read from the connection's own state, never from an error variant.
//!
//! One of those rules cannot be kept everywhere, because the cause is in russh: it arms its keepalive timer at the server's version line
//! and re-arms it only when a packet arrives, so until the login is done a wait that outlasts the keepalive interval makes its loop spin
//! on the elapsed timer, a whole core until the wait ends (measured: 4.2 s of CPU in a 5 s wait at a 1 s interval). `stall_limit` ends
//! the waits on the server that the engine can end: the handshake and each login request (`none`, public key with its signature,
//! password, the start of keyboard-interactive). Not bounded by it: the TCP connect (the timer does not exist yet); the server's verdict
//! on keyboard-interactive answers, which keeps `prompt_wait` because a PAM module may wait for a push approval longer than any interval,
//! and which spins when it outlasts the interval; and the waits for a person. An answer to a keyboard-interactive round costs nothing,
//! because russh is parked inside the login call until the answers are written, but a password asked for while the connection is open
//! (the fallback after a refused key) spins like any other wait. Callers avoid that by asking a person before they connect, as the
//! engine does for a hop that starts with the password method.

use std::borrow::Cow;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use russh::client::{self, AuthResult, Config, Handle, Handler, KeyboardInteractiveAuthResponse, Msg};
use russh::client::DisconnectReason as RusshDisconnect;
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{AlgorithmKind, Channel, ChannelMsg, ChannelOpenFailure, ChannelReadHalf, ChannelWriteHalf, Disconnect, MethodKind, MethodSet, Preferred, Sig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

#[path = "russh_forward.rs"]
mod forwarding;

use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
use super::error::{AuthError, ConnectError, SessionError};
use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
use super::types::{
    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, IapTarget, Phase, Prompt, Pty, RsaHash, Secret,
    Target, Transport,
};
use crate::gcp::auth::{user_agent, FileStore, TokenSource};
use crate::gcp::iap::{self, IapError};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Knobs of the engine that are not part of a host record. The defaults are what the app uses; tests turn some of them down.
#[derive(Clone)]
pub struct EngineOptions {
    /// Bytes of shell output kept between the channel reader and the thread that reads the shell (see `ByteQueue`).
    pub shell_queue_bytes: usize,
    /// How long the person may take to answer one keyboard-interactive round and, separately, how long the server may then take over its
    /// verdict on the answers (one round can take up to twice this). `None` = 4 × the hop's connect timeout, at least 60 s (spec §6.2
    /// step 4).
    pub prompt_wait: Option<Duration>,
    /// Worker threads of the engine's runtime.
    pub worker_threads: usize,
    /// Where a Google Cloud IAP tunnel gets its access tokens: gcloud's credential files by default; `None` refuses every IAP hop with a
    /// sentence. Tests give a fixed token.
    pub gcp_tokens: Option<Arc<dyn TokenSource>>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions { shell_queue_bytes: 4 * 1024 * 1024, prompt_wait: None, worker_threads: 2, gcp_tokens: Some(Arc::new(FileStore::from_environment())) }
    }
}

impl fmt::Debug for EngineOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineOptions")
            .field("shell_queue_bytes", &self.shell_queue_bytes)
            .field("prompt_wait", &self.prompt_wait)
            .field("worker_threads", &self.worker_threads)
            .field("gcp_tokens", &self.gcp_tokens.as_ref().map(|_| "<token source>"))
            .finish()
    }
}

impl EngineOptions {
    /// The time a person gets to answer one keyboard-interactive round.
    fn prompt_wait_for(&self, connect_timeout: Duration) -> Duration {
        self.prompt_wait.unwrap_or_else(|| connect_timeout.saturating_mul(4).max(Duration::from_secs(60)))
    }
}

/// The engine's runtime, shut down without waiting when the last owner lets go (dropping a runtime the normal way panics when it
/// happens on one of the runtime's own threads, which is where the last session can end up being dropped).
struct RuntimeOwner {
    runtime: Option<tokio::runtime::Runtime>,
    handle: tokio::runtime::Handle,
}

impl RuntimeOwner {
    fn handle(&self) -> tokio::runtime::Handle {
        self.handle.clone()
    }
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// The russh engine. Cheap to create (it starts a small runtime), meant to live as long as the app.
pub struct RusshEngine {
    runtime: Arc<RuntimeOwner>,
    options: EngineOptions,
}

impl Default for RusshEngine {
    fn default() -> Self {
        RusshEngine::new()
    }
}

impl RusshEngine {
    pub fn new() -> RusshEngine {
        RusshEngine::with_options(EngineOptions::default())
    }

    pub fn with_options(options: EngineOptions) -> RusshEngine {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(options.worker_threads.max(1))
            .thread_name("sshelter-ssh")
            .enable_all()
            .build()
            .expect("the SSH engine's runtime");
        let handle = runtime.handle().clone();
        RusshEngine { runtime: Arc::new(RuntimeOwner { runtime: Some(runtime), handle }), options }
    }

    /// Attaches no watcher (a hop that ends does not take the rest of the chain down): sessions come from `SshEngine::connect`, not from this.
    ///
    /// Connects every hop of `target` and logs in to each; the connection-level half of `SshEngine::connect`. Blocks the calling thread
    /// (never call it from inside an async task).
    pub fn connect_chain(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
        self.runtime.handle().block_on(connect_chain(target, host_keys, auth, &self.options))
    }
}

/// What the handler and the engine both need to know about one hop's connection.
struct HopShared {
    forwards: forwarding::Routes,
    /// The last host key the policy judged, and its verdict.
    observed: Mutex<Option<(HostKey, HostKeyVerdict)>>,
    /// Set by `Handler::disconnected`: how this hop's connection ended.
    ended: Mutex<Option<(DisconnectKind, String)>>,
    /// Set by `Handler::disconnected`, just before `ended` is written, when the connection ended because the server had no login method
    /// to offer (russh's `NoAuthMethod`).
    no_login_method: std::sync::atomic::AtomicBool,
    /// Banner text the server sent during the login, not yet handed to the auth source (`deliver_banners`); bounded, see `Banners`.
    banners: Mutex<Banners>,
    /// For a hop carried by a Google Cloud IAP tunnel: where the tunnel writes why it ended, which explains the connection's end better
    /// than the end-of-file russh then sees.
    tunnel: Mutex<Option<iap::TunnelEnd>>,
}

impl HopShared {
    fn new() -> Arc<HopShared> {
        Arc::new(HopShared {
            forwards: forwarding::Routes::default(),
            observed: Mutex::new(None),
            ended: Mutex::new(None),
            no_login_method: std::sync::atomic::AtomicBool::new(false),
            banners: Mutex::new(Banners::default()),
            tunnel: Mutex::new(None),
        })
    }

    /// Why the hop's IAP tunnel ended, when it was one and the relay or the credentials ended it.
    fn tunnel_ended(&self) -> Option<iap::IapError> {
        locked(&self.tunnel).as_ref().and_then(|record| record.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone())
    }
}

/// The most banner text kept for one hop's connection, in all, counting what was handed to the auth source already. A real banner is a
/// few lines; a server whose host key was confirmed can send a banner per login request, each up to 256 KiB (with compression a packet of
/// a few hundred bytes unpacks to that), for as long as the login lasts, and the broker and every session live in one process.
pub(crate) const MAX_BANNER_BYTES: usize = 64 * 1024;

/// The one line that ends the banner text when the server sent more than `MAX_BANNER_BYTES`.
pub(crate) const BANNER_CUT_NOTICE: &str = "[Lunport: the rest of the server's banner was dropped.]\n";

/// The banner text of one hop's login: what has arrived and has not been handed to the auth source yet, within `MAX_BANNER_BYTES`. The
/// banners that arrive between two deliveries are joined into one text, in the order they came, the way OpenSSH writes them one after the
/// other, so that a server that sends many small banners costs one call to `AuthSource::banner` per delivery.
#[derive(Default)]
struct Banners {
    /// Arrived and not delivered.
    pending: String,
    /// Bytes of the server's text accepted so far, delivered or not (the notice is not counted).
    accepted: usize,
    /// The accepted text ends in the middle of a line, so the notice needs a line break in front of it.
    line_open: bool,
    /// The cap was reached: the notice is in `pending` or was delivered, and everything that comes later is dropped.
    capped: bool,
}

impl Banners {
    /// Keeps `text`, up to the cap. The first banner that does not fit is cut on a character boundary, and `BANNER_CUT_NOTICE` follows it
    /// (on a line of its own); from then on nothing is kept.
    fn push(&mut self, text: &str) {
        if self.capped {
            return;
        }
        let room = MAX_BANNER_BYTES - self.accepted;
        let kept = if text.len() <= room {
            text
        } else {
            let mut end = room;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        };
        self.pending.push_str(kept);
        self.accepted += kept.len();
        if let Some(last) = kept.chars().next_back() {
            self.line_open = last != '\n';
        }
        if kept.len() < text.len() {
            if self.line_open {
                self.pending.push('\n');
            }
            self.pending.push_str(BANNER_CUT_NOTICE);
            self.capped = true;
        }
    }

    /// What arrived since the last call, if anything.
    fn take(&mut self) -> Option<String> {
        (!self.pending.is_empty()).then(|| std::mem::take(&mut self.pending))
    }
}

/// Hands the banner text the server has sent since the last delivery to the auth source, on the thread that called `connect` (the handler
/// runs on russh's task, where the caller's `&dyn AuthSource` cannot go). The lock is not held across the call.
fn deliver_banners(shared: &HopShared, auth: &dyn AuthSource, hop: &HopRef) {
    let text = locked(&shared.banners).take();
    if let Some(text) = text {
        auth.banner(hop, &text);
    }
}

/// A host key waiting for the policy's verdict, sent from the connection's task to the thread blocked in `connect`.
struct KeyQuestion {
    key: HostKey,
    reply: oneshot::Sender<HostKeyVerdict>,
}

struct EngineHandler {
    shared: Arc<HopShared>,
    questions: mpsc::UnboundedSender<KeyQuestion>,
}

/// The host key in the form a host record stores it, through the OpenSSH text form (only bytes cross between the two `ssh-key` generations).
fn host_key_of(key: &PublicKey) -> Option<HostKey> {
    HostKey::from_openssh_line(&key.to_openssh().ok()?)
}

impl Handler for EngineHandler {
    type Error = russh::Error;

    async fn server_channel_open_forwarded_tcpip(
        &mut self, channel: Channel<Msg>, _address: &str, port: u32,
        _origin: &str, _origin_port: u32, reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.shared.forwards.deliver(port, channel, reply);
        Ok(())
    }

    /// Never waits for a person (spec §6.2 step 3): the policy answers from its table through the connect thread, and `Unknown` or
    /// `Mismatch` makes the handshake fail with `UnknownKey`, which `connect` turns into `HostKeyUnknown` or `HostKeyMismatch`.
    ///
    /// russh asks once, in the first key exchange; a later one (the server's `RekeyLimit`, the client's 1 GiB or one hour) reuses that key
    /// and does not ask again (measured with russh 0.64.1). The question channel is closed once `connect` has returned, so a question
    /// asked later could only be answered `false`; `a_connection_survives_the_key_exchanges_the_server_asks_for` fails if an upgrade of
    /// russh ever does that.
    async fn check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else { return Ok(false) };
        let Some(host_key) = host_key_of(key) else { return Ok(false) };
        let (reply, answer) = oneshot::channel();
        if self.questions.send(KeyQuestion { key: host_key.clone(), reply }).is_err() {
            return Ok(false);
        }
        let Ok(verdict) = answer.await else { return Ok(false) };
        let trusted = verdict == HostKeyVerdict::Pinned;
        *locked(&self.shared.observed) = Some((host_key, verdict));
        Ok(trusted)
    }

    /// Keeps the banner for the connect thread, which hands it to the auth source (`deliver_banners`); nothing waits here.
    async fn auth_banner(&mut self, banner: &str, _session: &mut client::Session) -> Result<(), Self::Error> {
        locked(&self.shared.banners).push(banner);
        Ok(())
    }

    async fn disconnected(&mut self, reason: RusshDisconnect<Self::Error>) -> Result<(), Self::Error> {
        let record = match &reason {
            RusshDisconnect::ReceivedDisconnect(info) => (DisconnectKind::ClosedByPeer, format!("the server closed the connection: {}", info.message)),
            RusshDisconnect::Error(error) => classify_end(error),
        };
        if matches!(&reason, RusshDisconnect::Error(russh::Error::NoAuthMethod)) {
            self.shared.no_login_method.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        *locked(&self.shared.ended) = Some(record);
        match reason {
            RusshDisconnect::ReceivedDisconnect(_) => Ok(()),
            RusshDisconnect::Error(error) => Err(error),
        }
    }
}

/// How a connection that ended with this error is described. `Error::Disconnect` is what a disconnect we asked for looks like.
fn classify_end(error: &russh::Error) -> (DisconnectKind, String) {
    match error {
        russh::Error::KeepaliveTimeout => (DisconnectKind::KeepaliveTimeout, "the server stopped answering keepalive messages".to_string()),
        russh::Error::Disconnect => (DisconnectKind::ClosedByUs, "the connection was closed on our side".to_string()),
        russh::Error::HUP => (DisconnectKind::ClosedByPeer, "the server closed the connection".to_string()),
        russh::Error::IO(io) => (DisconnectKind::ConnectionLost, describe_io(io)),
        russh::Error::NoAuthMethod => (DisconnectKind::Other, "the server offers no login method".to_string()),
        other => (DisconnectKind::Other, other.to_string()),
    }
}

/// An I/O error as a short lowercase phrase: no OS error number, no leading capital, no final period (Windows' messages have one; the
/// sentences that contain the phrase bring their own).
fn describe_io(error: &std::io::Error) -> String {
    let text = error.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text).trim_end_matches('.');
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if first.is_ascii_uppercase() && second.is_ascii_lowercase() => format!("{}{}", first.to_ascii_lowercase(), &text[1..]),
        _ => text.to_string(),
    }
}

/// The host key algorithms offered to a server: russh's defaults without `ssh-rsa` (SHA-1), or, for a host with a pinned key, only that
/// key's family (spec §6.2 step 3, §6.3 a). An algorithm that is not in the default list (or that cannot be parsed) restricts nothing.
fn host_key_algorithms(pinned: Option<&HostKey>) -> Vec<Algorithm> {
    let defaults: Vec<Algorithm> = Preferred::DEFAULT.key.iter().filter(|algorithm| !matches!(algorithm, Algorithm::Rsa { hash: None })).cloned().collect();
    let Some(pinned) = pinned else { return defaults };
    let family: Vec<Algorithm> = match Algorithm::new(&pinned.algorithm) {
        Ok(Algorithm::Rsa { .. }) => vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }],
        Ok(other) => vec![other],
        Err(_) => return defaults,
    };
    let restricted: Vec<Algorithm> = defaults.iter().filter(|algorithm| family.contains(algorithm)).cloned().collect();
    if restricted.is_empty() {
        defaults
    } else {
        restricted
    }
}

/// How long the engine waits for the server to answer between its version line and the end of the login (the handshake, and each login
/// request): the connect timeout, but never more than three quarters of the keepalive interval, and at least a second.
///
/// russh arms its keepalive timer when its session loop starts, which is as soon as the server's version line is in, and does nothing with
/// it before the login is done. A packet from the server re-arms it, but once the interval has passed in silence the loop spins on the
/// elapsed timer until the next packet comes (client/mod.rs: the `keepalive_timer` branch of `run_inner` acts only on a logged-in
/// connection, and the timer is reset only after received data or a sent keepalive). Measured: about 4.2 s of CPU in a 6 s stall with a 2 s
/// interval. The defaults (15 s connect timeout, 30 s interval) never get there; a host record with a short interval or a long connect
/// timeout would. Not covered: the TCP connect (the timer does not exist yet) and the waits for a person (see the module rules). The host
/// key question and the signature are answered inside this limit, which is one more reason both must be quick; while they are asked,
/// russh's loop is parked, and it re-arms the timer when it moves on.
fn stall_limit(hop: &Hop) -> Duration {
    let budget = hop.connect_timeout.max(Duration::from_secs(1));
    if hop.keepalive_every.is_zero() {
        return budget;
    }
    budget.min(hop.keepalive_every.mul_f32(0.75).max(Duration::from_secs(1)))
}

/// russh's `Config` for one hop: keepalive from the host record (russh's own default is off), the host key list above, and nothing else
/// changed from russh's defaults (mlkem768x25519, curve25519, chacha20-poly1305, aes-gcm, strict kex, rsa-sha2).
fn client_config(hop: &Hop) -> Config {
    Config {
        keepalive_interval: (!hop.keepalive_every.is_zero()).then_some(hop.keepalive_every),
        keepalive_max: hop.keepalive_max_missed as usize,
        preferred: Preferred { key: Cow::Owned(host_key_algorithms(hop.pinned.as_ref())), ..Preferred::DEFAULT },
        ..Config::default()
    }
}

/// A hop that is connected and logged in.
pub struct Established {
    hop: HopRef,
    handle: Handle<EngineHandler>,
    shared: Arc<HopShared>,
}

/// The whole chain, outermost hop first. Owns every hop's `Handle`; a connection is closed by an explicit `disconnect()` on each hop,
/// because dropping the outer `Handle` ends nothing while an inner hop still holds one of its channels. It does not own the runtime that
/// drives it: the engine, the sessions made from it and the shells opened on those each keep the runtime alive, so it goes when the last
/// of them is dropped, and every hop ends then.
pub struct Connection {
    hops: Vec<Established>,
    /// Set when we are the ones closing it, so that the reason is ours whatever order the hops notice in.
    closing: AtomicBool,
    /// Why the connection ended, written down the first time anybody sees that it has. Our own disconnects follow and make every hop
    /// record `ClosedByUs`; this keeps the real cause.
    ended: Mutex<Option<DisconnectReason>>,
}

impl Connection {
    fn new() -> Connection {
        Connection { hops: Vec::new(), closing: AtomicBool::new(false), ended: Mutex::new(None) }
    }

    #[cfg(test)]
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// No hop's connection has ended, and nobody is closing it.
    pub fn is_open(&self) -> bool {
        !self.closing.load(Ordering::SeqCst) && self.hops.iter().all(|established| !established.handle.is_closed())
    }

    /// The hop the user asked for: the last one.
    fn destination(&self) -> Result<&Established, SessionError> {
        self.hops.last().ok_or(SessionError::Closed)
    }

    /// Why the connection ended, once it has: written down at the first look, so that what the teardown does afterwards cannot change it.
    fn reason(&self) -> Option<DisconnectReason> {
        let mut ended = locked(&self.ended);
        if ended.is_none() {
            *ended = self.find_reason();
        }
        ended.clone()
    }

    /// The record of the outermost hop that has one (a hop that dies after its carrier is gone records nothing useful, spec §6.2 step 2),
    /// else ours when we closed it. A hop whose `Handle` is closed but has not recorded anything yet is about to (russh closes the handle
    /// first and calls the handler a moment later), so it is given a short while before the fallback is used.
    fn find_reason(&self) -> Option<DisconnectReason> {
        let deadline = std::time::Instant::now() + Duration::from_millis(300);
        loop {
            for established in &self.hops {
                if let Some((kind, detail)) = locked(&established.shared.ended).clone() {
                    // A hop carried by an IAP tunnel that the relay or the credentials ended: the tunnel's sentence, not russh's end-of-file.
                    return Some(match established.shared.tunnel_ended() {
                        Some(reason) => DisconnectReason { hop: established.hop.clone(), kind: DisconnectKind::ConnectionLost, detail: reason.to_string() },
                        None => DisconnectReason { hop: established.hop.clone(), kind, detail },
                    });
                }
            }
            if self.closing.load(Ordering::SeqCst) {
                let hop = self.hops.last()?.hop.clone();
                return Some(DisconnectReason { hop, kind: DisconnectKind::ClosedByUs, detail: "the connection was closed on our side".to_string() });
            }
            let Some(closed) = self.hops.iter().find(|established| established.handle.is_closed()) else { return None };
            if std::time::Instant::now() >= deadline {
                return Some(DisconnectReason { hop: closed.hop.clone(), kind: DisconnectKind::ConnectionLost, detail: "the connection ended".to_string() });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Sends a disconnect on every hop, innermost first, and gives each a moment to leave before the next (outer) one goes.
    async fn disconnect_all(&self) {
        for established in self.hops.iter().rev() {
            let sent = tokio::time::timeout(Duration::from_secs(2), established.handle.disconnect(Disconnect::ByApplication, "", "en")).await;
            if matches!(sent, Ok(Ok(()))) {
                let gone = Instant::now() + Duration::from_millis(500);
                while !established.handle.is_closed() && Instant::now() < gone {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource, options: &EngineOptions) -> Result<Connection, ConnectError> {
    check_chain(target)?;
    let mut connection = Connection::new();
    for hop in &target.hops {
        match connect_one(hop, connection.hops.last(), host_keys, auth, options).await {
            Ok(established) => connection.hops.push(established),
            Err(error) => {
                connection.disconnect_all().await;
                return Err(error);
            }
        }
    }
    Ok(connection)
}

/// A chain needs at least one hop, may not list a host twice, and may put an IAP tunnel only first (a tunnel replaces the client's own
/// connection; a later hop is reached through the hop before it).
fn check_chain(target: &Target) -> Result<(), ConnectError> {
    if target.hops.is_empty() {
        return Err(ConnectError::BadJumpChain { why: "the target has no hosts".to_string() });
    }
    for (index, hop) in target.hops.iter().enumerate() {
        if index > 0 && matches!(hop.transport, Transport::GcpIap(_)) {
            return Err(ConnectError::BadJumpChain { why: format!("{} connects through Google Cloud IAP and cannot be reached through a jump host", hop.alias) });
        }
        if target.hops[..index].iter().any(|earlier| earlier.id == hop.id) {
            return Err(ConnectError::BadJumpChain { why: format!("{} appears twice", hop.alias) });
        }
    }
    Ok(())
}

async fn connect_one(
    hop: &Hop,
    via: Option<&Established>,
    host_keys: &dyn HostKeyPolicy,
    auth: &dyn AuthSource,
    options: &EngineOptions,
) -> Result<Established, ConnectError> {
    let reference = hop.reference();
    // A hop that starts with the password method asks for it before anything is connected: a person typing must not keep an
    // unauthenticated connection waiting (the server's login grace time runs, and russh spins while it idles).
    let password = (hop.auth == AuthMethod::Password).then(|| auth.password(&reference));
    let (mut handle, shared) = connect_hop(hop, via, host_keys, options).await?;
    let login = authenticate(hop, &mut handle, &shared, auth, password, options).await;
    deliver_banners(&shared, auth, &reference);
    login?;
    Ok(Established { hop: reference, handle, shared })
}

/// Connects one hop: over TCP for the first (or through a Google Cloud IAP tunnel, when its transport says so), through a direct-tcpip
/// channel of the hop in front of it for every later one (the way OpenSSH's ProxyJump does), and runs the handshake with the host key
/// check. TCP (or the tunnel) plus handshake share the hop's connect timeout.
async fn connect_hop(hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, options: &EngineOptions) -> Result<(Handle<EngineHandler>, Arc<HopShared>), ConnectError> {
    let reference = hop.reference();
    let shared = HopShared::new();
    let (questions_in, mut questions) = mpsc::unbounded_channel();
    let handler = EngineHandler { shared: Arc::clone(&shared), questions: questions_in };
    let config = Arc::new(client_config(hop));
    let phase = std::cell::Cell::new(Phase::Tcp);
    let attempt = async {
        match (via, &hop.transport) {
            (None, Transport::Tcp) => {
                let tcp = TcpStream::connect((hop.hostname.as_str(), hop.port)).await.map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
                if hop.nodelay {
                    let _ = tcp.set_nodelay(true);
                }
                let (tcp, closer) = SocketGuard::new(tcp).map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
                phase.set(Phase::Handshake);
                let handle = handshake(tcp, config, handler, &mut questions, host_keys, hop, &shared).await?;
                closer.release();
                Ok(handle)
            }
            // The tunnel is opened within the hop's budget (still `Phase::Tcp`: it stands in for the TCP connection), then the handshake
            // runs over it. The guard plays `SocketGuard`'s part: a handshake that runs out of time drops it, which aborts the tunnel's pump
            // and ends russh's detached task on end-of-file.
            (None, Transport::GcpIap(target)) => {
                let Some(tokens) = options.gcp_tokens.clone() else {
                    return Err(ConnectError::Tunnel { hop: reference.clone(), text: "Google Cloud credentials are not configured.".to_string(), code: None });
                };
                let tunnel = iap::open(target.endpoint(hop.port), tokens, target.account.clone(), user_agent())
                    .await
                    .map_err(|error| iap_failure(&reference, target, hop.port, error))?;
                *locked(&shared.tunnel) = Some(tunnel.end_record());
                let iap::Tunnel { stream, guard, .. } = tunnel;
                phase.set(Phase::Handshake);
                let handle = handshake(stream, config, handler, &mut questions, host_keys, hop, &shared).await?;
                guard.release();
                Ok(handle)
            }
            (Some(previous), _) => {
                let tunnel = previous
                    .handle
                    .channel_open_direct_tcpip(hop.hostname.as_str(), u32::from(hop.port), "127.0.0.1", 0)
                    .await
                    .map_err(|error| tunnel_error(&reference, &previous.hop, error))?;
                phase.set(Phase::Handshake);
                handshake(tunnel.into_stream(), config, handler, &mut questions, host_keys, hop, &shared).await
            }
        }
    };
    let budget = hop.connect_timeout.max(Duration::from_secs(1));
    match tokio::time::timeout(budget, attempt).await {
        Ok(result) => result.map(|handle| (handle, shared)),
        Err(_) => Err(ConnectError::Timeout { hop: reference, phase: phase.get() }),
    }
}

/// The SSH handshake over `stream`. While it runs, the handler's host key questions are answered here, on the caller's thread, from `host_keys`.
/// It is given `stall_limit(hop)`, not the whole connect timeout: russh's keepalive timer runs from the server's version line.
async fn handshake<R>(
    stream: R,
    config: Arc<Config>,
    handler: EngineHandler,
    questions: &mut mpsc::UnboundedReceiver<KeyQuestion>,
    host_keys: &dyn HostKeyPolicy,
    hop: &Hop,
    shared: &HopShared,
) -> Result<Handle<EngineHandler>, ConnectError>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let reference = hop.reference();
    let connecting = client::connect_stream(config, stream, handler);
    tokio::pin!(connecting);
    let stall = tokio::time::sleep(stall_limit(hop));
    tokio::pin!(stall);
    let connected = loop {
        tokio::select! {
            connected = &mut connecting => break connected,
            Some(question) = questions.recv() => {
                let verdict = host_keys.check(&reference, &question.key);
                let _ = question.reply.send(verdict);
            }
            () = &mut stall => return Err(ConnectError::Timeout { hop: reference.clone(), phase: Phase::Handshake }),
        }
    };
    connected.map_err(|error| handshake_error(&reference, shared, error))
}

/// The sentence for a Google Cloud IAP tunnel that could not be opened (design 2026-10-25, "Error texts"), as a `ConnectError::Tunnel`.
/// The account named is the target's; without one, gcloud's active account was used.
fn iap_failure(hop: &HopRef, target: &IapTarget, port: u16, error: IapError) -> ConnectError {
    let instance = target.instance.as_str();
    let account = target.account.as_deref().unwrap_or("the active gcloud account");
    let code = match &error {
        IapError::Closed { code, .. } => Some(*code),
        _ => None,
    };
    let text = match error {
        IapError::Refused { status } => format!(
            "Google Cloud IAP refused the tunnel to {instance} (HTTP {status}): check that {account} has roles/iap.tunnelResourceAccessor on the instance, and for production that a PAM grant is active."
        ),
        IapError::Closed { code: 4003, .. } => format!("IAP could not reach port {port} on {instance}: nothing is listening, or the firewall does not allow 35.235.240.0/20."),
        IapError::Closed { code: 4033, .. } => format!("{account} is not authorized to tunnel to {instance} through IAP."),
        IapError::Closed { code: 4004, .. } => "IAP asked for a fresh sign-in and the new token was refused.".to_string(),
        IapError::Closed { code, reason } if reason.is_empty() => format!("IAP closed the tunnel to {instance} ({code})."),
        IapError::Closed { code, reason } => format!("IAP closed the tunnel to {instance} ({code}: {reason})."),
        IapError::Credentials(error) => error.to_string(),
        IapError::Protocol(text) | IapError::Io(text) => format!("The IAP tunnel to {instance} could not be opened: {text}."),
        IapError::ReconnectExhausted => format!("The IAP tunnel to {instance} could not be reconnected within 15 minutes."),
    };
    ConnectError::Tunnel { hop: hop.clone(), text, code }
}

/// Why the jump host `via` could not give us a connection to `hop`: it refused to open the tunnel, or it is gone.
fn tunnel_error(hop: &HopRef, via: &HopRef, error: russh::Error) -> ConnectError {
    let reason = match error {
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => format!("{} could not connect to it", via.alias),
        russh::Error::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => format!("{} does not allow forwarding", via.alias),
        russh::Error::ChannelOpenFailure(other) => format!("{} refused to open the connection ({other:?})", via.alias),
        _ => format!("the connection to {} was lost", via.alias),
    };
    ConnectError::Unreachable { hop: hop.clone(), reason }
}

/// Turns what russh said about a failed handshake into a `ConnectError`. A rejected host key is the same `UnknownKey` whether the key
/// was unknown or changed; the handler wrote down which.
fn handshake_error(hop: &HopRef, shared: &HopShared, error: russh::Error) -> ConnectError {
    match error {
        russh::Error::UnknownKey => match locked(&shared.observed).clone() {
            Some((key, HostKeyVerdict::Unknown)) => ConnectError::HostKeyUnknown { hop: hop.clone(), key },
            Some((key, HostKeyVerdict::Mismatch { pinned })) => ConnectError::HostKeyMismatch { hop: hop.clone(), key, pinned },
            _ => ConnectError::Protocol { hop: hop.clone(), text: "the server's host key was rejected".to_string() },
        },
        russh::Error::NoCommonAlgo { kind: AlgorithmKind::Key, ours, theirs } => ConnectError::NoCommonHostKeyAlgorithm { hop: hop.clone(), ours, theirs },
        russh::Error::IO(io) => ConnectError::Unreachable { hop: hop.clone(), reason: describe_io(&io) },
        russh::Error::HUP | russh::Error::Disconnect => ConnectError::Unreachable { hop: hop.clone(), reason: "the connection was closed during the handshake".to_string() },
        other => ConnectError::Protocol { hop: hop.clone(), text: other.to_string() },
    }
}

/// A second handle to the socket of a hop, held here while russh drives the first. `connect_stream` starts russh's session task as soon as
/// the server's version line is in. When the handshake then runs out of time, the future is dropped but the task is not (dropping the
/// handle of a task only detaches it), and a task that is still in its first key exchange never ends by itself: it keeps the socket open
/// and, once the keepalive interval has passed, loops on it without waiting. Dropped before `release`, the guard shuts the socket down,
/// the task's reads fail and it ends.
struct SocketGuard(Option<std::net::TcpStream>);

impl SocketGuard {
    /// `tcp` again, for russh, and the guard that holds the other handle to its socket.
    fn new(tcp: TcpStream) -> std::io::Result<(TcpStream, SocketGuard)> {
        let socket = tcp.into_std()?;
        let spare = socket.try_clone()?;
        Ok((TcpStream::from_std(socket)?, SocketGuard(Some(spare))))
    }

    /// The handshake is done: the connection belongs to russh, and the guard only lets go of its handle.
    fn release(mut self) {
        self.0 = None;
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Some(socket) = self.0.take() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// What to do about an RSA key, given `Handle::best_supported_rsa_hash`: `Some(Some(h))` = the server lists rsa-sha2 (best first),
/// `Some(None)` = it lists only `ssh-rsa`, `None` = it sent no `server-sig-algs` at all.
#[derive(Debug, PartialEq, Eq)]
enum RsaChoice {
    Use(HashAlg),
    Sha1Only,
}

fn choose_rsa_hash(best: Option<Option<HashAlg>>) -> RsaChoice {
    match best {
        Some(Some(hash)) => RsaChoice::Use(hash),
        Some(None) => RsaChoice::Sha1Only,
        // A server that never announced its signature algorithms: try SHA-256. One that does not know it refuses, and nothing was signed with SHA-1.
        None => RsaChoice::Use(HashAlg::Sha256),
    }
}

/// russh's `Signer` over the caller's `AuthSource`. `sign` is called right here, on the thread blocked in `connect`: it is quick by
/// contract, and the connection is waiting for the signature anyway.
struct EngineSigner<'a> {
    auth: &'a dyn AuthSource,
    key_id: &'a str,
}

#[derive(Debug)]
enum SignerFailure {
    /// russh's session is gone.
    SessionEnded,
    /// An RSA signature with SHA-1 was asked for: refused, `sign` was not called (spec §6.3 b).
    Sha1Refused,
    Auth(AuthError),
}

impl From<russh::SendError> for SignerFailure {
    fn from(_: russh::SendError) -> SignerFailure {
        SignerFailure::SessionEnded
    }
}

impl russh::Signer for EngineSigner<'_> {
    type Error = SignerFailure;

    /// `to_sign` is the session id and the login request without a signature; russh wants it back unchanged with the signature
    /// (`u32 length || blob`) appended, and cuts the session id off itself.
    async fn auth_sign(&mut self, key: &AgentIdentity, hash_alg: Option<HashAlg>, to_sign: Vec<u8>) -> Result<Vec<u8>, SignerFailure> {
        let rsa_hash = if key.public_key().algorithm().is_rsa() {
            match hash_alg {
                Some(HashAlg::Sha256) => Some(RsaHash::Sha256),
                Some(HashAlg::Sha512) => Some(RsaHash::Sha512),
                _ => return Err(SignerFailure::Sha1Refused),
            }
        } else {
            None
        };
        let signature = self.auth.sign(self.key_id, &to_sign, rsa_hash).map_err(SignerFailure::Auth)?;
        let mut signed = to_sign;
        signed.extend_from_slice(&(signature.0.len() as u32).to_be_bytes());
        signed.extend_from_slice(&signature.0);
        Ok(signed)
    }
}

fn method_kind(method: &AuthMethod) -> MethodKind {
    match method {
        AuthMethod::Key { .. } => MethodKind::PublicKey,
        AuthMethod::Password => MethodKind::Password,
        AuthMethod::Interactive => MethodKind::KeyboardInteractive,
    }
}

/// What one step of the login sequence came to, when it did not end the login.
enum Step {
    /// The server refused the method and listed the methods it would still take.
    Refused(MethodSet),
    /// The method was not tried (no key, no password, SHA-1 only): the server has not been asked anything.
    Skipped,
}

/// How long `authenticate` waits for the handler's record of how a connection ended: russh closes the `Handle` first and calls the handler a
/// moment later (spec §6.2 step 2).
const LOGIN_END_WAIT: Duration = Duration::from_secs(1);

/// What an answer to a login request that names no method to go on with came to.
enum EmptyAnswer {
    /// The server has no login method to offer: it said so, and russh then ended the connection with `NoAuthMethod`.
    NoLoginMethod,
    /// The connection ended some other way, or its end was not recorded in time: it was lost while we waited.
    Lost,
    /// Nothing ended the connection: a refusal like any other.
    Refusal,
}

/// russh answers a login request with "refused, and no method is left" in two cases that have to be told apart: the server really named no
/// method (russh passes that refusal on and then ends the connection with `NoAuthMethod`), and the connection died while we waited (the
/// reply channel closed). The handler's record of how the connection ended decides. It may not be written yet, so it is waited for, but
/// at most `wait`; if there is none by then, the connection is lost when it is `closed()` and a plain refusal when it is not.
async fn classify_empty_answer(shared: &HopShared, closed: impl Fn() -> bool, wait: Duration) -> EmptyAnswer {
    let deadline = Instant::now() + wait;
    loop {
        if locked(&shared.ended).is_some() {
            return if shared.no_login_method.load(std::sync::atomic::Ordering::SeqCst) { EmptyAnswer::NoLoginMethod } else { EmptyAnswer::Lost };
        }
        if Instant::now() >= deadline {
            return if closed() { EmptyAnswer::Lost } else { EmptyAnswer::Refusal };
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The failure for a server with no login method to offer, with what the methods that were skipped had to say.
fn no_login_method(hop: &HopRef, tried: Vec<AuthMethod>, mut reasons: Vec<String>) -> ConnectError {
    reasons.push("The server offers no login method.".to_string());
    ConnectError::AuthFailed { hop: hop.clone(), tried, reason: reasons.join(" "), password_wanted: false }
}

/// The failure for a connection that went away while the login was under way.
fn lost_during_login(hop: &HopRef) -> ConnectError {
    ConnectError::Unreachable { hop: hop.clone(), reason: "the connection was lost during login".to_string() }
}

/// Settles a refusal that names no method to go on with (see `classify_empty_answer`): the (empty) list for a plain refusal; the failure
/// when the server offers no login method (`tried` and `reasons` go into it) or the connection was lost while we waited.
async fn after_empty_refusal(
    shared: &HopShared,
    handle: &Handle<EngineHandler>,
    hop: &HopRef,
    tried: &mut Vec<AuthMethod>,
    reasons: &mut Vec<String>,
    remaining: MethodSet,
) -> Result<MethodSet, ConnectError> {
    match classify_empty_answer(shared, || handle.is_closed(), LOGIN_END_WAIT).await {
        EmptyAnswer::NoLoginMethod => Err(no_login_method(hop, std::mem::take(tried), std::mem::take(reasons))),
        EmptyAnswer::Lost => Err(lost_during_login(hop)),
        EmptyAnswer::Refusal => Ok(remaining),
    }
}

/// Logs in to a freshly connected hop. The methods of `hop.auth_sequence()` are tried in order, each only if the server still offers
/// it; a refusal moves to the next method on the same connection. A method that cannot be tried here is skipped, and then the server is
/// asked once what it does offer (`none`), so later methods are not sent blindly. Anything that is our fault (the signer failed, a
/// prompt was cancelled or ran late) or the server's silence abandons the login: the caller drops the connection (spec §6.2 step 4). Each
/// request is given `stall_limit` to be answered, except the reply to a keyboard-interactive round, which gets `prompt_wait`. That wait
/// and a call to `AuthSource::password` as a fallback (the connection is open while a person types) cost CPU when they outlast the
/// keepalive interval; the module rules say how much and why.
async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, shared: &HopShared, auth: &dyn AuthSource, mut prefetched_password: Option<Option<Secret>>, options: &EngineOptions) -> Result<(), ConnectError> {
    let reference = hop.reference();
    let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
    let timed_out = || ConnectError::Timeout { hop: reference.clone(), phase: Phase::Auth };
    let lost = |_: russh::Error| lost_during_login(&reference);
    let call_limit = stall_limit(hop);
    let prompt_wait = options.prompt_wait_for(hop.connect_timeout);
    let user = hop.user.as_str();
    let mut tried: Vec<AuthMethod> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut offered: Option<MethodSet> = None;

    for method in hop.auth_sequence() {
        if offered.as_ref().is_some_and(|offered| !offered.contains(&method_kind(&method))) {
            continue;
        }
        // A banner arrives with the server's answer to a login request; it is shown before the next prompt.
        deliver_banners(shared, auth, &reference);
        let step = match &method {
            AuthMethod::Key { key_id } => 'key: {
                let Some(line) = auth.public_key(key_id) else {
                    reasons.push(format!("The key {key_id} is not available on this computer."));
                    break 'key Step::Skipped;
                };
                let Ok(public) = PublicKey::from_openssh(&line) else {
                    reasons.push(format!("The key {key_id} is not a public key Lunport can use."));
                    break 'key Step::Skipped;
                };
                let hash = if public.algorithm().is_rsa() {
                    let best = tokio::time::timeout(call_limit, handle.best_supported_rsa_hash()).await.map_err(|_| timed_out())?.map_err(lost)?;
                    match choose_rsa_hash(best) {
                        RsaChoice::Use(hash) => Some(hash),
                        RsaChoice::Sha1Only => {
                            tried.push(method.clone());
                            reasons.push("The server accepts RSA keys only with SHA-1 signatures, which Lunport does not make.".to_string());
                            break 'key Step::Skipped;
                        }
                    }
                } else {
                    None
                };
                tried.push(method.clone());
                let mut signer = EngineSigner { auth, key_id };
                match tokio::time::timeout(call_limit, handle.authenticate_publickey_with(user, public, hash, &mut signer)).await {
                    Err(_) => return Err(timed_out()),
                    Ok(Err(SignerFailure::SessionEnded)) => return Err(lost(russh::Error::SendError)),
                    Ok(Err(SignerFailure::Sha1Refused)) => return Err(abandoned("an RSA signature with SHA-1 was asked for")),
                    Ok(Err(SignerFailure::Auth(error))) => return Err(abandoned(&error.to_string())),
                    Ok(Ok(AuthResult::Success)) => return Ok(()),
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) if remaining_methods.is_empty() => {
                        Step::Refused(after_empty_refusal(shared, handle, &reference, &mut tried, &mut reasons, remaining_methods).await?)
                    }
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) => Step::Refused(remaining_methods),
                }
            }
            AuthMethod::Password => 'password: {
                let password = match prefetched_password.take() {
                    Some(answer) => answer,
                    None => auth.password(&reference),
                };
                let Some(password) = password else {
                    reasons.push("No password was given.".to_string());
                    break 'password Step::Skipped;
                };
                tried.push(method.clone());
                match tokio::time::timeout(call_limit, handle.authenticate_password(user, password.as_str())).await {
                    Err(_) => return Err(timed_out()),
                    Ok(Err(error)) => return Err(lost(error)),
                    Ok(Ok(AuthResult::Success)) => return Ok(()),
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) if remaining_methods.is_empty() => {
                        Step::Refused(after_empty_refusal(shared, handle, &reference, &mut tried, &mut reasons, remaining_methods).await?)
                    }
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) => Step::Refused(remaining_methods),
                }
            }
            AuthMethod::Interactive => {
                tried.push(method.clone());
                let mut response = tokio::time::timeout(call_limit, handle.authenticate_keyboard_interactive_start(user, None::<String>))
                    .await
                    .map_err(|_| timed_out())?
                    .map_err(lost)?;
                loop {
                    match response {
                        KeyboardInteractiveAuthResponse::Success => return Ok(()),
                        KeyboardInteractiveAuthResponse::Failure { remaining_methods, .. } => break Step::Refused(remaining_methods),
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                            let answers = if prompts.is_empty() {
                                Vec::new()
                            } else {
                                let prompts: Vec<Prompt> = prompts.into_iter().map(|prompt| Prompt { text: prompt.prompt, echo: prompt.echo }).collect();
                                let deadline = std::time::Instant::now() + prompt_wait.min(LONGEST_TIMEOUT);
                                deliver_banners(shared, auth, &reference);
                                let Some(answers) = auth.interactive(&reference, &prompts, deadline) else { return Err(abandoned("the prompt was cancelled")) };
                                if std::time::Instant::now() > deadline {
                                    return Err(abandoned("the prompt was answered after its deadline"));
                                }
                                if answers.len() != prompts.len() {
                                    return Err(abandoned("the answers do not match the prompts"));
                                }
                                answers.iter().map(|answer| answer.to_string()).collect()
                            };
                            response = tokio::time::timeout(prompt_wait, handle.authenticate_keyboard_interactive_respond(answers))
                                .await
                                .map_err(|_| timed_out())?
                                .map_err(lost)?;
                        }
                    }
                }
            }
        };
        match step {
            Step::Refused(remaining) => offered = Some(remaining),
            Step::Skipped if offered.is_none() => {
                match tokio::time::timeout(call_limit, handle.authenticate_none(user)).await.map_err(|_| timed_out())?.map_err(lost)? {
                    AuthResult::Success => return Ok(()),
                    AuthResult::Failure { remaining_methods, .. } if remaining_methods.is_empty() => {
                        offered = Some(after_empty_refusal(shared, handle, &reference, &mut tried, &mut reasons, remaining_methods).await?);
                    }
                    AuthResult::Failure { remaining_methods, .. } => offered = Some(remaining_methods),
                }
            }
            Step::Skipped => {}
        }
    }
    // The server still offers the password method and no password was tried: one typed now could get in. The broker asks the person and
    // connects again with the hop's own method order, its `AuthSource::password` answering from memory at once (a person must not type
    // while a connection waits). Only a hop with no password method in its sequence, one that starts with keyboard-interactive, is
    // connected again with the password first: for a `publickey,password` server that would drop the key.
    let password_wanted = offered.as_ref().is_some_and(|offered| offered.contains(&MethodKind::Password)) && !tried.contains(&AuthMethod::Password);
    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" "), password_wanted })
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The session: what a caller does with a connection.

/// How long opening a channel, and the PTY and shell requests that follow it, may take.
const CHANNEL_SETUP_LIMIT: Duration = Duration::from_secs(15);
/// How long one write to a shell may wait for the connection's flow control.
const SHELL_WRITE_LIMIT: Duration = Duration::from_secs(30);
/// How long one request on a channel (a command, a window change, a close) may wait to be handed to the connection. Every request of every
/// channel goes through one queue of ten messages, and the connection stops emptying it while its peer does not read (the socket buffers
/// are full: a dead link that keepalive has not given up on yet), so without this bound the caller's thread would wait for as long as the
/// link stays dead. `Session::shell`'s and `Session::exec`'s other waits have their own bounds above.
const SEND_LIMIT: Duration = Duration::from_secs(5);
/// The longest `exec` timeout that is taken literally. Longer ones, up to `Duration::MAX`, mean "no timeout": the deadline is the present
/// plus the timeout, which the clock cannot hold for the largest durations (and thirty years is what tokio itself uses for "never").
const LONGEST_TIMEOUT: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 30);

/// A live connection: the chain, the runtime that drives it, and what a caller does with it. Dropping it closes the connection.
pub struct RusshSession {
    runtime: Arc<RuntimeOwner>,
    connection: Arc<Connection>,
    options: EngineOptions,
}

impl SshEngine for RusshEngine {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
        let connection = Arc::new(self.connect_chain(target, host_keys, auth)?);
        watch_connection(&self.runtime, Arc::clone(&connection));
        Ok(Box::new(RusshSession { runtime: Arc::clone(&self.runtime), connection, options: self.options.clone() }))
    }
}

/// How often the watcher looks at a connection.
const WATCH_EVERY: Duration = Duration::from_millis(100);

/// Watches a connection for as long as it lives. When one hop ends (the server dropped it, its keepalive ran out, the hop in front of it
/// went away) every other hop is disconnected too, so that a chain never lingers half open (spec §6.2 step 2). It stops when the
/// session is closed or dropped.
fn watch_connection(runtime: &RuntimeOwner, connection: Arc<Connection>) {
    runtime.handle().spawn(async move {
        loop {
            tokio::time::sleep(WATCH_EVERY).await;
            if connection.closing.load(Ordering::SeqCst) {
                return;
            }
            if connection.hops.iter().any(|established| established.handle.is_closed()) {
                // The first look at the reason is what keeps it real, so it comes before the teardown. It can sleep for a while (see
                // `find_reason`), which a worker of the runtime must not do: the blocking pool does it, and this task waits for it.
                let first_look = Arc::clone(&connection);
                let _ = tokio::task::spawn_blocking(move || first_look.reason()).await;
                connection.disconnect_all().await;
                return;
            }
        }
    });
}

impl Drop for RusshSession {
    /// Sends the disconnects. On a plain thread it waits for them (up to 3 s) before it returns, so that the server reads a disconnect
    /// message and not a dropped socket. Inside any tokio runtime context (a thread of the engine's runtime or of another one) blocking
    /// is not allowed, so a task does it, and the task owns the engine's runtime until it is done.
    fn drop(&mut self) {
        self.connection.closing.store(true, Ordering::SeqCst);
        let connection = Arc::clone(&self.connection);
        if tokio::runtime::Handle::try_current().is_err() {
            let _ = self.runtime.handle().block_on(async { tokio::time::timeout(Duration::from_secs(3), connection.disconnect_all()).await });
        } else {
            // Used inside the task, so it is moved into it: the runtime cannot go away under the disconnect when this session is its last owner.
            let runtime = Arc::clone(&self.runtime);
            self.runtime.handle().spawn(async move {
                connection.disconnect_all().await;
                drop(runtime);
            });
        }
    }
}

/// russh's errors on a call that needs the session, as the session's: a gone session is `Closed`, anything else is the server's answer.
fn channel_error(error: russh::Error) -> SessionError {
    match error {
        russh::Error::SendError | russh::Error::RecvError | russh::Error::Disconnect => SessionError::Closed,
        // What a write to a channel says when the connection behind it is gone ("channel closed"): the same as the calls above.
        russh::Error::IO(io) if io.kind() == std::io::ErrorKind::BrokenPipe => SessionError::Closed,
        other => SessionError::Channel(other.to_string()),
    }
}

/// One request on a channel, given `SEND_LIMIT` to be handed to the connection; `Timeout` when it was not.
async fn sent<T>(request: impl std::future::Future<Output = Result<T, russh::Error>>) -> Result<T, SessionError> {
    match tokio::time::timeout(SEND_LIMIT, request).await {
        Err(_) => Err(SessionError::Timeout),
        Ok(result) => result.map_err(channel_error),
    }
}

async fn open_channel(established: &Established, limit: Duration) -> Result<Channel<Msg>, SessionError> {
    match tokio::time::timeout(limit, established.handle.channel_open_session()).await {
        Err(_) => Err(SessionError::Channel("opening a channel timed out".to_string())),
        Ok(Ok(channel)) => Ok(channel),
        Ok(Err(error)) => Err(channel_error(error)),
    }
}

/// The signal's name without the `SIG` prefix.
fn signal_name(signal: &Sig) -> String {
    match signal {
        Sig::Custom(name) => name.clone(),
        other => format!("{other:?}"),
    }
}

impl Session for RusshSession {
    fn forward(&self, spec: &super::forward::ForwardSpec) -> Result<Box<dyn super::forward::Forwarder>, SessionError> {
        forwarding::start(self, spec)
    }

    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
        if !self.is_alive() {
            return Err(SessionError::Closed);
        }
        let destination = self.connection.destination()?;
        let handle = self.runtime.handle();
        handle.block_on(async {
            let channel = open_channel(destination, CHANNEL_SETUP_LIMIT).await?;
            let setup = async {
                channel.request_pty(true, &pty.term, u32::from(pty.cols), u32::from(pty.rows), 0, 0, &[]).await?;
                channel.request_shell(true).await
            };
            match tokio::time::timeout(CHANNEL_SETUP_LIMIT, setup).await {
                Err(_) => {
                    let _ = sent(channel.close()).await;
                    return Err(SessionError::Channel("starting the shell timed out".to_string()));
                }
                Ok(Err(error)) => return Err(channel_error(error)),
                Ok(Ok(())) => {}
            }
            let (read_half, write_half) = channel.split();
            let write_half = Arc::new(write_half);
            let (queue, exit) = (ByteQueue::new(self.options.shell_queue_bytes), ExitCell::new());
            let (closed_by_us, closed) = watch::channel(false);
            tokio::spawn(read_shell(read_half, Arc::clone(&write_half), Arc::clone(&queue), Arc::clone(&exit), closed));
            let input = RusshShellInput { write_half, runtime: Arc::clone(&self.runtime), closed_by_us };
            Ok(Box::new(QueuedShell::new(Box::new(input), queue, exit)) as Box<dyn ShellChannel>)
        })
    }

    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError> {
        if !self.is_alive() {
            return Err(SessionError::Closed);
        }
        let destination = self.connection.destination()?;
        self.runtime.handle().block_on(exec_on(destination, command, timeout, output_cap))
    }

    fn is_alive(&self) -> bool {
        self.connection.is_open()
    }

    fn disconnect_reason(&self) -> Option<DisconnectReason> {
        if self.is_alive() {
            None
        } else {
            self.connection.reason()
        }
    }

    fn close(&self) {
        if !self.connection.is_open() {
            let _ = self.connection.reason();
        }
        self.connection.closing.store(true, Ordering::SeqCst);
        self.runtime.handle().block_on(self.connection.disconnect_all());
    }
}

/// Runs one command on its own channel and reads the channel until it ends, the output reaches `output_cap` bytes or `timeout` is up.
///
/// `timeout` runs from the start of the call and bounds the wait for the command's output. The other waits have bounds of their own: the
/// channel is given `CHANNEL_SETUP_LIMIT` to open however short `timeout` is, so on a connection that does not answer a call can last that
/// long before it reports anything, and the requests that start the command, end its input and close the channel are given `SEND_LIMIT` each.
///
/// A command that has exited can still end as `TimedOut`, with the status it reported: a background job it started may hold its output,
/// and the channel stays open for as long as that lasts.
async fn exec_on(destination: &Established, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError> {
    let deadline = Instant::now() + timeout.min(LONGEST_TIMEOUT);
    let mut channel = open_channel(destination, CHANNEL_SETUP_LIMIT.max(timeout)).await?;
    // If the connection does not take the request, the channel stays open on the server and holds one of its sessions. A close is tried in
    // the background (it is bounded as well, and on a connection that does not take requests it may be given up too); the call does not wait.
    match sent(channel.exec(true, command)).await {
        Ok(()) => {}
        Err(SessionError::Timeout) => {
            tokio::spawn(async move {
                let _ = sent(channel.close()).await;
            });
            return Err(SessionError::Timeout);
        }
        Err(error) => return Err(error),
    }
    // The command's standard input is empty, as with `ssh host command < /dev/null`: one that reads it sees the end at once instead of
    // waiting for the timeout. On a connection that does not take the request in time the command reads on, and the timeout ends it.
    let _ = sent(channel.eof()).await;
    let mut result = ExecResult { ended: Ended::Disconnected, exit_code: None, signal: None, stdout: Vec::new(), stderr: Vec::new(), truncated: false };
    loop {
        let message = match tokio::time::timeout_at(deadline, channel.wait()).await {
            Err(_) => {
                let _ = sent(channel.close()).await;
                result.ended = Ended::TimedOut;
                return Ok(result);
            }
            Ok(None) => break,
            Ok(Some(message)) => message,
        };
        match message {
            ChannelMsg::Data { data } => {
                if !keep(&mut result.stdout, result.stderr.len(), &data, output_cap) {
                    return Ok(cut_off(&channel, result).await);
                }
            }
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                if !keep(&mut result.stderr, result.stdout.len(), &data, output_cap) {
                    return Ok(cut_off(&channel, result).await);
                }
            }
            ChannelMsg::ExitStatus { exit_status } => result.exit_code = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name: signal, .. } => result.signal = Some(signal_name(&signal)),
            ChannelMsg::Failure => {
                let _ = sent(channel.close()).await;
                return Err(SessionError::Channel("the server refused to run the command".to_string()));
            }
            _ => {}
        }
    }
    result.ended = if result.signal.is_some() {
        Ended::Signaled
    } else if result.exit_code.is_some() {
        Ended::Exited
    } else {
        Ended::Disconnected
    };
    Ok(result)
}

/// Appends as much of `data` to `stream` as the cap leaves room for (`other` is the length of the other stream); false when some of it did not fit.
fn keep(stream: &mut Vec<u8>, other: usize, data: &[u8], output_cap: usize) -> bool {
    let room = output_cap.saturating_sub(stream.len() + other);
    let fitting = room.min(data.len());
    stream.extend_from_slice(&data[..fitting]);
    fitting == data.len()
}

/// The output hit the cap: the channel is asked to close (the connection stays usable; on a connection that does not take the request
/// within `SEND_LIMIT` it is given up) and what was read is the result.
async fn cut_off(channel: &Channel<Msg>, mut result: ExecResult) -> ExecResult {
    let _ = sent(channel.close()).await;
    result.truncated = true;
    result.ended = Ended::Truncated;
    result.exit_code = None;
    result.signal = None;
    result
}

/// The write side of a shell, on the engine's runtime. It owns the runtime, not just a handle to it: a shell can outlive the session and
/// the engine that made it, and the tasks that read it and close its connection must still be able to run.
struct RusshShellInput {
    write_half: Arc<ChannelWriteHalf<Msg>>,
    runtime: Arc<RuntimeOwner>,
    /// Tells the reader task that the shell was closed from our side: russh never ends a channel's reads after the channel was closed
    /// locally (it ignores the server's close for it), so without this the reader would wait for ever.
    closed_by_us: watch::Sender<bool>,
}

impl ShellInput for RusshShellInput {
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
        // The timer is created inside the future: building it before `block_on` would need a runtime on this thread.
        match self.runtime.handle().block_on(async { tokio::time::timeout(SHELL_WRITE_LIMIT, self.write_half.data(bytes)).await }) {
            Err(_) => Err(SessionError::Timeout),
            Ok(result) => result.map_err(channel_error),
        }
    }

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
        self.runtime.handle().block_on(sent(self.write_half.window_change(u32::from(cols), u32::from(rows), 0, 0)))
    }

    fn close(&self) {
        let _ = self.closed_by_us.send(true);
        let _ = self.runtime.handle().block_on(async { tokio::time::timeout(Duration::from_secs(2), self.write_half.close()).await });
    }
}

impl Drop for RusshShellInput {
    /// A shell that is dropped without being closed is closed here; nothing blocks (this may run on one of the runtime's threads).
    fn drop(&mut self) {
        let _ = self.closed_by_us.send(true);
        let write_half = Arc::clone(&self.write_half);
        self.runtime.handle().spawn(async move {
            let _ = sent(write_half.close()).await;
        });
    }
}

/// The one task that reads a shell's channel (spec §6.3: every channel has a reader, or russh stalls the whole connection). It moves the
/// output into the queue without ever waiting for the consumer, and when the channel ends it records how, then closes the queue, in
/// that order, so a consumer that sees the end of the output finds the exit.
async fn read_shell(mut read_half: ChannelReadHalf, write_half: Arc<ChannelWriteHalf<Msg>>, queue: Arc<ByteQueue>, exit: Arc<ExitCell>, mut closed_by_us: watch::Receiver<bool>) {
    let (mut code, mut signal, mut refused) = (None, None, None);
    // The PTY request and the shell request both ask for a reply, and a server replies in the order of the requests: the first reply is
    // the PTY's.
    let mut replies = 0;
    loop {
        let message = tokio::select! {
            message = read_half.wait() => message,
            _ = closed_by_us.wait_for(|closed| *closed) => None,
        };
        let Some(message) = message else { break };
        match message {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                queue.push(data.to_vec());
            }
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name: name, .. } => signal = Some(signal_name(&name)),
            ChannelMsg::Success => replies += 1,
            ChannelMsg::Failure => {
                refused = Some(if replies == 0 { "the server refused to allocate a terminal (PTY)" } else { "the server refused to start a shell" });
                let _ = sent(write_half.close()).await;
                break;
            }
            _ => {}
        }
    }
    exit.set(match (signal, code, refused) {
        (Some(signal), _, _) => Exit::Signal(signal),
        (None, _, Some(refused)) => Exit::Refused(refused.to_string()),
        (None, Some(code), None) => Exit::Code(code),
        (None, None, None) => Exit::Disconnected,
    });
    queue.close();
}

/// A small SSH server in process, on russh's own server side, for the logins that a scratch OpenSSH cannot do because it has no PAM:
/// password and keyboard-interactive. It is a test fixture, not a model of any real server; the PAM job of the CI runs the same login
/// tests against OpenSSH. It lives in this file because russh is named here and nowhere else (the test in `ssh/mod.rs`).
#[cfg(test)]
pub(crate) mod toy_server {
    use std::borrow::Cow;
    use std::sync::Arc;

    use russh::keys::{PrivateKey, PublicKey};
    use russh::server::{self, Auth, Config, Msg, Response, Server as _, Session};
    use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
    use tokio::net::TcpListener;

    use crate::sync::slot_rules::test_keys;

    /// Who may log in, and what the server asks in keyboard-interactive.
    #[derive(Clone)]
    pub(crate) struct ToyLogin {
        pub user: String,
        pub password: String,
        pub prompt: String,
        /// The rounds of a keyboard-interactive login: each is a list of (prompt, the answer it wants), and an empty list is a request with
        /// no prompt at all (a "wait" round). `None` is one round that asks `prompt` and wants `password`.
        pub rounds: Option<Vec<Vec<(String, String)>>>,
    }

    impl ToyLogin {
        /// The rounds of keyboard-interactive, as the `rounds` field says them, with the single round of a plain login filled in.
        fn rounds_asked(&self) -> Vec<Vec<(String, String)>> {
            self.rounds.clone().unwrap_or_else(|| vec![vec![(self.prompt.clone(), self.password.clone())]])
        }
    }

    /// What a toy server does besides logging people in. The default is the plain server: no banner, every request is answered with success.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct ToyBehavior {
        /// How long the server thinks about the answers of a keyboard-interactive round before it says whether they are right.
        pub verdict_delay: std::time::Duration,
        /// Sent as the authentication banner as soon as the client asks for the login service, so it reaches the client before the server's
        /// answer to the first login request.
        pub banner: Option<String>,
        /// The request on a session channel that the server answers with a failure instead of a success.
        pub refuses: Option<Refusal>,
        /// The OpenSSH line of the one public key the server lets in, and with it the server wants that key first and then the password:
        /// OpenSSH's `AuthenticationMethods publickey,password`. The key is checked before anything else and answered with "partial success,
        /// the password next"; a password that comes before the key is refused with the key as the method to go on with, a wrong one after
        /// it with the password again (the key stays through); keyboard-interactive is no part of the chain and is refused. Without this the
        /// server takes the password or keyboard-interactive and refuses every key.
        pub key_then_password: Option<String>,
    }

    /// A request on a session channel that a toy server turns down.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Refusal {
        /// The request for a terminal (PTY).
        Pty,
        /// The request to start a shell.
        Shell,
    }

    /// The request that puts the prompts of one round to the client (no echo).
    fn ask(round: &[(String, String)]) -> Auth {
        Auth::Partial {
            name: Cow::Borrowed(""),
            instructions: Cow::Borrowed(""),
            prompts: Cow::Owned(round.iter().map(|(prompt, _)| (Cow::Owned(prompt.clone()), false)).collect()),
        }
    }

    /// The server's side of one client.
    struct Toy {
        login: Arc<ToyLogin>,
        behavior: Arc<ToyBehavior>,
        /// The round of keyboard-interactive that the client is answering. A `Toy` is made for each client, so the count is that client's own.
        round: usize,
        /// The key of `ToyBehavior::key_then_password`, parsed.
        required_key: Option<PublicKey>,
        /// The key of `required_key` has been through on this connection, so the password is what the server waits for.
        key_passed: bool,
    }

    impl Toy {
        /// Whether `key` is the key `key_then_password` asks for, offered by the user it asks for.
        fn is_the_required_key(&self, user: &str, key: &PublicKey) -> bool {
            user == self.login.user && self.required_key.as_ref().is_some_and(|required| required.key_data() == key.key_data())
        }

        /// The method that a server that wants a key and then a password lets the client go on with: the one it waits for.
        fn next_in_chain(&self) -> MethodSet {
            MethodSet::from(&[if self.key_passed { MethodKind::Password } else { MethodKind::PublicKey }][..])
        }
    }

    impl server::Handler for Toy {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            let right = user == self.login.user && password == self.login.password;
            if self.behavior.key_then_password.is_none() {
                return Ok(if right { Auth::Accept } else { Auth::reject() });
            }
            if self.key_passed && right {
                return Ok(Auth::Accept);
            }
            // No key before it: the key is still what the server waits for. A wrong password after it: the key stays through, as in OpenSSH,
            // and the server waits for the password again.
            Ok(Auth::Reject { proceed_with_methods: Some(self.next_in_chain()), partial_success: false })
        }

        /// The rounds of the login (one round that asks for the password, unless the `rounds` of `ToyLogin` say more): the first request puts the
        /// prompts of round 0, the right answers to a round are followed by the prompts of the next one and, after the last, by acceptance.
        /// A wrong answer, or the wrong number of them, rejects the login.
        async fn auth_keyboard_interactive<'a>(&'a mut self, user: &str, _submethods: &str, response: Option<Response<'a>>) -> Result<Auth, Self::Error> {
            if self.behavior.key_then_password.is_some() {
                // No part of the chain of key and password: refused, whatever the answers.
                return Ok(Auth::Reject { proceed_with_methods: Some(self.next_in_chain()), partial_success: false });
            }
            let rounds = self.login.rounds_asked();
            match response {
                None => {
                    self.round = 0;
                    Ok(ask(&rounds[0]))
                }
                Some(mut response) => {
                    if !self.behavior.verdict_delay.is_zero() {
                        tokio::time::sleep(self.behavior.verdict_delay).await;
                    }
                    let answered_right = rounds[self.round]
                        .iter()
                        .all(|(_, wanted)| response.next().is_some_and(|answer| answer[..] == *wanted.as_bytes()));
                    if user != self.login.user || !answered_right || response.next().is_some() {
                        return Ok(Auth::reject());
                    }
                    self.round += 1;
                    Ok(rounds.get(self.round).map_or(Auth::Accept, |next| ask(next)))
                }
            }
        }

        /// Every key is refused, except the one `key_then_password` names.
        async fn auth_publickey_offered(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
            Ok(if self.is_the_required_key(user, key) { Auth::Accept } else { Auth::reject() })
        }

        /// Called once russh has checked the signature of a key that `auth_publickey_offered` let through. The key of `key_then_password`
        /// is through, and the password is next (partial success).
        async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
            if !self.is_the_required_key(user, key) {
                return Ok(Auth::reject());
            }
            self.key_passed = true;
            Ok(Auth::Reject { proceed_with_methods: Some(self.next_in_chain()), partial_success: true })
        }

        /// The banner of `ToyBehavior`, if it has one: russh asks once per client, when the client requests the login service.
        async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
            Ok(self.behavior.banner.clone())
        }

        async fn channel_open_session(&mut self, _channel: Channel<Msg>, reply: server::ChannelOpenHandle, _session: &mut Session) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        /// The terminal is given, unless the server was told to refuse it.
        #[allow(clippy::too_many_arguments)]
        async fn pty_request(
            &mut self,
            channel: ChannelId,
            _term: &str,
            _col_width: u32,
            _row_height: u32,
            _pix_width: u32,
            _pix_height: u32,
            _modes: &[(Pty, u32)],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            if self.behavior.refuses == Some(Refusal::Pty) {
                session.channel_failure(channel)?;
            } else {
                session.channel_success(channel)?;
            }
            Ok(())
        }

        /// The shell starts (and says nothing), unless the server was told to refuse it.
        async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
            if self.behavior.refuses == Some(Refusal::Shell) {
                session.channel_failure(channel)?;
            } else {
                session.channel_success(channel)?;
            }
            Ok(())
        }

        /// Whatever the command, it prints `ok` and exits 0.
        async fn exec_request(&mut self, channel: ChannelId, _command: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            session.data(channel, b"ok\n".to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    struct Factory {
        login: Arc<ToyLogin>,
        behavior: Arc<ToyBehavior>,
        required_key: Option<PublicKey>,
    }

    impl server::Server for Factory {
        type Handler = Toy;

        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Toy {
            Toy {
                login: Arc::clone(&self.login),
                behavior: Arc::clone(&self.behavior),
                round: 0,
                required_key: self.required_key.clone(),
                key_passed: false,
            }
        }
    }

    /// The running server. Dropping it stops it.
    pub(crate) struct ToyServer {
        pub port: u16,
        runtime: Option<tokio::runtime::Runtime>,
    }

    impl ToyServer {
        pub(crate) fn start(login: ToyLogin) -> ToyServer {
            ToyServer::start_with(login, ToyBehavior::default())
        }

        /// A server that takes `verdict_delay` to say whether the answers of a keyboard-interactive round are right, as a PAM module does
        /// while it waits for a push approval.
        pub(crate) fn start_slow(login: ToyLogin, verdict_delay: std::time::Duration) -> ToyServer {
            ToyServer::start_with(login, ToyBehavior { verdict_delay, ..ToyBehavior::default() })
        }

        /// A server that behaves as `behavior` says.
        pub(crate) fn start_with(login: ToyLogin, behavior: ToyBehavior) -> ToyServer {
            let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("the toy server's runtime");
            let listener = runtime.block_on(TcpListener::bind(("127.0.0.1", 0))).expect("bind the toy server");
            let port = listener.local_addr().expect("the toy server's address").port();
            let host_key = PrivateKey::from_openssh(&test_keys::plain()).expect("the test key is an OpenSSH private key");
            let required_key = behavior
                .key_then_password
                .as_deref()
                .map(|line| PublicKey::from_openssh(line).expect("`key_then_password` is an OpenSSH public key line"));
            // What the server lists before the client has tried anything: with a chain of key and password, the key alone.
            let methods = if required_key.is_some() {
                MethodSet::from(&[MethodKind::PublicKey][..])
            } else {
                MethodSet::from(&[MethodKind::PublicKey, MethodKind::Password, MethodKind::KeyboardInteractive][..])
            };
            let config = Config {
                methods,
                auth_rejection_time: std::time::Duration::from_millis(10),
                auth_rejection_time_initial: Some(std::time::Duration::ZERO),
                keys: vec![host_key],
                ..Config::default()
            };
            let mut factory = Factory { login: Arc::new(login), behavior: Arc::new(behavior), required_key };
            runtime.spawn(async move {
                let _ = factory.run_on_socket(Arc::new(config), &listener).await;
            });
            ToyServer { port, runtime: Some(runtime) }
        }
    }

    impl Drop for ToyServer {
        fn drop(&mut self) {
            if let Some(runtime) = self.runtime.take() {
                runtime.shutdown_background();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use russh::keys::EcdsaCurve;
    use russh::Signer;

    use super::*;
    use crate::ssh::{AuthError, Signature};
    use crate::sync::slot_rules::test_keys;

    /// `assert_eq!` for long texts: on a difference it says where and how long the texts are, not the texts (these tests compare hundreds of
    /// KiB).
    fn assert_same_text(actual: &str, expected: &str) {
        if actual != expected {
            let at = actual.bytes().zip(expected.bytes()).position(|(a, b)| a != b).unwrap_or(actual.len().min(expected.len()));
            panic!("the texts differ at byte {at}: {} bytes, {} expected", actual.len(), expected.len());
        }
    }

    /// A server can send banners for as long as the login lasts, each up to 256 KiB: the text that is kept is bounded, what comes before
    /// the cap is exactly what the server sent, and one line says the rest was dropped.
    #[test]
    fn banner_text_is_kept_up_to_a_cap_and_one_line_says_the_rest_was_dropped() {
        let sent: Vec<String> = (0..100).map(|index| format!("{index:03} {}\n", "x".repeat(8 * 1024))).collect();
        let all = sent.concat();
        assert!(all.len() > 10 * MAX_BANNER_BYTES, "the test sends far more than the cap");

        let mut banners = Banners::default();
        for banner in &sent {
            banners.push(banner);
        }
        let kept = banners.take().expect("the text before the cap was kept");
        assert_same_text(&kept, &format!("{}\n{BANNER_CUT_NOTICE}", &all[..MAX_BANNER_BYTES])); // the first 64 KiB as sent, a line break, the one line
        assert_eq!(kept.matches(BANNER_CUT_NOTICE).count(), 1, "the notice appears once");

        // Whatever comes after the cap is dropped without being kept.
        banners.push(&"y".repeat(1 << 20));
        banners.push("one more\n");
        assert!(banners.take().is_none(), "nothing is kept after the notice");
        assert_eq!(banners.pending.capacity(), 0, "and nothing was allocated for it");
    }

    /// The cut is between two characters: a character that would straddle the cap is left out whole.
    #[test]
    fn the_banner_cap_cuts_between_characters() {
        // Three bytes each: the cap (65536 = 3 × 21845 + 1) falls inside the 21846th character.
        let mut banners = Banners::default();
        banners.push(&"€".repeat(30_000));
        let kept = banners.take().expect("the text before the cap was kept");
        let text = kept.strip_suffix(&format!("\n{BANNER_CUT_NOTICE}")).expect("the notice follows the cut text");
        assert_same_text(text, &"€".repeat(21_845));
        assert!(text.len() <= MAX_BANNER_BYTES);
    }

    /// A banner that ends exactly at the cap loses nothing and gets no notice; a cut at the end of a line needs no extra line break.
    #[test]
    fn a_banner_that_fits_the_cap_exactly_is_kept_whole_and_a_cut_at_a_line_end_adds_no_blank_line() {
        let line = format!("{}\n", "z".repeat(1023));
        let full = line.repeat(MAX_BANNER_BYTES / line.len());
        assert_eq!(full.len(), MAX_BANNER_BYTES);

        let mut banners = Banners::default();
        banners.push(&full);
        assert_same_text(&banners.take().expect("the banner"), &full); // exactly the cap: nothing was dropped, so nothing is said

        banners.push("more\n");
        assert_eq!(banners.take().as_deref(), Some(BANNER_CUT_NOTICE), "the first byte over the cap: the notice, on its own line");
        banners.push("and more\n");
        assert!(banners.take().is_none());

        let mut banners = Banners::default();
        banners.push(&format!("{full}more\n"));
        assert_same_text(&banners.take().expect("the cut text"), &format!("{full}{BANNER_CUT_NOTICE}")); // cut where a line ended: no blank line before the notice
    }

    /// The cap is for the whole login of a hop: text that was handed to the auth source already counts, so a server cannot get more through
    /// by sending a little before each delivery.
    #[test]
    fn text_that_was_handed_over_counts_against_the_cap() {
        let block = format!("{}\n", "a".repeat(40 * 1024 - 1));
        let mut banners = Banners::default();
        banners.push("");
        assert!(banners.take().is_none(), "an empty banner is nothing to hand over");

        banners.push(&block);
        let first = banners.take().expect("the first block");
        assert_same_text(&first, &block);

        banners.push(&block);
        let second = banners.take().expect("the part of the second block that still fits");
        let text = second.strip_suffix(&format!("\n{BANNER_CUT_NOTICE}")).expect("then the notice");
        assert_eq!(first.len() + text.len(), MAX_BANNER_BYTES, "the 64 KiB are used up across the two deliveries");

        banners.push(&block);
        assert!(banners.take().is_none(), "later deliveries get nothing");
    }

    #[test]
    fn io_errors_are_described_without_the_os_number_or_a_leading_capital() {
        let os = std::io::Error::new(std::io::ErrorKind::Other, "Connection refused (os error 61)");
        assert_eq!(describe_io(&os), "connection refused");
        let dns = std::io::Error::new(std::io::ErrorKind::Other, "DNS lookup failed");
        assert_eq!(describe_io(&dns), "DNS lookup failed", "an acronym keeps its capitals");
        let plain = std::io::Error::new(std::io::ErrorKind::Other, "failed to lookup address information");
        assert_eq!(describe_io(&plain), "failed to lookup address information");
        let windows = std::io::Error::new(std::io::ErrorKind::Other, "No connection could be made because the target machine actively refused it. (os error 10061)");
        assert_eq!(describe_io(&windows), "no connection could be made because the target machine actively refused it", "Windows ends its messages with a period");
    }

    #[test]
    fn a_connection_that_ended_is_described_by_the_error_that_ended_it() {
        assert_eq!(classify_end(&russh::Error::KeepaliveTimeout).0, DisconnectKind::KeepaliveTimeout);
        assert_eq!(classify_end(&russh::Error::Disconnect).0, DisconnectKind::ClosedByUs);
        assert_eq!(classify_end(&russh::Error::HUP).0, DisconnectKind::ClosedByPeer);
        let eof = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof");
        assert_eq!(classify_end(&russh::Error::IO(eof)), (DisconnectKind::ConnectionLost, "early eof".to_string()));
        assert_eq!(classify_end(&russh::Error::Kex).0, DisconnectKind::Other);
        assert_eq!(classify_end(&russh::Error::NoAuthMethod), (DisconnectKind::Other, "the server offers no login method".to_string()));
    }

    /// What stands on the other end of the question channel while the handler asks about a host key.
    enum Listener {
        /// The thread blocked in `connect`: it takes the question and answers it.
        Answers(HostKeyVerdict),
        /// It takes the question and drops the reply without answering.
        DropsTheReply,
        /// The channel is closed already (`connect` has returned).
        Gone,
    }

    /// Puts the question of `check_server_key` for an ed25519 host key to a handler and returns what it decided and what it wrote down.
    fn ask(listener: Listener) -> (bool, Option<(HostKey, HostKeyVerdict)>) {
        let key = PublicKey::from_openssh(test_keys::PLAIN_PUBLIC).expect("an ed25519 key");
        let offered = PublicKeyOrCertificate::from(key.clone());
        let shared = HopShared::new();
        let (questions_in, mut questions) = mpsc::unbounded_channel::<KeyQuestion>();
        let mut handler = EngineHandler { shared: Arc::clone(&shared), questions: questions_in };
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime");
        let decided = runtime.block_on(async {
            match listener {
                Listener::Gone => {
                    drop(questions);
                    handler.check_server_key(&offered).await
                }
                Listener::Answers(verdict) => {
                    let (decided, ()) = tokio::join!(handler.check_server_key(&offered), async {
                        let question = questions.recv().await.expect("the handler asks");
                        assert_eq!(Some(question.key), host_key_of(&key), "the question carries the key the server presented");
                        question.reply.send(verdict).expect("the handler waits for the answer");
                    });
                    decided
                }
                Listener::DropsTheReply => {
                    let (decided, ()) = tokio::join!(handler.check_server_key(&offered), async {
                        drop(questions.recv().await.expect("the handler asks"));
                    });
                    decided
                }
            }
        });
        let observed = locked(&shared.observed).clone();
        (decided.expect("the handler does not fail"), observed)
    }

    /// Spec §6.2 step 3: the host key question fails closed. Only a key the policy pinned is trusted; an unknown or a changed key is written
    /// down, so that `connect` can report it, and refused; a question nobody can answer is refused and writes nothing down.
    #[test]
    fn the_host_key_check_trusts_a_pinned_key_only_and_refuses_when_nobody_can_answer() {
        let host_key = HostKey::from_openssh_line(test_keys::PLAIN_PUBLIC).expect("a host key");
        let other = HostKey::from_openssh_line(test_keys::RSA_PUBLIC).expect("another host key");

        assert_eq!(ask(Listener::Answers(HostKeyVerdict::Pinned)), (true, Some((host_key.clone(), HostKeyVerdict::Pinned))));
        assert_eq!(ask(Listener::Answers(HostKeyVerdict::Unknown)), (false, Some((host_key.clone(), HostKeyVerdict::Unknown))));
        let mismatch = HostKeyVerdict::Mismatch { pinned: other };
        assert_eq!(ask(Listener::Answers(mismatch.clone())), (false, Some((host_key, mismatch))));
        assert_eq!(ask(Listener::Gone), (false, None), "nobody is listening");
        assert_eq!(ask(Listener::DropsTheReply), (false, None), "the question was taken and never answered");
    }

    /// The engine knows plain host keys only. A server that presents a certificate is refused without a question to the policy, and nothing
    /// is written down.
    #[test]
    fn a_host_certificate_is_refused_without_asking_anyone() {
        // From `ssh-keygen -s ca -h -I test-host -n example.com -V always:forever host.pub`; both keys were made for this test and thrown away.
        const HOST_CERTIFICATE: &str = "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAINwwxhX0B8jFpZdoffWQvh2jZLQBC3rtcOkq/ItAuYJkAAAAIBGWOXFF4bRDJKRTnjiI74NFyaSQ0K04eH7+r9XZrddGAAAAAAAAAAAAAAACAAAACXRlc3QtaG9zdAAAAA8AAAALZXhhbXBsZS5jb20AAAAAAAAAAP//////////AAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCsPdhbEvHHpY8XoMBbREyLQmLsbf9e/jlR7y85GB3N1AAAAFMAAAALc3NoLWVkMjU1MTkAAABAWgvqqRWT0FGqC0f+j5p8cl9SZfczv/2DDxpy4Hpp2DG0Tf2F9WJScvlbOK06A72x0tP0AHrTY/KqJG2Y2L18CQ== host";
        let certificate = russh::keys::Certificate::from_openssh(HOST_CERTIFICATE).expect("a host certificate");
        let shared = HopShared::new();
        let (questions_in, mut questions) = mpsc::unbounded_channel::<KeyQuestion>();
        let mut handler = EngineHandler { shared: Arc::clone(&shared), questions: questions_in };
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime");

        let decided = runtime.block_on(handler.check_server_key(&PublicKeyOrCertificate::from(certificate)));
        assert!(matches!(decided, Ok(false)), "{decided:?}");
        assert!(questions.try_recv().is_err(), "the policy was not asked");
        assert!(locked(&shared.observed).is_none());
    }

    /// What a login answer with no method left is taken for (the integration tests have the real thing; the timing is pinned here).
    #[test]
    fn an_empty_login_answer_is_told_from_a_lost_connection_by_the_recorded_end_and_that_is_waited_for() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().expect("a runtime");
        let wait = Duration::from_millis(600);
        let ended = |shared: &HopShared, no_login_method: bool| {
            shared.no_login_method.store(no_login_method, std::sync::atomic::Ordering::SeqCst);
            *locked(&shared.ended) = Some((DisconnectKind::Other, "an end".to_string()));
        };
        let classify = |shared: &HopShared, closed: bool| runtime.block_on(classify_empty_answer(shared, || closed, wait));

        // Already written down: no waiting.
        let shared = HopShared::new();
        ended(&shared, true);
        let started = std::time::Instant::now();
        assert!(matches!(classify(&shared, true), EmptyAnswer::NoLoginMethod));
        let shared = HopShared::new();
        ended(&shared, false);
        assert!(matches!(classify(&shared, true), EmptyAnswer::Lost), "any other end is a lost connection");
        assert!(started.elapsed() < Duration::from_millis(300), "a record that is there is not waited for");

        // Written down a moment later, as russh does it (the handle is closed first, the handler is called after): it is waited for.
        let shared = HopShared::new();
        let writer = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                ended(&shared, true);
            })
        };
        assert!(matches!(classify(&shared, true), EmptyAnswer::NoLoginMethod), "the end that shows up within the wait counts");
        writer.join().unwrap();

        // Never written down: after the wait it is the state of the handle that decides.
        let shared = HopShared::new();
        let started = std::time::Instant::now();
        assert!(matches!(classify(&shared, true), EmptyAnswer::Lost));
        assert!(started.elapsed() >= wait, "the wait is used up before the verdict");
        assert!(matches!(classify(&shared, false), EmptyAnswer::Refusal), "nothing ended an open connection: a plain refusal");
    }

    fn key(algorithm: &str) -> HostKey {
        HostKey { algorithm: algorithm.into(), public_key: vec![], fingerprint: String::new() }
    }

    #[test]
    fn the_host_key_list_has_no_ssh_rsa_and_a_pinned_key_narrows_it_to_its_family() {
        let defaults = host_key_algorithms(None);
        assert!(!defaults.contains(&Algorithm::Rsa { hash: None }), "ssh-rsa (SHA-1) is not offered: {defaults:?}");
        assert!(defaults.contains(&Algorithm::Ed25519) && defaults.contains(&Algorithm::Rsa { hash: Some(HashAlg::Sha512) }));

        assert_eq!(host_key_algorithms(Some(&key("ssh-ed25519"))), vec![Algorithm::Ed25519]);
        assert_eq!(host_key_algorithms(Some(&key("ecdsa-sha2-nistp384"))), vec![Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }]);
        assert_eq!(
            host_key_algorithms(Some(&key("ssh-rsa"))),
            vec![Algorithm::Rsa { hash: Some(HashAlg::Sha512) }, Algorithm::Rsa { hash: Some(HashAlg::Sha256) }],
            "an RSA key is offered as rsa-sha2-512 and rsa-sha2-256, never as SHA-1"
        );
        assert_eq!(host_key_algorithms(Some(&key("sk-ssh-ed25519@openssh.com"))), defaults, "a type we do not offer restricts nothing");
        assert_eq!(host_key_algorithms(Some(&key("not-an-algorithm"))), defaults);
    }

    /// The keepalive settings of a host record reach russh's config as they are: an interval of zero is "off", and the number of unanswered
    /// keepalives is russh's own `keepalive_max`, neither one more nor one less (russh gives up when more than that many went unanswered,
    /// and a limit of zero means never). The timing tests would not notice a limit that is off by one.
    #[test]
    fn the_keepalive_settings_of_a_host_record_reach_the_config_unchanged() {
        let mut hop = Hop::new("h1", "web", "127.0.0.1", 22, "tester", AuthMethod::Password);
        let config = client_config(&hop);
        assert_eq!((config.keepalive_interval, config.keepalive_max), (Some(Duration::from_secs(30)), 3), "the defaults of a host record");

        hop.keepalive_every = Duration::from_secs(7);
        hop.keepalive_max_missed = 5;
        let config = client_config(&hop);
        assert_eq!((config.keepalive_interval, config.keepalive_max), (Some(Duration::from_secs(7)), 5));

        hop.keepalive_every = Duration::ZERO;
        hop.keepalive_max_missed = 0;
        let config = client_config(&hop);
        assert_eq!((config.keepalive_interval, config.keepalive_max), (None, 0), "zero turns keepalive off");
    }

    /// The longest the engine waits for the server's answer during the handshake and the login: the connect timeout, but short of the
    /// keepalive interval (a silence that outlasts the interval makes russh's loop spin, see `stall_limit`).
    #[test]
    fn a_wait_for_the_server_ends_before_the_keepalive_interval_does() {
        let hop = |connect_secs: u64, keepalive_secs: u64| {
            let mut hop = Hop::new("h1", "web", "127.0.0.1", 22, "tester", AuthMethod::Password);
            hop.connect_timeout = Duration::from_secs(connect_secs);
            hop.keepalive_every = Duration::from_secs(keepalive_secs);
            hop
        };
        assert_eq!(stall_limit(&hop(15, 30)), Duration::from_secs(15), "the defaults: the connect timeout is the shorter of the two");
        assert_eq!(stall_limit(&hop(60, 30)), Duration::from_millis(22_500), "a long connect timeout is cut to three quarters of the interval");
        assert_eq!(stall_limit(&hop(6, 2)), Duration::from_millis(1_500));
        assert_eq!(stall_limit(&hop(6, 1)), Duration::from_secs(1), "never under a second, whatever the interval");
        assert_eq!(stall_limit(&hop(60, 0)), Duration::from_secs(60), "keepalive off: the connect timeout alone");
        assert_eq!(stall_limit(&hop(0, 0)), Duration::from_secs(1), "a connect timeout of nothing still waits a second");
    }

    #[test]
    fn the_rsa_hash_is_what_the_server_lists_and_never_sha1() {
        assert_eq!(choose_rsa_hash(Some(Some(HashAlg::Sha512))), RsaChoice::Use(HashAlg::Sha512));
        assert_eq!(choose_rsa_hash(Some(Some(HashAlg::Sha256))), RsaChoice::Use(HashAlg::Sha256));
        assert_eq!(choose_rsa_hash(Some(None)), RsaChoice::Sha1Only, "the server lists only ssh-rsa");
        assert_eq!(choose_rsa_hash(None), RsaChoice::Use(HashAlg::Sha256), "a server that never announced its algorithms is tried with SHA-256");
    }

    #[test]
    fn a_keyboard_interactive_answer_gets_four_connect_timeouts_and_at_least_a_minute() {
        let options = EngineOptions::default();
        assert_eq!(options.prompt_wait_for(Duration::from_secs(15)), Duration::from_secs(60));
        assert_eq!(options.prompt_wait_for(Duration::from_secs(30)), Duration::from_secs(120));
        assert_eq!(options.prompt_wait_for(Duration::from_secs(5)), Duration::from_secs(60));
        let short = EngineOptions { prompt_wait: Some(Duration::from_secs(2)), ..EngineOptions::default() };
        assert_eq!(short.prompt_wait_for(Duration::from_secs(15)), Duration::from_secs(2));
        assert_eq!(options.prompt_wait_for(Duration::MAX), Duration::MAX, "an absurd connect timeout saturates instead of panicking");
    }

    /// Counts the calls to `sign` and the hash each one got.
    #[derive(Default)]
    struct Counting {
        signs: Mutex<Vec<Option<RsaHash>>>,
    }

    impl AuthSource for Counting {
        fn public_key(&self, _key_id: &str) -> Option<String> {
            None
        }
        fn sign(&self, _key_id: &str, _data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            locked(&self.signs).push(rsa_hash);
            Ok(Signature(vec![7, 7]))
        }
        fn password(&self, _hop: &HopRef) -> Option<Secret> {
            None
        }
        fn interactive(&self, _hop: &HopRef, _prompts: &[Prompt], _deadline: std::time::Instant) -> Option<Vec<Secret>> {
            None
        }
    }

    /// A bare russh handler for the measurements: it trusts any host key and writes down how the connection ended.
    struct Bare {
        ended: Arc<Mutex<Option<String>>>,
    }

    impl Handler for Bare {
        type Error = russh::Error;

        async fn check_server_key(&mut self, _key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn disconnected(&mut self, reason: RusshDisconnect<Self::Error>) -> Result<(), Self::Error> {
            *locked(&self.ended) = Some(format!("{reason:?}"));
            match reason {
                RusshDisconnect::ReceivedDisconnect(_) => Ok(()),
                RusshDisconnect::Error(error) => Err(error),
            }
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("a runtime")
    }

    /// Spec §6.2 step 4, read from russh's source and measured here for the first time. When the signer fails, russh's session is left
    /// waiting for a signature that never comes: later calls get no answer, `disconnect()` is accepted and does nothing, and only
    /// dropping the `Handle` ends it. That is why a failed login drops the connection and never tries another method on it.
    #[test]
    fn a_session_whose_signer_failed_is_stuck_and_only_dropping_the_handle_ends_it() {
        use crate::ssh::testing::fact;
        use crate::ssh::testing::fixture::Server;
        use crate::ssh::testing::harness::tools;

        let Some(tools) = tools() else { return };
        let server = Server::start(&tools, &[]);
        let failing = server.vault("k1").failing_to_sign(AuthError::Refused("the vault is locked".into()));
        let public = PublicKey::from_openssh(&server.key.public_line).expect("the user key");
        let ended = Arc::new(Mutex::new(None));

        runtime().block_on(async {
            let mut handle = client::connect(Arc::new(Config::default()), ("127.0.0.1", server.sshd.port), Bare { ended: Arc::clone(&ended) }).await.expect("connects");
            let mut signer = EngineSigner { auth: &failing, key_id: "k1" };
            let result = tokio::time::timeout(Duration::from_secs(5), handle.authenticate_publickey_with(server.sshd.user.as_str(), public, None, &mut signer)).await;
            fact("signer_failure.login_call", format!("{result:?}"));
            assert!(matches!(result, Ok(Err(SignerFailure::Auth(_)))), "the signer's error comes straight back: {result:?}");

            let next = tokio::time::timeout(Duration::from_secs(2), handle.authenticate_none(server.sshd.user.as_str())).await;
            fact("signer_failure.authenticate_none_within_2s", format!("{next:?}"));
            assert!(next.is_err(), "a call on the stuck session got an answer: {next:?}");

            let disconnect = handle.disconnect(Disconnect::ByApplication, "", "en").await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            fact("signer_failure.disconnect_call", format!("{disconnect:?}"));
            fact("signer_failure.is_closed_1s_after_disconnect", handle.is_closed());
            assert!(disconnect.is_ok() && !handle.is_closed() && locked(&ended).is_none(), "disconnect() did something to a stuck session");

            drop(handle);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while locked(&ended).is_none() && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            fact("signer_failure.end_after_drop", format!("{:?}", locked(&ended)));
            assert!(locked(&ended).is_some(), "dropping the handle did not end the session");
        });
    }

    /// Review focus, read from russh's source (client/mod.rs: the `keepalive_timer` branch of the session loop acts only on a logged-in
    /// connection, and the timer is re-armed only by received data or a sent keepalive) and measured here: once the keepalive interval has
    /// passed on a connection that is not logged in, the loop spins on the elapsed timer until the server says something. That is the
    /// reason for the engine's rules: a login never waits for a person while connected (the password is asked for before connecting), the
    /// handshake and each login request are given up on before the interval is over (`stall_limit`), and a host key question or a
    /// signature parks russh's loop, which re-arms the timer when it moves on. So the spin is no bug of the engine, and this test is the
    /// canary for those rules: it turns red when a russh upgrade fixes the spin, and they can be relaxed then.
    ///
    /// The spin is measured as the time the workers of the test's own runtime are busy (the runtime's metrics). That is wall-clock time, so
    /// it does not depend on how much CPU a loaded machine gives the process, which the process's CPU time did (it failed on one).
    #[test]
    fn russh_spins_when_a_connection_idles_unauthenticated_past_the_keepalive_interval() {
        use crate::ssh::testing::fact;
        use crate::ssh::testing::fixture::Server;
        use crate::ssh::testing::harness::tools;

        let Some(tools) = tools() else { return };
        let server = Server::start(&tools, &[]);
        let runtime = runtime();
        let metrics = runtime.handle().metrics();
        let busy = || -> Duration { (0..metrics.num_workers()).map(|worker| metrics.worker_total_busy_duration(worker)).sum() };
        let mut used = Vec::new();
        runtime.block_on(async {
            for (label, interval) in [("keepalive_1s", Some(Duration::from_secs(1))), ("no_keepalive", None)] {
                let config = Config { keepalive_interval: interval, keepalive_max: 3, ..Config::default() };
                let handle = client::connect(Arc::new(config), ("127.0.0.1", server.sshd.port), Bare { ended: Arc::default() }).await.expect("connects");
                tokio::time::sleep(Duration::from_millis(200)).await;
                let before = busy();
                tokio::time::sleep(Duration::from_secs(3)).await;
                let spent = busy() - before;
                fact(&format!("idle.unauthenticated.{label}.busy_ms"), spent.as_millis());
                used.push(spent);
                assert!(!handle.is_closed());
            }
        });
        let (with_keepalive, without) = (used[0], used[1]);
        // the design expected: an idle connection costs nothing, whatever its state
        assert!(without < Duration::from_millis(100), "without keepalive an idle connection kept the runtime busy for {without:?} in 3 s");
        assert!(
            with_keepalive > Duration::from_millis(1000),
            "russh no longer spins ({with_keepalive:?} busy in 3 s): the unauthenticated-idle rule can be relaxed"
        );
    }

    /// The last line of defence for spec §6.3 b: even if the caller of the signer asked for SHA-1, an RSA key is never signed with it and
    /// `sign` is not called. For the other key types the hash means nothing and is not passed on.
    #[test]
    fn the_signer_never_asks_for_an_rsa_signature_with_sha1_and_appends_the_signature_to_what_russh_gave_it() {
        let rsa: AgentIdentity = PublicKey::from_openssh(test_keys::RSA_PUBLIC).expect("an rsa key").into();
        let ed25519: AgentIdentity = PublicKey::from_openssh(test_keys::PLAIN_PUBLIC).expect("an ed25519 key").into();
        let auth = Counting::default();
        let mut signer = EngineSigner { auth: &auth, key_id: "k1" };
        let runtime = tokio::runtime::Builder::new_current_thread().build().expect("a runtime");

        assert!(matches!(runtime.block_on(signer.auth_sign(&rsa, None, vec![1, 2, 3])), Err(SignerFailure::Sha1Refused)));
        assert!(locked(&auth.signs).is_empty(), "sign was not called for SHA-1");

        let signed = runtime.block_on(signer.auth_sign(&rsa, Some(HashAlg::Sha512), vec![1, 2, 3])).expect("signs with SHA-512");
        assert_eq!(signed, vec![1, 2, 3, 0, 0, 0, 2, 7, 7], "the buffer comes back unchanged, then the length and the signature blob");
        let signed = runtime.block_on(signer.auth_sign(&ed25519, None, vec![9])).expect("an ed25519 key has no hash");
        assert_eq!(signed, vec![9, 0, 0, 0, 2, 7, 7]);
        assert_eq!(*locked(&auth.signs), vec![Some(RsaHash::Sha512), None]);
    }
}

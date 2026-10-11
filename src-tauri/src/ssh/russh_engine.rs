//! The russh-backed engine (own-ssh spec §6): the only file in the app that imports russh (`ssh/mod.rs` has a test that keeps it so).
//!
//! The engine owns a dedicated tokio runtime and drives it with `block_on`, so everything on the `SshEngine` side is synchronous. The
//! caller's references (`&dyn HostKeyPolicy`, `&dyn AuthSource`) never leave the connect call: the connection tasks russh spawns see only
//! `'static` data, and the one question they must ask the caller (is this host key trusted?) travels over a channel to the thread that
//! is blocked in `connect`, which answers it.
//!
//! What the phase-0 spike taught, as rules (spec §6.2, §6.3): a handshake or a login call that waits for the application stalls the
//! whole connection, so nothing here waits for a person inside a callback; every wait is bounded; a failed or abandoned login drops the
//! connection instead of switching method on it; liveness is read from the connection's own state, never from an error variant.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use russh::client::{self, AuthResult, Config, Handle, Handler, Msg};
use russh::client::DisconnectReason as RusshDisconnect;
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{AlgorithmKind, Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, MethodKind, MethodSet, Preferred, Sig};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
use super::error::{AuthError, ConnectError, SessionError};
use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
use super::types::{
    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Phase, Pty, RsaHash, Target,
};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Knobs of the engine that are not part of a host record. The defaults are what the app uses; tests turn some of them down.
#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// Bytes of shell output kept between the channel reader and the thread that reads the shell (see `ByteQueue`).
    pub shell_queue_bytes: usize,
    /// Worker threads of the engine's runtime.
    pub worker_threads: usize,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions { shell_queue_bytes: 4 * 1024 * 1024, worker_threads: 2 }
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

    /// Connects every hop of `target` and logs in to each; the connection-level half of `SshEngine::connect`. Blocks the calling thread
    /// (never call it from inside an async task).
    pub fn connect_chain(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
        self.runtime.handle().block_on(connect_chain(target, host_keys, auth))
    }
}

/// What the handler and the engine both need to know about one hop's connection.
struct HopShared {
    /// The last host key the policy judged, and its verdict.
    observed: Mutex<Option<(HostKey, HostKeyVerdict)>>,
    /// Set by `Handler::disconnected`: how this hop's connection ended.
    ended: Mutex<Option<(DisconnectKind, String)>>,
    /// Set by `Handler::disconnected`, just before `ended` is written, when the connection ended because the server had no login method
    /// to offer (russh's `NoAuthMethod`).
    no_login_method: std::sync::atomic::AtomicBool,
}

impl HopShared {
    fn new() -> Arc<HopShared> {
        Arc::new(HopShared { observed: Mutex::new(None), ended: Mutex::new(None), no_login_method: std::sync::atomic::AtomicBool::new(false) })
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

/// An I/O error as a short lowercase phrase: no OS error number, no leading capital.
fn describe_io(error: &std::io::Error) -> String {
    let text = error.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
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
}

impl Connection {
    fn new() -> Connection {
        Connection { hops: Vec::new(), closing: AtomicBool::new(false) }
    }

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

    /// Why the connection ended: the record of the outermost hop that has one (a hop that dies after its carrier is gone records nothing
    /// useful, spec §6.2 step 2), else ours when we closed it. A hop whose `Handle` is closed but has not recorded anything yet is about
    /// to (russh closes the handle first and calls the handler a moment later), so it is given a short while before the fallback is used.
    fn reason(&self) -> Option<DisconnectReason> {
        let deadline = std::time::Instant::now() + Duration::from_millis(300);
        loop {
            for established in &self.hops {
                if let Some((kind, detail)) = locked(&established.shared.ended).clone() {
                    return Some(DisconnectReason { hop: established.hop.clone(), kind, detail });
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

async fn connect_chain(target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Connection, ConnectError> {
    check_chain(target)?;
    let mut connection = Connection::new();
    for (index, hop) in target.hops.iter().enumerate() {
        match connect_one(index, hop, connection.hops.last(), host_keys, auth).await {
            Ok(established) => connection.hops.push(established),
            Err(error) => {
                connection.disconnect_all().await;
                return Err(error);
            }
        }
    }
    Ok(connection)
}

/// A chain needs at least one hop and may not list a host twice.
fn check_chain(target: &Target) -> Result<(), ConnectError> {
    if target.hops.is_empty() {
        return Err(ConnectError::BadJumpChain { why: "the target has no hosts".to_string() });
    }
    for (index, hop) in target.hops.iter().enumerate() {
        if target.hops[..index].iter().any(|earlier| earlier.id == hop.id) {
            return Err(ConnectError::BadJumpChain { why: format!("{} appears twice", hop.alias) });
        }
    }
    Ok(())
}

async fn connect_one(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Established, ConnectError> {
    let reference = hop.reference();
    let (mut handle, shared) = connect_hop(index, hop, via, host_keys).await?;
    authenticate(hop, &mut handle, &shared, auth).await?;
    Ok(Established { hop: reference, handle, shared })
}

async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<(Handle<EngineHandler>, Arc<HopShared>), ConnectError> {
    let reference = hop.reference();
    if via.is_some() || index > 0 {
        return Err(ConnectError::BadJumpChain { why: "jump hosts are not connected yet".to_string() });
    }
    let shared = HopShared::new();
    let (questions_in, mut questions) = mpsc::unbounded_channel();
    let handler = EngineHandler { shared: Arc::clone(&shared), questions: questions_in };
    let config = Arc::new(client_config(hop));
    let phase = std::cell::Cell::new(Phase::Tcp);
    let attempt = async {
        let tcp = TcpStream::connect((hop.hostname.as_str(), hop.port)).await.map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
        if hop.nodelay {
            let _ = tcp.set_nodelay(true);
        }
        let (tcp, closer) = SocketGuard::new(tcp).map_err(|error| ConnectError::Unreachable { hop: reference.clone(), reason: describe_io(&error) })?;
        phase.set(Phase::Handshake);
        let connecting = client::connect_stream(config, tcp, handler);
        tokio::pin!(connecting);
        let connected = loop {
            tokio::select! {
                connected = &mut connecting => break connected,
                Some(question) = questions.recv() => {
                    let verdict = host_keys.check(&reference, &question.key);
                    let _ = question.reply.send(verdict);
                }
            }
        };
        if connected.is_ok() {
            closer.release();
        }
        connected.map_err(|error| handshake_error(&reference, &shared, error))
    };
    let budget = hop.connect_timeout.max(Duration::from_secs(1));
    match tokio::time::timeout(budget, attempt).await {
        Ok(result) => result.map(|handle| (handle, shared)),
        Err(_) => Err(ConnectError::Timeout { hop: reference, phase: phase.get() }),
    }
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
    ConnectError::AuthFailed { hop: hop.clone(), tried, reason: reasons.join(" ") }
}

/// Logs in to a freshly connected hop. The methods of `hop.auth_sequence()` are tried in order, each only if the server still offers
/// it; a refusal moves to the next method on the same connection. A method that cannot be tried here is skipped, and then the server is
/// asked once what it does offer (`none`), so later methods are not sent blindly. Anything that is our fault (the signer failed, a
/// prompt was cancelled or ran late) or the server's silence abandons the login: the caller drops the connection (spec §6.2 step 4).
async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, shared: &HopShared, auth: &dyn AuthSource) -> Result<(), ConnectError> {
    let reference = hop.reference();
    let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
    let timed_out = || ConnectError::Timeout { hop: reference.clone(), phase: Phase::Auth };
    let lost = |_: russh::Error| ConnectError::Unreachable { hop: reference.clone(), reason: "the connection was lost during login".to_string() };
    let call_limit = hop.connect_timeout.max(Duration::from_secs(1));
    let user = hop.user.as_str();
    let mut tried: Vec<AuthMethod> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    let mut offered: Option<MethodSet> = None;

    for method in hop.auth_sequence() {
        if offered.as_ref().is_some_and(|offered| !offered.contains(&method_kind(&method))) {
            continue;
        }
        let step = match &method {
            AuthMethod::Key { key_id } => 'key: {
                let Some(line) = auth.public_key(key_id) else {
                    reasons.push(format!("The key {key_id} is not available on this computer."));
                    break 'key Step::Skipped;
                };
                let Ok(public) = PublicKey::from_openssh(&line) else {
                    reasons.push(format!("The key {key_id} is not a public key SSHelter can use."));
                    break 'key Step::Skipped;
                };
                let hash = if public.algorithm().is_rsa() {
                    let best = tokio::time::timeout(call_limit, handle.best_supported_rsa_hash()).await.map_err(|_| timed_out())?.map_err(lost)?;
                    match choose_rsa_hash(best) {
                        RsaChoice::Use(hash) => Some(hash),
                        RsaChoice::Sha1Only => {
                            tried.push(method.clone());
                            reasons.push("The server accepts RSA keys only with SHA-1 signatures, which SSHelter does not make.".to_string());
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
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) if remaining_methods.is_empty() => match classify_empty_answer(shared, || handle.is_closed(), LOGIN_END_WAIT).await {
                        EmptyAnswer::NoLoginMethod => return Err(no_login_method(&reference, tried, reasons)),
                        EmptyAnswer::Lost => return Err(lost(russh::Error::SendError)),
                        EmptyAnswer::Refusal => Step::Refused(remaining_methods),
                    },
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) => Step::Refused(remaining_methods),
                }
            }
            // Password and keyboard-interactive logins come in Task 11; until then these methods are skipped like any method with nothing to offer.
            AuthMethod::Password | AuthMethod::Interactive => Step::Skipped,
        };
        match step {
            Step::Refused(remaining) => offered = Some(remaining),
            Step::Skipped if offered.is_none() => {
                match tokio::time::timeout(call_limit, handle.authenticate_none(user)).await.map_err(|_| timed_out())?.map_err(lost)? {
                    AuthResult::Success => return Ok(()),
                    AuthResult::Failure { remaining_methods, .. } if remaining_methods.is_empty() => match classify_empty_answer(shared, || handle.is_closed(), LOGIN_END_WAIT).await {
                        EmptyAnswer::NoLoginMethod => return Err(no_login_method(&reference, tried, reasons)),
                        EmptyAnswer::Lost => return Err(lost(russh::Error::SendError)),
                        EmptyAnswer::Refusal => offered = Some(remaining_methods),
                    },
                    AuthResult::Failure { remaining_methods, .. } => offered = Some(remaining_methods),
                }
            }
            Step::Skipped => {}
        }
    }
    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" ") })
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
        Ok(Box::new(RusshSession { runtime: Arc::clone(&self.runtime), connection, options: self.options.clone() }))
    }
}

impl Drop for RusshSession {
    /// Does not block (it may run on one of the runtime's own threads): the disconnect is sent by a task.
    fn drop(&mut self) {
        self.connection.closing.store(true, Ordering::SeqCst);
        let connection = Arc::clone(&self.connection);
        self.runtime.handle().spawn(async move { connection.disconnect_all().await });
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
        self.connection.closing.store(true, Ordering::SeqCst);
        self.runtime.handle().block_on(self.connection.disconnect_all());
    }
}

/// Runs one command on its own channel and reads the channel until it ends, the output reaches `output_cap` bytes or `timeout` is up.
///
/// `timeout` runs from the start of the call and bounds the wait for the command's output. The other waits have bounds of their own: the
/// channel is given `CHANNEL_SETUP_LIMIT` to open however short `timeout` is, so on a connection that does not answer a call can last that
/// long before it reports anything, and the requests that start and end the command are given `SEND_LIMIT` each.
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
    let (mut code, mut signal, mut refused) = (None, None, false);
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
            ChannelMsg::Failure => {
                refused = true;
                let _ = sent(write_half.close()).await;
                break;
            }
            _ => {}
        }
    }
    exit.set(match (signal, code) {
        (Some(signal), _) => Exit::Signal(signal),
        (None, Some(code)) if !refused => Exit::Code(code),
        _ => Exit::Disconnected,
    });
    queue.close();
}

#[cfg(test)]
mod tests {
    use russh::keys::EcdsaCurve;
    use russh::Signer;

    use super::*;
    use crate::ssh::{AuthError, Prompt, Secret, Signature};
    use crate::sync::slot_rules::test_keys;

    #[test]
    fn io_errors_are_described_without_the_os_number_or_a_leading_capital() {
        let os = std::io::Error::new(std::io::ErrorKind::Other, "Connection refused (os error 61)");
        assert_eq!(describe_io(&os), "connection refused");
        let dns = std::io::Error::new(std::io::ErrorKind::Other, "DNS lookup failed");
        assert_eq!(describe_io(&dns), "DNS lookup failed", "an acronym keeps its capitals");
        let plain = std::io::Error::new(std::io::ErrorKind::Other, "failed to lookup address information");
        assert_eq!(describe_io(&plain), "failed to lookup address information");
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

    #[test]
    fn the_rsa_hash_is_what_the_server_lists_and_never_sha1() {
        assert_eq!(choose_rsa_hash(Some(Some(HashAlg::Sha512))), RsaChoice::Use(HashAlg::Sha512));
        assert_eq!(choose_rsa_hash(Some(Some(HashAlg::Sha256))), RsaChoice::Use(HashAlg::Sha256));
        assert_eq!(choose_rsa_hash(Some(None)), RsaChoice::Sha1Only, "the server lists only ssh-rsa");
        assert_eq!(choose_rsa_hash(None), RsaChoice::Use(HashAlg::Sha256), "a server that never announced its algorithms is tried with SHA-256");
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

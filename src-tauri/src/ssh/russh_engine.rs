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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use russh::client::{self, AuthResult, Config, Handle, Handler};
use russh::client::DisconnectReason as RusshDisconnect;
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{AlgorithmKind, Disconnect, MethodKind, MethodSet, Preferred};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use super::error::{AuthError, ConnectError};
use super::traits::{AuthSource, HostKeyPolicy};
use super::types::{AuthMethod, DisconnectKind, Hop, HopRef, HostKey, HostKeyVerdict, Phase, RsaHash, Target};

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
        RusshEngine { runtime: Arc::new(RuntimeOwner { runtime: Some(runtime), handle }) }
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
}

impl HopShared {
    fn new() -> Arc<HopShared> {
        Arc::new(HopShared { observed: Mutex::new(None), ended: Mutex::new(None) })
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
    handle: Handle<EngineHandler>,
}

/// The whole chain, outermost hop first. Owns every hop's `Handle`; a connection is closed by an explicit `disconnect()` on each hop,
/// because dropping the outer `Handle` ends nothing while an inner hop still holds one of its channels. It does not own the runtime that
/// drives it: when the engine that made it is dropped the runtime goes with it, and every hop ends.
pub struct Connection {
    hops: Vec<Established>,
}

impl Connection {
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// No hop's connection has ended.
    pub fn is_open(&self) -> bool {
        self.hops.iter().all(|established| !established.handle.is_closed())
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
    let mut connection = Connection { hops: Vec::new() };
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
    let mut handle = connect_hop(index, hop, via, host_keys).await?;
    authenticate(hop, &mut handle, auth).await?;
    Ok(Established { handle })
}

async fn connect_hop(index: usize, hop: &Hop, via: Option<&Established>, host_keys: &dyn HostKeyPolicy) -> Result<Handle<EngineHandler>, ConnectError> {
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
        Ok(result) => result,
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

/// russh answers a login request with "refused, and no method is left" when its reply channel closes, which is also what a connection that
/// died while we waited looks like. An answer that came from the server came over a connection that is still open.
fn died_during_login(handle: &Handle<EngineHandler>, remaining: &MethodSet) -> bool {
    remaining.is_empty() && handle.is_closed()
}

/// Logs in to a freshly connected hop. The methods of `hop.auth_sequence()` are tried in order, each only if the server still offers
/// it; a refusal moves to the next method on the same connection. A method that cannot be tried here is skipped, and then the server is
/// asked once what it does offer (`none`), so later methods are not sent blindly. Anything that is our fault (the signer failed, a
/// prompt was cancelled or ran late) or the server's silence abandons the login: the caller drops the connection (spec §6.2 step 4).
async fn authenticate(hop: &Hop, handle: &mut Handle<EngineHandler>, auth: &dyn AuthSource) -> Result<(), ConnectError> {
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
                    Ok(Ok(AuthResult::Failure { remaining_methods, .. })) if died_during_login(handle, &remaining_methods) => return Err(lost(russh::Error::SendError)),
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
                    AuthResult::Failure { remaining_methods, .. } if died_during_login(handle, &remaining_methods) => return Err(lost(russh::Error::SendError)),
                    AuthResult::Failure { remaining_methods, .. } => offered = Some(remaining_methods),
                }
            }
            Step::Skipped => {}
        }
    }
    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" ") })
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

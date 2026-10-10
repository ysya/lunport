//! The spike's russh client side: a `Handler` that asks the test what to do with the host key, `connect`, login and exec helpers.
//!
//! Written against the docs.rs pages of russh 0.64.1 (read on 2026-10-10). Where a name here differs from the compiler's, the compiler wins.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, AuthResult, Config, DisconnectReason, Handle, Handler, Msg};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg};
use tokio::sync::{mpsc, oneshot};

/// A host key the server presented and the test must judge. Answer through `reply` (the stand-in for the confirmation window).
pub struct HostKeyQuestion {
    pub fingerprint: String,
    pub algorithm: String,
    pub reply: oneshot::Sender<bool>,
}

#[derive(Clone)]
pub enum HostKeyVerdict {
    AcceptAny,
    RejectAll,
    /// Accept only this "SHA256:..." fingerprint.
    Pinned(String),
    /// Ask the test; the handshake waits for the answer.
    Ask(mpsc::UnboundedSender<HostKeyQuestion>),
}

/// What the handler saw, shared with the test.
#[derive(Clone, Default)]
pub struct Observed {
    /// "SHA256:..." of each host key the server presented, in order.
    pub host_keys: Arc<Mutex<Vec<String>>>,
    /// The `Debug` text of the reason, once russh has called `Handler::disconnected`.
    pub disconnect: Arc<Mutex<Option<String>>>,
}

impl Observed {
    /// Waits until russh has called `Handler::disconnected` and returns the reason.
    pub async fn wait_for_disconnect(&self, seconds: u64) -> String {
        crate::within(seconds, "russh to report the disconnect", async {
            loop {
                let reason = self.disconnect.lock().unwrap().clone();
                if let Some(reason) = reason {
                    return reason;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
    }
}

pub struct SpikeHandler {
    verdict: HostKeyVerdict,
    observed: Observed,
}

impl SpikeHandler {
    pub fn new(verdict: HostKeyVerdict) -> (SpikeHandler, Observed) {
        let observed = Observed::default();
        (SpikeHandler { verdict, observed: observed.clone() }, observed)
    }
}

impl Handler for SpikeHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        self.observed.host_keys.lock().unwrap().push(fingerprint.clone());
        Ok(match &self.verdict {
            HostKeyVerdict::AcceptAny => true,
            HostKeyVerdict::RejectAll => false,
            HostKeyVerdict::Pinned(pinned) => *pinned == fingerprint,
            HostKeyVerdict::Ask(questions) => {
                let (reply, answer) = oneshot::channel();
                let question = HostKeyQuestion { fingerprint, algorithm: key.algorithm().to_string(), reply };
                questions.send(question).is_ok() && answer.await.unwrap_or(false)
            }
        })
    }

    async fn disconnected(&mut self, reason: DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        *self.observed.disconnect.lock().unwrap() = Some(format!("{reason:?}"));
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            DisconnectReason::Error(error) => Err(error),
        }
    }
}

pub struct Connection {
    pub handle: Handle<SpikeHandler>,
    pub observed: Observed,
}

/// TCP to 127.0.0.1:`port`, then the SSH handshake. `Err` carries russh's own error (a rejected host key is `Error::UnknownKey`).
pub async fn connect(port: u16, config: Config, verdict: HostKeyVerdict) -> Result<Connection, russh::Error> {
    let (handler, observed) = SpikeHandler::new(verdict);
    let handle = client::connect(Arc::new(config), (Ipv4Addr::LOCALHOST, port), handler).await?;
    Ok(Connection { handle, observed })
}

/// The same handshake over a stream somebody else carries (a direct-tcpip channel in the jump tests).
pub async fn connect_over<R>(stream: R, config: Config, verdict: HostKeyVerdict) -> Result<Connection, russh::Error>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (handler, observed) = SpikeHandler::new(verdict);
    let handle = client::connect_stream(Arc::new(config), stream, handler).await?;
    Ok(Connection { handle, observed })
}

/// Public-key login with a key russh loads itself (the vault's `Signer` is the other path: signer.rs).
pub async fn login_with_key_file(handle: &mut Handle<SpikeHandler>, user: &str, key_path: &Path) -> Result<AuthResult, russh::Error> {
    let key = russh::keys::load_secret_key(key_path, None).map_err(russh::Error::Keys)?;
    // `Some(Some(hash))`: the server lists rsa-sha2-*; `Some(None)`: it lists ssh-rsa only; `None`: it said nothing (no server-sig-algs).
    let hash_alg = handle.best_supported_rsa_hash().await?.flatten();
    handle.authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg)).await
}

/// What one exec channel delivered.
#[derive(Debug, Default)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
    /// The signal name when the command was killed by one (`Debug` of russh's `Sig`, e.g. "KILL").
    pub exit_signal: Option<String>,
    /// The server answered a channel request with Failure.
    pub refused: bool,
}

impl ExecOutput {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Opens a session channel, runs `command` (no PTY) and reads the channel until russh reports it closed.
pub async fn exec(handle: &Handle<SpikeHandler>, command: &str) -> Result<ExecOutput, russh::Error> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;
    Ok(drain(&mut channel).await)
}

/// Reads `channel` until `wait()` says it is closed. Every channel needs a reader like this one: russh stalls the whole connection
/// behind a channel nobody reads (the spec's §6.3; `tests/channels.rs` measures it).
pub async fn drain(channel: &mut Channel<Msg>) -> ExecOutput {
    let mut out = ExecOutput::default();
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => out.stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => out.exit_signal = Some(format!("{signal_name:?}")),
            ChannelMsg::Failure => out.refused = true,
            _ => {}
        }
    }
    out
}

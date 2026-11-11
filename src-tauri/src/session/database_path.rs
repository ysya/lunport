//! The way to a saved database reached through a host of the library: one SSH session to that host, opened as connecting to the host opens
//! it (its jump hosts, its Google Cloud IAP route, the questions its login asks), and a local forward on it from a port the system picks on
//! 127.0.0.1 to the instance's private address on Cloud SQL's port. The database's connections dial that port with TLS, so Cloud SQL still
//! takes only the client certificate it signed for them.

use std::net::IpAddr;

use super::auth::Owner;
use super::connect::CancelToken;
use super::protocol::HostQuery;
use crate::gcp::cloudsql_tls;
use crate::identity::thread_name;
use crate::ssh::forward::{ForwardKind, ForwardSpec, Forwarder};
use crate::ssh::{Session, SessionError};

/// What a forward that reports no port is refused with.
const NO_PORT: &str = "No local port was opened for it.";

/// Opens a session to a host of the library.
pub(crate) trait HostLink: Send + Sync {
    /// Connects to the saved host `host_id` as connecting to that host does, asking `owner` what its login needs, until the session is
    /// open, the connect fails or `cancel` is set. `Err` is the sentence of why no session was opened. It blocks (the network, the
    /// person's answers), so it runs on a blocking thread, never in async code.
    fn open(&self, host_id: &str, owner: &dyn Owner, cancel: &CancelToken) -> Result<Box<dyn Session>, String>;
}

/// The app's way to its hosts: the broker's connector, which a connection to a host opens its session with.
pub(crate) struct BrokerLink {
    pub app: tauri::AppHandle,
}

impl HostLink for BrokerLink {
    fn open(&self, host_id: &str, owner: &dyn Owner, cancel: &CancelToken) -> Result<Box<dyn Session>, String> {
        let broker = super::databases::started_broker(&self.app)?;
        let connected = broker.connector().connect(&HostQuery::Id(host_id.to_string()), owner, cancel).map_err(|failure| failure.text)?;
        Ok(connected.session)
    }
}

/// A forward a path keeps, and the address it leads to.
struct Forward {
    target: IpAddr,
    forwarder: Box<dyn Forwarder>,
}

/// One session to the host a database is reached through, and the forward on it to the instance. Dropping it stops the forward and closes
/// the session on a thread of their own, which waits for the disconnect where nothing else waits: a path may be dropped in async code.
pub(crate) struct HostPath {
    /// The host's alias as it was when the session opened, for the sentences that say what failed on the way.
    alias: String,
    /// Taken only when the path is dropped, by the thread that closes it.
    session: Option<Box<dyn Session>>,
    forward: Option<Forward>,
}

impl HostPath {
    /// The path over `session`, a session to the host `alias` names, with no forward yet.
    pub(crate) fn new(session: Box<dyn Session>, alias: String) -> HostPath {
        HostPath { alias, session: Some(session), forward: None }
    }

    pub(crate) fn alias(&self) -> &str {
        &self.alias
    }

    /// Whether it can carry connections: its session is alive, and its forward, if it has one, runs.
    pub(crate) fn alive(&self) -> bool {
        self.session_alive() && self.forward.as_ref().is_none_or(|forward| forward.forwarder.status().running)
    }

    /// The loopback port of a forward to Cloud SQL's port at `target`: the one that runs, else one opened now from a port the system picks
    /// on 127.0.0.1. A forward that stopped, or that leads elsewhere, is stopped on a thread of its own. Opening one blocks briefly (the
    /// engine binds its listener), so it runs on a blocking thread.
    pub(crate) fn forward_to(&mut self, target: IpAddr) -> Result<u16, String> {
        if let Some(port) = self.port_for(target) {
            return Ok(port);
        }
        if let Some(before) = self.forward.take() {
            close_later(Some(before.forwarder), None);
        }
        let session = self.session.as_ref().ok_or_else(|| SessionError::Closed.to_string())?;
        let spec = ForwardSpec { kind: ForwardKind::Local, bind_address: "127.0.0.1".into(), port: 0, target_host: target.to_string(), target_port: cloudsql_tls::PORT };
        let forwarder = session.forward(&spec).map_err(|error| error.to_string())?;
        let port = forwarder.status().port;
        if port == 0 {
            close_later(Some(forwarder), None);
            return Err(NO_PORT.to_string());
        }
        self.forward = Some(Forward { target, forwarder });
        Ok(port)
    }

    /// The loopback port of its forward to `target`, while the forward runs and the session lives. It only looks, so async code may ask.
    pub(crate) fn port_for(&self, target: IpAddr) -> Option<u16> {
        let forward = self.forward.as_ref().filter(|forward| forward.target == target)?;
        let status = forward.forwarder.status();
        (status.running && self.session_alive()).then_some(status.port)
    }

    /// The most recent error of a connection its forward to `target` carried, as the forward reports it: why the host could not reach
    /// the instance, when it could not.
    pub(crate) fn forward_error(&self, target: IpAddr) -> Option<String> {
        self.forward.as_ref().filter(|forward| forward.target == target)?.forwarder.status().error
    }

    fn session_alive(&self) -> bool {
        self.session.as_ref().is_some_and(|session| session.is_alive())
    }
}

impl Drop for HostPath {
    fn drop(&mut self) {
        close_later(self.forward.take().map(|forward| forward.forwarder), self.session.take());
    }
}

/// Stops `forwarder` and then closes `session`, on a thread of their own: closing waits for the disconnect to go out, for a few seconds on a
/// host that stopped answering. When no thread can be started they are dropped here instead, and a dropped forward stops and a dropped
/// session closes without waiting in async code.
fn close_later(forwarder: Option<Box<dyn Forwarder>>, session: Option<Box<dyn Session>>) {
    let closing = move || {
        if let Some(forwarder) = forwarder {
            forwarder.stop();
        }
        if let Some(session) = session {
            session.close();
        }
    };
    let _ = std::thread::Builder::new().name(thread_name("database-path")).spawn(closing);
}

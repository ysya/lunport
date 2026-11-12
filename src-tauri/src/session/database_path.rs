//! The way to a saved database reached through a host of the library: one SSH session to that host, opened as connecting to the host opens
//! it (its jump hosts, its Google Cloud IAP route, the questions its login asks), and a local forward on it from a port the system picks on
//! 127.0.0.1 to the instance's private address on Cloud SQL's port. The database's connections dial that port with TLS, so Cloud SQL still
//! takes only the client certificate it signed for them.

use std::net::IpAddr;

use super::auth::Owner;
use super::connect::{CancelToken, Connector};
use super::protocol::{AiAsker, HostQuery};
use crate::gcp::cloudsql_tls;
use crate::identity::thread_name;
use crate::mcp::records::ClientConfirmer;
use crate::ssh::forward::{ForwardKind, ForwardSpec, Forwarder};
use crate::ssh::{Session, SessionError};

/// What a forward that reports no port is refused with.
const NO_PORT: &str = "No local port was opened for it.";

/// Opens a session to a host of the library.
pub(crate) trait HostLink: Send + Sync {
    /// Connects to the saved host `host_id` as connecting to that host does, asking `owner` what its login needs, until the session is
    /// open, the connect fails or `cancel` is set; a server key it asks about names `ai`, the AI client whose request starts the database
    /// (`None`: the person's start, and an app's connection). `Err` is the sentence of why no session was opened. It blocks (the network,
    /// the person's answers), so it runs on a blocking thread, never in async code.
    fn open(&self, host_id: &str, owner: &dyn Owner, cancel: &CancelToken, ai: Option<&AiAsker>) -> Result<Box<dyn Session>, String>;
}

/// The app's way to its hosts: the broker's connector, which a connection to a host opens its session with.
pub(crate) struct BrokerLink {
    pub app: tauri::AppHandle,
}

impl HostLink for BrokerLink {
    fn open(&self, host_id: &str, owner: &dyn Owner, cancel: &CancelToken, ai: Option<&AiAsker>) -> Result<Box<dyn Session>, String> {
        let broker = super::databases::started_broker(&self.app)?;
        open_on(&broker.connector(), host_id, owner, cancel, ai)
    }
}

/// `HostLink::open` over `base`, the connector a connection to the host opens its session with. For an AI client's start the server key
/// questions go to `base`'s window through `ClientConfirmer`, which names the client there as a tunnel the client starts does; otherwise
/// they are asked as `base` asks them.
pub(crate) fn open_on(base: &Connector<'_>, host_id: &str, owner: &dyn Owner, cancel: &CancelToken, ai: Option<&AiAsker>) -> Result<Box<dyn Session>, String> {
    let query = HostQuery::Id(host_id.to_string());
    let connected = match ai {
        Some(ai) => {
            let confirmer = ClientConfirmer::new(base.confirmer, ai.clone());
            Connector { confirmer: &confirmer, ..*base }.connect(&query, owner, cancel)
        }
        None => base.connect(&query, owner, cancel),
    };
    connected.map(|connected| connected.session).map_err(|failure| failure.text)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::grants::GrantGates;
    use crate::session::protocol::Unreviewed;
    use crate::session::testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::fake::FakeEngine;
    use crate::ssh::{AuthMethod, HostKey};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    /// The server of web-1 presents another key than the one pinned for it. The window that asks about the changed key names the AI
    /// client whose request starts the database, and nobody when the person starts it; once the new key is accepted the session opens.
    #[test]
    fn a_changed_server_key_is_asked_in_the_name_of_whoever_starts_the_database() {
        let pinned = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
        let claude = AiAsker { client: "Claude".into(), unreviewed: Some(Unreviewed::Database) };
        for ai in [Some(claude), None] {
            let directory = FakeDirectory::new().with_host("web-1", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web-1", pinned.clone());
            let (engine, keys, keychain, grants) = (FakeEngine::new(), FakeKeys::new(), MemKeychain::default(), GrantGates::default());
            let window = FakeConfirmer::deciding(vec![Decision::Trust]);
            let base = Connector { engine: &engine, directory: &directory, keys: &keys, keychain: &keychain, confirmer: &window, grants: &grants };
            let opened = open_on(&base, "id-web-1", &FakeOwner::default(), &CancelToken::default(), ai.as_ref());
            assert!(opened.is_ok(), "the session opens once the new key is accepted: {:?}", opened.err());
            let asked: Vec<_> = window.asked().into_iter().map(|question| (question.changed.map(|pin| pin.fingerprint), question.ai)).collect();
            assert_eq!(asked, [(Some(pinned.fingerprint.clone()), ai)]);
        }
    }
}

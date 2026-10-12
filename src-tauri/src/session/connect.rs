//! Opening a session (own-ssh spec §6.2, §7.2, §10): the broker's connect loop around the engine. The engine fails fast where a person
//! must decide (an unknown or changed host key, a password wanted after a refused key); the broker asks — the window for host keys, the
//! session's owner for everything else — and connects again with what it learned. Every call here blocks: it runs on the thread of the
//! client's connection, never in async code and never on the UI thread.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::auth::{prompt_wait, BrokerAuth, KeyStore, Owner, PinPolicy, Reply};
use super::directory::{DirectoryError, HostDirectory};
use super::protocol::{kinds, HostQuery, QuestionKind};
use crate::ssh::{AuthMethod, ConnectError, HopRef, HostId, HostKey, Session, SshEngine, Target};
use crate::sync::env::Keychain;

/// How many passwords the person may type for one host in one connect (OpenSSH's `NumberOfPasswordPrompts`).
pub const PASSWORD_PROMPTS: usize = 3;

/// How many times one connect may go round (host keys confirmed, a password typed, the key type of a changed pin): enough for every
/// question on every hop of a chain, and a bound in case a server keeps changing its answer.
const MAX_ROUNDS: usize = 12;

/// The `kind` of a failure nobody is told about: the client went away.
pub const CANCELLED: &str = "cancelled";

/// Set when the session's owner went away (its connection ended): whatever the broker waits for (the window, a question) gives up, and
/// nothing more is connected.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The key that was pinned, for a changed-key question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedSummary {
    pub fingerprint: String,
    pub pinned_at_ms: u64,
}

/// A host key for the person to confirm in SSHelter's window (spec §10, §14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeyQuestion {
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// `None` for a key SSHelter has not seen; for a changed key, the one that is pinned.
    pub changed: Option<PinnedSummary>,
}

/// SSHelter's host key window, for the broker. It blocks until the person decides, the question times out or `cancel` is set, and returns
/// the fingerprint the person trusted (`None`: refused, closed, timed out, cancelled). The broker pins only the key it observed itself,
/// and only when the fingerprints match.
pub trait HostKeyConfirmer: Send + Sync {
    fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String>;
}

/// A session that is open, and the target it reached (with what the connect learned: pins, the password-first hops).
pub struct Connected {
    pub session: Box<dyn Session>,
    pub target: Target,
}

/// Why no session was opened: the sentence for the user (spec §11) and the `kind` word of the error event (`protocol::kinds`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectFailure {
    pub kind: String,
    pub text: String,
}

impl ConnectFailure {
    fn new(kind: &str, text: impl Into<String>) -> ConnectFailure {
        ConnectFailure { kind: kind.to_string(), text: text.into() }
    }

    fn cancelled() -> ConnectFailure {
        ConnectFailure::new(CANCELLED, "The connection was cancelled.")
    }
}

/// What the broker connects with.
pub struct Connector<'a> {
    pub engine: &'a dyn SshEngine,
    pub directory: &'a dyn HostDirectory,
    pub keys: &'a dyn KeyStore,
    pub keychain: &'a dyn Keychain,
    pub confirmer: &'a dyn HostKeyConfirmer,
}

/// The hop an error is about; `None` for an error about the whole chain.
fn hop_of(error: &ConnectError) -> Option<&HopRef> {
    match error {
        ConnectError::BadJumpChain { .. } => None,
        ConnectError::Unreachable { hop, .. }
        | ConnectError::Timeout { hop, .. }
        | ConnectError::HostKeyUnknown { hop, .. }
        | ConnectError::HostKeyMismatch { hop, .. }
        | ConnectError::NoCommonHostKeyAlgorithm { hop, .. }
        | ConnectError::AuthFailed { hop, .. }
        | ConnectError::AuthAbandoned { hop, .. }
        | ConnectError::Protocol { hop, .. } => Some(hop),
    }
}

/// The failure the user sees for an engine error. A failure on a jump host is said through it (spec §11:
/// `Could not connect through {jump alias}: {reason}`).
fn failure_of(error: &ConnectError, target: &Target) -> ConnectFailure {
    let kind = match error {
        ConnectError::HostKeyUnknown { .. } | ConnectError::HostKeyMismatch { .. } => kinds::HOST_KEY,
        ConnectError::AuthFailed { .. } | ConnectError::AuthAbandoned { .. } => kinds::AUTH,
        _ => kinds::CONNECT,
    };
    let destination = target.hops.last().map(|hop| &hop.id);
    match hop_of(error) {
        Some(hop) if Some(&hop.id) != destination => ConnectFailure::new(kind, format!("Could not connect through {}: {error}", hop.alias)),
        _ => ConnectFailure::new(kind, error.to_string()),
    }
}

fn directory_failure(error: DirectoryError) -> ConnectFailure {
    ConnectFailure::new(kinds::HOST, error.to_string())
}

impl Connector<'_> {
    /// Opens a session to the saved host `query` names, asking `owner` (the person at the client's terminal) what the login needs and the
    /// window about host keys, until it is open, it fails, or `cancel` is set.
    pub fn connect(&self, query: &HostQuery, owner: &dyn Owner, cancel: &CancelToken) -> Result<Connected, ConnectFailure> {
        if cancel.is_cancelled() {
            return Err(ConnectFailure::cancelled());
        }
        let mut target = self.directory.resolve(query).map_err(directory_failure)?;
        let auth = BrokerAuth::new(self.keys, self.keychain, owner, self.directory);
        auth.unlock(&target).map_err(|text| ConnectFailure::new(kinds::AUTH, text))?;
        let policy = PinPolicy::from_target(&target);
        let mut unrestricted: HashSet<HostId> = HashSet::new();
        let mut passwords_typed: HashMap<HostId, usize> = HashMap::new();
        for _ in 0..MAX_ROUNDS {
            if cancel.is_cancelled() {
                return Err(ConnectFailure::cancelled());
            }
            auth.prepare(&target);
            let error = match self.engine.connect(&target, &policy, &auth) {
                Ok(session) => return Ok(Connected { session, target }),
                Err(error) => error,
            };
            match error {
                ConnectError::HostKeyUnknown { hop, key } => self.confirm(&mut target, &policy, owner, cancel, &hop, &key, None)?,
                ConnectError::HostKeyMismatch { hop, key, pinned } => self.confirm(&mut target, &policy, owner, cancel, &hop, &key, Some(pinned))?,
                // Plan 1b R17: the handshake offered only the pinned key's type and the server has none of it any more. Once more without the
                // restriction: the policy still knows the pin, so a key of another type comes back as a changed key, with its warning.
                ConnectError::NoCommonHostKeyAlgorithm { ref hop, .. } if policy.pinned(&hop.id).is_some() && unrestricted.insert(hop.id.clone()) => {
                    if let Some(restricted) = target.hops.iter_mut().find(|candidate| candidate.id == hop.id) {
                        restricted.pinned = None;
                    }
                }
                ConnectError::AuthFailed { ref hop, ref tried, password_wanted, .. } if !auth.cancelled(&hop.id) => {
                    // A password given and refused: a typed one is forgotten; a saved one stays saved, and what the person types is used instead.
                    let refused = tried.contains(&AuthMethod::Password) && auth.password_source(&hop.id).is_some();
                    let typed = passwords_typed.entry(hop.id.clone()).or_default();
                    if !(password_wanted || refused) || *typed >= PASSWORD_PROMPTS {
                        return Err(failure_of(&error, &target));
                    }
                    auth.forget_typed(&hop.id);
                    let question = if refused { format!("That password didn't work. {}@{}'s password: ", hop.user, hop.alias) } else { format!("{}@{}'s password: ", hop.user, hop.alias) };
                    let Some(index) = target.hops.iter().position(|candidate| candidate.id == hop.id) else { return Err(failure_of(&error, &target)) };
                    let deadline = std::time::Instant::now().checked_add(prompt_wait(&target.hops[index]));
                    *typed += 1;
                    match owner.ask(QuestionKind::Password, &question, false, deadline) {
                        Reply::Answer(password) => {
                            auth.set_typed(&hop.id, password);
                            target.hops[index].auth = AuthMethod::Password;
                        }
                        Reply::Cancelled | Reply::TimedOut => {
                            return Err(ConnectFailure::new(kinds::AUTH, ConnectError::AuthAbandoned { hop: hop.clone(), reason: "the password was not given".to_string() }.to_string()));
                        }
                        Reply::Gone => return Err(ConnectFailure::cancelled()),
                    }
                }
                other => return Err(failure_of(&other, &target)),
            }
        }
        let alias = target.hops.last().map(|hop| hop.alias.clone()).unwrap_or_default();
        Err(ConnectFailure::new(kinds::CONNECT, format!("SSHelter gave up connecting to {alias}: the server kept asking for something new.")))
    }

    /// Asks the window about `key`, which `hop` presented (`pinned`: the key on record, for a changed key). When the person trusts exactly
    /// this key, it is pinned (or replaces the old pin) and the next round connects with it; anything else ends the connect.
    #[allow(clippy::too_many_arguments)]
    fn confirm(
        &self,
        target: &mut Target,
        policy: &PinPolicy,
        owner: &dyn Owner,
        cancel: &CancelToken,
        hop: &HopRef,
        key: &HostKey,
        pinned: Option<HostKey>,
    ) -> Result<(), ConnectFailure> {
        owner.host_key_notice(&format!("Waiting for you to confirm {}'s host key in SSHelter.", hop.alias));
        let changed = match &pinned {
            None => None,
            Some(pinned) => {
                let pinned_at_ms = self.directory.pinned(&hop.id).map_err(directory_failure)?.map(|pin| pin.pinned_at_ms).unwrap_or(0);
                Some(PinnedSummary { fingerprint: pinned.fingerprint.clone(), pinned_at_ms })
            }
        };
        let question = HostKeyQuestion {
            alias: hop.alias.clone(),
            hostname: hop.hostname.clone(),
            port: hop.port,
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            changed,
        };
        let trusted = self.confirmer.confirm(&question, cancel);
        if cancel.is_cancelled() {
            return Err(ConnectFailure::cancelled());
        }
        if trusted.as_deref() != Some(key.fingerprint.as_str()) {
            let refused = match pinned {
                None => ConnectError::HostKeyUnknown { hop: hop.clone(), key: key.clone() },
                Some(pinned) => ConnectError::HostKeyMismatch { hop: hop.clone(), key: key.clone(), pinned },
            };
            return Err(ConnectFailure::new(kinds::HOST_KEY, refused.to_string()));
        }
        match &pinned {
            None => self.directory.pin(&hop.id, key),
            Some(pinned) => self.directory.replace_pin(&hop.id, pinned, key),
        }
        .map_err(|error| ConnectFailure::new(kinds::HOST_KEY, error.to_string()))?;
        policy.pin(&hop.id, key.clone());
        if let Some(confirmed) = target.hops.iter_mut().find(|candidate| candidate.id == hop.id) {
            confirmed.pinned = Some(key.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::auth::Reply;
    use crate::session::testing::{locked, Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner, PINNED_AT_MS, TEST_PASSPHRASE};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
    use crate::ssh::{AuthMethod, HostKey};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    const WAITING: &str = "Waiting for you to confirm web's host key in SSHelter.";

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).unwrap()
    }

    fn web() -> HostQuery {
        HostQuery::Alias("web".into())
    }

    struct World {
        engine: FakeEngine,
        directory: FakeDirectory,
        keys: FakeKeys,
        keychain: MemKeychain,
        confirmer: FakeConfirmer,
        owner: FakeOwner,
        cancel: CancelToken,
    }

    fn world(engine: FakeEngine, directory: FakeDirectory) -> World {
        World { engine, directory, keys: FakeKeys::new(), keychain: MemKeychain::default(), confirmer: FakeConfirmer::default(), owner: FakeOwner::default(), cancel: CancelToken::default() }
    }

    impl World {
        fn deciding(mut self, decisions: Vec<Decision>) -> World {
            self.confirmer = FakeConfirmer::deciding(decisions);
            self
        }

        fn typing(mut self, answers: &[&str]) -> World {
            self.owner = FakeOwner::typing(answers);
            self
        }

        fn connect(&self, query: &HostQuery) -> Result<Connected, ConnectFailure> {
            let connector = Connector { engine: &self.engine, directory: &self.directory, keys: &self.keys, keychain: &self.keychain, confirmer: &self.confirmer };
            connector.connect(query, &self.owner, &self.cancel)
        }

        fn connects(&self) -> usize {
            self.engine.events().iter().filter(|event| matches!(event, FakeEvent::Connect { .. })).count()
        }
    }

    fn failure(kind: &str, text: &str) -> ConnectFailure {
        ConnectFailure { kind: kind.to_string(), text: text.to_string() }
    }

    #[test]
    fn a_host_whose_key_is_pinned_connects_without_a_question() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()));
        world.keychain.set("host:id-web", "saved").unwrap();
        let connected = world.connect(&web()).expect("connects");
        assert!(connected.session.is_alive());
        assert_eq!(connected.target.hops[0].alias, "web");
        assert!(world.confirmer.asked().is_empty() && world.owner.asked().is_empty());
        assert!(locked(&world.owner.notices).is_empty());
    }

    /// Spec §10: the first connect fails on the unknown key; the window asks; the trusted key is pinned and the broker connects again, so
    /// the user sees "confirm, connected".
    #[test]
    fn an_unknown_host_key_is_confirmed_in_the_window_then_pinned_and_the_broker_connects_again() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust]);
        world.keychain.set("host:id-web", "saved").unwrap();
        world.connect(&web()).expect("connects after the key was trusted");
        assert_eq!(*locked(&world.owner.notices), [WAITING]);
        let asked = world.confirmer.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!(
            asked[0],
            HostKeyQuestion {
                alias: "web".into(),
                hostname: "web.example.com".into(),
                port: 22,
                algorithm: "ssh-ed25519".into(),
                fingerprint: test_keys::PLAIN_FINGERPRINT.into(),
                changed: None,
            }
        );
        assert_eq!(world.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
        assert_eq!(world.connects(), 1, "one connect got through, after the one that stopped at the key");
    }

    #[test]
    fn an_unknown_host_key_the_person_does_not_trust_ends_the_connect_and_pins_nothing() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Refuse]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web has not been confirmed yet.")));
        assert!(world.directory.pins().is_empty());
    }

    /// The window answers for one fingerprint; only the key the broker itself observed is pinned, and only when the two match (as deploy's
    /// "trust this key" works): a stale answer pins nothing.
    #[test]
    fn an_answer_for_another_fingerprint_pins_nothing() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::TrustFingerprint("SHA256:stale".into())]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web has not been confirmed yet.")));
        assert!(world.directory.pins().is_empty());
    }

    #[test]
    fn a_changed_host_key_shows_the_pinned_one_and_replaces_it_only_when_accepted() {
        let old = key(test_keys::ENC_PUBLIC);
        let refusing = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", old.clone())).deciding(vec![Decision::Refuse]);
        assert_eq!(refusing.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web changed. Connection refused.")));
        assert_eq!(refusing.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(old.clone()), "the old pin stays");
        let asked = refusing.confirmer.asked();
        assert_eq!(asked[0].changed, Some(PinnedSummary { fingerprint: test_keys::ENC_FINGERPRINT.into(), pinned_at_ms: PINNED_AT_MS }));
        assert_eq!(asked[0].fingerprint, test_keys::PLAIN_FINGERPRINT);

        let accepting = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", old)).deciding(vec![Decision::Trust]);
        accepting.keychain.set("host:id-web", "saved").unwrap();
        accepting.connect(&web()).expect("connects with the accepted key");
        assert_eq!(accepting.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
        assert_eq!(*locked(&accepting.owner.notices), [WAITING]);
    }

    /// Plan 1b R17: a pinned host whose server no longer has a key of the pinned type would fail with "no common algorithm", because the
    /// handshake offers only the pinned type. The broker connects once more without that restriction, so the person gets the normal
    /// changed-key warning instead.
    #[test]
    fn a_pinned_host_that_now_has_another_key_type_gets_the_changed_key_warning_not_an_algorithm_error() {
        let ecdsa = key(test_keys::ECDSA_PUBLIC);
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", ecdsa.clone())).deciding(vec![Decision::Trust]);
        world.keychain.set("host:id-web", "saved").unwrap();
        let connected = world.connect(&web()).expect("connects once the new key was accepted");
        let asked = world.confirmer.asked();
        assert_eq!((asked.len(), asked[0].algorithm.as_str()), (1, "ssh-ed25519"));
        assert_eq!(asked[0].changed.as_ref().map(|pinned| pinned.fingerprint.as_str()), Some(test_keys::ECDSA_FINGERPRINT));
        assert_eq!(world.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
        assert_eq!(connected.target.hops[0].pinned, Some(default_server_key()), "the reconnect offered the new key's type");

        let refusing = world_refusing_algorithm_change(ecdsa);
        assert_eq!(refusing.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web changed. Connection refused.")));
    }

    fn world_refusing_algorithm_change(pinned: HostKey) -> World {
        world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", pinned)).deciding(vec![Decision::Refuse])
    }

    /// The fallback password after a refused key is not typed while the connection waits (russh spins then): the engine reports that a
    /// password is wanted, the broker asks, and connects again with the password first.
    #[test]
    fn a_password_wanted_after_a_refused_key_is_asked_for_and_the_broker_connects_again_with_the_password_first() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world(engine, directory).typing(&["right"]);
        let connected = world.connect(&web()).expect("the typed password gets in");
        assert_eq!(world.owner.questions(), ["deploy@web's password: "]);
        assert_eq!(connected.target.hops[0].auth, AuthMethod::Password);
    }

    #[test]
    fn a_refused_password_is_asked_for_again_up_to_three_times() {
        let engine = || FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = || FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let third_time = world(engine(), directory()).typing(&["one", "two", "right"]);
        third_time.connect(&web()).expect("the third password is right");
        let again = "That password didn't work. deploy@web's password: ";
        assert_eq!(third_time.owner.questions(), ["deploy@web's password: ", again, again]);

        let never = world(engine(), directory()).typing(&["one", "two", "three", "right"]);
        assert_eq!(never.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication failed for deploy@web (tried: password).")));
        assert_eq!(never.owner.asked().len(), PASSWORD_PROMPTS);
    }

    /// A saved password that the server refuses: the person is asked, and what they type is used instead of the saved one.
    #[test]
    fn a_saved_password_that_is_refused_is_asked_for() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("new")));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key())).typing(&["new"]);
        world.keychain.set("host:id-web", "old").unwrap();
        world.connect(&web()).expect("the typed password gets in");
        assert_eq!(world.owner.questions(), ["That password didn't work. deploy@web's password: "]);
        assert_eq!(world.keychain.entry("host:id-web").as_deref(), Some("old"), "the saved password is not changed");
    }

    #[test]
    fn a_cancelled_password_question_abandons_the_connect() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let mut world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key()));
        world.owner = FakeOwner::answering(vec![Reply::Cancelled]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication for web was abandoned (the password was not given).")));
    }

    /// A first contact with a password-first host connects twice (the key is unknown the first time); the person types the password once.
    #[test]
    fn the_first_contact_with_a_password_host_asks_for_the_password_once() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust]).typing(&["right"]);
        world.connect(&web()).expect("connects");
        assert_eq!(world.owner.questions(), ["deploy@web's password: "]);
        assert_eq!(world.confirmer.asked().len(), 1);
    }

    #[test]
    fn a_passphrase_is_asked_for_before_anything_connects() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::key()));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-enc".into() }).with_pin("web", default_server_key())).typing(&[TEST_PASSPHRASE]);
        world.connect(&web()).expect("the key opens and logs in");
        assert_eq!(world.owner.questions(), ["Enter the passphrase for the key laptop: "]);

        let mut cancelled = self::world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-enc".into() }));
        cancelled.owner = FakeOwner::answering(vec![Reply::Cancelled]);
        assert_eq!(cancelled.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication for web was abandoned (the passphrase was not given).")));
        assert!(cancelled.engine.events().is_empty() && cancelled.confirmer.asked().is_empty(), "nothing was connected");
    }

    /// Spec §11: a failure on a jump host is said through it.
    #[test]
    fn a_failure_on_a_jump_host_names_the_jump_host() {
        let directory = FakeDirectory::new().with_host("bastion", AuthMethod::Password).with_host_via("db", AuthMethod::Password, &["bastion"]);
        let bastion = directory.resolve(&HostQuery::Alias("bastion".into())).unwrap().hops.remove(0).reference();
        let engine = FakeEngine::new().failing_with(ConnectError::Unreachable { hop: bastion, reason: "connection refused".into() });
        let world = world(engine, directory);
        assert_eq!(
            world.connect(&HostQuery::Alias("db".into())).err(),
            Some(failure(kinds::CONNECT, "Could not connect through bastion: Could not reach bastion.example.com:22 (connection refused)."))
        );
    }

    #[test]
    fn a_saved_host_that_cannot_be_found_or_named_by_its_alias_alone_is_a_host_error() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_second_host_called("web"));
        assert_eq!(world.connect(&HostQuery::Alias("mail".into())).err(), Some(failure(kinds::HOST, "No saved host is called mail.")));
        assert_eq!(
            world.connect(&web()).err(),
            Some(failure(kinds::HOST, "More than one saved host is called web. Connect with --id and the host's id."))
        );
    }

    /// The client went away (its terminal was closed while the window or a question waited): nothing more is connected.
    #[test]
    fn when_the_owner_goes_away_the_broker_stops_without_connecting_again() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust]);
        world.cancel.cancel();
        assert_eq!(world.connect(&web()).err().map(|failure| failure.kind), Some(CANCELLED.to_string()));
        assert!(world.engine.events().is_empty());
    }
}

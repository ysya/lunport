//! Opening a session (own-ssh spec §6.2, §7.2, §10): the broker's connect loop around the engine. The engine fails fast where a person
//! must decide (an unknown or changed host key, a password wanted after a refused key); the broker asks — the window for host keys, the
//! session's owner for everything else — and connects again with what it learned. Every call here blocks: it runs on the thread of the
//! client's connection, never in async code and never on the UI thread.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::auth::{label, printable, prompt_wait, BrokerAuth, KeyStore, Owner, PasswordSource, PinPolicy, Reply};
use super::directory::{DirectoryError, HostDirectory};
use super::protocol::{kinds, HostQuery, QuestionKind};
use crate::ssh::{AuthMethod, ConnectError, HopRef, HostId, HostKey, Session, SshEngine, Target};
use crate::sync::env::Keychain;

/// How many passwords the person may type for one host in one connect (OpenSSH's `NumberOfPasswordPrompts`). The one that
/// `BrokerAuth::password` asks before it connects a host that starts with the password method is the first of them.
pub const PASSWORD_PROMPTS: usize = 3;

/// What one host can ask of a connect, in connects, when the person answers everything it asks: its host key confirmed (once, see
/// `Done::asked_host_key`), the key type of a changed pin (once, plan 1b R17: `Done::unrestricted`) and its password typed
/// `PASSWORD_PROMPTS` times. Each is paid for by one answer and followed by one more connect.
const ROUNDS_PER_HOP: usize = 1 + 1 + PASSWORD_PROMPTS;

/// How many times a connect through `target` may go round: every host of the chain at the most it can ask (`ROUNDS_PER_HOP`), and the
/// connect that gets through. Everything that makes the loop go round again is capped for each host (`Done`), so no server reaches
/// this, whatever it does, and neither does a person who answers: it is a net under those caps, not a limit on what a chain may ask.
fn round_limit(target: &Target) -> usize {
    target.hops.len() * ROUNDS_PER_HOP + 1
}

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

/// A session that is open, and the target it reached (with what the connect learned: the pins the person confirmed, and a hop that starts
/// with keyboard-interactive and went password first for a typed password).
pub struct Connected {
    pub session: Box<dyn Session>,
    pub target: Target,
}

/// Why no session was opened: the sentence for the user (spec §11) and the `kind` word of the error event (`protocol::kinds`). The text
/// is printable (`printable`): it is shown outside the shell's own data stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectFailure {
    pub kind: String,
    pub text: String,
}

impl ConnectFailure {
    /// Every failure is made here, so this is where its text goes through `printable`: some of it was written by a server (a protocol
    /// error, the algorithms a server offers) and some comes from the person's configuration or the client's request (aliases and user
    /// names), and none of it may reach a terminal with an escape sequence or a carriage return in it. The sentences themselves have no
    /// such character and come out as they are.
    fn new(kind: &str, text: impl Into<String>) -> ConnectFailure {
        ConnectFailure { kind: kind.to_string(), text: printable(&text.into()) }
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

/// The failure the user sees when the connect stops at `hop` (`None`: at the chain as a whole) for `reason`. A failure on a jump host
/// is said through it (spec §11: `Could not connect through {jump alias}: {reason}`).
fn failure_at(hop: Option<&HopRef>, target: &Target, kind: &str, reason: impl fmt::Display) -> ConnectFailure {
    let destination = target.hops.last().map(|hop| &hop.id);
    match hop {
        Some(hop) if Some(&hop.id) != destination => ConnectFailure::new(kind, format!("Could not connect through {}: {reason}", hop.alias)),
        _ => ConnectFailure::new(kind, reason.to_string()),
    }
}

/// The failure the user sees for an engine error.
fn failure_of(error: &ConnectError, target: &Target) -> ConnectFailure {
    let kind = match error {
        ConnectError::HostKeyUnknown { .. } | ConnectError::HostKeyMismatch { .. } => kinds::HOST_KEY,
        ConnectError::AuthFailed { .. } | ConnectError::AuthAbandoned { .. } => kinds::AUTH,
        _ => kinds::CONNECT,
    };
    failure_at(hop_of(error), target, kind, error)
}

/// The login of `hop` was abandoned because the person did not give the password (they cancelled the question, let it run out, or
/// the client went away): spec §11's sentence, said through the jump host when `hop` is one. `BrokerAuth` remembers that a prompt of a
/// hop ended unanswered but not how, so the reason is the same for all three.
fn password_abandoned(hop: &HopRef, target: &Target) -> ConnectFailure {
    failure_of(&ConnectError::AuthAbandoned { hop: hop.clone(), reason: "the password was not given".to_string() }, target)
}

fn directory_failure(error: DirectoryError) -> ConnectFailure {
    ConnectFailure::new(kinds::HOST, error.to_string())
}

/// What a connect has done for each host so far, for the things it does only so often. A pass of the loop that is not the last is one
/// of these, so together they bound it (`round_limit`).
#[derive(Default)]
struct Done {
    /// Hosts whose key the person has been asked about. Once is all a connect needs: after the key was trusted (or the changed one
    /// accepted) the server presents that key. A server that then presents another one is not asked about again.
    asked_host_key: HashSet<HostId>,
    /// Hosts connected once more without the pinned key type (plan 1b R17).
    unrestricted: HashSet<HostId>,
    /// The passwords the person has been asked for, by host (`PASSWORD_PROMPTS` at the most).
    passwords_typed: HashMap<HostId, usize>,
}

impl Connector<'_> {
    /// Opens a session to the saved host `query` names, asking `owner` (the person at the client's terminal) what the login needs and the
    /// window about host keys, until it is open, it fails, or `cancel` is set. Once `cancel` is set the connect is over, however it
    /// came out: the failure is `cancelled` (nobody is told about it, whatever was being asked or tried when the client went away), and
    /// a session that did open meanwhile is closed here, on the caller's thread, instead of being handed to a client that is gone.
    pub fn connect(&self, query: &HostQuery, owner: &dyn Owner, cancel: &CancelToken) -> Result<Connected, ConnectFailure> {
        let result = self.connect_within(query, owner, cancel, round_limit);
        if !cancel.is_cancelled() {
            return result;
        }
        if let Ok(connected) = result {
            connected.session.close();
        }
        Err(ConnectFailure::cancelled())
    }

    /// `connect` with the bound on the rounds given (`round_limit` is the one `connect` uses): the net itself is tested with a smaller one.
    fn connect_within(&self, query: &HostQuery, owner: &dyn Owner, cancel: &CancelToken, rounds: fn(&Target) -> usize) -> Result<Connected, ConnectFailure> {
        if cancel.is_cancelled() {
            return Err(ConnectFailure::cancelled());
        }
        let mut target = self.directory.resolve(query).map_err(directory_failure)?;
        let auth = BrokerAuth::new(self.keys, self.keychain, owner, self.directory);
        auth.unlock(&target).map_err(|text| ConnectFailure::new(kinds::AUTH, text))?;
        let policy = PinPolicy::from_target(&target);
        let mut done = Done::default();
        for _ in 0..rounds(&target) {
            if cancel.is_cancelled() {
                return Err(ConnectFailure::cancelled());
            }
            auth.prepare(&target);
            let error = match self.engine.connect(&target, &policy, &auth) {
                Ok(session) => return Ok(Connected { session, target }),
                Err(error) => error,
            };
            match error {
                // The person gave up the password of a hop (cancelled the question, let it run out, or their client went away). The engine
                // asked it before it connected (a hop that starts with the password method) and went on without it, to a host key that was
                // not known yet, or a pinned key type the server no longer has, or a login that ended for want of the password ("no login
                // method could be tried" when the server offers nothing else). The attempt is over (spec §10, §11): the window is not opened
                // for it and nothing is pinned or connected again; the sentence is the abandonment, and the person connects again.
                ConnectError::HostKeyUnknown { ref hop, .. }
                | ConnectError::HostKeyMismatch { ref hop, .. }
                | ConnectError::NoCommonHostKeyAlgorithm { ref hop, .. }
                | ConnectError::AuthFailed { ref hop, .. }
                    if auth.cancelled(&hop.id) =>
                {
                    return Err(password_abandoned(hop, &target));
                }
                ConnectError::HostKeyUnknown { hop, key } => self.confirm(&mut target, &policy, &mut done, owner, cancel, &hop, &key, None)?,
                ConnectError::HostKeyMismatch { hop, key, pinned } => self.confirm(&mut target, &policy, &mut done, owner, cancel, &hop, &key, Some(pinned))?,
                // Plan 1b R17: the handshake offered only the pinned key's type and the server has none of it any more. Once more without the
                // restriction: the policy still knows the pin, so a key of another type comes back as a changed key, with its warning.
                ConnectError::NoCommonHostKeyAlgorithm { ref hop, .. } if policy.pinned(&hop.id).is_some() && done.unrestricted.insert(hop.id.clone()) => {
                    if let Some(restricted) = target.hops.iter_mut().find(|candidate| candidate.id == hop.id) {
                        restricted.pinned = None;
                    }
                }
                ConnectError::AuthFailed { ref hop, ref tried, password_wanted, .. } => {
                    // A password given and refused: a typed one is forgotten; a saved one stays saved, and what the person types is used instead.
                    let refused = tried.contains(&AuthMethod::Password) && auth.password_source(&hop.id).is_some();
                    // The first time a hop is counted, a password the person typed is already there when `BrokerAuth::password` asked for it
                    // before the connect (a hop that starts with the password method): that was their first of `PASSWORD_PROMPTS`.
                    let typed = done.passwords_typed.entry(hop.id.clone()).or_insert_with(|| usize::from(auth.password_source(&hop.id) == Some(PasswordSource::Typed)));
                    if !(password_wanted || refused) || *typed >= PASSWORD_PROMPTS {
                        return Err(failure_of(&error, &target));
                    }
                    auth.forget_typed(&hop.id);
                    let asks = format!("{}@{}'s password: ", label(&hop.user), label(&hop.alias));
                    let question = if refused { format!("That password didn't work. {asks}") } else { asks };
                    let Some(index) = target.hops.iter().position(|candidate| candidate.id == hop.id) else { return Err(failure_of(&error, &target)) };
                    let deadline = std::time::Instant::now().checked_add(prompt_wait(&target.hops[index]));
                    *typed += 1;
                    match owner.ask(QuestionKind::Password, &question, false, deadline) {
                        Reply::Answer(password) => {
                            auth.set_typed(&hop.id, password);
                            // Amended R8: the hop is connected again as it is. A server that takes a key and then wants the password
                            // (`AuthenticationMethods publickey,password`) still gets the key first, which a password-first reconnect
                            // would drop, and `BrokerAuth::password` answers the typed password from memory at once, so nobody waits while
                            // the connection is open. Only a hop with no password method in its sequence (it starts with
                            // keyboard-interactive) can use the password just by going password first.
                            if !target.hops[index].auth_sequence().contains(&AuthMethod::Password) {
                                target.hops[index].auth = AuthMethod::Password;
                            }
                        }
                        Reply::Cancelled | Reply::TimedOut => return Err(password_abandoned(hop, &target)),
                        Reply::Gone => return Err(ConnectFailure::cancelled()),
                    }
                }
                other => return Err(failure_of(&other, &target)),
            }
        }
        let alias = target.hops.last().map(|hop| hop.alias.clone()).unwrap_or_default();
        Err(ConnectFailure::new(kinds::CONNECT, format!("SSHelter gave up connecting to {alias} after too many attempts.")))
    }

    /// The pinned key `pinned`, which the key the server presented was compared with, as the question about a changed key shows it: its
    /// fingerprint, and when the directory pinned it. The date is the one of the directory's record of that very key. A directory that no
    /// longer holds it (another connection replaced or forgot the pin since this connect resolved the host) has no date to give, and a key
    /// that is not pinned any more cannot be replaced either (`replace_pin` refuses it, after the person has decided), so the connect
    /// ends here with a directory failure and connecting again starts from the pin as it is now. The refusal is the safest answer: the
    /// question has no place for a missing date, and a date that is made up (1970) or belongs to another key is worse than none.
    fn pinned_summary(&self, hop: &HopRef, pinned: &HostKey) -> Result<PinnedSummary, ConnectFailure> {
        match self.directory.pinned(&hop.id).map_err(directory_failure)? {
            Some(record) if record.key.fingerprint == pinned.fingerprint => Ok(PinnedSummary { fingerprint: pinned.fingerprint.clone(), pinned_at_ms: record.pinned_at_ms }),
            _ => Err(directory_failure(DirectoryError::Failed(format!("SSHelter's record of {}'s host key changed while it was connecting. Connect again.", hop.alias)))),
        }
    }

    /// Asks the window about `key`, which `hop` presented (`pinned`: the key on record, for a changed key). When the person trusts exactly
    /// this key, it is pinned (or replaces the old pin) and the next round connects with it; anything else ends the connect.
    #[allow(clippy::too_many_arguments)]
    fn confirm(
        &self,
        target: &mut Target,
        policy: &PinPolicy,
        done: &mut Done,
        owner: &dyn Owner,
        cancel: &CancelToken,
        hop: &HopRef,
        key: &HostKey,
        pinned: Option<HostKey>,
    ) -> Result<(), ConnectFailure> {
        // A host's key is asked about once in a connect. After the person trusted a key (or accepted the changed one) the server presents
        // that key; one that presents another still is a server whose key keeps changing, and asking again for each key it shows would
        // only teach clicking through. The sentence is about the server's key and blames nobody.
        if !done.asked_host_key.insert(hop.id.clone()) {
            let sentence = format!("The host key of {} kept changing while SSHelter was connecting. Connection refused.", hop.alias);
            return Err(failure_at(Some(hop), target, kinds::HOST_KEY, sentence));
        }
        // The summary first: when there is none to give, nobody is asked, and nobody is told to wait for a window that stays closed.
        let changed = match &pinned {
            None => None,
            Some(pinned) => Some(self.pinned_summary(hop, pinned)?),
        };
        owner.host_key_notice(&format!("Waiting for you to confirm {}'s host key in SSHelter.", label(&hop.alias)));
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
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use super::*;
    use crate::session::auth::Reply;
    use crate::session::directory::PinnedKey;
    use crate::session::testing::{locked, Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner, PINNED_AT_MS, TEST_PASSPHRASE};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
    use crate::ssh::russh_engine::toy_server::{ToyBehavior, ToyLogin, ToyServer};
    use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
    use crate::ssh::{AuthMethod, AuthSource, Hop, HostKey, HostKeyPolicy, HostKeyVerdict};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    const WAITING: &str = "Waiting for you to confirm web's host key in SSHelter.";

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).unwrap()
    }

    fn web() -> HostQuery {
        HostQuery::Alias("web".into())
    }

    /// An engine that counts the connects it is asked for, the ones that fail too (`FakeEngine::events` only has the ones that got through).
    /// It dereferences to the engine it wraps.
    struct Counting<E> {
        inner: E,
        attempts: AtomicUsize,
    }

    impl<E> Counting<E> {
        fn new(inner: E) -> Counting<E> {
            Counting { inner, attempts: AtomicUsize::new(0) }
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    impl<E> std::ops::Deref for Counting<E> {
        type Target = E;

        fn deref(&self) -> &E {
            &self.inner
        }
    }

    impl<E: SshEngine> SshEngine for Counting<E> {
        fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.inner.connect(target, host_keys, auth)
        }
    }

    struct World {
        engine: Counting<FakeEngine>,
        directory: FakeDirectory,
        keys: FakeKeys,
        keychain: MemKeychain,
        confirmer: FakeConfirmer,
        owner: FakeOwner,
        cancel: CancelToken,
    }

    fn world(engine: FakeEngine, directory: FakeDirectory) -> World {
        World { engine: Counting::new(engine), directory, keys: FakeKeys::new(), keychain: MemKeychain::default(), confirmer: FakeConfirmer::default(), owner: FakeOwner::default(), cancel: CancelToken::default() }
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

        /// The password of `web` is saved in the keychain, so that nobody is asked for it (the owner who has nothing to say would end the
        /// connect at that question, which these tests are not about).
        fn with_saved_password(self) -> World {
            self.keychain.set("host:id-web", "saved").unwrap();
            self
        }

        fn connect(&self, query: &HostQuery) -> Result<Connected, ConnectFailure> {
            self.connect_as(query, &self.owner)
        }

        /// The same, with another person at the terminal than the scripted one.
        fn connect_as(&self, query: &HostQuery, owner: &dyn Owner) -> Result<Connected, ConnectFailure> {
            self.connect_through(&self.directory, query, owner)
        }

        /// The same, with another directory than the world's.
        fn connect_through(&self, directory: &dyn HostDirectory, query: &HostQuery, owner: &dyn Owner) -> Result<Connected, ConnectFailure> {
            let connector = Connector { engine: &self.engine, directory, keys: &self.keys, keychain: &self.keychain, confirmer: &self.confirmer };
            connector.connect(query, owner, &self.cancel)
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
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).with_saved_password().deciding(vec![Decision::Refuse]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web has not been confirmed yet.")));
        assert!(world.directory.pins().is_empty());
    }

    /// The window answers for one fingerprint; only the key the broker itself observed is pinned, and only when the two match (as deploy's
    /// "trust this key" works): a stale answer pins nothing.
    #[test]
    fn an_answer_for_another_fingerprint_pins_nothing() {
        let world = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).with_saved_password().deciding(vec![Decision::TrustFingerprint("SHA256:stale".into())]);
        assert_eq!(world.connect(&web()).err(), Some(failure(kinds::HOST_KEY, "The host key of web has not been confirmed yet.")));
        assert!(world.directory.pins().is_empty());
    }

    #[test]
    fn a_changed_host_key_shows_the_pinned_one_and_replaces_it_only_when_accepted() {
        let old = key(test_keys::ENC_PUBLIC);
        let refusing = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", old.clone())).with_saved_password().deciding(vec![Decision::Refuse]);
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

    /// A directory whose record of the pin is another one by the time the broker looks it up for the question: another connection
    /// replaced or forgot the pin after this one resolved the host. `now` is what `pinned` answers from then on.
    struct PinMovedOn {
        inner: FakeDirectory,
        now: Option<PinnedKey>,
    }

    impl HostDirectory for PinMovedOn {
        fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
            self.inner.resolve(query)
        }

        fn pinned(&self, _host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
            Ok(self.now.clone())
        }

        fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
            self.inner.pin(host, key)
        }

        fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
            self.inner.replace_pin(host, previous, key)
        }

        fn password_account(&self, host: &HostId) -> String {
            self.inner.password_account(host)
        }
    }

    /// The question about a changed key names the key that is pinned and when it was pinned, and the date belongs to that key. When the
    /// directory does not hold the key the server's was compared with any more (another connection replaced or forgot the pin since this
    /// one resolved the host), there is no date to show: not 1970, and not the date of some other key. Nor is it worth asking: replacing a
    /// key that is not pinned is refused, after the person has decided. The connect ends and says so; connecting again starts from the
    /// pin as it is now, with nothing to ask when another connection accepted the new key.
    #[test]
    fn a_changed_host_key_is_not_asked_about_when_the_directory_no_longer_has_the_pin_it_was_compared_with() {
        let old = key(test_keys::ENC_PUBLIC);
        let saved = || FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", old.clone());
        let forgotten = PinMovedOn { inner: saved(), now: None };
        let replaced = PinMovedOn { inner: saved(), now: Some(PinnedKey { key: key(test_keys::ECDSA_PUBLIC), pinned_at_ms: 42 }) };
        let sentence = "SSHelter's record of web's host key changed while it was connecting. Connect again.";
        for (what, directory) in [("forgotten", forgotten), ("replaced", replaced)] {
            let world = world(FakeEngine::new(), FakeDirectory::new()).with_saved_password().deciding(vec![Decision::Trust]);
            assert_eq!(world.connect_through(&directory, &web(), &world.owner).err(), Some(failure(kinds::HOST, sentence)), "{what}");
            assert!(world.confirmer.asked().is_empty(), "{what}: the window was not asked");
            assert!(locked(&world.owner.notices).is_empty(), "{what}: nobody was told to wait for it either");
            assert_eq!(directory.inner.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(old.clone()), "{what}: nothing was pinned over the old key");
        }
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
        world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", pinned)).with_saved_password().deciding(vec![Decision::Refuse])
    }

    /// The fallback password after a refused key is not typed while the connection waits (russh spins then): the engine reports that a
    /// password is wanted, the broker asks, and connects again with the hop as it is (amended R8): the key stays first, as OpenSSH does
    /// it, and the engine gets the typed password from memory. The fake engine does not model a server that takes the key and then wants
    /// the password, so it cannot tell this order from the password first in a login; the tests on the in-process server below can.
    #[test]
    fn a_password_wanted_after_a_refused_key_is_asked_for_and_the_broker_connects_again_with_the_hops_own_method_order() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world(engine, directory).typing(&["right"]);
        let connected = world.connect(&web()).expect("the typed password gets in");
        assert_eq!(world.owner.questions(), ["deploy@web's password: "]);
        assert_eq!(connected.target.hops[0].auth, AuthMethod::Key { key_id: "k-plain".into() }, "the hop keeps its own method order");
    }

    /// A hop with no password method in its sequence (it starts with keyboard-interactive) can use a typed password only when it goes
    /// password first: it is the one hop whose method changes.
    #[test]
    fn a_keyboard_interactive_only_hop_is_connected_again_with_the_password_first() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Interactive).with_pin("web", default_server_key());
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
        assert_eq!(never.connect(&web()).err(), Some(failure(kinds::AUTH, "Authentication failed for deploy@web (tried: publickey, password).")));
        assert_eq!(never.owner.asked().len(), PASSWORD_PROMPTS);
    }

    /// The password a hop that starts with the password method is asked for before it connects (`BrokerAuth::password`) is the first
    /// password the person types for that hop, and the limit of three counts it: with nothing saved and every answer wrong, the person is
    /// asked three times, not four. A saved password that is refused is not one the person typed, so it is not counted.
    #[test]
    fn a_password_first_host_asks_for_its_password_three_times_at_most_the_one_before_the_connect_included() {
        let engine = || FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let directory = || FakeDirectory::new().with_host("web", AuthMethod::Password);
        let wrong = ["one", "two", "three", "four", "five"];
        let failed = failure(kinds::AUTH, "Authentication failed for deploy@web (tried: password).");
        let again = "That password didn't work. deploy@web's password: ";

        let never = world(engine(), directory().with_pin("web", default_server_key())).typing(&wrong);
        assert_eq!(never.connect(&web()).err(), Some(failed.clone()));
        assert_eq!(never.owner.questions(), ["deploy@web's password: ", again, again]);

        let first_contact = world(engine(), directory()).deciding(vec![Decision::Trust]).typing(&wrong);
        assert_eq!(first_contact.connect(&web()).err(), Some(failed.clone()));
        assert_eq!(first_contact.owner.questions(), ["deploy@web's password: ", again, again], "the host key window in between changes nothing");

        let saved = world(engine(), directory().with_pin("web", default_server_key())).typing(&wrong);
        saved.keychain.set("host:id-web", "old").unwrap();
        assert_eq!(saved.connect(&web()).err(), Some(failed));
        assert_eq!(saved.owner.questions(), [again; PASSWORD_PROMPTS], "the saved password was not typed by the person: three questions are theirs");

        let third_time = world(engine(), directory().with_pin("web", default_server_key())).typing(&["one", "two", "right"]);
        third_time.connect(&web()).expect("the third password is right");
        assert_eq!(third_time.owner.asked().len(), PASSWORD_PROMPTS);
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

    /// The password a hop that starts with the password method is asked for before it connects was cancelled, let run out, or its client
    /// went away, and the server offers nothing else: the engine ends the login with "no login method could be tried". The person did not
    /// fail to log in, they declined to, so it reads as the abandonment it is (spec §11), and they are not asked again.
    #[test]
    fn a_password_prompt_that_ended_unanswered_reads_as_abandoned_and_not_as_a_failed_login() {
        for reply in [Reply::Cancelled, Reply::TimedOut, Reply::Gone] {
            let label = format!("{reply:?}");
            let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
            let mut world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()));
            world.owner = FakeOwner::answering(vec![reply]);
            let abandoned = failure(kinds::AUTH, "Authentication for web was abandoned (the password was not given).");
            assert_eq!(world.connect(&web()).err(), Some(abandoned), "{label}");
            assert_eq!(world.owner.asked().len(), 1, "{label}: not asked again");
        }
    }

    /// The person cancels the password question of a first contact with a password-first host, lets it run out, or their client goes away.
    /// The engine asks it before it connects and goes on to the host key, which it has not seen yet, and the connect ends right there as
    /// abandoned (spec §10, §11: a cancelled or overdue prompt ends the attempt, and the person connects again). The window is not opened
    /// for a connect the person gave up, nobody is told to wait for it, nothing is pinned or replaced, and nothing connects again.
    #[test]
    fn a_cancelled_password_question_ends_the_connect_before_any_host_key_is_asked_about() {
        let abandoned = failure(kinds::AUTH, "Authentication for web was abandoned (the password was not given).");
        let cases = [
            ("a key not seen before", None),
            ("a changed key", Some(key(test_keys::ENC_PUBLIC))),
            ("a pinned key of another type", Some(key(test_keys::ECDSA_PUBLIC))),
        ];
        for (what, pin) in cases {
            for reply in [Reply::Cancelled, Reply::TimedOut, Reply::Gone] {
                let label = format!("{what}, {reply:?}");
                let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
                let directory = match &pin {
                    Some(pin) => directory.with_pin("web", pin.clone()),
                    None => directory,
                };
                let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
                let mut world = world(engine, directory).deciding(vec![Decision::Trust]);
                world.owner = FakeOwner::answering(vec![reply]);
                assert_eq!(world.connect(&web()).err(), Some(abandoned.clone()), "{label}");
                assert_eq!(world.owner.asked().len(), 1, "{label}: the password was asked for once");
                assert!(world.confirmer.asked().is_empty(), "{label}: the window was not asked");
                assert!(locked(&world.owner.notices).is_empty(), "{label}: nobody was told to wait for it");
                assert_eq!(world.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), pin, "{label}: nothing was pinned or replaced");
            }
        }
    }

    /// The same for a jump host that starts with the password method: the connect ends there, said through it (spec §11).
    #[test]
    fn a_cancelled_password_question_of_a_jump_host_ends_the_connect_before_its_host_key_is_asked_about() {
        let directory = FakeDirectory::new().with_host("bastion", AuthMethod::Password).with_host_via("db", AuthMethod::Password, &["bastion"]);
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let mut world = world(engine, directory).deciding(vec![Decision::Trust; 2]);
        world.owner = FakeOwner::answering(vec![Reply::Cancelled]);
        let through_bastion = "Could not connect through bastion: Authentication for bastion was abandoned (the password was not given).";
        assert_eq!(world.connect(&HostQuery::Alias("db".into())).err(), Some(failure(kinds::AUTH, through_bastion)));
        assert!(world.confirmer.asked().is_empty() && locked(&world.owner.notices).is_empty() && world.directory.pins().is_empty());
    }

    /// Spec §11: a failure on a jump host is said through it, an abandoned login too, whoever asked for the password: the engine, before
    /// it connected (a hop that starts with the password method), or the broker, between two connects (a hop that starts with a key).
    #[test]
    fn an_abandoned_password_on_a_jump_host_is_said_through_it() {
        let through_bastion = "Could not connect through bastion: Authentication for bastion was abandoned (the password was not given).";
        for bastion in [AuthMethod::Password, AuthMethod::Key { key_id: "k-plain".into() }] {
            let directory = FakeDirectory::new()
                .with_host("bastion", bastion.clone())
                .with_host_via("db", AuthMethod::Password, &["bastion"])
                .with_pin("bastion", default_server_key())
                .with_pin("db", default_server_key());
            let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
            let mut world = world(engine, directory);
            world.owner = FakeOwner::answering(vec![Reply::Cancelled]);
            assert_eq!(world.connect(&HostQuery::Alias("db".into())).err(), Some(failure(kinds::AUTH, through_bastion)), "{bastion:?}");
        }
    }

    /// The person at the terminal whose client goes away while a question waits: the connection's token is set first, and then the
    /// question ends as `Gone` (as the broker's connection does it).
    struct GoingOwner(CancelToken);

    impl Owner for GoingOwner {
        fn ask(&self, _kind: QuestionKind, _text: &str, _echo: bool, _deadline: Option<std::time::Instant>) -> Reply {
            self.0.cancel();
            Reply::Gone
        }

        fn host_key_notice(&self, _text: &str) {}

        fn banner(&self, _text: &str) {}
    }

    /// The person at the terminal who answers, and whose client goes away while the connect goes on: the token is set during the
    /// question, which the answer then still ends (as when the connection breaks between the answer and the next thing the broker does).
    struct AnswersThenGoes(CancelToken);

    impl Owner for AnswersThenGoes {
        fn ask(&self, _kind: QuestionKind, _text: &str, _echo: bool, _deadline: Option<std::time::Instant>) -> Reply {
            self.0.cancel();
            Reply::Answer(zeroize::Zeroizing::new("right".to_string()))
        }

        fn host_key_notice(&self, _text: &str) {}

        fn banner(&self, _text: &str) {}
    }

    /// A connect that gets through after the client went away has nobody to serve: the session is closed there and then, on the thread
    /// that connected, and the failure is `cancelled`, which nobody is told about; it is not handed over.
    #[test]
    fn a_connect_that_gets_through_after_the_client_went_away_closes_its_session() {
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let world = world(engine, FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()));
        let failed = world.connect_as(&web(), &AnswersThenGoes(world.cancel.clone()));
        assert_eq!(failed.err(), Some(failure(CANCELLED, "The connection was cancelled.")));
        assert_eq!(world.engine.events(), [FakeEvent::Connect { aliases: vec!["web".to_string()] }, FakeEvent::Closed], "the session was open, and is closed");
    }

    /// Whatever the client was asked when it went away, the failure is `cancelled`: a passphrase before anything connects, and a
    /// keyboard-interactive prompt while the connection is open (the engine ends that one as an abandoned login, which is not what
    /// happened to the person).
    #[test]
    fn a_client_that_goes_away_during_a_passphrase_or_a_keyboard_interactive_prompt_cancels_the_connect() {
        let passphrase = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-enc".into() }));
        let interactive = world(
            FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::interactive("Password: ", "right"))),
            FakeDirectory::new().with_host("web", AuthMethod::Interactive).with_pin("web", default_server_key()),
        );
        for (what, world) in [("a passphrase", passphrase), ("a keyboard-interactive prompt", interactive)] {
            let failed = world.connect_as(&web(), &GoingOwner(world.cancel.clone())).err();
            assert_eq!(failed, Some(failure(CANCELLED, "The connection was cancelled.")), "{what}");
        }
    }

    /// What a server wrote can end up in a failure: a protocol error, the algorithms it offers. A failure is printed on the person's
    /// terminal, so (plan 1b: server text outside the shell's own data stream goes through `printable`) nothing a terminal would act on
    /// gets through: not an escape sequence that clears the screen or redraws a prompt, not a carriage return that overwrites the line.
    #[test]
    fn a_failure_carries_no_control_character_of_the_text_a_server_wrote() {
        let hostile = "key exchange failed\u{1b}[2J\u{1b}[Hpassword: \rnow\r\nthen";
        let safe = "key exchange failed?[2J?[Hpassword: ?now\nthen";
        let key = || AuthMethod::Key { key_id: "k-plain".into() };
        let directory = || FakeDirectory::new().with_host("bastion", key()).with_host_via("db", key(), &["bastion"]).with_pin("bastion", default_server_key());
        let hop = |alias: &str| directory().resolve(&HostQuery::Alias(alias.into())).unwrap().hops.pop().unwrap().reference();
        let db = HostQuery::Alias("db".into());
        let protocol = |alias: &str| FakeEngine::new().failing_with(ConnectError::Protocol { hop: hop(alias), text: hostile.to_string() });

        let on_the_destination = world(protocol("db"), directory());
        assert_eq!(on_the_destination.connect(&db).err(), Some(failure(kinds::CONNECT, &format!("SSH error: {safe}"))));
        let on_a_jump_host = world(protocol("bastion"), directory());
        assert_eq!(on_a_jump_host.connect(&db).err(), Some(failure(kinds::CONNECT, &format!("Could not connect through bastion: SSH error: {safe}"))));

        // The algorithms a server offers are its own text.
        let offered = ConnectError::NoCommonHostKeyAlgorithm { hop: hop("db"), ours: vec!["ssh-ed25519".into()], theirs: vec!["ssh-dss\u{1b}[31m".into(), "evil\r\nline".into()] };
        let no_common = world(FakeEngine::new().failing_with(offered), directory());
        assert_eq!(
            no_common.connect(&db).err(),
            Some(failure(kinds::CONNECT, "Could not agree on a host key algorithm with db: the server offers ssh-dss?[31m, evil\nline, SSHelter accepts ssh-ed25519."))
        );
    }

    /// Every failure is made in one place, which is where its text is made printable, so no route to a failure can forget it: the
    /// directory's sentences (they name what the client asked for), the sentences of the engine and the broker's own.
    #[test]
    fn every_failure_text_is_printable_whatever_made_it() {
        let nobody = world(FakeEngine::new(), FakeDirectory::new());
        assert_eq!(nobody.connect(&HostQuery::Alias("we\u{1b}[2Jb".into())).err(), Some(failure(kinds::HOST, "No saved host is called we?[2Jb.")));
        assert_eq!(ConnectFailure::new(kinds::CONNECT, "a\u{1b}[2Jb\rc\r\nd\te\u{202E}f").text, "a?[2Jb?c\nd\te?f", "controls and bidirectional marks, not tabs and line feeds");
        assert_eq!(ConnectFailure::new(kinds::AUTH, "Authentication failed for deploy@web (tried: publickey).").text, "Authentication failed for deploy@web (tried: publickey).");
    }

    /// A client that goes away is not an abandoned login that anybody is told about (`cancelled`), whichever of the two asked for the
    /// password: the engine, before it connected, or the broker, between two connects.
    #[test]
    fn a_client_that_goes_away_while_a_password_is_asked_for_cancels_the_connect() {
        for auth in [AuthMethod::Password, AuthMethod::Key { key_id: "k-plain".into() }] {
            let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
            let world = world(engine, FakeDirectory::new().with_host("web", auth.clone()).with_pin("web", default_server_key()));
            let failed = world.connect_as(&web(), &GoingOwner(world.cancel.clone())).err();
            assert_eq!(failed, Some(failure(CANCELLED, "The connection was cancelled.")), "{auth:?}");
        }
    }

    /// The words the loop writes itself name the host and the user, and both come from the person's configuration (`ssh -G` copies the
    /// user unchecked): they are `printable` and on one line (spec §7.1), as in the questions `BrokerAuth` writes for the same hop. This
    /// is what reaches the terminal, in the password questions and in the notice that the window waits.
    #[test]
    fn the_names_in_the_loops_own_questions_and_notice_carry_no_control_character() {
        let alias = "we\u{1b}[2Jb";
        let query = HostQuery::Alias(alias.into());
        let hostile = |auth: AuthMethod| FakeDirectory::new().with_hop(Hop::new(&format!("id-{alias}"), alias, "web.example.com", 22, "de\u{1b}[2Jpl\noy", auth));
        let asks = "de?[2Jpl?oy@we?[2Jb's password: ";
        let engine = || FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));

        // The broker asks between two connects, for a hop that starts with a key: first, and again after a wrong password.
        let between = world(engine(), hostile(AuthMethod::Key { key_id: "k-plain".into() }).with_pin(alias, default_server_key())).typing(&["wrong", "right"]);
        between.connect(&query).expect("the second password is right");
        assert_eq!(between.owner.questions(), [asks.to_string(), format!("That password didn't work. {asks}")]);

        // `BrokerAuth` asks before the connect, for a hop that starts with the password method: the same words.
        let before = world(engine(), hostile(AuthMethod::Password).with_pin(alias, default_server_key())).typing(&["right"]);
        before.connect(&query).expect("the password is right");
        assert_eq!(before.owner.questions(), [asks]);

        // The notice that the host key waits in SSHelter's window.
        let noticed = world(FakeEngine::new(), hostile(AuthMethod::Key { key_id: "k-plain".into() })).deciding(vec![Decision::Trust]);
        noticed.connect(&query).expect("connects once the key is trusted");
        assert_eq!(*locked(&noticed.owner.notices), ["Waiting for you to confirm we?[2Jb's host key in SSHelter."]);
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

    // -----------------------------------------------------------------------------------------------------------------------------
    // How long a connect may go round. Every round after the first is paid for by one answer: a host key confirmed, the key type of a
    // changed pin, a password typed. A person who answers everything right must never be turned away by the bound.

    /// Five jump hosts and the destination, each a first contact whose server also wants a password after the key: twelve questions, all
    /// answered right, and thirteen connects.
    #[test]
    fn a_chain_of_six_hosts_that_each_ask_for_a_host_key_and_a_password_connects() {
        let key = || AuthMethod::Key { key_id: "k-plain".into() };
        let directory = FakeDirectory::new()
            .with_host("j1", key())
            .with_host("j2", key())
            .with_host("j3", key())
            .with_host("j4", key())
            .with_host("j5", key())
            .with_host_via("db", key(), &["j1", "j2", "j3", "j4", "j5"]);
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let world = world(engine, directory).deciding(vec![Decision::Trust; 6]).typing(&["right"; 6]);
        let connected = world.connect(&HostQuery::Alias("db".into())).expect("every question was answered right");
        assert_eq!(connected.target.hops.len(), 6);
        assert_eq!((world.confirmer.asked().len(), world.owner.asked().len(), world.engine.attempts()), (6, 6, 13));
    }

    /// Two typos and then the right password on each of three hosts (the limit is three passwords a host): the person did nothing wrong.
    #[test]
    fn two_typos_before_the_right_password_on_each_of_three_hosts_still_connect() {
        let key = || AuthMethod::Key { key_id: "k-plain".into() };
        let directory = FakeDirectory::new().with_host("j1", key()).with_host("j2", key()).with_host_via("db", key(), &["j1", "j2"]);
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let answers = ["x", "y", "right", "x", "y", "right", "x", "y", "right"];
        let world = world(engine, directory).deciding(vec![Decision::Trust; 3]).typing(&answers);
        world.connect(&HostQuery::Alias("db".into())).expect("the right password was typed within the limit on every host");
        assert_eq!((world.confirmer.asked().len(), world.owner.asked().len(), world.engine.attempts()), (3, 9, 13));
    }

    /// The most that one host can ask of a connect, on every host of a chain of three: its pinned key is of a type its server no longer
    /// has (the handshake is repeated without the restriction, plan 1b R17), the key it has now is accepted as the changed key it is, and
    /// the password is typed wrong twice before it is right. Five rounds a host, and the one that gets in.
    #[test]
    fn a_chain_of_three_hosts_that_each_need_every_kind_of_round_connects() {
        let key_hop = || AuthMethod::Key { key_id: "k-plain".into() };
        let ecdsa = || key(test_keys::ECDSA_PUBLIC);
        let directory = FakeDirectory::new()
            .with_host("j1", key_hop())
            .with_host("j2", key_hop())
            .with_host_via("db", key_hop(), &["j1", "j2"])
            .with_pin("j1", ecdsa())
            .with_pin("j2", ecdsa())
            .with_pin("db", ecdsa());
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let answers = ["x", "y", "right", "x", "y", "right", "x", "y", "right"];
        let world = world(engine, directory).deciding(vec![Decision::Trust; 3]).typing(&answers);
        let connected = world.connect(&HostQuery::Alias("db".into())).expect("every host got what it asked for");
        assert_eq!((world.confirmer.asked().len(), world.owner.asked().len(), world.engine.attempts()), (3, 9, 16));
        assert!(connected.target.hops.iter().all(|hop| hop.pinned == Some(default_server_key())), "every changed key was accepted");
    }

    /// A server whose host key is another one on every connect: several servers behind one name that do not share a key, or someone in the
    /// middle. The n-th connect presents `keys[n]` (the last key from then on), whichever host of the chain it is about.
    struct KeysInTurn {
        keys: Vec<HostKey>,
        connects: AtomicUsize,
    }

    impl SshEngine for KeysInTurn {
        fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, _auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
            let turn = self.connects.fetch_add(1, Ordering::SeqCst);
            let key = self.keys[turn.min(self.keys.len() - 1)].clone();
            let hop = target.hops[0].reference();
            Err(match host_keys.check(&hop, &key) {
                HostKeyVerdict::Pinned => ConnectError::Protocol { hop, text: "this server lets nobody in".to_string() },
                HostKeyVerdict::Unknown => ConnectError::HostKeyUnknown { hop, key },
                HostKeyVerdict::Mismatch { pinned } => ConnectError::HostKeyMismatch { hop, key, pinned },
            })
        }
    }

    /// The person trusted a key and the server shows another one on the next connect, and another after that: they are asked once, whatever
    /// they would answer, and the connect ends with a sentence about the server's key, not about anything they did (and said through the
    /// jump host when it is the jump host's key).
    #[test]
    fn a_server_whose_host_key_changes_after_it_was_trusted_is_asked_about_once() {
        let server = || KeysInTurn { keys: vec![key(test_keys::PLAIN_PUBLIC), key(test_keys::ENC_PUBLIC), key(test_keys::ECDSA_PUBLIC), key(test_keys::RSA_PUBLIC)], connects: AtomicUsize::new(0) };
        let refused = |text: &str| Some(failure(kinds::HOST_KEY, text));
        let connect = |world: &World, server: &KeysInTurn, query: &str| {
            let connector = Connector { engine: server, directory: &world.directory, keys: &world.keys, keychain: &world.keychain, confirmer: &world.confirmer };
            connector.connect(&HostQuery::Alias(query.into()), &world.owner, &world.cancel).err()
        };

        let unknown = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).deciding(vec![Decision::Trust; 4]);
        let (first, rest) = (server(), "The host key of web kept changing while SSHelter was connecting. Connection refused.");
        assert_eq!(connect(&unknown, &first, "web"), refused(rest));
        assert_eq!((unknown.confirmer.asked().len(), first.connects.load(Ordering::SeqCst)), (1, 2), "one question, and the connect that showed the other key");
        assert_eq!(unknown.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(key(test_keys::PLAIN_PUBLIC)), "the key the person trusted stays pinned");

        // A key that was pinned and changed: the person accepts the new one, and the server shows yet another.
        let changed = world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", key(test_keys::RSA_PUBLIC))).deciding(vec![Decision::Trust; 4]);
        assert_eq!(connect(&changed, &server(), "web"), refused(rest));
        assert_eq!(changed.confirmer.asked().len(), 1);
        assert_eq!(changed.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(key(test_keys::PLAIN_PUBLIC)));

        let through = world(FakeEngine::new(), FakeDirectory::new().with_host("bastion", AuthMethod::Password).with_host_via("db", AuthMethod::Password, &["bastion"])).deciding(vec![Decision::Trust; 4]);
        let sentence = "Could not connect through bastion: The host key of bastion kept changing while SSHelter was connecting. Connection refused.";
        assert_eq!(connect(&through, &server(), "db"), refused(sentence));
        assert_eq!(through.confirmer.asked().len(), 1);
    }

    /// The bound grows with the chain: every host at the most it can ask (its key, the key type of a changed pin, `PASSWORD_PROMPTS`
    /// passwords), and the connect that gets through.
    #[test]
    fn the_bound_on_the_rounds_is_derived_from_the_chain() {
        let chain = |hops: usize| Target { hops: (0..hops).map(|n| Hop::new(&format!("id-{n}"), &format!("h{n}"), "h.example.com", 22, "deploy", AuthMethod::Password)).collect() };
        for hops in 1..=6 {
            assert_eq!(round_limit(&chain(hops)), hops * (1 + 1 + PASSWORD_PROMPTS) + 1, "{hops} hosts");
        }
    }

    /// The bound is a net under the caps: no server and no person reaches it (every round after the first is paid for by something that is
    /// capped for each host), so it is tried with a smaller one. A connect that needs more rounds than it is given ends with a sentence
    /// that blames nobody, and one that needs exactly as many gets through.
    #[test]
    fn a_connect_that_needs_more_rounds_than_it_is_given_ends_with_a_sentence_that_blames_nobody() {
        let new = || world(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password)).with_saved_password().deciding(vec![Decision::Trust]);
        let within = |world: &World, rounds: fn(&Target) -> usize| {
            let connector = Connector { engine: &world.engine, directory: &world.directory, keys: &world.keys, keychain: &world.keychain, confirmer: &world.confirmer };
            connector.connect_within(&web(), &world.owner, &world.cancel, rounds)
        };
        // The first round stops at the host key, which the person confirms; the second gets through.
        let short = new();
        assert_eq!(within(&short, |_| 1).err(), Some(failure(kinds::CONNECT, "SSHelter gave up connecting to web after too many attempts.")));
        assert_eq!(short.engine.attempts(), 1);
        let enough = new();
        within(&enough, |_| 2).expect("two rounds are enough");
        assert_eq!(enough.engine.attempts(), 2);
    }

    // -----------------------------------------------------------------------------------------------------------------------------
    // The connect loop with the REAL engine, against the in-process server of the engine's tests (a port on 127.0.0.1: no OpenSSH, no
    // network beyond the machine). The fake engine does not model a server that takes a key and then wants the password (partial success),
    // so a test on the fake cannot tell a reconnect with the hop's own method order from one with the password first; these can.

    const TOY_PASSWORD: &str = "correct horse battery staple";

    fn toy_login() -> ToyLogin {
        ToyLogin { user: "deploy".to_string(), password: TOY_PASSWORD.to_string(), prompt: "Password: ".to_string(), rounds: None }
    }

    /// A server that wants the key of the vault key `k-plain` first and the password next (OpenSSH's `AuthenticationMethods
    /// publickey,password`). The test key is also the server's own host key, the one every fake server presents: the two roles are
    /// independent.
    fn toy_that_wants_a_key_and_then_the_password() -> ToyServer {
        ToyServer::start_with(toy_login(), ToyBehavior { key_then_password: Some(test_keys::PLAIN_PUBLIC.to_string()), ..ToyBehavior::default() })
    }

    /// The saved host `web` at `127.0.0.1:port`, starting its login with `auth`, with the server's host key pinned (or not).
    fn web_at(port: u16, auth: AuthMethod, pinned: bool) -> FakeDirectory {
        let directory = FakeDirectory::new().with_host("web", auth).with_address("web", "127.0.0.1", port);
        if pinned {
            directory.with_pin("web", default_server_key())
        } else {
            directory
        }
    }

    /// The real engine, with the fake window, vault, keychain and person around it.
    struct RealWorld {
        engine: RusshEngine,
        directory: FakeDirectory,
        keys: FakeKeys,
        keychain: MemKeychain,
        confirmer: FakeConfirmer,
        owner: FakeOwner,
    }

    fn real_world(directory: FakeDirectory, typing: &[&str]) -> RealWorld {
        RealWorld {
            engine: RusshEngine::with_options(EngineOptions { worker_threads: 2, ..EngineOptions::default() }),
            directory,
            keys: FakeKeys::new(),
            keychain: MemKeychain::default(),
            confirmer: FakeConfirmer::default(),
            owner: FakeOwner::typing(typing),
        }
    }

    impl RealWorld {
        fn connect(&self) -> Result<Connected, ConnectFailure> {
            let connector = Connector { engine: &self.engine, directory: &self.directory, keys: &self.keys, keychain: &self.keychain, confirmer: &self.confirmer };
            connector.connect(&web(), &self.owner, &CancelToken::default())
        }

        /// The connected session, or a panic that says what the person was asked on the way.
        fn connects(&self) -> Connected {
            self.connect().unwrap_or_else(|failure| panic!("the connect failed with {failure:?} after the questions {:?}", self.owner.questions()))
        }
    }

    /// The host is saved with a vault key and no password; the server wants the key and then the password. The first connect gets the key
    /// through and ends with the password wanted; the person types it, and the broker connects again with the hop as it is: the key, then
    /// the typed password from memory. With the password first the server would turn the password down for want of the key, and nobody
    /// could ever log in.
    #[test]
    fn a_typed_password_logs_in_to_a_server_that_wants_a_key_and_then_the_password() {
        let server = toy_that_wants_a_key_and_then_the_password();
        let world = real_world(web_at(server.port, AuthMethod::Key { key_id: "k-plain".into() }, true), &[TOY_PASSWORD]);
        let connected = world.connects();
        assert_eq!(world.owner.questions(), ["deploy@web's password: "], "the person typed the password once");
        assert_eq!(connected.target.hops[0].auth, AuthMethod::Key { key_id: "k-plain".into() }, "the hop kept its own method order");
        let result = connected.session.exec("true", Duration::from_secs(10), 1024).expect("a command runs on the connection");
        assert_eq!((result.exit_code, result.stdout), (Some(0), b"ok\n".to_vec()), "the server ran the command");
        assert_eq!(world.keychain.entry("host:id-web"), None, "what the person types is not saved");
    }

    /// A typed password the server turns down is asked for again, in the same order (the key goes through again, the password is the new
    /// one), and the limit of three still holds.
    #[test]
    fn a_typed_password_the_server_refuses_is_asked_for_again_up_to_three_times_in_the_hops_own_order() {
        let server = toy_that_wants_a_key_and_then_the_password();
        let key = || AuthMethod::Key { key_id: "k-plain".into() };

        let second_time = real_world(web_at(server.port, key(), true), &["not the password", TOY_PASSWORD]);
        second_time.connects();
        assert_eq!(second_time.owner.questions(), ["deploy@web's password: ", "That password didn't work. deploy@web's password: "]);

        let never = real_world(web_at(server.port, key(), true), &["one", "two", "three", TOY_PASSWORD]);
        assert_eq!(never.connect().err(), Some(failure(kinds::AUTH, "Authentication failed for deploy@web (tried: publickey, password).")));
        assert_eq!(never.owner.asked().len(), PASSWORD_PROMPTS, "the fourth answer was never asked for");
    }

    /// A first contact: the host key is confirmed in the window and pinned, the person types the password once, and the broker connects
    /// the third time.
    #[test]
    fn the_first_contact_with_a_server_that_wants_a_key_and_then_the_password_confirms_the_key_and_asks_for_the_password_once() {
        let server = toy_that_wants_a_key_and_then_the_password();
        let world = RealWorld {
            confirmer: FakeConfirmer::deciding(vec![Decision::Trust]),
            ..real_world(web_at(server.port, AuthMethod::Key { key_id: "k-plain".into() }, false), &[TOY_PASSWORD])
        };
        world.connects();
        assert_eq!(world.confirmer.asked().len(), 1);
        assert_eq!(world.owner.questions(), ["deploy@web's password: "]);
        assert_eq!(world.directory.pins().get(&HostId::from("id-web")).map(|pin| pin.key.clone()), Some(default_server_key()));
    }

    /// The one hop that does change its method: it starts with keyboard-interactive, so its sequence has no password method, and a typed
    /// password can only be used when the hop goes password first. (The server is the plain one: it takes the password and asks for it as
    /// a keyboard-interactive prompt too, and the first answer is wrong.)
    #[test]
    fn a_keyboard_interactive_only_hop_goes_password_first_on_the_in_process_server() {
        let server = ToyServer::start(toy_login());
        let world = real_world(web_at(server.port, AuthMethod::Interactive, true), &["not it", TOY_PASSWORD]);
        let connected = world.connects();
        assert_eq!(world.owner.questions(), ["(deploy@web) Password: ", "deploy@web's password: "]);
        assert_eq!(connected.target.hops[0].auth, AuthMethod::Password);
    }
}

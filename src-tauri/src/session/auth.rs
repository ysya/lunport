//! What the broker gives the engine for one connect (own-ssh spec §6.1, §7.2, decision 7): the host key policy, over the pins, and the
//! auth source, over the vault, the keychain and the session's owner (the person at the `sshelter connect` terminal, asked through
//! `question` frames). One `BrokerAuth` serves one `open_shell`, all its reconnects included: what the person typed lives in memory for
//! that long (a first contact connects twice: the host key is unknown the first time) and is dropped with it.
//!
//! The engine's rules (spec §6.1): passphrases and vault unlocking happen before `connect` (`BrokerAuth::unlock`); `sign` and a password
//! asked during the login must be quick, so a person is asked for a password only before the connection is opened, for a hop that
//! starts with the password method. A password wanted later, after a refused key, comes back as `AuthFailed { password_wanted }`, and the
//! broker asks and connects again with the password first.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::directory::HostDirectory;
use super::protocol::QuestionKind;
use crate::ssh::{AuthError, AuthMethod, AuthSource, ConnectError, Hop, HopRef, HostId, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, RsaHash, Secret, Signature, Target};
use crate::sync::env::Keychain;
use crate::vault::material::{self, Material, OpenError, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How many passphrases the person may try for one key (as the agent allows).
pub const PASSPHRASE_ATTEMPTS: usize = 3;

/// The keychain account of a passphrase remembered on this computer (the vault's: `vault:passphrase:<key id>`).
pub fn passphrase_account(key_id: &str) -> String {
    format!("vault:passphrase:{key_id}")
}

/// How long a person gets to answer a prompt for `hop`: 4 × its connect timeout, at least a minute (spec §6.2 step 4; the engine gives
/// keyboard-interactive the same).
pub fn prompt_wait(hop: &Hop) -> Duration {
    hop.connect_timeout.saturating_mul(4).max(Duration::from_secs(60))
}

/// `now + wait`, or a year from now when the clock cannot hold that.
fn deadline_after(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
}

/// A vault key as the broker sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultKey {
    /// The name the user gave it, for questions and messages.
    pub name: String,
    /// Its OpenSSH public key line.
    pub public_key: String,
    pub has_passphrase: bool,
}

/// The vault, for the broker: the keys it holds and their private halves. The app's implementation reads the sync state and the vault
/// file; tests keep keys in memory.
pub trait KeyStore: Send + Sync {
    fn key(&self, key_id: &str) -> Option<VaultKey>;
    /// The private key as the vault stores it: OpenSSH text, passphrase-protected when the key has a passphrase.
    fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String>;
}

/// How a question to the person ended.
#[derive(Debug)]
pub enum Reply {
    Answer(Secret),
    /// The person said no (Ctrl-C, Ctrl-D).
    Cancelled,
    /// The deadline passed.
    TimedOut,
    /// The client went away.
    Gone,
}

/// The owner of a session: the person at the client's terminal, who is asked for what a login needs (spec §7.2).
pub trait Owner: Send + Sync {
    /// Asks and waits for the answer until `deadline` (`None`: for as long as the owner is there).
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply;
    /// Shows that the host key waits for the person in SSHelter's window (spec §11); no answer.
    fn host_key_notice(&self, text: &str);
    /// Shows the server's banner (control characters already replaced).
    fn banner(&self, text: &str);
}

/// The text of a banner that is safe to print on a terminal: CRLF becomes LF, and every other control character (an escape sequence
/// from the server could rewrite the screen) becomes `?`. Tabs and line feeds stay.
pub fn printable(text: &str) -> String {
    text.replace("\r\n", "\n").chars().map(|c| if c.is_control() && c != '\n' && c != '\t' { '?' } else { c }).collect()
}

/// The host key policy of one connect: the pins of its hops, plus the keys the person trusts while it runs.
pub struct PinPolicy {
    pins: Mutex<HashMap<HostId, HostKey>>,
}

impl PinPolicy {
    /// The pins the directory put in the target's hops.
    pub fn from_target(target: &Target) -> PinPolicy {
        let pins = target.hops.iter().filter_map(|hop| hop.pinned.clone().map(|key| (hop.id.clone(), key))).collect();
        PinPolicy { pins: Mutex::new(pins) }
    }

    /// The person trusted `key` for `host` (and the directory has pinned it).
    pub fn pin(&self, host: &HostId, key: HostKey) {
        locked(&self.pins).insert(host.clone(), key);
    }

    pub fn pinned(&self, host: &HostId) -> Option<HostKey> {
        locked(&self.pins).get(host).cloned()
    }
}

impl HostKeyPolicy for PinPolicy {
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
        match locked(&self.pins).get(&hop.id) {
            Some(pinned) if pinned.fingerprint == key.fingerprint => HostKeyVerdict::Pinned,
            Some(pinned) => HostKeyVerdict::Mismatch { pinned: pinned.clone() },
            None => HostKeyVerdict::Unknown,
        }
    }
}

/// Where the last password given for a hop came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordSource {
    Keychain,
    Typed,
}

/// The auth source of one connect (see the module documentation).
pub struct BrokerAuth<'a> {
    keys: &'a dyn KeyStore,
    keychain: &'a dyn Keychain,
    owner: &'a dyn Owner,
    directory: &'a dyn HostDirectory,
    /// Keys opened for this connect (`unlock`), with their public key lines: the login asks for both and must not wait for the vault.
    opened: Mutex<HashMap<String, (Material, String)>>,
    /// Passwords the person typed, by hop: given again on the reconnects of this connect.
    typed: Mutex<HashMap<HostId, Secret>>,
    /// Hops whose prompt the person cancelled or let run out: they are not asked again in this connect.
    cancelled: Mutex<HashSet<HostId>>,
    /// Where the last password given for each hop came from.
    gave: Mutex<HashMap<HostId, PasswordSource>>,
    /// The hops of the target being connected that start with the password method, and their prompt deadlines.
    password_first: Mutex<HashMap<HostId, Duration>>,
}

impl<'a> BrokerAuth<'a> {
    pub fn new(keys: &'a dyn KeyStore, keychain: &'a dyn Keychain, owner: &'a dyn Owner, directory: &'a dyn HostDirectory) -> BrokerAuth<'a> {
        BrokerAuth {
            keys,
            keychain,
            owner,
            directory,
            opened: Mutex::new(HashMap::new()),
            typed: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(HashSet::new()),
            gave: Mutex::new(HashMap::new()),
            password_first: Mutex::new(HashMap::new()),
        }
    }

    /// The target the next `connect` uses: the engine asks a hop that starts with the password method for its password before it
    /// connects, and only then may a person be asked.
    pub fn prepare(&self, target: &Target) {
        *locked(&self.password_first) = target.hops.iter().filter(|hop| hop.auth == AuthMethod::Password).map(|hop| (hop.id.clone(), prompt_wait(hop))).collect();
    }

    /// Opens the vault keys of `target` before anything connects (spec §6.1): a key with a passphrase takes the one remembered in the
    /// keychain, or asks the person, up to `PASSPHRASE_ATTEMPTS` times. A key the vault does not have is left to the engine, which skips
    /// it and says so. `Err` is the sentence for the user; nothing has connected.
    pub fn unlock(&self, target: &Target) -> Result<(), String> {
        for hop in &target.hops {
            let AuthMethod::Key { key_id } = &hop.auth else { continue };
            if locked(&self.opened).contains_key(key_id) {
                continue;
            }
            let Some(key) = self.keys.key(key_id) else { continue };
            let Some(text) = self.keys.private_text(key_id).map_err(|error| format!("SSHelter cannot read the key {} from its vault ({error}).", key.name))? else {
                continue;
            };
            let material = self.open(hop, key_id, &key, &text)?;
            locked(&self.opened).insert(key_id.clone(), (material, key.public_key));
        }
        Ok(())
    }

    fn open(&self, hop: &Hop, key_id: &str, key: &VaultKey, text: &str) -> Result<Material, String> {
        let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: hop.reference(), reason: reason.to_string() }.to_string();
        match material::open(text, None) {
            Ok(material) => return Ok(material),
            Err(OpenError::NeedsPassphrase) => {}
            Err(OpenError::UnsupportedCipher(cipher)) => return Err(format!("The key {} is encrypted with {cipher}, which SSHelter cannot open.", key.name)),
            Err(OpenError::Unreadable | OpenError::WrongPassphrase) => return Err(format!("The key {} in SSHelter's vault cannot be read.", key.name)),
        }
        let account = passphrase_account(key_id);
        if let Ok(Some(saved)) = self.keychain.get(&account) {
            let saved = Zeroizing::new(saved);
            match material::open(text, Some(&saved)) {
                Ok(material) => return Ok(material),
                Err(_) => {
                    // A remembered passphrase that no longer opens the key (the key was replaced) is forgotten, so it is not tried again.
                    if let Err(error) = self.keychain.delete(&account) {
                        eprintln!("[session] cannot forget the stale remembered passphrase of key {key_id}: {error}");
                    }
                }
            }
        }
        let mut text_of_question = format!("Enter the passphrase for the key {}: ", key.name);
        for _ in 0..PASSPHRASE_ATTEMPTS {
            let passphrase = match self.owner.ask(QuestionKind::Passphrase, &text_of_question, false, Some(deadline_after(prompt_wait(hop)))) {
                Reply::Answer(passphrase) => passphrase,
                Reply::Cancelled | Reply::Gone => return Err(abandoned("the passphrase was not given")),
                Reply::TimedOut => return Err(abandoned("the passphrase prompt timed out")),
            };
            match material::open(text, Some(&passphrase)) {
                Ok(material) => return Ok(material),
                Err(OpenError::WrongPassphrase) => text_of_question = format!("That passphrase didn't work. Enter the passphrase for the key {}: ", key.name),
                Err(_) => return Err(format!("The key {} in SSHelter's vault cannot be read.", key.name)),
            }
        }
        Err(abandoned("the passphrase was wrong three times"))
    }

    /// The person typed `password` for `hop` (asked by the broker after `AuthFailed { password_wanted }`): it is given on the reconnect.
    pub fn set_typed(&self, hop: &HostId, password: Secret) {
        locked(&self.typed).insert(hop.clone(), password);
    }

    /// Forgets what the person typed for `hop` (the server refused it).
    pub fn forget_typed(&self, hop: &HostId) {
        locked(&self.typed).remove(hop);
    }

    /// The person cancelled a prompt for `hop` (or let it run out) during this connect.
    pub fn cancelled(&self, hop: &HostId) -> bool {
        locked(&self.cancelled).contains(hop)
    }

    /// Marks `hop` as cancelled: no more questions for it in this connect.
    pub fn cancel(&self, hop: &HostId) {
        locked(&self.cancelled).insert(hop.clone());
    }

    /// Where the last password given for `hop` came from.
    pub fn password_source(&self, hop: &HostId) -> Option<PasswordSource> {
        locked(&self.gave).get(hop).copied()
    }
}

impl AuthSource for BrokerAuth<'_> {
    /// Only a key `unlock` opened: anything else is skipped by the engine, which says the key is not available.
    fn public_key(&self, key_id: &str) -> Option<String> {
        locked(&self.opened).get(key_id).map(|(_, public_key)| public_key.clone())
    }

    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        let opened = locked(&self.opened);
        let (material, _) = opened.get(key_id).ok_or_else(|| AuthError::KeyUnavailable(format!("the key {key_id} was not opened")))?;
        let flags = match rsa_hash {
            Some(RsaHash::Sha512) => SSH_AGENT_RSA_SHA2_512,
            Some(RsaHash::Sha256) => SSH_AGENT_RSA_SHA2_256,
            None => 0,
        };
        material.sign(data, flags).map(Signature).map_err(|error| AuthError::Failed(error.to_string()))
    }

    /// What the person typed in this connect, else the keychain's; a person is asked only for a hop that starts with the password method,
    /// whose password the engine asks for before it connects. A fallback password (after a refused key) never waits for a person.
    fn password(&self, hop: &HopRef) -> Option<Secret> {
        if let Some(typed) = locked(&self.typed).get(&hop.id) {
            locked(&self.gave).insert(hop.id.clone(), PasswordSource::Typed);
            return Some(typed.clone());
        }
        match self.keychain.get(&self.directory.password_account(&hop.id)) {
            Ok(Some(saved)) if !saved.is_empty() => {
                locked(&self.gave).insert(hop.id.clone(), PasswordSource::Keychain);
                return Some(Zeroizing::new(saved));
            }
            Ok(_) => {}
            Err(error) => eprintln!("[session] cannot read the saved password of {}: {error}", hop.alias),
        }
        let wait = locked(&self.password_first).get(&hop.id).copied();
        let wait = wait.filter(|_| !self.cancelled(&hop.id))?;
        match self.owner.ask(QuestionKind::Password, &format!("{}@{}'s password: ", hop.user, hop.alias), false, Some(deadline_after(wait))) {
            Reply::Answer(password) => {
                locked(&self.typed).insert(hop.id.clone(), password.clone());
                locked(&self.gave).insert(hop.id.clone(), PasswordSource::Typed);
                Some(password)
            }
            Reply::Cancelled | Reply::TimedOut => {
                self.cancel(&hop.id);
                None
            }
            Reply::Gone => None,
        }
    }

    /// One question per prompt, in order, each showing which host asks (as OpenSSH does: `(user@host) Password:`), until `deadline`.
    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        if self.cancelled(&hop.id) {
            return None;
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            match self.owner.ask(QuestionKind::Interactive, &format!("({}@{}) {}", hop.user, hop.alias, prompt.text), prompt.echo, Some(deadline)) {
                Reply::Answer(answer) => answers.push(answer),
                Reply::Cancelled => {
                    self.cancel(&hop.id);
                    return None;
                }
                Reply::TimedOut | Reply::Gone => return None,
            }
        }
        Some(answers)
    }

    fn banner(&self, _hop: &HopRef, text: &str) {
        self.owner.banner(&printable(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::testing::{FakeDirectory, FakeKeys, FakeOwner, TEST_PASSPHRASE};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).unwrap()
    }

    fn target(auth: AuthMethod) -> Target {
        Target { hops: vec![Hop::new("id-web", "web", "web.example.com", 22, "deploy", auth)] }
    }

    fn web() -> HopRef {
        target(AuthMethod::Password).hops[0].reference()
    }

    struct World {
        keys: FakeKeys,
        keychain: MemKeychain,
        directory: FakeDirectory,
    }

    fn world() -> World {
        World { keys: FakeKeys::new(), keychain: MemKeychain::default(), directory: FakeDirectory::new() }
    }

    impl World {
        fn auth<'a>(&'a self, owner: &'a FakeOwner) -> BrokerAuth<'a> {
            BrokerAuth::new(&self.keys, &self.keychain, owner, &self.directory)
        }
    }

    #[test]
    fn the_policy_trusts_the_pinned_key_only_and_learns_the_keys_the_person_trusts() {
        let mut pinned = target(AuthMethod::Password);
        pinned.hops[0].pinned = Some(key(test_keys::PLAIN_PUBLIC));
        let policy = PinPolicy::from_target(&pinned);
        assert_eq!(policy.check(&web(), &key(test_keys::PLAIN_PUBLIC)), HostKeyVerdict::Pinned);
        assert_eq!(policy.check(&web(), &key(test_keys::ECDSA_PUBLIC)), HostKeyVerdict::Mismatch { pinned: key(test_keys::PLAIN_PUBLIC) });
        let other = HopRef { id: HostId::from("id-db"), ..web() };
        assert_eq!(policy.check(&other, &key(test_keys::PLAIN_PUBLIC)), HostKeyVerdict::Unknown);
        policy.pin(&other.id, key(test_keys::ECDSA_PUBLIC));
        assert_eq!(policy.check(&other, &key(test_keys::ECDSA_PUBLIC)), HostKeyVerdict::Pinned);
    }

    #[test]
    fn a_key_without_a_passphrase_opens_without_a_question_and_signs() {
        let world = world();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        assert_eq!(auth.public_key("k-plain"), None, "nothing is offered before the key is opened");
        auth.unlock(&target(AuthMethod::Key { key_id: "k-plain".into() })).unwrap();
        assert_eq!(auth.public_key("k-plain").as_deref(), Some(test_keys::PLAIN_PUBLIC));
        let signature = auth.sign("k-plain", b"challenge", None).unwrap();
        assert_eq!(&signature.0[4..15], b"ssh-ed25519");
        assert!(owner.asked().is_empty());
        assert!(matches!(auth.sign("k-enc", b"challenge", None), Err(AuthError::KeyUnavailable(_))), "a key that was not opened does not sign");
    }

    #[test]
    fn a_passphrase_remembered_in_the_keychain_opens_the_key_without_a_question() {
        let world = world();
        world.keychain.set(&passphrase_account("k-enc"), TEST_PASSPHRASE).unwrap();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        auth.unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })).unwrap();
        assert_eq!(auth.public_key("k-enc").as_deref(), Some(test_keys::ENC_PUBLIC));
        assert!(owner.asked().is_empty());
    }

    /// Asked before anything connects, without echo, and again after a wrong one; a stale remembered passphrase is forgotten first.
    #[test]
    fn a_passphrase_is_asked_before_the_connection_and_again_after_a_wrong_one() {
        let world = world();
        world.keychain.set(&passphrase_account("k-enc"), "an old passphrase").unwrap();
        let owner = FakeOwner::typing(&["wrong", TEST_PASSPHRASE]);
        let auth = world.auth(&owner);
        auth.unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })).unwrap();
        assert_eq!(
            owner.questions(),
            ["Enter the passphrase for the key laptop: ", "That passphrase didn't work. Enter the passphrase for the key laptop: "]
        );
        assert!(owner.asked().iter().all(|asked| asked.kind == QuestionKind::Passphrase && !asked.echo && asked.deadline.is_some()));
        assert_eq!(world.keychain.entry(&passphrase_account("k-enc")), None, "the stale passphrase was forgotten");
        assert!(auth.sign("k-enc", b"challenge", None).is_ok());
    }

    #[test]
    fn a_cancelled_passphrase_or_three_wrong_ones_abandon_the_connect_with_the_spec_sentence() {
        let world = world();
        let cancelled = FakeOwner::answering(vec![Reply::Cancelled]);
        assert_eq!(
            world.auth(&cancelled).unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })),
            Err("Authentication for web was abandoned (the passphrase was not given).".to_string())
        );
        let wrong = FakeOwner::typing(&["one", "two", "three", TEST_PASSPHRASE]);
        assert_eq!(
            world.auth(&wrong).unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })),
            Err("Authentication for web was abandoned (the passphrase was wrong three times).".to_string())
        );
        assert_eq!(wrong.asked().len(), PASSPHRASE_ATTEMPTS);
    }

    #[test]
    fn a_saved_password_is_given_without_asking_anyone() {
        let world = world();
        world.keychain.set("host:id-web", "saved secret").unwrap();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Password));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("saved secret"));
        assert_eq!(auth.password_source(&web().id), Some(PasswordSource::Keychain));
        assert!(owner.asked().is_empty());
    }

    /// The engine asks a password-first hop before it connects, and asks again on the reconnect after the host key was confirmed: the
    /// person types it once.
    #[test]
    fn the_password_of_a_password_first_hop_is_asked_once_and_kept_for_the_reconnect() {
        let world = world();
        let owner = FakeOwner::typing(&["typed secret"]);
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Password));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("typed secret"));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("typed secret"));
        assert_eq!(owner.questions(), ["deploy@web's password: "]);
        let asked = &owner.asked()[0];
        assert!(asked.kind == QuestionKind::Password && !asked.echo);
        let given = asked.deadline.unwrap().saturating_duration_since(Instant::now());
        assert!(given > Duration::from_secs(55) && given <= Duration::from_secs(60), "four connect timeouts, at least a minute: {given:?}");
        assert_eq!(auth.password_source(&web().id), Some(PasswordSource::Typed));
    }

    /// After a refused key the engine asks during the login, while the connection waits: a person is never asked then.
    #[test]
    fn a_fallback_password_never_asks_a_person() {
        let world = world();
        let owner = FakeOwner::typing(&["typed secret"]);
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Key { key_id: "k-plain".into() }));
        assert_eq!(auth.password(&web()), None);
        assert!(owner.asked().is_empty());
        auth.set_typed(&web().id, Zeroizing::new("asked by the broker".into()));
        assert_eq!(auth.password(&web()).as_deref().map(String::as_str), Some("asked by the broker"), "what the broker asked for is given");
    }

    /// The person said no to the password: keyboard-interactive, which the server may offer next, does not ask again.
    #[test]
    fn a_cancelled_password_is_not_asked_again_and_keyboard_interactive_does_not_ask_either() {
        let world = world();
        let owner = FakeOwner::answering(vec![Reply::Cancelled]);
        let auth = world.auth(&owner);
        auth.prepare(&target(AuthMethod::Password));
        assert_eq!(auth.password(&web()), None);
        assert!(auth.cancelled(&web().id));
        assert_eq!(auth.password(&web()), None);
        assert_eq!(auth.interactive(&web(), &[Prompt { text: "Password: ".into(), echo: false }], Instant::now() + Duration::from_secs(60)), None);
        assert_eq!(owner.asked().len(), 1);
    }

    #[test]
    fn keyboard_interactive_prompts_are_asked_one_by_one_with_their_echo_and_the_engines_deadline() {
        let world = world();
        let owner = FakeOwner::typing(&["secret", "123456"]);
        let auth = world.auth(&owner);
        let deadline = Instant::now() + Duration::from_secs(90);
        let prompts = [Prompt { text: "Password: ".into(), echo: false }, Prompt { text: "Verification code: ".into(), echo: true }];
        let answers = auth.interactive(&web(), &prompts, deadline).expect("answered");
        assert_eq!(answers.iter().map(|answer| answer.as_str()).collect::<Vec<_>>(), ["secret", "123456"]);
        assert_eq!(owner.questions(), ["(deploy@web) Password: ", "(deploy@web) Verification code: "]);
        assert_eq!(owner.asked().iter().map(|asked| (asked.kind, asked.echo, asked.deadline)).collect::<Vec<_>>(), [(QuestionKind::Interactive, false, Some(deadline)), (QuestionKind::Interactive, true, Some(deadline))]);

        let cancelling = FakeOwner::answering(vec![Reply::Cancelled]);
        let auth = world.auth(&cancelling);
        assert_eq!(auth.interactive(&web(), &prompts, deadline), None);
        assert!(auth.cancelled(&web().id));
    }

    /// A server's banner can carry escape sequences that would rewrite the user's terminal: they are replaced before it is shown.
    #[test]
    fn a_banner_reaches_the_owner_without_control_characters() {
        let world = world();
        let owner = FakeOwner::default();
        world.auth(&owner).banner(&web(), "Welcome\r\n\x1b[2JAll\tclear\x07\n");
        assert_eq!(*crate::session::testing::locked(&owner.banners), ["Welcome\n?[2JAll\tclear?\n"]);
    }
}

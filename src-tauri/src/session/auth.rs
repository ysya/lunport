//! What the broker gives the engine for one connect (own-ssh spec §6.1, §7.2, decision 7): the host key policy, over the pins, and the
//! auth source, over the vault, the keychain and the session's owner (the person at the `sshelter connect` terminal, asked through
//! `question` frames). One `BrokerAuth` serves one `open_shell`, all its reconnects included: what the person typed lives in memory for
//! that long (a first contact connects twice: the host key is unknown the first time) and is dropped with it.
//!
//! The engine's rules (spec §6.1): passphrases and vault unlocking happen before `connect` (`BrokerAuth::unlock`); `sign` and a password
//! asked during the login must be quick, so a person is asked for a password only before the connection is opened, for a hop that
//! starts with the password method (`BrokerAuth::prepare` records which). A password wanted later, after a refused key, comes back as
//! `AuthFailed { password_wanted }`: the broker asks the person between two connects, keeps the answer (`BrokerAuth::set_typed`) and connects
//! again with the hop's original method order, so a `publickey,password` server still gets the key first; `password` then answers the typed
//! password from memory at once, so nobody waits while a connection is open. Only a hop whose method sequence has no password method (it
//! starts with keyboard-interactive) is connected again with the password first.

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
    /// Asks and waits for the answer until `deadline` (`None`: for as long as the owner is there). Whatever a server wrote in `text` has
    /// been through `printable` already, so the owner shows it as it is.
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply;
    /// Shows that the host key waits for the person in SSHelter's window (spec §11); no answer.
    fn host_key_notice(&self, text: &str);
    /// Shows the server's banner (already through `printable`).
    fn banner(&self, text: &str);
}

/// Text a server wrote, made safe to print on a terminal: CRLF becomes LF, and every other control character (an escape sequence from
/// the server could rewrite the screen, or erase the line in front of the text) becomes `?`. The bidirectional controls and the line and
/// paragraph separators (`is_deceptive_format`) are not control characters but become `?` too. Tabs and line feeds stay, and a line feed
/// is the only line break left. Whatever a server wrote and the broker shows outside the shell's own data stream (a banner, a
/// keyboard-interactive prompt, and so on) goes through here before it is framed.
pub fn printable(text: &str) -> String {
    text.replace("\r\n", "\n").chars().map(|c| if (c.is_control() && c != '\n' && c != '\t') || is_deceptive_format(c) { '?' } else { c }).collect()
}

/// The characters `printable` replaces although they are not control characters. The bidirectional marks (U+061C, U+200E, U+200F),
/// embeddings and overrides (U+202A to U+202E) and isolates (U+2066 to U+2069) make text read in another order than it is written (as in
/// the "Trojan Source" attacks on source code: after U+202E the characters `drowssap` are shown as `password`). Some terminals may break
/// the line at U+2028 and U+2029, the line and paragraph separators; only a line feed may end a line here.
fn is_deceptive_format(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
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
    /// Hops whose prompt the person cancelled or let run out, or whose client went away: they are not asked again in this connect.
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

    /// The person cancelled a prompt for `hop` or let it run out, or the client went away, during this connect: `hop` is not asked again.
    pub fn cancelled(&self, hop: &HostId) -> bool {
        locked(&self.cancelled).contains(hop)
    }

    /// Marks `hop` as not to be asked again in this connect.
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
            // The person said no, let it run out or went away: this hop is not asked again in this connect.
            Reply::Cancelled | Reply::TimedOut | Reply::Gone => {
                self.cancel(&hop.id);
                None
            }
        }
    }

    /// One question per prompt, in order, each showing which host asks (as OpenSSH does: `(user@host) Password:`), until `deadline`. The
    /// prompt text is the server's, so it is shown without control characters (`printable`): a jump host must not be able to erase its own
    /// `(user@host) ` and draw another hop's in front of a password prompt. Nothing else of the server's reaches this call: the engine does
    /// not hand over a round's name and instructions.
    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        if self.cancelled(&hop.id) {
            return None;
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for prompt in prompts {
            let text = format!("({}@{}) {}", hop.user, hop.alias, printable(&prompt.text));
            match self.owner.ask(QuestionKind::Interactive, &text, prompt.echo, Some(deadline)) {
                Reply::Answer(answer) => answers.push(answer),
                // As in `password`: remembered however the prompt ended; the answers given so far are dropped with the round.
                Reply::Cancelled | Reply::TimedOut | Reply::Gone => {
                    self.cancel(&hop.id);
                    return None;
                }
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

    /// The agent remembers a passphrase under its own `passphrase_account`, and `sync/slots.rs` forgets the one of a slot whose key was
    /// replaced through that function: were the two formats to part, passphrases remembered on this computer would silently stop being
    /// found here, and stale ones would stay. The first assertion pins the documented format; when plan 1c deletes `agent/`, the second goes.
    #[test]
    fn the_passphrase_account_is_the_one_the_agent_remembers_under() {
        assert_eq!(passphrase_account("k-enc"), "vault:passphrase:k-enc");
        for key_id in ["k-enc", "0123456789abcdef0123456789abcdef", ""] {
            assert_eq!(passphrase_account(key_id), crate::agent::broker::passphrase_account(key_id), "key id {key_id:?}");
        }
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

    /// The passphrase prompt ran out, or the client went away: the connect ends with the sentence for it, nothing more is asked (no empty
    /// passphrase is tried in the person's place) and the key stays closed.
    #[test]
    fn a_passphrase_prompt_that_runs_out_or_finds_nobody_abandons_the_connect_and_leaves_the_key_closed() {
        let world = world();
        for (reply, sentence) in [
            (Reply::TimedOut, "Authentication for web was abandoned (the passphrase prompt timed out)."),
            (Reply::Gone, "Authentication for web was abandoned (the passphrase was not given)."),
        ] {
            let owner = FakeOwner::answering(vec![reply]);
            let auth = world.auth(&owner);
            assert_eq!(auth.unlock(&target(AuthMethod::Key { key_id: "k-enc".into() })), Err(sentence.to_string()));
            assert_eq!(owner.asked().len(), 1, "{sentence} Nothing is asked after it.");
            assert_eq!(auth.public_key("k-enc"), None);
            assert!(matches!(auth.sign("k-enc", b"challenge", None), Err(AuthError::KeyUnavailable(_))), "the key stays closed");
        }
    }

    /// Two hops of a chain use the same vault key: it is opened, and asked about, once; and again when the next connect of the session
    /// (after the host key was confirmed) unlocks the same target.
    #[test]
    fn a_key_that_two_hops_share_is_opened_and_asked_about_once() {
        let world = world();
        let owner = FakeOwner::typing(&[TEST_PASSPHRASE]);
        let auth = world.auth(&owner);
        let shared = AuthMethod::Key { key_id: "k-enc".into() };
        let chain = Target {
            hops: vec![
                Hop::new("id-bastion", "bastion", "bastion.example.com", 22, "jump", shared.clone()),
                Hop::new("id-web", "web", "web.example.com", 22, "deploy", shared),
            ],
        };
        auth.unlock(&chain).unwrap();
        auth.unlock(&chain).unwrap();
        assert_eq!(owner.questions(), ["Enter the passphrase for the key laptop: "]);
        assert_eq!(auth.public_key("k-enc").as_deref(), Some(test_keys::ENC_PUBLIC));
        assert!(auth.sign("k-enc", b"challenge", None).is_ok());
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

    /// A person gets four connect timeouts to answer, and at least a minute (the engine gives keyboard-interactive the same): a hop with a
    /// 30 s connect timeout waits two minutes, for a passphrase and for a password alike.
    #[test]
    fn a_prompt_is_waited_for_four_connect_timeouts_and_at_least_a_minute() {
        let hop = |id: &str, alias: &str, secs: u64, auth: AuthMethod| {
            Hop { connect_timeout: Duration::from_secs(secs), ..Hop::new(id, alias, "host.example.com", 22, "deploy", auth) }
        };
        for (secs, wait) in [(5, 60), (15, 60), (30, 120), (600, 2400)] {
            assert_eq!(prompt_wait(&hop("id-web", "web", secs, AuthMethod::Password)), Duration::from_secs(wait), "a connect timeout of {secs} s");
        }

        // The questions carry it. Nobody answers here: the deadlines are what is looked at.
        let chain = Target {
            hops: vec![hop("id-bastion", "bastion", 30, AuthMethod::Key { key_id: "k-enc".into() }), hop("id-web", "web", 30, AuthMethod::Password)],
        };
        let world = world();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        assert!(auth.unlock(&chain).is_err());
        auth.prepare(&chain);
        assert_eq!(auth.password(&chain.hops[1].reference()), None);
        let asked = owner.asked();
        assert_eq!(asked.iter().map(|asked| asked.kind).collect::<Vec<_>>(), [QuestionKind::Passphrase, QuestionKind::Password]);
        for question in &asked {
            let given = question.deadline.unwrap().saturating_duration_since(Instant::now());
            assert!(given > Duration::from_secs(115) && given <= Duration::from_secs(120), "the {:?} question was given {given:?}", question.kind);
        }
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

    /// What the person typed beats the saved password. When the server refuses it, `forget_typed` takes it back: the saved password is given
    /// again (and is still saved), what was typed for another hop stays, and nobody is asked.
    #[test]
    fn a_typed_password_is_given_before_the_saved_one_until_it_is_forgotten() {
        let world = world();
        world.keychain.set("host:id-web", "saved secret").unwrap();
        let owner = FakeOwner::default();
        let auth = world.auth(&owner);
        let db = HopRef { id: HostId::from("id-db"), alias: "db".into(), ..web() };
        let given = |hop: &HopRef| auth.password(hop).map(|password| password.to_string());
        auth.set_typed(&web().id, Zeroizing::new("typed for web".into()));
        auth.set_typed(&db.id, Zeroizing::new("typed for db".into()));
        assert_eq!(given(&web()).as_deref(), Some("typed for web"));
        assert_eq!(auth.password_source(&web().id), Some(PasswordSource::Typed));

        auth.forget_typed(&web().id);
        assert_eq!(given(&web()).as_deref(), Some("saved secret"));
        assert_eq!(auth.password_source(&web().id), Some(PasswordSource::Keychain));
        assert_eq!(world.keychain.entry("host:id-web").as_deref(), Some("saved secret"), "the saved password is still saved");
        assert_eq!(given(&db).as_deref(), Some("typed for db"), "what was typed for another hop stays");

        auth.forget_typed(&db.id);
        assert_eq!(given(&db), None, "nothing typed and nothing saved");
        assert!(owner.asked().is_empty());
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

    /// A prompt that ran out, or that nobody was there to answer (the client went away), is remembered like a cancelled one: neither the
    /// retry nor the keyboard-interactive round the server may offer next asks again.
    #[test]
    fn a_password_prompt_that_runs_out_or_finds_nobody_is_not_asked_again_either() {
        let world = world();
        for (reply, what) in [(Reply::TimedOut, "ran out"), (Reply::Gone, "found nobody")] {
            let owner = FakeOwner::answering(vec![reply]);
            let auth = world.auth(&owner);
            auth.prepare(&target(AuthMethod::Password));
            assert_eq!(auth.password(&web()), None, "the prompt {what}");
            assert!(auth.cancelled(&web().id), "the prompt {what}: it is not asked again in this connect");
            assert_eq!(auth.password(&web()), None);
            assert_eq!(auth.interactive(&web(), &[Prompt { text: "Password: ".into(), echo: false }], Instant::now() + Duration::from_secs(60)), None);
            assert_eq!(owner.asked().len(), 1, "the prompt {what}: neither the retry nor keyboard-interactive asked again");
        }
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

    /// A prompt that ran out, or that nobody was there to answer, ends the round (the prompts after it are not asked, and the answers given
    /// so far are not returned) and is remembered like a cancelled one: the round the server may offer next does not ask.
    #[test]
    fn a_keyboard_interactive_prompt_that_runs_out_or_finds_nobody_ends_the_round_and_is_not_asked_again() {
        let world = world();
        let prompts = [Prompt { text: "Password: ".into(), echo: false }, Prompt { text: "Code: ".into(), echo: true }, Prompt { text: "Again: ".into(), echo: true }];
        let deadline = Instant::now() + Duration::from_secs(60);
        for (reply, what) in [(Reply::TimedOut, "ran out"), (Reply::Gone, "found nobody")] {
            let owner = FakeOwner::answering(vec![Reply::Answer(Zeroizing::new("secret".into())), reply]);
            let auth = world.auth(&owner);
            assert_eq!(auth.interactive(&web(), &prompts, deadline), None, "the second prompt {what}");
            assert_eq!(owner.asked().len(), 2, "the third prompt is not asked");
            assert!(auth.cancelled(&web().id), "the second prompt {what}: it is not asked again in this connect");
            assert_eq!(auth.interactive(&web(), &prompts, deadline), None);
            assert_eq!(owner.asked().len(), 2, "the next round is not asked at all");
        }
    }

    /// The prompt text is the server's, and in a chain a jump host's: with a carriage return, a sequence that clears the line or a C1
    /// control it could erase the `(user@alias)` in front of it and draw another hop's, to be given that hop's password. The owner gets
    /// the text without control characters, behind its prefix; line feeds and tabs stay, so a prompt of several lines is still readable.
    #[test]
    fn a_keyboard_interactive_prompt_reaches_the_owner_without_control_characters_and_behind_its_prefix() {
        let world = world();
        let owner = FakeOwner::typing(&["one", "two", "three"]);
        let auth = world.auth(&owner);
        let prompts = [
            Prompt { text: "\r\x1b[2K(deploy@db) Password: ".into(), echo: false },
            Prompt { text: "Code:\u{9b}2J\r\nsecond\tline\n".into(), echo: true },
            Prompt { text: "\0\x08\x7f\u{85}tail".into(), echo: false },
        ];
        auth.interactive(&web(), &prompts, Instant::now() + Duration::from_secs(60)).expect("answered");
        let questions = owner.questions();
        for text in &questions {
            assert!(text.starts_with("(deploy@web) "), "the prefix stays in front: {text:?}");
            assert!(!text.chars().any(|c| c.is_control() && c != '\n' && c != '\t'), "no control character reaches the terminal: {text:?}");
        }
        assert_eq!(questions, ["(deploy@web) ??[2K(deploy@db) Password: ", "(deploy@web) Code:?2J\nsecond\tline\n", "(deploy@web) ????tail"]);
    }

    /// Bidirectional controls make text read in another order than it is written (`drowssap` shown as `password`), and the line and
    /// paragraph separators may end a line on some terminals; none of them is a control character in the Unicode sense, so `printable` names
    /// them. Text in right-to-left scripts, the joiners emoji and Persian need, and the characters next to the ranges stay. (The sample
    /// text is written as escapes: right-to-left letters in a source file are displayed in an order of their own.)
    #[test]
    fn printable_replaces_the_bidirectional_controls_and_the_line_separators_and_keeps_text_in_every_script() {
        let replaced = ['\u{061C}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}'].into_iter().chain('\u{202A}'..='\u{202E}').chain('\u{2066}'..='\u{2069}');
        for c in replaced {
            assert_eq!(printable(&format!("a{c}b")), "a?b", "U+{:04X}", c as u32);
        }
        assert_eq!(printable("Password\u{202E}: \u{2066}ssap\u{2069}\u{200F}"), "Password?: ?ssap??");
        assert_eq!(printable("a\u{2028}b\u{2029}c\nd"), "a?b?c\nd", "only a line feed ends a line");

        let kept = [
            "\u{0643}\u{0644}\u{0645}\u{0629}",                                // Arabic letters
            "\u{05E1}\u{05D9}\u{05E1}\u{05DE}\u{05D4}",                        // Hebrew letters
            "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}", // Persian with a zero-width non-joiner
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",                     // an emoji family, joined by zero-width joiners
            "\u{5BC6}\u{78BC} \u{e9} \u{fc}",                                   // Chinese and accented Latin letters
            "a\tb\nc",                                                         // the tab and the line feed
            "\u{2027}\u{202F}",                                                // the characters just outside the replaced ranges
        ];
        for text in kept {
            assert_eq!(printable(text), text);
        }
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

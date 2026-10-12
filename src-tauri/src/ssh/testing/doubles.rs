//! Stand-ins for what the broker will supply: a host key policy with a table of pins, and an auth source that signs with real vault
//! keys (`Material`), answers prompts from a script, and can be told to fail or to take its time. Both record what they were asked.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::ssh::{AuthError, AuthSource, HopRef, HostId, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, RsaHash, Secret, Signature};
use crate::vault::material::{open, Material, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a host that has no pin gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unpinned {
    /// `Unknown`: the engine must stop and report the key.
    Unknown,
    /// `Pinned`: any key is fine (for tests that are about something else).
    Trusted,
}

struct PolicyState {
    pins: HashMap<HostId, HostKey>,
    unpinned: Unpinned,
    seen: Vec<(HopRef, HostKey)>,
}

/// A `HostKeyPolicy` with a table of pins by host id, like the broker's will be. `pin` models the user confirming a key: a test connects,
/// gets `HostKeyUnknown { key }`, pins that key and connects again with the same policy.
pub struct TestPolicy {
    state: Mutex<PolicyState>,
}

impl TestPolicy {
    pub fn new(unpinned: Unpinned) -> Arc<TestPolicy> {
        Arc::new(TestPolicy { state: Mutex::new(PolicyState { pins: HashMap::new(), unpinned, seen: Vec::new() }) })
    }

    /// Every host is trusted, whatever key it presents.
    pub fn trusting() -> Arc<TestPolicy> {
        TestPolicy::new(Unpinned::Trusted)
    }

    /// Nothing is pinned: every key is `Unknown` until a test pins it.
    pub fn knowing_nothing() -> Arc<TestPolicy> {
        TestPolicy::new(Unpinned::Unknown)
    }

    pub fn pin(&self, hop: &HopRef, key: HostKey) {
        locked(&self.state).pins.insert(hop.id.clone(), key);
    }

    /// The (hop, key) pairs `check` was asked about, in order.
    pub fn seen(&self) -> Vec<(HopRef, HostKey)> {
        locked(&self.state).seen.clone()
    }
}

impl HostKeyPolicy for TestPolicy {
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
        let mut state = locked(&self.state);
        state.seen.push((hop.clone(), key.clone()));
        match state.pins.get(&hop.id) {
            Some(pinned) if pinned.fingerprint == key.fingerprint => HostKeyVerdict::Pinned,
            Some(pinned) => HostKeyVerdict::Mismatch { pinned: pinned.clone() },
            None if state.unpinned == Unpinned::Trusted => HostKeyVerdict::Pinned,
            None => HostKeyVerdict::Unknown,
        }
    }
}

/// One call of `AuthSource::sign`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignCall {
    pub key_id: String,
    pub rsa_hash: Option<RsaHash>,
    /// The algorithm named inside the signature that was returned (`ssh-ed25519`, `rsa-sha2-512`, …); `None` when signing failed.
    pub algorithm: Option<String>,
}

/// An `AuthSource` over real vault entries. Keys are registered under ids with `with_key`; passwords and answers come from the script.
pub struct VaultAuth {
    keys: HashMap<String, (Material, String)>,
    presented: HashMap<String, String>,
    password: Option<String>,
    answers: Option<Vec<String>>,
    answer_delay: Duration,
    overrun_deadline: bool,
    sign_error: Option<AuthError>,
    signs: Mutex<Vec<SignCall>>,
    password_asks: Mutex<Vec<HopRef>>,
    prompts: Mutex<Vec<Vec<Prompt>>>,
    banners: Mutex<Vec<(HopRef, String)>>,
    calls: Mutex<Vec<&'static str>>,
}

impl VaultAuth {
    pub fn new() -> VaultAuth {
        VaultAuth {
            keys: HashMap::new(),
            presented: HashMap::new(),
            password: None,
            answers: None,
            answer_delay: Duration::ZERO,
            overrun_deadline: false,
            sign_error: None,
            signs: Mutex::new(Vec::new()),
            password_asks: Mutex::new(Vec::new()),
            prompts: Mutex::new(Vec::new()),
            banners: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Puts the OpenSSH private key `private_text` in the vault double under `key_id`.
    pub fn with_key(mut self, key_id: &str, private_text: &str) -> VaultAuth {
        let material = open(private_text, None).expect("the vault opens the key");
        let public_line = ssh_key::PublicKey::new(material.key_data(), "").to_openssh().expect("the public key has an OpenSSH form");
        self.keys.insert(key_id.to_string(), (material, public_line));
        self
    }

    /// `public_key(key_id)` answers `public_line` instead of the public half of the key registered under `key_id`: the login announces one
    /// key and signs with another (the negative control of the signature check).
    pub fn presenting_public_key(mut self, key_id: &str, public_line: &str) -> VaultAuth {
        self.presented.insert(key_id.to_string(), public_line.to_string());
        self
    }

    /// `password` returns this (the user "typed" it). Without it `password` returns `None`.
    pub fn with_password(mut self, password: &str) -> VaultAuth {
        self.password = Some(password.to_string());
        self
    }

    /// `interactive` returns these answers. Without them it returns `None`, as a cancelled prompt does.
    pub fn with_answers(mut self, answers: &[&str]) -> VaultAuth {
        self.answers = Some(answers.iter().map(|answer| answer.to_string()).collect());
        self
    }

    /// `interactive` takes this long to answer. A source that behaves like the broker gives up at the deadline and returns `None`.
    pub fn with_answer_delay(mut self, delay: Duration) -> VaultAuth {
        self.answer_delay = delay;
        self
    }

    /// `interactive` ignores the deadline: it answers after its delay even when that is too late (a misbehaving source).
    pub fn overrunning_the_deadline(mut self) -> VaultAuth {
        self.overrun_deadline = true;
        self
    }

    /// `sign` fails with this error (a locked vault, a refused approval).
    pub fn failing_to_sign(mut self, error: AuthError) -> VaultAuth {
        self.sign_error = Some(error);
        self
    }

    pub fn sign_calls(&self) -> Vec<SignCall> {
        locked(&self.signs).clone()
    }

    pub fn password_asked_for(&self) -> Vec<HopRef> {
        locked(&self.password_asks).clone()
    }

    pub fn prompts_seen(&self) -> Vec<Vec<Prompt>> {
        locked(&self.prompts).clone()
    }

    /// The banners the engine handed over, with the hop that sent each.
    pub fn banners(&self) -> Vec<(HopRef, String)> {
        locked(&self.banners).clone()
    }

    /// The `AuthSource` methods the engine called, by name, in the order it called them (the other accessors keep one list per method and
    /// say nothing about the order between them).
    pub fn calls_in_order(&self) -> Vec<&'static str> {
        locked(&self.calls).clone()
    }

    fn called(&self, method: &'static str) {
        locked(&self.calls).push(method);
    }
}

impl Default for VaultAuth {
    fn default() -> Self {
        VaultAuth::new()
    }
}

/// The first SSH string of a signature blob: the algorithm name.
fn algorithm_of(blob: &[u8]) -> Option<String> {
    let length = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    String::from_utf8(blob.get(4..4 + length)?.to_vec()).ok()
}

impl AuthSource for VaultAuth {
    fn public_key(&self, key_id: &str) -> Option<String> {
        self.called("public_key");
        self.presented.get(key_id).cloned().or_else(|| self.keys.get(key_id).map(|(_, public_line)| public_line.clone()))
    }

    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        self.called("sign");
        let record = |algorithm: Option<String>| locked(&self.signs).push(SignCall { key_id: key_id.to_string(), rsa_hash, algorithm });
        if let Some(error) = &self.sign_error {
            record(None);
            return Err(error.clone());
        }
        let Some((material, _)) = self.keys.get(key_id) else {
            record(None);
            return Err(AuthError::KeyUnavailable(format!("no key {key_id} in the vault double")));
        };
        let flags = match rsa_hash {
            Some(RsaHash::Sha512) => SSH_AGENT_RSA_SHA2_512,
            Some(RsaHash::Sha256) => SSH_AGENT_RSA_SHA2_256,
            // Flag 0 is SHA-1 for RSA, on purpose: the double does not refuse, so the engine's own refusal shows as a missing call in `sign_calls`.
            None => 0,
        };
        match material.sign(data, flags) {
            Ok(blob) => {
                record(algorithm_of(&blob));
                Ok(Signature(blob))
            }
            Err(error) => {
                record(None);
                Err(AuthError::Failed(error.to_string()))
            }
        }
    }

    fn password(&self, hop: &HopRef) -> Option<Secret> {
        self.called("password");
        locked(&self.password_asks).push(hop.clone());
        self.password.clone().map(Zeroizing::new)
    }

    fn interactive(&self, _hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        self.called("interactive");
        locked(&self.prompts).push(prompts.to_vec());
        if !self.overrun_deadline && Instant::now() + self.answer_delay > deadline {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            return None;
        }
        std::thread::sleep(self.answer_delay);
        self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
    }

    fn banner(&self, hop: &HopRef, text: &str) {
        self.called("banner");
        locked(&self.banners).push((hop.clone(), text.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn hop(id: &str) -> HopRef {
        HopRef { id: HostId::from(id), alias: id.into(), hostname: "127.0.0.1".into(), port: 22, user: "tester".into() }
    }

    fn key(fingerprint: &str, algorithm: &str) -> HostKey {
        HostKey { algorithm: algorithm.into(), public_key: vec![1], fingerprint: fingerprint.into() }
    }

    #[test]
    fn the_policy_answers_from_its_pins_and_remembers_what_it_saw() {
        let policy = TestPolicy::knowing_nothing();
        let (web, db) = (hop("web"), hop("db"));
        assert_eq!(policy.check(&web, &key("SHA256:a", "ssh-ed25519")), HostKeyVerdict::Unknown);
        policy.pin(&web, key("SHA256:a", "ssh-ed25519"));
        assert_eq!(policy.check(&web, &key("SHA256:a", "ssh-ed25519")), HostKeyVerdict::Pinned);
        assert_eq!(
            policy.check(&web, &key("SHA256:b", "ssh-ed25519")),
            HostKeyVerdict::Mismatch { pinned: key("SHA256:a", "ssh-ed25519") }
        );
        assert_eq!(policy.check(&db, &key("SHA256:a", "ssh-ed25519")), HostKeyVerdict::Unknown, "pins are per host");
        assert_eq!(policy.seen().len(), 4);
        assert_eq!(TestPolicy::trusting().check(&db, &key("SHA256:z", "ssh-rsa")), HostKeyVerdict::Pinned);
    }

    #[test]
    fn the_vault_double_signs_with_the_hash_it_is_given_and_records_the_call() {
        let auth = VaultAuth::new().with_key("ed", &test_keys::plain()).with_key("rsa", &test_keys::rsa());
        assert_eq!(auth.public_key("ed").as_deref(), Some(test_keys::PLAIN_PUBLIC));
        assert_eq!(auth.public_key("missing"), None);
        let signature = auth.sign("ed", b"challenge", None).unwrap();
        assert_eq!(algorithm_of(&signature.0).as_deref(), Some("ssh-ed25519"));
        let signature = auth.sign("rsa", b"challenge", Some(RsaHash::Sha256)).unwrap();
        assert_eq!(algorithm_of(&signature.0).as_deref(), Some("rsa-sha2-256"));
        let signature = auth.sign("rsa", b"challenge", Some(RsaHash::Sha512)).unwrap();
        assert_eq!(algorithm_of(&signature.0).as_deref(), Some("rsa-sha2-512"));
        assert_eq!(auth.sign("missing", b"x", None), Err(AuthError::KeyUnavailable("no key missing in the vault double".into())));
        assert_eq!(
            auth.sign_calls(),
            vec![
                SignCall { key_id: "ed".into(), rsa_hash: None, algorithm: Some("ssh-ed25519".into()) },
                SignCall { key_id: "rsa".into(), rsa_hash: Some(RsaHash::Sha256), algorithm: Some("rsa-sha2-256".into()) },
                SignCall { key_id: "rsa".into(), rsa_hash: Some(RsaHash::Sha512), algorithm: Some("rsa-sha2-512".into()) },
                SignCall { key_id: "missing".into(), rsa_hash: None, algorithm: None },
            ]
        );
    }

    #[test]
    fn the_vault_double_can_be_told_to_fail_and_to_answer_prompts() {
        let failing = VaultAuth::new().with_key("ed", &test_keys::plain()).failing_to_sign(AuthError::Refused("locked".into()));
        assert_eq!(failing.sign("ed", b"x", None), Err(AuthError::Refused("locked".into())));

        let auth = VaultAuth::new().with_password("pw").with_answers(&["one", "two"]);
        assert_eq!(auth.password(&hop("web")).as_deref().map(String::as_str), Some("pw"));
        let prompts = [Prompt { text: "Code: ".into(), echo: true }];
        let deadline = Instant::now() + Duration::from_secs(5);
        let answers = auth.interactive(&hop("web"), &prompts, deadline).unwrap();
        assert_eq!(answers.iter().map(|answer| answer.as_str()).collect::<Vec<_>>(), ["one", "two"]);
        assert_eq!(auth.password_asked_for(), vec![hop("web")]);
        assert_eq!(auth.prompts_seen(), vec![prompts.to_vec()]);
        auth.banner(&hop("web"), "Authorized use only.");
        assert_eq!(auth.banners(), vec![(hop("web"), "Authorized use only.".to_string())]);
        assert_eq!(auth.calls_in_order(), vec!["password", "interactive", "banner"], "the order of the calls is kept, which the lists above do not say");

        let silent = VaultAuth::new();
        assert!(silent.password(&hop("web")).is_none() && silent.interactive(&hop("web"), &prompts, deadline).is_none());
    }

    #[test]
    fn a_slow_answer_is_given_up_at_the_deadline_unless_the_double_misbehaves_on_purpose() {
        let prompts = [Prompt { text: "Code: ".into(), echo: true }];
        let patient = VaultAuth::new().with_answers(&["late"]).with_answer_delay(Duration::from_secs(2));
        let started = Instant::now();
        assert!(patient.interactive(&hop("web"), &prompts, Instant::now() + Duration::from_millis(200)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1), "it gave up at the deadline: {:?}", started.elapsed());

        let rude = VaultAuth::new().with_answers(&["late"]).with_answer_delay(Duration::from_millis(300)).overrunning_the_deadline();
        let answers = rude.interactive(&hop("web"), &prompts, Instant::now() + Duration::from_millis(50));
        assert_eq!(answers.map(|answers| answers.len()), Some(1), "a misbehaving source answers anyway");
    }
}

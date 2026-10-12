//! Test doubles for the broker's tests (`#[cfg(test)]` in `session/mod.rs`): saved hosts in memory, and the checks every
//! `HostDirectory` must pass.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use zeroize::Zeroizing;

use super::auth::{KeyStore, Owner, Reply, VaultKey};
use super::directory::{decide_pin, decide_replace, DirectoryError, HostDirectory, PinDecision, PinnedKey};
use super::protocol::{HostQuery, QuestionKind};
use super::ssh_config_directory::MAX_JUMPS;
use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target};
use crate::sync::slot_rules::test_keys;

/// The passphrase of `test_keys::encrypted()`.
pub const TEST_PASSPHRASE: &str = "test-passphrase";

/// A vault in memory: `k-plain` is the ed25519 test key without a passphrase (named "plain"), `k-enc` the one with the passphrase
/// `TEST_PASSPHRASE` (named "laptop").
pub struct FakeKeys {
    keys: HashMap<String, (VaultKey, String)>,
}

impl FakeKeys {
    pub fn new() -> FakeKeys {
        let mut keys = HashMap::new();
        keys.insert(
            "k-plain".to_string(),
            (VaultKey { name: "plain".into(), public_key: test_keys::PLAIN_PUBLIC.into() }, test_keys::plain()),
        );
        keys.insert(
            "k-enc".to_string(),
            (VaultKey { name: "laptop".into(), public_key: test_keys::ENC_PUBLIC.into() }, test_keys::encrypted()),
        );
        FakeKeys { keys }
    }
}

impl KeyStore for FakeKeys {
    fn key(&self, key_id: &str) -> Option<VaultKey> {
        self.keys.get(key_id).map(|(key, _)| key.clone())
    }

    fn private_text(&self, key_id: &str) -> Result<Option<Zeroizing<String>>, String> {
        Ok(self.keys.get(key_id).map(|(_, text)| Zeroizing::new(text.clone())))
    }
}

/// One question the fake owner was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub kind: QuestionKind,
    pub text: String,
    pub echo: bool,
    pub deadline: Option<Instant>,
}

/// The person at the client's terminal, scripted: each question takes the next reply (none left: `Reply::Gone`, the person left).
/// Everything shown and asked is recorded.
#[derive(Default)]
pub struct FakeOwner {
    replies: Mutex<VecDeque<Reply>>,
    pub asked: Mutex<Vec<Asked>>,
    pub notices: Mutex<Vec<String>>,
    pub banners: Mutex<Vec<String>>,
}

impl FakeOwner {
    pub fn answering(replies: Vec<Reply>) -> FakeOwner {
        FakeOwner { replies: Mutex::new(replies.into()), ..FakeOwner::default() }
    }

    /// The person answers each question with these, in order.
    pub fn typing(answers: &[&str]) -> FakeOwner {
        FakeOwner::answering(answers.iter().map(|answer| Reply::Answer(Zeroizing::new(answer.to_string()))).collect())
    }

    pub fn asked(&self) -> Vec<Asked> {
        locked(&self.asked).clone()
    }

    /// The texts of the questions asked, in order.
    pub fn questions(&self) -> Vec<String> {
        self.asked().into_iter().map(|asked| asked.text).collect()
    }
}

impl Owner for FakeOwner {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        locked(&self.asked).push(Asked { kind, text: text.to_string(), echo, deadline });
        locked(&self.replies).pop_front().unwrap_or(Reply::Gone)
    }

    fn host_key_notice(&self, text: &str) {
        locked(&self.notices).push(text.to_string());
    }

    fn banner(&self, text: &str) {
        locked(&self.banners).push(text.to_string());
    }
}

pub fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One saved host of a `FakeDirectory`.
#[derive(Clone)]
struct FakeHost {
    hop: Hop,
    /// The aliases of its jump hosts, in the order they are connected.
    jumps: Vec<String>,
}

/// Saved hosts and pins in memory. A host added as `web` has the id `id-web`, the hostname `web.example.com`, port 22 and the user
/// `deploy`; pins are dated `PINNED_AT_MS`. Chains are resolved as the ssh_config adapter will: the first jump host's own jump hosts come
/// in front of it (a later one is just itself, as OpenSSH routes a list), and a chain that loops, names a host twice without looping
/// (`bastion,bastion`, the host itself as a later jump host, a later jump host that the first one's own jump hosts have) or names a host
/// that is not saved is refused with the adapter's sentences.
#[derive(Default)]
pub struct FakeDirectory {
    hosts: Vec<FakeHost>,
    pins: Mutex<HashMap<HostId, PinnedKey>>,
    /// Every call that reads the pins fails (`with_unreadable_pins`).
    unreadable_pins: bool,
}

/// The time every pin of a `FakeDirectory` was made.
pub const PINNED_AT_MS: u64 = 1_700_000_000_000;

impl FakeDirectory {
    pub fn new() -> FakeDirectory {
        FakeDirectory::default()
    }

    /// A saved host reached directly, starting its login with `auth`.
    pub fn with_host(self, alias: &str, auth: AuthMethod) -> FakeDirectory {
        self.with_host_via(alias, auth, &[])
    }

    /// A saved host reached through the saved hosts `jumps`, in this order. As OpenSSH routes `ProxyJump a,b`, only the first of them is
    /// reached through jump hosts of its own; each later one is reached through the one before it, whatever jump hosts it has itself.
    pub fn with_host_via(mut self, alias: &str, auth: AuthMethod, jumps: &[&str]) -> FakeDirectory {
        let hop = Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", auth);
        self.hosts.push(FakeHost { hop, jumps: jumps.iter().map(|jump| jump.to_string()).collect() });
        self
    }

    /// A second saved host called `alias`, with the id `id-<alias>-2`: the alias alone no longer says which.
    pub fn with_second_host_called(mut self, alias: &str) -> FakeDirectory {
        let hop = Hop::new(&format!("id-{alias}-2"), alias, &format!("{alias}-2.example.com"), 22, "deploy", AuthMethod::Password);
        self.hosts.push(FakeHost { hop, jumps: Vec::new() });
        self
    }

    /// The key pinned for the host with this alias.
    pub fn with_pin(self, alias: &str, key: HostKey) -> FakeDirectory {
        locked(&self.pins).insert(HostId::from(format!("id-{alias}")), PinnedKey { key, pinned_at_ms: PINNED_AT_MS });
        self
    }

    /// The pins cannot be read, as when the pin file is damaged: `resolve`, `pinned`, `pin` and `replace_pin` fail with `Failed`, which
    /// names `host-pins.json` as the real store's does, and write nothing. `pins()` still shows what was set with `with_pin`.
    pub fn with_unreadable_pins(mut self) -> FakeDirectory {
        self.unreadable_pins = true;
        self
    }

    /// What is pinned now, by host id.
    pub fn pins(&self) -> HashMap<HostId, PinnedKey> {
        locked(&self.pins).clone()
    }

    fn by_alias(&self, alias: &str) -> Result<&FakeHost, DirectoryError> {
        let mut found = self.hosts.iter().filter(|host| host.hop.alias == alias);
        match (found.next(), found.next()) {
            (None, _) => Err(DirectoryError::NotFound(format!("No saved host is called {alias}."))),
            (Some(host), None) => Ok(host),
            (Some(_), Some(_)) => Err(DirectoryError::Ambiguous(format!("More than one saved host is called {alias}. Connect with --id and the host's id."))),
        }
    }

    /// The pins, or the failure the real store gives when its file cannot be read.
    fn readable_pins(&self) -> Result<MutexGuard<'_, HashMap<HostId, PinnedKey>>, DirectoryError> {
        if self.unreadable_pins {
            return Err(DirectoryError::Failed("SSHelter cannot read its pinned host keys in host-pins.json (the file is damaged).".to_string()));
        }
        Ok(locked(&self.pins))
    }

    fn with_its_pin(&self, hop: &Hop) -> Result<Hop, DirectoryError> {
        Ok(Hop { pinned: self.readable_pins()?.get(&hop.id).map(|pin| pin.key.clone()), ..hop.clone() })
    }

    /// The hops of `host` and of its jump hosts, as OpenSSH routes them (`ProxyJump a,b,c` is `ssh -J a,b -W host c`, and `-J` replaces
    /// what a later jump host says about how it is reached): the first jump host behind its own jump hosts, each later one just itself,
    /// then `host`. `above` holds the hosts above `host` in the chain, the target first; `host` among them makes a loop, which can only
    /// happen through first jump hosts, the only ones followed into their own. A host that comes up twice without a loop is refused as
    /// well (a chain has one hop per host id).
    fn hops_of<'a>(&'a self, host: &'a FakeHost, above: &mut Vec<&'a Hop>) -> Result<Vec<Hop>, DirectoryError> {
        let loops = above.iter().any(|hop| hop.id == host.hop.id);
        above.push(&host.hop);
        if loops {
            let path: Vec<&str> = above.iter().map(|hop| hop.alias.as_str()).collect();
            return Err(DirectoryError::Unsupported(format!("The jump hosts go round in a circle: {}.", path.join(" → "))));
        }
        // More than `MAX_JUMPS` hosts above this one (the target first) are all jump hosts of the chain: refused at once, as the adapter does
        // before it runs `ssh -G` for more hosts.
        if above.len() > MAX_JUMPS + 1 {
            return Err(DirectoryError::Unsupported(format!("{} needs more than {MAX_JUMPS} jump hosts.", above[0].alias)));
        }
        let mut hops: Vec<Hop> = Vec::new();
        for (index, jump) in host.jumps.iter().enumerate() {
            let jump_host = match self.by_alias(jump) {
                Err(DirectoryError::NotFound(_)) => {
                    return Err(DirectoryError::Unsupported(format!("{} jumps through {jump}, which is not a saved host.", host.hop.alias)));
                }
                found => found?,
            };
            let jump_hops = if index == 0 { self.hops_of(jump_host, above)? } else { vec![self.with_its_pin(&jump_host.hop)?] };
            // The host named is the last of these hops that the earlier ones have too: the one nearest the jump host written.
            if let Some(twice) = jump_hops.iter().rev().find(|hop| hops.iter().any(|seen| seen.id == hop.id)) {
                return Err(DirectoryError::Unsupported(format!("{}'s jump hosts name {} twice.", host.hop.alias, twice.alias)));
            }
            hops.extend(jump_hops);
            // Every hop gathered so far is a jump host of the chain asked for (`above[0]`), whatever level this host is on.
            if hops.len() > MAX_JUMPS {
                return Err(DirectoryError::Unsupported(format!("{} needs more than {MAX_JUMPS} jump hosts.", above[0].alias)));
            }
        }
        if hops.iter().any(|seen| seen.id == host.hop.id) {
            return Err(DirectoryError::Unsupported(format!("{}'s jump hosts name {} twice.", host.hop.alias, host.hop.alias)));
        }
        hops.push(self.with_its_pin(&host.hop)?);
        above.pop();
        Ok(hops)
    }
}

impl HostDirectory for FakeDirectory {
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        let host = match query {
            HostQuery::Alias(alias) => self.by_alias(alias)?,
            HostQuery::Id(id) => self
                .hosts
                .iter()
                .find(|host| host.hop.id.as_str() == id)
                .ok_or_else(|| DirectoryError::NotFound(format!("No saved host has the id {id}.")))?,
        };
        Ok(Target { hops: self.hops_of(host, &mut Vec::new())? })
    }

    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        Ok(self.readable_pins()?.get(host).cloned())
    }

    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        let mut pins = self.readable_pins()?;
        match decide_pin(host, pins.get(host).map(|pinned| pinned.key.fingerprint.as_str()), key) {
            PinDecision::AlreadyPinned => Ok(()),
            PinDecision::Refuse(sentence) => Err(DirectoryError::Failed(sentence)),
            PinDecision::Write => {
                pins.insert(host.clone(), PinnedKey { key: key.clone(), pinned_at_ms: PINNED_AT_MS });
                Ok(())
            }
        }
    }

    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
        let mut pins = self.readable_pins()?;
        match decide_replace(host, pins.get(host).map(|pinned| pinned.key.fingerprint.as_str()), previous, key) {
            PinDecision::AlreadyPinned => Ok(()),
            PinDecision::Refuse(sentence) => Err(DirectoryError::Failed(sentence)),
            PinDecision::Write => {
                pins.insert(host.clone(), PinnedKey { key: key.clone(), pinned_at_ms: PINNED_AT_MS });
                Ok(())
            }
        }
    }

    fn password_account(&self, host: &HostId) -> String {
        format!("host:{host}")
    }
}

/// What every `HostDirectory` must do with pins, for the host `query` names, which has no pin yet: a replace has nothing to replace, pin
/// once (again is fine, another key is refused), and replace only from the key that is pinned. A refused call writes nothing. The
/// resolved hop carries the pin.
pub fn check_the_pin_contract(directory: &dyn HostDirectory, query: &HostQuery, first: &HostKey, second: &HostKey, third: &HostKey) {
    let hop = directory.resolve(query).expect("the host resolves").hops.pop().expect("a hop");
    assert_eq!(hop.pinned, None, "nothing is pinned yet");
    assert_eq!(directory.pinned(&hop.id), Ok(None));
    assert!(directory.replace_pin(&hop.id, first, second).is_err(), "nothing is pinned: there is nothing to replace");
    assert_eq!(directory.pinned(&hop.id), Ok(None), "a refused replace pins nothing");
    directory.pin(&hop.id, first).expect("a first pin");
    directory.pin(&hop.id, first).expect("the same key again");
    assert!(directory.pin(&hop.id, second).is_err(), "another key is not pinned over the first");
    assert_eq!(directory.pinned(&hop.id).unwrap().map(|pin| pin.key), Some(first.clone()));
    assert_eq!(directory.resolve(query).unwrap().hops.pop().unwrap().pinned, Some(first.clone()), "the resolved hop carries the pin");
    assert!(directory.replace_pin(&hop.id, third, second).is_err(), "only the pinned key can be replaced");
    assert_eq!(directory.pinned(&hop.id).unwrap().map(|pin| pin.key), Some(first.clone()), "a refused replace writes nothing: the pin stays");
    directory.replace_pin(&hop.id, first, second).expect("the changed key replaces the pinned one");
    assert_eq!(directory.pinned(&hop.id).unwrap().map(|pin| pin.key), Some(second.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).expect("a test key")
    }

    #[test]
    fn the_fake_directory_keeps_the_pin_contract() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
        check_the_pin_contract(&directory, &HostQuery::Alias("web".into()), &key(test_keys::PLAIN_PUBLIC), &key(test_keys::ECDSA_PUBLIC), &key(test_keys::RSA_PUBLIC));
    }

    #[test]
    fn the_fake_directory_resolves_by_alias_or_id_with_the_jump_hosts_first_and_says_when_an_alias_is_not_enough() {
        let directory = FakeDirectory::new()
            .with_host("bastion", AuthMethod::Key { key_id: "k1".into() })
            .with_host_via("db", AuthMethod::Password, &["bastion"])
            .with_second_host_called("web")
            .with_host("web", AuthMethod::Password)
            .with_pin("bastion", key(test_keys::PLAIN_PUBLIC));
        let chain = directory.resolve(&HostQuery::Alias("db".into())).unwrap();
        let aliases: Vec<&str> = chain.hops.iter().map(|hop| hop.alias.as_str()).collect();
        assert_eq!(aliases, ["bastion", "db"]);
        assert_eq!(chain.hops[0].pinned, Some(key(test_keys::PLAIN_PUBLIC)));
        assert_eq!(directory.resolve(&HostQuery::Id("id-db".into())).unwrap(), chain);
        assert!(matches!(directory.resolve(&HostQuery::Alias("web".into())), Err(DirectoryError::Ambiguous(_))));
        assert_eq!(directory.resolve(&HostQuery::Id("id-web-2".into())).unwrap().hops[0].hostname, "web-2.example.com");
        assert!(matches!(directory.resolve(&HostQuery::Alias("mail".into())), Err(DirectoryError::NotFound(_))));
        assert_eq!(directory.password_account(&HostId::from("id-db")), "host:id-db");
    }

    #[test]
    fn a_jump_host_with_jump_hosts_of_its_own_has_them_in_front_of_it() {
        let directory = FakeDirectory::new()
            .with_host("edge", AuthMethod::Password)
            .with_host_via("bastion", AuthMethod::Password, &["edge"])
            .with_host_via("db", AuthMethod::Password, &["bastion"])
            .with_host_via("web", AuthMethod::Password, &["bastion"]);
        let aliases = |alias: &str| -> Vec<String> {
            directory.resolve(&HostQuery::Alias(alias.into())).unwrap().hops.iter().map(|hop| hop.alias.clone()).collect()
        };
        assert_eq!(aliases("db"), ["edge", "bastion", "db"]);
        assert_eq!(aliases("web"), ["edge", "bastion", "web"], "a jump host that two hosts share is not a loop");
    }

    /// The trait says a chain that loops is an error: refused with the hosts from the one asked for round the circle, as the ssh_config
    /// adapter does it. Only the first jump host of a list is followed into its own jump hosts (as OpenSSH routes a list), so only there
    /// can a loop be found.
    #[test]
    fn a_chain_that_goes_round_in_a_circle_is_refused_with_the_path_round_it() {
        let directory = FakeDirectory::new()
            .with_host_via("self", AuthMethod::Password, &["self"])
            .with_host_via("loop1", AuthMethod::Password, &["loop2"])
            .with_host_via("loop2", AuthMethod::Password, &["loop1"])
            .with_host("bastion", AuthMethod::Password)
            .with_host_via("behind", AuthMethod::Password, &["loop1", "bastion"])
            .with_host_via("after", AuthMethod::Password, &["bastion", "loop1"]);
        let refused = |query: HostQuery| directory.resolve(&query);
        let circle = |path: &str| Err(DirectoryError::Unsupported(format!("The jump hosts go round in a circle: {path}.")));
        assert_eq!(refused(HostQuery::Alias("self".into())), circle("self → self"));
        assert_eq!(refused(HostQuery::Alias("loop1".into())), circle("loop1 → loop2 → loop1"));
        assert_eq!(refused(HostQuery::Id("id-loop2".into())), circle("loop2 → loop1 → loop2"), "by id as well");
        assert_eq!(refused(HostQuery::Alias("behind".into())), circle("behind → loop1 → loop2 → loop1"), "the first jump host is followed into its own");
        let after = refused(HostQuery::Alias("after".into())).unwrap();
        assert_eq!(after.hops.iter().map(|hop| hop.alias.as_str()).collect::<Vec<_>>(), ["bastion", "loop1", "after"], "a later one is not followed: no loop");
    }

    /// Pins are keyed by host id and the broker keeps what it knows about a hop by it too, so a chain names each host once. A host that comes
    /// up twice without a loop (`bastion,bastion`, a later jump host that the first one's own jump hosts have, or the host itself named as a
    /// later jump host) is refused with a sentence of its own, the same as the ssh_config adapter's; the host whose jump hosts name it twice
    /// is the one the sentence is about.
    #[test]
    fn a_host_that_a_chain_names_twice_is_refused_although_nothing_loops() {
        let directory = FakeDirectory::new()
            .with_host("bastion", AuthMethod::Password)
            .with_host_via("edge", AuthMethod::Password, &["bastion"])
            .with_host_via("twice", AuthMethod::Password, &["bastion", "bastion"])
            .with_host_via("via-edge", AuthMethod::Password, &["edge", "bastion"])
            .with_host_via("own", AuthMethod::Password, &["bastion", "own"])
            .with_host_via("deep", AuthMethod::Password, &["twice"])
            .with_host_via("down", AuthMethod::Password, &["bastion", "edge"]);
        let refused = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into()));
        let named_twice = |text: &str| Err(DirectoryError::Unsupported(text.to_string()));
        assert_eq!(refused("twice"), named_twice("twice's jump hosts name bastion twice."));
        assert_eq!(refused("via-edge"), named_twice("via-edge's jump hosts name bastion twice."), "`edge` is reached through `bastion`, and `bastion` comes again");
        assert_eq!(refused("own"), named_twice("own's jump hosts name own twice."), "a later jump host that is the host itself");
        assert_eq!(refused("deep"), named_twice("twice's jump hosts name bastion twice."), "the host that names it twice, not the one asked for");
        assert!(refused("edge").is_ok() && refused("bastion").is_ok(), "each of them is fine alone");
        let aliases = |alias: &str| refused(alias).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>());
        assert_eq!(aliases("down"), Ok(["bastion", "edge", "down"].map(String::from).to_vec()), "ssh goes bastion → edge → down: `edge` is no second `bastion`");
    }

    /// OpenSSH routes `ProxyJump a,b,c` as `ssh -J a,b -W target c` (and for `c` as `ssh -J a -W c b`, for `b` as `ssh -W b a`): only the
    /// first jump host is reached through its own jump hosts, and a later one is just its own hop, behind the one before it; `-J` replaces
    /// everything it says about how it is reached. The ssh_config adapter does the same.
    #[test]
    fn only_the_first_jump_host_of_a_list_is_reached_through_its_own_jump_hosts() {
        let directory = FakeDirectory::new()
            .with_host("x", AuthMethod::Password)
            .with_host_via("a", AuthMethod::Password, &["x"])
            .with_host("y", AuthMethod::Password)
            .with_host_via("b", AuthMethod::Password, &["y"])
            .with_host_via("t", AuthMethod::Password, &["a", "b"])
            .with_host_via("lost", AuthMethod::Password, &["gate"])
            .with_host_via("t2", AuthMethod::Password, &["a", "lost"])
            .with_host_via("t3", AuthMethod::Password, &["lost", "a"]);
        let aliases = |alias: &str| {
            directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>())
        };
        assert_eq!(aliases("t"), Ok(["x", "a", "b", "t"].map(String::from).to_vec()), "a's own jump host x comes first; b's own jump host y is not visited");
        assert_eq!(aliases("t2"), Ok(["x", "a", "lost", "t2"].map(String::from).to_vec()), "a later jump host's own unsaved jump host is not used");
        assert_eq!(
            aliases("t3"),
            Err(DirectoryError::Unsupported("lost jumps through gate, which is not a saved host.".to_string())),
            "the first one is reached the way it is saved"
        );
    }


    /// A chain has at most five jump hosts, counted over the whole chain: the first jump host's own and the later ones together, however
    /// they are written or nested, as the ssh_config adapter counts them. The sentence names the host that was asked for.
    #[test]
    fn a_chain_of_more_than_five_jump_hosts_is_refused_however_they_are_listed_or_nested() {
        let directory = ["j1", "j2", "j3", "j4", "j5", "j6"]
            .iter()
            .fold(FakeDirectory::new(), |fake, alias| fake.with_host(alias, AuthMethod::Password))
            .with_host_via("five", AuthMethod::Password, &["j1", "j2", "j3", "j4", "j5"])
            .with_host_via("six", AuthMethod::Password, &["j1", "j2", "j3", "j4", "j5", "j6"])
            .with_host_via("front", AuthMethod::Password, &["j1", "j2", "j3"])
            .with_host_via("exact", AuthMethod::Password, &["front", "j4"])
            .with_host_via("over", AuthMethod::Password, &["front", "j4", "j5"])
            .with_host_via("nested", AuthMethod::Password, &["front"])
            .with_host_via("deeper", AuthMethod::Password, &["nested"])
            .with_host_via("deepest", AuthMethod::Password, &["deeper"])
            .with_host_via("via-six", AuthMethod::Password, &["six"]);
        let hops = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.len());
        let too_many = |alias: &str| Err(DirectoryError::Unsupported(format!("{alias} needs more than 5 jump hosts.")));
        assert_eq!(hops("five"), Ok(6), "five jump hosts in a list");
        assert_eq!(hops("six"), too_many("six"), "six in a list: nothing is nested");
        assert_eq!(hops("exact"), Ok(6), "the first jump host's three and itself, and one more: five");
        assert_eq!(hops("over"), too_many("over"), "the first jump host's three and itself, and two more: six");
        assert_eq!(hops("nested"), Ok(5));
        assert_eq!(hops("deeper"), Ok(6), "five jump hosts, three levels deep");
        assert_eq!(hops("deepest"), too_many("deepest"), "six jump hosts, only four levels deep");
        assert_eq!(hops("via-six"), too_many("via-six"), "the host that was asked for, not the jump host that has the six");
    }

    /// The sentence is the ssh_config adapter's, so a broker test sees what the app will say.
    #[test]
    fn a_jump_host_that_is_not_saved_is_worded_the_way_the_ssh_config_adapter_will_word_it() {
        let directory = FakeDirectory::new()
            .with_host_via("db", AuthMethod::Password, &["gate"])
            .with_host_via("web", AuthMethod::Password, &["bastion"])
            .with_host_via("bastion", AuthMethod::Password, &["gate"]);
        let refused = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into()));
        let not_saved = |alias: &str| Err(DirectoryError::Unsupported(format!("{alias} jumps through gate, which is not a saved host.")));
        assert_eq!(refused("db"), not_saved("db"));
        assert_eq!(refused("web"), not_saved("bastion"), "the host that names the jump host is the one the sentence is about");
    }

    /// Pins that cannot be read fail closed, as the real pin file does: an error from every call that reads them, never "nothing pinned",
    /// and nothing is written.
    #[test]
    fn pins_that_cannot_be_read_fail_every_call_that_reads_them_and_write_nothing() {
        let (pinned, other) = (key(test_keys::PLAIN_PUBLIC), key(test_keys::ECDSA_PUBLIC));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", pinned.clone()).with_unreadable_pins();
        let web = HostId::from("id-web");
        let unreadable = |call: &str, result: Result<(), DirectoryError>| match result {
            Err(DirectoryError::Failed(text)) => assert!(text.contains("host-pins.json"), "{call}: {text}"),
            got => panic!("{call}: expected the failure of an unreadable pin file, got {got:?}"),
        };
        unreadable("resolve by alias", directory.resolve(&HostQuery::Alias("web".into())).map(|_| ()));
        unreadable("resolve by id", directory.resolve(&HostQuery::Id("id-web".into())).map(|_| ()));
        unreadable("pinned", directory.pinned(&web).map(|_| ()));
        unreadable("pin the pinned key", directory.pin(&web, &pinned));
        unreadable("pin a host that has none", directory.pin(&HostId::from("id-db"), &other));
        unreadable("replace_pin", directory.replace_pin(&web, &pinned, &other));
        assert_eq!(directory.pins().into_iter().map(|(host, pin)| (host, pin.key)).collect::<Vec<_>>(), [(web, pinned)], "nothing was written");
        let unknown = directory.resolve(&HostQuery::Alias("mail".into()));
        assert!(matches!(unknown, Err(DirectoryError::NotFound(_))), "a host that is not saved is still not found: {unknown:?}");
    }
}

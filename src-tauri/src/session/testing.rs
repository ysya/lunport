//! Test doubles for the broker's tests (`#[cfg(test)]` in `session/mod.rs`): saved hosts in memory, and the checks every
//! `HostDirectory` must pass.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::directory::{decide_pin, decide_replace, DirectoryError, HostDirectory, PinDecision, PinnedKey};
use super::protocol::HostQuery;
use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target};

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
/// `deploy`; pins are dated `PINNED_AT_MS`.
#[derive(Default)]
pub struct FakeDirectory {
    hosts: Vec<FakeHost>,
    pins: Mutex<HashMap<HostId, PinnedKey>>,
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

    /// A saved host reached through the saved hosts `jumps`, in this order.
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

    fn with_its_pin(&self, hop: &Hop) -> Hop {
        Hop { pinned: locked(&self.pins).get(&hop.id).map(|pin| pin.key.clone()), ..hop.clone() }
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
        let mut hops = Vec::new();
        for jump in &host.jumps {
            hops.push(self.with_its_pin(&self.by_alias(jump)?.hop));
        }
        hops.push(self.with_its_pin(&host.hop));
        Ok(Target { hops })
    }

    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        Ok(locked(&self.pins).get(host).cloned())
    }

    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        let mut pins = locked(&self.pins);
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
        let mut pins = locked(&self.pins);
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

/// What every `HostDirectory` must do with pins, for a host `host` that has none yet: pin once (again is fine, another key is refused),
/// and replace only from the key that is pinned. The resolved hop carries the pin.
pub fn check_the_pin_contract(directory: &dyn HostDirectory, query: &HostQuery, first: &HostKey, second: &HostKey, third: &HostKey) {
    let hop = directory.resolve(query).expect("the host resolves").hops.pop().expect("a hop");
    assert_eq!(hop.pinned, None, "nothing is pinned yet");
    assert_eq!(directory.pinned(&hop.id), Ok(None));
    directory.pin(&hop.id, first).expect("a first pin");
    directory.pin(&hop.id, first).expect("the same key again");
    assert!(directory.pin(&hop.id, second).is_err(), "another key is not pinned over the first");
    assert_eq!(directory.pinned(&hop.id).unwrap().map(|pin| pin.key), Some(first.clone()));
    assert_eq!(directory.resolve(query).unwrap().hops.pop().unwrap().pinned, Some(first.clone()), "the resolved hop carries the pin");
    assert!(directory.replace_pin(&hop.id, third, second).is_err(), "only the pinned key can be replaced");
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
}

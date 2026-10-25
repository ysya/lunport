//! Where the broker finds saved hosts (own-ssh spec §5.1, §6.2 step 1, §7.1): a host by alias or by host id, resolved into the jump chain
//! the engine connects through, with the pinned host keys in `Hop::pinned`; pinning a key the person trusted; and the keychain account
//! of a host's saved password. In this version the hosts are the app's ssh_config blocks, through a temporary adapter
//! (`ssh_config_directory.rs`; plan 1c replaces it with host records). The broker sees only this trait.

use std::fmt;
use std::time::SystemTime;

use super::protocol::HostQuery;
use crate::ssh::{HostId, HostKey, HopRef, Target};

/// What `HostDirectory::prepare` learned that the broker needs to explain a refusal (design 2026-10-25): `recent_grant` is a Privileged
/// Access Manager grant that became active within the last two minutes, which IAP can take about 1½ minutes to see; `granted_at` is when
/// the grant in flight was given (never ahead of this clock; now, for a grant still activating), for the broker's wait on IAP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Prepared {
    pub recent_grant: bool,
    pub granted_at: Option<SystemTime>,
}

/// A Privileged Access Manager grant the connection needs and nobody holds (design 2026-10-25, PAM grant requests): everything the
/// broker needs to ask the person and to request one. `entitlement` is the first the transport lists (the one requested); `entitlements`
/// are all of them, for the refusal sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantNeed {
    pub host: HostId,
    pub account: Option<String>,
    pub project: String,
    pub location: String,
    pub entitlement: String,
    pub entitlements: Vec<String>,
    /// The transport's stored duration, in seconds.
    pub duration_secs: u32,
    /// The transport's last justification, offered again.
    pub justification: Option<String>,
}

impl GrantNeed {
    /// The refusal the person reads when nothing is requested: how to request a grant by hand.
    pub fn refusal_sentence(&self) -> String {
        format!(
            "No active Privileged Access Manager grant for {} on {}. Request one (for example gcloud pam grants create --entitlement={} --requested-duration=30m --justification=\"…\" --location={} --project={}) and connect again.",
            self.entitlements.join(" or "),
            self.project,
            self.entitlement,
            self.location,
            self.project
        )
    }
}

/// A grant that was requested (or found) and is active: when it was given and when it ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantReceipt {
    pub entitlement: String,
    pub granted_at: SystemTime,
    pub active_until: SystemTime,
}

/// A pinned host key and when it was pinned (milliseconds since the Unix epoch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    pub key: HostKey,
    pub pinned_at_ms: u64,
}

/// Why a host could not be found or a pin not written. The text is the sentence to show the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryError {
    /// No saved host matches.
    NotFound(String),
    /// Several saved hosts have this alias; the client has to name one by its id (spec §7.1).
    Ambiguous(String),
    /// The host is saved, but Lunport's own client cannot connect to it as it is saved: it uses a ProxyCommand, or its key is not in
    /// Lunport, or its chain of jump hosts loops, includes a host that is not saved, names one host twice, has more than five jump hosts
    /// in all, or would give two endpoints one host id.
    Unsupported(String),
    /// Reading the saved hosts or the pins, or writing a pin, failed.
    Failed(String),
    /// The account may not connect as the host is saved (design 2026-10-25): OS Login names another user, Google refused the call, or a
    /// grant could not be had. The broker reports it as a login failure.
    Denied(String),
    /// No Privileged Access Manager grant is in flight for the host's transport (design 2026-10-25, PAM grant requests): a connection a
    /// person drives asks them and requests one; automation gets `for_automation`'s refusal.
    GrantNeeded(Box<GrantNeed>),
}

impl DirectoryError {
    /// The error as a connection nobody is watching sees it: a needed grant is the refusal that names the gcloud command, since no one
    /// is there to answer a question. Everything else is unchanged.
    pub fn for_automation(self) -> DirectoryError {
        match self {
            DirectoryError::GrantNeeded(need) => DirectoryError::Denied(need.refusal_sentence()),
            other => other,
        }
    }
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryError::NotFound(text) | DirectoryError::Ambiguous(text) | DirectoryError::Unsupported(text) | DirectoryError::Failed(text) | DirectoryError::Denied(text) => {
                f.write_str(text)
            }
            DirectoryError::GrantNeeded(need) => f.write_str(&need.refusal_sentence()),
        }
    }
}

impl std::error::Error for DirectoryError {}

/// The saved hosts, as the broker needs them. Implementations are called from the broker's connection threads, never from async code.
///
/// A host id stands for exactly one server: one hostname and one port. Pins are keyed by host id (`pinned`, `pin`, `replace_pin`), so two
/// endpoints that shared an id would share one pin; it would flip between their two keys, and each flip would reach the person as a
/// changed key ("someone could be intercepting the connection"). An implementation must therefore never resolve two different endpoints
/// to the same id. Where a request would do that it returns an error (`Unsupported`, with the reason) instead: a jump written as
/// `bastion:2200` is not the saved host `bastion` when that one is saved with port 22.
pub trait HostDirectory: Send + Sync {
    /// The saved host `query` names, with its jump hosts in front (each a saved host too: the hops are in the order they are connected),
    /// ready for the engine. The jump hosts are those of OpenSSH's routing of `ProxyJump a,b,c`, which is `ssh -J a,b -W host c`: the first
    /// jump host is reached the way it is saved, behind the jump hosts of its own, and a later one through the one before it, its own
    /// `ProxyJump` and `ProxyCommand` not used (`-J` replaces them). The pin of each hop is in `Hop::pinned`. A chain that loops, names a
    /// host that is not saved, would give two different endpoints one host id or has more than five jump hosts in all (counted over the
    /// whole chain, however they are listed or nested) is an error here, before anything connects. So is a chain that names one host twice
    /// without looping (`bastion,bastion`, a later jump host that the first one's own jump hosts have already, the host itself as a later
    /// jump host): the broker keeps what it knows about a hop (typed passwords, cancels, the pin policy) by host id, so a chain has one hop
    /// per id.
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError>;
    /// Public resolution for approval and noninteractive connections. Implementations must not read private material here.
    fn resolve_public(&self, query:&HostQuery)->Result<Target,DirectoryError>{self.resolve(query)}

    /// Everything a resolved target needs settled with the outside world before the engine connects (design 2026-10-25): for a first hop
    /// that goes through Google Cloud IAP, the Privileged Access Manager grant check and OS Login (the key registration, the username
    /// check). Reads `target`, changes nothing, may wait on the network for a while; called on the broker's thread between the resolve and
    /// the connect, never while a lock is held. `public_key` is the vault's OpenSSH public line for a key id. The default does nothing: a
    /// directory without transports has nothing to settle.
    fn prepare(&self, _target: &Target, _public_key: &dyn Fn(&str) -> Option<String>, _cancel: &super::connect::CancelToken) -> Result<Prepared, DirectoryError> {
        Ok(Prepared::default())
    }

    /// Requests the grant `prepare` said was needed, with the person's `justification` and `duration_secs`, and waits for it to be
    /// active (design 2026-10-25, PAM grant requests). A directory without Google has nothing to request from.
    fn request_grant(&self, _need: &GrantNeed, _justification: &str, _duration_secs: u32, _cancel: &super::connect::CancelToken) -> Result<GrantReceipt, DirectoryError> {
        Err(DirectoryError::Unsupported("Requesting a grant is not available here.".into()))
    }

    /// Handshake-only identity verification must not require destination login credentials.
    /// Jump hosts still require their normal credentials to reach the destination.
    fn resolve_host_key(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        let mut target = self.resolve_public(query)?;
        if let Some(last) = target.hops.last_mut() {
            last.auth = crate::ssh::AuthMethod::Interactive;
        }
        Ok(target)
    }

    /// The key pinned for `host`, if any. An error reading the pins is `Err`, never "nothing pinned": a host that was pinned must not
    /// look new because a file could not be read.
    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError>;

    /// Pins `key` for `host`: the person trusted it in the window. Pinning the key that is pinned already is fine; when another key was
    /// pinned in the meantime, nothing is written and the call fails.
    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError>;

    /// Replaces the pin of `host` with `key`: the person accepted a changed key. Only while `previous` is still the pinned key (or `key`
    /// already is); otherwise nothing is written and the call fails.
    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError>;

    /// Record IDs survive endpoint edits; pin reads and writes must use the endpoint that connected.
    /// Legacy adapters encode endpoint identity in their IDs and keep their existing contract.
    fn pinned_for(&self, hop: &HopRef) -> Result<Option<PinnedKey>, DirectoryError> {
        self.pinned(&hop.id)
    }
    fn pin_for(&self, hop: &HopRef, key: &HostKey) -> Result<(), DirectoryError> {
        self.pin(&hop.id, key)
    }
    fn replace_pin_for(&self, hop: &HopRef, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
        self.replace_pin(&hop.id, previous, key)
    }

    /// A native trust decision. Records adapters may prepare credentials/relay outside lifecycle,
    /// then revalidate cancellation and the public snapshot before committing the pin.
    fn pin_confirmed(
        &self,
        hop: &HopRef,
        previous: Option<&HostKey>,
        key: &HostKey,
        cancel: &super::connect::CancelToken,
        guard: &(dyn Fn() -> Result<(), DirectoryError> + Sync),
    ) -> Result<(), DirectoryError> {
        guard()?;
        if cancel.is_cancelled() {
            return Err(DirectoryError::Failed(
                "The connection was cancelled.".into(),
            ));
        }
        match previous {
            Some(previous) => self.replace_pin_for(hop, previous, key),
            None => self.pin_for(hop, key),
        }
    }
    /// The keychain account of the saved password of `host` (spec §5.5: `host:<host id>`).
    fn password_account(&self, host: &HostId) -> String;
    /// Saved secrets remain native; Records can supply authenticated encrypted library material.
    fn saved_password(&self, hop: &HopRef, keychain: &dyn crate::sync::env::Keychain) -> Result<Option<crate::ssh::Secret>, DirectoryError> {
        keychain.get(&self.password_account(&hop.id)).map(|value|value.map(zeroize::Zeroizing::new)).map_err(|_|DirectoryError::Failed("The saved password is unavailable.".into()))
    }
    /// Records independently approve the effective endpoint, user and server key locally.
    fn password_authorized(&self, _hop: &HopRef, _server_key: Option<&HostKey>) -> Result<bool, DirectoryError> { Ok(true) }

}

/// What a `pin` or a `replace_pin` has to do, given the key pinned now. The rules are the ones documented on those two methods. They are
/// written down once, here, so that the pin file, the test fake and the later host records decide the same way (and say the same
/// sentence); `check_the_pin_contract` (test builds) checks the outcome of any directory. The caller makes the decision while it holds
/// its lock, between reading the pin and writing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinDecision {
    /// The key asked for is the pinned one already: nothing is written and the call succeeds.
    AlreadyPinned,
    /// Write the key as the host's pin.
    Write,
    /// Nothing is written and the call fails with this sentence.
    Refuse(String),
}

/// `pin(host, key)` when `pinned` is the fingerprint of the key pinned now (`None`: nothing is): write the key when nothing is pinned,
/// accept it when it is the pinned one, refuse it when another key is.
pub fn decide_pin(host: &HostId, pinned: Option<&str>, key: &HostKey) -> PinDecision {
    match pinned {
        Some(pinned) if pinned == key.fingerprint => PinDecision::AlreadyPinned,
        Some(_) => PinDecision::Refuse(format!("Lunport did not pin the key of {host}: another key was pinned for it in the meantime.")),
        None => PinDecision::Write,
    }
}

/// `replace_pin(host, previous, key)` when `pinned` is the fingerprint of the key pinned now (`None`: nothing is): accept `key` when it is
/// the pinned one, write it when `previous` is the pinned one, refuse anything else (another key, or no pin at all).
pub fn decide_replace(host: &HostId, pinned: Option<&str>, previous: &HostKey, key: &HostKey) -> PinDecision {
    match pinned {
        Some(pinned) if pinned == key.fingerprint => PinDecision::AlreadyPinned,
        Some(pinned) if pinned == previous.fingerprint => PinDecision::Write,
        _ => PinDecision::Refuse(format!("Lunport did not replace the key of {host}: the pinned key is not the one you were shown.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).expect("a test key")
    }

    #[test]
    fn pinning_writes_when_nothing_is_pinned_accepts_the_pinned_key_and_refuses_another() {
        let web = HostId::from("web");
        let (first, second) = (key(test_keys::PLAIN_PUBLIC), key(test_keys::ECDSA_PUBLIC));
        assert_eq!(decide_pin(&web, None, &first), PinDecision::Write);
        assert_eq!(decide_pin(&web, Some(&first.fingerprint), &first), PinDecision::AlreadyPinned);
        assert_eq!(
            decide_pin(&web, Some(&first.fingerprint), &second),
            PinDecision::Refuse("Lunport did not pin the key of web: another key was pinned for it in the meantime.".to_string())
        );
    }

    #[test]
    fn replacing_writes_only_from_the_key_that_was_shown_as_pinned_and_a_key_that_is_pinned_already_is_fine() {
        let web = HostId::from("web");
        let (old, new, other) = (key(test_keys::PLAIN_PUBLIC), key(test_keys::ECDSA_PUBLIC), key(test_keys::RSA_PUBLIC));
        let refused = PinDecision::Refuse("Lunport did not replace the key of web: the pinned key is not the one you were shown.".to_string());
        assert_eq!(decide_replace(&web, Some(&old.fingerprint), &old, &new), PinDecision::Write);
        assert_eq!(decide_replace(&web, Some(&new.fingerprint), &old, &new), PinDecision::AlreadyPinned, "the replace was made already");
        assert_eq!(decide_replace(&web, Some(&new.fingerprint), &other, &new), PinDecision::AlreadyPinned, "the key asked for wins over `previous`");
        assert_eq!(decide_replace(&web, Some(&other.fingerprint), &old, &new), refused, "another key is pinned now");
        assert_eq!(decide_replace(&web, None, &old, &new), refused, "nothing is pinned: there is nothing to replace");
    }
}

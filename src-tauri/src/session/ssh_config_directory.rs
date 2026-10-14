//! TEMPORARY: plan 1c deletes this file, when host records (spec §5.1) replace the ssh_config blocks. Until then it is the broker's
//! `HostDirectory` over the data the app has today, read-only: the hosts are the `Host` patterns of the app's ssh_config, their settings
//! come from `ssh -G` (no connection), a host's key is the vault key ("Only in SSHelter") that its first matching `IdentityFile` names
//! (the SP3 slot rules), a password is the keychain's `host:<alias>`, and pins live in `host-pins.json` (`pins.rs`). A host id is its
//! alias here. Never written: `~/.ssh` (spec §1). Never read: `~/.ssh/known_hosts`.
//!
//! The settings are read the way `ssh <alias>` reads them, because `sshelter connect` replaces that command: the app's source runs `ssh -G`
//! without `-F`, so it reads the default config files (`~/.ssh/config` and the system's), as today's Connect does
//! (`effective_config(alias, None)`), and not only the file the app has loaded (the hosts are the `Host` patterns of that one). `ssh -G`
//! runs the `Match exec` commands of those files and waits for them, so the source has a deadline (`Sources::effective`, `ssh_g.rs`).
//!
//! What it cannot give the broker, and says so: a `ProxyCommand`, a key in a file instead of the vault (SSHelter's own client signs with
//! vault keys only), and a `ProxyJump` that is anything but a chain of saved hosts, each one as it is saved.
//!
//! A host names a key file when an `IdentityFile` value that `ssh -G` prints is not a vault slot. It names no key when `ssh -G` prints
//! `none` for it (`IdentityFile none`) or OpenSSH's whole default list, which `ssh -G` prints for a host that names no `IdentityFile`
//! and for such a host only: a host that names `~/.ssh/id_ed25519` gets that one line, and it is a key file (`DEFAULT_IDENTITY_SEQUENCES`).
//!
//! A `ProxyJump` list is read as OpenSSH routes it. `ProxyJump a,b,c` makes ssh run `ssh -J a,b -W host c`, and for `c` that is
//! `ssh -J a -W c b`, and for `b` `ssh -W b a`: only the first jump host, `a`, is reached the way it is saved, behind the jump hosts of
//! its own, while `-J` takes the place of everything a later jump host says about how it is reached, its `ProxyJump` and its
//! `ProxyCommand` alike. A later jump host is therefore just its own hop, behind the one before it; its own `ProxyJump` is not followed
//! and its own `ProxyCommand` does not refuse the chain. (Checked with `ssh -vvv` on a config of its own.) Every jump host, first or later,
//! is still a saved host with its own key. The chain of jump hosts is refused when it has:
//!
//! - a jump host that is not a saved host;
//! - a jump with a port or user of its own, as in `ProxyJump admin@bastion:2200` for a `bastion` saved with port 22. OpenSSH lets such an
//!   entry override the jump host's port and user, but a host id stands for one server (`HostDirectory`), and its pin, saved password and
//!   typed answers belong to the id: the entry would be a second endpoint under the same id. An entry that only repeats the saved port
//!   and user is the saved host and is fine;
//! - a loop, with the hosts round the circle in the sentence (found through the first jump hosts, the only ones followed into their own);
//! - a chain that names a host twice without a loop: `ProxyJump bastion,bastion`, a later jump host that the first one's own jump hosts
//!   have already (`ProxyJump edge,bastion` for an `edge` behind `bastion`), the host itself as a later jump host. The broker keeps what
//!   it knows about a hop (typed passwords, cancels, the pin policy) by host id, so a chain has one hop per id. The sentence is about the
//!   host whose jump hosts name a host twice: `web's jump hosts name bastion twice.`;
//! - more than five jump hosts in all, counted over the whole chain: the first jump host's own and the later ones together, however they
//!   are listed or nested (`ProxyJump h1,h2,h3,h4,h5,h6`, or six hosts one behind the other, or a mix).

use std::path::Path;

use super::directory::{DirectoryError, HostDirectory, PinnedKey};
use super::pins::PinStore;
use super::protocol::HostQuery;
use crate::config::model::SshConfigDoc;
use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY};
use crate::sync::slot_rules::{resolve_identity_value, IdentityTarget};
use crate::sync::state_v2::{SlotSource, SyncStateV2};

/// How many jump hosts a chain may have in all, counted over the whole chain: the first jump host's own and the later ones together,
/// however they are listed or nested (`config::intel::jump_chain` stops the chain it shows at the host and five more, the same limit).
pub(super) const MAX_JUMPS: usize = 5;

/// The lists of `IdentityFile` values that `ssh -G` prints for a host that names none, by OpenSSH version. OpenSSH adds its default key
/// files when a host names no `IdentityFile`, and only then: a host with `IdentityFile ~/.ssh/id_ed25519` gets exactly that one line, and
/// `IdentityFile none` gets `none`. So whether a host names a key is decided by the whole list `ssh -G` prints, never by the names of
/// the files in it (`named_key_file`). The lists are what `fill_default_options` in readconf.c makes: 10.3p1 prints the first (measured on
/// a machine with it), and each list was read in the sources at the tags named beside it; the versions between two tags are taken to
/// print the list of the tag next to them. (A build without ECDSA support lacks the two ecdsa files; no such build is known.)
const DEFAULT_IDENTITY_SEQUENCES: &[&[&str]] = &[
    // 10.1 and later, no DSA and no XMSS any more: V_10_1_P1, V_10_2_P1.
    &["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk"],
    // 9.8 to 10.0, XMSS still there and DSA only in a build that asks for it: V_9_9_P2, V_10_0_P1.
    &["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk", "~/.ssh/id_xmss"],
    // 8.9 to 9.7 (and a 9.8 to 10.0 built with DSA), DSA last: V_8_9_P1, V_9_6_P1.
    &["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk", "~/.ssh/id_xmss", "~/.ssh/id_dsa"],
    // 8.2 to 8.8, DSA second: V_8_2_P1, V_8_4_P1, V_8_8_P1.
    &["~/.ssh/id_rsa", "~/.ssh/id_dsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk", "~/.ssh/id_xmss"],
    // 7.9 to 8.1, no security-key files yet: V_7_9_P1, V_8_0_P1.
    &["~/.ssh/id_rsa", "~/.ssh/id_dsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519", "~/.ssh/id_xmss"],
    // 7.4 to 7.8, no XMSS either: V_7_4_P1, V_7_6_P1.
    &["~/.ssh/id_rsa", "~/.ssh/id_dsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ed25519"],
];

/// One element of a `ProxyJump` list: `[user@]host[:port]`, or `ssh://[user@]host[:port]`. A port or user written here has to be the saved
/// host's own (`check_jump_is_the_saved_host`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpSpec {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

/// The jump hosts of a `ProxyJump` value, in the order they are connected; `none` (or nothing) is none.
pub fn parse_proxy_jump(value: &str) -> Result<Vec<JumpSpec>, String> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|element| {
            let element = element.trim();
            let rest = element.strip_prefix("ssh://").unwrap_or(element);
            let (user, rest) = match rest.rsplit_once('@') {
                Some((user, rest)) => (Some(user.to_string()), rest),
                None => (None, rest),
            };
            let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
                let (host, after) = bracketed.split_once(']').ok_or_else(|| format!("ProxyJump {element} is not [user@]host[:port]"))?;
                (host, after.strip_prefix(':'))
            } else {
                match rest.rsplit_once(':') {
                    Some((host, port)) => (host, Some(port)),
                    None => (rest, None),
                }
            };
            let port = port.map(|port| port.parse::<u16>().map_err(|_| format!("ProxyJump {element} has no valid port"))).transpose()?;
            if host.is_empty() {
                return Err(format!("ProxyJump {element} names no host"));
            }
            Ok(JumpSpec { user, host: host.to_string(), port })
        })
        .collect()
}

/// A `ProxyJump` entry has to name the saved host `saved` as it is saved. OpenSSH lets an entry override the jump host's port and user
/// (`ssh -J admin@bastion:2200`), but a host id stands for one server (`HostDirectory`), and the pin, the saved password and the typed
/// answers belong to the id: with a port or user of its own the entry would be a second endpoint under the same id. An entry that only
/// repeats the saved port and user, or names none, is the saved host. `alias` is the host whose `ProxyJump` the entry is.
fn check_jump_is_the_saved_host(alias: &str, jump: &JumpSpec, saved: &Hop) -> Result<(), DirectoryError> {
    let name = jump.host.as_str();
    if let Some(port) = jump.port.filter(|port| *port != saved.port) {
        return Err(DirectoryError::Unsupported(format!("{alias} jumps through {name} on port {port}, but {name} is saved with port {}.", saved.port)));
    }
    if let Some(user) = jump.user.as_deref().filter(|user| *user != saved.user) {
        // `ssh -G` names the local user for a host that has no `User`, so a saved user is empty only when its answer lacks the line; the
        // user written for the jump cannot then be shown to be the saved one.
        let saved_user = if saved.user.is_empty() { "your local user name".to_string() } else { format!("user {}", saved.user) };
        return Err(DirectoryError::Unsupported(format!("{alias} jumps through {name} as {user}, but {name} is saved with {saved_user}.")));
    }
    Ok(())
}

/// The first key file that the `IdentityFile` values of a host (`ssh -G`'s, in order) name, if they name one. A host names no key when
/// the list is empty, is a whole default list (`DEFAULT_IDENTITY_SEQUENCES`: OpenSSH adds those for a host that names none) or holds
/// only `none` (OpenSSH loads no file for that value, whatever its case). Any other value is a key file the host logs in with; a `none`
/// next to it skips itself and nothing else. A value that is a vault slot is dealt with before this (`Sources::vault_key`).
fn named_key_file<'a>(identity_files: &[&'a str]) -> Option<&'a str> {
    if DEFAULT_IDENTITY_SEQUENCES.iter().any(|sequence| *sequence == identity_files) {
        return None;
    }
    identity_files.iter().copied().find(|file| !file.eq_ignore_ascii_case("none"))
}

/// The refusal of a chain with more than `MAX_JUMPS` jump hosts; `target` is the host that was asked for.
fn too_many_jumps(target: &str) -> DirectoryError {
    DirectoryError::Unsupported(format!("{target} needs more than {MAX_JUMPS} jump hosts."))
}

/// The first value of `keyword` in `ssh -G`'s output.
fn value<'a>(pairs: &'a [(String, String)], keyword: &str) -> Option<&'a str> {
    pairs.iter().find(|(key, _)| key == keyword).map(|(_, value)| value.as_str())
}

/// A positive number of seconds; `none`, 0 or something else is `None`.
fn seconds(value: Option<&str>) -> Option<std::time::Duration> {
    value.and_then(|value| value.parse::<u64>().ok()).filter(|seconds| *seconds > 0).map(std::time::Duration::from_secs)
}

/// The hop of the saved host `alias` from its `ssh -G` settings. `key_id` is the vault key its `IdentityFile`s name, if any;
/// `password_saved` says whether the keychain holds its password. Keepalive: the host's `ServerAliveInterval` when it sets one, else
/// SSHelter's default (spec §5.1: 30 s; OpenSSH's own default is off); a dead link is given up after `ServerAliveCountMax` more.
pub fn hop_from_effective(alias: &str, pairs: &[(String, String)], key_id: Option<String>, password_saved: bool) -> Result<Hop, DirectoryError> {
    let hostname = value(pairs, "hostname").filter(|hostname| !hostname.is_empty()).unwrap_or(alias);
    let port = match value(pairs, "port") {
        None => 22,
        Some(port) => port.parse::<u16>().map_err(|_| DirectoryError::Unsupported(format!("{alias} has a port SSHelter cannot use ({port}).")))?,
    };
    let user = value(pairs, "user").unwrap_or_default();
    let auth = match key_id {
        Some(key_id) => AuthMethod::Key { key_id },
        None => {
            let identity_files: Vec<&str> = pairs.iter().filter(|(key, _)| key == "identityfile").map(|(_, value)| value.as_str()).collect();
            if let Some(file) = named_key_file(&identity_files) {
                return Err(DirectoryError::Unsupported(format!(
                    "{alias} logs in with the key file {file}, which SSHelter's own SSH client cannot use. Put the key in SSHelter (Keychain, Only in SSHelter) to connect with it."
                )));
            }
            // No key: a saved password is tried first; without one, keyboard-interactive comes first, and the broker asks for a password
            // only when the server wants one (`ConnectError::AuthFailed::password_wanted`), so a server that asks through
            // keyboard-interactive is not asked twice.
            if password_saved {
                AuthMethod::Password
            } else {
                AuthMethod::Interactive
            }
        }
    };
    let mut hop = Hop::new(alias, alias, hostname, port, user, auth);
    hop.connect_timeout = seconds(value(pairs, "connecttimeout")).unwrap_or(DEFAULT_CONNECT_TIMEOUT);
    hop.keepalive_every = seconds(value(pairs, "serveraliveinterval")).unwrap_or(DEFAULT_KEEPALIVE_EVERY);
    if let Some(count) = value(pairs, "serveralivecountmax").and_then(|count| count.parse::<u32>().ok()) {
        hop.keepalive_max_missed = count;
    }
    Ok(hop)
}

/// The vault key ("Only in SSHelter" slot) that the first of `identity_files` (`ssh -G`'s values, in order) names, if any. Copied from
/// the one-shot key channel that plan 1b-2 deleted (`agent/oneshot.rs`).
pub fn vault_slot_of(identity_files: &[String], state: &SyncStateV2, home: &Path) -> Option<String> {
    identity_files.iter().find_map(|value| {
        let IdentityTarget::Slot(file) = resolve_identity_value(value, home) else { return None };
        state
            .key_slots
            .iter()
            .find(|(_, local)| local.file_name == file && matches!(local.source, Some(SlotSource::Vault { .. })))
            .map(|(id, _)| id.clone())
    })
}

/// The sources the adapter reads; in the app they are the loaded ssh_config, `ssh -G`, the sync state and the keychain (wired in by the
/// app), in tests whatever the test gives.
pub struct Sources {
    /// The ssh_config the app manages: the hosts one can connect to are its `Host` patterns.
    pub doc: Box<dyn Fn() -> Result<SshConfigDoc, String> + Send + Sync>,
    /// `ssh -G <alias>`: the effective settings of a host, keywords in lower case. It is called on the thread that serves the client, for
    /// every host of the chain, at every connect and reconnect, and it has to come back within a bound: `ssh -G` runs the `Match exec`
    /// commands of the config and waits for them, and reads its `Include`d files, so a source without a deadline stalls the client's
    /// connect with no word to the person and leaves its process behind, again at the next try. A source that cannot answer in time ends
    /// what it started and returns `Err` with a sentence ("ssh -G did not finish within 10 seconds."), which the adapter turns into
    /// `DirectoryError::Failed`. The app's source is `ssh_g::effective_within(alias, None, ssh_g::EFFECTIVE_DEADLINE)`.
    pub effective: Box<dyn Fn(&str) -> Result<Vec<(String, String)>, String> + Send + Sync>,
    /// The vault key the `IdentityFile` values name, if any (`vault_slot_of`).
    pub vault_key: Box<dyn Fn(&[String]) -> Option<String> + Send + Sync>,
    /// Whether the keychain holds a password for the host.
    pub password_saved: Box<dyn Fn(&HostId) -> bool + Send + Sync>,
}

/// The temporary `HostDirectory` (see the module documentation).
pub struct SshConfigDirectory {
    sources: Sources,
    pins: PinStore,
}

impl SshConfigDirectory {
    pub fn new(sources: Sources, pins: PinStore) -> SshConfigDirectory {
        SshConfigDirectory { sources, pins }
    }

    /// Whether `alias` is a saved host: a safe name that is a `Host` pattern of the doc.
    fn check_saved(&self, doc: &SshConfigDoc, alias: &str) -> Result<(), DirectoryError> {
        crate::connect::validate_alias(doc, alias).map_err(|_| DirectoryError::NotFound(format!("No saved host is called {alias}.")))
    }

    /// The settings of the saved host `alias`, from `ssh -G`.
    fn settings(&self, alias: &str) -> Result<Vec<(String, String)>, DirectoryError> {
        (self.sources.effective)(alias).map_err(|error| DirectoryError::Failed(format!("SSHelter cannot read the settings of {alias}: {error}")))
    }

    /// The hop of the saved host `alias` alone, jump hosts left out: its address and login from its `ssh -G` settings, its key (a vault
    /// key, or no key; a key file is refused), the password the keychain holds for it and its pin.
    fn hop_of(&self, alias: &str, pairs: &[(String, String)]) -> Result<Hop, DirectoryError> {
        let identity_files: Vec<String> = pairs.iter().filter(|(key, _)| key == "identityfile").map(|(_, value)| value.clone()).collect();
        let key_id = (self.sources.vault_key)(&identity_files);
        let id = HostId::from(alias);
        let mut hop = hop_from_effective(alias, pairs, key_id, (self.sources.password_saved)(&id))?;
        hop.pinned = self.pinned(&hop.id)?.map(|pin| pin.key);
        Ok(hop)
    }

    /// The hops of `alias` and of its jump hosts, jump hosts first, as OpenSSH routes them: for `ProxyJump a,b,c` ssh runs
    /// `ssh -J a,b -W host c`, and for `c` that is `ssh -J a -W c b`, and for `b` `ssh -W b a`. So the first jump host `a` is reached the way
    /// it is saved, through its own jump hosts, while `-J` takes the place of everything the later ones say about how they are reached
    /// (their `ProxyJump` and their `ProxyCommand`): each of them is just its own hop, behind the one before it. (The test fake does the
    /// same.) `path` holds the hosts above `alias` in the chain, to find a loop; only the first jump host is followed into its own jump
    /// hosts, so a loop can only be found through it. A host that comes up twice without a loop (`bastion,bastion`, a later jump host that
    /// the first one's own jump hosts have already, the host itself as a later jump host) is refused too: a chain has one hop per host id.
    fn hops(&self, doc: &SshConfigDoc, alias: &str, path: &mut Vec<String>) -> Result<Vec<Hop>, DirectoryError> {
        if path.iter().any(|seen| seen == alias) {
            path.push(alias.to_string());
            return Err(DirectoryError::Unsupported(format!("The jump hosts go round in a circle: {}.", path.join(" → "))));
        }
        // An early cut, before `ssh -G` is run for more hosts: every host above this one is a jump host of the chain, so with more than
        // `MAX_JUMPS` of them above, the count below would refuse the chain anyway.
        if path.len() > MAX_JUMPS {
            return Err(too_many_jumps(&path[0]));
        }
        path.push(alias.to_string());
        let pairs = self.settings(alias)?;
        if value(&pairs, "proxycommand").is_some_and(|command| !command.trim().is_empty() && !command.trim().eq_ignore_ascii_case("none")) {
            return Err(DirectoryError::Unsupported(format!("{alias} uses ProxyCommand, which SSHelter's own SSH client does not support.")));
        }
        let jumps = parse_proxy_jump(value(&pairs, "proxyjump").unwrap_or_default()).map_err(|error| DirectoryError::Unsupported(format!("{alias}: {error}.")))?;
        let mut hops: Vec<Hop> = Vec::new();
        for (index, jump) in jumps.iter().enumerate() {
            if self.check_saved(doc, &jump.host).is_err() {
                return Err(DirectoryError::Unsupported(format!("{alias} jumps through {}, which is not a saved host.", jump.host)));
            }
            let jump_hops = if index == 0 {
                self.hops(doc, &jump.host, path)?
            } else {
                vec![self.hop_of(&jump.host, &self.settings(&jump.host)?)?]
            };
            // The last of them is the jump host itself; the ones before it are its own jump hosts.
            if let Some(saved) = jump_hops.last() {
                check_jump_is_the_saved_host(alias, jump, saved)?;
            }
            // A host that the hops so far have already: no loop (that is refused on the way down), but one id twice. The host named is the
            // last of these hops that is in both, the one nearest the jump host that was written.
            if let Some(twice) = jump_hops.iter().rev().find(|hop| hops.iter().any(|seen| seen.id == hop.id)) {
                return Err(DirectoryError::Unsupported(format!("{alias}'s jump hosts name {} twice.", twice.alias)));
            }
            hops.extend(jump_hops);
            // Every hop gathered so far is a jump host of the chain asked for (`path[0]`), whatever level this host is on.
            if hops.len() > MAX_JUMPS {
                return Err(too_many_jumps(&path[0]));
            }
        }
        let hop = self.hop_of(alias, &pairs)?;
        if hops.iter().any(|seen| seen.id == hop.id) {
            return Err(DirectoryError::Unsupported(format!("{alias}'s jump hosts name {alias} twice.")));
        }
        hops.push(hop);
        path.pop();
        Ok(hops)
    }
}

impl HostDirectory for SshConfigDirectory {
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError> {
        // A host id is the alias in this adapter.
        let alias = match query {
            HostQuery::Alias(alias) | HostQuery::Id(alias) => alias.as_str(),
        };
        let doc = (self.sources.doc)().map_err(|error| DirectoryError::Failed(format!("SSHelter cannot read your SSH config: {error}")))?;
        self.check_saved(&doc, alias)?;
        Ok(Target { hops: self.hops(&doc, alias, &mut Vec::new())? })
    }

    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
        self.pins.get(host).map_err(DirectoryError::Failed)
    }

    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError> {
        self.pins.pin(host, key).map_err(DirectoryError::Failed)
    }

    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError> {
        self.pins.replace(host, previous, key).map_err(DirectoryError::Failed)
    }

    /// Today's keychain entries are `host:<alias>`, and the id is the alias here.
    fn password_account(&self, host: &HostId) -> String {
        crate::secrets::host_account(host.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::*;
    use crate::session::testing::{check_the_pin_contract, FakeDirectory};
    use crate::sync::slot_rules::test_keys;
    use crate::sync::state_v2::LocalSlot;

    fn pairs(text: &str) -> Vec<(String, String)> {
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (key, value) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
                (key.to_string(), value.to_string())
            })
            .collect()
    }

    /// `ssh -G`'s defaults for the key files of a host that names none.
    const NO_KEY: &str = "identityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ecdsa\nidentityfile ~/.ssh/id_ecdsa_sk\nidentityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_ed25519_sk\n";

    #[test]
    fn a_proxy_jump_list_is_read_in_order_with_its_users_and_ports() {
        assert_eq!(parse_proxy_jump("none"), Ok(vec![]));
        assert_eq!(parse_proxy_jump(""), Ok(vec![]));
        assert_eq!(parse_proxy_jump("bastion"), Ok(vec![JumpSpec { user: None, host: "bastion".into(), port: None }]));
        assert_eq!(
            parse_proxy_jump("admin@web:2200,bastion"),
            Ok(vec![JumpSpec { user: Some("admin".into()), host: "web".into(), port: Some(2200) }, JumpSpec { user: None, host: "bastion".into(), port: None }])
        );
        assert_eq!(parse_proxy_jump("ssh://ops@gate:22"), Ok(vec![JumpSpec { user: Some("ops".into()), host: "gate".into(), port: Some(22) }]));
        assert_eq!(parse_proxy_jump("[fe80::1]:2222"), Ok(vec![JumpSpec { user: None, host: "fe80::1".into(), port: Some(2222) }]));
        assert!(parse_proxy_jump("gate:port").is_err());
        assert!(parse_proxy_jump("admin@").is_err());
    }

    #[test]
    fn a_hop_takes_its_address_user_and_timeouts_from_ssh_g_and_the_spec_defaults_otherwise() {
        let hop = hop_from_effective("web", &pairs(&format!("hostname web.example.com\nport 2222\nuser deploy\nconnecttimeout none\nserveraliveinterval 0\nserveralivecountmax 3\n{NO_KEY}")), None, true).unwrap();
        assert_eq!((hop.id.as_str(), hop.alias.as_str(), hop.hostname.as_str(), hop.port, hop.user.as_str()), ("web", "web", "web.example.com", 2222, "deploy"));
        assert_eq!((hop.connect_timeout, hop.keepalive_every, hop.keepalive_max_missed), (Duration::from_secs(15), Duration::from_secs(30), 3), "OpenSSH's 'off' keepalive becomes SSHelter's default");
        assert_eq!(hop.auth, AuthMethod::Password, "no key, a saved password: the password goes first");
        assert!(hop.nodelay && hop.pinned.is_none());

        let hop = hop_from_effective("db", &pairs("hostname 10.0.0.5\nport 22\nuser ops\nconnecttimeout 7\nserveraliveinterval 20\nserveralivecountmax 5\nidentityfile ~/.ssh/sshelter/keys/id_mac-aaaaaaaa\n"), Some("a".repeat(32)), false).unwrap();
        assert_eq!((hop.connect_timeout, hop.keepalive_every, hop.keepalive_max_missed), (Duration::from_secs(7), Duration::from_secs(20), 5));
        assert_eq!(hop.auth, AuthMethod::Key { key_id: "a".repeat(32) });
    }

    #[test]
    fn a_host_without_a_key_or_a_saved_password_starts_with_keyboard_interactive_and_a_key_file_is_refused() {
        let hop = hop_from_effective("mail", &pairs(&format!("hostname mail\nuser me\n{NO_KEY}")), None, false).unwrap();
        assert_eq!(hop.auth, AuthMethod::Interactive);
        let error = hop_from_effective("old", &pairs("hostname old\nuser me\nidentityfile ~/.ssh/work_key\n"), None, true).unwrap_err();
        assert_eq!(
            error,
            DirectoryError::Unsupported("old logs in with the key file ~/.ssh/work_key, which SSHelter's own SSH client cannot use. Put the key in SSHelter (Keychain, Only in SSHelter) to connect with it.".into())
        );
        assert!(matches!(hop_from_effective("x", &pairs("hostname x\nport 99999\n"), None, false), Err(DirectoryError::Unsupported(_))));
    }

    /// What `ssh -G` prints for the key files of a host that names none, by OpenSSH version: OpenSSH adds its default key files when a host
    /// names no `IdentityFile`, and only then. These are the lists `fill_default_options` in readconf.c makes (see
    /// `DEFAULT_IDENTITY_SEQUENCES` for the tags they were read at); the first is what the 10.3p1 of a development machine prints. They
    /// are written out here again, so that a slip in the table of the code is not copied into the test.
    const DEFAULT_LISTS: &[(&str, &[&str])] = &[
        ("10.1 and later", &["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk"]),
        ("9.8 to 10.0 without DSA", &["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss"]),
        ("8.9 to 9.7", &["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa"]),
        ("8.2 to 8.8", &["id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss"]),
        ("7.9 to 8.1", &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss"]),
        ("7.4 to 7.8", &["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]),
    ];

    /// `ssh -G`'s lines for these key files in the `~/.ssh` of the person.
    fn identity_lines(names: &[&str]) -> String {
        names.iter().map(|name| format!("identityfile ~/.ssh/{name}\n")).collect()
    }

    /// The sentence for a host that logs in with a key file of its own.
    fn key_file_refusal(alias: &str, file: &str) -> DirectoryError {
        DirectoryError::Unsupported(format!(
            "{alias} logs in with the key file {file}, which SSHelter's own SSH client cannot use. Put the key in SSHelter (Keychain, Only in SSHelter) to connect with it."
        ))
    }

    /// `ssh -G` lists the default key files for a host that names no `IdentityFile`, and only for such a host: one that names
    /// `~/.ssh/id_ed25519` itself gets exactly that line back, and it logs in with that file. Judging a file by its name would send such a
    /// host to keyboard-interactive, instead of saying that its key is a file and not in SSHelter.
    #[test]
    fn a_host_that_names_one_default_named_key_file_logs_in_with_a_key_file_and_is_refused() {
        for name in ["id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss"] {
            let answer = pairs(&format!("hostname old\nuser me\n{}", identity_lines(&[name])));
            for password_saved in [false, true] {
                assert_eq!(
                    hop_from_effective("old", &answer, None, password_saved),
                    Err(key_file_refusal("old", &format!("~/.ssh/{name}"))),
                    "{name}, password saved: {password_saved}"
                );
            }
        }
    }

    /// A list of default-named files is the default only when it is a whole default list, in its order. A part of one, another order or
    /// one more file are files that the host names itself; the first of them is the one the sentence names.
    #[test]
    fn a_list_of_default_named_files_that_is_not_a_whole_default_list_names_key_files() {
        let newest = DEFAULT_LISTS[0].1;
        let mut swapped = newest.to_vec();
        swapped.swap(0, 1);
        let mut one_more = newest.to_vec();
        one_more.push("work_key");
        let mut two_lists = DEFAULT_LISTS[1].1.to_vec();
        two_lists.extend_from_slice(newest);
        for names in [&newest[..4], &newest[1..], &swapped[..], &one_more[..], &two_lists[..], &newest[..2]] {
            let answer = pairs(&format!("hostname old\nuser me\n{}", identity_lines(names)));
            assert_eq!(hop_from_effective("old", &answer, None, false), Err(key_file_refusal("old", &format!("~/.ssh/{}", names[0]))), "{names:?}");
        }
    }

    /// `IdentityFile none` loads no key file (OpenSSH compares the value with "none" without regard to case) and `ssh -G` prints it as
    /// `identityfile none`: the host names no key, as a host with no `IdentityFile` at all, and so do the default lists of every OpenSSH.
    #[test]
    fn a_host_that_names_none_or_gets_a_whole_default_list_names_no_key() {
        let mut cases: Vec<(String, String)> = DEFAULT_LISTS.iter().map(|(version, names)| (format!("the default list of {version}"), identity_lines(names))).collect();
        for lines in ["identityfile none\n", "identityfile NONE\n", "identityfile none\nidentityfile None\n", ""] {
            cases.push((format!("{lines:?}"), lines.to_string()));
        }
        for (what, lines) in &cases {
            let answer = pairs(&format!("hostname mail\nuser me\n{lines}"));
            assert_eq!(hop_from_effective("mail", &answer, None, false).map(|hop| hop.auth), Ok(AuthMethod::Interactive), "{what}");
            assert_eq!(hop_from_effective("mail", &answer, None, true).map(|hop| hop.auth), Ok(AuthMethod::Password), "{what}");
        }
    }

    /// `none` skips its own entry and nothing else: a key file named next to it is still one the host logs in with.
    #[test]
    fn a_key_file_named_next_to_none_is_still_a_key_file() {
        let refused = |lines: &str| hop_from_effective("old", &pairs(&format!("hostname old\nuser me\n{lines}")), None, true);
        assert_eq!(refused("identityfile none\nidentityfile ~/.ssh/work_key\n"), Err(key_file_refusal("old", "~/.ssh/work_key")));
        assert_eq!(refused("identityfile ~/.ssh/work_key\nidentityfile none\n"), Err(key_file_refusal("old", "~/.ssh/work_key")));
        assert_eq!(refused("identityfile none\nidentityfile ~/.ssh/id_ed25519\n"), Err(key_file_refusal("old", "~/.ssh/id_ed25519")));
    }

    fn slot(file: &str, source: Option<SlotSource>) -> LocalSlot {
        LocalSlot {
            file_name: file.into(),
            source,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
            local_only: false,
        }
    }

    #[test]
    fn the_first_identity_file_on_a_vault_slot_names_the_key() {
        let home = Path::new("/h");
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let vault = |fingerprint: &str| Some(SlotSource::Vault { fingerprint: fingerprint.into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: false });
        state.key_slots.insert("a".repeat(32), slot("id_mac-aaaaaaaa", vault("SHA256:a")));
        state.key_slots.insert("b".repeat(32), slot("work-bbbbbbbb", Some(SlotSource::SyncedCopy { fingerprint: "SHA256:w".into() })));
        state.key_slots.insert("c".repeat(32), slot("work-cccccccc", vault("SHA256:c")));
        let files = |values: &[&str]| values.iter().map(|value| value.to_string()).collect::<Vec<_>>();
        assert_eq!(vault_slot_of(&files(&["~/.ssh/id_rsa", "~/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("a".repeat(32)));
        assert_eq!(vault_slot_of(&files(&["%d/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("a".repeat(32)));
        assert_eq!(vault_slot_of(&files(&["~/.ssh/sshelter/keys/work-bbbbbbbb"]), &state, home), None, "a file slot is not a vault key");
        assert_eq!(vault_slot_of(&files(&["~/.ssh/sshelter/keys/work-cccccccc", "~/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("c".repeat(32)), "the first one wins");
    }

    /// A directory over a canned ssh_config (`config_text`) and canned `ssh -G` answers (`effective`, by alias).
    fn directory(dir: &tempfile::TempDir, config_text: &str, effective: &[(&str, &str)]) -> SshConfigDirectory {
        let config = dir.path().join("config");
        std::fs::write(&config, config_text).unwrap();
        let answers: HashMap<String, Vec<(String, String)>> = effective.iter().map(|(alias, text)| (alias.to_string(), pairs(text))).collect();
        let sources = Sources {
            doc: Box::new(move || crate::config::include::load_doc(&config).map_err(|error| error.to_string())),
            effective: Box::new(move |alias| answers.get(alias).cloned().ok_or_else(|| format!("ssh -G does not know {alias}"))),
            vault_key: Box::new(|files| files.iter().any(|file| file.ends_with("id_mac-aaaaaaaa")).then(|| "a".repeat(32))),
            password_saved: Box::new(|host| host.as_str() == "web"),
        };
        SshConfigDirectory::new(sources, PinStore::with_clock(dir.path().join("host-pins.json"), || 1_700_000_000_000))
    }

    /// A directory over canned `ssh -G` answers alone: each alias given is a saved host (a `Host` block with no settings of its own; the
    /// adapter takes the settings from `ssh -G`).
    fn directory_over(dir: &tempfile::TempDir, effective: &[(&str, &str)]) -> SshConfigDirectory {
        let config: String = effective.iter().map(|(alias, _)| format!("Host {alias}\n")).collect();
        directory(dir, &config, effective)
    }

    const CONFIG: &str = "Host web\n  HostName web.example.com\nHost bastion\n  HostName gate.example.com\n  Port 2200\n  User admin\nHost db\n  ProxyJump admin@bastion:2200\nHost pc\n  ProxyCommand nc %h %p\nHost loop1\n  ProxyJump loop2\nHost loop2\n  ProxyJump loop1\nHost outside\n  ProxyJump gate.example.org\n";

    fn effective() -> Vec<(&'static str, &'static str)> {
        vec![
            ("web", "hostname web.example.com\nport 22\nuser deploy\nidentityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ecdsa\nidentityfile ~/.ssh/id_ecdsa_sk\nidentityfile ~/.ssh/id_ed25519\nidentityfile ~/.ssh/id_ed25519_sk\n"),
            ("bastion", "hostname gate.example.com\nport 2200\nuser admin\nidentityfile ~/.ssh/sshelter/keys/id_mac-aaaaaaaa\n"),
            ("db", "hostname db\nport 22\nuser deploy\nproxyjump admin@bastion:2200\nidentityfile none\n"),
            ("pc", "hostname pc\nport 22\nuser deploy\nproxycommand nc %h %p\n"),
            ("loop1", "hostname loop1\nproxyjump loop2\n"),
            ("loop2", "hostname loop2\nproxyjump loop1\n"),
            ("outside", "hostname outside\nproxyjump gate.example.org\n"),
        ]
    }

    #[test]
    fn a_saved_host_resolves_with_its_jump_hosts_first_and_a_jump_that_repeats_the_saved_port_and_user_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory(&dir, CONFIG, &effective());
        let target = directory.resolve(&HostQuery::Alias("db".into())).unwrap();
        let hops: Vec<(&str, &str, u16, &str)> = target.hops.iter().map(|hop| (hop.alias.as_str(), hop.hostname.as_str(), hop.port, hop.user.as_str())).collect();
        assert_eq!(hops, [("bastion", "gate.example.com", 2200, "admin"), ("db", "db", 22, "deploy")]);
        assert_eq!(target.hops[0].auth, AuthMethod::Key { key_id: "a".repeat(32) });
        assert_eq!(target.hops[1].auth, AuthMethod::Interactive);
        assert_eq!(directory.resolve(&HostQuery::Id("db".into())).unwrap(), target, "a host's id is its alias here");
        // One id is one server: every hop of a chain is its host as saved, so resolving that host by its id gives the very same hop.
        for hop in &target.hops {
            assert_eq!(directory.resolve(&HostQuery::Id(hop.id.to_string())).unwrap().hops.last(), Some(hop), "{} in the chain is {} as saved", hop.alias, hop.alias);
        }
        assert_eq!(directory.resolve(&HostQuery::Alias("web".into())).unwrap().hops[0].auth, AuthMethod::Password, "a saved password goes first");
        assert_eq!(directory.password_account(&HostId::from("web")), "host:web");
    }

    #[test]
    fn what_sshelter_cannot_connect_to_is_refused_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory(&dir, CONFIG, &effective());
        let refused = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).unwrap_err().to_string();
        assert_eq!(refused("mail"), "No saved host is called mail.");
        assert_eq!(refused("-oProxyCommand=evil"), "No saved host is called -oProxyCommand=evil.");
        assert_eq!(refused("pc"), "pc uses ProxyCommand, which SSHelter's own SSH client does not support.");
        assert_eq!(refused("outside"), "outside jumps through gate.example.org, which is not a saved host.");
        assert_eq!(refused("loop1"), "The jump hosts go round in a circle: loop1 → loop2 → loop1.");
    }

    /// The key files a host names decide how it logs in, whether it is the host asked for or a jump host: none (or the default list)
    /// starts with a password or keyboard-interactive, a file of its own is refused.
    #[test]
    fn a_host_is_judged_by_the_key_files_it_names_when_it_is_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let defaults = format!("hostname defaults\nport 22\nuser me\n{}", identity_lines(DEFAULT_LISTS[0].1));
        let directory = directory_over(
            &dir,
            &[
                ("named", "hostname named\nport 22\nuser me\nidentityfile ~/.ssh/id_ed25519\n"),
                ("nothing", "hostname nothing\nport 22\nuser me\nidentityfile none\n"),
                ("defaults", &defaults),
                ("through", "hostname through\nport 22\nuser me\nidentityfile none\nproxyjump named\n"),
            ],
        );
        let auth = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.last().unwrap().auth.clone());
        assert_eq!(auth("nothing"), Ok(AuthMethod::Interactive));
        assert_eq!(auth("defaults"), Ok(AuthMethod::Interactive));
        assert_eq!(auth("named"), Err(key_file_refusal("named", "~/.ssh/id_ed25519")));
        assert_eq!(auth("through"), Err(key_file_refusal("named", "~/.ssh/id_ed25519")), "the jump host's key counts as well");
    }

    /// A jump is the saved host, not a variant of it. The pin, the saved password and what a person typed belong to the host id, and an id
    /// stands for one server (`HostDirectory`): `ProxyJump bastion:22` for a `bastion` saved with port 2200 would be a second endpoint under
    /// the same id, and the two would share one pin.
    #[test]
    fn a_jump_written_with_another_port_or_user_than_the_saved_host_has_is_refused_with_the_reason() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("bastion", "hostname gate.example.com\nport 2200\nuser admin\n"),
                ("by-port", "hostname by-port\nport 22\nuser deploy\nproxyjump bastion:22\n"),
                ("by-user", "hostname by-user\nport 22\nuser deploy\nproxyjump ops@bastion:2200\n"),
                ("by-both", "hostname by-both\nport 22\nuser deploy\nproxyjump ops@bastion:22\n"),
                ("anon", "hostname anon\nport 22\n"),
                ("by-anon", "hostname by-anon\nport 22\nuser deploy\nproxyjump root@anon\n"),
            ],
        );
        let refused = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into()));
        let unsupported = |text: &str| Err(DirectoryError::Unsupported(text.to_string()));
        assert_eq!(refused("by-port"), unsupported("by-port jumps through bastion on port 22, but bastion is saved with port 2200."));
        assert_eq!(refused("by-user"), unsupported("by-user jumps through bastion as ops, but bastion is saved with user admin."));
        assert_eq!(refused("by-both"), unsupported("by-both jumps through bastion on port 22, but bastion is saved with port 2200."), "the port is named first");
        // `ssh -G` names the local user for a host with no `User`, so a saved user is empty only when the answer lacks the line; a user
        // written for the jump cannot then be shown to be the saved one.
        assert_eq!(refused("by-anon"), unsupported("by-anon jumps through anon as root, but anon is saved with your local user name."));
    }

    /// An entry that says nothing the saved host does not say already is the saved host, however it is written.
    #[test]
    fn a_jump_entry_that_only_repeats_the_saved_port_and_user_resolves_to_the_saved_host() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("bastion", "hostname gate.example.com\nport 2200\nuser admin\n"),
                ("by-name", "hostname by-name\nport 22\nuser deploy\nproxyjump bastion\n"),
                ("by-user", "hostname by-user\nport 22\nuser deploy\nproxyjump admin@bastion\n"),
                ("by-port", "hostname by-port\nport 22\nuser deploy\nproxyjump bastion:2200\n"),
                ("by-both", "hostname by-both\nport 22\nuser deploy\nproxyjump admin@bastion:2200\n"),
                ("by-uri", "hostname by-uri\nport 22\nuser deploy\nproxyjump ssh://admin@bastion:2200\n"),
            ],
        );
        let saved = directory.resolve(&HostQuery::Alias("bastion".into())).unwrap().hops[0].clone();
        assert_eq!((saved.hostname.as_str(), saved.port, saved.user.as_str()), ("gate.example.com", 2200, "admin"));
        for alias in ["by-name", "by-user", "by-port", "by-both", "by-uri"] {
            let target = directory.resolve(&HostQuery::Alias(alias.into())).unwrap();
            assert_eq!(target.hops.len(), 2, "{alias}");
            assert_eq!(target.hops[0], saved, "{alias}: the jump host is the saved one");
            assert_eq!(target.hops[1].alias, alias);
        }
    }

    /// The port and user of a jump entry are compared with the jump host itself: the last hop its own jump hosts lead up to.
    #[test]
    fn a_jump_entry_is_compared_with_the_jump_host_itself_and_not_with_the_jump_hosts_in_front_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("edge", "hostname edge.example.com\nport 22\nuser ops\n"),
                ("gate", "hostname gate.example.com\nport 2201\nuser root\nproxyjump edge\n"),
                ("far", "hostname far\nport 22\nuser deploy\nproxyjump root@gate:2201\n"),
                ("far-wrong", "hostname far-wrong\nport 22\nuser deploy\nproxyjump ops@gate:22\n"),
            ],
        );
        let aliases = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>());
        assert_eq!(aliases("far"), Ok(vec!["edge".to_string(), "gate".to_string(), "far".to_string()]));
        let wrong = DirectoryError::Unsupported("far-wrong jumps through gate on port 22, but gate is saved with port 2201.".to_string());
        assert_eq!(aliases("far-wrong"), Err(wrong), "22 and ops are edge's, not gate's");
    }

    /// The broker keeps what it knows about a hop (typed passwords, cancels, the pin policy) by host id, so a chain names each host once. A
    /// host that comes up twice without a loop is refused with a sentence of its own, and the host whose jump hosts name it twice is the
    /// one the sentence is about. Only the first jump host of a list brings jump hosts of its own (see
    /// `only_the_first_jump_host_of_a_list_is_reached_through_its_own_jump_hosts`), so a host comes up twice when the list names it twice,
    /// when the chain of the first jump host has a later one of the list, or when a later one names the host that has the list.
    #[test]
    fn a_host_that_a_chain_names_twice_is_refused_although_nothing_loops() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("bastion", "hostname gate.example.com\nport 22\nuser ops\n"),
                ("edge", "hostname edge.example.com\nport 22\nuser ops\nproxyjump bastion\n"),
                ("twice", "hostname twice\nport 22\nuser deploy\nproxyjump bastion,bastion\n"),
                ("via-edge", "hostname via-edge\nport 22\nuser deploy\nproxyjump edge,bastion\n"),
                ("own", "hostname own\nport 22\nuser deploy\nproxyjump bastion,own\n"),
                ("deep", "hostname deep\nport 22\nuser deploy\nproxyjump twice\n"),
                ("down", "hostname down\nport 22\nuser deploy\nproxyjump bastion,edge\n"),
            ],
        );
        let refused = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into()));
        let named_twice = |text: &str| Err(DirectoryError::Unsupported(text.to_string()));
        assert_eq!(refused("twice"), named_twice("twice's jump hosts name bastion twice."));
        assert_eq!(refused("via-edge"), named_twice("via-edge's jump hosts name bastion twice."), "`edge` is reached through `bastion`, and `bastion` comes again");
        assert_eq!(refused("own"), named_twice("own's jump hosts name own twice."), "a later jump host that is the host itself");
        assert_eq!(refused("deep"), named_twice("twice's jump hosts name bastion twice."), "the host that names it twice, not the one asked for");
        assert!(refused("edge").is_ok() && refused("bastion").is_ok(), "each of them is fine alone");
        // `edge` behind `bastion` is no repeat when the list names `bastion` and then `edge`: ssh goes bastion → edge → down.
        let aliases = |alias: &str| refused(alias).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>());
        assert_eq!(aliases("down"), Ok(["bastion", "edge", "down"].map(String::from).to_vec()));
    }

    /// OpenSSH routes `ProxyJump a,b,c` as `ssh -J a,b -W target c`, and for `c` as `ssh -J a -W c b`, and for `b` as `ssh -W b a` (checked
    /// with `ssh -vvv` on a config of its own): only `a`, the first, is reached the way it is saved, through its own jump hosts. `-J` takes
    /// the place of everything a later jump host says about how it is reached, its `ProxyJump` and its `ProxyCommand` alike. Such a host is
    /// just its own hop, behind the one before it.
    #[test]
    fn only_the_first_jump_host_of_a_list_is_reached_through_its_own_jump_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("x", "hostname x\nport 22\nuser ops\n"),
                ("a", "hostname a\nport 22\nuser ops\nproxyjump x\n"),
                ("y", "hostname y\nport 22\nuser ops\n"),
                ("b", "hostname b\nport 22\nuser ops\nproxyjump y\nidentityfile ~/.ssh/sshelter/keys/id_mac-aaaaaaaa\n"),
                ("t", "hostname t\nport 22\nuser deploy\nproxyjump a,b\n"),
                ("bastion", "hostname gate.example.com\nport 22\nuser ops\n"),
                ("edge", "hostname edge.example.com\nport 22\nuser ops\nproxyjump bastion\n"),
                ("down", "hostname down\nport 22\nuser deploy\nproxyjump bastion,edge\n"),
                ("left", "hostname left\nport 22\nuser ops\nproxyjump bastion\n"),
                ("right", "hostname right\nport 22\nuser ops\nproxyjump bastion\n"),
                ("top", "hostname top\nport 22\nuser deploy\nproxyjump left,right\n"),
            ],
        );
        let chain = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).unwrap();
        let aliases = |alias: &str| chain(alias).hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>();
        assert_eq!(aliases("t"), ["x", "a", "b", "t"], "a's own jump host x comes first; b's own jump host y is not visited");
        assert_eq!(aliases("down"), ["bastion", "edge", "down"], "ssh goes bastion → edge → down, and `edge` is not behind a second `bastion`");
        assert_eq!(aliases("top"), ["bastion", "left", "right", "top"], "`right` is reached through `left`, not through a `bastion` of its own");
        // A later jump host is its own hop as saved, its key and password included: resolved alone, its last hop is the same.
        let target = chain("t");
        assert_eq!(target.hops[2].auth, AuthMethod::Key { key_id: "a".repeat(32) });
        for hop in &target.hops {
            assert_eq!(chain(hop.id.as_str()).hops.last(), Some(hop), "{} in the chain is {} as saved", hop.alias, hop.alias);
        }
    }

    /// What keeps the first jump host from being reached and what does not follow the same rule: its own `ProxyCommand` and the jump hosts
    /// of its own are used, and a later one has neither used, so that neither can refuse the chain.
    #[test]
    fn the_first_jump_hosts_own_proxy_command_and_jump_hosts_count_and_a_later_ones_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("a", "hostname a\nport 22\nuser ops\n"),
                ("c", "hostname c\nport 22\nuser ops\nproxycommand nc %h %p\n"),
                ("lost", "hostname lost\nport 22\nuser ops\nproxyjump gate.example.org\n"),
                ("loop1", "hostname loop1\nport 22\nuser ops\nproxyjump loop2\n"),
                ("loop2", "hostname loop2\nport 22\nuser ops\nproxyjump loop1\n"),
                ("later-c", "hostname later-c\nport 22\nuser deploy\nproxyjump a,c\n"),
                ("first-c", "hostname first-c\nport 22\nuser deploy\nproxyjump c,a\n"),
                ("later-lost", "hostname later-lost\nport 22\nuser deploy\nproxyjump a,lost\n"),
                ("first-lost", "hostname first-lost\nport 22\nuser deploy\nproxyjump lost,a\n"),
                ("later-loop", "hostname later-loop\nport 22\nuser deploy\nproxyjump a,loop1\n"),
                ("first-loop", "hostname first-loop\nport 22\nuser deploy\nproxyjump loop1,a\n"),
            ],
        );
        let aliases = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>());
        let unsupported = |text: &str| Err(DirectoryError::Unsupported(text.to_string()));
        // ssh runs `ssh -J a -W target c` for these: c's ProxyCommand and lost's ProxyJump are replaced, never used.
        assert_eq!(aliases("later-c"), Ok(["a", "c", "later-c"].map(String::from).to_vec()));
        assert_eq!(aliases("later-lost"), Ok(["a", "lost", "later-lost"].map(String::from).to_vec()));
        assert_eq!(aliases("later-loop"), Ok(["a", "loop1", "later-loop"].map(String::from).to_vec()), "loop1's own loop is never followed");
        // As the first jump host, each is reached the way it is saved.
        assert_eq!(aliases("first-c"), unsupported("c uses ProxyCommand, which SSHelter's own SSH client does not support."));
        assert_eq!(aliases("first-lost"), unsupported("lost jumps through gate.example.org, which is not a saved host."));
        assert_eq!(aliases("first-loop"), unsupported("The jump hosts go round in a circle: first-loop → loop1 → loop2 → loop1."));
    }

    /// A later jump host is a saved host like any other: it has to be saved, a port or user written for it has to be its own, and a key
    /// it logs in with has to be in the vault.
    #[test]
    fn a_later_jump_host_is_checked_as_a_saved_host_for_its_port_user_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("a", "hostname a\nport 22\nuser ops\n"),
                ("b", "hostname b\nport 2200\nuser admin\n"),
                ("old", "hostname old\nport 22\nuser ops\nidentityfile ~/.ssh/work_key\n"),
                ("unknown", "hostname unknown\nport 22\nuser deploy\nproxyjump a,gate\n"),
                ("by-port", "hostname by-port\nport 22\nuser deploy\nproxyjump a,b:22\n"),
                ("by-user", "hostname by-user\nport 22\nuser deploy\nproxyjump a,ops@b:2200\n"),
                ("by-key", "hostname by-key\nport 22\nuser deploy\nproxyjump a,old\n"),
                ("same", "hostname same\nport 22\nuser deploy\nproxyjump a,admin@b:2200\n"),
            ],
        );
        let resolved = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.len());
        let unsupported = |text: &str| Err(DirectoryError::Unsupported(text.to_string()));
        assert_eq!(resolved("unknown"), unsupported("unknown jumps through gate, which is not a saved host."));
        assert_eq!(resolved("by-port"), unsupported("by-port jumps through b on port 22, but b is saved with port 2200."));
        assert_eq!(resolved("by-user"), unsupported("by-user jumps through b as ops, but b is saved with user admin."));
        assert_eq!(resolved("by-key"), Err(key_file_refusal("old", "~/.ssh/work_key")));
        assert_eq!(resolved("same"), Ok(3), "an entry that only repeats the saved port and user is the saved host");
    }

    /// A loop keeps its own sentence, with the hosts from the one asked for round the circle. Only a first jump host is followed into its
    /// own jump hosts, so it is only there that a loop can be found.
    #[test]
    fn a_loop_is_refused_with_the_path_round_the_circle() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(
            &dir,
            &[
                ("bastion", "hostname gate.example.com\nport 22\nuser ops\n"),
                ("self", "hostname self\nport 22\nuser deploy\nproxyjump self\n"),
                ("loop1", "hostname loop1\nport 22\nuser deploy\nproxyjump loop2\n"),
                ("loop2", "hostname loop2\nport 22\nuser deploy\nproxyjump loop1\n"),
                ("behind", "hostname behind\nport 22\nuser deploy\nproxyjump loop1,bastion\n"),
                ("after", "hostname after\nport 22\nuser deploy\nproxyjump bastion,loop1\n"),
            ],
        );
        let refused = |query: HostQuery| directory.resolve(&query);
        let circle = |path: &str| Err(DirectoryError::Unsupported(format!("The jump hosts go round in a circle: {path}.")));
        assert_eq!(refused(HostQuery::Alias("self".into())), circle("self → self"));
        assert_eq!(refused(HostQuery::Alias("loop1".into())), circle("loop1 → loop2 → loop1"));
        assert_eq!(refused(HostQuery::Id("loop2".into())), circle("loop2 → loop1 → loop2"), "by id as well");
        assert_eq!(refused(HostQuery::Alias("behind".into())), circle("behind → loop1 → loop2 → loop1"), "the first jump host is followed into its own");
        let after = refused(HostQuery::Alias("after".into())).unwrap();
        assert_eq!(after.hops.iter().map(|hop| hop.alias.as_str()).collect::<Vec<_>>(), ["bastion", "loop1", "after"], "a later one is not followed: no loop");
    }

    /// The sentences of the test fake and of the adapter are written twice; the same chains, given to both, are answered the same way (the
    /// hops, or the error), one host after the other, so that nothing is left over from one chain to the next.
    #[test]
    fn the_adapter_and_the_test_fake_answer_the_same_chains_the_same_way() {
        // Each saved host, and the saved hosts it jumps through, in order. `gate` is not saved.
        let chains: &[(&str, &[&str])] = &[
            ("edge", &[]),
            ("bastion", &["edge"]),
            ("db", &["bastion"]),
            ("web", &["bastion"]),
            ("self", &["self"]),
            ("loop1", &["loop2"]),
            ("loop2", &["loop1"]),
            ("behind", &["loop1", "bastion"]),
            ("after", &["bastion", "loop1"]),
            ("twice", &["bastion", "bastion"]),
            ("down", &["bastion", "web"]),
            ("via-web", &["web", "bastion"]),
            ("own", &["bastion", "own"]),
            ("left", &["bastion"]),
            ("right", &["bastion"]),
            ("top", &["left", "right"]),
            ("deep", &["twice"]),
            ("lost", &["gate"]),
            ("lost-down", &["bastion", "lost"]),
            ("lost-first", &["lost", "bastion"]),
            ("gone", &["bastion", "gate"]),
            ("n1", &[]),
            ("n2", &["n1"]),
            ("n3", &["n2"]),
            ("n4", &["n3"]),
            ("n5", &["n4"]),
            ("n6", &["n5"]),
            ("n7", &["n6"]),
            ("list5", &["n1", "n2", "n3", "n4", "n5"]),
            ("list6", &["n1", "n2", "n3", "n4", "n5", "n6"]),
            ("via-list6", &["list6"]),
            ("mixed", &["n3", "n4", "n5", "n6"]),
        ];
        let fake = chains.iter().fold(FakeDirectory::new(), |fake, (alias, jumps)| fake.with_host_via(alias, AuthMethod::Password, jumps));
        let answers: Vec<(String, String)> = chains
            .iter()
            .map(|(alias, jumps)| {
                let jump = if jumps.is_empty() { String::new() } else { format!("proxyjump {}\n", jumps.join(",")) };
                (alias.to_string(), format!("hostname {alias}\nport 22\nuser deploy\n{jump}"))
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let adapter = directory_over(&dir, &answers.iter().map(|(alias, text)| (alias.as_str(), text.as_str())).collect::<Vec<_>>());
        let aliases = |directory: &dyn HostDirectory, alias: &str| {
            directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>())
        };
        for (alias, _) in chains {
            assert_eq!(aliases(&adapter, alias), aliases(&fake, alias), "{alias}");
        }
        // The answers themselves, so that two matching refusals for another reason would not pass.
        let chain = |names: &[&str]| Ok(names.iter().map(|name| name.to_string()).collect::<Vec<_>>());
        assert_eq!(aliases(&adapter, "db"), chain(&["edge", "bastion", "db"]));
        assert_eq!(aliases(&adapter, "web"), chain(&["edge", "bastion", "web"]), "a jump host that two hosts share is not a loop");
        // ssh routes `ProxyJump a,b` as `ssh -J a -W target b`: only the first jump host has jump hosts of its own.
        assert_eq!(aliases(&adapter, "down"), chain(&["edge", "bastion", "web", "down"]), "web's own jump host `bastion` is not visited again");
        assert_eq!(aliases(&adapter, "top"), chain(&["edge", "bastion", "left", "right", "top"]), "right is reached through left, not through a bastion of its own");
        assert_eq!(aliases(&adapter, "after"), chain(&["edge", "bastion", "loop1", "after"]), "loop1 comes later: its own loop is not followed");
        assert_eq!(aliases(&adapter, "lost-down"), chain(&["edge", "bastion", "lost", "lost-down"]), "lost comes later: its own unsaved jump host is not used");
        let refused = |alias: &str, sentence: &str| assert_eq!(aliases(&adapter, alias), Err(DirectoryError::Unsupported(sentence.to_string())), "{alias}");
        refused("behind", "The jump hosts go round in a circle: behind → loop1 → loop2 → loop1.");
        refused("twice", "twice's jump hosts name bastion twice.");
        refused("via-web", "via-web's jump hosts name bastion twice.");
        refused("own", "own's jump hosts name own twice.");
        refused("deep", "twice's jump hosts name bastion twice.");
        refused("lost", "lost jumps through gate, which is not a saved host.");
        refused("lost-first", "lost jumps through gate, which is not a saved host.");
        refused("gone", "gone jumps through gate, which is not a saved host.");
        // At most five jump hosts in all, counted over the whole chain: nested, listed, or both.
        assert_eq!(aliases(&adapter, "n6"), chain(&["n1", "n2", "n3", "n4", "n5", "n6"]), "five jump hosts, nested");
        assert_eq!(aliases(&adapter, "list5"), chain(&["n1", "n2", "n3", "n4", "n5", "list5"]), "five jump hosts, listed");
        refused("n7", "n7 needs more than 5 jump hosts.");
        refused("list6", "list6 needs more than 5 jump hosts.");
        refused("via-list6", "via-list6 needs more than 5 jump hosts.");
        refused("mixed", "mixed needs more than 5 jump hosts.");
    }

    /// Five jump hosts one behind the other are fine, a sixth is not: the host that would need more than five is refused, by its own alias.
    #[test]
    fn jump_hosts_nested_more_than_five_deep_are_refused() {
        // h0 jumps through h1, which jumps through h2, and so on up to h6.
        let answers: Vec<(String, String)> = (0..=6)
            .map(|n| {
                let jump = if n < 6 { format!("proxyjump h{}\n", n + 1) } else { String::new() };
                (format!("h{n}"), format!("hostname h{n}\nport 22\nuser ops\n{jump}"))
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(&dir, &answers.iter().map(|(alias, text)| (alias.as_str(), text.as_str())).collect::<Vec<_>>());
        let aliases = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>());
        assert_eq!(aliases("h1"), Ok(["h6", "h5", "h4", "h3", "h2", "h1"].map(String::from).to_vec()));
        assert_eq!(aliases("h0"), Err(DirectoryError::Unsupported("h0 needs more than 5 jump hosts.".to_string())));
    }

    /// A chain has at most five jump hosts, counted over the whole chain: the first jump host's own and the later ones together, however
    /// they are written or nested. The sentence names the host that was asked for.
    #[test]
    fn a_chain_of_more_than_five_jump_hosts_is_refused_however_they_are_listed_or_nested() {
        let plain = |alias: &str| (alias.to_string(), format!("hostname {alias}\nport 22\nuser ops\n"));
        let jumping = |alias: &str, through: &str| (alias.to_string(), format!("hostname {alias}\nport 22\nuser ops\nproxyjump {through}\n"));
        let answers: Vec<(String, String)> = vec![
            plain("j1"),
            plain("j2"),
            plain("j3"),
            plain("j4"),
            plain("j5"),
            plain("j6"),
            jumping("five", "j1,j2,j3,j4,j5"),
            jumping("six", "j1,j2,j3,j4,j5,j6"),
            jumping("front", "j1,j2,j3"),
            jumping("exact", "front,j4"),
            jumping("over", "front,j4,j5"),
            jumping("nested", "front"),
            jumping("deeper", "nested"),
            jumping("deepest", "deeper"),
            jumping("via-six", "six"),
        ];
        let dir = tempfile::tempdir().unwrap();
        let directory = directory_over(&dir, &answers.iter().map(|(alias, text)| (alias.as_str(), text.as_str())).collect::<Vec<_>>());
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

    /// `ssh -G` is run for every host of a chain (and may take a while), so a chain that is too long is refused as soon as it is known to be
    /// too long, not after `ssh -G` was run for every host of it.
    #[test]
    fn a_chain_that_is_too_long_is_refused_before_ssh_g_is_run_for_all_of_it() {
        let answers: std::collections::HashMap<String, Vec<(String, String)>> = (1..=20)
            .map(|n| {
                let jump = if n > 1 { format!("proxyjump n{}\n", n - 1) } else { String::new() };
                (format!("n{n}"), pairs(&format!("hostname n{n}\nport 22\nuser ops\n{jump}")))
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, (1..=20).map(|n| format!("Host n{n}\n")).collect::<String>()).unwrap();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let sources = Sources {
            doc: Box::new(move || crate::config::include::load_doc(&config).map_err(|error| error.to_string())),
            effective: Box::new(move |alias| {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                answers.get(alias).cloned().ok_or_else(|| format!("ssh -G does not know {alias}"))
            }),
            vault_key: Box::new(|_| None),
            password_saved: Box::new(|_| false),
        };
        let directory = SshConfigDirectory::new(sources, PinStore::new(dir.path().join("host-pins.json")));
        assert_eq!(directory.resolve(&HostQuery::Alias("n20".into())), Err(DirectoryError::Unsupported("n20 needs more than 5 jump hosts.".to_string())));
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) <= MAX_JUMPS + 1, "ssh -G ran {} times", calls.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn a_pin_from_the_pin_file_is_in_the_resolved_hop_and_an_unreadable_file_stops_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let directory = directory(&dir, CONFIG, &effective());
        let key = |line: &str| HostKey::from_openssh_line(line).unwrap();
        check_the_pin_contract(&directory, &HostQuery::Alias("web".into()), &key(test_keys::PLAIN_PUBLIC), &key(test_keys::ECDSA_PUBLIC), &key(test_keys::RSA_PUBLIC));
        std::fs::write(dir.path().join("host-pins.json"), "{ damaged").unwrap();
        assert!(matches!(directory.resolve(&HostQuery::Alias("web".into())), Err(DirectoryError::Failed(text)) if text.contains("host-pins.json")));
    }

    /// A directory over a config file of the test's own, with the real `ssh -G` (`-F`: the user's `~/.ssh` is not read).
    fn real_ssh_directory(dir: &tempfile::TempDir, config: &Path) -> SshConfigDirectory {
        let (doc_path, ssh_g_path) = (config.to_path_buf(), config.to_path_buf());
        let sources = Sources {
            doc: Box::new(move || crate::config::include::load_doc(&doc_path).map_err(|error| error.to_string())),
            effective: Box::new(move |alias| crate::config::intel::effective_config_in_fixture(alias, &ssh_g_path).map_err(|error| error.to_string())),
            vault_key: Box::new(|_| None),
            password_saved: Box::new(|_| false),
        };
        SshConfigDirectory::new(sources, PinStore::new(dir.path().join("host-pins.json")))
    }

    /// The adapter's reading of `ssh -G` against the real tool, on a config file of the test's own (`-F`; the user's `~/.ssh` is not read).
    /// `db`'s jump entry repeats the port and user that `bastion` is saved with, as an entry has to.
    #[test]
    fn the_real_ssh_g_output_resolves_into_the_same_hops() {
        let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Host bastion\n  HostName gate.example.com\n  User admin\n  Port 2200\n  ServerAliveInterval 20\nHost db\n  HostName 10.0.0.5\n  Port 2222\n  User deploy\n  ProxyJump admin@bastion:2200\n  ConnectTimeout 7\n").unwrap();
        let directory = real_ssh_directory(&dir, &config);
        let target = directory.resolve(&HostQuery::Alias("db".into())).unwrap();
        let hops: Vec<(&str, &str, u16, &str, Duration, Duration)> =
            target.hops.iter().map(|hop| (hop.alias.as_str(), hop.hostname.as_str(), hop.port, hop.user.as_str(), hop.connect_timeout, hop.keepalive_every)).collect();
        assert_eq!(
            hops,
            [
                ("bastion", "gate.example.com", 2200, "admin", Duration::from_secs(15), Duration::from_secs(20)),
                ("db", "10.0.0.5", 2222, "deploy", Duration::from_secs(7), Duration::from_secs(30)),
            ]
        );
        assert!(target.hops.iter().all(|hop| hop.auth == AuthMethod::Interactive));
    }

    /// The default key files against the real tool: `ssh -G` (with `-F`) lists them for a host that names no `IdentityFile`, prints
    /// `none` for `IdentityFile none` and prints exactly what a host names otherwise. If this fails on a new OpenSSH, the list that
    /// version prints is not in `DEFAULT_IDENTITY_SEQUENCES` yet.
    #[test]
    fn the_real_ssh_g_prints_the_default_key_files_only_for_a_host_that_names_none() {
        let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            "Host plain\n  HostName plain.example.com\nHost named\n  HostName named.example.com\n  IdentityFile ~/.ssh/id_ed25519\nHost nothing\n  HostName nothing.example.com\n  IdentityFile none\n",
        )
        .unwrap();
        let directory = real_ssh_directory(&dir, &config);
        let auth = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops[0].auth.clone());
        assert_eq!(auth("plain"), Ok(AuthMethod::Interactive), "a host that names no key gets the default list");
        assert_eq!(auth("nothing"), Ok(AuthMethod::Interactive), "IdentityFile none");
        assert_eq!(auth("named"), Err(key_file_refusal("named", "~/.ssh/id_ed25519")), "one default-named file is a key file");
    }

    /// The routing of a jump list against the real tool. `ssh -J a -W target b` is what ssh runs for the later jump host `b` of
    /// `ProxyJump a,b`, and `-J a` takes the place of the `ProxyJump` and the `ProxyCommand` that `b` has (`ssh -G -J a b` shows it, on a
    /// config of the test's own with `-F`); the adapter reads the list from the real `ssh -G` output the same way.
    #[test]
    fn the_real_ssh_g_output_of_a_jump_list_resolves_the_way_openssh_routes_it() {
        let Some(tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let hosts = [("x", ""), ("a", "  ProxyJump x\n"), ("y", ""), ("b", "  ProxyJump y\n"), ("c", "  ProxyCommand nc %h %p\n"), ("t", "  ProxyJump a,b\n"), ("t2", "  ProxyJump a,c\n")];
        let text: String = hosts.iter().map(|(alias, settings)| format!("Host {alias}\n  HostName {alias}.example.com\n{settings}")).collect();
        std::fs::write(&config, text).unwrap();
        let ssh_g = |jump: &str, host: &str| -> Vec<String> {
            let output = crate::process::output(std::process::Command::new(&tools.ssh).arg("-F").arg(&config).args(["-G", "-J", jump, host])).unwrap();
            assert!(output.status.success(), "ssh -G -J {jump} {host}");
            String::from_utf8_lossy(&output.stdout).lines().map(str::to_string).collect()
        };
        let (via_a_to_b, via_a_to_c) = (ssh_g("a", "b"), ssh_g("a", "c"));
        assert!(via_a_to_b.contains(&"proxyjump a".to_string()) && !via_a_to_b.iter().any(|line| line.starts_with("proxyjump y")), "{via_a_to_b:?}");
        assert!(via_a_to_c.contains(&"proxyjump a".to_string()) && !via_a_to_c.iter().any(|line| line.starts_with("proxycommand")), "{via_a_to_c:?}");
        let directory = real_ssh_directory(&dir, &config);
        let aliases = |alias: &str| directory.resolve(&HostQuery::Alias(alias.into())).map(|target| target.hops.into_iter().map(|hop| hop.alias).collect::<Vec<_>>());
        assert_eq!(aliases("t"), Ok(["x", "a", "b", "t"].map(String::from).to_vec()), "b's own jump host y is not visited");
        assert_eq!(aliases("t2"), Ok(["x", "a", "c", "t2"].map(String::from).to_vec()), "c's own ProxyCommand is not used");
        assert!(matches!(aliases("c"), Err(DirectoryError::Unsupported(text)) if text.contains("ProxyCommand")), "alone, c is reached through its ProxyCommand");
    }

    /// `ssh -G` names the local user for a host that has no `User` (the adapter does not look the name up itself), so a jump entry that
    /// names the local user repeats the saved value, and one that names another user does not.
    #[test]
    fn a_jump_that_names_the_local_user_is_the_saved_host_when_the_host_has_no_user_of_its_own() {
        let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Host plain\n  HostName plain.example.com\n").unwrap();
        let answer = crate::config::intel::effective_config_in_fixture("plain", &config).unwrap();
        let local = answer.iter().find(|(key, _)| key == "user").map(|(_, user)| user.clone()).expect("ssh -G names a user");
        if !local.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            return; // not a name that can be written into a ProxyJump line (a Windows account with a space, say)
        }
        std::fs::write(
            &config,
            format!("Host plain\n  HostName plain.example.com\nHost far\n  HostName far.example.com\n  ProxyJump {local}@plain\nHost wrong\n  HostName wrong.example.com\n  ProxyJump not-{local}@plain\n"),
        )
        .unwrap();
        let directory = real_ssh_directory(&dir, &config);
        let far = directory.resolve(&HostQuery::Alias("far".into())).unwrap();
        let hops: Vec<(&str, &str)> = far.hops.iter().map(|hop| (hop.alias.as_str(), hop.user.as_str())).collect();
        assert_eq!(hops, [("plain", local.as_str()), ("far", local.as_str())]);
        assert_eq!(
            directory.resolve(&HostQuery::Alias("wrong".into())),
            Err(DirectoryError::Unsupported(format!("wrong jumps through plain as not-{local}, but plain is saved with user {local}.")))
        );
    }
}

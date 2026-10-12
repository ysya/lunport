//! TEMPORARY: plan 1c deletes this file, when host records (spec §5.1) replace the ssh_config blocks. Until then it is the broker's
//! `HostDirectory` over the data the app has today, read-only: the hosts are the `Host` patterns of the app's ssh_config, their settings
//! come from `ssh -G` (no connection), a host's key is the vault key ("Only in SSHelter") that its first matching `IdentityFile` names
//! (the SP3 slot rules), a password is the keychain's `host:<alias>`, and pins live in `host-pins.json` (`pins.rs`). A host id is its
//! alias here. Never written: `~/.ssh` (spec §1). Never read: `~/.ssh/known_hosts`.
//!
//! What it cannot give the broker, and says so: a `ProxyCommand`, a key in a file instead of the vault (SSHelter's own client signs with
//! vault keys only), and a `ProxyJump` that is anything but a chain of saved hosts, each one as it is saved:
//!
//! - a jump host that is not a saved host;
//! - a jump with a port or user of its own, as in `ProxyJump admin@bastion:2200` for a `bastion` saved with port 22. OpenSSH lets such an
//!   entry override the jump host's port and user, but a host id stands for one server (`HostDirectory`), and its pin, saved password and
//!   typed answers belong to the id: the entry would be a second endpoint under the same id. An entry that only repeats the saved port
//!   and user is the saved host and is fine.

use std::path::Path;

use super::directory::{DirectoryError, HostDirectory, PinnedKey};
use super::pins::PinStore;
use super::protocol::HostQuery;
use crate::config::model::SshConfigDoc;
use crate::ssh::{AuthMethod, Hop, HostId, HostKey, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY};
use crate::sync::slot_rules::{resolve_identity_value, IdentityTarget};
use crate::sync::state_v2::{SlotSource, SyncStateV2};

/// How many jump hosts deep a chain may go (as `config::intel::jump_chain` shows chains).
const MAX_JUMPS: usize = 5;

/// The `IdentityFile` values `ssh -G` lists when a host names none (OpenSSH 10.3p1): no key was chosen for the host.
const DEFAULT_IDENTITY_FILES: &[&str] = &["~/.ssh/id_rsa", "~/.ssh/id_ecdsa", "~/.ssh/id_ecdsa_sk", "~/.ssh/id_ed25519", "~/.ssh/id_ed25519_sk", "~/.ssh/id_xmss", "~/.ssh/id_dsa"];

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
            if let Some(file) = identity_files.iter().find(|file| !DEFAULT_IDENTITY_FILES.contains(file)) {
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
/// `agent::oneshot`, which goes away with the one-shot channel.
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
    /// `ssh -G <alias>`: the effective settings of a host, keywords in lower case.
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

    /// The hops of `alias` and of its jump hosts, jump hosts first. `path` holds the hosts being expanded, to find a loop.
    fn hops(&self, doc: &SshConfigDoc, alias: &str, path: &mut Vec<String>) -> Result<Vec<Hop>, DirectoryError> {
        if path.iter().any(|seen| seen == alias) {
            path.push(alias.to_string());
            return Err(DirectoryError::Unsupported(format!("The jump hosts go round in a circle: {}.", path.join(" → "))));
        }
        if path.len() > MAX_JUMPS {
            return Err(DirectoryError::Unsupported(format!("{} needs more than {MAX_JUMPS} jump hosts.", path[0])));
        }
        path.push(alias.to_string());
        let pairs = (self.sources.effective)(alias).map_err(|error| DirectoryError::Failed(format!("SSHelter cannot read the settings of {alias}: {error}")))?;
        if value(&pairs, "proxycommand").is_some_and(|command| !command.trim().is_empty() && !command.trim().eq_ignore_ascii_case("none")) {
            return Err(DirectoryError::Unsupported(format!("{alias} uses ProxyCommand, which SSHelter's own SSH client does not support.")));
        }
        let jumps = parse_proxy_jump(value(&pairs, "proxyjump").unwrap_or_default()).map_err(|error| DirectoryError::Unsupported(format!("{alias}: {error}.")))?;
        let mut hops = Vec::new();
        for jump in jumps {
            if self.check_saved(doc, &jump.host).is_err() {
                return Err(DirectoryError::Unsupported(format!("{alias} jumps through {}, which is not a saved host.", jump.host)));
            }
            let jump_hops = self.hops(doc, &jump.host, path)?;
            // The last of them is the jump host itself; the ones before it are its own jump hosts.
            if let Some(saved) = jump_hops.last() {
                check_jump_is_the_saved_host(alias, &jump, saved)?;
            }
            hops.extend(jump_hops);
        }
        let identity_files: Vec<String> = pairs.iter().filter(|(key, _)| key == "identityfile").map(|(_, value)| value.clone()).collect();
        let key_id = (self.sources.vault_key)(&identity_files);
        let id = HostId::from(alias);
        let mut hop = hop_from_effective(alias, &pairs, key_id, (self.sources.password_saved)(&id))?;
        hop.pinned = self.pinned(&hop.id)?.map(|pin| pin.key);
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
    use crate::session::testing::check_the_pin_contract;
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
            ("web", "hostname web.example.com\nport 22\nuser deploy\nidentityfile ~/.ssh/id_rsa\n"),
            ("bastion", "hostname gate.example.com\nport 2200\nuser admin\nidentityfile ~/.ssh/sshelter/keys/id_mac-aaaaaaaa\n"),
            ("db", "hostname db\nport 22\nuser deploy\nproxyjump admin@bastion:2200\nidentityfile ~/.ssh/id_rsa\n"),
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
            effective: Box::new(move |alias| crate::config::intel::effective_config(alias, Some(&ssh_g_path)).map_err(|error| error.to_string())),
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

    /// `ssh -G` names the local user for a host that has no `User` (the adapter does not look the name up itself), so a jump entry that
    /// names the local user repeats the saved value, and one that names another user does not.
    #[test]
    fn a_jump_that_names_the_local_user_is_the_saved_host_when_the_host_has_no_user_of_its_own() {
        let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(&config, "Host plain\n  HostName plain.example.com\n").unwrap();
        let answer = crate::config::intel::effective_config("plain", Some(&config)).unwrap();
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

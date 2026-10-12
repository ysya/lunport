//! The pinned host keys of the temporary ssh_config directory (plan 1b): a small JSON file in the app's data directory,
//! `host-pins.json`, keyed by host id. A host id stands for exactly one server, one hostname and one port (see `HostDirectory`): the pin
//! of an id is the one key that server may present. The store cannot tell two endpoints under one id apart, so the directory that owns
//! it must never hand out one id for two. Plan 1c moves the pins into the host records (`host_key`, spec §5.1) and deletes this file's
//! code. SSHelter's own client never reads or writes `~/.ssh/known_hosts` (spec §1, non-goals).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::directory::{decide_pin, decide_replace, PinDecision, PinnedKey};
use crate::ssh::{HostId, HostKey};

/// The version of the file's format; a file with another one is not read (and never overwritten).
const FILE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct PinFile {
    version: u32,
    pins: BTreeMap<String, StoredPin>,
}

/// A pin as the file stores it (spec §5.1's `host_key`, without the device that pinned it).
#[derive(Serialize, Deserialize)]
struct StoredPin {
    algorithm: String,
    /// The public key in SSH wire format, base64.
    public_key: String,
    fingerprint: String,
    pinned_at_ms: u64,
}

impl StoredPin {
    fn of(key: &HostKey, pinned_at_ms: u64) -> StoredPin {
        StoredPin {
            algorithm: key.algorithm.clone(),
            public_key: base64::engine::general_purpose::STANDARD.encode(&key.public_key),
            fingerprint: key.fingerprint.clone(),
            pinned_at_ms,
        }
    }

    fn pinned_key(&self) -> Option<PinnedKey> {
        let public_key = base64::engine::general_purpose::STANDARD.decode(&self.public_key).ok()?;
        Some(PinnedKey { key: HostKey { algorithm: self.algorithm.clone(), public_key, fingerprint: self.fingerprint.clone() }, pinned_at_ms: self.pinned_at_ms })
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0)
}

/// The pin file. Every change is a read, a check and an atomic write under one lock, so two connections that pin at once cannot lose a pin.
///
/// There must be exactly one `PinStore` per file, shared by everything that pins. The lock belongs to the instance: two stores on one file
/// do not exclude each other, so both can read the old file and the second write drops the pin the first one made.
pub struct PinStore {
    path: PathBuf,
    lock: Mutex<()>,
    clock: fn() -> u64,
}

impl PinStore {
    /// The store at `path` (`<app data>/host-pins.json` in the app). Nothing is read or created until it is used. Make one per file.
    pub fn new(path: PathBuf) -> PinStore {
        PinStore::with_clock(path, now_ms)
    }

    /// The same, with the clock that dates the pins.
    pub fn with_clock(path: PathBuf, clock: fn() -> u64) -> PinStore {
        PinStore { path, lock: Mutex::new(()), clock }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn unreadable(&self, why: impl std::fmt::Display) -> String {
        format!("SSHelter cannot read its pinned host keys in {} ({why}).", self.path.display())
    }

    /// The whole file; a missing file is an empty one. The format version is read before anything else: a newer SSHelter may have changed
    /// the structure, and its file is then in another format, not damaged.
    fn read(&self) -> Result<PinFile, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(PinFile { version: FILE_VERSION, pins: BTreeMap::new() }),
            Err(error) => return Err(self.unreadable(error)),
        };
        let damaged = || self.unreadable("the file is damaged");
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| damaged())?;
        match value.get("version").and_then(serde_json::Value::as_u64) {
            Some(version) if version == u64::from(FILE_VERSION) => {}
            Some(version) => return Err(self.unreadable(format!("it is in format {version}, which this version of SSHelter does not know"))),
            None => return Err(damaged()),
        }
        serde_json::from_value(value).map_err(|_| damaged())
    }

    fn write(&self, file: &PinFile) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(file).map_err(|error| format!("SSHelter cannot save the pinned host key: {error}"))?;
        crate::fsutil::atomic_write(&self.path, &bytes, 0o600).map_err(|error| format!("SSHelter cannot save the pinned host key in {}: {error}", self.path.display()))
    }

    /// The key pinned for `host`. An unreadable file is an error, never "nothing pinned".
    pub fn get(&self, host: &HostId) -> Result<Option<PinnedKey>, String> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let file = self.read()?;
        match file.pins.get(host.as_str()) {
            None => Ok(None),
            Some(stored) => stored.pinned_key().map(Some).ok_or_else(|| self.unreadable(format!("the pin of {host} is damaged"))),
        }
    }

    /// Pins `key` for `host`, unless another key is pinned for it (then nothing is written). Pinning the pinned key again changes nothing.
    pub fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = self.read()?;
        match decide_pin(host, file.pins.get(host.as_str()).map(|stored| stored.fingerprint.as_str()), key) {
            PinDecision::AlreadyPinned => Ok(()),
            PinDecision::Refuse(sentence) => Err(sentence),
            PinDecision::Write => {
                file.pins.insert(host.as_str().to_string(), StoredPin::of(key, (self.clock)()));
                self.write(&file)
            }
        }
    }

    /// Replaces the pin of `host` with `key`, only while `previous` is the pinned key (or `key` already is).
    pub fn replace(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut file = self.read()?;
        match decide_replace(host, file.pins.get(host.as_str()).map(|stored| stored.fingerprint.as_str()), previous, key) {
            PinDecision::AlreadyPinned => Ok(()),
            PinDecision::Refuse(sentence) => Err(sentence),
            PinDecision::Write => {
                file.pins.insert(host.as_str().to_string(), StoredPin::of(key, (self.clock)()));
                self.write(&file)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    fn key(line: &str) -> HostKey {
        HostKey::from_openssh_line(line).expect("a test key")
    }

    fn store(dir: &tempfile::TempDir) -> PinStore {
        PinStore::with_clock(dir.path().join("app-data").join("host-pins.json"), || 1_700_000_000_000)
    }

    #[test]
    fn a_pin_is_written_to_the_file_and_read_back_with_the_time_it_was_made() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        assert_eq!(pins.get(&web), Ok(None), "no file yet: nothing is pinned");
        pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).unwrap();
        assert_eq!(pins.get(&web), Ok(Some(PinnedKey { key: key(test_keys::PLAIN_PUBLIC), pinned_at_ms: 1_700_000_000_000 })));

        let path = dir.path().join("app-data").join("host-pins.json");
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved["version"], 1);
        assert_eq!(saved["pins"]["web"]["algorithm"], "ssh-ed25519");
        assert_eq!(saved["pins"]["web"]["fingerprint"], test_keys::PLAIN_FINGERPRINT);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let reopened = store(&dir);
        assert_eq!(reopened.get(&web).unwrap().map(|pin| pin.key), Some(key(test_keys::PLAIN_PUBLIC)), "a new store reads the same file");
    }

    #[test]
    fn pinning_the_pinned_key_again_is_fine_and_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).unwrap();
        pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).unwrap();
        let error = pins.pin(&web, &key(test_keys::ECDSA_PUBLIC)).unwrap_err();
        assert!(error.contains("another key"), "{error}");
        assert_eq!(pins.get(&web).unwrap().map(|pin| pin.key), Some(key(test_keys::PLAIN_PUBLIC)), "the first pin stays");
    }

    #[test]
    fn a_changed_key_replaces_the_pin_only_while_the_old_one_is_still_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        let (old, new, other) = (key(test_keys::PLAIN_PUBLIC), key(test_keys::ECDSA_PUBLIC), key(test_keys::RSA_PUBLIC));
        pins.pin(&web, &old).unwrap();
        assert!(pins.replace(&web, &other, &new).is_err(), "the pin is not the key the person was shown as the old one");
        assert_eq!(pins.get(&web).unwrap().map(|pin| pin.key), Some(old.clone()), "a refused replace writes nothing: the old key stays");
        pins.replace(&web, &old, &new).unwrap();
        assert_eq!(pins.get(&web).unwrap().map(|pin| pin.key), Some(new.clone()));
        pins.replace(&web, &old, &new).unwrap();
        assert!(pins.replace(&HostId::from("db"), &old, &new).is_err(), "nothing pinned: there is nothing to replace");
        assert_eq!(pins.get(&HostId::from("db")), Ok(None), "a refused replace pins nothing");
    }

    #[test]
    fn pins_belong_to_one_host_id_each() {
        let dir = tempfile::tempdir().unwrap();
        let pins = store(&dir);
        pins.pin(&HostId::from("web"), &key(test_keys::PLAIN_PUBLIC)).unwrap();
        pins.pin(&HostId::from("db"), &key(test_keys::ECDSA_PUBLIC)).unwrap();
        assert_eq!(pins.get(&HostId::from("web")).unwrap().map(|pin| pin.key.algorithm), Some("ssh-ed25519".to_string()));
        assert_eq!(pins.get(&HostId::from("db")).unwrap().map(|pin| pin.key.algorithm), Some("ecdsa-sha2-nistp256".to_string()));
        assert_eq!(pins.get(&HostId::from("mail")), Ok(None));
    }

    /// A file that cannot be read is an error, not "nothing pinned": a pinned host must not look new (the person would be asked to trust
    /// whatever key is presented), and a pin written now must not wipe the others. A file of another format version says so, also when the
    /// newer format changed the structure, and one that is not in any format says that it is damaged.
    #[test]
    fn an_unreadable_or_newer_file_is_an_error_and_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-data").join("host-pins.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let pins = store(&dir);
        for (contents, says) in [
            (&b"{ not json"[..], "damaged"),
            (br#"{"pins":{}}"#, "damaged"),
            (br#"{"version":"one","pins":{}}"#, "damaged"),
            (br#"{"version":1,"pins":["web"]}"#, "damaged"),
            (br#"{"version":2,"pins":{}}"#, "format 2"),
            (br#"{"version":2,"hosts":[{"id":"web"}]}"#, "format 2"),
            (br#"{"version":3,"pins":["web"]}"#, "format 3"),
        ] {
            std::fs::write(&path, contents).unwrap();
            let error = pins.get(&HostId::from("web")).unwrap_err();
            assert!(error.contains("host-pins.json"), "{error}");
            assert!(error.contains(says), "{error}");
            assert_eq!(error.contains("damaged"), says == "damaged", "{error}");
            assert!(pins.pin(&HostId::from("web"), &key(test_keys::PLAIN_PUBLIC)).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), contents, "the file is left as it was");
        }
    }

    /// Only a missing file means "nothing pinned"; a file that cannot be read for any other reason is an error as well. Here the path is a
    /// directory: reading it fails with an error that is not "not found" (which one differs by platform, so only that is relied on).
    #[test]
    fn a_pin_file_that_cannot_be_read_for_a_reason_other_than_being_missing_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-data").join("host-pins.json");
        std::fs::create_dir_all(&path).unwrap();
        let pins = store(&dir);
        let web = HostId::from("web");
        let error = pins.get(&web).unwrap_err();
        assert!(error.contains("host-pins.json"), "{error}");
        assert!(pins.pin(&web, &key(test_keys::PLAIN_PUBLIC)).is_err(), "nothing is pinned over what cannot be read");
        assert!(pins.replace(&web, &key(test_keys::PLAIN_PUBLIC), &key(test_keys::ECDSA_PUBLIC)).is_err());
        assert!(path.is_dir(), "what was at the path is left as it was");
    }
}

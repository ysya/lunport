//! Stable observed vault decryptors for the local encrypted source package. Never a frontend DTO.
use super::{
    crypto,
    wire::{hex, invalid},
};
use crate::{error::AppError, sync::env::Keychain, vault::store};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use zeroize::Zeroizing;
const MAX_ROLES: usize = 8192;
const MAX_BYTES: usize = 2 * 1024 * 1024;
fn allowed(role: &str) -> bool {
    if store::is_vault_key_account(role) {
        return true;
    }
    role.strip_prefix("migration:")
        .and_then(|v| v.split_once(':'))
        .is_some_and(|(operation, account)| {
            hex(operation, 32) && store::is_vault_key_account(account)
        })
}
fn check(role: &str, value: &str) -> Result<(), AppError> {
    if !allowed(role) || value.len() > 128 {
        return Err(invalid());
    }
    let _key = Zeroizing::new(crypto::decode(value, 32, 32)?);
    Ok(())
}
/// A short-lived read observer, not a runtime owner or a writable credential store.
pub(super) struct Capture<'a> {
    inner: &'a dyn Keychain,
    seen: Mutex<BTreeMap<String, Option<Zeroizing<String>>>>,
    failed: AtomicBool,
}
impl<'a> Capture<'a> {
    pub fn new(inner: &'a dyn Keychain) -> Self {
        Self {
            inner,
            seen: Mutex::new(BTreeMap::new()),
            failed: AtomicBool::new(false),
        }
    }
    fn read(&self, role: &str) -> Result<Option<String>, AppError> {
        if !allowed(role) || self.failed.load(Ordering::SeqCst) {
            return Err(invalid());
        }
        {
            let seen = self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !seen.contains_key(role) && seen.len() >= MAX_ROLES {
                return Err(invalid());
            }
        }
        let mut value = self
            .inner
            .get(role)
            .map_err(|_| {
                AppError::Other(
                    "Protected vault material could not be read for the source backup.".into(),
                )
            })?
            .map(Zeroizing::new);
        if let Some(value) = &value {
            check(role, value)?;
        }
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if seen.get(role).is_some_and(|before| before != &value)
            || !seen.contains_key(role) && seen.len() >= MAX_ROLES
        {
            return Err(invalid());
        }
        seen.insert(role.into(), value.clone());
        Ok(value.as_mut().map(|v| std::mem::take(&mut **v)))
    }
    pub fn finish(self) -> Result<Snapshot, AppError> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(invalid());
        }
        let roles: Vec<_> = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        for role in roles {
            drop(self.read(&role)?.map(Zeroizing::new));
        }
        Ok(Snapshot {
            keys: self
                .seen
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .into_iter()
                .filter_map(|(role, value)| value.map(|v| (role, v)))
                .collect(),
        })
    }
}
impl Keychain for Capture<'_> {
    fn get(&self, role: &str) -> Result<Option<String>, AppError> {
        let result = self.read(role);
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        self.failed.store(true, Ordering::SeqCst);
        Err(invalid())
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        self.failed.store(true, Ordering::SeqCst);
        Err(invalid())
    }
}
/// Only explicit native encode/decode; no Debug/Serialize/OS fallback.
pub(super) struct Snapshot {
    keys: BTreeMap<String, Zeroizing<String>>,
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
impl Snapshot {
    pub fn encode_local(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        #[derive(Serialize)]
        struct Key<'a> {
            role: &'a str,
            value: &'a str,
        }
        #[derive(Serialize)]
        struct Body<'a> {
            version: u32,
            keys: Vec<Key<'a>>,
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Body {
                version: 1,
                keys: self
                    .keys
                    .iter()
                    .map(|(role, value)| Key { role, value })
                    .collect(),
            })
            .map_err(|_| invalid())?,
        );
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub fn decode_local(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Key {
            role: String,
            #[serde(deserialize_with = "secret")]
            value: Zeroizing<String>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Body {
            version: u32,
            keys: Vec<Key>,
        }
        let body: Body = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if body.version != 1 || body.keys.len() > MAX_ROLES {
            return Err(invalid());
        }
        let mut keys = BTreeMap::new();
        for key in body.keys {
            check(&key.role, &key.value)?;
            if keys.insert(key.role, key.value).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self { keys })
    }
}
impl Keychain for Snapshot {
    fn get(&self, role: &str) -> Result<Option<String>, AppError> {
        if !allowed(role) {
            return Err(invalid());
        }
        Ok(self.keys.get(role).map(|value| value.to_string()))
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        Err(invalid())
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync::{
            central::{migration_files::Files, migration_materials::Materials},
            fake_relay::FakeRelay,
            testkit::{MemKeychain, TestClock, TestDevice},
        },
        vault::{material, store::Vault},
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::json;
    use std::{fs, path::Path};
    fn entry(raw: &str) -> store::VaultEntry {
        let key = material::parse(raw).unwrap();
        store::VaultEntry {
            private_key: raw.into(),
            public_key: key.public_key().to_openssh().unwrap(),
            fingerprint: key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            origin: store::EntryOrigin::Imported,
            added_at_ms: 1,
        }
    }
    #[test]
    fn captured_decryptors_restore_exact_vault_images_without_the_original_os_items() {
        let device = TestDevice::new("vault-decryptors", &FakeRelay::new(), &TestClock::new());
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        fs::create_dir_all(root).unwrap();
        let raw = crate::sync::slot_rules::test_keys::encrypted();
        let path = root.join("vault.json");
        let mut vault = Vault::open(&path, &device.keychain, 0).unwrap();
        vault.put(&device.keychain, "orphan", &entry(&raw)).unwrap();
        let files = Files::capture(&env, None).unwrap();
        let state:crate::sync::records_v3::SyncStateV3=serde_json::from_value(json!({"version":3,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
        let capture = Capture::new(&device.keychain);
        assert!(Materials::from_files(
            &state,
            &crypto::VaultKeys::generate().unwrap(),
            &files,
            &capture,
            &BTreeMap::new()
        )
        .is_ok());
        let snapshot = capture.finish().unwrap();
        assert_eq!(snapshot.keys.len(), 1);
        let encoded = snapshot.encode_local().unwrap();
        let restored = Snapshot::decode_local(&encoded).unwrap();
        for role in snapshot.keys.keys() {
            device.keychain.delete(role).unwrap();
        }
        assert!(store::read_vault_image(
            &files.bytes[Path::new("data/vault.json")],
            &device.keychain
        )
        .is_err());
        let independent =
            store::read_vault_image(&files.bytes[Path::new("data/vault.json")], &restored).unwrap();
        assert!(
            independent
                .get_inventory("orphan")
                .unwrap()
                .unwrap()
                .private_key
                == raw
        );
        assert!(restored.set("vault:key", &B64.encode([9u8; 32])).is_err());
        assert!(restored.delete("vault:key").is_err());
        files.require_unchanged(&env, None).unwrap();
    }
    struct Forbidden;
    impl Keychain for Forbidden {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("forbidden role must not reach the OS keychain")
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("read observer cannot mutate")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("read observer cannot mutate")
        }
    }
    #[test]
    fn passwords_tokens_identities_source_archive_keys_and_untrusted_role_names_never_reach_live_storage(
    ) {
        for role in [
            "host:password",
            "ssh:passphrase",
            "central:v2:device:abc",
            "central:v2:source-archive-op:abc",
            "vault:key:../escape",
            "migration:not-an-operation:vault:key",
        ] {
            let capture = Capture::new(&Forbidden);
            assert!(capture.get(role).is_err());
            assert!(capture.finish().is_err());
        }
        let capture = Capture::new(&Forbidden);
        assert!(capture.set("vault:key", "synthetic").is_err());
        assert!(capture.finish().is_err());
        let capture = Capture::new(&Forbidden);
        assert!(capture.delete("vault:key").is_err());
        assert!(capture.finish().is_err());
    }
    #[test]
    fn any_observed_role_drift_or_invalid_master_taints_the_snapshot_instead_of_returning_a_partial_book(
    ) {
        let memory = MemKeychain::default();
        let role = "vault:key:0123456789abcdef";
        for missing in [false, true] {
            memory.set(role, &B64.encode([1u8; 32])).unwrap();
            let capture = Capture::new(&memory);
            assert!(capture.get(role).unwrap().is_some());
            if missing {
                memory.delete(role).unwrap();
            } else {
                memory.set(role, &B64.encode([2u8; 32])).unwrap();
            }
            assert!(capture.get(role).is_err());
            assert!(capture.finish().is_err());
        }
        memory.delete(role).unwrap();
        let capture = Capture::new(&memory);
        assert!(capture.get(role).unwrap().is_none());
        memory.set(role, &B64.encode([1u8; 32])).unwrap();
        assert!(capture.get(role).is_err());
        assert!(capture.finish().is_err());
        memory.set(role, "PRIVATE_SENTINEL").unwrap();
        let capture = Capture::new(&memory);
        let error = capture.get(role).unwrap_err().to_string();
        assert!(!error.contains("PRIVATE_SENTINEL"));
        assert!(capture.finish().is_err());
    }
    #[test]
    fn finish_rechecks_all_observed_presence_and_values_including_an_absent_scoped_import_role() {
        for before in [None, Some(B64.encode([1u8; 32]))] {
            let memory = MemKeychain::default();
            let role = format!("migration:{}:vault:key", "a".repeat(32));
            if let Some(value) = &before {
                memory.set(&role, value).unwrap();
            }
            let observer = Capture::new(&memory);
            assert_eq!(observer.get(&role).unwrap(), before);
            memory.set(&role, &B64.encode([2u8; 32])).unwrap();
            assert!(observer.finish().is_err());
        }
    }
    #[test]
    fn strict_local_codec_preserves_valid_import_roles_and_rejects_duplicates_unknowns_schema_and_size_errors(
    ) {
        let memory = MemKeychain::default();
        let role = format!("migration:{}:vault:key:0123456789abcdef", "a".repeat(32));
        memory.set(&role, &B64.encode([1u8; 32])).unwrap();
        let capture = Capture::new(&memory);
        capture.get(&role).unwrap();
        let snapshot = capture.finish().unwrap();
        let bytes = snapshot.encode_local().unwrap();
        let restored = Snapshot::decode_local(&bytes).unwrap();
        assert_eq!(restored.get(&role).unwrap(), memory.get(&role).unwrap());
        let key = json!({"role":role,"value":B64.encode([1u8;32])});
        for value in [
            json!({"version":1,"keys":[key.clone(),key.clone()]}),
            json!({"version":2,"keys":[key.clone()]}),
            json!({"version":1,"keys":[key],"extra":"PRIVATE_SENTINEL"}),
            json!({"version":1,"keys":[{"role":"host:password","value":B64.encode([1u8;32])}]}),
            json!({"version":1,"keys":[{"role":"vault:key","value":"PRIVATE_SENTINEL"}]}),
        ] {
            assert!(Snapshot::decode_local(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(Snapshot::decode_local(&vec![b' '; MAX_BYTES + 1]).is_err());
        assert!(restored.get("host:password").is_err());
        assert!(restored
            .get("vault:key:ffffffffffffffff")
            .unwrap()
            .is_none());
    }
}

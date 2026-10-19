//! Join only descriptor-captured images. Extra source copies cannot become active material.
use super::*;
use crate::{
    sync::{central::migration_files::Files, env::Keychain},
    vault::store::{self, EntryOrigin},
};
use std::path::Path;

/// Read-only access to a known vault role. This adapter cannot create, promote or erase a master.
struct SourceMaster<'a> {
    inner: &'a dyn Keychain,
    import: Option<&'a str>,
}
impl Keychain for SourceMaster<'_> {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        if !store::is_vault_key_account(account) {
            return Err(invalid());
        }
        if let Some(import) = self.import {
            if !hex(import, 32) {
                return Err(invalid());
            }
            if let Some(value) = self
                .inner
                .get(&format!("migration:{import}:{account}"))
                .map_err(|_| invalid())?
            {
                return Ok(Some(value));
            }
        }
        self.inner.get(account).map_err(|_| invalid())
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        Err(invalid())
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(invalid())
    }
}
fn image<'a>(
    path: &'a Path,
    bytes: &[u8],
    inner: &'a dyn Keychain,
) -> Result<ReadOnlyVault, AppError> {
    let parts: Vec<_> = path
        .iter()
        .map(|v| v.to_str().ok_or_else(invalid))
        .collect::<Result<_, _>>()?;
    if parts.first() != Some(&"data") {
        return Err(invalid());
    }
    let import = if parts.get(1) == Some(&"imports") {
        if parts.len() != 4 || !hex(parts[2], 32) {
            return Err(invalid());
        }
        (parts[3] == "vault.json").then_some(parts[2])
    } else {
        None
    };
    store::read_vault_image(bytes, &SourceMaster { inner, import }).map_err(|_| invalid())
}
pub(super) fn raw_index(materials: &Materials) -> BTreeMap<String, usize> {
    materials
        .history
        .iter()
        .enumerate()
        .filter_map(|(index, (_, data))| match data {
            Data::Key(private) => Some((private.digest(), index)),
            _ => None,
        })
        .collect()
}
pub(super) fn same_private(
    materials: &Materials,
    index: &BTreeMap<String, usize>,
    entry: &VaultEntry,
) -> Result<bool, AppError> {
    let private = original(entry)?;
    let Some(index) = index.get(&private.digest()) else {
        return Ok(false);
    };
    match &materials.history[*index].1 {
        Data::Key(known) if known.private() == private.private() => Ok(true),
        _ => Err(invalid()),
    }
}
impl Materials {
    /// Preserve old local-only metadata/pointers without allowing them into current activation.
    pub(in crate::sync::central) fn with_retained_states(
        mut self,
        states: &[SyncStateV3],
        files: &Files,
        keychain: &dyn Keychain,
    ) -> Result<Self, AppError> {
        if states.iter().all(|state| state.local.keys.is_empty()) {
            return Ok(self);
        }
        let mut views = vec![];
        for (path, bytes) in &files.bytes {
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?;
            if path.starts_with("data")
                && (name.starts_with("vault") || name == "original-vault.json")
            {
                views.push(image(path, bytes, keychain)?);
            }
        }
        let mut seen = BTreeSet::new();
        for (identity, data) in &self.history {
            seen.insert((
                identity.kind.clone(),
                identity.id.clone(),
                super::super::crypto::hash(&payload::encode(identity, data)?),
            ));
        }
        for state in states {
            records_v3::validate_state(state).map_err(|_| invalid())?;
            for (id, local) in &state.local.keys {
                let mut matched = false;
                for view in &views {
                    let Some(entry) = view.get_inventory(&local.vault_id).map_err(|_| invalid())?
                    else {
                        continue;
                    };
                    let private = original(&entry)?;
                    let slot = SharedKeyslot {
                        public: local.public.clone(),
                        storage: KeyStorage::Managed {
                            sha256: private.digest(),
                        },
                    };
                    if private.validate_against(id, &slot).is_err() {
                        continue;
                    }
                    matched = true;
                    for (identity, data) in [
                        (identity("keyslot", id), Data::Keyslot(slot)),
                        (identity("key", id), Data::Key(private)),
                    ] {
                        let hash = super::super::crypto::hash(&payload::encode(&identity, &data)?);
                        if seen.insert((identity.kind.clone(), identity.id.clone(), hash)) {
                            if matches!(data, Data::Key(_)) {
                                self.retained = self.retained.checked_add(1).ok_or_else(invalid)?;
                            }
                            self.append(identity, data)?;
                        }
                    }
                }
                if !matched {
                    return Err(invalid());
                }
            }
        }
        Ok(self)
    }
    pub fn from_files(
        state: &SyncStateV3,
        keys: &VaultKeys,
        files: &Files,
        keychain: &dyn Keychain,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<Self, AppError> {
        Self::from_files_with_key_inputs(state, keys, files, keychain, references, vec![])
    }
    pub(in crate::sync::central) fn from_files_with_key_inputs(
        state: &SyncStateV3,
        keys: &VaultKeys,
        files: &Files,
        keychain: &dyn Keychain,
        references: &BTreeMap<String, KeyStorage>,
        inputs: Vec<crate::sync::central::migration_sources::KeyInput>,
    ) -> Result<Self, AppError> {
        let active_path = Path::new("data/vault.json");
        let empty = br#"{"version":1,"entries":{}}"#;
        let active = image(
            active_path,
            files
                .bytes
                .get(active_path)
                .map_or(empty.as_slice(), |v| v.as_slice()),
            keychain,
        )?;
        let mut result = Self::from_vault_inputs(state, keys, &active, references, &inputs)?;
        let mut index = raw_index(&result);
        let mut occupied: BTreeSet<_> = result
            .history
            .iter()
            .filter(|(identity, _)| identity.kind == "keyslot")
            .map(|(identity, _)| identity.id.clone())
            .collect();
        // Strictly admit every entry before duplicate-copy elimination. The captured original image
        // remains in Files for the independent encrypted archive, even when no duplicate wire row is needed.
        for (path, bytes) in &files.bytes {
            if path == active_path || !path.starts_with("data") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(invalid)?;
            if !name.starts_with("vault") && name != "original-vault.json" {
                continue;
            }
            let view = image(path, bytes, keychain)?;
            for id in view.ids() {
                let entry = view
                    .get_inventory(&id)
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                if same_private(&result, &index, &entry)? {
                    continue;
                }
                let private_index =
                    result.keep_retained(state, keys, &id, &entry, &mut occupied)?;
                index.insert(
                    super::super::crypto::hash(entry.private_key.as_bytes()),
                    private_index,
                );
            }
        }
        let mut public_claims = vec![];
        for (path, bytes) in files
            .bytes
            .iter()
            .filter(|(path, _)| path.starts_with("keys"))
        {
            if bytes.len() > crate::sync::record_import::MAX_PRIVATE_SOURCE_BYTES as usize {
                return Err(invalid());
            }
            let raw = std::str::from_utf8(bytes).map_err(|_| invalid())?;
            if let Ok(public) = ssh_key::PublicKey::from_openssh(raw.trim()) {
                public_claims.push(public.to_bytes().map_err(|_| invalid())?);
                continue;
            }
            // Hardware stubs or unsupported/encrypted formats cannot be reclassified as exportable
            // material or an external reference merely because a private source is unavailable.
            let private = PrivateMaterial::new(Zeroizing::new(raw.to_owned()))?;
            let parsed = material::parse(private.private()).ok_or_else(invalid)?;
            let entry = VaultEntry {
                private_key: private.private().into(),
                public_key: parsed.public_key().to_openssh().map_err(|_| invalid())?,
                fingerprint: private.fingerprint.clone(),
                origin: EntryOrigin::Imported,
                added_at_ms: 0,
            };
            if same_private(&result, &index, &entry)? {
                continue;
            }
            let source = format!("file:{}", path.to_str().ok_or_else(invalid)?);
            let private_index =
                result.keep_retained(state, keys, &source, &entry, &mut occupied)?;
            index.insert(private.digest(), private_index);
        }
        let known_public: BTreeSet<_> = result
            .history
            .iter()
            .filter_map(|(_, data)| match data {
                Data::Keyslot(slot) => Some(
                    ssh_key::PublicKey::from_openssh(slot.public.public_key.trim())
                        .map_err(|_| invalid())
                        .and_then(|v| v.to_bytes().map_err(|_| invalid())),
                ),
                _ => None,
            })
            .collect::<Result<_, _>>()?;
        if public_claims
            .iter()
            .any(|claim| !known_public.contains(claim))
        {
            return Err(invalid());
        }
        result.with_key_inputs(state, keys, inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{entry, metadata, state};
    use super::*;
    use crate::{
        sync::{
            fake_relay::FakeRelay,
            records_v3::LocalKeyMetadata,
            testkit::{MemKeychain, TestClock, TestDevice},
        },
        vault::store::Vault,
    };
    use std::{fs, sync::Mutex};
    fn device() -> TestDevice {
        TestDevice::new("captured-materials", &FakeRelay::new(), &TestClock::new())
    }
    fn put(path: &Path, memory: &dyn Keychain, id: &str, raw: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        Vault::open(path, memory, 0)
            .unwrap()
            .put(memory, id, &entry(raw))
            .unwrap();
    }
    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    struct Spy<'a> {
        inner: &'a MemKeychain,
        reads: Mutex<Vec<String>>,
    }
    impl Keychain for Spy<'_> {
        fn get(&self, account: &str) -> Result<Option<String>, AppError> {
            self.reads.lock().unwrap().push(account.into());
            self.inner.get(account)
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("inventory must not write a credential")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("inventory must not erase a credential")
        }
    }
    struct Staged<'a> {
        inner: &'a MemKeychain,
        id: &'a str,
    }
    impl Keychain for Staged<'_> {
        fn get(&self, account: &str) -> Result<Option<String>, AppError> {
            self.inner.get(&format!("migration:{}:{account}", self.id))
        }
        fn set(&self, account: &str, value: &str) -> Result<(), AppError> {
            self.inner
                .set(&format!("migration:{}:{account}", self.id), value)
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("synthetic stage does not delete")
        }
    }
    #[test]
    fn combines_current_backup_scoped_import_and_file_keys_without_activating_extra_sources() {
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        let id = "1".repeat(32);
        let plain = crate::sync::slot_rules::test_keys::plain();
        let encrypted = crate::sync::slot_rules::test_keys::encrypted();
        let rsa = crate::sync::slot_rules::test_keys::rsa();
        let ecdsa = crate::sync::slot_rules::test_keys::ecdsa();
        put(&root.join("vault.json"), &device.keychain, &id, &plain);
        fs::copy(root.join("vault.json"), root.join("vault.original.json")).unwrap();
        put(
            &root.join("vault.retained.json"),
            &device.keychain,
            "orphan",
            &encrypted,
        );
        fs::copy(
            root.join("vault.retained.json"),
            root.join("vault.duplicate.json"),
        )
        .unwrap();
        let operation = "a".repeat(32);
        put(
            &root.join("imports").join(&operation).join("vault.json"),
            &Staged {
                inner: &device.keychain,
                id: &operation,
            },
            "staged-only",
            &ecdsa,
        );
        let keypath = env.ssh_dir.join("sshelter/keys");
        write(&keypath.join("original-private"), rsa.as_bytes());
        write(
            &keypath.join("original-private.pub"),
            metadata(&rsa).public_key.as_bytes(),
        );
        write(&keypath.join("duplicate-active-private"), plain.as_bytes());
        write(&keypath.join("encrypted-copy"), encrypted.as_bytes());
        let captured = Files::capture(&env, None).unwrap();
        let mut state = state();
        state.local.keys.insert(
            id.clone(),
            LocalKeyMetadata {
                vault_id: id.clone(),
                public: metadata(&plain),
            },
        );
        let spy = Spy {
            inner: &device.keychain,
            reads: Mutex::new(vec![]),
        };
        let inventory = Materials::from_files(
            &state,
            &VaultKeys::generate().unwrap(),
            &captured,
            &spy,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            inventory.active.keys().cloned().collect::<Vec<_>>(),
            vec![id]
        );
        assert_eq!(inventory.retained, 3);
        let mut found = BTreeSet::new();
        for (_, data) in &inventory.history {
            if let Data::Key(private) = data {
                found.insert(private.digest());
                assert!([&plain, &encrypted, &rsa, &ecdsa]
                    .iter()
                    .any(|raw| private.private() == raw.as_str()));
            }
        }
        assert_eq!(found.len(), 4);
        assert_eq!(
            inventory
                .history
                .iter()
                .filter(|(_, data)| matches!(data, Data::Key(_)))
                .count(),
            4
        );
        assert!(spy
            .reads
            .lock()
            .unwrap()
            .iter()
            .all(|role| role.starts_with("vault:key:")
                || role.starts_with(&format!("migration:{operation}:vault:key:"))));
        captured.require_unchanged(&env, None).unwrap();
    }
    #[test]
    fn captured_bytes_win_over_later_disk_edits_but_a_backup_cannot_replace_a_missing_live_binding()
    {
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        let id = "1".repeat(32);
        let plain = crate::sync::slot_rules::test_keys::plain();
        let encrypted = crate::sync::slot_rules::test_keys::encrypted();
        put(&root.join("vault.json"), &device.keychain, &id, &plain);
        fs::copy(root.join("vault.json"), root.join("vault.original.json")).unwrap();
        let captured = Files::capture(&env, None).unwrap();
        let mut state = state();
        state.local.keys.insert(
            id.clone(),
            LocalKeyMetadata {
                vault_id: id.clone(),
                public: metadata(&plain),
            },
        );
        put(&root.join("vault.json"), &device.keychain, &id, &encrypted);
        let inventory = Materials::from_files(
            &state,
            &VaultKeys::generate().unwrap(),
            &captured,
            &device.keychain,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(inventory
            .history
            .iter()
            .any(|(_, data)| matches!(data,Data::Key(private) if private.private()==plain)));
        assert!(captured.require_unchanged(&env, None).is_err());
        fs::remove_file(root.join("vault.json")).unwrap();
        let missing = Files::capture(&env, None).unwrap();
        assert!(Materials::from_files(
            &state,
            &VaultKeys::generate().unwrap(),
            &missing,
            &device.keychain,
            &BTreeMap::new()
        )
        .is_err());
    }
    #[test]
    fn corrupt_or_unrecognized_backup_entries_block_even_when_their_private_copy_is_already_present(
    ) {
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        let raw = crate::sync::slot_rules::test_keys::plain();
        put(
            &root.join("vault.json"),
            &device.keychain,
            "active-copy",
            &raw,
        );
        fs::copy(root.join("vault.json"), root.join("vault.corrupt.json")).unwrap();
        let mut image: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("vault.corrupt.json")).unwrap()).unwrap();
        image["entries"]["active-copy"]["unexpected"] = "not ignorable".into();
        write(
            &root.join("vault.corrupt.json"),
            &serde_json::to_vec(&image).unwrap(),
        );
        let captured = Files::capture(&env, None).unwrap();
        assert!(Materials::from_files(
            &state(),
            &VaultKeys::generate().unwrap(),
            &captured,
            &device.keychain,
            &BTreeMap::new()
        )
        .is_err());
        image["entries"]["active-copy"]
            .as_object_mut()
            .unwrap()
            .remove("unexpected");
        image["entries"]["active-copy"]["ciphertext"] = "AAAA".into();
        write(
            &root.join("vault.corrupt.json"),
            &serde_json::to_vec(&image).unwrap(),
        );
        let captured = Files::capture(&env, None).unwrap();
        assert!(Materials::from_files(
            &state(),
            &VaultKeys::generate().unwrap(),
            &captured,
            &device.keychain,
            &BTreeMap::new()
        )
        .is_err());
    }
    #[test]
    fn a_present_bad_scoped_master_never_falls_back_to_a_working_global_master() {
        use base64::Engine as _;
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        let operation = "a".repeat(32);
        let staged = root.join("imports").join(&operation).join("vault.json");
        let raw = crate::sync::slot_rules::test_keys::plain();
        put(&staged, &device.keychain, "staged", &raw);
        let view = store::read_vault(&staged, &device.keychain).unwrap();
        let account = view.key_account();
        let captured = Files::capture(&env, None).unwrap();
        assert!(Materials::from_files(
            &state(),
            &VaultKeys::generate().unwrap(),
            &captured,
            &device.keychain,
            &BTreeMap::new()
        )
        .is_ok());
        device
            .keychain
            .set(
                &format!("migration:{operation}:{account}"),
                &base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
            )
            .unwrap();
        assert!(Materials::from_files(
            &state(),
            &VaultKeys::generate().unwrap(),
            &captured,
            &device.keychain,
            &BTreeMap::new()
        )
        .is_err());
        captured.require_unchanged(&env, None).unwrap();
    }
    #[test]
    fn malformed_private_files_unsupported_ciphers_and_unmatched_public_claims_cannot_be_omitted_or_reclassified(
    ) {
        let device = device();
        let env = device.env();
        let path = env.ssh_dir.join("sshelter/keys/source");
        for raw in [
            "unreadable private source".to_owned(),
            crate::sync::slot_rules::test_keys::encrypted_with_3des_label(),
            metadata(&crate::sync::slot_rules::test_keys::plain()).public_key,
        ] {
            write(&path, raw.as_bytes());
            let captured = Files::capture(&env, None).unwrap();
            assert!(Materials::from_files(
                &state(),
                &VaultKeys::generate().unwrap(),
                &captured,
                &device.keychain,
                &BTreeMap::new()
            )
            .is_err());
        }
    }
}

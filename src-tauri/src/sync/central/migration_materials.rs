//! Preserve every protected source entry. Pure native history inputs; no consent/publication authority.
use super::{
    crypto::VaultKeys,
    payload::{self, Data, Identity, KeyStorage, PrivateMaterial, SharedKeyslot},
    wire::{canonical, hex, invalid, MAX_SAFE_INTEGER},
};
use crate::{
    error::AppError,
    sync::{
        record::RecordKind,
        records_v3::{self, KeySlotPayload, SyncStateV3},
    },
    vault::{
        material,
        store::{ReadOnlyVault, VaultEntry},
    },
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
mod files;
mod records;

/// No Debug/Serialize: original private bytes are only consumed by explicit native encryption.
pub(super) struct Materials {
    pub storage: BTreeMap<String, KeyStorage>,
    pub active: BTreeMap<String, SharedKeyslot>,
    pub retained: usize,
    history: Vec<(Identity, Data)>,
    history_bytes: usize,
}
fn identity(kind: &str, id: &str) -> Identity {
    Identity {
        kind: kind.into(),
        id: id.into(),
        scope: None,
    }
}
fn original(entry: &VaultEntry) -> Result<PrivateMaterial, AppError> {
    let private = PrivateMaterial::new(Zeroizing::new(entry.private_key.clone()))?;
    let parsed = material::parse(private.private()).ok_or_else(invalid)?;
    if entry.fingerprint != private.fingerprint
        || material::public_key_data(&entry.public_key).as_ref()
            != Some(parsed.public_key().key_data())
        || entry.added_at_ms > MAX_SAFE_INTEGER
    {
        return Err(invalid());
    }
    Ok(private)
}
fn reference(storage: &KeyStorage) -> Result<(), AppError> {
    if matches!(storage, KeyStorage::Hardware | KeyStorage::ExternalAgent) {
        Ok(())
    } else {
        Err(invalid())
    }
}
impl Materials {
    pub fn from_vault(
        state: &SyncStateV3,
        keys: &VaultKeys,
        vault: &ReadOnlyVault,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<Self, AppError> {
        Self::from_vault_inputs(state, keys, vault, references, &[])
    }
    fn from_vault_inputs(
        state: &SyncStateV3,
        keys: &VaultKeys,
        vault: &ReadOnlyVault,
        references: &BTreeMap<String, KeyStorage>,
        inputs: &[super::migration_sources::KeyInput],
    ) -> Result<Self, AppError> {
        records_v3::validate_state(state).map_err(|_| invalid())?;
        if state.local.central_projection.is_some()
            || state
                .local
                .central
                .as_ref()
                .is_some_and(|w| w.control.cutover)
        {
            return Err(invalid());
        }
        // First admit every entry, even when it is unrelated to a live slot. No partial result escapes.
        let mut entries = BTreeMap::new();
        for id in vault.ids() {
            if id.len() > 1024 || entries.len() >= 4096 {
                return Err(invalid());
            }
            let entry = vault
                .get_inventory(&id)
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?;
            original(&entry)?;
            entries.insert(id, entry);
        }
        Self::adopt_current(state, &mut entries, inputs)?;
        Self::from_entries(state, keys, entries, references)
    }
    fn from_entries(
        state: &SyncStateV3,
        keys: &VaultKeys,
        entries: BTreeMap<String, VaultEntry>,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<Self, AppError> {
        let mut public = BTreeMap::new();
        let mut deleted = BTreeSet::new();
        if let Some(account) = &state.account {
            for row in account
                .records
                .values()
                .filter(|row| row.record.kind == RecordKind::KeySlot)
            {
                if row.record.deleted {
                    deleted.insert(row.record.id.clone());
                    continue;
                }
                let records_v3::TypedRecord::Live(slot) =
                    records_v3::decode_keyslot(&row.record).map_err(|_| invalid())?
                else {
                    return Err(invalid());
                };
                public.insert(row.record.id.clone(), slot);
            }
        }
        for (id, local) in &state.local.keys {
            // A public deletion suppresses activation, never retention of the local protected source.
            let entry = entries.get(&local.vault_id).ok_or_else(invalid)?;
            let private = original(entry)?;
            private.validate_against(
                id,
                &SharedKeyslot {
                    public: local.public.clone(),
                    storage: KeyStorage::Managed {
                        sha256: private.digest(),
                    },
                },
            )?;
            if deleted.contains(id) {
                continue;
            }
            if public.get(id).is_some_and(|known| known != &local.public) {
                return Err(invalid());
            }
            public.insert(id.clone(), local.public.clone());
        }
        if references.keys().any(|id| !public.contains_key(id)) {
            return Err(invalid());
        }
        let mut result = Self {
            storage: BTreeMap::new(),
            active: BTreeMap::new(),
            retained: 0,
            history: vec![],
            history_bytes: 0,
        };
        let mut used = BTreeSet::new();
        let mut occupied: BTreeSet<_> = public
            .keys()
            .cloned()
            .chain(deleted.iter().cloned())
            .collect();
        for (id, public) in public {
            let protected_id = state
                .local
                .keys
                .get(&id)
                .map_or(id.as_str(), |local| local.vault_id.as_str());
            let entry = entries.get(protected_id);
            let (slot, private) = if let Some(entry) = entry {
                // A reference classification can never suppress available exportable App material.
                if references.contains_key(&id) {
                    return Err(invalid());
                }
                let private = original(entry)?;
                let slot = SharedKeyslot {
                    public,
                    storage: KeyStorage::Managed {
                        sha256: private.digest(),
                    },
                };
                private.validate_against(&id, &slot)?;
                used.insert(protected_id.to_owned());
                (slot, Some(private))
            } else {
                if state.local.keys.contains_key(&id) {
                    return Err(invalid());
                }
                let storage = references.get(&id).ok_or_else(invalid)?.clone();
                reference(&storage)?;
                let slot = SharedKeyslot { public, storage };
                slot.validate(&id)?;
                (slot, None)
            };
            result.storage.insert(id.clone(), slot.storage.clone());
            result.active.insert(id.clone(), slot.clone());
            result.append(identity("keyslot", &id), Data::Keyslot(slot))?;
            if let Some(private) = private {
                result.append(identity("key", &id), Data::Key(private))?;
            }
        }
        for (source, entry) in entries {
            if used.contains(&source) {
                continue;
            }
            result.keep_retained(state, keys, &source, &entry, &mut occupied)?;
        }
        // Preserve public deletion intent even if its private material has a distinct retained ID.
        for id in deleted {
            result.append(identity("keyslot", &id), Data::Deleted)?;
        }
        Ok(result)
    }
    fn keep_retained(
        &mut self,
        state: &SyncStateV3,
        keys: &VaultKeys,
        source: &str,
        entry: &VaultEntry,
        occupied: &mut BTreeSet<String>,
    ) -> Result<usize, AppError> {
        let private_index = self.history.len() + 1;
        let private = original(entry)?;
        let binding = canonical(&[
            "lunport-retained-vault-material-v1",
            source,
            &private.digest(),
        ])?;
        let id = keys.record_id(
            "keyslot",
            std::str::from_utf8(&binding).map_err(|_| invalid())?,
        )?[..32]
            .to_owned();
        if !hex(&id, 32) || !occupied.insert(id.clone()) {
            return Err(invalid());
        }
        let parsed = material::parse(private.private()).ok_or_else(invalid)?;
        let slot = SharedKeyslot {
            public: KeySlotPayload {
                schema: records_v3::KEYSLOT_SCHEMA,
                name: "Retained key".into(),
                public_key: entry.public_key.clone(),
                fingerprint: entry.fingerprint.clone(),
                key_type: parsed.public_key().algorithm().as_str().into(),
                has_passphrase: parsed.is_encrypted(),
                created_at_ms: entry.added_at_ms,
                origin_device_id: state.device_id.clone(),
            },
            storage: KeyStorage::Managed {
                sha256: private.digest(),
            },
        };
        private.validate_against(&id, &slot)?;
        self.append(identity("keyslot", &id), Data::Keyslot(slot))?;
        self.append(identity("key", &id), Data::Key(private))?;
        self.append(identity("keyslot", &id), Data::Deleted)?;
        self.retained += 1;
        Ok(private_index)
    }
    fn append(&mut self, identity: Identity, data: Data) -> Result<(), AppError> {
        if self.history.len() >= 16384 {
            return Err(invalid());
        }
        let encoded = payload::encode(&identity, &data)?;
        self.history_bytes = self
            .history_bytes
            .checked_add(encoded.len())
            .ok_or_else(invalid)?;
        if self.history_bytes > 32 * 1024 * 1024 - 256 * 1024 {
            return Err(invalid());
        }
        self.history.push((identity, data));
        Ok(())
    }
    pub(in crate::sync::central) fn with_retained_materials(
        mut self,
        historical: Self,
    ) -> Result<Self, AppError> {
        let mut seen: BTreeSet<_> = self
            .history
            .iter()
            .map(|(id, data)| {
                payload::encode(id, data)
                    .map(|bytes| (id.kind.clone(), id.id.clone(), super::crypto::hash(&bytes)))
            })
            .collect::<Result<_, _>>()?;
        for (id, data) in historical.history {
            if seen.insert((
                id.kind.clone(),
                id.id.clone(),
                super::crypto::hash(&payload::encode(&id, &data)?),
            )) {
                if matches!(data, Data::Key(_)) {
                    self.retained = self.retained.checked_add(1).ok_or_else(invalid)?;
                }
                self.append(id, data)?;
            }
        }
        Ok(self)
    }
    pub(in crate::sync::central) fn with_retained_history(
        self,
        history: super::migration_library::History,
    ) -> Result<Self, AppError> {
        let mut material = Self {
            storage: BTreeMap::new(),
            active: BTreeMap::new(),
            retained: 0,
            history: vec![],
            history_bytes: 0,
        };
        for (id, data) in history.into_rows() {
            if matches!(data, Data::Key(_) | Data::Keyslot(_)) {
                material.append(id, data)?;
            }
        }
        self.with_retained_materials(material)
    }
    pub fn into_history(self) -> Vec<(Identity, Data)> {
        self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync::{
            record::{record_key, LocalRecord, Record},
            records_v3::LocalKeyMetadata,
            state_v2::AccountState,
            testkit::MemKeychain,
        },
        vault::store::{self, EntryOrigin, Vault},
    };
    use serde_json::json;
    pub(super) fn state() -> SyncStateV3 {
        serde_json::from_value(json!({"version":3,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap()
    }
    pub(super) fn entry(raw: &str) -> VaultEntry {
        let parsed = material::parse(raw).unwrap();
        VaultEntry {
            private_key: raw.into(),
            public_key: parsed.public_key().to_openssh().unwrap(),
            fingerprint: parsed
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string(),
            origin: EntryOrigin::Imported,
            added_at_ms: 1,
        }
    }
    pub(super) fn metadata(raw: &str) -> KeySlotPayload {
        let entry = entry(raw);
        let parsed = material::parse(raw).unwrap();
        KeySlotPayload {
            schema: 2,
            name: "Synthetic".into(),
            public_key: entry.public_key.clone(),
            fingerprint: entry.fingerprint.clone(),
            key_type: parsed.public_key().algorithm().as_str().into(),
            has_passphrase: parsed.is_encrypted(),
            created_at_ms: 1,
            origin_device_id: "d".repeat(32),
        }
    }
    fn account_slot(state: &mut SyncStateV3, id: &str, raw: &str, deleted: bool) {
        let account = state
            .account
            .get_or_insert_with(|| AccountState::new(&"a".repeat(64)));
        account.records.insert(
            record_key(RecordKind::KeySlot, id),
            LocalRecord {
                record: Record {
                    kind: RecordKind::KeySlot,
                    id: id.into(),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted,
                    payload: if deleted {
                        serde_json::Value::Null
                    } else {
                        serde_json::to_value(metadata(raw)).unwrap()
                    },
                },
                seq: 1,
                dirty: false,
            },
        );
    }
    fn put(vault: &mut Vault, keychain: &MemKeychain, id: &str, raw: &str) {
        vault.put(keychain, id, &entry(raw)).unwrap();
    }
    #[test]
    fn all_active_local_retired_and_orphan_bytes_enter_history_with_original_encryption_and_no_inactive_activation(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let memory = MemKeychain::default();
        let plain = crate::sync::slot_rules::test_keys::plain();
        let encrypted = crate::sync::slot_rules::test_keys::encrypted();
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        put(&mut vault, &memory, &"1".repeat(32), &plain);
        put(&mut vault, &memory, &"2".repeat(32), &encrypted);
        put(&mut vault, &memory, "retired:old:1", &encrypted);
        put(&mut vault, &memory, "orphan-old", &plain);
        let mut state = state();
        for (id, raw) in [("1".repeat(32), &plain), ("2".repeat(32), &encrypted)] {
            state.local.keys.insert(
                id.clone(),
                LocalKeyMetadata {
                    vault_id: id,
                    public: metadata(raw),
                },
            );
        }
        let keys = VaultKeys::generate().unwrap();
        let original_file = std::fs::read(&path).unwrap();
        let read = store::read_vault(&path, &memory).unwrap();
        let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
        assert_eq!(materials.active.len(), 2);
        assert_eq!(materials.retained, 2);
        assert_eq!(materials.history.len(), 10);
        assert_eq!(
            materials
                .history
                .iter()
                .filter(|(_, data)| matches!(data, Data::Key(_)))
                .count(),
            4
        );
        for (id, data) in &materials.history {
            if let Data::Key(raw) = data {
                assert!(raw.private() == plain || raw.private() == encrypted);
                assert_eq!(id.kind, "key");
            }
        }
        let inactive: Vec<_> = materials
            .history
            .iter()
            .filter(|(_, data)| matches!(data, Data::Deleted))
            .map(|(id, _)| id.id.clone())
            .collect();
        assert_eq!(inactive.len(), 2);
        assert!(inactive.iter().all(|id| !materials.active.contains_key(id)));
        let again = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
        assert_eq!(
            inactive,
            again
                .history
                .iter()
                .filter(|(_, data)| matches!(data, Data::Deleted))
                .map(|(id, _)| id.id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original_file);
        let (owner, plan_keys, signer) = super::super::migration_history::tests::initial();
        let material = Materials::from_vault(&state, &plan_keys, &read, &BTreeMap::new()).unwrap();
        let mut history = vec![(
            Identity {
                kind: "meta".into(),
                id: "catalog".into(),
                scope: None,
            },
            Data::Catalog(payload::Catalog {
                collections: vec![],
                group_orders: vec![],
            }),
        )];
        history.extend(material.into_history());
        let plan = super::super::migration_history::prepare(
            &owner,
            &plan_keys,
            &signer,
            super::super::migration_history::Context {
                operation: "7".repeat(32),
                inventory_digest: "8".repeat(64),
                sources: vec![],
            },
            &history,
        )
        .unwrap();
        assert_eq!(plan.rows.len(), 11);
        assert!(!plan.before().control.cutover);
        let checkpoint = super::super::rekey::Checkpoint {
            epoch: 1,
            sequence: 11,
            history_hash: plan.manifest.body.target_history_hash.clone(),
        };
        let chain = owner.control.verified_chain().unwrap();
        let mut verified = owner;
        for rows in plan.pages() {
            verified.replica = Some(
                verified
                    .replica
                    .as_ref()
                    .unwrap()
                    .prepare_page(&chain, &plan_keys, rows, &checkpoint)
                    .unwrap()
                    .next,
            );
        }
        let projected = super::super::projection::Plan::inventory(verified, &plan_keys).unwrap();
        assert!(projected.complete());
        assert_eq!(projected.materials().len(), 2);
        assert_eq!(
            projected.materials().keys().cloned().collect::<Vec<_>>(),
            vec!["1".repeat(32), "2".repeat(32)]
        );
    }
    #[test]
    fn aggregate_inventory_capacity_stops_large_valid_sources_without_trimming_a_subset() {
        let mut key = material::parse(&crate::sync::slot_rules::test_keys::plain()).unwrap();
        key.set_comment("x".repeat(32768));
        let raw = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let memory = MemKeychain::default();
        let protected = "f".repeat(32);
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        put(&mut vault, &memory, &protected, &raw);
        let public = metadata(&raw);
        let read = store::read_vault(&path, &memory).unwrap();
        let keys = VaultKeys::generate().unwrap();
        let mut state = state();
        for i in 0..200 {
            state.local.keys.insert(
                format!("{i:032x}"),
                LocalKeyMetadata {
                    vault_id: protected.clone(),
                    public: public.clone(),
                },
            );
        }
        assert_eq!(
            Materials::from_vault(&state, &keys, &read, &BTreeMap::new())
                .unwrap()
                .active
                .len(),
            200
        );
        for i in 200..600 {
            state.local.keys.insert(
                format!("{i:032x}"),
                LocalKeyMetadata {
                    vault_id: protected.clone(),
                    public: public.clone(),
                },
            );
        }
        let before = std::fs::read(&path).unwrap();
        assert!(Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).is_err());
        assert_eq!(state.local.keys.len(), 600);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    #[test]
    fn deleted_public_slots_keep_local_material_in_inactive_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let memory = MemKeychain::default();
        let raw = crate::sync::slot_rules::test_keys::plain();
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        let id = "1".repeat(32);
        put(&mut vault, &memory, &id, &raw);
        let mut state = state();
        state.local.keys.insert(
            id.clone(),
            LocalKeyMetadata {
                vault_id: id.clone(),
                public: metadata(&raw),
            },
        );
        account_slot(&mut state, &id, &raw, true);
        let result = Materials::from_vault(
            &state,
            &VaultKeys::generate().unwrap(),
            &store::read_vault(&path, &memory).unwrap(),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(result.active.is_empty());
        assert_eq!(result.retained, 1);
        assert_eq!(result.history.len(), 4);
        assert!(result
            .history
            .iter()
            .any(|(identity, data)| identity.id == id && matches!(data, Data::Deleted)));
        assert!(result
            .history
            .iter()
            .any(|(identity, data)| identity.id != id && matches!(data, Data::Key(_))));
    }
    #[test]
    fn unrelated_unreadable_or_malformed_entries_block_the_entire_inventory_without_mutation() {
        for encrypted_corrupt in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("vault.json");
            let memory = MemKeychain::default();
            let raw = crate::sync::slot_rules::test_keys::plain();
            let mut vault = Vault::open(&path, &memory, 0).unwrap();
            put(&mut vault, &memory, "orphan", &raw);
            if encrypted_corrupt {
                let mut file: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                file["entries"]["orphan"]["ciphertext"] = "AAAA".into();
                std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
            } else {
                let mut bad = entry(&raw);
                bad.private_key = "unreadable synthetic private".into();
                vault.put(&memory, "unreadable", &bad).unwrap();
            }
            let bytes = std::fs::read(&path).unwrap();
            let result = Materials::from_vault(
                &state(),
                &VaultKeys::generate().unwrap(),
                &store::read_vault(&path, &memory).unwrap(),
                &BTreeMap::new(),
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }
    #[test]
    fn missing_or_mismatched_material_and_reference_claims_cannot_suppress_exportable_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let memory = MemKeychain::default();
        let raw = crate::sync::slot_rules::test_keys::plain();
        let id = "1".repeat(32);
        let mut state = state();
        account_slot(&mut state, &id, &raw, false);
        let keys = VaultKeys::generate().unwrap();
        let missing = store::read_vault(&path, &memory).unwrap();
        assert!(Materials::from_vault(&state, &keys, &missing, &BTreeMap::new()).is_err());
        let references = BTreeMap::from([(id.clone(), KeyStorage::ExternalAgent)]);
        let reference = Materials::from_vault(&state, &keys, &missing, &references).unwrap();
        assert_eq!(reference.history.len(), 1);
        assert!(
            matches!(&reference.history[0].1,Data::Keyslot(slot) if slot.storage==KeyStorage::ExternalAgent)
        );
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        put(&mut vault, &memory, &id, &raw);
        let read = store::read_vault(&path, &memory).unwrap();
        assert!(Materials::from_vault(&state, &keys, &read, &references).is_err());
        state.local.keys.insert(
            id.clone(),
            LocalKeyMetadata {
                vault_id: id.clone(),
                public: metadata(&raw),
            },
        );
        state.local.keys.get_mut(&id).unwrap().public.has_passphrase = true;
        assert!(Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).is_err());
        state.local.keys.get_mut(&id).unwrap().public = metadata(&raw);
        state.local.keys.get_mut(&id).unwrap().vault_id = "f".repeat(32);
        assert!(Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).is_err());
    }
    #[test]
    fn oversized_unsupported_or_contradictory_original_bytes_cannot_be_silently_retained_as_a_reference(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let memory = MemKeychain::default();
        let raw = crate::sync::slot_rules::test_keys::plain();
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        let mut bad = entry(&raw);
        bad.fingerprint = "different".into();
        vault.put(&memory, "orphan", &bad).unwrap();
        assert!(Materials::from_vault(
            &state(),
            &VaultKeys::generate().unwrap(),
            &store::read_vault(&path, &memory).unwrap(),
            &BTreeMap::new()
        )
        .is_err());
        bad = entry(&raw);
        bad.private_key.push_str(&" ".repeat(65537));
        vault.put(&memory, "orphan", &bad).unwrap();
        assert!(Materials::from_vault(
            &state(),
            &VaultKeys::generate().unwrap(),
            &store::read_vault(&path, &memory).unwrap(),
            &BTreeMap::new()
        )
        .is_err());
    }
}

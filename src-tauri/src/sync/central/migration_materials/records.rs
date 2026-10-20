//! Add all admitted original legacy containers to retained history, without activating a winner.
use super::*;
use crate::sync::central::migration_sources::{KeyInput, Position, Scope};
impl Materials {
    /// Supply a passive remote-copy plan only from the exact current account key frame.
    pub(super) fn adopt_current(
        state: &SyncStateV3,
        entries: &mut BTreeMap<String, VaultEntry>,
        inputs: &[KeyInput],
    ) -> Result<(), AppError> {
        let Some(account) = &state.account else {
            return if inputs.is_empty() {
                Ok(())
            } else {
                Err(invalid())
            };
        };
        let mut seen = BTreeSet::new();
        for input in inputs {
            if input.location.scope != Scope::Account(account.chain_id.clone())
                || input.location.position != Position::Sealed
                || input.deleted
            {
                continue;
            }
            if !seen.insert(input.id.clone()) {
                return Err(invalid());
            }
            let key = crate::sync::record::record_key(RecordKind::KeySlot, &input.id);
            let Some(row) = account.records.get(&key).filter(|row| !row.record.deleted) else {
                continue;
            };
            // Never replace an original protected source, including a missing physical local alias.
            if entries.contains_key(&input.id)
                || state.local.keys.contains_key(&input.id)
                || state
                    .local
                    .keys
                    .values()
                    .any(|local| local.vault_id == input.id)
            {
                continue;
            }
            if [&key, &input.location.key].iter().any(|key| {
                account
                    .recovery
                    .conflicts
                    .get(*key)
                    .is_some_and(|rows| !rows.is_empty())
            }) {
                return Err(AppError::Other("Resolve the legacy key conflict before choosing its current material; every source is retained.".into()));
            }
            let records_v3::TypedRecord::Live(public) =
                records_v3::decode_keyslot(&row.record).map_err(|_| invalid())?
            else {
                return Err(invalid());
            };
            let private = input.material.as_ref().ok_or_else(invalid)?;
            private.validate_against(
                &input.id,
                &SharedKeyslot {
                    public: public.clone(),
                    storage: KeyStorage::Managed {
                        sha256: private.digest(),
                    },
                },
            )?;
            if entries.len() >= 4096 {
                return Err(invalid());
            }
            entries.insert(
                input.id.clone(),
                VaultEntry {
                    private_key: private.private().into(),
                    public_key: public.public_key,
                    fingerprint: public.fingerprint,
                    origin: crate::vault::store::EntryOrigin::Synced,
                    added_at_ms: public.created_at_ms,
                },
            );
        }
        Ok(())
    }
    pub(in crate::sync::central) fn with_key_inputs(
        mut self,
        state: &SyncStateV3,
        keys: &VaultKeys,
        inputs: Vec<KeyInput>,
    ) -> Result<Self, AppError> {
        if inputs.is_empty() {
            return Ok(self);
        }
        let mut index = super::files::raw_index(&self);
        let mut occupied: BTreeSet<_> = self
            .history
            .iter()
            .filter(|(id, _)| id.kind == "keyslot")
            .map(|(id, _)| id.id.clone())
            .collect();
        for input in inputs {
            let Scope::Account(chain) = &input.location.scope else {
                return Err(invalid());
            };
            // Null deletion intent remains in the archived source input; there are no bytes to copy.
            let Some(private) = input.material else {
                continue;
            };
            let parsed = material::parse(private.private()).ok_or_else(invalid)?;
            let entry = VaultEntry {
                private_key: private.private().into(),
                public_key: parsed.public_key().to_openssh().map_err(|_| invalid())?,
                fingerprint: private.fingerprint.clone(),
                origin: crate::vault::store::EntryOrigin::Synced,
                // A legacy key body carries no creation time. Preserve source timestamps in inputs.
                added_at_ms: 0,
            };
            if super::files::same_private(&self, &index, &entry)? {
                continue;
            }
            let source = format!("legacy-key:{chain}:{}", input.id);
            let private_index = self.keep_retained(state, keys, &source, &entry, &mut occupied)?;
            index.insert(private.digest(), private_index);
        }
        Ok(self)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        central::migration_sources::{Inventory, Sources},
        crypto::ChainKeys,
        record::Record,
        slot_rules::test_keys,
        state_v2::{AccountState, SealedRecord},
        testkit::MemKeychain,
    };
    use crate::vault::store::{self, EntryOrigin, Vault};
    use serde_json::json;
    fn fixture() -> (SyncStateV3, Vec<KeyInput>, String, String) {
        let plain = test_keys::plain();
        let encrypted = test_keys::encrypted();
        let parent = ChainKeys::generate().unwrap();
        let mut state = super::super::tests::state();
        let mut account = AccountState::new(&parent.chain_id);
        for (n, deleted, raw) in [
            (1, false, Some(plain.as_str())),
            (2, false, Some(encrypted.as_str())),
            (3, true, Some(plain.as_str())),
            (4, true, None),
        ] {
            let row = SealedRecord::seal(
                &parent,
                &Record {
                    kind: RecordKind::Key,
                    id: format!("{n:032x}"),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted,
                    payload: raw.map_or(
                        serde_json::Value::Null,
                        |raw| json!({"schema":1,"private_key":raw}),
                    ),
                },
                0,
            )
            .unwrap();
            if deleted {
                account.chain_deletes.push(row);
            } else {
                account.sealed.insert(row.key(), row);
            }
        }
        state.account = Some(account);
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let inputs = Inventory::from_state(&sources, &state)
            .unwrap()
            .keys()
            .unwrap();
        (state, inputs, plain, encrypted)
    }
    #[test]
    fn all_unique_containers_enter_inactive_history_and_identical_protected_copies_are_not_duplicated(
    ) {
        let (state, inputs, plain, encrypted) = fixture();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("vault.json");
        let memory = MemKeychain::default();
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        let mut entry = super::super::tests::entry(&encrypted);
        entry.origin = EntryOrigin::Imported;
        vault.put(&memory, "orphan", &entry).unwrap();
        let original = std::fs::read(&path).unwrap();
        let read = store::read_vault(&path, &memory).unwrap();
        let keys = VaultKeys::generate().unwrap();
        let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new())
            .unwrap()
            .with_key_inputs(&state, &keys, inputs)
            .unwrap();
        assert!(materials.active.is_empty());
        assert!(materials.storage.is_empty());
        assert_eq!(materials.retained, 2);
        let history = materials.into_history();
        assert_eq!(history.len(), 6);
        let private: Vec<_> = history
            .iter()
            .filter_map(|(_, v)| match v {
                Data::Key(private) => Some(private.private()),
                _ => None,
            })
            .collect();
        assert_eq!(private.len(), 2);
        assert!(private.contains(&plain.as_str()));
        assert!(private.contains(&encrypted.as_str()));
        for rows in history.chunks(3) {
            assert!(matches!(&rows[0].1, Data::Keyslot(_)));
            assert!(matches!(&rows[1].1, Data::Key(_)));
            assert!(matches!(&rows[2].1, Data::Deleted));
            assert_eq!(rows[0].0.id, rows[1].0.id);
            assert_eq!(rows[0].0.id, rows[2].0.id);
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    #[test]
    fn history_capacity_failure_retains_original_vault_and_returns_no_partial_builder() {
        let (state, inputs, _, _) = fixture();
        let memory = MemKeychain::default();
        let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
        let keys = VaultKeys::generate().unwrap();
        let mut materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
        materials.history_bytes = 32 * 1024 * 1024 - 256 * 1024;
        assert!(materials.with_key_inputs(&state, &keys, inputs).is_err());
        assert!(read.ids().is_empty());
    }
    fn add_public(state: &mut SyncStateV3, id: &str, raw: &str) -> KeySlotPayload {
        use crate::sync::record::{record_key, LocalRecord};
        let public = super::super::tests::metadata(raw);
        state.account.as_mut().unwrap().records.insert(
            record_key(RecordKind::KeySlot, id),
            LocalRecord {
                record: Record {
                    kind: RecordKind::KeySlot,
                    id: id.into(),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted: false,
                    payload: serde_json::to_value(&public).unwrap(),
                },
                seq: 1,
                dirty: false,
            },
        );
        public
    }
    #[test]
    fn only_current_matching_remote_plain_or_encrypted_material_is_adopted_into_the_passive_plan() {
        for (number, encrypted) in [(1, false), (2, true)] {
            let (mut state, inputs, plain, locked) = fixture();
            let id = format!("{number:032x}");
            let raw = if encrypted { &locked } else { &plain };
            let public = add_public(&mut state, &id, raw);
            let memory = MemKeychain::default();
            let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
            let keys = VaultKeys::generate().unwrap();
            let before = serde_json::to_vec(&state).unwrap();
            let materials =
                Materials::from_vault_inputs(&state, &keys, &read, &BTreeMap::new(), &inputs)
                    .unwrap()
                    .with_key_inputs(&state, &keys, inputs)
                    .unwrap();
            assert_eq!(materials.active.len(), 1);
            assert_eq!(materials.active[&id].public, public);
            assert_eq!(materials.retained, 1);
            assert!(materials
                .into_history()
                .iter()
                .any(|(logical, data)| logical.id == id
                    && matches!(data,Data::Key(private) if private.private()==raw)));
            assert_eq!(serde_json::to_vec(&state).unwrap(), before);
            assert!(state.local.keys.is_empty());
            assert!(read.ids().is_empty());
        }
    }
    #[test]
    fn retained_only_deleted_wrong_scope_conflicting_or_missing_local_material_cannot_be_used_as_a_current_remote_fallback(
    ) {
        use crate::sync::{
            record::record_key,
            record_conflicts::{RecordConflict, RecordVersion},
            records_v3::LocalKeyMetadata,
        };
        for case in 0..8 {
            let (mut state, mut inputs, plain, _) = fixture();
            state.version = 7;
            let id = format!("{:032x}", 1);
            let public = add_public(&mut state, &id, &plain);
            let input = inputs.iter_mut().find(|input| input.id == id).unwrap();
            match case {
                0 => input.location.position = Position::RecoveryBase,
                1 => input.deleted = true,
                2 => input.location.scope = Scope::Account("f".repeat(64)),
                3 => {
                    state.local.keys.insert(
                        id.clone(),
                        LocalKeyMetadata {
                            vault_id: "9".repeat(32),
                            public: public.clone(),
                        },
                    );
                }
                4 => {
                    state.local.keys.insert(
                        "a".repeat(32),
                        LocalKeyMetadata {
                            vault_id: id.clone(),
                            public: public.clone(),
                        },
                    );
                }
                5 => {
                    let key = record_key(RecordKind::KeySlot, &id);
                    let account = state.account.as_mut().unwrap();
                    let original = account.records[&key].clone();
                    let mut local = original.clone();
                    local.dirty = true;
                    let mut remote = original;
                    remote.record.version = 2;
                    remote.record.updated_at_ms = 2;
                    account.recovery.conflicts.insert(
                        key,
                        vec![RecordConflict {
                            base: None,
                            local: RecordVersion::Public(local),
                            remote: RecordVersion::Public(remote),
                        }],
                    );
                }
                6 => {
                    let account = state.account.as_mut().unwrap();
                    let local = account.sealed[&input.location.key].clone();
                    let mut remote = local.clone();
                    remote.dirty = false;
                    account.recovery.conflicts.insert(
                        input.location.key.clone(),
                        vec![RecordConflict {
                            base: None,
                            local: RecordVersion::Sealed(local),
                            remote: RecordVersion::Sealed(remote),
                        }],
                    );
                }
                _ => {
                    let key = record_key(RecordKind::KeySlot, &id);
                    let original = &mut state
                        .account
                        .as_mut()
                        .unwrap()
                        .records
                        .get_mut(&key)
                        .unwrap()
                        .record
                        .payload;
                    original["has_passphrase"] = true.into();
                }
            }
            let memory = MemKeychain::default();
            let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
            let keys = VaultKeys::generate().unwrap();
            assert!(
                Materials::from_vault_inputs(&state, &keys, &read, &BTreeMap::new(), &inputs)
                    .is_err(),
                "reconciliation case {case} must retain its source instead of guessing"
            );
            assert!(read.ids().is_empty());
        }
    }
    #[test]
    fn an_existing_protected_copy_is_never_overwritten_and_external_classification_cannot_hide_exportable_current_bytes(
    ) {
        let (mut state, inputs, plain, encrypted) = fixture();
        let id = format!("{:032x}", 1);
        add_public(&mut state, &id, &plain);
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("vault.json");
        let memory = MemKeychain::default();
        let mut vault = Vault::open(&path, &memory, 0).unwrap();
        vault
            .put(&memory, &id, &super::super::tests::entry(&encrypted))
            .unwrap();
        let original = std::fs::read(&path).unwrap();
        let read = store::read_vault(&path, &memory).unwrap();
        let keys = VaultKeys::generate().unwrap();
        assert!(
            Materials::from_vault_inputs(&state, &keys, &read, &BTreeMap::new(), &inputs).is_err()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let empty = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
        for storage in [KeyStorage::Hardware, KeyStorage::ExternalAgent] {
            let references = BTreeMap::from([(id.clone(), storage)]);
            assert!(
                Materials::from_vault_inputs(&state, &keys, &empty, &references, &inputs).is_err()
            );
        }
    }
    #[test]
    fn two_encrypted_containers_with_the_same_public_identity_keep_their_distinct_original_bytes() {
        let encrypted = test_keys::encrypted();
        let alternate = encrypted.replace('\n', "\r\n");
        assert_ne!(encrypted, alternate);
        let parent = ChainKeys::generate().unwrap();
        let mut state = super::super::tests::state();
        let mut account = AccountState::new(&parent.chain_id);
        for (n, raw) in [(1, encrypted.as_str()), (2, alternate.as_str())] {
            let row = SealedRecord::seal(
                &parent,
                &Record {
                    kind: RecordKind::Key,
                    id: format!("{n:032x}"),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted: false,
                    payload: json!({"schema":1,"private_key":raw}),
                },
                0,
            )
            .unwrap();
            account.sealed.insert(row.key(), row);
        }
        state.account = Some(account);
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let inputs = Inventory::from_state(&sources, &state)
            .unwrap()
            .keys()
            .unwrap();
        let memory = MemKeychain::default();
        let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
        let keys = VaultKeys::generate().unwrap();
        let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new())
            .unwrap()
            .with_key_inputs(&state, &keys, inputs)
            .unwrap();
        assert_eq!(materials.retained, 2);
        assert!(materials.active.is_empty());
        let history = materials.into_history();
        let originals: Vec<_> = history
            .iter()
            .filter_map(|(_, data)| match data {
                Data::Key(private) => Some(private),
                _ => None,
            })
            .collect();
        assert_eq!(originals.len(), 2);
        assert_eq!(originals[0].fingerprint, originals[1].fingerprint);
        assert!(originals
            .iter()
            .any(|private| private.private() == encrypted));
        assert!(originals
            .iter()
            .any(|private| private.private() == alternate));
    }
}

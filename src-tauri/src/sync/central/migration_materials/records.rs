//! Add all admitted original legacy containers to retained history, without activating a winner.
use super::*;
use crate::sync::central::migration_sources::{KeyInput, Scope};
impl Materials {
    pub(in crate::sync::central) fn with_key_inputs(
        mut self,
        state: &SyncStateV3,
        keys: &VaultKeys,
        inputs: Vec<KeyInput>,
    ) -> Result<Self, AppError> {
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
}

//! Direct typed admission of every retained legacy private-key frame; no active winner selection.
use super::*;
use crate::sync::central::payload::PrivateMaterial;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema: u32,
    #[serde(deserialize_with = "super::super::secret")]
    private_key: Zeroizing<String>,
}
pub(in crate::sync::central) struct KeyInput {
    pub location: Location,
    pub id: String,
    pub sequence: u64,
    pub dirty: bool,
    pub deleted: bool,
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: String,
    pub material: Option<PrivateMaterial>,
}
pub(super) fn payload(raw: &str, deleted: bool) -> Result<Option<PrivateMaterial>, AppError> {
    let body: Option<Body> = serde_json::from_str(raw).map_err(|_| invalid())?;
    match body {
        None if deleted => Ok(None),
        Some(body) if body.schema == 1 => PrivateMaterial::new(body.private_key).map(Some),
        _ => Err(invalid()),
    }
}
impl Inventory {
    /// Every known key is admitted, even a deleted or nonvisible side. No partial Vec on error.
    pub fn keys(&self) -> Result<Vec<KeyInput>, AppError> {
        let mut keys = vec![];
        for item in self.rows() {
            let view = item.view()?;
            if view.kind != "key" {
                continue;
            }
            if !matches!(item.location.scope, Scope::Account(_)) || !hex(view.id, 32) {
                return Err(invalid());
            }
            let material = payload(view.payload.get(), view.deleted)?;
            keys.push(KeyInput {
                location: item.location.clone(),
                id: view.id.into(),
                sequence: item.sequence,
                dirty: item.dirty,
                deleted: view.deleted,
                version: view.version,
                updated_at_ms: view.updated_at_ms,
                device_id: view.device_id.into(),
                material,
            });
        }
        Ok(keys)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        record::Record,
        record_conflicts::RecordConflict,
        slot_rules::test_keys,
        state_v2::AccountState,
    };
    use serde_json::json;
    fn frame(
        parent: &ChainKeys,
        id: &str,
        version: u64,
        deleted: bool,
        raw: Option<&str>,
    ) -> SealedRecord {
        SealedRecord::seal(
            parent,
            &Record {
                kind: RecordKind::Key,
                id: id.into(),
                version,
                updated_at_ms: version,
                device_id: "d".repeat(32),
                deleted,
                payload: raw.map_or(
                    serde_json::Value::Null,
                    |raw| json!({"schema":1,"private_key":raw}),
                ),
            },
            version,
        )
        .unwrap()
    }
    fn fixture() -> (SyncStateV3, ChainKeys, String, String) {
        let parent = ChainKeys::generate().unwrap();
        let plain = test_keys::plain();
        let encrypted = test_keys::encrypted();
        let mut state:SyncStateV3=serde_json::from_value(json!({"version":7,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
        let mut account = AccountState::new(&parent.chain_id);
        let current = frame(&parent, &"1".repeat(32), 4, false, Some(&plain));
        account.sealed.insert(current.key(), current);
        account
            .chain_deletes
            .push(frame(&parent, &"2".repeat(32), 2, true, Some(&encrypted)));
        account
            .chain_deletes
            .push(frame(&parent, &"3".repeat(32), 1, true, None));
        let mut base = frame(&parent, &"4".repeat(32), 1, false, Some(&plain));
        base.dirty = false;
        let common = RecordVersion::Sealed(base);
        account.recovery.bases.insert(common.key(), common.clone());
        let mut remote = frame(&parent, &"4".repeat(32), 3, false, Some(&encrypted));
        remote.dirty = false;
        account.recovery.conflicts.insert(
            common.key(),
            vec![RecordConflict {
                base: Some(common),
                local: RecordVersion::Sealed(frame(
                    &parent,
                    &"4".repeat(32),
                    2,
                    false,
                    Some(&plain),
                )),
                remote: RecordVersion::Sealed(remote),
            }],
        );
        state.account = Some(account);
        (state, parent, plain, encrypted)
    }
    #[test]
    fn current_dirty_retained_deleted_and_all_conflict_private_containers_are_admitted_exactly() {
        let (state, parent, plain, encrypted) = fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let inventory = Inventory::from_state(&sources, &state).unwrap();
        let keys = inventory.keys().unwrap();
        assert_eq!(keys.len(), 7);
        assert_eq!(keys.iter().filter(|r| r.material.is_some()).count(), 6);
        assert!(keys.iter().any(|r| r.deleted
            && r.material
                .as_ref()
                .is_some_and(|v| v.private() == encrypted)));
        assert!(keys.iter().any(|r| r.deleted && r.material.is_none()));
        assert!(keys
            .iter()
            .any(|r| r.dirty && r.location.position == Position::ConflictLocal));
        assert!(keys.iter().any(|r| !r.dirty
            && r.location.position == Position::ConflictRemote
            && r.material.as_ref().unwrap().private() == encrypted));
        assert!(keys
            .iter()
            .filter_map(|r| r.material.as_ref())
            .all(|v| v.private() == plain || v.private() == encrypted));
        assert!(keys.iter().all(|r| r.id.len() == 32
            && r.sequence > 0
            && r.version > 0
            && r.updated_at_ms == r.version
            && r.device_id == "d".repeat(32)));
    }
    #[test]
    fn malformed_final_private_side_refuses_the_entire_material_result_without_echoing_it() {
        let (mut state, parent, _, _) = fixture();
        let account = state.account.as_mut().unwrap();
        let conflict = &mut account.recovery.conflicts.values_mut().next().unwrap()[0];
        let mut wrong = frame(
            &parent,
            &"4".repeat(32),
            3,
            false,
            Some("PRIVATE_INVALID_SENTINEL"),
        );
        wrong.dirty = false;
        conflict.remote = RecordVersion::Sealed(wrong);
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let inventory = Inventory::from_state(&sources, &state).unwrap();
        let error = inventory.keys().err().unwrap();
        assert!(!error.to_string().contains("SENTINEL"));
    }
    #[test]
    fn future_unknown_or_duplicate_fields_and_nonempty_deleted_bodies_are_never_ignored() {
        let raw = serde_json::to_string(&test_keys::encrypted()).unwrap();
        for body in [
            format!(r#"{{"schema":2,"private_key":{raw}}}"#),
            format!(r#"{{"schema":1,"private_key":{raw},"password":"PRIVATE_SENTINEL"}}"#),
            format!(r#"{{"schema":1,"private_key":{raw},"private_key":{raw}}}"#),
            r#"{"schema":1,"private_key":"PRIVATE_SENTINEL"}"#.into(),
        ] {
            for deleted in [false, true] {
                assert!(payload(&body, deleted).is_err());
            }
        }
        assert!(payload("null", false).is_err());
        assert!(payload("null", true).unwrap().is_none());
    }
    #[test]
    fn valid_private_bytes_in_a_child_chain_are_not_misclassified_as_account_key_material() {
        let (mut state, parent, plain, _) = fixture();
        let child = ChainKeys::generate().unwrap();
        let secret = SealedRecord::seal(
            &parent,
            &Record {
                kind: RecordKind::SpaceKey,
                id: child.chain_id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: "d".repeat(32),
                deleted: false,
                payload: serde_json::to_value(crate::sync::record::SpaceKeyPayload::from_keys(
                    &child,
                ))
                .unwrap(),
            },
            1,
        )
        .unwrap();
        state
            .account
            .as_mut()
            .unwrap()
            .sealed
            .insert(secret.key(), secret);
        let mut scope = crate::sync::records_v3::SpaceStateV3::default();
        let row = frame(&child, &"a".repeat(32), 1, false, Some(&plain));
        scope.sealed.insert(row.key(), row);
        state.spaces.insert(child.chain_id.clone(), scope);
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        assert!(Inventory::from_state(&sources, &state)
            .unwrap()
            .keys()
            .is_err());
    }
}

//! Authenticate all retained envelopes without moving decrypted secrets through serde_json::Value.
use super::*;
const MAX_RECORDS: usize = 16384;
const MAX_BYTES: usize = 32 * 1024 * 1024 - 256 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct View<'a> {
    pub kind: &'a str,
    pub id: &'a str,
    pub version: u64,
    pub updated_at_ms: u64,
    pub device_id: &'a str,
    pub deleted: bool,
    #[serde(borrow)]
    pub payload: &'a RawValue,
}
/// Private backing bytes stay zeroizing; no Debug, Deserialize, Serialize or writable payload.
pub(in crate::sync::central) struct Authenticated {
    bytes: Zeroizing<Vec<u8>>,
}
impl Authenticated {
    pub fn view(&self) -> Result<View<'_>, AppError> {
        serde_json::from_slice(&self.bytes).map_err(|_| invalid())
    }
}
#[derive(Default)]
struct Budget {
    records: usize,
    bytes: usize,
}
impl Budget {
    fn add(&mut self, bytes: usize) -> Result<(), AppError> {
        self.records = self.records.checked_add(1).ok_or_else(invalid)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(invalid)?;
        if self.records > MAX_RECORDS || self.bytes > MAX_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Sources {
    pub fn open(&self, chain: &str, row: &SealedRecord) -> Result<Authenticated, AppError> {
        let envelope = &row.envelope;
        if !hex(chain, 64)
            || !hex(&envelope.id_hash, 64)
            || envelope.kind.is_empty()
            || envelope.kind.len() > 16
            || !envelope.kind.bytes().all(|v| v.is_ascii_lowercase())
            || envelope.seq > MAX_SAFE_INTEGER
            || envelope.nonce.len() > 64
            || envelope.ciphertext.len() > 65536
        {
            return Err(invalid());
        }
        super::super::crypto::decode(&envelope.nonce, 24, 24)?;
        super::super::crypto::decode(&envelope.ciphertext, 16, 49152)?;
        let key = self.keys.get(chain).ok_or_else(invalid)?;
        let temporary = Temporary(
            ChainKeys::from_parts(chain, &key.token, &key.encryption).map_err(|_| invalid())?,
        );
        let bytes = Zeroizing::new(
            crypto::open(
                &temporary.0,
                &envelope.kind,
                &envelope.id_hash,
                &crypto::Sealed {
                    id_hash: envelope.id_hash.clone(),
                    nonce: envelope.nonce.clone(),
                    ciphertext: envelope.ciphertext.clone(),
                },
            )
            .map_err(|_| invalid())?,
        );
        if bytes.len() > 49152 {
            return Err(invalid());
        }
        let view: View<'_> = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if view.kind != envelope.kind
            || view.id.is_empty()
            || view.id.len() > 1024
            || crypto::id_hash(&temporary.0, view.kind, view.id) != envelope.id_hash
            || view.deleted != envelope.deleted
            || view.version == 0
            || view.version > MAX_SAFE_INTEGER
            || view.updated_at_ms > MAX_SAFE_INTEGER
            || !hex(view.device_id, 32)
            || row.public_identity.as_ref().is_some_and(|hint| {
                !hint.is_valid_for(envelope)
                    || hint.id != view.id
                    || hint.version != view.version
                    || hint.updated_at_ms != view.updated_at_ms
                    || hint.device_id != view.device_id
                    || hint.deleted != view.deleted
            })
        {
            return Err(invalid());
        }
        Ok(Authenticated { bytes })
    }
    /// Authenticate every known encrypted version. Payload semantics and complete history mapping
    /// remain separate gates; a valid future payload cannot silently become a supported record.
    pub fn verify_retained(&self, state: &SyncStateV3) -> Result<usize, AppError> {
        drop(Self::decode_local(&self.encode_local()?, state)?);
        let mut budget = Budget::default();
        let mut visit = |chain: &str, row: &SealedRecord| -> Result<(), AppError> {
            let opened = self.open(chain, row)?;
            budget.add(opened.bytes.len())
        };
        if let Some(account) = &state.account {
            for row in account.sealed.values().chain(&account.chain_deletes) {
                visit(&account.chain_id, row)?;
            }
            recovery(&account.chain_id, &account.recovery, &mut visit)?;
        }
        for (chain, space) in &state.spaces {
            for row in space.sealed.values() {
                visit(chain, row)?;
            }
            recovery(chain, &space.recovery, &mut visit)?;
        }
        Ok(budget.records)
    }
}
fn recovery(
    chain: &str,
    recovery: &RecordRecovery,
    visit: &mut impl FnMut(&str, &SealedRecord) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let mut version = |row: &RecordVersion| match row {
        RecordVersion::Sealed(row) => visit(chain, row),
        RecordVersion::Public(_) => Ok(()),
    };
    for row in recovery.bases.values() {
        version(row)?;
    }
    for conflicts in recovery.conflicts.values() {
        for conflict in conflicts {
            if let Some(base) = &conflict.base {
                version(base)?;
            }
            version(&conflict.local)?;
            version(&conflict.remote)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::sync::central::migration_sources) mod tests {
    use super::*;
    use crate::sync::{
        record::SpaceKeyPayload,
        record_conflicts::RecordConflict,
        records_v3::SpaceStateV3,
        state_v2::{AccountState, VerifiedPublicIdentity},
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::json;
    fn row(
        keys: &ChainKeys,
        kind: RecordKind,
        id: &str,
        version: u64,
        deleted: bool,
    ) -> SealedRecord {
        SealedRecord::seal(
            keys,
            &Record {
                kind,
                id: id.into(),
                version,
                updated_at_ms: version,
                device_id: "d".repeat(32),
                deleted,
                payload: json!({"schema":999,"private_key":"PRIVATE_RETAINED_SENTINEL"}),
            },
            version,
        )
        .unwrap()
    }
    fn clean(mut row: SealedRecord) -> RecordVersion {
        row.dirty = false;
        RecordVersion::Sealed(row)
    }
    fn conflict(
        keys: &ChainKeys,
        kind: RecordKind,
        id: &str,
    ) -> (String, RecordVersion, RecordConflict) {
        let base = row(keys, kind, id, 1, false);
        let key = base.key();
        let common = clean(base);
        (
            key,
            common.clone(),
            RecordConflict {
                base: Some(common),
                local: RecordVersion::Sealed(row(keys, kind, id, 2, false)),
                remote: clean(row(keys, kind, id, 3, false)),
            },
        )
    }
    pub(in crate::sync::central::migration_sources) fn fixture(
    ) -> (SyncStateV3, ChainKeys, ChainKeys) {
        let parent = ChainKeys::generate().unwrap();
        let child = ChainKeys::generate().unwrap();
        let mut state:SyncStateV3=serde_json::from_value(json!({"version":7,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
        let mut account = AccountState::new(&parent.chain_id);
        let child_key = SealedRecord::seal(
            &parent,
            &Record {
                kind: RecordKind::SpaceKey,
                id: child.chain_id.clone(),
                version: 1,
                updated_at_ms: 1,
                device_id: state.device_id.clone(),
                deleted: false,
                payload: serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
            },
            0,
        )
        .unwrap();
        account.sealed.insert(child_key.key(), child_key);
        let current = row(&parent, RecordKind::Key, &"1".repeat(32), 4, false);
        account.sealed.insert(current.key(), current);
        account
            .chain_deletes
            .push(row(&parent, RecordKind::Key, &"2".repeat(32), 2, true));
        let (key, common, conflict) = conflict(&parent, RecordKind::Key, &"3".repeat(32));
        account.recovery.bases.insert(key.clone(), common);
        account.recovery.conflicts.insert(key, vec![conflict]);
        let mut space = SpaceStateV3 {
            selected: false,
            missing: true,
            ..Default::default()
        };
        let current = row(&child, RecordKind::Host, &"4".repeat(16), 4, false);
        space.sealed.insert(current.key(), current);
        let (key, common, conflict) = self::conflict(&child, RecordKind::Host, &"5".repeat(16));
        space.recovery.bases.insert(key.clone(), common);
        space.recovery.conflicts.insert(key, vec![conflict]);
        state.account = Some(account);
        state.spaces.insert(child.chain_id.clone(), space);
        records_v3::validate_state(&state).unwrap();
        (state, parent, child)
    }
    #[test]
    fn all_account_pending_deletions_unselected_missing_scopes_and_every_conflict_side_are_authenticated(
    ) {
        let (state, parent, child) = fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        assert_eq!(sources.verify_retained(&state).unwrap(), 12);
        let original = serde_json::to_vec(&state).unwrap();
        let sealed = state.spaces[&child.chain_id]
            .sealed
            .values()
            .next()
            .unwrap();
        let opened = sources.open(&child.chain_id, sealed).unwrap();
        let view = opened.view().unwrap();
        assert_eq!(view.kind, "host");
        assert_eq!(view.version, 4);
        assert!(view.payload.get().contains("PRIVATE_RETAINED_SENTINEL"));
        assert!(sources.open(&parent.chain_id, sealed).is_err());
        assert_eq!(serde_json::to_vec(&state).unwrap(), original);
    }
    fn sealed_mut(version: &mut RecordVersion) -> &mut SealedRecord {
        match version {
            RecordVersion::Sealed(row) => row,
            _ => panic!("synthetic sealed fixture"),
        }
    }
    #[test]
    fn a_corrupt_retained_version_in_any_nonvisible_location_blocks_the_whole_input_set() {
        let (state, parent, child) = fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        for location in [
            "current",
            "delete",
            "base",
            "conflict-base",
            "conflict-local",
            "conflict-remote",
            "space-current",
            "space-base",
            "space-conflict-base",
            "space-conflict-local",
            "space-conflict-remote",
        ] {
            let mut changed = state.clone();
            let account = changed.account.as_mut().unwrap();
            let target = match location {
                "current" => account
                    .sealed
                    .values_mut()
                    .find(|row| row.envelope.kind == "key")
                    .unwrap(),
                "delete" => &mut account.chain_deletes[0],
                "base" => sealed_mut(account.recovery.bases.values_mut().next().unwrap()),
                "conflict-base" => sealed_mut(
                    account.recovery.conflicts.values_mut().next().unwrap()[0]
                        .base
                        .as_mut()
                        .unwrap(),
                ),
                "conflict-local" => sealed_mut(
                    &mut account.recovery.conflicts.values_mut().next().unwrap()[0].local,
                ),
                "conflict-remote" => sealed_mut(
                    &mut account.recovery.conflicts.values_mut().next().unwrap()[0].remote,
                ),
                other => {
                    let space = changed.spaces.get_mut(&child.chain_id).unwrap();
                    match other {
                        "space-current" => space.sealed.values_mut().next().unwrap(),
                        "space-base" => {
                            sealed_mut(space.recovery.bases.values_mut().next().unwrap())
                        }
                        "space-conflict-base" => sealed_mut(
                            space.recovery.conflicts.values_mut().next().unwrap()[0]
                                .base
                                .as_mut()
                                .unwrap(),
                        ),
                        "space-conflict-local" => sealed_mut(
                            &mut space.recovery.conflicts.values_mut().next().unwrap()[0].local,
                        ),
                        _ => sealed_mut(
                            &mut space.recovery.conflicts.values_mut().next().unwrap()[0].remote,
                        ),
                    }
                }
            };
            target.envelope.ciphertext = B64.encode([0u8; 32]);
            assert!(sources.verify_retained(&changed).is_err(), "{location}");
        }
    }
    fn raw(keys: &ChainKeys, kind: &str, id: &str, plain: &[u8], deleted: bool) -> SealedRecord {
        let sealed = crypto::seal(keys, kind, id, plain).unwrap();
        SealedRecord {
            envelope: crate::sync::record::Envelope {
                id_hash: sealed.id_hash,
                kind: kind.into(),
                seq: 0,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                deleted,
            },
            dirty: true,
            public_identity: None,
        }
    }
    #[test]
    fn authentication_rejects_mismatched_headers_hints_and_strict_json_without_leaking_payloads() {
        let (state, parent, _) = fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let id = "6".repeat(16);
        let value = json!({"kind":"host","id":id,"version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false,"payload":{"private_key":"PRIVATE_SENTINEL"}});
        let good = raw(
            &parent,
            "host",
            &id,
            &serde_json::to_vec(&value).unwrap(),
            false,
        );
        assert!(sources.open(&parent.chain_id, &good).is_ok());
        for change in [
            "kind",
            "id",
            "version-zero",
            "version-large",
            "time",
            "device",
            "deleted",
            "extra",
            "hint",
        ] {
            let mut value = value.clone();
            match change {
                "kind" => value["kind"] = "group".into(),
                "id" => value["id"] = "7".repeat(16).into(),
                "version-zero" => value["version"] = 0.into(),
                "version-large" => value["version"] = (MAX_SAFE_INTEGER + 1).into(),
                "time" => value["updated_at_ms"] = (MAX_SAFE_INTEGER + 1).into(),
                "device" => value["device_id"] = "bad".into(),
                "deleted" => value["deleted"] = true.into(),
                "extra" => value["unrecognized"] = "PRIVATE_SENTINEL".into(),
                _ => {}
            }
            let mut row = raw(
                &parent,
                "host",
                &id,
                &serde_json::to_vec(&value).unwrap(),
                false,
            );
            if change == "hint" {
                row.public_identity = Some(VerifiedPublicIdentity {
                    id: id.clone(),
                    version: 2,
                    updated_at_ms: 1,
                    device_id: "d".repeat(32),
                    deleted: false,
                });
            }
            let error = sources
                .open(&parent.chain_id, &row)
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("PRIVATE_SENTINEL"), "{change}");
        }
        let duplicate = serde_json::to_string(&value).unwrap().replacen(
            "\"version\":1",
            "\"version\":1,\"version\":2",
            1,
        );
        assert!(sources
            .open(
                &parent.chain_id,
                &raw(&parent, "host", &id, duplicate.as_bytes(), false)
            )
            .is_err());
        let mut wrong = good;
        wrong.envelope.id_hash = "f".repeat(64);
        assert!(sources.open(&parent.chain_id, &wrong).is_err());
        wrong.envelope.nonce = "x".repeat(65);
        assert!(sources.open(&parent.chain_id, &wrong).is_err());
    }
    #[test]
    fn unknown_payloads_remain_native_opaque_data_and_aggregate_limits_cannot_return_partial_success(
    ) {
        let (state, parent, _) = fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let value = json!({"kind":"future","id":"opaque","version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false,"payload":{"schema":999,"private_key":"PRIVATE_FUTURE_SENTINEL"}});
        let row = raw(
            &parent,
            "future",
            "opaque",
            &serde_json::to_vec(&value).unwrap(),
            false,
        );
        let authenticated = sources.open(&parent.chain_id, &row).unwrap();
        assert_eq!(authenticated.view().unwrap().kind, "future");
        let mut count = Budget {
            records: MAX_RECORDS,
            bytes: 0,
        };
        assert!(count.add(1).is_err());
        let mut bytes = Budget {
            records: 0,
            bytes: MAX_BYTES,
        };
        assert!(bytes.add(1).is_err());
        let mut overflow = Budget {
            records: 0,
            bytes: usize::MAX,
        };
        assert!(overflow.add(1).is_err());
        let mut oversized = row;
        oversized.envelope.ciphertext = "x".repeat(65537);
        assert!(sources.open(&parent.chain_id, &oversized).is_err());
    }
}

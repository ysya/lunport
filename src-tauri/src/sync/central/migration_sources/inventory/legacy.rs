//! Pure conversion of admitted old public schemas. Captured sources remain byte-for-byte intact.
use super::*;
use crate::sync::central::{crypto, migration_files::Files, payload::PrivateMaterial};
use crate::sync::{
    record::{record_key, Record, RecordKind},
    records_v3::{self, importer, HostScope, KeySlotPayload},
};
use std::path::Path;
fn blocked() -> AppError {
    AppError::Other("A legacy host or key needs source review before central migration. Every original version is retained.".into())
}
fn live(row: &KnownInput) -> bool {
    matches!(row.location.position, Position::Current | Position::Sealed)
}
fn record(row: &KnownInput) -> Result<Record, AppError> {
    let KnownData::LegacyHost(host) = &row.data else {
        return Err(invalid());
    };
    if host.text.contains("PRIVATE KEY-----") {
        return Err(blocked());
    }
    Ok(Record {
        kind: RecordKind::Host,
        id: row.id.clone(),
        version: row.version,
        updated_at_ms: row.updated_at_ms,
        device_id: row.device_id.clone(),
        deleted: false,
        payload: serde_json::json!({"schema":1,"text":host.text.as_str()}),
    })
}
fn public(state: &mut SyncStateV3, old: &str, row: &KnownInput) -> Result<(), AppError> {
    if !live(row) {
        return Ok(());
    }
    let payload = match &row.data {
        KnownData::Host(value) => serde_json::to_value(value),
        KnownData::Keyslot(value) => serde_json::to_value(value),
        KnownData::Deleted => Ok(serde_json::Value::Null),
        _ => return Ok(()),
    }
    .map_err(|_| invalid())?;
    let kind = RecordKind::parse(&row.kind).ok_or_else(invalid)?;
    let rows = match &row.location.scope {
        Scope::Local if kind == RecordKind::Host => &mut state.local.hosts,
        Scope::Space(id) => &mut state.spaces.get_mut(id).ok_or_else(invalid)?.records,
        Scope::Account(_) => &mut state.account.as_mut().ok_or_else(invalid)?.records,
        _ => return Err(invalid()),
    };
    let old_key = record_key(kind, old);
    let new_key = record_key(kind, &row.id);
    if old_key != new_key && rows.contains_key(&new_key) {
        return Err(blocked());
    }
    rows.remove(&old_key);
    rows.insert(
        new_key,
        LocalRecord {
            record: Record {
                kind,
                id: row.id.clone(),
                version: row.version,
                updated_at_ms: row.updated_at_ms,
                device_id: row.device_id.clone(),
                deleted: row.deleted,
                payload,
            },
            seq: row.sequence,
            dirty: row.dirty,
        },
    );
    Ok(())
}
impl Known {
    pub(in crate::sync::central) fn normalize_legacy(
        mut self,
        state: &mut SyncStateV3,
        files: Option<&Files>,
    ) -> Result<Self, AppError> {
        let mut slot_names = BTreeMap::new();
        let mut extra = vec![];
        for index in 0..self.rows.len() {
            let row = &self.rows[index];
            let KnownData::LegacySlot(slot) = &row.data else {
                continue;
            };
            let name = crate::sync::slot_rules::slot_file_name(&slot.name, &row.id);
            if slot_names
                .insert(name.clone(), row.id.clone())
                .is_some_and(|old| old != row.id)
            {
                return Err(blocked());
            }
            let physical = files.and_then(|files| files.bytes.get(&Path::new("keys").join(&name)));
            let private = physical
                .map(|bytes| {
                    let raw = std::str::from_utf8(bytes).map_err(|_| invalid())?;
                    PrivateMaterial::new(Zeroizing::new(raw.to_owned()))
                })
                .transpose()?;
            let parsed = private
                .as_ref()
                .map(|private| crate::vault::material::parse(private.private()).ok_or_else(invalid))
                .transpose()?;
            let mut converted = KeySlotPayload {
                schema: 2,
                name: slot.name.clone(),
                public_key: slot
                    .public_key
                    .clone()
                    .or_else(|| {
                        parsed
                            .as_ref()
                            .and_then(|key| key.public_key().to_openssh().ok())
                    })
                    .ok_or_else(blocked)?,
                fingerprint: slot
                    .fingerprint
                    .clone()
                    .or_else(|| private.as_ref().map(|key| key.fingerprint.clone()))
                    .ok_or_else(blocked)?,
                key_type: slot
                    .key_type
                    .clone()
                    .or_else(|| {
                        parsed
                            .as_ref()
                            .map(|key| key.algorithm().as_str().to_owned())
                    })
                    .ok_or_else(blocked)?,
                has_passphrase: slot
                    .has_passphrase
                    .or_else(|| parsed.as_ref().map(|key| key.is_encrypted()))
                    .ok_or_else(blocked)?,
                created_at_ms: slot.created_at_ms,
                origin_device_id: slot.origin_device_id.clone(),
            };
            if !crate::sync::central::wire::hex(&converted.origin_device_id, 32) {
                converted.origin_device_id = crypto::hash(
                    format!("lunport-legacy-device-v1:{}", converted.origin_device_id).as_bytes(),
                )[..32]
                    .to_owned();
            }
            records_v3::validate_keyslot(&row.id, &converted).map_err(|_| invalid())?;
            if let Some(private) = private {
                let shared = crate::sync::central::payload::SharedKeyslot {
                    public: converted.clone(),
                    storage: crate::sync::central::payload::KeyStorage::Managed {
                        sha256: private.digest(),
                    },
                };
                private.validate_against(&row.id, &shared)?;
                if live(row) && !row.deleted {
                    let candidates: Vec<_> = self
                        .rows
                        .iter()
                        .filter(|candidate| {
                            candidate.id == row.id
                                && candidate.location.scope == row.location.scope
                                && live(candidate)
                                && !candidate.deleted
                        })
                        .filter_map(|candidate| match &candidate.data {
                            KnownData::Key(value) => Some(value),
                            _ => None,
                        })
                        .collect();
                    if candidates.iter().any(|value| {
                        value
                            .as_ref()
                            .is_none_or(|value| value.private() != private.private())
                    }) {
                        return Err(blocked());
                    }
                    if candidates.is_empty() {
                        let mut location = row.location.clone();
                        location.position = Position::Sealed;
                        location.key = record_key(RecordKind::Key, &row.id);
                        location.index = self.rows.len() + extra.len();
                        extra.push(KnownInput {
                            location,
                            sequence: row.sequence,
                            dirty: row.dirty,
                            kind: "key".into(),
                            id: row.id.clone(),
                            version: row.version,
                            updated_at_ms: row.updated_at_ms,
                            device_id: row.device_id.clone(),
                            deleted: false,
                            data: KnownData::Key(Some(private)),
                        });
                    }
                }
            }
            let old = row.id.clone();
            self.rows[index].data = KnownData::Keyslot(converted);
            public(state, &old, &self.rows[index])?;
        }
        self.rows.extend(extra);
        // All versions of one old alias map to one stable identity. Each conversion sees a complete
        // immutable alias snapshot, so jump links cannot depend on row iteration or random IDs.
        let mut ids = BTreeMap::new();
        let mut converted = vec![];
        for (index, row) in self.rows.iter().enumerate() {
            if !matches!(row.data, KnownData::LegacyHost(_)) {
                continue;
            }
            let chain = match &row.location.scope {
                Scope::Space(id) => id.clone(),
                Scope::Local => crypto::hash(b"lunport-local-legacy-hosts-v1"),
                _ => return Err(invalid()),
            };
            let mut snapshot: BTreeMap<String, Record> = BTreeMap::new();
            for peer in &self.rows {
                if peer.location.scope == row.location.scope
                    && matches!(peer.data, KnownData::LegacyHost(_))
                    && !peer.deleted
                {
                    let candidate = record(peer)?;
                    if let Some(previous) = snapshot.get(&peer.id) {
                        let saved_live = self.rows.iter().any(|saved| {
                            saved.id == peer.id
                                && saved.location.scope == peer.location.scope
                                && live(saved)
                                && matches!(saved.data, KnownData::LegacyHost(_))
                                && saved.version == previous.version
                        });
                        if saved_live && !live(peer)
                            || saved_live == live(peer) && previous.version > candidate.version
                        {
                            continue;
                        }
                        if saved_live == live(peer)
                            && previous.version == candidate.version
                            && previous.payload != candidate.payload
                        {
                            return Err(blocked());
                        }
                    }
                    snapshot.insert(peer.id.clone(), candidate);
                }
            }
            snapshot.insert(row.id.clone(), record(row)?);
            let records: Vec<_> = snapshot.into_values().collect();
            let home = Path::new("/lunport-captured-source");
            let mut options = crate::sync::record_migration::legacy_key_options(
                home,
                &chain,
                &records,
                &slot_names,
            );
            options.reserved_host_ids = self
                .rows
                .iter()
                .filter(|peer| {
                    peer.location.scope == row.location.scope
                        && matches!(peer.data, KnownData::Host(_))
                })
                .map(|peer| peer.id.clone())
                .collect();
            let preview = importer::preview_legacy_records(&records, &chain, &options)
                .map_err(|_| blocked())?;
            if preview
                .warnings
                .iter()
                .any(|warning| warning.blocks_connection)
            {
                return Err(blocked());
            }
            let id = preview.host_ids.get(&row.id).ok_or_else(blocked)?.clone();
            let mut host = preview
                .candidates
                .into_iter()
                .find(|host| host.id == id)
                .ok_or_else(blocked)?;
            if row.location.scope == Scope::Local {
                host.scope = HostScope::Local;
            }
            if host.payload.key_id.as_ref().is_some_and(|key| {
                !self
                    .rows
                    .iter()
                    .any(|peer| peer.id == *key && matches!(peer.data, KnownData::Keyslot(_)))
            }) {
                return Err(blocked());
            }
            if ids
                .insert((row.location.scope.clone(), row.id.clone()), id.clone())
                .is_some_and(|old| old != id)
            {
                return Err(invalid());
            }
            converted.push((index, id, host.payload));
        }
        for (index, id, payload) in converted {
            let old = self.rows[index].id.clone();
            self.rows[index].id = id;
            self.rows[index].data = KnownData::Host(payload);
            public(state, &old, &self.rows[index])?;
        }
        for row in &mut self.rows {
            if row.kind == "host" && matches!(row.data, KnownData::Deleted) {
                if let Some(id) = ids.get(&(row.location.scope.clone(), row.id.clone())) {
                    let old = row.id.clone();
                    row.id = id.clone();
                    public(state, &old, row)?;
                } else if !crate::sync::central::wire::hex(&row.id, 16) {
                    let Scope::Space(chain) = &row.location.scope else {
                        return Err(blocked());
                    };
                    let old = row.id.clone();
                    row.id = records_v3::migration_host_id(chain, &old).map_err(|_| invalid())?;
                    public(state, &old, row)?;
                }
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests;

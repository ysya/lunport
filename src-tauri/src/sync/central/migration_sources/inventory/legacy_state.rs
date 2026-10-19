//! Read-only admission of captured v1/v2 backups; no old network operation is resumed.
use super::*;
use crate::sync::{
    record::{record_key, Record, RecordKind},
    records_v3::DecodedState,
    state_v2,
};
fn unavailable() -> AppError {
    AppError::Other("A legacy backup needs its original source keys, completed rotation, or supported source review. Every original file is retained.".into())
}
fn root_fields(bytes: &[u8], allowed: &[&str]) -> Result<(), AppError> {
    use serde::de::{self, IgnoredAny, MapAccess, Visitor};
    struct Fields<'a>(&'a [&'a str]);
    impl<'de> Visitor<'de> for Fields<'_> {
        type Value = ();
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a known legacy state image")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
            let mut seen = BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !self.0.contains(&key.as_str()) || !seen.insert(key) {
                    return Err(de::Error::custom("unsupported legacy field"));
                }
                map.next_value::<IgnoredAny>()?;
            }
            Ok(())
        }
    }
    use serde::Deserializer;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    decoder
        .deserialize_map(Fields(allowed))
        .map_err(|_| unavailable())?;
    decoder.end().map_err(|_| unavailable())
}
impl Inventory {
    fn legacy_minimum(
        &mut self,
        sources: &Sources,
        chain: &str,
        minimum: u64,
    ) -> Result<(), AppError> {
        if !sources.keys.contains_key(chain)
            || minimum > MAX_SAFE_INTEGER
            || self.frozen_context.is_some()
                && self.frozen.get(chain).is_none_or(|known| {
                    super::super::super::wire::number(&known.sequence, true)
                        .map_or(true, |sequence| sequence < minimum)
                })
        {
            return Err(unavailable());
        }
        self.minima
            .entry(chain.into())
            .and_modify(|saved| *saved = (*saved).max(minimum))
            .or_insert(minimum);
        Ok(())
    }
    pub(in crate::sync::central) fn with_retained_legacy(
        mut self,
        sources: &Sources,
        bytes: &[u8],
    ) -> Result<Self, AppError> {
        if self.keybook != super::super::super::crypto::hash(&sources.encode_local()?) {
            return Err(invalid());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
        let decoded = records_v3::decode_state(text).map_err(|_| unavailable())?;
        match decoded {
            DecodedState::V1(old) => {
                root_fields(
                    bytes,
                    &[
                        "version",
                        "chain_id",
                        "device_id",
                        "device_name",
                        "relay_url",
                        "cursor_seq",
                        "password_sync",
                        "remote_schema_version",
                        "baseline_established",
                        "phrase_cleanup_pending",
                        "records",
                        "sealed",
                        "last_sync_ms",
                        "last_error",
                    ],
                )?;
                if !hex(&old.device_id, 32) {
                    return Err(unavailable());
                }
                let Some(chain) = old.chain_id else {
                    return if old.records.is_empty() && old.sealed.is_empty() && old.cursor_seq == 0
                    {
                        Ok(self)
                    } else {
                        Err(unavailable())
                    };
                };
                if old.relay_url != sources.legacy_origin.as_deref().unwrap_or("") {
                    return Err(unavailable());
                }
                self.legacy_minimum(sources, &chain, old.cursor_seq)?;
                for (key, row) in old.records {
                    let scope = if row.record.kind == RecordKind::Host {
                        Scope::Space(chain.clone())
                    } else {
                        Scope::Account(chain.clone())
                    };
                    self.public(scope, Position::Retained, &key, self.rows.len(), &row)?;
                }
                for (key, envelope) in old.sealed {
                    let scope = if envelope.kind == "host" {
                        Scope::Space(chain.clone())
                    } else {
                        Scope::Account(chain.clone())
                    };
                    self.sealed(
                        sources,
                        scope,
                        Position::Retained,
                        &key,
                        self.rows.len(),
                        &state_v2::SealedRecord {
                            envelope,
                            dirty: false,
                            public_identity: None,
                        },
                    )?;
                }
            }
            DecodedState::V2(old) => {
                root_fields(
                    bytes,
                    &[
                        "version",
                        "device_id",
                        "device_name",
                        "relay_url",
                        "account",
                        "spaces",
                        "rotation",
                        "legacy_v1_backup",
                        "relay_features",
                        "phrase_cleanup_pending",
                        "last_sync_ms",
                        "last_error",
                        "key_slots",
                        "notices",
                    ],
                )?;
                if old.rotation.is_some() || !hex(&old.device_id, 32) {
                    return Err(unavailable());
                }
                let Some(account) = old.account else {
                    if !old.spaces.is_empty() {
                        return Err(unavailable());
                    }
                    for (id, slot) in old.key_slots {
                        self.retained_slot(&old.device_id, Scope::Local, id, slot)?;
                    }
                    drop(self.admit_known()?);
                    return Ok(self);
                };
                if old.relay_url != sources.legacy_origin.as_deref().unwrap_or("") {
                    return Err(unavailable());
                }
                self.legacy_minimum(sources, &account.chain_id, account.cursor_seq)?;
                let scope = Scope::Account(account.chain_id.clone());
                for (key, row) in account.records {
                    self.public(
                        scope.clone(),
                        Position::Retained,
                        &key,
                        self.rows.len(),
                        &row,
                    )?;
                }
                for (key, row) in account.sealed {
                    self.sealed(
                        sources,
                        scope.clone(),
                        Position::Retained,
                        &key,
                        self.rows.len(),
                        &row,
                    )?;
                }
                for row in account.chain_deletes {
                    self.sealed(
                        sources,
                        scope.clone(),
                        Position::Retained,
                        &row.key(),
                        self.rows.len(),
                        &row,
                    )?;
                }
                for (key, base) in &account.recovery.bases {
                    self.version(
                        sources,
                        &scope,
                        Position::Retained,
                        key,
                        self.rows.len(),
                        base,
                    )?;
                }
                for (key, conflicts) in &account.recovery.conflicts {
                    for conflict in conflicts {
                        if let Some(base) = &conflict.base {
                            self.version(
                                sources,
                                &scope,
                                Position::Retained,
                                key,
                                self.rows.len(),
                                base,
                            )?;
                        }
                        self.version(
                            sources,
                            &scope,
                            Position::Retained,
                            key,
                            self.rows.len(),
                            &conflict.local,
                        )?;
                        self.version(
                            sources,
                            &scope,
                            Position::Retained,
                            key,
                            self.rows.len(),
                            &conflict.remote,
                        )?;
                    }
                }
                for (id, slot) in old.key_slots {
                    self.retained_slot(&old.device_id, scope.clone(), id, slot)?;
                }
                for (id, space) in old.spaces {
                    self.legacy_minimum(sources, &id, space.cursor_seq)?;
                    let scope = Scope::Space(id);
                    for (key, row) in space.records {
                        self.public(
                            scope.clone(),
                            Position::Retained,
                            &key,
                            self.rows.len(),
                            &row,
                        )?;
                    }
                    for (key, pending) in space.pending_approvals {
                        self.public(
                            scope.clone(),
                            Position::Retained,
                            &key,
                            self.rows.len(),
                            &LocalRecord {
                                record: pending.record.clone(),
                                seq: pending.seq,
                                dirty: false,
                            },
                        )?;
                        if !pending.record.deleted
                            && pending
                                .record
                                .payload
                                .get("text")
                                .and_then(serde_json::Value::as_str)
                                != Some(&pending.text)
                        {
                            let mut record = pending.record;
                            record.payload = serde_json::json!({"schema":1,"text":pending.text});
                            self.public(
                                scope.clone(),
                                Position::Retained,
                                &key,
                                self.rows.len(),
                                &LocalRecord {
                                    record,
                                    seq: pending.seq,
                                    dirty: false,
                                },
                            )?;
                        }
                    }
                    for declined in space.declined.values() {
                        self.legacy_minimum(
                            sources,
                            match &scope {
                                Scope::Space(id) => id,
                                _ => return Err(invalid()),
                            },
                            declined.seq,
                        )?;
                    }
                }
            }
            DecodedState::V3(_) => return Err(invalid()),
        }
        drop(self.admit_known()?);
        Ok(self)
    }
    fn retained_slot(
        &mut self,
        device: &str,
        scope: Scope,
        id: String,
        slot: state_v2::LocalSlot,
    ) -> Result<(), AppError> {
        let payload = slot.payload.ok_or_else(unavailable)?;
        if slot.file_name != crate::sync::slot_rules::slot_file_name(&payload.name, &id) {
            return Err(unavailable());
        }
        let row = LocalRecord {
            record: Record {
                kind: RecordKind::KeySlot,
                id,
                version: 1,
                updated_at_ms: payload.created_at_ms,
                device_id: device.into(),
                deleted: false,
                payload: serde_json::to_value(payload).map_err(|_| invalid())?,
            },
            seq: 0,
            dirty: false,
        };
        self.public(
            scope,
            Position::Retained,
            &record_key(row.record.kind, &row.record.id),
            self.rows.len(),
            &row,
        )
    }
    pub(in crate::sync::central) fn with_retained_envelopes(
        mut self,
        sources: &Sources,
        chain: &str,
        rows: Vec<crate::sync::record::Envelope>,
    ) -> Result<Self, AppError> {
        if self.keybook != super::super::super::crypto::hash(&sources.encode_local()?) {
            return Err(invalid());
        }
        self.legacy_minimum(
            sources,
            chain,
            rows.iter().map(|row| row.seq).max().unwrap_or(0),
        )?;
        for envelope in rows {
            let scope = if matches!(envelope.kind.as_str(), "host" | "group") {
                Scope::Space(chain.into())
            } else {
                Scope::Account(chain.into())
            };
            let row = state_v2::SealedRecord {
                envelope,
                dirty: false,
                public_identity: None,
            };
            self.sealed(
                sources,
                scope,
                Position::Retained,
                &row.key(),
                self.rows.len(),
                &row,
            )?;
        }
        drop(self.admit_known()?);
        Ok(self)
    }
    pub(in crate::sync::central) fn reconcile_captured(
        self,
        state: &SyncStateV3,
    ) -> Result<super::super::reconcile::Reconciliation, AppError> {
        if self.frozen_context.is_none() && (!self.frozen.is_empty() || !self.minima.is_empty()) {
            return Err(invalid());
        }
        super::super::reconcile::Reconciliation::from_complete(self, state)
    }
}

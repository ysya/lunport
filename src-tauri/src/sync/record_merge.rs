//! Reading a chain-era account section: the space keys sealed in it and the old alias/text host shape, and the account
//! `meta` payload central's migration sources decode. No network, filesystem, credential or vault access; unsupported records
//! remain encrypted.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;
use crate::sync::crypto::{self, ChainKeys, Sealed};

use crate::sync::record::{
    record_key, DevicePayload, Envelope, Record, RecordKind, SpacePayload, ACCOUNT_META_ID,
};
use crate::sync::records_v3::{
    decode_host, decode_keyslot, validate_migration_gate, HostScope, ACCOUNT_SCHEMA,
    MIN_ACCOUNT_SCHEMA,
};
use crate::sync::slot_rules::is_slot_id;
use crate::sync::state_v2::{sealed_key, AccountState};

pub use crate::sync::records_v3::MigrationGate;

// The relay stores JavaScript safe integers; invalid transport metadata must never poison cursors.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaPayloadV3 {
    pub schema_version: u32,
    pub created_by_app_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<MigrationGate>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCode {
    Unreadable,
    Unsupported,
    InvalidShape,
}

/// Successful decrypted JSON is zeroized on every exit, including unsupported schema/identity.
/// Public records are cloned only after typed admission; secret records never enter a section.
struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        clear_json(&mut self.0);
    }
}
struct OpenedRecord(Record);
impl Drop for OpenedRecord {
    fn drop(&mut self) {
        clear_json(&mut self.0.payload);
        self.0.id.zeroize();
        self.0.device_id.zeroize();
    }
}
fn clear_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(clear_json),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                clear_json(&mut value);
            }
        }
        _ => {}
    }
    *value = Value::Null;
}
fn failure() -> AppError {
    AppError::Other("typed sync record is invalid or unavailable".into())
}
fn open_record(keys: &ChainKeys, envelope: &Envelope) -> Result<OpenedRecord, DiagnosticCode> {
    let kind = RecordKind::parse(&envelope.kind).ok_or(DiagnosticCode::Unsupported)?;
    let sealed = Sealed {
        id_hash: envelope.id_hash.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    };
    let bytes = Zeroizing::new(
        crypto::open(keys, &envelope.kind, &envelope.id_hash, &sealed)
            .map_err(|_| DiagnosticCode::Unreadable)?,
    );
    // Construct the protection before checking required/unknown fields. A complete JSON payload
    // is cleared even when later header validation fails, without a second secret payload clone.
    let mut value = SensitiveJson(
        serde_json::from_slice::<Value>(&bytes).map_err(|_| DiagnosticCode::Unreadable)?,
    );
    let fields = value.0.as_object().ok_or(DiagnosticCode::InvalidShape)?;
    if fields.keys().any(|key| {
        ![
            "kind",
            "id",
            "version",
            "updated_at_ms",
            "device_id",
            "deleted",
            "payload",
        ]
        .contains(&key.as_str())
    }) {
        return Err(DiagnosticCode::Unsupported);
    }
    let wire_kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .and_then(RecordKind::parse)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let id = fields
        .get("id")
        .and_then(Value::as_str)
        .ok_or(DiagnosticCode::InvalidShape)?
        .to_string();
    let version = fields
        .get("version")
        .and_then(Value::as_u64)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let updated_at_ms = fields
        .get("updated_at_ms")
        .and_then(Value::as_u64)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let device_id = fields
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or(DiagnosticCode::InvalidShape)?
        .to_string();
    let deleted = fields
        .get("deleted")
        .and_then(Value::as_bool)
        .ok_or(DiagnosticCode::InvalidShape)?;
    let payload = std::mem::take(
        value
            .0
            .get_mut("payload")
            .ok_or(DiagnosticCode::InvalidShape)?,
    );
    let record = OpenedRecord(Record {
        kind: wire_kind,
        id,
        version,
        updated_at_ms,
        device_id,
        deleted,
        payload,
    });
    if record.0.kind != kind
        || record.0.deleted != envelope.deleted
        || crypto::id_hash(keys, kind.as_str(), &record.0.id) != envelope.id_hash
    {
        return Err(DiagnosticCode::InvalidShape);
    }
    Ok(record)
}

fn opened_secret(
    section: &AccountState,
    keys: &ChainKeys,
    kind: RecordKind,
    id: &str,
) -> Result<Option<OpenedRecord>, AppError> {
    if section.chain_id != keys.chain_id {
        return Err(failure());
    }
    if section.recovery.conflicts.contains_key(&sealed_key(
        kind.as_str(),
        &crypto::id_hash(keys, kind.as_str(), id),
    )) {
        return Err(failure());
    }
    let key = sealed_key(kind.as_str(), &crypto::id_hash(keys, kind.as_str(), id));
    let Some(sealed) = section.sealed.get(&key) else {
        return Ok(None);
    };
    let opened = open_record(keys, &sealed.envelope).map_err(|_| failure())?;
    if opened.0.kind != kind || opened.0.id != id || !valid_secret(&opened.0) {
        return Err(failure());
    }
    if opened.0.deleted {
        return Ok(None);
    }
    Ok(Some(opened))
}
fn live_metadata(
    section: &AccountState,
    keys: &ChainKeys,
    kind: RecordKind,
    id: &str,
) -> Result<bool, AppError> {
    if section.chain_id != keys.chain_id {
        return Err(failure());
    }
    let Some(row) = section.records.get(&record_key(kind, id)) else {
        return Ok(false);
    };
    if row.record.deleted {
        return Ok(false);
    }
    if !valid_public(&row.record, true, keys)
        || section
            .recovery
            .conflicts
            .contains_key(&record_key(kind, id))
        || section.sealed.contains_key(&sealed_key(
            kind.as_str(),
            &crypto::id_hash(keys, kind.as_str(), id),
        ))
    {
        return Err(failure());
    }
    Ok(true)
}
/// Transport credentials require a live, recognized public space. The caller still checks the
/// fresh account gate before any space request; only the intended live ChainKeys leaves this scope.
pub fn space_keys(
    section: &AccountState,
    keys: &ChainKeys,
    id: &str,
) -> Result<Option<ChainKeys>, AppError> {
    if !live_metadata(section, keys, RecordKind::Space, id)? {
        return Ok(None);
    }
    let Some(opened) = opened_secret(section, keys, RecordKind::SpaceKey, id)? else {
        return Ok(None);
    };
    let token = opened
        .0
        .payload
        .get("auth_token")
        .and_then(Value::as_str)
        .ok_or_else(failure)?;
    let encoded = opened
        .0
        .payload
        .get("enc_key")
        .and_then(Value::as_str)
        .ok_or_else(failure)?;
    ChainKeys::from_parts(id, token, encoded).map(Some)
}

/// Old alias/text hosts intentionally retained by migration are source evidence, not active hosts.
/// This recognizes only the old shape; callers must still reject an opaque shadow of a typed id.
pub(crate) fn is_legacy_alias_host(keys: &ChainKeys, envelope: &Envelope) -> bool {
    let Ok(opened) = open_record(keys, envelope) else {
        return false;
    };
    let Some(fields) = opened.0.payload.as_object() else {
        return false;
    };
    opened.0.kind == RecordKind::Host
        && !opened.0.deleted
        && fields.len() == 2
        && fields.get("schema").and_then(Value::as_u64) == Some(1)
        && fields.get("text").and_then(Value::as_str).is_some()
}

/// An account `meta` row this build understands: live, a supported schema, and a valid migration marker if it has one.
fn valid_meta(record: &Record) -> bool {
    if record.deleted {
        return false;
    }
    let Ok(meta) = serde_json::from_value::<MetaPayloadV3>(record.payload.clone()) else {
        return false;
    };
    (MIN_ACCOUNT_SCHEMA..=ACCOUNT_SCHEMA).contains(&meta.schema_version)
        && meta.migration.as_ref().is_none_or(|marker| validate_migration_gate(marker).is_ok())
}
fn valid_secret(record: &Record) -> bool {
    let id_valid = match record.kind {
        RecordKind::Key => is_slot_id(&record.id),
        RecordKind::SpaceKey => crypto::is_chain_id(&record.id),
        _ => false,
    };
    if !id_valid {
        return false;
    }
    if record.deleted {
        return record.payload.is_null()
            || record.payload.get("schema").and_then(Value::as_u64) == Some(1);
    }
    if record.payload.get("schema").and_then(Value::as_u64) != Some(1) {
        return false;
    }
    match record.kind {
        RecordKind::Key => record
            .payload
            .get("private_key")
            .and_then(Value::as_str)
            .is_some_and(|text| !text.is_empty() && text.len() <= 16 * 1024),
        RecordKind::SpaceKey => {
            let token = record.payload.get("auth_token").and_then(Value::as_str);
            let encoded = record.payload.get("enc_key").and_then(Value::as_str);
            token.is_some_and(crypto::is_chain_id)
                && encoded
                    .and_then(|text| B64.decode(text).ok())
                    .map(Zeroizing::new)
                    .is_some_and(|bytes| bytes.len() == 32)
        }
        _ => false,
    }
}
fn valid_public(record: &Record, account: bool, keys: &ChainKeys) -> bool {
    if account {
        match record.kind {
            RecordKind::Meta if record.id == ACCOUNT_META_ID => valid_meta(record),
            RecordKind::Meta if record.id == crate::sync::group_order::RECORD_ID => {
                crate::sync::group_order::decode(record).is_some()
            }
            RecordKind::Meta if crate::sync::tunnel_rules::is_id(&record.id) => crate::sync::tunnel_rules::valid(record),
            RecordKind::KeySlot => {
                decode_keyslot(record).is_ok()
                    && (!record.deleted
                        || record.payload.is_null()
                        || record.payload.get("schema").and_then(Value::as_u64) == Some(2))
            }
            RecordKind::Space => {
                crypto::is_chain_id(&record.id)
                    && (record.deleted && record.payload.is_null()
                        || serde_json::from_value::<SpacePayload>(record.payload.clone())
                            .is_ok_and(|payload| {
                                payload.schema == 1
                                    && !payload.name.trim().is_empty()
                                    && payload
                                        .previous_id
                                        .as_deref()
                                        .is_none_or(crypto::is_chain_id)
                            }))
            }
            RecordKind::Device => {
                is_slot_id(&record.id)
                    && (record.deleted && record.payload.is_null()
                        || serde_json::from_value::<DevicePayload>(record.payload.clone())
                            .is_ok_and(|payload| {
                                payload.schema == 1
                                    && payload.spaces.iter().all(|id| crypto::is_chain_id(id))
                            }))
            }
            _ => false,
        }
    } else if record.kind == RecordKind::Group {
        crate::sync::records_v3::decode_group(
            record,
            HostScope::Space {
                space_id: keys.chain_id.clone(),
            },
        )
        .is_ok()
            && (!record.deleted || record.payload.is_null())
    } else {
        decode_host(
            record,
            HostScope::Space {
                space_id: keys.chain_id.clone(),
            },
        )
        .is_ok()
            && (!record.deleted
                || record.payload.is_null()
                || record.payload.get("schema").and_then(Value::as_u64) == Some(2))
    }
}

#[cfg(test)]
#[path = "record_merge_tests.rs"]
mod tests;

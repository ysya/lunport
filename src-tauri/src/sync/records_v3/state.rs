use super::*;
use crate::sync::crypto::is_chain_id;
use crate::sync::record::{record_key, LocalRecord, MetaPayload, RecordKind, ACCOUNT_META_ID};
use crate::sync::slot_rules::is_slot_id;
use crate::sync::state::SyncState;
use crate::sync::state_v2::{
    AccountState, RelayFeatures, RotationProgress, SealedRecord, SyncNotice, SyncStateV2,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Passive data only; SyncCore must remain the one runtime owner when a later plan activates this model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncStateV3 {
    pub version: u32,
    pub device_id: String,
    pub device_name: String,
    pub relay_url: String,
    #[serde(default)]
    pub account: Option<AccountState>,
    #[serde(default)]
    pub spaces: BTreeMap<String, SpaceStateV3>,
    #[serde(default)]
    pub local: LocalState,
    #[serde(default)]
    pub rotation: Option<RotationProgress>,
    #[serde(default)]
    pub relay_features: Option<RelayFeatures>,
    #[serde(default)]
    pub legacy_v1_backup: Option<String>,
    #[serde(default)]
    pub phrase_cleanup_pending: bool,
    #[serde(default)]
    pub notices: Vec<SyncNotice>,
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalState {
    #[serde(default)]
    pub hosts: BTreeMap<String, LocalRecord>,
    #[serde(default)]
    pub keys: BTreeMap<String, LocalKeyMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalKeyMetadata {
    pub vault_id: String,
    pub public: KeySlotPayload,
}

/// No file_name or slot maintenance; unknown sealed envelopes are retained without opening them.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceStateV3 {
    pub selected: bool,
    pub cursor_seq: u64,
    #[serde(default)]
    pub baseline_established: bool,
    #[serde(default)]
    pub records: BTreeMap<String, LocalRecord>,
    #[serde(default)]
    pub sealed: BTreeMap<String, SealedRecord>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub missing: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DecodedState {
    V1(Box<SyncState>),
    V2(Box<SyncStateV2>),
    V3(Box<SyncStateV3>),
}
/// Decode in memory only. The caller retains the original bytes on any error, including newer versions.
pub fn decode_state(text: &str) -> Result<DecodedState, RecordValidationError> {
    #[derive(Deserialize)]
    struct Probe {
        version: u32,
    }
    let version = serde_json::from_str::<Probe>(text)
        .map_err(state_decode_error)?
        .version;
    match version {
        1 => serde_json::from_str(text)
            .map(DecodedState::V1)
            .map_err(state_decode_error),
        2 => serde_json::from_str(text)
            .map(DecodedState::V2)
            .map_err(state_decode_error),
        STATE_VERSION => {
            let state = serde_json::from_str(text).map_err(state_decode_error)?;
            validate_state(&state)?;
            Ok(DecodedState::V3(Box::new(state)))
        }
        found => Err(RecordValidationError::UnsupportedSchema {
            kind: "state",
            found,
        }),
    }
}
fn state_decode_error(error: serde_json::Error) -> RecordValidationError {
    RecordValidationError::Decode {
        kind: "state",
        reason: error.to_string(),
    }
}
fn state_invalid(field: &'static str, id: &str, reason: &str) -> RecordValidationError {
    RecordValidationError::Invalid {
        field,
        id: id.into(),
        reason: reason.into(),
    }
}

pub fn validate_state(state: &SyncStateV3) -> Result<(), RecordValidationError> {
    if state.version != STATE_VERSION {
        return Err(RecordValidationError::UnsupportedSchema {
            kind: "state",
            found: state.version,
        });
    }
    if !is_slot_id(&state.device_id) {
        return Err(state_invalid(
            "device_id",
            &state.device_id,
            "expected a device id",
        ));
    }
    if state.account.is_none() && !state.spaces.is_empty() {
        return Err(state_invalid(
            "spaces",
            "state",
            "spaces require an account",
        ));
    }
    read_hosts(&state.local.hosts, HostScope::Local)?;
    for (id, material) in &state.local.keys {
        validate_keyslot(id, &material.public)?;
        if !is_slot_id(&material.vault_id) {
            return Err(state_invalid("vault_id", id, "expected a vault id"));
        }
    }
    for (space_id, space) in &state.spaces {
        if !is_chain_id(space_id) {
            return Err(state_invalid("space_id", space_id, "expected a chain id"));
        }
        read_hosts(
            &space.records,
            HostScope::Space {
                space_id: space_id.clone(),
            },
        )?;
        validate_sealed(&space.sealed)?;
    }
    if let Some(account) = &state.account {
        if !is_chain_id(&account.chain_id) {
            return Err(state_invalid(
                "chain_id",
                &account.chain_id,
                "expected an account chain id",
            ));
        }
        for (key, local) in &account.records {
            validate_cache_key(key, local)?;
            let record = &local.record;
            match record.kind {
                RecordKind::KeySlot => {
                    decode_keyslot(record)?;
                }
                RecordKind::Meta if record.id == ACCOUNT_META_ID && !record.deleted => {
                    let meta: MetaPayload = serde_json::from_value(record.payload.clone())
                        .map_err(state_decode_error)?;
                    validate_account_meta(&meta)?;
                }
                RecordKind::Host => {
                    return Err(RecordValidationError::WrongKind {
                        expected: "account metadata",
                        found: "host".into(),
                    })
                }
                _ => {}
            }
        }
        validate_sealed(&account.sealed)?;
    }
    Ok(())
}

fn validate_cache_key(key: &str, local: &LocalRecord) -> Result<(), RecordValidationError> {
    if local.record.kind.is_secret() {
        return Err(state_invalid(
            "records",
            local.record.kind.as_str(),
            "secret records must remain sealed",
        ));
    }
    if key != record_key(local.record.kind, &local.record.id) {
        return Err(state_invalid(
            "record_key",
            &local.record.id,
            "cache key does not match kind and id",
        ));
    }
    Ok(())
}
fn read_hosts(
    records: &BTreeMap<String, LocalRecord>,
    scope: HostScope,
) -> Result<(), RecordValidationError> {
    for (key, local) in records {
        validate_cache_key(key, local)?;
        decode_host(&local.record, scope.clone())?;
    }
    Ok(())
}
fn validate_sealed(sealed: &BTreeMap<String, SealedRecord>) -> Result<(), RecordValidationError> {
    for (key, record) in sealed {
        if key
            != &crate::sync::state_v2::sealed_key(&record.envelope.kind, &record.envelope.id_hash)
        {
            return Err(state_invalid(
                "sealed_key",
                &record.envelope.id_hash,
                "cache key does not match envelope",
            ));
        }
    }
    Ok(())
}

pub fn account_meta(app_version: &str) -> MetaPayload {
    MetaPayload {
        schema_version: ACCOUNT_SCHEMA,
        created_by_app_version: app_version.into(),
    }
}
pub fn validate_account_meta(meta: &MetaPayload) -> Result<(), RecordValidationError> {
    if meta.schema_version != ACCOUNT_SCHEMA {
        return Err(RecordValidationError::UnsupportedSchema {
            kind: "account",
            found: meta.schema_version,
        });
    }
    Ok(())
}

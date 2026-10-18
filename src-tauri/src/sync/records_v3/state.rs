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
    /// Authenticated pending migration blocks shared writes even though schema 3 is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_gate: Option<MigrationGate>,
    /// Shared writes remain blocked until a fresh authenticated compatible account pull.
    #[serde(default)]
    pub shared_writes_blocked: bool,
    /// Resumable account operations contain only public metadata and sealed records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_account: Option<crate::sync::record_account::PendingAccountOperation>,
    #[serde(default)]
    pub notices: Vec<SyncNotice>,
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalState {
    /// Public control proofs and ciphertext only; native credentials remain in OS storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub central: Option<crate::sync::central::workspace::Workspace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_order: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub groups: BTreeMap<String, LocalRecord>,
    #[serde(default)]
    pub hosts: BTreeMap<String, LocalRecord>,
    #[serde(default)]
    pub keys: BTreeMap<String, LocalKeyMetadata>,
    /// Published atomically with an import overlay; retries preserve subsequent edits/deletions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub import_receipts: BTreeMap<String, LocalImportReceipt>,
    /// Local human approvals only; never published as synchronized records.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credential_approvals: BTreeMap<String, CredentialApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialApproval {
    pub device_id: String,
    pub scope: HostScope,
    pub account_id: Option<String>,
    pub relay_url: Option<String>,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalKeyMetadata {
    pub vault_id: String,
    pub public: KeySlotPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalImportReceipt {
    pub source_digest: String,
    pub host_ids: Vec<String>,
    pub key_ids: Vec<String>,
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
    #[serde(default, skip_serializing_if = "crate::sync::record_conflicts::RecordRecovery::is_empty")]
    pub recovery: crate::sync::record_conflicts::RecordRecovery,
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
        STATE_VERSION | GROUP_STATE_VERSION | NAVIGATION_STATE_VERSION | LOCAL_CREDENTIAL_STATE_VERSION | LOCAL_CONFLICT_STATE_VERSION | CENTRAL_STATE_VERSION => {
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

pub fn validate_migration_gate(gate: &MigrationGate) -> Result<(), RecordValidationError> {
    if !is_slot_id(&gate.id) {
        return Err(state_invalid(
            "migration_id",
            "migration",
            "expected 32 lowercase hex characters",
        ));
    }
    if !is_chain_id(&gate.source_digest) {
        return Err(state_invalid(
            "source_digest",
            "migration",
            "expected a SHA-256 digest",
        ));
    }
    Ok(())
}
/// A separately observed marker survives unchanged account caches and cursors.
pub fn account_migration_pending(state: &SyncStateV3) -> bool {
    if state
        .migration_gate
        .as_ref()
        .is_some_and(|gate| gate.phase != MigrationPhase::Active)
    {
        return true;
    }
    state
        .account
        .as_ref()
        .and_then(|account| {
            account
                .records
                .get(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        })
        .filter(|local| !local.record.deleted)
        .and_then(|local| local.record.payload.get("migration"))
        .filter(|value| !value.is_null())
        .is_some_and(|value| {
            serde_json::from_value::<MigrationGate>(value.clone())
                .map_or(true, |gate| gate.phase != MigrationPhase::Active)
        })
}

/// Only a new authenticated compatible account pull can clear the durable write gate.
pub fn account_writes_blocked(state: &SyncStateV3) -> bool {
    state.pending_account.is_some()
        || state.shared_writes_blocked
        || account_migration_pending(state)
        || state.account.as_ref().is_some_and(|a| {
            a.frozen.is_some()
                || a.remote_schema_version
                    .is_some_and(|version| version > ACCOUNT_SCHEMA)
        })
}

pub fn validate_state(state: &SyncStateV3) -> Result<(), RecordValidationError> {
    if let Some(central) = &state.local.central {
        if state.version < CENTRAL_STATE_VERSION || central.validate().is_err() {
            return Err(state_invalid("central","local","central state needs schema 8 and a verified anchored replica"));
        }
    }

    if !state.local.credential_approvals.is_empty() && state.version < LOCAL_CREDENTIAL_STATE_VERSION {
        return Err(state_invalid("credential_approvals", "local", "local credential approvals need state version 6"));
    }
    if !matches!(
        state.version,
        STATE_VERSION | GROUP_STATE_VERSION | NAVIGATION_STATE_VERSION | LOCAL_CREDENTIAL_STATE_VERSION | LOCAL_CONFLICT_STATE_VERSION | CENTRAL_STATE_VERSION
    ) {
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
    if let Some(gate) = &state.migration_gate {
        if state.account.is_none() {
            return Err(state_invalid(
                "migration_gate",
                "state",
                "a migration gate requires an account",
            ));
        }
        validate_migration_gate(gate)?;
    }
    if state.shared_writes_blocked && state.account.is_none() {
        return Err(state_invalid(
            "shared_writes_blocked",
            "state",
            "a shared write gate requires an account",
        ));
    }
    if let Some(operation) = &state.pending_account {
        crate::sync::record_account::validate_pending(operation).map_err(|_| {
            state_invalid(
                "pending_account",
                "state",
                "invalid pending account operation",
            )
        })?;
        let mut prepared = state.clone();
        prepared.pending_account = None;
        prepared.account = Some(operation.prepared_account.clone());
        prepared.spaces.clear();
        if let (Some(id), Some(space)) = (&operation.space_id, &operation.prepared_space) {
            prepared.spaces.insert(id.clone(), space.clone());
        }
        validate_state(&prepared)?;
    }
    if !crate::sync::group_order::valid_ids(&state.local.group_order)
        || !state.local.group_order.is_empty() && state.version < NAVIGATION_STATE_VERSION
    {
        return Err(state_invalid(
            "group_order",
            "local",
            "invalid navigation format",
        ));
    }
    read_hosts(&state.local.hosts, HostScope::Local)?;
    for (key, row) in &state.local.groups {
        validate_cache_key(key, row)?;
        decode_group(&row.record, HostScope::Local)?;
    }
    if state.version == STATE_VERSION
        && (!state.local.groups.is_empty()
            || state
                .local
                .hosts
                .values()
                .chain(state.spaces.values().flat_map(|s| s.records.values()))
                .any(|r| {
                    r.record.kind == RecordKind::Group
                        || r.record
                            .payload
                            .get("schema")
                            .and_then(serde_json::Value::as_u64)
                            == Some(3)
                }))
    {
        return Err(state_invalid(
            "version",
            "state",
            "groups require state version 4",
        ));
    }
    for (id, material) in &state.local.keys {
        validate_keyslot(id, &material.public)?;
        if !is_slot_id(&material.vault_id) {
            return Err(state_invalid("vault_id", id, "expected a vault id"));
        }
    }
    for (id, receipt) in &state.local.import_receipts {
        if !is_slot_id(id)
            || !is_chain_id(&receipt.source_digest)
            || receipt.host_ids.iter().any(|id| !super::is_host_id(id))
            || receipt.key_ids.iter().any(|id| !is_slot_id(id))
        {
            return Err(state_invalid(
                "import_receipt",
                "state",
                "invalid import receipt identity",
            ));
        }
    }
    for (space_id, space) in &state.spaces {
        validate_recovery(state.version, &space.recovery)?;
        if !is_chain_id(space_id) {
            return Err(state_invalid("space_id", space_id, "expected a chain id"));
        }
        read_hosts(
            &space.records,
            HostScope::Space {
                space_id: space_id.clone(),
            },
        )?;
        validate_sealed(&space.sealed, false)?;
    }
    if let Some(account) = &state.account {
        validate_recovery(state.version, &account.recovery)?;
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
                RecordKind::Meta if record.id == crate::sync::group_order::RECORD_ID => {
                    if crate::sync::group_order::decode(record).is_none() {
                        return Err(state_invalid(
                            "group_order",
                            &record.id,
                            "invalid navigation metadata",
                        ));
                    }
                }
                RecordKind::Meta if record.id == ACCOUNT_META_ID && !record.deleted => {
                    let meta: MetaPayload = serde_json::from_value(record.payload.clone())
                        .map_err(state_decode_error)?;
                    validate_account_meta(&meta)?;
                    if let Some(value) = record
                        .payload
                        .get("migration")
                        .filter(|value| !value.is_null())
                    {
                        let gate: MigrationGate =
                            serde_json::from_value(value.clone()).map_err(|_| {
                                RecordValidationError::Decode {
                                    kind: "migration",
                                    reason: "migration marker is invalid".into(),
                                }
                            })?;
                        validate_migration_gate(&gate)?;
                    }
                }
                RecordKind::Host | RecordKind::Group => {
                    return Err(RecordValidationError::WrongKind {
                        expected: "account metadata",
                        found: "host".into(),
                    })
                }
                _ => {}
            }
        }
        validate_sealed(&account.sealed, true)?;
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
        if local.record.kind == RecordKind::Group {
            decode_group(&local.record, scope.clone())?;
        } else {
            decode_host(&local.record, scope.clone())?;
        }
    }
    Ok(())
}
fn validate_sealed(
    sealed: &BTreeMap<String, SealedRecord>,
    account: bool,
) -> Result<(), RecordValidationError> {
    for (key, record) in sealed {
        if let Some(hint) = &record.public_identity {
            if !hint.is_valid_for(&record.envelope)
                || !matches!(
                    (account, record.envelope.kind.as_str()),
                    (true, "keyslot" | "meta") | (false, "host" | "group")
                )
            {
                return Err(state_invalid(
                    "public_identity",
                    "sealed",
                    "invalid public ordering evidence",
                ));
            }
        }
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
        schema_version: MIN_ACCOUNT_SCHEMA,
        created_by_app_version: app_version.into(),
    }
}
pub fn validate_account_meta(meta: &MetaPayload) -> Result<(), RecordValidationError> {
    if !(MIN_ACCOUNT_SCHEMA..=ACCOUNT_SCHEMA).contains(&meta.schema_version) {
        return Err(RecordValidationError::UnsupportedSchema {
            kind: "account",
            found: meta.schema_version,
        });
    }
    Ok(())
}

fn validate_recovery(version: u32, recovery: &crate::sync::record_conflicts::RecordRecovery) -> Result<(), RecordValidationError> {
    if !recovery.valid() || !recovery.conflicts.is_empty() && version < LOCAL_CONFLICT_STATE_VERSION {
        return Err(state_invalid("recovery", "state", "invalid or unsupported conflict recovery state"));
    }
    Ok(())
}

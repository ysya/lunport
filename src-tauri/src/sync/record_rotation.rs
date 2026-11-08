//! The rotation plan a chain-era `pending_account` can still carry (decoded from an old state file) and its validation.
use crate::error::AppError;
use crate::sync::{
    crypto,
    record::{record_key, RecordKind, ACCOUNT_META_ID},
    record_account::PendingAccountOperation,
    records_v3::{self, MigrationGate, MigrationPhase, SpaceStateV3},
    state_v2::AccountState,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const SOURCE_CODE_PREFIX: &str = "sync:records-rotation-source:";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStep {
    Prepared,
    Freezing,
    Copying,
    Activating,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPlan {
    pub step: RotationStep,
    pub source_code_account: String,
    pub source_account: AccountState,
    pub source_spaces: BTreeMap<String, SpaceStateV3>,
    pub space_ids: BTreeMap<String, String>,
    pub target_spaces: BTreeMap<String, SpaceStateV3>,
    pub frozen: BTreeSet<String>,
    pub created: BTreeSet<String>,
    pub source_digest: String,
}
fn error(s: &str) -> AppError {
    AppError::Other(s.into())
}
fn minimal(
    account: AccountState,
    spaces: BTreeMap<String, SpaceStateV3>,
    device: &str,
) -> records_v3::SyncStateV3 {
    records_v3::SyncStateV3 {
        version: records_v3::GROUP_STATE_VERSION,
        device_id: device.into(),
        device_name: "rotation validation".into(),
        relay_url: crate::sync::state::DEFAULT_RELAY_URL.into(),
        account: Some(account),
        spaces,
        local: Default::default(),
        rotation: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        migration_gate: None,
        shared_writes_blocked: false,
        pending_account: None,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    }
}
pub fn validate_plan(op: &PendingAccountOperation) -> Result<(), AppError> {
    let p = op
        .rotation
        .as_ref()
        .ok_or_else(|| error("rotation plan missing"))?;
    if p.source_code_account != format!("{SOURCE_CODE_PREFIX}{}", op.id)
        || p.source_account.chain_id == op.prepared_account.chain_id
        || !crypto::is_chain_id(&p.source_digest)
        || p.space_ids
            .iter()
            .any(|(a, b)| !crypto::is_chain_id(a) || !crypto::is_chain_id(b) || a == b)
        || p.space_ids.values().collect::<BTreeSet<_>>().len() != p.space_ids.len()
        || p.created
            .iter()
            .any(|id| id != &op.prepared_account.chain_id && !p.space_ids.values().any(|v| v == id))
        || p.frozen
            .iter()
            .any(|id| id != &p.source_account.chain_id && !p.space_ids.contains_key(id))
    {
        return Err(error("invalid rotation identity or receipt"));
    }
    if matches!(p.step, RotationStep::Copying | RotationStep::Activating) {
        if p.source_spaces.keys().collect::<BTreeSet<_>>()
            != p.space_ids.keys().collect::<BTreeSet<_>>()
            || p.target_spaces.keys().collect::<BTreeSet<_>>()
                != p.space_ids.values().collect::<BTreeSet<_>>()
            || !p.frozen.contains(&p.source_account.chain_id)
            || p.source_spaces.keys().any(|id| !p.frozen.contains(id))
        {
            return Err(error("incomplete frozen source or destination plan"));
        }
        let meta = op
            .prepared_account
            .records
            .get(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
            .ok_or_else(|| error("rotation metadata missing"))?;
        let m: MigrationGate = serde_json::from_value(meta.record.payload["migration"].clone())
            .map_err(|_| error("rotation marker missing"))?;
        if m.id != op.id
            || m.source_digest != p.source_digest
            || m.phase
                != if p.step == RotationStep::Activating {
                    MigrationPhase::Active
                } else {
                    MigrationPhase::Publishing
                }
        {
            return Err(error("rotation marker does not match the durable phase"));
        }
    }
    let device = op
        .prepared_account
        .records
        .values()
        .next()
        .or_else(|| p.source_account.records.values().next())
        .map(|r| r.record.device_id.as_str())
        .unwrap_or("00000000000000000000000000000001");
    records_v3::validate_state(&minimal(
        p.source_account.clone(),
        p.source_spaces.clone(),
        device,
    ))
    .map_err(|_| error("invalid rotation source"))?;
    records_v3::validate_state(&minimal(
        op.prepared_account.clone(),
        p.target_spaces.clone(),
        device,
    ))
    .map_err(|_| error("invalid rotation target"))?;
    if p.target_spaces
        .keys()
        .any(|id| !p.space_ids.values().any(|v| v == id))
    {
        return Err(error("invalid target space mapping"));
    }
    Ok(())
}

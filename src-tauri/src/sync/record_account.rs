//! Active record account lifecycle. Pending operations contain public metadata and ciphertext only.

use crate::error::AppError;
use crate::sync::records_v3::SpaceStateV3;
use crate::sync::state_v2::AccountState;
use serde::{Deserialize, Serialize};

pub const PENDING_CODE_PREFIX: &str = "sync:records-pending:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingAccountKind {
    CreateAccount,
    JoinAccount,
    CreateSpace,
    LeaveAccount,
    RotateAccount,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingAccountPhase {
    Prepared,
    RemoteCreated,
    Publishing,
    ActivationReady,
    Activated,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAccountOperation {
    pub id: String,
    pub device_name: String,
    pub kind: PendingAccountKind,
    pub phase: PendingAccountPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_gate: Option<crate::sync::records_v3::MigrationGate>,
    pub relay_url: String,
    /// This is only an operation-specific Keychain account name, never a mnemonic.
    pub staged_code_account: Option<String>,
    pub prepared_account: AccountState,
    pub space_id: Option<String>,
    pub prepared_space: Option<SpaceStateV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leave: Option<crate::sync::record_leave::LeavePlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<crate::sync::record_rotation::RotationPlan>,
}

pub fn validate_pending(op: &PendingAccountOperation) -> Result<(), AppError> {
    let invalid = || AppError::Other("invalid pending record account operation".into());
    if !crate::sync::slot_rules::is_slot_id(&op.id)
        || op.device_name.trim() != op.device_name
        || op.device_name.is_empty()
        || op.device_name.len() > 128
        || !crate::sync::crypto::is_chain_id(&op.prepared_account.chain_id)
        || crate::sync::relay::validate_url(&op.relay_url).is_err()
    {
        return Err(invalid());
    }
    if let Some(marker) = &op.migration_gate {
        crate::sync::records_v3::validate_migration_gate(marker).map_err(|_| invalid())?;
    }
    if op.kind != PendingAccountKind::LeaveAccount && op.leave.is_some() {
        return Err(invalid());
    }
    if op.kind != PendingAccountKind::RotateAccount && op.rotation.is_some() {
        return Err(invalid());
    }
    match op.kind {
        PendingAccountKind::CreateAccount | PendingAccountKind::JoinAccount => {
            if op.staged_code_account.as_deref()
                != Some(format!("{PENDING_CODE_PREFIX}{}", op.id).as_str())
                || op.space_id.is_some()
                || op.prepared_space.is_some()
            {
                return Err(invalid());
            }
        }
        PendingAccountKind::RotateAccount => {
            if op.staged_code_account.as_deref()
                != Some(format!("{PENDING_CODE_PREFIX}{}", op.id).as_str())
                || op.space_id.is_some()
                || op.prepared_space.is_some()
                || op.leave.is_some()
            {
                return Err(invalid());
            }
            crate::sync::record_rotation::validate_plan(op)?;
        }
        PendingAccountKind::LeaveAccount => {
            if op.staged_code_account.is_some()
                || op.space_id.is_some()
                || op.prepared_space.is_some()
            {
                return Err(invalid());
            }
            crate::sync::record_leave::validate_plan(op.leave.as_ref().ok_or_else(invalid)?)?;
        }
        PendingAccountKind::CreateSpace => {
            if op.staged_code_account.is_some()
                || !op
                    .space_id
                    .as_deref()
                    .is_some_and(crate::sync::crypto::is_chain_id)
                || op.prepared_space.is_none()
            {
                return Err(invalid());
            }
        }
    }
    for (key, row) in &op.prepared_account.records {
        if row.record.kind.is_secret()
            || *key != crate::sync::record::record_key(row.record.kind, &row.record.id)
        {
            return Err(invalid());
        }
    }
    for (key, row) in &op.prepared_account.sealed {
        if *key != crate::sync::state_v2::sealed_key(&row.envelope.kind, &row.envelope.id_hash) {
            return Err(invalid());
        }
    }
    Ok(())
}

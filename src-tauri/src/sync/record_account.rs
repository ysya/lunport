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
}

pub fn validate_pending(op: &PendingAccountOperation) -> Result<(), AppError> {
    let invalid = || AppError::Other("invalid pending record account operation".into());
    if !crate::sync::slot_rules::is_slot_id(&op.id)
        || op.device_name.trim() != op.device_name
        || op.device_name.is_empty()
        || op.device_name.len() > 128
        || !crate::sync::crypto::is_chain_id(&op.prepared_account.chain_id)
        || crate::sync::relay::RelayClient::validate_url(&op.relay_url).is_err()
    {
        return Err(invalid());
    }
    if let Some(marker) = &op.migration_gate {
        crate::sync::records_v3::validate_migration_gate(marker).map_err(|_| invalid())?;
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

pub struct AccountCreation {
    pub code: zeroize::Zeroizing<String>,
    pub operation_id: String,
    pub complete: bool,
    pub pending_error: Option<String>,
}
impl std::fmt::Debug for AccountCreation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountCreation")
            .field("operation_id", &self.operation_id)
            .field("complete", &self.complete)
            .field("pending_error", &self.pending_error)
            .finish_non_exhaustive()
    }
}
use crate::sync::crypto::{self, ChainKeys};
use crate::sync::env::SyncEnv;
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind, ACCOUNT_META_ID};
use crate::sync::record_merge::{self, AccountGate};
use crate::sync::record_runtime;
use crate::sync::records_v3::{self, KeySlotPayload};

use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::sealed_key;
use serde_json::json;
use zeroize::Zeroizing;
fn failure(message: &str) -> AppError {
    AppError::Other(message.into())
}
fn new_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| failure("cannot create operation identity"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn clean_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(failure("record name must have 1 to 128 bytes"));
    }
    Ok(name.into())
}
fn row(
    state: &records_v3::SyncStateV3,
    kind: RecordKind,
    id: &str,
    payload: serde_json::Value,
    now: u64,
) -> Record {
    Record {
        kind,
        id: id.into(),
        version: 1,
        updated_at_ms: now,
        device_id: state.device_id.clone(),
        deleted: false,
        payload,
    }
}
fn insert_public(account: &mut AccountState, record: Record) {
    account.records.insert(
        record_key(record.kind, &record.id),
        LocalRecord {
            record,
            seq: 0,
            dirty: true,
        },
    );
}
fn plan_device(
    state: &records_v3::SyncStateV3,
    account: &mut AccountState,
    name: &str,
    now: u64,
) -> Result<(), AppError> {
    let previous = account
        .records
        .get(&record_key(RecordKind::Device, &state.device_id));
    let version = previous
        .map(|r| r.record.version)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| failure("device revision exhausted"))?;
    let timestamp = match previous {
        Some(row) => row
            .record
            .updated_at_ms
            .checked_add(1)
            .ok_or_else(|| failure("device timestamp exhausted"))?
            .max(now),
        None => now,
    };
    let mut record = row(
        state,
        RecordKind::Device,
        &state.device_id,
        json!({"schema":1,"name":name,"platform":std::env::consts::OS,"joined_at_ms":now,"last_seen_ms":now,"keys":[],"spaces":state.spaces.iter().filter(|(_,s)|s.selected&&!s.missing).map(|(id,_)|id.clone()).collect::<Vec<_>>()}),
        timestamp,
    );
    record.version = version;
    let seq = previous.map(|r| r.seq).unwrap_or(0);
    account.records.insert(
        record_key(record.kind, &record.id),
        LocalRecord {
            record,
            seq,
            dirty: true,
        },
    );
    Ok(())
}
fn ensure_empty(state: &records_v3::SyncStateV3) -> Result<(), AppError> {
    if state.account.is_some() {
        return Err(failure("this record workspace already has an account"));
    }
    if state.pending_account.is_some() {
        return Err(failure("finish the pending record account operation first"));
    }
    Ok(())
}
fn ensure_shared(state: &records_v3::SyncStateV3) -> Result<(), AppError> {
    if state.account.is_none() {
        return Err(failure("join or create a record account first"));
    }
    if records_v3::account_writes_blocked(state) || state.rotation.is_some() {
        return Err(failure("record account shared writes are blocked"));
    }
    Ok(())
}
fn save_pending(env: &SyncEnv, op: PendingAccountOperation) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |latest| {
        if latest.relay_url != op.relay_url {
            return Err(crate::sync::runtime::superseded());
        }
        if latest
            .pending_account
            .as_ref()
            .is_some_and(|old| old.id != op.id)
        {
            return Err(failure("another record operation is pending"));
        }
        let mut next = latest.clone();
        next.pending_account = Some(op);
        Ok(next)
    })
    .map(|_| ())
}
fn pending(env: &SyncEnv) -> Result<PendingAccountOperation, AppError> {
    record_runtime::snapshot(env)?
        .0
        .pending_account
        .ok_or_else(|| failure("no record account operation is pending"))
}
fn replace_pending(
    env: &SyncEnv,
    op: PendingAccountOperation,
    accepted: bool,
) -> Result<(), AppError> {
    if !accepted {
        return save_pending(env, op);
    }
    // Acknowledged remote effects are retained in memory even when their disk receipt cannot be saved.
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(reason) = &core.save_blocked {
        return Err(failure(reason));
    }
    let latest = record_runtime::active_state(&core)?;
    if latest.pending_account.as_ref().map(|old| old.id.as_str()) != Some(op.id.as_str())
        || latest.relay_url != op.relay_url
    {
        return Err(crate::sync::runtime::superseded());
    }
    let mut next = latest.clone();
    next.pending_account = Some(op);
    records_v3::validate_state(&next)
        .map_err(|_| failure("cannot retain invalid pending receipt"))?;
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| failure("record state generation exhausted"))?;
    core.records = Some(next);
    core.generation = generation;
    crate::sync::runtime::save_core(&mut core, &env.state_path)
}
fn gate_error(gate: &AccountGate) -> AppError {
    failure(match gate {
        AccountGate::NeedsMigration { .. } => {
            "this account needs explicit migration before joining records mode"
        }
        AccountGate::NeedsUpdate { .. } => "this account uses a newer format; update SSHelter",
        AccountGate::MigrationPending(_) => "this account migration is still being published",
        _ => "this record account is not writable",
    })
}
fn observe_pending_gate(
    env: &SyncEnv,
    op: &PendingAccountOperation,
    gate: &AccountGate,
    schema: Option<u32>,
) -> Result<(), AppError> {
    let _publication = env.runtime.format_publication.lock().unwrap();
    let result = record_runtime::mutate_records(env, |latest| {
        if latest.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str()) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next = latest.clone();
        let marker = match gate {
            AccountGate::MigrationPending(marker) => Some(marker.clone()),
            _ => None,
        };
        next.pending_account.as_mut().unwrap().migration_gate = marker.clone();
        if next.account.is_some() {
            next.shared_writes_blocked = true;
            next.migration_gate = marker;
        }
        next.last_error = Some(gate_error(gate).to_string());
        if let Some(schema) = schema.filter(|schema| *schema > records_v3::ACCOUNT_SCHEMA) {
            next.pending_account
                .as_mut()
                .unwrap()
                .prepared_account
                .remote_schema_version = Some(schema);
        }
        Ok(next)
    });
    if let Err(e) = result {
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(state) = core
            .records
            .as_mut()
            .filter(|s| s.pending_account.as_ref().is_some_and(|p| p.id == op.id))
        {
            state.shared_writes_blocked = true;
            core.save_blocked =
                Some("pending authenticated account gate could not be saved".into());
        }
        return Err(e);
    }
    Err(gate_error(gate))
}
fn target_pull(
    env: &SyncEnv,
    op: &PendingAccountOperation,
    keys: &ChainKeys,
) -> Result<AccountState, AppError> {
    crate::sync::record_round::preflight(env)?;
    let relay = env.relay(&op.relay_url)?;
    let pulled = relay.pull(&keys.chain_id, &keys.auth_token, 0)?;
    let mut empty = AccountState::new(&keys.chain_id);
    empty.remote_schema_version = op.prepared_account.remote_schema_version;
    let fresh = record_merge::merge_account(&empty, keys, &pulled, 0);
    let new_empty = op.kind == PendingAccountKind::CreateAccount
        && pulled.records.is_empty()
        && matches!(fresh.gate,AccountGate::NeedsMigration{schema} if schema<=records_v3::ACCOUNT_SCHEMA);
    if fresh.gate != AccountGate::Compatible && !new_empty {
        return observe_pending_gate(env, op, &fresh.gate, fresh.observed_schema)
            .and_then(|_| Err(gate_error(&fresh.gate)));
    }
    let mut account = op.prepared_account.clone();
    if new_empty {
        account.baseline_established = true;
        account.cursor_seq = 0;
        account.remote_schema_version = Some(records_v3::ACCOUNT_SCHEMA);
        return Ok(account);
    }
    let merged = record_merge::merge_account(&account, keys, &pulled, 0);
    if merged.gate != AccountGate::Compatible {
        return observe_pending_gate(env, op, &merged.gate, merged.observed_schema)
            .and_then(|_| Err(gate_error(&merged.gate)));
    }
    account = merged.section;
    Ok(account)
}
fn pending_keys(
    env: &SyncEnv,
    op: &PendingAccountOperation,
    provided: Option<&str>,
) -> Result<(ChainKeys, Option<Zeroizing<String>>), AppError> {
    if op.kind == PendingAccountKind::CreateSpace {
        let (state, _) = record_runtime::snapshot(env)?;
        let keys = record_runtime::read_account_keys(&state, env.keychain)?
            .ok_or_else(|| failure("the current record account code is unavailable"))?;
        if keys.chain_id != op.prepared_account.chain_id {
            return Err(failure("pending operation belongs to a different account"));
        }
        return Ok((keys, None));
    }
    let name = op
        .staged_code_account
        .as_deref()
        .ok_or_else(|| failure("pending staged code identity is invalid"))?;
    let stored = if op.phase == PendingAccountPhase::Activated {
        env.keychain.get(MNEMONIC_ACCOUNT)
    } else {
        env.keychain.get(name)
    }
    .map_err(|_| failure("the pending sync code could not be read"))?;
    let phrase = Zeroizing::new(match provided {
        Some(code) => crypto::normalize_mnemonic(code)?,
        None => stored.ok_or_else(|| {
            failure("re-enter the pending sync code to resume this fixed account identity")
        })?,
    });
    let keys =
        crypto::derive_account(&phrase).map_err(|_| failure("the pending sync code is invalid"))?;
    if keys.chain_id != op.prepared_account.chain_id {
        return Err(failure(
            "the supplied sync code does not match the pending account",
        ));
    }
    Ok((keys, Some(phrase)))
}
fn resume_locked(env: &SyncEnv, provided: Option<&str>) -> Result<(), AppError> {
    crate::sync::record_round::preflight(env)?;
    let mut op = pending(env)?;
    validate_pending(&op)?;
    let (keys, phrase) = pending_keys(env, &op, provided)?;
    if op.phase == PendingAccountPhase::Activated {
        // Cleanup remains a credential mutation, so an upgraded account must stop it too.
        let proof = crate::sync::record_round::fresh_account_gate(env)?;
        proof.ensure_compatible()?;
        if let Some(name) = &op.staged_code_account {
            env.keychain
                .delete(name)
                .map_err(|_| failure("the staged sync code cleanup is pending"))?;
        }
        record_runtime::mutate_records(env, |latest| {
            if latest.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str()) {
                return Err(crate::sync::runtime::superseded());
            }
            let mut next = latest.clone();
            next.pending_account = None;
            next.shared_writes_blocked = false;
            next.last_error = None;
            Ok(next)
        })?;
        return Ok(());
    }
    let relay = env.relay(&op.relay_url)?;
    if op.kind != PendingAccountKind::CreateSpace {
        // Initial random account staging precedes create. Every retry of an existing target, and
        // every known future target, verifies its full account before any credential write.
        if op.kind == PendingAccountKind::JoinAccount
            || op.phase != PendingAccountPhase::Prepared
            || op
                .prepared_account
                .remote_schema_version
                .is_some_and(|schema| schema > records_v3::ACCOUNT_SCHEMA)
        {
            op.prepared_account = target_pull(env, &op, &keys)?;
            op.migration_gate = None;
            save_pending(env, op.clone())?;
        }
        env.keychain
            .set(
                op.staged_code_account.as_deref().unwrap(),
                phrase.as_ref().unwrap(),
            )
            .map_err(|_| failure("the pending sync code could not be stored"))?;
    }
    if op.kind == PendingAccountKind::CreateAccount && op.phase == PendingAccountPhase::Prepared {
        relay.create_chain(&keys.chain_id, &keys.auth_token)?;
        op.phase = PendingAccountPhase::RemoteCreated;
        replace_pending(env, op.clone(), true)?;
    }
    if op.kind == PendingAccountKind::CreateSpace {
        let proof = crate::sync::record_round::fresh_account_gate(env)?;
        proof.ensure_compatible()?;
        if proof.keys.chain_id != keys.chain_id {
            return Err(crate::sync::runtime::superseded());
        }
        // Overlay only the fixed operation's rows onto the fresh authoritative account. Local hosts stay latest.
        let latest = record_runtime::snapshot(env)?.0;
        let mut account = latest.account.unwrap();
        let id = op.space_id.as_ref().unwrap();
        let public_key = record_key(RecordKind::Space, id);
        let secret_key = sealed_key("spacekey", &crypto::id_hash(&keys, "spacekey", id));
        for key in [&public_key] {
            if let Some(row) = op.prepared_account.records.get(key) {
                account.records.insert(key.clone(), row.clone());
            }
        }
        if let Some(row) = op.prepared_account.sealed.get(&secret_key) {
            account.sealed.insert(secret_key, row.clone());
        }
        op.prepared_account = account;
        let child = record_merge::space_keys(&op.prepared_account, &keys, id)?
            .ok_or_else(|| failure("pending space credentials are unavailable"))?;
        relay.create_chain(&child.chain_id, &child.auth_token)?;
        let pulled = relay.pull(&child.chain_id, &child.auth_token, 0)?;
        let merged = record_merge::merge_space(
            op.prepared_space.as_ref().unwrap(),
            &child,
            &pulled,
            0,
            &AccountGate::Compatible,
        );
        if merged.gate != AccountGate::Compatible {
            return observe_pending_gate(env, &op, &merged.gate, None);
        }
        op.prepared_space = Some(merged.section);
        op.phase = PendingAccountPhase::RemoteCreated;
        replace_pending(env, op.clone(), true)?;
    }
    // Every publication/credential promotion gets a new authenticated target-account proof.
    op.prepared_account = target_pull(env, &op, &keys)?;
    save_pending(env, op.clone())?;
    let sent = record_merge::account_outgoing(&op.prepared_account, &keys)?;
    if !sent.is_empty() {
        let outgoing: Vec<_> = sent.iter().map(|s| s.outgoing.clone()).collect();
        let pushed =
            crate::sync::merge::push_outgoing(&*relay, &keys.chain_id, &keys.auth_token, &outgoing);
        op.prepared_account =
            record_merge::apply_account_receipts(&op.prepared_account, &sent, &pushed);
        op.phase = PendingAccountPhase::Publishing;
        replace_pending(env, op.clone(), true)?;
        if pushed.frozen {
            return observe_pending_gate(env, &op, &AccountGate::InvalidMigration, None);
        }
        if let Some(error) = pushed.error {
            return Err(error.into());
        }
        if pushed.conflicts > 0 {
            return Err(failure(
                "pending account publication conflicted; retry after a fresh pull",
            ));
        }
    }
    op.phase = PendingAccountPhase::ActivationReady;
    save_pending(env, op.clone())?;
    // Check once more after partial publication; no account activation from a cached gate.
    op.prepared_account = target_pull(env, &op, &keys)?;
    save_pending(env, op.clone())?;
    if let Some(phrase) = &phrase {
        env.keychain
            .set(MNEMONIC_ACCOUNT, phrase)
            .map_err(|_| failure("the current sync code promotion is pending"))?;
    }
    record_runtime::mutate_records(env, |latest| {
        if latest.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str()) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next = latest.clone();
        next.account = Some(op.prepared_account.clone());
        next.device_name = op.device_name.clone();
        for row in op
            .prepared_account
            .records
            .values()
            .filter(|r| r.record.kind == RecordKind::Space && !r.record.deleted)
        {
            next.spaces.entry(row.record.id.clone()).or_default();
        }
        if let (Some(id), Some(space)) = (&op.space_id, &op.prepared_space) {
            next.spaces.insert(id.clone(), space.clone());
        }
        op.phase = PendingAccountPhase::Activated;
        next.pending_account = Some(op.clone());
        next.shared_writes_blocked = false;
        next.migration_gate = None;
        Ok(next)
    })?;
    if let Some(name) = &op.staged_code_account {
        env.keychain
            .delete(name)
            .map_err(|_| failure("the staged sync code cleanup is pending"))?;
    }
    record_runtime::mutate_records(env, |latest| {
        if latest.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str()) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next = latest.clone();
        next.pending_account = None;
        next.last_error = None;
        Ok(next)
    })?;
    let mut core = env.runtime.core.lock().unwrap();
    core.account_keys = Some(keys);
    Ok(())
}
pub fn resume_pending(env: &SyncEnv, code: Option<&str>) -> Result<(), AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let result = resume_locked(env, code);
    drop(lifecycle);
    env.events.status();
    result
}
pub fn create_account(env: &SyncEnv, device_name: &str) -> Result<AccountCreation, AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let device_name = clean_name(device_name)?;
    crate::sync::record_round::preflight(env)?;
    let (state, _) = record_runtime::snapshot(env)?;
    ensure_empty(&state)?;
    let code = Zeroizing::new(crypto::generate_mnemonic()?);
    let keys = crypto::derive_account(&code)?;
    let id = new_id()?;
    let now = env.now();
    let mut account = AccountState::new(&keys.chain_id);
    account.remote_schema_version = Some(records_v3::ACCOUNT_SCHEMA);
    insert_public(
        &mut account,
        row(
            &state,
            RecordKind::Meta,
            ACCOUNT_META_ID,
            json!({"schema_version":3,"created_by_app_version":env!("CARGO_PKG_VERSION")}),
            now,
        ),
    );
    plan_device(&state, &mut account, &device_name, now)?;
    let op = PendingAccountOperation {
        device_name: device_name.clone(),
        id: id.clone(),
        kind: PendingAccountKind::CreateAccount,
        phase: PendingAccountPhase::Prepared,
        migration_gate: None,
        relay_url: state.relay_url,
        staged_code_account: Some(format!("{PENDING_CODE_PREFIX}{id}")),
        prepared_account: account,
        space_id: None,
        prepared_space: None,
    };
    save_pending(env, op)?;
    let result = resume_locked(env, Some(&code));
    let outcome = AccountCreation {
        code,
        operation_id: id,
        complete: result.is_ok(),
        pending_error: result.err().map(|e| e.to_string()),
    };
    drop(lifecycle);
    env.events.status();
    Ok(outcome)
}
pub fn join_account(env: &SyncEnv, code: &str, device_name: &str) -> Result<(), AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let device_name = clean_name(device_name)?;
    crate::sync::record_round::preflight(env)?;
    let code = Zeroizing::new(crypto::normalize_mnemonic(code)?);
    let keys = crypto::derive_account(&code)?;
    let (state, _) = record_runtime::snapshot(env)?;
    if let Some(op) = &state.pending_account {
        if op.kind != PendingAccountKind::JoinAccount
            || op.prepared_account.chain_id != keys.chain_id
        {
            return Err(failure("a different record account operation is pending"));
        }
        let result = resume_locked(env, Some(&code));
        drop(lifecycle);
        env.events.status();
        return result;
    }
    ensure_empty(&state)?;
    let relay = env.relay(&state.relay_url)?;
    let pulled = relay.pull(&keys.chain_id, &keys.auth_token, 0)?;
    let merged = record_merge::merge_account(&AccountState::new(&keys.chain_id), &keys, &pulled, 0);
    if merged.gate != AccountGate::Compatible {
        return Err(gate_error(&merged.gate));
    }
    let mut account = merged.section;
    plan_device(&state, &mut account, &device_name, env.now())?;
    let id = new_id()?;
    let op = PendingAccountOperation {
        device_name: device_name.clone(),
        id: id.clone(),
        kind: PendingAccountKind::JoinAccount,
        phase: PendingAccountPhase::ActivationReady,
        migration_gate: None,
        relay_url: state.relay_url,
        staged_code_account: Some(format!("{PENDING_CODE_PREFIX}{id}")),
        prepared_account: account,
        space_id: None,
        prepared_space: None,
    };
    save_pending(env, op)?;
    let result = resume_locked(env, Some(&code));
    drop(lifecycle);
    env.events.status();
    result
}
pub fn create_space(env: &SyncEnv, name: &str) -> Result<String, AppError> {
    let name = clean_name(name)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    crate::sync::record_round::preflight(env)?;
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let (state, _) = record_runtime::snapshot(env)?;
    ensure_shared(&state)?;
    let child = ChainKeys::generate()?;
    let id = new_id()?;
    let now = env.now();
    let mut account = state.account.as_ref().unwrap().clone();
    insert_public(
        &mut account,
        row(
            &state,
            RecordKind::Space,
            &child.chain_id,
            json!({"schema":1,"name":name,"slug":"records","created_at_ms":now}),
            now,
        ),
    );
    let private = row(
        &state,
        RecordKind::SpaceKey,
        &child.chain_id,
        json!({"schema":1,"auth_token":child.auth_token,"enc_key":child.enc_key_b64()}),
        now,
    );
    let sealed = record_merge::seal_secret_record(&proof.keys, private, 0)?;
    account.sealed.insert(
        sealed_key(&sealed.envelope.kind, &sealed.envelope.id_hash),
        sealed,
    );
    let op = PendingAccountOperation {
        device_name: state.device_name.clone(),
        id,
        kind: PendingAccountKind::CreateSpace,
        phase: PendingAccountPhase::Prepared,
        migration_gate: None,
        relay_url: state.relay_url,
        staged_code_account: None,
        prepared_account: account,
        space_id: Some(child.chain_id.clone()),
        prepared_space: Some(SpaceStateV3 {
            selected: true,
            ..Default::default()
        }),
    };
    save_pending(env, op)?;
    let result = resume_locked(env, None);
    drop(lifecycle);
    env.events.status();
    result.map(|_| child.chain_id)
}
pub fn select_space(env: &SyncEnv, id: &str, selected: bool) -> Result<(), AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let result = record_runtime::mutate_records(env, |latest| {
        ensure_shared(latest)?;
        let mut next = latest.clone();
        let space = next
            .spaces
            .get_mut(id)
            .ok_or_else(|| failure("record space is unavailable"))?;
        if selected && space.missing {
            return Err(failure("record space is missing"));
        }
        space.selected = selected;
        Ok(next)
    })
    .map(|_| ());
    drop(lifecycle);
    env.events.status();
    env.events.wake();
    result
}
pub fn rename_space(env: &SyncEnv, id: &str, name: &str) -> Result<(), AppError> {
    let name = clean_name(name)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let now = env.now();
    let result = record_runtime::mutate_records(env, |latest| {
        ensure_shared(latest)?;
        let mut next = latest.clone();
        let row = next
            .account
            .as_mut()
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Space, id))
            .filter(|r| !r.record.deleted)
            .ok_or_else(|| failure("record space is unavailable"))?;
        row.record.payload["name"] = json!(name);
        row.record.version = row
            .record
            .version
            .checked_add(1)
            .ok_or_else(|| failure("record revision exhausted"))?;
        row.record.updated_at_ms = now.max(
            row.record
                .updated_at_ms
                .checked_add(1)
                .ok_or_else(|| failure("record timestamp exhausted"))?,
        );
        row.record.device_id = latest.device_id.clone();
        row.dirty = true;
        Ok(next)
    })
    .map(|_| ());
    drop(lifecycle);
    env.events.status();
    env.events.wake();
    result
}
pub fn publish_key(
    env: &SyncEnv,
    id: &str,
    public: KeySlotPayload,
    private: Zeroizing<String>,
) -> Result<(), AppError> {
    records_v3::validate_keyslot(id, &public).map_err(|_| failure("key metadata is invalid"))?;
    let parsed = crate::vault::material::parse(&private)
        .ok_or_else(|| failure("private key is unreadable"))?;
    let line = parsed
        .public_key()
        .to_openssh()
        .map_err(|_| failure("private key public identity is invalid"))?;
    let fingerprint = parsed
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    records_v3::key_material_matches(&public, &line, &fingerprint)
        .map_err(|_| failure("private key does not match account public metadata"))?;
    if parsed.is_encrypted() != public.has_passphrase {
        return Err(failure("private key passphrase metadata does not match"));
    }
    drop(parsed);
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let (state, _) = record_runtime::snapshot(env)?;
    ensure_shared(&state)?;
    let now = env.now();
    let account = state.account.as_ref().unwrap();
    let key = record_key(RecordKind::KeySlot, id);
    let existing = account.records.get(&key);
    if let Some(row) = existing {
        let records_v3::TypedRecord::Live(authoritative) = records_v3::decode_keyslot(&row.record)
            .map_err(|_| failure("account key metadata is invalid"))?
        else {
            return Err(failure("account key was deleted"));
        };
        records_v3::key_material_matches(&authoritative, &public.public_key, &public.fingerprint)
            .map_err(|_| failure("account key identity conflicts; review before publishing"))?;
    }
    if account.sealed.contains_key(&sealed_key(
        "keyslot",
        &crypto::id_hash(&proof.keys, "keyslot", id),
    )) {
        return Err(failure(
            "account key authority is opaque; review before publishing",
        ));
    }
    let secret_key = sealed_key("key", &crypto::id_hash(&proof.keys, "key", id));
    let base = account
        .sealed
        .get(&secret_key)
        .map(|r| r.envelope.seq)
        .unwrap_or(0);
    let revision = record_merge::secret_revision(account, &proof.keys, RecordKind::Key, id)?;
    let changed_at = match &revision {
        Some(revision) => revision
            .updated_at_ms
            .checked_add(1)
            .ok_or_else(|| failure("secret timestamp exhausted"))?
            .max(now),
        None => now,
    };
    let version = revision
        .as_ref()
        .map(|revision| revision.version)
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| failure("secret revision exhausted"))?;
    let mut secret = row(
        &state,
        RecordKind::Key,
        id,
        json!({"schema":1,"private_key":private.as_str()}),
        changed_at,
    );
    secret.version = version;
    let sealed = record_merge::seal_secret_record(&proof.keys, secret, base)?;
    let metadata = row(
        &state,
        RecordKind::KeySlot,
        id,
        serde_json::to_value(public).map_err(|_| failure("key metadata cannot be encoded"))?,
        now,
    );
    record_runtime::mutate_records(env, |latest| {
        ensure_shared(latest)?;
        let mut next = latest.clone();
        let account = next.account.as_mut().unwrap();
        if account.records.get(&key) != existing {
            return Err(crate::sync::runtime::superseded());
        }
        if existing.is_none() {
            insert_public(account, metadata);
        }
        account.sealed.insert(secret_key, sealed);
        Ok(next)
    })?;
    let result = publish_current(env, &proof);
    drop(lifecycle);
    env.events.status();
    env.events.wake();
    result
}
fn publish_current(
    env: &SyncEnv,
    proof: &crate::sync::record_round::FreshAccountProof,
) -> Result<(), AppError> {
    let fresh = crate::sync::record_round::fresh_account_gate(env)?;
    fresh.ensure_compatible()?;
    let (state, _) = record_runtime::snapshot(env)?;
    ensure_shared(&state)?;
    let sent = record_merge::account_outgoing(state.account.as_ref().unwrap(), &fresh.keys)?;
    let relay = env.relay(&fresh.relay_url)?;
    let outgoing: Vec<_> = sent.iter().map(|s| s.outgoing.clone()).collect();
    let pushed = crate::sync::merge::push_outgoing(
        &*relay,
        &fresh.keys.chain_id,
        &fresh.keys.auth_token,
        &outgoing,
    );
    crate::sync::record_round::receipt_commit(env, proof, None, &sent, &pushed)?;
    if pushed.frozen {
        crate::sync::record_round::mark_frozen(env, proof)?;
        return Err(failure("the record account is frozen"));
    }
    if let Some(e) = pushed.error {
        return Err(e.into());
    }
    if pushed.conflicts > 0 {
        return Err(failure("key publication conflicted; sync and retry"));
    }
    Ok(())
}
pub fn unpublish_key(env: &SyncEnv, id: &str) -> Result<(), AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let (state, _) = record_runtime::snapshot(env)?;
    ensure_shared(&state)?;
    let account = state.account.as_ref().unwrap();
    let cached = account
        .records
        .get(&record_key(RecordKind::KeySlot, id))
        .ok_or_else(|| failure("synced public metadata is unavailable"))?;
    if !matches!(
        records_v3::decode_keyslot(&cached.record),
        Ok(records_v3::TypedRecord::Live(_))
    ) {
        return Err(failure("synced public metadata is invalid or deleted"));
    }
    if account.sealed.contains_key(&sealed_key(
        "keyslot",
        &crypto::id_hash(&proof.keys, "keyslot", id),
    )) {
        return Err(failure("account key authority is opaque"));
    }
    let Some(revision) = record_merge::secret_revision(account, &proof.keys, RecordKind::Key, id)?
    else {
        return Ok(());
    };
    if revision.deleted {
        return Ok(());
    }
    let now = env.now();
    let timestamp = revision
        .updated_at_ms
        .checked_add(1)
        .ok_or_else(|| failure("secret timestamp exhausted"))?
        .max(now);
    let version = revision
        .version
        .checked_add(1)
        .ok_or_else(|| failure("secret revision exhausted"))?;
    let key = sealed_key("key", &crypto::id_hash(&proof.keys, "key", id));
    let previous = account.sealed.get(&key).unwrap();
    let mut tombstone = row(
        &state,
        RecordKind::Key,
        id,
        serde_json::Value::Null,
        timestamp,
    );
    tombstone.deleted = true;
    tombstone.version = version;
    let sealed = record_merge::seal_secret_record(&proof.keys, tombstone, previous.envelope.seq)?;
    record_runtime::mutate_records(env, |latest| {
        ensure_shared(latest)?;
        let mut next = latest.clone();
        let account = next.account.as_mut().unwrap();
        if account.sealed.get(&key) != Some(previous) {
            return Err(crate::sync::runtime::superseded());
        }
        account.sealed.insert(key, sealed);
        Ok(next)
    })?;
    let result = publish_current(env, &proof);
    drop(lifecycle);
    env.events.status();
    env.events.wake();
    result
}

pub fn download_key(env: &SyncEnv, id: &str) -> Result<(), AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let (state, _) = record_runtime::snapshot(env)?;
    ensure_shared(&state)?;
    let account = state.account.as_ref().unwrap();
    let cached = account
        .records
        .get(&record_key(RecordKind::KeySlot, id))
        .ok_or_else(|| failure("synced public key metadata is unavailable"))?;
    let records_v3::TypedRecord::Live(public) = records_v3::decode_keyslot(&cached.record)
        .map_err(|_| failure("synced public key metadata is invalid"))?
    else {
        return Err(failure("synced key was deleted"));
    };
    let private = record_merge::key_secret(account, &proof.keys, id)?
        .ok_or_else(|| failure("synced private material is unavailable"))?;
    // This worker entry owns vault -> publication only. Lifecycle is already owned here; the
    // journal compares latest authoritative public revision before activating a new vault ID.
    let result = crate::sync::record_keys::activate_synced(env, id, public, private).map(|_| ());
    drop(lifecycle);
    env.events.status();
    env.events.wake();
    result
}
#[cfg(test)]
#[path = "record_account_tests.rs"]
mod tests;

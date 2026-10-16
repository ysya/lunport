//! Resumable typed-record rotation. The source is frozen and retained; Local/Vault are untouched.
use crate::error::AppError;
use crate::sync::{
    crypto::{self, ChainKeys, Sealed},
    env::SyncEnv,
    record::{record_key, Envelope, LocalRecord, Record, RecordKind, ACCOUNT_META_ID},
    record_account::{
        PendingAccountKind, PendingAccountOperation, PendingAccountPhase, PENDING_CODE_PREFIX,
    },
    record_merge::{self, AccountGate},
    record_runtime,
    records_v3::{self, MigrationGate, MigrationPhase, SpaceStateV3},
    state::MNEMONIC_ACCOUNT,
    state_v2::{sealed_key, AccountState, SealedRecord},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};
pub const SOURCE_CODE_PREFIX: &str = "sync:records-rotation-source:";
pub type RotationCreation = crate::sync::record_account::AccountCreation;
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
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn error(s: &str) -> AppError {
    AppError::Other(s.into())
}
fn new_id() -> Result<String, AppError> {
    let mut b = [0; 16];
    getrandom::fill(&mut b).map_err(|_| error("cannot create rotation identity"))?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
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
fn clear_json(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(clear_json),
        Value::Object(o) => {
            for (mut k, mut v) in std::mem::take(o) {
                k.zeroize();
                clear_json(&mut v);
            }
        }
        _ => {}
    }
    *v = Value::Null;
}
struct Protected(Value);
impl Drop for Protected {
    fn drop(&mut self) {
        clear_json(&mut self.0)
    }
}
fn open(keys: &ChainKeys, e: &Envelope) -> Result<Protected, AppError> {
    let bytes = Zeroizing::new(
        crypto::open(
            keys,
            &e.kind,
            &e.id_hash,
            &Sealed {
                id_hash: e.id_hash.clone(),
                nonce: e.nonce.clone(),
                ciphertext: e.ciphertext.clone(),
            },
        )
        .map_err(|_| error("rotation source ciphertext could not be authenticated"))?,
    );
    let value = Protected(
        serde_json::from_slice(&bytes).map_err(|_| error("rotation source record is malformed"))?,
    );
    let o = value
        .0
        .as_object()
        .ok_or_else(|| error("rotation source record is malformed"))?;
    if o.len() != 7
        || o.keys().any(|k| {
            ![
                "kind",
                "id",
                "version",
                "updated_at_ms",
                "device_id",
                "deleted",
                "payload",
            ]
            .contains(&k.as_str())
        })
        || o.get("kind").and_then(Value::as_str) != Some(&e.kind)
        || o.get("deleted").and_then(Value::as_bool) != Some(e.deleted)
        || !o
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty() && crypto::id_hash(keys, &e.kind, id) == e.id_hash)
        || !o
            .get("version")
            .and_then(Value::as_u64)
            .is_some_and(|v| v > 0)
        || o.get("updated_at_ms").and_then(Value::as_u64).is_none()
        || !o
            .get("device_id")
            .and_then(Value::as_str)
            .is_some_and(crate::sync::slot_rules::is_slot_id)
    {
        return Err(error("rotation source record identity is inconsistent"));
    }
    Ok(value)
}
fn envelope(keys: &ChainKeys, kind: &str, id: &str, value: &Value) -> Result<Envelope, AppError> {
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, value)
        .map_err(|_| error("cannot encode rotation record"))?;
    let s = crypto::seal(keys, kind, id, &bytes)?;
    Ok(Envelope {
        kind: kind.into(),
        id_hash: s.id_hash,
        nonce: s.nonce,
        ciphertext: s.ciphertext,
        seq: 0,
        deleted: value["deleted"]
            .as_bool()
            .ok_or_else(|| error("invalid rotation tombstone"))?,
    })
}
fn limits(rows: &[Envelope]) -> Result<(), AppError> {
    if rows.len() > 4096
        || rows
            .iter()
            .try_fold(0usize, |n, r| {
                n.checked_add(r.ciphertext.len() + r.nonce.len() + r.kind.len() + r.id_hash.len())
            })
            .is_none_or(|n| n > 1024 * 1024)
    {
        return Err(error(
            "rotation exceeds the per-chain storage budget; no source freeze was attempted",
        ));
    }
    Ok(())
}
fn source_full(
    env: &SyncEnv,
    source: &AccountState,
    keys: &ChainKeys,
    cached: &BTreeMap<String, SpaceStateV3>,
) -> Result<(AccountState, BTreeMap<String, SpaceStateV3>), AppError> {
    let relay = env.relay(&record_runtime::snapshot(env)?.0.relay_url)?;
    let pulled = relay.pull(&keys.chain_id, &keys.auth_token, 0)?;
    limits(&pulled.records)?;
    for e in &pulled.records {
        open(keys, e)?;
    }
    let merged = record_merge::merge_account(source, keys, &pulled, 0);
    if merged.gate != AccountGate::Compatible {
        return Err(error("source account format prevents rotation"));
    }
    if !merged.conflicts.is_empty()
        || merged.section.records.values().any(|r| r.dirty)
        || merged.section.sealed.values().any(|r| r.dirty)
    {
        return Err(error(
            "finish or review source account changes before rotation",
        ));
    }
    let account = merged.section;
    let mut spaces = BTreeMap::new();
    for row in account
        .records
        .values()
        .filter(|r| r.record.kind == RecordKind::Space && !r.record.deleted)
    {
        let id = &row.record.id;
        let old = cached.get(id).cloned().unwrap_or_default();
        if old.missing {
            return Err(error(
                "a source space is missing; rotation did not preserve it",
            ));
        }
        let child = record_merge::space_keys(&account, keys, id)?
            .ok_or_else(|| error("source space credentials unavailable"))?;
        let pulled = relay
            .pull(id, &child.auth_token, 0)
            .map_err(|_| error("a source space could not be read; rotation did not preserve it"))?;
        limits(&pulled.records)?;
        for e in &pulled.records {
            open(&child, e)?;
        }
        let merged = record_merge::merge_space(&old, &child, &pulled, 0, &AccountGate::Compatible);
        if merged.gate != AccountGate::Compatible
            || !merged.conflicts.is_empty()
            || merged.section.records.values().any(|r| r.dirty)
            || merged.section.sealed.values().any(|r| r.dirty)
        {
            return Err(error(
                "finish or review source space changes before rotation",
            ));
        }
        spaces.insert(id.clone(), merged.section);
    }
    if cached
        .iter()
        .any(|(id, s)| s.selected && !spaces.contains_key(id))
    {
        return Err(error("a selected source space is unavailable"));
    }
    Ok((account, spaces))
}
fn code(env: &SyncEnv, name: &str) -> Result<Option<Zeroizing<String>>, AppError> {
    env.keychain
        .get(name)
        .map(|v| v.map(Zeroizing::new))
        .map_err(|_| error("rotation code could not be read"))
}
fn keys_for(
    env: &SyncEnv,
    op: &PendingAccountOperation,
    provided: Option<&str>,
) -> Result<(ChainKeys, Zeroizing<String>), AppError> {
    let phrase = match provided {
        Some(s) => Zeroizing::new(crypto::normalize_mnemonic(s)?),
        None => code(
            env,
            if op.phase == PendingAccountPhase::Activated {
                MNEMONIC_ACCOUNT
            } else {
                op.staged_code_account.as_deref().unwrap()
            },
        )?
        .ok_or_else(|| error("re-enter the pending new sync code to resume rotation"))?,
    };
    let keys = crypto::derive_account(&phrase)?;
    if keys.chain_id != op.prepared_account.chain_id {
        return Err(error("new code does not match the pending rotation"));
    }
    Ok((keys, phrase))
}
fn source_code(
    env: &SyncEnv,
    op: &PendingAccountOperation,
) -> Result<Option<Zeroizing<String>>, AppError> {
    let p = op.rotation.as_ref().unwrap();
    if let Some(s) = code(env, &p.source_code_account)? {
        return Ok(Some(s));
    }
    if op.phase == PendingAccountPhase::Activated {
        return Ok(None);
    }
    let s = code(env, MNEMONIC_ACCOUNT)?.ok_or_else(|| error("source sync code is unavailable"))?;
    if crypto::derive_account(&s)?.chain_id != p.source_account.chain_id {
        return Err(error(
            "source code backup is unavailable; review pending rotation",
        ));
    }
    Ok(Some(s))
}
fn store(env: &SyncEnv, mut op: PendingAccountOperation, accepted: bool) -> Result<(), AppError> {
    let transform = |s: &records_v3::SyncStateV3| -> Result<records_v3::SyncStateV3, AppError> {
        if s.relay_url != op.relay_url || s.pending_account.as_ref().is_some_and(|p| p.id != op.id)
        {
            return Err(crate::sync::runtime::superseded());
        }
        let mut n = s.clone();
        if let Some(old) = &s.pending_account {
            op.prepared_account.remote_schema_version = match (
                op.prepared_account.remote_schema_version,
                old.prepared_account.remote_schema_version,
            ) {
                (a, b) => a.into_iter().chain(b).max(),
            };
            if let (Some(new), Some(old)) = (&mut op.rotation, &old.rotation) {
                new.source_account.remote_schema_version = new
                    .source_account
                    .remote_schema_version
                    .into_iter()
                    .chain(old.source_account.remote_schema_version)
                    .max();
            }
        }
        let future = op
            .prepared_account
            .remote_schema_version
            .is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA)
            || op.rotation.as_ref().is_some_and(|p| {
                p.source_account
                    .remote_schema_version
                    .is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA)
            });
        if future {
            n.last_error =
                Some("a pending rotation account uses a newer format; update SSHelter".into());
            if n.account.is_some() {
                n.shared_writes_blocked = true;
            }
        }
        n.pending_account = Some(op);
        Ok(n)
    };
    if !accepted {
        return record_runtime::mutate_records(env, transform).map(|_| ());
    }
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(s) = &core.save_blocked {
        return Err(error(s));
    }
    let n = transform(record_runtime::active_state(&core)?)?;
    records_v3::validate_state(&n).map_err(|_| error("invalid rotation receipt"))?;
    let g = core
        .generation
        .checked_add(1)
        .ok_or_else(|| error("record generation exhausted"))?;
    core.records = Some(n);
    core.generation = g;
    crate::sync::runtime::save_core(&mut core, &env.state_path)
}
fn retain_blocked_gate(env: &SyncEnv, op: &PendingAccountOperation) -> Result<(), AppError> {
    if let Err(e) = store(env, op.clone(), false) {
        let mut core = env.runtime.core.lock().unwrap();
        let mut retained = false;
        if let Some(state) = core
            .records
            .as_mut()
            .filter(|s| s.relay_url == op.relay_url)
        {
            if let Some(latest) = state.pending_account.as_mut().filter(|p| p.id == op.id) {
                latest.prepared_account.remote_schema_version = latest
                    .prepared_account
                    .remote_schema_version
                    .into_iter()
                    .chain(op.prepared_account.remote_schema_version)
                    .max();
                if let (Some(latest), Some(observed)) = (&mut latest.rotation, &op.rotation) {
                    latest.source_account.remote_schema_version = latest
                        .source_account
                        .remote_schema_version
                        .into_iter()
                        .chain(observed.source_account.remote_schema_version)
                        .max();
                }
                state.last_error =
                    Some("an authenticated rotation account gate could not be saved".into());
                if state.account.is_some() {
                    state.shared_writes_blocked = true;
                }
                retained = true;
            }
        }
        if retained {
            core.save_blocked=Some("an authenticated rotation gate could not be saved; repair record storage before resuming".into());
        }
        return Err(e);
    }
    Ok(())
}
fn current(env: &SyncEnv) -> Result<PendingAccountOperation, AppError> {
    record_runtime::snapshot(env)?
        .0
        .pending_account
        .ok_or_else(|| error("no rotation is pending"))
}
fn ensure_latest(env: &SyncEnv, op: &PendingAccountOperation) -> Result<(), AppError> {
    crate::sync::record_round::preflight(env)?;
    let s = record_runtime::snapshot(env)?.0;
    let pending = s
        .pending_account
        .as_ref()
        .filter(|p| p.id == op.id)
        .ok_or_else(crate::sync::runtime::superseded)?;
    if s.account
        .as_ref()
        .is_some_and(|a| a.remote_schema_version.is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA))
        || pending
            .prepared_account
            .remote_schema_version
            .is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA)
        || pending.rotation.as_ref().is_some_and(|p| {
            p.source_account
                .remote_schema_version
                .is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA)
        })
        || records_v3::account_migration_pending(&s)
    {
        return Err(error("latest account observation blocks rotation effects"));
    }
    Ok(())
}
fn source_proof(
    env: &SyncEnv,
    op: &mut PendingAccountOperation,
    keys: &ChainKeys,
) -> Result<AccountState, AppError> {
    crate::sync::record_round::preflight(env)?;
    let p = op.rotation.as_ref().unwrap();
    if keys.chain_id != p.source_account.chain_id {
        return Err(error("source code identity changed"));
    }
    let latest = record_runtime::snapshot(env)?.0;
    let mut source = p.source_account.clone();
    if let Some(current) = latest
        .account
        .as_ref()
        .filter(|a| a.chain_id == keys.chain_id)
    {
        source.remote_schema_version = source
            .remote_schema_version
            .into_iter()
            .chain(current.remote_schema_version)
            .max();
    }
    let pulled = env
        .relay(&op.relay_url)?
        .pull(&keys.chain_id, &keys.auth_token, 0)?;
    let merged = record_merge::merge_account(&source, keys, &pulled, 0);
    if merged.gate != AccountGate::Compatible {
        if let Some(v) = merged
            .observed_schema
            .filter(|v| *v > records_v3::ACCOUNT_SCHEMA)
        {
            op.rotation
                .as_mut()
                .unwrap()
                .source_account
                .remote_schema_version = Some(v);
        }
        retain_blocked_gate(env, op)?;
        return Err(error(
            "source format prevents rotation or credential cleanup",
        ));
    }
    Ok(merged.section)
}
fn marker(op: &PendingAccountOperation, phase: MigrationPhase) -> MigrationGate {
    MigrationGate {
        id: op.id.clone(),
        source_digest: op.rotation.as_ref().unwrap().source_digest.clone(),
        phase,
    }
}
fn prepare_targets(
    op: &mut PendingAccountOperation,
    old: &ChainKeys,
    new: &ChainKeys,
) -> Result<(), AppError> {
    let p = op.rotation.as_ref().unwrap();
    let source = p.source_account.clone();
    let source_spaces = p.source_spaces.clone();
    let mapping = p.space_ids.clone();
    let mut children = BTreeMap::new();
    for (old_id, new_id) in &mapping {
        let generated = ChainKeys::generate()?;
        children.insert(
            old_id.clone(),
            ChainKeys::from_parts(new_id, &generated.auth_token, &generated.enc_key_b64())?,
        );
    }
    let mut account = AccountState::new(&new.chain_id);
    let schema = source
        .records
        .get(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        .and_then(|r| r.record.payload.get("schema_version"))
        .and_then(Value::as_u64)
        .unwrap_or(3);
    account.remote_schema_version = Some(schema as u32);
    let pending = marker(op, MigrationPhase::Publishing);
    for row in source.records.values() {
        let mut r = row.record.clone();
        if r.kind == RecordKind::Meta && r.id == ACCOUNT_META_ID {
            r.payload = json!({"schema_version":schema,"created_by_app_version":env!("CARGO_PKG_VERSION"),"migration":pending});
        } else if r.kind == RecordKind::Space && !r.deleted {
            let oldid = r.id.clone();
            r.id = mapping
                .get(&oldid)
                .ok_or_else(|| error("source space mapping missing"))?
                .clone();
            r.payload["previous_id"] = json!(oldid);
        } else if r.kind == RecordKind::Device && !r.deleted {
            if let Some(ids) = r.payload.get_mut("spaces").and_then(Value::as_array_mut) {
                for v in ids {
                    if let Some(mapped) = v.as_str().and_then(|id| mapping.get(id)) {
                        *v = json!(mapped);
                    }
                }
            }
        }
        account.records.insert(
            record_key(r.kind, &r.id),
            LocalRecord {
                record: r,
                seq: 0,
                dirty: true,
            },
        );
    }
    for sealed in source.sealed.values() {
        let mut v = open(old, &sealed.envelope)?;
        let kind = sealed.envelope.kind.clone();
        let oldid = v.0["id"].as_str().unwrap().to_string();
        let id = if kind == "spacekey" && !sealed.envelope.deleted {
            if let Some(child) = children.get(&oldid) {
                v.0["id"] = json!(child.chain_id);
                clear_json(&mut v.0["payload"]);
                v.0["payload"] =
                    json!({"schema":1,"auth_token":child.auth_token,"enc_key":child.enc_key_b64()});
                child.chain_id.clone()
            } else {
                oldid
            }
        } else {
            oldid
        };
        let e = envelope(new, &kind, &id, &v.0)?;
        account.sealed.insert(
            sealed_key(&e.kind, &e.id_hash),
            SealedRecord {
                envelope: e,
                dirty: true,
                public_identity: None,
            },
        );
    }
    let mut targets = BTreeMap::new();
    for (oldid, source) in &source_spaces {
        let oldchild =
            record_merge::space_keys(&op.rotation.as_ref().unwrap().source_account, old, oldid)?
                .ok_or_else(|| error("source space unavailable"))?;
        let child = children.get(oldid).unwrap();
        let mut target = source.clone();
        target.cursor_seq = 0;
        target.baseline_established = false;
        target.missing = false;
        for row in target.records.values_mut() {
            row.seq = 0;
            row.dirty = true;
        }
        target.sealed.clear();
        for r in source.sealed.values() {
            let v = open(&oldchild, &r.envelope)?;
            let id = v.0["id"].as_str().unwrap();
            let e = envelope(child, &r.envelope.kind, id, &v.0)?;
            target.sealed.insert(
                sealed_key(&e.kind, &e.id_hash),
                SealedRecord {
                    envelope: e,
                    dirty: true,
                    public_identity: None,
                },
            );
        }
        targets.insert(child.chain_id.clone(), target);
    }
    op.prepared_account = account;
    op.rotation.as_mut().unwrap().target_spaces = targets;
    Ok(())
}
fn same_cipher(a: &Envelope, b: &Envelope) -> bool {
    a.kind == b.kind
        && a.id_hash == b.id_hash
        && a.nonce == b.nonce
        && a.ciphertext == b.ciphertext
        && a.deleted == b.deleted
}
fn complete_transport(
    records: &BTreeMap<String, LocalRecord>,
    sealed: &BTreeMap<String, SealedRecord>,
    keys: &ChainKeys,
    pulled: &crate::sync::relay::PullResponse,
    cursor: u64,
    baseline: bool,
) -> Result<(), AppError> {
    let known = records
        .values()
        .map(|r| r.seq)
        .chain(sealed.values().map(|r| r.envelope.seq))
        .max()
        .unwrap_or(0);
    if !record_merge::valid_pull(cursor, baseline, known, pulled, 0) {
        return Err(error("destination transport baseline is inconsistent"));
    }
    let present: BTreeSet<_> = pulled
        .records
        .iter()
        .map(|r| sealed_key(&r.kind, &r.id_hash))
        .collect();
    if records.values().filter(|r| !r.dirty && r.seq > 0).any(|r| {
        !present.contains(&sealed_key(
            r.record.kind.as_str(),
            &crypto::id_hash(keys, r.record.kind.as_str(), &r.record.id),
        ))
    }) || sealed
        .values()
        .filter(|r| !r.dirty && r.envelope.seq > 0)
        .any(|r| !present.contains(&sealed_key(&r.envelope.kind, &r.envelope.id_hash)))
    {
        return Err(error(
            "destination full baseline omitted an accepted record",
        ));
    }
    Ok(())
}

fn target_proof(
    env: &SyncEnv,
    op: &mut PendingAccountOperation,
    keys: &ChainKeys,
) -> Result<(), AppError> {
    crate::sync::record_round::preflight(env)?;
    let pulled = env
        .relay(&op.relay_url)?
        .pull(&keys.chain_id, &keys.auth_token, 0)?;
    limits(&pulled.records)?;
    let mut empty = AccountState::new(&keys.chain_id);
    empty.remote_schema_version = op.prepared_account.remote_schema_version;
    let check = record_merge::merge_account(&empty, keys, &pulled, 0);
    let authorized = match &check.gate {
        AccountGate::Compatible => {
            let meta = pulled
                .records
                .iter()
                .filter(|e| e.kind == "meta")
                .filter_map(|e| open(keys, e).ok())
                .find(|v| v.0["id"] == ACCOUNT_META_ID);
            meta.is_some_and(|v| {
                serde_json::from_value::<MigrationGate>(v.0["payload"]["migration"].clone())
                    .is_ok_and(|m| {
                        m.id == op.id
                            && m.source_digest == op.rotation.as_ref().unwrap().source_digest
                            && m.phase == MigrationPhase::Active
                    })
            })
        }
        AccountGate::MigrationPending(m) => {
            m.id == op.id && m.source_digest == op.rotation.as_ref().unwrap().source_digest
        }
        AccountGate::NeedsMigration { schema } => {
            *schema <= records_v3::ACCOUNT_SCHEMA && pulled.records.is_empty()
        }
        _ => false,
    };
    if !authorized {
        if let Some(v) = check
            .observed_schema
            .filter(|v| *v > records_v3::ACCOUNT_SCHEMA)
        {
            op.prepared_account.remote_schema_version = Some(v);
        }
        retain_blocked_gate(env, op)?;
        return Err(error(
            "destination format or marker prevents rotation; update SSHelter if it is newer",
        ));
    }
    complete_transport(
        &op.prepared_account.records,
        &op.prepared_account.sealed,
        keys,
        &pulled,
        op.prepared_account.cursor_seq,
        op.prepared_account.baseline_established,
    )?;
    for e in &pulled.records {
        let v = open(keys, e)?;
        let id = v.0["id"].as_str().unwrap();
        let wire = sealed_key(&e.kind, &e.id_hash);
        if let Some(row) = op.prepared_account.sealed.get_mut(&wire) {
            if !same_cipher(&row.envelope, e) {
                return Err(error(
                    "destination opaque or private record changed; review rotation",
                ));
            }
            row.envelope.seq = e.seq;
            row.dirty = false;
            continue;
        }
        let kind = RecordKind::parse(&e.kind)
            .ok_or_else(|| error("destination introduced an unknown record"))?;
        let row = op
            .prepared_account
            .records
            .get_mut(&record_key(kind, id))
            .ok_or_else(|| error("destination introduced an unexpected record"))?;
        let desired =
            serde_json::to_value(&row.record).map_err(|_| error("invalid destination record"))?;
        if v.0 == desired {
            row.seq = e.seq;
            row.dirty = false;
        } else if kind == RecordKind::Meta
            && id == ACCOUNT_META_ID
            && row.dirty
            && row.record.version > v.0["version"].as_u64().unwrap()
            && matches!(check.gate, AccountGate::MigrationPending(_))
        {
            row.seq = e.seq;
        } else {
            return Err(error("destination public record changed; review rotation"));
        }
    }
    op.prepared_account.cursor_seq = pulled.latest_seq;
    op.prepared_account.baseline_established = true;
    store(env, op.clone(), false)
}
#[derive(Clone)]
struct Sent {
    key: String,
    item: crate::sync::relay::PushItem,
    public: Option<Record>,
    cipher: Option<Envelope>,
    version: u64,
    time: u64,
}
fn outgoing(
    records: &BTreeMap<String, LocalRecord>,
    sealed: &BTreeMap<String, SealedRecord>,
    keys: &ChainKeys,
) -> Result<Vec<Sent>, AppError> {
    let mut sent = vec![];
    for (k, r) in records.iter().filter(|(_, r)| r.dirty) {
        sent.push(Sent {
            key: k.clone(),
            item: record_merge::encode_record(keys, &r.record, r.seq)?,
            public: Some(r.record.clone()),
            cipher: None,
            version: r.record.version,
            time: r.record.updated_at_ms,
        });
    }
    for (k, r) in sealed.iter().filter(|(_, r)| r.dirty) {
        let v = open(keys, &r.envelope)?;
        sent.push(Sent {
            key: k.clone(),
            item: crate::sync::relay::PushItem {
                id_hash: r.envelope.id_hash.clone(),
                kind: r.envelope.kind.clone(),
                nonce: r.envelope.nonce.clone(),
                ciphertext: r.envelope.ciphertext.clone(),
                deleted: r.envelope.deleted,
                base_seq: r.envelope.seq,
            },
            public: None,
            cipher: Some(r.envelope.clone()),
            version: v.0["version"].as_u64().unwrap(),
            time: v.0["updated_at_ms"].as_u64().unwrap(),
        });
    }
    Ok(sent)
}
fn receipts(
    records: &mut BTreeMap<String, LocalRecord>,
    sealed: &mut BTreeMap<String, SealedRecord>,
    sent: &[Sent],
    pushed: &crate::sync::merge::Pushed,
) {
    for s in sent {
        let Some((_, seq)) = pushed.accepted.iter().find(|(k, seq)| {
            k == &s.key && *seq > 0 && *seq <= 9_007_199_254_740_991 && *seq > s.item.base_seq
        }) else {
            continue;
        };
        if let Some(expected) = &s.public {
            if let Some(r) = records.get_mut(&s.key).filter(|r| r.record == *expected) {
                r.seq = *seq;
                r.dirty = false;
            }
        } else if let Some(expected) = &s.cipher {
            if let Some(r) = sealed
                .get_mut(&s.key)
                .filter(|r| same_cipher(&r.envelope, expected))
            {
                r.envelope.seq = *seq;
                r.dirty = false;
            }
        }
    }
}
fn push(
    env: &SyncEnv,
    op: &mut PendingAccountOperation,
    new: &ChainKeys,
    space: Option<&str>,
) -> Result<(), AppError> {
    target_proof(env, op, new)?;
    let keys = match space {
        Some(id) => record_merge::space_keys(&op.prepared_account, new, id)?
            .ok_or_else(|| error("destination space unavailable"))?,
        None => new.clone(),
    };
    let sent = if let Some(id) = space {
        let s = &op.rotation.as_ref().unwrap().target_spaces[id];
        outgoing(&s.records, &s.sealed, &keys)?
    } else {
        outgoing(
            &op.prepared_account.records,
            &op.prepared_account.sealed,
            &keys,
        )?
    };
    if sent.is_empty() {
        return Ok(());
    }
    let raw: Vec<_> = sent
        .iter()
        .map(|s| crate::sync::merge::Outgoing {
            key: s.key.clone(),
            item: s.item.clone(),
            version: s.version,
            updated_at_ms: s.time,
        })
        .collect();
    let relay = env.relay(&op.relay_url)?;
    ensure_latest(env, op)?;
    let pushed = crate::sync::merge::push_outgoing(&*relay, &keys.chain_id, &keys.auth_token, &raw);
    if let Some(id) = space {
        let s = op
            .rotation
            .as_mut()
            .unwrap()
            .target_spaces
            .get_mut(id)
            .unwrap();
        receipts(&mut s.records, &mut s.sealed, &sent, &pushed);
    } else {
        receipts(
            &mut op.prepared_account.records,
            &mut op.prepared_account.sealed,
            &sent,
            &pushed,
        );
    }
    store(env, op.clone(), true)?;
    if pushed.frozen || pushed.conflicts > 0 || pushed.error.is_some() {
        return Err(error(
            "destination publication is pending or conflicted; resume after review",
        ));
    }
    Ok(())
}
fn space_proof(
    env: &SyncEnv,
    op: &mut PendingAccountOperation,
    new: &ChainKeys,
    id: &str,
) -> Result<(), AppError> {
    target_proof(env, op, new)?;
    let keys = record_merge::space_keys(&op.prepared_account, new, id)?
        .ok_or_else(|| error("destination space credentials unavailable"))?;
    let pulled = env.relay(&op.relay_url)?.pull(id, &keys.auth_token, 0)?;
    let old = op.rotation.as_ref().unwrap().target_spaces[id].clone();
    complete_transport(
        &old.records,
        &old.sealed,
        &keys,
        &pulled,
        old.cursor_seq,
        old.baseline_established,
    )?;
    let merged = record_merge::merge_space(&old, &keys, &pulled, 0, &AccountGate::Compatible);
    if merged.gate != AccountGate::Compatible || !merged.conflicts.is_empty() {
        return Err(error("destination space baseline is inconsistent"));
    }
    for (k, r) in &old.records {
        if !r.dirty && merged.section.records.get(k).map(|x| &x.record) != Some(&r.record) {
            return Err(error("destination host changed; review rotation"));
        }
    }
    for (k, r) in &old.sealed {
        if !r.dirty
            && !merged
                .section
                .sealed
                .get(k)
                .is_some_and(|x| same_cipher(&r.envelope, &x.envelope))
        {
            return Err(error("destination opaque host changed; review rotation"));
        }
    }
    op.rotation
        .as_mut()
        .unwrap()
        .target_spaces
        .insert(id.into(), merged.section);
    store(env, op.clone(), false)
}
/// Caller owns lifecycle; source/target credentials stay in scoped Keychain until activation/cleanup.
pub(crate) fn resume_locked(env: &SyncEnv, provided: Option<&str>) -> Result<(), AppError> {
    crate::sync::record_round::preflight(env)?;
    let mut op = current(env)?;
    if op.kind != PendingAccountKind::RotateAccount {
        return Err(error("a different operation is pending"));
    }
    crate::sync::record_account::validate_pending(&op)?;
    let (new, phrase) = keys_for(env, &op, provided)?;
    if op.phase == PendingAccountPhase::Activated {
        target_proof(env, &mut op, &new)?;
        if let Some(source) = source_code(env, &op)? {
            let old = crypto::derive_account(&source)?;
            source_proof(env, &mut op, &old)?;
        }
        for name in [
            op.staged_code_account.as_deref().unwrap(),
            &op.rotation.as_ref().unwrap().source_code_account,
        ] {
            ensure_latest(env, &op)?;
            env.keychain
                .delete(name)
                .map_err(|_| error("rotation is active; scoped code cleanup is pending"))?;
        }
        record_runtime::mutate_records(env, |s| {
            if s.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str()) {
                return Err(crate::sync::runtime::superseded());
            }
            let mut n = s.clone();
            n.pending_account = None;
            n.last_error = None;
            Ok(n)
        })?;
        return Ok(());
    }
    let source = source_code(env, &op)?.ok_or_else(|| error("source code unavailable"))?;
    let old = crypto::derive_account(&source)?;
    let fresh = source_proof(env, &mut op, &old)?;
    ensure_latest(env, &op)?;
    // Destination proof precedes every retry credential write once the fixed target exists.
    if op
        .rotation
        .as_ref()
        .unwrap()
        .created
        .contains(&new.chain_id)
    {
        target_proof(env, &mut op, &new)?;
    }
    ensure_latest(env, &op)?;
    env.keychain
        .set(&op.rotation.as_ref().unwrap().source_code_account, &source)
        .map_err(|_| error("source code archive is pending"))?;
    ensure_latest(env, &op)?;
    env.keychain
        .set(op.staged_code_account.as_deref().unwrap(), &phrase)
        .map_err(|_| error("new code staging is pending"))?;
    let relay = env.relay(&op.relay_url)?;
    if matches!(
        op.rotation.as_ref().unwrap().step,
        RotationStep::Prepared | RotationStep::Freezing
    ) {
        op.rotation.as_mut().unwrap().step = RotationStep::Freezing;
        store(env, op.clone(), false)?;
        if !op.rotation.as_ref().unwrap().frozen.contains(&old.chain_id) {
            // Account freeze fixes membership before any child freeze; the source is never deleted.
            ensure_latest(env, &op)?;
            relay.freeze_chain(&old.chain_id, &old.auth_token)?;
            op.rotation
                .as_mut()
                .unwrap()
                .frozen
                .insert(old.chain_id.clone());
            store(env, op.clone(), true)?;
        }
        let (account, spaces) = source_full(
            env,
            &fresh,
            &old,
            &op.rotation.as_ref().unwrap().source_spaces,
        )?;
        op.rotation.as_mut().unwrap().source_account = account;
        op.rotation.as_mut().unwrap().source_spaces = spaces;
        let live_ids = op
            .rotation
            .as_ref()
            .unwrap()
            .source_spaces
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        op.rotation
            .as_mut()
            .unwrap()
            .space_ids
            .retain(|id, _| live_ids.contains(id));
        let ids: Vec<_> = op
            .rotation
            .as_ref()
            .unwrap()
            .source_spaces
            .keys()
            .cloned()
            .collect();
        for id in &ids {
            if !op.rotation.as_ref().unwrap().space_ids.contains_key(id) {
                op.rotation
                    .as_mut()
                    .unwrap()
                    .space_ids
                    .insert(id.clone(), ChainKeys::generate()?.chain_id);
            }
        }
        store(env, op.clone(), false)?;
        for id in &ids {
            if !op.rotation.as_ref().unwrap().frozen.contains(id) {
                let child = record_merge::space_keys(
                    &op.rotation.as_ref().unwrap().source_account,
                    &old,
                    id,
                )?
                .ok_or_else(|| error("source space unavailable"))?;
                ensure_latest(env, &op)?;
                relay.freeze_chain(id, &child.auth_token)?;
                op.rotation.as_mut().unwrap().frozen.insert(id.clone());
                store(env, op.clone(), true)?;
            }
        }
        let (account, spaces) = source_full(
            env,
            &op.rotation.as_ref().unwrap().source_account,
            &old,
            &op.rotation.as_ref().unwrap().source_spaces,
        )?;
        op.rotation.as_mut().unwrap().source_account = account;
        op.rotation.as_mut().unwrap().source_spaces = spaces;
        let bytes = serde_json::to_vec(&(
            &op.rotation.as_ref().unwrap().source_account,
            &op.rotation.as_ref().unwrap().source_spaces,
        ))
        .map_err(|_| error("cannot stamp source snapshot"))?;
        op.rotation.as_mut().unwrap().source_digest = digest(&bytes);
        prepare_targets(&mut op, &old, &new)?;
        let own = record_runtime::snapshot(env)?.0.device_id;
        if let Some(row) = op
            .prepared_account
            .records
            .get_mut(&record_key(RecordKind::Device, &own))
        {
            row.record.payload["name"] = json!(op.device_name);
        }
        op.rotation.as_mut().unwrap().step = RotationStep::Copying;
        store(env, op.clone(), false)?;
        let frozen_at = env.now();
        record_runtime::mutate_records(env, |s| {
            let mut n = s.clone();
            if let Some(a) = n.account.as_mut().filter(|a| a.chain_id == old.chain_id) {
                a.frozen = Some(crate::sync::state_v2::FreezeInfo {
                    detected_at_ms: frozen_at,
                    markers: vec![],
                });
                n.shared_writes_blocked = true;
            }
            Ok(n)
        })?;
    }
    if !op
        .rotation
        .as_ref()
        .unwrap()
        .created
        .contains(&new.chain_id)
    {
        ensure_latest(env, &op)?;
        relay.create_chain(&new.chain_id, &new.auth_token)?;
        op.rotation
            .as_mut()
            .unwrap()
            .created
            .insert(new.chain_id.clone());
        op.phase = PendingAccountPhase::RemoteCreated;
        store(env, op.clone(), true)?;
    }
    let ids: Vec<_> = op
        .rotation
        .as_ref()
        .unwrap()
        .target_spaces
        .keys()
        .cloned()
        .collect();
    for id in &ids {
        if !op.rotation.as_ref().unwrap().created.contains(id) {
            target_proof(env, &mut op, &new)?;
            let child = record_merge::space_keys(&op.prepared_account, &new, id)?
                .ok_or_else(|| error("destination space unavailable"))?;
            ensure_latest(env, &op)?;
            relay.create_chain(id, &child.auth_token)?;
            op.rotation.as_mut().unwrap().created.insert(id.clone());
            store(env, op.clone(), true)?;
        }
    }
    if op.rotation.as_ref().unwrap().step == RotationStep::Copying {
        push(env, &mut op, &new, None)?;
        for id in &ids {
            space_proof(env, &mut op, &new, id)?;
            push(env, &mut op, &new, Some(id))?;
            space_proof(env, &mut op, &new, id)?;
            let s = &op.rotation.as_ref().unwrap().target_spaces[id];
            if s.records.values().any(|r| r.dirty) || s.sealed.values().any(|r| r.dirty) {
                return Err(error("destination space receipts are incomplete"));
            }
        }
        target_proof(env, &mut op, &new)?;
        if op.prepared_account.records.values().any(|r| r.dirty)
            || op.prepared_account.sealed.values().any(|r| r.dirty)
        {
            return Err(error("destination account receipts are incomplete"));
        }
        let active = marker(&op, MigrationPhase::Active);
        let r = op
            .prepared_account
            .records
            .get_mut(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
            .ok_or_else(|| error("destination metadata missing"))?;
        r.record.version = r
            .record
            .version
            .checked_add(1)
            .ok_or_else(|| error("metadata revision exhausted"))?;
        r.record.updated_at_ms = r
            .record
            .updated_at_ms
            .checked_add(1)
            .ok_or_else(|| error("metadata timestamp exhausted"))?;
        r.record.payload["migration"] = serde_json::to_value(active).unwrap();
        r.dirty = true;
        op.rotation.as_mut().unwrap().step = RotationStep::Activating;
        op.phase = PendingAccountPhase::ActivationReady;
        store(env, op.clone(), false)?;
    }
    push(env, &mut op, &new, None)?;
    target_proof(env, &mut op, &new)?;
    source_proof(env, &mut op, &old)?;
    if op.prepared_account.records.values().any(|r| r.dirty)
        || op.prepared_account.sealed.values().any(|r| r.dirty)
    {
        return Err(error("destination account release receipt is incomplete"));
    }
    ensure_latest(env, &op)?;
    env.keychain
        .set(MNEMONIC_ACCOUNT, &phrase)
        .map_err(|_| error("new code promotion is pending; source archive is retained"))?;
    record_runtime::mutate_records(env, |s| {
        if s.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str()) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut n = s.clone();
        n.account = Some(op.prepared_account.clone());
        n.spaces = op.rotation.as_ref().unwrap().target_spaces.clone();
        n.device_name = op.device_name.clone();
        n.rotation = None;
        n.shared_writes_blocked = false;
        n.migration_gate = None;
        n.last_error = None;
        op.phase = PendingAccountPhase::Activated;
        n.pending_account = Some(op.clone());
        Ok(n)
    })?;
    resume_locked(env, None)
}
/// Predict the complete observed copy before staging credentials or freezing sources. The
/// serializer counts public/ciphertext bytes only, including worst-width transport receipts.
/// Remote edits racing the freeze still require the normal bounded post-freeze recheck.
fn check_storage_budget(
    state: &records_v3::SyncStateV3,
    op: &PendingAccountOperation,
    old: &ChainKeys,
    new: &ChainKeys,
    limit: u64,
) -> Result<(), AppError> {
    struct Budget {
        bytes: u64,
        limit: u64,
    }
    impl std::io::Write for Budget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| std::io::Error::other("rotation storage budget exhausted"))?;
            if self.bytes > self.limit {
                return Err(std::io::Error::other("rotation storage budget exhausted"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn receipts(account: &mut AccountState) {
        account.cursor_seq = 9_007_199_254_740_991;
        account.baseline_established = true;
        for row in account.records.values_mut() {
            row.seq = account.cursor_seq;
            row.dirty = false;
        }
        for row in account.sealed.values_mut() {
            row.envelope.seq = account.cursor_seq;
            row.dirty = false;
        }
    }
    let mut copy = op.clone();
    prepare_targets(&mut copy, old, new)?;
    if let Some(row) = copy
        .prepared_account
        .records
        .get_mut(&record_key(RecordKind::Device, &state.device_id))
    {
        row.record.payload["name"] = json!(op.device_name);
    }
    let meta = copy
        .prepared_account
        .records
        .get_mut(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        .ok_or_else(|| error("source metadata missing"))?;
    meta.record.version = meta
        .record
        .version
        .checked_add(1)
        .ok_or_else(|| error("source metadata stamp exhausted"))?;
    meta.record.updated_at_ms = meta
        .record
        .updated_at_ms
        .checked_add(1)
        .ok_or_else(|| error("source metadata stamp exhausted"))?;
    receipts(&mut copy.prepared_account);
    let plan = copy.rotation.as_mut().unwrap();
    plan.frozen = plan
        .source_spaces
        .keys()
        .cloned()
        .chain([plan.source_account.chain_id.clone()])
        .collect();
    plan.created = plan
        .target_spaces
        .keys()
        .cloned()
        .chain([new.chain_id.clone()])
        .collect();
    for space in plan.target_spaces.values_mut() {
        space.cursor_seq = 9_007_199_254_740_991;
        space.baseline_established = true;
        for row in space.records.values_mut() {
            row.seq = space.cursor_seq;
            row.dirty = false;
        }
        for row in space.sealed.values_mut() {
            row.envelope.seq = space.cursor_seq;
            row.dirty = false;
        }
    }
    copy.phase = PendingAccountPhase::ActivationReady;
    let mut candidate = state.clone();
    candidate.pending_account = Some(copy);
    let mut counter = Budget {
        bytes: 0,
        limit: limit.saturating_sub(8192),
    };
    serde_json::to_writer_pretty(&mut counter, &candidate).map_err(|_| {
        error("complete rotation copy exceeds the record storage budget; no source was frozen")
    })?;
    Ok(())
}

pub fn start_rotation(env: &SyncEnv, name: &str) -> Result<RotationCreation, AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    crate::sync::record_round::preflight(env)?;
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(error("device name must have 1 to 128 bytes"));
    }
    let initial = record_runtime::snapshot(env)?.0;
    if initial.pending_account.is_some()
        || initial.rotation.is_some()
        || records_v3::account_migration_pending(&initial)
        || records_v3::account_writes_blocked(&initial)
    {
        return Err(error(
            "finish pending migration or account work before rotation",
        ));
    }
    crate::sync::record_round::flush_for_rotation(env)?;
    let proof = crate::sync::record_round::fresh_account_gate(env)?;
    proof.ensure_compatible()?;
    let s = record_runtime::snapshot(env)?.0;
    let relay = env.relay(&s.relay_url)?;
    if !relay.info()?.supports(crate::sync::relay::FEATURE_FREEZE) {
        return Err(error(
            "the relay must support freeze before rotating records",
        ));
    }
    let source = s
        .account
        .as_ref()
        .ok_or_else(|| error("join or create a record account first"))?;
    let (account, spaces) = source_full(env, source, &proof.keys, &s.spaces)?;
    let meta = &account
        .records
        .get(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        .ok_or_else(|| error("source metadata unavailable"))?
        .record;
    if meta.version.checked_add(1).is_none() || meta.updated_at_ms.checked_add(1).is_none() {
        return Err(error(
            "source metadata stamp exhausted; review before rotation",
        ));
    }

    // Reserve the bounded growth from the pending marker, device name and previous space IDs.
    let account_bytes = relay
        .pull(&proof.keys.chain_id, &proof.keys.auth_token, 0)?
        .records
        .iter()
        .map(|r| r.ciphertext.len() + r.nonce.len() + r.kind.len() + r.id_hash.len())
        .sum::<usize>();
    if account_bytes
        .checked_add(1024)
        .and_then(|n| n.checked_add(spaces.len().saturating_mul(256)))
        .is_none_or(|n| n > 1024 * 1024)
    {
        return Err(error(
            "destination metadata exceeds the rotation storage budget",
        ));
    }
    let code = Zeroizing::new(crypto::generate_mnemonic()?);
    let keys = crypto::derive_account(&code)?;
    let id = new_id()?;
    let mut mapping = BTreeMap::new();
    for old in spaces.keys() {
        mapping.insert(old.clone(), ChainKeys::generate()?.chain_id);
    }
    let digest = digest(
        &serde_json::to_vec(&(&account, &spaces))
            .map_err(|_| error("cannot stamp source snapshot"))?,
    );
    let op = PendingAccountOperation {
        id: id.clone(),
        device_name: name.into(),
        kind: PendingAccountKind::RotateAccount,
        phase: PendingAccountPhase::Prepared,
        migration_gate: None,
        relay_url: s.relay_url.clone(),
        staged_code_account: Some(format!("{PENDING_CODE_PREFIX}{id}")),
        prepared_account: AccountState::new(&keys.chain_id),
        space_id: None,
        prepared_space: None,
        leave: None,
        rotation: Some(RotationPlan {
            step: RotationStep::Prepared,
            source_code_account: format!("{SOURCE_CODE_PREFIX}{id}"),
            source_account: account,
            source_spaces: spaces,
            space_ids: mapping,
            target_spaces: BTreeMap::new(),
            frozen: BTreeSet::new(),
            created: BTreeSet::new(),
            source_digest: digest,
        }),
    };
    check_storage_budget(&s, &op, &proof.keys, &keys, record_runtime::MAX_STATE_BYTES)?;
    store(env, op, false)?;
    let result = resume_locked(env, Some(&code));
    let receipt = RotationCreation {
        code,
        operation_id: id,
        complete: result.is_ok(),
        pending_error: result.err().map(|_| {
            "record rotation is pending; retain this new code and resume the operation".into()
        }),
    };
    drop(lifecycle);
    env.events.status();
    Ok(receipt)
}
#[cfg(test)]
#[path = "record_rotation_tests.rs"]
mod tests;

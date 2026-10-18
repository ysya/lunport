//! Local account detach with durable public mappings and resumable password namespace copies.
use crate::error::AppError;
use crate::sync::{
    env::SyncEnv,
    record::{record_key, LocalRecord, RecordKind},
    record_account::{PendingAccountKind, PendingAccountOperation, PendingAccountPhase},
    record_merge::{self, AccountGate},
    record_runtime,
    records_v3::{self, HostScope, SpaceStateV3, SyncStateV3, TypedRecord},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRemap {
    pub source_space_id: String,
    pub source_host_id: String,
    pub local_host_id: String,
    pub alias: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedHost {
    pub mapping: HostRemap,
    pub local: LocalRecord,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeavePlan {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<PlannedGroup>,
    pub source_spaces: BTreeMap<String, SpaceStateV3>,
    pub hosts: Vec<PlannedHost>,
    pub passwords_copied: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedGroup {
    pub source_space_id: String,
    pub source_group_id: String,
    pub local_group_id: String,
    pub local: LocalRecord,
}
#[derive(Clone, Debug, Serialize)]
pub struct LeaveReceipt {
    pub operation_id: String,
    pub complete: bool,
    pub copied_hosts: usize,
    pub mappings: Vec<HostRemap>,
    pub pending_error: Option<String>,
}
fn error(s: &str) -> AppError {
    AppError::Other(s.into())
}
fn new_id(bytes: usize) -> Result<String, AppError> {
    let mut b = vec![0; bytes];
    getrandom::fill(&mut b).map_err(|_| error("cannot create local preservation identity"))?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
fn remapped_group_name(name: &str, id: &str) -> String {
    format!("{}-{id}", name.chars().take(111).collect::<String>())
}
pub fn validate_plan(plan: &LeavePlan) -> Result<(), AppError> {
    let mut ids = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for (id, space) in &plan.source_spaces {
        if !crate::sync::crypto::is_chain_id(id) || !space.selected || space.missing {
            return Err(error("invalid leave source space"));
        }
        for (key, row) in &space.records {
            if *key != record_key(row.record.kind, &row.record.id)
                || !matches!(row.record.kind, RecordKind::Host | RecordKind::Group)
            {
                return Err(error("invalid leave source row"));
            }
            if row.record.kind == RecordKind::Group {
                records_v3::decode_group(
                    &row.record,
                    HostScope::Space {
                        space_id: id.clone(),
                    },
                )
                .map_err(|_| error("invalid leave source group"))?;
                continue;
            }
            records_v3::decode_host(
                &row.record,
                HostScope::Space {
                    space_id: id.clone(),
                },
            )
            .map_err(|_| error("invalid leave source host"))?;
        }
    }
    let remap: BTreeMap<_, _> = plan
        .hosts
        .iter()
        .map(|h| {
            (
                h.mapping.source_host_id.as_str(),
                h.mapping.local_host_id.as_str(),
            )
        })
        .collect();
    let group_remap: BTreeMap<_, _> = plan
        .groups
        .iter()
        .map(|g| (g.source_group_id.as_str(), g.local_group_id.as_str()))
        .collect();
    for host in &plan.hosts {
        let m = &host.mapping;
        if !records_v3::is_host_id(&m.local_host_id)
            || !ids.insert(&m.local_host_id)
            || !sources.insert((&m.source_space_id, &m.source_host_id))
        {
            return Err(error("invalid leave mapping identity"));
        }
        let source = plan
            .source_spaces
            .get(&m.source_space_id)
            .and_then(|s| {
                s.records
                    .get(&record_key(RecordKind::Host, &m.source_host_id))
            })
            .filter(|r| !r.record.deleted)
            .ok_or_else(|| error("leave mapping has no source"))?;
        let TypedRecord::Live(local) =
            records_v3::decode_host(&host.local.record, HostScope::Local)
                .map_err(|_| error("invalid planned local host"))?
        else {
            return Err(error("leave plan cannot copy a tombstone"));
        };
        let TypedRecord::Live(mut expected) =
            records_v3::decode_host(&source.record, HostScope::Local)
                .map_err(|_| error("invalid leave source host"))?
        else {
            return Err(error("leave source is deleted"));
        };
        if m.alias != expected.payload.alias
            && m.alias != format!("{}-{}", expected.payload.alias, m.local_host_id)
        {
            return Err(error("leave alias is not a stable source remap"));
        }
        expected.payload.alias = m.alias.clone();
        if let Some(id) = &mut expected.payload.group_id {
            *id = group_remap
                .get(id.as_str())
                .ok_or_else(|| error("missing preserved group"))?
                .to_string();
        }
        for jump in &mut expected.payload.jump {
            if let Some(target) = remap.get(jump.as_str()) {
                *jump = (*target).to_string();
            }
        }
        if local.payload != expected.payload {
            return Err(error("leave plan does not preserve its source host"));
        }
        if local.id != m.local_host_id
            || local.payload.alias != m.alias
            || host.local.seq != 0
            || host.local.dirty
            || source.record.id != m.source_host_id
        {
            return Err(error("inconsistent leave mapping"));
        }
    }
    for g in &plan.groups {
        if !ids.insert(&g.local_group_id)
            || !sources.insert((&g.source_space_id, &g.source_group_id))
        {
            return Err(error("duplicate preserved group identity"));
        }
        let source = plan
            .source_spaces
            .get(&g.source_space_id)
            .and_then(|s| {
                s.records
                    .get(&record_key(RecordKind::Group, &g.source_group_id))
            })
            .ok_or_else(|| error("group source missing"))?;
        let TypedRecord::Live(mut expected) =
            records_v3::decode_group(&source.record, HostScope::Local)
                .map_err(|_| error("invalid group source"))?
        else {
            return Err(error("deleted group source"));
        };
        let TypedRecord::Live(local) = records_v3::decode_group(&g.local.record, HostScope::Local)
            .map_err(|_| error("invalid preserved group"))?
        else {
            return Err(error("deleted preserved group"));
        };
        if let Some(parent) = &mut expected.payload.parent_id {
            *parent = group_remap
                .get(parent.as_str())
                .ok_or_else(|| error("missing preserved parent"))?
                .to_string();
        }
        if let Some(jumps) = &mut expected.payload.defaults.jump {
            for jump in jumps {
                if let Some(target) = remap.get(jump.as_str()) {
                    *jump = target.to_string();
                }
            }
        }
        if local.payload.name != expected.payload.name
            && local.payload.name != remapped_group_name(&expected.payload.name, &g.local_group_id)
        {
            return Err(error("group name is not a stable remap"));
        }
        expected.payload.name = local.payload.name.clone();
        if local.id != g.local_group_id
            || local.payload != expected.payload
            || g.local.seq != 0
            || g.local.dirty
        {
            return Err(error("group preservation mismatch"));
        }
    }
    if plan
        .passwords_copied
        .iter()
        .any(|id| !plan.hosts.iter().any(|h| &h.mapping.local_host_id == id))
    {
        return Err(error("invalid leave credential receipt"));
    }
    if plan
        .source_spaces
        .values()
        .map(|s| s.records.values().filter(|r| !r.record.deleted).count())
        .sum::<usize>()
        != plan.hosts.len() + plan.groups.len()
    {
        return Err(error("incomplete leave plan"));
    }
    Ok(())
}
fn source_spaces(
    env: &SyncEnv,
    account: &crate::sync::state_v2::AccountState,
    keys: &crate::sync::crypto::ChainKeys,
    cached: &BTreeMap<String, SpaceStateV3>,
) -> Result<BTreeMap<String, SpaceStateV3>, AppError> {
    let relay = env.relay(&record_runtime::snapshot(env)?.0.relay_url)?;
    let mut out = BTreeMap::new();
    for (id, old) in cached.iter().filter(|(_, s)| s.selected) {
        if old.missing {
            return Err(error(
                "a selected space is missing; local preservation did not complete",
            ));
        }
        let child = record_merge::space_keys(account, keys, id)?.ok_or_else(|| {
            error("a selected space is unavailable; local preservation did not complete")
        })?;
        let pulled = relay.pull(id, &child.auth_token, 0).map_err(|_| {
            error("a selected space could not be read; local preservation did not complete")
        })?;
        let merged = record_merge::merge_space(old, &child, &pulled, 0, &AccountGate::Compatible);
        if !merged.section.recovery.conflicts.is_empty() {
            return Err(error("Sync and resolve saved conflicts before leaving this account. Existing versions have been kept."));
        }
        if merged.gate != AccountGate::Compatible
            || !merged.baseline_established
            || merged.section.sealed.values().any(|r| {
                (r.envelope.kind == "group" || r.envelope.kind == "host")
                    && !r.envelope.deleted
                    && (!record_merge::is_legacy_alias_host(&child, &r.envelope)
                        || merged.section.records.values().any(|known| {
                            known.record.kind == RecordKind::Host
                                && crate::sync::crypto::id_hash(&child, "host", &known.record.id)
                                    == r.envelope.id_hash
                        }))
            })
        {
            return Err(error(
                "a selected space has unreadable hosts or groups; local preservation did not complete",
            ));
        }
        let mut section = merged.section;
        for (key, row) in old.records.iter().filter(|(_, r)| r.dirty) {
            section.records.insert(key.clone(), row.clone());
        }
        out.insert(id.clone(), section);
    }
    Ok(out)
}
fn check_source_key_material(
    state: &SyncStateV3,
    keys: &crate::sync::crypto::ChainKeys,
    spaces: &BTreeMap<String, SpaceStateV3>,
) -> Result<(), AppError> {
    let account = state
        .account
        .as_ref()
        .ok_or_else(|| error("source account changed"))?;
    let mut source = state.clone();
    source.spaces = spaces.clone();
    for view in crate::sync::record_repository::snapshot(&source)
        .map_err(|_| error("invalid source hosts"))?
        .hosts
        .into_iter()
        .filter(|h| matches!(h.host.scope, HostScope::Space { .. }))
    {
        let effective = crate::sync::record_groups::resolve_effective(&source, &view.host)
            .map_err(|_| error("invalid source inheritance"))?;
        let Some(id) = effective.payload.key_id.as_ref() else {
            continue;
        };
        let Some(local) = state.local.keys.get(id) else {
            continue;
        };
        if account
            .sealed
            .contains_key(&crate::sync::state_v2::sealed_key(
                "keyslot",
                &crate::sync::crypto::id_hash(keys, "keyslot", id),
            ))
        {
            if account
                .records
                .contains_key(&record_key(RecordKind::KeySlot, id))
                || record_merge::legacy_own_slot_revision(account, keys, id)
                    .map_err(|_| {
                        error("authoritative key metadata needs review before local detach")
                    })?
                    .is_none()
            {
                return Err(error(
                    "authoritative key metadata needs review before local detach",
                ));
            }
        }
        if let Some(row) = account.records.get(&record_key(RecordKind::KeySlot, id)) {
            match records_v3::decode_keyslot(&row.record)
                .map_err(|_| error("authoritative key needs review"))?
            {
                TypedRecord::Live(public) => {
                    records_v3::key_material_matches(
                        &public,
                        &local.public.public_key,
                        &local.public.fingerprint,
                    )
                    .map_err(|_| {
                        error("local key conflicts with the account; review before leaving")
                    })?;
                }
                TypedRecord::Tombstone { .. } => {
                    return Err(error(
                        "deleted account key cannot be revived by local detach",
                    ))
                }
            }
        }
    }
    Ok(())
}
fn ensure_latest(env: &SyncEnv, op: &PendingAccountOperation) -> Result<(), AppError> {
    crate::sync::record_round::preflight(env)?;
    let s = record_runtime::snapshot(env)?.0;
    let p = s
        .pending_account
        .as_ref()
        .filter(|p| p.id == op.id)
        .ok_or_else(crate::sync::runtime::superseded)?;
    if s.account.as_ref().is_some_and(|a| {
        a.remote_schema_version
            .is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA)
    }) || p
        .prepared_account
        .remote_schema_version
        .is_some_and(|v| v > records_v3::ACCOUNT_SCHEMA)
        || records_v3::account_migration_pending(&s)
    {
        return Err(error(
            "latest account observation prevents local detach effects",
        ));
    }
    Ok(())
}
fn local_hosts(state: &SyncStateV3) -> Result<Vec<records_v3::HostRecord>, AppError> {
    state
        .local
        .hosts
        .values()
        .filter(|r| !r.record.deleted)
        .map(|r| {
            match records_v3::decode_host(&r.record, HostScope::Local)
                .map_err(|_| error("invalid local host"))?
            {
                TypedRecord::Live(h) => Ok(h),
                _ => Err(error("invalid local host")),
            }
        })
        .collect()
}
fn plan(
    env: &SyncEnv,
    state: &SyncStateV3,
    spaces: BTreeMap<String, SpaceStateV3>,
) -> Result<LeavePlan, AppError> {
    let mut existing = local_hosts(state)?;
    let mut used_ids: BTreeSet<String> = state
        .local
        .hosts
        .values()
        .map(|r| r.record.id.clone())
        .collect();
    used_ids.extend(state.local.groups.values().map(|r| r.record.id.clone()));
    let local_ids = used_ids.clone();
    used_ids.extend(
        spaces
            .values()
            .flat_map(|s| s.records.values().map(|r| r.record.id.clone())),
    );
    let mut aliases: BTreeSet<String> = existing.iter().map(|r| r.payload.alias.clone()).collect();
    let mut remap = BTreeMap::new();
    let mut rows = Vec::new();
    for (sid, space) in &spaces {
        for source in space.records.values().filter(|r| !r.record.deleted) {
            if local_ids.contains(&source.record.id) || remap.contains_key(&source.record.id) {
                return Err(error(
                    "duplicate source host identity requires review before leaving",
                ));
            }
            let id = loop {
                let id = new_id(8)?;
                if used_ids.insert(id.clone()) {
                    break id;
                }
            };
            remap.insert(source.record.id.clone(), id.clone());
            rows.push((sid, source, id));
        }
    }
    let now = env.now();
    let mut hosts = Vec::new();
    let mut groups = Vec::new();
    let mut names: BTreeSet<_> = crate::sync::record_groups::list_groups(state)
        .map_err(|_| error("invalid existing groups"))?
        .into_iter()
        .filter(|g| g.group.scope == HostScope::Local)
        .map(|g| (g.group.payload.parent_id, g.group.payload.name))
        .collect();
    for (sid, source, id) in rows {
        if source.record.kind == RecordKind::Group {
            let TypedRecord::Live(mut g) =
                records_v3::decode_group(&source.record, HostScope::Local)
                    .map_err(|_| error("invalid source group"))?
            else {
                unreachable!()
            };
            if let Some(parent) = &mut g.payload.parent_id {
                *parent = remap
                    .get(parent)
                    .ok_or_else(|| error("missing source parent"))?
                    .clone();
            }
            if let Some(jumps) = &mut g.payload.defaults.jump {
                for jump in jumps {
                    if let Some(target) = remap.get(jump) {
                        *jump = target.clone();
                    }
                }
            }
            if !names.insert((g.payload.parent_id.clone(), g.payload.name.clone())) {
                g.payload.name = remapped_group_name(&g.payload.name, &id);
            }
            let mut record = source.record.clone();
            record.id = id.clone();
            record.version = 1;
            record.updated_at_ms = now;
            record.device_id = state.device_id.clone();
            record.payload = serde_json::to_value(g.payload).unwrap();
            groups.push(PlannedGroup {
                source_space_id: sid.clone(),
                source_group_id: source.record.id.clone(),
                local_group_id: id,
                local: LocalRecord {
                    record,
                    seq: 0,
                    dirty: false,
                },
            });
            continue;
        }
        let TypedRecord::Live(mut h) = records_v3::decode_host(&source.record, HostScope::Local)
            .map_err(|_| error("source host needs review before leaving"))?
        else {
            unreachable!()
        };
        h.id = id.clone();
        if let Some(group) = &mut h.payload.group_id {
            *group = remap
                .get(group)
                .ok_or_else(|| error("missing source group"))?
                .clone();
        }
        for jump in &mut h.payload.jump {
            if let Some(new) = remap.get(jump) {
                *jump = new.clone();
            }
        }
        if !aliases.insert(h.payload.alias.clone()) {
            h.payload.alias = format!("{}-{}", h.payload.alias, id);
            if !aliases.insert(h.payload.alias.clone()) {
                return Err(error("local alias collision requires review"));
            }
        }
        existing.push(h.clone());
        let mapping = HostRemap {
            source_space_id: sid.clone(),
            source_host_id: source.record.id.clone(),
            local_host_id: id.clone(),
            alias: h.payload.alias.clone(),
        };
        let mut record = source.record.clone();
        record.id = id;
        record.version = 1;
        record.updated_at_ms = now;
        record.device_id = state.device_id.clone();
        record.payload =
            serde_json::to_value(h.payload).map_err(|_| error("cannot prepare preserved host"))?;
        hosts.push(PlannedHost {
            mapping,
            local: LocalRecord {
                record,
                seq: 0,
                dirty: false,
            },
        });
    }
    let mut candidate = state.clone();
    candidate.spaces.clear();
    for g in &groups {
        candidate.local.groups.insert(
            record_key(RecordKind::Group, &g.local_group_id),
            g.local.clone(),
        );
    }
    let effective = existing
        .iter()
        .map(|h| {
            crate::sync::record_groups::resolve_effective(&candidate, h).map(|e| {
                records_v3::HostRecord {
                    payload: e.payload,
                    ..h.clone()
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error("source inheritance requires review"))?;
    records_v3::validate_hosts(&effective).map_err(|_| {
        error("selected hosts have unresolved routes or conflicts; review before leaving")
    })?;
    let plan = LeavePlan {
        groups,
        source_spaces: spaces,
        hosts,
        passwords_copied: BTreeSet::new(),
    };
    validate_plan(&plan)?;
    Ok(plan)
}
fn store(env: &SyncEnv, op: PendingAccountOperation) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |s| {
        if s.relay_url != op.relay_url || s.pending_account.as_ref().is_some_and(|p| p.id != op.id)
        {
            return Err(crate::sync::runtime::superseded());
        }
        let mut n = s.clone();
        n.pending_account = Some(op);
        Ok(n)
    })
    .map(|_| ())
}
fn proof(
    env: &SyncEnv,
    op: &PendingAccountOperation,
) -> Result<Option<crate::sync::crypto::ChainKeys>, AppError> {
    crate::sync::record_round::preflight(env)?;
    let s = record_runtime::snapshot(env)?.0;
    if s.account.is_some() {
        let p = crate::sync::record_round::fresh_account_gate(env)?;
        if p.keys.chain_id != op.prepared_account.chain_id
            || p.format_gate != AccountGate::Compatible
        {
            return Err(error("account format prevents local detach"));
        }
        return Ok(Some(p.keys));
    }
    let code = env
        .keychain
        .get(crate::sync::state::MNEMONIC_ACCOUNT)
        .map_err(|_| error("sync code cleanup is pending"))?
        .map(Zeroizing::new);
    let Some(code) = code else {
        if op.phase == PendingAccountPhase::Activated {
            return Ok(None);
        }
        return Err(error("source sync code is unavailable"));
    };
    let keys = crate::sync::crypto::derive_account(&code)?;
    if keys.chain_id != op.prepared_account.chain_id {
        return Err(error("source sync code changed; review pending detach"));
    }
    let pulled = env
        .relay(&op.relay_url)?
        .pull(&keys.chain_id, &keys.auth_token, 0)?;
    let merged = record_merge::merge_account(&op.prepared_account, &keys, &pulled, 0);
    if merged.gate != AccountGate::Compatible {
        let mut retained = op.clone();
        if let Some(schema) = merged
            .observed_schema
            .filter(|v| *v > records_v3::ACCOUNT_SCHEMA)
        {
            retained.prepared_account.remote_schema_version = Some(schema);
        }
        retained.migration_gate = match merged.gate {
            AccountGate::MigrationPending(m) => Some(m),
            _ => None,
        };
        if let Err(failure) = store(env, retained.clone()) {
            let mut core = env.runtime.core.lock().unwrap();
            let mut blocked = false;
            if let Some(state) = core
                .records
                .as_mut()
                .filter(|s| s.relay_url == retained.relay_url)
            {
                if let Some(latest) = state
                    .pending_account
                    .as_mut()
                    .filter(|p| p.id == retained.id)
                {
                    latest.prepared_account.remote_schema_version = latest
                        .prepared_account
                        .remote_schema_version
                        .into_iter()
                        .chain(retained.prepared_account.remote_schema_version)
                        .max();
                    latest.migration_gate = retained.migration_gate;
                    state.last_error =
                        Some("an authenticated detach gate could not be saved".into());
                    state.shared_writes_blocked = true;
                    blocked = true;
                }
            }
            if blocked {
                core.save_blocked=Some("an authenticated detach gate could not be saved; repair record storage before resuming".into());
            }
            return Err(failure);
        }
        return Err(error("account format prevents sync code cleanup"));
    }
    Ok(Some(keys))
}
/// Caller owns lifecycle. No vault/doc locks, relay mutations or source-password deletion.
pub(crate) fn resume_locked(env: &SyncEnv) -> Result<(), AppError> {
    crate::sync::record_round::preflight(env)?;
    let mut op = record_runtime::snapshot(env)?
        .0
        .pending_account
        .ok_or_else(|| error("no detach is pending"))?;
    if op.kind != PendingAccountKind::LeaveAccount {
        return Err(error("a different operation is pending"));
    }
    crate::sync::record_account::validate_pending(&op)?;
    let keys = proof(env, &op)?;
    if op.phase != PendingAccountPhase::Activated {
        let s = record_runtime::snapshot(env)?.0;
        let account = s
            .account
            .as_ref()
            .ok_or_else(|| error("source account changed"))?;
        let source = source_spaces(
            env,
            account,
            keys.as_ref().unwrap(),
            &op.leave.as_ref().unwrap().source_spaces,
        )?;
        check_source_key_material(&s, keys.as_ref().unwrap(), &source)?;
        let expected = &op.leave.as_ref().unwrap().source_spaces;
        for (id, space) in &source {
            let a = &expected[id];
            if space
                .records
                .iter()
                .map(|(k, r)| (k, &r.record))
                .collect::<BTreeMap<_, _>>()
                != a.records
                    .iter()
                    .map(|(k, r)| (k, &r.record))
                    .collect::<BTreeMap<_, _>>()
            {
                return Err(error(
                    "source hosts changed; review pending local preservation",
                ));
            }
        }
        let planned = op.leave.as_ref().unwrap().hosts.clone();
        for h in planned {
            ensure_latest(env, &op)?;
            let source_name = format!("host:{}", h.mapping.source_host_id);
            let target_name = format!("host:{}", h.mapping.local_host_id);
            let source = env
                .keychain
                .get(&source_name)
                .map_err(|_| error("source password could not be read"))?
                .map(Zeroizing::new);
            let target = env
                .keychain
                .get(&target_name)
                .map_err(|_| error("target password could not be read"))?
                .map(Zeroizing::new);
            ensure_latest(env, &op)?;
            match (&source, &target) {
                (Some(a), Some(b)) if **a == **b => {}
                (None, None) => {}
                (Some(a), None) => {
                    env.keychain
                        .set(&target_name, a)
                        .map_err(|_| error("password namespace copy is pending"))?;
                }
                _ => return Err(error("target password differs; review before continuing")),
            }
            op.leave
                .as_mut()
                .unwrap()
                .passwords_copied
                .insert(h.mapping.local_host_id);
            store(env, op.clone())?;
        }
        proof(env, &op)?;
        ensure_latest(env, &op)?;
        record_runtime::mutate_records(env, |latest| {
            if latest.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str())
                || latest.account.as_ref().map(|a| a.chain_id.as_str())
                    != Some(op.prepared_account.chain_id.as_str())
            {
                return Err(crate::sync::runtime::superseded());
            }
            let mut n = latest.clone();
            for h in &op.leave.as_ref().unwrap().hosts {
                let k = record_key(RecordKind::Host, &h.mapping.local_host_id);
                if n.local.hosts.contains_key(&k) {
                    return Err(error("planned local identity became occupied"));
                }
                n.local.hosts.insert(k, h.local.clone());
            }
            for g in &op.leave.as_ref().unwrap().groups {
                let key = record_key(RecordKind::Group, &g.local_group_id);
                if n.local.groups.contains_key(&key) {
                    return Err(error("planned group identity became occupied"));
                }
                n.local.groups.insert(key, g.local.clone());
            }
            let effective = local_hosts(&n)?
                .into_iter()
                .map(|h| {
                    crate::sync::record_groups::resolve_effective(&n, &h).map(|e| {
                        records_v3::HostRecord {
                            payload: e.payload,
                            ..h
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| error("preserved inheritance needs review"))?;
            records_v3::validate_hosts(&effective)
                .map_err(|_| error("latest local routes conflict with preservation plan"))?;
            let order = crate::sync::group_order::view(latest).ids;
            n.local.group_order = order
                .into_iter()
                .map(|id| {
                    op.leave
                        .as_ref()
                        .unwrap()
                        .groups
                        .iter()
                        .find(|g| g.source_group_id == id)
                        .map_or(id.clone(), |g| g.local_group_id.clone())
                })
                .collect();
            if !n.local.group_order.is_empty() {
                n.version = n.version.max(records_v3::NAVIGATION_STATE_VERSION);
            }
            n.account = None;
            n.spaces.clear();
            n.rotation = None;
            n.migration_gate = None;
            n.shared_writes_blocked = false;
            n.last_error = None;
            op.phase = PendingAccountPhase::Activated;
            n.pending_account = Some(op.clone());
            Ok(n)
        })?;
    }
    // An absent code after Activated means cleanup already succeeded, including a disk-clear failure.
    if proof(env, &op)?.is_some() {
        ensure_latest(env, &op)?;
        env.keychain
            .delete(crate::sync::state::MNEMONIC_ACCOUNT)
            .map_err(|_| error("local data is preserved; sync code cleanup is pending"))?;
    }
    record_runtime::mutate_records(env, |s| {
        if s.pending_account.as_ref().map(|p| p.id.as_str()) != Some(op.id.as_str())
            || s.account.is_some()
        {
            return Err(crate::sync::runtime::superseded());
        }
        let mut n = s.clone();
        n.pending_account = None;
        n.last_error = None;
        Ok(n)
    })?;
    Ok(())
}
pub fn leave_account(env: &SyncEnv) -> Result<LeaveReceipt, AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    crate::sync::record_round::preflight(env)?;
    let s = record_runtime::snapshot(env)?.0;
    if s.pending_account.is_some() {
        return Err(error("finish the pending record operation before leaving"));
    }
    if records_v3::account_migration_pending(&s) {
        return Err(error("finish account migration before leaving"));
    }
    let p = crate::sync::record_round::fresh_account_gate(env)?;
    if p.format_gate != AccountGate::Compatible {
        return Err(error("account format prevents local detach"));
    }
    let s = record_runtime::snapshot(env)?.0;
    crate::sync::record_conflicts::require_resolved(&s)?;
    let account = s.account.as_ref().unwrap();
    let spaces = source_spaces(env, account, &p.keys, &s.spaces)?;
    check_source_key_material(&s, &p.keys, &spaces)?;
    let plan = plan(env, &s, spaces)?;
    let id = new_id(16)?;
    let mappings = plan
        .hosts
        .iter()
        .map(|h| h.mapping.clone())
        .collect::<Vec<_>>();
    let op = PendingAccountOperation {
        id: id.clone(),
        device_name: s.device_name.clone(),
        kind: PendingAccountKind::LeaveAccount,
        phase: PendingAccountPhase::Prepared,
        migration_gate: None,
        relay_url: s.relay_url,
        staged_code_account: None,
        prepared_account: account.clone(),
        space_id: None,
        prepared_space: None,
        leave: Some(plan),
        rotation: None,
    };
    store(env, op)?;
    let result = resume_locked(env);
    let receipt = LeaveReceipt {
        operation_id: id,
        complete: result.is_ok(),
        copied_hosts: if record_runtime::snapshot(env)?.0.account.is_none() {
            mappings.len()
        } else {
            0
        },
        mappings,
        pending_error: result.err().map(|_| {
            "local preservation or credential cleanup is pending; resume the operation".into()
        }),
    };
    drop(lifecycle);
    env.events.status();
    Ok(receipt)
}
#[cfg(test)]
#[path = "record_leave_tests.rs"]
mod tests;

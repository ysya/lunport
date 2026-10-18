use super::*;
use crate::{
    error::AppError,
    sync::{
        crypto::ChainKeys,
        env::SyncEnv,
        record::{Record, RecordKind},
        records_v3::{HostScope, SyncStateV3},
    },
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize)]
pub struct VersionView {
    seq: String,
    record: Option<Record>,
    deleted: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ConflictView {
    space_id: Option<String>,
    key: String,
    token: String,
    pub label: String,
    base: Option<VersionView>,
    local: VersionView,
    remote: Vec<VersionView>,
    can_copy_remote: bool,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Local,
    Remote,
    CopyRemote,
}
fn error(message: &str) -> AppError {
    AppError::Other(message.into())
}
fn view(version: &RecordVersion) -> VersionView {
    match version {
        RecordVersion::Public(row) => VersionView {
            seq: row.seq.to_string(),
            record: Some(row.record.clone()),
            deleted: row.record.deleted,
        },
        RecordVersion::Sealed(row) => VersionView {
            seq: row.envelope.seq.to_string(),
            record: None,
            deleted: row.envelope.deleted,
        },
    }
}
fn token(
    state: &SyncStateV3,
    space: Option<&str>,
    key: &str,
    conflicts: &[RecordConflict],
    current: &RecordVersion,
) -> Result<String, AppError> {
    let bytes = serde_json::to_vec(&(
        "lunport-local-conflict-v1",
        &state.device_id,
        &state.relay_url,
        state.account.as_ref().map(|a| &a.chain_id),
        space,
        key,
        conflicts,
        current,
    ))
    .map_err(|_| error("Cannot inspect the saved conflict."))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn current(
    records: &BTreeMap<String, LocalRecord>,
    sealed: &BTreeMap<String, SealedRecord>,
    key: &str,
    versions: &[RecordConflict],
) -> Result<RecordVersion, AppError> {
    match versions.first().map(|c| &c.local) {
        Some(RecordVersion::Public(_)) => records.get(key).cloned().map(RecordVersion::Public),
        Some(RecordVersion::Sealed(_)) => sealed.get(key).cloned().map(RecordVersion::Sealed),
        None => None,
    }
    .ok_or_else(|| error("The conflict changed. Refresh before resolving it."))
}
pub fn views(state: &SyncStateV3) -> Result<Vec<ConflictView>, AppError> {
    let mut result = Vec::new();
    let mut append = |space: Option<&str>,
                      recovery: &RecordRecovery,
                      records: &BTreeMap<String, LocalRecord>,
                      sealed: &BTreeMap<String, SealedRecord>|
     -> Result<(), AppError> {
        for (key, conflicts) in &recovery.conflicts {
            let local = current(records, sealed, key, conflicts)?;
            let label = match &local {
                RecordVersion::Public(row) => row
                    .record
                    .payload
                    .get("alias")
                    .or_else(|| row.record.payload.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(&row.record.id)
                    .to_owned(),
                RecordVersion::Sealed(row) => if row.envelope.kind == "key" {
                    "Encrypted SSH key"
                } else {
                    "Encrypted space credentials"
                }
                .into(),
            };
            let mut remote: Vec<_> = conflicts.iter().map(|c| &c.remote).collect();
            remote.sort_by_key(|row| row.seq());
            let can_copy_remote = matches!(remote.last(), Some(RecordVersion::Public(row)) if row.record.kind == RecordKind::Host && !row.record.deleted);
            result.push(ConflictView {
                space_id: space.map(str::to_owned),
                key: key.clone(),
                token: token(state, space, key, conflicts, &local)?,
                label,
                base: conflicts.first().and_then(|c| c.base.as_ref()).map(view),
                local: view(&local),
                remote: remote.into_iter().map(view).collect(),
                can_copy_remote,
            });
        }
        Ok(())
    };
    if let Some(account) = &state.account {
        append(None, &account.recovery, &account.records, &account.sealed)?;
    }
    for (id, space) in &state.spaces {
        append(Some(id), &space.recovery, &space.records, &space.sealed)?;
    }
    Ok(result)
}
fn rebase_public(
    mut local: LocalRecord,
    remote: &[RecordVersion],
    device: &str,
    now: u64,
) -> Result<LocalRecord, AppError> {
    for row in remote {
        let RecordVersion::Public(row) = row else {
            return Err(error("Invalid saved conflict."));
        };
        local.record.version = local.record.version.max(row.record.version);
        local.record.updated_at_ms = local.record.updated_at_ms.max(row.record.updated_at_ms);
    }
    local.record.version = local
        .record
        .version
        .checked_add(1)
        .ok_or_else(|| error("Record version exhausted."))?;
    local.record.updated_at_ms = local
        .record
        .updated_at_ms
        .checked_add(1)
        .ok_or_else(|| error("Record timestamp exhausted."))?
        .max(now);
    local.record.device_id = device.into();
    local.seq = remote
        .iter()
        .map(RecordVersion::seq)
        .max()
        .unwrap_or(local.seq);
    local.dirty = true;
    Ok(local)
}
fn resolve(
    state: &SyncStateV3,
    space_id: Option<&str>,
    key: &str,
    expected: &str,
    choice: Resolution,
    copy_alias: Option<&str>,
    keys: Option<&ChainKeys>,
    now: u64,
) -> Result<SyncStateV3, AppError> {
    if state.pending_account.is_some()
        || state.rotation.is_some()
        || crate::sync::records_v3::account_migration_pending(state)
    {
        return Err(error(
            "Finish the pending account operation before resolving conflicts.",
        ));
    }
    let (recovery, records, sealed) = if let Some(id) = space_id {
        let section = state
            .spaces
            .get(id)
            .ok_or_else(|| error("The conflict space is unavailable."))?;
        (&section.recovery, &section.records, &section.sealed)
    } else {
        let section = state
            .account
            .as_ref()
            .ok_or_else(|| error("The conflict account is unavailable."))?;
        (&section.recovery, &section.records, &section.sealed)
    };
    let conflicts = recovery
        .conflicts
        .get(key)
        .ok_or_else(|| error("The conflict has already been resolved."))?;
    let local = current(records, sealed, key, conflicts)?;
    if token(state, space_id, key, conflicts, &local)? != expected {
        return Err(error(
            "The conflict changed. Review the current versions before resolving it.",
        ));
    }
    let remote: Vec<_> = conflicts.iter().map(|c| c.remote.clone()).collect();
    let latest = remote
        .iter()
        .max_by_key(|r| r.seq())
        .ok_or_else(|| error("The conflict has no remote version."))?;
    let mut next = state.clone();
    if matches!(choice, Resolution::CopyRemote) {
        let RecordVersion::Public(row) = latest else {
            return Err(error("Encrypted credentials cannot be copied as hosts."));
        };
        if row.record.kind != RecordKind::Host || row.record.deleted {
            return Err(error("Only a live host can be saved as a copy."));
        }
        let scope = HostScope::Space {
            space_id: space_id
                .ok_or_else(|| error("The host space is unavailable."))?
                .into(),
        };
        let crate::sync::records_v3::TypedRecord::Live(host) =
            crate::sync::records_v3::decode_host(&row.record, scope.clone())
                .map_err(|_| error("The remote host cannot be copied."))?
        else {
            return Err(error("A deleted host cannot be copied."));
        };
        let mut payload = host.payload;
        payload.alias = copy_alias
            .ok_or_else(|| error("Enter a name for the copied host."))?
            .trim()
            .into();
        next = crate::sync::record_repository::create_host(
            &next,
            &crate::sync::record_commands::new_host_id()?,
            scope,
            payload,
            now,
        )
        .map_err(|e| error(&e.to_string()))?;
    }
    let resolved = if matches!(choice, Resolution::Remote) {
        latest.clone()
    } else {
        match local {
            RecordVersion::Public(local) => {
                RecordVersion::Public(rebase_public(local, &remote, &state.device_id, now)?)
            }
            RecordVersion::Sealed(local) => {
                RecordVersion::Sealed(crate::sync::record_merge::rebase_conflicted_secret(
                    &local,
                    &remote,
                    keys.ok_or_else(|| {
                        error("Unlock the sync account to resolve encrypted credentials.")
                    })?,
                    &state.device_id,
                    now,
                )?)
            }
        }
    };
    let (recovery, records, sealed) = if let Some(id) = space_id {
        let section = next.spaces.get_mut(id).unwrap();
        (
            &mut section.recovery,
            &mut section.records,
            &mut section.sealed,
        )
    } else {
        let section = next.account.as_mut().unwrap();
        (
            &mut section.recovery,
            &mut section.records,
            &mut section.sealed,
        )
    };
    let space_status = match &resolved {
        RecordVersion::Public(row)
            if row.record.kind == RecordKind::Space && space_id.is_none() =>
        {
            Some((row.record.id.clone(), row.record.deleted))
        }
        _ => None,
    };
    match resolved {
        RecordVersion::Public(row) => {
            records.insert(key.into(), row);
        }
        RecordVersion::Sealed(row) => {
            sealed.insert(key.into(), row);
        }
    }
    recovery.bases.insert(key.into(), latest.clone());
    recovery.conflicts.remove(key);
    if let Some((id, deleted)) = space_status {
        if let Some(space) = next.spaces.get_mut(&id) {
            space.missing = deleted;
        }
    }
    Ok(next)
}
pub fn resolve_saved(
    env: &SyncEnv,
    space: Option<&str>,
    key: &str,
    expected: &str,
    choice: Resolution,
    copy_alias: Option<&str>,
) -> Result<crate::sync::record_commands::RecordOverview, AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    crate::sync::record_round::preflight(env)?;
    let (state, _) = crate::sync::record_runtime::snapshot(env)?;
    let keys = if space.is_none() && !matches!(choice, Resolution::Remote) {
        crate::sync::record_runtime::read_account_keys(&state, env.keychain)?
    } else {
        None
    };
    crate::sync::record_runtime::mutate_records(env, |latest| {
        resolve(
            latest,
            space,
            key,
            expected,
            choice,
            copy_alias,
            keys.as_ref(),
            env.now(),
        )
    })?;
    drop(lifecycle);
    let overview = crate::sync::record_commands::overview(env)?;
    env.events.status();
    env.events.wake();
    Ok(overview)
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

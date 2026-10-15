//! One user-facing library, backed by the existing encrypted record transport.
//! Per-device opt-in is public device metadata; old clients can ignore it.
use crate::error::AppError;
use crate::sync::{
    env::SyncEnv,
    record::{record_key, LocalRecord, RecordKind},
    record_repository::{self as repo, RepositoryError},
    record_runtime,
    records_v3::{HostScope, SyncStateV3},
};

const LIBRARY_SLUG: &str = "sshelter-library";
const DEVICE_FLAG: &str = "sync_library";

pub fn enabled(state: &SyncStateV3) -> bool {
    state
        .account
        .as_ref()
        .and_then(|a| {
            a.records
                .get(&record_key(RecordKind::Device, &state.device_id))
        })
        .is_some_and(|r| {
            !r.record.deleted
                && r.record
                    .payload
                    .get(DEVICE_FLAG)
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
        })
}
pub fn space_id(state: &SyncStateV3) -> Option<String> {
    state
        .account
        .as_ref()?
        .records
        .values()
        .filter(|r| {
            r.record.kind == RecordKind::Space
                && !r.record.deleted
                && r.record
                    .payload
                    .get("slug")
                    .and_then(serde_json::Value::as_str)
                    == Some(LIBRARY_SLUG)
        })
        .map(|r| r.record.id.clone())
        .min()
}
pub fn creation_scope(state: &SyncStateV3) -> Result<HostScope, RepositoryError> {
    if !enabled(state) {
        return Ok(HostScope::Local);
    }
    let id = space_id(state).ok_or_else(|| RepositoryError::SpaceUnavailable("library".into()))?;
    let scope = HostScope::Space { space_id: id };
    repo::ensure_scope(state, &scope)?;
    Ok(scope)
}

/// Move public records together, preserving IDs, raw inheritance, routes, pins and local keys.
/// No mutation is published if any destination ID/name or relationship conflicts.
pub(crate) fn include_existing(
    state: &SyncStateV3,
    destination: &str,
    confirmed: bool,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let scope = HostScope::Space {
        space_id: destination.into(),
    };
    repo::ensure_scope(state, &scope)?;
    let target = &state.spaces[destination];
    if !target.baseline_established
        || state
            .spaces
            .values()
            .any(|s| s.selected && !s.missing && !s.baseline_established)
    {
        return Err(RepositoryError::SpaceUnavailable(
            "Finish downloading the library before including existing records".into(),
        ));
    }
    for (rows, expected) in [
        (&state.local.groups, RecordKind::Group),
        (&state.local.hosts, RecordKind::Host),
    ] {
        for (key, row) in rows {
            repo::validate_cache(key, row)?;
            if row.record.kind != expected {
                return Err(repo::invalid(
                    "library",
                    &row.record.id,
                    "record kind does not match its source collection",
                ));
            }
        }
    }
    let rows: Vec<_> = state
        .local
        .groups
        .values()
        .chain(state.local.hosts.values())
        .filter(|r| !r.record.deleted)
        .cloned()
        .collect();
    if rows.is_empty() {
        return Ok(state.clone());
    }
    let mut next = state.clone();
    if rows.iter().any(|r| {
        r.record.kind == RecordKind::Group
            || r.record
                .payload
                .get("schema")
                .and_then(serde_json::Value::as_u64)
                == Some(3)
    }) {
        crate::sync::record_groups::promote(&mut next, &scope, confirmed, now)?;
    }
    for row in &rows {
        let id = &row.record.id;
        let kind = row.record.kind;
        let key = record_key(kind, id);
        for space in state.spaces.values() {
            if space.records.get(&key).is_some_and(|r| !r.record.deleted)
                || space.sealed.values().any(|r| {
                    r.envelope.kind == kind.as_str()
                        && (r.public_identity.is_none()
                            || r.public_identity.as_ref().is_some_and(|p| p.id == *id))
                })
            {
                return Err(RepositoryError::Validation(
                    crate::sync::records_v3::RecordValidationError::DuplicateId(id.clone()),
                ));
            }
        }
        let existing = target.records.get(&key);
        let mut previous = vec![&row.record];
        if let Some(existing) = existing {
            repo::validate_cache(&key, existing)?;
            previous.push(&existing.record);
        }
        let mut record =
            repo::ordered_record(state, id, row.record.payload.clone(), false, now, &previous)?;
        record.kind = kind;
        let mut tombstone = record.clone();
        tombstone.deleted = true;
        tombstone.payload = serde_json::Value::Null;
        let source = if kind == RecordKind::Group {
            &mut next.local.groups
        } else {
            &mut next.local.hosts
        };
        source.insert(
            key.clone(),
            repo::cached(tombstone, row.seq, &HostScope::Local),
        );
        next.spaces.get_mut(destination).unwrap().records.insert(
            key,
            repo::cached(record, existing.map_or(0, |r| r.seq), &scope),
        );
    }
    crate::sync::record_groups::validate_groups(&next, &scope)?;
    repo::validate_transition(state, &next)?;
    crate::sync::records_v3::validate_state(&next)?;
    Ok(next)
}

/// Used inside the atomic state publication. Failed inclusion leaves the saved records
/// inspectable and the UI reports them as requiring sync setup; unrelated pulls still work.
pub(crate) fn include_new_records(state: SyncStateV3) -> SyncStateV3 {
    if !enabled(&state) || crate::sync::records_v3::account_writes_blocked(&state) {
        return state;
    }
    if !state
        .local
        .hosts
        .values()
        .chain(state.local.groups.values())
        .any(|r| !r.record.deleted)
    {
        return state;
    }
    let Some(id) = space_id(&state) else {
        return state;
    };
    include_existing(&state, &id, false, 0).unwrap_or(state)
}

pub(crate) fn select_library_spaces(state: &mut SyncStateV3) {
    if enabled(state) {
        for space in state.spaces.values_mut().filter(|s| !s.missing) {
            space.selected = true;
        }
    }
}

/// Setup can be retried after a failed child-chain creation or publication. Existing
/// resumable account operations retain their original identities.
pub fn enable(env: &SyncEnv, confirmed: bool) -> Result<(), AppError> {
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        crate::sync::record_round::fresh_account_gate(env)?.ensure_compatible()?;
    }
    let (state, _) = record_runtime::snapshot(env)?;
    if space_id(&state).is_none() {
        crate::sync::record_account::create_library_space(env)?;
    }
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        crate::sync::record_round::fresh_account_gate(env)?.ensure_compatible()?;
        record_runtime::mutate_records(env, |state| {
            let mut next = state.clone();
            for space in next.spaces.values_mut().filter(|s| !s.missing) {
                space.selected = true;
            }
            Ok(next)
        })?;
    }
    // Establish authoritative space baselines before checking IDs and names.
    let report = crate::sync::record_round::sync_once(env)?;
    if report.review_required
        || report.gate != Some(crate::sync::record_merge::AccountGate::Compatible)
    {
        return Err(AppError::Other(
            "Review sync account data before including the library".into(),
        ));
    }
    {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        crate::sync::record_round::fresh_account_gate(env)?.ensure_compatible()?;
        let now = env.now();
        record_runtime::mutate_records(env, |state| {
            let id = space_id(state)
                .ok_or_else(|| AppError::Other("The sync library is unavailable".into()))?;
            let mut next = include_existing(state, &id, confirmed, now)
                .map_err(|e| AppError::Other(e.to_string()))?;
            let key = record_key(RecordKind::Device, &state.device_id);
            let previous = state
                .account
                .as_ref()
                .and_then(|a| a.records.get(&key))
                .ok_or_else(|| AppError::Other("Device metadata is unavailable".into()))?;
            if !enabled(state) {
                let mut payload = previous.record.payload.clone();
                payload[DEVICE_FLAG] = true.into();
                let mut record = repo::ordered_record(
                    state,
                    &state.device_id,
                    payload,
                    false,
                    now,
                    &[&previous.record],
                )
                .map_err(|e| AppError::Other(e.to_string()))?;
                record.kind = RecordKind::Device;
                next.account.as_mut().unwrap().records.insert(
                    key,
                    LocalRecord {
                        record,
                        seq: previous.seq,
                        dirty: true,
                    },
                );
            }
            Ok(next)
        })?;
    }
    env.events.status();
    env.events.wake();
    Ok(())
}

pub(crate) fn library_slug() -> &'static str {
    LIBRARY_SLUG
}
pub(crate) fn group_scope(state: &SyncStateV3, id: &str) -> Result<HostScope, RepositoryError> {
    let groups = crate::sync::record_groups::list_groups(state)?;
    let matching: Vec<_> = groups.iter().filter(|g| g.group.id == id).collect();
    if matching.len() != 1 || matching[0].group_error.is_some() {
        return Err(RepositoryError::Group(
            "Group is unavailable or needs review".into(),
        ));
    }
    repo::ensure_scope(state, &matching[0].group.scope)?;
    Ok(matching[0].group.scope.clone())
}
pub(crate) fn update_host(
    state: &SyncStateV3,
    id: &str,
    revision: &repo::RecordRevision,
    payload: crate::sync::records_v3::HostPayload,
    confirmed: bool,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let saved = repo::get_host(state, id)?;
    let destination = if enabled(state) {
        payload
            .group_id
            .as_deref()
            .map(|id| group_scope(state, id))
            .transpose()?
    } else {
        None
    };
    let moved = if let Some(scope) = destination.filter(|scope| scope != &saved.host.scope) {
        repo::move_host(state, id, revision, scope, now)?
    } else {
        state.clone()
    };
    let current = repo::get_host(&moved, id)?;
    let expected = if current.host.scope != saved.host.scope {
        &current.revision
    } else {
        revision
    };
    let next = crate::sync::record_groups::promote_for_host(
        &moved,
        &current.host.scope,
        &payload,
        confirmed,
        now,
    )?;
    repo::update_host(&next, id, expected, payload, now)
}

pub fn set_host_group(
    state: &SyncStateV3,
    id: &str,
    revision: &repo::RecordRevision,
    group_id: Option<&str>,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let host = repo::get_host(state, id)?;
    if &host.revision != revision {
        return Err(RepositoryError::RevisionConflict {
            id: id.into(),
            current: host.revision,
        });
    }
    if host.host.payload.group_id.as_deref() == group_id {
        return Ok(state.clone());
    }
    let destination = if let Some(id) = group_id {
        let groups = crate::sync::record_groups::list_groups(state)?;
        let matching: Vec<_> = groups.iter().filter(|g| g.group.id == id).collect();
        if matching.len() != 1 || matching[0].group_error.is_some() {
            return Err(RepositoryError::Group(
                "Group is unavailable or needs review".into(),
            ));
        }
        matching[0].group.scope.clone()
    } else {
        host.host.scope.clone()
    };
    let next = if destination != host.host.scope {
        repo::move_host(state, id, revision, destination, now)?
    } else {
        state.clone()
    };
    let current = repo::get_host(&next, id)?;
    let mut payload = crate::sync::record_groups::materialize(&current.effective_payload);
    // Group membership needs schema 3 even when settings remain explicit overrides.
    if group_id.is_some() {
        payload.schema = crate::sync::records_v3::GROUPED_HOST_SCHEMA;
    }
    payload.group_id = group_id.map(str::to_owned);
    repo::update_host(&next, id, &current.revision, payload, now)
}

#[cfg(test)]
mod tests;

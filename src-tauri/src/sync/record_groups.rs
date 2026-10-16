//! Scope-bound group inheritance and immutable, revision-checked group edits.
use crate::sync::{
    record::{record_key, LocalRecord, RecordKind, ACCOUNT_META_ID},
    record_repository::{self as repo, RecordRevision, RepositoryError},
    records_v3::*,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveHost {
    pub payload: HostPayload,
    pub inherited_from: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupView {
    pub group: GroupRecord,
    pub revision: RecordRevision,
    pub group_error: Option<String>,
}
fn error(reason: impl Into<String>) -> RepositoryError {
    RepositoryError::Group(reason.into())
}
fn records<'a>(
    s: &'a SyncStateV3,
    scope: &HostScope,
) -> Result<&'a BTreeMap<String, LocalRecord>, RepositoryError> {
    match scope {
        HostScope::Local => Ok(&s.local.groups),
        HostScope::Space { space_id } => s
            .spaces
            .get(space_id)
            .filter(|s| s.selected && !s.missing)
            .map(|s| &s.records)
            .ok_or_else(|| RepositoryError::SpaceUnavailable(space_id.clone())),
    }
}
fn records_mut<'a>(
    s: &'a mut SyncStateV3,
    scope: &HostScope,
) -> &'a mut BTreeMap<String, LocalRecord> {
    match scope {
        HostScope::Local => &mut s.local.groups,
        HostScope::Space { space_id } => {
            &mut s.spaces.get_mut(space_id).expect("validated scope").records
        }
    }
}
fn group(s: &SyncStateV3, scope: &HostScope, id: &str) -> Result<GroupRecord, RepositoryError> {
    let rows = records(s, scope)?;
    let local = rows.get(&record_key(RecordKind::Group, id));
    if let HostScope::Space { space_id } = scope {
        if s.spaces[space_id]
            .sealed
            .values()
            .any(|row| repo::opaque_shadows(row, local, RecordKind::Group, id))
        {
            return Err(error(format!(
                "group {id} has unsupported winning authority"
            )));
        }
    }
    let local = local.ok_or_else(|| error(format!("group {id} does not exist in this scope")))?;
    repo::validate_cache(&record_key(RecordKind::Group, id), local)?;
    match decode_group(&local.record, scope.clone())? {
        TypedRecord::Live(g) => Ok(g),
        _ => Err(error(format!("group {id} was deleted"))),
    }
}
pub fn ancestor_path(
    s: &SyncStateV3,
    scope: &HostScope,
    id: Option<&str>,
) -> Result<Vec<GroupRecord>, RepositoryError> {
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursor = id.map(str::to_owned);
    while let Some(id) = cursor {
        if path.len() == 32 || !seen.insert(id.clone()) {
            return Err(error(format!(
                "group {id} has a cycle or exceeds 32 ancestors"
            )));
        }
        let g = group(s, scope, &id)?;
        cursor = g.payload.parent_id.clone();
        path.push(g);
    }
    Ok(path)
}
/// Empty user is the established OS-username sentinel, resolved by the Records directory.
pub fn resolve_effective(
    s: &SyncStateV3,
    host: &HostRecord,
) -> Result<EffectiveHost, RepositoryError> {
    let path = ancestor_path(s, &host.scope, host.payload.group_id.as_deref())?;
    let mut p = host.payload.clone();
    let mut inherited_from = BTreeMap::new();
    for field in &host.payload.inherit {
        let mut from = "default".to_owned();
        macro_rules! inherit {
            ($name:ident, $default:expr) => {{
                let selected = path
                    .iter()
                    .find_map(|g| g.payload.defaults.$name.as_ref().map(|v| (&g.id, v)));
                p.$name = match selected {
                    Some((id, v)) => {
                        from = id.clone();
                        v.clone()
                    }
                    None => $default,
                };
            }};
        }
        match field {
            InheritedField::Port => inherit!(port, 22),
            InheritedField::User => inherit!(user, String::new()),
            InheritedField::Jump => inherit!(jump, Vec::new()),
            InheritedField::KeepaliveSecs => inherit!(keepalive_secs, 30),
            InheritedField::KeepaliveMaxMissed => inherit!(keepalive_max_missed, 3),
            InheritedField::ConnectTimeoutSecs => inherit!(connect_timeout_secs, 15),
            InheritedField::Authentication => {
                let selected = path.iter().find_map(|g| {
                    g.payload
                        .defaults
                        .authentication
                        .as_ref()
                        .map(|v| (&g.id, v))
                });
                match selected {
                    Some((id, a)) => {
                        from = id.clone();
                        p.auth = a.auth;
                        p.key_id = a.key_id.clone();
                    }
                    None => {
                        p.auth = AuthKind::Password;
                        p.key_id = None;
                    }
                }
            }
        }
        inherited_from.insert(field.as_str().into(), from);
    }
    validate_host(&HostRecord {
        payload: p.clone(),
        ..host.clone()
    })?;
    Ok(EffectiveHost {
        payload: p,
        inherited_from,
    })
}
pub fn materialize(p: &HostPayload) -> HostPayload {
    let mut p = p.clone();
    p.group_id = None;
    p.inherit.clear();
    p.schema = HOST_SCHEMA;
    p
}
pub fn list_groups(s: &SyncStateV3) -> Result<Vec<GroupView>, RepositoryError> {
    let mut out = Vec::new();
    let scopes = std::iter::once(HostScope::Local).chain(
        s.spaces
            .iter()
            .filter(|(_, s)| s.selected && !s.missing)
            .map(|(id, _)| HostScope::Space {
                space_id: id.clone(),
            }),
    );
    for scope in scopes {
        for (key, row) in records(s, &scope)?
            .iter()
            .filter(|(_, r)| r.record.kind == RecordKind::Group)
        {
            repo::validate_cache(key, row)?;
            if let TypedRecord::Live(group) = decode_group(&row.record, scope.clone())? {
                let group_error = ancestor_path(s, &scope, Some(&group.id))
                    .err()
                    .map(|e| e.to_string());
                out.push(GroupView {
                    group,
                    revision: repo::revision(&row.record),
                    group_error,
                });
            }
        }
    }
    Ok(out)
}
fn checked(
    s: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
) -> Result<GroupView, RepositoryError> {
    let all = list_groups(s)?;
    let mut matches = all.into_iter().filter(|g| g.group.id == id);
    let g = matches
        .next()
        .ok_or_else(|| error(format!("group {id} not found")))?;
    if matches.next().is_some() {
        return Err(error(format!("duplicate group {id}")));
    }
    if &g.revision != expected {
        return Err(RepositoryError::RevisionConflict {
            id: id.into(),
            current: g.revision,
        });
    }
    repo::ensure_scope(s, &g.group.scope)?;
    group(s, &g.group.scope, id)?;
    Ok(g)
}
/// Native host commands use the same confirmed format/account promotion as Group creation.
pub fn promote_for_host(
    state: &SyncStateV3,
    scope: &HostScope,
    payload: &HostPayload,
    confirmed: bool,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let mut next = state.clone();
    if payload.schema == GROUPED_HOST_SCHEMA {
        repo::ensure_scope(state, scope)?;
        promote(&mut next, scope, confirmed, now)?;
    }
    Ok(next)
}
pub fn require_host_format(
    s: &SyncStateV3,
    p: &HostPayload,
    scope: &HostScope,
) -> Result<(), RepositoryError> {
    if p.schema == GROUPED_HOST_SCHEMA {
        if s.version != GROUP_STATE_VERSION {
            return Err(RepositoryError::UpgradeConfirmationRequired);
        }
        if matches!(scope, HostScope::Space { .. }) && !account_group_enabled(s) {
            return Err(RepositoryError::UpgradeConfirmationRequired);
        }
    }
    Ok(())
}
fn account_group_enabled(s: &SyncStateV3) -> bool {
    s.account
        .as_ref()
        .and_then(|a| {
            a.records
                .get(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
        })
        .is_some_and(|r| {
            !r.record.deleted
                && r.record
                    .payload
                    .get("schema_version")
                    .and_then(serde_json::Value::as_u64)
                    == Some(4)
        })
}
/// Acknowledgement is required for the first local format or shared-account promotion.
pub(crate) fn promote(
    s: &mut SyncStateV3,
    scope: &HostScope,
    confirmed: bool,
    now: u64,
) -> Result<(), RepositoryError> {
    let shared = matches!(scope, HostScope::Space { .. });
    if (s.version != GROUP_STATE_VERSION || shared && !account_group_enabled(s)) && !confirmed {
        return Err(RepositoryError::UpgradeConfirmationRequired);
    }
    s.version = GROUP_STATE_VERSION;
    if shared && !account_group_enabled(s) {
        let key = record_key(RecordKind::Meta, ACCOUNT_META_ID);
        let old = s
            .account
            .as_ref()
            .and_then(|a| a.records.get(&key))
            .ok_or_else(|| error("account metadata missing"))?
            .clone();
        let mut payload = old.record.payload.clone();
        payload["schema_version"] = 4.into();
        let mut row =
            repo::ordered_record(s, ACCOUNT_META_ID, payload, false, now, &[&old.record])?;
        row.kind = RecordKind::Meta;
        s.account.as_mut().unwrap().records.insert(
            key,
            LocalRecord {
                record: row,
                seq: old.seq,
                dirty: true,
            },
        );
    }
    Ok(())
}
pub(crate) fn validate_groups(s: &SyncStateV3, scope: &HostScope) -> Result<(), RepositoryError> {
    let groups = list_groups(s)?;
    let mut names = BTreeSet::new();
    for g in groups.iter().filter(|g| &g.group.scope == scope) {
        ancestor_path(s, scope, Some(&g.group.id))?;
        if !names.insert((
            g.group.payload.parent_id.clone(),
            g.group.payload.name.clone(),
        )) {
            return Err(error("duplicate group name under the same parent"));
        }
    }
    Ok(())
}
/// Persist pin clearing with the exact group edit that changed the effective endpoint.
fn finish(
    before: &SyncStateV3,
    mut next: SyncStateV3,
    scope: &HostScope,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    validate_groups(&next, scope)?;
    repo::validate_transition(before, &next)?;
    let old = repo::snapshot(before)?.hosts;
    let new = repo::snapshot(&next)?.hosts;
    for view in new {
        if view.host.payload.host_key.is_some()
            && old
                .iter()
                .find(|o| o.host.id == view.host.id && o.host.scope == view.host.scope)
                .is_some_and(|o| o.effective_payload.port != view.effective_payload.port)
        {
            let key = record_key(RecordKind::Host, &view.host.id);
            let rows = match &view.host.scope {
                HostScope::Local => &mut next.local.hosts,
                HostScope::Space { space_id } => {
                    &mut next.spaces.get_mut(space_id).unwrap().records
                }
            };
            let old = rows[&key].clone();
            let mut payload = view.host.payload;
            payload.host_key = None;
            // Ordering uses the immutable device identity without borrowing the mutable map.
            let mut stamp = old.record.clone();
            stamp.version = stamp
                .version
                .checked_add(1)
                .ok_or_else(|| RepositoryError::OrderingOverflow(stamp.id.clone()))?;
            stamp.updated_at_ms = now.max(
                stamp
                    .updated_at_ms
                    .checked_add(1)
                    .ok_or_else(|| RepositoryError::OrderingOverflow(stamp.id.clone()))?,
            );
            stamp.device_id = next.device_id.clone();
            stamp.payload = serde_json::to_value(payload).expect("host payload");
            rows.insert(key, repo::cached(stamp, old.seq, &view.host.scope));
        }
    }
    Ok(next)
}
pub fn has_group_data(s: &SyncStateV3) -> bool {
    account_group_enabled(s)
        || s.spaces
            .values()
            .any(|s| s.sealed.values().any(|r| r.envelope.kind == "group"))
        || !s.local.groups.is_empty()
        || s.local
            .hosts
            .values()
            .chain(s.spaces.values().flat_map(|s| s.records.values()))
            .any(|r| {
                r.record.kind == RecordKind::Group
                    || r.record.kind == RecordKind::Host
                        && r.record
                            .payload
                            .get("schema")
                            .and_then(serde_json::Value::as_u64)
                            == Some(3)
            })
}
/// Remote group changes also invalidate pins before the merged candidate reaches disk.
pub fn invalidate_changed_pins(
    before: &SyncStateV3,
    mut next: SyncStateV3,
) -> Result<SyncStateV3, RepositoryError> {
    let old = repo::snapshot(before)?.hosts;
    for view in repo::snapshot(&next)?.hosts {
        if view.host.payload.host_key.is_none() {
            continue;
        }
        let changed = old
            .iter()
            .find(|h| h.host.id == view.host.id && h.host.scope == view.host.scope)
            .is_some_and(|h| {
                h.effective_payload.port != view.effective_payload.port
                    || h.group_error != view.group_error
            });
        if !changed {
            continue;
        }
        let key = record_key(RecordKind::Host, &view.host.id);
        let rows = match &view.host.scope {
            HostScope::Local => &mut next.local.hosts,
            HostScope::Space { space_id } => &mut next.spaces.get_mut(space_id).unwrap().records,
        };
        let row = rows.get_mut(&key).unwrap();
        row.record.payload["host_key"] = serde_json::Value::Null;
        row.record.version = row
            .record
            .version
            .checked_add(1)
            .ok_or_else(|| RepositoryError::OrderingOverflow(view.host.id.clone()))?;
        row.record.updated_at_ms = row
            .record
            .updated_at_ms
            .checked_add(1)
            .ok_or_else(|| RepositoryError::OrderingOverflow(view.host.id.clone()))?;
        row.record.device_id = next.device_id.clone();
        row.dirty = matches!(view.host.scope, HostScope::Space { .. });
    }
    Ok(next)
}
pub fn create_group(
    s: &SyncStateV3,
    id: &str,
    scope: HostScope,
    mut payload: GroupPayload,
    confirmed: bool,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    repo::ensure_scope(s, &scope)?;
    payload.name = payload.name.trim().into();
    validate_group(&GroupRecord {
        id: id.into(),
        scope: scope.clone(),
        payload: payload.clone(),
    })?;
    let key = record_key(RecordKind::Group, id);
    if s.local.groups.contains_key(&key) || s.spaces.values().any(|s| s.records.contains_key(&key))
    {
        return Err(error("group identity already exists"));
    }
    let mut next = s.clone();
    promote(&mut next, &scope, confirmed, now)?;
    let mut row = repo::ordered_record(
        &next,
        id,
        serde_json::to_value(payload).unwrap(),
        false,
        now,
        &[],
    )?;
    row.kind = RecordKind::Group;
    records_mut(&mut next, &scope).insert(key, repo::cached(row, 0, &scope));
    finish(s, next, &scope, now)
}
pub fn update_group(
    s: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
    mut payload: GroupPayload,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let g = checked(s, id, expected)?;
    let scope = g.group.scope;
    payload.name = payload.name.trim().into();
    validate_group(&GroupRecord {
        id: id.into(),
        scope: scope.clone(),
        payload: payload.clone(),
    })?;
    let key = record_key(RecordKind::Group, id);
    let old = &records(s, &scope)?[&key];
    let mut row = repo::ordered_record(
        s,
        id,
        serde_json::to_value(payload).unwrap(),
        false,
        now,
        &[&old.record],
    )?;
    row.kind = RecordKind::Group;
    let mut next = s.clone();
    records_mut(&mut next, &scope).insert(key, repo::cached(row, old.seq, &scope));
    finish(s, next, &scope, now)
}
/// Conservative review fingerprint over public connection records, including ancestors outside
/// the deleted subtree. Unrelated Group/host edits also require a fresh human review.
/// No credentials, private key material, or process-local generation enter this token.
pub fn deletion_snapshot_token(
    snapshot: &repo::RepositorySnapshot,
) -> Result<String, RepositoryError> {
    use sha2::{Digest, Sha256};
    let hosts: Vec<_> = snapshot
        .hosts
        .iter()
        .map(|h| {
            (
                &h.host,
                &h.revision,
                &h.effective_payload,
                &h.inherited_from,
                &h.group_error,
            )
        })
        .collect();
    let bytes = serde_json::to_vec(&("group-delete-v1", &snapshot.groups, hosts))
        .map_err(|_| error("Group deletion review could not be prepared."))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn delete_group(
    s: &SyncStateV3,
    id: &str,
    expected: &RecordRevision,
    reviewed_snapshot: Option<&str>,
    now: u64,
) -> Result<SyncStateV3, RepositoryError> {
    let root = checked(s, id, expected)?;
    let snapshot = repo::snapshot(s)?;
    if reviewed_snapshot != Some(deletion_snapshot_token(&snapshot)?.as_str()) {
        return Err(error("Group deletion review is missing or stale. Refresh the records and review the deletion again."));
    }
    let scope = root.group.scope;
    if let HostScope::Space { space_id } = &scope {
        if s.spaces[space_id]
            .sealed
            .values()
            .any(|r| r.envelope.kind == "group" && !r.envelope.deleted)
        {
            return Err(error("unreadable groups prevent subtree deletion"));
        }
    }
    let mut removed = BTreeSet::from([id.to_owned()]);
    let groups = list_groups(s)?;
    loop {
        let old = removed.len();
        for g in groups.iter().filter(|g| g.group.scope == scope) {
            if g.group
                .payload
                .parent_id
                .as_ref()
                .is_some_and(|id| removed.contains(id))
            {
                removed.insert(g.group.id.clone());
            }
        }
        if old == removed.len() {
            break;
        }
    }
    let mut next = s.clone();
    for view in snapshot.hosts.into_iter().filter(|h| {
        h.host.scope == scope
            && h.host
                .payload
                .group_id
                .as_ref()
                .is_some_and(|id| removed.contains(id))
    }) {
        let resolved = resolve_effective(s, &view.host)?;
        next = repo::update_host(
            &next,
            &view.host.id,
            &view.revision,
            materialize(&resolved.payload),
            now,
        )?;
    }
    for id in removed {
        // Winning opaque descendants must never be silently deleted.
        group(s, &scope, &id)?;
        let key = record_key(RecordKind::Group, &id);
        let old = &records(s, &scope)?[&key];
        let mut row =
            repo::ordered_record(s, &id, serde_json::Value::Null, true, now, &[&old.record])?;
        row.kind = RecordKind::Group;
        records_mut(&mut next, &scope).insert(key, repo::cached(row, old.seq, &scope));
    }
    finish(s, next, &scope, now)
}
#[cfg(test)]
#[path = "record_groups_tests.rs"]
mod test_cases;

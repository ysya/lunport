//! Explicit, generation-bound review of already verified central conflicts.
//! Private material stays native. A user choice changes no membership, checkpoint or projection receipt.
use super::{
    controller,
    crypto::{self, DeviceKeys, VaultKeys},
    payload::{self, Admitted, Data},
    wire::{invalid, number},
};
use crate::{
    error::AppError,
    sync::{
        env::SyncEnv,
        record::{record_key, RecordKind},
        record_import::central_local::Context,
        record_repository as repo, record_runtime,
        records_v3::{self, HostScope, SyncStateV3},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct View {
    id: String,
    token: String,
    kind: String,
    name: String,
    local: Option<serde_json::Value>,
    remote: Option<serde_json::Value>,
    local_deleted: bool,
    remote_deleted: bool,
    remote_revision: String,
    can_resolve: bool,
    can_remote: bool,
    can_copy: bool,
}
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    Local,
    Remote,
    CopyRemote,
}
fn token(state: &SyncStateV3, generation: u64, id: &str) -> Result<String, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    Ok(crypto::hash(
        &serde_json::to_vec(&(
            "lunport-conflict-review-v1",
            generation,
            &owner.control,
            &replica.checkpoint,
            id,
            replica.pending.get(id),
            replica.current.get(id),
            replica.conflicts.get(id),
        ))
        .map_err(|_| invalid())?,
    ))
}
fn open(
    state: &SyncStateV3,
    keys: &VaultKeys,
    envelope: &super::crypto::RecordEnvelope,
    hash: &str,
) -> Result<Admitted, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let chain = owner.control.verified_chain()?;
    let author = chain
        .author_at(&envelope.header.membership_head, &envelope.header.author)
        .ok_or_else(invalid)?;
    let bytes = envelope.verify(&author.signing)?.open(keys)?;
    if crypto::hash(&bytes) != hash {
        return Err(invalid());
    }
    payload::admit(keys, &envelope.header, &bytes)
}
fn public(value: &Data) -> Result<Option<serde_json::Value>, AppError> {
    Ok(match value {
        Data::Host(host) => Some(serde_json::to_value(host).map_err(|_| invalid())?),
        Data::Group(group) => Some(serde_json::to_value(group).map_err(|_| invalid())?),
        Data::Keyslot(slot) => Some(
            serde_json::json!({"name":slot.public.name,"fingerprint":slot.public.fingerprint,"type":slot.public.key_type}),
        ),
        Data::Catalog(catalog) => Some(serde_json::to_value(catalog).map_err(|_| invalid())?),
        Data::Deleted | Data::Key(_) => None,
    })
}
fn settled(replica: &super::replica::Replica, id: &str) -> Result<bool, AppError> {
    let Some(pending) = replica.pending.get(id) else {
        return Ok(false);
    };
    let Some(remote) = replica.current.get(id) else {
        return Ok(false);
    };
    // A newer verified CAS revision proves an unacknowledged old expected-revision write
    // can no longer commit. Claimed receipts must still be read and verified by normal sync.
    Ok(pending.claimed.is_none()
        && pending.sent.as_ref().is_none_or(|sent| {
            number(&sent.envelope.header.expected_revision, true)
                .ok()
                .zip(number(&remote.version.revision, false).ok())
                .is_some_and(|(sent, current)| sent < current)
        }))
}
fn views(state: &SyncStateV3, generation: u64, keys: &VaultKeys) -> Result<Vec<View>, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    let mut rows = vec![];
    for id in replica.conflicts.keys() {
        let pending = replica.pending.get(id).ok_or_else(invalid)?;
        let remote = replica.current.get(id).ok_or_else(invalid)?;
        let local = open(
            state,
            keys,
            &pending.latest.envelope,
            &pending.latest.content_hash,
        )?;
        let other = open(state, keys, &remote.version.envelope, &remote.content_hash)?;
        if local.identity != other.identity {
            return Err(invalid());
        }
        let kind = local.identity.kind.clone();
        let local_value = public(&local.data)?;
        let remote_value = public(&other.data)?;
        let name = local_value
            .as_ref()
            .or(remote_value.as_ref())
            .and_then(|v| v.get("alias").or_else(|| v.get("name")))
            .and_then(|v| v.as_str())
            .unwrap_or(&kind)
            .to_owned();
        let can_resolve = settled(replica, id)?;
        rows.push(View {
            id: id.clone(),
            token: token(state, generation, id)?,
            kind: kind.clone(),
            name,
            local: local_value,
            remote: remote_value,
            local_deleted: matches!(local.data, Data::Deleted),
            remote_deleted: matches!(other.data, Data::Deleted),
            remote_revision: remote.version.revision.clone(),
            can_resolve,
            can_remote: can_resolve && matches!(kind.as_str(), "host" | "group"),
            can_copy: can_resolve && matches!(other.data, Data::Host(_)),
        });
    }
    Ok(rows)
}
/// Replace only a reviewed public cache row, retaining monotonic local ordering. Ordinary
/// repository checks reject new alias/relationship defects and normal commit clears stale pins.
fn public_remote(
    state: &SyncStateV3,
    admitted: &Admitted,
    now: u64,
) -> Result<SyncStateV3, AppError> {
    let identity = &admitted.identity;
    let scope = identity.scope.as_ref().ok_or_else(invalid)?;
    let kind = match identity.kind.as_str() {
        "host" => RecordKind::Host,
        "group" => RecordKind::Group,
        _ => return Err(invalid()),
    };
    let mut body = match &admitted.data {
        Data::Host(host) => {
            let mut host = host.clone();
            host.host_key = None;
            serde_json::to_value(host).map_err(|_| invalid())?
        }
        Data::Group(group) => serde_json::to_value(group).map_err(|_| invalid())?,
        Data::Deleted => serde_json::Value::Null,
        _ => return Err(invalid()),
    };
    if kind == RecordKind::Host && !matches!(admitted.data, Data::Deleted) {
        body.as_object_mut().ok_or_else(invalid)?.remove("host_key");
    }
    let key = record_key(kind, &identity.id);
    let rows = match scope {
        HostScope::Local if kind == RecordKind::Group => &state.local.groups,
        HostScope::Local => &state.local.hosts,
        HostScope::Space { space_id } => &state.spaces.get(space_id).ok_or_else(invalid)?.records,
    };
    let previous = rows.get(&key);
    let mut record = repo::ordered_record(
        state,
        &identity.id,
        body,
        matches!(admitted.data, Data::Deleted),
        now,
        &previous.map(|row| vec![&row.record]).unwrap_or_default(),
    )
    .map_err(|e| AppError::Other(e.to_string()))?;
    record.kind = kind;
    let mut next = state.clone();
    let rows = match scope {
        HostScope::Local if kind == RecordKind::Group => &mut next.local.groups,
        HostScope::Local => &mut next.local.hosts,
        HostScope::Space { space_id } => {
            &mut next.spaces.get_mut(space_id).ok_or_else(invalid)?.records
        }
    };
    rows.insert(
        key,
        repo::cached(record, previous.map_or(0, |row| row.seq), scope),
    );
    crate::sync::record_groups::validate_groups(&next, scope)
        .map_err(|e| AppError::Other(e.to_string()))?;
    repo::validate_transition(state, &next).map_err(|e| AppError::Other(e.to_string()))?;
    Ok(next)
}
fn candidate(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    id: &str,
    choice: Choice,
    copy_alias: Option<&str>,
    now: u64,
) -> Result<SyncStateV3, AppError> {
    if copy_alias.is_some_and(|alias| alias.len() > 128) {
        return Err(invalid());
    }
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    if !replica.conflicts.contains_key(id) || !settled(replica, id)? {
        return Err(AppError::Other(
            "Finish syncing the pending write receipt, then refresh conflict review.".into(),
        ));
    }
    let pending = replica.pending.get(id).ok_or_else(invalid)?;
    let remote = replica.current.get(id).ok_or_else(invalid)?;
    let local = open(
        state,
        keys,
        &pending.latest.envelope,
        &pending.latest.content_hash,
    )?;
    let other = open(state, keys, &remote.version.envelope, &remote.content_hash)?;
    if local.identity != other.identity {
        return Err(invalid());
    }
    let mut next = state.clone();
    match choice {
        Choice::Remote => {
            next = public_remote(&next, &other, now)?;
        }
        Choice::CopyRemote => {
            let Data::Host(host) = &other.data else {
                return Err(invalid());
            };
            let mut host = host.clone();
            host.host_key = None;
            host.alias = copy_alias.ok_or_else(invalid)?.trim().into();
            next = repo::create_host(
                &next,
                &crate::sync::record_commands::new_host_id()?,
                other.identity.scope.clone().ok_or_else(invalid)?,
                host,
                now,
            )
            .map_err(|e| AppError::Other(e.to_string()))?;
        }
        Choice::Local => {}
    }
    let owner = next.local.central.as_mut().ok_or_else(invalid)?;
    let chain = owner.control.verified_chain()?;
    let replica = owner.replica.as_mut().ok_or_else(invalid)?;
    replica.conflicts.remove(id);
    replica.pending.remove(id);
    if !matches!(choice, Choice::Remote) {
        let bytes = payload::encode(&local.identity, &local.data)?;
        let mut header = pending.latest.envelope.header.clone();
        header.author = owner.control.device.id.clone();
        header.membership_head = chain.current().head().into();
        header.key_epoch = replica.checkpoint.epoch.to_string();
        replica.enqueue(
            &chain,
            keys,
            signer,
            pending
                .latest
                .local_revision
                .checked_add(1)
                .ok_or_else(invalid)?,
            header,
            &bytes,
        )?;
        if let Some(pending) = replica.pending.get_mut(id) {
            pending.confirmed = Some(remote.clone());
        }
    }
    // Capture any normalized host pins and the optional new host under the same existing
    // public-edit path. The selected remote basis is explicitly acknowledged by this review.
    let mut next = super::capture_public(&next, keys, signer)?;
    let replica = next
        .local
        .central
        .as_mut()
        .ok_or_else(invalid)?
        .replica
        .as_mut()
        .ok_or_else(invalid)?;
    if let Some(pending) = replica.pending.get_mut(id) {
        pending.confirmed = Some(remote.clone());
    }
    replica.conflicts.remove(id);
    records_v3::validate_state(&next).map_err(|_| invalid())?;
    Ok(next)
}
#[tauri::command]
pub async fn central_conflicts(app: tauri::AppHandle) -> Result<Vec<View>, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let _life = env.runtime.lifecycle.lock().unwrap();
            let _vault = env
                .runtime
                .vault
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _publication = env.runtime.format_publication.lock().unwrap();
            let (before, mut generation) = record_runtime::snapshot(env)?;
            let context = Context::load(env, &before)?;
            let captured = super::capture_public(&before, context.keys(), context.signer())?;
            context.verify(env, &before)?;
            if captured != before {
                generation = record_runtime::commit_candidate(env, generation, captured.clone())?;
            }
            views(&captured, generation, context.keys())
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn central_conflict_resolve(
    app: tauri::AppHandle,
    id: String,
    token: String,
    choice: Choice,
    copy_alias: Option<String>,
) -> Result<controller::Status, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            resolve(env, &id, &token, choice, copy_alias.as_deref())
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
fn archive_operation(state: &SyncStateV3, id: &str) -> Result<String, AppError> {
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    Ok(crypto::hash(&super::wire::canonical(&[
        "lunport-conflict-archive-v1",
        &owner.control.profile.locator,
        &owner.control.device.id,
        &owner.control.device.keys.signing,
        &owner.control.device.keys.encryption,
        id,
    ])?)[..32]
        .to_owned())
}
fn resolve(
    env: &SyncEnv,
    id: &str,
    expected: &str,
    choice: Choice,
    copy_alias: Option<&str>,
) -> Result<controller::Status, AppError> {
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (before, generation) = record_runtime::snapshot(env)?;
    if !super::wire::hex(id, 64)
        || !super::wire::hex(expected, 64)
        || token(&before, generation, id)? != expected
    {
        return Err(AppError::Other(
            "This conflict changed. Refresh the review before choosing a version.".into(),
        ));
    }
    let context = Context::load(env, &before)?;
    if super::capture_public(&before, context.keys(), context.signer())? != before {
        return Err(AppError::Other("Local changes need a new conflict review. Refresh the review before choosing a version.".into()));
    }
    let next = candidate(
        &before,
        context.keys(),
        context.signer(),
        id,
        choice,
        copy_alias,
        env.clock.now_ms(),
    )?;
    // Reuse the existing encrypted, immutable recovery snapshot transaction. An unsent local
    // version is not server history, so it must be durably retained before retiring a conflict.
    let operation = archive_operation(&before, id)?;
    let archive = super::replacement_archive::prepare(env, &life, &before, generation, &operation)?;
    archive.verify_source(&before, generation)?;
    context.verify(env, &before)?;
    record_runtime::commit_candidate(env, generation, next)?;
    drop(_publication);
    drop(_vault);
    drop(life);
    env.events.status();
    env.events.wake();
    controller::status(env)
}

#[cfg(test)]
mod tests {
    use super::super::{
        projection_capture::tests::{apply, remote},
        projection_state::tests::initial,
    };
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn fixture() -> (SyncStateV3, VaultKeys, DeviceKeys, String) {
        let (mut state, keys, _) = initial();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        state
            .local
            .hosts
            .get_mut(&record_key(RecordKind::Host, "0000000000000001"))
            .unwrap()
            .record
            .payload["alias"] = "local-B".into();
        let mut state = super::super::capture_public(&state, &keys, &signer).unwrap();
        let version = remote(&state, &keys, "remote-C", None);
        apply(&mut state, &keys, version);
        let state = super::super::capture_public(&state, &keys, &signer).unwrap();
        let id = state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts
            .keys()
            .next()
            .unwrap()
            .clone();
        (state, keys, signer, id)
    }
    #[test]
    fn local_choice_rebases_once_without_resurrecting_the_conflict_or_changing_history() {
        let (state, keys, signer, id) = fixture();
        let next = candidate(&state, &keys, &signer, &id, Choice::Local, None, 100).unwrap();
        let owner = next.local.central.as_ref().unwrap();
        let replica = owner.replica.as_ref().unwrap();
        assert!(!replica.conflicts.contains_key(&id));
        assert_eq!(
            replica.current,
            state
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .current
        );
        assert_eq!(
            replica.pending[&id]
                .latest
                .envelope
                .header
                .expected_revision,
            replica.current[&id].version.revision
        );
        let captured = super::super::capture_public(&next, &keys, &signer).unwrap();
        assert!(captured
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts
            .is_empty());
        assert_eq!(
            state.local.central_projection,
            next.local.central_projection
        );
    }
    #[test]
    fn remote_and_copy_choices_validate_public_cache_and_keep_signed_history() {
        let (state, keys, signer, id) = fixture();
        let chosen = candidate(&state, &keys, &signer, &id, Choice::Remote, None, 100).unwrap();
        assert_eq!(
            chosen.local.hosts[&record_key(RecordKind::Host, "0000000000000001")]
                .record
                .payload["alias"],
            "remote-C"
        );
        let captured = super::super::capture_public(&chosen, &keys, &signer).unwrap();
        assert!(!captured
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts
            .contains_key(&id));
        let copied = candidate(
            &state,
            &keys,
            &signer,
            &id,
            Choice::CopyRemote,
            Some("remote-copy"),
            100,
        )
        .unwrap();
        assert_eq!(
            repo::list_hosts(&copied).unwrap().len(),
            repo::list_hosts(&state).unwrap().len() + 1
        );
        assert!(repo::find_by_alias(&copied, "remote-copy").is_ok());
        assert!(candidate(
            &state,
            &keys,
            &signer,
            &id,
            Choice::CopyRemote,
            Some("local-B"),
            100
        )
        .is_err());
        assert_ne!(
            token(&state, 10, &id).unwrap(),
            token(&state, 11, &id).unwrap()
        );
    }

    #[test]
    fn review_fences_change_with_remote_and_local_edits_and_receipts_cannot_be_dropped() {
        let (state, keys, signer, id) = fixture();
        let token_before = token(&state, 8, &id).unwrap();
        let mut changed = state.clone();
        changed
            .local
            .hosts
            .get_mut(&record_key(RecordKind::Host, "0000000000000001"))
            .unwrap()
            .record
            .payload["alias"] = "local-D".into();
        let changed = super::super::capture_public(&changed, &keys, &signer).unwrap();
        assert_ne!(token_before, token(&changed, 8, &id).unwrap());
        let mut claimed = state.clone();
        let owner = claimed.local.central.as_mut().unwrap();
        let replica = owner.replica.as_mut().unwrap();
        let pending = replica.pending.get_mut(&id).unwrap();
        let sent = pending.latest.clone();
        pending.sent = Some(sent.clone());
        pending.claimed = Some(super::super::replica::Receipt {
            operation_id: sent.envelope.header.operation_id.clone(),
            record_id: id.clone(),
            revision: (number(&sent.envelope.header.expected_revision, true).unwrap() + 1)
                .to_string(),
            sequence: (replica.checkpoint.sequence + 1).to_string(),
            digest: super::super::rekey::envelope_digest(&sent.envelope).unwrap(),
            history_hash: "f".repeat(64),
        });
        let before_claim = pending_claim(&claimed, &id);
        assert!(candidate(&claimed, &keys, &signer, &id, Choice::Local, None, 100).is_err());
        assert_eq!(pending_claim(&claimed, &id), before_claim);
    }
    fn pending_claim(state: &SyncStateV3, id: &str) -> Option<super::super::replica::Receipt> {
        state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[id]
            .claimed
            .clone()
    }
    #[test]
    fn review_does_not_publish_private_material_or_treat_deleted_hosts_as_copies() {
        let private = payload::PrivateMaterial::new(zeroize::Zeroizing::new(
            crate::sync::slot_rules::test_keys::plain(),
        ))
        .unwrap();
        assert!(public(&Data::Key(private)).unwrap().is_none());
        let (state, keys, signer, id) = fixture();
        let rows = views(&state, 8, &keys).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].can_remote && rows[0].can_copy);
        let mut deleted = state.clone();
        let owner = deleted.local.central.as_mut().unwrap();
        let chain = owner.control.verified_chain().unwrap();
        let replica = owner.replica.as_mut().unwrap();
        let mut row = replica.current[&id].version.clone();
        row.envelope.header.deleted = true;
        let identity = payload::Identity {
            kind: "host".into(),
            id: "0000000000000001".into(),
            scope: Some(HostScope::Local),
        };
        let bytes = payload::encode(&identity, &Data::Deleted).unwrap();
        row.envelope = crypto::seal_record(&keys, &signer, row.envelope.header, &bytes).unwrap();
        row.digest = super::super::rekey::envelope_digest(&row.envelope).unwrap();
        let remote = replica.current.get_mut(&id).unwrap();
        remote.version = row;
        remote.content_hash = crypto::hash(&bytes);
        replica.validate(&chain).unwrap();
        let rows = views(&deleted, 8, &keys).unwrap();
        assert!(rows[0].remote_deleted && !rows[0].can_copy);
        assert!(candidate(
            &deleted,
            &keys,
            &signer,
            &id,
            Choice::CopyRemote,
            Some("deleted-copy"),
            100
        )
        .is_err());
    }
    #[test]
    fn remote_group_uses_the_group_cache_and_rejects_dangling_parent_relationships() {
        let (mut state, keys, signer, id) = fixture();
        // Reuse the verified conflict envelope boundary with typed Group data.
        let group_id = "0000000000000003";
        let identity = payload::Identity {
            kind: "group".into(),
            id: group_id.into(),
            scope: Some(HostScope::Local),
        };
        let original: records_v3::GroupPayload =
            serde_json::from_value(serde_json::json!({"schema":1,"name":"local-group"})).unwrap();
        state = crate::sync::record_groups::create_group(
            &state,
            group_id,
            HostScope::Local,
            original.clone(),
            true,
            100,
        )
        .unwrap();
        let mut remote = original;
        remote.name = "synced-group".into();
        let admitted = Admitted {
            identity: identity.clone(),
            data: Data::Group(remote.clone()),
        };
        let next = public_remote(&state, &admitted, 101).unwrap();
        assert_eq!(
            next.local.groups[&record_key(RecordKind::Group, group_id)]
                .record
                .payload["name"],
            "synced-group"
        );
        assert!(!next
            .local
            .hosts
            .contains_key(&record_key(RecordKind::Group, group_id)));
        remote.parent_id = Some("f".repeat(16));
        assert!(public_remote(
            &state,
            &Admitted {
                identity,
                data: Data::Group(remote)
            },
            101
        )
        .is_err());
        assert_eq!(
            state
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .conflicts[&id],
            next.local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .conflicts[&id]
        );
        let _ = keys;
        let _ = signer;
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn native_resolution_is_durable_and_rejects_replayed_reviews() {
        let d = crate::sync::record_import::central_local::tests::fixture();
        let env = d.env();
        let (mut state, generation) = record_runtime::snapshot(&env).unwrap();
        let context = Context::load(&env, &state).unwrap();
        state
            .local
            .hosts
            .get_mut(&record_key(RecordKind::Host, "0000000000000001"))
            .unwrap()
            .record
            .payload["alias"] = "local-B".into();
        let mut state =
            super::super::capture_public(&state, context.keys(), context.signer()).unwrap();
        let row = remote(&state, context.keys(), "remote-C", None);
        apply(&mut state, context.keys(), row);
        let state = super::super::capture_public(&state, context.keys(), context.signer()).unwrap();
        let generation = record_runtime::commit_candidate(&env, generation, state.clone()).unwrap();
        let id = state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts
            .keys()
            .next()
            .unwrap()
            .clone();
        let review = token(&state, generation, &id).unwrap();
        let slot = state
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap()
            .slot(&format!(
                "replacement-archive-{}",
                archive_operation(&state, &id).unwrap()
            ));
        d.keychain.fail_writes_to(&slot, true);
        assert!(resolve(&env, &id, &review, Choice::Local, None).is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap().0, state);
        assert_eq!(
            record_runtime::read_saved_records(&env.state_path).unwrap(),
            state
        );
        d.keychain.fail_writes_to(&slot, false);
        resolve(&env, &id, &review, Choice::Local, None).unwrap();
        let saved = record_runtime::read_saved_records(&env.state_path).unwrap();
        assert!(saved
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts
            .is_empty());
        assert_eq!(
            saved.local.central_projection,
            state.local.central_projection
        );
        let files = super::super::migration_files::Files::capture(&env, None).unwrap();
        let retained =
            super::super::replacement_archive::captured::read_all(&files.bytes, &d.keychain)
                .unwrap();
        assert!(retained.states.iter().any(|old| old == &state));
        for (path, bytes) in &files.bytes {
            if matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("lparch" | "lphist")
            ) {
                assert!(!bytes
                    .windows(b"local-B".len())
                    .any(|value| value == b"local-B"));
            }
        }
        assert!(resolve(&env, &id, &review, Choice::Remote, None).is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap().0, saved);
        assert_eq!(
            record_runtime::read_saved_records(&env.state_path).unwrap(),
            saved
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn status_remains_responsive_during_unlock_and_exposes_the_server_wait() {
        let d = crate::sync::record_import::central_local::tests::fixture();
        d.runtime.core.lock().unwrap().central_poll.service_retry_at =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(65));
        let worker = d.runtime.central_unlock.lock().unwrap();
        let status = controller::status(&d.env()).unwrap();
        assert!(status.connecting && status.cooldown_seconds > 0);
        assert_eq!(
            super::super::automatic::status(&d.env()).unwrap().phase,
            "connecting"
        );
        drop(worker);
        let ready = controller::status(&d.env()).unwrap();
        assert!(!ready.connecting);
        assert!(
            ready.observation.parse::<u64>().unwrap() > status.observation.parse::<u64>().unwrap()
        );
    }
}

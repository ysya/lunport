//! Replacement history is passive provenance, never the selected device's write authority.
use super::{
    client_state::Phase, controller::Session, credentials::DeviceIdentity, crypto::VaultKeys,
    historical_state::Captured, migration_library::History, replacement_publication::Archive,
    source_package::snapshot::Group, wire::invalid, workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{
        env::{Keychain, SyncEnv},
        records_v3::{self, SyncStateV3},
    },
};
use std::{collections::BTreeMap, path::PathBuf};
use zeroize::Zeroizing;

pub(in crate::sync) fn required(owner: &Workspace) -> bool {
    owner
        .replacement_archives
        .iter()
        .any(|a| a.needs_reconciliation)
}
/// Independent admission: initial adoption deliberately keeps its original strict contract.
pub(super) fn target(
    env: &SyncEnv,
    state: &SyncStateV3,
    session: &Session,
    keys: &VaultKeys,
) -> Result<(), AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    owner.require_key_recipients()?;
    super::source_capture::require_selected(env, owner, session)?;
    if !required(owner)
        || !matches!(owner.control.phase, Phase::Enrolled | Phase::Active)
        || owner.bootstrap.is_some()
        || owner.replacement.is_some()
        || owner.recovery.is_some()
        || owner.rotation.is_some()
        || owner.control.cutover
            != (state.local.central_projection.is_some()
                || state.local.central_cache_source.is_some())
    {
        return Err(invalid());
    }
    let replica = owner.replica.as_ref().ok_or_else(invalid)?;
    if !replica.pending.is_empty() || !replica.conflicts.is_empty() {
        return Err(invalid());
    }
    let chain = owner.control.verified_chain()?;
    let wrap = owner
        .own_wraps
        .iter()
        .find(|w| w.header.key_epoch == replica.checkpoint.epoch.to_string())
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&wrap.header.membership_head, &wrap.header.author)
        .ok_or_else(invalid)?;
    wrap.open(
        &session.identity.as_ref().ok_or_else(invalid)?.keys,
        &wrap.header,
        &author.signing,
    )?
    .verify_index(keys)
}
/// Exact file/receipt coverage before any candidate may release the corresponding flags.
pub(super) fn archives(
    state: &SyncStateV3,
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keys: &dyn Keychain,
) -> Result<super::replacement_archive::captured::Captured, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    if !required(owner) {
        return Err(invalid());
    }
    let captured = super::replacement_archive::captured::read_all(files, keys)?;
    for archive in &owner.replacement_archives {
        let index = captured
            .receipts
            .iter()
            .position(|r| {
                r.context == archive.receipt.context && r.file_hash == archive.receipt.file_hash
            })
            .ok_or_else(invalid)?;
        let receipt = &captured.receipts[index];
        let original = &captured.states[index];
        let old = original.local.central.as_ref().ok_or_else(invalid)?;
        if archive
            .receipt
            .history_hash
            .as_ref()
            .is_some_and(|h| receipt.history_hash.as_ref() != Some(h))
            || archive.previous_selection != old.identity_slot
            || archive.receipt.context.device != old.control.device
            || archive.target != owner.control.device
                && !owner
                    .replacement_archives
                    .iter()
                    .any(|later| later.receipt.context.device == archive.target)
            || old.control.profile != owner.control.profile
            || old
                .control
                .anchor
                .as_ref()
                .is_some_and(|a| Some(a) != owner.control.anchor.as_ref())
        {
            return Err(invalid());
        }
    }
    Ok(captured)
}
/// Capture the selected cache under its original ledger's authorization. That authorization
/// never escapes this reader. Every original private version comes from authenticated history.
pub(super) fn capture_projected(
    state: &SyncStateV3,
    files: &BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    keys: &dyn Keychain,
    identities: &dyn Fn(&Workspace) -> Result<DeviceIdentity, AppError>,
) -> Result<Captured, AppError> {
    let captured = archives(state, files, keys)?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let mut receipt = state.local.central_cache_source.as_ref();
    let mut original = state;
    let mut depth = 0;
    while let Some(source) = receipt {
        depth += 1;
        if depth > 64 {
            return Err(invalid());
        }
        let index = captured
            .receipts
            .iter()
            .position(|r| r.context == source.context && r.file_hash == source.file_hash)
            .ok_or_else(invalid)?;
        original = &captured.states[index];
        receipt = original.local.central_cache_source.as_ref();
    }
    let ledger = original
        .local
        .central_projection
        .as_ref()
        .ok_or_else(invalid)?;
    let mut history = History::empty_retained();
    let mut floors = vec![];
    let mut controls = vec![];
    for archive in &owner.replacement_archives {
        let index = captured
            .receipts
            .iter()
            .position(|r| {
                r.context == archive.receipt.context && r.file_hash == archive.receipt.file_hash
            })
            .ok_or_else(invalid)?;
        let original = &captured.states[index];
        let old = original.local.central.as_ref().ok_or_else(invalid)?;
        if old.control.anchor.is_none() {
            continue;
        }
        let group = match captured
            .histories
            .iter()
            .find(|g| g.require_state(original).is_ok())
        {
            Some(group) => group.clone(),
            None => Group::state_captured(
                original,
                super::historical_state::read(original, &identities(old)?)?,
            )?,
        };
        floors.extend(group.floors().iter().cloned());
        controls.extend(group.controls().iter().cloned());
        for (id, data) in group.history()?.into_rows() {
            history.push_retained(id, data)?;
        }
    }
    let old = original.local.central.as_ref().ok_or_else(invalid)?;
    ledger.validate(old)?;
    // New private pointers require a separately signed local-material transaction. Public
    // cache edits are retained below; raw bytes are never guessed from a fingerprint.
    if state.local.keys != original.local.keys
        || state.rotation.is_some()
        || state.pending_account.is_some()
        || state
            .account
            .as_ref()
            .is_some_and(|a| !a.recovery.is_empty())
        || state.spaces.values().any(|s| !s.recovery.is_empty())
    {
        return Err(invalid());
    }
    let mut storage = ledger.storage.clone();
    for id in state.local.keys.keys() {
        storage.insert(
            id.clone(),
            ledger.key_storage(id).ok_or_else(invalid)?.clone(),
        );
    }
    let mut selected = History::empty_retained();
    for (id, data) in
        super::projection_local::public_rows(state, &ledger.catalog, &storage)?
    {
        selected.push_selected(id, data)?;
    }
    let mut selected_private = vec![];
    for (id, local) in &state.local.keys {
        let private = history
            .rows()
            .iter()
            .find_map(|(_, data)| {
                let super::payload::Data::Key(private) = data else {
                    return None;
                };
                let entry = crate::vault::store::VaultEntry {
                    private_key: private.private().into(),
                    public_key: local.public.public_key.clone(),
                    fingerprint: private.fingerprint.clone(),
                    origin: crate::vault::store::EntryOrigin::Imported,
                    added_at_ms: local.public.created_at_ms,
                };
                ledger
                    .verify_source_material(old, id, local, &entry)
                    .ok()
                    .map(|_| Zeroizing::new(private.private().to_owned()))
            })
            .ok_or_else(invalid)?;
        selected_private.push((
            super::payload::Identity {
                kind: "key".into(),
                id: id.clone(),
                scope: None,
            },
            super::payload::Data::Key(super::payload::PrivateMaterial::new(private)?),
        ));
    }
    for (id, data) in selected_private {
        selected.push_selected(id, data)?;
    }
    let history = selected.with_retained(vec![history])?;

    // Both old and selected replica floors survive; the final authenticated read must meet all.
    if let Some(replica) = &owner.replica {
        floors.push(replica.checkpoint.clone());
        floors.extend(replica.minimum.iter().cloned());
    }
    controls.push(super::adoption::captured::ControlMinimum {
        highwater: owner.control.verified_chain()?.highwater(),
        auth_epoch: owner.control.auth_epoch,
    });
    floors.sort_by(|a, b| {
        (a.epoch, a.sequence, &a.history_hash).cmp(&(b.epoch, b.sequence, &b.history_hash))
    });
    floors.dedup();
    controls.dedup();
    Ok(Captured {
        history,
        floors,
        controls,
    })
}
/// Native-only exact transition check, called only by the sealed reconciliation publication.
/// Ordinary Workspace publication continues to reject every archive mutation.
pub(in crate::sync) fn verify_completed(
    before: &SyncStateV3,
    after: &SyncStateV3,
) -> Result<(), AppError> {
    let old = before.local.central.as_ref().ok_or_else(invalid)?;
    let next = after.local.central.as_ref().ok_or_else(invalid)?;
    if !required(old)
        || after.local.central_cache_source.is_some()
        || required(next)
        || old.control.profile != next.control.profile
        || old.control.anchor != next.control.anchor
        || old.control.device != next.control.device
        || old.identity_slot != next.identity_slot
        || old.replacement_archives.len() != next.replacement_archives.len()
    {
        return Err(invalid());
    }
    for (old, next) in old
        .replacement_archives
        .iter()
        .zip(&next.replacement_archives)
    {
        let mut completed: Archive = old.clone();
        completed.needs_reconciliation = false;
        if next != &completed {
            return Err(invalid());
        }
    }
    Ok(())
}

/// An empty legacy view is only for enumerating physical retained files. The real selected
/// state stays immutable in Package, its signed snapshot and every publication fence.
#[inline(never)]
pub(super) fn physical_view(state: &SyncStateV3) -> Result<Box<SyncStateV3>, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    if !projected(state) {
        return Ok(Box::new(state.clone()));
    }
    history_view(state)
}
/// Pure historical enumeration, including an active source before replacement publication.
#[inline(never)]
pub(super) fn history_view(state: &SyncStateV3) -> Result<Box<SyncStateV3>, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    if !super::historical_state::projected(state) || state.local.central.is_none() {
        return Err(invalid());
    }
    let mut view = Box::new(state.clone());
    view.account = None;
    view.spaces.clear();
    view.local.hosts.clear();
    view.local.groups.clear();
    view.local.group_order.clear();
    view.local.keys.clear();
    view.local.credential_approvals.clear();
    view.local.central_projection = None;
    view.local.central_cache_source = None;
    view.local.central = None;
    view.pending_account = None;
    view.rotation = None;
    view.migration_gate = None;
    view.shared_writes_blocked = false;
    records_v3::validate_state(&view).map_err(|_| invalid())?;
    Ok(view)
}
pub(super) fn projected(state: &SyncStateV3) -> bool {
    (state.local.central_projection.is_some() || state.local.central_cache_source.is_some())
        && state
            .local
            .central
            .as_ref()
            .is_some_and(|w| w.control.cutover && required(w))
}

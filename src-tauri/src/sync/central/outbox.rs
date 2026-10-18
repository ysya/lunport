//! Pure dependency-ready ciphertext dispatch. Not session, network or durable publication authority.
pub(super) mod claims;
use super::{
    crypto::{self, DeviceKeys, RecordEnvelope, VaultKeys},
    payload::{self, Data, Identity, SharedKeyslot},
    replica::{Base, Draft},
    trust::VerifiedChain,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::records_v3::{self, SyncStateV3},
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Prepared {
    pub owner: Workspace,
    pub records: Vec<RecordEnvelope>,
    pub waiting_private: usize,
    pub ready_remaining: usize,
    pub cursor: Option<String>,
}
fn open(
    keys: &VaultKeys,
    chain: &VerifiedChain,
    draft: &Draft,
) -> Result<payload::Admitted, AppError> {
    let h = &draft.envelope.header;
    let author = chain
        .author_at(&h.membership_head, &h.author)
        .ok_or_else(invalid)?;
    let plain = draft.envelope.verify(&author.signing)?.open(keys)?;
    if crypto::hash(&plain) != draft.content_hash {
        return Err(invalid());
    }
    payload::admit(keys, h, &plain)
}
fn current(
    keys: &VaultKeys,
    chain: &VerifiedChain,
    base: &Base,
) -> Result<payload::Admitted, AppError> {
    let h = &base.version.envelope.header;
    let author = chain
        .author_at(&h.membership_head, &h.author)
        .ok_or_else(invalid)?;
    let plain = base.version.envelope.verify(&author.signing)?.open(keys)?;
    if crypto::hash(&plain) != base.content_hash {
        return Err(invalid());
    }
    payload::admit(keys, h, &plain)
}
fn same_material(id: &str, a: &SharedKeyslot, b: &SharedKeyslot) -> Result<bool, AppError> {
    a.validate(id)?;
    b.validate(id)?;
    Ok(a.storage == b.storage
        && a.public.key_type == b.public.key_type
        && a.public.has_passphrase == b.public.has_passphrase
        && records_v3::key_material_matches(&a.public, &b.public.public_key, &b.public.fingerprint)
            .is_ok())
}
pub(super) fn prepare(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    after: Option<&str>,
) -> Result<Prepared, AppError> {
    records_v3::validate_state(state).map_err(|_| invalid())?;
    let before = state.local.central.as_ref().ok_or_else(invalid)?;
    if !before.control.cutover
        || !before.can_upload()
        || signer.public() != before.control.device.keys
        || after.is_some_and(|id| !super::wire::hex(id, 64))
    {
        return Err(invalid());
    }
    before.require_key_recipients()?;
    let ledger = state
        .local
        .central_projection
        .as_ref()
        .ok_or_else(invalid)?;
    ledger.validate(before)?;
    ledger.verify_native(before, keys)?;
    // An authenticated selected own wrap binds the supplied index and epoch keys.
    let chain = before.control.verified_chain()?;
    let replica = before.replica.as_ref().ok_or_else(invalid)?;
    let epoch = replica.checkpoint.epoch;
    replica.verify_write_authority(&chain, before.control.auth_epoch, epoch, &before.epochs)?;
    let wrap = before
        .own_wraps
        .iter()
        .find(|w| w.header.key_epoch == epoch.to_string())
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&wrap.header.membership_head, &wrap.header.author)
        .ok_or_else(invalid)?;
    wrap.open(signer, &wrap.header, &author.signing)?
        .verify_same(keys)?;
    for base in replica.current.values() {
        drop(current(keys, &chain, base)?);
    }
    for change in ledger.public_changes(state, keys)? {
        let opaque = change.identity.opaque(keys)?;
        let hash = crypto::hash(&payload::encode(&change.identity, &change.data)?);
        let captured = replica
            .pending
            .get(&opaque)
            .is_some_and(|p| p.latest.content_hash == hash);
        let accepted_same = match replica.current.get(&opaque) {
            Some(base) => {
                let admitted = current(keys, &chain, base)?;
                crypto::hash(&payload::encode(&admitted.identity, &admitted.data)?) == hash
            }
            None => false,
        };
        if !captured && !accepted_same {
            return Err(AppError::Other(
                "Capture current public changes before dispatch; local data is retained.".into(),
            ));
        }
    }
    let mut public = BTreeMap::new();
    // Verify everything before building any send flags. Superseded sent A is not an unchecked blob.
    for pending in replica.pending.values() {
        for draft in std::iter::once(&pending.latest).chain(pending.sent.as_ref()) {
            let admitted = open(keys, &chain, draft)?;
            if draft.envelope.header.kind == "key" {
                let source = ledger
                    .local_source(&admitted.identity.id)
                    .ok_or_else(invalid)?;
                if source.wire_handles().1 != draft.envelope.header.record_id
                    || source.private_content_hash() != draft.content_hash
                {
                    return Err(invalid());
                }
                let Data::Key(material) = admitted.data else {
                    return Err(invalid());
                };
                material.validate_against(&admitted.identity.id, source.slot())?;
            } else if draft.envelope.header.kind == "keyslot"
                && std::ptr::eq(draft, &pending.latest)
            {
                public.insert(admitted.identity.id, admitted.data);
            }
        }
    }
    let mut eligible = BTreeSet::new();
    let mut waiting_private = 0;
    for (opaque, pending) in &replica.pending {
        if pending.claimed.is_some() || replica.conflicts.get(opaque).is_some_and(|v| !v.is_empty())
        {
            if pending.latest.envelope.header.kind == "key" {
                waiting_private += 1;
            }
            continue;
        }
        let draft = pending.sent.as_ref().unwrap_or(&pending.latest);
        let h = &draft.envelope.header;
        if h.membership_head != chain.current().head()
            || number(&h.key_epoch, false)? != epoch
            || number(&h.expected_revision, true)?
                != replica
                    .current
                    .get(opaque)
                    .map_or(Ok(0), |b| number(&b.version.revision, false))?
        {
            if h.kind == "key" {
                waiting_private += 1;
            }
            continue;
        }
        if h.kind == "key" {
            let admitted = open(keys, &chain, draft)?;
            let source = ledger
                .local_source(&admitted.identity.id)
                .ok_or_else(invalid)?;
            let (public_handle, private_handle) = source.wire_handles();
            if (Identity {
                kind: "keyslot".into(),
                id: admitted.identity.id.clone(),
                scope: None,
            })
            .opaque(keys)?
                != public_handle
                || private_handle != opaque
            {
                return Err(invalid());
            }
            let blocked = replica
                .conflicts
                .get(public_handle)
                .is_some_and(|v| !v.is_empty());
            let latest_matches = match public.get(&admitted.identity.id) {
                Some(Data::Keyslot(slot)) => {
                    same_material(&admitted.identity.id, source.slot(), slot)?
                }
                Some(_) => false,
                None => true,
            };
            let remote_public_matches = match replica.current.get(public_handle) {
                Some(base) => {
                    let admitted = current(keys, &chain, base)?;
                    match admitted.data {
                        Data::Keyslot(slot) => {
                            same_material(source.key_id(), source.slot(), &slot)?
                        }
                        _ => false,
                    }
                }
                None => false,
            };
            let remote_private_matches = match replica.current.get(private_handle) {
                Some(base) => {
                    let remote = current(keys, &chain, base)?;
                    matches!(remote.data, Data::Key(_))
                        && base.content_hash == source.private_content_hash()
                }
                None => true,
            };
            if blocked || !latest_matches || !remote_public_matches || !remote_private_matches {
                waiting_private += 1;
                continue;
            }
        }
        eligible.insert(opaque.clone());
    }
    let mut ids = eligible
        .iter()
        .filter(|id| after.is_none_or(|cursor| id.as_str() > cursor))
        .cloned()
        .collect::<Vec<_>>();
    ids.extend(
        eligible
            .iter()
            .filter(|id| after.is_some_and(|cursor| id.as_str() <= cursor))
            .cloned(),
    );
    let mut owner = before.clone();
    let records = owner
        .replica
        .as_mut()
        .ok_or_else(invalid)?
        .prepare_send_selected(
            &chain,
            epoch,
            before.control.auth_epoch,
            &before.epochs,
            &ids,
        )?;
    owner.validate()?;
    let cursor = records
        .last()
        .map(|r| r.header.record_id.clone())
        .or_else(|| after.map(str::to_owned));
    Ok(Prepared {
        ready_remaining: eligible.len().saturating_sub(records.len()),
        owner,
        records,
        waiting_private,
        cursor,
    })
}

#[cfg(test)]
pub(super) mod tests;

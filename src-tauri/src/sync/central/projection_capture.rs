//! Encrypt exact latest local public semantics before network/delta publication. Pure candidate only.
//! A caller must CAS/persist it under the single SyncCore before dispatch; no I/O or ACK here.
use super::{
    crypto::{DeviceKeys, VaultKeys},
    payload::{self, Data, Identity},
    projection_state::Ledger,
    replica::{Base, Conflict, Replica},
    wire::{invalid, RecordHeader},
};
use crate::{
    error::AppError,
    sync::records_v3::{self, SyncStateV3},
};

/// The basis a capture holds a change of the public record `opaque` against: the remote version a pending change of it was last
/// confirmed on, else the one this device last read into its rows (the ledger's). A change captured while the replica's current version
/// is another becomes a conflict (`public_candidate`).
fn basis_of<'a>(replica: &'a Replica, ledger: &'a Ledger, opaque: &str) -> Option<&'a Base> {
    replica
        .pending
        .get(opaque)
        .and_then(|pending| pending.confirmed.as_ref())
        .or_else(|| ledger.bases.get(opaque).map(|basis| &basis.wire))
}

/// Whether this device can change the library's Catalog now without a conflict (R64a): none is held on it, and its basis
/// (`basis_of`) is the replica's current Catalog, so the latest Catalog the pull staged has been read into this device's rows (the
/// delta projection reads it at the end of the round that staged it). Until then a Catalog captured from those rows would be held
/// against an older basis and conflict with the library's.
pub(super) fn catalog_settled(state: &SyncStateV3, keys: &VaultKeys) -> Result<bool, AppError> {
    let ledger = state.local.central_projection.as_ref().ok_or_else(invalid)?;
    let replica = state
        .local
        .central
        .as_ref()
        .and_then(|owner| owner.replica.as_ref())
        .ok_or_else(invalid)?;
    let opaque = Identity {
        kind: "meta".into(),
        id: "catalog".into(),
        scope: None,
    }
    .opaque(keys)?;
    Ok(!replica.conflicts.contains_key(&opaque)
        && basis_of(replica, ledger, &opaque) == replica.current.get(&opaque))
}

/// The publish step (design 2026-10-26, Existing routes move in; R64a) as a pure transition: `state` with the routes saved on this
/// device alone that the library takes made its rows (`transports::publish_local`), or `None` when none moves. It waits while the
/// Catalog is not settled (`catalog_settled`): while the library's latest Catalog is not yet read into this device's rows, or is in
/// conflict. The central dispatch saves what it returns before its capture.
pub(super) fn move_local_routes(
    state: &SyncStateV3,
    keys: &VaultKeys,
    now: u64,
) -> Result<Option<SyncStateV3>, AppError> {
    if state.local.transports.is_empty() || !catalog_settled(state, keys)? {
        return Ok(None);
    }
    crate::sync::transports::publish_local(state, now)
}

pub fn public_candidate(
    state: &SyncStateV3,
    keys: &VaultKeys,
    signer: &DeviceKeys,
) -> Result<SyncStateV3, AppError> {
    let ledger = state
        .local
        .central_projection
        .as_ref()
        .ok_or_else(invalid)?;
    let before = state.local.central.as_ref().ok_or_else(invalid)?;
    if !before.can_upload() || signer.public() != before.control.device.keys {
        return Err(invalid());
    }
    let changes = ledger.public_changes(state, keys)?;
    let chain = before.control.verified_chain()?;
    let mut candidate = state.clone();
    let owner = candidate.local.central.as_mut().ok_or_else(invalid)?;
    let replica = owner.replica.as_mut().ok_or_else(invalid)?;
    for change in changes {
        let opaque = change.identity.opaque(keys)?;
        let plaintext = payload::encode(&change.identity, &change.data)?;
        let local_revision = replica.pending.get(&opaque).map_or(Ok(1), |pending| {
            pending
                .latest
                .local_revision
                .checked_add(1)
                .ok_or_else(invalid)
        })?;
        let header = RecordHeader {
            origin: ledger.anchor.origin.clone(),
            account_id: ledger.anchor.account_id.clone(),
            genesis_hash: ledger.anchor.genesis_hash.clone(),
            vault_id: ledger.vault.clone(),
            record_id: opaque.clone(),
            key_epoch: replica.checkpoint.epoch.to_string(),
            membership_head: chain.current().head().into(),
            author: owner.control.device.id.clone(),
            operation_id: "0".repeat(32),
            expected_revision: "0".into(),
            kind: change.identity.kind,
            deleted: matches!(change.data, Data::Deleted),
        };
        replica.enqueue(&chain, keys, signer, local_revision, header, &plaintext)?;
        let Some(pending) = replica.pending.get(&opaque) else {
            continue;
        };
        // Remote ciphertext may have advanced while the material/public cache transaction still
        // held A. Keep signed A + encrypted local B + signed C; never silently rebase B over C.
        if let Some(remote) = replica.current.get(&opaque) {
            let basis = basis_of(replica, ledger, &opaque);
            let own_source_ack =
                basis.is_none() && ledger.own_unprojected_keyslot(before, keys, &opaque, remote)?;
            if basis != Some(remote)
                && !own_source_ack
                && remote.content_hash != pending.latest.content_hash
            {
                let conflict = Conflict {
                    base: basis.cloned(),
                    local: pending.latest.clone(),
                    remote: remote.clone(),
                };
                let conflicts = replica.conflicts.entry(opaque).or_default();
                if !conflicts.iter().any(|known| {
                    known.local.local_revision == conflict.local.local_revision
                        && known.local.content_hash == conflict.local.content_hash
                        && known.remote == conflict.remote
                }) {
                    conflicts.push(conflict);
                }
            }
        }
    }
    replica.validate(&chain)?;
    let candidate = super::passwords::capture_removed(&candidate, keys, signer)?;
    records_v3::validate_state(&candidate).map_err(|_| invalid())?;
    Ok(candidate)
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::{
        crypto,
        projection_state::tests::initial,
        rekey::{self, Checkpoint, Version},
        wire::canonical,
    };
    use super::*;
    use crate::sync::{
        record::{record_key, RecordKind},
        records_v3::HostScope,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn signer() -> DeviceKeys {
        DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap()
    }
    fn edit(state: &mut SyncStateV3, value: &str) {
        state
            .local
            .hosts
            .get_mut(&record_key(RecordKind::Host, "0000000000000001"))
            .unwrap()
            .record
            .payload["alias"] = value.into();
    }
    fn opaque(state: &SyncStateV3, _keys: &VaultKeys) -> String {
        state
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .bases
            .iter()
            .find(|(_, b)| b.remote.kind == "host" && b.remote.scope == Some(HostScope::Local))
            .unwrap()
            .0
            .clone()
    }
    fn pending_alias(state: &SyncStateV3, keys: &VaultKeys) -> String {
        let ws = state.local.central.as_ref().unwrap();
        let pending = &ws.replica.as_ref().unwrap().pending[&opaque(state, keys)];
        let verified = pending
            .latest
            .envelope
            .verify(&ws.control.device.keys.signing)
            .unwrap();
        let bytes = verified.open(keys).unwrap();
        let value = payload::admit(keys, &pending.latest.envelope.header, &bytes).unwrap();
        let Data::Host(host) = value.data else {
            panic!()
        };
        host.alias
    }
    pub(in crate::sync::central) fn remote(
        state: &SyncStateV3,
        keys: &VaultKeys,
        alias: &str,
        operation: Option<&str>,
    ) -> Version {
        let ws = state.local.central.as_ref().unwrap();
        let replica = ws.replica.as_ref().unwrap();
        let id = opaque(state, keys);
        let base = &replica.current[&id];
        let header = RecordHeader {
            expected_revision: base.version.revision.clone(),
            operation_id: operation.map(str::to_owned).unwrap_or("a".repeat(32)),
            ..base.version.envelope.header.clone()
        };
        let mut host: crate::sync::records_v3::HostPayload = serde_json::from_value(
            state.local.hosts[&record_key(RecordKind::Host, "0000000000000001")]
                .record
                .payload
                .clone(),
        )
        .unwrap();
        host.alias = alias.into();
        let identity = payload::Identity {
            kind: "host".into(),
            id: "0000000000000001".into(),
            scope: Some(HostScope::Local),
        };
        let plaintext = payload::encode(&identity, &Data::Host(host)).unwrap();
        let envelope = crypto::seal_record(keys, &signer(), header, &plaintext).unwrap();
        let digest = rekey::envelope_digest(&envelope).unwrap();
        let sequence = (replica.checkpoint.sequence + 1).to_string();
        let history_hash = crypto::hash(
            &canonical(&[
                "lunport-history-v2",
                &replica.checkpoint.history_hash,
                &sequence,
                &digest,
            ])
            .unwrap(),
        );
        Version {
            envelope,
            digest,
            sequence,
            history_hash,
            revision: (super::super::wire::number(&base.version.revision, false).unwrap() + 1)
                .to_string(),
        }
    }
    pub(in crate::sync::central) fn apply(state: &mut SyncStateV3, keys: &VaultKeys, row: Version) {
        let ws = state.local.central.as_mut().unwrap();
        let target = Checkpoint {
            epoch: 1,
            sequence: super::super::wire::number(&row.sequence, false).unwrap(),
            history_hash: row.history_hash.clone(),
        };
        ws.replica = Some(
            ws.replica
                .as_ref()
                .unwrap()
                .prepare_page(&ws.control.verified_chain().unwrap(), keys, &[row], &target)
                .unwrap()
                .next,
        );
    }
    #[test]
    fn repeated_capture_is_idempotent_and_a_local_revert_replaces_latest_without_erasing_uncertain_sent_b(
    ) {
        let (mut state, keys, _) = initial();
        edit(&mut state, "B");
        let mut captured = public_candidate(&state, &keys, &signer()).unwrap();
        assert_eq!(pending_alias(&captured, &keys), "B");
        assert_eq!(
            public_candidate(&captured, &keys, &signer()).unwrap(),
            captured
        );
        let id = opaque(&captured, &keys);
        let p = captured
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .get_mut(&id)
            .unwrap();
        p.sent = Some(p.latest.clone());
        let sent = p.sent.clone();
        edit(&mut captured, "fixture");
        let reverted = public_candidate(&captured, &keys, &signer()).unwrap();
        assert_eq!(pending_alias(&reverted, &keys), "fixture");
        assert_eq!(
            reverted
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .pending[&id]
                .sent,
            sent
        );
    }
    #[test]
    fn a_remote_c_received_during_publication_retains_signed_base_a_and_encrypted_local_b() {
        let (mut state, keys, _) = initial();
        let row = remote(&state, &keys, "C", None);
        apply(&mut state, &keys, row);
        edit(&mut state, "B");
        let next = public_candidate(&state, &keys, &signer()).unwrap();
        let id = opaque(&next, &keys);
        let replica = next
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap();
        let conflict = &replica.conflicts[&id][0];
        assert_eq!(
            conflict.base.as_ref().unwrap(),
            &next.local.central_projection.as_ref().unwrap().bases[&id].wire
        );
        assert_eq!(conflict.remote, replica.current[&id]);
        assert_eq!(pending_alias(&next, &keys), "B");
        let saved = serde_json::to_string(&next).unwrap();
        assert!(!saved.contains("\"alias\":\"C\""));
        assert!(!saved.contains("private_key"));
        assert_eq!(public_candidate(&next, &keys, &signer()).unwrap(), next);
    }
    #[test]
    fn receipt_for_sent_a_does_not_clear_newer_b_and_following_c_is_a_durable_conflict() {
        let (mut state, keys, _) = initial();
        edit(&mut state, "sent-A");
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let id = opaque(&state, &keys);
        let pending = state
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .get_mut(&id)
            .unwrap();
        pending.sent = Some(pending.latest.clone());
        let sent = pending.sent.as_ref().unwrap().clone();
        edit(&mut state, "newer-B");
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let mut ack = remote(
            &state,
            &keys,
            "sent-A",
            Some(&sent.envelope.header.operation_id),
        );
        // Use the exact dispatched ciphertext, not a newly encrypted copy of the same value.
        ack.envelope = sent.envelope;
        ack.digest = rekey::envelope_digest(&ack.envelope).unwrap();
        let previous = &state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .checkpoint
            .history_hash;
        ack.history_hash = crypto::hash(
            &canonical(&["lunport-history-v2", previous, &ack.sequence, &ack.digest]).unwrap(),
        );
        apply(&mut state, &keys, ack);
        assert_eq!(pending_alias(&state, &keys), "newer-B");
        assert!(state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&id]
            .confirmed
            .is_some());
        state = public_candidate(&state, &keys, &signer()).unwrap();
        assert!(state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .conflicts
            .is_empty());
        let latest = &state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&id]
            .latest;
        assert_eq!(
            latest.envelope.header.expected_revision,
            state
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .current[&id]
                .version
                .revision
        );
        let row = remote(&state, &keys, "C", None);
        apply(&mut state, &keys, row);
        let replica = state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap();
        assert!(!replica.conflicts[&id].is_empty());
        assert_eq!(pending_alias(&state, &keys), "newer-B");
    }
    #[test]
    fn a_created_then_removed_row_replaces_its_unsent_draft_with_a_tombstone() {
        let (state, keys, _) = initial();
        let host:crate::sync::records_v3::HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"new","hostname":"fixture.invalid","auth":"password"})).unwrap();
        let mut state = crate::sync::record_repository::create_host(
            &state,
            "0000000000000008",
            HostScope::Local,
            host,
            100,
        )
        .unwrap();
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let id = payload::Identity {
            kind: "host".into(),
            id: "0000000000000008".into(),
            scope: Some(HostScope::Local),
        }
        .opaque(&keys)
        .unwrap();
        state
            .local
            .hosts
            .remove(&record_key(RecordKind::Host, "0000000000000008"));
        let next = public_candidate(&state, &keys, &signer()).unwrap();
        let pending = &next
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&id];
        assert!(pending.latest.envelope.header.deleted);
        assert_eq!(pending.latest.local_revision, 2);
        assert_eq!(public_candidate(&next, &keys, &signer()).unwrap(), next);
    }
    #[test]
    fn removing_a_new_row_while_its_create_is_uncertain_survives_the_create_ack_and_rebases_the_delete(
    ) {
        let (state, keys, _) = initial();
        let host:crate::sync::records_v3::HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"new","hostname":"fixture.invalid","auth":"password"})).unwrap();
        let mut state = crate::sync::record_repository::create_host(
            &state,
            "0000000000000008",
            HostScope::Local,
            host,
            100,
        )
        .unwrap();
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let id = payload::Identity {
            kind: "host".into(),
            id: "0000000000000008".into(),
            scope: Some(HostScope::Local),
        }
        .opaque(&keys)
        .unwrap();
        let p = state
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .get_mut(&id)
            .unwrap();
        p.sent = Some(p.latest.clone());
        let sent = p.sent.clone().unwrap();
        state
            .local
            .hosts
            .remove(&record_key(RecordKind::Host, "0000000000000008"));
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let replica = state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap();
        let sequence = (replica.checkpoint.sequence + 1).to_string();
        let digest = rekey::envelope_digest(&sent.envelope).unwrap();
        let hash = crypto::hash(
            &canonical(&[
                "lunport-history-v2",
                &replica.checkpoint.history_hash,
                &sequence,
                &digest,
            ])
            .unwrap(),
        );
        apply(
            &mut state,
            &keys,
            Version {
                envelope: sent.envelope,
                digest,
                sequence,
                history_hash: hash,
                revision: "1".into(),
            },
        );
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let replica = state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap();
        let pending = &replica.pending[&id];
        assert!(pending.latest.envelope.header.deleted);
        assert_eq!(pending.latest.envelope.header.expected_revision, "1");
        assert!(pending.sent.is_none());
        assert!(pending.confirmed.is_some());
        assert!(replica.conflicts.is_empty());
        assert!(state
            .local
            .hosts
            .get(&record_key(RecordKind::Host, "0000000000000008"))
            .is_none());
    }
    #[test]
    fn a_corrupt_superseded_or_current_pending_hash_blocks_capture_without_erasing_the_draft() {
        let (mut state, keys, _) = initial();
        edit(&mut state, "B");
        state = public_candidate(&state, &keys, &signer()).unwrap();
        let id = opaque(&state, &keys);
        state
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .get_mut(&id)
            .unwrap()
            .latest
            .content_hash = "e".repeat(64);
        let before = state.clone();
        assert!(public_candidate(&state, &keys, &signer()).is_err());
        assert_eq!(state, before);
    }
    #[test]
    fn unavailable_owner_or_wrong_signer_cannot_capture_or_change_the_source() {
        let (mut state, keys, _) = initial();
        edit(&mut state, "B");
        assert!(public_candidate(&state, &keys, &DeviceKeys::generate().unwrap()).is_err());
        assert!(public_candidate(&state, &VaultKeys::generate().unwrap(), &signer()).is_err());
        state.local.central.as_mut().unwrap().control.cutover = false;
        assert!(public_candidate(&state, &keys, &signer()).is_err());
    }
    /// `state` with a local-scope host `id` and an IAP route for it saved on this device alone, as 1.12 saved it.
    fn with_local_route(state: &SyncStateV3, id: &str) -> SyncStateV3 {
        let host: crate::sync::records_v3::HostPayload = serde_json::from_value(serde_json::json!({"schema":2,"alias":format!("jump-{id}"),"hostname":"fixture.invalid","auth":"password"})).unwrap();
        let state = crate::sync::record_repository::create_host(state, id, HostScope::Local, host, 100).unwrap();
        let route = serde_json::from_value(serde_json::json!({"host_id":id,"kind":{"type":"gcp_iap","project":"eng-dev-396409","zone":"asia-east1-b","instance":"jumpbox"}})).unwrap();
        crate::sync::transports::tests::saved_on_this_device(&state, &route)
    }
    fn catalog_identity() -> Identity {
        Identity {
            kind: "meta".into(),
            id: "catalog".into(),
            scope: None,
        }
    }
    /// R64a: the publish step waits while a Catalog captured now would conflict with the library's: while the latest Catalog a pull
    /// staged is not yet read into this device's rows, and while the Catalog is in conflict. Otherwise it moves the routes in.
    #[test]
    fn the_publish_step_waits_for_the_staged_catalog_to_be_read_and_while_it_is_in_conflict() {
        use crate::sync::transports;
        let (state, keys, _) = initial();
        let catalog_id = catalog_identity().opaque(&keys).unwrap();
        let (x, y) = ("0000000000000009", "000000000000000a");
        let state = with_local_route(&state, x);
        assert!(catalog_settled(&state, &keys).unwrap());
        let moved = move_local_routes(&state, &keys, 200).unwrap().expect("the Catalog is settled");
        assert!(transports::synced(&moved, x) && moved.local.transports.is_empty());
        // Another device's Catalog, staged by a pull and not yet read into this device's rows: the basis is behind the current one.
        let mut staged = state.clone();
        let mut catalog = staged.local.central_projection.as_ref().unwrap().catalog.clone();
        catalog.collections.reverse();
        super::super::projection_delta::tests::append(&mut staged, &keys, catalog_identity(), Data::Catalog(catalog));
        assert!(!catalog_settled(&staged, &keys).unwrap());
        assert!(transports::publish_local(&staged, 200).unwrap().is_some(), "the basis alone holds the route back");
        assert_eq!(move_local_routes(&staged, &keys, 200).unwrap(), None);
        // Moving it in regardless is what the step must not do: the capture holds the Catalog against the older basis, a conflict.
        let forced = public_candidate(&transports::publish_local(&staged, 200).unwrap().unwrap(), &keys, &signer()).unwrap();
        let mut conflicted = with_local_route(&forced, y);
        let replica = conflicted.local.central.as_ref().unwrap().replica.as_ref().unwrap();
        assert!(replica.conflicts.contains_key(&catalog_id));
        // Held in conflict, it waits even once its basis is the current Catalog (here: the pending change confirmed on it).
        let current = replica.current[&catalog_id].clone();
        let replica = conflicted.local.central.as_mut().unwrap().replica.as_mut().unwrap();
        replica.pending.get_mut(&catalog_id).unwrap().confirmed = Some(current.clone());
        assert_eq!(basis_of(replica, conflicted.local.central_projection.as_ref().unwrap(), &catalog_id), Some(&current));
        assert!(transports::publish_local(&conflicted, 300).unwrap().is_some(), "y could move");
        assert!(!catalog_settled(&conflicted, &keys).unwrap());
        assert_eq!(move_local_routes(&conflicted, &keys, 300).unwrap(), None);
    }
}

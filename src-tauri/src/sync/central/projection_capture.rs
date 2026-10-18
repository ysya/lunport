//! Encrypt exact latest local public semantics before network/delta publication. Pure candidate only.
//! A caller must CAS/persist it under the single SyncCore before dispatch; no I/O or ACK here.
use super::{
    crypto::{DeviceKeys, VaultKeys},
    payload::{self, Data},
    replica::Conflict,
    wire::{invalid, RecordHeader},
};
use crate::{
    error::AppError,
    sync::records_v3::{self, SyncStateV3},
};

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
            let basis = ledger.bases.get(&opaque).map(|basis| &basis.wire);
            if basis != Some(remote) && remote.content_hash != pending.latest.content_hash {
                let conflict = Conflict {
                    base: basis.cloned(),
                    local: pending.latest.clone(),
                    remote: remote.clone(),
                };
                let conflicts = replica.conflicts.entry(opaque).or_default();
                if !conflicts.contains(&conflict) {
                    conflicts.push(conflict);
                }
            }
        }
    }
    replica.validate(&chain)?;
    records_v3::validate_state(&candidate).map_err(|_| invalid())?;
    Ok(candidate)
}

#[cfg(test)]
mod tests {
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
    fn remote(
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
    fn apply(state: &mut SyncStateV3, keys: &VaultKeys, row: Version) {
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
    fn unavailable_owner_or_wrong_signer_cannot_capture_or_change_the_source() {
        let (mut state, keys, _) = initial();
        edit(&mut state, "B");
        assert!(public_candidate(&state, &keys, &DeviceKeys::generate().unwrap()).is_err());
        assert!(public_candidate(&state, &VaultKeys::generate().unwrap(), &signer()).is_err());
        state.local.central.as_mut().unwrap().control.cutover = false;
        assert!(public_candidate(&state, &keys, &signer()).is_err());
    }
}

use super::*;
use crate::sync::central::{
    local_material,
    rekey::{self, Checkpoint, Version},
    wire::canonical,
};

pub(super) fn fixture() -> (SyncStateV3, VaultKeys, DeviceKeys, String) {
    let (state, keys, signer, context, public, entry) = local_material::tests::fixture(false);
    let id = context.key_id.clone();
    let state = local_material::prepare_new(&state, &keys, &signer, context, public, &entry)
        .unwrap()
        .intent()
        .unwrap()
        .candidate(&state, &keys, &signer, &entry)
        .unwrap();
    (state, keys, signer, id)
}
pub(super) fn accept(state: &mut SyncStateV3, keys: &VaultKeys, envelope: RecordEnvelope) {
    let owner = state.local.central.as_mut().unwrap();
    let replica = owner.replica.as_ref().unwrap();
    let digest = rekey::envelope_digest(&envelope).unwrap();
    let sequence = replica.checkpoint.sequence + 1;
    let history_hash = crypto::hash(
        &canonical(&[
            "lunport-history-v2",
            &replica.checkpoint.history_hash,
            &sequence.to_string(),
            &digest,
        ])
        .unwrap(),
    );
    let row = Version {
        revision: (number(&envelope.header.expected_revision, true).unwrap() + 1).to_string(),
        sequence: sequence.to_string(),
        envelope,
        digest,
        history_hash: history_hash.clone(),
    };
    owner.replica = Some(
        replica
            .prepare_page(
                &owner.control.verified_chain().unwrap(),
                keys,
                &[row],
                &Checkpoint {
                    epoch: 1,
                    sequence,
                    history_hash,
                },
            )
            .unwrap()
            .next,
    );
}
#[test]
fn private_waits_for_authenticated_public_history_and_retry_after_restart_uses_exact_bytes() {
    let (mut state, keys, signer, _) = fixture();
    let original = state.clone();
    let first = prepare(&state, &keys, &signer, None).unwrap();
    assert_eq!(state, original);
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].header.kind, "keyslot");
    assert_eq!(first.waiting_private, 1);
    state.local.central = Some(first.owner);
    let serialized = serde_json::to_vec(&state).unwrap();
    let mut restored: SyncStateV3 = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(
        prepare(&restored, &keys, &signer, None).unwrap().records,
        first.records
    );
    // A server receipt is not publication evidence: only verified signed history releases private data.
    let h = &first.records[0].header;
    let fake = super::super::replica::Receipt {
        operation_id: h.operation_id.clone(),
        record_id: h.record_id.clone(),
        revision: "1".into(),
        sequence: "999".into(),
        digest: rekey::envelope_digest(&first.records[0]).unwrap(),
        history_hash: "a".repeat(64),
    };
    let chain = restored
        .local
        .central
        .as_ref()
        .unwrap()
        .control
        .verified_chain()
        .unwrap();
    restored
        .local
        .central
        .as_mut()
        .unwrap()
        .replica
        .as_mut()
        .unwrap()
        .note_receipt(&chain, fake)
        .unwrap();
    let waiting = prepare(&restored, &keys, &signer, None).unwrap();
    assert!(waiting.records.is_empty());
    assert_eq!(waiting.waiting_private, 1);
    accept(&mut state, &keys, first.records[0].clone());
    let private = prepare(&state, &keys, &signer, first.cursor.as_deref()).unwrap();
    assert_eq!(private.records.len(), 1);
    assert_eq!(private.records[0].header.kind, "key");
    assert_eq!(private.waiting_private, 0);
    assert_eq!(private.ready_remaining, 0);
    state.local.central = Some(private.owner);
    assert_eq!(
        prepare(&state, &keys, &signer, None).unwrap().records,
        private.records
    );
}
#[test]
fn a_later_bad_draft_or_current_hash_rejects_every_candidate_without_mutating_input() {
    let (mut state, keys, signer, _) = fixture();
    for private in [false, true] {
        let mut bad = state.clone();
        let pending = bad
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .values_mut()
            .find(|p| (p.latest.envelope.header.kind == "key") == private)
            .unwrap();
        pending.latest.content_hash = "f".repeat(64);
        let original = bad.clone();
        assert!(prepare(&bad, &keys, &signer, None).is_err());
        assert_eq!(bad, original);
    }
    let first = prepare(&state, &keys, &signer, None).unwrap();
    state.local.central = Some(first.owner);
    accept(&mut state, &keys, first.records[0].clone());
    state
        .local
        .central
        .as_mut()
        .unwrap()
        .replica
        .as_mut()
        .unwrap()
        .current
        .get_mut(&first.records[0].header.record_id)
        .unwrap()
        .content_hash = "f".repeat(64);
    assert!(prepare(&state, &keys, &signer, None).is_err());
}
#[test]
fn captured_name_change_keeps_material_dependency_and_missing_capture_blocks_the_whole_batch() {
    let (state, keys, signer, id) = fixture();
    let public = state.local.keys[&id].public.clone();
    let renamed =
        crate::sync::record_repository::rename_key(&state, &id, &public, "new_name", 300).unwrap();
    assert!(prepare(&renamed, &keys, &signer, None).is_err());
    let mut captured =
        super::super::projection_capture::public_candidate(&renamed, &keys, &signer).unwrap();
    let first = prepare(&captured, &keys, &signer, None).unwrap();
    assert_eq!(first.records.len(), 1);
    captured.local.central = Some(first.owner);
    accept(&mut captured, &keys, first.records[0].clone());
    let next = prepare(&captured, &keys, &signer, None).unwrap();
    assert_eq!(next.records.len(), 1);
    assert_eq!(next.records[0].header.kind, "key");
}
#[test]
fn remote_deleted_or_changed_private_material_and_public_conflicts_never_reupload_old_sources() {
    use super::super::projection_delta::tests::append;
    for change in 0..3 {
        let (mut state, keys, signer, id) = fixture();
        let first = prepare(&state, &keys, &signer, None).unwrap();
        state.local.central = Some(first.owner);
        let public_draft = state
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[&first.records[0].header.record_id]
            .latest
            .clone();
        accept(&mut state, &keys, first.records[0].clone());
        if change == 0 {
            append(
                &mut state,
                &keys,
                Identity {
                    kind: "key".into(),
                    id: id.clone(),
                    scope: None,
                },
                Data::Deleted,
            );
        } else if change == 1 {
            let mut key =
                crate::vault::material::parse(&crate::sync::slot_rules::test_keys::plain())
                    .unwrap();
            key.set_comment("different original bytes");
            let raw = key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();
            append(
                &mut state,
                &keys,
                Identity {
                    kind: "key".into(),
                    id: id.clone(),
                    scope: None,
                },
                Data::Key(payload::PrivateMaterial::new(zeroize::Zeroizing::new(raw)).unwrap()),
            );
        } else {
            let owner = state.local.central.as_mut().unwrap();
            let replica = owner.replica.as_mut().unwrap();
            let public = first.records[0].header.record_id.clone();
            let base = replica.current[&public].clone();
            let local = public_draft;
            replica.conflicts.insert(
                public,
                vec![super::super::replica::Conflict {
                    base: Some(base.clone()),
                    local,
                    remote: base,
                }],
            );
        }
        if change < 2 {
            // Even an explicitly rebased old draft must not replace newer remote private data.
            let owner = state.local.central.as_mut().unwrap();
            let chain = owner.control.verified_chain().unwrap();
            let replica = owner.replica.as_mut().unwrap();
            let handle = Identity {
                kind: "key".into(),
                id: id.clone(),
                scope: None,
            }
            .opaque(&keys)
            .unwrap();
            let draft = replica.pending[&handle].latest.clone();
            let plain = draft
                .envelope
                .verify(&signer.public().signing)
                .unwrap()
                .open(&keys)
                .unwrap();
            replica.conflicts.remove(&handle);
            replica
                .enqueue(
                    &chain,
                    &keys,
                    &signer,
                    draft.local_revision,
                    draft.envelope.header,
                    &plain,
                )
                .unwrap();
            assert_eq!(
                replica.pending[&handle]
                    .latest
                    .envelope
                    .header
                    .expected_revision,
                replica.current[&handle].version.revision
            );
        }
        let original = state.clone();
        records_v3::validate_state(&state).unwrap();
        let prepared = prepare(&state, &keys, &signer, None).unwrap();
        assert!(prepared.records.iter().all(|r| r.header.kind != "key"));
        assert_eq!(state, original);
    }
}
#[test]
fn invalid_cursor_and_untrusted_supplied_keys_or_signer_cannot_prepare_any_send() {
    let (state, keys, signer, _) = fixture();
    assert!(prepare(&state, &keys, &signer, Some("bad")).is_err());
    assert!(prepare(&state, &VaultKeys::generate().unwrap(), &signer, None).is_err());
    assert!(prepare(&state, &keys, &DeviceKeys::generate().unwrap(), None).is_err());
}

#[test]
fn renaming_between_own_public_ack_and_private_send_does_not_create_a_false_conflict_or_deadlock() {
    let (mut state, keys, signer, id) = fixture();
    let first = prepare(&state, &keys, &signer, None).unwrap();
    state.local.central = Some(first.owner);
    accept(&mut state, &keys, first.records[0].clone());
    let public = state.local.keys[&id].public.clone();
    let renamed = crate::sync::record_repository::rename_key(
        &state,
        &id,
        &public,
        "name_after_public_ack",
        400,
    )
    .unwrap();
    let captured =
        super::super::projection_capture::public_candidate(&renamed, &keys, &signer).unwrap();
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
    let next = prepare(&captured, &keys, &signer, None).unwrap();
    assert!(next.records.iter().any(|r| r.header.kind == "key"));
}
#[test]
fn a_large_queue_is_bounded_and_rotating_cursor_reaches_rows_outside_the_first_batch() {
    let (mut state, keys, signer, _) = fixture();
    let template = state.local.hosts.values().next().unwrap().clone();
    for index in 100..140 {
        let mut row = template.clone();
        row.record.id = format!("{index:016x}");
        row.record.payload["alias"] = format!("host_{index}").into();
        state.local.hosts.insert(
            crate::sync::record::record_key(crate::sync::record::RecordKind::Host, &row.record.id),
            row,
        );
    }
    let mut state =
        super::super::projection_capture::public_candidate(&state, &keys, &signer).unwrap();
    let first = prepare(&state, &keys, &signer, None).unwrap();
    assert_eq!(first.records.len(), 32);
    assert!(first.ready_remaining > 0);
    let mut seen = first
        .records
        .iter()
        .map(|r| r.header.record_id.clone())
        .collect::<BTreeSet<_>>();
    state.local.central = Some(first.owner);
    let second = prepare(&state, &keys, &signer, first.cursor.as_deref()).unwrap();
    assert!(second.records.len() <= 32);
    seen.extend(second.records.iter().map(|r| r.header.record_id.clone()));
    assert_eq!(seen.len(), 41);
    assert!(second.records.iter().all(|r| r.header.kind != "key"));
}

#[test]
fn an_own_public_material_change_still_conflicts_and_cannot_release_the_old_private_source() {
    let (mut state, keys, signer, id) = fixture();
    let first = prepare(&state, &keys, &signer, None).unwrap();
    state.local.central = Some(first.owner);
    accept(&mut state, &keys, first.records[0].clone());
    let mut slot = state
        .local
        .central_projection
        .as_ref()
        .unwrap()
        .local_source(&id)
        .unwrap()
        .slot()
        .clone();
    slot.storage = payload::KeyStorage::Managed {
        sha256: "f".repeat(64),
    };
    super::super::projection_delta::tests::append(
        &mut state,
        &keys,
        Identity {
            kind: "keyslot".into(),
            id: id.clone(),
            scope: None,
        },
        Data::Keyslot(slot),
    );
    let public = state.local.keys[&id].public.clone();
    let renamed =
        crate::sync::record_repository::rename_key(&state, &id, &public, "keep_local_name", 500)
            .unwrap();
    let captured =
        super::super::projection_capture::public_candidate(&renamed, &keys, &signer).unwrap();
    assert!(!captured
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap()
        .conflicts
        .is_empty());
    assert!(prepare(&captured, &keys, &signer, None)
        .unwrap()
        .records
        .iter()
        .all(|r| r.header.kind != "key"));
}

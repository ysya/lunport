use super::*;
use crate::sync::central::{migration::legacy_checkpoint, migration_freeze::Phase as FreezePhase};
fn fixture() -> (
    SyncStateV3,
    Sources,
    Workspace,
    Progress,
    Vec<FrozenSnapshot>,
) {
    let (mut state, sources, owner, mut progress, parent, child, parent_response, child_response) =
        super::super::frozen::tests::fixture_with_state();
    state.version = crate::sync::records_v3::CENTRAL_STATE_VERSION;
    state.local.central = Some(owner.clone());
    progress.sources.push(
        legacy_checkpoint(&child, child_response.latest_seq, &child_response.records).unwrap(),
    );
    progress.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
    progress.phase = FreezePhase::Frozen;
    progress.next.clear();
    let snapshots = vec![
        sources
            .admit_frozen(
                &owner,
                &"7".repeat(32),
                &progress,
                None,
                &parent,
                parent_response,
            )
            .unwrap(),
        sources
            .admit_frozen(
                &owner,
                &"7".repeat(32),
                &progress,
                None,
                &child,
                child_response,
            )
            .unwrap(),
    ];
    (state, sources, owner, progress, snapshots)
}
#[test]
fn complete_collection_retains_every_local_pending_conflict_and_frozen_position_after_restore() {
    let (state, sources, _, progress, snapshots) = fixture();
    let before = serde_json::to_vec(&state).unwrap();
    let local = Inventory::from_state(&sources, &state).unwrap();
    let local_len = local.rows().len();
    let dirty = local.rows().iter().filter(|row| row.dirty).count();
    let remote = snapshots.iter().map(|v| v.records().len()).sum::<usize>();
    let frozen = FrozenSet::capture(
        &state,
        &sources,
        &"7".repeat(32),
        &progress,
        None,
        snapshots,
    )
    .unwrap();
    let bytes = frozen.encode_local().unwrap();
    drop(frozen);
    let restored = FrozenSet::decode_local(&bytes, &sources, &state).unwrap();
    assert_eq!(
        restored.encode_local().unwrap().as_slice(),
        bytes.as_slice()
    );
    let inventory = restored.inventory(&sources, &state).unwrap();
    assert_eq!(inventory.rows().len(), local_len + remote);
    assert_eq!(inventory.rows().iter().filter(|v| v.dirty).count(), dirty);
    assert_eq!(
        inventory
            .rows()
            .iter()
            .filter(|v| v.location.position == Position::Frozen)
            .count(),
        remote
    );
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    // Ciphertext retention itself never silently admits an unknown legacy payload.
    assert!(inventory.admit_known().is_err());
}
#[test]
fn terminal_progress_is_insufficient_without_exactly_one_snapshot_for_every_source() {
    let (state, sources, _, progress, mut snapshots) = fixture();
    snapshots.pop();
    assert!(FrozenSet::capture(
        &state,
        &sources,
        &"7".repeat(32),
        &progress,
        None,
        snapshots
    )
    .is_err());
    let (state, sources, owner, progress, mut snapshots) = fixture();
    let first = &snapshots[0];
    let duplicate = sources
        .admit_frozen(
            &owner,
            &"7".repeat(32),
            &progress,
            None,
            &first.checkpoint().chain_id,
            PullResponse {
                records: first.records().to_vec(),
                latest_seq: first.checkpoint().sequence.parse().unwrap(),
            },
        )
        .unwrap();
    snapshots[1] = duplicate;
    assert!(FrozenSet::capture(
        &state,
        &sources,
        &"7".repeat(32),
        &progress,
        None,
        snapshots
    )
    .is_err());
    let (state, sources, _, mut progress, snapshots) = fixture();
    progress.phase = FreezePhase::Freezing;
    assert!(FrozenSet::capture(
        &state,
        &sources,
        &"7".repeat(32),
        &progress,
        None,
        snapshots
    )
    .is_err());
}
#[test]
fn modified_archived_snapshots_context_and_progress_are_rejected_as_a_whole() {
    let (state, sources, _, progress, snapshots) = fixture();
    let frozen = FrozenSet::capture(
        &state,
        &sources,
        &"7".repeat(32),
        &progress,
        None,
        snapshots,
    )
    .unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&frozen.encode_local().unwrap()).unwrap();
    for case in [
        "checkpoint",
        "ciphertext",
        "missing",
        "duplicate",
        "order",
        "context",
        "keybook",
        "operation",
        "phase",
        "proof",
        "unknown",
        "version",
    ] {
        let mut value = original.clone();
        match case {
            "checkpoint" => value["snapshots"][0]["sequence"] = 99.into(),
            "ciphertext" => value["snapshots"][0]["records"][0]["ciphertext"] = "AAAA".into(),
            "missing" => {
                value["snapshots"].as_array_mut().unwrap().pop();
            }
            "duplicate" => value["snapshots"][1] = value["snapshots"][0].clone(),
            "order" => value["snapshots"].as_array_mut().unwrap().reverse(),
            "context" => value["local_context"] = "0".repeat(64).into(),
            "keybook" => value["keybook"] = "0".repeat(64).into(),
            "operation" => value["operation"] = "6".repeat(32).into(),
            "phase" => value["progress"]["phase"] = "freezing".into(),
            "proof" => value["progress"]["proof"] = serde_json::json!([]),
            "unknown" => value["other"] = true.into(),
            _ => value["version"] = 2.into(),
        }
        assert!(
            FrozenSet::decode_local(&serde_json::to_vec(&value).unwrap(), &sources, &state)
                .is_err(),
            "{case}"
        );
    }
    assert!(FrozenSet::decode_local(&vec![b' '; MAX_FROZEN_BYTES + 1], &sources, &state).is_err());
}
#[test]
fn original_source_cursor_minima_and_enrollment_binding_are_rechecked_on_restore() {
    let (state, sources, _, progress, snapshots) = fixture();
    let frozen = FrozenSet::capture(
        &state,
        &sources,
        &"7".repeat(32),
        &progress,
        None,
        snapshots,
    )
    .unwrap();
    let bytes = frozen.encode_local().unwrap();
    for case in ["cursor", "slot"] {
        let mut changed = state.clone();
        if case == "cursor" {
            changed.account.as_mut().unwrap().cursor_seq = 6;
        } else {
            changed.local.central.as_mut().unwrap().identity_slot = Some("9".repeat(32));
        }
        assert!(
            FrozenSet::decode_local(&bytes, &sources, &changed).is_err(),
            "{case}"
        );
    }
}
#[test]
fn a_local_only_library_still_requires_explicit_valid_empty_terminal_progress() {
    let (mut state, _, owner, _, _) = fixture();
    state.account = None;
    state.spaces.clear();
    let sources = Sources::discover(&state, None).unwrap();
    let (_, _, signer) = crate::sync::central::migration_history::tests::initial();
    let intent = sources
        .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
        .unwrap();
    let progress = Progress {
        proof: vec![crate::sync::central::migration_freeze::ProofStep {
            digest: intent.digest().unwrap(),
            intent,
        }],
        sources: vec![],
        phase: FreezePhase::Frozen,
        next: vec![],
    };
    let frozen =
        FrozenSet::capture(&state, &sources, &"7".repeat(32), &progress, None, vec![]).unwrap();
    FrozenSet::decode_local(&frozen.encode_local().unwrap(), &sources, &state).unwrap();
}

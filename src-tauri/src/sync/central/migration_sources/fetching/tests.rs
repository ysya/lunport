use super::*;
use crate::sync::central::{migration::legacy_checkpoint, migration_freeze::Phase as FreezePhase};
fn fixture() -> (
    SyncStateV3,
    Sources,
    Workspace,
    Progress,
    String,
    String,
    PullResponse,
    PullResponse,
) {
    let (mut state, sources, owner, progress, parent, child, parent_response, child_response) =
        super::super::frozen::tests::fixture_with_state();
    state.version = records_v3::CENTRAL_STATE_VERSION;
    state.local.central = Some(owner.clone());
    (
        state,
        sources,
        owner,
        progress,
        parent,
        child,
        parent_response,
        child_response,
    )
}
fn terminal(mut progress: Progress, child: &str, response: &PullResponse) -> Progress {
    progress
        .sources
        .push(legacy_checkpoint(child, response.latest_seq, &response.records).unwrap());
    progress.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
    progress.phase = FreezePhase::Frozen;
    progress.next.clear();
    progress
}
#[test]
fn partial_roundtrip_retains_exact_responses_and_requires_terminal_complete_inputs() {
    let (state, sources, owner, progress, parent, child, parent_response, child_response) =
        fixture();
    let mut fetching = Fetching::new(&sources, &state, &"7".repeat(32), &progress).unwrap();
    assert_eq!(
        fetching.next_source(&sources, &state).unwrap(),
        Some(parent.clone())
    );
    let snapshot = sources
        .admit_frozen(
            &owner,
            fetching.operation(),
            &progress,
            None,
            &parent,
            parent_response.clone(),
        )
        .unwrap();
    assert!(fetching.insert(&sources, &state, snapshot).unwrap());
    let mut reordered = parent_response;
    reordered.records.reverse();
    let retry = sources
        .admit_frozen(
            &owner,
            fetching.operation(),
            &progress,
            None,
            &parent,
            reordered,
        )
        .unwrap();
    let bytes = fetching.encode_local().unwrap();
    assert!(!fetching.insert(&sources, &state, retry).unwrap());
    assert_eq!(
        fetching.encode_local().unwrap().as_slice(),
        bytes.as_slice()
    );
    assert!(Fetching::decode_local(&bytes, &sources, &state)
        .unwrap()
        .complete(&sources, &state)
        .is_err());
    let mut restored = Fetching::decode_local(&bytes, &sources, &state).unwrap();
    assert_eq!(restored.next_source(&sources, &state).unwrap(), None);
    let terminal = terminal(progress, &child, &child_response);
    restored.advance(&sources, &state, &terminal).unwrap();
    assert_eq!(
        restored.next_source(&sources, &state).unwrap(),
        Some(child.clone())
    );
    let incomplete = restored.encode_local().unwrap();
    assert!(Fetching::decode_local(&incomplete, &sources, &state)
        .unwrap()
        .complete(&sources, &state)
        .is_err());
    let snapshot = sources
        .admit_frozen(
            &owner,
            restored.operation(),
            &terminal,
            None,
            &child,
            child_response,
        )
        .unwrap();
    restored.insert(&sources, &state, snapshot).unwrap();
    assert_eq!(restored.next_source(&sources, &state).unwrap(), None);
    let complete = restored.complete(&sources, &state).unwrap();
    complete.inventory(&sources, &state).unwrap();
}
#[test]
fn rollback_crossed_context_and_changed_book_cannot_drop_completed_obligations() {
    let (state, sources, owner, progress, parent, child, parent_response, child_response) =
        fixture();
    let mut fetching = Fetching::new(&sources, &state, &"7".repeat(32), &progress).unwrap();
    let snapshot = sources
        .admit_frozen(
            &owner,
            fetching.operation(),
            &progress,
            None,
            &parent,
            parent_response,
        )
        .unwrap();
    fetching.insert(&sources, &state, snapshot).unwrap();
    let terminal = terminal(progress.clone(), &child, &child_response);
    fetching.advance(&sources, &state, &terminal).unwrap();
    let before = fetching.encode_local().unwrap();
    assert!(fetching.advance(&sources, &state, &progress).is_err());
    let mut other = state.clone();
    other.local.central.as_mut().unwrap().identity_slot = Some("9".repeat(32));
    assert!(fetching.advance(&sources, &other, &terminal).is_err());
    let (_, other_sources, _, _, _, _, _, _) = fixture();
    assert!(fetching.advance(&other_sources, &state, &terminal).is_err());
    assert_eq!(
        fetching.encode_local().unwrap().as_slice(),
        before.as_slice()
    );
    let mut changed = terminal.clone();
    changed
        .sources
        .iter_mut()
        .find(|s| s.chain_id == parent)
        .unwrap()
        .sequence = "6".into();
    assert!(fetching.advance(&sources, &state, &changed).is_err());
    assert_eq!(
        fetching.encode_local().unwrap().as_slice(),
        before.as_slice()
    );
}
#[test]
fn altered_partial_data_never_restores_a_different_response_or_target() {
    let (state, sources, owner, progress, parent, _, parent_response, _) = fixture();
    let mut fetching = Fetching::new(&sources, &state, &"7".repeat(32), &progress).unwrap();
    let snapshot = sources
        .admit_frozen(
            &owner,
            fetching.operation(),
            &progress,
            None,
            &parent,
            parent_response,
        )
        .unwrap();
    fetching.insert(&sources, &state, snapshot).unwrap();
    let original: serde_json::Value =
        serde_json::from_slice(&fetching.encode_local().unwrap()).unwrap();
    for case in [
        "version",
        "unknown",
        "operation",
        "context",
        "keybook",
        "sequence",
        "ciphertext",
        "chain",
        "proof",
    ] {
        let mut value = original.clone();
        match case {
            "version" => value["version"] = 2.into(),
            "unknown" => value["unknown"] = true.into(),
            "operation" => value["operation"] = "6".repeat(32).into(),
            "context" => value["local_context"] = "0".repeat(64).into(),
            "keybook" => value["keybook"] = "0".repeat(64).into(),
            "sequence" => value["responses"][&parent]["sequence"] = 999.into(),
            "ciphertext" => value["responses"][&parent]["records"][0]["ciphertext"] = "AAAA".into(),
            "chain" => value["responses"][&parent]["chain"] = "0".repeat(64).into(),
            _ => value["progress"]["proof"] = serde_json::json!([]),
        }
        assert!(
            Fetching::decode_local(&serde_json::to_vec(&value).unwrap(), &sources, &state).is_err(),
            "{case}"
        );
    }
    assert!(Fetching::decode_local(&vec![b' '; MAX_FROZEN_BYTES + 1], &sources, &state).is_err());
}

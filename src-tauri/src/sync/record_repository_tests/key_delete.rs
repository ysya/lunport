use super::*;

fn fixture() -> (SyncStateV3, String, KeySlotPayload) {
    let mut state = with_spaces();
    let id = "a".repeat(32);
    let public = slot(PUBLIC);
    state.local.keys.insert(
        id.clone(),
        LocalKeyMetadata {
            vault_id: "f".repeat(32),
            public: public.clone(),
        },
    );
    (state, id, public)
}
fn token(state: &SyncStateV3) -> String {
    crate::sync::record_groups::deletion_snapshot_token(&snapshot(state).unwrap()).unwrap()
}
#[test]
fn deleting_a_local_key_keeps_hosts_and_source_identity_but_disables_use() {
    let (mut state, id, public) = fixture();
    let row = state
        .local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap();
    row.record.payload["auth"] = "key".into();
    row.record.payload["key_id"] = id.clone().into();
    let reviewed = token(&state);
    assert_eq!(
        delete_key(&state, &id, &public, &reviewed, false, 200),
        Err(RepositoryError::KeyInUse(id.clone()))
    );
    let next = delete_key(&state, &id, &public, &reviewed, true, 200).unwrap();
    assert_eq!(next.local.hosts, state.local.hosts);
    assert_eq!(next.spaces, state.spaces);
    assert!(!next.local.keys.contains_key(&id));
    assert_eq!(
        get_host(&next, ID).unwrap().readiness,
        HostReadiness::NeedsKey(id)
    );
}
#[test]
fn deletion_detects_references_in_unselected_libraries() {
    let (mut state, id, public) = fixture();
    let space = state.spaces.get_mut(&"a".repeat(64)).unwrap();
    space.selected = false;
    let mut host = payload("hidden");
    host.auth = AuthKind::Key;
    host.key_id = Some(id.clone());
    space
        .records
        .insert(record_key(RecordKind::Host, OTHER), cached(OTHER, host, 2));
    assert_eq!(
        delete_key(&state, &id, &public, &token(&state), false, 200),
        Err(RepositoryError::KeyInUse(id.clone()))
    );
    let next = delete_key(&state, &id, &public, &token(&state), true, 200).unwrap();
    assert_eq!(next.spaces, state.spaces);
}
#[test]
fn account_deletion_queues_a_tombstone_and_cannot_be_replaced_by_local_material() {
    let (mut state, id, public) = fixture();
    account_key(&mut state, &id, public.clone(), false);
    let next = delete_key(&state, &id, &public, &token(&state), false, 200).unwrap();
    let row = &next.account.as_ref().unwrap().records[&record_key(RecordKind::KeySlot, &id)];
    assert!(row.record.deleted && row.dirty);
    assert_eq!(row.record.version, 2);
    assert_eq!(row.seq, 9);
    assert!(row.record.payload.is_null());
    assert_eq!(resolve_key(&next, &id).unwrap().status, KeyStatus::Deleted);
    assert!(!next.local.keys.contains_key(&id));
    assert!(delete_key(&next, &id, &public, &token(&next), true, 201).is_err());
}
#[test]
fn force_does_not_bypass_stale_review_conflict_or_account_write_gate() {
    let (mut state, id, public) = fixture();
    let reviewed = token(&state);
    state
        .local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap()
        .record
        .payload["alias"] = "changed".into();
    assert!(delete_key(&state, &id, &public, &reviewed, true, 200).is_err());
    account_key(&mut state, &id, public.clone(), false);
    state.shared_writes_blocked = true;
    assert_eq!(
        delete_key(&state, &id, &public, &token(&state), true, 200),
        Err(RepositoryError::ReadOnlyAccount)
    );
    state.shared_writes_blocked = false;
    state.local.keys.get_mut(&id).unwrap().public = slot(ECDSA);
    assert!(delete_key(&state, &id, &public, &token(&state), true, 200).is_err());
}

#[test]
fn deleting_an_inherited_group_key_preserves_group_and_requires_reselection() {
    let (mut state, id, public) = fixture();
    state.version = 4;
    let group_id = "0000000000000003";
    let mut record = cached(group_id, payload("unused"), 0);
    record.record.kind = RecordKind::Group;
    record.record.payload = serde_json::json!({"schema":1,"name":"Team","defaults":{"authentication":{"auth":"key","key_id":id}}});
    state
        .local
        .groups
        .insert(record_key(RecordKind::Group, group_id), record);
    let host = state
        .local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap();
    host.record.payload["schema"] = 3.into();
    host.record.payload["group_id"] = group_id.into();
    host.record.payload["inherit"] = serde_json::json!(["authentication"]);
    assert_eq!(
        get_host(&state, ID).unwrap().readiness,
        HostReadiness::Ready
    );
    assert!(matches!(
        delete_key(&state, &id, &public, &token(&state), false, 200),
        Err(RepositoryError::KeyInUse(_))
    ));
    let next = delete_key(&state, &id, &public, &token(&state), true, 200).unwrap();
    assert_eq!(next.local.hosts, state.local.hosts);
    assert_eq!(next.local.groups, state.local.groups);
    assert_eq!(
        get_host(&next, ID).unwrap().readiness,
        HostReadiness::NeedsKey(id)
    );
}

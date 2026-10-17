use super::*;

fn local_key() -> (SyncStateV3, String, KeySlotPayload) {
    let mut state = with_host();
    let id = "a".repeat(32);
    let public = slot(PUBLIC);
    state.local.keys.insert(id.clone(), LocalKeyMetadata {
        vault_id: "f".repeat(32), public: public.clone(),
    });
    let host = state.local.hosts.get_mut(&record_key(RecordKind::Host, ID)).unwrap();
    host.record.payload["auth"] = "key".into();
    host.record.payload["key_id"] = id.clone().into();
    (state, id, public)
}

#[test]
fn local_rename_preserves_identity_material_reference_and_connected_hosts() {
    let (state, id, public) = local_key();
    let next = rename_key(&state, &id, &public, "  production-key  ", 200).unwrap();
    let mut expected = state.clone();
    expected.local.keys.get_mut(&id).unwrap().public.name = "production-key".into();
    assert_eq!(next, expected);
    assert_eq!(get_host(&next, ID).unwrap().readiness, HostReadiness::Ready);
    assert_eq!(resolve_key(&next, &id).unwrap().vault_id, Some("f".repeat(32)));
    assert_eq!(resolve_key(&state, &id).unwrap().public.unwrap(), public);
}

#[test]
fn account_rename_queues_only_metadata_and_preserves_ordering_and_local_material() {
    let (mut state, id, public) = local_key();
    state.account = Some(AccountState::new(&"b".repeat(64)));
    account_key(&mut state, &id, public.clone(), false);
    let next = rename_key(&state, &id, &public, "account-key", 50).unwrap();
    let cache_key = record_key(RecordKind::KeySlot, &id);
    let account = next.account.as_ref().unwrap();
    let row = &account.records[&cache_key];
    assert_eq!(row.record.kind, RecordKind::KeySlot);
    assert_eq!(row.record.version, 2);
    assert_eq!(row.record.updated_at_ms, 101);
    assert_eq!(row.seq, 9);
    assert!(row.dirty);
    assert_eq!(account.sealed, state.account.as_ref().unwrap().sealed);
    let mut expected = public.clone();
    expected.name = "account-key".into();
    assert_eq!(decode_keyslot(&row.record).unwrap(), TypedRecord::Live(expected.clone()));
    assert_eq!(next.local.keys[&id].public, expected);
    assert_eq!(next.local.hosts, state.local.hosts);
    assert_eq!(next.local.keys[&id].vault_id, state.local.keys[&id].vault_id);
    // Public metadata can be named on a second device before downloading its private key.
    state.local.keys.clear();
    let next = rename_key(&state, &id, &public, "remote-key", 200).unwrap();
    assert_eq!(resolve_key(&next, &id).unwrap().status, KeyStatus::NeedsMaterial);
    assert!(next.local.keys.is_empty());
}

#[test]
fn rename_rejects_stale_metadata_invalid_names_and_removed_keys() {
    let (state, id, public) = local_key();
    let changed = rename_key(&state, &id, &public, "first-change", 200).unwrap();
    assert!(rename_key(&changed, &id, &public, "stale-overwrite", 201).is_err());
    for name in ["", "   ", "../key", "key\nname", "key.pub"] {
        assert!(rename_key(&state, &id, &public, name, 200).is_err(), "{name:?}");
    }
    assert!(rename_key(&state, &"e".repeat(32), &public, "missing", 200).is_err());
    assert_eq!(rename_key(&state, &id, &public, &public.name, 200).unwrap(), state);
}

#[test]
fn account_rename_cannot_override_a_write_gate_deleted_identity_or_conflicting_material() {
    let (mut state, id, public) = local_key();
    state.account = Some(AccountState::new(&"b".repeat(64)));
    account_key(&mut state, &id, public.clone(), false);
    state.shared_writes_blocked = true;
    assert_eq!(rename_key(&state, &id, &public, "blocked", 200), Err(RepositoryError::ReadOnlyAccount));
    state.shared_writes_blocked = false;
    state.local.keys.get_mut(&id).unwrap().public = slot(ECDSA);
    assert!(rename_key(&state, &id, &public, "conflict", 200).is_err());
    state.local.keys.get_mut(&id).unwrap().public = public.clone();
    account_key(&mut state, &id, public.clone(), true);
    assert!(rename_key(&state, &id, &public, "deleted", 200).is_err());
}
